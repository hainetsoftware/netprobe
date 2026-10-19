#!/usr/bin/env python3
"""
NetProbe Sensitivity & Robustness Verification Tool:
Esegue test statistici di perturbazione e sweep sintetici sul modello di stima fisica:
1. Perturbazione Monte Carlo (200 trial, seed fisso 42): perturbazione RTT/jitter +-15% e throughput +-10%
2. Iniezione di picchi isolati (1-3 spike di 200-700 ms su campioni hop-2 ed edge) per verificare l'invarianza del verdetto FTTC (target variazione <= 5%)
3. Sweep sintetico su access_delta da 1 a 14 ms per individuare i confini di decisione tra FTTH e FTTC.
"""

import copy
import json
import os
import random
import sys
from typing import Dict, Any, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.estimators import NetworkEstimator

FIXTURES = [
    "real_wifi_fttc.anon.json",
    "real_hotspot_wind3.json",
    "real_wifi_fttc_dazn_1.json",
    "real_wifi_fttc_dazn_2.json"
]


def load_fixture(fixture_name: str) -> Tuple[str, Dict[str, Any]]:
    fixtures_dir = os.path.join(BASE_DIR, "tests", "fixtures")
    path = os.path.join(fixtures_dir, fixture_name)
    if not os.path.exists(path):
        clean_name = fixture_name.replace(".anon.json", ".json")
        path = os.path.join(fixtures_dir, clean_name)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return path, data


def perturb_value(val: Any, pct: float) -> Any:
    if val is None or not isinstance(val, (int, float)):
        return val
    factor = 1.0 + random.uniform(-pct, pct)
    return round(max(0.1, val * factor), 2)


def run_perturbation_analysis(fixture_name: str, trials: int = 200, seed: int = 42) -> Dict[str, Any]:
    random.seed(seed)
    path, base_data = load_fixture(fixture_name)
    estimator = NetworkEstimator()

    verdict_counts: Dict[str, int] = {}
    ambiguous_count = 0
    conf_sum = 0.0

    for _ in range(trials):
        d = copy.deepcopy(base_data)
        perf = d.get("performance") or {}
        ixp = d.get("ixp") or {}

        # Perturba RTT e jitter +-15%
        for lat_key in ("gateway_latency", "primary_latency"):
            tgt = perf.get(lat_key) or {}
            for metric in ("min_ms", "avg_ms", "median_ms", "max_ms", "jitter_ms", "spread_ms"):
                if metric in tgt and tgt[metric] is not None:
                    tgt[metric] = perturb_value(tgt[metric], 0.15)

        hop2 = ixp.get("hop2_bng") or {}
        for metric in ("min_ms", "avg_ms", "median_ms", "p95_ms", "jitter_ms", "tail_variance_ms", "spread_ms"):
            if metric in hop2 and hop2[metric] is not None:
                hop2[metric] = perturb_value(hop2[metric], 0.15)

        # Perturba throughput +-10%
        speed = perf.get("speed") or {}
        for spd_key in ("download_mbps", "upload_mbps", "download_peak_mbps", "upload_peak_mbps"):
            if spd_key in speed and speed[spd_key] is not None:
                speed[spd_key] = perturb_value(speed[spd_key], 0.10)

        res = estimator.calculate_all(d.get("lan") or {}, d.get("wan") or {}, perf, ixp)
        pm = res.get("physical_medium", {})
        pred = pm.get("predicted_medium", "N/D")
        is_ambig = pm.get("ambiguous", False)
        conf = pm.get("confidence_pct", 0.0)

        verdict_counts[pred] = verdict_counts.get(pred, 0) + 1
        if is_ambig:
            ambiguous_count += 1
        conf_sum += conf

    avg_conf = round(conf_sum / trials, 1)
    ambig_pct = round(ambiguous_count / trials * 100.0, 1)

    distribution = {k: round(v / trials * 100.0, 1) for k, v in verdict_counts.items()}
    return {
        "fixture": os.path.basename(path),
        "trials": trials,
        "distribution_pct": distribution,
        "ambiguous_pct": ambig_pct,
        "avg_confidence_pct": avg_conf
    }


def run_spike_injection_test(fixture_name: str, trials: int = 200, seed: int = 42) -> Dict[str, Any]:
    random.seed(seed)
    path, base_data = load_fixture(fixture_name)
    estimator = NetworkEstimator()

    base_res = estimator.calculate_all(
        base_data.get("lan") or {},
        base_data.get("wan") or {},
        base_data.get("performance") or {},
        base_data.get("ixp") or {}
    )
    base_pred = base_res["physical_medium"]["predicted_medium"]

    changed_count = 0
    for _ in range(trials):
        d = copy.deepcopy(base_data)
        ixp = d.get("ixp") or {}
        hop2 = ixp.get("hop2_bng") or {}

        # Inietta da 1 a 3 spike isolati da 200 a 700 ms
        k_spikes = random.randint(1, 3)
        spikes = [random.uniform(200.0, 700.0) for _ in range(k_spikes)]
        
        # Le metriche robuste (min, median, spread) rimangono stabili,
        # mentre le metriche di coda (p95, tail_variance, jitter, spike_fraction) aumentano drasticamente
        old_n = hop2.get("samples_count") or 30
        new_n = old_n + k_spikes
        hop2["samples_count"] = new_n
        hop2["p95_ms"] = round(max(hop2.get("p95_ms", 15.0), max(spikes) * 0.9), 2)
        hop2["tail_variance_ms"] = round(max(50.0, hop2["p95_ms"] - (hop2.get("median_ms") or 14.0)), 2)
        hop2["jitter_ms"] = round((hop2.get("jitter_ms") or 1.0) + random.uniform(15.0, 40.0), 2)
        hop2["spike_fraction"] = round(k_spikes / new_n, 3)

        res = estimator.calculate_all(d.get("lan") or {}, d.get("wan") or {}, d.get("performance") or {}, ixp)
        pred = res["physical_medium"]["predicted_medium"]
        if pred != base_pred:
            changed_count += 1

    change_rate = round(changed_count / trials * 100.0, 1)
    return {
        "fixture": os.path.basename(path),
        "base_prediction": base_pred,
        "trials": trials,
        "changed_predictions": changed_count,
        "change_rate_pct": change_rate,
        "stable": change_rate <= 5.0
    }


def run_synthetic_sweep() -> List[Dict[str, Any]]:
    """Sweep su access_delta da 1 a 14 ms (passo 1 ms) per individuare le soglie decisionali."""
    estimator = NetworkEstimator()
    results = []

    for delta_ms in range(1, 15):
        gw_min = 3.0
        hop2_min = gw_min + float(delta_ms)
        hop2_med = hop2_min + 1.0

        # Scenario A: Profilo tipico FTTC (Upload 18 Mbps, Download 40 Mbps, MTU 1492)
        lan_a = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1492}}
        wan_a = {"isp": "TIM", "asn": "AS3269", "country": "IT", "nat": {}}
        perf_a = {
            "gateway_latency": {"min_ms": gw_min, "median_ms": gw_min + 0.8},
            "primary_latency": {"min_ms": hop2_min + 1.0, "median_ms": hop2_min + 2.0},
            "speed": {"download_mbps": 40.0, "upload_mbps": 18.0}
        }
        ixp_a = {
            "hop2_bng": {
                "ip": "195.22.196.1",
                "min_ms": hop2_min,
                "median_ms": hop2_med,
                "spread_ms": 1.0,
                "iqr_ms": 1.2,
                "is_responsive": True,
                "samples_count": 30
            },
            "path_mtu": 1492
        }
        res_a = estimator.calculate_all(lan_a, wan_a, perf_a, ixp_a)["physical_medium"]

        # Scenario B: Profilo tipico FTTH (Upload 100 Mbps, Download 300 Mbps, MTU 1500)
        lan_b = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1500}}
        wan_b = {"isp": "TIM", "asn": "AS3269", "country": "IT", "nat": {}}
        perf_b = {
            "gateway_latency": {"min_ms": gw_min, "median_ms": gw_min + 0.8},
            "primary_latency": {"min_ms": hop2_min + 1.0, "median_ms": hop2_min + 2.0},
            "speed": {"download_mbps": 300.0, "upload_mbps": 100.0}
        }
        ixp_b = {
            "hop2_bng": {
                "ip": "195.22.196.1",
                "min_ms": hop2_min,
                "median_ms": hop2_med,
                "spread_ms": 1.0,
                "iqr_ms": 1.2,
                "is_responsive": True,
                "samples_count": 30
            },
            "path_mtu": 1500
        }
        res_b = estimator.calculate_all(lan_b, wan_b, perf_b, ixp_b)["physical_medium"]

        def _short(name: str) -> str:
            if "FTTH" in name: return "FTTH"
            if "FTTC" in name: return "FTTC"
            if "Mobile" in name: return "Mobile"
            if "FWA" in name: return "FWA"
            return name.split()[0]

        results.append({
            "access_delta_ms": float(delta_ms),
            "scenario_a": {
                "pred": _short(res_a["predicted_medium"]),
                "conf": res_a["confidence_pct"],
                "ambiguous": res_a["ambiguous"],
                "verdict": res_a["verdict_label"]
            },
            "scenario_b": {
                "pred": _short(res_b["predicted_medium"]),
                "conf": res_b["confidence_pct"],
                "ambiguous": res_b["ambiguous"],
                "verdict": res_b["verdict_label"]
            }
        })

    return results


def main():
    print("=" * 80)
    print("NETPROBE SENSITIVITY & ROBUSTNESS ANALYSIS")
    print("=" * 80)

    print("\n1. ANALISI DI PERTURBAZIONE MONTE CARLO (200 trial, RTT +-15%, Speed +-10%):")
    print("-" * 80)
    for fix in FIXTURES:
        try:
            res = run_perturbation_analysis(fix, trials=200, seed=42)
            dist_str = ", ".join(f"{k.split()[0]}: {v}%" for k, v in res["distribution_pct"].items())
            print(f"• {res['fixture']:<28} => Confidenza media: {res['avg_confidence_pct']}% | Ambiguità: {res['ambiguous_pct']}%")
            print(f"  └─ Distribuzione: {dist_str}")
        except Exception as e:
            print(f"• {fix:<28} => ERRORE: {e}")

    print("\n2. TEST INIEZIONE SPIKE ISOLATI (1-3 spike da 200-700 ms, target variazione <= 5%):")
    print("-" * 80)
    for fix in ("real_wifi_fttc.anon.json", "real_wifi_fttc_dazn_1.json"):
        try:
            sp_res = run_spike_injection_test(fix, trials=200, seed=42)
            status = "PASS" if sp_res["stable"] else "FAIL"
            print(f"• {sp_res['fixture']:<28} => Previsione base: {sp_res['base_prediction'].split()[0]}")
            print(f"  └─ Variazioni: {sp_res['changed_predictions']}/{sp_res['trials']} ({sp_res['change_rate_pct']}%) => [{status}] (target <= 5%)")
        except Exception as e:
            print(f"• {fix:<28} => ERRORE: {e}")

    print("\n3. SWEEP SINTETICO ACCESS DELTA (1 - 14 ms, confini di decisione):")
    print("-" * 80)
    print(f"  {'Delta (ms)':<12} {'Scenario A (VDSL 40/18M)':<32} {'Scenario B (FTTH 300/100M)':<32}")
    print(f"  {'-'*10:<12} {'-'*30:<32} {'-'*30:<32}")
    sweep = run_synthetic_sweep()
    for row in sweep:
        a = row["scenario_a"]
        b = row["scenario_b"]
        a_str = f"{a['pred']} ({a['conf']}%, ambig={a['ambiguous']})"
        b_str = f"{b['pred']} ({b['conf']}%, ambig={b['ambiguous']})"
        print(f"  {row['access_delta_ms']:<12.1f} {a_str:<32} {b_str:<32}")
    print("=" * 80)


if __name__ == "__main__":
    main()
