import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.estimators import NetworkEstimator
from tools.replay import replay_file, recalculate_classification
from tools.sensitivity import run_perturbation_analysis, run_spike_injection_test


class TestFixesV3(unittest.TestCase):
    def setUp(self):
        self.est = NetworkEstimator()
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.fttc_file = os.path.join(self.fixtures_dir, "real_wifi_fttc.anon.json")
        self.wind3_file = os.path.join(self.fixtures_dir, "real_hotspot_wind3.json")
        self.dazn1_file = os.path.join(self.fixtures_dir, "real_wifi_fttc_dazn_1.json")
        self.dazn2_file = os.path.join(self.fixtures_dir, "real_wifi_fttc_dazn_2.json")

    # 1. Synthetic hop-2 samples with spikes: must keep FTTC, must not trigger radio
    def test_synthetic_fttc_with_spikes_no_radio(self):
        # 30 valori: min ~ 11.8, median ~ 13.3, due spike da 400-700 ms
        samples = [11.8, 12.0, 12.2, 12.5, 12.8, 13.0, 13.1, 13.2, 13.3, 13.3,
                   13.4, 13.5, 13.6, 13.7, 13.8, 14.0, 14.1, 14.2, 14.5, 14.8,
                   15.0, 15.2, 15.5, 16.0, 16.5, 17.0, 18.0, 22.0, 480.0, 690.0]
        # Calcolo metriche
        samples.sort()
        med = samples[15] # 13.8
        min_v = samples[0] # 11.8
        spread = med - min_v # 2.0 ms
        iqr = samples[22] - samples[7] # 15.5 - 13.2 = 2.3 ms
        
        lan = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1492}}
        wan = {"isp": "TIM", "asn": "AS3269", "country": "IT", "nat": {}}
        perf = {
            "gateway_latency": {"min_ms": 2.5, "median_ms": 3.2},
            "primary_latency": {"min_ms": 12.5, "median_ms": 14.0},
            "speed": {"download_mbps": 38.0, "upload_mbps": 14.0}
        }
        ixp = {
            "hop2_bng": {
                "ip": "195.22.196.1",
                "min_ms": min_v,
                "median_ms": med,
                "spread_ms": round(spread, 2),
                "iqr_ms": round(iqr, 2),
                "tail_variance_ms": 676.2,
                "p95_ms": 690.0,
                "spike_fraction": 2 / 30,
                "is_responsive": True,
                "samples_count": 30
            },
            "path_mtu": 1492
        }
        res = self.est.calculate_all(lan, wan, perf, ixp)["physical_medium"]
        self.assertIn("FTTC", res["predicted_medium"])
        # Non deve contenere evidenza di scheduling radio
        radio_ev = [e for e in res["evidence"] if "scheduling radio" in e["reason"]]
        self.assertEqual(len(radio_ev), 0, f"Spurious radio evidence triggered: {radio_ev}")
        # Deve contenere evidenza neutra per picchi isolati
        spike_ev = [e for e in res["evidence"] if "Picchi isolati" in e["reason"]]
        self.assertEqual(len(spike_ev), 1)

    # 2. Genuine radio-like samples: must trigger radio evidence
    def test_genuine_radio_samples_trigger_radio_evidence(self):
        lan = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1500}}
        wan = {"isp": "Generic Wireless", "nat": {}}
        perf = {
            "gateway_latency": {"min_ms": 3.0, "median_ms": 4.0},
            "primary_latency": {"min_ms": 30.0, "median_ms": 42.0},
            "speed": {"download_mbps": 50.0, "upload_mbps": 15.0},
            "bufferbloat": {"download_delta_ms": 90.0, "upload_delta_ms": 110.0}
        }
        # IQR >= 15 ms, min ~ 25, median ~ 35, spread = 10 ms
        ixp = {
            "hop2_bng": {
                "ip": "151.5.1.1",
                "min_ms": 25.0,
                "median_ms": 35.0,
                "spread_ms": 10.0,
                "iqr_ms": 15.0,
                "is_responsive": True,
                "samples_count": 30
            }
        }
        res = self.est.calculate_all(lan, wan, perf, ixp)["physical_medium"]
        radio_ev = [e for e in res["evidence"] if "scheduling radio" in e["reason"]]
        self.assertGreaterEqual(len(radio_ev), 1, "Expected radio dispersion evidence to trigger")
        self.assertIn(res["predicted_medium"].split()[0], ("Mobile", "FWA"))

    # 3. Noisy FTTC fixtures (dazn_1 and dazn_2): FTTC, never confident Mobile
    def test_dazn_fixtures_are_fttc_and_noisy(self):
        for fix_path in (self.dazn1_file, self.dazn2_file):
            if not os.path.exists(fix_path):
                continue
            res = replay_file(fix_path)
            pm = res["physical_medium"]
            # Deve essere FTTC
            self.assertIn("FTTC", pm["predicted_medium"])
            # Non deve mai essere Mobile come primario
            self.assertNotIn("Mobile", pm["predicted_medium"])
            # Deve essere marcato come noisy
            mq = pm.get("measurement_quality", {})
            self.assertTrue(mq.get("noisy"), f"{fix_path} should be flagged noisy")
            # Con confidenza < 40% deve essere ambiguous
            self.assertTrue(pm["ambiguous"])
            self.assertIn("FTTC", pm["verdict_label"])

    # 4. Clean FTTC and Hotspot fixtures remain accurate
    def test_clean_fixtures_remain_accurate(self):
        fttc_res = replay_file(self.fttc_file)["physical_medium"]
        self.assertIn("FTTC", fttc_res["predicted_medium"])
        self.assertGreaterEqual(fttc_res["confidence_pct"], 40.0)
        self.assertFalse(fttc_res["ambiguous"])

        wind3_res = replay_file(self.wind3_file)["physical_medium"]
        self.assertIn("Mobile", wind3_res["predicted_medium"])
        self.assertGreaterEqual(wind3_res["confidence_pct"], 60.0)
        self.assertFalse(wind3_res["ambiguous"])

    # 5. Hotspot fixture with iOS gateway ablated: ambiguous between Mobile and FWA
    def test_hotspot_ablated_gateway_is_ambiguous(self):
        res = replay_file(self.wind3_file)
        pm = res["physical_medium"]
        # Ablazione dell'impronta gateway 172.20.10.1
        ablated = recalculate_classification(pm["evidence"], ablate_list=["172.20.10.1"])
        self.assertTrue(ablated["ambiguous"])
        self.assertIn("Mobile o FWA", ablated["verdict_label"])

    # 6. Verdict coherence and unassigned_pct math
    def test_verdict_coherence_and_unassigned_math(self):
        for fix_path in (self.fttc_file, self.wind3_file, self.dazn1_file, self.dazn2_file):
            if not os.path.exists(fix_path):
                continue
            pm = replay_file(fix_path)["physical_medium"]
            conf = pm["confidence_pct"]
            alts = pm["alternatives"]
            for a in alts:
                self.assertLessEqual(a["confidence_share_pct"], conf,
                    f"Alternative {a['medium']} share {a['confidence_share_pct']} exceeds primary {conf}")
            total_sum = round(conf + sum(a["confidence_share_pct"] for a in alts) + pm["unassigned_pct"], 1)
            self.assertAlmostEqual(total_sum, 100.0, delta=0.3)

    # 7. Sensitivity Monte Carlo trial rates
    def test_sensitivity_rates(self):
        fttc_sens = run_perturbation_analysis("real_wifi_fttc.anon.json", trials=100, seed=42)
        fttc_rate = fttc_sens["distribution_pct"].get("FTTC / VDSL2 (Fibra Misto Rame)", 0.0)
        self.assertGreaterEqual(fttc_rate, 90.0, f"Clean FTTC stability {fttc_rate}% < 90%")

        hotspot_sens = run_perturbation_analysis("real_hotspot_wind3.json", trials=100, seed=42)
        hotspot_rate = hotspot_sens["distribution_pct"].get("Mobile Cellular (4G LTE / 5G Mobile Hotspot)", 0.0)
        self.assertGreaterEqual(hotspot_rate, 90.0, f"Hotspot stability {hotspot_rate}% < 90%")

        spike_fttc = run_spike_injection_test("real_wifi_fttc.anon.json", trials=100, seed=42)
        self.assertTrue(spike_fttc["stable"])
        self.assertLessEqual(spike_fttc["change_rate_pct"], 5.0)


if __name__ == "__main__":
    unittest.main()
