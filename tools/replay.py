#!/usr/bin/env python3
"""
NetProbe Replay Tool:
Carica uno o piu' file JSON di diagnostica NetProbe da disco,
esegue offline esclusivamente il livello di stima e modellazione matematica (core/estimators.py),
e visualizza per ciascun file:
- Mezzo fisico previsto e confidenza
- Alternative (top-2) con punteggio e quota di confidenza
- Lista dettagliata delle evidenze con contributo di punteggio per mezzo
Supporta inoltre:
- '--diff fileA.json fileB.json' per comparare due classificazioni
- '--ablate SUBSTRING' per testare l'impatto della rimozione di specifiche evidenze
- Validazione automatica contro file Ground Truth (.truth.json)
"""

import argparse
import json
import math
import os
import sys
from typing import Dict, Any, List, Optional, Tuple

# Assicura importazione dei moduli di NetProbe
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.estimators import NetworkEstimator

MEDIA_NAMES = [
    "FTTH (Fibra Ottica Pura GPON / XGS-PON)",
    "FTTC / VDSL2 (Fibra Misto Rame)",
    "Mobile Cellular (4G LTE / 5G Mobile Hotspot)",
    "FWA (Fixed Wireless Access / Eolo / Linkem)",
    "DOCSIS (Cavo Coassiale HFC)",
    "Satellite LEO (Starlink Bassa Orbita)",
    "Satellite GEO (Geostazionario Tradizionale)"
]


def replay_file(file_path: str) -> Dict[str, Any]:
    """Carica un file JSON di scansione NetProbe ed esegue la stima offline."""
    res, _ = replay_file_with_data(file_path)
    return res


def replay_file_with_data(file_path: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Carica un file JSON di scansione NetProbe e restituisce stime e dati grezzi."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    lan_data = data.get("lan") or {}
    wan_data = data.get("wan") or {}
    perf_data = data.get("performance") or {}
    ixp_data = data.get("ixp") or {}

    estimator = NetworkEstimator()
    res = estimator.calculate_all(lan_data, wan_data, perf_data, ixp_data)
    return res, data


def recalculate_classification(
    evidence: List[Dict[str, Any]],
    ablate_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Ricalcola la classificazione del mezzo fisico e la confidenza
    a partire dalle evidenze, escludendo quelle corrispondenti a sottostringhe in ablate_list.
    """
    ablate_lower = [s.lower() for s in (ablate_list or [])]
    scores = {m: 0.0 for m in MEDIA_NAMES}
    active_ev = []
    ablated_ev = []

    for ev in evidence:
        reason = ev.get("reason", "")
        if any(sub in reason.lower() for sub in ablate_lower):
            ablated_ev.append(ev)
            continue
        active_ev.append(ev)
        for k, v in ev.get("contributions", {}).items():
            scores[k] = scores.get(k, 0.0) + v

    fttc_vetoed = scores.get("FTTC / VDSL2 (Fibra Misto Rame)", 0.0) <= -500.0
    positive_scores = {k: max(0.0, v) for k, v in scores.items()}
    ranked = sorted(positive_scores.items(), key=lambda x: x[1], reverse=True)
    if fttc_vetoed and ranked[0][0].startswith("FTTC"):
        ranked = [c for c in ranked if not c[0].startswith("FTTC")]

    best_medium = ranked[0]
    denom_exp = sum(math.exp((c[1] - best_medium[1]) / 20.0) for c in ranked)
    p_best = 1.0 / denom_exp if denom_exp > 0 else 0.0
    strength = min(1.0, best_medium[1] / 35.0)
    confidence = round(min(90.0, 100.0 * p_best * (0.5 + 0.5 * strength)), 1)

    insufficient = best_medium[1] < 30.0
    predicted = "Indeterminato (dati insufficienti)" if insufficient else best_medium[0]
    if insufficient:
        confidence = min(confidence, 25.0)

    alternatives = []
    if not insufficient and best_medium[1] > 0.0:
        for cand_name, cand_score in ranked[1:3]:
            if cand_score > 0.0:
                cand_share = round(confidence * math.exp((cand_score - best_medium[1]) / 20.0), 1)
                alternatives.append({
                    "medium": cand_name,
                    "score": round(cand_score, 1),
                    "confidence_share_pct": cand_share
                })

    assert all(a["confidence_share_pct"] <= confidence for a in alternatives), "No alternative may exceed primary confidence"
    alts_share_sum = sum(a["confidence_share_pct"] for a in alternatives)
    unassigned_pct = round(max(0.0, 100.0 - confidence - alts_share_sum), 1)

    second_score = ranked[1][1] if len(ranked) > 1 else 0.0
    score_margin = best_medium[1] - second_score
    is_ambiguous = False
    verdict_label = predicted
    if insufficient:
        is_ambiguous = True
        verdict_label = "Indeterminato (dati insufficienti)"
    elif confidence < 40.0 or (score_margin < 15.0 and second_score > 0.0):
        is_ambiguous = True
        cand1 = best_medium[0]
        cand2 = ranked[1][0] if len(ranked) > 1 else ""
        def _short(name: str) -> str:
            for k in ("FTTH", "FTTC", "Mobile", "FWA", "DOCSIS", "LEO", "GEO"):
                if k in name: return k
            return name.split()[0]
        s1, s2 = _short(cand1), _short(cand2)
        if {s1, s2} == {"FTTC", "FTTH"}:
            verdict_label = "FTTC o FTTH (non distinguibile da rete)"
        elif {s1, s2} == {"Mobile", "FWA"}:
            verdict_label = "Mobile o FWA (non distinguibile senza impronta del gateway)"
        elif s2:
            verdict_label = f"{s1} o {s2} (non distinguibile da rete)"
        else:
            verdict_label = f"{s1} (ambiguo)"

    return {
        "predicted_medium": predicted,
        "verdict_label": verdict_label,
        "confidence_pct": confidence,
        "ambiguous": is_ambiguous,
        "alternatives": alternatives,
        "unassigned_pct": unassigned_pct,
        "remainder_share_pct": unassigned_pct,
        "scores_breakdown": positive_scores,
        "ranked": ranked,
        "active_evidence": active_ev,
        "ablated_evidence": ablated_ev
    }


def find_truth_file(file_path: str) -> Optional[str]:
    """Cerca il file .truth.json associato al percorso del file, rimuovendo .anon."""
    dirname = os.path.dirname(file_path)
    base = os.path.basename(file_path)
    clean = base.replace(".anon.json", ".json")
    if clean.endswith(".json"):
        clean = clean[:-5]
    candidate = os.path.join(dirname, f"{clean}.truth.json")
    if os.path.exists(candidate):
        return candidate
    return None


def format_alternatives(alts: List[Dict[str, Any]]) -> str:
    if not alts:
        return "Nessuna alternativa significativa"
    items = []
    for a in alts:
        med = a.get("medium", "Sconosciuto")
        score = a.get("score", 0.0)
        share = a.get("confidence_share_pct", 0.0)
        items.append(f"{med} (punti: {score}, share: {share}%)")
    return "; ".join(items)


def print_single_report(
    file_path: str,
    res: Dict[str, Any],
    raw_data: Optional[Dict[str, Any]] = None,
    ablate_list: Optional[List[str]] = None
) -> None:
    med = res.get("physical_medium", {})
    predicted = med.get("predicted_medium", "N/D")
    verdict = med.get("verdict_label") or predicted
    conf = med.get("confidence_pct", "N/D")
    alts = med.get("alternatives", [])
    unassigned = med.get("unassigned_pct")
    evidence = med.get("evidence", [])
    mq = med.get("measurement_quality") or res.get("measurement_quality") or {}

    print("=" * 80)
    print(f"FILE: {file_path}")
    print("=" * 80)
    print(f"Mezzo Fisico Previsto : {predicted}")
    if med.get("ambiguous"):
        print(f"Etichetta Verdetto    : {verdict}")
    print(f"Confidenza Modello    : {conf}%")
    print(f"Alternative           : {format_alternatives(alts)}")
    if unassigned is not None:
        print(f"Non Attribuito        : {unassigned}%")
    if mq.get("noisy"):
        print(f"Qualità Misura        : DISTURBATA (possibile traffico concorrente: {'; '.join(mq.get('reasons', []))})")
    print("-" * 80)
    print("Evidenze e Contributi di Punteggio per Mezzo:")

    if not evidence:
        for r in med.get("rationale", []):
            print(f"  • {r}")
    else:
        for idx, ev in enumerate(evidence, 1):
            reason = ev.get("reason", "")
            contribs = ev.get("contributions", {})
            print(f"  {idx}. {reason}")
            if contribs:
                c_strs = [f"{k}: {'+' if v > 0 else ''}{v}" for k, v in contribs.items()]
                print(f"     └─ Contributi: {', '.join(c_strs)}")

    # Validazione Ground Truth
    truth_file = find_truth_file(file_path)
    if truth_file and os.path.exists(truth_file):
        try:
            with open(truth_file, "r", encoding="utf-8") as tf:
                truth = json.load(tf)
            print("-" * 80)
            print(f"VALIDAZIONE GROUND TRUTH ({os.path.basename(truth_file)}):")
            expected = truth.get("medium_contains")
            if expected:
                matched = (expected.lower() in predicted.lower()) or (expected.lower() in verdict.lower())
                status = "PASS" if matched else "FAIL"
                print(f"  • Mezzo Atteso : contiene '{expected}' => [{status}] (Previsto: {verdict})")
            if truth.get("patched"):
                print("  • Fixture con campi patched: controlli derivati esclusi (noisy, access)")
            else:
                if "noisy" in truth:
                    noisy_exp = truth.get("noisy")
                    noisy_act = bool(mq.get("noisy", False))
                    noisy_status = "PASS" if noisy_act == noisy_exp else "FAIL"
                    print(f"  • Disturbo Misura (Noisy)       : atteso {noisy_exp} => [{noisy_status}] (Rilevato: {noisy_act})")
                if "access" in truth:
                    access_exp = str(truth.get("access")).lower()
                    lan = (raw_data or {}).get("lan") or {}
                    p_iface = lan.get("primary_interface") or {}
                    access_act = str(lan.get("interface_type") or p_iface.get("interface_type") or p_iface.get("type") or "").lower()
                    access_status = "PASS" if access_exp in access_act else "FAIL"
                    print(f"  • Tipo Accesso LAN (Link Type)  : atteso '{access_exp}' => [{access_status}] (Rilevato: {access_act or 'N/D'})")
            speed = (raw_data or {}).get("performance", {}).get("speed", {})
            down_mbps = speed.get("download_mbps")
            sync_down = truth.get("sync_down_kbps")
            if sync_down and down_mbps:
                sync_down_mbps = sync_down / 1000.0
                ratio = down_mbps / sync_down_mbps
                print(f"  • Velocità Portante / Sync Down : {down_mbps:.2f} Mbps / {sync_down_mbps:.2f} Mbps (Rapporto: {ratio:.2f}x / {ratio*100:.1f}%)")
            up_mbps = speed.get("upload_mbps")
            sync_up = truth.get("sync_up_kbps")
            if sync_up and up_mbps:
                sync_up_mbps = sync_up / 1000.0
                ratio_up = up_mbps / sync_up_mbps
                print(f"  • Velocità Portante / Sync Up   : {up_mbps:.2f} Mbps / {sync_up_mbps:.2f} Mbps (Rapporto: {ratio_up:.2f}x / {ratio_up*100:.1f}%)")
        except Exception as e:
            print(f"  • Errore lettura ground truth: {e}")

    # Analisi di Ablazione opzionale
    if ablate_list:
        ablated_res = recalculate_classification(evidence, ablate_list)
        print("-" * 80)
        print(f"ANALISI DI ABLAZIONE (filtro: {', '.join(ablate_list)}):")
        print(f"  • Evidenze Rimosse ({len(ablated_res['ablated_evidence'])}):")
        for a_ev in ablated_res["ablated_evidence"]:
            print(f"    - {a_ev.get('reason')}")
        print(f"  • Mezzo Previsto Originario : {predicted} ({conf}%)")
        print(f"  • Mezzo Previsto Ablato     : {ablated_res['predicted_medium']} ({ablated_res['confidence_pct']}%)")
        print(f"  • Alternative Ablate        : {format_alternatives(ablated_res['alternatives'])}")
        print(f"  • Top-2 Media Ablati        : {[c[0] for c in ablated_res['ranked'][:2]]}")
    print()


def print_diff(file_a: str, file_b: str, res_a: Dict[str, Any], res_b: Dict[str, Any]) -> None:
    med_a = res_a.get("physical_medium", {})
    med_b = res_b.get("physical_medium", {})

    print("=" * 80)
    print(f"CONFRONTO CLASSIFICAZIONI (DIFF):")
    print(f"  [A] {file_a}")
    print(f"  [B] {file_b}")
    print("=" * 80)

    print(f"Mezzo Previsto [A] : {med_a.get('predicted_medium')}")
    print(f"Mezzo Previsto [B] : {med_b.get('predicted_medium')}")
    print(f"Confidenza [A]     : {med_a.get('confidence_pct')}%")
    print(f"Confidenza [B]     : {med_b.get('confidence_pct')}%")
    print("-" * 80)
    print(f"Alternative [A]    : {format_alternatives(med_a.get('alternatives', []))}")
    print(f"Alternative [B]    : {format_alternatives(med_b.get('alternatives', []))}")
    print("-" * 80)
    print("Delta Punteggi Totali [B - A]:")
    scores_a = med_a.get("scores_breakdown", {})
    scores_b = med_b.get("scores_breakdown", {})
    all_keys = sorted(set(scores_a.keys()).union(set(scores_b.keys())))
    for k in all_keys:
        sa = scores_a.get(k, 0.0)
        sb = scores_b.get(k, 0.0)
        delta = round(sb - sa, 1)
        sign = "+" if delta > 0 else ""
        print(f"  • {k:45s} : A={sa:5.1f} | B={sb:5.1f} | Delta={sign}{delta}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="NetProbe Estimator Offline Replay Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Percorso di uno o piu' file JSON di scansione NetProbe"
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("FILE_A", "FILE_B"),
        help="Confronta la stima del mezzo fisico tra due scansioni JSON"
    )
    parser.add_argument(
        "--ablate",
        action="append",
        default=[],
        help="Sottostringa dell'evidenza da escludere per verificare la resilienza della classificazione"
    )

    args = parser.parse_args()

    if args.diff:
        file_a, file_b = args.diff
        res_a = replay_file(file_a)
        res_b = replay_file(file_b)
        print_diff(file_a, file_b, res_a, res_b)
        return

    valid_files = [f for f in args.files if not f.endswith(".truth.json")]
    if not valid_files:
        parser.print_help()
        sys.exit(1)

    for fpath in valid_files:
        if not os.path.exists(fpath):
            print(f"Errore: file non trovato '{fpath}'", file=sys.stderr)
            continue
        res, raw_data = replay_file_with_data(fpath)
        print_single_report(fpath, res, raw_data=raw_data, ablate_list=args.ablate)


if __name__ == "__main__":
    main()
