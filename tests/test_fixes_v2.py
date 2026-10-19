import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.estimators import NetworkEstimator
from core.ixp_analyzer import IXPAnalyzer
from cli.terminal_ui import TerminalUI
from tools.replay import (
    replay_file,
    replay_file_with_data,
    recalculate_classification,
    find_truth_file,
    print_single_report,
    main as replay_main,
)


class TestFixesV2(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.fttc_file = os.path.join(self.fixtures_dir, "real_wifi_fttc.anon.json")
        self.wind3_file = os.path.join(self.fixtures_dir, "real_hotspot_wind3.json")
        self.est = NetworkEstimator()
        self.ixp = IXPAnalyzer()

    # 1. Routing efficiency (core/estimators.py)
    def test_item1_routing_efficiency_incoherent_fttc(self):
        res = replay_file(self.fttc_file)
        opt = res["optical_routing"]
        self.assertIsNone(opt["routing_efficiency_pct"])
        self.assertFalse(opt["applicable"])
        self.assertEqual(opt["not_applicable_reason"], "premessa geografica incoerente")
        self.assertIsNone(opt["switching_and_queuing_delay_ms"])
        self.assertEqual(opt["detour_rating"], "Non applicabile")

    # 2. IXP identification (core/ixp_analyzer.py)
    def test_item2_ixp_identification_no_bogus_peering(self):
        with open(self.fttc_file, "r", encoding="utf-8") as f:
            fttc_data = json.load(f)
        with open(self.wind3_file, "r", encoding="utf-8") as f:
            wind3_data = json.load(f)

        fttc_hops = fttc_data.get("ixp", {}).get("traceroute_hops", [])
        wind3_hops = wind3_data.get("ixp", {}).get("traceroute_hops", [])

        # Nessun hop reale nelle fixture deve matchare una peering LAN o rDNS IXP
        ixp_match_1, ev_1 = self.ixp._find_ixp_in_hops(fttc_hops)
        self.assertIsNone(ixp_match_1)
        self.assertIsNone(ev_1)

        ixp_match_2, ev_2 = self.ixp._find_ixp_in_hops(wind3_hops)
        self.assertIsNone(ixp_match_2)
        self.assertIsNone(ev_2)

        # Fallback ipotetico etichettato come ipotesi con confidenza <= 40 e matched_hop_ip None
        fallback = self.ixp._classify_exchange(
            matched_ixp=None,
            match_evidence=None,
            hops=fttc_hops,
            peeringdb_info={},
            wan_data=fttc_data.get("wan", {}),
            hop2_metrics={}
        )
        self.assertIn("ipotesi", fallback["confidence"].lower())
        self.assertIn("ipotesi", fallback["peering_type"].lower())
        self.assertIsNone(fallback["matched_hop_ip"])
        self.assertIsNone(fallback["rtt_to_ixp_ms"])

        # Quando passato all'estimatore senza verified IXP, non calcola distanza né floor
        opt = self.est.estimate_optical_routing(fttc_data.get("wan", {}), fttc_data.get("performance", {}), fallback)
        self.assertIsNone(opt["straight_line_distance_km"])
        self.assertIsNone(opt["theoretical_optical_min_rtt_ms"])
        self.assertIsNone(opt["routing_efficiency_pct"])
        self.assertFalse(opt["applicable"])

    # 3. Access delta (core/estimators.py)
    def test_item3_access_delta(self):
        perf = {
            "gateway_latency": {"min_ms": 3.1, "jitter_ms": 0.5},
            "primary_latency": {"min_ms": 13.0, "jitter_ms": 0.9}
        }
        ixp_data = {
            "hop2_bng": {
                "ip": "100.110.147.129",
                "min_ms": 12.21,
                "median_ms": 13.0,
                "jitter_ms": 0.92,
                "is_responsive": True
            }
        }
        res = self.est.estimate_physical_medium({}, {}, perf, ixp_data)
        bng = res["bng_hop"]
        self.assertEqual(bng["access_delta_ms"], 9.11)
        self.assertEqual(res["access_delta_ms"], 9.11)
        self.assertTrue(any("delta netto gateway: 9.11 ms" in r for r in res["rationale"]))

        # Senza gateway_latency usa hop2_min come fallback senza crash
        res_no_gw = self.est.estimate_physical_medium({}, {}, {"primary_latency": {"min_ms": 13.0}}, ixp_data)
        self.assertEqual(res_no_gw["bng_hop"]["access_delta_ms"], 12.21)

    # 4. Replay ablation (tools/replay.py)
    def test_item4_replay_ablation_wind3(self):
        res, _ = replay_file_with_data(self.wind3_file)
        ev = res["physical_medium"]["evidence"]
        ablated = recalculate_classification(ev, ablate_list=["172.20.10.1"])
        top2 = [c[0] for c in ablated["ranked"][:2]]
        self.assertIn("Mobile Cellular", top2[0])
        self.assertIn("FWA", top2[1])
        for cand in top2:
            self.assertNotIn("FTTH", cand)
            self.assertNotIn("FTTC", cand)

    # 5. LEO dispersion rule requires marker
    def test_item5_leo_requires_marker(self):
        # RTT 30 ms con jitter e spread tipici ma operatore generico (nessun marker Starlink)
        perf = {
            "primary_latency": {"min_ms": 25.0, "median_ms": 35.0, "jitter_ms": 4.0, "samples_count": 10}
        }
        wan_generic = {"asn": "AS1267", "isp": "Wind Tre SpA", "nat": {}}
        res_generic = self.est.estimate_physical_medium({}, wan_generic, perf)
        self.assertEqual(res_generic["scores_breakdown"]["Satellite LEO (Starlink Bassa Orbita)"], 0.0)

        # Stesso RTT ma con marker Starlink
        wan_starlink = {"asn": "AS14593", "isp": "Starlink", "nat": {}}
        res_starlink = self.est.estimate_physical_medium({}, wan_starlink, perf)
        self.assertGreaterEqual(res_starlink["scores_breakdown"]["Satellite LEO (Starlink Bassa Orbita)"], 95.0)

    # 6. Alternatives shares normalization: sum to 100
    def test_item6_alternatives_shares_sum_100(self):
        for fpath in (self.fttc_file, self.wind3_file):
            res = replay_file(fpath)
            med = res["physical_medium"]
            conf = med["confidence_pct"]
            alts_sum = sum(a["confidence_share_pct"] for a in med.get("alternatives", []))
            rem = med.get("remainder_share_pct", 0.0)
            total = round(conf + alts_sum + rem, 1)
            self.assertEqual(total, 100.0, f"Sum was {total} for {fpath}")

    # 7. Suitability and loaded MOS
    def test_item7_suitability_and_loaded_mos(self):
        res_wind3 = replay_file(self.wind3_file)
        # Hotspot Wind3: upload 1.93 Mbps, bufferbloat D
        work_wind3 = res_wind3["application_suitability"]["video_conferencing"]
        self.assertIn(work_wind3["status"], ("SUFFICIENTE", "LIMITATO"))
        self.assertLess(work_wind3["score"], 80)
        self.assertIsNotNone(res_wind3["voice_quality_mos"]["loaded_mos_score"])

        res_fttc = replay_file(self.fttc_file)
        # FTTC: upload 14.4 Mbps, bufferbloat C
        work_fttc = res_fttc["application_suitability"]["video_conferencing"]
        self.assertIn(work_fttc["status"], ("IMPECCABILE", "OTTIMO"))
        self.assertGreaterEqual(work_fttc["score"], 80)

    # 8. Labels: CGNAT on mobile and hidden SSID
    def test_item8_labels_cgnat_and_ssid(self):
        # Hidden SSID
        data_hidden = {
            "lan": {"wifi": {"connected": True, "ssid_hidden_by_os": True}, "primary_interface": {"type": "Wi-Fi"}},
            "wan": {"public_ipv4": "1.2.3.4", "nat": {"cgnat_detected": False}},
            "performance": {},
            "estimations": {"physical_medium": {"predicted_medium": "FTTH"}}
        }
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TerminalUI(no_color=True).render_full_report(data_hidden)
        out = buf.getvalue()
        self.assertIn("Nascosto dal sistema (serve il permesso Posizione)", out)

        # Mobile connection -> CGNAT non rilevabile
        data_mobile = {
            "lan": {},
            "wan": {"public_ipv4": "1.2.3.4", "nat": {"cgnat_detected": False}},
            "performance": {},
            "estimations": {"physical_medium": {"predicted_medium": "Mobile Cellular (4G LTE / 5G)"}}
        }
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            TerminalUI(no_color=True).render_full_report(data_mobile)
        out2 = buf2.getvalue()
        self.assertIn("non rilevabile (su rete mobile il CGNAT è probabile)", out2)

    # 9. Ground Truth validation in replay
    def test_item9_ground_truth_and_sync(self):
        truth_fttc = find_truth_file(self.fttc_file)
        self.assertIsNotNone(truth_fttc)
        self.assertTrue(os.path.exists(truth_fttc))

        truth_wind3 = find_truth_file(self.wind3_file)
        self.assertIsNotNone(truth_wind3)
        self.assertTrue(os.path.exists(truth_wind3))

        buf = io.StringIO()
        res_fttc, raw_fttc = replay_file_with_data(self.fttc_file)
        with contextlib.redirect_stdout(buf):
            print_single_report(self.fttc_file, res_fttc, raw_data=raw_fttc)
        out = buf.getvalue()
        self.assertIn("[PASS]", out)
        self.assertIn("0.93x", out)

    # 10. No interleaving claims and BNG label rename
    def test_item10_no_interleaving_and_bng_rename(self):
        res = replay_file(self.fttc_file)
        for ev in res["physical_medium"]["evidence"]:
            self.assertNotIn("interleaving", ev["reason"].lower())
            self.assertNotIn("framing vdsl2", ev["reason"].lower())

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TerminalUI(no_color=True).render_full_report(
                {"lan": {}, "wan": {}, "performance": {}, "estimations": res, "ixp": {}}
            )
        out = buf.getvalue()
        self.assertTrue(
            ("Primo salto pubblico responsivo" in out) or ("Primo Salto Operatore (hop responsivo)" in out),
            "Attesa etichetta relabeled per hop2_bng nel report terminale"
        )
        self.assertNotIn("BNG Hop 2", out)

    # 11. Italy-aware FTTC veto
    def test_item11_italy_aware_fttc_veto(self):
        # In Italia: upload > 21 Mbps deve escludere FTTC
        wan_it = {"country_code": "IT", "nat": {}}
        perf_it = {"speed": {"download_mbps": 100.0, "upload_mbps": 25.0}}
        res_it = self.est.estimate_physical_medium({}, wan_it, perf_it)
        self.assertEqual(res_it["scores_breakdown"]["FTTC / VDSL2 (Fibra Misto Rame)"], 0.0)
        self.assertTrue(any("20 Mbps" in r for r in res_it["rationale"]))

        # Fuori Italia (es. Germania): upload 25 Mbps è valido su VDSL2 35b
        wan_de = {"country_code": "DE", "isp": "Deutsche Telekom", "nat": {}}
        ixp_de = {"hop2_bng": {"ip": "194.25.0.1", "min_ms": 8.0, "jitter_ms": 0.8, "is_responsive": True}}
        perf_de = {"speed": {"download_mbps": 100.0, "upload_mbps": 25.0}}
        res_de = self.est.estimate_physical_medium({}, wan_de, perf_de, ixp_de)
        self.assertGreater(res_de["scores_breakdown"]["FTTC / VDSL2 (Fibra Misto Rame)"], 0.0)

        # Upload > 35.5 Mbps escluso ovunque
        perf_high = {"speed": {"download_mbps": 100.0, "upload_mbps": 40.0}}
        res_de_high = self.est.estimate_physical_medium({}, wan_de, perf_high, ixp_de)
        self.assertEqual(res_de_high["scores_breakdown"]["FTTC / VDSL2 (Fibra Misto Rame)"], 0.0)

    # 12. Asymmetry signal weights and rationale
    def test_item12_asymmetry_weights(self):
        # Asimmetria elevata >= 8:1 (es. 160 / 10 Mbps)
        perf = {"speed": {"download_mbps": 160.0, "upload_mbps": 10.0}}
        wan = {"country_code": "DE", "nat": {}}
        res = self.est.estimate_physical_medium({}, wan, perf)
        ev_asym = [e for e in res["evidence"] if "Asimmetria D/U" in e["reason"]]
        self.assertTrue(len(ev_asym) > 0)
        contribs = ev_asym[0]["contributions"]
        # Contributo token <= 2.0
        self.assertLessEqual(contribs.get("FTTC / VDSL2 (Fibra Misto Rame)", 0.0), 2.0)
        self.assertLessEqual(contribs.get("DOCSIS (Cavo Coassiale HFC)", 0.0), 2.0)
        # Non deve affermare che il rapporto >= 8 è tipico di VDSL
        self.assertNotIn("tipica di vdsl", ev_asym[0]["reason"].lower())


if __name__ == "__main__":
    unittest.main()
