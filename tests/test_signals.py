import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.estimators import NetworkEstimator
from core.ixp_analyzer import IXPAnalyzer

FTTH = "FTTH (Fibra Ottica Pura GPON / XGS-PON)"
FTTC = "FTTC / VDSL2 (Fibra Misto Rame)"
DOCSIS = "DOCSIS (Cavo Coassiale HFC)"
GEO = "Satellite GEO (Geostazionario Tradizionale)"


def _reasons(res):
    return " ".join(res["rationale"])


class TestNewSignals(unittest.TestCase):
    def setUp(self):
        self.est = NetworkEstimator()

    # --- GEO ---
    def test_geo_floor_strong(self):
        ixp = {"hop2_bng": {"ip": "93.1.1.1", "min_ms": 560.0, "median_ms": 600.0, "jitter_ms": 20.0,
                            "samples_count": 30, "is_responsive": True}}
        res = self.est.estimate_physical_medium({}, {}, {"primary_latency": {"min_ms": 580.0, "samples_count": 6}}, ixp)
        self.assertIn("GEO", res["predicted_medium"])
        self.assertIn("geostazionario", _reasons(res))

    def test_geo_no_claim_with_single_sample(self):
        res = self.est.estimate_physical_medium({}, {}, {"primary_latency": {"min_ms": 600.0, "samples_count": 1}})
        self.assertEqual(res["scores_breakdown"][GEO], 0.0)

    def test_geo_not_triggered_by_terrestrial_rtt(self):
        res = self.est.estimate_physical_medium({}, {}, {"primary_latency": {"min_ms": 300.0, "samples_count": 6}})
        self.assertEqual(res["scores_breakdown"][GEO], 0.0)

    # --- Asimmetria ---
    def test_symmetric_favors_ftth(self):
        res = self.est.estimate_physical_medium({}, {}, {"speed": {"download_mbps": 900.0, "upload_mbps": 800.0}})
        self.assertGreater(res["scores_breakdown"][FTTH], 0.0)
        self.assertIn("Asimmetria", _reasons(res))

    def test_strong_asymmetry_weak_docsis(self):
        res = self.est.estimate_physical_medium({}, {}, {"speed": {"download_mbps": 300.0, "upload_mbps": 10.0}})
        self.assertGreater(res["scores_breakdown"][DOCSIS], 0.0)
        self.assertIn("Asimmetria", _reasons(res))

    def test_asymmetry_no_claim_without_upload(self):
        res = self.est.estimate_physical_medium({}, {}, {"speed": {"download_mbps": 300.0, "upload_mbps": None}})
        self.assertNotIn("Asimmetria", _reasons(res))

    # --- Delta idle vs loaded ---
    def test_loaded_delta_large_is_radio_or_shared(self):
        perf = {"primary_latency": {"median_ms": 30.0},
                "speed": {"download_mbps": 40.0, "upload_mbps": 10.0},
                "bufferbloat": {"download_delta_ms": 120.0, "upload_delta_ms": 20.0}}
        res = self.est.estimate_physical_medium({}, {}, perf)
        self.assertIn("Delta latenza", _reasons(res))
        self.assertGreater(res["scores_breakdown"]["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"], 0.0)

    def test_loaded_delta_zero_is_no_claim(self):
        perf = {"primary_latency": {"median_ms": 30.0},
                "speed": {"download_mbps": 40.0, "upload_mbps": 10.0},
                "bufferbloat": {"download_delta_ms": 0.0, "upload_delta_ms": 0.0}}
        res = self.est.estimate_physical_medium({}, {}, perf)
        self.assertNotIn("Delta latenza", _reasons(res))

    def test_upload_bufferbloat_signal(self):
        perf = {"primary_latency": {"median_ms": 20.0},
                "speed": {"download_mbps": 100.0, "upload_mbps": 10.0},
                "bufferbloat": {"download_delta_ms": 10.0, "upload_delta_ms": 90.0}}
        res = self.est.estimate_physical_medium({}, {}, perf)
        self.assertIn("upload", _reasons(res))

    # --- DOCSIS mai classificazione dura ---
    # --- DOCSIS mai classificazione dura ---
    def test_docsis_never_wins_primary_without_enough_evidence(self):
        wan = {"asn": "AS7922", "isp": "Comcast Cable", "nat": {}}
        perf = {"primary_latency": {"min_ms": 12.0, "median_ms": 17.0, "jitter_ms": 3.0, "samples_count": 6},
                "speed": {"download_mbps": 300.0, "upload_mbps": 12.0},
                "bufferbloat": {"download_delta_ms": 90.0, "upload_delta_ms": 150.0}}
        res = self.est.estimate_physical_medium({}, wan, perf)
        # Sotto la soglia di 30 punti non puo' essere il primario
        self.assertNotIn("DOCSIS", res["predicted_medium"])
        self.assertGreater(res["scores_breakdown"][DOCSIS], 0.0)

    def test_docsis_strong_secondary_in_alternatives(self):
        # Profilo dove FTTH e' primario ma DOCSIS riceve punteggio come forte secondario (alternatives)
        wan = {"asn": "AS7922", "isp": "Comcast Cable", "nat": {}}
        perf = {"primary_latency": {"min_ms": 2.0, "median_ms": 3.0, "jitter_ms": 0.5, "samples_count": 20},
                "speed": {"download_mbps": 300.0, "upload_mbps": 15.0},
                "bufferbloat": {"download_delta_ms": 85.0, "upload_delta_ms": 140.0}}
        res = self.est.estimate_physical_medium({}, wan, perf)
        self.assertIn("FTTH", res["predicted_medium"])
        alt_names = [a["medium"] for a in res.get("alternatives", [])]
        self.assertIn(DOCSIS, alt_names)
        docsis_alt = next(a for a in res["alternatives"] if a["medium"] == DOCSIS)
        self.assertGreater(docsis_alt["score"], 10.0)
        self.assertGreater(docsis_alt["confidence_share_pct"], 0.0)

    def test_geo_vpn_skipped(self):
        # Con VPN/proxy attivo, il pavimento GEO (RTT >= 470ms) non deve scattare
        wan = {"privacy_and_routing": {"is_vpn_or_proxy": True}}
        ixp = {"hop2_bng": {"ip": "93.1.1.1", "min_ms": 560.0, "median_ms": 600.0, "jitter_ms": 20.0,
                            "samples_count": 30, "is_responsive": True}}
        res = self.est.estimate_physical_medium({}, wan, {"primary_latency": {"min_ms": 580.0, "samples_count": 6}}, ixp)
        self.assertEqual(res["scores_breakdown"][GEO], 0.0)
        self.assertNotIn("geostazionario", _reasons(res))

    def test_rtt_shape_no_claim_with_few_samples(self):
        perf = {"primary_latency": {"min_ms": 12.0, "median_ms": 17.0, "jitter_ms": 3.0, "samples_count": 3}}
        res = self.est.estimate_physical_medium({}, {}, perf)
        self.assertNotIn("request-grant", _reasons(res))

    # --- Path MTU nello stimatore ---
    def test_path_mtu_1492_signal(self):
        res = self.est.estimate_physical_medium({}, {}, {}, {"path_mtu": 1492})
        self.assertGreater(res["scores_breakdown"][FTTC], 0.0)
        self.assertIn("PPPoE", _reasons(res))

    def test_path_mtu_none_no_claim(self):
        res = self.est.estimate_physical_medium({}, {}, {}, {"path_mtu": None})
        self.assertNotIn("Path MTU", _reasons(res))


class TestHop2Selection(unittest.TestCase):
    def setUp(self):
        self.a = IXPAnalyzer()

    def _hops(self, *ips):
        return [{"hop": i + 1, "ip": ip, "rtt_ms": 5.0, "rdns": None} for i, ip in enumerate(ips)]

    def test_selects_cgnat_hop(self):
        # Part 1.1: hop list [192.168.1.1, 100.110.147.129, 188.114.100.5] must select 100.110.147.129 and tag cgnat_hop: true
        hops = self._hops("192.168.1.1", "100.110.147.129", "188.114.100.5")
        with mock.patch.object(IXPAnalyzer, "_ping_burst", return_value=([25.0 + 0.1 * i for i in range(30)], 30)) as pb:
            ip, m = self.a._probe_hop2_bng(hops)
        self.assertEqual(ip, "100.110.147.129")
        self.assertTrue(m["cgnat_hop"])
        self.assertTrue(m["is_responsive"])
        self.assertEqual(m["samples_count"], 30)

    def test_skips_rfc1918_and_silent(self):
        hops = self._hops("192.168.1.1", "10.0.0.1", "172.16.5.1", "*", "93.57.1.1")
        with mock.patch.object(IXPAnalyzer, "_ping_burst", return_value=([5.0 + 0.1 * i for i in range(30)], 30)) as pb:
            ip, m = self.a._probe_hop2_bng(hops)
        self.assertEqual(ip, "93.57.1.1")
        self.assertFalse(m["cgnat_hop"])
        self.assertEqual(pb.call_args[0][1], 30)
        self.assertIn("10.0.0.1", m["skipped_hops"])
        self.assertIn("172.16.5.1", m["skipped_hops"])
        self.assertEqual(m["samples_count"], 30)
        self.assertLessEqual(m["min_ms"], m["median_ms"])
        self.assertLessEqual(m["median_ms"], m["p95_ms"])

    def test_all_private_returns_none(self):
        hops = self._hops("192.168.1.1", "10.0.0.1", "172.16.0.1")
        with mock.patch.object(IXPAnalyzer, "_ping_burst", return_value=([], 0)) as pb:
            ip, m = self.a._probe_hop2_bng(hops)
        self.assertIsNone(ip)
        self.assertFalse(m["is_responsive"])
        pb.assert_not_called()

    def test_non_responding_public_hop_skipped(self):
        hops = self._hops("192.168.1.1", "93.57.1.1", "93.57.2.2")
        ok = ([4.0 + 0.1 * i for i in range(30)], 30)
        with mock.patch.object(IXPAnalyzer, "_ping_burst", side_effect=[([], 30), ok]):
            ip, m = self.a._probe_hop2_bng(hops)
        self.assertEqual(ip, "93.57.2.2")
        self.assertIn("93.57.1.1", m["skipped_hops"])

    def test_no_responsive_hop_returns_none_and_estimator_copes(self):
        hops = self._hops("192.168.1.1", "93.57.1.1")
        with mock.patch.object(IXPAnalyzer, "_ping_burst", return_value=([4.0, 4.1], 30)):
            ip, _ = self.a._probe_hop2_bng(hops)
        self.assertIsNone(ip)
        res = NetworkEstimator().estimate_physical_medium({}, {}, {}, {"hop2_bng": None})
        self.assertTrue(res["insufficient_data"])

    def test_p95_nearest_rank(self):
        hops = self._hops("192.168.1.1", "93.57.1.1")
        times = [float(i) for i in range(1, 21)]  # n=20 -> ceil(19)=19 -> indice 18 -> 19.0
        with mock.patch.object(IXPAnalyzer, "_ping_burst", return_value=(times, 20)):
            _, m = self.a._probe_hop2_bng(hops)
        self.assertEqual(m["p95_ms"], 19.0)


class TestPathMtuProbe(unittest.TestCase):
    def setUp(self):
        self.a = IXPAnalyzer()

    def _fake(self, path_mtu):
        def f(host, payload, timeout_s=2.0):
            return ("ok", None) if payload + 28 <= path_mtu else ("big", None)
        return f

    def test_finds_exact_mtu(self):
        for m in (1500, 1492, 1480, 1428, 1360, 1280):
            with mock.patch.object(IXPAnalyzer, "_ping_df", side_effect=self._fake(m)):
                self.assertEqual(self.a.probe_path_mtu(), m, m)

    def test_filtered_icmp_returns_none(self):
        with mock.patch.object(IXPAnalyzer, "_ping_df", return_value=("timeout", None)):
            self.assertIsNone(self.a.probe_path_mtu())

    def test_unsupported_df_returns_none(self):
        with mock.patch.object(IXPAnalyzer, "_ping_df", return_value=(None, None)):
            self.assertIsNone(self.a.probe_path_mtu())

    def test_below_minimum_returns_none(self):
        with mock.patch.object(IXPAnalyzer, "_ping_df", side_effect=self._fake(1200)):
            self.assertIsNone(self.a.probe_path_mtu())

    def test_router_hint_used(self):
        calls = []

        def f(host, payload, timeout_s=2.0):
            calls.append(payload)
            return ("ok", None) if payload + 28 <= 1492 else ("big", 1492)
        with mock.patch.object(IXPAnalyzer, "_ping_df", side_effect=f):
            self.assertEqual(self.a.probe_path_mtu(), 1492)


if __name__ == "__main__":
    unittest.main()
