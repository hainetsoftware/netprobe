#!/usr/bin/env python3
"""
tests/test_ixp_and_optical_generalization.py

Unit tests for multi-ISP and multi-technology generalization:
1. FTTH Open Fiber / Dimensione / Fastweb crossing MIX Milano (217.29.66.x) or NaMeX Roma (193.201.28.x) (Tier 1).
2. TIM / Vodafone / WindTre crossing Direct PNI / Transit in Milan (colo=MXP) or Rome (colo=FCO) with varying private/CGNAT hops (Tier 2).
3. Eolo FWA (AS8612) / Mobile Hotspot / Starlink (AS14593): hub identified via colo, optical routing cleanly not applicable (Tier 2 + applicability guard).
4. Inaccurate GeoIP edge case: gracefully reports "Geolocalizzazione IP imprecisa" instead of clamping to >100%.
"""

import unittest
from core.ixp_analyzer import IXPAnalyzer, build_access_profile_from_hops
from core.estimators import NetworkEstimator, IncoherentGeoReason


class TestIXPAndOpticalGeneralization(unittest.TestCase):
    def setUp(self):
        self.analyzer = IXPAnalyzer()
        self.estimator = NetworkEstimator()

    # ------------------------------------------------------------------
    # 1. FTTH Open Fiber / Dimensione / Fastweb (Tier 1: On-Wire IXP)
    # ------------------------------------------------------------------
    def test_ftth_dimensione_mix_milano_tier1(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [0.8], "rtt_ms": 0.8},
            {"hop": 2, "ip": "100.64.10.1", "rtts": [1.5], "rtt_ms": 1.5},
            {"hop": 3, "ip": "217.29.66.9", "rtts": [2.8], "rtt_ms": 2.8},
            {"hop": 4, "ip": "1.1.1.1", "rtts": [3.2], "rtt_ms": 3.2, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        wan = {
            "asn": 29119,
            "as_name": "Dimensione",
            "isp": "Dimensione S.r.l.",
            "city": "Milano",
            "coordinates": {"latitude": 45.4642, "longitude": 9.1900}
        }
        res = self.analyzer.reclassify_offline(wan, hops, target="1.1.1.1")
        self.assertEqual(res["detected_ixp"], "MIX - Milan Internet eXchange")
        self.assertEqual(res["peering_type"], "Public IXP Peering (Fabric di Interscambio)")
        self.assertEqual(res["matched_hop_ip"], "217.29.66.9")
        self.assertEqual(res["matched_subnet"], "217.29.66.0/23")
        self.assertEqual(res["confidence"], "100% (Verificato on-wire)")

        # Verify role notes in access profile
        prof_hops = res["access_profile"]["hops"]
        self.assertEqual(prof_hops[0]["role"], "Gateway locale")
        self.assertEqual(prof_hops[1]["role"], "Primo salto oltre il CPE")
        self.assertIn("CGNAT", prof_hops[1]["role_note"])
        self.assertEqual(prof_hops[2]["role"], "LAN Peering IXP")
        self.assertIn("MIX - Milan Internet eXchange", prof_hops[2]["role_note"])
        self.assertEqual(prof_hops[3]["role"], "Destinazione")

        # Verify optical routing estimation
        perf = {"primary_latency": {"min_ms": 3.2}, "gateway_latency": {"min_ms": 0.8}}
        opt = self.estimator.estimate_optical_routing(wan, perf, res, medium_name="FTTH (Fibra Ottica Pura GPON / XGS-PON)")
        self.assertEqual(opt["nearest_ixp_name"], "MIX - Milan Internet eXchange")

    def test_ftth_namex_roma_tier1(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [0.6], "rtt_ms": 0.6},
            {"hop": 2, "ip": "193.201.28.11", "rtts": [2.4], "rtt_ms": 2.4},
            {"hop": 3, "ip": "1.1.1.1", "rtts": [2.9], "rtt_ms": 2.9, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        wan = {
            "asn": 12874,
            "as_name": "Fastweb",
            "city": "Roma",
            "coordinates": {"latitude": 41.8988, "longitude": 12.5186}
        }
        res = self.analyzer.reclassify_offline(wan, hops, target="1.1.1.1")
        self.assertEqual(res["detected_ixp"], "NAMEX - Nautilus Mediterranean eXchange")
        self.assertEqual(res["peering_type"], "Public IXP Peering (Fabric di Interscambio)")
        self.assertEqual(res["matched_hop_ip"], "193.201.28.11")

    # ------------------------------------------------------------------
    # 2. TIM / Vodafone / WindTre (Tier 2: Verified Direct PNI / Transit)
    # ------------------------------------------------------------------
    def test_tim_fttc_sparkle_direct_pni_milano(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [1.1], "rtt_ms": 1.1},
            {"hop": 2, "ip": "*", "rtts": [], "rtt_ms": None},
            {"hop": 3, "ip": "172.18.34.130", "rtts": [5.8], "rtt_ms": 5.8},
            {"hop": 4, "ip": "172.18.33.230", "rtts": [6.1], "rtt_ms": 6.1},
            {"hop": 5, "ip": "195.22.205.116", "rtts": [10.5], "rtt_ms": 10.5, "asn": 6762, "asn_name": "Sparkle"},
            {"hop": 6, "ip": "195.22.212.33", "rtts": [11.2], "rtt_ms": 11.2, "asn": 6762, "asn_name": "Sparkle"},
            {"hop": 7, "ip": "188.114.100.31", "rtts": [12.1], "rtt_ms": 12.1, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        wan = {
            "asn": 3269,
            "as_name": "Telecom Italia",
            "city": "Bologna",
            "coordinates": {"latitude": 44.4949, "longitude": 11.3426}
        }
        res = self.analyzer.reclassify_offline(wan, hops, anycast_colo="MXP", target="1.1.1.1")
        self.assertIn("Milano (Hub Caldera / MIX)", res["detected_ixp"])
        self.assertEqual(res["ixp_city"], "Milano")
        self.assertEqual(res["peering_type"], "Direct PNI / Transit Handoff")
        self.assertEqual(res["confidence"], "85% (Verificato da Anycast PoP + AS-Boundary)")
        # Dynamic egress selection: must be hop 6 (195.22.212.33), the last public hop before AS13335
        self.assertEqual(res["matched_hop_ip"], "195.22.212.33")
        self.assertEqual(res["rtt_to_ixp_ms"], 11.2)

        # Dynamic optical routing estimation
        perf = {"primary_latency": {"min_ms": 12.1}, "gateway_latency": {"min_ms": 1.1}}
        opt = self.estimator.estimate_optical_routing(wan, perf, res, medium_name="FTTC / VDSL2 (Fibra Misto Rame)")
        self.assertTrue(opt["applicable"])
        self.assertIn("Milano (Hub Caldera / MIX)", opt["nearest_ixp_name"])
        # Access hop is dynamically separated (Hop 3: 5.8 ms)
        self.assertEqual(opt["calculation_basis"], "Solo tratta di trasporto (isolato nodo di accesso locale)")
        self.assertEqual(opt["local_access_hop_ms"], 5.8)
        self.assertAlmostEqual(opt["optical_backhaul_rtt_ms"], 11.2 - 5.8, places=1)
        self.assertIsNotNone(opt["routing_efficiency_pct"])
        self.assertGreater(opt["routing_efficiency_pct"], 0.0)
        self.assertLessEqual(opt["routing_efficiency_pct"], 100.0)

    def test_vodafone_direct_pni_roma_fco(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [1.0], "rtt_ms": 1.0},
            {"hop": 2, "ip": "100.64.0.1", "rtts": [8.2], "rtt_ms": 8.2},
            {"hop": 3, "ip": "83.224.40.1", "rtts": [12.0], "rtt_ms": 12.0, "asn": 30722, "asn_name": "Vodafone Italia"},
            {"hop": 4, "ip": "188.114.100.1", "rtts": [12.8], "rtt_ms": 12.8, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        wan = {
            "asn": 30722,
            "as_name": "Vodafone Italia",
            "city": "Napoli",
            "coordinates": {"latitude": 40.8518, "longitude": 14.2681}
        }
        res = self.analyzer.reclassify_offline(wan, hops, anycast_colo="FCO", target="1.1.1.1")
        self.assertIn("Roma (Hub NaMeX / Tiburtina)", res["detected_ixp"])
        self.assertEqual(res["ixp_city"], "Roma")
        self.assertEqual(res["matched_hop_ip"], "83.224.40.1")

    # ------------------------------------------------------------------
    # 3. Radio / Wireless / Satellite (Applicability Guard)
    # ------------------------------------------------------------------
    def test_eolo_fwa_applicability_guard(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [2.0], "rtt_ms": 2.0},
            {"hop": 2, "ip": "88.149.128.1", "rtts": [14.5], "rtt_ms": 14.5, "asn": 8612, "asn_name": "Eolo"},
            {"hop": 3, "ip": "1.1.1.1", "rtts": [16.0], "rtt_ms": 16.0, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        wan = {
            "asn": 8612,
            "as_name": "Eolo SpA",
            "city": "Varese",
            "coordinates": {"latitude": 45.8206, "longitude": 8.8251}
        }
        res = self.analyzer.reclassify_offline(wan, hops, anycast_colo="MXP")
        self.assertIn("Milano", res["detected_ixp"])

        # Optical routing must cleanly report applicable = False for FWA
        opt = self.estimator.estimate_optical_routing(
            wan, {"primary_latency": {"min_ms": 16.0}}, res, medium_name="FWA (Fixed Wireless Access / Eolo / Linkem)"
        )
        self.assertFalse(opt["applicable"])
        self.assertIsNone(opt["routing_efficiency_pct"])
        self.assertEqual(opt["not_applicable_reason"],
                         "Non applicabile su collegamenti mobili o con latenza di accesso instabile/radio")

    def test_starlink_satellite_applicability_guard(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [1.5], "rtt_ms": 1.5},
            {"hop": 2, "ip": "145.224.0.1", "rtts": [32.0], "rtt_ms": 32.0, "asn": 14593, "asn_name": "Starlink"},
            {"hop": 3, "ip": "1.1.1.1", "rtts": [34.5], "rtt_ms": 34.5, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        wan = {
            "asn": 14593,
            "as_name": "Starlink",
            "isp": "Starlink",
            "city": "Milano",
            "coordinates": {"latitude": 45.4642, "longitude": 9.1900}
        }
        res = self.analyzer.reclassify_offline(wan, hops, anycast_colo="MXP")
        self.assertEqual(res["detected_ixp"], "Starlink Ground Station / POP (Milano)")
        self.assertEqual(res["peering_type"], "Interconnessione Starlink Satellite Ground Station")

        opt = self.estimator.estimate_optical_routing(
            wan, {"primary_latency": {"min_ms": 34.5}}, res, medium_name="Satellite LEO (Starlink Bassa Orbita)"
        )
        self.assertFalse(opt["applicable"])
        self.assertIsNone(opt["routing_efficiency_pct"])
        self.assertEqual(opt["not_applicable_reason"],
                         "Non applicabile su collegamenti mobili o con latenza di accesso instabile/radio")

    def test_mobile_hotspot_applicability_guard(self):
        wan = {"asn": 1267, "city": "Milano", "coordinates": {"latitude": 45.46, "longitude": 9.19}}
        opt = self.estimator.estimate_optical_routing(
            wan, {"primary_latency": {"min_ms": 42.0}}, None, medium_name="Mobile Cellular (4G LTE / 5G Mobile Hotspot)"
        )
        self.assertFalse(opt["applicable"])
        self.assertEqual(opt["not_applicable_reason"],
                         "Non applicabile su collegamenti mobili o con latenza di accesso instabile/radio")

    # ------------------------------------------------------------------
    # 4. Inaccurate GeoIP Edge Case
    # ------------------------------------------------------------------
    def test_inaccurate_geoip_reported_cleanly(self):
        # User GeoIP falsely placed in Palermo (lat 38.11, lon 13.36), but actually in Milan
        # Hub is in Milan (~880 km away, theoretical optical floor ~11.8 ms), but measured RTT is only 3.5 ms
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [0.8], "rtt_ms": 0.8},
            {"hop": 2, "ip": "195.22.212.33", "rtts": [3.5], "rtt_ms": 3.5, "asn": 6762, "asn_name": "Sparkle"},
            {"hop": 3, "ip": "1.1.1.1", "rtts": [3.9], "rtt_ms": 3.9, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        wan = {
            "asn": 3269,
            "city": "Palermo",
            "coordinates": {"latitude": 38.1157, "longitude": 13.3615}
        }
        res = self.analyzer.reclassify_offline(wan, hops, anycast_colo="MXP")
        self.assertEqual(res["ixp_city"], "Milano")

        perf = {"primary_latency": {"min_ms": 3.9}, "gateway_latency": {"min_ms": 0.8}}
        opt = self.estimator.estimate_optical_routing(wan, perf, res, medium_name="FTTH (Fibra Ottica Pura GPON / XGS-PON)")
        # Must report inapplicable due to inaccurate GeoIP instead of clamping to >100%
        self.assertFalse(opt["applicable"])
        self.assertIsNone(opt["routing_efficiency_pct"])
        self.assertTrue("Geolocalizzazione IP imprecisa" in opt["not_applicable_reason"] or "premessa geografica incoerente" in opt["not_applicable_reason"])


if __name__ == "__main__":
    unittest.main()
