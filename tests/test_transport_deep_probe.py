#!/usr/bin/env python3
"""
Unit tests for Advanced Internet Backhaul, Edge Datacenter & IXP Deep Reconstruction.
Covers:
1. Mocked parallel traceroute parsing with multi-target path merging and divergence pinpointing.
2. Deep rDNS token extraction and grammar parsing for Sparkle, Fastweb, TIM, WindTre, Vodafone, Open Fiber, GARR, and Tier-1 transits.
3. Datacenter facility resolution and coordinates mapping (Milano, Roma, and Regional hubs).
4. Multi-CDN Edge PoP inspection (Cloudflare, Fastly, AWS CloudFront).
5. Offline fixture replay for real_ethernet_school.json and real_wifi_fttc.json.
6. Optical routing recalibration against verified colocation campus coordinates and backhaul isolation.
"""

import json
import os
import unittest
from unittest.mock import patch, MagicMock

from core.ixp_analyzer import (
    IXPAnalyzer,
    parse_rdns_metro_and_role,
    resolve_datacenter_facility,
    probe_multi_cdn_pops,
    merge_multi_target_paths,
    build_topological_flow,
    DATACENTER_FACILITIES
)
from core.estimators import NetworkEstimator


class TestTransportDeepProbe(unittest.TestCase):
    def setUp(self):
        self.analyzer = IXPAnalyzer()
        self.estimator = NetworkEstimator()
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")

    # =========================================================================
    # 1. Deep rDNS Grammar & Metro-Node Parser
    # =========================================================================
    def test_rdns_sparkle_seabone(self):
        # Sparkle Seabone Milan core router
        res_mil = parse_rdns_metro_and_role("mil52-cr01.seabone.net")
        self.assertEqual(res_mil["carrier"], "Telecom Italia Sparkle")
        self.assertEqual(res_mil["metro_code"], "MXP")
        self.assertEqual(res_mil["city"], "Milano")
        self.assertEqual(res_mil["node_role"], "Core Router")

        # Sparkle Seabone Palermo provider edge
        res_pal = parse_rdns_metro_and_role("pal-pe02.seabone.net")
        self.assertEqual(res_pal["carrier"], "Telecom Italia Sparkle")
        self.assertEqual(res_pal["metro_code"], "PMO")
        self.assertEqual(res_pal["city"], "Palermo")
        self.assertEqual(res_pal["node_role"], "Provider Edge (PE)")

        # Sparkle Seabone Frankfurt core router
        res_fra = parse_rdns_metro_and_role("fra-cr01.seabone.net")
        self.assertEqual(res_fra["carrier"], "Telecom Italia Sparkle")
        self.assertEqual(res_fra["metro_code"], "FRA")
        self.assertEqual(res_fra["city"], "Francoforte")
        self.assertEqual(res_fra["node_role"], "Core Router")

    def test_rdns_telecom_italia(self):
        # TIM Rome core router
        res_rom = parse_rdns_metro_and_role("rom1-cr1.telecomitalia.it")
        self.assertEqual(res_rom["carrier"], "Telecom Italia")
        self.assertEqual(res_rom["metro_code"], "FCO")
        self.assertEqual(res_rom["city"], "Roma")
        self.assertEqual(res_rom["node_role"], "Core Router")

        # TIM Interbusiness Milan backbone router
        res_ib = parse_rdns_metro_and_role("r-mi24-vl2.opb.interbusiness.it")
        self.assertEqual(res_ib["carrier"], "Telecom Italia")
        self.assertEqual(res_ib["metro_code"], "MXP")
        self.assertEqual(res_ib["city"], "Milano")
        self.assertEqual(res_ib["node_role"], "Backbone Router")

        # TIM BNG Turin
        res_bng = parse_rdns_metro_and_role("bng-torino01.telecomitalia.it")
        self.assertEqual(res_bng["carrier"], "Telecom Italia")
        self.assertEqual(res_bng["metro_code"], "TRN")
        self.assertEqual(res_bng["city"], "Torino")
        self.assertEqual(res_bng["node_role"], "Access Gateway / BRAS")

    def test_rdns_fastweb(self):
        # Fastweb Milan core router
        res_mi = parse_rdns_metro_and_role("10.0.1.1-mi-cr.fastwebnet.it")
        self.assertEqual(res_mi["carrier"], "Fastweb")
        self.assertEqual(res_mi["metro_code"], "MXP")
        self.assertEqual(res_mi["city"], "Milano")
        self.assertEqual(res_mi["node_role"], "Core Router")

        # Fastweb Rome provider edge
        res_rm = parse_rdns_metro_and_role("rm-c-pe.fastwebnet.it")
        self.assertEqual(res_rm["carrier"], "Fastweb")
        self.assertEqual(res_rm["metro_code"], "FCO")
        self.assertEqual(res_rm["city"], "Roma")
        self.assertEqual(res_rm["node_role"], "Provider Edge (PE)")

        # Fastweb Turin ASR aggregation router
        res_to = parse_rdns_metro_and_role("to-asr-01.fastwebnet.it")
        self.assertEqual(res_to["carrier"], "Fastweb")
        self.assertEqual(res_to["metro_code"], "TRN")
        self.assertEqual(res_to["city"], "Torino")
        self.assertEqual(res_to["node_role"], "Access Gateway / BRAS")

        # Fastweb Bologna BNG
        res_bo = parse_rdns_metro_and_role("bo-bng01.fastwebnet.it")
        self.assertEqual(res_bo["carrier"], "Fastweb")
        self.assertEqual(res_bo["metro_code"], "BLQ")
        self.assertEqual(res_bo["city"], "Bologna")

        # Fastweb Florence core router
        res_fi = parse_rdns_metro_and_role("fi-cr02.fastwebnet.it")
        self.assertEqual(res_fi["carrier"], "Fastweb")
        self.assertEqual(res_fi["metro_code"], "FLR")
        self.assertEqual(res_fi["city"], "Firenze")

        # Fastweb Naples PE
        res_na = parse_rdns_metro_and_role("na-pe-01.fastwebnet.it")
        self.assertEqual(res_na["carrier"], "Fastweb")
        self.assertEqual(res_na["metro_code"], "NAP")
        self.assertEqual(res_na["city"], "Napoli")

    def test_rdns_windtre(self):
        # WindTre Milan BNG
        res_mi = parse_rdns_metro_and_role("mi-bng-01.wind.it")
        self.assertEqual(res_mi["carrier"], "Wind Tre")
        self.assertEqual(res_mi["metro_code"], "MXP")
        self.assertEqual(res_mi["city"], "Milano")
        self.assertEqual(res_mi["node_role"], "Access Gateway / BRAS")

        # WindTre Rome core router
        res_rm = parse_rdns_metro_and_role("core-rm1.windtre.it")
        self.assertEqual(res_rm["carrier"], "Wind Tre")
        self.assertEqual(res_rm["metro_code"], "FCO")
        self.assertEqual(res_rm["city"], "Roma")
        self.assertEqual(res_rm["node_role"], "Core Router")

        # WindTre Naples PE
        res_na = parse_rdns_metro_and_role("pe-nap1.windgroup.it")
        self.assertEqual(res_na["carrier"], "Wind Tre")
        self.assertEqual(res_na["metro_code"], "NAP")
        self.assertEqual(res_na["city"], "Napoli")

    def test_rdns_vodafone(self):
        # Vodafone Milan core router
        res_mil = parse_rdns_metro_and_role("mil-cr01.d2-gws.it")
        self.assertEqual(res_mil["carrier"], "Vodafone Italia")
        self.assertEqual(res_mil["metro_code"], "MXP")
        self.assertEqual(res_mil["city"], "Milano")
        self.assertEqual(res_mil["node_role"], "Core Router")

        # Vodafone Rome PE
        res_rom = parse_rdns_metro_and_role("rom-pe02.vodafone.it")
        self.assertEqual(res_rom["carrier"], "Vodafone Italia")
        self.assertEqual(res_rom["metro_code"], "FCO")
        self.assertEqual(res_rom["city"], "Roma")
        self.assertEqual(res_rom["node_role"], "Provider Edge (PE)")

    def test_rdns_openfiber_and_garr(self):
        # Open Fiber Milan backbone router
        res_of = parse_rdns_metro_and_role("rx-mil-1.openfiber.it")
        self.assertEqual(res_of["carrier"], "Open Fiber")
        self.assertEqual(res_of["metro_code"], "MXP")
        self.assertEqual(res_of["city"], "Milano")

        # GARR Milan backbone router
        res_garr = parse_rdns_metro_and_role("rt-mi-1.garr.it")
        self.assertEqual(res_garr["carrier"], "GARR")
        self.assertEqual(res_garr["metro_code"], "MXP")
        self.assertEqual(res_garr["city"], "Milano")

    def test_rdns_tier1_transit_carriers(self):
        # Telia / Arelion Milan border router
        res_telia = parse_rdns_metro_and_role("mil-b1-link.telia.net")
        self.assertEqual(res_telia["carrier"], "Telia / Arelion")
        self.assertEqual(res_telia["metro_code"], "MXP")
        self.assertEqual(res_telia["city"], "Milano")
        self.assertEqual(res_telia["node_role"], "Border Router")

        # Lumen / Level3 Milan transit node
        res_lumen = parse_rdns_metro_and_role("milan.level3.net")
        self.assertEqual(res_lumen["carrier"], "Lumen / Level3")
        self.assertEqual(res_lumen["metro_code"], "MXP")
        self.assertEqual(res_lumen["city"], "Milano")

        # Cogent Milan core router
        res_cogent = parse_rdns_metro_and_role("be3042.ccr41.mil01.atlas.cogentco.com")
        self.assertEqual(res_cogent["carrier"], "Cogent Communications")
        self.assertEqual(res_cogent["metro_code"], "MXP")
        self.assertEqual(res_cogent["city"], "Milano")
        self.assertEqual(res_cogent["node_role"], "Core Router")

        # GTT Milan core router
        res_gtt = parse_rdns_metro_and_role("cr1-mil.as3257.net")
        self.assertEqual(res_gtt["carrier"], "GTT Communications")
        self.assertEqual(res_gtt["metro_code"], "MXP")
        self.assertEqual(res_gtt["city"], "Milano")
        self.assertEqual(res_gtt["node_role"], "Core Router")

    # =========================================================================
    # 2. Datacenter Facility Resolution & Coordinates Mapping
    # =========================================================================
    def test_facility_resolution_milano_campus_caldera(self):
        # Subnet match on MIX Milano LAN
        fac = resolve_datacenter_facility(ip="217.29.66.9")
        self.assertIsNotNone(fac)
        self.assertEqual(fac["id"], "campus-caldera")
        self.assertEqual(fac["facility_name"], "Campus Caldera (Milano)")
        self.assertIn("Via Caldera 21", fac["address"])
        self.assertEqual(fac["city"], "Milano")
        self.assertEqual(fac["metro_code"], "MXP")
        self.assertAlmostEqual(fac["coordinates"]["lat"], 45.4642, places=3)
        self.assertAlmostEqual(fac["coordinates"]["lon"], 9.1028, places=3)
        self.assertIn(13335, fac["host_asns"])
        self.assertIn(6762, fac["host_asns"])

        # Subnet match on Sparkle Milan peering range
        fac_sp = resolve_datacenter_facility(ip="195.22.205.116")
        self.assertIsNotNone(fac_sp)
        self.assertEqual(fac_sp["id"], "campus-caldera")

        # rDNS token match
        fac_rdns = resolve_datacenter_facility(rdns="border-caldera.mix-it.net")
        self.assertIsNotNone(fac_rdns)
        self.assertEqual(fac_rdns["id"], "campus-caldera")

    def test_facility_resolution_roma_namex_tiburtina(self):
        # Subnet match on NaMeX Roma LAN
        fac = resolve_datacenter_facility(ip="193.201.28.11")
        self.assertIsNotNone(fac)
        self.assertEqual(fac["id"], "namex-tiburtina")
        self.assertEqual(fac["facility_name"], "Tiburtina / NaMeX Hub (Roma)")
        self.assertIn("Via dei Luxardo", fac["address"])
        self.assertEqual(fac["city"], "Roma")
        self.assertEqual(fac["metro_code"], "FCO")
        self.assertAlmostEqual(fac["coordinates"]["lat"], 41.8988, places=3)
        self.assertAlmostEqual(fac["coordinates"]["lon"], 12.5186, places=3)

    def test_facility_resolution_regional_hubs(self):
        # TOP-IX Torino
        fac_trn = resolve_datacenter_facility(ip="194.116.86.1")
        self.assertIsNotNone(fac_trn)
        self.assertEqual(fac_trn["id"], "top-ix-torino")
        self.assertIn("Torino", fac_trn["facility_name"])
        self.assertIn("Corso Svizzera", fac_trn["address"])

        # VSIX Padova
        fac_pdv = resolve_datacenter_facility(ip="194.242.224.1")
        self.assertIsNotNone(fac_pdv)
        self.assertEqual(fac_pdv["id"], "vsix-padova")
        self.assertIn("Padova", fac_pdv["facility_name"])

        # TIX Firenze
        fac_flr = resolve_datacenter_facility(ip="193.42.140.1")
        self.assertIsNotNone(fac_flr)
        self.assertEqual(fac_flr["id"], "tix-firenze")
        self.assertIn("Firenze", fac_flr["facility_name"])

        # DE-CIX Frankfurt
        fac_fra = resolve_datacenter_facility(ip="80.81.192.1")
        self.assertIsNotNone(fac_fra)
        self.assertEqual(fac_fra["id"], "de-cix-frankfurt")
        self.assertIn("Frankfurt", fac_fra["facility_name"])
        self.assertIn("Kleyerstrasse", fac_fra["address"])

    # =========================================================================
    # 3. Mocked Parallel Traceroute Parsing with Multi-Target Path Merging
    # =========================================================================
    def test_multi_target_path_merging_and_divergence(self):
        # Mocked outputs representing 4 divergent targets
        target_results = {
            "cloudflare": [
                {"hop": 1, "ip": "192.168.1.1", "rtts": [1.1], "rtt_ms": 1.1},
                {"hop": 2, "ip": "100.64.0.1", "rtts": [6.2], "rtt_ms": 6.2},
                {"hop": 3, "ip": "151.6.1.1", "rtts": [8.5], "rtt_ms": 8.5, "asn": 1267, "asn_name": "Wind Tre"},
                {"hop": 4, "ip": "151.6.2.2", "rtts": [10.1], "rtt_ms": 10.1, "asn": 1267, "asn_name": "Wind Tre"},
                {"hop": 5, "ip": "188.114.100.1", "rtts": [12.0], "rtt_ms": 12.0, "asn": 13335, "asn_name": "Cloudflare", "rdns": "mxp.as13335.net"}
            ],
            "google": [
                {"hop": 1, "ip": "192.168.1.1", "rtts": [1.0], "rtt_ms": 1.0},
                {"hop": 2, "ip": "100.64.0.1", "rtts": [6.0], "rtt_ms": 6.0},
                {"hop": 3, "ip": "151.6.1.1", "rtts": [8.4], "rtt_ms": 8.4, "asn": 1267, "asn_name": "Wind Tre"},
                {"hop": 4, "ip": "151.6.2.2", "rtts": [10.0], "rtt_ms": 10.0, "asn": 1267, "asn_name": "Wind Tre"},
                {"hop": 5, "ip": "142.250.160.1", "rtts": [11.5], "rtt_ms": 11.5, "asn": 15169, "asn_name": "Google", "rdns": "mil01.1e100.net"}
            ],
            "aws": [
                {"hop": 1, "ip": "192.168.1.1", "rtts": [1.2], "rtt_ms": 1.2},
                {"hop": 2, "ip": "100.64.0.1", "rtts": [6.1], "rtt_ms": 6.1},
                {"hop": 3, "ip": "151.6.1.1", "rtts": [8.6], "rtt_ms": 8.6, "asn": 1267, "asn_name": "Wind Tre"},
                {"hop": 4, "ip": "195.22.205.116", "rtts": [11.0], "rtt_ms": 11.0, "asn": 6762, "asn_name": "Telecom Italia Sparkle", "rdns": "mil52-cr01.seabone.net"},
                {"hop": 5, "ip": "13.248.118.1", "rtts": [13.2], "rtt_ms": 13.2, "asn": 16509, "asn_name": "Amazon", "rdns": "aws-mxp.amazon.com"}
            ],
            "domestic_ixp": [
                {"hop": 1, "ip": "192.168.1.1", "rtts": [1.1], "rtt_ms": 1.1},
                {"hop": 2, "ip": "100.64.0.1", "rtts": [6.3], "rtt_ms": 6.3},
                {"hop": 3, "ip": "151.6.1.1", "rtts": [8.5], "rtt_ms": 8.5, "asn": 1267, "asn_name": "Wind Tre"},
                {"hop": 4, "ip": "217.29.66.1", "rtts": [9.2], "rtt_ms": 9.2, "rdns": "cisco-gw.mix-it.net"}
            ]
        }

        merged = merge_multi_target_paths(target_results)

        # 1. Common path: Local Gateway (hop 1), BRAS (hop 2), Core Aggregation (hop 3)
        self.assertEqual(len(merged["common_path"]), 3)
        self.assertEqual(merged["common_path"][0]["ip"], "192.168.1.1")
        self.assertEqual(merged["common_path"][1]["ip"], "100.64.0.1")
        self.assertEqual(merged["common_path"][2]["ip"], "151.6.1.1")

        # 2. Divergence point is Hop 4
        self.assertEqual(merged["divergence_hop"], 4)
        self.assertEqual(merged["common_ancestor_ip"], "151.6.1.1")
        self.assertIn("MIX Peering LAN", merged["divergence_description"])

        # 3. Targets summary
        targets = merged["targets"]
        self.assertIn("cloudflare", targets)
        self.assertIn("google", targets)
        self.assertIn("aws", targets)
        self.assertIn("domestic_ixp", targets)

        self.assertEqual(targets["cloudflare"]["exit_pop"], "MXP")
        self.assertEqual(targets["google"]["exit_pop"], "MXP")
        self.assertEqual(targets["aws"]["exit_pop"], "MXP")
        self.assertEqual(targets["domestic_ixp"]["exit_pop"], "MXP")

        # 4. Transit carriers detected
        self.assertTrue(any("Sparkle" in c for c in merged["transit_carriers"]))

    # =========================================================================
    # 4. Multi-CDN Edge PoP & Colocation Inspection
    # =========================================================================
    def test_multi_cdn_edge_inspection(self):
        mock_cf = {"colo": "MXP", "ip": "1.2.3.4"}
        
        # Test Fastly response parsing with X-Served-By
        fastly_headers = {"X-Served-By": "cache-sjc10036-SJC, cache-lin1730063-LIN", "X-Cache": "HIT, MISS"}
        # Test CloudFront response parsing with x-amz-cf-pop
        cf_headers = {"x-amz-cf-pop": "MXP53-P7"}

        with patch("core.ixp_analyzer.probe_cloudflare_trace", return_value=mock_cf):
            with patch("urllib.request.urlopen") as mock_url:
                resp1 = MagicMock()
                resp1.headers = fastly_headers
                resp2 = MagicMock()
                resp2.headers = cf_headers
                mock_url.side_effect = [
                    MagicMock(__enter__=MagicMock(return_value=resp1), __exit__=MagicMock(return_value=None)),
                    MagicMock(__enter__=MagicMock(return_value=resp2), __exit__=MagicMock(return_value=None))
                ]
                res = probe_multi_cdn_pops(timeout_s=1.0)
                self.assertEqual(res["verified_metro_code"], "MXP")
                self.assertEqual(res["verified_metro"], "Milano")
                self.assertTrue(res["consensus"])
                self.assertIn("cloudflare", res["responding_providers"])

    # =========================================================================
    # 5. Offline Fixture Replay Verification
    # =========================================================================
    def test_offline_fixture_replay_school_and_fttc(self):
        # A. real_ethernet_school.json
        school_path = os.path.join(self.fixtures_dir, "real_ethernet_school.json")
        with open(school_path, "r", encoding="utf-8") as f:
            school_data = json.load(f)

        school_res = self.analyzer.reclassify_offline(
            wan_data=school_data["wan"],
            hops=school_data["ixp"].get("traceroute_hops", []),
            anycast_colo=school_data["ixp"].get("anycast_colo")
        )

        self.assertIn("datacenter_facility", school_res)
        fac_school = school_res["datacenter_facility"]
        self.assertIsNotNone(fac_school)
        self.assertEqual(fac_school["facility_name"], "Campus Caldera (Milano)")
        self.assertIn("Via Caldera 21", fac_school["address"])
        self.assertEqual(fac_school["metro_code"], "MXP")

        self.assertIn("metro_egress", school_res)
        metro_school = school_res["metro_egress"]
        self.assertEqual(metro_school["metro_city"], "Milano")
        self.assertEqual(metro_school["metro_code"], "MXP")

        # B. real_wifi_fttc.json
        fttc_path = os.path.join(self.fixtures_dir, "real_wifi_fttc.json")
        with open(fttc_path, "r", encoding="utf-8") as f:
            fttc_data = json.load(f)

        fttc_res = self.analyzer.reclassify_offline(
            wan_data=fttc_data["wan"],
            hops=fttc_data["ixp"].get("traceroute_hops", []),
            anycast_colo=fttc_data["ixp"].get("anycast_colo")
        )

        self.assertIn("datacenter_facility", fttc_res)
        fac_fttc = fttc_res["datacenter_facility"]
        self.assertIsNotNone(fac_fttc)
        self.assertEqual(fac_fttc["facility_name"], "Campus Caldera (Milano)")
        self.assertIn("Via Caldera 21", fac_fttc["address"])
        self.assertEqual(fac_fttc["city"], "Milano")

        self.assertIn("metro_egress", fttc_res)
        metro_fttc = fttc_res["metro_egress"]
        self.assertEqual(metro_fttc["metro_city"], "Milano")
        self.assertEqual(metro_fttc["metro_code"], "MXP")

        # Verify topological flow breadcrumb is populated in both
        self.assertIn("topological_flow", school_res)
        self.assertIn("Client Locale", school_res["topological_flow"]["breadcrumb"])
        self.assertIn("Hub / Datacenter Campus", school_res["topological_flow"]["breadcrumb"])

        self.assertIn("topological_flow", fttc_res)
        self.assertIn("Accesso BRAS/DSLAM", fttc_res["topological_flow"]["breadcrumb"])

    # =========================================================================
    # 6. Optical Routing Recalibration against Verified Campus Coordinates
    # =========================================================================
    def test_optical_routing_recalibration_with_facility(self):
        # User in Bologna (lat 44.49, lon 11.34)
        wan = {
            "asn": 3269,
            "city": "Bologna",
            "coordinates": {"latitude": 44.4949, "longitude": 11.3426}
        }
        perf = {
            "primary_latency": {"min_ms": 12.1},
            "gateway_latency": {"min_ms": 1.1}
        }
        # Hops leading to Campus Caldera in Milan
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtts": [1.1], "rtt_ms": 1.1},
            {"hop": 2, "ip": "172.18.34.130", "rtts": [5.8], "rtt_ms": 5.8},
            {"hop": 3, "ip": "195.22.205.116", "rtts": [10.5], "rtt_ms": 10.5, "asn": 6762, "asn_name": "Sparkle"},
            {"hop": 4, "ip": "188.114.100.31", "rtts": [12.1], "rtt_ms": 12.1, "asn": 13335, "asn_name": "Cloudflare"}
        ]
        ixp_data = self.analyzer.reclassify_offline(wan, hops, anycast_colo="MXP", target="1.1.1.1")
        
        opt = self.estimator.estimate_optical_routing(
            wan_data=wan,
            perf_data=perf,
            ixp_data=ixp_data,
            medium_name="FTTC / VDSL2 (Fibra Misto Rame)"
        )

        self.assertTrue(opt["applicable"])
        self.assertIsNotNone(opt["datacenter_facility"])
        self.assertEqual(opt["datacenter_facility"]["facility_name"], "Campus Caldera (Milano)")

        # Straight-line distance from Bologna (44.49, 11.34) to Caldera (45.4642, 9.1028) is ~200-220 km
        self.assertGreater(opt["straight_line_distance_km"], 190.0)
        self.assertLess(opt["straight_line_distance_km"], 230.0)

        # Fiber path is 1.35x straight line
        self.assertAlmostEqual(opt["estimated_fiber_path_km"], round(opt["straight_line_distance_km"] * 1.35, 1), places=1)

        # Isolated backhaul: (10.5 ms hop 3 - 5.8 ms local access hop 2) = 4.7 ms backhaul
        self.assertAlmostEqual(opt["local_access_hop_ms"], 5.8, places=1)
        self.assertAlmostEqual(opt["optical_backhaul_rtt_ms"], 10.5 - 5.8, places=1)

        # Efficiency and queuing delay must be calibrated against verified facility floor
        self.assertIsNotNone(opt["routing_efficiency_pct"])
        self.assertGreater(opt["routing_efficiency_pct"], 0.0)
        self.assertLessEqual(opt["routing_efficiency_pct"], 100.0)
        self.assertIsNotNone(opt["switching_and_queuing_delay_ms"])


if __name__ == "__main__":
    unittest.main()
