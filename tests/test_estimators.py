import unittest
from core.estimators import NetworkEstimator


class TestEstimators(unittest.TestCase):
    def setUp(self):
        self.est = NetworkEstimator()

    def test_ftth_estimation(self):
        lan_data = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1500}}
        wan_data = {"isp": "Fastweb", "org": "Fastweb SpA", "asn": "AS12874", "nat": {}}
        perf_data = {
            "primary_latency": {"min_ms": 2.1, "jitter_ms": 0.4},
            "speed": {"download_mbps": 850.0, "upload_mbps": 280.0}
        }
        ixp_data = {
            "hop2_bng": {"ip": "10.0.0.1", "min_ms": 1.8, "median_ms": 2.0, "jitter_ms": 0.3, "is_responsive": True}
        }
        res = self.est.estimate_physical_medium(lan_data, wan_data, perf_data, ixp_data=ixp_data)
        self.assertIn("FTTH", res["predicted_medium"])
        self.assertGreater(res["confidence_pct"], 80.0)

    def test_fttc_veto_on_high_upload(self):
        # Upload 55 Mbps è fisicamente impossibile su VDSL2 profilo 35b (cappato a 35 Mbps)
        lan_data = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1492}}
        wan_data = {"isp": "TIM", "org": "Telecom Italia", "asn": "AS3269", "nat": {}}
        perf_data = {
            "primary_latency": {"min_ms": 8.0, "jitter_ms": 1.0},
            "speed": {"download_mbps": 120.0, "upload_mbps": 55.0}
        }
        ixp_data = {
            "hop2_bng": {"ip": "172.16.0.1", "min_ms": 7.5, "median_ms": 8.0, "jitter_ms": 0.8, "is_responsive": True}
        }
        res = self.est.estimate_physical_medium(lan_data, wan_data, perf_data, ixp_data=ixp_data)
        # Non deve essere classificato come FTTC
        self.assertNotIn("FTTC", res["predicted_medium"])
        self.assertTrue(any("35.0 Mbps" in r for r in res["rationale"]))

    def test_fttc_classification(self):
        # Linea FTTC classica: 18 Mbps upload (entro 21.6/35 Mbps), BNG a 8.5 ms, MTU 1492 PPPoE
        lan_data = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1492}}
        wan_data = {"isp": "TIM", "org": "Telecom Italia", "asn": "AS3269", "nat": {}}
        perf_data = {
            "primary_latency": {"min_ms": 8.8, "jitter_ms": 0.8},
            "speed": {"download_mbps": 95.0, "upload_mbps": 19.5}
        }
        ixp_data = {
            "hop2_bng": {"ip": "172.16.0.1", "min_ms": 8.2, "median_ms": 8.5, "jitter_ms": 0.6, "is_responsive": True}
        }
        res = self.est.estimate_physical_medium(lan_data, wan_data, perf_data, ixp_data=ixp_data)
        self.assertIn("FTTC", res["predicted_medium"])

    def test_ios_hotspot_cellular_fingerprint(self):
        # Gateway 172.20.10.1 identifica in modo univoco iPhone Personal Hotspot
        lan_data = {"gateway": {"ipv4": "172.20.10.1"}, "primary_interface": {"mtu": 1500}}
        wan_data = {"isp": "WindTre", "org": "Wind Tre SpA", "asn": "AS1267", "nat": {"cgnat_detected": True}}
        perf_data = {
            "primary_latency": {"min_ms": 35.0, "jitter_ms": 7.5},
            "speed": {"download_mbps": 45.0, "upload_mbps": 12.0}
        }
        ixp_data = {
            "hop2_bng": {"ip": "100.110.147.129", "min_ms": 32.0, "median_ms": 40.0, "jitter_ms": 8.0, "is_responsive": True}
        }
        res = self.est.estimate_physical_medium(lan_data, wan_data, perf_data, ixp_data=ixp_data)
        self.assertIn("Mobile", res["predicted_medium"])
        self.assertGreaterEqual(res["confidence_pct"], 80.0)

    def test_eolo_fwa(self):
        lan_data = {"gateway": {"ipv4": "192.168.1.1"}, "primary_interface": {"mtu": 1500}}
        wan_data = {"isp": "EOLO", "org": "Eolo SpA", "asn": "AS8612", "nat": {}}
        perf_data = {
            "primary_latency": {"min_ms": 14.0, "jitter_ms": 2.2},
            "speed": {"download_mbps": 100.0, "upload_mbps": 20.0}
        }
        res = self.est.estimate_physical_medium(lan_data, wan_data, perf_data)
        self.assertIn("FWA", res["predicted_medium"])

    def test_mos_reference_points(self):
        ok = {"primary_latency": {"median_ms": 0.0, "jitter_ms": 0.0, "packet_loss_pct": 0.0}}
        self.assertAlmostEqual(self.est.calculate_itu_mos(ok)["r_factor"], 93.2, places=1)
        lossy = {"primary_latency": {"median_ms": 0.0, "jitter_ms": 0.0, "packet_loss_pct": 1.0}}
        self.assertAlmostEqual(self.est.calculate_itu_mos(lossy)["r_factor"], 93.2 - 95 / 5.3, places=1)

    def test_mos_insufficient_data(self):
        res = self.est.calculate_itu_mos({})
        self.assertTrue(res["insufficient_data"])
        self.assertIsNone(res["mos_score"])

    def test_routing_efficiency_not_applicable_on_hotspot(self):
        wan = {"coordinates": {"latitude": 45.5, "longitude": 9.2}, "nat": {"cgnat_detected": True}}
        perf = {"primary_latency": {"min_ms": 48.0}}
        res = self.est.estimate_optical_routing(wan, perf, None, "Mobile Cellular (4G LTE / 5G Mobile Hotspot)")
        self.assertIsNone(res["routing_efficiency_pct"])
        self.assertFalse(res["applicable"])

    def test_routing_efficiency_vpn_not_applicable(self):
        wan = {"coordinates": {"latitude": 41.9, "longitude": 12.5},
               "privacy_and_routing": {"is_vpn_or_proxy": True}}
        res = self.est.estimate_optical_routing(wan, {"primary_latency": {"min_ms": 30.0}})
        self.assertFalse(res["applicable"])

    def test_insufficient_data_medium(self):
        res = self.est.estimate_physical_medium({}, {}, {})
        self.assertTrue(res["insufficient_data"])
        self.assertLessEqual(res["confidence_pct"], 25.0)

    def test_asn_exact_match(self):
        wan = {"asn": "AS38612", "nat": {}}
        res = self.est.estimate_physical_medium({}, wan, {})
        self.assertEqual(res["scores_breakdown"]["FWA (Fixed Wireless Access / Eolo / Linkem)"], 0.0)

    def test_hop2_no_gap_between_4_2_and_5_5(self):
        ixp = {"hop2_bng": {"ip": "10.0.0.1", "min_ms": 4.8, "jitter_ms": 0.5, "is_responsive": True}}
        res = self.est.estimate_physical_medium({}, {}, {"primary_latency": {"min_ms": 6.0}}, ixp)
        self.assertGreater(res["scores_breakdown"]["FTTC / VDSL2 (Fibra Misto Rame)"], 0.0)


if __name__ == "__main__":
    unittest.main()
