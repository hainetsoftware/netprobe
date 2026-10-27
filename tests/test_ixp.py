import unittest
import ipaddress
from core.ixp_analyzer import IXPAnalyzer


class TestIXPAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = IXPAnalyzer()

    def test_ixp_subnets_loaded(self):
        self.assertGreaterEqual(len(IXPAnalyzer.IXP_SUBNETS), 10)

    def test_peering_subnet_match(self):
        # 217.29.66.9 è un IP del MIX Milano
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.2, "rdns": None},
            {"hop": 2, "ip": "100.64.0.1", "rtt_ms": 15.0, "rdns": None},
            {"hop": 3, "ip": "217.29.66.9", "rtt_ms": 18.5, "rdns": None},
            {"hop": 4, "ip": "1.1.1.1", "rtt_ms": 20.1, "rdns": None}
        ]
        ixp_def, evidence = self.analyzer._find_ixp_in_hops(hops)
        self.assertIsNotNone(ixp_def)
        self.assertEqual(ixp_def["id"], "mix-it")
        self.assertEqual(evidence["type"], "peering_subnet_match")
        self.assertEqual(evidence["ip"], "217.29.66.9")

    def test_namex_subnet_match(self):
        # 193.201.28.11 è un IP di NAMEX Roma
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.0, "rdns": None},
            {"hop": 2, "ip": "193.201.28.11", "rtt_ms": 12.0, "rdns": None}
        ]
        ixp_def, evidence = self.analyzer._find_ixp_in_hops(hops)
        self.assertIsNotNone(ixp_def)
        self.assertEqual(ixp_def["id"], "namex")
        self.assertEqual(evidence["type"], "peering_subnet_match")

    def test_rdns_match(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.0, "rdns": None},
            {"hop": 2, "ip": "151.6.1.1", "rtt_ms": 14.0, "rdns": "router-caldera.mix-it.net"}
        ]
        ixp_def, evidence = self.analyzer._find_ixp_in_hops(hops)
        self.assertIsNotNone(ixp_def)
        self.assertEqual(ixp_def["id"], "mix-it")
        self.assertEqual(evidence["type"], "rdns_match")

    def test_pni_fallback_classification(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.0, "rdns": None},
            {"hop": 2, "ip": "100.64.0.1", "rtt_ms": 14.0, "rdns": None},
            {"hop": 3, "ip": "151.7.1.1", "rtt_ms": 22.0, "rdns": None},
            {"hop": 4, "ip": "1.1.1.1", "rtt_ms": 23.0, "rdns": None}
        ]
        classification = self.analyzer._classify_exchange(
            matched_ixp=None,
            match_evidence=None,
            hops=hops,
            peeringdb_info={"facilities": [{"name": "MIX-IT"}]},
            wan_data={"city": "Milano", "coordinates": {"latitude": 45.46, "longitude": 9.19}},
            hop2_metrics={"min_ms": 14.0}
        )
        self.assertIn("PNI", classification["peering_type"])
        self.assertIsNone(classification["city"])  # Subscriber city is not exit evidence.


if __name__ == "__main__":
    unittest.main()
