import unittest
from core.switch_probe import SwitchProbe


class TestSwitchProbe(unittest.TestCase):
    def setUp(self):
        self.probe = SwitchProbe()

    def test_lldp_tlv_parsing(self):
        # TLV 5: System Name = "SW-Main-01"
        tlv5 = bytes([(5 << 1) | 0, 10]) + b"SW-Main-01"
        # TLV 2: Port ID = "GigabitEthernet1/0/2" (subtype 5)
        tlv2 = bytes([(2 << 1) | 0, 21]) + b"\x05GigabitEthernet1/0/2"
        # TLV 6: System Description = "Cisco Catalyst 2960-X"
        tlv6 = bytes([(6 << 1) | 0, 21]) + b"Cisco Catalyst 2960-X"
        # End of LLDPDU
        end_tlv = b"\x00\x00"

        payload = tlv5 + tlv2 + tlv6 + end_tlv
        info = self.probe.parse_lldp_payload(payload)

        self.assertEqual(info["system_name"], "SW-Main-01")
        self.assertEqual(info["port_id"], "GigabitEthernet1/0/2")
        self.assertEqual(info["system_description"], "Cisco Catalyst 2960-X")

    def test_cdp_tlv_parsing(self):
        # CDP packet: version 2, ttl 180, checksum 0x0000
        hdr = b"\x02\xb4\x00\x00"
        # TLV 1: Device ID = "Core-Switch" (len = 4 + 11 = 15)
        tlv1 = (1).to_bytes(2, "big") + (15).to_bytes(2, "big") + b"Core-Switch"
        # TLV 3: Port ID = "Gi0/1" (len = 4 + 5 = 9)
        tlv3 = (3).to_bytes(2, "big") + (9).to_bytes(2, "big") + b"Gi0/1"
        # TLV 6: Platform = "cisco WS-C3560" (len = 4 + 14 = 18)
        tlv6 = (6).to_bytes(2, "big") + (18).to_bytes(2, "big") + b"cisco WS-C3560"

        payload = hdr + tlv1 + tlv3 + tlv6
        info = self.probe.parse_cdp_payload(payload)

        self.assertEqual(info["device_id"], "Core-Switch")
        self.assertEqual(info["port_id"], "Gi0/1")
        self.assertEqual(info["platform"], "cisco WS-C3560")

    def test_unmanaged_fallback(self):
        res = self.probe.probe_connected_switch(
            interface="fake_eth0",
            gateway_ip="192.168.1.1",
            arp_table=[],
            timeout_seconds=0.1
        )
        self.assertFalse(res["detected"])
        self.assertIn("Unmanaged", res["switch_type"])


if __name__ == "__main__":
    unittest.main()
