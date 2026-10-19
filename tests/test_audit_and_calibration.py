"""
Unit tests per la suite di audit di base, calibrazione tool ceiling e provenienza dati:
- core.lan_scanner.discover_lan_devices (inclusa separazione 'this_device')
- core.performance.measure_tool_ceiling
- core.provenance.build_field_provenance
- tools.audit_basics.render_table
"""

import unittest
from unittest.mock import patch, MagicMock
from core.lan_scanner import LanScanner
from core.oui_data import is_locally_administered_mac
from core.performance import PerformanceTester
from core.provenance import build_field_provenance
from tools.audit_basics import render_table


class TestLanDevicesDiscovery(unittest.TestCase):
    """Verifica l'unione multi-sorgente dei dispositivi LAN e separazione 'this_device'."""

    def test_discover_lan_devices_separation(self):
        scanner = LanScanner()

        # Mock delle sorgenti interne
        scanner.get_arp_table = MagicMock(side_effect=[
            [
                {"ip": "192.168.1.1", "mac": "78:90:a2:11:22:33", "interface": "en0", "is_router": True, "vendor": "ZTE Corporation"},
                {"ip": "192.168.1.95", "mac": "a8:8f:d9:11:22:33", "interface": "en0", "is_router": False, "vendor": "Apple, Inc."}
            ],
            [
                {"ip": "192.168.1.1", "mac": "78:90:a2:11:22:33", "interface": "en0", "is_router": True, "vendor": "ZTE Corporation"},
                {"ip": "192.168.1.11", "mac": "dc:a6:32:12:34:56", "interface": "en0", "is_router": False, "vendor": "Raspberry Pi Trading Ltd"},
                {"ip": "192.168.1.95", "mac": "a8:8f:d9:11:22:33", "interface": "en0", "is_router": False, "vendor": "Apple, Inc."}
            ]
        ])
        scanner._discover_mdns_services = MagicMock(return_value={
            "192.168.1.50": "nas.local"
        })
        scanner.sweep_local_subnet = MagicMock(return_value=[
            {"ip": "192.168.1.1", "hostname": "router.local"},
            {"ip": "192.168.1.11", "hostname": "pihole.local"},
            {"ip": "192.168.1.50", "hostname": "nas.local"}
        ])
        scanner._query_netbios_name = MagicMock(return_value=None)

        primary_iface = {
            "name": "en0",
            "ipv4": "192.168.1.95",
            "mac": "a8:8f:d9:11:22:33",
            "netmask": "255.255.255.0",
            "type": "Wi-Fi"
        }
        gateway_info = {
            "ipv4": "192.168.1.1",
            "mac": "78:90:a2:11:22:33",
            "vendor": "ZTE Corporation"
        }
        dhcp_info = {"server_ip": "192.168.1.1"}
        dns_info = {"resolvers": ["192.168.1.11", "192.168.1.1"]}

        this_dev, lan_devs = scanner.discover_lan_devices(
            primary_iface=primary_iface,
            gateway_info=gateway_info,
            dhcp_info=dhcp_info,
            dns_info=dns_info,
            quick_scan=False
        )

        # Verifica 'this_device' separato
        self.assertIsNotNone(this_dev)
        self.assertEqual(this_dev.get("ip"), "192.168.1.95")
        self.assertEqual(this_dev.get("mac"), "a8:8f:d9:11:22:33")

        # Verifica che 'this_device' non compaia in lan_devices
        lan_ips = [d.get("ip") for d in lan_devs]
        self.assertNotIn("192.168.1.95", lan_ips)

        # Verifica inclusione Gateway
        self.assertIn("192.168.1.1", lan_ips)
        gw_entry = next(d for d in lan_devs if d["ip"] == "192.168.1.1")
        self.assertTrue(gw_entry.get("is_gateway"))
        self.assertIn("Default Gateway", gw_entry.get("how_found", ""))

        # Verifica inclusione DNS server (192.168.1.11)
        self.assertIn("192.168.1.11", lan_ips)
        dns_entry = next(d for d in lan_devs if d["ip"] == "192.168.1.11")
        self.assertTrue(dns_entry.get("is_dns"))
        self.assertIn("DNS Configurato", dns_entry.get("how_found", ""))

        # Verifica inclusione mDNS device (192.168.1.50)
        self.assertIn("192.168.1.50", lan_ips)
        mdns_entry = next(d for d in lan_devs if d["ip"] == "192.168.1.50")
        self.assertEqual(mdns_entry.get("hostname"), "nas.local")
        self.assertIn("mDNS", mdns_entry.get("how_found", ""))


class TestSpeedCeilingCalibration(unittest.TestCase):
    """Verifica l'auto-calibrazione del tool ceiling in loopback."""

    def test_measure_tool_ceiling_real_loopback(self):
        # Esegue il test reale in-process con server loopback (durata 0.15s per test rapido)
        tester = PerformanceTester()
        ceiling_mbps = tester.measure_tool_ceiling(duration=0.15)

        # Il throughput in memoria/loopback locale deve essere significativo (> 50 Mbps)
        self.assertIsInstance(ceiling_mbps, (int, float))
        self.assertGreater(ceiling_mbps, 50.0)


class TestFieldProvenance(unittest.TestCase):
    """Verifica la corretta generazione del dizionario field_status."""

    def test_build_field_provenance_structure(self):
        sample_results = {
            "lan": {
                "primary_interface": {"name": "en0", "mac": "a8:8f:d9:11:22:33", "ipv4": "192.168.1.95"},
                "gateway": {"ipv4": "192.168.1.1", "mac": "78:90:a2:11:22:33", "vendor": "ZTE Corporation"},
                "wifi": {"ssid": "Fastweb", "channel": 52, "standard": "Wi-Fi 6 (802.11ax)", "rssi": -48},
                "dns": {"resolvers": ["192.168.1.11"], "dnssec_validating": True, "dnssec_breakdown": {}}
            },
            "wan": {
                "public_ip": "82.91.100.1",
                "asn": "AS3269",
                "reverse_dns": "host-82-91-100-1.business.telecomitalia.it",
                "nat_mapping_type": "Endpoint-Independent Mapping"
            },
            "performance": {
                "primary_latency": {"min_ms": 12.3, "median_ms": 13.5},
                "speed": {"download_mbps": 42.5, "upload_mbps": 15.2}
            }
        }

        provenance = build_field_provenance(sample_results)
        self.assertIsInstance(provenance, dict)

        # Verifica chiavi gerarchiche
        expected_keys = [
            "lan.primary_interface.mac", "lan.primary_interface.ipv4",
            "lan.gateway.mac", "lan.gateway.vendor",
            "lan.wifi.ssid", "lan.dns.resolvers",
            "wan.public_ipv4", "wan.asn",
            "performance.speed.download_mbps"
        ]
        for key in expected_keys:
            self.assertIn(key, provenance, f"Manca chiave di provenienza: {key}")
            entry = provenance[key]
            self.assertIn("status", entry)
            self.assertIn("source", entry)
            self.assertIn(entry["status"], ["measured", "parsed", "inferred", "unavailable"])


class TestAuditBasicsTable(unittest.TestCase):
    """Verifica la renderizzazione corretta della tabella di audit."""

    def test_render_table_formatting(self):
        mock_results = [
            {"field": "lan.interface.name", "netprobe": "en0", "reference": "en0", "status": "OK", "source": "route"},
            {"field": "lan.wifi.standard", "netprobe": "Wi-Fi 6", "reference": "802.11ax", "status": "OK", "source": "system_profiler"},
            {"field": "wan.public_ipv6", "netprobe": "Non attivo", "reference": "Non attivo", "status": "N/A", "source": "icanhazip_v6", "note": "IPv4-only"},
            {"field": "performance.latency.min_ms", "netprobe": "12.5 ms", "reference": "17.0 ms", "status": "WARN", "source": "ping", "note": "Δ 4.5 ms"}
        ]
        table = render_table(mock_results, use_color=False)
        self.assertIn("lan.interface.name", table)
        self.assertIn("NETPROBE", table)
        self.assertIn("REFERENCE", table)
        self.assertIn("OK: 2", table)
        self.assertIn("WARN: 1", table)
        self.assertIn("N/A: 1", table)
        self.assertIn("SUPERATO con successo", table)


if __name__ == "__main__":
    unittest.main()
