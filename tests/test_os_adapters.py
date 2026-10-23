"""
Test unitari per gli adapter di sistema operativo (MacOSAdapter, LinuxAdapter, WindowsAdapter)
utilizzando i golden fixtures reali e documentati.
"""

import os
import unittest
from unittest.mock import patch

from core.adapters.macos import MacOSAdapter
from core.adapters.linux import LinuxAdapter
from core.adapters.windows import WindowsAdapter
from core.oui_data import is_placeholder_mac


class TestOSAdapters(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "os")

    def _read_fixture(self, os_name: str, filename: str) -> str:
        path = os.path.join(self.fixtures_dir, os_name, filename)
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    # ----------------------------------------------------
    # macOS Adapter Tests
    # ----------------------------------------------------
    def test_macos_route_get_default_fixture(self):
        adapter = MacOSAdapter()
        route_out = self._read_fixture("macos", "route_get_default.txt")

        with patch("core.adapters.macos.run_cmd", return_value=(0, route_out, "")):
            # Evita chiamata reale a system_profiler per questo test isolato
            with patch.object(adapter, "get_gateway_mac", return_value="78:90:a2:11:22:33"):
                gw = adapter.get_default_gateway()
                self.assertEqual(gw["ipv4"], "192.168.1.1")
                self.assertEqual(gw["interface"], "en0")
                self.assertEqual(gw["mac"], "78:90:a2:11:22:33")
                self.assertEqual(gw["vendor"], "ZTE Corporation")

    def test_macos_system_profiler_mac_extraction(self):
        adapter = MacOSAdapter()
        sp_out = self._read_fixture("macos", "system_profiler.txt")
        adapter._cached_system_profiler_network = sp_out

        gw_mac = adapter.get_gateway_mac("192.168.1.1")
        self.assertEqual(gw_mac, "78:90:a2:11:22:33")
        self.assertFalse(is_placeholder_mac(gw_mac))

        # Simula fallimento di networksetup e ipconfig per forzare l'estrazione da system_profiler
        with patch("core.adapters.macos.run_cmd", return_value=(1, "", "")):
            iface_mac = adapter.get_interface_mac("en0")
            self.assertEqual(iface_mac, "a8:8f:d9:11:22:33")
            self.assertFalse(is_placeholder_mac(iface_mac))

    def test_macos_arp_an_fixture(self):
        adapter = MacOSAdapter()
        adapter._get_sysctl_arp = lambda: []
        arp_out = self._read_fixture("macos", "arp_an.txt")

        with patch("core.adapters.macos.run_cmd", return_value=(0, arp_out, "")):
            entries = adapter.get_arp_table()
            self.assertGreater(len(entries), 5)
            ips = [e["ip"] for e in entries]
            self.assertIn("192.168.1.1", ips)
            self.assertIn("192.168.1.11", ips)
            # Nessun placeholder e nessun broadcast .255
            self.assertNotIn("192.168.1.255", ips)
            for e in entries:
                self.assertFalse(is_placeholder_mac(e["mac"]))
                self.assertEqual(len(e["mac"].split(":")), 6)

    def test_macos_scutil_dns_fixture(self):
        adapter = MacOSAdapter()
        dns_out = self._read_fixture("macos", "scutil_dns.txt")

        with patch("core.adapters.macos.run_cmd", return_value=(0, dns_out, "")):
            dns = adapter.get_dns_configuration()
            self.assertIn("192.168.1.11", dns["resolvers"])
            self.assertIn("192.168.1.1", dns["resolvers"])

    def test_macos_dhcp_getpacket_fixture(self):
        adapter = MacOSAdapter()
        dhcp_out = self._read_fixture("macos", "ipconfig_getpacket.txt")

        with patch("core.adapters.macos.run_cmd", return_value=(0, dhcp_out, "")):
            dhcp = adapter.get_dhcp_info("en0")
            self.assertEqual(dhcp["server_ip"], "192.168.1.1")
            self.assertEqual(dhcp["lease_time_seconds"], 86400)
            self.assertEqual(dhcp["subnet_mask"], "255.255.255.0")
            self.assertIn("192.168.1.11", dhcp["dns_servers"])

    # ----------------------------------------------------
    # Linux Adapter Tests
    # ----------------------------------------------------
    def test_linux_adapter_fixtures(self):
        adapter = LinuxAdapter()
        route_out = self._read_fixture("linux", "ip_route.txt")
        addr_out = self._read_fixture("linux", "ip_addr.txt")

        with patch("core.adapters.linux.run_cmd", return_value=(0, route_out, "")):
            with patch.object(adapter, "get_gateway_mac", return_value="78:90:a2:11:22:33"):
                gw = adapter.get_default_gateway()
                self.assertEqual(gw["ipv4"], "192.168.1.1")
                self.assertEqual(gw["interface"], "eth0")

        with patch("core.adapters.linux.run_cmd", return_value=(0, addr_out, "")):
            ifaces = adapter.get_network_interfaces()
            self.assertIn("eth0", ifaces)
            self.assertEqual(ifaces["eth0"]["ipv4"], "192.168.1.50")
            self.assertEqual(ifaces["eth0"]["mac"], "b8:27:eb:1a:2b:3c")
            self.assertEqual(ifaces["eth0"]["vendor"], "Raspberry Pi Foundation")

    # ----------------------------------------------------
    # Windows Adapter Tests
    # ----------------------------------------------------
    def test_windows_adapter_fixtures(self):
        adapter = WindowsAdapter()
        route_out = self._read_fixture("windows", "get_net_route.csv")
        adapter_out = self._read_fixture("windows", "get_net_adapter.json")
        arp_out = self._read_fixture("windows", "arp_a.txt")

        with patch("core.adapters.windows.run_cmd", return_value=(0, route_out, "")):
            with patch.object(adapter, "get_gateway_mac", return_value="78:90:a2:11:22:33"):
                gw = adapter.get_default_gateway()
                self.assertEqual(gw["ipv4"], "192.168.1.1")
                self.assertEqual(gw["interface"], "Ethernet0")

        with patch("core.adapters.windows.run_cmd", return_value=(0, adapter_out, "")):
            ifaces = adapter.get_network_interfaces()
            self.assertIn("Ethernet0", ifaces)
            self.assertEqual(ifaces["Ethernet0"]["ipv4"], "192.168.1.100")
            self.assertEqual(ifaces["Ethernet0"]["mac"], "00:0c:29:ab:cd:ef")

        with patch("core.adapters.windows.run_cmd", return_value=(0, arp_out, "")):
            entries = adapter.get_arp_table()
            ips = [e["ip"] for e in entries]
            self.assertIn("192.168.1.1", ips)
            self.assertIn("192.168.1.11", ips)
            self.assertNotIn("192.168.1.255", ips)


    def test_windows_wifi_parsing_connected(self):
        adapter = WindowsAdapter()
        mock_wlan = """There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Telecom-Fiber-5G
    BSSID                  : 78:90:a2:0b:7a:d4
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Band                   : 5 GHz
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 96%
"""
        with patch("core.adapters.windows.run_cmd", return_value=(0, mock_wlan, "")):
            res = adapter.get_wifi_details()
            self.assertTrue(res["supported"])
            self.assertTrue(res["connected"])
            self.assertEqual(res["ssid"], "Telecom-Fiber-5G")
            self.assertEqual(res["bssid"], "78:90:a2:0b:7a:d4")
            self.assertEqual(res["wifi_generation"], "Wi-Fi 6 (802.11ax)")
            self.assertEqual(res["channel"], 36)
            self.assertEqual(res["frequency_ghz"], 5.18)
            self.assertEqual(res["signal_quality_pct"], 96)
            self.assertEqual(res["rssi_dbm"], -52)
            self.assertEqual(res["noise_dbm"], -90.0)
            self.assertEqual(res["snr_db"], 38.0)
            self.assertEqual(res["tx_rate_mbps"], 1201.0)
            self.assertEqual(res["rx_rate_mbps"], 1201.0)
            self.assertEqual(res["security"], "WPA2-Personal / CCMP")

    def test_windows_wifi_disconnected(self):
        adapter = WindowsAdapter()
        mock_wlan = """There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : disconnected
"""
        with patch("core.adapters.windows.run_cmd", return_value=(0, mock_wlan, "")):
            res = adapter.get_wifi_details()
            self.assertTrue(res["supported"])
            self.assertFalse(res["connected"])
            self.assertIsNone(res["ssid"])

    def test_windows_wifi_when_active_ethernet(self):
        adapter = WindowsAdapter()
        res = adapter.get_wifi_details(iface_type="Ethernet")
        self.assertFalse(res["connected"])

    def test_windows_dhcp_parsing(self):
        adapter = WindowsAdapter()
        mock_ipconfig = """Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : homenet.telecomitalia.it
   Description . . . . . . . . . . . : Intel(R) Ethernet Controller (3) I225-V
   Physical Address. . . . . . . . . : 50-EB-F6-95-3B-C1
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.83(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.11
                                       192.168.1.1
"""
        with patch("core.adapters.windows.run_cmd", return_value=(0, mock_ipconfig, "")):
            dhcp = adapter.get_dhcp_info("Ethernet 2")
            self.assertEqual(dhcp["server_ip"], "192.168.1.1")
            self.assertEqual(dhcp["subnet_mask"], "255.255.255.0")
            self.assertEqual(dhcp["domain_name"], "homenet.telecomitalia.it")
            self.assertIn("192.168.1.11", dhcp["dns_servers"])

    def test_windows_dns_configuration(self):
        adapter = WindowsAdapter()
        mock_ipconfig = """Windows IP Configuration

   DNS Servers . . . . . . . . . . . : 192.168.1.11
                                       192.168.1.1
"""
        with patch("core.adapters.windows.run_cmd", return_value=(0, mock_ipconfig, "")):
            dns = adapter.get_dns_configuration()
            self.assertIn("192.168.1.11", dns["resolvers"])
            self.assertIn("192.168.1.1", dns["resolvers"])
            self.assertEqual(dns["system_dns_service"], "Windows DNS Client")


if __name__ == "__main__":
    unittest.main()
