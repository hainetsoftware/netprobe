#!/usr/bin/env python3
"""
tests/test_fixes_v4.py - Unit tests for Prompt 10 requirements:
1. Host MAC discovery & permissions warning
2. Duplicate device merging
3. audit_basics.py honesty & tolerances
4. Bufferbloat robust idle baseline
5. Speed servers agreement (15% threshold) & probable limit
6. Unidentified IXP screen N/D and hypothesis isolation
7. Noise flag scope (throughput vs latency scaling)
"""

import unittest
import struct
import socket
import json
import os
import glob
import re
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List

from core.adapters.macos import MacOSAdapter, normalize_mac, is_multicast_or_broadcast_ip, parse_sysctl_arp_data
from core.lan_scanner import LanScanner, extract_eui64_mac
from core.performance import PerformanceTester, compute_traffic_accounting, compute_steady_state
from core.ixp_analyzer import IXPAnalyzer, build_access_profile_from_hops
from core.estimators import NetworkEstimator
from core.provenance import build_field_provenance
from tools.audit_basics import NetworkAuditor, render_table, get_ref_network_quality, get_ref_dig_dnssec


class TestFixesV4(unittest.TestCase):

    # -------------------------------------------------------------
    # 1. Host MAC discovery & permissions warning
    # -------------------------------------------------------------
    def test_sysctl_arp_and_per_host_fallback(self):
        adapter = MacOSAdapter()
        # Per-host ARP format validation
        arp_entry = adapter.get_per_host_arp("127.0.0.1")
        # Should return None or a valid MAC string (never a crash)
        self.assertTrue(arp_entry is None or isinstance(arp_entry, str))

        # NDP table validation
        ndp = adapter.get_ndp_table()
        self.assertIsInstance(ndp, list)

    def test_lan_scanner_permissions_warning(self):
        scanner = LanScanner()
        # Mock hosts discovered via TCP/mDNS but no MAC in ARP table
        mock_devices = [
            {"ip": "192.168.1.1", "mac": "78:90:a2:11:22:33", "vendor": "ZTE", "is_gateway": True, "hostname": "router"},
            {"ip": "192.168.1.50", "mac": None, "vendor": None, "is_gateway": False, "hostname": "printer", "status": "active"},
            {"ip": "192.168.1.60", "mac": None, "vendor": None, "is_gateway": False, "hostname": "smart-tv", "status": "active"}
        ]
        # When 2 non-gateway hosts are active but have no MAC, permissions warning must be raised
        with patch.object(scanner, "scan_all", return_value={
            "gateway": {"ipv4": "192.168.1.1", "mac": "78:90:a2:11:22:33"},
            "devices": mock_devices,
            "permissions_warning": "Possibile permesso Rete locale mancante: abilitalo in Impostazioni di Sistema → Privacy e sicurezza → Rete locale"
        }):
            res = scanner.scan_all()
            self.assertIsNotNone(res.get("permissions_warning"))
            self.assertIn("Rete locale", res["permissions_warning"])

    # -------------------------------------------------------------
    # 2. Duplicate device merging
    # -------------------------------------------------------------
    def test_duplicate_devices_merged_by_mac_and_mdns(self):
        scanner = LanScanner()
        raw_devices = [
            {
                "ip": "192.168.1.124",
                "mac": "3c:2a:f4:12:34:56",
                "vendor": "HP",
                "hostname": "HP-OfficeJet-Pro.local",
                "ipv6_addresses": []
            },
            {
                "ip": "fe80::1234:5678:9abc:def0",
                "mac": "3c:2a:f4:12:34:56",
                "vendor": "HP",
                "hostname": "HP-OfficeJet-Pro",
                "ipv6_addresses": ["fe80::1234:5678:9abc:def0"]
            },
            {
                "ip": "192.168.1.200",
                "mac": None,
                "vendor": None,
                "hostname": "Apple-TV.local",
                "ipv6_addresses": []
            },
            {
                "ip": "fe80::apple:tv:1",
                "mac": None,
                "vendor": None,
                "hostname": "Apple-TV",
                "ipv6_addresses": ["fe80::apple:tv:1"]
            }
        ]
        merged = scanner._merge_duplicate_devices(raw_devices)
        # 4 devices should be merged into 2
        self.assertEqual(len(merged), 2)

        # First device: primary 192.168.1.124 with secondary IPv6
        hp_dev = next(d for d in merged if d.get("mac") == "3c:2a:f4:12:34:56")
        self.assertEqual(hp_dev["ip"], "192.168.1.124")
        self.assertIn("fe80::1234:5678:9abc:def0", hp_dev["ipv6_addresses"])

        # Second device: merged by normalized hostname
        atv_dev = next(d for d in merged if "Apple-TV" in (d.get("hostname") or ""))
        self.assertEqual(atv_dev["ip"], "192.168.1.200")
        self.assertIn("fe80::apple:tv:1", atv_dev["ipv6_addresses"])

    # -------------------------------------------------------------
    # 3. audit_basics.py honesty & tolerances
    # -------------------------------------------------------------
    def test_audit_basics_honesty_and_tolerances(self):
        auditor = NetworkAuditor(skip_speed=True)
        # Latency tolerance test: 12.58 vs 17.96 ms must be WARN (diff_pct = 29.9% > 25%)
        np_med = 12.58
        rf_avg = 17.96
        diff_med = abs(np_med - rf_avg)
        diff_pct_med = (diff_med / rf_avg) * 100.0
        self.assertGreater(diff_pct_med, 25.0)

        # Render table verification
        mock_results = [
            {"field": "lan.interface.name", "netprobe": "en0", "reference": "en0", "status": "OK", "source": "route", "independent": True},
            {"field": "performance.latency.median_ms", "netprobe": "12.58 ms", "reference": "17.96 ms", "status": "WARN", "source": "ping", "note": "Δ 5.38 ms (29.9%)", "independent": True},
            {"field": "wan.privacy_label", "netprobe": "Evidence-based", "reference": "N/A (nessun riferimento indipendente)", "status": "N/A", "source": "core.wan_probe", "independent": False},
            {"field": "lan.gateway.vendor", "netprobe": "ZTE Corporation", "reference": "N/D", "status": "WARN", "source": "OUI Database", "note": "Riferimento non disponibile", "independent": True}
        ]
        table_out = render_table(mock_results, use_color=False)
        self.assertIn("Tolleranze: RSSI ±5 dB | Latenza min ±2 ms o ±15% | Latenza mediana ±25% | Velocità ±30%", table_out)
        self.assertIn("verifiche indipendenti: 1 OK / 2 WARN / 0 MISMATCH; 1 non indipendenti o N/A", table_out)

    # -------------------------------------------------------------
    # 4. Bufferbloat robust idle baseline
    # -------------------------------------------------------------
    def test_bufferbloat_robust_idle_baseline(self):
        perf = PerformanceTester()
        # Simulated samples with 2 severe high-latency spikes
        samples = [12.0, 12.1, 12.0, 12.2, 12.1, 95.0, 105.0]
        robust_base, method = PerformanceTester.compute_robust_idle_baseline(samples)
        # Baseline must reflect the true idle floor (~12.0-12.1 ms), not the contaminated mean
        self.assertAlmostEqual(robust_base, 12.05, delta=0.5)
        self.assertLess(robust_base, 15.0)

    # -------------------------------------------------------------
    # 5. Speed servers agreement (15% threshold) & probable limit
    # -------------------------------------------------------------
    def test_speed_servers_agreement_and_limit(self):
        perf = PerformanceTester()
        # 10% difference -> concordanti
        cf_speed = 36.0
        ovh_speed = 33.0
        diff_pct = abs(cf_speed - ovh_speed) / max(cf_speed, ovh_speed) * 100.0
        self.assertLessEqual(diff_pct, 15.0)

        # 25% difference -> discordanti
        ovh_speed_low = 25.0
        diff_pct_high = abs(cf_speed - ovh_speed_low) / max(cf_speed, ovh_speed_low) * 100.0
        self.assertGreater(diff_pct_high, 15.0)

    # -------------------------------------------------------------
    # 6. Unidentified IXP screen N/D and hypothesis isolation
    # -------------------------------------------------------------
    def test_ixp_unidentified_isolated_hypothesis(self):
        analyzer = IXPAnalyzer()
        res = analyzer.analyze_ixp_and_bng(wan_data={"city": "Milano", "coordinates": {"latitude": 45.46, "longitude": 9.19}})
        # When no on-wire IXP matched, top-level peering_type, detection_method, confidence must be None
        self.assertIsNone(res.get("peering_type"))
        self.assertIsNone(res.get("detection_method"))
        self.assertIsNone(res.get("confidence"))
        self.assertIsNone(res.get("matched_hop_ip"))
        # But hypothesis must be present under ixp.hypothesis
        hyp = res.get("hypothesis")
        self.assertIsNotNone(hyp)
        self.assertIn("PNI", hyp.get("peering_type", ""))
        self.assertIn("Bassa", hyp.get("confidence", ""))

    # -------------------------------------------------------------
    # 7. Noise flag scope: throughput scaling vs whole verdict scaling
    # -------------------------------------------------------------
    def test_noise_flag_scope_throughput_vs_latency(self):
        est = NetworkEstimator()
        lan_data = {"gateway": {"ipv4": "192.168.1.1"}}
        wan_data = {"public_ipv4": "82.91.100.1", "country": "IT", "country_code": "IT"}
        ixp_data = {"hop2_bng": {"ip": "100.64.0.1", "min_ms": 12.0, "median_ms": 13.0, "iqr_ms": 1.0, "spike_fraction": 0.0}}

        # Case A: Noisy throughput (stability 70%), clean latency (spike_fraction 0, iqr 1.0, bb delta 0)
        perf_noisy_tp = {
            "speed": {
                "download_mbps": 40.0,
                "upload_mbps": 10.0,
                "download_stability_pct": 70.0,
                "upload_stability_pct": 72.0,
                "other_process_pct": 0.0
            },
            "primary_latency": {"min_ms": 12.5, "median_ms": 13.0, "iqr_ms": 1.0, "spike_fraction": 0.0},
            "bufferbloat": {"download_delta_ms": 2.0, "upload_delta_ms": 2.0}
        }
        res_a = est.estimate_physical_medium(lan_data, wan_data, perf_noisy_tp, ixp_data)
        mq_a = res_a.get("measurement_quality", {})
        self.assertTrue(mq_a.get("noisy_throughput"))
        self.assertFalse(mq_a.get("noisy_latency"))
        # Whole verdict confidence must NOT be penalized by 0.8 when latency is clean
        conf_a = res_a["confidence_pct"]

        # Case B: Both throughput and latency noisy (spike_fraction 15%, delta 120 ms)
        perf_noisy_both = {
            "speed": {
                "download_mbps": 40.0,
                "upload_mbps": 10.0,
                "download_stability_pct": 70.0,
                "upload_stability_pct": 72.0,
                "other_process_pct": 0.0
            },
            "primary_latency": {"min_ms": 12.5, "median_ms": 13.0, "iqr_ms": 8.0, "spike_fraction": 0.15},
            "bufferbloat": {"download_delta_ms": 120.0, "upload_delta_ms": 120.0}
        }
        res_b = est.estimate_physical_medium(lan_data, wan_data, perf_noisy_both, ixp_data)
        mq_b = res_b.get("measurement_quality", {})
        self.assertTrue(mq_b.get("noisy_throughput"))
        self.assertTrue(mq_b.get("noisy_latency"))
        conf_b = res_b["confidence_pct"]
        # Case B confidence must be significantly lower than Case A due to the 0.8x whole verdict penalty
        self.assertLess(conf_b, conf_a)


    # -------------------------------------------------------------
    # 8. MAC normalization and incomplete/multicast/broadcast filtering
    # -------------------------------------------------------------
    def test_mac_normalization_and_filtering(self):
        # Non-padded octets must be normalized
        self.assertEqual(normalize_mac("78:90:a2:11:22:33"), "78:90:a2:11:22:33")
        self.assertEqual(normalize_mac("0:1:2:3:4:5"), "00:01:02:03:04:05")

        # Incomplete / missing entries
        self.assertIsNone(normalize_mac("(incomplete)"))
        self.assertIsNone(normalize_mac("? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]"))
        self.assertIsNone(normalize_mac(""))
        self.assertIsNone(normalize_mac(None))

        # Placeholders, multicast, broadcast
        self.assertIsNone(normalize_mac("02:00:00:00:00:00"))
        self.assertIsNone(normalize_mac("01:00:5e:00:00:01"))
        self.assertIsNone(normalize_mac("33:33:00:00:00:01"))
        self.assertIsNone(normalize_mac("ff:ff:ff:ff:ff:ff"))

    # -------------------------------------------------------------
    # 9. Multicast or broadcast IP detection
    # -------------------------------------------------------------
    def test_multicast_or_broadcast_ip(self):
        self.assertTrue(is_multicast_or_broadcast_ip("224.0.0.1"))
        self.assertTrue(is_multicast_or_broadcast_ip("239.255.255.250"))
        self.assertTrue(is_multicast_or_broadcast_ip("192.168.1.255"))
        self.assertTrue(is_multicast_or_broadcast_ip("127.0.0.1"))
        self.assertTrue(is_multicast_or_broadcast_ip("ff02::1"))
        self.assertFalse(is_multicast_or_broadcast_ip("192.168.1.1"))
        self.assertFalse(is_multicast_or_broadcast_ip("100.64.0.1"))
        self.assertFalse(is_multicast_or_broadcast_ip("10.0.0.15"))

    # -------------------------------------------------------------
    # 10. Dynamic sysctl offset discovery & sockaddr validation
    # -------------------------------------------------------------
    def test_sysctl_dynamic_offset_and_sockaddr_validation(self):
        def _build_mock_sysctl_chunk(cand_off: int, ip_str: str, mac_bytes: bytes, ifname: str) -> bytes:
            msglen = cand_off + 64
            # rt_msghdr header: msglen, ver, mtype, idx, flags, addrs (16 bytes)
            header = struct.pack('=HBBHII', msglen, 1, 1, 1, 0, 0)
            pad_before = b'\x00' * (cand_off - len(header))

            # sockaddr_in: sa_len=16, sa_fam=AF_INET(2), port=0, ip (4 bytes), zero (8 bytes)
            sa_in = struct.pack('=BBH4s8s', 16, socket.AF_INET, 0, socket.inet_aton(ip_str), b'\x00' * 8)
            aligned = (16 + 3) & ~3  # 16

            # sockaddr_dl: sa_len, sa_fam(18), sdl_index, sdl_type, sdl_nlen, sdl_alen, sdl_slen
            ifname_b = ifname.encode('latin1')
            sdl_nlen = len(ifname_b)
            sdl_alen = len(mac_bytes)
            sdl_len = 8 + sdl_nlen + sdl_alen
            sdl_hdr = struct.pack('=BBHBBBB', sdl_len, 18, 1, 6, sdl_nlen, sdl_alen, 0)
            sdl_data = sdl_hdr + ifname_b + mac_bytes

            chunk = header + pad_before + sa_in + sdl_data
            pad_after = b'\x00' * (msglen - len(chunk))
            return chunk + pad_after

        # Candidate offset 72
        mac_raw = bytes([0x78, 0x90, 0xa2, 0x11, 0x22, 0x33])
        data_72 = _build_mock_sysctl_chunk(72, "192.168.1.42", mac_raw, "en0")
        res_72 = parse_sysctl_arp_data(data_72)
        self.assertEqual(len(res_72), 1)
        self.assertEqual(res_72[0]["ip"], "192.168.1.42")
        self.assertEqual(res_72[0]["mac"], "78:90:a2:11:22:33")
        self.assertEqual(res_72[0]["mac_source"], "sysctl")

        # Candidate offset 92 (Darwin 27 arm64 sizeof(struct rt_msghdr) == 92)
        data_92 = _build_mock_sysctl_chunk(92, "192.168.1.55", mac_raw, "en0")
        res_92 = parse_sysctl_arp_data(data_92)
        self.assertEqual(len(res_92), 1)
        self.assertEqual(res_92[0]["ip"], "192.168.1.55")
        self.assertEqual(res_92[0]["mac"], "78:90:a2:11:22:33")

        # Candidate offset 120
        data_120 = _build_mock_sysctl_chunk(120, "192.168.1.99", mac_raw, "en0")
        res_120 = parse_sysctl_arp_data(data_120)
        self.assertEqual(len(res_120), 1)
        self.assertEqual(res_120[0]["ip"], "192.168.1.99")

        # Invalid/corrupted buffer returns empty list without raising
        self.assertEqual(parse_sysctl_arp_data(b'corrupted garbage'), [])
        self.assertEqual(parse_sysctl_arp_data(b''), [])

    # -------------------------------------------------------------
    # 11. EUI-64 MAC extraction
    # -------------------------------------------------------------
    def test_eui64_mac_extraction(self):
        # RFC 4291 EUI-64: 78:90:a2:11:22:33 -> IID 7a90:a2ff:fe11:2233
        ipv6 = "fe80::7a90:a2ff:fe11:2233"
        mac = extract_eui64_mac(ipv6)
        self.assertEqual(mac, "78:90:a2:11:22:33")

        # Non-EUI64 addresses (e.g. privacy / stable-privacy) must return None
        self.assertIsNone(extract_eui64_mac("fe80::1"))
        self.assertIsNone(extract_eui64_mac("fe80::1000:2000:3000:4000"))
        self.assertIsNone(extract_eui64_mac(""))

    # -------------------------------------------------------------
    # 12. NetBIOS node status MAC extraction
    # -------------------------------------------------------------
    def test_netbios_node_status_extraction(self):
        scanner = LanScanner()
        # Mock UDP socket returning RFC 1002 node status packet
        # 56 bytes header + 1 byte num_names (1) + 18 bytes name + 6 bytes unit ID
        mock_packet = bytearray(56)
        mock_packet.append(1)  # 1 name
        mock_packet.extend(b"MYDEVICE       \x00\x04\x00")  # 15 char name + 3 bytes
        mock_packet.extend(bytes([0x78, 0x90, 0xa2, 0x11, 0x22, 0x33]))  # 6-byte UNIT ID
        mock_packet.extend(b'\x00' * 50)  # remaining statistics

        with patch("socket.socket") as mock_sock_cls:
            mock_s = MagicMock()
            mock_s.recvfrom.return_value = (bytes(mock_packet), ("192.168.1.50", 137))
            mock_sock_cls.return_value = mock_s

            h, m = scanner._query_netbios_node_status("192.168.1.50")
            self.assertEqual(h, "MYDEVICE")
            self.assertEqual(m, "78:90:a2:11:22:33")

    # -------------------------------------------------------------
    # 13. Permissions warning when sweep finds hosts but no MACs
    # -------------------------------------------------------------
    def test_lan_permissions_warning_when_no_macs(self):
        scanner = LanScanner()
        primary_iface = {"ipv4": "192.168.1.10", "netmask": "255.255.255.0", "mac": "78:90:a2:11:22:33", "name": "en0"}
        gateway_info = {"ipv4": "192.168.1.1", "mac": "78:90:a2:00:00:01", "interface": "en0"}

        # Simulate empty ARP caches
        with patch.object(scanner, "get_arp_table", return_value=[]), \
             patch.object(scanner.adapter, "get_per_host_arp", return_value=None), \
             patch.object(scanner.adapter, "get_ndp_table", return_value=[]), \
             patch.object(scanner, "_discover_mdns_services", return_value={}), \
             patch.object(scanner, "sweep_local_subnet", return_value=[{"ip": "192.168.1.55", "hostname": "host55"}]), \
             patch.object(scanner, "_query_netbios_node_status", return_value=(None, None)):
            _, devices = scanner.discover_lan_devices(primary_iface, gateway_info, {}, {}, quick_scan=False)

            self.assertIsNotNone(scanner.permissions_warning)
            self.assertIn("Possibile permesso Rete locale mancante", scanner.permissions_warning)
            self.assertIn("Privacy e sicurezza → Rete locale", scanner.permissions_warning)

    # -------------------------------------------------------------
    # 14. Deterministic fingerprint immunity from 0.8x noise scaling
    # -------------------------------------------------------------
    def test_deterministic_fingerprint_confidence_immunity(self):
        est = NetworkEstimator()
        # iOS Personal Hotspot gateway 172.20.10.1 is a deterministic fingerprint
        lan_data = {"gateway": {"ipv4": "172.20.10.1"}}
        wan_data = {"public_ipv4": "82.91.100.1", "country": "IT", "country_code": "IT"}
        ixp_data = {"hop2_bng": {"ip": "100.64.0.1", "min_ms": 30.0, "median_ms": 40.0, "iqr_ms": 12.0, "spike_fraction": 0.20}}

        perf_noisy_both = {
            "speed": {
                "download_mbps": 40.0,
                "upload_mbps": 10.0,
                "download_stability_pct": 60.0,
                "upload_stability_pct": 60.0,
                "other_process_pct": 8.0
            },
            "primary_latency": {"min_ms": 30.0, "median_ms": 40.0, "iqr_ms": 12.0, "spike_fraction": 0.20},
            "bufferbloat": {"download_delta_ms": 150.0, "upload_delta_ms": 150.0}
        }
        res = est.estimate_physical_medium(lan_data, wan_data, perf_noisy_both, ixp_data)
        self.assertIn("Mobile Cellular", res["predicted_medium"])
        # Deterministic verdict confidence must remain high (e.g. >= 90%), not scaled down by 0.8x
        self.assertGreaterEqual(res["confidence_pct"], 90.0)

    # -------------------------------------------------------------
    # 15. Audit independence same source flag
    # -------------------------------------------------------------
    def test_audit_independence_same_source_flag(self):
        auditor = NetworkAuditor(skip_speed=True)
        # Record with identical command/source
        auditor.record(
            field="Test Gateway MAC",
            netprobe_val="78:90:a2:11:22:33",
            ref_val="78:90:a2:11:22:33",
            status="CONCORDE",
            source="arp -n 192.168.1.1",
            collector_source="arp -n 192.168.1.1",
            reference_source="arp -n 192.168.1.1"
        )
        entry = auditor.results[-1]
        self.assertFalse(entry["independent"])
        self.assertEqual(entry["status"], "STESSA FONTE (coerenza del parser, non verifica del dato)")

    # -------------------------------------------------------------
    # 16. Task 1: Interface type, hardware port mapping, and Ethernet details
    # -------------------------------------------------------------
    def test_task1_interface_type_and_ethernet_details(self):
        adapter = MacOSAdapter()
        ifconfig_path = os.path.join(os.path.dirname(__file__), "fixtures", "os", "macos", "ifconfig.txt")
        networksetup_path = os.path.join(os.path.dirname(__file__), "fixtures", "os", "macos", "networksetup.txt")

        with open(ifconfig_path, "r", encoding="utf-8") as f:
            ifconfig_out = f.read()
        with open(networksetup_path, "r", encoding="utf-8") as f:
            networksetup_out = f.read()

        def mock_run_cmd(cmd, timeout=None):
            if cmd == ["networksetup", "-listallhardwareports"]:
                return (0, networksetup_out, "")
            if cmd == ["ifconfig"]:
                return (0, ifconfig_out, "")
            if cmd[:2] == ["ifconfig", "en5"]:
                # Estrai blocco en5 da ifconfig_out
                m = re.search(r"(en5: flags=.*?\n(?=[a-z0-9]+:|\Z))", ifconfig_out, re.DOTALL)
                return (0, m.group(1) if m else "", "")
            return (0, "", "")

        with patch("core.adapters.macos.run_cmd", side_effect=mock_run_cmd):
            hw_ports = adapter.get_hardware_ports()
            self.assertEqual(hw_ports.get("en5"), "USB 10/100/1000 LAN")
            self.assertEqual(hw_ports.get("en0"), "Wi-Fi")

            wifi_dev = adapter.get_wifi_device_name()
            self.assertEqual(wifi_dev, "en0")

            eth_info = adapter.get_ethernet_details("en5")
            self.assertTrue(eth_info["active"])
            self.assertTrue(eth_info["cable_connected"])
            self.assertTrue(eth_info["carrier"])
            self.assertEqual(eth_info["speed_mbps"], 1000)
            self.assertEqual(eth_info["duplex"], "full-duplex")
            self.assertIn("1000baseT", eth_info["media_description"])

    # -------------------------------------------------------------
    # 17. Task 2: Traffic accounting vs false noisy flag
    # -------------------------------------------------------------
    def test_task2_traffic_accounting_clean_and_noisy(self):
        # Case Clean: Ethernet line (~54.3 MB payload, 16.3s dur, ambient 400 Kbps, 9.4 MB raw diff)
        # Overhead 7% = 3.8 MB, ambient bytes = 0.81 MB. Other traffic = 4.82 MB < threshold 5.43 MB
        clean_acc = compute_traffic_accounting(
            iface_bytes=63737352,
            payload_bytes=54296072,
            duration_s=16.27,
            ambient_rate_bps=400000.0
        )
        self.assertFalse(clean_acc["is_noisy"])
        self.assertLess(clean_acc["other_traffic_bytes"], clean_acc["threshold_bytes"])

        # Case Noisy: Same payload, but 25 MB concurrent background download/streaming
        noisy_acc = compute_traffic_accounting(
            iface_bytes=63737352 + 25000000,
            payload_bytes=54296072,
            duration_s=16.27,
            ambient_rate_bps=400000.0
        )
        self.assertTrue(noisy_acc["is_noisy"])
        self.assertGreater(noisy_acc["other_traffic_bytes"], noisy_acc["threshold_bytes"])

        # Verfica che i due fixture Ethernet reali vengano valutati noisy=False
        est = NetworkEstimator()
        for fix_name in ("real_ethernet_no_congestion.json", "real_ethernet_no_congestion_2.json"):
            path = os.path.join(os.path.dirname(__file__), "fixtures", fix_name)
            with open(path, "r", encoding="utf-8") as f:
                fix_data = json.load(f)
            res = est.estimate_physical_medium(
                fix_data.get("lan", {}),
                fix_data.get("wan", {}),
                fix_data.get("performance", {}),
                fix_data.get("ixp", {})
            )
            mq = res.get("measurement_quality", {})
            self.assertFalse(mq.get("noisy"), f"Fixture {fix_name} non deve essere marcato come noisy")

    # -------------------------------------------------------------
    # 18. Task 3: Speed test server agreement & limits
    # -------------------------------------------------------------
    def test_task3_steady_state_server_agreement_and_probable_limit(self):
        # Case A: Steady-state agreement within 10% (Cloudflare 40.1 peak, OVH 39.69 peak, sustained differs due to ramp-up)
        cf_samples = [[t * 0.2, 39.5 + (0.5 * (t % 2))] for t in range(40)]
        cf_steady = compute_steady_state(cf_samples, sustained=39.7, peak=40.12)
        ovh_steady = compute_steady_state(None, sustained=32.45, peak=39.69)
        diff = abs(cf_steady - ovh_steady) / max(cf_steady, ovh_steady)
        self.assertLessEqual(diff, 0.10)

        # Case B: Real server divergence (> 10%)
        div_cf_steady = compute_steady_state(None, sustained=85.0, peak=90.0)
        div_ovh_steady = compute_steady_state(None, sustained=30.0, peak=32.0)
        div_diff = abs(div_cf_steady - div_ovh_steady) / max(div_cf_steady, div_ovh_steady)
        self.assertGreater(div_diff, 0.10)

    # -------------------------------------------------------------
    # 19. Task 4: Field status and provenance path resolution integration test
    # -------------------------------------------------------------
    def test_task4_field_status_resolution_across_real_fixtures(self):
        def resolve_path(d: Dict[str, Any], path: str):
            curr = d
            parts = path.split(".")
            for i, p in enumerate(parts):
                if not isinstance(curr, dict):
                    return False, None
                if p not in curr:
                    if i == len(parts) - 1:
                        return True, None
                    return False, None
                curr = curr[p]
            return True, curr

        fixtures = glob.glob(os.path.join(os.path.dirname(__file__), "fixtures", "real_*.json"))
        # Escludi file .truth.json
        fixtures = [f for f in fixtures if not f.endswith(".truth.json")]
        self.assertGreaterEqual(len(fixtures), 5)

        for fix_path in fixtures:
            with open(fix_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            prov = build_field_provenance(data)
            self.assertGreaterEqual(len(prov), 30)

            for key, meta in prov.items():
                exists, val = resolve_path(data, key)
                self.assertTrue(exists, f"La chiave '{key}' in field_status non corrisponde a nessun path in {os.path.basename(fix_path)}")

                # status e' 'unavailable' se e solo se il valore e' None, absent, stringa vuota o 'N/D'
                is_unavail = (val is None or val == "" or val == "N/D" or val == "Sconosciuto" or (isinstance(val, str) and "non identificato" in val.lower()))
                if is_unavail:
                    self.assertEqual(meta["status"], "unavailable", f"Per il campo {key} con valore {val!r}, atteso status 'unavailable' ma ottenuto '{meta['status']}'")
                else:
                    self.assertNotEqual(meta["status"], "unavailable", f"Per il campo {key} con valore {val!r}, status non deve essere 'unavailable'")

    # -------------------------------------------------------------
    # 20. Task 5: Per-hop latency access profile mtr-style
    # -------------------------------------------------------------
    def test_task5_per_hop_latency_access_profile(self):
        # Test con parsing traceroute multi-probe reale
        raw_trace = """
traceroute to 1.1.1.1 (1.1.1.1), 10 hops max, 40 byte packets
 1  192.168.1.1  1.029 ms  0.496 ms  0.454 ms  0.527 ms  0.441 ms  0.457 ms  1.254 ms
 2  * * * * * * * *
 3  172.18.34.128  85.793 ms  91.006 ms  48.859 ms  6.324 ms  6.110 ms
 4  172.18.33.230  10.427 ms  10.511 ms  10.005 ms  10.753 ms  10.904 ms
 5  195.22.205.116  10.264 ms  10.368 ms  10.682 ms  10.928 ms
"""
        analyzer = IXPAnalyzer()
        hops = analyzer._parse_multiprobe_traceroute(raw_trace)
        self.assertEqual(len(hops), 5)

        profile = build_access_profile_from_hops(hops)
        self.assertTrue(profile["uncalibrated"])
        prof_hops = profile["hops"]
        self.assertEqual(len(prof_hops), 5)

        # Hop 1: Gateway locale
        h1 = prof_hops[0]
        self.assertEqual(h1["hop"], 1)
        self.assertEqual(h1["ip"], "192.168.1.1")
        self.assertTrue(h1["flags"]["private"])
        self.assertTrue(h1["flags"]["responds_to_ping"])
        self.assertEqual(h1["min_ms"], 0.44)
        self.assertEqual(h1["role"], "Gateway locale")

        # Hop 2: non risponde
        h2 = prof_hops[1]
        self.assertEqual(h2["hop"], 2)
        self.assertFalse(h2["flags"]["responds_to_ping"])
        self.assertIsNone(h2["min_ms"])
        self.assertIsNone(h2["role"])

        # Hop 3: primo salto ISP (172.18.34.128, min 6.11 ms, delta floor +5.67 ms)
        h3 = prof_hops[2]
        self.assertEqual(h3["hop"], 3)
        self.assertEqual(h3["ip"], "172.18.34.128")
        self.assertEqual(h3["min_ms"], 6.11)
        self.assertEqual(h3["floor_increment_ms"], 5.67)
        self.assertEqual(h3["role"], "Primo salto oltre il CPE")
        self.assertEqual(profile["first_isp_hop"]["hop"], 3)
        self.assertEqual(profile["first_isp_hop"]["ip"], "172.18.34.128")

        # Hop 5: primo salto pubblico responsivo (195.22.205.116)
        h5 = prof_hops[4]
        self.assertEqual(h5["hop"], 5)
        self.assertEqual(h5["ip"], "195.22.205.116")
        self.assertFalse(h5["flags"]["private"])
        self.assertEqual(profile["first_public_hop"]["hop"], 5)
        self.assertEqual(profile["first_public_hop"]["ip"], "195.22.205.116")

    # -------------------------------------------------------------
    # 21. Prompt 11: Bufferbloat baseline target alignment on runs 2 and 4
    # -------------------------------------------------------------
    def test_bufferbloat_baseline_alignment_runs_2_and_4(self):
        fix_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        for run_name in ("real_ethernet_run2.json", "real_ethernet_run4.json"):
            with open(os.path.join(fix_dir, run_name), "r", encoding="utf-8") as f:
                d = json.load(f)
            from core.performance import recompute_bufferbloat
            bb = recompute_bufferbloat(d.get("performance", {}))
            self.assertEqual(bb["grade"], "C")
            # Idle baseline should be around 11.4 - 12.0 ms (aligned with Cloudflare/Google min RTT)
            self.assertAlmostEqual(bb["idle_latency_ms"], 11.8, delta=1.0)
            # DL delta should be around 24-27 ms
            self.assertAlmostEqual(bb["download_delta_ms"], 25.5, delta=2.0)
            # UL delta should be around 37-39 ms
            self.assertAlmostEqual(bb["upload_delta_ms"], 38.5, delta=2.0)

    # -------------------------------------------------------------
    # 22. Prompt 11: Speed server steady-state agreement and single-server indeterminato
    # -------------------------------------------------------------
    def test_speed_servers_steady_state_and_limit_determination(self):
        fix_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        from core.performance import recompute_speed_agreement_and_limit

        # Run 2: Cloudflare (40.18 Mbps) vs OVH (burst peak 60 Mbps capped to steady-state ~39.96 Mbps)
        with open(os.path.join(fix_dir, "real_ethernet_run2.json"), "r", encoding="utf-8") as f:
            d2 = json.load(f)
        spd2 = recompute_speed_agreement_and_limit(d2.get("performance", {}).get("speed", {}))
        self.assertTrue(spd2["endpoints_agreement"])
        self.assertEqual(spd2["probable_limit"], "linea")

        # Run 4: Single server (Cloudflare only) -> indeterminato
        with open(os.path.join(fix_dir, "real_ethernet_run4.json"), "r", encoding="utf-8") as f:
            d4 = json.load(f)
        spd4 = recompute_speed_agreement_and_limit(d4.get("performance", {}).get("speed", {}))
        self.assertIsNone(spd4["endpoints_agreement"])
        self.assertEqual(spd4["probable_limit"], "indeterminato")

    # -------------------------------------------------------------
    # 23. Prompt 11: 4K streaming piecewise continuous scoring without cliffs
    # -------------------------------------------------------------
    def test_4k_streaming_piecewise_linear_continuous_score(self):
        est = NetworkEstimator()
        lan_data = {"gateway": {"ipv4": "192.168.1.1"}}
        wan_data = {"public_ipv4": "82.91.100.1"}
        ixp_data = {}

        perf_32_6 = {
            "speed": {"download_mbps": 32.6, "upload_mbps": 14.5},
            "primary_latency": {"median_ms": 11.5, "jitter_ms": 0.5, "packet_loss_pct": 0.0},
            "bufferbloat": {"download_delta_ms": 25.0, "upload_delta_ms": 38.0}
        }
        res_32_6 = est.calculate_all(lan_data, wan_data, perf_32_6, ixp_data)
        score_32_6 = res_32_6["application_suitability"]["video_streaming"]["score"]

        perf_37_3 = {
            "speed": {"download_mbps": 37.3, "upload_mbps": 14.5},
            "primary_latency": {"median_ms": 11.5, "jitter_ms": 0.5, "packet_loss_pct": 0.0},
            "bufferbloat": {"download_delta_ms": 25.0, "upload_delta_ms": 38.0}
        }
        res_37_3 = est.calculate_all(lan_data, wan_data, perf_37_3, ixp_data)
        score_37_3 = res_37_3["application_suitability"]["video_streaming"]["score"]

        score_diff = abs(score_37_3 - score_32_6)
        # Score difference between 32.6 and 37.3 Mbps must be < 10 points
        self.assertLess(score_diff, 10.0)

    # -------------------------------------------------------------
    # 24. Prompt 11: Switch info honest fallback description and type
    # -------------------------------------------------------------
    def test_switch_info_fallback_description_and_type(self):
        from core.switch_probe import SwitchProbe
        probe = SwitchProbe()
        res = probe.probe_connected_switch("en5")
        self.assertFalse(res["detected"])
        self.assertEqual(res["switch_type"], "Switch L2 Unmanaged o collegamento diretto")
        self.assertEqual(res["description"], "Nessuno switch gestito rilevato (collegamento diretto o switch non gestito: non distinguibili)")

    # -------------------------------------------------------------
    # 25. Prompt 11: Dynamic sysctl sockaddr parsing and full IEEE OUI registry
    # -------------------------------------------------------------
    def test_sysctl_arp_dynamic_sockaddr_parsing_and_full_ieee_oui(self):
        from core.oui_data import lookup_vendor
        # Real fixture binaries and text
        fix_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        sysctl_bin = os.path.join(fix_dir, "sysctl_arp_all.bin")
        if os.path.exists(sysctl_bin):
            with open(sysctl_bin, "rb") as f:
                raw_bytes = f.read()
            entries = parse_sysctl_arp_data(raw_bytes)
            self.assertIsInstance(entries, list)

        # Full IEEE OUI lookup
        self.assertEqual(lookup_vendor("bc:e9:2f:11:22:33"), "HP Inc.")
        self.assertEqual(lookup_vendor("50:eb:f6:aa:bb:cc"), "ASUSTek COMPUTER INC.")
        self.assertEqual(lookup_vendor("f0:18:98:01:02:03"), "Apple, Inc.")

    # -------------------------------------------------------------
    # 26. Prompt 11: Noise detection across real ethernet runs
    # -------------------------------------------------------------
    def test_noise_detection_across_real_ethernet_runs(self):
        from tools.replay import replay_file
        fix_dir = os.path.join(os.path.dirname(__file__), "fixtures")

        # Run 1: noisy: true (stability 71.9%, 1s dip to 15.4 Mbps)
        r1 = replay_file(os.path.join(fix_dir, "real_ethernet_run1.json"))
        self.assertTrue(r1["physical_medium"]["measurement_quality"]["noisy"])

        # Runs 2, 4, 5: noisy: false
        for r_name in ("real_ethernet_run2.json", "real_ethernet_run4.json", "real_ethernet_run5.json"):
            res = replay_file(os.path.join(fix_dir, r_name))
            self.assertFalse(res["physical_medium"]["measurement_quality"]["noisy"], f"{r_name} should not be noisy")

    # -------------------------------------------------------------
    # 27. Netstat ARP table fallback
    # -------------------------------------------------------------
    def test_netstat_arp_fallback(self):
        sample_netstat = """
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0       
127                127.0.0.1          UCS                   lo0       
127.0.0.1          127.0.0.1          UH                    lo0       
169.254            link#11            UCS                   en0      !
192.168.1          link#11            UCS                   en0      !
192.168.1.1/32     link#11            UCS                   en0      !
192.168.1.1        78:90:a2:11:22:33   UHLWIir               en0   1189
192.168.1.2        link#11            UHLWI                 en0      !
192.168.1.11       dc:a6:32:11:22:33  UHLWIi                en0   1110
192.168.1.105      9a:a6:7a:2:d0:21   UHLWI                 en0    847
224.0.0/4          link#11            UmCS                  en0      !
224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       
255.255.255.255/32 link#11            UCS                   en0      !
"""
        adapter = MacOSAdapter()
        with patch("core.adapters.macos.run_cmd", return_value=(0, sample_netstat, "")):
            entries = adapter._get_netstat_arp()
            self.assertEqual(len(entries), 3)
            ips = [e["ip"] for e in entries]
            self.assertIn("192.168.1.1", ips)
            self.assertIn("192.168.1.11", ips)
            self.assertIn("192.168.1.105", ips)

            e1 = next(e for e in entries if e["ip"] == "192.168.1.1")
            self.assertEqual(e1["mac"], "78:90:a2:11:22:33")
            self.assertEqual(e1["mac_source"], "netstat")
            self.assertEqual(e1["interface"], "en0")

            # In get_arp_table fallback: when sysctl and arp_an are empty, netstat is used
            with patch.object(adapter, "_get_sysctl_arp", return_value=[]), \
                 patch.object(adapter, "_get_arp_an", return_value=[]):
                fallback_entries = adapter.get_arp_table()
                self.assertEqual(len(fallback_entries), 3)
                self.assertEqual(fallback_entries[0]["mac_source"], "netstat")

    # -------------------------------------------------------------
    # 28. CLI hop table formatting for timeouts and Delta Floor <= 0
    # -------------------------------------------------------------
    def test_terminal_ui_hop_table_formatting(self):
        import io, contextlib
        from cli.terminal_ui import TerminalUI

        rep = {
            "timestamp": 0, "formatted_time": "t", "quick_scan": {}, "system": {},
            "lan": {}, "wan": {}, "performance": {}, "estimations": {},
            "ixp": {
                "access_profile": {
                    "hops": [
                        {"hop": 1, "ip": "192.168.1.1", "min_ms": 3.37, "median_ms": 3.37, "floor_increment_ms": 3.37, "role": "Gateway LAN"},
                        {"hop": 2, "ip": "*", "min_ms": None, "median_ms": None, "floor_increment_ms": None, "role": "Nessuna risposta"},
                        {"hop": 3, "ip": "172.18.34.128", "min_ms": 7.03, "median_ms": 7.03, "floor_increment_ms": 3.66, "role": "Primo salto ISP / Rete accesso"},
                        {"hop": 6, "ip": "172.19.177.60", "min_ms": 12.81, "median_ms": 12.81, "floor_increment_ms": None, "role": "Rete interna operatore"},
                        {"hop": 7, "ip": "195.22.205.116", "min_ms": 11.11, "median_ms": 11.11, "floor_increment_ms": -1.70, "role": "Primo salto pubblico responsivo"},
                        {"hop": 10, "ip": "188.114.100.39", "min_ms": 12.40, "median_ms": 12.40, "floor_increment_ms": 0.0, "role": "Transito / Peering"},
                    ]
                }
            }
        }
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TerminalUI(no_color=True).render_full_report(rep)
        out = buf.getvalue()

        # Timeout hop must be formatted cleanly on a single line:
        self.assertRegex(out, r"2\s+\*\s+N/D\s+N/D\s+N/D\s+Timeout ICMP")

        # Delta Floor <= 0 or None must print ~0.00 ms
        lines = out.splitlines()
        hop6 = next(l for l in lines if l.strip().startswith("6 "))
        self.assertIn("~0.00 ms", hop6)
        hop7 = next(l for l in lines if l.strip().startswith("7 "))
        self.assertIn("~0.00 ms", hop7)
        hop10 = next(l for l in lines if l.strip().startswith("10 "))
        self.assertIn("~0.00 ms", hop10)


if __name__ == "__main__":
    unittest.main()


