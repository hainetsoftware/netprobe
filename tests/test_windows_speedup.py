"""Regression coverage for bounded discovery and run-scoped trace caching."""
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
import socket
import concurrent.futures
import time
import unittest
from unittest.mock import MagicMock, patch

from core.interfaces import is_virtual_or_secondary_interface
from core.lan_scanner import LanScanner
from core.ixp_analyzer import IXPAnalyzer
from core.storage import StorageManager
from core.wan_probe import WanProbe
from core.adapters.windows import WindowsAdapter
from core.performance import PerformanceTester
from core.windows_ping import echo_burst


class DiscoveryTests(unittest.TestCase):
    def test_virtual_names_descriptions_and_apipa(self):
        for name in ('VirtualBox', 'VMware', 'Hyper-V', 'vEthernet', 'Host-Only',
                     'WSL', 'TAP-Windows', 'WireGuard', 'Tailscale', 'Loopback',
                     'Pseudo-Interface'):
            self.assertTrue(is_virtual_or_secondary_interface(name.upper(), '', '10.0.0.2'))
            self.assertTrue(is_virtual_or_secondary_interface('Ethernet 2', name, '10.0.0.2'))
        self.assertTrue(is_virtual_or_secondary_interface('Ethernet', '', '169.254.1.2'))
        self.assertFalse(is_virtual_or_secondary_interface('Ethernet', 'Intel', '192.168.1.2'))

    def test_virtual_adapters_remain_in_report_but_are_not_primary(self):
        scanner = LanScanner.__new__(LanScanner)
        scanner.adapter = MagicMock()
        scanner.adapter.get_wifi_device_name.return_value = 'Wi-Fi'
        scanner.adapter.get_arp_diagnostics.return_value = {}
        scanner.permissions_warning = None
        interfaces = {
            'vEthernet': {'name': 'vEthernet', 'ipv4': '172.22.0.1', 'is_up': True},
            'Wi-Fi': {'name': 'Wi-Fi', 'ipv4': '192.168.1.2', 'is_up': True, 'type': 'Wi-Fi'},
        }
        methods = {
            'get_default_gateway': {'interface': 'vEthernet', 'ipv4': '172.22.0.2'},
            'get_network_interfaces': interfaces,
            'get_wifi_details': {'connected': True}, 'get_ethernet_details': {},
            'get_dhcp_info': {}, 'get_dns_configuration': {'resolvers': []},
            'benchmark_dns': {}, 'discover_lan_devices': ({}, []), 'get_arp_table': [],
        }
        with ExitStack() as stack:
            stack.enter_context(patch('core.lan_scanner.identify_router', return_value={}))
            for method, value in methods.items():
                stack.enter_context(patch.object(scanner, method, return_value=value))
            report = scanner.scan_all()
        self.assertEqual(report['primary_interface_name'], 'Wi-Fi')
        self.assertIs(report['all_interfaces'], interfaces)
        self.assertIn('vEthernet', report['all_interfaces'])

    def test_sweep_obeys_small_subnet_and_closes_sockets(self):
        scanner = LanScanner.__new__(LanScanner)
        scanner.get_arp_table = MagicMock(return_value=[{'ip': '10.0.0.6'}, {'ip': '192.168.1.1'}])
        scanner._fast_reverse_dns = MagicMock(return_value=None)
        sock = MagicMock()
        sock.connect_ex.return_value = 10061
        with patch('core.lan_scanner.socket.socket', return_value=sock), \
                patch('core.lan_scanner.concurrent.futures.ThreadPoolExecutor', wraps=concurrent.futures.ThreadPoolExecutor) as pool:
            hosts = scanner.sweep_local_subnet('10.0.0.5', '/30')
        self.assertEqual([h['ip'] for h in hosts], ['10.0.0.6'])
        pool.assert_any_call(max_workers=64)
        sock.bind.assert_called_with(('10.0.0.5', 0))
        self.assertLessEqual(sock.settimeout.call_args.args[0], 0.15)
        sock.close.assert_called_once()
        with patch('core.lan_scanner.socket.socket') as factory:
            self.assertEqual(scanner.sweep_local_subnet('169.254.1.2', '/24'), [])
            self.assertEqual(scanner.sweep_local_subnet('10.0.0.5', None), [])
            factory.assert_not_called()

    def test_windows_dns_only_uses_selected_physical_adapter(self):
        output = '''Windows IP Configuration
Ethernet adapter Lab:
   Description . . . : VMware Virtual Ethernet Adapter
   DNS Servers . . . : 10.0.0.1
Ethernet adapter Ethernet:
   Description . . . : Intel Ethernet
   DNS Servers . . . : 192.168.1.1
Ethernet adapter Unconfigured:
   Autoconfiguration IPv4 Address . . . : 169.254.1.2
   DNS Servers . . . : 10.1.0.1
'''
        with patch('core.adapters.windows.iphlpapi', None), \
                patch('core.adapters.windows.run_cmd', return_value=(0, output, '')):
            adapter = WindowsAdapter()
            self.assertEqual(adapter.get_dns_configuration()['resolvers'], ['192.168.1.1'])
            self.assertEqual(adapter.get_dns_configuration('Ethernet')['resolvers'], ['192.168.1.1'])
            self.assertEqual(adapter.get_dns_configuration('Lab')['resolvers'], [])

    def test_virtual_discovery_performs_no_active_queries(self):
        scanner = LanScanner.__new__(LanScanner)
        with patch.object(scanner, '_discover_mdns_services') as mdns, \
                patch.object(scanner, 'sweep_local_subnet') as sweep, \
                patch.object(scanner, 'get_arp_table') as arp:
            _, devices = scanner.discover_lan_devices(
                {'name': 'Ethernet 2', 'description': 'VirtualBox', 'ipv4': '10.0.0.2'}, {}, {}, {})
        self.assertEqual(devices, [])
        mdns.assert_not_called()
        sweep.assert_not_called()
        arp.assert_not_called()

    def test_ssdp_binds_primary_and_has_aggregate_budget(self):
        clock = [0.0]
        sockets = []

        def factory(*args):
            sock = MagicMock()
            def receive(*args):
                clock[0] += sock.settimeout.call_args.args[0]
                raise socket.timeout()
            sock.recvfrom.side_effect = receive
            sockets.append(sock)
            return sock

        with patch('core.wan_probe.socket.socket', side_effect=factory), \
                patch('core.wan_probe.time.monotonic', side_effect=lambda: clock[0]):
            result = WanProbe().probe_upnp_and_nat_pmp('192.168.1.1', '192.168.1.2')
        self.assertLessEqual(clock[0], 1.5)
        self.assertFalse(result['upnp_igd_available'])
        for sock in sockets:
            sock.bind.assert_called_once_with(('192.168.1.2', 0))
            sock.close.assert_called_once()
        sockets[0].setsockopt.assert_called_once_with(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('192.168.1.2'))
        with patch('core.wan_probe.socket.socket') as factory:
            WanProbe().probe_upnp_and_nat_pmp('192.168.1.1')
            factory.assert_not_called()


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = IXPAnalyzer.__new__(IXPAnalyzer)

    def test_shared_cache_reduces_probes_and_secondary_stops_after_hop_four(self):
        calls = Counter()
        def probe(target, max_hops, **kwargs):
            calls[target, max_hops] += 1
            self.assertEqual(kwargs['timeout_s'], 0.5)
            ip = '*' if max_hops == 2 or max_hops > 4 else '192.168.1.1'
            return [{'hop': max_hops, 'ip': ip, 'rtts': [] if ip == '*' else [1.0]}]
        silent = set()
        with patch.object(self.analyzer, '_icmp_ttl_stepping_traceroute', side_effect=probe), \
                patch.dict('os.environ', {'NETPROBE_SPEED_HOST': ''}):
            self.analyzer._measure_cached_profile('primary', 10, 3, silent, False, time.monotonic() + 10)
            secondary = self.analyzer._measure_cached_profile('secondary', 10, 3, silent, True, time.monotonic() + 10)
        self.assertEqual(calls['primary', 2], 3)
        self.assertEqual(calls['secondary', 2], 1)
        self.assertEqual(calls['secondary', 3], 3)
        self.assertEqual(secondary['hops'][-1]['hop'], 7)
        self.assertEqual(calls['secondary', 8], 0)

    def test_expired_deadline_sends_no_probes(self):
        with patch.object(self.analyzer, '_icmp_ttl_stepping_traceroute') as probe:
            self.analyzer._measure_cached_profile('target', 15, 3, set(), True, time.monotonic() - 1)
            probe.assert_not_called()

    def test_cache_is_shared_within_one_run_and_reset_for_the_next(self):
        primaries = []
        def profile(target, max_hops, probes, silent, secondary, deadline):
            if not secondary:
                self.assertEqual(silent, set())
                primaries.append(silent)
                silent.add(2)
            else:
                self.assertIn(2, silent)
            return {'hops': [{'hop': 1, 'ip': '192.168.1.1', 'rtts': [1]}]}
        targets = [{'id': 'primary', 'ip': '1.1.1.1'}, {'id': 'secondary', 'ip': '8.8.8.8'}]
        with patch.object(self.analyzer, '_measure_cached_profile', side_effect=profile):
            for _ in range(2):
                paths = self.analyzer.probe_parallel_targets(targets)['raw_paths']
                self.assertEqual(set(paths), {'primary', 'secondary'})
        self.assertIsNot(primaries[0], primaries[1])

    def test_windows_tracert_fallback_limits(self):
        with patch('core.ixp_analyzer.is_windows', return_value=True), \
                patch('core.ixp_analyzer.is_macos', return_value=False), \
                patch('core.ixp_analyzer.run_cmd', return_value=(0, '1 1 ms 1 ms 1 ms 192.168.1.1', '')) as run:
            self.analyzer.measure_access_profile('1.1.1.1', max_hops=30)
        self.assertEqual(run.call_args.args[0], ['tracert', '-d', '-w', '500', '-h', '15', '1.1.1.1'])


class WindowsPingTests(unittest.TestCase):
    def test_single_probe_burst_has_bounded_intervals_and_actual_sent_count(self):
        clock = [0.0]
        def run(cmd, timeout):
            self.assertEqual(cmd[:3], ['ping', '-n', '1'])
            self.assertLessEqual(timeout, 0.5)
            clock[0] += 0.02
            return 0, 'Reply from 192.168.1.1: bytes=32 time=1ms TTL=64', ''
        with patch('core.windows_ping.time.monotonic', side_effect=lambda: clock[0]), \
                patch('core.windows_ping.time.sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            outputs, sent = echo_burst('192.168.1.1', 12, 0.25, run)
        self.assertEqual(sent, 3)
        self.assertEqual(len(outputs), sent)
        self.assertLessEqual(clock[0], 0.25)

    def test_windows_ping_summary_is_not_counted_as_extra_replies(self):
        output = '''Reply from 192.168.1.1: bytes=32 time=5ms TTL=64
Minimum = 5ms, Maximum = 5ms, Average = 5ms
'''
        tester = PerformanceTester()
        self.assertEqual(tester._parse_windows_ping(output)[0], [5.0])
        self.assertEqual(IXPAnalyzer._parse_ping_times(output), [5.0])
        with patch('core.performance.is_macos', return_value=False), \
                patch('core.performance.is_linux', return_value=False), \
                patch('core.performance.is_windows', return_value=True), \
                patch('core.windows_ping.echo_burst', return_value=([output, 'Request timed out.'], 2)):
            result = tester.ping_host('192.168.1.1', count=2)
        self.assertEqual(result['samples_count'], 1)
        self.assertEqual(result['packet_loss_pct'], 50.0)


class FolderTests(unittest.TestCase):
    def test_native_openers_and_failure(self):
        storage = StorageManager.__new__(StorageManager)
        storage.db_path = Path('unused') / 'netprobe.db'
        with patch.object(Path, 'mkdir'), patch('core.storage.os.startfile', create=True) as start, \
                patch('core.storage.subprocess.run') as run:
            for platform, command in (('darwin', 'open'), ('linux', 'xdg-open')):
                with patch('core.storage.sys.platform', platform):
                    self.assertTrue(storage.open_storage_dir())
                    run.assert_called_with([command, str(storage.db_path.parent)], check=True)
            with patch('core.storage.sys.platform', 'win32'):
                self.assertTrue(storage.open_storage_dir())
                start.assert_called_once_with(str(storage.db_path.parent))
                start.side_effect = OSError('unavailable')
                self.assertFalse(storage.open_storage_dir())

    def test_cli_exits_before_dependency_bootstrap(self):
        import netprobe
        with patch('sys.argv', ['netprobe.py', '--open-db']), \
                patch('core.storage.StorageManager') as storage, \
                patch('core.bootstrap.ensure_dependencies') as bootstrap:
            with self.assertRaises(SystemExit) as exited:
                netprobe.main()
        self.assertEqual(exited.exception.code, 0)
        storage.return_value.open_storage_dir.assert_called_once()
        bootstrap.assert_not_called()
