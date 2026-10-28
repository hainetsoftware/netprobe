"""Cross-platform names, canonical header bindings and emoji-free views."""
import contextlib
import io
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch

from cli.terminal_ui import TerminalUI
from core.platform_info import get_system_summary
from core.system_info import format_system_header, get_pretty_os_info


class SystemInfoTests(unittest.TestCase):
    def test_macos_marketing_version_and_architecture(self):
        for arch in ('arm64', 'x86_64'):
            with self.subTest(arch=arch), \
                 patch('core.system_info.platform.system', return_value='Darwin'), \
                 patch('core.system_info.platform.machine', return_value=arch), \
                 patch('core.system_info.platform.mac_ver', return_value=('15.1', (), '')), \
                 patch('core.system_info.subprocess.run') as command:
                self.assertEqual(get_pretty_os_info(), f'macOS 15.1 ({arch})')
                command.assert_not_called()

    def test_macos_sw_vers_fallback(self):
        with patch('core.system_info.platform.system', return_value='Darwin'), \
             patch('core.system_info.platform.machine', return_value='arm64'), \
             patch('core.system_info.platform.mac_ver', return_value=('', (), '')), \
             patch('core.system_info.subprocess.run', return_value=SimpleNamespace(stdout='26.1\n')) as command:
            self.assertEqual(get_pretty_os_info(), 'macOS 26.1 (arm64)')
            self.assertEqual(command.call_args.args[0], ['/usr/bin/sw_vers', '-productVersion'])

    def test_macos_plist_fallback(self):
        with patch('core.system_info.platform.system', return_value='Darwin'), \
             patch('core.system_info.platform.machine', return_value='x86_64'), \
             patch('core.system_info.platform.mac_ver', return_value=('', (), '')), \
             patch('core.system_info.subprocess.run', side_effect=subprocess.TimeoutExpired('sw_vers', 3)), \
             patch('builtins.open', mock_open(read_data=b'<plist/>')), \
             patch('core.system_info.plistlib.load', return_value={'ProductVersion': '14.7'}):
            self.assertEqual(get_pretty_os_info(), 'macOS 14.7 (x86_64)')

    def test_windows_release_build_and_service_pack(self):
        for major, minor, build, service, expected in (
            (6, 1, 7601, 'Service Pack 1', 'Windows 7 Service Pack 1 Build 7601'),
            (6, 2, 9200, '', 'Windows 8 Build 9200'),
            (6, 3, 9600, '', 'Windows 8.1 Build 9600'),
            (10, 0, 21999, '', 'Windows 10 Build 21999'),
            (10, 0, 22000, '', 'Windows 11 Build 22000'),
            (10, 0, 26100, '', 'Windows 11 Build 26100'),
        ):
            windows = SimpleNamespace(major=major, minor=minor, build=build, service_pack=service)
            with self.subTest(expected=expected), \
                 patch('core.system_info.platform.system', return_value='Windows'), \
                 patch('core.system_info.platform.machine', return_value='AMD64'), \
                 patch('core.system_info.platform.win32_ver', return_value=('', '', '', '')), \
                 patch('core.system_info.sys.getwindowsversion', return_value=windows, create=True):
                self.assertEqual(get_pretty_os_info(), f'{expected} (AMD64)')

    def test_windows_uses_real_platform_version_and_win32_fallback(self):
        windows = SimpleNamespace(major=6, minor=2, build=9200,
                                  platform_version=(10, 0, 22631), service_pack='')
        with patch('core.system_info.platform.system', return_value='Windows'), \
             patch('core.system_info.platform.machine', return_value='ARM64'), \
             patch('core.system_info.platform.win32_ver', return_value=('10', '10.0.22631', '', '')), \
             patch('core.system_info.sys.getwindowsversion', return_value=windows, create=True) as query:
            self.assertEqual(get_pretty_os_info(), 'Windows 11 Build 22631 (ARM64)')
            query.side_effect = OSError('Unavailable')
            self.assertEqual(get_pretty_os_info(), 'Windows 11 Build 22631 (ARM64)')

    def test_linux_distribution_kernel_and_architecture(self):
        for release, expected in (
            ({'PRETTY_NAME': 'Ubuntu 24.04 LTS'}, 'Ubuntu 24.04 LTS'),
            ({'NAME': 'CachyOS Linux'}, 'CachyOS Linux'),
            ({'NAME': 'Debian GNU/Linux', 'VERSION_ID': '12'}, 'Debian GNU/Linux 12'),
        ):
            with self.subTest(release=release), \
                 patch('core.system_info.platform.system', return_value='Linux'), \
                 patch('core.system_info.platform.machine', return_value='x86_64'), \
                 patch('core.system_info.platform.release', return_value='6.8.0-45-generic'), \
                 patch('core.system_info.platform.freedesktop_os_release', return_value=release, create=True):
                self.assertEqual(get_pretty_os_info(), f'{expected} (6.8.0-45-generic x86_64)')

    def test_linux_os_release_file_fallback(self):
        with patch('core.system_info.platform.system', return_value='Linux'), \
             patch('core.system_info.platform.machine', return_value='aarch64'), \
             patch('core.system_info.platform.release', return_value='6.11.5-cachyos'), \
             patch('core.system_info.platform.freedesktop_os_release', side_effect=AttributeError, create=True), \
             patch('builtins.open', mock_open(read_data='NAME="CachyOS Linux"\nPRETTY_NAME="CachyOS Linux"\n')):
            self.assertEqual(get_pretty_os_info(), 'CachyOS Linux (6.11.5-cachyos aarch64)')

    def test_summary_and_cli_bind_canonical_fields(self):
        with patch('core.platform_info.get_pretty_os_info', return_value='macOS 15.1 (arm64)'), \
             patch('core.platform_info.platform.node', return_value='test-host'), \
             patch('core.platform_info.sys.version', '3.15.0 (test runtime)'):
            system = get_system_summary()
        lan = {'primary_interface': {'name': 'en0', 'type': 'Ethernet'}, 'interface_type': 'Wi-Fi'}
        expected = 'Host: test-host | OS: macOS 15.1 (arm64) | Python: 3.15.0 | Interfaccia: en0 (Wi-Fi)'
        self.assertEqual(format_system_header(system, lan), expected)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            TerminalUI(no_color=True).print_banner(system)
            TerminalUI(no_color=True).render_full_report({'system': system, 'lan': lan})
        self.assertIn(expected, output.getvalue())
        self.assertNotIn('(-)', output.getvalue())

    def test_saved_report_never_borrows_local_host_version(self):
        with patch('core.system_info.platform.system', side_effect=AssertionError('Local probe')):
            self.assertEqual(get_pretty_os_info({'os': 'Darwin', 'machine': 'arm64'}), 'macOS (arm64)')

    def test_no_emoji_in_shipped_views_and_backend(self):
        root = Path(__file__).resolve().parents[1]
        paths = [root / 'netprobe.py', *root.glob('cli/*.py'), *root.glob('tui/*.py'),
                 *root.glob('core/*.py'), *root.glob('tools/*.py'),
                 root / 'old/gui/web/server.py', *root.glob('old/gui/web/static/*')]
        for path in paths:
            if path.suffix in ('.py', '.js', '.css', '.html'):
                with self.subTest(path=path):
                    self.assertNotRegex(path.read_text(), '[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F\u231a\u231b\u23e9-\u23f3\u23f8-\u23fa\u2b50\u2b55]')
