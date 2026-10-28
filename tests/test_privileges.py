"""Privilege detection and bounded, reaped native process fallbacks."""
import contextlib
import io
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from core.privileges import announce_restrictions, is_elevated
from core.platform_info import run_cmd


class PrivilegeTests(unittest.TestCase):
    def test_posix_and_notice(self):
        with patch('core.privileges.os.name', 'posix'), patch('core.privileges.os.geteuid', return_value=1000, create=True):
            self.assertFalse(is_elevated())
            with contextlib.redirect_stderr(io.StringIO()) as output:
                announce_restrictions()
            self.assertIn('senza privilegi', output.getvalue())
        with patch('core.privileges.os.name', 'posix'), patch('core.privileges.os.geteuid', return_value=0, create=True):
            self.assertTrue(is_elevated())

    def test_windows_admin_and_standard_user(self):
        for value in (0, 1):
            api = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: value))
            with patch('core.privileges.os.name', 'nt'), patch.dict(sys.modules, {'ctypes': SimpleNamespace(windll=api)}):
                self.assertEqual(is_elevated(), bool(value))

    def test_native_timeout_kills_and_reaps(self):
        process = Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired('ping', 1), ('', '')]
        with patch('core.platform_info.subprocess.Popen', return_value=process):
            code, _, error = run_cmd(['ping', '127.0.0.1'], timeout=1)
        self.assertEqual(code, -1)
        self.assertIn('Timeout', error)
        process.kill.assert_called_once()
        self.assertEqual(process.communicate.call_count, 2)

    def test_missing_native_command_is_structured_failure(self):
        with patch('core.platform_info.subprocess.Popen', side_effect=FileNotFoundError):
            self.assertEqual(run_cmd(['missing-ping'])[0], 127)
