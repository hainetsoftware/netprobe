"""Bootstrap subprocesses are simulated; tests never install or uninstall packages."""
import io
import os
import sys
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr
from core import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_import_name_mapping(self):
        with patch.object(bootstrap.importlib.util, 'find_spec', side_effect=lambda name: None if name == 'dns' else object()), patch.object(bootstrap.metadata, 'version', return_value='99.0.0'):
            self.assertEqual(bootstrap.missing_packages(), ['dnspython>=2.6.0'])

    def test_outdated_textual_is_upgraded_before_app_import(self):
        with patch.object(bootstrap.importlib.util, 'find_spec', return_value=object()), patch.object(bootstrap.metadata, 'version', side_effect=lambda name: '0.85.0' if name == 'textual' else '99.0.0'):
            self.assertEqual(bootstrap.missing_packages(), ['textual>=0.89.1'])

    def test_silent_when_present(self):
        with patch.object(bootstrap, 'missing_packages', return_value=[]), patch.object(bootstrap, '_run') as run, redirect_stderr(io.StringIO()) as output:
            bootstrap.ensure_dependencies()
            run.assert_not_called()
            self.assertEqual(output.getvalue(), '')

    def test_pip_install_then_continue(self):
        with patch.object(bootstrap, 'missing_packages', side_effect=[['dnspython>=2.6.0'], []]), patch.object(bootstrap, '_run', return_value=(True, '')) as run, redirect_stderr(io.StringIO()):
            bootstrap.ensure_dependencies()
            command = run.call_args.args[0]
            self.assertEqual(command[:5], [sys.executable, '-m', 'pip', 'install', '--quiet'])
            self.assertEqual('--user' in command, sys.prefix == sys.base_prefix)

    def test_ensurepip_then_retry(self):
        with patch.object(bootstrap, 'missing_packages', side_effect=[['dnspython>=2.6.0'], []]), patch.object(bootstrap, '_run', side_effect=[(False, 'No module named pip'), (True, ''), (True, '')]) as run, redirect_stderr(io.StringIO()):
            bootstrap.ensure_dependencies()
            self.assertIn('ensurepip', run.call_args_list[1].args[0])

    def test_pep668_user_venv_reexec(self):
        class Reexecuted(Exception):
            pass
        with patch.object(bootstrap, 'missing_packages', return_value=['dnspython>=2.6.0']), patch.object(bootstrap, '_run', side_effect=[(False, 'externally-managed-environment'), (True, ''), (True, '')]) as run, patch('core.storage.data_directory', return_value=__import__('pathlib').Path('/tmp/netprobe-bootstrap-test')), patch.object(bootstrap.os, 'execve', side_effect=Reexecuted) as reexec, patch.dict(os.environ, {}, clear=True), redirect_stderr(io.StringIO()):
            with self.assertRaises(Reexecuted):
                bootstrap.ensure_dependencies()
            self.assertIn('venv', run.call_args_list[1].args[0])
            self.assertEqual(reexec.call_args.args[2]['NETPROBE_BOOTSTRAPPED'], '1')

    def test_failure_exits_cleanly_with_manual_help(self):
        with patch.object(bootstrap, 'missing_packages', return_value=['dnspython>=2.6.0']), patch.object(bootstrap, '_run', return_value=(False, 'failed')), patch.dict(os.environ, {'NETPROBE_BOOTSTRAPPED': '1'}), redirect_stderr(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as caught:
                bootstrap.ensure_dependencies()
            self.assertEqual(caught.exception.code, 1)
            self.assertIn('Comandi suggeriti', output.getvalue())
