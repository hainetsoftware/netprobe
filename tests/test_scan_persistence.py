"""The CLI stores completed reports without contaminating its JSON output."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from core.storage import StorageManager
from netprobe import run_cli_scan
from test_storage_ingestion import report


class ScanPersistenceTests(unittest.TestCase):
    def test_cli_json_ingests_report_and_survives_cache_failure(self):
        data = report()
        with tempfile.TemporaryDirectory() as directory:
            storage = StorageManager(Path(directory) / 'netprobe.db')
            for cache_failure in (False, True):
                with contextlib.ExitStack() as mocks:
                    for module, cls, method, result in (
                        ('core.lan_scanner', 'LanScanner', 'scan_all', data['lan']),
                        ('core.wan_probe', 'WanProbe', 'probe_all', data['wan']),
                        ('core.ixp_analyzer', 'IXPAnalyzer', 'analyze_ixp_and_bng', data['ixp']),
                        ('core.performance', 'PerformanceTester', 'test_all', data['performance']),
                        ('core.estimators', 'NetworkEstimator', 'calculate_all', data['estimations'])):
                        instance = mocks.enter_context(patch(f'{module}.{cls}')).return_value
                        getattr(instance, method).return_value = result
                    mocks.enter_context(patch('core.platform_info.get_system_summary', return_value=data['system']))
                    mocks.enter_context(patch('core.storage.StorageManager', return_value=storage,
                                              side_effect=OSError('read-only cache') if cache_failure else None))
                    stdout = mocks.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    stderr = mocks.enter_context(contextlib.redirect_stderr(io.StringIO()))
                    run_cli_scan(json_output=True)
                    self.assertEqual(json.loads(stdout.getvalue())['ixp'], data['ixp'])
                    if cache_failure:
                        self.assertIn('Cache non disponibile', stderr.getvalue())
            self.assertEqual(storage.status()['total'], 1)
            self.assertEqual(storage.baseline_runs()[0]['bng_floor_ms'], 2.5)
