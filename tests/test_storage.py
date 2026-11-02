"""Completed scans persist silently; cache failures never replace diagnostics."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from core.ingestion import ingest_report, prepare_telemetry
from core.storage import StorageManager
from netprobe import run_cli_scan
from tests.test_storage_ingestion import report


def latest_report():
    data = report()
    data['formatted_time'] = '2026-11-02 12:34:56'
    data['system']['pretty_os'] = 'macOS 26'
    data['lan'].update(primary_interface_name='en5', gateway={'ipv4': '192.168.4.1'})
    data['lan']['primary_interface'].update(ipv4='192.168.5.12', netmask='255.255.252.0')
    data['wan']['asn'] = 'AS137'
    physical = data['estimations']['physical_medium']
    physical['bng_hop'] = dict(ip='193.206.136.17', min_ms=1.89, avg_ms=80,
                               spread_ms=2.5, iqr_ms=1.5, spike_fraction=0.1)
    data['performance']['speed'] = dict(valid=True, download={'valid': True, 'mbps': 920},
                                      upload={'valid': True, 'mbps': 935})
    data['performance']['bufferbloat'].update(grade='A', download_delta_ms=5, upload_delta_ms=12)
    return data


@contextlib.contextmanager
def simulated_scan(data, tui=False):
    with contextlib.ExitStack() as mocks:
        for module, cls, method, result in (
            ('core.lan_scanner', 'LanScanner', 'scan_all', data['lan']),
            ('core.wan_probe', 'WanProbe', 'probe_all', data['wan']),
            ('core.ixp_analyzer', 'IXPAnalyzer', 'analyze_ixp_and_bng', data['ixp']),
            ('core.performance', 'PerformanceTester', 'test_all', data['performance']),
            ('core.estimators', 'NetworkEstimator', 'calculate_all', data['estimations'])):
            target = 'tui.app' if tui else module
            instance = mocks.enter_context(patch(f'{target}.{cls}')).return_value
            getattr(instance, method).return_value = result
        target = 'tui.app' if tui else 'core.platform_info'
        mocks.enter_context(patch(f'{target}.get_system_summary', return_value=data['system']))
        yield


class AutomaticTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'netprobe.db'
        self.storage = StorageManager(self.path)

    def test_simulated_scan_exports_then_inserts_once_without_flags(self):
        destination = Path(self.temp.name) / 'netprobe_report_test.json'
        original_store = self.storage.store_telemetry_run

        def store(data):
            self.assertEqual(json.loads(destination.read_text()), data)
            return original_store(data)

        stdout = io.StringIO()
        with simulated_scan(latest_report()), patch('core.storage.StorageManager', return_value=self.storage), \
                patch.object(self.storage, 'store_telemetry_run', side_effect=store), \
                contextlib.redirect_stdout(stdout):
            run_cli_scan(json_output=True, export_path=str(destination))
        output = json.loads(stdout.getvalue())
        with contextlib.closing(sqlite3.connect(str(self.path))) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM telemetry_runs').fetchone()[0], 1)
            row = db.execute('SELECT timestamp, bng_floor_ms, is_congested, download_mbps, upload_mbps, is_valid FROM telemetry_runs').fetchone()
        self.assertEqual(row, (output['timestamp'], 1.89, 0, 920, 935, 1))

    def test_scan_without_export_persists_automatically(self):
        with simulated_scan(latest_report()), patch('core.storage.StorageManager', return_value=self.storage), \
                contextlib.redirect_stdout(io.StringIO()):
            run_cli_scan(json_output=True)
            run_cli_scan(quick=True, json_output=True)
        with contextlib.closing(sqlite3.connect(str(self.path))) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM telemetry_runs').fetchone()[0], 2)

    def test_latest_schema_field_alignment_and_floor(self):
        data = latest_report()
        self.assertIsNotNone(ingest_report(data, storage=self.storage))
        with self.storage.connection() as db:
            actual = dict(db.execute('SELECT * FROM telemetry_runs').fetchone())
        expected = dict(timestamp=data['timestamp'], formatted_time=data['formatted_time'],
                        os_family='Darwin', kernel_release='macOS 26', interface_name='en5',
                        interface_type='Ethernet', public_asn=137, public_isp='Private ISP',
                        subnet_prefix='192.168.4.0/22', gateway_ip='192.168.4.1',
                        gateway_min_ms=1, gateway_iqr_ms=1, bng_ip='193.206.136.17',
                        bng_floor_ms=1.89, bng_spread_ms=2.5, bng_iqr_ms=1.5,
                        bng_spike_fraction=0.1, download_mbps=920, upload_mbps=935,
                        bufferbloat_grade='A', bufferbloat_delta_ms=5, is_congested=0,
                        is_valid=1, predicted_medium='FTTH', confidence_pct=80)
        for key, value in expected.items():
            self.assertEqual(actual[key], value, key)
        salt = self.storage.get_setting('host_salt')
        self.assertEqual(actual['host_hash'], hashlib.sha256(('private-host' + salt).encode()).hexdigest())
        self.assertNotIn('private-host', actual['host_hash'])

    def test_latest_bng_congestion_and_explicit_missing_speed(self):
        for key, value in (('iqr_ms', 16), ('spike_fraction', 0.3)):
            data = latest_report()
            data['estimations']['physical_medium']['bng_hop'][key] = value
            self.assertEqual(prepare_telemetry(data, 'salt')['is_congested'], 1)
        data = latest_report()
        data['performance']['bufferbloat']['upload_delta_ms'] = 50
        self.assertEqual(prepare_telemetry(data, 'salt')['is_congested'], 1)
        self.assertEqual(prepare_telemetry(data, 'salt')['bufferbloat_delta_ms'], 5)
        data['performance']['speed'].update(download_mbps=999)
        data['performance']['speed']['download']['mbps'] = None
        self.assertEqual(prepare_telemetry(data, 'salt')['is_valid'], 0)

    def test_invalid_database_path_and_unexpected_error_preserve_report(self):
        for failure in (lambda: StorageManager(self.temp.name),
                        lambda: (_ for _ in ()).throw(PermissionError('read-only cache')),
                        lambda: (_ for _ in ()).throw(RuntimeError('schema failure'))):
            with self.subTest(failure=failure), simulated_scan(latest_report()), \
                    patch('core.storage.StorageManager', side_effect=failure), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertIsNone(run_cli_scan(json_output=True))
                self.assertIn('performance', json.loads(stdout.getvalue()))
                self.assertEqual(stderr.getvalue(), '')

    def test_locked_database_is_bounded_and_recovers(self):
        with contextlib.closing(sqlite3.connect(str(self.path))) as lock:
            lock.execute('BEGIN IMMEDIATE')
            start = time.monotonic()
            self.assertIsNone(ingest_report(latest_report(), storage=self.storage))
            self.assertLess(time.monotonic() - start, 2)
        self.assertIsNotNone(ingest_report(latest_report(), storage=self.storage))
        self.assertEqual(self.storage.status()['total'], 1)

    def test_status_counts_invalid_clean_runs_separately_from_baselines(self):
        for congested, valid in ((False, True), (False, False), (True, True)):
            data = latest_report()
            if congested:
                data['performance']['bufferbloat']['download_delta_ms'] = 50
            if not valid:
                data['performance']['speed']['valid'] = False
            ingest_report(data, storage=self.storage)
        status = self.storage.status()
        self.assertEqual((status['total'], status['clean'], status['congested']), (3, 2, 1))
        self.assertEqual(len(self.storage.baseline_runs()), 1)


class TUITelemetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_worker_ingests_once_and_survives_insertion_failure(self):
        from tui.app import NetProbeTUIApp
        for failing in (False, True):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as directory:
                storage = StorageManager(Path(directory) / 'netprobe.db')
                app = NetProbeTUIApp(storage=storage)
                with simulated_scan(latest_report(), tui=True), contextlib.ExitStack() as mocks:
                    if failing:
                        mocks.enter_context(patch.object(storage, 'store_telemetry_run', side_effect=RuntimeError('write failed')))
                    async with app.run_test(size=(100, 60)) as pilot:
                        app.action_start_quick_scan()
                        await app.workers.wait_for_complete()
                        await pilot.pause()
                        self.assertIsNotNone(app.scan_data)
                        self.assertIn('COMPLETATO', str(app.query_one('#status-label').render()))
                        self.assertEqual(storage.status()['total'], 0 if failing else 1)
