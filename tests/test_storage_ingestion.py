"""Persistent cache integration, privacy boundaries and anti-poisoning policies."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from core.ingestion import prepare_telemetry
from core.storage import StorageManager, data_directory


def report():
    return {'timestamp': 1750000000., 'quick_scan': False,
            'system': {'hostname': 'private-host', 'os': 'Darwin', 'os_release': '24.1'},
            'lan': {'primary_interface': {'name': 'en0'}, 'interface_type': 'Ethernet'},
            'wan': {'public_ipv4': '8.8.8.8', 'asn': 'AS15169', 'isp': 'Private ISP'},
            'ixp': {'hop2_bng': {'ip': '1.2.3.4', 'min_ms': 2.5, 'avg_ms': 90,
                                  'iqr_ms': 1, 'spike_fraction': .1}},
            'performance': {'gateway_latency': {'min_ms': 1, 'iqr_ms': 1},
                            'speed': {'download_mbps': 100, 'upload_mbps': 20},
                            'bufferbloat': {'download_delta_ms': 5, 'upload_delta_ms': 4}},
            'estimations': {'physical_medium': {'predicted_medium': 'FTTH', 'confidence_pct': 80}}}


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'private' / 'netprobe.db'
        self.storage = StorageManager(self.path)

    def rows(self):
        with self.storage.connection() as db:
            return [dict(row) for row in db.execute('SELECT * FROM telemetry_runs')]

    def test_theme_restart_and_engine_settings(self):
        self.storage.set_theme('oled-black')
        self.storage.set_setting('arbitrary', {'nested': [True, 1]})
        restarted = StorageManager(self.path)
        self.assertEqual(restarted.get_theme(), 'oled-black')
        self.assertEqual(restarted.get_setting('arbitrary'), {'nested': [True, 1]})
        with restarted.connection() as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0], 1)
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0], 1)
        if os.name != 'nt':
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)

    def test_streaming_floor_and_baseline_exclusion(self):
        noisy = report()
        noisy['performance']['bufferbloat']['download_delta_ms'] = 46
        self.storage.store_telemetry_run(noisy)
        self.assertEqual(self.rows()[0]['is_congested'], 1)
        self.assertEqual(self.rows()[0]['bng_floor_ms'], 2.5)
        self.assertEqual(self.storage.baseline_runs(), [])
        self.storage.store_telemetry_run(report())
        self.assertEqual(len(self.storage.baseline_runs()), 1)

    def test_each_congestion_threshold_is_strict(self):
        for section, key, threshold in (('bufferbloat', 'download_delta_ms', 45),
                                        ('bufferbloat', 'upload_delta_ms', 45),
                                        ('gateway_latency', 'iqr_ms', 8),
                                        ('bng', 'iqr_ms', 15), ('bng', 'spike_fraction', .2)):
            data = report()
            target = data['ixp']['hop2_bng'] if section == 'bng' else data['performance'][section]
            target[key] = threshold
            self.assertEqual(prepare_telemetry(data, 'salt')['is_congested'], 0)
            target[key] += .01
            self.assertEqual(prepare_telemetry(data, 'salt')['is_congested'], 1)

    def test_invalid_timeout_nan_and_missing_bng(self):
        for mutation in ('bng', 'timeout', 'incomplete', 'nan', 'speed', 'worker_errors'):
            data = report()
            if mutation == 'bng':
                data['ixp']['hop2_bng'] = None
            elif mutation == 'timeout':
                data['performance']['speed']['download'] = {'valid': False, 'timed_out': True}
            elif mutation == 'incomplete':
                data['performance']['speed']['upload'] = {'complete': False}
            elif mutation == 'nan':
                data['ixp']['hop2_bng']['min_ms'] = float('nan')
            elif mutation == 'worker_errors':
                data['performance']['speed']['errors'] = ['socket timeout']
            else:
                data['performance']['speed']['upload_mbps'] = None
            self.storage.store_telemetry_run(data)
        self.assertTrue(all(row['is_valid'] == 0 for row in self.rows()))
        self.assertEqual(self.storage.clean_invalids(), 6)
        self.assertEqual(self.rows(), [])

    def test_quick_scan_without_speed_can_be_valid(self):
        data = report()
        data['quick_scan'] = True
        data['performance']['speed'] = {}
        self.assertEqual(prepare_telemetry(data, 'salt')['is_valid'], 1)

    def test_subnet_weights_concurrent_and_seven_day_expiry(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(self.storage.store_telemetry_run, [report() for _ in range(13)]))
        rows = self.rows()
        self.assertEqual(sum(row['statistical_weight'] == 1 for row in rows), 10)
        self.assertAlmostEqual(rows[-1]['statistical_weight'], 10/13)
        later = report()
        later['timestamp'] += 8*86400
        self.storage.store_telemetry_run(later)
        self.assertEqual(self.rows()[-1]['statistical_weight'], 1)
        self.assertEqual(rows[0]['subnet_prefix'], '8.8.8.0/24')
        later['wan'] = {'public_ipv6': '2001:4860:1234:abcd::1'}
        self.assertEqual(prepare_telemetry(later, 'salt')['subnet_prefix'], '2001:4860:1234::/48')

    def test_salt_persistence_export_and_reset_boundaries(self):
        self.storage.store_telemetry_run(report())
        StorageManager(self.path).store_telemetry_run(report())
        self.assertEqual(self.rows()[0]['host_hash'], self.rows()[1]['host_hash'])
        self.assertNotIn('private-host', self.rows()[0]['host_hash'])
        output = self.path.parent / 'export.jsonl'
        self.assertEqual(self.storage.export_anonymized(output), 2)
        text = output.read_text()
        for sensitive in ('private-host', 'host_hash', '8.8.8', '1.2.3.4', 'Private ISP', 'timestamp', 'subnet_prefix'):
            self.assertNotIn(sensitive, text)
        self.assertEqual(len([json.loads(line) for line in text.splitlines()]), 2)
        self.storage.set_theme('oled-black')
        self.storage.reset_telemetry()
        self.assertEqual(self.storage.get_theme(), 'oled-black')
        self.assertEqual(self.storage.status()['total'], 0)
        self.storage.factory_reset()
        self.assertEqual(self.storage.get_theme(), 'midnight-slate')
        self.storage.store_telemetry_run(report())
        self.assertNotEqual(self.rows()[0]['host_hash'], prepare_telemetry(report(), 'salt')['host_hash'])

    def test_platform_paths(self):
        with patch('core.storage.platform.system', return_value='Linux'), patch.dict(os.environ, {'XDG_DATA_HOME': '/tmp/xdg'}):
            self.assertEqual(data_directory(), Path('/tmp/xdg/netprobe'))
        with patch('core.storage.platform.system', return_value='Darwin'):
            self.assertTrue(str(data_directory()).endswith('Library/Application Support/NetProbe'))
        with patch('core.storage.platform.system', return_value='Windows'), patch.dict(os.environ, {'LOCALAPPDATA': '/tmp/local'}):
            self.assertEqual(data_directory(), Path('/tmp/local/NetProbe'))
