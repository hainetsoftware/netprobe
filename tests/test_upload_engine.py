"""Deterministic transport regressions; no external speed service is used."""
import socket
import time
import unittest
from unittest.mock import patch

from core.performance import PerformanceTester, _STATIC_UPLOAD_BUFFER


class UploadEngineTests(unittest.TestCase):
    def run_transport(self, reject=False, ceiling=False, fail=False, workers=1,
                      download_mbps=None, delayed_response=False, write_timeout=False):
        connections = []

        class Connection:
            def __init__(self, *args, **kwargs):
                self.sock = self
                self.closed = False
                self.requests = []
                self.sent = 0
                self.length = 0
                self.options = []
                self.timeouts = []
                self.write_sizes = []
                connections.append(self)

            def connect(self):
                time.sleep(0.12)  # Deliberately exclude setup from transfer time.

            def setsockopt(self, *args):
                self.options.append(args)

            def settimeout(self, timeout):
                self.timeouts.append(timeout)

            def putrequest(self, method, path):
                self.sent = 0

            def putheader(self, name, value):
                if name == 'Content-Length':
                    self.length = int(value)
                    self.requests.append(self.length)

            def endheaders(self):
                pass

            def send(self, data):
                assert isinstance(data, memoryview)
                assert data.obj is _STATIC_UPLOAD_BUFFER
                assert len(data) <= 256 * 1024
                self.write_sizes.append(len(data))
                time.sleep(0.065 if delayed_response else 0.001)
                if write_timeout:
                    raise TimeoutError('write stalled')
                if fail and self.sent >= 65536:
                    raise ConnectionError('interrupted')
                n = min(len(data), 65536)  # Always force partial writes.
                self.sent += n
                return n

            def getresponse(self):
                assert self.sent == self.length
                if delayed_response:
                    assert 0 < self.timeouts[-1] <= 1.5
                    time.sleep(self.timeouts[-1])
                    raise TimeoutError('The read operation timed out')
                status = 403 if reject else 413 if ceiling and self.length > 1024 * 1024 else 200

                class Response:
                    will_close = False
                    reason = 'test'

                    def read(self, size):
                        return b''

                resp = Response()
                resp.status = status
                return resp

            def shutdown(self, how):
                pass

            def close(self):
                self.closed = True

        tester = PerformanceTester()
        tester.speed_scheme = 'http'
        with patch('http.client.HTTPConnection', Connection), patch.object(tester, 'ping_host', return_value={}):
            before = time.perf_counter()
            result, _ = tester.measure_upload_stream(
                duration=4.5 if delayed_response else 1.3 if ceiling else 0.48,
                workers=workers, download_mbps=download_mbps)
            elapsed = time.perf_counter() - before
        self.assertTrue(all(conn.closed for conn in connections))
        self.assertTrue(all(mbps >= 0 for _, mbps in result['samples']))
        return result, connections, elapsed

    def test_partial_writes_keepalive_setup_and_shutdown(self):
        result, connections, elapsed = self.run_transport()
        self.assertTrue(result['valid'])
        self.assertGreater(result['completed_requests'], 1)
        self.assertEqual(len(connections), 1)
        self.assertLess(result['duration_s'], 0.55)
        self.assertGreater(elapsed, result['duration_s'] + 0.10)
        self.assertIn((socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024), connections[0].options)
        self.assertLessEqual(max(connections[0].requests), 8 * 1024 * 1024)

    def test_rejected_endpoint_is_not_valid_throughput(self):
        result, _, _ = self.run_transport(reject=True)
        self.assertFalse(result['valid'])
        self.assertEqual(result['sustained_mbps'], 0)
        self.assertIn('403', result['errors'][0]['error'])

    def test_failed_requests_never_roll_counters_back(self):
        result, _, _ = self.run_transport(fail=True)
        self.assertFalse(result['valid'])
        self.assertGreater(result['total_bytes'], 0)

    def test_request_ceiling_reduces_body_and_recovers(self):
        result, connections, _ = self.run_transport(ceiling=True)
        self.assertTrue(result['valid'])
        self.assertTrue(any('413' in error['error'] for error in result['errors']))
        self.assertTrue(any(1024 * 1024 in c.requests for c in connections))

    def test_parallel_workers(self):
        result, connections, _ = self.run_transport(workers=4)
        self.assertEqual(result['workers'], 4)
        self.assertEqual(len(connections), 4)
        self.assertTrue(result['valid'])

    def test_capacity_selects_workers(self):
        for download, expected in [(None, (2, 64, 2)), (38, (2, 64, 2)),
                                   (59.9, (2, 64, 2)), (60, (3, 128, 10)),
                                   (149.9, (3, 128, 10)), (150, (6, 256, 25))]:
            with self.subTest(download=download):
                workers, chunk, body = PerformanceTester._upload_profile(download)
                self.assertEqual((workers, chunk // 1024, body // (1024 * 1024)), expected)
                self.assertEqual(PerformanceTester._upload_workers(download, 1000), workers)

    def test_asymmetric_line_samples_survive_delayed_responses(self):
        result, connections, elapsed = self.run_transport(
            workers=None, download_mbps=38.0, delayed_response=True)
        self.assertEqual(result['workers'], 2)
        self.assertEqual(result['chunk_size'], 64 * 1024)
        self.assertEqual(result['post_body_size'], 2 * 1024 * 1024)
        self.assertTrue(all(max(c.write_sizes) == 64 * 1024 for c in connections))
        self.assertTrue(result['valid'])
        self.assertIsNone(result['invalid_reason'])
        self.assertGreaterEqual(result['total_bytes'], 2 * 1024 * 1024)
        self.assertGreater(len(result['samples']), 20)
        self.assertGreater(result['sustained_mbps'], 0)
        self.assertEqual(result['completed_requests'], 0)
        self.assertEqual(result['errors'], [])
        self.assertLess(elapsed, 5.0)

    def test_write_timeouts_do_not_validate_upload(self):
        result, _, _ = self.run_transport(write_timeout=True)
        self.assertFalse(result['valid'])
        self.assertEqual(result['total_bytes'], 0)
        self.assertTrue(result['errors'])

    def test_warmup_and_top_eighty_percent(self):
        series = [(0.0, 0)]
        # Slow warmup, followed by ten stable intervals: two low, eight at 800 Mbps.
        rates = [10] * 15 + [100] * 2 + [800] * 8
        for i, rate in enumerate(rates, 1):
            series.append((round(i * 0.1, 2), series[-1][1] + rate * 12500))
        result = PerformanceTester()._summarize_upload(series, 1.5)
        self.assertEqual(result['sustained_mbps'], 800)
        self.assertEqual(len(result['samples']), 25)
