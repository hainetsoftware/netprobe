import os
import sys
import unittest
import http.server
import socketserver
import threading
import socket
import struct
from core.performance import PerformanceTester
from core.estimators import NetworkEstimator

class LoopbackSpeedHandler(http.server.BaseHTTPRequestHandler):
    mode = "normal"  # "normal", "reset", "under_2mb"
    lock = threading.Lock()
    bytes_served_down = 0
    bytes_served_up = 0
    reset_happened = False

    @classmethod
    def reset_state(cls, mode="normal"):
        with cls.lock:
            cls.mode = mode
            cls.bytes_served_down = 0
            cls.bytes_served_up = 0
            cls.reset_happened = False

    def do_GET(self):
        cls = self.__class__
        if cls.mode == "reset":
            with cls.lock:
                first = not cls.reset_happened
                cls.reset_happened = True
            if first:
                try:
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n")
                    self.wfile.write(b"X" * 65536)
                    self.wfile.flush()
                except Exception:
                    pass
            try:
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                self.connection.close()
            except Exception:
                pass
            return

        if cls.mode == "under_2mb":
            with cls.lock:
                remaining = max(0, (500 * 1024) - cls.bytes_served_down)
                to_send = min(remaining, 64 * 1024)
                cls.bytes_served_down += to_send

            if to_send == 0:
                self.send_error(503, "Budget exceeded")
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(to_send))
            self.end_headers()
            try:
                self.wfile.write(b"0" * to_send)
            except Exception:
                pass
            return

        # Normal mode: stream chunks continuously
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", "100000000")
        self.end_headers()
        chunk = b"0" * 65536
        try:
            while True:
                self.wfile.write(chunk)
        except Exception:
            pass

    def do_POST(self):
        cls = self.__class__
        if cls.mode == "reset":
            try:
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                self.connection.close()
            except Exception:
                pass
            return

        if cls.mode == "under_2mb":
            with cls.lock:
                remaining = max(0, (500 * 1024) - cls.bytes_served_up)
                to_read = min(remaining, 64 * 1024)
                cls.bytes_served_up += to_read

            if to_read == 0:
                self.send_error(503, "Budget exceeded")
                return

            try:
                self.rfile.read(to_read)
                self.send_response(200)
                self.end_headers()
            except Exception:
                pass
            return

        try:
            while True:
                data = self.rfile.read(65536)
                if not data:
                    break
        except Exception:
            pass

    def log_message(self, *args):
        pass


class TestLivePath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), LoopbackSpeedHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        LoopbackSpeedHandler.reset_state("normal")

    def test_live_path_loopback_success(self):
        tester = PerformanceTester()
        tester.speed_host = "127.0.0.1"
        tester.speed_port = self.port
        tester.speed_scheme = "http"
        tester.stream_duration = 2.5
        tester.warmup_duration = 0.5
        tester.targets = [
            {"name": "Loopback Target", "host": "127.0.0.1", "type": "anycast"}
        ]

        perf_data = tester.test_all(gateway_ip=None, run_speed_test=True)
        speed = perf_data.get("speed", {})
        bb = perf_data.get("bufferbloat", {})

        # Invariants on success
        self.assertTrue(speed.get("valid"))
        self.assertIsNotNone(speed.get("download_mbps"))
        self.assertGreater(speed.get("download_mbps"), 0)
        self.assertIsNotNone(speed.get("upload_mbps"))
        self.assertGreater(speed.get("upload_mbps"), 0)
        self.assertGreaterEqual(speed.get("bytes_transferred", 0), 2 * 1024 * 1024)

        # Loaded latency target must match idle target host
        self.assertEqual(bb.get("idle_target"), "Loopback Target")
        self.assertIsNotNone(bb.get("grade"))

        # Verify downstream estimators behave correctly on valid speed
        est = NetworkEstimator()
        lan_data = {"primary_interface": {"name": "en0", "type": "Ethernet"}}
        wan_data = {"dns": {"primary": "127.0.0.1"}}
        est_data = est.calculate_all(lan_data, wan_data, perf_data)

        bdp = est_data.get("bandwidth_delay_product", {})
        self.assertIsNotNone(bdp.get("bdp_bytes"))
        self.assertGreater(bdp.get("bdp_bytes"), 0)

        apps = est_data.get("application_suitability", {})
        for app_name, app_info in apps.items():
            self.assertIsNotNone(app_info.get("score"))
            self.assertNotEqual(app_info.get("status"), "N/D")

    def test_live_path_connection_refused(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            unused_port = s.getsockname()[1]

        tester = PerformanceTester()
        tester.speed_host = "127.0.0.1"
        tester.speed_port = unused_port
        tester.speed_scheme = "http"
        tester.stream_duration = 0.5
        tester.warmup_duration = 0.1
        tester.targets = [
            {"name": "Loopback Target", "host": "127.0.0.1", "type": "anycast"}
        ]

        perf_data = tester.test_all(gateway_ip=None, run_speed_test=True)
        speed = perf_data.get("speed", {})
        bb = perf_data.get("bufferbloat", {})

        self.assertFalse(speed.get("valid"))
        self.assertIsNone(speed.get("download_mbps"))
        self.assertIsNone(speed.get("upload_mbps"))
        self.assertIsNone(bb.get("grade"))

        est = NetworkEstimator()
        est_data = est.calculate_all({}, {}, perf_data)

        bdp = est_data.get("bandwidth_delay_product", {})
        self.assertIsNone(bdp.get("bdp_bytes"))
        self.assertIsNone(bdp.get("recommended_tcp_window_kb"))

        apps = est_data.get("application_suitability", {})
        for app_name, app_info in apps.items():
            self.assertIsNone(app_info.get("score"))
            self.assertEqual(app_info.get("status"), "N/D")

    def test_live_path_connection_reset(self):
        LoopbackSpeedHandler.reset_state("reset")

        tester = PerformanceTester()
        tester.speed_host = "127.0.0.1"
        tester.speed_port = self.port
        tester.speed_scheme = "http"
        tester.stream_duration = 0.5
        tester.warmup_duration = 0.1
        tester.targets = [
            {"name": "Loopback Target", "host": "127.0.0.1", "type": "anycast"}
        ]

        perf_data = tester.test_all(gateway_ip=None, run_speed_test=True)
        speed = perf_data.get("speed", {})
        bb = perf_data.get("bufferbloat", {})

        self.assertFalse(speed.get("valid"))
        self.assertIsNone(speed.get("download_mbps"))
        self.assertIsNone(speed.get("upload_mbps"))
        self.assertIsNone(bb.get("grade"))

        est = NetworkEstimator()
        est_data = est.calculate_all({}, {}, perf_data)
        bdp = est_data.get("bandwidth_delay_product", {})
        self.assertIsNone(bdp.get("bdp_bytes"))

    def test_live_path_transfer_under_2mb(self):
        LoopbackSpeedHandler.reset_state("under_2mb")

        tester = PerformanceTester()
        tester.speed_host = "127.0.0.1"
        tester.speed_port = self.port
        tester.speed_scheme = "http"
        tester.stream_duration = 0.5
        tester.warmup_duration = 0.1
        tester.targets = [
            {"name": "Loopback Target", "host": "127.0.0.1", "type": "anycast"}
        ]

        perf_data = tester.test_all(gateway_ip=None, run_speed_test=True)
        speed = perf_data.get("speed", {})
        bb = perf_data.get("bufferbloat", {})

        self.assertFalse(speed.get("valid"))
        self.assertIn("insufficiente", str(speed.get("invalid_reason", "")))
        self.assertIsNone(speed.get("download_mbps"))
        self.assertIsNone(speed.get("upload_mbps"))
        self.assertIsNone(bb.get("grade"))

        est = NetworkEstimator()
        est_data = est.calculate_all({}, {}, perf_data)
        bdp = est_data.get("bandwidth_delay_product", {})
        self.assertIsNone(bdp.get("bdp_bytes"))
        apps = est_data.get("application_suitability", {})
        for app_name, app_info in apps.items():
            self.assertIsNone(app_info.get("score"))
            self.assertEqual(app_info.get("status"), "N/D")

        mq = est_data.get("physical_medium", {}).get("measurement_quality", {})
        self.assertFalse(mq.get("noisy_throughput"))

    def test_real_entrypoint_loopback_env_vars(self):
        import subprocess
        import json
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_export = tf.name

        try:
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "utf-8"
            env["NETPROBE_SPEED_HOST"] = "127.0.0.1"
            env["NETPROBE_SPEED_PORT"] = str(self.port)
            env["NETPROBE_SPEED_SCHEME"] = "http"
            env["NETPROBE_SPEED_DURATION"] = "1.0"
            env["NETPROBE_WARMUP_DURATION"] = "0.2"
            env["NETPROBE_QUICK_TRACEROUTE"] = "1"

            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cmd = [sys.executable, os.path.join(base_dir, "netprobe.py"), "--cli", "--full", "--export", tmp_export]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
            self.assertEqual(res.returncode, 0, f"netprobe.py failed with stderr: {res.stderr}")

            with open(tmp_export, "r", encoding="utf-8") as f:
                data = json.load(f)

            perf = data.get("performance", {})
            speed = perf.get("speed", {})
            self.assertTrue(speed.get("valid"))
            self.assertTrue(speed.get("download", {}).get("valid"))
            self.assertTrue(speed.get("upload", {}).get("valid"))
            self.assertGreater(speed.get("download_mbps", 0), 0)
            self.assertGreater(speed.get("upload_mbps", 0), 0)
            self.assertGreaterEqual(speed.get("bytes_transferred", 0), 2 * 1024 * 1024)
        finally:
            if os.path.exists(tmp_export):
                try:
                    os.remove(tmp_export)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
