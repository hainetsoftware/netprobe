"""
Server HTTP locale e leggero basato su libreria standard Python.
Fornisce API REST per la scansione della rete e serve la dashboard Web GUI.
Non richiede alcuna dipendenza esterna (Flask, FastAPI, ecc.).
"""

import sys
import os
import json
import time
import socket
import webbrowser
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional

from core.platform_info import get_system_summary
from core.lan_scanner import LanScanner
from core.wan_probe import WanProbe
from core.performance import PerformanceTester
from core.estimators import NetworkEstimator
from core.validators import validate_scan_results
from core.provenance import build_field_provenance

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class NetProbeDataCache:
    """Stato condiviso: ultimo report + job di scansione asincrono con progresso live."""
    _instance = None
    _lock = threading.RLock()

    def __init__(self):
        self.cached_data: Optional[Dict[str, Any]] = None
        self.is_scanning = False
        self.last_scan_time = 0.0
        self.status_message = "Pronto"
        self.progress = 0
        self.phase = "idle"
        self.live = {"dir": None, "mbps": 0.0}
        self.error: Optional[str] = None
        self.job_id = 0
        self.cancel = False

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = NetProbeDataCache()
            return cls._instance

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "scanning": self.is_scanning, "message": self.status_message,
                "progress": self.progress, "phase": self.phase, "live": dict(self.live),
                "error": self.error, "job_id": self.job_id,
                "has_data": self.cached_data is not None, "last_scan_time": self.last_scan_time,
            }

    def _set(self, message=None, progress=None, phase=None, live=None):
        with self._lock:
            if message is not None:
                self.status_message = message
            if progress is not None:
                self.progress = progress
            if phase is not None:
                self.phase = phase
            if live is not None:
                self.live = live

    def start_scan(self, quick_scan: bool = False) -> bool:
        """Avvia la scansione in un thread; ritorna False se ce n'e' gia' una in corso."""
        with self._lock:
            if self.is_scanning:
                return False
            self.is_scanning = True
            self.error = None
            self.progress = 0
            self.phase = "lan"
            self.live = {"dir": None, "mbps": 0.0}
            self.status_message = "Scansione in corso..."
            self.job_id += 1
        threading.Thread(target=self._worker, args=(quick_scan,), daemon=True).start()
        return True

    def run_scan(self, quick_scan: bool = False) -> Dict[str, Any]:
        """Versione sincrona (usata per il primo caricamento)."""
        if self.start_scan(quick_scan):
            pass
        while self.is_scanning:
            time.sleep(0.2)
        return self.cached_data or {}

    def _worker(self, quick_scan: bool):
        try:
            from core.ixp_analyzer import IXPAnalyzer

            lan_scanner = LanScanner()
            wan_probe = WanProbe()
            ixp_analyzer = IXPAnalyzer()
            perf_tester = PerformanceTester()
            estimator = NetworkEstimator()

            self._set("Analisi scheda di rete, LAN e apparato switch...", 5, "lan")
            sys_summary = get_system_summary()
            lan_data = lan_scanner.scan_all(quick_scan=quick_scan, progress_cb=lambda m, p: self._set(m, p, "lan"))
            p_iface = lan_data.get("primary_interface") or {}
            local_ip = p_iface.get("ipv4")
            gateway_ip = (lan_data.get("gateway") or {}).get("ipv4")

            self._set("Analisi rete pubblica, NAT e ISP...", 15, "wan")
            wan_data = wan_probe.probe_all(local_ip=local_ip, gateway_ip=gateway_ip)

            self._set("Traceroute diagnostico, Peering IXP e Hop 2 BNG...", 25, "ixp")
            ixp_data = ixp_analyzer.analyze_ixp_and_bng(wan_data, progress_cb=lambda m, p: self._set(m, p, "ixp"))

            def cb(msg, pct, live=None):
                phase = "download" if "ownload" in msg else "upload" if "pload" in msg else "latency"
                scaled_pct = 40 + int(pct * 0.55)
                self._set(msg, scaled_pct, phase, live if live is not None else None)

            perf_data = perf_tester.test_all(gateway_ip=gateway_ip, run_speed_test=(not quick_scan), progress_cb=cb)
            self._set("Calcolo stime fisiche e modelli matematici...", 97, "estimation", {"dir": None, "mbps": 0.0})
            est_data = estimator.calculate_all(lan_data, wan_data, perf_data, ixp_data=ixp_data)

            report = {
                "timestamp": time.time(),
                "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "quick_scan": quick_scan,
                "system": sys_summary, "lan": lan_data, "wan": wan_data,
                "ixp": ixp_data,
                "performance": perf_data, "estimations": est_data,
                "diagnostics": {"arp": lan_data.get("diagnostics_arp", {})},
            }
            validate_scan_results(report)
            report["field_status"] = build_field_provenance(report)
            with self._lock:
                self.cached_data = report
                self.last_scan_time = time.time()
                self.status_message = "Completato"
                self.progress = 100
                self.phase = "done"
        except Exception as e:  # noqa
            with self._lock:
                self.error = f"{type(e).__name__}: {e}"
                self.status_message = "Errore durante la scansione"
                self.phase = "error"
        finally:
            with self._lock:
                self.is_scanning = False


class NetProbeHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self._serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html; charset=utf-8")
        elif path.startswith("/static/"):
            rel_file = path[len("/static/"):]
            # Protezione traversal
            safe_file = os.path.normpath(os.path.join(STATIC_DIR, rel_file))
            if safe_file.startswith(STATIC_DIR) and os.path.exists(safe_file):
                mime = self._get_mime_type(safe_file)
                self._serve_file(safe_file, mime)
            else:
                self.send_error(404, "File non trovato")
        elif path == "/api/status":
            self._send_json(NetProbeDataCache.get_instance().snapshot())
        elif path == "/api/data":
            cache = NetProbeDataCache.get_instance()
            if cache.cached_data:
                self._send_json(cache.cached_data)
            else:
                self._send_json({"pending": True, **cache.snapshot()}, status=202)
        elif path == "/api/scan":
            qs = parse_qs(parsed.query)
            quick = qs.get("quick", ["false"])[0].lower() in ("true", "1", "yes")
            cache = NetProbeDataCache.get_instance()
            started = cache.start_scan(quick_scan=quick)
            self._send_json({"started": started, **cache.snapshot()}, status=200 if started else 409)
        else:
            self.send_error(404, "Endpoint non trovato")

    def _serve_file(self, file_path: str, content_type: str):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Errore interno: {e}")

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _get_mime_type(self, file_path: str) -> str:
        if file_path.endswith(".html"):
            return "text/html; charset=utf-8"
        elif file_path.endswith(".css"):
            return "text/css; charset=utf-8"
        elif file_path.endswith(".js"):
            return "application/javascript; charset=utf-8"
        elif file_path.endswith(".json"):
            return "application/json; charset=utf-8"
        elif file_path.endswith(".svg"):
            return "image/svg+xml"
        elif file_path.endswith(".png"):
            return "image/png"
        return "application/octet-stream"

    def log_message(self, format, *args):
        # Silenzia i log delle richieste HTTP per non intasare la console
        pass


def find_free_port(start_port: int = 8765, max_attempts: int = 20) -> int:
    """Trova una porta TCP libera a partire da start_port."""
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start_port


def start_gui_server(initial_scan_quick: bool = False, open_browser: bool = True, port: Optional[int] = None) -> int:
    """Avvia il server web locale e apre la dashboard nel browser."""
    actual_port = port or find_free_port(8765)
    
    server = ThreadingHTTPServer(("127.0.0.1", actual_port), NetProbeHTTPRequestHandler)
    
    url = f"http://127.0.0.1:{actual_port}"
    print(f"\n⚡ Server Web GUI avviato con successo su: \033[1;36m{url}\033[0m")
    
    # Pre-riscalda la cache in background
    NetProbeDataCache.get_instance().start_scan(quick_scan=True)

    if open_browser:
        def open_b():
            time.sleep(0.4)
            webbrowser.open(url)
        threading.Thread(target=open_b, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArresto del server GUI in corso...")
        server.server_close()
        return 0

    return actual_port
