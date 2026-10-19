import contextlib
import io
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.terminal_ui import TerminalUI
from core.estimators import NetworkEstimator
import netprobe


def _report():
    est = NetworkEstimator().calculate_all({}, {}, {}, None)
    return {
        "timestamp": 0, "formatted_time": "t", "quick_scan": {}, "system": {},
        "lan": {}, "wan": {}, "ixp": {}, "performance": {}, "estimations": est,
    }


class TestNoneRendering(unittest.TestCase):
    def test_estimates_are_none(self):
        est = _report()["estimations"]
        self.assertIsNone(est["voice_quality_mos"]["mos_score"])
        self.assertIsNone(est["optical_routing"]["routing_efficiency_pct"])
        self.assertTrue(est["physical_medium"]["insufficient_data"])

    def test_cli_render_no_none(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TerminalUI(no_color=True).render_full_report(_report())
        out = buf.getvalue()
        self.assertIn("N/D", out)
        for line in out.splitlines():
            if any(k in line for k in ("MOS", "R-Factor", "Efficienza", "Confidenza", "Mezzo Fisico", "Accodamento", "Path MTU", "Ipotesi Alternative", "Distanza", "Tratta Fibra", "Latenza Luce")):
                self.assertNotRegex(line, r"\bNone\b", line)
        # Assicura che Path MTU Misurato compaia come N/D
        self.assertIn("Path MTU Misurato (DF)", out)
        self.assertNotIn("~None km", out)
        self.assertNotIn("None ms", out)

    def test_unverified_ixp_hypothesis_rendering(self):
        rep = _report()
        rep["estimations"]["optical_routing"].update({
            "nearest_ixp_name": "Milano / Hub Peering",
            "ixp_city": "Milano",
            "straight_line_distance_km": None,
            "estimated_fiber_path_km": None,
            "theoretical_optical_min_rtt_ms": None,
            "routing_efficiency_pct": None,
            "not_applicable_reason": "ipotesi non verificata su interfaccia fisica"
        })
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TerminalUI(no_color=True).render_full_report(rep)
        out = buf.getvalue()
        self.assertNotIn("~None km", out)
        self.assertNotIn("None ms", out)
        self.assertIn("N/D", out)

    def test_cgnat_label_neutral_on_weak_verdict(self):
        rep = _report()
        rep["wan"] = {"public_ipv4": "1.2.3.4", "nat": {"cgnat_detected": False}}
        rep["estimations"]["physical_medium"] = {
            "predicted_medium": "Mobile Cellular (4G LTE / 5G)",
            "confidence_pct": 34.6,
            "ambiguous": True
        }
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TerminalUI(no_color=True).render_full_report(rep)
        out = buf.getvalue()
        self.assertNotIn("su rete mobile il CGNAT è probabile", out)
        self.assertIn("non rilevabile (nessun indizio di CGNAT", out)

    def test_html_export_no_none(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.html")
            netprobe.export_report(_report(), path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
        self.assertNotRegex(html, r'(?<!["\w])None(?!["\w])')
        self.assertIn("null", html)
        # il JS deve proteggere i null (nessun .toFixed su valore non numerico)
        self.assertIn('typeof mos.mos_score === "number"', html)
        self.assertNotIn('routing_efficiency_pct || "--"', html)
        self.assertIn('wan-path-mtu', html)
        self.assertIn('model-medium-alternatives', html)


    def test_render_with_one_direction_failed(self):
        rep = _report()
        # Simulate: Download failed (<2 MB: 0.0 MB), Upload succeeded (14.2 Mbps, 14.0 MB)
        # Bufferbloat measured only on upload (e.g. 50.56 ms loaded, idle 12.14 ms -> delta +38.42 ms, Grade C)
        rep["performance"] = {
            "primary_latency": {"min_ms": 12.14, "median_ms": 12.35, "jitter_ms": 1.2, "packet_loss_pct": 0.0},
            "bufferbloat": {
                "grade": "C",
                "max_delta_ms": 38.42,
                "idle_latency_ms": 12.14,
                "idle_target": "Cloudflare DNS",
                "download_loaded_ms": None,
                "download_delta_ms": None,
                "upload_loaded_ms": 50.56,
                "upload_delta_ms": 38.42,
                "description": "Misurato solo in upload (DL non disponibile): Moderato incremento della latenza sotto carico."
            },
            "speed": {
                "valid": False,
                "invalid_reason": "Download insufficiente (< 2 MB trasferiti: 0.0 MB)",
                "errors": [{"phase": "stream_down", "status": 429, "reason": "Too Many Requests"}],
                "download": {
                    "valid": False,
                    "invalid_reason": "Download insufficiente (< 2 MB trasferiti: 0.0 MB)",
                    "mbps": None,
                    "bytes": 0
                },
                "upload": {
                    "valid": True,
                    "invalid_reason": None,
                    "mbps": 14.2,
                    "peak_mbps": 15.1,
                    "stability_pct": 92.0,
                    "bytes": 14 * 1024 * 1024
                },
                "download_mbps": None,
                "upload_mbps": 14.2,
                "bytes_downloaded": 0,
                "bytes_uploaded": 14 * 1024 * 1024,
                "bytes_transferred": 14 * 1024 * 1024,
                "test_duration_s": 16.35
            }
        }
        # Recompute estimations
        rep["estimations"] = NetworkEstimator().calculate_all(rep["lan"], rep["wan"], rep["performance"])

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TerminalUI(no_color=True).render_full_report(rep)
        out = buf.getvalue()

        # Invariant 1: No literal None or "+None" in output
        self.assertNotIn("None", out)
        self.assertNotIn("(+None ms)", out)
        self.assertNotIn("+None", out)

        # Invariant 2: Download indicates N/D with reason, Upload shows throughput
        self.assertIn("Download (Sostenuto / Regime)", out)
        self.assertIn("N/D (Download insufficiente", out)
        self.assertIn("Upload (Sostenuto / Regime)", out)
        self.assertIn("14.2", out)
        self.assertIn("14.0 MB", out)

        # Invariant 3: Bufferbloat shows Grado C and upload loaded latency
        self.assertIn("Grado C", out)
        self.assertIn("50.56 ms (+38.42 ms)", out)
        self.assertIn("Latenza Sotto Carico Download", out)

        # Invariant 4: Speedtest error summary printed
        self.assertIn("Errori Speedtest Rilevati", out)
        self.assertIn("HTTP 429", out)

        # Invariant 5: HTML export
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r_one_failed.html")
            netprobe.export_report(rep, path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
        self.assertNotRegex(html, r'(?<!["\w])None(?!["\w])')
        self.assertIn("null", html)


if __name__ == "__main__":
    unittest.main()
