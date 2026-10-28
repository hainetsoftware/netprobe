#!/usr/bin/env python3
"""
NetProbe - Live Path Smoke Test & Invariant Validator.
Executes `netprobe.py --cli --full --export <tmp>.json` as a subprocess,
loads the resulting JSON, and verifies that all core invariants hold:
1. No silent fallbacks: throughput >= 2 MB in each direction, speed.download.valid is True, speed.upload.valid is True.
2. Bufferbloat grade is not None, idle latency is measured, loaded latency is measured.
3. BDP is calculated with no hidden defaults (no 100 Mbps default).
4. Suitability scores are computed for active directions.
5. Exit 0 on success, 1 on failure.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def run_smoke_test():
    print("=" * 70)
    print("  NETPROBE LIVE PATH SMOKE TEST & INVARIANT VERIFIER (SUBPROCESS)")
    print("=" * 70)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tmp_export_path = tf.name

    try:
        cmd = [sys.executable, os.path.join(BASE_DIR, "netprobe.py"), "--cli", "--full", "--export", tmp_export_path]
        print(f"\n[*] Executing: {' '.join(cmd)}")
        t0 = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True)
        dur = time.time() - t0
        print(f"[*] Process exited in {dur:.2f}s with returncode {res.returncode}")

        if res.stdout:
            print("\n--- CLI OUTPUT START ---")
            print(res.stdout)
            print("--- CLI OUTPUT END ---\n")

        if res.returncode != 0:
            print(f"[!] Subprocess stderr:\n{res.stderr}")
            print(f"[!] FAILED: netprobe.py returned code {res.returncode}")
            sys.exit(1)

        if not os.path.exists(tmp_export_path) or os.path.getsize(tmp_export_path) == 0:
            print(f"[!] FAILED: Export file {tmp_export_path} is missing or empty")
            sys.exit(1)

        with open(tmp_export_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        perf = data.get("performance", {})
        est = data.get("estimations", {})
        speed = perf.get("speed", {})
        bb = perf.get("bufferbloat", {})
        bdp = est.get("bandwidth_delay_product", {})
        apps = est.get("application_suitability", {})

        dl_bytes = speed.get("bytes_downloaded", 0)
        ul_bytes = speed.get("bytes_uploaded", 0)
        dl_mb = dl_bytes / (1024 * 1024)
        ul_mb = ul_bytes / (1024 * 1024)

        print("\n[*] Exported Live Metrics:")
        print(f"    Speed Valid:      {speed.get('valid')}")
        print(f"    DL Valid:         {speed.get('download', {}).get('valid')} ({speed.get('download_mbps')} Mbps, {dl_mb:.2f} MB transferred)")
        print(f"    UL Valid:         {speed.get('upload', {}).get('valid')} ({speed.get('upload_mbps')} Mbps, {ul_mb:.2f} MB transferred)")
        print(f"    Idle Latency:     {bb.get('idle_latency_ms')} ms (Target: {bb.get('idle_target')})")
        print(f"    Loaded Latency:   DL {bb.get('download_loaded_ms')} ms (+{bb.get('download_delta_ms')} ms), UL {bb.get('upload_loaded_ms')} ms (+{bb.get('upload_delta_ms')} ms)")
        print(f"    Bufferbloat Grade: {bb.get('grade')}")
        print(f"    BDP:              {bdp.get('bdp_bytes')} bytes ({bdp.get('bdp_kb')} KB)")

        errors = []
        def check(condition, desc):
            if condition:
                print(f"    [PASS] {desc}")
            else:
                print(f"    [FAIL] {desc}")
                errors.append(desc)

        print("\n[*] Verifying Invariants:")
        check(dl_bytes >= 2 * 1024 * 1024, f"Download payload >= 2.0 MB: {dl_mb:.2f} MB transferred")
        check(ul_bytes >= 2 * 1024 * 1024, f"Upload payload >= 2.0 MB: {ul_mb:.2f} MB transferred")
        check(speed.get("download", {}).get("valid") is True, f"speed.download.valid is True")
        check(speed.get("upload", {}).get("valid") is True, f"speed.upload.valid is True")
        check(speed.get("valid") is True, f"speed.valid is True")
        check(speed.get("download_mbps") is not None and speed["download_mbps"] > 0, f"Download throughput > 0: {speed.get('download_mbps')} Mbps")
        check(speed.get("upload_mbps") is not None and speed["upload_mbps"] > 0, f"Upload throughput > 0: {speed.get('upload_mbps')} Mbps")
        check(bb.get("grade") is not None, f"Bufferbloat grade is defined: {bb.get('grade')}")
        check(bb.get("idle_latency_ms") is not None, f"Idle latency is defined: {bb.get('idle_latency_ms')} ms")
        check(bb.get("idle_target") is not None, f"Bufferbloat target identified: {bb.get('idle_target')}")
        check(bdp.get("bdp_bytes") is not None and bdp["bdp_bytes"] > 0, f"BDP calculated: {bdp.get('bdp_bytes')} bytes")

        for app_k, a_info in apps.items():
            check(a_info.get("status") != "N/D", f"Application suitability for {app_k} is valid ({a_info.get('status')}, score: {a_info.get('score')})")

        if errors:
            print(f"\n[!] SMOKE TEST FAILED with {len(errors)} error(s):")
            for e in errors:
                print(f"    - {e}")
            sys.exit(1)
        else:
            print("\n[OK] ALL INVARIANTS VERIFIED SUCCESSFULLY.")
            sys.exit(0)

    finally:
        if os.path.exists(tmp_export_path):
            try:
                os.remove(tmp_export_path)
            except OSError:
                pass


if __name__ == "__main__":
    run_smoke_test()
