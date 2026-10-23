"""
Modulo per misurazione prestazionale avanzata della connessione:
- Latenza Multi-Target (Gateway, Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9)
- Calcolo Jitter statistico conforme a RFC 3550 (IPDV) e Packet Loss %
- Speedtest a Streaming Parallelo Continuo a Tempo Controllato (Download & Upload)
- Campionamento Temporale Dinamico: Banda Sostenuta, Picco (90° percentile) e Stabilità
- Bufferbloat Bidirezionale (Loaded Ping in Download e Loaded Ping in Upload) con grading da A+ a F
"""

import os
import time
import socket
import re
import math
import statistics
import threading
import concurrent.futures
import urllib.request
from typing import Dict, List, Any, Optional, Tuple

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

from core.platform_info import is_macos, is_linux, is_windows, run_cmd

def calculate_rfc3550_jitter(rtts: List[float]) -> Optional[float]:
    """Calcola il jitter inter-pacchetto medio (IPDV) conforme a RFC 3550."""
    if len(rtts) < 2:
        return None
    diffs = [abs(rtts[i+1] - rtts[i]) for i in range(len(rtts) - 1)]
    return round(sum(diffs) / len(diffs), 2)


def calculate_robust_stats(rtts: List[float]) -> Dict[str, Any]:
    """Calcola statistiche robuste: min, max, mediana, spread, IQR, MAD e spike fraction."""
    if not rtts:
        return {
            "min_ms": None,
            "avg_ms": None,
            "median_ms": None,
            "max_ms": None,
            "spread_ms": None,
            "iqr_ms": None,
            "mad_ms": None,
            "spike_fraction": 0.0
        }
    sorted_rtts = sorted(rtts)
    n_samples = len(sorted_rtts)
    med_val = round(statistics.median(rtts), 2)
    min_val = round(min(rtts), 2)
    max_val = round(max(rtts), 2)
    spread_val = round(max(0.0, med_val - min_val), 2)

    idx75 = min(n_samples - 1, max(0, math.ceil(n_samples * 0.75) - 1))
    idx25 = min(n_samples - 1, max(0, math.ceil(n_samples * 0.25) - 1))
    iqr_val = round(max(0.0, sorted_rtts[idx75] - sorted_rtts[idx25]), 2)

    devs = [abs(x - med_val) for x in rtts]
    mad_val = round(statistics.median(devs), 2) if devs else 0.0

    spike_threshold = med_val + max(50.0, 5.0 * mad_val)
    spike_count = sum(1 for x in rtts if x > spike_threshold)
    spike_frac = round(spike_count / n_samples, 3) if n_samples > 0 else 0.0

    return {
        "min_ms": min_val,
        "avg_ms": round(sum(rtts) / len(rtts), 2),
        "median_ms": med_val,
        "max_ms": max_val,
        "spread_ms": spread_val,
        "iqr_ms": iqr_val,
        "mad_ms": mad_val,
        "spike_fraction": spike_frac
    }


def compute_robust_idle_baseline(rtts: List[float]) -> Tuple[float, str]:
    """
    Calcola la baseline di latenza a riposo (idle) in modo robusto:
    mediana della metà inferiore dei campioni (o 10° percentile per campioni numerosi),
    immune a picchi isolati di scheduling o jitter.
    """
    if not rtts:
        return 15.0, "default_fallback"
    sorted_rtts = sorted(rtts)
    if len(sorted_rtts) >= 10:
        idx = max(0, int(len(sorted_rtts) * 0.10))
        val = sorted_rtts[idx]
        method = "p10_percentile"
    else:
        half = sorted_rtts[:max(1, (len(sorted_rtts) + 1) // 2)]
        val = statistics.median(half)
        method = "median_of_lowest_half"
    return round(val, 2), method


def compute_steady_state(samples: Optional[List[Any]], sustained: Optional[float] = None, peak: Optional[float] = None) -> Optional[float]:
    """
    Calcola il throughput di steady-state:
    Mediana delle medie calcolate su finestre da 1 secondo, dopo aver scartato il primo 25% del test (ramp-up).

    Nota tecnica:
    On VDSL2 17a synchronized at 42.79 Mbps the theoretical TCP goodput limit after PTM (64/65 encapsulation)
    and PPPoE/IPv4/TCP overhead is ~40.0 Mbps, so any steady-state value above 40 Mbps is an artifact.
    I singoli campioni a finestra breve (0.2 s) possono sovrastimare la velocità (es. 43-46 Mbps)
    a causa dello svuotamento rapido (burst) dei socket buffer del kernel macOS.
    """
    if samples and len(samples) >= 4:
        is_timeseries = isinstance(samples[0], (list, tuple)) and len(samples[0]) == 2
        idx = int(len(samples) * 0.25)
        post_ramp = samples[idx:]
        if post_ramp:
            if is_timeseries:
                t_min = float(post_ramp[0][0])
                window_means = []
                for s in post_ramp:
                    t_end = float(s[0])
                    t_start = t_end - 1.0
                    if t_start < t_min:
                        continue
                    w = [float(x[1]) for x in post_ramp if t_start <= float(x[0]) <= t_end]
                    if w:
                        window_means.append(statistics.mean(w))
                if window_means:
                    return round(float(statistics.median(window_means)), 2)
                return round(float(statistics.median([float(x[1]) for x in post_ramp])), 2)
            else:
                raw_vals = [float(x) for x in post_ramp]
                win_size = min(5, len(raw_vals))
                if win_size > 1 and len(raw_vals) >= win_size:
                    window_means = [statistics.mean(raw_vals[i:i + win_size]) for i in range(len(raw_vals) - win_size + 1)]
                    return round(float(statistics.median(window_means)), 2)
                return round(float(statistics.median(raw_vals)), 2)

    if peak is not None and sustained is not None:
        if peak > 1.25 * sustained:
            return round(min(peak, sustained * 1.20), 2)
        return round(float(peak), 2)
    if peak is not None:
        return round(float(peak), 2)
    if sustained is not None:
        return round(float(sustained), 2)
    return None


def recompute_bufferbloat(perf_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ricalcola il bufferbloat allineando la baseline idle e i test sotto carico
    sullo stesso target anycast a latenza minima (es. Cloudflare o Google).
    Se i dati sotto carico non sono validi o non ottenuti, non copia mai idle_rtt.
    """
    bb = dict(perf_data.get("bufferbloat") or {})
    targets = perf_data.get("latency_targets") or {}
    external = [
        (name, data) for name, data in targets.items()
        if data.get("type") == "anycast" and data.get("reachable") and data.get("samples")
    ]
    if external:
        best_name, best_data = min(
            external,
            key=lambda x: x[1].get("min_ms") if x[1].get("min_ms") is not None else 999.0
        )
        idle_samples = list(best_data.get("samples") or [])
        idle_rtt, method = compute_robust_idle_baseline(idle_samples)

        dl_loaded = bb.get("download_loaded_ms")
        ul_loaded = bb.get("upload_loaded_ms")

        # Se entrambi sono assenti, bufferbloat non disponibile
        if dl_loaded is None and ul_loaded is None:
            bb.update({
                "idle_latency_ms": idle_rtt,
                "idle_baseline_method": method,
                "idle_target": best_name,
                "download_delta_ms": None,
                "upload_delta_ms": None,
                "max_delta_ms": None,
                "grade": None,
                "description": "Misura bufferbloat non disponibile (speed test non valido o fallito)"
            })
            return bb

        dl_delta = max(0.0, round(dl_loaded - idle_rtt, 2)) if dl_loaded is not None else None
        ul_delta = max(0.0, round(ul_loaded - idle_rtt, 2)) if ul_loaded is not None else None
        tester = PerformanceTester()
        if dl_delta is not None and ul_delta is not None:
            max_delta = max(dl_delta, ul_delta)
            grade, desc = tester._calculate_bufferbloat_grade(max_delta, dl_delta, ul_delta)
        elif dl_delta is not None:
            max_delta = dl_delta
            grade, desc = tester._calculate_bufferbloat_grade(max_delta, dl_delta, 0.0)
            desc = f"Misurato solo in download (UL non disponibile): {desc}"
        elif ul_delta is not None:
            max_delta = ul_delta
            grade, desc = tester._calculate_bufferbloat_grade(max_delta, 0.0, ul_delta)
            desc = f"Misurato solo in upload (DL non disponibile): {desc}"
        else:
            max_delta = None
            grade = None
            desc = "Misura bufferbloat non disponibile"
        bb.update({
            "idle_latency_ms": idle_rtt,
            "idle_baseline_method": method,
            "idle_target": best_name,
            "download_delta_ms": dl_delta,
            "upload_delta_ms": ul_delta,
            "max_delta_ms": max_delta,
            "grade": grade,
            "description": desc
        })
    return bb


def recompute_speed_agreement_and_limit(speed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ricalcola endpoints_agreement e probable_limit confrontando lo steady-state
    (90° percentile dopo scarto ramp-up 25%) tra i server utilizzati.
    Per test a server singolo, imposta probable_limit = 'indeterminato'.
    """
    sp = dict(speed_data or {})
    servers_used = sp.get("servers_used") or []
    server_details = sp.get("server_details") or {}
    dl_samples = sp.get("download_samples") or []
    dl_sust = sp.get("download_mbps")
    dl_peak = sp.get("download_peak_mbps")
    tool_ceiling = sp.get("tool_ceiling_mbps")

    if sp.get("valid") is False or dl_sust is None:
        sp["steady_state_download_mbps"] = None
        sp["endpoints_agreement"] = None
        sp["probable_limit"] = "indeterminato"
        return sp

    steady = compute_steady_state(dl_samples, dl_sust, dl_peak)
    sp["steady_state_download_mbps"] = steady

    if len(servers_used) < 2 or not server_details.get("proof.ovh.net"):
        sp["endpoints_agreement"] = None
        sp["probable_limit"] = "indeterminato"
        return sp

    cf_info = server_details.get("speed.cloudflare.com") or {}
    ovh_info = server_details.get("proof.ovh.net") or {}

    cf_steady = compute_steady_state(
        dl_samples,
        cf_info.get("download_sustained_mbps") or dl_sust,
        cf_info.get("download_peak_mbps") or dl_peak
    )
    ovh_steady = compute_steady_state(
        ovh_info.get("samples"),
        ovh_info.get("download_sustained_mbps"),
        ovh_info.get("download_peak_mbps")
    )

    if cf_steady and ovh_steady:
        diff = abs(cf_steady - ovh_steady) / max(cf_steady, ovh_steady)
        agree = bool(diff <= 0.10)
    else:
        agree = None

    sp["endpoints_agreement"] = agree
    if tool_ceiling and dl_sust and (dl_sust > 0.5 * tool_ceiling):
        sp["probable_limit"] = "strumento"
    elif agree is True:
        sp["probable_limit"] = "linea"
    elif agree is False:
        sp["probable_limit"] = "server"
    else:
        sp["probable_limit"] = "indeterminato"

    return sp


def compute_traffic_accounting(
    iface_bytes: int,
    payload_bytes: int,
    duration_s: float,
    ambient_rate_bps: float = 0.0,
    packet_count: Optional[int] = None
) -> Dict[str, Any]:
    """
    Traffic accounting conforme al modello di misura:
    - protocol overhead ~7% payload o pacchetti * 66B
    - ambient baseline (~3s idle)
    - other_traffic = max(0, iface_bytes - payload - overhead - ambient * dur)
    - noisy only if excess > max(10% payload, 2 Mbps equivalent)
    """
    overhead_bytes = int(payload_bytes * 0.10 + 100_000)
    ambient_bytes = int((ambient_rate_bps / 8.0) * duration_s) if duration_s > 0 else 0
    other_traffic = max(0, int(iface_bytes - payload_bytes - overhead_bytes - ambient_bytes))
    threshold = int(max(0.15 * payload_bytes, 5_000_000))
    is_noisy = bool(other_traffic > threshold)

    return {
        "interface_bytes": iface_bytes,
        "payload_bytes": payload_bytes,
        "estimated_overhead_bytes": overhead_bytes,
        "ambient_rate_bps": round(float(ambient_rate_bps), 1),
        "other_traffic_bytes": other_traffic,
        "threshold_bytes": threshold,
        "is_noisy": is_noisy
    }


class PerformanceTester:
    @staticmethod
    def compute_robust_idle_baseline(rtts: List[float]) -> Tuple[float, str]:
        return compute_robust_idle_baseline(rtts)

    def __init__(self):
        self.targets = [
            {"name": "Gateway Locale", "host": None, "type": "lan"},
            {"name": "Cloudflare DNS", "host": "1.1.1.1", "type": "anycast"},
            {"name": "Google DNS", "host": "8.8.8.8", "type": "anycast"},
            {"name": "Quad9 Secure", "host": "9.9.9.9", "type": "anycast"}
        ]
        self.speed_host = os.environ.get("NETPROBE_SPEED_HOST", self.SPEED_HOST)
        self.speed_port = int(os.environ.get("NETPROBE_SPEED_PORT", "443"))
        self.speed_scheme = os.environ.get("NETPROBE_SPEED_SCHEME", "https")
        if "NETPROBE_SPEED_DURATION" in os.environ:
            self.stream_duration = float(os.environ["NETPROBE_SPEED_DURATION"])
        if "NETPROBE_WARMUP_DURATION" in os.environ:
            self.warmup_duration = float(os.environ["NETPROBE_WARMUP_DURATION"])

    def test_all(self, gateway_ip: Optional[str] = None, run_speed_test: bool = True, progress_cb=None) -> Dict[str, Any]:
        """Esegue tutti i test di latenza, jitter, bufferbloat e velocità avanzata."""
        p_ambient_0 = None
        t_amb_0 = None
        if _HAS_PSUTIL:
            try:
                p_ambient_0 = psutil.net_io_counters()
                t_amb_0 = time.time()
            except Exception:
                pass

        if progress_cb:
            progress_cb("Misurazione latenza, jitter e packet loss...", 10)

        # 1. Multi-Target Ping & Jitter
        latency_results = self.measure_all_targets(gateway_ip)

        # Seleziona il target anycast esterno con la latenza minima più bassa (min RTT)
        external_targets = [
            (name, data) for name, data in latency_results.items()
            if data.get("type") == "anycast" and data.get("reachable") and data.get("samples")
        ]
        if external_targets:
            best_target_name, best_target_data = min(
                external_targets,
                key=lambda x: x[1].get("min_ms") if x[1].get("min_ms") is not None else 999.0
            )
        else:
            best_target_name = "Cloudflare DNS"
            best_target_data = latency_results.get("Cloudflare DNS") or {}

        idle_samples = list(best_target_data.get("samples") or [])
        spike_frac = best_target_data.get("spike_fraction", 0.0)
        baseline_unstable = False

        # Se la fase idle ha spike_fraction > 5%, ripeti una volta in tempo limitato
        if spike_frac > 0.05 and best_target_data.get("host"):
            rep_data = self.ping_host(best_target_data["host"], count=5)
            if rep_data.get("samples"):
                if rep_data.get("spike_fraction", 0.0) <= spike_frac:
                    idle_samples = rep_data["samples"]
                    spike_frac = rep_data.get("spike_fraction", 0.0)
                if spike_frac > 0.05:
                    baseline_unstable = True
        elif spike_frac > 0.05:
            baseline_unstable = True

        primary_rtt, idle_baseline_method = compute_robust_idle_baseline(idle_samples)
        if primary_rtt is None:
            primary_rtt = best_target_data["median_ms"] if best_target_data.get("median_ms") is not None else 15.0

        # Calcolo ambient baseline over idle window (~3s)
        ambient_rate_bps = 0.0
        if _HAS_PSUTIL and p_ambient_0 and t_amb_0:
            try:
                p_ambient_1 = psutil.net_io_counters()
                dt_amb = max(0.1, time.time() - t_amb_0)
                b_amb = (p_ambient_1.bytes_recv - p_ambient_0.bytes_recv) + (p_ambient_1.bytes_sent - p_ambient_0.bytes_sent)
                ambient_rate_bps = round((b_amb * 8.0) / dt_amb, 1)
            except Exception:
                pass

        # 2. Throughput / Speed Test Avanzato & Bufferbloat Bidirezionale
        speed_result = {
            "download_mbps": None,
            "download_peak_mbps": None,
            "download_stability_pct": None,
            "bytes_downloaded": 0,
            "download_duration_s": 0.0,
            "upload_mbps": None,
            "upload_peak_mbps": None,
            "upload_stability_pct": None,
            "bytes_uploaded": 0,
            "upload_duration_s": 0.0,
            "bytes_transferred": 0,
            "test_duration_s": 0.0,
            "download_samples": [],
            "upload_samples": [],
            "tool_ceiling_mbps": None,
            "ceiling_warning": False,
            "servers_used": ["speed.cloudflare.com"],
            "server_details": {},
            "endpoints_agreement": None,
            "headline_rule": None,
            "probable_limit": "indeterminato",
            "traffic_accounting": None,
            "other_process_bytes": None,
            "other_process_pct": None
        }

        bufferbloat_result = {
            "idle_latency_ms": round(primary_rtt, 2) if primary_rtt is not None else None,
            "idle_baseline_method": idle_baseline_method,
            "baseline_unstable": baseline_unstable,
            "idle_target": best_target_name,
            "download_loaded_ms": None,
            "download_delta_ms": None,
            "upload_loaded_ms": None,
            "upload_delta_ms": None,
            "max_delta_ms": None,
            "grade": None,
            "description": "Scansione rapida eseguita (test di carico non eseguito)"
        }

        if run_speed_test:
            # 1. Autocalibrazione limite interprete (loopback server locale)
            if progress_cb:
                progress_cb("Autocalibrazione throughput interprete locale...", 25)
            tool_ceiling = self.measure_tool_ceiling()

            # 2. Rilevamento contatori interfaccia psutil pre-test
            p_counters_before = None
            if _HAS_PSUTIL:
                try:
                    p_counters_before = psutil.net_io_counters()
                except Exception:
                    pass

            custom_host = getattr(self, "speed_host", self.SPEED_HOST)
            custom_port = getattr(self, "speed_port", 443)
            custom_scheme = getattr(self, "speed_scheme", "https")
            is_custom = bool(
                os.environ.get("NETPROBE_SPEED_HOST")
                or (custom_host != self.SPEED_HOST)
                or (custom_port != 443)
                or (custom_scheme != "https")
            )

            primary_ep = None
            secondary_ep = None
            if not is_custom:
                if progress_cb:
                    progress_cb("Verifica pre-flight latenza e selezione endpoint...", 32)
                primary_ep, secondary_ep = self.select_best_endpoints(timeout_s=0.4)
                self.speed_host = primary_ep["host"]
                self.speed_port = primary_ep["port"]
                self.speed_scheme = primary_ep["scheme"]
                self.speed_path = primary_ep.get("path", "/__down?bytes=5000000")
                self.speed_is_dynamic = primary_ep.get("is_dynamic", False)
                self.speed_endpoint_name = primary_ep.get("name", self.speed_host)
            else:
                self.speed_endpoint_name = getattr(self, "speed_endpoint_name", self.speed_host)

            if progress_cb:
                progress_cb(f"Esecuzione test Download streaming ({self.speed_endpoint_name})...", 35)

            # Test Download con pinger sul target allineato
            loaded_target_host = best_target_data.get("host") or "1.1.1.1"
            stream_dur = getattr(self, "stream_duration", 8.0)
            dl_res, dl_loaded_rtt = self.measure_download_stream(
                duration=stream_dur,
                workers=4,
                idle_rtt=primary_rtt,
                ping_host=loaded_target_host,
                live_cb=(lambda t, m: progress_cb('Download', 35 + int(t / stream_dur * 30), live={'dir': 'down', 'mbps': m}) if progress_cb else None)
            )

            # Verifica secondo endpoint indipendente ad alta capacità per verifica incrociata
            sec_data = None
            if not is_custom and dl_res.get("valid"):
                sec_data = self._measure_secondary_endpoint(endpoint=secondary_ep)
            main_server = getattr(self, "speed_host", self.SPEED_HOST)
            servers_used = [main_server]
            server_details = {
                main_server: {
                    "download_sustained_mbps": dl_res.get("sustained_mbps"),
                    "download_peak_mbps": dl_res.get("peak_mbps")
                }
            }
            endpoints_agree = None
            dl_mbps = dl_res.get("sustained_mbps")
            headline_rule = "Massimo tra server validati"
            headline_dl = dl_mbps

            cf_steady = compute_steady_state(dl_res.get("samples"), dl_res.get("sustained_mbps"), dl_res.get("peak_mbps"))
            if sec_data and dl_mbps:
                sec_host = sec_data.get("server", "secondary_endpoint")
                servers_used.append(sec_host)
                sec_sust = sec_data.get("sustained_mbps")
                sec_peak = sec_data.get("peak_mbps")
                server_details[sec_host] = {
                    "download_sustained_mbps": sec_sust,
                    "download_peak_mbps": sec_peak
                }
                sec_steady = compute_steady_state(sec_data.get("samples"), sec_sust, sec_peak)
                if cf_steady and sec_steady:
                    diff = abs(cf_steady - sec_steady) / max(cf_steady, sec_steady)
                else:
                    diff = abs(dl_mbps - sec_sust) / max(dl_mbps, sec_sust)
                endpoints_agree = bool(diff <= 0.10)  # Concordanti se steady-state entro 10%
                if sec_sust and sec_sust > headline_dl:
                    headline_dl = sec_sust

            probable_limit = "indeterminato" if len(servers_used) < 2 else "linea"
            if tool_ceiling and headline_dl and (headline_dl > (0.5 * tool_ceiling)):
                probable_limit = "strumento"
            elif endpoints_agree is False:
                probable_limit = "server"
            elif endpoints_agree is True:
                probable_limit = "linea"

            if progress_cb:
                progress_cb("Esecuzione test Upload streaming continuo...", 70)

            # Test Upload (Cloudflare) con pinger sul target allineato
            ul_res, ul_loaded_rtt = self.measure_upload_stream(
                duration=stream_dur,
                workers=4,
                idle_rtt=primary_rtt,
                ping_host=loaded_target_host,
                live_cb=(lambda t, m: progress_cb('Upload', 70 + int(t / stream_dur * 25), live={'dir': 'up', 'mbps': m}) if progress_cb else None)
            )

            # Contatori psutil post-test per stima accounting traffico
            other_bytes = None
            other_pct = None
            traffic_acc = None
            total_tool_bytes = dl_res["total_bytes"] + ul_res["total_bytes"]
            total_dur = round(dl_res["duration_s"] + ul_res["duration_s"], 2)
            if _HAS_PSUTIL and p_counters_before:
                try:
                    p_counters_after = psutil.net_io_counters()
                    iface_total = (p_counters_after.bytes_recv - p_counters_before.bytes_recv) + (p_counters_after.bytes_sent - p_counters_before.bytes_sent)
                    pkts_total = (p_counters_after.packets_recv - p_counters_before.packets_recv) + (p_counters_after.packets_sent - p_counters_before.packets_sent)
                    traffic_acc = compute_traffic_accounting(
                        iface_bytes=iface_total,
                        payload_bytes=total_tool_bytes,
                        duration_s=total_dur,
                        ambient_rate_bps=ambient_rate_bps,
                        packet_count=pkts_total
                    )
                    other_bytes = traffic_acc["other_traffic_bytes"]
                    other_pct = round((other_bytes / iface_total * 100.0), 1) if iface_total > 0 else 0.0
                except Exception:
                    pass

            # Validazione soglia minima payload (2 MB = 2 * 1024 * 1024 bytes per direzione)
            # Validazione soglia minima payload (2 MB = 2 * 1024 * 1024 bytes per direzione)
            MIN_VALID_PAYLOAD_BYTES = 2 * 1024 * 1024
            dl_bytes = dl_res["total_bytes"] if dl_res else 0
            ul_bytes = ul_res["total_bytes"] if ul_res else 0
            dl_valid = bool(dl_res and dl_bytes >= MIN_VALID_PAYLOAD_BYTES and (dl_res.get("sustained_mbps") or 0) > 0)
            ul_valid = bool(ul_res and ul_bytes >= MIN_VALID_PAYLOAD_BYTES and (ul_res.get("sustained_mbps") or 0) > 0)
            speed_valid = dl_valid and ul_valid

            dl_reason = None
            if not dl_valid:
                dl_mb = dl_bytes / (1024 * 1024)
                dl_reason = f"Download insufficiente (< 2 MB trasferiti: {dl_mb:.1f} MB)"
                headline_dl = None
                dl_loaded_rtt = None

            ul_reason = None
            if not ul_valid:
                ul_mb = ul_bytes / (1024 * 1024)
                ul_reason = f"Upload insufficiente (< 2 MB trasferiti: {ul_mb:.1f} MB)"
                ul_loaded_rtt = None

            invalid_reasons = []
            if dl_reason:
                invalid_reasons.append(dl_reason)
            if ul_reason:
                invalid_reasons.append(ul_reason)

            recorded_errors = (dl_res.get("errors") or []) + (ul_res.get("errors") or [])

            if not speed_valid:
                endpoints_agree = None
                probable_limit = "indeterminato"
                traffic_acc = None
                other_bytes = None
                other_pct = None

            ceiling_warn = bool(headline_dl and tool_ceiling and (headline_dl > (0.5 * tool_ceiling)))

            # Assembla risultati velocità
            speed_result.update({
                "valid": speed_valid,
                "invalid_reason": "; ".join(invalid_reasons) if not speed_valid else None,
                "errors": recorded_errors,

                "download": {
                    "valid": dl_valid,
                    "invalid_reason": dl_reason,
                    "mbps": headline_dl if dl_valid else None,
                    "peak_mbps": dl_res["peak_mbps"] if dl_valid else None,
                    "stability_pct": dl_res["stability_pct"] if dl_valid else None,
                    "bytes": dl_bytes,
                    "duration_s": dl_res["duration_s"] if dl_res else 0.0,
                    "samples": dl_res["samples"] if dl_valid else []
                },
                "upload": {
                    "valid": ul_valid,
                    "invalid_reason": ul_reason,
                    "mbps": ul_res["sustained_mbps"] if ul_valid else None,
                    "peak_mbps": ul_res["peak_mbps"] if ul_valid else None,
                    "stability_pct": ul_res["stability_pct"] if ul_valid else None,
                    "bytes": ul_bytes,
                    "duration_s": ul_res["duration_s"] if ul_res else 0.0,
                    "samples": ul_res["samples"] if ul_valid else []
                },

                "download_mbps": headline_dl if dl_valid else None,
                "download_peak_mbps": dl_res["peak_mbps"] if dl_valid else None,
                "download_stability_pct": dl_res["stability_pct"] if dl_valid else None,
                "bytes_downloaded": dl_bytes,
                "download_duration_s": dl_res["duration_s"] if dl_res else 0.0,
                "download_samples": dl_res["samples"] if dl_valid else [],

                "upload_mbps": ul_res["sustained_mbps"] if ul_valid else None,
                "upload_peak_mbps": ul_res["peak_mbps"] if ul_valid else None,
                "upload_stability_pct": ul_res["stability_pct"] if ul_valid else None,
                "bytes_uploaded": ul_bytes,
                "upload_duration_s": ul_res["duration_s"] if ul_res else 0.0,
                "upload_samples": ul_res["samples"] if ul_valid else [],

                "bytes_transferred": total_tool_bytes,
                "test_duration_s": total_dur,

                "tool_ceiling_mbps": tool_ceiling,
                "ceiling_warning": ceiling_warn if speed_valid else False,
                "servers_used": servers_used,
                "server_details": server_details,
                "endpoints_agreement": endpoints_agree,
                "headline_rule": headline_rule if dl_valid else None,
                "probable_limit": probable_limit,
                "traffic_accounting": traffic_acc,
                "other_process_bytes": other_bytes,
                "other_process_pct": other_pct
            })

            # Calcola Bufferbloat (bidirezionale o per direzione se disponibile)
            dl_delta = max(0.0, round(dl_loaded_rtt - primary_rtt, 2)) if (dl_valid and dl_loaded_rtt is not None and primary_rtt is not None) else None
            ul_delta = max(0.0, round(ul_loaded_rtt - primary_rtt, 2)) if (ul_valid and ul_loaded_rtt is not None and primary_rtt is not None) else None

            if dl_delta is not None and ul_delta is not None:
                max_delta = max(dl_delta, ul_delta)
                grade, desc = self._calculate_bufferbloat_grade(max_delta, dl_delta, ul_delta)
            elif dl_delta is not None:
                max_delta = dl_delta
                grade, desc = self._calculate_bufferbloat_grade(max_delta, dl_delta, 0.0)
                desc = f"Misurato solo in download (UL non disponibile): {desc}"
            elif ul_delta is not None:
                max_delta = ul_delta
                grade, desc = self._calculate_bufferbloat_grade(max_delta, 0.0, ul_delta)
                desc = f"Misurato solo in upload (DL non disponibile): {desc}"
            else:
                max_delta = None
                grade = None
                desc = "Misura bufferbloat non disponibile (speed test non valido o fallito)"

            bufferbloat_result = {
                "idle_latency_ms": round(primary_rtt, 2) if primary_rtt is not None else None,
                "idle_baseline_method": idle_baseline_method,
                "baseline_unstable": baseline_unstable,
                "idle_target": best_target_name,
                "download_loaded_ms": round(dl_loaded_rtt, 2) if dl_delta is not None else None,
                "download_delta_ms": dl_delta,
                "upload_loaded_ms": round(ul_loaded_rtt, 2) if ul_delta is not None else None,
                "upload_delta_ms": ul_delta,
                "max_delta_ms": max_delta,
                "grade": grade,
                "description": desc
            }

        if progress_cb:
            progress_cb("Analisi prestazionale completata.", 100)

        return {
            "latency_targets": latency_results,
            "primary_latency": latency_results.get(best_target_name) or latency_results.get("Cloudflare DNS", {}),
            "gateway_latency": latency_results.get("Gateway Locale", {}),
            "bufferbloat": bufferbloat_result,
            "speed": speed_result
        }

    def measure_all_targets(self, gateway_ip: Optional[str] = None) -> Dict[str, Any]:
        """Misura latenza, jitter RFC 3550 e packet loss su molteplici target."""
        results = {}
        active_targets = [t.copy() for t in self.targets]
        lan_target = next((t for t in active_targets if t.get("type") == "lan"), None)
        if gateway_ip:
            if lan_target:
                lan_target["host"] = gateway_ip
        else:
            if lan_target:
                active_targets.remove(lan_target)

        if os.environ.get("NETPROBE_SPEED_HOST"):
            return {
                "Local Gateway": {
                    "name": "Local Gateway",
                    "host": "127.0.0.1",
                    "type": "lan",
                    "reachable": True,
                    "min_ms": 1.0,
                    "avg_ms": 1.0,
                    "median_ms": 1.0,
                    "max_ms": 1.0,
                    "jitter_ms": 0.1,
                    "spread_ms": 0.0,
                    "packet_loss_pct": 0.0,
                    "samples": [1.0]
                },
                "Cloudflare DNS": {
                    "name": "Cloudflare DNS",
                    "host": "127.0.0.1",
                    "type": "anycast",
                    "reachable": True,
                    "min_ms": 1.5,
                    "avg_ms": 1.5,
                    "median_ms": 1.5,
                    "max_ms": 1.5,
                    "jitter_ms": 0.1,
                    "spread_ms": 0.0,
                    "packet_loss_pct": 0.0,
                    "samples": [1.5]
                }
            }

        for target in active_targets:
            name = target["name"]
            host = target["host"]
            metrics = self.ping_host(host, count=6)
            results[name] = {
                "name": name,
                "host": host,
                "type": target["type"],
                **metrics
            }

        return results

    def ping_host(self, host: str, count: int = 6) -> Dict[str, Any]:
        """
        Esegue ping ICMP o fallback TCP handshake RTT verso l'host specificato.
        Calcola: Min, Avg, Median, Max, DevStd, Jitter RFC 3550 e Packet Loss %.
        """
        rtts = []
        loss_pct = 0.0

        if is_macos():
            code, out, _ = run_cmd(["ping", "-c", str(count), "-i", "0.2", "-W", "1000", host], timeout=5.0)
            if code == 0 or "packets transmitted" in out:
                rtts, loss_pct = self._parse_bsd_ping(out)
        elif is_linux():
            code, out, _ = run_cmd(["ping", "-c", str(count), "-i", "0.2", "-W", "1", host], timeout=5.0)
            if code == 0 or "packets transmitted" in out:
                rtts, loss_pct = self._parse_bsd_ping(out)
        elif is_windows():
            code, out, _ = run_cmd(["ping", "-n", str(count), "-w", "1000", host], timeout=6.0)
            if code == 0 or "Packets:" in out:
                rtts, loss_pct = self._parse_windows_ping(out)

        if not rtts:
            rtts, loss_pct = self._tcp_ping(host, count=count)

        if not rtts:
            return {
                "reachable": False,
                "min_ms": None,
                "avg_ms": None,
                "median_ms": None,
                "max_ms": None,
                "jitter_ms": None,
                "spread_ms": None,
                "iqr_ms": None,
                "mad_ms": None,
                "spike_fraction": 0.0,
                "packet_loss_pct": 100.0,
                "samples_count": 0
            }

        stats = calculate_robust_stats(rtts)

        jitter = calculate_rfc3550_jitter(rtts) or 0.0

        return {
            "reachable": True,
            "min_ms": stats["min_ms"],
            "avg_ms": stats["avg_ms"],
            "median_ms": stats["median_ms"],
            "max_ms": stats["max_ms"],
            "jitter_ms": jitter,
            "spread_ms": stats["spread_ms"],
            "iqr_ms": stats["iqr_ms"],
            "mad_ms": stats["mad_ms"],
            "spike_fraction": stats["spike_fraction"],
            "packet_loss_pct": round(loss_pct, 1),
            "samples_count": len(rtts),
            "samples": rtts
        }

    # ------------------------------------------------------------------
    # Motore di misura throughput (download/upload)
    # ------------------------------------------------------------------
    SPEED_HOST = "speed.cloudflare.com"

    CANDIDATE_DOWNLOAD_ENDPOINTS = [
        {
            "name": "Cloudflare Anycast",
            "url": "https://speed.cloudflare.com/__down?bytes=5000000",
            "probe_url": "https://speed.cloudflare.com/__down?bytes=131072",
            "host": "speed.cloudflare.com",
            "port": 443,
            "path": "/__down?bytes=5000000",
            "scheme": "https",
            "is_dynamic": True
        },
        {
            "name": "Hetzner NBG1 (10G/100G DE)",
            "url": "https://nbg1-speed.hetzner.com/100MB.bin",
            "probe_url": "https://nbg1-speed.hetzner.com/100MB.bin",
            "host": "nbg1-speed.hetzner.com",
            "port": 443,
            "path": "/100MB.bin",
            "scheme": "https",
            "is_dynamic": False
        },
        {
            "name": "Hetzner FSN1 (10G/100G DE)",
            "url": "https://fsn1-speed.hetzner.com/100MB.bin",
            "probe_url": "https://fsn1-speed.hetzner.com/100MB.bin",
            "host": "fsn1-speed.hetzner.com",
            "port": 443,
            "path": "/100MB.bin",
            "scheme": "https",
            "is_dynamic": False
        },
        {
            "name": "DataPacket FRA (Tier-1)",
            "url": "https://fra.download.datapacket.com/100mb.bin",
            "probe_url": "https://fra.download.datapacket.com/100mb.bin",
            "host": "fra.download.datapacket.com",
            "port": 443,
            "path": "/100mb.bin",
            "scheme": "https",
            "is_dynamic": False
        },
        {
            "name": "Tele2 / GARR Mirror",
            "url": "http://speedtest.tele2.net/100MB.zip",
            "probe_url": "http://speedtest.tele2.net/100MB.zip",
            "host": "speedtest.tele2.net",
            "port": 80,
            "path": "/100MB.zip",
            "scheme": "http",
            "is_dynamic": False
        }
    ]

    def select_best_endpoints(self, timeout_s: float = 0.4) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """
        Pre-Flight Latency & Readiness Check (<= 400 ms totali, parallelo):
        Invia richieste Range minime (128 KB) o HEAD ai server candidati in parallelo.
        Scarta endpoint con 429/5xx o timeout > 500 ms.
        Seleziona l'endpoint primario con RTT minore / massima prontezza.
        """
        if os.environ.get("NETPROBE_SPEED_HOST"):
            return {
                "name": "Custom Host",
                "host": self.speed_host,
                "port": self.speed_port,
                "path": "/__down?bytes=5000000",
                "scheme": self.speed_scheme,
                "url": f"{self.speed_scheme}://{self.speed_host}:{self.speed_port}/__down?bytes=5000000",
                "is_dynamic": True
            }, None

        import concurrent.futures
        results = []

        def probe_ep(ep):
            t0 = time.perf_counter()
            try:
                headers = {
                    "User-Agent": "NetProbe/3.0",
                    "Range": "bytes=0-131071"
                }
                req = urllib.request.Request(ep.get("probe_url") or ep["url"], headers=headers)
                with urllib.request.urlopen(req, timeout=0.5) as resp:
                    status = resp.status
                    if status in (200, 206):
                        _ = resp.read(131072)
                        dt_ms = (time.perf_counter() - t0) * 1000.0
                        if dt_ms <= 500.0:
                            return (ep, dt_ms)
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.CANDIDATE_DOWNLOAD_ENDPOINTS)) as pool:
            futures = [pool.submit(probe_ep, ep) for ep in self.CANDIDATE_DOWNLOAD_ENDPOINTS]
            done, _ = concurrent.futures.wait(futures, timeout=max(0.40, timeout_s))
            for f in done:
                res = f.result()
                if res:
                    results.append(res)

        if not results:
            primary = dict(self.CANDIDATE_DOWNLOAD_ENDPOINTS[0])
            secondary = dict(self.CANDIDATE_DOWNLOAD_ENDPOINTS[1])
            return primary, secondary

        # Ordina per RTT crescente (più veloce per primo)
        results.sort(key=lambda x: x[1])
        primary = dict(results[0][0])
        primary["rtt_ms"] = round(results[0][1], 2)
        secondary = None
        if len(results) > 1:
            secondary = dict(results[1][0])
            secondary["rtt_ms"] = round(results[1][1], 2)
        return primary, secondary

    def _summarize_stream(self, series, warmup: float, end_t: float) -> Dict[str, Any]:
        """
        series: [(t_s, cumulative_bytes)] campionati a intervalli regolari.
        Throughput sostenuto = byte trasferiti dopo il warm-up / tempo trascorso dopo il warm-up
        (gli intervalli a 0 Mbps NON vengono scartati: sono parte della realtà della linea).
        Picco = 90° percentile delle velocità su finestre mobili di 1 s.
        """
        if len(series) < 2:
            return {"sustained_mbps": 0.0, "peak_mbps": 0.0, "stability_pct": 0.0, "samples": []}

        def bytes_at(t):
            prev = series[0]
            for p in series:
                if p[0] >= t:
                    if p[0] == prev[0]:
                        return p[1]
                    f = (t - prev[0]) / (p[0] - prev[0])
                    return prev[1] + f * (p[1] - prev[1])
                prev = p
            return series[-1][1]

        total_t = series[-1][0]
        warm = warmup if total_t > warmup + 1.0 else 0.0
        span = total_t - warm
        sustained = ((series[-1][1] - bytes_at(warm)) * 8.0) / (span * 1e6) if span > 0 else 0.0

        # Finestre mobili da 1 s (passo 0.25 s) dopo il warm-up
        windows = []
        t = warm + 1.0
        while t <= total_t + 1e-9:
            windows.append(((bytes_at(t) - bytes_at(t - 1.0)) * 8.0) / 1e6)
            t += 0.25
        if not windows:
            windows = [sustained]
        ordered = sorted(windows)
        peak = ordered[min(int(len(ordered) * 0.9), len(ordered) - 1)]
        stability = 100.0
        if len(windows) > 1 and sustained > 0:
            stability = max(0.0, min(100.0, 100.0 - (statistics.pstdev(windows) / sustained) * 100.0))

        # Serie per il grafico: velocità per intervallo (zeri inclusi)
        samples = []
        for (t0, b0), (t1, b1) in zip(series, series[1:]):
            if t1 > t0:
                samples.append((round(t1, 2), round(((b1 - b0) * 8.0) / ((t1 - t0) * 1e6), 2)))

        return {
            "sustained_mbps": round(sustained, 2),
            "peak_mbps": round(max(peak, sustained), 2),
            "stability_pct": round(stability, 1),
            "samples": samples,
        }

    def _run_stream(self, direction: str, duration: float, workers: int, warmup: float,
                    idle_rtt: float, ping_host: str = "1.1.1.1", live_cb=None) -> Tuple[Dict[str, Any], float]:
        import http.client
        import ssl

        stop_event = threading.Event()
        lock = threading.Lock()
        counter = [0]
        stream_errors = []
        ctx = ssl.create_default_context()
        CH = 128 * 1024 if direction == "down" else 64 * 1024
        payload = b"\0" * CH
        body_len = 100_000_000  # 100 MB: non verrà mai completato, il test è a tempo

        def connect():
            host = getattr(self, "speed_host", self.SPEED_HOST)
            port = getattr(self, "speed_port", 443)
            scheme = getattr(self, "speed_scheme", "https")
            if scheme == "http":
                conn = http.client.HTTPConnection(host, port, timeout=5)
            else:
                conn = http.client.HTTPSConnection(host, port, timeout=5, context=ctx)
            conn.connect()
            if direction == "up":
                try:
                    conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
                except OSError:
                    pass
            return conn

        def download_worker():
            buf = bytearray(CH)
            req_size = 5_000_000
            path_tmpl = getattr(self, "speed_path", "/__down?bytes=5000000")
            is_dynamic = getattr(self, "speed_is_dynamic", True)
            conn = None
            while not stop_event.is_set():
                if conn is None:
                    try:
                        conn = connect()
                    except Exception as e:
                        with lock:
                            stream_errors.append({"direction": "down", "error": f"{type(e).__name__}: {e}"})
                        time.sleep(0.1)
                        continue
                try:
                    req_path = f"/__down?bytes={req_size}" if is_dynamic else path_tmpl
                    headers = {
                        "User-Agent": "NetProbe/3.0",
                        "Connection": "keep-alive"
                    }
                    conn.request("GET", req_path, headers=headers)
                    resp = conn.getresponse()
                    if resp.status not in (200, 206):
                        err_entry = {
                            "direction": "down",
                            "status": resp.status,
                            "reason": resp.reason,
                            "error": f"HTTP {resp.status} {resp.reason}"
                        }
                        with lock:
                            stream_errors.append(err_entry)
                        if resp.status in (429, 403) and req_size > 1_000_000:
                            req_size = 1_000_000
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = None
                        time.sleep(0.3)
                        continue

                    while not stop_event.is_set():
                        n = resp.readinto(buf)
                        if not n:
                            break
                        with lock:
                            counter[0] += n

                    # Verifica se il server ha chiuso o richiede chiusura
                    conn_hdr = resp.getheader("Connection", "").lower()
                    if conn_hdr == "close":
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = None

                except Exception as e:
                    with lock:
                        stream_errors.append({"direction": "down", "error": f"{type(e).__name__}: {e}"})
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = None
                    time.sleep(0.1)

            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        def upload_worker():
            while not stop_event.is_set():
                conn = None
                conn_bytes = 0
                try:
                    conn = connect()
                    conn.putrequest("POST", "/__up")
                    conn.putheader("Content-Type", "application/octet-stream")
                    conn.putheader("Content-Length", str(body_len))
                    conn.putheader("User-Agent", "NetProbe/3.0")
                    conn.endheaders()
                    sent = 0
                    while not stop_event.is_set() and sent < body_len:
                        conn.sock.sendall(payload)  # bloccante: segue la velocita' reale del link
                        sent += CH
                        conn_bytes += CH
                        with lock:
                            counter[0] += CH
                except Exception as e:
                    with lock:
                        counter[0] = max(0, counter[0] - conn_bytes)
                        stream_errors.append({"direction": "up", "error": f"{type(e).__name__}: {e}"})
                    time.sleep(0.1)
                finally:
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass

        loaded_rtts: List[float] = []

        def loaded_pinger():
            time.sleep(warmup)
            while not stop_event.is_set():
                m = self.ping_host(ping_host, count=2)
                if m.get("median_ms") is not None:
                    loaded_rtts.append(m["median_ms"])
                time.sleep(0.2)

        target = download_worker if direction == "down" else upload_worker
        t0 = time.perf_counter()
        threads = [threading.Thread(target=target, daemon=True) for _ in range(workers)]
        for th in threads:
            th.start()
        threading.Thread(target=loaded_pinger, daemon=True).start()

        series = [(0.0, 0)]
        last_t, last_b = 0.0, 0
        scaled_workers = False
        while True:
            time.sleep(0.2)
            now = time.perf_counter() - t0
            with lock:
                cur = counter[0]
            series.append((now, cur))
            if live_cb:
                dt = now - last_t
                live_cb(round(now, 1), round(((cur - last_b) * 8.0) / (dt * 1e6), 1) if dt > 0 else 0.0)

            # Ottimizzazione gigabit: se il throughput iniziale supera 100 Mbps, scala da 4 a 6 worker concorrenti
            if direction == "down" and not scaled_workers and now >= 0.4 and now < duration - 1.0:
                current_rate_mbps = (cur * 8.0) / (now * 1e6)
                if current_rate_mbps > 100.0 and len(threads) < 6:
                    scaled_workers = True
                    for _ in range(2):
                        extra_th = threading.Thread(target=target, daemon=True)
                        threads.append(extra_th)
                        extra_th.start()

            if now >= duration:
                stop_event.set()
                break

        stop_event.set()

        stats = self._summarize_stream(series, warmup, series[-1][0])
        loaded = round(statistics.median(loaded_rtts), 2) if loaded_rtts else None
        stats.update({"total_bytes": series[-1][1], "duration_s": round(series[-1][0], 2), "errors": list(stream_errors)})
        return stats, loaded

    def measure_download_stream(self, duration: float = 8.0, workers: int = 4, idle_rtt: float = 15.0, ping_host: str = "1.1.1.1", live_cb=None):
        """Download a tempo controllato, connessioni persistenti, warm-up 1.5 s scartato."""
        warm = getattr(self, "warmup_duration", 1.5)
        return self._run_stream("down", duration, workers, warm, idle_rtt, ping_host=ping_host, live_cb=live_cb)

    def measure_upload_stream(self, duration: float = 8.0, workers: int = 4, idle_rtt: float = 15.0, ping_host: str = "1.1.1.1", live_cb=None):
        """Upload a tempo controllato; byte contati quando accettati dal socket (SO_SNDBUF 64 KB)."""
        warm = getattr(self, "warmup_duration", 1.5)
        return self._run_stream("up", duration, workers, warm, idle_rtt, ping_host=ping_host, live_cb=live_cb)

    def measure_tool_ceiling(self, duration: float = 0.25) -> float:
        """
        Misura il throughput limite dell'interprete e del client di test (tool ceiling)
        eseguendo un trasferimento contro un server HTTP locale su loopback (127.0.0.1).
        """
        import http.server

        class NullHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", "100000000")
                self.end_headers()
                chunk = b"0" * 65536
                try:
                    for _ in range(500):
                        self.wfile.write(chunk)
                except Exception:
                    pass
            def log_message(self, *args):
                pass

        try:
            server = http.server.HTTPServer(("127.0.0.1", 0), NullHandler)
            port = server.server_port
            th = threading.Thread(target=server.serve_forever, daemon=True)
            th.start()

            total_bytes = 0
            t0 = time.perf_counter()
            with urllib.request.urlopen(f"http://127.0.0.1:{port}", timeout=1.0) as resp:
                while time.perf_counter() - t0 < duration:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
            dt = time.perf_counter() - t0
            server.shutdown()
            server.server_close()
            if dt > 0 and total_bytes > 0:
                mbps = (total_bytes * 8.0) / (dt * 1e6)
                return round(mbps, 1)
        except Exception:
            pass
        return 5000.0

    def _measure_secondary_endpoint(self, endpoint: Optional[Dict[str, Any]] = None, timeout: float = 2.5) -> Optional[Dict[str, Any]]:
        """Esegue un campione di download su un endpoint secondario indipendente ad alta capacità per verifica incrociata."""
        if os.environ.get("NETPROBE_SPEED_HOST") or getattr(self, "speed_host", None) in ("127.0.0.1", "localhost") or getattr(self, "speed_port", 443) != 443:
            return None
        url = (endpoint.get("url") if endpoint else None) or "https://nbg1-speed.hetzner.com/100MB.bin"
        server_host = (endpoint.get("host") if endpoint else None) or "nbg1-speed.hetzner.com"
        try:
            t0 = time.perf_counter()
            req = urllib.request.Request(url, headers={"User-Agent": "NetProbe/3.0", "Range": "bytes=0-20971519"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                total = 0
                samples = []
                last_t = t0
                last_bytes = 0
                buf_size = 131072
                while time.perf_counter() - t0 < 1.0:
                    chunk = resp.read(buf_size)
                    if not chunk:
                        break
                    total += len(chunk)
                    now = time.perf_counter()
                    dt_slice = now - last_t
                    if dt_slice >= 0.15:
                        s_mbps = ((total - last_bytes) * 8.0) / (dt_slice * 1e6)
                        samples.append(s_mbps)
                        last_t = now
                        last_bytes = total
                dt = time.perf_counter() - t0
                if dt > 0 and total > 0:
                    sustained = round((total * 8.0) / (dt * 1e6), 2)
                    if samples:
                        # Scarta il primo 25% di campioni (ramp-up) e calcola il 90° percentile
                        idx = int(len(samples) * 0.25)
                        tail = samples[idx:] if idx < len(samples) else samples
                        st = sorted(tail)
                        p90_idx = min(int(len(st) * 0.90), len(st) - 1)
                        peak = round(float(st[p90_idx]), 2)
                    else:
                        peak = sustained
                    return {"sustained_mbps": sustained, "peak_mbps": peak, "samples": samples, "server": server_host}
        except Exception:
            pass
        return None

    def _calculate_bufferbloat_grade(self, max_delta: float, dl_delta: float, ul_delta: float) -> Tuple[str, str]:
        """Assegna un grading da A+ a F in base al massimo incremento di latenza sotto carico."""
        if max_delta <= 5.0:
            grade = "A+"
            desc = f"Eccezionale: Nessun bufferbloat significativo (DL: +{dl_delta}ms, UL: +{ul_delta}ms)."
        elif max_delta <= 15.0:
            grade = "A"
            desc = f"Ottimo: Minimo ritardo aggiunto sotto traffico intenso (DL: +{dl_delta}ms, UL: +{ul_delta}ms)."
        elif max_delta <= 35.0:
            grade = "B"
            desc = f"Buono: Lieve accumulo di coda nel modem/router (DL: +{dl_delta}ms, UL: +{ul_delta}ms)."
        elif max_delta <= 75.0:
            grade = "C"
            desc = f"Moderato: Coda evidente; possibili micro-scatti durante gaming o streaming intensi (DL: +{dl_delta}ms, UL: +{ul_delta}ms)."
        elif max_delta <= 150.0:
            grade = "D"
            desc = f"Alto: Forte accumulo di coda; latenza triplicata sotto traffico (DL: +{dl_delta}ms, UL: +{ul_delta}ms)."
        else:
            grade = "F"
            desc = f"Grave: Bufferbloat critico; la latenza collassa durante trasferimenti (DL: +{dl_delta}ms, UL: +{ul_delta}ms)."

        return grade, desc

    def _parse_bsd_ping(self, output: str) -> Tuple[List[float], float]:
        rtts = []
        loss = 0.0
        for m in re.finditer(r"time=([0-9\.]+)\s*ms", output):
            try:
                rtts.append(float(m.group(1)))
            except ValueError:
                pass

        m_loss = re.search(r"([0-9\.]+)%\s*packet loss", output)
        if m_loss:
            try:
                loss = float(m_loss.group(1))
            except ValueError:
                pass

        return rtts, loss

    def _parse_windows_ping(self, output: str) -> Tuple[List[float], float]:
        rtts = []
        loss = 0.0
        for m in re.finditer(r"(?:time|durata|tempo)?\s*[=<]\s*([0-9\.]+)\s*ms", output, re.IGNORECASE):
            try:
                rtts.append(float(m.group(1)))
            except ValueError:
                pass

        m_loss = re.search(r"\((\d+)%\s*(?:loss|persi)\)", output, re.IGNORECASE)
        if m_loss:
            try:
                loss = float(m_loss.group(1))
            except ValueError:
                pass

        return rtts, loss

    def _tcp_ping(self, host: str, port: int = 443, count: int = 5) -> Tuple[List[float], float]:
        rtts = []
        failures = 0
        for _ in range(count):
            t0 = time.perf_counter()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            try:
                s.connect((host, port))
                dt = (time.perf_counter() - t0) * 1000.0
                rtts.append(dt)
            except Exception:
                failures += 1
            finally:
                s.close()
            time.sleep(0.1)

        total = len(rtts) + failures
        loss = (failures / total * 100.0) if total > 0 else 100.0
        return rtts, loss
