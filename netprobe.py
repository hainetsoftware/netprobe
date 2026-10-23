#!/usr/bin/env python3
"""
NetProbe Pro - Advanced LAN & Internet Intelligence Suite
Entrypoint principale: supporto sia CLI (riga di comando) che GUI (Local Web Dashboard).
Funziona su macOS (Apple Silicon M1/M2/M3 / Intel), Windows e Linux.
"""

import sys
import os
import argparse
import json
import time

# Assicura encoding UTF-8 per console multipiattaforma (Windows cp1252 / CI fix)
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Abilita Virtual Terminal Processing (VT100) e code page UTF-8 su Windows
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Set console to UTF-8
        kernel32.SetConsoleCP(65001)
        kernel32.SetConsoleOutputCP(65001)
        # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) for stdout/stderr
        h_out = kernel32.GetStdHandle(-11) # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
            kernel32.SetConsoleMode(h_out, mode.value | 0x0004)
        h_err = kernel32.GetStdHandle(-12) # STD_ERROR_HANDLE
        mode_err = ctypes.c_ulong()
        if kernel32.GetConsoleMode(h_err, ctypes.byref(mode_err)):
            kernel32.SetConsoleMode(h_err, mode_err.value | 0x0004)
    except Exception:
        pass

# Assicura che la directory del progetto sia nel sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.platform_info import get_system_summary
from core.lan_scanner import LanScanner
from core.wan_probe import WanProbe
from core.ixp_analyzer import IXPAnalyzer
from core.performance import PerformanceTester
from core.estimators import NetworkEstimator
from core.validators import validate_scan_results
from core.provenance import build_field_provenance
from cli.terminal_ui import TerminalUI


def run_cli_scan(quick: bool = False, full: bool = False, json_output: bool = False, no_color: bool = False, export_path: str = None):
    """Esegue la scansione in modalità CLI."""
    ui = TerminalUI(no_color=no_color)
    sys_summary = get_system_summary()

    if not json_output:
        ui.print_banner(sys_summary)
        scan_type_str = "RAPIDA" if quick else "COMPLETA (con test banda e bufferbloat)"
        print(f"{ui.BOLD}{ui.BRIGHT_CYAN}⏳ Avvio scansione di rete {scan_type_str}...{ui.RESET}\n")

    # 1. LAN Scanner (con eventuale Switch Discovery se Ethernet)
    lan_scanner = LanScanner()
    lan_data = lan_scanner.scan_all(quick_scan=quick)

    p_iface = lan_data.get("primary_interface") or {}
    local_ip = p_iface.get("ipv4")
    gw_info = lan_data.get("gateway") or {}
    gateway_ip = gw_info.get("ipv4")

    # 2. WAN Probe
    wan_probe = WanProbe()
    wan_data = wan_probe.probe_all(local_ip=local_ip, gateway_ip=gateway_ip)

    # 3. IXP & Peering Intelligence (Traceroute multi-target + PeeringDB + Hop 2 BNG burst)
    ixp_analyzer = IXPAnalyzer()
    ixp_data = ixp_analyzer.analyze_ixp_and_bng(wan_data, full_scan=full)

    # 4. Performance Tester
    perf_tester = PerformanceTester()
    perf_data = perf_tester.test_all(gateway_ip=gateway_ip, run_speed_test=(not quick))

    # 5. Estimators & Physics (integra metriche Hop 2 BNG e instradamento IXP)
    estimator = NetworkEstimator()
    est_data = estimator.calculate_all(lan_data, wan_data, perf_data, ixp_data=ixp_data)

    full_report = {
        "timestamp": time.time(),
        "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "quick_scan": quick,
        "system": sys_summary,
        "lan": lan_data,
        "wan": wan_data,
        "ixp": ixp_data,
        "performance": perf_data,
        "estimations": est_data,
        "diagnostics": {"arp": lan_data.get("diagnostics_arp", {})}
    }

    # Validazione automatica dei dati di scansione (Task 4)
    validate_scan_results(full_report)

    # Mappatura della provenienza dei campi (Task 3)
    full_report["field_status"] = build_field_provenance(full_report)

    # Output JSON puro
    if json_output:
        print(json.dumps(full_report, ensure_ascii=False, indent=2))
        return

    # Render report formattato su terminale
    ui.render_full_report(full_report)

    # Export opzionale
    if export_path:
        export_report(full_report, export_path)
        print(f"{ui.BRIGHT_GREEN}✓ Report esportato con successo in: {export_path}{ui.RESET}\n")


def export_report(data: dict, file_path: str):
    """Esporta i dati diagnostici in formato JSON o HTML standalone."""
    if file_path.endswith(".html"):
        html_file = os.path.join(BASE_DIR, "old", "gui", "web", "static", "index.html")
        css_file = os.path.join(BASE_DIR, "old", "gui", "web", "static", "style.css")
        js_file = os.path.join(BASE_DIR, "old", "gui", "web", "static", "app.js")

        if os.path.exists(html_file) and os.path.exists(css_file) and os.path.exists(js_file):
            with open(html_file, "r", encoding="utf-8") as f:
                html_content = f.read()
            with open(css_file, "r", encoding="utf-8") as f:
                css_content = f.read()
            with open(js_file, "r", encoding="utf-8") as f:
                js_content = f.read()

            html_content = html_content.replace('<link rel="stylesheet" href="/static/style.css">', f"<style>\n{css_content}\n</style>")
            injected_js = f"""
            <script>
            window.PRELOADED_NETPROBE_DATA = {json.dumps(data, ensure_ascii=False)};
            </script>
            <script>
            {js_content.replace('fetch("/api/data")', 'Promise.resolve({ json: () => Promise.resolve(window.PRELOADED_NETPROBE_DATA) })')}
            </script>
            """
            html_content = html_content.replace('<script src="/static/app.js"></script>', injected_js)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            return

    # Default: JSON
    if not file_path.endswith(".json") and not file_path.endswith(".html"):
        file_path = file_path + ".json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="NetProbe Pro - Advanced LAN & Internet Intelligence and Estimation Suite",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--tui", action="store_true", help="Avvia la dashboard interattiva moderna a schermo intero (default se nessun flag è specificato)")
    parser.add_argument("--non-interactive", "--cli", action="store_true", dest="non_interactive", help="Esegui in modalità non-interattiva / headless nel terminale")
    parser.add_argument("--quick", action="store_true", help="Scansione veloce (salta il test di banda approfondito)")
    parser.add_argument("--full", action="store_true", help="Scansione approfondita con misurazione banda e bufferbloat")
    parser.add_argument("--json", action="store_true", help="Stampa l'output unicamente in formato JSON puro (per automazione)")
    parser.add_argument("--no-color", action="store_true", help="Disattiva la colorazione ANSI nel terminale")
    parser.add_argument("--export", type=str, metavar="FILE", help="Esporta il report diagnostico in file JSON o HTML")

    args = parser.parse_args()

    # Se l'utente specifica --non-interactive, --cli, --json, --export, --quick o --full senza --tui esplicito, esegui headless
    headless = args.non_interactive or args.json or args.quick or args.full or (args.export and not args.tui)

    if headless and not args.tui:
        run_cli_scan(
            quick=args.quick,
            full=args.full,
            json_output=args.json,
            no_color=args.no_color,
            export_path=args.export
        )
    else:
        # Modalità interattiva predefinita TUI (senza auto-start: attende interazione dell'utente)
        try:
            from tui.app import NetProbeTUIApp
            NetProbeTUIApp(auto_scan=False).run()
        except ImportError:
            # Ripiego su modalità CLI se textual o altre dipendenze TUI non sono installate
            if args.tui:
                sys.stderr.write("Nota: La dashboard TUI richiede 'textual' (pip install textual).\nPassaggio alla visualizzazione CLI standard...\n\n")
            run_cli_scan(
                quick=args.quick,
                full=args.full,
                json_output=args.json,
                no_color=args.no_color,
                export_path=args.export
            )
        except Exception:
            # Ripiego pulito su modalità CLI in caso di assenza TTY o terminale non supportato
            run_cli_scan(
                quick=args.quick,
                full=args.full,
                json_output=args.json,
                no_color=args.no_color,
                export_path=args.export
            )


if __name__ == "__main__":
    main()
