"""
Applicazione principale TUI per NetProbe Pro.
Gestisce il ciclo interattivo, rendering curses a schermo intero, thread di scansione e navigazione da tastiera.
"""

import curses
import os
import sys
import time
import json
import threading
from typing import Optional, Dict, Any, List

from core.platform_info import get_system_summary
from core.lan_scanner import LanScanner
from core.wan_probe import WanProbe
from core.ixp_analyzer import IXPAnalyzer
from core.performance import PerformanceTester
from core.estimators import NetworkEstimator
from core.validators import validate_scan_results
from core.provenance import build_field_provenance
from tui.views import (
    get_tab_names,
    format_overview,
    format_physical_medium,
    format_routing_ixp,
    format_performance,
    format_raw_json
)


class NetProbeTUI:
    def __init__(self, initial_data: Optional[Dict[str, Any]] = None, auto_scan: bool = True):
        self.data: Optional[Dict[str, Any]] = initial_data
        self.auto_scan = auto_scan
        self.is_scanning = False
        self.scan_phase = "In attesa"
        self.scan_pct = 0
        self.scan_live_metric = ""
        self.scan_error = None
        
        self.active_tab = 0
        self.tab_names = get_tab_names()
        self.scroll_offsets = [0] * len(self.tab_names)
        
        self.show_help = False
        self.status_msg = ""
        self.status_expire = 0.0
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_idx = 0
        self.running = True

    def set_status(self, msg: str, duration: float = 3.0):
        self.status_msg = msg
        self.status_expire = time.time() + duration

    def run_scan_worker(self, full_speed: bool = True):
        """Esegue la scansione completa di rete in un thread separato senza bloccare la UI."""
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_error = None
        self.scan_pct = 5
        self.scan_phase = "Inizializzazione componenti..."

        def progress_cb(phase: str, pct: int, live: Optional[Dict[str, Any]] = None):
            self.scan_phase = phase
            self.scan_pct = max(5, min(98, pct))
            if live and "mbps" in live:
                self.scan_live_metric = f"{live['mbps']:.1f} Mbps ({live.get('dir', 'DL')})"
            else:
                self.scan_live_metric = ""

        try:
            # 1. LAN Scanner
            progress_cb("Scansione hardware LAN, Wi-Fi e switch...", 15)
            lan_scanner = LanScanner()
            lan_data = lan_scanner.scan_all(quick_scan=not full_speed)

            p_iface = lan_data.get("primary_interface") or {}
            local_ip = p_iface.get("ipv4")
            gw_info = lan_data.get("gateway") or {}
            gateway_ip = gw_info.get("ipv4")

            # 2. WAN Probe
            progress_cb("Interrogazione WAN, STUN RFC 5389 e CGNAT...", 30)
            wan_probe = WanProbe()
            wan_data = wan_probe.probe_all(local_ip=local_ip, gateway_ip=gateway_ip)

            # 3. IXP & Traceroute
            progress_cb("Analisi Peering IXP/PNI e burst BNG Hop 2...", 45)
            ixp_analyzer = IXPAnalyzer()
            ixp_data = ixp_analyzer.analyze_ixp_and_bng(wan_data, progress_cb=progress_cb)

            # 4. Performance Tester
            progress_cb("Misurazione latenza multi-target e bufferbloat...", 65)
            perf_tester = PerformanceTester()
            perf_data = perf_tester.test_all(
                gateway_ip=gateway_ip,
                run_speed_test=full_speed,
                progress_cb=progress_cb
            )

            # 5. Estimators
            progress_cb("Calcolo modello probabilistico e routing ottico...", 90)
            estimator = NetworkEstimator()
            est_data = estimator.calculate_all(lan_data, wan_data, perf_data, ixp_data=ixp_data)

            report = {
                "timestamp": time.time(),
                "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "system": get_system_summary(),
                "lan": lan_data,
                "wan": wan_data,
                "ixp": ixp_data,
                "performance": perf_data,
                "estimations": est_data,
                "diagnostics": {"arp": lan_data.get("diagnostics_arp", {})}
            }

            validate_scan_results(report)
            report["field_status"] = build_field_provenance(report)
            self.data = report
            self.set_status("✓ Scansione completata con successo!", 4.0)

        except Exception as e:
            self.scan_error = str(e)
            self.set_status(f"✗ Errore scansione: {e}", 5.0)
        finally:
            self.is_scanning = False
            self.scan_pct = 100
            self.scan_phase = "Pronto"

    def export_json(self):
        """Esporta il report corrente su scan.json."""
        if not self.data:
            self.set_status("Nessun dato da esportare.", 2.5)
            return
        filename = "scan.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            self.set_status(f"✓ Dati esportati in: {filename}", 4.0)
        except Exception as e:
            self.set_status(f"✗ Errore salvataggio: {e}", 4.0)

    def main_loop(self, stdscr):
        """Ciclo di visualizzazione e gestione eventi da tastiera."""
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)
        curses.use_default_colors()

        # Inizializza palette colori
        curses.init_pair(1, curses.COLOR_CYAN, -1)     # Cyan
        curses.init_pair(2, curses.COLOR_GREEN, -1)    # Green
        curses.init_pair(3, curses.COLOR_YELLOW, -1)   # Yellow
        curses.init_pair(4, curses.COLOR_RED, -1)      # Red
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # Magenta
        curses.init_pair(6, curses.COLOR_WHITE, -1)    # White
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)   # Inverted Cyan (active tab)
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Inverted White (header)
        curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_GREEN)  # Inverted Green (badge)

        # Avvio scansione automatica in background se richiesta
        if self.auto_scan and not self.data:
            threading.Thread(target=self.run_scan_worker, args=(True,), daemon=True).start()

        while self.running:
            max_y, max_x = stdscr.getmaxyx()
            stdscr.erase()

            if max_y < 16 or max_x < 70:
                msg = "Finestra troppo piccola (min 70x16)"
                stdscr.addstr(max_y // 2, max(0, (max_x - len(msg)) // 2), msg, curses.color_pair(4) | curses.A_BOLD)
                stdscr.refresh()
                time.sleep(0.1)
                ch = stdscr.getch()
                if ch in (ord('q'), ord('Q'), 27):
                    break
                continue

            self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_chars)

            # 1. Disegna Header
            self._render_header(stdscr, max_x)

            # 2. Disegna Barra Schede (Tabs)
            self._render_tabs(stdscr, max_x)

            # 3. Disegna Barra di Progresso se in scansione
            content_start_y = 4
            if self.is_scanning:
                self._render_progress_bar(stdscr, content_start_y, max_x)
                content_start_y += 2

            # 4. Disegna Contenuto Scheda Attiva
            footer_y = max_y - 1
            available_h = footer_y - content_start_y
            self._render_content(stdscr, content_start_y, available_h, max_x)

            # 5. Disegna Modale Aiuto se attiva
            if self.show_help:
                self._render_help_modal(stdscr, max_y, max_x)

            # 6. Disegna Footer
            self._render_footer(stdscr, footer_y, max_x)

            stdscr.refresh()

            # Gestione Input (non bloccante)
            ch = stdscr.getch()
            if ch != -1:
                self._handle_key(ch)

            time.sleep(0.06)

    def _handle_key(self, ch: int):
        # Aiuto modale
        if ch in (ord('?'), ord('h'), ord('H')) and not self.show_help:
            self.show_help = True
            return
        if self.show_help:
            self.show_help = False
            return

        # Uscita
        if ch in (ord('q'), ord('Q'), 27):  # 27 = ESC
            self.running = False
            return

        # Selezione rapida schede 1..5
        if ord('1') <= ch <= ord('5'):
            self.active_tab = ch - ord('1')
            return

        # Navigazione schede (Tab, Frecce Orizzontali)
        if ch in (9, curses.KEY_RIGHT):  # Tab o Freccia Destra
            self.active_tab = (self.active_tab + 1) % len(self.tab_names)
            return
        if ch in (curses.KEY_BTAB, curses.KEY_LEFT):  # Shift-Tab o Freccia Sinistra
            self.active_tab = (self.active_tab - 1) % len(self.tab_names)
            return

        # Scorrimento Verticale (Frecce, j/k, PgUp/PgDn, Home/End)
        offset = self.scroll_offsets[self.active_tab]
        if ch in (curses.KEY_UP, ord('k')):
            self.scroll_offsets[self.active_tab] = max(0, offset - 1)
        elif ch in (curses.KEY_DOWN, ord('j')):
            self.scroll_offsets[self.active_tab] = offset + 1
        elif ch in (curses.KEY_PPAGE, ord('b')):
            self.scroll_offsets[self.active_tab] = max(0, offset - 10)
        elif ch in (curses.KEY_NPAGE, ord(' '), ord('f')):
            self.scroll_offsets[self.active_tab] = offset + 10
        elif ch in (curses.KEY_HOME, ord('g')):
            self.scroll_offsets[self.active_tab] = 0
        elif ch in (curses.KEY_END, ord('G')):
            self.scroll_offsets[self.active_tab] = 999999

        # Azioni
        elif ch in (ord('r'), ord('R')):
            if not self.is_scanning:
                self.set_status("Avvio nuova scansione...", 2.0)
                threading.Thread(target=self.run_scan_worker, args=(True,), daemon=True).start()
        elif ch in (ord('s'), ord('S')):
            if not self.is_scanning:
                self.set_status("Avvio scansione rapida (senza test banda esteso)...", 2.0)
                threading.Thread(target=self.run_scan_worker, args=(False,), daemon=True).start()
        elif ch in (ord('e'), ord('E')):
            self.export_json()

    def _render_header(self, stdscr, max_x: int):
        title = " ⚡ NetProbe Pro v1.0.0 "
        info_str = "LAN & Internet Intelligence Suite"
        if self.data:
            p_iface = self.data.get("lan", {}).get("primary_interface", {})
            wan = self.data.get("wan", {})
            dev = p_iface.get("name") or "en0"
            ip_pub = wan.get("public_ipv4") or "N/D"
            isp = wan.get("isp") or "ISP"
            info_str = f"[{dev}] IP: {ip_pub} ({isp})"

        bar = f"{title}│ {info_str}"
        bar = bar[:max_x - 1]
        stdscr.addstr(0, 0, bar, curses.color_pair(8) | curses.A_BOLD)

        # Riempimento riga header
        remaining = max_x - 1 - len(bar)
        if remaining > 0:
            stdscr.addstr(0, len(bar), " " * remaining, curses.color_pair(8))

    def _render_tabs(self, stdscr, max_x: int):
        x = 1
        stdscr.addstr(2, 0, " ", curses.A_NORMAL)
        for idx, name in enumerate(self.tab_names):
            label = f" {name} "
            if idx == self.active_tab:
                attr = curses.color_pair(7) | curses.A_BOLD
            else:
                attr = curses.color_pair(6) | curses.A_DIM

            if x + len(label) < max_x - 2:
                stdscr.addstr(2, x, label, attr)
                x += len(label) + 1

        # Riga separatore sotto le schede
        sep = "─" * (max_x - 1)
        stdscr.addstr(3, 0, sep, curses.color_pair(1) | curses.A_DIM)

    def _render_progress_bar(self, stdscr, y: int, max_x: int):
        spin = self.spinner_chars[self.spinner_idx]
        pct = self.scan_pct
        phase = self.scan_phase
        if self.scan_live_metric:
            phase += f" ── {self.scan_live_metric}"

        status_txt = f" {spin} [{pct:>2}%] {phase} "
        status_txt = status_txt[:max_x - 2]
        stdscr.addstr(y, 1, status_txt, curses.color_pair(3) | curses.A_BOLD)

        # Barra visiva di riempimento
        bar_width = max(10, min(50, max_x - 10))
        filled = int((pct / 100.0) * bar_width)
        bar_str = "[" + "█" * filled + "░" * (bar_width - filled) + "]"
        stdscr.addstr(y + 1, 3, bar_str, curses.color_pair(2) | curses.A_BOLD)

    def _render_content(self, stdscr, start_y: int, height: int, max_x: int):
        # Ottieni le righe formattate per la scheda attiva
        if self.active_tab == 0:
            lines = format_overview(self.data)
        elif self.active_tab == 1:
            lines = format_physical_medium(self.data)
        elif self.active_tab == 2:
            lines = format_routing_ixp(self.data)
        elif self.active_tab == 3:
            lines = format_performance(self.data)
        else:
            lines = format_raw_json(self.data)

        # Regola offset di scorrimento entro i limiti consentiti
        max_scroll = max(0, len(lines) - height)
        curr_offset = min(self.scroll_offsets[self.active_tab], max_scroll)
        self.scroll_offsets[self.active_tab] = curr_offset

        visible_lines = lines[curr_offset:curr_offset + height]

        for i, (text, style) in enumerate(visible_lines):
            row_y = start_y + i
            if row_y >= start_y + height:
                break

            attr = curses.A_NORMAL
            if style == "bold_cyan":
                attr = curses.color_pair(1) | curses.A_BOLD
            elif style == "cyan":
                attr = curses.color_pair(1)
            elif style == "bold_green":
                attr = curses.color_pair(2) | curses.A_BOLD
            elif style == "green":
                attr = curses.color_pair(2)
            elif style == "bold_yellow":
                attr = curses.color_pair(3) | curses.A_BOLD
            elif style == "yellow":
                attr = curses.color_pair(3)
            elif style == "bold_red":
                attr = curses.color_pair(4) | curses.A_BOLD
            elif style == "red":
                attr = curses.color_pair(4)
            elif style == "bold_magenta":
                attr = curses.color_pair(5) | curses.A_BOLD
            elif style == "magenta":
                attr = curses.color_pair(5)
            elif style == "bold_white":
                attr = curses.color_pair(6) | curses.A_BOLD
            elif style == "white":
                attr = curses.color_pair(6)
            elif style == "dim":
                attr = curses.A_DIM

            # Tronca alla larghezza schermo
            safe_text = text[:max_x - 2]
            try:
                stdscr.addstr(row_y, 1, safe_text, attr)
            except curses.error:
                pass

        # Indicatore di scroll se ci sono più righe
        if max_scroll > 0:
            scroll_pct = int((curr_offset / max_scroll) * 100) if max_scroll else 100
            indic = f" [{curr_offset + 1}-{min(len(lines), curr_offset + height)}/{len(lines)} ({scroll_pct}%)] "
            try:
                stdscr.addstr(start_y, max_x - len(indic) - 2, indic, curses.color_pair(1) | curses.A_DIM)
            except curses.error:
                pass

    def _render_footer(self, stdscr, y: int, max_x: int):
        # Mostra messaggio temporaneo o comandi tastiera
        if self.status_msg and time.time() < self.status_expire:
            footer = f" {self.status_msg} "
            attr = curses.color_pair(9) | curses.A_BOLD
        else:
            footer = " [Tab/1-5] Schede  [↑/↓] Scorri  [r] Riscansiona  [s] Rapida  [e] Esporta  [?] Aiuto  [q] Esci"
            attr = curses.color_pair(8)

        footer = footer[:max_x - 1]
        stdscr.addstr(y, 0, footer, attr)
        rem = max_x - 1 - len(footer)
        if rem > 0:
            stdscr.addstr(y, len(footer), " " * rem, attr)

    def _render_help_modal(self, stdscr, max_y: int, max_x: int):
        """Disegna una finestra modale al centro con i comandi da tastiera."""
        box_w = min(64, max_x - 4)
        box_h = 16
        start_x = (max_x - box_w) // 2
        start_y = (max_y - box_h) // 2

        # Pulisci e disegna bordo
        for r in range(box_h):
            stdscr.addstr(start_y + r, start_x, " " * box_w, curses.color_pair(8))

        border_top = "┌" + "─" * (box_w - 2) + "┐"
        border_bot = "└" + "─" * (box_w - 2) + "┘"
        stdscr.addstr(start_y, start_x, border_top, curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(start_y + box_h - 1, start_x, border_bot, curses.color_pair(1) | curses.A_BOLD)

        title = " COMANDI DA TASTIERA NETPROBE "
        stdscr.addstr(start_y, start_x + (box_w - len(title)) // 2, title, curses.color_pair(7) | curses.A_BOLD)

        help_lines = [
            ("Tab / Shift-Tab", "Passa alla scheda successiva / precedente"),
            ("1 .. 5", "Vai direttamente alla scheda indicata"),
            ("↑ / ↓ (o k / j)", "Scorri la vista in alto o in basso di una riga"),
            ("PgUp / PgDn", "Scorri velocemente una pagina intera"),
            ("g / G", "Salta all'inizio / fine del documento"),
            ("r", "Avvia una scansione approfondita (con speed test)"),
            ("s", "Avvia una scansione rapida (solo latenze e BNG)"),
            ("e", "Esporta i dati attuali su file scan.json"),
            ("? / h", "Mostra o nasconde questa guida ai tasti"),
            ("q / ESC", "Esci da NetProbe e torna alla shell"),
        ]

        for idx, (key, desc) in enumerate(help_lines):
            row_y = start_y + 2 + idx
            line = f" {key:<18} : {desc}"
            line = line[:box_w - 2]
            stdscr.addstr(row_y, start_x + 1, line, curses.color_pair(8))

        prompt = "[ Premi un tasto qualsiasi per chiudere ]"
        stdscr.addstr(start_y + box_h - 2, start_x + (box_w - len(prompt)) // 2, prompt, curses.color_pair(3) | curses.A_BOLD)


def start_tui(initial_data: Optional[Dict[str, Any]] = None, auto_scan: bool = True):
    """Entry point pubblico per avviare la TUI interattiva."""
    app = NetProbeTUI(initial_data=initial_data, auto_scan=auto_scan)
    curses.wrapper(app.main_loop)
