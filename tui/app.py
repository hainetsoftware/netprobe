"""
Applicazione principale TUI moderna Textual per NetProbe Pro.
Fornisce una dashboard reattiva, resiliente al ridimensionamento e navigabile a schede.
Supporta esecuzione asincrona non-bloccante tramite worker background thread.
"""

import os
import sys
import time
import json
from typing import Optional, Dict, Any, List, Tuple

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.theme import Theme
from textual.widgets import Header, Footer, TabbedContent, TabPane, Button, ProgressBar, Label, DataTable
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive

from core.platform_info import get_system_summary
from core.lan_scanner import LanScanner
from core.wan_probe import WanProbe
from core.ixp_analyzer import IXPAnalyzer
from core.performance import PerformanceTester
from core.estimators import NetworkEstimator
from core.validators import validate_scan_results
from core.provenance import build_field_provenance
from tui.views import (
    DashboardView,
    WifiView,
    EthernetView,
    LanView,
    WanView,
    PerformanceView,
    MediumView,
    IxpView,
    DevicesView
)

TAB_IDS: List[str] = [
    "tab-dashboard",
    "tab-wifi",
    "tab-ethernet",
    "tab-lan",
    "tab-wan",
    "tab-performance",
    "tab-medium",
    "tab-ixp",
    "tab-devices",
]

CUSTOM_THEMES: List[Theme] = [
    Theme(
        name="netprobe-dark",
        primary="#38bdf8",
        secondary="#2563eb",
        accent="#38bdf8",
        foreground="#f1f5f9",
        background="#0b0f17",
        surface="#131b26",
        panel="#202d3d",
        success="#4ade80",
        warning="#facc15",
        error="#f87171",
        dark=True,
    ),
    Theme(
        name="netprobe-cyberpunk",
        primary="#ff2a85",
        secondary="#00f0ff",
        accent="#fcee0a",
        foreground="#f8fafc",
        background="#090414",
        surface="#160b2e",
        panel="#2d1657",
        success="#00ff9f",
        warning="#fcee0a",
        error="#ff0055",
        dark=True,
    ),
    Theme(
        name="netprobe-matrix",
        primary="#00ff41",
        secondary="#008f11",
        accent="#00ff41",
        foreground="#d1ffd7",
        background="#020804",
        surface="#07140b",
        panel="#0f2916",
        success="#00ff41",
        warning="#a6ff00",
        error="#ff3333",
        dark=True,
    ),
]

THEME_CYCLE: List[Tuple[str, str, str]] = [
    ("netprobe-dark", "theme-dark", "NetProbe Dark (Default)"),
    ("dracula", "theme-dracula", "Dracula"),
    ("netprobe-cyberpunk", "theme-cyberpunk", "Cyberpunk Neon"),
    ("netprobe-matrix", "theme-matrix", "Matrix Terminal"),
    ("nord", "theme-nord", "Arctic Nord"),
    ("tokyo-night", "theme-tokyo-night", "Tokyo Night"),
    ("textual-light", "theme-light", "High-Contrast Light"),
]


class NetProbeTUIApp(App):
    """Applicazione TUI moderna Textual per NetProbe Pro."""

    TITLE = "⚡ NETPROBE PRO"
    SUB_TITLE = "Advanced LAN & Internet Intelligence and Estimation Suite"
    CSS_PATH = "style.tcss"

    BINDINGS = [
        Binding("q", "quit", "Esci"),
        Binding("space", "start_full_scan", "Scansione Completa"),
        Binding("s", "start_full_scan", "Completa", show=False),
        Binding("r", "start_quick_scan", "Scansione Rapida"),
        Binding("e", "export_report", "Esporta"),
        Binding("t", "toggle_theme", "Tema"),
        Binding("T", "toggle_theme", "Tema", show=False),
        Binding("left", "previous_tab", "Scheda Prec.", show=False),
        Binding("h", "previous_tab", "Scheda Prec.", show=False),
        Binding("right", "next_tab", "Scheda Succ.", show=False),
        Binding("l", "next_tab", "Scheda Succ.", show=False),
        Binding("up", "scroll_up", "Scorri Su", show=False),
        Binding("k", "scroll_up", "Scorri Su", show=False),
        Binding("down", "scroll_down", "Scorri Giù", show=False),
        Binding("j", "scroll_down", "Scorri Giù", show=False),
        Binding("1", "tab_1", "Sintesi", show=False),
        Binding("2", "tab_2", "Wi-Fi", show=False),
        Binding("3", "tab_3", "Ethernet", show=False),
        Binding("4", "tab_4", "LAN", show=False),
        Binding("5", "tab_5", "WAN", show=False),
        Binding("6", "tab_6", "Performance", show=False),
        Binding("7", "tab_7", "Mezzo Fisico", show=False),
        Binding("8", "tab_8", "IXP", show=False),
        Binding("9", "tab_9", "Dispositivi", show=False),
    ]

    def __init__(self, initial_data: Optional[Dict[str, Any]] = None, auto_scan: bool = False):
        super().__init__()
        self.initial_data = initial_data
        self.auto_scan = auto_scan
        self.is_scanning = False
        self.scan_data = initial_data
        self.scan_start_time: Optional[float] = None
        self._scan_timer = None
        self._scan_quick = False
        self._scan_status_message = ""
        self._scan_progress = 0
        self._theme_index = 0
        for custom_theme in CUSTOM_THEMES:
            self.register_theme(custom_theme)
        self.theme = THEME_CYCLE[0][0]
        self.add_class(THEME_CYCLE[0][1])

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="hero-bar"):
            with Horizontal(id="action-buttons"):
                yield Button("▶ Completa", id="btn-full")
                yield Button("⚡ Rapida", id="btn-quick")
                yield Button("💾 Export", id="btn-export")
                yield Button("🎨 Tema (T)", id="btn-theme")
            with Vertical(id="status-container"):
                yield Label("Pronto. Seleziona un'azione per iniziare.", id="status-label")
                yield ProgressBar(id="progress-bar", total=100, show_eta=False)
        with TabbedContent(id="tabs"):
            with TabPane("📊 Sintesi", id="tab-dashboard"):
                yield DashboardView(id="view-dashboard")
            with TabPane("📶 Wi-Fi Wireless", id="tab-wifi"):
                yield WifiView(id="view-wifi")
            with TabPane("🔌 Ethernet & Switch", id="tab-ethernet"):
                yield EthernetView(id="view-ethernet")
            with TabPane("💻 LAN & Rete Locale", id="tab-lan"):
                yield LanView(id="view-lan")
            with TabPane("🌐 WAN & Sicurezza", id="tab-wan"):
                yield WanView(id="view-wan")
            with TabPane("🚀 Performance & Banda", id="tab-performance"):
                yield PerformanceView(id="view-performance")
            with TabPane("🔬 Mezzo Fisico & Salti", id="tab-medium"):
                yield MediumView(id="view-medium")
            with TabPane("🌍 IXP & Routing Ottico", id="tab-ixp"):
                yield IxpView(id="view-ixp")
            with TabPane("📱 Dispositivi LAN", id="tab-devices"):
                yield DevicesView(id="view-devices")
        yield Footer()

    def on_mount(self):
        if self.initial_data:
            self._apply_scan_data(self.initial_data)
            self.query_one("#status-label", Label).update("Dati diagnostici caricati con successo.")
        elif self.auto_scan:
            self.action_start_full_scan()

    def watch_theme(self, theme_name: str) -> None:
        all_theme_classes = [cls for _, cls, _ in THEME_CYCLE]
        for cls in all_theme_classes:
            self.remove_class(cls)
        matched_class = f"theme-{theme_name}"
        for idx, (t_id, t_cls, _) in enumerate(THEME_CYCLE):
            if t_id == theme_name:
                matched_class = t_cls
                self._theme_index = idx
                break
        self.add_class(matched_class)
        self.refresh_css(animate=False)

    def action_toggle_theme(self) -> None:
        self._theme_index = (self._theme_index + 1) % len(THEME_CYCLE)
        theme_id, theme_cls, theme_label = THEME_CYCLE[self._theme_index]
        self.theme = theme_id
        try:
            self.query_one("#status-label", Label).update(f"🎨 Tema grafico attivo: {theme_label}")
        except Exception:
            pass

    def action_previous_tab(self) -> None:
        tc = self.query_one(TabbedContent)
        active = tc.active
        if active in TAB_IDS:
            idx = TAB_IDS.index(active)
            new_idx = (idx - 1) % len(TAB_IDS)
            tc.active = TAB_IDS[new_idx]

    def action_next_tab(self) -> None:
        tc = self.query_one(TabbedContent)
        active = tc.active
        if active in TAB_IDS:
            idx = TAB_IDS.index(active)
            new_idx = (idx + 1) % len(TAB_IDS)
            tc.active = TAB_IDS[new_idx]

    def action_scroll_down(self) -> None:
        if isinstance(self.focused, DataTable):
            self.focused.action_cursor_down()
            return
        tc = self.query_one(TabbedContent)
        try:
            pane = tc.get_pane(tc.active)
            for scroll in pane.query(VerticalScroll):
                if scroll.max_scroll_y > 0:
                    scroll.scroll_down(animate=False)
                    return
            if pane.max_scroll_y > 0:
                pane.scroll_down(animate=False)
        except Exception:
            pass

    def action_scroll_up(self) -> None:
        if isinstance(self.focused, DataTable):
            self.focused.action_cursor_up()
            return
        tc = self.query_one(TabbedContent)
        try:
            pane = tc.get_pane(tc.active)
            for scroll in pane.query(VerticalScroll):
                if scroll.max_scroll_y > 0:
                    scroll.scroll_up(animate=False)
                    return
            if pane.max_scroll_y > 0:
                pane.scroll_up(animate=False)
        except Exception:
            pass

    def action_tab_1(self):
        self.query_one(TabbedContent).active = "tab-dashboard"

    def action_tab_2(self):
        self.query_one(TabbedContent).active = "tab-wifi"

    def action_tab_3(self):
        self.query_one(TabbedContent).active = "tab-ethernet"

    def action_tab_4(self):
        self.query_one(TabbedContent).active = "tab-lan"

    def action_tab_5(self):
        self.query_one(TabbedContent).active = "tab-wan"

    def action_tab_6(self):
        self.query_one(TabbedContent).active = "tab-performance"

    def action_tab_7(self):
        self.query_one(TabbedContent).active = "tab-medium"

    def action_tab_8(self):
        self.query_one(TabbedContent).active = "tab-ixp"

    def action_tab_9(self):
        self.query_one(TabbedContent).active = "tab-devices"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-full":
            self.action_start_full_scan()
        elif btn_id == "btn-quick":
            self.action_start_quick_scan()
        elif btn_id == "btn-export":
            self.action_export_report()
        elif btn_id == "btn-theme":
            self.action_toggle_theme()

    def action_start_full_scan(self):
        if self.is_scanning:
            self.notify("Scansione già in corso...", severity="warning")
            return
        self._begin_scan(quick=False)

    def action_start_quick_scan(self):
        if self.is_scanning:
            self.notify("Scansione già in corso...", severity="warning")
            return
        self._begin_scan(quick=True)

    def _begin_scan(self, quick: bool) -> None:
        """Initialize UI-owned telemetry before dispatching the worker thread."""
        self.scan_start_time = time.monotonic()
        self._scan_quick = quick
        self._scan_status_message = "Avvio scansione..."
        self._scan_progress = 0
        self.run_scan_worker(quick=quick)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        total = max(0, int(seconds))
        return f"{total // 60:02d}:{total % 60:02d}"

    def _update_scan_timer(self) -> None:
        """Refresh elapsed and baseline ETA while the scan worker is active."""
        if not self.is_scanning or self.scan_start_time is None:
            self._stop_scan_timer()
            return
        elapsed = max(0.0, time.monotonic() - self.scan_start_time)
        estimated_total = 8 if self._scan_quick else 40
        eta = max(0, estimated_total - int(elapsed))
        phase = self._scan_status_message or "Avvio scansione..."
        self.query_one("#status-label", Label).update(
            f"[● SCANNING] Fase: {phase} ({self._scan_progress}%) | "
            f"Tempo: {self._format_duration(elapsed)} / ETA: ~{self._format_duration(eta)}"
        )

    def _stop_scan_timer(self) -> None:
        if self._scan_timer is not None:
            self._scan_timer.stop()
            self._scan_timer = None

    def action_export_report(self):
        if not self.scan_data:
            self.notify("Nessun dato da esportare. Esegui prima una scansione.", severity="warning")
            return
        ts = int(time.time())
        filename = f"netprobe_report_{ts}.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.scan_data, f, ensure_ascii=False, indent=2)
            self.notify(f"Report esportato in {filename}", title="Esportazione Completata", severity="information")
        except Exception as e:
            self.notify(f"Errore esportazione: {e}", severity="error")

    @work(thread=True)
    def run_scan_worker(self, quick: bool = False):
        self.is_scanning = True
        self.call_from_thread(self._on_scan_start, quick)

        def progress_cb(phase: str, pct: int, live: Optional[Dict[str, Any]] = None):
            live_str = ""
            if live and "mbps" in live:
                live_str = f" - {live['mbps']:.1f} Mbps ({live.get('dir', 'DL')})"
            msg = f"{phase}{live_str}"
            self.call_from_thread(self._on_scan_progress, msg, pct)

        try:
            sys_summary = get_system_summary()

            # 1. LAN Scanner
            progress_cb("Scansione hardware LAN, Wi-Fi e switch...", 15)
            lan_scanner = LanScanner()
            lan_data = lan_scanner.scan_all(quick_scan=quick)

            p_iface = lan_data.get("primary_interface") or {}
            local_ip = p_iface.get("ipv4")
            gw_info = lan_data.get("gateway") or {}
            gateway_ip = gw_info.get("ipv4")

            # 2. WAN Probe
            progress_cb("Interrogazione WAN, STUN RFC 5389 e CGNAT...", 30)
            wan_probe = WanProbe()
            wan_data = wan_probe.probe_all(local_ip=local_ip, gateway_ip=gateway_ip)

            # 3. IXP & Traceroute
            progress_cb("Analisi Peering IXP/PNI e burst BNG Hop 2...", 50)
            ixp_analyzer = IXPAnalyzer()
            ixp_data = ixp_analyzer.analyze_ixp_and_bng(wan_data, progress_cb=progress_cb, full_scan=(not quick))

            # 4. Performance Tester
            progress_cb("Misurazione latenza multi-target e bufferbloat...", 70)
            perf_tester = PerformanceTester()
            perf_data = perf_tester.test_all(
                gateway_ip=gateway_ip,
                run_speed_test=(not quick),
                progress_cb=progress_cb
            )

            # 5. Estimators & Physics
            progress_cb("Modellazione fisica e stime probabilistiche...", 90)
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

            validate_scan_results(full_report)
            full_report["field_status"] = build_field_provenance(full_report)

            progress_cb("Scansione completata con successo!", 100)
            self.call_from_thread(self._on_scan_success, full_report)

        except Exception as e:
            self.call_from_thread(self._on_scan_error, str(e))
        finally:
            self.is_scanning = False

    def _on_scan_start(self, quick: bool):
        self.is_scanning = True
        self._scan_quick = quick
        if self.scan_start_time is None:
            self.scan_start_time = time.monotonic()
        self.query_one("#btn-full", Button).disabled = True
        self.query_one("#btn-quick", Button).disabled = True
        scan_type = "Rapida" if quick else "Completa"
        self._scan_status_message = f"Avvio scansione di rete {scan_type}..."
        self._scan_progress = 5
        self.query_one("#status-label", Label).update(self._scan_status_message)
        self.query_one("#progress-bar", ProgressBar).update(progress=5)
        self._stop_scan_timer()
        self._scan_timer = self.set_interval(0.2, self._update_scan_timer)

    def _on_scan_progress(self, msg: str, pct: int):
        self._scan_status_message = msg
        self._scan_progress = pct
        self.query_one("#progress-bar", ProgressBar).update(progress=pct)
        self._update_scan_timer()

    def _on_scan_success(self, report: Dict[str, Any]):
        elapsed = time.monotonic() - self.scan_start_time if self.scan_start_time is not None else 0
        self._stop_scan_timer()
        self.is_scanning = False
        self.scan_data = report
        self._apply_scan_data(report)
        self.query_one("#btn-full", Button).disabled = False
        self.query_one("#btn-quick", Button).disabled = False
        self.query_one("#status-label", Label).update(
            f"[✓ COMPLETATO] Scansione completata in {self._format_duration(elapsed)}"
        )
        self.query_one("#progress-bar", ProgressBar).update(progress=100)
        self.notify("Scansione completata con successo!", title="NetProbe Pro", severity="information")

    def _on_scan_error(self, err_msg: str):
        self._stop_scan_timer()
        self.is_scanning = False
        self.query_one("#btn-full", Button).disabled = False
        self.query_one("#btn-quick", Button).disabled = False
        self.query_one("#status-label", Label).update(f"❌ Errore durante la scansione: {err_msg}")
        self.notify(f"Errore scansione: {err_msg}", title="NetProbe Pro", severity="error")

    def on_unmount(self) -> None:
        self._stop_scan_timer()

    def _apply_scan_data(self, report: Dict[str, Any]):
        self.query_one("#view-dashboard", DashboardView).data = report
        self.query_one("#view-wifi", WifiView).data = report
        self.query_one("#view-ethernet", EthernetView).data = report
        self.query_one("#view-lan", LanView).data = report
        self.query_one("#view-wan", WanView).data = report
        self.query_one("#view-performance", PerformanceView).data = report
        self.query_one("#view-medium", MediumView).data = report
        self.query_one("#view-ixp", IxpView).data = report
        self.query_one("#view-devices", DevicesView).data = report


def start_tui(initial_data: Optional[Dict[str, Any]] = None, auto_scan: bool = False):
    """Funzione di avvio per la Textual TUI."""
    app = NetProbeTUIApp(initial_data=initial_data, auto_scan=auto_scan)
    app.run()
