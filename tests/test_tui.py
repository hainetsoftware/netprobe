"""
Test per il modulo TUI (Text User Interface) di NetProbe Pro.
Verifica che tutte le viste formattino correttamente l'intero dataset diagnostico
senza perdita di dati, errori di formattazione o eccezioni su dati reali o parziali.
"""

import os
import json
import unittest
from typing import Dict, Any

from tui.views import (
    get_tab_names,
    format_overview,
    format_physical_medium,
    format_routing_ixp,
    format_performance,
    format_raw_json
)


class TestTUIViews(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        wifi_path = os.path.join(fixtures_dir, "real_wifi_fttc.json")
        eth_path = os.path.join(fixtures_dir, "real_ethernet_run1.json")

        with open(wifi_path, "r", encoding="utf-8") as f:
            cls.wifi_data = json.load(f)

        with open(eth_path, "r", encoding="utf-8") as f:
            cls.eth_data = json.load(f)

    def test_tab_names(self):
        tabs = get_tab_names()
        self.assertEqual(len(tabs), 5)
        self.assertIn("1. Panoramica", tabs[0])
        self.assertIn("2. Mezzo Fisico", tabs[1])
        self.assertIn("3. IXP & Routing", tabs[2])
        self.assertIn("4. Performance", tabs[3])
        self.assertIn("5. Dati JSON", tabs[4])

    def test_empty_data_rendering(self):
        """Verifica che tutte le viste gestiscano elegantemente dizionari vuoti."""
        for fn in [format_overview, format_physical_medium, format_routing_ixp, format_performance, format_raw_json]:
            lines = fn({})
            self.assertIsInstance(lines, list)
            self.assertGreater(len(lines), 0)
            for text, style in lines:
                self.assertIsInstance(text, str)
                self.assertIsInstance(style, str)

    def test_overview_full_wifi_fields(self):
        """Verifica che la vista Panoramica mostri tutti i dettagli LAN, Wi-Fi, DHCP, DNS, WAN e NAT."""
        lines = format_overview(self.wifi_data)
        all_text = "\n".join(t for t, _ in lines)

        # 1. Topologia & Header
        self.assertIn("TOPOLOGIA DI RETE", all_text)
        self.assertIn("MEZZO FISICO", all_text)
        self.assertIn("BUFFERBLOAT", all_text)

        # 2. LAN & Hardware
        self.assertIn("1. SCHEDA DI RETE & CONFIGURAZIONE LAN", all_text)
        self.assertIn("Interfaccia Attiva", all_text)
        self.assertIn("Indirizzo Fisico (MAC)", all_text)
        self.assertIn("Indirizzo IPv4 Locale", all_text)
        self.assertIn("Maschera di Sottorete", all_text)
        self.assertIn("MTU Interfaccia", all_text)

        # 3. Parametri Wi-Fi
        self.assertIn("Parametri Radio Wi-Fi Wireless", all_text)
        self.assertIn("SSID Rete", all_text)
        self.assertIn("Potenza Segnale (RSSI)", all_text)
        self.assertIn("Link Speed (Tx Rate)", all_text)

        # 4. Gateway, DHCP, DNS
        self.assertIn("2. GATEWAY, DHCP & RISOLUZIONE DNS", all_text)
        self.assertIn("Default Gateway (Router)", all_text)
        self.assertIn("Server DNS di Sistema", all_text)
        self.assertIn("Convalida Crittografica DNSSEC", all_text)

        # 5. WAN & Geointelligence
        self.assertIn("3. CONNESSIONE INTERNET & GEOINTELLIGENCE WAN", all_text)
        self.assertIn("Indirizzo IPv4 Pubblico", all_text)
        self.assertIn("Provider Internet (ISP)", all_text)
        self.assertIn("Autonomous System (ASN)", all_text)
        self.assertIn("Posizione Geografica", all_text)

        # 6. NAT & Firewall
        self.assertIn("4. ANALISI NAT & SICUREZZA ROUTER (STUN RFC 5389)", all_text)
        self.assertIn("Carrier-Grade NAT (CGNAT)", all_text)
        self.assertIn("UPnP IGD Router", all_text)
        self.assertIn("NAT-PMP Router", all_text)

    def test_overview_full_ethernet_fields(self):
        """Verifica la formattazione dei parametri cablati Ethernet e Switch discovery."""
        lines = format_overview(self.eth_data)
        all_text = "\n".join(t for t, _ in lines)

        self.assertIn("Parametri Connessione Cablata Ethernet", all_text)
        self.assertIn("Velocità di Link Negoziata", all_text)
        self.assertIn("Modalità Duplex", all_text)

    def test_physical_medium_full_fields(self):
        """Verifica la scheda Mezzo Fisico con modello bayesiano, hop BNG, access profile, BDP e MOS."""
        lines = format_physical_medium(self.wifi_data)
        all_text = "\n".join(t for t, _ in lines)

        self.assertIn("CLASSIFICAZIONE FISICA DELL'ULTIMO MIGLIO", all_text)
        self.assertIn("Mezzo Fisico Ultimo Miglio", all_text)
        self.assertIn("Indice di Confidenza Modello", all_text)
        self.assertIn("PARAMETRI DI ACCESSO HOP 2", all_text)
        self.assertIn("Indirizzo Gateway Operatore (BNG)", all_text)
        self.assertIn("Latenza Minima di Tratta (Min RTT)", all_text)

        # BDP e Buffer TCP
        self.assertIn("BANDWIDTH-DELAY PRODUCT (BDP)", all_text)

        # MOS ITU-T G.107
        self.assertIn("QUALITÀ VOCALE ITU-T G.107 & FATTORE R", all_text)

        # Idoneità Applicativa
        self.assertIn("VALUTAZIONE IDONEITÀ APPLICATIVA REAL-TIME", all_text)
        self.assertIn("Gaming Competitivo", all_text)
        self.assertIn("Streaming Video 4K", all_text)

        # Access Profile Hop-by-Hop su fixture Ethernet completa
        eth_lines = format_physical_medium(self.eth_data)
        eth_text = "\n".join(t for t, _ in eth_lines)
        self.assertIn("PROFILO LATENZA SALTO PER SALTO (Access Profile)", eth_text)
        self.assertIn("Delta Floor", eth_text)

    def test_routing_ixp_full_fields(self):
        """Verifica la scheda IXP & Routing Ottico con facility, efficienza e traceroute."""
        lines = format_routing_ixp(self.wifi_data)
        all_text = "\n".join(t for t, _ in lines)

        self.assertIn("INTELLIGENCE PEERING IXP & INSTRADAMENTO OTTICO", all_text)
        self.assertIn("Internet eXchange / Hub Peering", all_text)
        self.assertIn("Tipologia Interconnessione", all_text)
        self.assertIn("EFFICIENZA INSTRADAMENTO OTTICO", all_text)
        self.assertIn("Distanza Geodetica Ortodromica", all_text)
        self.assertIn("TABELLA SALTO PER SALTO (Traceroute Multi-Probe & ASN Cymru)", all_text)
        self.assertIn("Organizzazione / PTR", all_text)

    def test_performance_full_fields(self):
        """Verifica la scheda Performance con matrice latenza, bufferbloat e speed test."""
        lines = format_performance(self.wifi_data)
        all_text = "\n".join(t for t, _ in lines)

        self.assertIn("PERFORMANCE, LATENZA MULTI-TARGET, BUFFERBLOAT & VELOCITÀ", all_text)
        self.assertIn("MATRICE DI LATENZA TARGET", all_text)
        self.assertIn("Jitter RFC3550", all_text)
        self.assertIn("DIAGNOSI BUFFERBLOAT SOTTO CARICO", all_text)
        self.assertIn("Latenza a Riposo (Idle)", all_text)
        self.assertIn("Sotto Carico Download", all_text)
        self.assertIn("Sotto Carico Upload", all_text)
        self.assertIn("RISULTATI TEST DI VELOCITÀ", all_text)
        self.assertIn("Download (Regime)", all_text)
        self.assertIn("Upload (Regime)", all_text)

    def test_overview_lan_devices(self):
        """Verifica la presenza dei dispositivi rilevati nella LAN."""
        mock_data = {
            "lan": {
                "primary_interface": {"name": "en0", "type": "Wi-Fi", "ipv4": "192.168.1.50"},
                "this_device": {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:01", "vendor": "Apple, Inc.", "hostname": "MacBook.local", "type": "Wi-Fi"},
                "lan_devices": [
                    {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:02", "vendor": "Router Corp", "hostname": "router.local", "how_found": "mDNS", "ipv6_addresses": ["fe80::1"]},
                    {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:03", "vendor": "Smart TV", "hostname": "tv.local", "how_found": "UPnP"}
                ]
            }
        }
        lines = format_overview(mock_data)
        all_text = "\n".join(t for t, _ in lines)
        self.assertIn("Questo Dispositivo (Host Locale):", all_text)
        self.assertIn("192.168.1.50", all_text)
        self.assertIn("Dispositivi Rilevati nella LAN (2 host):", all_text)
        self.assertIn("Router Corp (router.local)", all_text)
        self.assertIn("Smart TV (tv.local)", all_text)
        self.assertIn("mDNS [+IPv6]", all_text)

    def test_access_profile_timeout_and_floor(self):
        """Verifica che i salti di timeout mostrino 'Timeout ICMP' e che delta <= 0 mostri '~0.00 ms'."""
        mock_data = {
            "ixp": {
                "access_profile": {
                    "hops": [
                        {"hop": 1, "ip": "192.168.1.1", "min_ms": 0.5, "median_ms": 0.6, "floor_increment_ms": -0.1, "role": "Gateway CPE"},
                        {"hop": 2, "ip": "*", "min_ms": None, "median_ms": None, "floor_increment_ms": None, "role": "*"},
                        {"hop": 3, "ip": "172.18.0.1", "min_ms": 5.2, "median_ms": 5.4, "floor_increment_ms": 4.7, "role": "BNG"}
                    ]
                }
            }
        }
        lines = format_physical_medium(mock_data)
        all_text = "\n".join(t for t, _ in lines)
        self.assertIn("PROFILO LATENZA SALTO PER SALTO (Access Profile):", all_text)
        self.assertIn("~0.00 ms", all_text)
        self.assertIn("Timeout ICMP", all_text)
        self.assertIn("+4.70 ms", all_text)


class TestTextualTUIApp(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        eth_path = os.path.join(fixtures_dir, "real_ethernet_run1.json")
        wifi_path = os.path.join(fixtures_dir, "real_wifi_fttc.json")
        with open(eth_path, "r", encoding="utf-8") as f:
            cls.eth_data = json.load(f)
        with open(wifi_path, "r", encoding="utf-8") as f:
            cls.wifi_data = json.load(f)

    async def test_tui_empty_launch(self):
        """Verifica che la TUI si avvii in stato pronto senza avviare scansioni automaticamente."""
        from tui.app import NetProbeTUIApp
        from textual.widgets import TabbedContent, Label, Button

        app = NetProbeTUIApp(initial_data=None, auto_scan=False)
        async with app.run_test() as pilot:
            tc = app.query_one(TabbedContent)
            self.assertEqual(tc.active, "tab-dashboard")

            empty_lbl = app.query_one("#empty-state-title", Label)
            self.assertIn("PRONTO", str(empty_lbl.render()))

            btn_full = app.query_one("#btn-full", Button)
            self.assertFalse(btn_full.disabled)

    async def test_tui_tab_navigation(self):
        """Verifica la navigazione rapida e con frecce tra tutte le 9 schede della TUI."""
        from tui.app import NetProbeTUIApp
        from textual.widgets import TabbedContent

        app = NetProbeTUIApp(initial_data=self.eth_data, auto_scan=False)
        async with app.run_test() as pilot:
            tc = app.query_one(TabbedContent)
            self.assertEqual(tc.active, "tab-dashboard")

            # 1 -> 9 direct actions
            app.action_tab_2()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-wifi")

            app.action_tab_3()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-ethernet")

            app.action_tab_4()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-lan")

            app.action_tab_5()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-wan")

            app.action_tab_6()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-performance")

            app.action_tab_7()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-medium")

            app.action_tab_8()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-ixp")

            app.action_tab_9()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-devices")

            # Next / Previous arrow navigation
            app.action_next_tab()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-dashboard")

            app.action_previous_tab()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-devices")

            app.action_previous_tab()
            await pilot.pause()
            self.assertEqual(tc.active, "tab-ixp")

            # Scroll actions do not crash
            app.action_scroll_down()
            await pilot.pause()
            app.action_scroll_up()
            await pilot.pause()

    async def test_tui_data_population(self):
        """Verifica che i dati popolino metriche, Wi-Fi, Ethernet e tutte le 5 DataTable."""
        from tui.app import NetProbeTUIApp
        from textual.widgets import DataTable, Label

        # Test con dati Ethernet
        app_eth = NetProbeTUIApp(initial_data=self.eth_data, auto_scan=False)
        async with app_eth.run_test() as pilot:
            # Dashboard
            med_lbl = app_eth.query_one("#dash-medium-title", Label)
            self.assertIn("Fibra", str(med_lbl.render()))

            # Ethernet Card
            eth_spd = app_eth.query_one("#eth-speed", Label)
            self.assertIn("1000", str(eth_spd.render()))
            eth_sw = app_eth.query_one("#eth-sw-type", Label)
            self.assertIn("Switch L2 Unmanaged", str(eth_sw.render()))

            # Wi-Fi in scenario Ethernet (hardware presente, non connessa)
            wifi_st = app_eth.query_one("#wifi-status", Label)
            self.assertIn("non connessa", str(wifi_st.render()))

            # DataTables
            t_dnssec = app_eth.query_one("#table-dnssec", DataTable)
            self.assertGreaterEqual(t_dnssec.row_count, 1)
            self.assertTrue(t_dnssec.can_focus)

            t_targets = app_eth.query_one("#table-targets", DataTable)
            self.assertGreaterEqual(t_targets.row_count, 1)
            self.assertTrue(t_targets.can_focus)

            t_hops = app_eth.query_one("#table-hops", DataTable)
            self.assertGreaterEqual(t_hops.row_count, 1)
            self.assertTrue(t_hops.can_focus)

            t_peering = app_eth.query_one("#table-peeringdb", DataTable)
            self.assertGreaterEqual(t_peering.row_count, 1)
            self.assertTrue(t_peering.can_focus)

            t_devs = app_eth.query_one("#table-devices", DataTable)
            self.assertGreaterEqual(t_devs.row_count, 1)
            self.assertTrue(t_devs.can_focus)

        # Test con dati Wi-Fi
        app_wifi = NetProbeTUIApp(initial_data=self.wifi_data, auto_scan=False)
        async with app_wifi.run_test() as pilot:
            wifi_st = app_wifi.query_one("#wifi-status", Label)
            self.assertIn("Connesso", str(wifi_st.render()))
            wifi_rate = app_wifi.query_one("#wifi-tx-rate", Label)
            self.assertIn("1200", str(wifi_rate.render()))
            wifi_rssi = app_wifi.query_one("#wifi-rssi", Label)
            self.assertIn("-45", str(wifi_rssi.render()))

    async def test_tui_export_report(self):
        """Verifica che l'azione di esportazione generi il file JSON corretto."""
        from tui.app import NetProbeTUIApp
        import glob

        app = NetProbeTUIApp(initial_data=self.eth_data, auto_scan=False)
        async with app.run_test() as pilot:
            app.action_export_report()
            await pilot.pause()

            exported_files = glob.glob("netprobe_report_*.json")
            self.assertGreater(len(exported_files), 0)
            for f in exported_files:
                try:
                    os.remove(f)
                except OSError:
                    pass

    async def test_tui_active_tab_label_not_occluded(self):
        """Verifica che l'indicatore della scheda attiva non copra né tronchi il titolo."""
        from tui.app import NetProbeTUIApp
        from textual.widgets import Tab, Tabs

        app = NetProbeTUIApp(initial_data=self.eth_data, auto_scan=False)
        async with app.run_test(size=(120, 40)) as pilot:
            expected_keywords = [
                "Sintesi", "Wi-Fi", "Ethernet", "LAN", "WAN",
                "Performance", "Mezzo Fisico", "IXP", "Dispositivi"
            ]
            for idx, keyword in enumerate(expected_keywords, start=1):
                getattr(app, f"action_tab_{idx}")()
                await pilot.pause()
                active_tab = app.query_one("ContentTab.-active", Tab)
                self.assertGreaterEqual(active_tab.content_size.height, 1)
                rendered_line = active_tab.render_line(0).text.strip()
                self.assertIn(keyword, rendered_line)

            # Verifica visibilità anche con focus diretto su Tabs
            app.query_one(Tabs).focus()
            await pilot.pause()
            active_tab = app.query_one("ContentTab.-active", Tab)
            self.assertGreaterEqual(active_tab.content_size.height, 1)
            self.assertIn("Dispositivi", active_tab.render_line(0).text.strip())

    async def test_tui_theme_toggle_updates_palette(self):
        """Verifica che la commutazione del tema aggiorni visibilmente colori, classi CSS e stato."""
        from tui.app import NetProbeTUIApp
        from textual.widgets import Label

        app = NetProbeTUIApp(initial_data=self.eth_data, auto_scan=False)
        async with app.run_test(size=(120, 40)) as pilot:
            card = app.query_one(".card")
            initial_theme = app.theme
            initial_screen_bg = app.screen.styles.background
            initial_card_bg = card.styles.background
            self.assertIn("theme-dark", app.classes)

            # Toggle tramite tasto 't'
            await pilot.press("t")
            await pilot.pause()
            self.assertNotEqual(app.theme, initial_theme)
            self.assertNotEqual(app.screen.styles.background, initial_screen_bg)
            self.assertNotEqual(card.styles.background, initial_card_bg)
            self.assertIn("theme-dracula", app.classes)
            status_text = str(app.query_one("#status-label", Label).render())
            self.assertIn("Tema grafico attivo", status_text)

            # Toggle tramite azione diretta
            prev_bg = app.screen.styles.background
            app.action_toggle_theme()
            await pilot.pause()
            self.assertNotEqual(app.screen.styles.background, prev_bg)
            self.assertIn("theme-cyberpunk", app.classes)


if __name__ == "__main__":
    unittest.main()
