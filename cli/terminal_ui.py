"""
Interfaccia utente da riga di comando (CLI) per NetProbe Pro.
Fornisce output a colori ANSI, tabelle Unicode, formattazione dati ad alta leggibilità
e riepiloghi visuali delle stime di rete.
"""

import sys
import os
from typing import Dict, Any, List

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


class TerminalUI:
    # Codici colore ANSI
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    CYAN = "\033[36m"
    BRIGHT_CYAN = "\033[96m"
    BLUE = "\033[34m"
    BRIGHT_BLUE = "\033[94m"
    GREEN = "\033[32m"
    BRIGHT_GREEN = "\033[92m"
    YELLOW = "\033[33m"
    BRIGHT_YELLOW = "\033[93m"
    RED = "\033[31m"
    BRIGHT_RED = "\033[91m"
    MAGENTA = "\033[35m"
    BRIGHT_MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BG_DARK = "\033[40m"

    def __init__(self, no_color: bool = False):
        if no_color or os.environ.get("NO_COLOR"):
            for attr in dir(self):
                if attr.isupper() and not attr.startswith("_"):
                    setattr(self, attr, "")

    def print_banner(self, system_info: Dict[str, Any]):
        """Stampa il banner di benvenuto dell'applicazione."""
        print(f"\n{self.BRIGHT_CYAN}{self.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗{self.RESET}")
        print(f"{self.BRIGHT_CYAN}{self.BOLD}║                          ⚡  NETPROBE PRO  ⚡                                ║{self.RESET}")
        print(f"{self.BRIGHT_CYAN}{self.BOLD}║           Advanced LAN & Internet Intelligence and Estimation Suite          ║{self.RESET}")
        print(f"{self.BRIGHT_CYAN}{self.BOLD}╚══════════════════════════════════════════════════════════════════════════════╝{self.RESET}")
        
        os_str = f"{system_info.get('os')} {system_info.get('os_release')} ({system_info.get('machine')})"
        host = system_info.get("hostname", "localhost")
        py_v = system_info.get("python_version", "")
        root_badge = f"{self.BRIGHT_RED}[ELEVATED/ROOT]{self.RESET}" if system_info.get("is_root") else f"{self.DIM}[USER MODE]{self.RESET}"
        
        print(f"{self.DIM}Host:{self.RESET} {self.WHITE}{host}{self.RESET}  |  {self.DIM}OS:{self.RESET} {self.CYAN}{os_str}{self.RESET}  |  {self.DIM}Python:{self.RESET} {py_v}  {root_badge}\n")

    def print_section_header(self, title: str, icon: str = "▶"):
        """Stampa l'intestazione di una sezione."""
        print(f"{self.BRIGHT_YELLOW}{self.BOLD}{icon}  {title.upper()}{self.RESET}")
        print(f"{self.DIM}{'─' * 78}{self.RESET}")

    def print_kv(self, key: str, value: Any, unit: str = "", highlight: bool = False, indent: int = 2):
        """Stampa una coppia chiave-valore allineata."""
        space = " " * indent
        val_str = str(value) if value is not None else "N/D"
        if val_str == "N/A":
            val_str = "N/D"
        color = self.BRIGHT_GREEN if highlight else self.WHITE
        if unit:
            val_str += f" {self.DIM}{unit}{self.RESET}"
        print(f"{space}{self.CYAN}{key:<32}{self.RESET} : {color}{val_str}{self.RESET}")

    def render_full_report(self, full_data: Dict[str, Any]):
        """Renderizza l'intero report diagnostico formattato."""
        lan = full_data.get("lan", {})
        wan = full_data.get("wan", {})
        perf = full_data.get("performance", {})
        est = full_data.get("estimations", {})

        # ==========================================
        # 1. INTERFACCIA PRIMARIA & HARDWARE LAN
        # ==========================================
        self.print_section_header("1. Scheda di Rete & Configurazione LAN", "💻")
        p_iface = lan.get("primary_interface") or {}
        p_name = lan.get("primary_interface_name", "N/A")
        
        self.print_kv("Interfaccia Attiva", f"{p_name} ({p_iface.get('type', 'N/A')})", highlight=True)
        self.print_kv("Indirizzo Fisico (MAC)", p_iface.get("mac"))
        self.print_kv("Produttore Hardware (OUI)", p_iface.get("vendor"))
        self.print_kv("Indirizzo IPv4 Locale", p_iface.get("ipv4"), highlight=True)
        self.print_kv("Maschera di Sottorete", p_iface.get("netmask"))
        self.print_kv("Indirizzo Broadcast", p_iface.get("broadcast"))
        self.print_kv("MTU Interfaccia", p_iface.get("mtu"), "bytes")
        
        # IPv6
        ipv6_list = p_iface.get("ipv6_list", [])
        if ipv6_list:
            for idx, ip6 in enumerate(ipv6_list):
                self.print_kv(f"IPv6 ({ip6.get('type')})", f"{ip6.get('address')}/{ip6.get('prefix')}")
        else:
            self.print_kv("Indirizzi IPv6", "Nessun indirizzo IPv6 configurato")

        # Media Wi-Fi o Ethernet
        wifi = lan.get("wifi", {})
        ethernet = lan.get("ethernet", {})
        ifname = p_iface.get("name", "")
        iface_type = lan.get("interface_type") or p_iface.get("interface_type") or p_iface.get("type") or ""
        is_wifi_link = (iface_type == "Wi-Fi")
        is_eth_link = (iface_type == "Ethernet") or (not is_wifi_link and bool(ethernet.get("active") or ethernet.get("speed_mbps") is not None or ethernet.get("cable_connected")))

        if is_wifi_link:
            print(f"\n  {self.BOLD}{self.BRIGHT_MAGENTA}Parametri Radio Wi-Fi Wireless ({ifname}):{self.RESET}")
            if wifi.get("ssid_hidden_by_os"):
                ssid_str = "Nascosto dal sistema (serve il permesso Posizione)"
            else:
                ssid_str = wifi.get("ssid") or "Connesso"
            self.print_kv("SSID Rete", ssid_str, highlight=True, indent=4)
            if wifi.get("bssid"):
                self.print_kv("BSSID (Access Point MAC)", f"{wifi.get('bssid')} ({wifi.get('bssid_vendor')})", indent=4)
            if wifi.get("wifi_generation") or wifi.get("phy_mode"):
                self.print_kv("Standard / Generazione", f"{wifi.get('wifi_generation') or ''} [{wifi.get('phy_mode') or ''}]", indent=4)
            if wifi.get("channel") or wifi.get("frequency_ghz"):
                self.print_kv("Banda & Canale", f"{wifi.get('frequency_ghz') or ''} (Canale {wifi.get('channel') or ''})", indent=4)
            if wifi.get("rssi_dbm") is not None:
                self.print_kv("Potenza Segnale (RSSI)", wifi.get("rssi_dbm"), "dBm", indent=4)
            if wifi.get("noise_dbm") is not None:
                self.print_kv("Rumore di Fondo (Noise)", wifi.get("noise_dbm"), "dBm", indent=4)
            if wifi.get("snr_db") is not None:
                self.print_kv("Rapporto Segnale/Rumore (SNR)", wifi.get("snr_db"), "dB", indent=4)
            if wifi.get("signal_quality_pct") is not None:
                self.print_kv("Qualità Segnale", f"{wifi.get('signal_quality_pct')}%", indent=4)
            if wifi.get("tx_rate_mbps") is not None:
                self.print_kv("Link Speed (Tx Rate)", wifi.get("tx_rate_mbps"), "Mbps", highlight=True, indent=4)
            if wifi.get("mcs_index") is not None:
                self.print_kv("MCS Index (Modulazione)", wifi.get("mcs_index"), indent=4)
            if wifi.get("security"):
                self.print_kv("Sicurezza & Crittografia", wifi.get("security"), indent=4)
        elif is_eth_link:
            print(f"\n  {self.BOLD}{self.BRIGHT_BLUE}Parametri Connessione Cablata Ethernet ({ifname}):{self.RESET}")
            self.print_kv("Velocità di Link Negoziata", ethernet.get("speed_mbps") or "Non rilevata", "Mbps", highlight=True, indent=4)
            self.print_kv("Modalità Duplex", ethernet.get("duplex") or "--", indent=4)
            self.print_kv("Descrizione Media", ethernet.get("media_description") or "--", indent=4)
            self.print_kv("Stato Cavo", "Attivo / Connesso" if ethernet.get("cable_connected") else "Non rilevato", indent=4)

            # Switch Discovery info
            sw = ethernet.get("switch_info")
            if sw:
                print(f"\n    {self.BOLD}Apparato Switch Collegato:{self.RESET}")
                if sw.get("detected"):
                    if sw.get("switch_name"):
                        self.print_kv("Nome Switch", sw.get("switch_name"), highlight=True, indent=6)
                    if sw.get("switch_model"):
                        self.print_kv("Modello Apparato", sw.get("switch_model"), indent=6)
                    if sw.get("port_id"):
                        self.print_kv("Porta Switch (Link)", sw.get("port_id"), highlight=True, indent=6)
                    if sw.get("vlan"):
                        self.print_kv("VLAN Porta", sw.get("vlan"), indent=6)
                    if sw.get("management_ip"):
                        self.print_kv("IP Gestione Switch", sw.get("management_ip"), indent=6)
                    if sw.get("protocol"):
                        self.print_kv("Protocollo di Rilevamento", sw.get("protocol"), indent=6)
                else:
                    self.print_kv("Tipologia Switch", sw.get("switch_type", "Switch L2 Unmanaged"), indent=6)
                    if sw.get("description"):
                        print(f"      {self.DIM}↳ {sw.get('description')}{self.RESET}")

        print()

        # ==========================================
        # 2. GATEWAY, DHCP & DNS
        # ==========================================
        self.print_section_header("2. Gateway, DHCP & Risoluzione DNS", "🌐")
        gw = lan.get("gateway", {})
        self.print_kv("Default Gateway (Router)", gw.get("ipv4"), highlight=True)
        self.print_kv("MAC Address Router", gw.get("mac"))
        self.print_kv("Produttore Router (OUI)", gw.get("vendor"))
        
        # DHCP
        dhcp = lan.get("dhcp", {})
        if dhcp.get("server_ip"):
            self.print_kv("Server DHCP", dhcp.get("server_ip"))
            self.print_kv("Durata Concessione (Lease)", dhcp.get("lease_time_human"))
            if dhcp.get("bootfile"):
                self.print_kv("Bootfile / PXE", dhcp.get("bootfile"))

        # DNS
        dns = lan.get("dns", {})
        resolvers = dns.get("resolvers", [])
        self.print_kv("Server DNS di Sistema", ", ".join(resolvers) if resolvers else "Nessuno")
        
        dns_bm = lan.get("dns_benchmark", {})
        if dns_bm.get("system_resolver_latency_ms") is not None:
            self.print_kv("Tempo Risoluzione DNS Locale", f"{dns_bm.get('system_resolver_latency_ms')} ms")
        
        resolvers_dnssec = dns_bm.get("resolvers_dnssec") or []
        if resolvers_dnssec:
            res_parts = []
            for r in resolvers_dnssec:
                st = r.get("status", "inconclusivo")
                if st == "validante":
                    res_parts.append(f"{self.BRIGHT_GREEN}{r['ip']}: validante{self.RESET}")
                elif "non validante" in st.lower():
                    res_parts.append(f"{self.YELLOW}{r['ip']}: {st}{self.RESET}")
                else:
                    res_parts.append(f"{self.DIM}{r['ip']}: inconclusivo{self.RESET}")
            self.print_kv("Convalida Crittografica DNSSEC", " | ".join(res_parts))
        else:
            dnssec_badge = f"{self.BRIGHT_GREEN}VALIDANTE{self.RESET}" if dns_bm.get("dnssec_validation_active") else f"{self.YELLOW}NON VALIDANTE{self.RESET}"
            self.print_kv("Convalida Crittografica DNSSEC", dnssec_badge)
        print()

        # ==========================================
        # 3. INTERNET & INTELLIGENCE WAN
        # ==========================================
        self.print_section_header("3. Connessione Internet & Geointelligence WAN", "🌍")
        self.print_kv("Indirizzo IPv4 Pubblico", wan.get("public_ipv4"), highlight=True)
        ipv6_pub = wan.get("public_ipv6")
        ipv6_status = f"{ipv6_pub} {self.BRIGHT_GREEN}(Dual-Stack OK){self.RESET}" if ipv6_pub else f"{self.DIM}Non Rilevato (IPv4-Only){self.RESET}"
        self.print_kv("Indirizzo IPv6 Pubblico", ipv6_status)
        self.print_kv("Reverse DNS (PTR Hostname)", wan.get("reverse_dns"))
        self.print_kv("Provider Internet (ISP)", wan.get("isp"), highlight=True)
        asn = wan.get('asn')
        org = wan.get('org')
        if asn or org:
            asn_str = f"{asn or 'N/D'} ({org or 'N/D'})"
        else:
            asn_str = "N/D"
        self.print_kv("Autonomous System (ASN)", asn_str)

        city = wan.get('city')
        region = wan.get('region')
        country = wan.get('country')
        if city or region or country:
            geo_parts = [p for p in (city, region) if p]
            loc_str = ", ".join(geo_parts)
            if country:
                loc_str = f"{loc_str} - {country}" if loc_str else country
        else:
            loc_str = "N/D"
        self.print_kv("Posizione Geografica", loc_str)

        coords = wan.get("coordinates", {})
        if coords.get("latitude") and coords.get("longitude"):
            self.print_kv("Coordinate Lat / Lon", f"{coords.get('latitude')}, {coords.get('longitude')}")
        self.print_kv("Fuso Orario Rete", wan.get("timezone"))
        
        privacy = wan.get("privacy_and_routing", {})
        priv_type = privacy.get('type')
        if priv_type:
            priv_badge = f"{self.BRIGHT_YELLOW}{priv_type}{self.RESET}" if privacy.get("is_vpn_or_proxy") else f"{self.BRIGHT_GREEN}{priv_type}{self.RESET}"
        else:
            priv_badge = "N/D"
        self.print_kv("Stato Privacy / VPN / Proxy", priv_badge)
        path_mtu = full_data.get("ixp", {}).get("path_mtu")
        self.print_kv("Path MTU Misurato (DF)", "N/D" if path_mtu is None else f"{path_mtu} bytes")
        print()

        # ==========================================
        # 4. ARCHITETTURA NAT & FIREWALL (STUN RFC 5389)
        # ==========================================
        self.print_section_header("4. Analisi NAT & Sicurezza Router (STUN RFC 5389)", "🛡️")
        nat = wan.get("nat", {})
        self.print_kv("Tipologia NAT Mappata", nat.get("nat_type"), highlight=True)
        self.print_kv("Comportamento Mappatura", nat.get("mapping_behavior"))
        self.print_kv("Porta Esterna STUN Mappata", nat.get("mapped_external_port"))
        pm = full_data.get("estimations", {}).get("physical_medium", {})
        pred_med = str(pm.get("predicted_medium", "")).lower()
        conf_val = pm.get("confidence_pct")
        conf_num = float(conf_val) if conf_val is not None else 100.0
        is_ambig = pm.get("ambiguous", False)
        is_mobile_pred = "mobile" in pred_med or "cellular" in pred_med
        is_mobile_confident = is_mobile_pred and conf_num >= 60.0 and not is_ambig
        wan_ip_ok = bool(wan.get("public_ipv4"))
        if nat.get("cgnat_detected"):
            cgnat_badge = f"{self.BRIGHT_RED}RILEVATO (RFC 6598){self.RESET}"
        elif is_mobile_confident:
            cgnat_badge = f"{self.YELLOW}non rilevabile (su rete mobile il CGNAT è probabile){self.RESET}"
        elif not wan_ip_ok:
            cgnat_badge = f"{self.YELLOW}non rilevabile (IP pubblico assente){self.RESET}"
        else:
            cgnat_badge = f"{self.BRIGHT_GREEN}non rilevabile (nessun indizio di CGNAT: IP pubblico fuori da 100.64.0.0/10){self.RESET}"
        self.print_kv("Carrier-Grade NAT (CGNAT)", cgnat_badge)
        
        services = wan.get("router_services", {})
        upnp_text = services.get("upnp_status_text") or ("ATTIVO" if services.get("upnp_igd_available") else "Nessuna risposta (UPnP non rilevato)")
        upnp_badge = f"{self.YELLOW}ATTIVO{self.RESET}" if services.get("upnp_igd_available") else f"{self.DIM}{upnp_text}{self.RESET}"
        self.print_kv("UPnP IGD Router", upnp_badge)

        pmp_text = services.get("nat_pmp_status_text") or ("ATTIVO" if services.get("nat_pmp_available") else "Nessuna risposta (NAT-PMP non rilevato)")
        pmp_badge = f"{self.YELLOW}ATTIVO{self.RESET}" if services.get("nat_pmp_available") else f"{self.DIM}{pmp_text}{self.RESET}"
        self.print_kv("NAT-PMP Router", pmp_badge)
        print()

        # ==========================================
        # 5. PERFORMANCE, BUFFERBLOAT & VELOCITÀ
        # ==========================================
        self.print_section_header("5. Performance, Latenza, Bufferbloat & Banda", "🚀")
        targets = perf.get("latency_targets", {})
        
        # Tabella Latenza
        print(f"  {self.BOLD}{'Target':<22} {'Min (ms)':<10} {'Mediana':<10} {'Max (ms)':<10} {'Jitter RFC3550':<16} {'Loss':<8}{self.RESET}")
        print(f"  {self.DIM}{'─' * 74}{self.RESET}")
        for name, t in targets.items():
            if t.get("reachable"):
                print(f"  {self.WHITE}{name:<22}{self.RESET} {t.get('min_ms', 0):<10.2f} {t.get('median_ms', 0):<10.2f} {t.get('max_ms', 0):<10.2f} {t.get('jitter_ms', 0):<16.2f} {t.get('packet_loss_pct', 0)}%")
            else:
                print(f"  {self.DIM}{name:<22} Non raggiungibile / Filtrato ICMP{self.RESET}")
        print()

        # Bufferbloat Bidirezionale
        bb = perf.get("bufferbloat", {})
        grade_colors = {
            "A+": self.BRIGHT_GREEN, "A": self.BRIGHT_GREEN,
            "B": self.GREEN, "C": self.YELLOW,
            "D": self.BRIGHT_RED, "F": self.RED
        }
        g_col = grade_colors.get(bb.get("grade", "C"), self.WHITE)
        grade_val = bb.get('grade')
        max_delta = bb.get('max_delta_ms')
        if grade_val is None:
            self.print_kv("Valutazione Bufferbloat", "N/D")
        else:
            delta_str = f" (Max Delta: +{max_delta} ms)" if max_delta is not None else ""
            self.print_kv("Valutazione Bufferbloat", f"{g_col}{self.BOLD}Grado {grade_val}{self.RESET}{delta_str}")
        self.print_kv("Latenza a Riposo (Idle)", "N/D" if bb.get("idle_latency_ms") is None else f"{bb.get('idle_latency_ms')} ms")

        dl_loaded = bb.get("download_loaded_ms")
        dl_delta = bb.get("download_delta_ms")
        if dl_loaded is None:
            dl_str = "N/D"
        else:
            dl_delta_str = f" (+{dl_delta} ms)" if dl_delta is not None else ""
            dl_str = f"{dl_loaded} ms{dl_delta_str}"
        self.print_kv("Latenza Sotto Carico Download", dl_str)

        ul_loaded = bb.get("upload_loaded_ms")
        ul_delta = bb.get("upload_delta_ms")
        if ul_loaded is None:
            ul_str = "N/D"
        else:
            ul_delta_str = f" (+{ul_delta} ms)" if ul_delta is not None else ""
            ul_str = f"{ul_loaded} ms{ul_delta_str}"
        self.print_kv("Latenza Sotto Carico Upload", ul_str)
        self.print_kv("Diagnosi Coda Router", bb.get("description") or "N/D")

        # Velocità e Throughput Streaming Continuo
        speed = perf.get("speed", {})
        dl_dict = speed.get("download") or {}
        ul_dict = speed.get("upload") or {}

        # Download
        dl_mbps = speed.get("download_mbps")
        dl_valid = dl_dict.get("valid", dl_mbps is not None)
        dl_bytes = speed.get("bytes_downloaded", 0) / (1024 * 1024)
        if dl_valid and dl_mbps is not None:
            dl_peak = speed.get("download_peak_mbps") or dl_mbps
            dl_stab = speed.get("download_stability_pct")
            stab_str = f" [Stabilità: {dl_stab}%]" if dl_stab is not None else ""
            self.print_kv("Download (Sostenuto / Regime)", f"{self.BOLD}{dl_mbps}{self.RESET}", f"Mbps  (Picco: {dl_peak} Mbps{stab_str})", highlight=True)
        else:
            dl_reason = dl_dict.get("invalid_reason") or speed.get("invalid_reason") or "misura non valida o fallita"
            self.print_kv("Download (Sostenuto / Regime)", f"{self.YELLOW}N/D{self.RESET} ({dl_reason})")

        # Upload
        ul_mbps = speed.get("upload_mbps")
        ul_valid = ul_dict.get("valid", ul_mbps is not None)
        ul_bytes = speed.get("bytes_uploaded", 0) / (1024 * 1024)
        if ul_valid and ul_mbps is not None:
            ul_peak = speed.get("upload_peak_mbps") or ul_mbps
            ul_stab = speed.get("upload_stability_pct")
            ul_stab_str = f" [Stabilità: {ul_stab}%]" if ul_stab is not None else ""
            self.print_kv("Upload (Sostenuto / Regime)", f"{self.BOLD}{ul_mbps}{self.RESET}", f"Mbps  (Picco: {ul_peak} Mbps{ul_stab_str})", highlight=True)
        else:
            ul_reason = ul_dict.get("invalid_reason") or speed.get("invalid_reason") or "misura non valida o fallita"
            self.print_kv("Upload (Sostenuto / Regime)", f"{self.YELLOW}N/D{self.RESET} ({ul_reason})")

        tot_mb = speed.get("bytes_transferred", 0) / (1024 * 1024)
        dur = speed.get("test_duration_s", 0)
        if tot_mb > 0 or dur > 0:
            self.print_kv("Traffico e Durata Speedtest", f"{tot_mb:.1f} MB trasferiti (DL: {dl_bytes:.1f} MB, UL: {ul_bytes:.1f} MB) in {dur}s")

        # Riepilogo errori speedtest se presenti
        speed_errors = speed.get("errors") or []
        if (not dl_valid or not ul_valid) and speed_errors:
            err_summaries = []
            for err in speed_errors[:3]:
                phase = err.get("phase", "stream")
                status = err.get("status")
                msg = err.get("error") or err.get("reason") or "errore"
                if status:
                    err_summaries.append(f"{phase} HTTP {status} ({msg})")
                else:
                    err_summaries.append(f"{phase}: {msg}")
            if len(speed_errors) > 3:
                err_summaries.append(f"...ed altri {len(speed_errors) - 3} errori")
            self.print_kv("Errori Speedtest Rilevati", f"{self.RED}{'; '.join(err_summaries)}{self.RESET}")

        if speed.get("tool_ceiling_mbps") is not None:
            ceil_mbps = speed["tool_ceiling_mbps"]
            ceil_warn = f" {self.YELLOW}⚠️ (>50% ceiling interprete){self.RESET}" if speed.get("ceiling_warning") else ""
            self.print_kv("Calibrazione Limite Tool (Loopback)", f"{ceil_mbps} Mbps{ceil_warn}")
        if speed.get("servers_used"):
            agree_str = " (concordanti)" if speed.get("endpoints_agreement") is True else (" (discordanti)" if speed.get("endpoints_agreement") is False else "")
            self.print_kv("Server Speedtest Utilizzati", f"{', '.join(speed['servers_used'])}{agree_str}")
        if speed.get("other_process_bytes") is not None:
            other_kb = speed["other_process_bytes"] / 1024
            other_pct = speed.get("other_process_pct", 0.0)
            self.print_kv("Traffico Altri Processi (psutil)", f"{other_kb:.1f} KB stimati ({other_pct}% del traffico su interfaccia)")
        print()

        # ==========================================
        # 6. STIME AVANZATE, MODELLI FISICI & ITU-T G.107
        # ==========================================
        self.print_section_header("6. Modelli Matematici, Stime Fisiche & Score Qualità", "🔬")
        
        # Mezzo Fisico Ultimo Miglio
        med = est.get("physical_medium", {})
        display_med = med.get("verdict_label") or med.get("predicted_medium") or "N/D"
        self.print_kv("Mezzo Fisico Ultimo Miglio", f"{self.BOLD}{display_med}{self.RESET}", highlight=True)
        conf = med.get("confidence_pct")
        self.print_kv("Indice di Confidenza Modello", "N/D" if conf is None else f"{conf}%")
        alts = med.get("alternatives", [])
        if alts:
            alt_strs = [f"{a.get('medium')} ({a.get('score')} pt, {a.get('confidence_share_pct')}%)" for a in alts]
            self.print_kv("Ipotesi Alternative", ", ".join(alt_strs))
        unassigned = med.get("unassigned_pct")
        if unassigned is not None:
            self.print_kv("Non Attribuito", f"{unassigned}%")
        mq = med.get("measurement_quality") or est.get("measurement_quality") or {}
        if mq.get("noisy"):
            print(f"  {self.YELLOW}⚠️  Misura disturbata: possibile traffico concorrente sulla linea (streaming, backup). Ripetere a linea libera per una stima più affidabile.{self.RESET}")
        bng = med.get("bng_hop", {})
        if bng and bng.get("ip"):
            cgnat_tag = " [CGNAT RFC 6598]" if bng.get("cgnat_hop") else ""
            bng_details = f"{bng.get('ip')}{cgnat_tag}  [Min RTT: {bng.get('min_ms')} ms, Mediana: {bng.get('median_ms')} ms, Jitter IPDV: {bng.get('jitter_ms')} ms"
            if bng.get("tail_variance_ms"):
                bng_details += f", Coda p95: +{bng.get('tail_variance_ms')} ms"
            bng_details += "]"
            self.print_kv("Primo salto pubblico responsivo", bng_details)
        for r in med.get("rationale", []):
            print(f"    {self.DIM}↳ {r}{self.RESET}")
        print()

        # Profilo Latenza Salto per Salto (Access Profile - Non calibrato)
        ixp = full_data.get("ixp", {})
        acc_prof = ixp.get("access_profile") or {}
        prof_hops = acc_prof.get("hops") or []
        if prof_hops:
            print(f"  {self.BOLD}Profilo Latenza Salto per Salto (Access Profile - Non calibrato):{self.RESET}")
            print(f"  {'Hop':<4} {'Indirizzo IP':<18} {'Min RTT':<11} {'Mediana':<11} {'Delta Floor':<14} {'Ruolo / Note'}")
            print(f"  {'-'*75}")
            for ph in prof_hops[:10]:
                h_num = ph.get("hop")
                h_ip = ph.get("ip") or "*"
                if h_ip == "*" or ph.get("min_ms") is None:
                    h_ip = "*"
                    h_min = "N/D"
                    h_med = "N/D"
                    h_inc = "N/D"
                    h_role = ph.get("role")
                    if not h_role or h_role in ("Nessuna risposta", "*", "-"):
                        h_role = "Timeout ICMP"
                else:
                    h_min = f"{ph['min_ms']:.2f} ms"
                    h_med = f"{ph['median_ms']:.2f} ms"
                    floor_inc = ph.get("floor_increment_ms")
                    if floor_inc is None or floor_inc <= 0:
                        h_inc = "~0.00 ms"
                    else:
                        h_inc = f"+{floor_inc:.2f} ms"
                    h_role = ph.get("role_note") or ph.get("role") or ""
                print(f"  {h_num:<4} {h_ip:<18} {h_min:<11} {h_med:<11} {h_inc:<14} {h_role}")
            print()

        # Routing Ottico & Internet eXchange
        opt = est.get("optical_routing", {})
        ixp = full_data.get("ixp", {})
        ixp_name = opt.get("nearest_ixp_name") or "N/D"
        is_unidentified = "non identificato" in str(ixp_name).lower() or ixp_name == "N/D"
        self.print_kv("Internet eXchange / Hub Peering", f"{self.BOLD}{ixp_name}{self.RESET}", highlight=True)
        if not is_unidentified and opt.get("ixp_facility"):
            self.print_kv("Struttura / Campus IXP", opt.get("ixp_facility"))
        peering_type_val = opt.get("peering_type") if not is_unidentified else None
        self.print_kv("Tipologia Interconnessione", peering_type_val or "N/D")
        det_method_val = f"{ixp.get('detection_method')} (Confidenza: {ixp.get('confidence')})" if (not is_unidentified and ixp.get("detection_method")) else "N/D"
        self.print_kv("Metodo di Identificazione", det_method_val)
        if ixp.get("anycast_colo"):
            self.print_kv("PoP Anycast Rilevato (Cloudflare)", f"{ixp.get('anycast_colo')} ({opt.get('ixp_city', '')})")
        if not is_unidentified and ixp.get("matched_hop_ip"):
            hop_str = f"{ixp.get('matched_hop_ip')}"
            if ixp.get("matched_subnet"):
                hop_str += f" (Subnet: {ixp.get('matched_subnet')})"
            self.print_kv("Interfaccia Peering / Egress (Hop IP)", hop_str)
        if opt.get("calculation_basis"):
            self.print_kv("Base di Calcolo Efficienza", opt.get("calculation_basis"))
        _nd = lambda v, u="": "N/D" if v is None else f"{v}{u}"
        dist_km = opt.get("straight_line_distance_km")
        target_city = f" verso {opt.get('ixp_city')}" if opt.get('ixp_city') else ""
        self.print_kv("Distanza Geodetica Ortodromica", "N/D" if dist_km is None else f"~{dist_km} km{target_city}")
        fiber_km = opt.get("estimated_fiber_path_km")
        self.print_kv("Tratta Fibra Ottica Stimata", "N/D" if fiber_km is None else f"~{fiber_km} km (con detour infrastrutturale)")
        min_opt_rtt = opt.get("theoretical_optical_min_rtt_ms")
        self.print_kv("Latenza Luce in Fibra (Minimo Fisico)", "N/D" if min_opt_rtt is None else f"{min_opt_rtt} ms (RTT Misurato: {_nd(opt.get('measured_rtt_ms'), ' ms')})")
        if opt.get("routing_efficiency_pct") is None:
            reason = opt.get("not_applicable_reason") or "dati insufficienti"
            self.print_kv("Indice di Efficienza di Routing", f"N/D ({reason})")
        else:
            self.print_kv("Indice di Efficienza di Routing", f"{opt.get('routing_efficiency_pct')}% ({opt.get('detour_rating')})")
        self.print_kv("Ritardo di Accodamento & Switch", _nd(opt.get('switching_and_queuing_delay_ms'), ' ms'))

        # PeeringDB presenze ASN operatore
        pdb_facs = ixp.get("peeringdb_facilities", [])
        if pdb_facs:
            fac_names = [f["name"] for f in pdb_facs[:4] if f.get("name")]
            if fac_names:
                self.print_kv("Poli di Peering Pubblico AS Operatore", ", ".join(fac_names))
        print()

        # BDP & Buffer TCP
        bdp = est.get("bandwidth_delay_product", {})
        if bdp.get("bdp_bytes") is None:
            bdp_desc = bdp.get("description") or "misura non valida"
            self.print_kv("Bandwidth-Delay Product (BDP)", f"N/D ({bdp_desc})")
            self.print_kv("Finestra TCP Consigliata (Socket Buffer)", "N/D")
        else:
            self.print_kv("Bandwidth-Delay Product (BDP)", f"{bdp.get('bdp_kb')} KB ({bdp.get('bdp_bytes')} bytes)")
            self.print_kv("Finestra TCP Consigliata (Socket Buffer)", f"{bdp.get('recommended_tcp_window_kb')} KB")
        print()

        # MOS ITU-T G.107
        mos = est.get("voice_quality_mos", {})
        mos_val = mos.get("mos_score")
        if mos_val is None:
            self.print_kv("Score Vocale ITU-T G.107 (MOS)", f"N/D ({mos.get('quality_rating') or 'Dati insufficienti'})")
            self.print_kv("Fattore di Trasmissione (R-Factor)", "N/D")
        else:
            mos_color = self.BRIGHT_GREEN if mos_val >= 4.0 else (self.YELLOW if mos_val >= 3.5 else self.RED)
            self.print_kv("Score Vocale ITU-T G.107 (MOS)", f"{mos_color}{self.BOLD}{mos_val} / 4.5{self.RESET} ({mos.get('quality_rating')})")
            self.print_kv("Fattore di Trasmissione (R-Factor)", f"{mos.get('r_factor')} / 100")
        print()

        # Rating Applicativo
        apps = est.get("application_suitability", {})
        print(f"  {self.BOLD}Valutazione Idoneità Applicativa Real-Time:{self.RESET}")
        for app_key, app_name in [
            ("competitive_gaming", "Gaming Competitivo / Esport"),
            ("video_streaming", "Streaming Video 4K HDR & 8K"),
            ("video_conferencing", "Smart Working & Zoom/Teams"),
            ("cloud_gaming", "Cloud Gaming (GeForce NOW/Parsec)")
        ]:
            info = apps.get(app_key, {})
            status = info.get("status", "N/A")
            score = info.get("score")
            if score is None:
                col = self.DIM
                score_str = "N/D"
            else:
                col = self.BRIGHT_GREEN if score >= 80 else (self.YELLOW if score >= 60 else self.RED)
                score_str = f"{score}/100"
            print(f"    • {self.WHITE}{app_name:<34}{self.RESET}: {col}{self.BOLD}{status:<12}{self.RESET} ({score_str}) - {self.DIM}{info.get('desc')}{self.RESET}")

        print(f"\n{self.DIM}{'─' * 78}{self.RESET}\n")

        # Dispositivi rilevati
        perm_warn = lan.get("permissions_warning")
        if perm_warn:
            print(f"  {self.YELLOW}⚠️  {perm_warn}{self.RESET}\n")

        this_dev = lan.get("this_device")
        if this_dev:
            print(f"  {self.BOLD}Questo Dispositivo (Host Locale):{self.RESET}")
            h_name = f" ({this_dev['hostname']})" if this_dev.get("hostname") else ""
            print(f"    • {self.BRIGHT_GREEN}{this_dev.get('ip', 'N/D'):<15}{self.RESET}  {self.WHITE}{this_dev.get('mac', 'N/D'):<17}{self.RESET}  {self.DIM}{this_dev.get('vendor', 'N/D')}{self.RESET}{h_name}  [{this_dev.get('type', 'LAN')}]")
            print()

        devices = lan.get("lan_devices") or lan.get("arp_table", [])
        if devices:
            print(f"  {self.BOLD}Dispositivi Rilevati nella LAN ({len(devices)} host):{self.RESET}")
            for d in devices[:15]:
                h_name = f" ({d['hostname']})" if (d.get("hostname") and d["hostname"] != "N/D") else ""
                src = f" [{d.get('how_found')}]" if d.get("how_found") else ""
                mac_val = d.get("mac") or "N/D"
                vendor_val = d.get("vendor") or "N/D"
                v6_extra = ""
                if d.get("ipv6_addresses"):
                    v6_extra = f"  {self.DIM}(+{len(d['ipv6_addresses'])} IPv6: {d['ipv6_addresses'][0]}){self.RESET}"
                print(f"    • {self.CYAN}{d['ip']:<15}{self.RESET}  {self.WHITE}{mac_val:<17}{self.RESET}  {self.DIM}{vendor_val}{self.RESET}{h_name}{v6_extra}{self.DIM}{src}{self.RESET}")
            if len(devices) > 15:
                print(f"    {self.DIM}... e altri {len(devices) - 15} host rilevati.{self.RESET}")
            print()
