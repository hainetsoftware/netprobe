"""
Viste e formattatori per la TUI di NetProbe Pro.
Genera le righe testuali formattate con attributi per ogni scheda:
1. Panoramica & LAN (Hardware, Wi-Fi/Eth, DHCP/DNS, WAN, NAT, Dispositivi LAN)
2. Mezzo Fisico (Stime, Modello Bayesiano, Hop BNG, Access Profile, BDP, MOS, Idoneità)
3. IXP & Routing Ottico (Peering, Facility, Detour Fibra, Traceroute con ASN & PTR)
4. Performance & Bufferbloat (Matrice Latenza, Bufferbloat DL/UL, Speedtest, psutil)
5. Dati Grezzi JSON (Dump strutturato)
"""

import json
from typing import Dict, Any, List, Tuple, Optional


def get_tab_names() -> List[str]:
    """Restituisce i nomi delle schede della TUI (ottimizzati per larghezza 80 colonne)."""
    return [
        "1. Panoramica",
        "2. Mezzo Fisico",
        "3. IXP & Routing",
        "4. Performance",
        "5. Dati JSON"
    ]


def _format_section_header(title: str, icon: str = "▶") -> List[Tuple[str, str]]:
    """Restituisce l'intestazione formattata di una sezione."""
    return [
        (f" {icon}  {title.upper()}", "bold_yellow"),
        (" " + "─" * 76, "dim")
    ]


def _format_kv(key: str, value: Any, unit: str = "", highlight: bool = False, indent: int = 2) -> Tuple[str, str]:
    """Formatta una coppia chiave-valore allineata con stile."""
    space = " " * indent
    val_str = str(value) if value is not None else "N/D"
    if val_str == "N/A":
        val_str = "N/D"
    if unit:
        val_str += f" {unit}"
    style = "bold_green" if highlight else "normal"
    return (f"{space}• {key:<34} : {val_str}", style)


def _format_sub_kv(key: str, value: Any, unit: str = "", highlight: bool = False, indent: int = 4) -> Tuple[str, str]:
    """Formatta una sotto-proprietà indentata con stile."""
    space = " " * indent
    val_str = str(value) if value is not None else "N/D"
    if val_str == "N/A":
        val_str = "N/D"
    if unit:
        val_str += f" {unit}"
    style = "bold_green" if highlight else "normal"
    return (f"{space}└─ {key:<32} : {val_str}", style)


# ==============================================================================
# SCHEDA 1: PANORAMICA, HARDWARE, LAN & WAN
# ==============================================================================

def format_overview(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Restituisce le righe formattate per la scheda Panoramica & LAN."""
    lines: List[Tuple[str, str]] = []
    if not data:
        lines.append(("Nessun dato disponibile. Premi 'r' per avviare una scansione.", "dim"))
        return lines

    lan = data.get("lan", {})
    wan = data.get("wan", {})
    ixp = data.get("ixp", {})
    perf = data.get("performance", {})
    est = data.get("estimations", {})

    p_iface = lan.get("primary_interface") or {}
    p_name = lan.get("primary_interface_name") or p_iface.get("name") or "N/D"
    gw = lan.get("gateway") or {}
    phys = est.get("physical_medium") or {}
    bb = perf.get("bufferbloat") or {}
    speed = perf.get("speed") or {}
    lat_targets = perf.get("latency_targets") or perf.get("latency") or {}

    # --- TOPOLOGIA DI RETE ---
    lines.append(("═" * 78, "cyan"))
    lines.append((" TOPOLOGIA DI RETE (Host Locale ──> Gateway ──> BNG ──> IXP/Dorsale ──> Internet)", "bold_cyan"))
    lines.append(("═" * 78, "cyan"))

    host_str = f"Host: {p_iface.get('ipv4') or 'N/D'} [{p_iface.get('type') or 'LAN'}]"
    gw_str = f"Gateway: {gw.get('ipv4') or 'N/D'} ({gw.get('vendor') or 'Router'})"

    hop2 = ixp.get("hop2_bng") or {}
    bng_str = f"BNG: {hop2.get('ip') or 'N/D'}"
    if hop2.get("min_ms") is not None:
        bng_str += f" ({hop2.get('min_ms'):.1f}ms)"

    hub_str = f"Hub: {ixp.get('ixp_name') or 'Direct PNI'}"
    if ixp.get("anycast_colo"):
        hub_str += f" [{ixp.get('anycast_colo')}]"

    topo_line = f" [{host_str}] ───> [{gw_str}] ───> [{bng_str}] ───> [{hub_str}]"
    lines.append((topo_line, "bold_white"))
    lines.append(("", "normal"))

    # --- BOX RIASSUNTIVO 2x2 ---
    lines.append(("┌" + "─" * 36 + "┬" + "─" * 39 + "┐", "dim"))

    # Riga 1: Mezzo Fisico & Bufferbloat
    med_name = phys.get("verdict_label") or phys.get("predicted_medium") or "In analisi..."
    conf_str = f"{phys.get('confidence_pct', 0):.1f}%" if phys.get("confidence_pct") is not None else "N/D"
    bb_grade = bb.get("grade") or "N/D"
    bb_dl = f"+{bb.get('download_delta_ms', 0):.1f}ms" if bb.get("download_delta_ms") is not None else "N/D"
    bb_ul = f"+{bb.get('upload_delta_ms', 0):.1f}ms" if bb.get("upload_delta_ms") is not None else "N/D"

    col1 = f" MEZZO FISICO: {med_name[:20]}"
    col2 = f" BUFFERBLOAT: Grado {bb_grade} (DL {bb_dl}, UL {bb_ul})"
    lines.append((f"│{col1:<36}│{col2:<39}│", "normal"))

    sub1 = f"   Confidenza modello: {conf_str}"
    idle_ms = f"{bb.get('idle_latency_ms', 0):.1f}ms" if bb.get('idle_latency_ms') is not None else "N/D"
    sub2 = f"   Latenza a riposo: {idle_ms}"
    lines.append((f"│{sub1:<36}│{sub2:<39}│", "dim"))

    lines.append(("├" + "─" * 36 + "┼" + "─" * 39 + "┤", "dim"))

    # Riga 2: Velocità & Latenza Media
    dl_mbps = f"{speed.get('download_mbps', 0):.1f} Mbps" if speed.get('download_mbps') else "N/D"
    ul_mbps = f"{speed.get('upload_mbps', 0):.1f} Mbps" if speed.get('upload_mbps') else "N/D"
    col1 = f" BANDA: DL {dl_mbps} / UL {ul_mbps}"

    # Latenza Cloudflare o primo target valido
    cf_lat = lat_targets.get("Cloudflare DNS") or (next(iter(lat_targets.values())) if lat_targets else {})
    rtt_val = f"{cf_lat.get('median_ms', 0):.1f} ms" if cf_lat.get('median_ms') is not None else "N/D"
    jit_val = f"{cf_lat.get('jitter_ms', 0):.2f} ms" if cf_lat.get('jitter_ms') is not None else "N/D"
    col2 = f" LATENZA: {rtt_val} (Jitter {jit_val})"
    lines.append((f"│{col1:<36}│{col2:<39}│", "normal"))

    dl_stab = f"Stab: {speed.get('download', {}).get('stability_pct', 0):.1f}%" if speed.get('download') else ""
    loss_val = f"{cf_lat.get('packet_loss_pct', 0):.1f}% loss" if cf_lat.get('packet_loss_pct') is not None else "0% loss"
    sub1 = f"   {dl_stab}"
    sub2 = f"   Affidabilità: {loss_val}"
    lines.append((f"│{sub1:<36}│{sub2:<39}│", "dim"))

    lines.append(("└" + "─" * 36 + "┴" + "─" * 39 + "┘", "dim"))
    lines.append(("", "normal"))

    # --- 1. SCHEDA DI RETE & CONFIGURAZIONE LAN ---
    lines.extend(_format_section_header("1. Scheda di Rete & Configurazione LAN", "💻"))
    lines.append(_format_kv("Interfaccia Attiva", f"{p_name} ({p_iface.get('type', 'N/A')})", highlight=True))
    lines.append(_format_kv("Indirizzo Fisico (MAC)", p_iface.get("mac")))
    lines.append(_format_kv("Produttore Hardware (OUI)", p_iface.get("vendor")))
    lines.append(_format_kv("Indirizzo IPv4 Locale", p_iface.get("ipv4"), highlight=True))
    lines.append(_format_kv("Maschera di Sottorete", p_iface.get("netmask")))
    lines.append(_format_kv("Indirizzo Broadcast", p_iface.get("broadcast")))
    lines.append(_format_kv("MTU Interfaccia", p_iface.get("mtu"), "bytes"))

    # Indirizzi IPv6
    ipv6_list = p_iface.get("ipv6_list", [])
    if ipv6_list:
        for ip6 in ipv6_list:
            lines.append(_format_kv(f"IPv6 ({ip6.get('type', 'Globale')})", f"{ip6.get('address')}/{ip6.get('prefix')}"))
    else:
        lines.append(_format_kv("Indirizzi IPv6", "Nessun indirizzo IPv6 configurato"))

    # Wi-Fi vs Ethernet
    wifi = lan.get("wifi", {})
    ethernet = lan.get("ethernet", {})
    ifname = p_iface.get("name", "")
    iface_type = lan.get("interface_type") or p_iface.get("interface_type") or p_iface.get("type") or ""
    is_wifi_link = (iface_type == "Wi-Fi")
    is_eth_link = (iface_type == "Ethernet") or (not is_wifi_link and bool(ethernet.get("active") or ethernet.get("speed_mbps") is not None or ethernet.get("cable_connected")))

    if is_wifi_link:
        lines.append(("", "normal"))
        lines.append((f"  Parametri Radio Wi-Fi Wireless ({ifname}):", "bold_magenta"))
        ssid_str = "Nascosto dal sistema (serve il permesso Posizione)" if wifi.get("ssid_hidden_by_os") else (wifi.get("ssid") or "Connesso")
        lines.append(_format_sub_kv("SSID Rete", ssid_str, highlight=True))
        if wifi.get("bssid"):
            lines.append(_format_sub_kv("BSSID (Access Point MAC)", f"{wifi.get('bssid')} ({wifi.get('bssid_vendor') or 'N/D'})"))
        if wifi.get("wifi_generation") or wifi.get("phy_mode"):
            lines.append(_format_sub_kv("Standard / Generazione", f"{wifi.get('wifi_generation') or ''} [{wifi.get('phy_mode') or ''}]"))
        if wifi.get("channel") or wifi.get("frequency_ghz"):
            lines.append(_format_sub_kv("Banda & Canale", f"{wifi.get('frequency_ghz') or ''} (Canale {wifi.get('channel') or ''})"))
        if wifi.get("rssi_dbm") is not None:
            lines.append(_format_sub_kv("Potenza Segnale (RSSI)", wifi.get("rssi_dbm"), "dBm"))
        if wifi.get("noise_dbm") is not None:
            lines.append(_format_sub_kv("Rumore di Fondo (Noise)", wifi.get("noise_dbm"), "dBm"))
        if wifi.get("snr_db") is not None:
            lines.append(_format_sub_kv("Rapporto Segnale/Rumore (SNR)", wifi.get("snr_db"), "dB"))
        if wifi.get("signal_quality_pct") is not None:
            lines.append(_format_sub_kv("Qualità Segnale", f"{wifi.get('signal_quality_pct')}%"))
        if wifi.get("tx_rate_mbps") is not None:
            lines.append(_format_sub_kv("Link Speed (Tx Rate)", wifi.get("tx_rate_mbps"), "Mbps", highlight=True))
        if wifi.get("mcs_index") is not None:
            lines.append(_format_sub_kv("MCS Index (Modulazione)", wifi.get("mcs_index")))
        if wifi.get("security"):
            lines.append(_format_sub_kv("Sicurezza & Crittografia", wifi.get("security")))
    elif is_eth_link:
        lines.append(("", "normal"))
        lines.append((f"  Parametri Connessione Cablata Ethernet ({ifname}):", "bold_cyan"))
        lines.append(_format_sub_kv("Velocità di Link Negoziata", ethernet.get("speed_mbps") or "Non rilevata", "Mbps", highlight=True))
        lines.append(_format_sub_kv("Modalità Duplex", ethernet.get("duplex") or "--"))
        lines.append(_format_sub_kv("Descrizione Media", ethernet.get("media_description") or "--"))
        lines.append(_format_sub_kv("Stato Cavo", "Attivo / Connesso" if ethernet.get("cable_connected") else "Non rilevato"))

        sw = ethernet.get("switch_info") or {}
        if sw:
            lines.append(("    Apparato Switch Collegato:", "bold_white"))
            if sw.get("detected"):
                if sw.get("switch_name"):
                    lines.append(_format_sub_kv("Nome Switch", sw.get("switch_name"), highlight=True, indent=6))
                if sw.get("switch_model"):
                    lines.append(_format_sub_kv("Modello Apparato", sw.get("switch_model"), indent=6))
                if sw.get("port_id"):
                    lines.append(_format_sub_kv("Porta Switch (Link)", sw.get("port_id"), highlight=True, indent=6))
                if sw.get("vlan"):
                    lines.append(_format_sub_kv("VLAN Porta", sw.get("vlan"), indent=6))
                if sw.get("management_ip"):
                    lines.append(_format_sub_kv("IP Gestione Switch", sw.get("management_ip"), indent=6))
                if sw.get("protocol"):
                    lines.append(_format_sub_kv("Protocollo di Rilevamento", sw.get("protocol"), indent=6))
            else:
                lines.append(_format_sub_kv("Tipologia Switch", sw.get("switch_type", "Switch L2 Unmanaged"), indent=6))
                if sw.get("description"):
                    lines.append((f"      ↳ {sw.get('description')}", "dim"))

    lines.append(("", "normal"))

    # --- 2. GATEWAY, DHCP & RISOLUZIONE DNS ---
    lines.extend(_format_section_header("2. Gateway, DHCP & Risoluzione DNS", "🌐"))
    lines.append(_format_kv("Default Gateway (Router)", gw.get("ipv4"), highlight=True))
    lines.append(_format_kv("MAC Address Router", gw.get("mac")))
    lines.append(_format_kv("Produttore Router (OUI)", gw.get("vendor")))

    dhcp = lan.get("dhcp", {})
    if dhcp.get("server_ip"):
        lines.append(_format_kv("Server DHCP", dhcp.get("server_ip")))
        lines.append(_format_kv("Durata Concessione (Lease)", dhcp.get("lease_time_human")))
        if dhcp.get("bootfile"):
            lines.append(_format_kv("Bootfile / PXE", dhcp.get("bootfile")))

    dns = lan.get("dns", {})
    resolvers = dns.get("resolvers", [])
    lines.append(_format_kv("Server DNS di Sistema", ", ".join(resolvers) if resolvers else "Nessuno"))

    dns_bm = lan.get("dns_benchmark", {})
    if dns_bm.get("system_resolver_latency_ms") is not None:
        lines.append(_format_kv("Tempo Risoluzione DNS Locale", f"{dns_bm.get('system_resolver_latency_ms')} ms"))

    resolvers_dnssec = dns_bm.get("resolvers_dnssec") or []
    if resolvers_dnssec:
        res_parts = [f"{r['ip']}: {r.get('status', 'inconclusivo')}" for r in resolvers_dnssec]
        lines.append(_format_kv("Convalida Crittografica DNSSEC", " | ".join(res_parts)))
    else:
        dnssec_badge = "VALIDANTE" if dns_bm.get("dnssec_validation_active") else "NON VALIDANTE"
        lines.append(_format_kv("Convalida Crittografica DNSSEC", dnssec_badge))

    lines.append(("", "normal"))

    # --- 3. CONNESSIONE INTERNET & GEOINTELLIGENCE WAN ---
    lines.extend(_format_section_header("3. Connessione Internet & Geointelligence WAN", "🌍"))
    lines.append(_format_kv("Indirizzo IPv4 Pubblico", wan.get("public_ipv4"), highlight=True))

    ipv6_pub = wan.get("public_ipv6")
    ipv6_status = f"{ipv6_pub} (Dual-Stack OK)" if ipv6_pub else "Non Rilevato (IPv4-Only)"
    lines.append(_format_kv("Indirizzo IPv6 Pubblico", ipv6_status))
    lines.append(_format_kv("Reverse DNS (PTR Hostname)", wan.get("reverse_dns")))
    lines.append(_format_kv("Provider Internet (ISP)", wan.get("isp"), highlight=True))

    asn = wan.get("asn")
    org = wan.get("org")
    asn_str = f"{asn or 'N/D'} ({org or 'N/D'})" if (asn or org) else "N/D"
    lines.append(_format_kv("Autonomous System (ASN)", asn_str))

    city = wan.get("city")
    region = wan.get("region")
    country = wan.get("country")
    if city or region or country:
        geo_parts = [p for p in (city, region) if p]
        loc_str = ", ".join(geo_parts)
        if country:
            loc_str = f"{loc_str} - {country}" if loc_str else country
    else:
        loc_str = "N/D"
    lines.append(_format_kv("Posizione Geografica", loc_str))

    coords = wan.get("coordinates", {})
    if coords.get("latitude") and coords.get("longitude"):
        lines.append(_format_kv("Coordinate Lat / Lon", f"{coords.get('latitude')}, {coords.get('longitude')}"))
    lines.append(_format_kv("Fuso Orario Rete", wan.get("timezone")))

    privacy = wan.get("privacy_and_routing", {})
    priv_type = privacy.get("type") or "N/D"
    lines.append(_format_kv("Stato Privacy / VPN / Proxy", priv_type))

    path_mtu = ixp.get("path_mtu")
    lines.append(_format_kv("Path MTU Misurato (DF)", "N/D" if path_mtu is None else f"{path_mtu} bytes"))

    lines.append(("", "normal"))

    # --- 4. ANALISI NAT & SICUREZZA ROUTER ---
    lines.extend(_format_section_header("4. Analisi NAT & Sicurezza Router (STUN RFC 5389)", "🛡️"))
    nat = wan.get("nat", {})
    lines.append(_format_kv("Tipologia NAT Mappata", nat.get("nat_type"), highlight=True))
    lines.append(_format_kv("Comportamento Mappatura", nat.get("mapping_behavior")))
    lines.append(_format_kv("Porta Esterna STUN Mappata", nat.get("mapped_external_port")))

    pred_med = str(phys.get("predicted_medium", "")).lower()
    conf_val = phys.get("confidence_pct")
    conf_num = float(conf_val) if conf_val is not None else 100.0
    is_ambig = phys.get("ambiguous", False)
    is_mobile_pred = "mobile" in pred_med or "cellular" in pred_med
    is_mobile_confident = is_mobile_pred and conf_num >= 60.0 and not is_ambig
    wan_ip_ok = bool(wan.get("public_ipv4"))

    if nat.get("cgnat_detected"):
        cgnat_badge = "RILEVATO (RFC 6598)"
    elif is_mobile_confident:
        cgnat_badge = "non rilevabile (su rete mobile il CGNAT è probabile)"
    elif not wan_ip_ok:
        cgnat_badge = "non rilevabile (IP pubblico assente)"
    else:
        cgnat_badge = "non rilevabile (nessun indizio di CGNAT: IP pubblico fuori da 100.64.0.0/10)"
    lines.append(_format_kv("Carrier-Grade NAT (CGNAT)", cgnat_badge))

    services = wan.get("router_services", {})
    upnp_text = services.get("upnp_status_text") or ("ATTIVO" if services.get("upnp_igd_available") else "Nessuna risposta (UPnP non rilevato)")
    lines.append(_format_kv("UPnP IGD Router", upnp_text))

    pmp_text = services.get("nat_pmp_status_text") or ("ATTIVO" if services.get("nat_pmp_available") else "Nessuna risposta (NAT-PMP non rilevato)")
    lines.append(_format_kv("NAT-PMP Router", pmp_text))

    lines.append(("", "normal"))

    # --- 5. DISPOSITIVI RILEVATI NELLA LAN ---
    perm_warn = lan.get("permissions_warning")
    if perm_warn:
        lines.append((f"  ⚠️  {perm_warn}", "yellow"))
        lines.append(("", "normal"))

    this_dev = lan.get("this_device")
    if this_dev:
        lines.append(("  Questo Dispositivo (Host Locale):", "bold_white"))
        h_name = f" ({this_dev['hostname']})" if this_dev.get("hostname") else ""
        dev_line = f"    • {this_dev.get('ip', 'N/D'):<15}  {this_dev.get('mac', 'N/D'):<17}  {this_dev.get('vendor', 'N/D')}{h_name}  [{this_dev.get('type', 'LAN')}]"
        lines.append((dev_line, "bold_green"))
        lines.append(("", "normal"))

    devices = lan.get("lan_devices") or lan.get("arp_table", [])
    if devices:
        lines.append((f"  Dispositivi Rilevati nella LAN ({len(devices)} host):", "bold_white"))
        dev_header = f"    {'IP Address':<16} {'MAC Address':<18} {'Produttore OUI / Hostname':<30} {'Metodo'}"
        lines.append((dev_header, "bold_cyan"))
        lines.append(("    " + "─" * (len(dev_header) - 4), "dim"))

        for d in devices:
            ip_val = d.get("ip") or "N/D"
            mac_val = d.get("mac") or "N/D"
            h_name = f" ({d['hostname']})" if (d.get("hostname") and d["hostname"] != "N/D") else ""
            vendor_val = (d.get("vendor") or "N/D") + h_name
            if len(vendor_val) > 28:
                vendor_val = vendor_val[:25] + "..."
            how = d.get("how_found") or "ARP"
            v6_flag = " [+IPv6]" if d.get("ipv6_addresses") else ""
            d_row = f"    {ip_val:<16} {mac_val:<18} {vendor_val:<30} {how}{v6_flag}"
            lines.append((d_row, "normal"))

    return lines


# ==============================================================================
# SCHEDA 2: MEZZO FISICO & MODELLI MATEMATICI
# ==============================================================================

def format_physical_medium(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Restituisce le righe formattate per la scheda Mezzo Fisico & Diagnosi."""
    lines: List[Tuple[str, str]] = []
    if not data:
        lines.append(("Nessun dato disponibile.", "dim"))
        return lines

    est = data.get("estimations", {})
    phys = est.get("physical_medium", {})
    ixp = data.get("ixp", {})

    lines.append(("═" * 78, "cyan"))
    lines.append((" CLASSIFICAZIONE FISICA DELL'ULTIMO MIGLIO (Modello Bayesiano & Diagnosi)", "bold_cyan"))
    lines.append(("═" * 78, "cyan"))

    display_med = phys.get("verdict_label") or phys.get("predicted_medium") or "N/D"
    conf = phys.get("confidence_pct", 0.0)
    lines.append((f" Mezzo Fisico Ultimo Miglio : {display_med}", "bold_green"))
    lines.append((f" Indice di Confidenza Modello: {conf:.1f}%", "bold_white"))
    lines.append(("", "normal"))

    # Valutazione sintetica & Rationale
    expl = phys.get("explanation", "")
    if expl:
        lines.append((" Valutazione Sintetica:", "bold_yellow"))
        lines.append((f"  {expl}", "normal"))
        lines.append(("", "normal"))

    rationale = phys.get("rationale", [])
    if rationale:
        lines.append((" Motivazioni Analitiche del Modello:", "bold_yellow"))
        for r in rationale:
            lines.append((f"  ↳ {r}", "dim"))
        lines.append(("", "normal"))

    # Veto deterministici
    vetoes = phys.get("vetoes_triggered", [])
    if vetoes:
        lines.append((" Veto Deterministici Attivati:", "bold_red"))
        for v in vetoes:
            lines.append((f"  ✗ {v}", "red"))
        lines.append(("", "normal"))

    # Alternative
    alt = phys.get("alternatives", [])
    if alt:
        lines.append((" Ipotesi Alternative Valutate:", "bold_yellow"))
        for a in alt:
            share = a.get("confidence_share_pct") or a.get("probability_pct", 0)
            lines.append((f"  • {a.get('medium')}: {a.get('score', 0):.1f} pt ({share:.1f}%)", "normal"))
        lines.append(("", "normal"))

    unassigned = phys.get("unassigned_pct")
    if unassigned is not None:
        lines.append((f" Quota Non Attribuita        : {unassigned}%", "dim"))
        lines.append(("", "normal"))

    mq = phys.get("measurement_quality") or est.get("measurement_quality") or {}
    if mq.get("noisy"):
        lines.append(("  ⚠️  Misura disturbata: possibile traffico concorrente sulla linea. Ripetere a linea libera.", "yellow"))
        lines.append(("", "normal"))

    # Evidenze con pesi applicati
    evidences = phys.get("evidence", [])
    if evidences:
        lines.append((" Evidenze e Pesi di Punteggio Applicati:", "bold_yellow"))
        for idx, ev in enumerate(evidences, 1):
            desc = ev.get("reason") or ev.get("description") or ev.get("rule") or f"Evidenza {idx}"
            lines.append((f"  {idx}. {desc}", "bold_white"))
            weights = ev.get("contributions") or ev.get("weights") or {}
            for med, w in weights.items():
                w_sign = f"+{w}" if w > 0 else str(w)
                lines.append((f"     └─ {med}: {w_sign} pt", "dim"))
        lines.append(("", "normal"))

    # Parametri di Accesso Hop 2 (BNG Provider)
    hop2 = ixp.get("hop2_bng") or phys.get("bng_hop") or {}
    lines.append((" PARAMETRI DI ACCESSO HOP 2 (BNG Provider):", "bold_yellow"))
    if hop2.get("ip"):
        cgnat_tag = " [CGNAT RFC 6598]" if hop2.get("cgnat_hop") else ""
        lines.append((f" • Indirizzo Gateway Operatore (BNG) : {hop2.get('ip')}{cgnat_tag}", "normal"))
        lines.append((f" • Latenza Minima di Tratta (Min RTT): {hop2.get('min_ms', 0):.2f} ms", "normal"))
        lines.append((f" • Latenza Mediana                    : {hop2.get('median_ms', 0):.2f} ms", "normal"))
        lines.append((f" • Jitter Interarrivo RFC 3550 / IPDV : {hop2.get('jitter_ms', 0):.2f} ms", "normal"))
        if hop2.get("iqr_ms") is not None:
            lines.append((f" • Dispersione Interquartile (IQR)    : {hop2.get('iqr_ms', 0):.2f} ms", "normal"))
        if hop2.get("tail_variance_ms") is not None:
            lines.append((f" • Coda p95 (Tail Variance)          : +{hop2.get('tail_variance_ms', 0):.2f} ms", "normal"))
    else:
        lines.append((" • Hop 2 non responsivo o non isolabile (filtro ICMP del provider).", "dim"))

    path_mtu = ixp.get("path_mtu")
    if path_mtu:
        mtu_desc = "Incapsulamento PPPoE (-8B standard FTTC/VDSL2)" if path_mtu == 1492 else f"MTU rilevato: {path_mtu}"
        lines.append((f" • Path MTU (Don't Fragment)         : {path_mtu} byte ({mtu_desc})", "normal"))

    lines.append(("", "normal"))

    # Profilo Latenza Salto per Salto (Access Profile)
    acc_prof = ixp.get("access_profile") or {}
    prof_hops = acc_prof.get("hops") or []
    if prof_hops:
        lines.append((" PROFILO LATENZA SALTO PER SALTO (Access Profile):", "bold_yellow"))
        prof_header = f" {'Hop':<4} {'Indirizzo IP':<18} {'Min RTT':<11} {'Mediana':<11} {'Delta Floor':<14} {'Ruolo / Note'}"
        lines.append((prof_header, "bold_cyan"))
        lines.append(("─" * len(prof_header), "dim"))

        for ph in prof_hops[:12]:
            h_num = str(ph.get("hop", "?"))
            h_ip = ph.get("ip") or "*"
            if h_ip == "*" or ph.get("min_ms") is None:
                h_ip = "*"
                h_min = "N/D"
                h_med = "N/D"
                h_inc = "N/D"
                h_role = ph.get("role") or ph.get("role_note")
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

            lines.append((f" {h_num:<4} {h_ip:<18} {h_min:<11} {h_med:<11} {h_inc:<14} {h_role}", "normal"))

        lines.append(("", "normal"))

    # BDP & Buffer TCP
    bdp = est.get("bandwidth_delay_product", {})
    lines.append((" BANDWIDTH-DELAY PRODUCT (BDP) & BUFFER TCP:", "bold_yellow"))
    if bdp.get("bdp_bytes") is None:
        bdp_desc = bdp.get("description") or "misura non valida"
        lines.append((f" • Bandwidth-Delay Product (BDP)     : N/D ({bdp_desc})", "normal"))
        lines.append((" • Finestra TCP Consigliata (Socket) : N/D", "normal"))
    else:
        lines.append((f" • Bandwidth-Delay Product (BDP)     : {bdp.get('bdp_kb')} KB ({bdp.get('bdp_bytes')} bytes)", "normal"))
        lines.append((f" • Finestra TCP Consigliata (Socket) : {bdp.get('recommended_tcp_window_kb')} KB", "normal"))

    lines.append(("", "normal"))

    # MOS ITU-T G.107 & R-Factor
    mos = est.get("voice_quality_mos") or est.get("mos_score") or {}
    lines.append((" QUALITÀ VOCALE ITU-T G.107 & FATTORE R:", "bold_yellow"))
    mos_val = mos.get("mos_score") or mos.get("score")
    if mos_val is None:
        lines.append((f" • Score Vocale ITU-T G.107 (MOS)    : N/D ({mos.get('quality_rating') or 'Dati insufficienti'})", "normal"))
        lines.append((" • Fattore di Trasmissione (R-Factor): N/D", "normal"))
    else:
        q_rating = mos.get("quality_rating") or "Buono"
        lines.append((f" • Score Vocale ITU-T G.107 (MOS)    : {mos_val:.2f} / 4.5 ({q_rating})", "bold_green"))
        r_fact = mos.get("r_factor", "N/D")
        lines.append((f" • Fattore di Trasmissione (R-Factor): {r_fact} / 100", "normal"))

    lines.append(("", "normal"))

    # Valutazione Idoneità Applicativa Real-Time
    apps = est.get("application_suitability") or est.get("suitability") or {}
    if apps:
        lines.append((" VALUTAZIONE IDONEITÀ APPLICATIVA REAL-TIME:", "bold_yellow"))
        app_list = [
            ("competitive_gaming", "gaming", "Gaming Competitivo / Esport"),
            ("video_streaming", "streaming_4k", "Streaming Video 4K HDR & 8K"),
            ("video_conferencing", "voip", "Smart Working & Zoom/Teams"),
            ("cloud_gaming", "cloud_gaming", "Cloud Gaming (GeForce NOW/Parsec)")
        ]
        for key1, key2, name in app_list:
            info = apps.get(key1) or apps.get(key2) or {}
            status = info.get("status") or info.get("verdict") or "N/D"
            score = info.get("score")
            score_str = f"{score}/100" if score is not None else "N/D"
            desc = info.get("desc") or info.get("reason") or ""
            lines.append((f" • {name:<34}: [{status:<10}] ({score_str}) - {desc}", "normal"))

    return lines


# ==============================================================================
# SCHEDA 3: IXP & ROUTING OTTICO
# ==============================================================================

def format_routing_ixp(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Restituisce le righe formattate per la scheda IXP & Routing Ottico."""
    lines: List[Tuple[str, str]] = []
    if not data:
        lines.append(("Nessun dato disponibile.", "dim"))
        return lines

    ixp = data.get("ixp", {})
    est = data.get("estimations", {})
    opt = est.get("optical_routing", {})

    lines.append(("═" * 78, "cyan"))
    lines.append((" INTELLIGENCE PEERING IXP & INSTRADAMENTO OTTICO", "bold_cyan"))
    lines.append(("═" * 78, "cyan"))

    ixp_name = opt.get("nearest_ixp_name") or ixp.get("ixp_name") or "Direct PNI / IP Transit"
    is_unidentified = "non identificato" in str(ixp_name).lower() or ixp_name == "N/D"

    lines.append((f" Internet eXchange / Hub Peering : {ixp_name}", "bold_green"))
    if not is_unidentified and opt.get("ixp_facility"):
        lines.append((f" Struttura / Campus IXP          : {opt.get('ixp_facility')}", "normal"))

    peering_type = opt.get("peering_type") or ixp.get("classification_tier") or "Tier 2 Direct PNI"
    lines.append((f" Tipologia Interconnessione      : {peering_type}", "bold_white"))

    if not is_unidentified and ixp.get("detection_method"):
        conf_str = f" (Confidenza: {ixp.get('confidence')})" if ixp.get("confidence") else ""
        lines.append((f" Metodo di Identificazione       : {ixp.get('detection_method')}{conf_str}", "normal"))

    if ixp.get("anycast_colo"):
        target_city = f" ({opt.get('ixp_city', '')})" if opt.get("ixp_city") else ""
        lines.append((f" PoP Anycast Rilevato (Cloudflare): {ixp.get('anycast_colo')}{target_city}", "bold_white"))

    if not is_unidentified and ixp.get("matched_hop_ip"):
        hop_str = f"{ixp.get('matched_hop_ip')}"
        if ixp.get("matched_subnet"):
            hop_str += f" (Subnet: {ixp.get('matched_subnet')})"
        lines.append((f" Interfaccia Peering / Egress    : {hop_str}", "normal"))

    if opt.get("calculation_basis"):
        lines.append((f" Base di Calcolo Efficienza      : {opt.get('calculation_basis')}", "dim"))

    # Poli di Peering AS Operatore (PeeringDB)
    pdb_facs = ixp.get("peeringdb_facilities", [])
    if pdb_facs:
        fac_names = [f["name"] for f in pdb_facs[:4] if f.get("name")]
        if fac_names:
            lines.append((f" Poli Peering Pubblico AS Operat.: {', '.join(fac_names)}", "normal"))

    lines.append(("", "normal"))

    # Note di analisi topologica
    notes = ixp.get("analysis_notes", [])
    if notes:
        lines.append((" Note e Deduzioni Topologiche:", "bold_yellow"))
        for n in notes:
            lines.append((f"  • {n}", "dim"))
        lines.append(("", "normal"))

    # Efficienza Routing Ottico
    if opt:
        lines.append((" EFFICIENZA INSTRADAMENTO OTTICO (FIBRA DIELETTRICA 204.000 km/s):", "bold_yellow"))
        dist_km = opt.get("straight_line_distance_km") or opt.get("user_to_hub_km")
        target_city = f" verso {opt.get('ixp_city') or opt.get('hub_city')}" if (opt.get('ixp_city') or opt.get('hub_city')) else ""
        lines.append((f" • Distanza Geodetica Ortodromica: ~{dist_km:.1f} km{target_city}" if dist_km else " • Distanza Geodetica Ortodromica: N/D", "normal"))

        fiber_km = opt.get("estimated_fiber_path_km")
        if fiber_km is not None:
            lines.append((f" • Tratta Fibra Ottica Stimata   : ~{fiber_km:.1f} km (con detour infrastrutturale)", "normal"))

        min_opt_rtt = opt.get("theoretical_optical_min_rtt_ms") or opt.get("dielectric_min_ms")
        meas_rtt = opt.get("measured_rtt_ms") or opt.get("transport_delta_ms")
        meas_str = f" (RTT Misurato: {meas_rtt:.2f} ms)" if meas_rtt is not None else ""
        lines.append((f" • Latenza Luce in Fibra (Minimo): {min_opt_rtt:.2f} ms{meas_str}" if min_opt_rtt is not None else " • Latenza Luce in Fibra: N/D", "normal"))

        if opt.get("routing_efficiency_pct") is not None:
            lines.append((f" • Indice di Efficienza Routing  : {opt.get('routing_efficiency_pct')}% ({opt.get('detour_rating') or 'Ottimo'})", "bold_white"))
        elif opt.get("routing_efficiency_ratio") is not None:
            lines.append((f" • Rapporto di Efficienza Routing: {opt.get('routing_efficiency_ratio'):.2f}x ({opt.get('rating') or 'Ottimo'})", "bold_white"))
        else:
            reason = opt.get("not_applicable_reason") or "dati insufficienti"
            lines.append((f" • Indice di Efficienza Routing  : N/D ({reason})", "dim"))

        if opt.get("switching_and_queuing_delay_ms") is not None:
            lines.append((f" • Ritardo Accodamento & Switch  : {opt.get('switching_and_queuing_delay_ms'):.2f} ms", "normal"))

        lines.append(("", "normal"))

    # Tabella Hop Traceroute
    hops = ixp.get("traceroute_hops", [])
    if hops:
        lines.append((" TABELLA SALTO PER SALTO (Traceroute Multi-Probe & ASN Cymru):", "bold_yellow"))
        header = f" {'Hop':<4} {'IP Address':<16} {'Min (ms)':<9} {'Med (ms)':<9} {'ASN':<8} {'Organizzazione / PTR':<30}"
        lines.append((header, "bold_cyan"))
        lines.append(("─" * len(header), "dim"))

        for h in hops:
            num = str(h.get("hop", "?"))
            ip = h.get("ip") or "*"
            min_ms = f"{h.get('min_ms'):.1f}" if h.get("min_ms") is not None else "*"
            med_ms = f"{h.get('median_ms'):.1f}" if h.get("median_ms") is not None else "*"
            asn = str(h.get("asn") or "-")
            org = h.get("as_name") or h.get("hostname") or "-"
            if len(org) > 28:
                org = org[:25] + "..."
            row = f" {num:<4} {ip:<16} {min_ms:<9} {med_ms:<9} {asn:<8} {org:<30}"
            lines.append((row, "normal"))

    return lines


# ==============================================================================
# SCHEDA 4: PERFORMANCE, LATENZA MULTI-TARGET & BUFFERBLOAT
# ==============================================================================

def format_performance(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Restituisce le righe formattate per la scheda Performance & Bufferbloat."""
    lines: List[Tuple[str, str]] = []
    if not data:
        lines.append(("Nessun dato disponibile.", "dim"))
        return lines

    perf = data.get("performance", {})
    bb = perf.get("bufferbloat", {})
    speed = perf.get("speed", {})
    targets = perf.get("latency_targets") or perf.get("latency", {})

    lines.append(("═" * 78, "cyan"))
    lines.append((" PERFORMANCE, LATENZA MULTI-TARGET, BUFFERBLOAT & VELOCITÀ", "bold_cyan"))
    lines.append(("═" * 78, "cyan"))

    # Tabella Latenza Multi-Target
    if targets:
        lines.append((" MATRICE DI LATENZA TARGET (ICMP & RFC 3550 Jitter):", "bold_yellow"))
        header = f" {'Target':<22} {'Min (ms)':<10} {'Mediana':<10} {'Max (ms)':<10} {'Jitter RFC3550':<16} {'Loss':<8}"
        lines.append((header, "bold_cyan"))
        lines.append(("─" * len(header), "dim"))

        for name, t in targets.items():
            if t.get("reachable", True) and t.get("median_ms") is not None:
                min_s = f"{t.get('min_ms', 0):.2f}"
                med_s = f"{t.get('median_ms', 0):.2f}"
                max_s = f"{t.get('max_ms', 0):.2f}"
                jit_s = f"{t.get('jitter_ms', 0):.2f}"
                loss_s = f"{t.get('packet_loss_pct', 0)}%"
                row = f" {name:<22} {min_s:<10} {med_s:<10} {max_s:<10} {jit_s:<16} {loss_s:<8}"
                lines.append((row, "normal"))
            else:
                lines.append((f" {name:<22} Non raggiungibile / Filtrato ICMP", "dim"))

        lines.append(("", "normal"))

    # Diagnosi Bufferbloat Bidirezionale
    lines.append((" DIAGNOSI BUFFERBLOAT SOTTO CARICO (BIDIREZIONALE):", "bold_yellow"))
    grade_val = bb.get("grade")
    max_delta = bb.get("max_delta_ms")
    delta_str = f" (Max Delta: +{max_delta} ms)" if max_delta is not None else ""
    lines.append((f" • Valutazione Bufferbloat : Grado {grade_val or 'N/D'}{delta_str}", "bold_green"))

    idle_target = f" (Target: {bb.get('idle_target')})" if bb.get("idle_target") else ""
    idle_ms = f"{bb.get('idle_latency_ms', 0):.2f} ms" if bb.get('idle_latency_ms') is not None else "N/D"
    lines.append((f" • Latenza a Riposo (Idle) : {idle_ms}{idle_target}", "normal"))

    dl_loaded = bb.get("download_loaded_ms")
    dl_delta = bb.get("download_delta_ms")
    dl_str = f"{dl_loaded:.2f} ms (+{dl_delta:.2f} ms)" if (dl_loaded is not None and dl_delta is not None) else "N/D"
    lines.append((f" • Sotto Carico Download   : {dl_str}", "normal"))

    ul_loaded = bb.get("upload_loaded_ms")
    ul_delta = bb.get("upload_delta_ms")
    ul_str = f"{ul_loaded:.2f} ms (+{ul_delta:.2f} ms)" if (ul_loaded is not None and ul_delta is not None) else "N/D"
    lines.append((f" • Sotto Carico Upload     : {ul_str}", "normal"))

    if bb.get("description"):
        lines.append((f" • Diagnosi Coda Router    : {bb.get('description')}", "dim"))

    lines.append(("", "normal"))

    # Velocità e Throughput Streaming Continuo
    lines.append((" RISULTATI TEST DI VELOCITÀ (Streaming Continuo HTTP/HTTPS):", "bold_yellow"))
    dl_mbps = speed.get("download_mbps")
    dl_dict = speed.get("download") or {}
    dl_valid = dl_dict.get("valid", dl_mbps is not None)
    if dl_valid and dl_mbps is not None:
        dl_peak = speed.get("download_peak_mbps") or dl_dict.get("peak_mbps") or dl_mbps
        dl_stab = speed.get("download_stability_pct") or dl_dict.get("stability_pct")
        stab_str = f" [Stabilità: {dl_stab:.1f}%]" if dl_stab is not None else ""
        lines.append((f" • Download (Regime)       : {dl_mbps:.1f} Mbps (Picco: {dl_peak:.1f} Mbps{stab_str})", "bold_white"))
    else:
        dl_reason = dl_dict.get("invalid_reason") or speed.get("invalid_reason") or "misura non valida o fallita"
        lines.append((f" • Download (Regime)       : N/D ({dl_reason})", "dim"))

    ul_mbps = speed.get("upload_mbps")
    ul_dict = speed.get("upload") or {}
    ul_valid = ul_dict.get("valid", ul_mbps is not None)
    if ul_valid and ul_mbps is not None:
        ul_peak = speed.get("upload_peak_mbps") or ul_dict.get("peak_mbps") or ul_mbps
        ul_stab = speed.get("upload_stability_pct") or ul_dict.get("stability_pct")
        ul_stab_str = f" [Stabilità: {ul_stab:.1f}%]" if ul_stab is not None else ""
        lines.append((f" • Upload (Regime)         : {ul_mbps:.1f} Mbps (Picco: {ul_peak:.1f} Mbps{ul_stab_str})", "bold_white"))
    else:
        ul_reason = ul_dict.get("invalid_reason") or speed.get("invalid_reason") or "misura non valida o fallita"
        lines.append((f" • Upload (Regime)         : N/D ({ul_reason})", "dim"))

    tot_mb = speed.get("bytes_transferred", 0) / (1024 * 1024)
    dl_bytes = speed.get("bytes_downloaded", 0) / (1024 * 1024)
    ul_bytes = speed.get("bytes_uploaded", 0) / (1024 * 1024)
    dur = speed.get("test_duration_s") or speed.get("total_duration_s", 0)
    if tot_mb > 0 or dur > 0:
        lines.append((f" • Traffico e Durata       : {tot_mb:.1f} MB trasferiti (DL: {dl_bytes:.1f} MB, UL: {ul_bytes:.1f} MB) in {dur:.1f}s", "dim"))

    # Errori speedtest se presenti
    speed_errors = speed.get("errors") or []
    if (not dl_valid or not ul_valid) and speed_errors:
        err_summaries = []
        for err in speed_errors[:3]:
            phase = err.get("phase", "stream")
            status = err.get("status")
            msg = err.get("error") or err.get("reason") or "errore"
            err_summaries.append(f"{phase} HTTP {status} ({msg})" if status else f"{phase}: {msg}")
        lines.append((f" • Errori Speedtest        : {'; '.join(err_summaries)}", "red"))

    # Calibrazione e psutil
    if speed.get("tool_ceiling_mbps") is not None:
        ceil_mbps = speed["tool_ceiling_mbps"]
        ceil_warn = " ⚠️ (>50% ceiling interprete)" if speed.get("ceiling_warning") else ""
        lines.append((f" • Limite Loopback Tool    : {ceil_mbps} Mbps{ceil_warn}", "dim"))

    if speed.get("servers_used"):
        agree_str = " (concordanti)" if speed.get("endpoints_agreement") is True else (" (discordanti)" if speed.get("endpoints_agreement") is False else "")
        lines.append((f" • Server Speedtest Usati  : {', '.join(speed['servers_used'])}{agree_str}", "dim"))

    if speed.get("other_process_bytes") is not None:
        other_kb = speed["other_process_bytes"] / 1024
        other_pct = speed.get("other_process_pct", 0.0)
        lines.append((f" • Traffico Altri Processi : {other_kb:.1f} KB stimati ({other_pct}% del traffico su interfaccia)", "dim"))

    return lines


# ==============================================================================
# SCHEDA 5: DATI GREZZI JSON
# ==============================================================================

def format_raw_json(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Restituisce il dump JSON formattato per l'ispezione riga per riga."""
    lines: List[Tuple[str, str]] = []
    if not data:
        lines.append(("Nessun dato disponibile.", "dim"))
        return lines

    text = json.dumps(data, ensure_ascii=False, indent=2)
    for l in text.splitlines():
        lines.append((l, "dim" if l.strip().startswith('"') else "normal"))

    return lines


# ==============================================================================
# MODERN TEXTUAL RESPONSIVE VIEWS & REACTIVE WIDGETS
# ==============================================================================

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Label, Static, DataTable
from textual.containers import Vertical, Horizontal, Container, VerticalScroll
from textual.reactive import reactive


def _make_kv(key: str, val: Any = "-", unit: str = "", val_id: Optional[str] = None, val_class: str = "kv-val") -> Horizontal:
    """Crea una riga orizzontale chiave-valore per le card Textual."""
    v_str = str(val) if val is not None else "-"
    if unit and v_str != "-":
        v_str = f"{v_str} {unit}"
    lbl_val = Label(v_str, id=val_id, classes=val_class) if val_id else Label(v_str, classes=val_class)
    return Horizontal(
        Label(f"• {key:<34} :", classes="kv-key"),
        lbl_val,
        classes="kv-row"
    )


class DashboardView(VerticalScroll):
    """Scheda 1: Panoramica e metriche sintetiche chiave."""
    data = reactive(None)

    def compose(self) -> ComposeResult:
        with Container(id="dash-empty"):
            yield Label("⚡  NETPROBE PRO - PRONTO", id="empty-state-title")
            yield Label("Nessuna scansione presente. Premi [▶ Avvia Scansione Completa] (o tasto Spazio) per avviare l'analisi.", id="empty-state-subtitle")

        with Container(id="dash-content"):
            with Container(classes="card"):
                yield Label("▶  SISTEMA & INTERFACCIA ATTIVA", classes="card-title")
                yield Label("-", id="dash-sys-label")

            with Horizontal(classes="hero-metric-row"):
                with Container(classes="hero-card"):
                    yield Label("▶ MEZZO FISICO (Stima)", classes="card-title-emerald")
                    yield Label("-", id="dash-medium-title", classes="hero-value")
                    yield Label("-", id="dash-medium-conf")
                    yield Label("-", id="dash-medium-bng", classes="hero-subtitle")

                with Container(classes="hero-card"):
                    yield Label("▶ BANDA PASSANTE", classes="card-title")
                    yield Label("-", id="dash-speed-title", classes="hero-value-cyan")
                    yield Label("-", id="dash-speed-ul")
                    yield Label("-", id="dash-speed-server", classes="hero-subtitle")

                with Container(classes="hero-card"):
                    yield Label("▶ LATENZA & BUFFERBLOAT", classes="card-title-amber")
                    yield Label("-", id="dash-bb-title", classes="hero-value")
                    yield Label("-", id="dash-bb-grade")
                    yield Label("-", id="dash-bb-deltas", classes="hero-subtitle")

            with Horizontal(classes="hero-metric-row"):
                with Container(classes="hero-card"):
                    yield Label("▶ INSTRADAMENTO & PEERING", classes="card-title")
                    yield Label("-", id="dash-ixp-title", classes="hero-value")
                    yield Label("-", id="dash-ixp-eff")
                    yield Label("-", id="dash-ixp-route", classes="hero-subtitle")

                with Container(classes="hero-card"):
                    yield Label("▶ QUALITÀ VOCALE & APPLICAZIONI", classes="card-title-emerald")
                    yield Label("-", id="dash-voice-title", classes="hero-value")
                    yield Label("-", id="dash-app-gaming")
                    yield Label("-", id="dash-app-streaming", classes="hero-subtitle")

    def on_mount(self):
        self._update_display(self.data)

    def watch_data(self, new_data):
        if self.is_mounted:
            self._update_display(new_data)

    def _update_display(self, data):
        c_empty = self.query_one("#dash-empty", Container)
        c_content = self.query_one("#dash-content", Container)
        if not data:
            c_empty.display = True
            c_content.display = False
            return

        c_empty.display = False
        c_content.display = True

        sys_s = data.get("system") or {}
        lan = data.get("lan") or {}
        p_if = lan.get("primary_interface") or {}
        self.query_one("#dash-sys-label", Label).update(
            f"Host: [b]{sys_s.get('hostname', '-')}[/b] | OS: {sys_s.get('os', '-')} ({sys_s.get('arch', '-')}) | Python {sys_s.get('python', '-')} | Interfaccia: [b]{p_if.get('name', '-')}[/b] ({p_if.get('type', '-')})"
        )

        est = data.get("estimations") or {}
        phys = est.get("physical_medium") or {}
        med_name = phys.get("predicted_medium", "Indeterminato")
        conf = phys.get("confidence_pct", 0.0)
        self.query_one("#dash-medium-title", Label).update(med_name)
        self.query_one("#dash-medium-conf", Label).update(f"Confidenza: {conf:.1f}% (Non attribuito: {phys.get('unattributed_pct', 0.0):.1f}%)")
        bng = phys.get("bng_hop") or {}
        if bng.get("ip"):
            self.query_one("#dash-medium-bng", Label).update(f"BNG: {bng.get('ip')} (Min RTT: {bng.get('min_ms')} ms)")
        else:
            self.query_one("#dash-medium-bng", Label).update("Nessun hop BNG rilevato")

        perf = data.get("performance") or {}
        speed = perf.get("speed") or {}
        dl_m = speed.get("download_mbps")
        ul_m = speed.get("upload_mbps")
        if dl_m is not None:
            self.query_one("#dash-speed-title", Label).update(f"DL: {dl_m:.1f} Mbps (Picco: {speed.get('download_peak_mbps', dl_m):.1f} Mbps)")
            self.query_one("#dash-speed-ul", Label).update(f"UL: {ul_m:.1f} Mbps (Picco: {speed.get('upload_peak_mbps', ul_m):.1f} Mbps)" if ul_m is not None else "UL: N/D")
            self.query_one("#dash-speed-server", Label).update(f"Server: {', '.join(speed.get('servers_used') or ['Cloudflare Anycast'])}")
        else:
            self.query_one("#dash-speed-title", Label).update("Test Velocità: N/D (Scansione Rapida)")
            self.query_one("#dash-speed-ul", Label).update("Banda sostenuta non misurata")
            self.query_one("#dash-speed-server", Label).update("Avvia scansione completa per il test di velocità")

        prim_lat = perf.get("primary_latency") or {}
        rtt_val = prim_lat.get("min_ms")
        jit_val = prim_lat.get("jitter_ms")
        self.query_one("#dash-bb-title", Label).update(f"Min RTT: {rtt_val if rtt_val is not None else 'N/D'} ms | Jitter: {jit_val if jit_val is not None else 'N/D'} ms")
        bb = perf.get("bufferbloat") or {}
        grade = bb.get("grade") or "N/D"
        self.query_one("#dash-bb-grade", Label).update(f"Bufferbloat: Grado [b]{grade}[/b]")
        self.query_one("#dash-bb-deltas", Label).update(f"DL delta: +{bb.get('download_delta_ms') or 0.0:.1f} ms | UL delta: +{bb.get('upload_delta_ms') or 0.0:.1f} ms")

        ixp = data.get("ixp") or {}
        opt = est.get("optical_routing") or {}
        self.query_one("#dash-ixp-title", Label).update(ixp.get("detected_ixp") or "IXP non identificato")
        eff = opt.get("routing_efficiency_pct")
        fiber_km = opt.get("estimated_fiber_path_km")
        self.query_one("#dash-ixp-eff", Label).update(f"Efficienza: {eff:.1f}% | Tratta Fibra: ~{fiber_km or 'N/D'} km" if eff is not None else "Efficienza ottica: Non applicabile")
        self.query_one("#dash-ixp-route", Label).update(f"Distanza Geodetica: ~{opt.get('straight_line_distance_km') or 'N/D'} km | {opt.get('detour_rating', 'N/D')}")

        voice = est.get("voice_quality_mos") or {}
        self.query_one("#dash-voice-title", Label).update(f"Voice MOS: {voice.get('mos_score', 'N/D')} / 4.5 ({voice.get('quality_rating', 'N/D')})")
        app_s = est.get("application_suitability") or {}
        game_st = (app_s.get("competitive_gaming") or {}).get("status", "N/D")
        stream_st = (app_s.get("video_streaming") or {}).get("status", "N/D")
        self.query_one("#dash-app-gaming", Label).update(f"Gaming: {game_st} | 4K Streaming: {stream_st}")
        conf_st = (app_s.get("video_conferencing") or {}).get("status", "N/D")
        cloud_st = (app_s.get("cloud_gaming") or {}).get("status", "N/D")
        self.query_one("#dash-app-streaming", Label).update(f"Video Call: {conf_st} | Cloud Gaming: {cloud_st}")


class LanView(VerticalScroll):
    """Scheda 2: Configurazione LAN, Wi-Fi / Ethernet, Gateway, DHCP e DNSSEC."""
    data = reactive(None)

    def compose(self) -> ComposeResult:
        with Container(classes="card"):
            yield Label("▶  SCHEDA DI RETE & CONFIGURAZIONE LAN", classes="card-title")
            yield _make_kv("Interfaccia Attiva", val_id="lan-iface")
            yield _make_kv("Indirizzo Fisico (MAC)", val_id="lan-mac")
            yield _make_kv("Produttore Hardware (OUI)", val_id="lan-oui")
            yield _make_kv("Indirizzo IPv4 Locale", val_id="lan-ip")
            yield _make_kv("Maschera di Sottorete", val_id="lan-mask")
            yield _make_kv("Indirizzo Broadcast", val_id="lan-bcast")
            yield _make_kv("MTU Interfaccia", val_id="lan-mtu")
            yield _make_kv("IPv6 Link-Local", val_id="lan-ipv6")

        with Container(classes="card"):
            yield Label("▶  PARAMETRI MEDIA (ETHERNET / WI-FI)", classes="card-title")
            yield _make_kv("Velocità di Link / Tx Rate", val_id="lan-speed")
            yield _make_kv("Modalità Duplex / Standard Wi-Fi", val_id="lan-duplex")
            yield _make_kv("Stato Cavo / Segnale RSSI", val_id="lan-carrier")
            yield _make_kv("Switch L2 / Rumore & SNR", val_id="lan-switch")

        with Container(classes="card"):
            yield Label("▶  GATEWAY, DHCP & RISOLUZIONE DNS", classes="card-title")
            yield _make_kv("Default Gateway (Router)", val_id="lan-gw")
            yield _make_kv("MAC Address Router", val_id="lan-gw-mac")
            yield _make_kv("Produttore Router (OUI)", val_id="lan-gw-oui")
            yield _make_kv("Server DHCP", val_id="lan-dhcp")
            yield _make_kv("Durata Concessione (Lease)", val_id="lan-lease")
            yield _make_kv("Server DNS di Sistema", val_id="lan-dns")
            yield _make_kv("Tempo Risoluzione DNS Locale", val_id="lan-dns-time")

        with Container(classes="card"):
            yield Label("▶  CONVALIDA CRITTOGRAFICA DNSSEC PER RISOLUTORE", classes="card-title")
            table = DataTable(id="table-dnssec")
            table.zebra_stripes = True
            yield table

    def on_mount(self):
        tbl = self.query_one("#table-dnssec", DataTable)
        tbl.add_columns("Server DNS", "PTR Hostname", "Tipo", "Stato Convalida DNSSEC")
        self._update_display(self.data)

    def watch_data(self, new_data):
        if self.is_mounted:
            self._update_display(new_data)

    def _update_display(self, data):
        if not data:
            return
        lan = data.get("lan") or {}
        p_if = lan.get("primary_interface") or {}
        self.query_one("#lan-iface", Label).update(f"{p_if.get('name', '-')} ({p_if.get('type', '-')})")
        self.query_one("#lan-mac", Label).update(str(p_if.get("mac", "-")))
        self.query_one("#lan-oui", Label).update(str(p_if.get("vendor", "-")))
        self.query_one("#lan-ip", Label).update(str(p_if.get("ipv4", "-")))
        self.query_one("#lan-mask", Label).update(f"{p_if.get('netmask', '-')} (/{p_if.get('cidr', '-')})")
        self.query_one("#lan-bcast", Label).update(str(p_if.get("broadcast", "-")))
        self.query_one("#lan-mtu", Label).update(f"{p_if.get('mtu', '-')} bytes" if p_if.get("mtu") else "-")
        self.query_one("#lan-ipv6", Label).update(str(p_if.get("ipv6_link_local", "-") or "-"))

        eth = lan.get("ethernet") or {}
        wifi = lan.get("wifi") or {}
        if eth:
            self.query_one("#lan-speed", Label).update(f"{eth.get('speed_mbps', '-')} Mbps")
            self.query_one("#lan-duplex", Label).update(f"{eth.get('duplex', '-')} ({eth.get('media_description', '-')})")
            self.query_one("#lan-carrier", Label).update(f"Attivo / {eth.get('status', 'Connesso')}")
            sw = lan.get("switch_discovery") or {}
            self.query_one("#lan-switch", Label).update(str(sw.get("summary") or sw.get("system_name") or "Switch L2 unmanaged / diretto"))
        elif wifi:
            self.query_one("#lan-speed", Label).update(f"Tx Rate: {wifi.get('tx_rate_mbps', '-')} Mbps (MCS {wifi.get('mcs_index', '-')})")
            self.query_one("#lan-duplex", Label).update(f"Standard: {wifi.get('standard', '-')} | Canale {wifi.get('channel', '-')}")
            self.query_one("#lan-carrier", Label).update(f"RSSI: {wifi.get('rssi_dbm', '-')} dBm | Rumore: {wifi.get('noise_dbm', '-')} dBm")
            self.query_one("#lan-switch", Label).update(f"SNR: {wifi.get('snr_db', '-')} dB | SSID: {wifi.get('ssid', '-')}")
        else:
            self.query_one("#lan-speed", Label).update("-")
            self.query_one("#lan-duplex", Label).update("-")
            self.query_one("#lan-carrier", Label).update("-")
            self.query_one("#lan-switch", Label).update("-")

        gw = lan.get("gateway") or {}
        self.query_one("#lan-gw", Label).update(str(gw.get("ipv4", "-")))
        self.query_one("#lan-gw-mac", Label).update(str(gw.get("mac", "-")))
        self.query_one("#lan-gw-oui", Label).update(str(gw.get("vendor", "-")))
        dhcp = lan.get("dhcp") or {}
        self.query_one("#lan-dhcp", Label).update(str(dhcp.get("server", "-")))
        lease_s = dhcp.get("lease_time_s")
        self.query_one("#lan-lease", Label).update(f"{lease_s / 3600:.1f} ore ({lease_s}s)" if lease_s else "-")
        dns = lan.get("dns") or {}
        srvs = dns.get("resolvers") or dns.get("nameservers") or []
        self.query_one("#lan-dns", Label).update(", ".join(srvs) if srvs else "-")
        time_ms = dns.get("local_resolution_time_ms")
        self.query_one("#lan-dns-time", Label).update(f"{time_ms:.1f} ms" if time_ms is not None else "-")

        tbl = self.query_one("#table-dnssec", DataTable)
        tbl.clear()
        dnssec = lan.get("dnssec") or {}
        resolvers = dnssec.get("resolvers") or []
        if not resolvers:
            for s in srvs:
                resolvers.append({"ip": s, "rdns": "-", "type": "Configurato", "status": "Non testato"})
        for r in resolvers:
            tbl.add_row(
                str(r.get("ip") or "-"),
                str(r.get("rdns") or "-"),
                str(r.get("type") or "Configurato"),
                str(r.get("status") or r.get("validation_status") or "-")
            )


class WanView(VerticalScroll):
    """Scheda 3: Connessione Internet, Geointelligence WAN e Analisi NAT (STUN)."""
    data = reactive(None)

    def compose(self) -> ComposeResult:
        with Container(classes="card"):
            yield Label("▶  CONNESSIONE INTERNET & GEOINTELLIGENCE WAN", classes="card-title")
            yield _make_kv("Indirizzo IPv4 Pubblico", val_id="wan-ip4")
            yield _make_kv("Indirizzo IPv6 Pubblico", val_id="wan-ip6")
            yield _make_kv("Connettività Dual-Stack", val_id="wan-dualstack")
            yield _make_kv("Reverse DNS (PTR Hostname)", val_id="wan-ptr")
            yield _make_kv("Provider Internet (ISP)", val_id="wan-isp")
            yield _make_kv("Autonomous System (ASN)", val_id="wan-asn")
            yield _make_kv("Posizione Geografica", val_id="wan-geo")
            yield _make_kv("Coordinate Lat / Lon", val_id="wan-coords")
            yield _make_kv("Fuso Orario Rete", val_id="wan-tz")
            yield _make_kv("Stato Privacy / VPN / Proxy", val_id="wan-privacy")
            yield _make_kv("Path MTU Misurato (DF)", val_id="wan-pmtu")

        with Container(classes="card"):
            yield Label("▶  ANALISI NAT & SICUREZZA ROUTER (STUN RFC 5389)", classes="card-title")
            yield _make_kv("Tipologia NAT Mappata", val_id="wan-nat-type")
            yield _make_kv("Comportamento Mappatura", val_id="wan-nat-behavior")
            yield _make_kv("Porta Esterna STUN Mappata", val_id="wan-nat-port")
            yield _make_kv("Carrier-Grade NAT (CGNAT)", val_id="wan-cgnat")
            yield _make_kv("UPnP IGD Router", val_id="wan-upnp")
            yield _make_kv("NAT-PMP Router", val_id="wan-natpmp")

    def on_mount(self):
        self._update_display(self.data)

    def watch_data(self, new_data):
        if self.is_mounted:
            self._update_display(new_data)

    def _update_display(self, data):
        if not data:
            return
        wan = data.get("wan") or {}
        self.query_one("#wan-ip4", Label).update(str(wan.get("public_ipv4") or "Non rilevato"))
        self.query_one("#wan-ip6", Label).update(str(wan.get("public_ipv6") or "Non Rilevato (IPv4-Only)"))
        self.query_one("#wan-dualstack", Label).update("Attivo" if wan.get("dual_stack_enabled") else "Disabilitato / Non presente")
        self.query_one("#wan-ptr", Label).update(str(wan.get("reverse_dns") or "-"))
        self.query_one("#wan-isp", Label).update(str(wan.get("isp") or "-"))
        self.query_one("#wan-asn", Label).update(f"{wan.get('asn', '-')} ({wan.get('org', '-')})")
        geo_str = f"{wan.get('city', '-')}, {wan.get('region', '-')} - {wan.get('country', '-')}"
        self.query_one("#wan-geo", Label).update(geo_str)
        coords = wan.get("coordinates") or {}
        c_lat, c_lon = coords.get("latitude"), coords.get("longitude")
        self.query_one("#wan-coords", Label).update(f"{c_lat}, {c_lon}" if c_lat and c_lon else "-")
        self.query_one("#wan-tz", Label).update(str(wan.get("timezone", "-")))
        priv = wan.get("privacy_and_routing") or {}
        self.query_one("#wan-privacy", Label).update(str(priv.get("type") or "Nessun indizio di VPN/proxy"))
        ixp = data.get("ixp") or {}
        pmtu = ixp.get("path_mtu")
        self.query_one("#wan-pmtu", Label).update(f"{pmtu} bytes" if pmtu else "-")

        nat = wan.get("nat") or {}
        self.query_one("#wan-nat-type", Label).update(str(nat.get("nat_type") or "-"))
        self.query_one("#wan-nat-behavior", Label).update(str(nat.get("mapping_behavior") or "-"))
        self.query_one("#wan-nat-port", Label).update(str(nat.get("mapped_external_port") or "-"))
        cgnat = "Rilevato (RFC 6598)" if nat.get("cgnat_detected") else "Non rilevato (IP pubblico)"
        self.query_one("#wan-cgnat", Label).update(cgnat)
        rs = wan.get("router_services") or {}
        self.query_one("#wan-upnp", Label).update(str(rs.get("upnp_status_text") or "-"))
        self.query_one("#wan-natpmp", Label).update(str(rs.get("nat_pmp_status_text") or "-"))


class PerformanceView(VerticalScroll):
    """Scheda 4: Matrice Latenza, Diagnosi Bufferbloat e Test di Velocità."""
    data = reactive(None)

    def compose(self) -> ComposeResult:
        with Container(classes="card"):
            yield Label("▶  MATRICE DI LATENZA TARGET", classes="card-title")
            table = DataTable(id="table-targets")
            table.zebra_stripes = True
            yield table

        with Container(classes="card"):
            yield Label("▶  DIAGNOSI BUFFERBLOAT SOTTO CARICO", classes="card-title")
            yield _make_kv("Latenza a Riposo (Idle Baseline)", val_id="perf-bb-idle")
            yield _make_kv("Latenza Sotto Carico Download", val_id="perf-bb-dl")
            yield _make_kv("Latenza Sotto Carico Upload", val_id="perf-bb-ul")
            yield _make_kv("Valutazione Grado Bufferbloat", val_id="perf-bb-grade", val_class="kv-val-green")
            yield _make_kv("Diagnosi Coda Router", val_id="perf-bb-desc")

        with Container(classes="card"):
            yield Label("▶  TEST DI VELOCITÀ & THROUGHPUT STREAMING", classes="card-title")
            yield _make_kv("Download (Regime Sostenuto)", val_id="perf-dl-mbps", val_class="kv-val-green")
            yield _make_kv("Download (Picco / Stabilità)", val_id="perf-dl-peak")
            yield _make_kv("Upload (Regime Sostenuto)", val_id="perf-ul-mbps", val_class="kv-val-green")
            yield _make_kv("Upload (Picco / Stabilità)", val_id="perf-ul-peak")
            yield _make_kv("Dati Totali Trasferiti / Durata", val_id="perf-data-transferred")
            yield _make_kv("Server Speedtest Utilizzati", val_id="perf-servers")
            yield _make_kv("Limite Loopback Tool (Interprete)", val_id="perf-ceiling")
            yield _make_kv("Accounting Traffico Interfaccia", val_id="perf-accounting")

    def on_mount(self):
        tbl = self.query_one("#table-targets", DataTable)
        tbl.add_columns("Target", "Host IP", "Tipo", "Min RTT (ms)", "Mediana (ms)", "Max RTT (ms)", "Jitter (ms)", "Loss (%)")
        self._update_display(self.data)

    def watch_data(self, new_data):
        if self.is_mounted:
            self._update_display(new_data)

    def _update_display(self, data):
        if not data:
            return
        perf = data.get("performance") or {}
        targets = perf.get("latency_targets") or perf.get("targets") or {}
        if not targets:
            targets = {}
            if perf.get("gateway_latency"):
                targets["Gateway Locale"] = perf["gateway_latency"]
            if perf.get("primary_latency"):
                targets[perf["primary_latency"].get("name", "Primary Target")] = perf["primary_latency"]

        tbl = self.query_one("#table-targets", DataTable)
        tbl.clear()
        for name, t in targets.items():
            tbl.add_row(
                name,
                str(t.get("host") or "-"),
                str(t.get("type") or "-"),
                f"{t.get('min_ms', '-'):.2f}" if isinstance(t.get('min_ms'), (int, float)) else "-",
                f"{t.get('median_ms', '-'):.2f}" if isinstance(t.get('median_ms'), (int, float)) else "-",
                f"{t.get('max_ms', '-'):.2f}" if isinstance(t.get('max_ms'), (int, float)) else "-",
                f"{t.get('jitter_ms', '-'):.2f}" if isinstance(t.get('jitter_ms'), (int, float)) else "-",
                f"{t.get('packet_loss_pct', 0.0):.1f}%"
            )

        bb = perf.get("bufferbloat") or {}
        self.query_one("#perf-bb-idle", Label).update(f"{bb.get('idle_latency_ms', '-')} ms" if bb.get("idle_latency_ms") else "-")
        dl_d = bb.get("download_delta_ms")
        self.query_one("#perf-bb-dl", Label).update(f"{bb.get('download_loaded_ms', '-')} ms (Delta: +{dl_d:.2f} ms)" if dl_d is not None else "-")
        ul_d = bb.get("upload_delta_ms")
        self.query_one("#perf-bb-ul", Label).update(f"{bb.get('upload_loaded_ms', '-')} ms (Delta: +{ul_d:.2f} ms)" if ul_d is not None else "-")
        self.query_one("#perf-bb-grade", Label).update(f"Grado {bb.get('grade', 'N/D')}")
        self.query_one("#perf-bb-desc", Label).update(str(bb.get("description") or "Scansione rapida o test non eseguito"))

        speed = perf.get("speed") or {}
        dl_m = speed.get("download_mbps")
        ul_m = speed.get("upload_mbps")
        self.query_one("#perf-dl-mbps", Label).update(f"{dl_m:.1f} Mbps" if dl_m is not None else "N/D (Scansione Rapida)")
        dl_pk = speed.get("download_peak_mbps")
        dl_st = speed.get("download_stability_pct")
        self.query_one("#perf-dl-peak", Label).update(f"Picco: {dl_pk:.1f} Mbps | Stabilità: {dl_st:.1f}%" if dl_pk is not None else "-")
        self.query_one("#perf-ul-mbps", Label).update(f"{ul_m:.1f} Mbps" if ul_m is not None else "N/D")
        ul_pk = speed.get("upload_peak_mbps")
        ul_st = speed.get("upload_stability_pct")
        self.query_one("#perf-ul-peak", Label).update(f"Picco: {ul_pk:.1f} Mbps | Stabilità: {ul_st:.1f}%" if ul_pk is not None else "-")
        b_tx = speed.get("bytes_transferred")
        t_dur = speed.get("test_duration_s")
        self.query_one("#perf-data-transferred", Label).update(f"{b_tx / (1024*1024):.1f} MB in {t_dur:.1f} s" if b_tx and t_dur else "-")
        srvs = speed.get("servers_used") or []
        self.query_one("#perf-servers", Label).update(", ".join(srvs) if srvs else "Cloudflare Anycast")
        ceil = speed.get("tool_ceiling_mbps")
        self.query_one("#perf-ceiling", Label).update(f"{ceil:.1f} Mbps" if ceil else "-")
        ta = speed.get("traffic_accounting") or {}
        if ta:
            self.query_one("#perf-accounting", Label).update(f"Interfaccia: {ta.get('interface_bytes', 0)/(1024*1024):.1f} MB | Altri processi: {ta.get('other_traffic_bytes', 0)/(1024*1024):.1f} MB")
        else:
            self.query_one("#perf-accounting", Label).update("-")


class MediumView(VerticalScroll):
    """Scheda 5: Stima Mezzo Fisico, Modello Bayesiano, Hop 2 BNG e Access Profile."""
    data = reactive(None)

    def compose(self) -> ComposeResult:
        with Container(classes="card"):
            yield Label("▶  CLASSIFICAZIONE FISICA DELL'ULTIMO MIGLIO", classes="card-title-emerald")
            yield _make_kv("Mezzo Fisico Previsto", val_id="med-predicted", val_class="kv-val-green")
            yield _make_kv("Indice di Confidenza Modello", val_id="med-conf")
            yield _make_kv("Ripartizione Punteggi Tecnologie", val_id="med-scores")
            yield Label("Evidenze e Contributi di Punteggio:", classes="sub-title")
            yield Label("-", id="med-rationale", classes="rationale-bullet")

        with Container(classes="card"):
            yield Label("▶  PARAMETRI DI ACCESSO HOP 2 (BNG / FIRST HOP PROVIDER)", classes="card-title")
            yield _make_kv("Indirizzo Gateway Operatore (BNG)", val_id="med-bng-ip")
            yield _make_kv("Latenza Minima di Tratta (Min RTT)", val_id="med-bng-min")
            yield _make_kv("Mediana / Coda p95 Salto", val_id="med-bng-med")
            yield _make_kv("Jitter IPDV / Tail Variance", val_id="med-bng-jit")

        with Container(classes="card"):
            yield Label("▶  PROFILO LATENZA SALTO PER SALTO (ACCESS PROFILE)", classes="card-title")
            table = DataTable(id="table-hops")
            table.zebra_stripes = True
            yield table

        with Container(classes="card"):
            yield Label("▶  BANDWIDTH-DELAY PRODUCT (BDP) & QUALITÀ VOCALE ITU-T", classes="card-title")
            yield _make_kv("Bandwidth-Delay Product (BDP)", val_id="med-bdp-bytes")
            yield _make_kv("Finestra TCP Consigliata", val_id="med-tcp-win")
            yield _make_kv("Capacità Canale in Transito", val_id="med-bdp-desc")
            yield _make_kv("Score Vocale ITU-T G.107 (MOS)", val_id="med-mos")
            yield _make_kv("Fattore di Trasmissione (R-Factor)", val_id="med-rfac")

    def on_mount(self):
        tbl = self.query_one("#table-hops", DataTable)
        tbl.add_columns("Salto", "Indirizzo IP", "Min RTT (ms)", "Mediana (ms)", "Delta Floor", "Ruolo Canonico", "Ruolo Fisico / Note")
        self._update_display(self.data)

    def watch_data(self, new_data):
        if self.is_mounted:
            self._update_display(new_data)

    def _update_display(self, data):
        if not data:
            return
        est = data.get("estimations") or {}
        phys = est.get("physical_medium") or {}
        self.query_one("#med-predicted", Label).update(str(phys.get("predicted_medium", "Indeterminato")))
        conf = phys.get("confidence_pct", 0.0)
        unattr = phys.get("unattributed_pct", 0.0)
        self.query_one("#med-conf", Label).update(f"{conf:.1f}% (Quota Non Attribuita: {unattr:.1f}%)")

        scores = phys.get("scores_breakdown") or {}
        sc_parts = []
        for k, v in scores.items():
            short_k = k.split("(")[0].strip()
            sc_parts.append(f"{short_k}: {v:.0f}")
        self.query_one("#med-scores", Label).update(" | ".join(sc_parts) if sc_parts else "-")

        rat = phys.get("rationale") or []
        self.query_one("#med-rationale", Label).update("\n".join(f"• {r}" for r in rat) if rat else "Nessuna evidenza registrata")

        ixp = data.get("ixp") or {}
        bng = ixp.get("hop2_bng") or {}
        self.query_one("#med-bng-ip", Label).update(str(bng.get("ip") or "Nessun hop BNG responsivo"))
        min_ms = bng.get("min_ms")
        self.query_one("#med-bng-min", Label).update(f"{min_ms:.2f} ms" if min_ms is not None else "-")
        med_ms = bng.get("median_ms")
        p95_ms = bng.get("p95_ms")
        self.query_one("#med-bng-med", Label).update(f"Mediana: {med_ms:.2f} ms | p95: {p95_ms:.2f} ms" if med_ms is not None and p95_ms is not None else "-")
        jit_ms = bng.get("jitter_ms")
        tail_ms = bng.get("tail_variance_ms")
        self.query_one("#med-bng-jit", Label).update(f"Jitter: {jit_ms:.2f} ms | Tail: {tail_ms:.2f} ms" if jit_ms is not None and tail_ms is not None else "-")

        # Table Access Profile
        tbl = self.query_one("#table-hops", DataTable)
        tbl.clear()
        acc = ixp.get("access_profile") or {}
        hops = acc.get("hops") or ixp.get("traceroute_hops") or []
        for h in hops:
            h_num = str(h.get("hop", "-"))
            ip_str = str(h.get("ip") or "*")
            min_r = f"{h.get('min_ms', '-'):.2f}" if isinstance(h.get('min_ms'), (int, float)) else ("N/D" if ip_str == "*" else f"{h.get('rtt_ms'):.2f}" if h.get("rtt_ms") else "N/D")
            med_r = f"{h.get('median_ms', '-'):.2f}" if isinstance(h.get('median_ms'), (int, float)) else "N/D"
            df = h.get("floor_increment_ms")
            df_str = f"+{df:.2f} ms" if isinstance(df, (int, float)) and df > 0 else ("~0.00 ms" if isinstance(df, (int, float)) else "N/D")
            tbl.add_row(
                h_num,
                ip_str,
                min_r,
                med_r,
                df_str,
                str(h.get("role") or "-"),
                str(h.get("role_note") or "-")
            )

        bdp = est.get("bandwidth_delay_product") or {}
        b_bytes = bdp.get("bdp_bytes")
        b_mb = bdp.get("bdp_mb")
        self.query_one("#med-bdp-bytes", Label).update(f"{b_bytes} bytes ({b_mb} MB)" if b_bytes else "N/D (misura non valida)")
        self.query_one("#med-tcp-win", Label).update(f"{bdp.get('recommended_tcp_window_kb')} KB" if bdp.get("recommended_tcp_window_kb") else "N/D")
        self.query_one("#med-bdp-desc", Label).update(str(bdp.get("pipe_capacity_description") or "-"))

        voice = est.get("voice_quality_mos") or {}
        self.query_one("#med-mos", Label).update(f"{voice.get('mos_score', 'N/D')} / 4.5 ({voice.get('quality_rating', 'N/D')})")
        self.query_one("#med-rfac", Label).update(f"{voice.get('r_factor', 'N/D')} / 100")


class IxpView(VerticalScroll):
    """Scheda 6: Intelligence IXP, Routing Ottico e Strutture PeeringDB."""
    data = reactive(None)

    def compose(self) -> ComposeResult:
        with Container(classes="card"):
            yield Label("▶  INTELLIGENCE PEERING IXP & AS-BOUNDARY", classes="card-title")
            yield _make_kv("Internet eXchange / Hub Peering", val_id="ixp-detected", val_class="kv-val-cyan")
            yield _make_kv("Struttura / Campus IXP", val_id="ixp-facility")
            yield _make_kv("Città IXP", val_id="ixp-city")
            yield _make_kv("Tipologia Interconnessione", val_id="ixp-type")
            yield _make_kv("Metodo di Identificazione", val_id="ixp-method")
            yield _make_kv("PoP Anycast Rilevato (Cloudflare)", val_id="ixp-colo")
            yield _make_kv("Interfaccia Peering / Egress (Hop IP)", val_id="ixp-egress")

        with Container(classes="card"):
            yield Label("▶  EFFICIENZA DI ROUTING OTTICO & FIBRA", classes="card-title")
            yield _make_kv("Distanza Geodetica Ortodromica", val_id="ixp-dist")
            yield _make_kv("Tratta Fibra Ottica Stimata", val_id="ixp-fiber")
            yield _make_kv("Latenza Luce in Fibra (Minimo Fisico)", val_id="ixp-light")
            yield _make_kv("RTT Tratta Misurato", val_id="ixp-rtt-meas")
            yield _make_kv("Indice di Efficienza di Routing", val_id="ixp-eff", val_class="kv-val-green")
            yield _make_kv("Valutazione Detour di Peering", val_id="ixp-detour")
            yield _make_kv("Base di Calcolo Efficienza", val_id="ixp-calc-basis")
            yield _make_kv("Ritardo di Accodamento & Switch", val_id="ixp-delay")

        with Container(classes="card"):
            yield Label("▶  STRUTTURE DI PEERING OPERATORE (PEERINGDB)", classes="card-title")
            table = DataTable(id="table-peeringdb")
            table.zebra_stripes = True
            yield table

    def on_mount(self):
        tbl = self.query_one("#table-peeringdb", DataTable)
        tbl.add_columns("Struttura / Hub Peering", "Città", "Paese")
        self._update_display(self.data)

    def watch_data(self, new_data):
        if self.is_mounted:
            self._update_display(new_data)

    def _update_display(self, data):
        if not data:
            return
        ixp = data.get("ixp") or {}
        self.query_one("#ixp-detected", Label).update(str(ixp.get("detected_ixp") or "Non identificato"))
        self.query_one("#ixp-facility", Label).update(str(ixp.get("ixp_facility") or "-"))
        self.query_one("#ixp-city", Label).update(str(ixp.get("ixp_city") or "-"))
        self.query_one("#ixp-type", Label).update(str(ixp.get("peering_type") or "-"))
        self.query_one("#ixp-method", Label).update(f"{ixp.get('detection_method', '-')} (Confidenza: {ixp.get('confidence', '-')})")
        self.query_one("#ixp-colo", Label).update(str(ixp.get("anycast_colo") or "-"))
        self.query_one("#ixp-egress", Label).update(str(ixp.get("matched_hop_ip") or "-"))

        est = data.get("estimations") or {}
        opt = est.get("optical_routing") or {}
        d_km = opt.get("straight_line_distance_km")
        self.query_one("#ixp-dist", Label).update(f"~{d_km:.1f} km" if d_km is not None else "-")
        f_km = opt.get("estimated_fiber_path_km")
        self.query_one("#ixp-fiber", Label).update(f"~{f_km:.1f} km (con detour 1.35x)" if f_km is not None else "-")
        l_ms = opt.get("theoretical_optical_min_rtt_ms")
        self.query_one("#ixp-light", Label).update(f"{l_ms:.2f} ms" if l_ms is not None else "-")
        m_ms = opt.get("measured_rtt_ms")
        self.query_one("#ixp-rtt-meas", Label).update(f"{m_ms:.2f} ms" if m_ms is not None else "-")
        eff = opt.get("routing_efficiency_pct")
        self.query_one("#ixp-eff", Label).update(f"{eff:.1f}%" if eff is not None else "Non applicabile")
        self.query_one("#ixp-detour", Label).update(str(opt.get("detour_rating") or "-"))
        self.query_one("#ixp-calc-basis", Label).update(str(opt.get("calculation_basis") or "-"))
        delay = opt.get("switching_and_queuing_delay_ms")
        self.query_one("#ixp-delay", Label).update(f"{delay:.2f} ms" if delay is not None else "-")

        tbl = self.query_one("#table-peeringdb", DataTable)
        tbl.clear()
        facs = ixp.get("peeringdb_facilities") or []
        if not facs:
            wan_asn = str((data.get("wan") or {}).get("asn") or "")
            clean_asn = "".join(c for c in wan_asn if c.isdigit())
            from core.ixp_analyzer import EMBEDDED_ASN_PEERING_HUBS
            if clean_asn and int(clean_asn) in EMBEDDED_ASN_PEERING_HUBS:
                facs = EMBEDDED_ASN_PEERING_HUBS[int(clean_asn)]

        if facs:
            for fac in facs:
                tbl.add_row(
                    str(fac.get("name") or "-"),
                    str(fac.get("city") or "-"),
                    str(fac.get("country") or "Italia")
                )
        else:
            tbl.add_row("Nessuna struttura PeeringDB", "-", "-")


class DevicesView(VerticalScroll):
    """Scheda 7: Dispositivi rilevati nella LAN (ARP, mDNS, UPnP, DHCP)."""
    data = reactive(None)

    def compose(self) -> ComposeResult:
        with Container(classes="card"):
            yield Label("▶  QUESTO DISPOSITIVO (HOST LOCALE)", classes="card-title")
            yield _make_kv("Indirizzo IPv4 Locale", val_id="dev-this-ip")
            yield _make_kv("Indirizzo MAC", val_id="dev-this-mac")
            yield _make_kv("Produttore Hardware (OUI)", val_id="dev-this-vendor")
            yield _make_kv("Nome Host Locale", val_id="dev-this-host")

        with Container(classes="card"):
            yield Label("▶  DISPOSITIVI RILEVATI NELLA RETE LAN", classes="card-title")
            yield Label("-", id="dev-total-label", classes="hero-subtitle")
            table = DataTable(id="table-devices")
            table.zebra_stripes = True
            yield table

    def on_mount(self):
        tbl = self.query_one("#table-devices", DataTable)
        tbl.add_columns("Indirizzo IP", "MAC Address", "Produttore Hardware (OUI)", "Nome Host / mDNS", "Fonti Discovery", "Indirizzi IPv6")
        self._update_display(self.data)

    def watch_data(self, new_data):
        if self.is_mounted:
            self._update_display(new_data)

    def _update_display(self, data):
        if not data:
            return
        lan = data.get("lan") or {}
        td = lan.get("this_device") or {}
        self.query_one("#dev-this-ip", Label).update(str(td.get("ip") or "-"))
        self.query_one("#dev-this-mac", Label).update(str(td.get("mac") or "-"))
        self.query_one("#dev-this-vendor", Label).update(str(td.get("vendor") or "-"))
        self.query_one("#dev-this-host", Label).update(str(td.get("hostname") or "-"))

        devs = lan.get("lan_devices") or []
        self.query_one("#dev-total-label", Label).update(f"Totale Dispositivi Rilevati nella LAN: {len(devs)} host attivi")
        tbl = self.query_one("#table-devices", DataTable)
        tbl.clear()
        for d in devs:
            ipv6_str = ", ".join(d.get("ipv6_addresses") or []) if d.get("ipv6_addresses") else "-"
            tbl.add_row(
                str(d.get("ip") or "-"),
                str(d.get("mac") or "-"),
                str(d.get("vendor") or "N/D"),
                str(d.get("hostname") or "-"),
                str(d.get("how_found") or "-"),
                ipv6_str
            )

