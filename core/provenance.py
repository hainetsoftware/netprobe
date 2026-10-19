"""
Modulo per tracciare la provenienza e l'affidabilità di ogni dato (Field Provenance):
Mappa ogni campo in `field_status` con:
- `source`: "os:ifconfig", "os:networksetup", "os:route", "api:ipify", "probe:stun", "inferred", ecc.
- `status`: "measured", "parsed", "inferred", "unavailable", "conflict"
"""

from typing import Dict, Any, Optional


def build_field_provenance(report: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """
    Costruisce la mappa `field_status` per tutti i principali campi diagnostici di NetProbe.
    Ogni chiave corrisponde a un path reale e risolvibile nel report.
    Lo status è "unavailable" se e solo se il valore è nullo, assente o non disponibile.
    """
    prov: Dict[str, Dict[str, str]] = {}

    lan = report.get("lan", {})
    wan = report.get("wan", {})
    perf = report.get("performance", {})
    ixp = report.get("ixp", {})
    est = report.get("estimations", {})

    p_iface = lan.get("primary_interface") or {}
    gw = lan.get("gateway") or {}
    wifi = lan.get("wifi") or {}
    dhcp = lan.get("dhcp") or {}
    dns = lan.get("dns") or {}
    dns_bm = lan.get("dns_benchmark") or {}

    # --- LAN Primary Interface ---
    v = p_iface.get("name")
    prov["lan.primary_interface.name"] = {"source": "os:adapter", "status": "parsed" if v else "unavailable"}

    v = p_iface.get("ipv4")
    prov["lan.primary_interface.ipv4"] = {"source": "os:ifconfig", "status": "measured" if v else "unavailable"}

    v = p_iface.get("mac")
    prov["lan.primary_interface.mac"] = {"source": "os:networksetup", "status": "parsed" if (v and v != "N/D") else "unavailable"}

    v = p_iface.get("vendor")
    prov["lan.primary_interface.vendor"] = {"source": "oui:ieee", "status": "parsed" if (v and v != "N/D" and v != "Sconosciuto") else "unavailable"}

    v = p_iface.get("mtu")
    prov["lan.primary_interface.mtu"] = {"source": "os:ifconfig", "status": "parsed" if v else "unavailable"}

    v = p_iface.get("type")
    prov["lan.primary_interface.type"] = {"source": "os:adapter", "status": "parsed" if v else "unavailable"}

    # --- Gateway ---
    v = gw.get("ipv4")
    prov["lan.gateway.ipv4"] = {"source": "os:route", "status": "parsed" if v else "unavailable"}

    v = gw.get("mac")
    gw_source = gw.get("mac_source") or "system_profiler"
    prov["lan.gateway.mac"] = {"source": f"os:{gw_source}", "status": "parsed" if (v and v != "N/D") else "unavailable"}

    v = gw.get("vendor")
    prov["lan.gateway.vendor"] = {"source": "oui:ieee", "status": "parsed" if (v and v != "N/D" and v != "Sconosciuto") else "unavailable"}

    # --- Wi-Fi (status "unavailable" se Wi-Fi non connesso o inattivo) ---
    wifi_connected = bool(wifi.get("connected"))

    v = wifi.get("ssid") if wifi_connected else None
    prov["lan.wifi.ssid"] = {"source": "os:corewlan", "status": "parsed" if v else "unavailable"}

    v = wifi.get("bssid") if wifi_connected else None
    prov["lan.wifi.bssid"] = {"source": "os:corewlan", "status": "parsed" if v else "unavailable"}

    v = wifi.get("rssi_dbm") if wifi_connected else None
    prov["lan.wifi.rssi_dbm"] = {"source": "os:corewlan", "status": "measured" if v is not None else "unavailable"}

    v = wifi.get("noise_dbm") if wifi_connected else None
    prov["lan.wifi.noise_dbm"] = {"source": "os:corewlan", "status": "measured" if v is not None else "unavailable"}

    v = wifi.get("snr_db") if wifi_connected else None
    prov["lan.wifi.snr_db"] = {"source": "inferred:rf_delta", "status": "inferred" if v is not None else "unavailable"}

    v = wifi.get("channel") if wifi_connected else None
    prov["lan.wifi.channel"] = {"source": "os:corewlan", "status": "parsed" if v else "unavailable"}

    v = wifi.get("frequency_ghz") if wifi_connected else None
    prov["lan.wifi.frequency_ghz"] = {"source": "os:corewlan", "status": "parsed" if v else "unavailable"}

    v = wifi.get("wifi_generation") if wifi_connected else None
    prov["lan.wifi.wifi_generation"] = {"source": "inferred:phy_channel", "status": "inferred" if v else "unavailable"}

    # --- DHCP & DNS ---
    v = dhcp.get("server_ip")
    prov["lan.dhcp.server_ip"] = {"source": "os:ipconfig_getpacket", "status": "parsed" if v else "unavailable"}

    v = dns.get("resolvers")
    prov["lan.dns.resolvers"] = {"source": "os:scutil", "status": "parsed" if v else "unavailable"}

    v = dns_bm.get("dnssec_validation_active")
    prov["lan.dns_benchmark.dnssec_validation_active"] = {"source": "probe:dnspython", "status": "measured" if v is not None else "unavailable"}

    # --- WAN ---
    v = wan.get("public_ipv4")
    prov["wan.public_ipv4"] = {"source": "api:ipify", "status": "measured" if v else "unavailable"}

    v = wan.get("asn")
    prov["wan.asn"] = {"source": "api:ip-api", "status": "parsed" if v else "unavailable"}

    v = wan.get("isp")
    prov["wan.isp"] = {"source": "api:ip-api", "status": "parsed" if v else "unavailable"}

    v = wan.get("reverse_dns")
    prov["wan.reverse_dns"] = {"source": "probe:dns_ptr", "status": "parsed" if v else "unavailable"}

    nat = wan.get("nat") or {}
    v = nat.get("nat_type")
    prov["wan.nat.nat_type"] = {"source": "probe:stun", "status": "measured" if v else "unavailable"}

    services = wan.get("router_services") or {}
    v_upnp = services.get("upnp_igd_available")
    prov["wan.router_services.upnp_igd_available"] = {"source": "probe:ssdp_upnp", "status": "measured" if v_upnp is not None else "unavailable"}
    v_pmp = services.get("nat_pmp_available")
    prov["wan.router_services.nat_pmp_available"] = {"source": "probe:nat_pmp", "status": "measured" if v_pmp is not None else "unavailable"}

    # --- Performance ---
    prim_lat = perf.get("primary_latency") or {}
    v = prim_lat.get("median_ms")
    prov["performance.primary_latency.median_ms"] = {"source": "probe:icmp_ping", "status": "measured" if v is not None else "unavailable"}

    v = prim_lat.get("jitter_ms")
    prov["performance.primary_latency.jitter_ms"] = {"source": "inferred:rfc3550", "status": "inferred" if v is not None else "unavailable"}

    speed = perf.get("speed") or {}
    v = speed.get("download_mbps")
    prov["performance.speed.download_mbps"] = {"source": "probe:http_stream", "status": "measured" if v is not None else "unavailable"}

    v = speed.get("upload_mbps")
    prov["performance.speed.upload_mbps"] = {"source": "probe:http_stream", "status": "measured" if v is not None else "unavailable"}

    v = speed.get("tool_ceiling_mbps")
    prov["performance.speed.tool_ceiling_mbps"] = {"source": "probe:loopback_http", "status": "measured" if v is not None else "unavailable"}

    # --- IXP ---
    matched = ixp.get("matched_hop_ip")
    det_ixp = ixp.get("detected_ixp")
    is_ixp_found = bool(det_ixp and "non identificato" not in det_ixp.lower())
    prov["ixp.detected_ixp"] = {
        "source": "probe:traceroute" if matched else "inferred:peeringdb",
        "status": "measured" if matched else ("inferred" if is_ixp_found else "unavailable")
    }

    # --- Estimations ---
    med = est.get("physical_medium") or {}
    prov["estimations.physical_medium.predicted_medium"] = {"source": "inferred:classifier", "status": "inferred" if med.get("predicted_medium") else "unavailable"}

    opt = est.get("optical_routing") or {}
    v = opt.get("routing_efficiency_pct")
    prov["estimations.optical_routing.routing_efficiency_pct"] = {"source": "inferred:physics_model", "status": "inferred" if v is not None else "unavailable"}

    mos = est.get("voice_quality_mos") or {}
    v = mos.get("mos_score")
    prov["estimations.voice_quality_mos.mos_score"] = {"source": "inferred:itu_t_g107", "status": "inferred" if v is not None else "unavailable"}

    bdp = est.get("bandwidth_delay_product") or {}
    v = bdp.get("bdp_bytes")
    prov["estimations.bandwidth_delay_product.bdp_bytes"] = {"source": "inferred:bdp_formula", "status": "inferred" if v is not None else "unavailable"}

    return prov
