"""
Modulo di validazione dei dati grezzi e delle misure di rete di NetProbe.
Garantisce che nessun valore inventato, placeholder o fisicamente inconsistente
venga propagato nell'interfaccia utente o nei modelli.
Le violazioni vengono registrate in `data_quality.issues` e i campi invalidati
vengono impostati su None / 'N/D'.
"""

import ipaddress
import re
from typing import Dict, List, Any, Optional, Tuple

from core.oui_data import is_placeholder_mac


def compute_network_and_broadcast(ip_str: str, netmask_str: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Calcola subnet network, broadcast e prefix length da IP e netmask."""
    try:
        # Se netmask ha formato "255.255.255.0 (/24)"
        clean_mask = netmask_str.split()[0].strip() if netmask_str else ""
        if "/" in clean_mask:
            clean_mask = clean_mask.replace("/", "")
            prefix = int(clean_mask)
            net = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
        else:
            net = ipaddress.IPv4Network(f"{ip_str}/{clean_mask}", strict=False)
        return str(net.network_address), str(net.broadcast_address), net.prefixlen
    except Exception:
        return None, None, None


def validate_ip_within_subnet(ip_str: Optional[str], netmask_str: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Verifica che l'IP locale appartenga alla sottorete indicata."""
    if not ip_str or not netmask_str:
        return False, "IP o netmask mancante"
    try:
        net_addr, bcast_addr, prefix = compute_network_and_broadcast(ip_str, netmask_str)
        if net_addr is None:
            return False, "Netmask non valida o non analizzabile"
        ip_obj = ipaddress.IPv4Address(ip_str)
        net_obj = ipaddress.IPv4Network(f"{net_addr}/{prefix}", strict=False)
        if ip_obj in net_obj:
            return True, None
        return False, f"IP {ip_str} fuori dalla subnet {net_obj}"
    except Exception as e:
        return False, str(e)


def validate_gateway_within_subnet(gw_ip: Optional[str], local_ip: Optional[str], netmask_str: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Verifica che il default gateway si trovi nella stessa sottorete dell'IP locale."""
    if not gw_ip:
        return False, "Gateway IP non specificato"
    if not local_ip or not netmask_str:
        return True, None  # Non verificabile senza interfaccia locale
    try:
        net_addr, _, prefix = compute_network_and_broadcast(local_ip, netmask_str)
        if net_addr is None:
            return False, "Netmask non valida"
        gw_obj = ipaddress.IPv4Address(gw_ip)
        net_obj = ipaddress.IPv4Network(f"{net_addr}/{prefix}", strict=False)
        if gw_obj in net_obj:
            return True, None
        return False, f"Gateway {gw_ip} non appartiene alla subnet locale {net_obj}"
    except Exception as e:
        return False, str(e)


def validate_broadcast(ip_str: Optional[str], netmask_str: Optional[str], bcast_str: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Verifica che l'indirizzo di broadcast coincida con quello matematicamente calcolato."""
    if not bcast_str or not ip_str or not netmask_str:
        return True, None
    _, expected_bcast, _ = compute_network_and_broadcast(ip_str, netmask_str)
    if expected_bcast and bcast_str != expected_bcast:
        return False, f"Broadcast misurato ({bcast_str}) discordante da quello calcolato ({expected_bcast})"
    return True, None


def validate_mtu(mtu: Optional[int]) -> Tuple[bool, Optional[str]]:
    """Verifica che l'MTU sia compreso tra 576 (minimo IPv4 RFC 791) e 9216 (Jumbo frame)."""
    if mtu is None:
        return True, None
    if not (576 <= mtu <= 9216):
        return False, f"MTU {mtu} fuori dal range valido [576, 9216]"
    return True, None


def validate_mac_not_placeholder(mac: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Verifica che l'indirizzo MAC non sia un placeholder fittizio."""
    if not mac:
        return False, "Indirizzo MAC mancante"
    if is_placeholder_mac(mac):
        return False, f"Indirizzo MAC {mac} è un placeholder non valido"
    return True, None


def validate_wifi_rf(rssi: Optional[int], noise: Optional[int], snr: Optional[int]) -> Tuple[bool, Optional[str]]:
    """Verifica coerenza delle metriche radio Wi-Fi (RSSI [-100, 0], SNR = RSSI - Noise ±1 dB)."""
    if rssi is not None:
        if not (-100 <= rssi <= 0):
            return False, f"RSSI {rssi} dBm fuori dal range fisico [-100, 0]"
    if noise is not None:
        if not (-120 <= noise <= -30):
            return False, f"Noise {noise} dBm fuori dal range fisico plausibile [-120, -30]"
    if rssi is not None and noise is not None and snr is not None:
        expected_snr = rssi - noise
        if abs(snr - expected_snr) > 1:
            return False, f"SNR misurato ({snr} dB) incoerente con RSSI - Noise ({expected_snr} dB)"
    return True, None


def validate_latency_triplet(min_ms: Optional[float], median_ms: Optional[float], max_ms: Optional[float]) -> Tuple[bool, Optional[str]]:
    """Verifica che min <= median <= max (con tolleranza per floating point)."""
    if min_ms is None or median_ms is None or max_ms is None:
        return True, None
    if not (min_ms <= median_ms + 1e-4 <= max_ms + 2e-4):
        return False, f"Incoerenza temporale: min ({min_ms}ms) <= median ({median_ms}ms) <= max ({max_ms}ms) non rispettata"
    return True, None


def validate_jitter(jitter_ms: Optional[float]) -> Tuple[bool, Optional[str]]:
    """Verifica che il jitter inter-pacchetto sia non negativo."""
    if jitter_ms is None:
        return True, None
    if jitter_ms < 0:
        return False, f"Jitter negativo non valido ({jitter_ms} ms)"
    return True, None


def validate_packet_loss(loss_pct: Optional[float]) -> Tuple[bool, Optional[str]]:
    """Verifica che la perdita pacchetti sia compresa tra 0% e 100%."""
    if loss_pct is None:
        return True, None
    if not (0.0 <= loss_pct <= 100.0):
        return False, f"Perdita pacchetti {loss_pct}% fuori dal range [0, 100]"
    return True, None


def validate_throughput(sustained_mbps: Optional[float], peak_mbps: Optional[float]) -> Tuple[bool, Optional[str]]:
    """Verifica che il throughput medio sostenuto non superi il picco istantaneo."""
    if sustained_mbps is None or peak_mbps is None:
        return True, None
    if sustained_mbps > peak_mbps + 0.1:
        return False, f"Throughput sostenuto ({sustained_mbps} Mbps) superiore al picco ({peak_mbps} Mbps)"
    return True, None


def validate_public_ip(public_ip: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Verifica che l'IP pubblico non sia un indirizzo privato, di loopback o riservato."""
    if not public_ip:
        return True, None
    try:
        obj = ipaddress.ip_address(public_ip)
        if obj.is_private:
            return False, f"IP pubblico indicato ({public_ip}) è in realtà un IP privato RFC 1918"
        if obj.is_loopback:
            return False, f"IP pubblico ({public_ip}) è un indirizzo di loopback"
        if obj.is_link_local:
            return False, f"IP pubblico ({public_ip}) è un indirizzo link-local"
        if obj.is_reserved:
            return False, f"IP pubblico ({public_ip}) è un indirizzo IETF riservato"
        return True, None
    except Exception as e:
        return False, f"Formato IP pubblico non valido: {e}"


def validate_asn_consistency(asn: Optional[str], isp: Optional[str], org: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Verifica che il prefisso ASN sia ben formato e coerente con la stringa ISP."""
    if not asn:
        return True, None
    m = re.match(r"^AS(\d+)$", asn.strip().upper())
    if not m:
        return False, f"Formato ASN non valido ({asn}): atteso 'AS<numero>'"
    return True, None


def validate_scan_results(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Esegue tutte le verifiche di validità su un dizionario di scansione completo.
    Registra eventuali violazioni in data['data_quality']['issues'] e
    sostituisce i campi invalidati con None / 'N/D'.
    """
    issues: List[Dict[str, Any]] = []

    lan = data.get("lan", {})
    wan = data.get("wan", {})
    perf = data.get("performance", {})
    p_iface = lan.get("primary_interface") or {}

    # 1. Validazione IP, Subnet e Broadcast
    local_ip = p_iface.get("ipv4")
    netmask = p_iface.get("netmask")
    bcast = p_iface.get("broadcast")

    if local_ip and netmask:
        ok, reason = validate_ip_within_subnet(local_ip, netmask)
        if not ok:
            issues.append({"field": "lan.primary_interface.ipv4", "issue": reason, "raw_value": local_ip})

        ok_bcast, reason_bcast = validate_broadcast(local_ip, netmask, bcast)
        if not ok_bcast:
            issues.append({"field": "lan.primary_interface.broadcast", "issue": reason_bcast, "raw_value": bcast})
            p_iface["broadcast"] = None

    # 2. Gateway in subnet
    gw = lan.get("gateway", {})
    gw_ip = gw.get("ipv4")
    if gw_ip and local_ip and netmask:
        ok_gw, reason_gw = validate_gateway_within_subnet(gw_ip, local_ip, netmask)
        if not ok_gw:
            issues.append({"field": "lan.gateway.ipv4", "issue": reason_gw, "raw_value": gw_ip})

    # 3. MTU
    mtu = p_iface.get("mtu")
    ok_mtu, reason_mtu = validate_mtu(mtu)
    if not ok_mtu:
        issues.append({"field": "lan.primary_interface.mtu", "issue": reason_mtu, "raw_value": mtu})
        p_iface["mtu"] = None

    # 4. MAC non placeholder
    iface_mac = p_iface.get("mac")
    if iface_mac and is_placeholder_mac(iface_mac):
        issues.append({"field": "lan.primary_interface.mac", "issue": f"MAC placeholder rilevato: {iface_mac}", "raw_value": iface_mac})
        p_iface["mac"] = None
        p_iface["vendor"] = "Indirizzo non disponibile"

    gw_mac = gw.get("mac")
    if gw_mac and is_placeholder_mac(gw_mac):
        issues.append({"field": "lan.gateway.mac", "issue": f"Gateway MAC placeholder: {gw_mac}", "raw_value": gw_mac})
        gw["mac"] = None
        gw["vendor"] = "Sconosciuto"

    # 5. Wi-Fi RF
    wifi = lan.get("wifi", {})
    ok_rf, reason_rf = validate_wifi_rf(wifi.get("rssi_dbm"), wifi.get("noise_dbm"), wifi.get("snr_db"))
    if not ok_rf:
        issues.append({"field": "lan.wifi.rf", "issue": reason_rf, "raw_value": {"rssi": wifi.get("rssi_dbm"), "noise": wifi.get("noise_dbm"), "snr": wifi.get("snr_db")}})

    # 6. Latenza, jitter, packet loss
    targets = perf.get("latency_targets", {})
    for t_name, t_data in targets.items():
        ok_triplet, reason_triplet = validate_latency_triplet(t_data.get("min_ms"), t_data.get("median_ms"), t_data.get("max_ms"))
        if not ok_triplet:
            issues.append({"field": f"performance.latency_targets.{t_name}.triplet", "issue": reason_triplet, "raw_value": [t_data.get("min_ms"), t_data.get("median_ms"), t_data.get("max_ms")]})

        ok_jit, reason_jit = validate_jitter(t_data.get("jitter_ms"))
        if not ok_jit:
            issues.append({"field": f"performance.latency_targets.{t_name}.jitter", "issue": reason_jit, "raw_value": t_data.get("jitter_ms")})
            t_data["jitter_ms"] = None

        ok_loss, reason_loss = validate_packet_loss(t_data.get("packet_loss_pct"))
        if not ok_loss:
            issues.append({"field": f"performance.latency_targets.{t_name}.loss", "issue": reason_loss, "raw_value": t_data.get("packet_loss_pct")})
            t_data["packet_loss_pct"] = None

    # 7. Throughput sostenuto <= picco
    speed = perf.get("speed", {})
    ok_dl, reason_dl = validate_throughput(speed.get("download_mbps"), speed.get("download_peak_mbps"))
    if not ok_dl:
        issues.append({"field": "performance.speed.download", "issue": reason_dl, "raw_value": [speed.get("download_mbps"), speed.get("download_peak_mbps")]})

    ok_ul, reason_ul = validate_throughput(speed.get("upload_mbps"), speed.get("upload_peak_mbps"))
    if not ok_ul:
        issues.append({"field": "performance.speed.upload", "issue": reason_ul, "raw_value": [speed.get("upload_mbps"), speed.get("upload_peak_mbps")]})

    # 8. IP pubblico non privato
    pub_v4 = wan.get("public_ipv4")
    ok_pub, reason_pub = validate_public_ip(pub_v4)
    if not ok_pub:
        issues.append({"field": "wan.public_ipv4", "issue": reason_pub, "raw_value": pub_v4})

    # 9. ASN consistency
    asn = wan.get("asn")
    ok_asn, reason_asn = validate_asn_consistency(asn, wan.get("isp"), wan.get("org"))
    if not ok_asn:
        issues.append({"field": "wan.asn", "issue": reason_asn, "raw_value": asn})

    # 10. DNS servers presenti tra i live hosts (se presenti nella subnet)
    dns_servers = (lan.get("dns", {}) or {}).get("resolvers", [])
    lan_devices = lan.get("lan_devices", []) or lan.get("arp_table", [])
    live_ips = {d.get("ip") for d in lan_devices if d.get("ip")}
    if local_ip and netmask:
        net_addr, _, prefix = compute_network_and_broadcast(local_ip, netmask)
        if net_addr:
            local_net = ipaddress.IPv4Network(f"{net_addr}/{prefix}", strict=False)
            for ds in dns_servers:
                try:
                    if ipaddress.IPv4Address(ds) in local_net and ds != local_ip:
                        if ds not in live_ips and len(lan_devices) > 0:
                            issues.append({
                                "field": "lan.dns.resolvers",
                                "issue": f"Il server DNS configurato {ds} appartiene alla subnet locale ma non è stato rilevato tra gli host attivi",
                                "raw_value": ds
                            })
                except Exception:
                    pass

    data["data_quality"] = {
        "valid": len(issues) == 0,
        "issues_count": len(issues),
        "issues": issues
    }

    return data
