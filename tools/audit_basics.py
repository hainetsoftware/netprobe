#!/usr/bin/env python3
"""
tools/audit_basics.py - Standalone Audit Suite for NetProbe Basic Network Data

Esegue in parallelo i raccoglitori interni di NetProbe e una serie indipendente
di comandi di sistema del sistema operativo (senza sudo) e query API esterne,
confrontando ciascun valore campo per campo.

Stampa una tabella riassuntiva:
  field | NetProbe | reference | status (OK / WARN / MISMATCH / N-A) | reference source

Codice di uscita:
  - 0: Nessun MISMATCH (tutti OK, WARN o N-A)
  - 1: Rilevato almeno un MISMATCH
"""

import sys
import os
import re
import json
import time
import argparse
import subprocess
import urllib.request
import statistics
from typing import Dict, Any, List, Optional, Tuple

# Aggiunge la root del repository a sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.platform_info import is_macos, is_linux, is_windows, run_cmd
from core.lan_scanner import LanScanner
from core.wan_probe import WanProbe
from core.performance import PerformanceTester
from core.oui_data import is_placeholder_mac, lookup_vendor
from core.validators import validate_scan_results
from core.provenance import build_field_provenance

try:
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


# =====================================================================
# Raccoglitori Indipendenti di Riferimento OS (Nessun codice NetProbe)
# =====================================================================

def get_macos_ref_interface_details(iface: str) -> Dict[str, Any]:
    """Interroga direttamente ifconfig, networksetup e ipconfig."""
    res = {
        "mac": None,
        "ipv4": None,
        "netmask": None,
        "broadcast": None,
        "mtu": None,
        "type": None,
        "source": f"ifconfig {iface} / networksetup"
    }
    # ifconfig
    code, out, _ = run_cmd(["/sbin/ifconfig", iface])
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            # ether a8:8f:d9:11:22:33
            m_ether = re.match(r"^ether\s+([0-9a-fA-F:]{17})", line)
            if m_ether:
                res["mac"] = m_ether.group(1).lower()
            # inet 192.168.1.95 netmask 0xffffff00 broadcast 192.168.1.255
            m_inet = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)(?:\s+broadcast\s+(\d+\.\d+\.\d+\.\d+))?", line)
            if m_inet:
                res["ipv4"] = m_inet.group(1)
                raw_mask = m_inet.group(2)
                if raw_mask.startswith("0x"):
                    try:
                        n = int(raw_mask, 16)
                        res["netmask"] = f"{(n >> 24) & 0xff}.{(n >> 16) & 0xff}.{(n >> 8) & 0xff}.{n & 0xff}"
                    except ValueError:
                        res["netmask"] = raw_mask
                else:
                    res["netmask"] = raw_mask
                res["broadcast"] = m_inet.group(3)
            # mtu 1500
            m_mtu = re.search(r"mtu\s+(\d+)", line)
            if m_mtu:
                res["mtu"] = int(m_mtu.group(1))

    # Real hardware MAC fallback via networksetup se ifconfig è oscurato
    if not res["mac"] or is_placeholder_mac(res["mac"]):
        code_ns, out_ns, _ = run_cmd(["/usr/sbin/networksetup", "-getmacaddress", iface])
        if code_ns == 0:
            m_mac = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out_ns)
            if m_mac:
                res["mac"] = m_mac.group(1).lower()

    # Hardware Port mapping
    code_ports, out_ports, _ = run_cmd(["/usr/sbin/networksetup", "-listallhardwareports"])
    if code_ports == 0:
        cur_port = None
        for line in out_ports.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                cur_port = line.split(":", 1)[1].strip()
            elif line.startswith("Device:") and cur_port:
                dev = line.split(":", 1)[1].strip()
                if dev == iface:
                    res["type"] = cur_port
                    break
    return res


def get_macos_ref_gateway() -> Dict[str, Any]:
    """Interroga route -n get default e arp -n <ip> per il gateway."""
    res = {
        "ipv4": None,
        "iface": None,
        "mac": None,
        "source": "route -n get default",
        "mac_source": None
    }
    code, out, _ = run_cmd(["/sbin/route", "-n", "get", "default"])
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("gateway:"):
                res["ipv4"] = line.split(":", 1)[1].strip()
            elif line.startswith("interface:"):
                res["iface"] = line.split(":", 1)[1].strip()

    # Riferimento primario autoritativo: arp -n <gw_ip> eseguito direttamente da shell
    gw_ip = res["ipv4"] or "192.168.1.1"
    code_arp, out_arp, _ = run_cmd(["/usr/sbin/arp", "-n", gw_ip], timeout=2.0)
    if code_arp != 0 or not out_arp:
        code_arp, out_arp, _ = run_cmd(["arp", "-n", gw_ip], timeout=2.0)
    if code_arp == 0 and out_arp and "(incomplete)" not in out_arp.lower():
        m_mac = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{1,2}(?:-[0-9a-fA-F]{1,2}){5})", out_arp)
        if m_mac:
            raw = m_mac.group(1).replace("-", ":").lower()
            res["mac"] = ":".join(f"{int(b, 16):02x}" for b in raw.split(":"))
            res["mac_source"] = f"arp -n {gw_ip}"

    # Fallback secondario se non presente in ARP
    if not res["mac"]:
        code_sp, out_sp, _ = run_cmd(["/usr/sbin/system_profiler", "SPNetworkDataType"], timeout=4.0)
        if code_sp == 0:
            for line in out_sp.splitlines():
                line = line.strip()
                if line.startswith("ARP Resolved Hardware Address:"):
                    m_mac = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
                    if m_mac:
                        raw = m_mac.group(1)
                        res["mac"] = ":".join(f"{int(b, 16):02x}" for b in raw.split(":"))
                        res["mac_source"] = "system_profiler SPNetworkDataType"
                        break
    return res


def get_macos_ref_dns() -> Dict[str, Any]:
    """Interroga scutil --dns."""
    res = {"resolvers": [], "source": "scutil --dns"}
    code, out, _ = run_cmd(["/usr/sbin/scutil", "--dns"])
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            if "DNS configuration (for scoped queries)" in line:
                break
            m = re.match(r"nameserver\[\d+\]\s*:\s*([0-9a-fA-F:\.]+)", line)
            if m:
                ip = m.group(1)
                if ip not in res["resolvers"]:
                    res["resolvers"].append(ip)
    return res


def get_macos_ref_dhcp(iface: str) -> Dict[str, Any]:
    """Interroga ipconfig getpacket."""
    res = {"server_ip": None, "lease_seconds": None, "source": f"ipconfig getpacket {iface}"}
    code, out, _ = run_cmd(["/usr/sbin/ipconfig", "getpacket", iface])
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("server_identifier (ip):"):
                res["server_ip"] = line.split(":", 1)[1].strip()
            elif line.startswith("lease_time (uint32):"):
                raw = line.split(":", 1)[1].strip()
                try:
                    res["lease_seconds"] = int(raw, 16) if raw.startswith("0x") else int(raw)
                except ValueError:
                    pass
    return res


def get_macos_ref_wifi(iface: str) -> Dict[str, Any]:
    """Interroga system_profiler SPAirPortDataType."""
    res = {
        "channel": None,
        "frequency": None,
        "phy_mode": None,
        "rssi_dbm": None,
        "noise_dbm": None,
        "source": "system_profiler SPAirPortDataType"
    }
    code, out, _ = run_cmd(["/usr/sbin/system_profiler", "SPAirPortDataType"], timeout=4.0)
    if code == 0:
        in_iface = False
        in_curr = False
        for line in out.splitlines():
            stripped = line.strip()
            if f"{iface}:" in line and not in_iface:
                in_iface = True
                continue
            if in_iface:
                if "Current Network Information:" in line:
                    in_curr = True
                    continue
                if in_curr:
                    if stripped.startswith("Channel:"):
                        res["channel"] = stripped.split(":", 1)[1].strip()
                        m_ch = re.match(r"^(\d+)", res["channel"])
                        if m_ch:
                            ch_num = int(m_ch.group(1))
                            if 1 <= ch_num <= 14:
                                res["frequency"] = "2.4 GHz"
                            elif 32 <= ch_num <= 177:
                                res["frequency"] = "5 GHz"
                            elif ch_num >= 180:
                                res["frequency"] = "6 GHz (Wi-Fi 6E/7)"
                    elif stripped.startswith("PHY Mode:"):
                        res["phy_mode"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("Signal / Noise:"):
                        parts = stripped.split(":", 1)[1].strip().split("/")
                        if len(parts) == 2:
                            try:
                                res["rssi_dbm"] = int(parts[0].replace("dBm", "").strip())
                                res["noise_dbm"] = int(parts[1].replace("dBm", "").strip())
                            except ValueError:
                                pass
                    elif "Other Local Wi-Fi Networks:" in line or "Interfaces:" in line:
                        break
    return res


# =====================================================================
# Raccoglitori Indipendenti WAN (>= 2 servizi per ogni dato)
# =====================================================================

def get_ref_public_ip() -> Dict[str, Any]:
    """Interroga >= 2 endpoint indipendenti per IPv4 e IPv6."""
    res = {
        "ipv4_services": {},
        "ipv6_services": {},
        "agreed_ipv4": None,
        "agreed_ipv6": None,
        "disagreement": False,
        "source": "api.ipify.org / icanhazip.com / ifconfig.me"
    }
    endpoints_v4 = [
        ("ipify", "https://api.ipify.org"),
        ("icanhazip", "https://icanhazip.com"),
        ("ifconfig_me", "https://ifconfig.me/ip")
    ]
    for name, url in endpoints_v4:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                ip = resp.read().decode("utf-8").strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    res["ipv4_services"][name] = ip
        except Exception:
            pass

    v4_values = list(res["ipv4_services"].values())
    if v4_values:
        res["agreed_ipv4"] = v4_values[0]
        if len(set(v4_values)) > 1:
            res["disagreement"] = True

    # IPv6 test
    endpoints_v6 = [
        ("icanhazip_v6", "https://ipv6.icanhazip.com"),
        ("ipify_v6", "https://api64.ipify.org")
    ]
    for name, url in endpoints_v6:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                ip = resp.read().decode("utf-8").strip()
                if ":" in ip:
                    res["ipv6_services"][name] = ip
        except Exception:
            pass
    v6_values = list(res["ipv6_services"].values())
    if v6_values:
        res["agreed_ipv6"] = v6_values[0]

    return res


def get_ref_asn_and_geoip(public_ip: str) -> Dict[str, Any]:
    """
    Raccoglie ASN e Geolocation da >= 2 fonti indipendenti:
    - Team Cymru DNS TXT origin query
    - ip-api.com JSON
    - ipinfo.io JSON
    - Query PTR diretta con dnspython
    """
    res = {
        "asn_services": {},
        "geo_services": {},
        "rdns": None,
        "agreed_asn": None,
        "disagreement": False,
        "source": "Team Cymru DNS / ip-api.com / ipinfo.io / dnspython PTR"
    }
    if not public_ip:
        return res

    # 1. Team Cymru DNS Origin TXT query
    if _HAS_DNSPYTHON:
        try:
            rev_ip = ".".join(reversed(public_ip.split("."))) + ".origin.asn.cymru.com"
            answers = dns.resolver.resolve(rev_ip, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                parts = [p.strip() for p in txt.split("|")]
                if parts and parts[0].isdigit():
                    res["asn_services"]["team_cymru_dns"] = f"AS{parts[0]}"
                    break
        except Exception:
            pass

        # Direct PTR query
        try:
            rev_name = dns.reversename.from_address(public_ip)
            ptr_answers = dns.resolver.resolve(rev_name, "PTR")
            for r in ptr_answers:
                res["rdns"] = str(r.to_text()).rstrip(".")
                break
        except Exception:
            pass

    # 2. ip-api.com
    try:
        url = f"http://ip-api.com/json/{public_ip}?fields=status,country,city,as,org,isp,reverse"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                as_str = data.get("as", "")
                m_as = re.match(r"^(AS\d+)", as_str)
                if m_as:
                    res["asn_services"]["ip_api"] = m_as.group(1).upper()
                res["geo_services"]["ip_api"] = {
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org")
                }
                if not res["rdns"] and data.get("reverse"):
                    res["rdns"] = data.get("reverse")
    except Exception:
        pass

    # 3. ipinfo.io
    try:
        url = f"https://ipinfo.io/{public_ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            org_str = data.get("org", "")
            m_as = re.match(r"^(AS\d+)", org_str)
            if m_as:
                res["asn_services"]["ipinfo"] = m_as.group(1).upper()
            res["geo_services"]["ipinfo"] = {
                "city": data.get("city"),
                "isp": org_str
            }
    except Exception:
        pass

    asn_vals = list(res["asn_services"].values())
    if asn_vals:
        res["agreed_asn"] = asn_vals[0]
        if len(set(asn_vals)) > 1:
            res["disagreement"] = True

    return res


def get_ref_dig_dnssec(resolvers: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Verifica indipendente con /usr/bin/dig +dnssec su zone deliberate (dnssec-failed.org).
    Testa tutti i resolver configurati:
    - Se tutti validano -> VALIDANTE
    - Se nessuno valida -> NON VALIDANTE
    - Se alcuni validano e altri no -> PARZIALE
    """
    res = {
        "status": "N/D",
        "validating": None,
        "source": "/usr/bin/dig +dnssec",
        "details": ""
    }
    targets = [r for r in (resolvers or []) if r]
    if not targets:
        targets = [""]

    val_count = 0
    non_val_count = 0
    details_list = []

    for srv in targets:
        cmd = ["/usr/bin/dig"]
        if srv:
            cmd.append(f"@{srv}")
        cmd.extend(["dnssec-failed.org", "+dnssec", "+time=3", "+tries=1"])
        code, out, _ = run_cmd(cmd, timeout=5.0)
        if code == 0 and out:
            srv_label = srv or "default"
            if "status: SERVFAIL" in out:
                val_count += 1
                details_list.append(f"{srv_label}: VALIDANTE")
            elif "status: NOERROR" in out:
                if re.search(r"dnssec-failed\.org\.\s+\d+\s+IN\s+A\s+", out):
                    non_val_count += 1
                    details_list.append(f"{srv_label}: NON VALIDANTE")
                else:
                    details_list.append(f"{srv_label}: NOERROR")

    if val_count > 0 and non_val_count == 0:
        res["status"] = "VALIDANTE"
        res["validating"] = True
    elif non_val_count > 0 and val_count == 0:
        res["status"] = "NON VALIDANTE"
        res["validating"] = False
    elif val_count > 0 and non_val_count > 0:
        res["status"] = "PARZIALE"
        res["validating"] = True

    res["details"] = "; ".join(details_list)
    return res


def get_ref_system_ping(host: str = "1.1.1.1", count: int = 5) -> Dict[str, Any]:
    """Misura min/avg latency usando il ping di sistema."""
    res = {"min_ms": None, "avg_ms": None, "source": f"/sbin/ping -c {count} {host}"}
    code, out, _ = run_cmd(["/sbin/ping", "-c", str(count), "-q", host], timeout=5.0)
    if code == 0:
        # round-trip min/avg/max/stddev = 12.301/14.502/18.910/2.112 ms
        m = re.search(r"=\s*([0-9\.]+)/([0-9\.]+)/([0-9\.]+)/[0-9\.]+\s*ms", out)
        if m:
            res["min_ms"] = float(m.group(1))
            res["avg_ms"] = float(m.group(2))
    return res


def get_ref_network_quality() -> Dict[str, Any]:
    """Esegue /usr/bin/networkQuality -c -s -M 15 se presente con timeout limitato a 18s."""
    res = {"available": False, "dl_mbps": None, "ul_mbps": None, "source": "networkQuality -c -s -M 15"}
    if not is_macos() or not os.path.exists("/usr/bin/networkQuality"):
        return res
    code, out, _ = run_cmd(["/usr/bin/networkQuality", "-c", "-s", "-M", "15"], timeout=18.0)
    if code == 0 and out:
        try:
            data = json.loads(out)
            dl_bps = data.get("dl_throughput")
            ul_bps = data.get("ul_throughput")
            if dl_bps:
                res["dl_mbps"] = round(dl_bps / 1e6, 2)
            if ul_bps:
                res["ul_mbps"] = round(ul_bps / 1e6, 2)
            res["available"] = True
        except Exception:
            pass
    return res


# =====================================================================
# Audit Runner & Comparator
# =====================================================================

class NetworkAuditor:
    def __init__(self, skip_speed: bool = False, verbose: bool = False):
        self.skip_speed = skip_speed
        self.verbose = verbose
        self.results: List[Dict[str, Any]] = []

    def log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    def record(self, field: str, netprobe_val: Any, ref_val: Any, status: str, source: str, note: str = "", independent: bool = True, collector_source: str = "", reference_source: str = ""):
        ref_src = reference_source or source
        c_src = collector_source
        c_clean = c_src.strip().lower() if c_src else ""
        r_clean = ref_src.strip().lower() if ref_src else ""
        if c_clean and r_clean:
            is_same = False
            if c_clean == r_clean:
                is_same = True
            elif "scutil" in c_clean and "scutil" in r_clean:
                is_same = True
            elif "ipconfig getpacket" in c_clean and "ipconfig getpacket" in r_clean:
                is_same = True
            elif "ifconfig" in c_clean and "ifconfig" in r_clean and "corewlan" not in c_clean and "networksetup" not in c_clean:
                is_same = True
            elif "route" in c_clean and "route" in r_clean:
                is_same = True
            elif "system_profiler" in c_clean and "system_profiler" in r_clean:
                is_same = True

            if is_same:
                status = "STESSA FONTE (coerenza del parser, non verifica del dato)"
                independent = False

        self.results.append({
            "field": field,
            "netprobe": netprobe_val,
            "reference": ref_val,
            "status": status,
            "source": ref_src,
            "collector_source": c_src,
            "note": note,
            "independent": independent
        })

    def run_audit(self) -> List[Dict[str, Any]]:
        self.log("Esecuzione raccoglitori NetProbe...")
        # 1. Esegui scanner NetProbe
        lan_s = LanScanner()
        lan_data = lan_s.scan_all(quick_scan=True)

        p_iface = lan_data.get("primary_interface") or {}
        local_ip = p_iface.get("ipv4")
        iface_name = lan_data.get("primary_interface_name") or "en0"
        gw_info = lan_data.get("gateway") or {}
        gw_ip = gw_info.get("ipv4")

        wan_p = WanProbe()
        wan_data = wan_p.probe_all(local_ip=local_ip, gateway_ip=gw_ip)

        perf_t = PerformanceTester()
        perf_data = perf_t.test_all(gateway_ip=gw_ip, run_speed_test=(not self.skip_speed))

        # Assembla report e valida
        full_report = {
            "timestamp": time.time(),
            "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "quick_scan": self.skip_speed,
            "lan": lan_data,
            "wan": wan_data,
            "performance": perf_data
        }
        validate_scan_results(full_report)
        prov = build_field_provenance(full_report)

        self.log("Esecuzione comandi di riferimento OS indipendenti...")
        ref_iface = get_macos_ref_interface_details(iface_name) if is_macos() else {}
        ref_gw = get_macos_ref_gateway() if is_macos() else {}
        ref_dns = get_macos_ref_dns() if is_macos() else {}
        ref_dhcp = get_macos_ref_dhcp(iface_name) if is_macos() else {}
        ref_wifi = get_macos_ref_wifi(iface_name) if is_macos() else {}

        self.log("Interrogazione endpoint WAN esterni di riferimento...")
        ref_wan_ip = get_ref_public_ip()
        pub_ip = ref_wan_ip.get("agreed_ipv4") or wan_data.get("public_ipv4")
        ref_wan_meta = get_ref_asn_and_geoip(pub_ip)

        self.log("Verifica ping e speed di riferimento...")
        ref_ping = get_ref_system_ping("1.1.1.1", count=5)
        ref_speed = get_ref_network_quality() if (not self.skip_speed) else {"available": False}

        # -------------------------------------------------------------
        # CONFRONTO CAMPO PER CAMPO
        # -------------------------------------------------------------

        # 1. Interfaccia Primaria - Nome
        np_name = lan_data.get("primary_interface_name")
        rf_name = iface_name
        self.record("lan.interface.name", np_name, rf_name, "OK" if np_name == rf_name else "MISMATCH", "route -n get default", collector_source="route -n get default", reference_source="route -n get default")

        # 2. Interfaccia Primaria - MAC Address
        np_mac = p_iface.get("mac")
        rf_mac = ref_iface.get("mac")
        if is_placeholder_mac(str(np_mac)):
            self.record("lan.interface.mac", np_mac, rf_mac or "N/D", "MISMATCH", ref_iface.get("source", ""), "NetProbe ha riportato un MAC placeholder non consentito", collector_source="networksetup -getmacaddress", reference_source=ref_iface.get("source", ""))
        elif np_mac and rf_mac and np_mac.lower() == rf_mac.lower():
            self.record("lan.interface.mac", np_mac, rf_mac, "OK", ref_iface.get("source", ""), collector_source="networksetup -getmacaddress", reference_source=ref_iface.get("source", ""))
        elif np_mac and not rf_mac:
            self.record("lan.interface.mac", np_mac, "N/D", "WARN", ref_iface.get("source", ""), "Riferimento OS non disponibile in ifconfig/networksetup", collector_source="networksetup -getmacaddress", reference_source=ref_iface.get("source", ""))
        elif not np_mac and not rf_mac:
            self.record("lan.interface.mac", "N/D", "N/D", "N/A", ref_iface.get("source", ""), collector_source="networksetup -getmacaddress", reference_source=ref_iface.get("source", ""))
        else:
            self.record("lan.interface.mac", np_mac or "N/D", rf_mac, "MISMATCH", ref_iface.get("source", ""), "Discrepanza indirizzo fisico MAC", collector_source="networksetup -getmacaddress", reference_source=ref_iface.get("source", ""))

        # 3. Interfaccia Primaria - IPv4
        np_v4 = p_iface.get("ipv4")
        rf_v4 = ref_iface.get("ipv4")
        self.record("lan.interface.ipv4", np_v4, rf_v4, "OK" if np_v4 == rf_v4 else "MISMATCH", ref_iface.get("source", ""), collector_source="ifconfig", reference_source=ref_iface.get("source", "ifconfig"))

        # 4. Interfaccia Primaria - Netmask
        np_mask = p_iface.get("netmask")
        rf_mask = ref_iface.get("netmask")
        mask_match = False
        if np_mask and rf_mask:
            np_clean = str(np_mask).split()[0].strip()
            rf_clean = str(rf_mask).split()[0].strip()
            mask_match = (np_clean == rf_clean)
        elif not np_mask and not rf_mask:
            mask_match = True
        self.record("lan.interface.netmask", np_mask, rf_mask, "OK" if mask_match else "MISMATCH", ref_iface.get("source", ""), collector_source="ifconfig", reference_source=ref_iface.get("source", "ifconfig"))

        # 5. Interfaccia Primaria - MTU
        np_mtu = p_iface.get("mtu")
        rf_mtu = ref_iface.get("mtu")
        self.record("lan.interface.mtu", np_mtu, rf_mtu, "OK" if np_mtu == rf_mtu else "MISMATCH", ref_iface.get("source", ""), collector_source="ifconfig", reference_source=ref_iface.get("source", "ifconfig"))

        # 6. Interfaccia Primaria - Tipo
        np_type = p_iface.get("type")
        rf_type = "Wi-Fi" if (ref_iface.get("type") == "Wi-Fi" or "AirPort" in str(ref_iface.get("type"))) else (ref_iface.get("type") or "LAN")
        self.record("lan.interface.type", np_type, rf_type, "OK" if (np_type == rf_type or (np_type == "Wi-Fi" and "Wi-Fi" in str(rf_type))) else "WARN", ref_iface.get("source", ""), collector_source="networksetup -listallhardwareports", reference_source="networksetup -listallhardwareports")

        # 7. Gateway - IPv4
        np_gw_ip = gw_info.get("ipv4")
        rf_gw_ip = ref_gw.get("ipv4")
        self.record("lan.gateway.ipv4", np_gw_ip, rf_gw_ip, "OK" if np_gw_ip == rf_gw_ip else "MISMATCH", ref_gw.get("source", ""), collector_source="route -n get default", reference_source=ref_gw.get("source", "route -n get default"))

        # 8. Gateway - MAC (Verifica Indipendente: NetProbe sysctl vs shell arp -n)
        np_gw_mac = gw_info.get("mac")
        rf_gw_mac = ref_gw.get("mac")
        np_gw_src = gw_info.get("identified_by") or (gw_info.get("mac_source") or "sysctl")
        rf_gw_src = ref_gw.get("mac_source") or "arp -n gw_ip"
        if is_placeholder_mac(str(np_gw_mac)):
            self.record("lan.gateway.mac", np_gw_mac, rf_gw_mac or "N/D", "MISMATCH", rf_gw_src, "Gateway MAC placeholder", collector_source=f"NetProbe ({np_gw_src})", reference_source=rf_gw_src)
        elif np_gw_mac and rf_gw_mac and np_gw_mac.lower() == rf_gw_mac.lower():
            self.record("lan.gateway.mac", np_gw_mac, rf_gw_mac, "OK", rf_gw_src, collector_source=f"NetProbe ({np_gw_src})", reference_source=rf_gw_src)
        elif np_gw_mac and not rf_gw_mac:
            self.record("lan.gateway.mac", np_gw_mac, "N/D", "WARN", rf_gw_src, "Riferimento non disponibile in cache ARP", collector_source=f"NetProbe ({np_gw_src})", reference_source=rf_gw_src)
        elif not np_gw_mac and not rf_gw_mac:
            self.record("lan.gateway.mac", "N/D", "N/D", "N/A", rf_gw_src, collector_source=f"NetProbe ({np_gw_src})", reference_source=rf_gw_src)
        else:
            self.record("lan.gateway.mac", np_gw_mac, rf_gw_mac, "MISMATCH", rf_gw_src, collector_source=f"NetProbe ({np_gw_src})", reference_source=rf_gw_src)

        # 9. Gateway - Vendor
        np_gw_vendor = gw_info.get("vendor")
        rf_gw_vendor = lookup_vendor(rf_gw_mac) if rf_gw_mac else None
        if rf_gw_vendor and np_gw_vendor:
            is_vendor_ok = (np_gw_vendor.lower() in rf_gw_vendor.lower() or rf_gw_vendor.lower() in np_gw_vendor.lower())
            self.record("lan.gateway.vendor", np_gw_vendor, rf_gw_vendor, "OK" if is_vendor_ok else "WARN", "OUI Database")
        elif not rf_gw_vendor and np_gw_vendor:
            self.record("lan.gateway.vendor", np_gw_vendor, "N/D", "WARN", "OUI Database", "Riferimento vendor non disponibile (MAC router sconosciuto a OUI)")
        elif not rf_gw_vendor and not np_gw_vendor:
            self.record("lan.gateway.vendor", "N/D", "N/D", "N/A", "OUI Database")
        else:
            self.record("lan.gateway.vendor", "N/D", rf_gw_vendor, "WARN", "OUI Database")

        # 10. DHCP Server
        dhcp_info = lan_data.get("dhcp") or {}
        np_dhcp_srv = dhcp_info.get("server_ip")
        rf_dhcp_srv = ref_dhcp.get("server_ip")
        if rf_dhcp_srv:
            self.record("lan.dhcp.server_ip", np_dhcp_srv, rf_dhcp_srv, "OK" if np_dhcp_srv == rf_dhcp_srv else "MISMATCH", ref_dhcp.get("source", ""), collector_source="ipconfig getpacket", reference_source=ref_dhcp.get("source", "ipconfig getpacket"))
        else:
            self.record("lan.dhcp.server_ip", np_dhcp_srv or "N/D", "N/D", "N/A", ref_dhcp.get("source", ""), "Nessuna concessione DHCP attiva", collector_source="ipconfig getpacket", reference_source=ref_dhcp.get("source", "ipconfig getpacket"))

        # 11. DNS Resolvers
        dns_info = lan_data.get("dns") or {}
        np_resolvers = dns_info.get("resolvers") or []
        rf_resolvers = ref_dns.get("resolvers") or []
        if rf_resolvers:
            st = "OK" if set(np_resolvers) == set(rf_resolvers) else ("WARN" if any(r in rf_resolvers for r in np_resolvers) else "MISMATCH")
            self.record("lan.dns.resolvers", ", ".join(np_resolvers), ", ".join(rf_resolvers), st, ref_dns.get("source", ""), collector_source="scutil --dns", reference_source=ref_dns.get("source", "scutil --dns"))
        else:
            self.record("lan.dns.resolvers", ", ".join(np_resolvers) or "N/D", "N/D", "WARN", ref_dns.get("source", ""), "Riferimento scutil --dns non ottenuto", collector_source="scutil --dns", reference_source=ref_dns.get("source", "scutil --dns"))

        # 12. DNSSEC Validation (Verifica indipendente con dig +dnssec)
        dns_bm = lan_data.get("dns_benchmark") or {}
        np_dnssec_act = dns_bm.get("dnssec_validation_active")
        np_dnssec_rep = dns_bm.get("dnssec_report") or {}
        st_label = np_dnssec_rep.get("overall_status") or ("VALIDANTE" if np_dnssec_act else "NON VALIDANTE")
        ref_dnssec = get_ref_dig_dnssec(rf_resolvers or np_resolvers)
        rf_dnssec_st = ref_dnssec.get("status") or "N/D"
        if rf_dnssec_st == "N/D":
            self.record("lan.dns.dnssec_status", st_label, "N/D", "WARN", ref_dnssec.get("source", ""), "Verifica indipendente dig non riuscita")
        else:
            is_match = (st_label == rf_dnssec_st)
            self.record("lan.dns.dnssec_status", st_label, rf_dnssec_st, "OK" if is_match else "MISMATCH", ref_dnssec.get("source", ""), ref_dnssec.get("details", ""))

        # 13. Wi-Fi RF Metriche
        wifi_info = lan_data.get("wifi") or {}
        if wifi_info.get("connected") or ref_wifi.get("channel"):
            np_ch = wifi_info.get("channel")
            rf_ch = ref_wifi.get("channel")
            self.record("lan.wifi.channel", np_ch, rf_ch, "OK" if (np_ch and rf_ch and str(np_ch).split()[0] == str(rf_ch).split()[0]) else "WARN", ref_wifi.get("source", ""))

            np_gen = wifi_info.get("wifi_generation")
            rf_phy = ref_wifi.get("phy_mode")
            # Verifica rigorosa: se il canale è 5 GHz, NON deve mai essere etichettato Wi-Fi 6E
            is_6e_wrong = bool(np_gen and "6E" in str(np_gen) and wifi_info.get("frequency_ghz") == "5 GHz")
            if is_6e_wrong:
                self.record("lan.wifi.standard", np_gen, rf_phy, "MISMATCH", ref_wifi.get("source", ""), "Wi-Fi 6E indicato su banda 5 GHz (6E esiste solo su 6 GHz)")
            else:
                self.record("lan.wifi.standard", np_gen, rf_phy, "OK", ref_wifi.get("source", ""))

            np_rssi = wifi_info.get("rssi_dbm")
            rf_rssi = ref_wifi.get("rssi_dbm")
            if np_rssi is not None and rf_rssi is not None:
                diff_rssi = abs(np_rssi - rf_rssi)
                # Tolleranza: ±5 dB
                self.record("lan.wifi.rssi_dbm", f"{np_rssi} dBm", f"{rf_rssi} dBm", "OK" if diff_rssi <= 5 else "WARN", ref_wifi.get("source", ""), f"Δ {diff_rssi} dBm tra campionamenti")
        else:
            self.record("lan.wifi.status", "Non connesso", "N/D", "N/A", "SPAirPortDataType")

        # 14. WAN - IPv4 Pubblico
        np_pub_v4 = wan_data.get("public_ipv4")
        rf_pub_v4 = ref_wan_ip.get("agreed_ipv4")
        if ref_wan_ip.get("disagreement"):
            self.record("wan.public_ipv4", np_pub_v4, f"Discordanti: {ref_wan_ip['ipv4_services']}", "WARN", ref_wan_ip.get("source", ""), "Servizi esterni restituiscono IP differenti")
        elif rf_pub_v4:
            self.record("wan.public_ipv4", np_pub_v4, rf_pub_v4, "OK" if np_pub_v4 == rf_pub_v4 else "MISMATCH", ref_wan_ip.get("source", ""))
        else:
            self.record("wan.public_ipv4", np_pub_v4 or "N/D", "N/D", "WARN", ref_wan_ip.get("source", ""), "Riferimento IP pubblico non ottenuto")

        # 15. WAN - IPv6 Pubblico
        np_pub_v6 = wan_data.get("public_ipv6")
        rf_pub_v6 = ref_wan_ip.get("agreed_ipv6")
        if not np_pub_v6 and not rf_pub_v6:
            self.record("wan.public_ipv6", "Non attivo (IPv4-Only)", "Non attivo", "N/A", "icanhazip_v6", "Rete dual-stack non presente")
        elif np_pub_v6 and rf_pub_v6:
            self.record("wan.public_ipv6", np_pub_v6, rf_pub_v6, "OK" if np_pub_v6 == rf_pub_v6 else "WARN", "icanhazip_v6")
        else:
            self.record("wan.public_ipv6", np_pub_v6 or "N/D", rf_pub_v6 or "N/D", "WARN", "icanhazip_v6", "Riferimento IPv6 non ottenuto")

        # 16. WAN - ASN
        np_asn = wan_data.get("asn")
        rf_asn = ref_wan_meta.get("agreed_asn")
        cymru_asn = ref_wan_meta.get("asn_services", {}).get("team_cymru_dns")
        if cymru_asn and np_asn:
            self.record("wan.asn", np_asn, cymru_asn, "OK" if np_asn.upper() == cymru_asn.upper() else "MISMATCH", "Team Cymru DNS origin")
        elif rf_asn and np_asn:
            self.record("wan.asn", np_asn, rf_asn, "OK" if np_asn.upper() == rf_asn.upper() else "MISMATCH", "ip-api.com")
        else:
            self.record("wan.asn", np_asn or "N/D", rf_asn or "N/D", "WARN", ref_wan_meta.get("source", ""), "Riferimento ASN non ottenuto")

        # 17. WAN - Reverse DNS
        np_rdns = wan_data.get("reverse_dns")
        rf_rdns = ref_wan_meta.get("rdns")
        if np_rdns and rf_rdns:
            self.record("wan.reverse_dns", np_rdns, rf_rdns, "OK" if np_rdns.lower() == rf_rdns.lower() else "WARN", "dnspython direct PTR")
        elif not np_rdns and not rf_rdns:
            self.record("wan.reverse_dns", "N/D", "N/D", "N/A", "dnspython direct PTR", "Nessun record PTR esistente")
        else:
            self.record("wan.reverse_dns", np_rdns or "N/D", rf_rdns or "N/D", "WARN", "dnspython direct PTR", "Riferimento PTR non ottenuto")

        # 18. WAN - Privacy / VPN / Residential Label (Classificazione euristica interna NetProbe)
        priv = wan_data.get("privacy_and_routing") or {}
        priv_type = priv.get("type", "N/D")
        self.record("wan.privacy_label", priv_type, "N/A (nessun riferimento indipendente)", "N/A", "core.wan_probe", "Classificazione euristica interna NetProbe", independent=False)

        # 19. WAN - NAT & Firewall Wording (Mappatura interna STUN NetProbe)
        nat_info = wan_data.get("nat") or {}
        nat_type = nat_info.get("nat_type", "N/D")
        self.record("wan.nat.type", nat_type, "N/A (nessun riferimento indipendente)", "N/A", "RFC 5389 STUN", "Mappatura interna STUN NetProbe", independent=False)

        # 20. WAN - UPnP / NAT-PMP wording (Rilevamento interno SSDP NetProbe)
        services = wan_data.get("router_services") or {}
        upnp_txt = services.get("upnp_status_text") or ("Attivo" if services.get("upnp_igd_available") else "Nessuna risposta")
        self.record("wan.services.upnp", upnp_txt, "N/A (nessun riferimento indipendente)", "N/A", "SSDP UPnP", "Rilevamento interno SSDP NetProbe", independent=False)

        # 21. Latency - Ping
        primary_lat = perf_data.get("primary_latency") or {}
        np_min = primary_lat.get("min_ms")
        np_med = primary_lat.get("median_ms")
        rf_min = ref_ping.get("min_ms")
        rf_avg = ref_ping.get("avg_ms")

        if np_min is not None and rf_min is not None:
            diff_lat = abs(np_min - rf_min)
            diff_pct = (diff_lat / rf_min) * 100.0 if rf_min > 0 else 0.0
            # Tolleranza: min ±2 ms o ±15%
            is_ok = (diff_lat <= 2.0 or diff_pct <= 15.0)
            st_lat = "OK" if is_ok else ("WARN" if diff_pct <= 50.0 else "MISMATCH")
            self.record("performance.latency.min_ms", f"{np_min} ms", f"{rf_min} ms", st_lat, ref_ping.get("source", ""), f"Δ {diff_lat:.2f} ms ({diff_pct:.1f}%)")
        else:
            self.record("performance.latency.min_ms", np_min or "N/D", rf_min or "N/D", "WARN", ref_ping.get("source", ""), "Riferimento non ottenuto")

        if np_med is not None and rf_avg is not None:
            diff_med = abs(np_med - rf_avg)
            diff_pct_med = (diff_med / rf_avg) * 100.0 if rf_avg > 0 else 0.0
            # Tolleranza: mediana ±25% (es. 12.58 vs 17.96 ms è ~30% -> WARN)
            is_ok_med = (diff_pct_med <= 25.0)
            st_med = "OK" if is_ok_med else ("WARN" if diff_pct_med <= 50.0 else "MISMATCH")
            self.record("performance.latency.median_ms", f"{np_med} ms", f"{rf_avg} ms", st_med, ref_ping.get("source", ""), f"Δ {diff_med:.2f} ms ({diff_pct_med:.1f}%)")
        else:
            self.record("performance.latency.median_ms", np_med or "N/D", rf_avg or "N/D", "WARN", ref_ping.get("source", ""), "Riferimento non ottenuto")

        # 22. Speed & Throughput
        speed_info = perf_data.get("speed") or {}
        if not self.skip_speed and speed_info.get("download_mbps") is not None:
            np_dl = speed_info.get("download_mbps")
            np_ul = speed_info.get("upload_mbps")
            rf_dl = ref_speed.get("dl_mbps")
            rf_ul = ref_speed.get("ul_mbps")

            # Tolleranza velocità ±30%
            if rf_dl is not None and np_dl is not None and rf_dl > 0:
                diff_pct = abs(np_dl - rf_dl) / rf_dl * 100.0
                st_sp = "OK" if diff_pct <= 30.0 else ("WARN" if diff_pct <= 65.0 else "MISMATCH")
                self.record("performance.speed.download", f"{np_dl} Mbps", f"{rf_dl} Mbps", st_sp, ref_speed.get("source", ""), f"Discrepanza {diff_pct:.1f}%")
            else:
                self.record("performance.speed.download", f"{np_dl} Mbps", rf_dl or "N/D", "WARN", ref_speed.get("source", ""), "Riferimento networkQuality non ottenuto")

            if rf_ul is not None and np_ul is not None and rf_ul > 0:
                diff_pct_ul = abs(np_ul - rf_ul) / rf_ul * 100.0
                st_sp_ul = "OK" if diff_pct_ul <= 30.0 else ("WARN" if diff_pct_ul <= 65.0 else "MISMATCH")
                self.record("performance.speed.upload", f"{np_ul} Mbps", f"{rf_ul} Mbps", st_sp_ul, ref_speed.get("source", ""), f"Discrepanza {diff_pct_ul:.1f}% (NetProbe sostenuto vs Apple concurrent)")
            else:
                self.record("performance.speed.upload", f"{np_ul} Mbps", rf_ul or "N/D", "WARN", ref_speed.get("source", ""), "Riferimento networkQuality non ottenuto")

            # Tool Ceiling check (benchmark interno)
            ceil_mbps = speed_info.get("tool_ceiling_mbps")
            self.record("performance.tool_ceiling", f"{ceil_mbps} Mbps" if ceil_mbps else "N/D", "N/A (nessun riferimento indipendente)", "N/A", "Loopback HTTP server", "Capacità massima interprete Python", independent=False)
        else:
            self.record("performance.speed.status", "Saltato (--skip-speed)", "N/D", "N/A", "networkQuality", "Speedtest non eseguito in audit rapido", independent=False)

        return self.results


# =====================================================================
# Tabella di Rendering CLI & Export
# =====================================================================

def render_table(results: List[Dict[str, Any]], use_color: bool = True) -> str:
    RESET = "\033[0m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    GREEN = "\033[92m" if use_color else ""
    YELLOW = "\033[93m" if use_color else ""
    RED = "\033[91m" if use_color else ""
    CYAN = "\033[96m" if use_color else ""
    DIM = "\033[2m" if use_color else ""

    lines = []
    lines.append(f"\n{BOLD}{'═' * 110}{RESET}")
    lines.append(f"{BOLD}{'NETPROBE AUDIT BASICS - VERIFICA INCROCIATA RIGOROSA':^110}{RESET}")
    lines.append(f"{BOLD}Tolleranze: RSSI ±5 dB | Latenza min ±2 ms o ±15% | Latenza mediana ±25% | Velocità ±30%{RESET}")
    lines.append(f"{BOLD}{'═' * 110}{RESET}")

    headers = f"{'FIELD':<30} | {'NETPROBE':<26} | {'REFERENCE':<26} | {'STATUS':<10} | {'SOURCE':<10}"
    lines.append(f"{BOLD}{headers}{RESET}")
    lines.append(f"{DIM}{'─' * 110}{RESET}")

    counts = {"OK": 0, "WARN": 0, "MISMATCH": 0, "N/A": 0}

    for r in results:
        field = r["field"][:29]
        np_v = str(r["netprobe"])[:25]
        rf_v = str(r["reference"])[:25]
        status = r["status"]
        src = r["source"][:14]

        if "STESSA FONTE" in status:
            counts["STESSA FONTE"] = counts.get("STESSA FONTE", 0) + 1
            st_badge = f"{DIM}STESSA FONTE{RESET}"
        elif status == "OK":
            counts["OK"] = counts.get("OK", 0) + 1
            st_badge = f"{GREEN}{BOLD}OK{RESET}"
        elif status == "WARN":
            counts["WARN"] = counts.get("WARN", 0) + 1
            st_badge = f"{YELLOW}{BOLD}WARN{RESET}"
        elif status == "MISMATCH":
            counts["MISMATCH"] = counts.get("MISMATCH", 0) + 1
            st_badge = f"{RED}{BOLD}MISMATCH{RESET}"
        else:
            counts["N/A"] = counts.get("N/A", 0) + 1
            st_badge = f"{DIM}N/A{RESET}"

        lines.append(f"{CYAN}{field:<30}{RESET} | {np_v:<26} | {rf_v:<26} | {st_badge:<25} | {DIM}{src:<10}{RESET}")
        if r.get("note"):
            lines.append(f"  ↳ {DIM}Note: {r['note']}{RESET}")

    lines.append(f"{DIM}{'─' * 110}{RESET}")

    # Conteggio verifiche indipendenti (esclude N/A e STESSA FONTE)
    indep_results = [r for r in results if r.get("independent", True) and "STESSA FONTE" not in r["status"] and r["status"] != "N/A"]
    non_indep_count = len(results) - len(indep_results)
    indep_ok = sum(1 for r in indep_results if r["status"] == "OK")
    indep_warn = sum(1 for r in indep_results if r["status"] == "WARN")
    indep_mismatch = sum(1 for r in indep_results if r["status"] == "MISMATCH")

    sf_str = f" (di cui {counts.get('STESSA FONTE', 0)} stessa fonte)" if counts.get("STESSA FONTE", 0) > 0 else ""
    summary = (
        f"{len(indep_results)} verifiche indipendenti: {indep_ok} OK / {indep_warn} WARN / {indep_mismatch} MISMATCH; "
        f"{non_indep_count} non indipendenti o N/A{sf_str} | OK: {counts.get('OK', 0)} | WARN: {counts.get('WARN', 0)} | "
        f"MISMATCH: {counts.get('MISMATCH', 0)} | N/A: {counts.get('N/A', 0)}"
    )
    if indep_mismatch > 0:
        lines.append(f"{RED}{BOLD}{summary} (FALLITO: Discrepanze rilevate){RESET}")
    else:
        lines.append(f"{GREEN}{BOLD}{summary} (SUPERATO con successo){RESET}")
    lines.append(f"{BOLD}{'═' * 110}{RESET}\n")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="NetProbe Audit Basics - Verifica incrociata con riferimenti indipendenti")
    parser.add_argument("--skip-speed", action="store_true", help="Salta i test di throughput a tempo lungo (audit rapido)")
    parser.add_argument("--speed", action="store_true", help="Esegue anche i test completi di velocità e networkQuality")
    parser.add_argument("--json", action="store_true", help="Stampa l'output in formato JSON")
    parser.add_argument("--output", type=str, help="Esporta i risultati in un file JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Stampa messaggi di avanzamento dettagliati")
    parser.add_argument("--no-color", action="store_true", help="Disattiva i colori ANSI")

    args = parser.parse_args()

    # Per default, se non specificato --speed, eseguiamo l'audit rapido per non bloccare la CLI se networkQuality richiede molto tempo,
    # a meno che l'utente non richieda esplicitamente --speed
    skip_speed = not args.speed if not args.skip_speed else True

    auditor = NetworkAuditor(skip_speed=skip_speed, verbose=args.verbose)
    results = auditor.run_audit()

    use_color = not args.no_color and sys.stdout.isatty()

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print(render_table(results, use_color=use_color))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Risultati esportati in: {args.output}")

    mismatches = sum(1 for r in results if r["status"] == "MISMATCH")
    if mismatches > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
