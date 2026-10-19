"""
Identificazione di produttore/modello del router (gateway) e vendor da MAC.
Pipeline: OUI locale -> OUI online (con cache su disco) -> UPnP/SSDP -> pagina admin HTTP.
Solo libreria standard.
"""

import json
import os
import re
import socket
import urllib.request
import urllib.parse
import html
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

from core.oui_data import lookup_vendor
from core.platform_info import is_macos, is_linux, is_windows, run_cmd

CACHE_PATH = os.path.join(os.path.expanduser("~"), ".netprobe", "oui_cache.json")
_UNKNOWN = ("Sconosciuto", "Produttore non catalogato")


def _load_cache() -> Dict[str, str]:
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: Dict[str, str]) -> None:
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception:
        pass


def is_private_mac(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def resolve_vendor(mac: Optional[str], online: bool = True) -> str:
    """Vendor da MAC: DB locale, poi cache, poi API online (timeout breve)."""
    if not mac or mac.count(":") < 5:
        return "Sconosciuto"
    local = lookup_vendor(mac)
    if local not in _UNKNOWN:
        return local
    if is_private_mac(mac):
        return local
    prefix = ":".join(p.zfill(2) for p in mac.lower().split(":")[:3])
    cache = _load_cache()
    if prefix in cache:
        return cache[prefix]
    if not online:
        return local
    for url in (f"https://api.macvendors.com/{urllib.parse.quote(mac)}",
                f"https://www.macvendorlookup.com/api/v2/{prefix.replace(':', '')}"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetProbe/3.0"})
            with urllib.request.urlopen(req, timeout=2.5) as r:
                txt = r.read().decode("utf-8", "ignore").strip()
            if txt.startswith("["):
                txt = json.loads(txt)[0].get("company", "")
            if txt and "errors" not in txt[:20].lower():
                cache[prefix] = txt
                _save_cache(cache)
                return txt
        except Exception:
            continue
    return local


def _read_arp(gateway_ip: str) -> Optional[str]:
    if is_windows():
        code, out, _ = run_cmd(["arp", "-a"], timeout=2.5)
    elif is_linux():
        code, out, _ = run_cmd(["ip", "neigh"], timeout=2.5)
        if code != 0:
            code, out, _ = run_cmd(["arp", "-an"], timeout=2.5)
    else:
        code, out, _ = run_cmd(["arp", "-an"], timeout=2.5)
    for line in (out or "").splitlines():
        if re.search(r"(?<![\d.])" + re.escape(gateway_ip) + r"(?![\d.])", line):
            m = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
            if m:
                return ":".join(p.zfill(2) for p in m.group(1).lower().replace("-", ":").split(":"))
    return None


def get_gateway_mac(gateway_ip: str) -> Optional[str]:
    """Popola la cache ARP (TCP/UDP verso il gateway) e legge il MAC."""
    if not gateway_ip:
        return None
    mac = _read_arp(gateway_ip)
    if mac and mac != "02:00:00:00:00:00" and not mac.startswith("ff:"):
        return mac
    for port in (80, 443, 53):  # una connessione provoca la risoluzione ARP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            s.connect_ex((gateway_ip, port))
            s.close()
        except Exception:
            pass
        mac = _read_arp(gateway_ip)
        if mac and mac != "02:00:00:00:00:00" and not mac.startswith("ff:"):
            return mac

    # Fallback con adapter di sistema (es: system_profiler su macOS)
    try:
        from core.adapters import get_os_adapter
        adapter_mac = get_os_adapter().get_gateway_mac(gateway_ip)
        if adapter_mac:
            return adapter_mac
    except Exception:
        pass

    return None


def _upnp_info(gateway_ip: str) -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {}
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 1\r\nST: upnp:rootdevice\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.2)
    location = None
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        sock.sendto(msg, (gateway_ip, 1900))
        for _ in range(8):
            data, addr = sock.recvfrom(4096)
            if addr[0] == gateway_ip:
                m = re.search(r"(?im)^location:\s*(\S+)", data.decode("utf-8", "ignore"))
                if m:
                    location = m.group(1)
                    break
    except Exception:
        pass
    finally:
        sock.close()
    if not location:
        return info
    try:
        with urllib.request.urlopen(location, timeout=2.5) as r:
            root = ET.fromstring(r.read())
        ns = {"d": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        def g(tag):
            el = root.find(f".//d:{tag}", ns) if ns else root.find(f".//{tag}")
            return el.text.strip() if el is not None and el.text else None
        info = {"manufacturer": g("manufacturer"), "model": g("modelName"),
                "friendly_name": g("friendlyName"), "model_number": g("modelNumber")}
    except Exception:
        pass
    return info


def _http_info(gateway_ip: str) -> Dict[str, Optional[str]]:
    for scheme in ("http", "https"):
        try:
            import ssl
            ctx = ssl._create_unverified_context()
            req = urllib.request.Request(f"{scheme}://{gateway_ip}/", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=2.0, context=ctx) as r:
                server = r.headers.get("Server")
                body = r.read(20000).decode("utf-8", "ignore")
            t = re.search(r"(?is)<title>\s*(.*?)\s*</title>", body)
            return {"http_server": server, "http_title": html.unescape(t.group(1))[:80] if t else None}
        except Exception as e:
            hdr = getattr(e, "headers", None)  # es. 401 con realm
            if hdr is not None:
                realm = hdr.get("WWW-Authenticate")
                return {"http_server": hdr.get("Server"), "http_title": realm}
            continue
    return {}


def identify_router(gateway_ip: Optional[str], gateway_mac: Optional[str] = None) -> Dict[str, Any]:
    """Ritorna produttore, modello e fonti per il gateway riconciliando MAC e servizi."""
    res: Dict[str, Any] = {
        "ip": gateway_ip,
        "mac": gateway_mac,
        "vendor": "Sconosciuto",
        "vendor_source": "N/D",
        "model": None,
        "sources": []
    }
    if not gateway_ip:
        return res
    if not gateway_mac:
        gateway_mac = get_gateway_mac(gateway_ip)
        res["mac"] = gateway_mac

    oui_vendor = resolve_vendor(gateway_mac) if gateway_mac else "Sconosciuto"
    if oui_vendor not in _UNKNOWN:
        res["vendor"] = oui_vendor
        res["vendor_source"] = "OUI"
        res["sources"].append("OUI")

    upnp = _upnp_info(gateway_ip)
    if upnp.get("manufacturer"):
        upnp_m = upnp["manufacturer"]
        res["sources"].append("UPnP")
        if res["vendor"] in _UNKNOWN:
            res["vendor"] = upnp_m
            res["vendor_source"] = "UPnP"
        elif upnp_m.lower() not in res["vendor"].lower():
            res["sources"].append(f"UPnP-Vendor:{upnp_m}")

    if upnp.get("model") or upnp.get("friendly_name"):
        res["model"] = upnp.get("model") or upnp.get("friendly_name")

    http = _http_info(gateway_ip)
    if http:
        res["http_server"] = http.get("http_server")
        res["http_title"] = http.get("http_title")
        http_vendor = None
        if http.get("http_server"):
            m = re.match(r"([A-Za-z][A-Za-z0-9-]+)", http["http_server"])
            if m and m.group(1).lower() not in ("http", "server", "httpd", "lighttpd", "nginx", "apache", "boa", "mini_httpd", "micro_httpd", "goahead-webs"):
                http_vendor = m.group(1)

        if http_vendor:
            res["sources"].append("HTTP")
            if res["vendor"] in _UNKNOWN:
                res["vendor"] = http_vendor
                res["vendor_source"] = "HTTP"
            elif http_vendor.lower() in res["vendor"].lower():
                res["sources"].append("HTTP-Confermato")
            else:
                res["sources"].append(f"HTTP-Vendor:{http_vendor}")

        if not res["model"] and http.get("http_title"):
            res["model"] = http["http_title"]

    return res

