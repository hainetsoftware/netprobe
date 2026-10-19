"""
Modulo di Riconoscimento Avanzato dell'Internet eXchange (IXP),
PeeringDB Intelligence, Multi-Hop Traceroute e Hop 2 (BNG) Deep Probing.

Funzionalità:
- Embedded Peering LAN Subnet Database per tutti i principali IXP italiani ed europei
  (MIX Milano, NAMEX Roma, TOP-IX Torino, MINAP Milano, VSIX Padova, TIX Firenze,
   DE-CIX Francoforte, AMS-IX Amsterdam, France-IX, LINX Londra, ecc.)
- Diagnostic Multi-Target Traceroute (cross-platform macOS/Linux/Windows, no root required)
- Match deterministico subnet Peering LAN (100% certezza crittografica/topologica)
- Hop Reverse DNS Pattern Matching (*.mix-it.net, *.namex.it, *.top-ix.org, *.de-cix.net, POP regionali)
- Query API PeeringDB con caching locale su ~/.netprobe/peeringdb_cache.json
- Hop 2 BNG Burst Probing (30 campioni: min_ms, median_ms, p95_ms, jitter IPDV, tail latency)
- Classificazione Public IXP Peering vs Direct PNI (Private Network Interconnect)
"""

import math
import os
import sys
import re
import json
import time
import socket
import statistics
import ipaddress
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional, Tuple

from core.platform_info import is_macos, is_linux, is_windows, run_cmd


# Mappatura generale e verificabile dei PoP Anycast / Interconnection Hubs (IATA / Codici Città)
ANYCAST_COLO_HUBS: Dict[str, Dict[str, Any]] = {
    "MXP": {
        "city": "Milano",
        "ixp_name": "Milano (Hub Caldera / MIX) - Interconnessione PNI / Transit",
        "facility": "Polo Tecnologico Caldera, Via Caldera 21 (Milano)",
        "coordinates": {"lat": 45.4756, "lon": 9.1064},
        "country": "Italia"
    },
    "LIN": {
        "city": "Milano",
        "ixp_name": "Milano (Hub Caldera / MIX) - Interconnessione PNI / Transit",
        "facility": "Polo Tecnologico Caldera, Via Caldera 21 (Milano)",
        "coordinates": {"lat": 45.4756, "lon": 9.1064},
        "country": "Italia"
    },
    "FCO": {
        "city": "Roma",
        "ixp_name": "Roma (Hub NaMeX / Tiburtina) - Interconnessione PNI / Transit",
        "facility": "Polo Tecnologico Roma (NaMeX / Via dei Luxardo)",
        "coordinates": {"lat": 41.9028, "lon": 12.4964},
        "country": "Italia"
    },
    "CIA": {
        "city": "Roma",
        "ixp_name": "Roma (Hub NaMeX / Tiburtina) - Interconnessione PNI / Transit",
        "facility": "Polo Tecnologico Roma (NaMeX / Via dei Luxardo)",
        "coordinates": {"lat": 41.9028, "lon": 12.4964},
        "country": "Italia"
    },
    "TRN": {
        "city": "Torino",
        "ixp_name": "Torino (Hub TOP-IX / CSI) - Interconnessione PNI / Transit",
        "facility": "CSI Piemonte, Corso Unione Sovietica 216 (Torino)",
        "coordinates": {"lat": 45.0392, "lon": 7.6496},
        "country": "Italia"
    },
    "BLQ": {
        "city": "Bologna",
        "ixp_name": "Bologna (Hub CINECA / Lepida) - Interconnessione PNI / Transit",
        "facility": "CINECA Data Center, Casalecchio di Reno (Bologna)",
        "coordinates": {"lat": 44.4949, "lon": 11.3426},
        "country": "Italia"
    },
    "FLR": {
        "city": "Firenze",
        "ixp_name": "Firenze (Hub TIX / Cascine) - Interconnessione PNI / Transit",
        "facility": "TIX, Cascine (Firenze)",
        "coordinates": {"lat": 43.7696, "lon": 11.2558},
        "country": "Italia"
    },
    "NAP": {
        "city": "Napoli",
        "ixp_name": "Napoli (Hub Federico II / CINECA) - Interconnessione PNI / Transit",
        "facility": "Data Center Monte Sant'Angelo (Napoli)",
        "coordinates": {"lat": 40.8518, "lon": 14.2681},
        "country": "Italia"
    },
    "PMO": {
        "city": "Palermo",
        "ixp_name": "Palermo (Hub Open Hub Med) - Interconnessione PNI / Transit",
        "facility": "Open Hub Med (OHM), Carini (Palermo)",
        "coordinates": {"lat": 38.1157, "lon": 13.3615},
        "country": "Italia"
    },
    "VCE": {
        "city": "Padova / Venezia",
        "ixp_name": "Padova / Venezia (Hub VSIX) - Interconnessione PNI / Transit",
        "facility": "VSIX Università di Padova",
        "coordinates": {"lat": 45.4064, "lon": 11.8768},
        "country": "Italia"
    },
    "PDV": {
        "city": "Padova / Venezia",
        "ixp_name": "Padova / Venezia (Hub VSIX) - Interconnessione PNI / Transit",
        "facility": "VSIX Università di Padova",
        "coordinates": {"lat": 45.4064, "lon": 11.8768},
        "country": "Italia"
    },
    "FRA": {
        "city": "Francoforte",
        "ixp_name": "Francoforte (Hub DE-CIX) - Interconnessione PNI / Transit",
        "facility": "Kleyerstrasse / Interxion Campus (Francoforte)",
        "coordinates": {"lat": 50.1109, "lon": 8.6821},
        "country": "Germania"
    },
    "AMS": {
        "city": "Amsterdam",
        "ixp_name": "Amsterdam (Hub AMS-IX) - Interconnessione PNI / Transit",
        "facility": "Science Park Amsterdam",
        "coordinates": {"lat": 52.3702, "lon": 4.8952},
        "country": "Paesi Bassi"
    },
    "MRS": {
        "city": "Marsiglia",
        "ixp_name": "Marsiglia (Hub Interxion MRS) - Interconnessione PNI / Transit",
        "facility": "Interxion MRS1/MRS2 (Marsiglia)",
        "coordinates": {"lat": 43.2965, "lon": 5.3698},
        "country": "Francia"
    },
    "CDG": {
        "city": "Parigi",
        "ixp_name": "Parigi (Hub France-IX / Telehouse) - Interconnessione PNI / Transit",
        "facility": "Telehouse Voltaire (Parigi)",
        "coordinates": {"lat": 48.8566, "lon": 2.3522},
        "country": "Francia"
    },
    "ZRH": {
        "city": "Zurigo",
        "ixp_name": "Zurigo (Hub SwissIX) - Interconnessione PNI / Transit",
        "facility": "Equinix Zurich ZH1/ZH2",
        "coordinates": {"lat": 47.3769, "lon": 8.5417},
        "country": "Svizzera"
    },
    "LHR": {
        "city": "Londra",
        "ixp_name": "Londra (Hub LINX / Telehouse) - Interconnessione PNI / Transit",
        "facility": "Telehouse Docklands / Equinix LD4 (Londra)",
        "coordinates": {"lat": 51.5074, "lon": -0.1278},
        "country": "Regno Unito"
    }
}

CITY_TOKEN_MAP = {
    "mil": "MXP", "mxp": "MXP", "lin": "LIN", "caldera": "MXP", "milan": "MXP", "milano": "MXP",
    "rom": "FCO", "fco": "FCO", "namex": "FCO", "rome": "FCO", "roma": "FCO",
    "trn": "TRN", "torino": "TRN", "turin": "TRN",
    "blq": "BLQ", "bologna": "BLQ",
    "flr": "FLR", "firenze": "FLR", "florence": "FLR",
    "pdv": "PDV", "padova": "PDV", "vce": "VCE", "venezia": "VCE", "venice": "VCE",
    "nap": "NAP", "napoli": "NAP", "naples": "NAP",
    "pmo": "PMO", "palermo": "PMO",
    "fra": "FRA", "frankfurt": "FRA", "francoforte": "FRA",
    "ams": "AMS", "amsterdam": "AMS",
    "zrh": "ZRH", "zurich": "ZRH", "zurigo": "ZRH",
    "mrs": "MRS", "marseille": "MRS", "marsiglia": "MRS",
    "lon": "LHR", "london": "LHR", "londra": "LHR", "lhr": "LHR",
    "par": "CDG", "paris": "CDG", "parigi": "CDG", "cdg": "CDG"
}

_ASN_PREFIX_CACHE: Dict[str, Tuple[Optional[int], Optional[str]]] = {}
_ASN_NAME_CACHE: Dict[int, str] = {}
_RDNS_CACHE: Dict[str, Optional[str]] = {}

# Minimal offline fallback ONLY if DNS resolution is unreachable
OFFLINE_ASN_FALLBACK = [
    (ipaddress.ip_network("195.22.0.0/16"), 6762, "Telecom Italia Sparkle"),
    (ipaddress.ip_network("217.29.64.0/18"), 6762, "Telecom Italia Sparkle"),
    (ipaddress.ip_network("82.84.0.0/14"), 3269, "Telecom Italia"),
    (ipaddress.ip_network("82.88.0.0/13"), 3269, "Telecom Italia"),
    (ipaddress.ip_network("82.91.0.0/16"), 3269, "Telecom Italia"),
    (ipaddress.ip_network("217.200.0.0/13"), 3269, "Telecom Italia"),
    (ipaddress.ip_network("188.114.96.0/20"), 13335, "Cloudflare"),
    (ipaddress.ip_network("162.158.0.0/15"), 13335, "Cloudflare"),
    (ipaddress.ip_network("172.64.0.0/13"), 13335, "Cloudflare"),
    (ipaddress.ip_network("104.16.0.0/12"), 13335, "Cloudflare"),
    (ipaddress.ip_network("1.1.1.0/24"), 13335, "Cloudflare"),
    (ipaddress.ip_network("142.250.0.0/15"), 15169, "Google"),
    (ipaddress.ip_network("172.217.0.0/16"), 15169, "Google"),
    (ipaddress.ip_network("8.8.8.0/24"), 15169, "Google"),
    (ipaddress.ip_network("151.0.0.0/12"), 1267, "Wind Tre"),
    (ipaddress.ip_network("2.32.0.0/11"), 12874, "Fastweb"),
    (ipaddress.ip_network("93.32.0.0/11"), 12874, "Fastweb"),
    (ipaddress.ip_network("91.80.0.0/15"), 30722, "Vodafone Italia"),
    (ipaddress.ip_network("83.224.0.0/14"), 30722, "Vodafone Italia"),
    (ipaddress.ip_network("185.25.0.0/16"), 208643, "Iliad Italia"),
    (ipaddress.ip_network("88.149.128.0/17"), 8612, "Eolo SpA"),
    (ipaddress.ip_network("109.168.0.0/18"), 42689, "OpNet / Linkem"),
    (ipaddress.ip_network("145.224.0.0/16"), 14593, "Starlink"),
    (ipaddress.ip_network("98.96.0.0/14"), 14593, "Starlink")
]

OFFLINE_ASN_NAMES = {
    3269: "Telecom Italia",
    6762: "Telecom Italia Sparkle",
    1267: "Wind Tre",
    12874: "Fastweb",
    30722: "Vodafone Italia",
    208643: "Iliad Italia",
    8612: "Eolo SpA",
    42689: "OpNet / Linkem",
    14593: "Starlink",
    13335: "Cloudflare",
    15169: "Google",
    29119: "Dimensione",
    198371: "PianetaFibra",
    31034: "Aruba",
    16008: "Spadhausen"
}

EMBEDDED_ASN_PEERING_HUBS = {
    3269: [
        {"name": "MIX-IT (Milano)", "city": "Milano"},
        {"name": "NaMeX (Roma)", "city": "Roma"},
        {"name": "TOP-IX (Torino)", "city": "Torino"},
        {"name": "TIX (Firenze)", "city": "Firenze"}
    ],
    6762: [
        {"name": "MIX-IT (Milano)", "city": "Milano"},
        {"name": "NaMeX (Roma)", "city": "Roma"},
        {"name": "DE-CIX Frankfurt", "city": "Francoforte"},
        {"name": "LINX London", "city": "Londra"}
    ],
    1267: [
        {"name": "MIX-IT (Milano)", "city": "Milano"},
        {"name": "NaMeX (Roma)", "city": "Roma"},
        {"name": "TOP-IX (Torino)", "city": "Torino"},
        {"name": "VSIX (Padova)", "city": "Padova"}
    ],
    12874: [
        {"name": "MIX-IT (Milano)", "city": "Milano"},
        {"name": "NaMeX (Roma)", "city": "Roma"},
        {"name": "TOP-IX (Torino)", "city": "Torino"},
        {"name": "VSIX (Padova)", "city": "Padova"},
        {"name": "C-IX (Catania)", "city": "Catania"}
    ],
    30722: [
        {"name": "MIX-IT (Milano)", "city": "Milano"},
        {"name": "NaMeX (Roma)", "city": "Roma"},
        {"name": "TOP-IX (Torino)", "city": "Torino"}
    ],
    208643: [
        {"name": "MIX-IT (Milano)", "city": "Milano"},
        {"name": "NaMeX (Roma)", "city": "Roma"}
    ]
}


def probe_cloudflare_trace(timeout_s: float = 1.5) -> Dict[str, str]:
    """
    Sonda leggera HTTP verso https://1.1.1.1/cdn-cgi/trace
    (fallback https://speed.cloudflare.com/cdn-cgi/trace).
    Estrae campi chiave inclusi colo (IATA PoP), ip, loc, ecc.
    """
    urls = [
        "https://1.1.1.1/cdn-cgi/trace",
        "https://speed.cloudflare.com/cdn-cgi/trace"
    ]
    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "NetProbe/2.0 (Anycast POP Intelligence)"}
            )
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                if resp.status == 200:
                    raw_text = resp.read().decode("utf-8", errors="replace")
                    data = {}
                    for line in raw_text.splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            data[k.strip()] = v.strip()
                    if "colo" in data:
                        return data
        except Exception:
            continue
    return {}


def lookup_asn_name(asn: int) -> str:
    """Risolve dinamicamente il nome dell'organizzazione AS via Team Cymru DNS con cache in memoria."""
    if asn in _ASN_NAME_CACHE:
        return _ASN_NAME_CACHE[asn]
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.timeout = 1.0
        res.lifetime = 1.0
        ans = res.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        for rdata in ans:
            txt = "".join([b.decode("utf-8", errors="replace") if isinstance(b, bytes) else str(b) for b in rdata.strings])
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 5:
                raw_name = parts[4].split(",", 1)[0].strip()
                if " - " in raw_name:
                    raw_name = raw_name.split(" - ", 1)[1].strip()
                _ASN_NAME_CACHE[asn] = raw_name
                return raw_name
    except Exception:
        pass
    fallback = OFFLINE_ASN_NAMES.get(asn, f"AS{asn}")
    _ASN_NAME_CACHE[asn] = fallback
    return fallback


def lookup_ip_asn(ip_str: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Risolve dinamicamente ASN e nome dell'organizzazione di un IP pubblico
    tramite Team Cymru DNS origin con caching per prefisso /24.
    """
    if not ip_str or ip_str == "*":
        return None, None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
            return None, None
    except ValueError:
        return None, None

    prefix_key = ip_str.rsplit(".", 1)[0] + ".0/24" if "." in ip_str else ip_str
    if prefix_key in _ASN_PREFIX_CACHE:
        return _ASN_PREFIX_CACHE[prefix_key]

    # 1. Team Cymru DNS origin lookup
    try:
        rev = ".".join(reversed(ip_str.split("."))) + ".origin.asn.cymru.com"
        import dns.resolver
        res = dns.resolver.Resolver()
        res.timeout = 1.0
        res.lifetime = 1.0
        ans = res.resolve(rev, "TXT")
        for rdata in ans:
            txt = "".join([b.decode("utf-8", errors="replace") if isinstance(b, bytes) else str(b) for b in rdata.strings])
            parts = [p.strip() for p in txt.split("|")]
            if parts and parts[0].isdigit():
                asn_num = int(parts[0])
                asn_name = lookup_asn_name(asn_num)
                _ASN_PREFIX_CACHE[prefix_key] = (asn_num, asn_name)
                return asn_num, asn_name
    except Exception:
        pass

    # 2. Offline fallback
    for net, asn_num, name in OFFLINE_ASN_FALLBACK:
        if ip_obj in net:
            _ASN_PREFIX_CACHE[prefix_key] = (asn_num, name)
            return asn_num, name

    _ASN_PREFIX_CACHE[prefix_key] = (None, None)
    return None, None


def lookup_ip_rdns(ip_str: str, timeout_s: float = 1.0) -> Optional[str]:
    """Risolve dinamicamente l'hostname PTR di un IP con timeout limitato (<= 1.0s)."""
    if not ip_str or ip_str == "*":
        return None
    if ip_str in _RDNS_CACHE:
        return _RDNS_CACHE[ip_str]
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            _RDNS_CACHE[ip_str] = None
            return None
    except ValueError:
        return None

    try:
        import dns.resolver, dns.reversename
        rev_name = dns.reversename.from_address(ip_str)
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_s
        resolver.lifetime = timeout_s
        ans = resolver.resolve(rev_name, "PTR")
        for rdata in ans:
            ptr = str(rdata).rstrip(".")
            if ptr:
                _RDNS_CACHE[ip_str] = ptr
                return ptr
    except Exception:
        pass

    try:
        orig = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout_s)
        try:
            ptr = socket.gethostbyaddr(ip_str)[0]
            _RDNS_CACHE[ip_str] = ptr
            return ptr
        finally:
            socket.setdefaulttimeout(orig)
    except Exception:
        pass

    _RDNS_CACHE[ip_str] = None
    return None


def build_access_profile_from_hops(
    hops: List[Dict[str, Any]],
    target: Optional[str] = None,
    egress_ip: Optional[str] = None,
    wan_asn: Optional[int] = None,
    dest_asn: Optional[int] = None,
    ixp_evidence: Optional[Dict[str, Any]] = None,
    matched_ixp: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Costruisce l'access_profile salto per salto con pavimenti (floors), incrementi
    e classificazione dinamica dei ruoli per ogni hop:
    - Ruoli canonici: 'Gateway locale', 'Primo salto oltre il CPE', 'Destinazione', o None (retrocompatibilità asserzioni)
    - role_note: Descrizione fisica arricchita (CPE, aggregazione, core, handoff PNI, edge).
    """
    profile_hops = []
    prev_floor = None
    first_isp_hop = None
    first_public_hop = None

    sorted_hops = sorted(hops, key=lambda x: x.get("hop", 0))

    for h in sorted_hops:
        hop_num = h.get("hop", 0)
        primary_ip = h.get("ip") or "*"
        ips = h.get("ips") or ([primary_ip] if primary_ip != "*" else [])
        rtts = h.get("rtts")
        if rtts is None:
            if h.get("rtt_ms") is not None:
                rtts = [float(h["rtt_ms"])]
            else:
                rtts = []

        is_priv = False
        is_cgnat = False
        if primary_ip != "*":
            try:
                ip_obj = ipaddress.ip_address(primary_ip)
                is_priv = ip_obj.is_private
                is_cgnat = ip_obj in ipaddress.ip_network("100.64.0.0/10")
            except ValueError:
                pass

        responds = len(rtts) > 0
        if responds:
            min_ms = round(min(rtts), 2)
            med_ms = round(statistics.median(rtts), 2)
            sorted_r = sorted(rtts)
            n_s = len(sorted_r)
            idx75 = min(n_s - 1, max(0, math.ceil(n_s * 0.75) - 1))
            idx25 = min(n_s - 1, max(0, math.ceil(n_s * 0.25) - 1))
            iqr_ms = round(max(0.0, sorted_r[idx75] - sorted_r[idx25]), 2)
            floor_ms = min_ms
            if prev_floor is not None and floor_ms < prev_floor:
                floor_inc = None
            else:
                floor_inc = round(floor_ms - (prev_floor or 0.0), 2)
            prev_floor = floor_ms
        else:
            min_ms = None
            med_ms = None
            iqr_ms = None
            floor_ms = None
            floor_inc = None

        # Risoluzione ASN dinamica per hop pubblici
        hop_asn = h.get("asn")
        hop_asn_name = h.get("asn_name")
        if hop_asn is None and responds and not is_priv and not is_cgnat:
            hop_asn, hop_asn_name = lookup_ip_asn(primary_ip)
            h["asn"] = hop_asn
            h["asn_name"] = hop_asn_name

        as_tag = f"AS{hop_asn} {hop_asn_name}" if (hop_asn and hop_asn_name) else (f"AS{hop_asn}" if hop_asn else "")
        as_suffix = f" [{as_tag}]" if as_tag else ""

        # Assegnazione dinamica di role (canonico) e role_note (dettagliato)
        if hop_num == 1:
            role = "Gateway locale"
            role_note = "Gateway locale (CPE)"
        elif not responds:
            role = None
            role_note = "Nessuna risposta ICMP (Hop silenzioso)"
        elif is_priv or is_cgnat:
            if responds and hop_num >= 2 and first_isp_hop is None:
                role = "Primo salto oltre il CPE"
                role_note = "Primo nodo di raccolta oltre il CPE (Accesso / BRAS / CGNAT)" if is_cgnat else "Primo nodo di accesso oltre il CPE (DSLAM/OLT/BRAS)"
            else:
                role = None
                cgnat_tag = " [CGNAT RFC 6598]" if is_cgnat else " (RFC 1918)"
                role_note = f"Rete di aggregazione / Backhaul interno ISP{cgnat_tag}"
        elif responds and not is_priv and not is_cgnat:
            is_dest = (target and primary_ip == target) or (dest_asn and hop_asn == dest_asn and hop_num == sorted_hops[-1].get("hop")) or (primary_ip == "1.1.1.1")
            is_egress = (egress_ip and primary_ip == egress_ip)
            is_ixp = (ixp_evidence and primary_ip == ixp_evidence.get("ip"))

            if is_ixp:
                role = "LAN Peering IXP"
                ixp_label = matched_ixp.get("name") if matched_ixp else "IXP"
                role_note = f"LAN di Peering Pubblico IXP [{ixp_label}]"
            elif is_dest:
                role = "Destinazione"
                role_note = f"Destinazione Anycast Edge{as_suffix or ' [AS13335 Cloudflare]'}"
            elif is_egress:
                role = "Handoff PNI"
                role_note = f"Handoff PNI / Confine AS{as_suffix}"
            elif first_public_hop is None:
                role = "Primo salto pubblico"
                role_note = f"Primo nodo pubblico responsivo (Backbone / Core){as_suffix}"
            elif wan_asn and hop_asn == wan_asn:
                role = None
                role_note = f"Rete Core / Backbone Operatore{as_suffix}"
            elif dest_asn and hop_asn == dest_asn:
                role = None
                role_note = f"Rete Anycast Edge / Transit Inbound{as_suffix}"
            else:
                role = None
                role_note = f"Transito Upstream / Carrier Tier-1{as_suffix}" if as_suffix else "Transito / Peering"
        else:
            role = None
            role_note = ""

        hop_entry = {
            "hop": hop_num,
            "ip": primary_ip,
            "ips": ips,
            "rtts": rtts,
            "probe_count": len(rtts),
            "min_ms": min_ms,
            "median_ms": med_ms,
            "iqr_ms": iqr_ms,
            "flags": {
                "private": is_priv,
                "cgnat": is_cgnat,
                "responds_to_ping": responds
            },
            "floor_ms": floor_ms,
            "floor_increment_ms": floor_inc,
            "role": role,
            "role_note": role_note,
            "asn": hop_asn,
            "asn_name": hop_asn_name
        }
        profile_hops.append(hop_entry)

        if responds and hop_num >= 2 and first_isp_hop is None:
            first_isp_hop = {
                "hop": hop_num,
                "ip": primary_ip,
                "floor_ms": floor_ms,
                "floor_increment_ms": floor_inc,
                "role": "Primo salto oltre il CPE",
                "role_note": role_note
            }

        if responds and not is_priv and not is_cgnat and first_public_hop is None:
            first_public_hop = {
                "hop": hop_num,
                "ip": primary_ip,
                "floor_ms": floor_ms,
                "floor_increment_ms": floor_inc,
                "asn": hop_asn,
                "asn_name": hop_asn_name
            }

    return {
        "uncalibrated": True,
        "hops": profile_hops,
        "first_isp_hop": first_isp_hop,
        "first_public_hop": first_public_hop
    }


class IXPAnalyzer:
    # Database autorevole delle Peering LAN Subnet (IPv4 e IPv6) dei principali IXP
    IXP_SUBNETS = [
        # --- ITALIA ---
        {
            "id": "mix-it",
            "name": "MIX - Milan Internet eXchange",
            "facility": "Campus Caldera, Via Caldera 21",
            "city": "Milano",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 45.4642, "lon": 9.1028},
            "subnets": ["217.29.66.0/23", "217.29.68.0/24", "2001:7f8:15::/64"],
            "rdns_patterns": [r"\bmix-it\.net\b", r"\bmix\.it\b", r"\bmilano-mix\b"]
        },
        {
            "id": "namex",
            "name": "NAMEX - Nautilus Mediterranean eXchange",
            "facility": "Via dei Tizii 6 / Cineca",
            "city": "Roma",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 41.8988, "lon": 12.5186},
            "subnets": ["193.201.28.0/24", "185.1.40.0/23", "2001:7f8:1b::/64"],
            "rdns_patterns": [r"\bnamex\.it\b", r"\broma-namex\b"]
        },
        {
            "id": "top-ix",
            "name": "TOP-IX - Torino Piemonte Internet eXchange",
            "facility": "CSI Piemonte, Corso Unione Sovietica 216",
            "city": "Torino",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 45.0392, "lon": 7.6496},
            "subnets": ["194.116.86.0/24", "194.116.96.0/24", "2001:7f8:53::/64"],
            "rdns_patterns": [r"\btop-ix\.org\b", r"\btorino-topix\b"]
        },
        {
            "id": "minap",
            "name": "MINAP - Milano Neutral Access Point",
            "facility": "Milano DC",
            "city": "Milano",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 45.4654, "lon": 9.1859},
            "subnets": ["185.1.114.0/24", "2001:7f8:c5::/64"],
            "rdns_patterns": [r"\bminap\.it\b"]
        },
        {
            "id": "vsix",
            "name": "VSIX - Venice / Padua Internet eXchange",
            "facility": "Università di Padova, Viale Trieste",
            "city": "Padova",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 45.4064, "lon": 11.8768},
            "subnets": ["194.242.224.0/24", "2001:7f8:56::/64"],
            "rdns_patterns": [r"\bvsix\.it\b"]
        },
        {
            "id": "tix",
            "name": "TIX - Tuscany Internet eXchange",
            "facility": "Firenze Cascine",
            "city": "Firenze",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 43.7696, "lon": 11.2558},
            "subnets": ["193.42.140.0/24", "2001:7f8:1a::/64"],
            "rdns_patterns": [r"\btix\.it\b"]
        },
        {
            "id": "c-ix",
            "name": "C-IX - Catania Internet eXchange",
            "facility": "Catania",
            "city": "Catania",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 37.5079, "lon": 15.0873},
            "subnets": ["185.1.134.0/24"],
            "rdns_patterns": [r"\bc-ix\.it\b"]
        },
        # --- EUROPA ---
        {
            "id": "de-cix-fra",
            "name": "DE-CIX Frankfurt",
            "facility": "Kleyerstrasse / Interxion Campus",
            "city": "Francoforte",
            "country": "Germania",
            "country_code": "DE",
            "coordinates": {"lat": 50.1109, "lon": 8.6821},
            "subnets": ["80.81.192.0/20", "80.81.196.0/22", "2001:7f8::/64"],
            "rdns_patterns": [r"\bde-cix\.net\b", r"\bdecix\b"]
        },
        {
            "id": "ams-ix",
            "name": "AMS-IX - Amsterdam Internet Exchange",
            "facility": "Science Park Amsterdam",
            "city": "Amsterdam",
            "country": "Paesi Bassi",
            "country_code": "NL",
            "coordinates": {"lat": 52.3702, "lon": 4.8952},
            "subnets": ["80.249.208.0/21", "2001:7f8:1::/64"],
            "rdns_patterns": [r"\bams-ix\.net\b"]
        },
        {
            "id": "france-ix-par",
            "name": "France-IX Paris",
            "facility": "Telehouse Voltaire",
            "city": "Parigi",
            "country": "Francia",
            "country_code": "FR",
            "coordinates": {"lat": 48.8566, "lon": 2.3522},
            "subnets": ["37.49.236.0/22", "2001:7f8:54::/64"],
            "rdns_patterns": [r"\bfrance-ix\.net\b"]
        },
        {
            "id": "france-ix-mrs",
            "name": "France-IX Marseille",
            "facility": "Interxion MRS1/MRS2",
            "city": "Marsiglia",
            "country": "Francia",
            "country_code": "FR",
            "coordinates": {"lat": 43.2965, "lon": 5.3698},
            "subnets": ["37.49.232.0/22"],
            "rdns_patterns": [r"\bmrs\.france-ix\.net\b"]
        },
        {
            "id": "linx-lon",
            "name": "LINX - London Internet Exchange",
            "facility": "Equinix LD4 / Telehouse Docklands",
            "city": "Londra",
            "country": "Regno Unito",
            "country_code": "GB",
            "coordinates": {"lat": 51.5074, "lon": -0.1278},
            "subnets": ["195.66.224.0/21", "195.66.226.0/23", "2001:7f8:4::/64"],
            "rdns_patterns": [r"\blinx\.net\b"]
        },
        {
            "id": "swiss-ix",
            "name": "SwissIX",
            "facility": "Zurigo",
            "city": "Zurigo",
            "country": "Svizzera",
            "country_code": "CH",
            "coordinates": {"lat": 47.3769, "lon": 8.5417},
            "subnets": ["91.206.52.0/24", "2001:7f8:24::/64"],
            "rdns_patterns": [r"\bswissix\.ch\b"]
        }
    ]

    # Pre-compila gli oggetti ip_network
    _compiled_networks = []
    for _ixp in IXP_SUBNETS:
        _nets = []
        for _s in _ixp["subnets"]:
            try:
                _nets.append(ipaddress.ip_network(_s))
            except Exception:
                pass
        _compiled_networks.append((_ixp, _nets))

    def __init__(self, cache_dir: Optional[str] = None):
        if not cache_dir:
            self.cache_dir = os.path.expanduser("~/.netprobe")
        else:
            self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.peeringdb_cache_file = os.path.join(self.cache_dir, "peeringdb_cache.json")

    def analyze_ixp_and_bng(self, wan_data: Dict[str, Any], progress_cb=None, anycast_colo: Optional[str] = None) -> Dict[str, Any]:
        """
        Esegue l'analisi completa:
        1. Query Anycast PoP (Cloudflare trace) se WAN attiva
        2. Traceroute diagnostico multi-target (edge targets: Cloudflare 1.1.1.1, Google 8.8.8.8)
        3. Risoluzione dinamica ASN & rDNS per ogni hop
        4. Burst ping dell'Hop 2 (BNG / First Provider Hop)
        5. Match deterministico subnet IXP Peering LAN
        6. Query PeeringDB per l'ASN utente
        7. Classificazione a 3 livelli: Tier 1 (Public IXP), Tier 2 (Verified PNI), Tier 3 (Unidentified)
        """
        # 1. Anycast Trace PoP
        if anycast_colo is None:
            anycast_colo = wan_data.get("colo") or (wan_data.get("cloudflare_trace") or {}).get("colo")
            if not anycast_colo and (wan_data.get("asn") or wan_data.get("public_ipv4") or wan_data.get("probe_anycast")):
                if progress_cb:
                    progress_cb("Verifica PoP Anycast Cloudflare cdn-cgi/trace...", 10)
                cf_trace = probe_cloudflare_trace(timeout_s=1.5)
                anycast_colo = cf_trace.get("colo")

        if progress_cb:
            progress_cb("Esecuzione traceroute multi-probe per profilo di accesso...", 15)

        # 2. Multi-probe Traceroute
        is_test_env = bool(os.environ.get("NETPROBE_SPEED_HOST") or os.environ.get("NETPROBE_QUICK_TRACEROUTE"))
        max_hops = 3 if is_test_env else 12
        probes = 1 if is_test_env else 8

        target = "1.1.1.1"
        access_profile = self.measure_access_profile(target, max_hops=max_hops, probes=probes)
        hops = access_profile.get("hops") or []
        if not is_test_env and (not hops or len([h for h in hops if h.get("flags", {}).get("responds_to_ping")]) < 2):
            target = "8.8.8.8"
            access_profile = self.measure_access_profile(target, max_hops=12, probes=8)
            hops = access_profile.get("hops") or []

        # Risoluzione dinamica ASN e rDNS per tutti gli hop pubblici responsivi
        for h in hops:
            h_ip = h.get("ip")
            if not h_ip or h_ip == "*":
                continue
            is_priv = False
            try:
                ip_obj = ipaddress.ip_address(h_ip)
                is_priv = ip_obj.is_private or ip_obj.is_loopback or (ip_obj in ipaddress.ip_network("100.64.0.0/10"))
            except ValueError:
                is_priv = True
            if not is_priv and (h.get("rtts") or h.get("rtt_ms") is not None):
                if h.get("asn") is None:
                    asn_num, asn_name = lookup_ip_asn(h_ip)
                    h["asn"] = asn_num
                    h["asn_name"] = asn_name
                if h.get("rdns") is None:
                    h["rdns"] = lookup_ip_rdns(h_ip, timeout_s=0.8)

        # 3. Individuazione e Burst Ping di Hop 2 (BNG / First Hop Provider)
        hop2_ip, hop2_metrics = self._probe_hop2_bng(hops, progress_cb=progress_cb)
        path_mtu = self.probe_path_mtu()

        # 4. Match Subnet Peering LAN IXP
        matched_ixp, match_evidence = self._find_ixp_in_hops(hops)

        # 5. PeeringDB lookup per ASN utente
        user_asn = wan_data.get("asn") or ""
        asn_clean = re.sub(r"[^\d]", "", str(user_asn))
        peeringdb_info = {}
        if asn_clean:
            asn_int = int(asn_clean)
            if progress_cb:
                progress_cb(f"Verifica strutture di peering PeeringDB per AS{asn_clean}...", 35)
            peeringdb_info = self.get_peeringdb_for_asn(asn_int)
            if not peeringdb_info and asn_int in EMBEDDED_ASN_PEERING_HUBS:
                peeringdb_info = {
                    "asn": asn_int,
                    "facilities": EMBEDDED_ASN_PEERING_HUBS[asn_int]
                }

        # 6. Classificazione IXP / PNI
        classification = self._classify_exchange(
            matched_ixp=matched_ixp,
            match_evidence=match_evidence,
            hops=hops,
            peeringdb_info=peeringdb_info,
            wan_data=wan_data,
            hop2_metrics=hop2_metrics,
            anycast_colo=anycast_colo,
            target=target
        )

        is_identified = classification.get("is_identified", bool(matched_ixp and match_evidence))
        egress_ip = classification.get("matched_hop_ip")
        wan_asn_val = int(asn_clean) if asn_clean else None
        dest_asn_val = 13335 if (target == "1.1.1.1" or any(h.get("asn") == 13335 for h in hops)) else (15169 if target == "8.8.8.8" else None)

        access_profile = build_access_profile_from_hops(
            hops,
            target=target,
            egress_ip=egress_ip,
            wan_asn=wan_asn_val,
            dest_asn=dest_asn_val,
            ixp_evidence=match_evidence,
            matched_ixp=matched_ixp
        )
        access_profile["target"] = target

        return {
            "detected_ixp": classification.get("ixp_name"),
            "ixp_city": classification.get("city"),
            "ixp_facility": classification.get("facility") if is_identified else None,
            "peering_type": classification.get("peering_type") if is_identified else None,
            "detection_method": classification.get("detection_method") if is_identified else None,
            "confidence": classification.get("confidence") if is_identified else None,
            "matched_hop_ip": classification.get("matched_hop_ip"),
            "matched_subnet": classification.get("matched_subnet"),
            "rtt_to_ixp_ms": classification.get("rtt_to_ixp_ms"),
            "coordinates": classification.get("coordinates"),
            "anycast_colo": anycast_colo,
            "traceroute_hops": hops,
            "access_profile": access_profile,
            "hop2_bng": ({"ip": hop2_ip, **hop2_metrics} if hop2_ip else None),
            "path_mtu": path_mtu,
            "hop2_skipped_hops": hop2_metrics.get("skipped_hops", []),
            "peeringdb_facilities": peeringdb_info.get("facilities", []),
            "analysis_notes": classification.get("notes", []),
            "hypothesis": classification.get("hypothesis"),
            "is_identified": is_identified
        }

    @staticmethod
    def _parse_multiprobe_traceroute(raw: str) -> List[Dict[str, Any]]:
        hops = []
        hop_chunks = []
        curr_hop = None
        curr_lines = []

        for line in raw.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("traceroute") or line_str.startswith("Tracing") or line_str.startswith("over a maximum"):
                continue
            m = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if m:
                if curr_hop is not None:
                    hop_chunks.append((curr_hop, " ".join(curr_lines)))
                curr_hop = int(m.group(1))
                curr_lines = [m.group(2)]
            elif curr_hop is not None and line_str:
                curr_lines.append(line_str)

        if curr_hop is not None:
            hop_chunks.append((curr_hop, " ".join(curr_lines)))

        for hop_num, chunk in hop_chunks:
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", chunk)
            rtts = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", chunk)]
            primary_ip = ips[0] if ips else "*"
            hops.append({
                "hop": hop_num,
                "ip": primary_ip,
                "ips": ips,
                "rtts": rtts,
                "rtt_ms": (round(min(rtts), 2) if rtts else None)
            })

        return hops

    def measure_access_profile(self, target: str = "1.1.1.1", max_hops: int = 10, probes: int = 8) -> Dict[str, Any]:
        """
        Esegue un traceroute rootless multi-probe (default 8 sonde per hop, max 10 hop)
        per costruire il profilo di latenza salto per salto.
        """
        if os.environ.get("NETPROBE_SPEED_HOST"):
            return {
                "target": target,
                "hops": [],
                "raw": "",
                "total_probed_hops": 0,
                "responsive_hops": 0,
                "access_delay_baseline_ms": None,
                "first_hop_rtt_min_ms": None,
                "isp_core_ingress_hop": None
            }
        if is_windows():
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", target]
        elif is_macos():
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", str(probes), "-w", "1", target]
        else:  # Linux
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", str(probes), "-w", "1", target]

        code, out, _ = run_cmd(cmd, timeout=30.0)
        parsed_hops = self._parse_multiprobe_traceroute(out)
        profile = build_access_profile_from_hops(parsed_hops, target=target)
        profile["target"] = target
        profile["raw"] = out
        return profile

    def run_traceroute(self, target: str, max_hops: int = 16) -> Dict[str, Any]:
        """
        Esegue un traceroute verso il target.
        Cross-platform: non richiede privilegi di root.
        """
        hops = []
        raw_output = ""

        if is_windows():
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", target]
        elif is_macos():
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", "1", "-w", "1", target]
        else:  # Linux
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", "1", "-w", "1", target]
            # Se traceroute non c'è, tenta tracepath
            code, _, _ = run_cmd(["which", "traceroute"])
            if code != 0:
                cmd = ["tracepath", "-n", "-m", str(max_hops), target]

        code, out, _ = run_cmd(cmd)
        raw_output = out

        # Parsing output riga per riga
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("traceroute") or line.startswith("Tracing") or line.startswith("over a maximum"):
                continue

            # Pattern tipico: " 2  100.110.147.129  42.471 ms" o " 2    42 ms    41 ms    43 ms  100.110.147.129"
            hop_match = re.match(r"^(\d+)\s+(.+)$", line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))
            rest = hop_match.group(2)

            if "*" in rest and not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", rest):
                hops.append({
                    "hop": hop_num,
                    "ip": "*",
                    "rtt_ms": None,
                    "rdns": None
                })
                continue

            # Cerca IPv4
            ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", rest)
            ip_str = ip_m.group(1) if ip_m else "*"

            # Cerca RTT ms
            rtt_m = re.search(r"(\d+(?:\.\d+)?)\s*ms", rest)
            rtt_val = float(rtt_m.group(1)) if rtt_m else None

            # Reverse DNS lookup leggero per gli hop (asincrono/breve)
            rdns_val = None
            if ip_str != "*" and not ip_str.startswith("10.") and not ip_str.startswith("192.168."):
                try:
                    rdns_val = socket.getnameinfo((ip_str, 0), 0)[0]
                    if rdns_val == ip_str:
                        rdns_val = None
                except Exception:
                    rdns_val = None

            hops.append({
                "hop": hop_num,
                "ip": ip_str,
                "rtt_ms": rtt_val,
                "rdns": rdns_val
            })

        return {"target": target, "hops": hops, "raw": raw_output}

    HOP2_BURST_COUNT = 30        # campioni per il burst
    HOP2_MIN_SAMPLES = 5         # sotto questa soglia l'hop e' considerato non responsivo
    HOP2_MAX_CANDIDATES = 2      # hop pubblici provati prima di rinunciare
    HOP2_TIME_BUDGET_S = 12.0    # tetto di tempo totale per la sonda (budget scan ~60 s)

    @staticmethod
    def _is_candidate_bng_ip(ip_str: str) -> Tuple[bool, bool]:
        """
        Verifica se l'IP puo' essere un BNG/gateway dell'operatore.
        Ritorna (is_candidate, is_cgnat).
        Accetta IP pubblici globali e IP CGNAT (RFC 6598: 100.64.0.0/10).
        Esclude RFC1918 (privati LAN), loopback, link-local, multicast, riservati.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                return False, False
            # Verifica RFC 6598 CGNAT (100.64.0.0/10)
            cgnat_net = ipaddress.ip_network("100.64.0.0/10")
            if ip_obj in cgnat_net:
                return True, True
            # Esclude privati RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            if ip_obj.is_private:
                return False, False
            return True, False
        except ValueError:
            return False, False

    @staticmethod
    def _parse_ping_times(out: str) -> List[float]:
        times = []
        for line in out.splitlines():
            m = re.search(r"time[=<]([\d\.]+)\s*ms", line, re.IGNORECASE)
            if m:
                try:
                    times.append(float(m.group(1)))
                except ValueError:
                    pass
        return times

    def _ping_burst(self, ip: str, count: int, deadline_s: float) -> Tuple[List[float], int]:
        """Burst di ping senza root. Ritorna (rtts, pacchetti_inviati_richiesti)."""
        deadline_s = max(2.0, deadline_s)
        if is_windows():
            count = min(count, 12)  # intervallo fisso ~1 s: tiene il tempo sotto controllo
            cmd = ["ping", "-n", str(count), "-w", "800", ip]
            _, out, _ = run_cmd(cmd, timeout=count + 4.0)
            return self._parse_ping_times(out), count
        # Intervalli sotto 0.2 s richiedono root su Linux (e a volte su macOS): fallback progressivo
        for interval in ("0.1", "0.2", "1"):
            n = count if interval != "1" else min(count, 8)
            if is_macos():
                cmd = ["ping", "-c", str(n), "-i", interval, "-t", str(int(deadline_s)), ip]
            else:
                cmd = ["ping", "-c", str(n), "-i", interval, "-W", "1", "-w", str(int(deadline_s)), ip]
            _, out, err = run_cmd(cmd, timeout=deadline_s + 2.0)
            times = self._parse_ping_times(out)
            if times:
                return times, n
            if not re.search(r"interval|permitted|too small|invalid", (out + err).lower()):
                return [], n  # nessuna risposta: non e' un problema di intervallo
        return [], count

    PATH_MTU_TARGET = "1.1.1.1"
    PATH_MTU_MIN = 1280          # sotto questo valore il path non e' considerato misurabile (IPv6 minimum MTU)
    PATH_MTU_BUDGET_S = 10.0     # tetto di tempo per l'intera ricerca

    def _ping_df(self, host: str, payload: int, timeout_s: float = 2.0) -> Tuple[Optional[str], Optional[int]]:
        """
        Un ping con bit DF (senza root). Ritorna (stato, mtu_suggerito):
        "ok" = risposta; "big" = frammentazione necessaria (esplicito, definitivo);
        "timeout" = nessuna risposta; None = opzione DF non supportata dal ping di sistema.
        """
        if is_windows():
            cmd = ["ping", "-f", "-l", str(payload), "-n", "1", "-w", str(int(timeout_s * 1000)), host]
        elif is_macos():
            cmd = ["ping", "-D", "-s", str(payload), "-c", "1", "-t", str(int(timeout_s)), host]
        else:
            cmd = ["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", str(int(timeout_s)), host]
        _, out, err = run_cmd(cmd, timeout=timeout_s + 2.0)
        text = (out + "\n" + err).lower()
        if self._parse_ping_times(out):
            return "ok", None
        if re.search(r"too long|frag|needs to be fragmented", text):
            m = re.search(r"mtu\s*=\s*(\d+)", text)
            return "big", (int(m.group(1)) if m else None)
        if re.search(r"illegal option|invalid option|usage:|unknown option|not permitted", text):
            return None, None
        return "timeout", None

    def probe_path_mtu(self, host: Optional[str] = None) -> Optional[int]:
        """
        Misura il path MTU verso internet con ping DF e ricerca binaria (nessun root).
        Ritorna None se non misurabile (ICMP filtrato, opzione DF assente, budget scaduto).
        Un timeout e' ambiguo (perdita casuale vs black hole): viene ritentato una volta.
        """
        host = host or self.PATH_MTU_TARGET
        t0 = time.monotonic()

        def fits(mtu: int):
            """True/False/None(=non misurabile), con eventuale MTU suggerito dal router."""
            for attempt in range(2):
                if time.monotonic() - t0 > self.PATH_MTU_BUDGET_S:
                    return None, None
                status, hint = self._ping_df(host, mtu - 28)
                if status is None:
                    return None, None
                if status == "ok":
                    return True, None
                if status == "big":
                    return False, hint
            return False, None

        ok, _ = fits(1500)
        if ok is None:
            return None
        if ok:
            return 1500
        lo_ok, _ = fits(self.PATH_MTU_MIN)
        if not lo_ok:
            return None  # anche il pacchetto piccolo fallisce: ICMP filtrato / nessuna rete
        lo, hi = self.PATH_MTU_MIN, 1500  # lo passa, hi no
        while hi - lo > 1:
            mid = (lo + hi) // 2
            ok, hint = fits(mid)
            if ok is None:
                return None
            if ok:
                lo = mid
            else:
                hi = mid
                if hint and lo < hint < hi:
                    # il router indica l'MTU: verifica diretta
                    ok_h, _ = fits(hint)
                    if ok_h:
                        lo = hint
        return lo

    def _probe_hop2_bng(self, hops: List[Dict[str, Any]], progress_cb=None) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Individua il primo hop *pubblico e responsivo* della rete dell'operatore (BNG)
        ed esegue un burst di ping per isolare latenza e jitter dell'ultimo miglio.
        Salta hop privati (RFC1918), CGNAT condiviso (100.64/10) e hop che non rispondono.
        Se nessun hop pubblico responsivo e' identificabile ritorna (None, metrics vuote):
        meglio nessuna stima che una stima su un hop sbagliato.
        """
        metrics = {
            "min_ms": None,
            "median_ms": None,
            "avg_ms": None,
            "p95_ms": None,
            "jitter_ms": None,
            "tail_variance_ms": None,
            "spread_ms": None,
            "iqr_ms": None,
            "mad_ms": None,
            "spike_fraction": 0.0,
            "samples_count": 0,
            "packet_loss_pct": 0.0,
            "is_responsive": False,
            "cgnat_hop": False,
            "skipped_hops": []
        }

        candidates = []
        cgnat_flags = {}
        for h in sorted(hops, key=lambda x: x["hop"]):
            ip = h.get("ip")
            if h["hop"] < 2 or not ip or ip == "*":
                continue
            is_cand, is_cgnat = self._is_candidate_bng_ip(ip)
            if not is_cand:
                metrics["skipped_hops"].append(ip)
                continue
            candidates.append(ip)
            cgnat_flags[ip] = is_cgnat
            if len(candidates) >= self.HOP2_MAX_CANDIDATES:
                break

        t_start = time.monotonic()
        for ip in candidates:
            remaining = self.HOP2_TIME_BUDGET_S - (time.monotonic() - t_start)
            if remaining < 2.0:
                break
            if progress_cb:
                progress_cb(f"Burst probing su Hop 2 BNG ({ip})...", 25)
            times, sent = self._ping_burst(ip, self.HOP2_BURST_COUNT, min(8.0, remaining))
            if len(times) < self.HOP2_MIN_SAMPLES:
                metrics["skipped_hops"].append(ip)  # non responsivo all'echo diretto
                continue

            metrics["is_responsive"] = True
            metrics["cgnat_hop"] = cgnat_flags.get(ip, False)
            metrics["samples_count"] = len(times)
            metrics["min_ms"] = round(min(times), 2)
            metrics["median_ms"] = round(statistics.median(times), 2)
            metrics["avg_ms"] = round(statistics.mean(times), 2)

            # 95° percentile (nearest-rank: ceil(0.95·n) − 1)
            sorted_times = sorted(times)
            n_samples = len(sorted_times)
            idx95 = min(n_samples - 1, max(0, math.ceil(n_samples * 0.95) - 1))
            metrics["p95_ms"] = round(sorted_times[idx95], 2)
            metrics["tail_variance_ms"] = round(max(0.0, metrics["p95_ms"] - metrics["median_ms"]), 2)

            # Robust statistics: spread, IQR (p75 - p25), MAD, spike_fraction
            metrics["spread_ms"] = round(max(0.0, metrics["median_ms"] - metrics["min_ms"]), 2)
            idx75 = min(n_samples - 1, max(0, math.ceil(n_samples * 0.75) - 1))
            idx25 = min(n_samples - 1, max(0, math.ceil(n_samples * 0.25) - 1))
            metrics["iqr_ms"] = round(max(0.0, sorted_times[idx75] - sorted_times[idx25]), 2)

            devs = [abs(x - metrics["median_ms"]) for x in times]
            mad_val = statistics.median(devs) if devs else 0.0
            metrics["mad_ms"] = round(mad_val, 2)

            spike_threshold = metrics["median_ms"] + max(50.0, 5.0 * mad_val)
            spike_count = sum(1 for x in times if x > spike_threshold)
            metrics["spike_fraction"] = round(spike_count / n_samples, 3) if n_samples > 0 else 0.0

            # Jitter RFC 3550 (differenza media campioni consecutivi)
            diffs = [abs(times[i] - times[i - 1]) for i in range(1, len(times))]
            metrics["jitter_ms"] = round(statistics.mean(diffs), 2)

            metrics["packet_loss_pct"] = round(max(0.0, (sent - len(times)) / sent * 100.0), 1)
            return ip, metrics

        return None, metrics

    def _find_ixp_in_hops(self, hops: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Analizza la lista di hop del traceroute per rilevare corrispondenze
        nelle Peering LAN Subnet o nei pattern rDNS.
        """
        for h in hops:
            ip_str = h.get("ip")
            if not ip_str or ip_str == "*":
                continue

            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # 1. Match deterministico subnet LAN IXP
            for ixp_def, net_list in self._compiled_networks:
                for net in net_list:
                    if ip_obj in net:
                        evidence = {
                            "type": "peering_subnet_match",
                            "hop": h["hop"],
                            "ip": ip_str,
                            "subnet": str(net),
                            "rtt_ms": h.get("rtt_ms")
                        }
                        return ixp_def, evidence

            # 2. Match pattern rDNS
            rdns = h.get("rdns") or ""
            if rdns:
                for ixp_def, _ in self._compiled_networks:
                    for pattern in ixp_def.get("rdns_patterns", []):
                        if re.search(pattern, rdns, re.IGNORECASE):
                            evidence = {
                                "type": "rdns_match",
                                "hop": h["hop"],
                                "ip": ip_str,
                                "rdns": rdns,
                                "pattern": pattern,
                                "rtt_ms": h.get("rtt_ms")
                            }
                            return ixp_def, evidence

        return None, None

    def get_peeringdb_for_asn(self, asn: int) -> Dict[str, Any]:
        """
        Interroga l'API ufficiale di PeeringDB per conoscere i punti di presenza
        e gli IXP in cui l'operatore utente ha peering pubblico.
        Include cache locale su disco per evitare richieste ripetute.
        """
        # Carica cache
        cache = {}
        if os.path.exists(self.peeringdb_cache_file):
            try:
                with open(self.peeringdb_cache_file, "r", encoding="utf-8") as f:
                    cache = json.load(f)
            except Exception:
                cache = {}

        asn_key = str(asn)
        now = time.time()
        # Se presente in cache da meno di 7 giorni, usa la cache
        if asn_key in cache:
            entry = cache[asn_key]
            if (now - entry.get("timestamp", 0)) < (7 * 86400):
                return entry.get("data", {})

        url = f"https://www.peeringdb.com/api/netixlan?asn={asn}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetProbe/2.0 (Network Peering Intelligence)"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                facilities = []
                for item in data.get("data", []):
                    facilities.append({
                        "name": item.get("name"),
                        "ix_id": item.get("ix_id"),
                        "ipaddr4": item.get("ipaddr4"),
                        "ipaddr6": item.get("ipaddr6"),
                        "speed": item.get("speed")
                    })
                
                result = {"asn": asn, "facilities": facilities}
                cache[asn_key] = {"timestamp": now, "data": result}
                try:
                    with open(self.peeringdb_cache_file, "w", encoding="utf-8") as f:
                        json.dump(cache, f, ensure_ascii=False, indent=2)
                except Exception:
                    pass

                return result
        except Exception:
            return cache.get(asn_key, {}).get("data", {})

    def _classify_exchange(
        self,
        matched_ixp: Optional[Dict[str, Any]],
        match_evidence: Optional[Dict[str, Any]],
        hops: List[Dict[str, Any]],
        peeringdb_info: Dict[str, Any],
        wan_data: Dict[str, Any],
        hop2_metrics: Dict[str, Any],
        anycast_colo: Optional[str] = None,
        target: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sintetizza i dati raccolti per determinare con alta precisione
        l'IXP di uscita o hub di interconnessione, secondo 3 livelli di evidenza:
        Tier 1: On-Wire Public IXP Match (Confidenza 95-100%)
        Tier 2: Verified PNI / Transit Hub via Anycast POP + rDNS Geolocation (Confidenza 85%)
        Tier 3: IXP / Hub non identificato (Ipotesi Bassa <= 40%)
        """
        notes = []

        # Tier 1: Match deterministico da subnet IXP o rDNS sul path
        if matched_ixp and match_evidence:
            ev_type = match_evidence["type"]
            if ev_type == "peering_subnet_match":
                notes.append(f"Hop {match_evidence['hop']} ({match_evidence['ip']}) appartiene alla subnet Peering LAN {match_evidence['subnet']} di {matched_ixp['name']}.")
                return {
                    "ixp_name": matched_ixp["name"],
                    "city": matched_ixp["city"],
                    "facility": matched_ixp["facility"],
                    "peering_type": "Public IXP Peering (Fabric di Interscambio)",
                    "detection_method": "Deterministica (Match Subnet Peering LAN)",
                    "confidence": "100% (Verificato on-wire)",
                    "matched_hop_ip": match_evidence["ip"],
                    "matched_subnet": match_evidence["subnet"],
                    "rtt_to_ixp_ms": match_evidence.get("rtt_ms"),
                    "coordinates": matched_ixp.get("coordinates"),
                    "is_identified": True,
                    "notes": notes
                }
            elif ev_type == "rdns_match":
                notes.append(f"Hop {match_evidence['hop']} ({match_evidence['ip']}) presenta reverse DNS '{match_evidence['rdns']}' associato a {matched_ixp['name']}.")
                return {
                    "ixp_name": matched_ixp["name"],
                    "city": matched_ixp["city"],
                    "facility": matched_ixp["facility"],
                    "peering_type": "Public IXP Peering",
                    "detection_method": "Firma Reverse DNS Router di Peering",
                    "confidence": "95%",
                    "matched_hop_ip": match_evidence["ip"],
                    "matched_subnet": None,
                    "rtt_to_ixp_ms": match_evidence.get("rtt_ms"),
                    "coordinates": matched_ixp.get("coordinates"),
                    "is_identified": True,
                    "notes": notes
                }

        # Tier 2: Interconnessione PNI / Transit verificata via Anycast PoP (Cloudflare trace) o rDNS Geolocation
        colo_cand = (anycast_colo or wan_data.get("colo") or (wan_data.get("cloudflare_trace") or {}).get("colo") or "").strip().upper()
        
        rdns_hub_code = None
        for h in hops:
            rdns = (h.get("rdns") or "").lower()
            if not rdns:
                continue
            for token, h_code in CITY_TOKEN_MAP.items():
                if re.search(r"\b" + re.escape(token) + r"\b", rdns):
                    rdns_hub_code = h_code
                    break
            if rdns_hub_code:
                break

        verified_hub_code = None
        det_method = None
        if colo_cand in ANYCAST_COLO_HUBS:
            verified_hub_code = colo_cand
            det_method = "Anycast PoP (Cloudflare cdn-cgi/trace) + Analisi AS-Boundary"
        elif rdns_hub_code in ANYCAST_COLO_HUBS:
            verified_hub_code = rdns_hub_code
            det_method = "Reverse DNS Geolocation + Analisi AS-Boundary"

        if verified_hub_code and verified_hub_code in ANYCAST_COLO_HUBS:
            hub_def = ANYCAST_COLO_HUBS[verified_hub_code]
            wan_asn = wan_data.get("asn")
            asn_clean = int(re.sub(r"[^\d]", "", str(wan_asn))) if (wan_asn and re.sub(r"[^\d]", "", str(wan_asn))) else None
            is_starlink = (asn_clean == 14593 or "starlink" in str(wan_data.get("isp", "")).lower() or "starlink" in str(wan_data.get("as_name", "")).lower())

            if is_starlink:
                ixp_name = f"Starlink Ground Station / POP ({hub_def['city']})"
                peering_type = "Interconnessione Starlink Satellite Ground Station"
            else:
                ixp_name = hub_def["ixp_name"]
                peering_type = "Direct PNI / Transit Handoff"

            # Egress router: ultimo salto pubblico responsivo prima di dest_asn
            target_ip = target or "1.1.1.1"
            dest_asn_num = 13335 if (target_ip == "1.1.1.1" or any(h.get("asn") == 13335 for h in hops)) else (15169 if target_ip == "8.8.8.8" else None)
            
            candidate_egress = []
            for h in sorted(hops, key=lambda x: x.get("hop", 0)):
                h_ip = h.get("ip")
                if not h_ip or h_ip == "*" or h_ip == target_ip or h_ip in ("1.1.1.1", "8.8.8.8"):
                    continue
                rtts = h.get("rtts") or ([h.get("rtt_ms")] if h.get("rtt_ms") is not None else [])
                if not rtts:
                    continue
                try:
                    ip_obj = ipaddress.ip_address(h_ip)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj in ipaddress.ip_network("100.64.0.0/10"):
                        continue
                except ValueError:
                    continue
                h_asn = h.get("asn")
                if dest_asn_num and h_asn == dest_asn_num:
                    continue
                candidate_egress.append(h)

            matched_egress_ip = None
            rtt_egress = None
            if candidate_egress:
                last_egress = candidate_egress[-1]
                matched_egress_ip = last_egress.get("ip")
                rtts = last_egress.get("rtts") or [last_egress.get("rtt_ms")]
                rtt_egress = round(min(rtts), 2) if rtts and min(rtts) is not None else None
                notes.append(f"Router di handoff / egress identificato su hop {last_egress.get('hop')} ({matched_egress_ip}).")

            notes.append(f"Interconnessione PNI / Transito verificata su hub di {hub_def['city']} via {det_method}.")
            return {
                "ixp_name": ixp_name,
                "city": hub_def["city"],
                "facility": hub_def["facility"],
                "peering_type": peering_type,
                "detection_method": det_method,
                "confidence": "85% (Verificato da Anycast PoP + AS-Boundary)",
                "matched_hop_ip": matched_egress_ip,
                "matched_subnet": None,
                "rtt_to_ixp_ms": rtt_egress,
                "coordinates": hub_def.get("coordinates"),
                "is_identified": True,
                "notes": notes
            }

        # Tier 3: Nessun match deterministico on-wire e nessun Anycast/rDNS verificato
        facilities = peeringdb_info.get("facilities", [])
        coords = wan_data.get("coordinates", {})
        user_lat = coords.get("latitude") or 45.46
        polo_name = "Milano" if abs(user_lat - 45.46) < abs(user_lat - 41.90) else "Roma"

        notes.append("Nessun hop nel traceroute appartiene a una subnet Peering LAN o presenta reverse DNS di un IXP noto.")
        if facilities:
            fac_names = [f["name"] for f in facilities if "MIX" in f.get("name", "") or "Namex" in f.get("name", "") or "TOP-IX" in f.get("name", "")][:3]
            if fac_names:
                notes.append(f"L'operatore mantiene peering pubblico registrato su: {', '.join(fac_names)}.")

        hypothesis = {
            "peering_type": "PNI / Transito Diretto (ipotesi)",
            "detection_method": "Inferenza da latenza Hop 2 / PeeringDB (ipotesi non verificata on-path)",
            "confidence": "Bassa (<=40%) / Ipotesi non verificata",
            "suggested_hub": polo_name
        }

        return {
            "ixp_name": "IXP non identificato",
            "city": polo_name,
            "facility": None,
            "peering_type": "PNI / Transito Diretto (ipotesi)",
            "detection_method": "Inferenza da latenza Hop 2 / PeeringDB (ipotesi non verificata on-path)",
            "confidence": "Bassa (<=40%) / Ipotesi non verificata",
            "matched_hop_ip": None,
            "matched_subnet": None,
            "rtt_to_ixp_ms": None,
            "is_identified": False,
            "hypothesis": hypothesis,
            "notes": notes
        }

    def reclassify_offline(
        self,
        wan_data: Dict[str, Any],
        hops: List[Dict[str, Any]],
        hop2_metrics: Optional[Dict[str, Any]] = None,
        anycast_colo: Optional[str] = None,
        target: Optional[str] = "1.1.1.1"
    ) -> Dict[str, Any]:
        """
        Rivaluta la classificazione IXP/PNI e l'access profile in modalità 100% offline
        a partire da traceroute_hops memorizzati (senza eseguire chiamate di rete live).
        """
        hop2_metrics = hop2_metrics or {}
        matched_ixp, match_evidence = self._find_ixp_in_hops(hops)

        user_asn = wan_data.get("asn") or ""
        asn_clean = re.sub(r"[^\d]", "", str(user_asn))
        peeringdb_info = {}
        if asn_clean:
            asn_int = int(asn_clean)
            if os.path.exists(self.peeringdb_cache_file):
                try:
                    with open(self.peeringdb_cache_file, "r", encoding="utf-8") as f:
                        cache = json.load(f)
                        if str(asn_int) in cache:
                            peeringdb_info = cache[str(asn_int)].get("data", {})
                except Exception:
                    pass
            if not peeringdb_info and asn_int in EMBEDDED_ASN_PEERING_HUBS:
                peeringdb_info = {
                    "asn": asn_int,
                    "facilities": EMBEDDED_ASN_PEERING_HUBS[asn_int]
                }

        classification = self._classify_exchange(
            matched_ixp=matched_ixp,
            match_evidence=match_evidence,
            hops=hops,
            peeringdb_info=peeringdb_info,
            wan_data=wan_data,
            hop2_metrics=hop2_metrics,
            anycast_colo=anycast_colo,
            target=target
        )
        is_identified = classification.get("is_identified", bool(matched_ixp and match_evidence))
        egress_ip = classification.get("matched_hop_ip")
        wan_asn_val = int(asn_clean) if asn_clean else None
        dest_asn_val = 13335 if (target == "1.1.1.1" or any(h.get("asn") == 13335 for h in hops)) else (15169 if target == "8.8.8.8" else None)

        access_profile = build_access_profile_from_hops(
            hops,
            target=target,
            egress_ip=egress_ip,
            wan_asn=wan_asn_val,
            dest_asn=dest_asn_val,
            ixp_evidence=match_evidence,
            matched_ixp=matched_ixp
        )

        return {
            "detected_ixp": classification.get("ixp_name"),
            "ixp_city": classification.get("city"),
            "ixp_facility": classification.get("facility") if is_identified else None,
            "peering_type": classification.get("peering_type") if is_identified else None,
            "detection_method": classification.get("detection_method") if is_identified else None,
            "confidence": classification.get("confidence") if is_identified else None,
            "matched_hop_ip": classification.get("matched_hop_ip"),
            "matched_subnet": classification.get("matched_subnet"),
            "rtt_to_ixp_ms": classification.get("rtt_to_ixp_ms"),
            "coordinates": classification.get("coordinates"),
            "anycast_colo": anycast_colo,
            "traceroute_hops": hops,
            "access_profile": access_profile,
            "hop2_bng": ({"ip": hops[1].get("ip"), **hop2_metrics} if len(hops) > 1 and hop2_metrics else None),
            "peeringdb_facilities": peeringdb_info.get("facilities", []),
            "analysis_notes": classification.get("notes", []),
            "hypothesis": classification.get("hypothesis"),
            "is_identified": is_identified
        }

