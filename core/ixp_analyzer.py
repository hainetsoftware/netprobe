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
import subprocess
import re
import json
import time
import socket
import statistics
import ipaddress
import urllib.request
import urllib.error
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple

from core.path_latency import bound_path_rtts, min_rtt

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
    "mil": "MXP", "mxp": "MXP", "lin": "LIN", "caldera": "MXP", "milan": "MXP", "milano": "MXP", "mi": "MXP",
    "rom": "FCO", "fco": "FCO", "namex": "FCO", "rome": "FCO", "roma": "FCO", "cia": "FCO", "rm": "FCO",
    "trn": "TRN", "torino": "TRN", "turin": "TRN", "to": "TRN",
    "blq": "BLQ", "bologna": "BLQ", "bo": "BLQ",
    "flr": "FLR", "firenze": "FLR", "florence": "FLR", "fi": "FLR",
    "pdv": "PDV", "padova": "PDV", "vce": "VCE", "venezia": "VCE", "venice": "VCE", "pd": "PDV",
    "nap": "NAP", "napoli": "NAP", "naples": "NAP", "na": "NAP",
    "pal": "PMO", "pmo": "PMO", "palermo": "PMO", "pa": "PMO",
    "cta": "CTA", "catania": "CTA", "ct": "CTA",
    "fra": "FRA", "frankfurt": "FRA", "francoforte": "FRA",
    "ams": "AMS", "amsterdam": "AMS",
    "zrh": "ZRH", "zurich": "ZRH", "zurigo": "ZRH",
    "mrs": "MRS", "marseille": "MRS", "marsiglia": "MRS",
    "lon": "LHR", "london": "LHR", "londra": "LHR", "lhr": "LHR",
    "par": "CDG", "paris": "CDG", "parigi": "CDG", "cdg": "CDG"
}

# These coordinates identify a metro, not a colocation building.
for _code, _city, _lat, _lon in [
    ("PSA", "Pisa", 43.7228, 10.4017), ("BRI", "Bari", 41.1171, 16.8719),
    ("CTA", "Catania", 37.5079, 15.0830), ("CAG", "Cagliari", 39.2238, 9.1217),
    ("GOA", "Genova", 44.4056, 8.9463), ("TRS", "Trieste", 45.6495, 13.7768),
]:
    ANYCAST_COLO_HUBS[_code] = {"city": _city, "coordinates": {"lat": _lat, "lon": _lon}}
CITY_TOKEN_MAP.update({"pi": "PSA", "pisa": "PSA", "ba": "BRI", "bari": "BRI",
                       "ca": "CAG", "cagliari": "CAG", "ge": "GOA", "genova": "GOA",
                       "ts": "TRS", "trieste": "TRS", "ve": "VCE"})


DATACENTER_FACILITIES: List[Dict[str, Any]] = [
    {
        "id": "campus-caldera",
        "facility_name": "Campus Caldera (Milano)",
        "campus": "Polo Tecnologico Caldera",
        "address": "Via Caldera 21, 20153 Milano MI",
        "operator": "Consorzio MIX-IT / Equinix (ML2) / Sparkle / Irideos / Seeweb",
        "city": "Milano",
        "country": "Italia",
        "metro_code": "MXP",
        "coordinates": {"lat": 45.4642, "lon": 9.1028},
        "interconnect_type": "Public IXP Peering / Direct PNI / IP Transit",
        "subnets": [
            "217.29.66.0/23", "217.29.68.0/24",
            "195.22.205.0/24", "195.22.196.0/24", "195.22.208.0/24",
            "185.1.114.0/24", "2001:7f8:15::/64"
        ],
        "rdns_tokens": ["caldera", "mix-it", "mix.it", "milano-mix", "seabone", "minap", "mil", "milano", "mxp", "lin"],
        "host_asns": [13335, 6762, 1267, 12874, 30722, 3269, 15169, 16509, 208643]
    },
    {
        "id": "data4-cornaredo",
        "facility_name": "Data4 Campus Milano (Cornaredo)",
        "campus": "Data4 Cornaredo Smart Campus",
        "address": "Via Monzoro 101, 20010 Cornaredo MI",
        "operator": "Data4 Group",
        "city": "Milano",
        "country": "Italia",
        "metro_code": "MXP",
        "coordinates": {"lat": 45.4950, "lon": 9.0250},
        "interconnect_type": "Direct PNI / Hyperscale Campus",
        "subnets": [],
        "rdns_tokens": ["data4", "cornaredo"],
        "host_asns": [13335, 16509, 15169]
    },
    {
        "id": "equinix-milan",
        "facility_name": "Equinix Milan Campus (ML1/ML3/ML4/ML5)",
        "campus": "Equinix IBX Data Centers (ML1/ML3/ML4/ML5)",
        "address": "Via Savona 125, 20144 Milano MI",
        "operator": "Equinix Italy",
        "city": "Milano",
        "country": "Italia",
        "metro_code": "MXP",
        "coordinates": {"lat": 45.4480, "lon": 9.1450},
        "interconnect_type": "Public IXP & Equinix Fabric / PNI",
        "subnets": [],
        "rdns_tokens": ["equinix-ml", "ml1", "ml3", "ml4", "ml5"],
        "host_asns": [13335, 16509, 15169, 1299, 3356]
    },
    {
        "id": "stack-vantage-milano",
        "facility_name": "Stack Infrastructure / Vantage Milan",
        "campus": "Milano Hyperscale Campus (Siziano / San Bovio)",
        "address": "Via Archimede, 27010 Siziano PV / Peschiera Borromeo MI",
        "operator": "Stack Infrastructure / Vantage",
        "city": "Milano",
        "country": "Italia",
        "metro_code": "MXP",
        "coordinates": {"lat": 45.3180, "lon": 9.2050},
        "interconnect_type": "Direct PNI / Cloud Edge",
        "subnets": [],
        "rdns_tokens": ["stack", "vantage"],
        "host_asns": [16509, 15169, 13335]
    },
    {
        "id": "namex-tiburtina",
        "facility_name": "Tiburtina / NaMeX Hub (Roma)",
        "campus": "Polo Tecnologico Roma Tiburtina",
        "address": "Via dei Luxardo 22 / Via Tiburtina, 00156 Roma RM",
        "operator": "Consorzio NaMeX / TIM OPM / Cineca Roma",
        "city": "Roma",
        "country": "Italia",
        "metro_code": "FCO",
        "coordinates": {"lat": 41.8988, "lon": 12.5186},
        "interconnect_type": "Public IXP Peering / Direct PNI",
        "subnets": [
            "193.201.28.0/23", "185.1.193.0/24", "185.1.40.0/23",
            "195.22.193.0/24", "195.22.219.0/24", "2001:7f8:1b::/64"
        ],
        "rdns_tokens": ["namex", "roma-namex", "luxardo", "tiburtina", "tizii", "rom", "roma", "fco", "cia"],
        "host_asns": [13335, 6762, 3269, 12874, 1267, 30722, 15169]
    },
    {
        "id": "equinix-rome",
        "facility_name": "Equinix Rome (RM1)",
        "campus": "Equinix RM1 IBX Data Center",
        "address": "Via di Tor Cervara 282, 00155 Roma RM",
        "operator": "Equinix Italy",
        "city": "Roma",
        "country": "Italia",
        "metro_code": "FCO",
        "coordinates": {"lat": 41.9210, "lon": 12.5850},
        "interconnect_type": "Direct PNI / Carrier Neutral Colocation",
        "subnets": [],
        "rdns_tokens": ["rm1", "torcervara"],
        "host_asns": [13335, 12874, 3269]
    },
    {
        "id": "top-ix-torino",
        "facility_name": "TOP-IX Consortium (Torino)",
        "campus": "CSI Piemonte / Centro Piero della Francesca",
        "address": "Corso Svizzera 185, 10149 Torino TO",
        "operator": "Consorzio TOP-IX",
        "city": "Torino",
        "country": "Italia",
        "metro_code": "TRN",
        "coordinates": {"lat": 45.0864, "lon": 7.6534},
        "interconnect_type": "Public IXP Peering / Consortium",
        "subnets": ["194.116.86.0/24", "194.116.96.0/22", "2001:7f8:53::/64"],
        "rdns_tokens": ["top-ix", "topix", "torino", "trn", "turin"],
        "host_asns": [3269, 1267, 12874, 30722, 13335]
    },
    {
        "id": "vsix-padova",
        "facility_name": "VSIX (Padova)",
        "campus": "VSIX Università degli Studi di Padova",
        "address": "Galleria Tito Livio 7, 35123 Padova PD",
        "operator": "Università degli Studi di Padova / VSIX",
        "city": "Padova",
        "country": "Italia",
        "metro_code": "PDV",
        "coordinates": {"lat": 45.4064, "lon": 11.8768},
        "interconnect_type": "Public IXP Peering",
        "subnets": ["194.242.224.0/24", "195.69.148.0/24", "185.1.201.0/24", "2001:7f8:56::/64"],
        "rdns_tokens": ["vsix", "padova", "pdv", "venezia", "vce"],
        "host_asns": [12874, 1267, 13335]
    },
    {
        "id": "tix-firenze",
        "facility_name": "TIX - Tuscany Internet eXchange (Firenze)",
        "campus": "TIX Cascine / Regione Toscana",
        "address": "Via Panciatichi 29, 50127 Firenze FI",
        "operator": "TIX Consorzio / Regione Toscana",
        "city": "Firenze",
        "country": "Italia",
        "metro_code": "FLR",
        "coordinates": {"lat": 43.8010, "lon": 11.2310},
        "interconnect_type": "Public IXP Peering",
        "subnets": ["193.42.140.0/24", "2001:7f8:1a::/64"],
        "rdns_tokens": ["tix", "firenze", "flr", "florence"],
        "host_asns": [3269, 13335]
    },
    {
        "id": "sicily-hub-palermo",
        "facility_name": "Sicily Hub / Open Hub Med (Palermo)",
        "campus": "Sparkle Sicily Hub / Open Hub Med Carini",
        "address": "Via Emerico Amari 8, 90139 Palermo PA / Carini",
        "operator": "Telecom Italia Sparkle / Open Hub Med",
        "city": "Palermo",
        "country": "Italia",
        "metro_code": "PMO",
        "coordinates": {"lat": 38.1250, "lon": 13.3600},
        "interconnect_type": "Public IXP Peering / Subsea Cable Landing Hub",
        "subnets": ["185.1.134.0/24"],
        "rdns_tokens": ["sicily", "openhubmed", "ohm", "c-ix", "palermo", "pmo", "catania", "cta"],
        "host_asns": [6762, 12874, 13335]
    },
    {
        "id": "de-cix-frankfurt",
        "facility_name": "DE-CIX Frankfurt Campus",
        "campus": "Kleyerstrasse 79-90 / Interxion Campus",
        "address": "Kleyerstrasse 79-90, 60326 Frankfurt am Main",
        "operator": "DE-CIX Management GmbH / Digital Realty Interxion",
        "city": "Francoforte",
        "country": "Germania",
        "metro_code": "FRA",
        "coordinates": {"lat": 50.1006, "lon": 8.6366},
        "interconnect_type": "Public IXP Peering / European Core",
        "subnets": ["80.81.192.0/21"],
        "rdns_tokens": ["de-cix", "decix", "kleyerstrasse", "frankfurt", "fra"],
        "host_asns": [13335, 15169, 16509, 1299, 3356, 6762]
    }
]

_COMPILED_FACILITY_NETWORKS = []
for _fac in DATACENTER_FACILITIES:
    _nets = []
    for _s in _fac.get("subnets", []):
        try:
            _nets.append(ipaddress.ip_network(_s))
        except Exception:
            pass
    _COMPILED_FACILITY_NETWORKS.append((_fac, _nets))

CARRIER_DOMAINS = [
    (r"seabone\.net", "Telecom Italia Sparkle", 6762),
    (r"telecomitalia\.it|interbusiness\.it", "Telecom Italia", 3269),
    (r"fastwebnet\.it", "Fastweb", 12874),
    (r"wind\.it|windtre\.it|windgroup\.it", "Wind Tre", 1267),
    (r"vodafone\.it|d2-gws\.it|omnitel\.it", "Vodafone Italia", 30722),
    (r"openfiber\.it", "Open Fiber", None),
    (r"(?:^|\.)garr\.(?:it|net)$", "GARR", 137),
    (r"telia\.net|arelion\.com", "Telia / Arelion", 1299),
    (r"level3\.net|lumen\.com|centurylink\.com", "Lumen / Level3", 3356),
    (r"cogentco\.com", "Cogent Communications", 174),
    (r"as3257\.net|gtt\.net", "GTT Communications", 3257),
    (r"1e100\.net|google\.com", "Google Network", 15169),
    (r"cloudflare\.com|as13335\.net", "Cloudflare Edge", 13335),
    (r"awsglobalaccelerator\.com|cloudfront\.net|amazonaws\.com", "Amazon Web Services", 16509)
]

ROLE_PATTERNS = [
    (r"\b(?:cr\d*|ccr\d*|core)\b", "Core Router"),
    (r"\b(?:br\d*|b\d+|c-br\d*|border)\b", "Border Router"),
    (r"\b(?:pe\d*|c-pe\d*|per\d*)\b", "Provider Edge (PE)"),
    (r"\b(?:bras\d*|bng\d*|fe\d*|asr\d*)\b", "Access Gateway / BRAS"),
    (r"\b(?:gw\d*|gws\d*)\b", "Gateway / Exchange Node"),
    (r"\b(?:rt\d*|rx\d*|r\b)", "Backbone Router"),
    (r"\b(?:pop\d*)\b", "Point of Presence (PoP)"),
]


def parse_rdns_metro_and_role(hostname: Optional[str]) -> Dict[str, Any]:
    """
    Offline pattern matching e grammar parser profondo per reverse DNS (PTR)
    dei principali backbone italiani ed europei (Telecom Italia, Sparkle Seabone,
    Fastweb, WindTre, Vodafone, Open Fiber, GARR, Arelion, Lumen, Cogent, GTT).
    Decodifica:
    - Ruolo del nodo: Core Router, Border Router, Provider Edge, BRAS/Access Gateway, ecc.
    - Metropoli / PoP: Milano (MXP), Roma (FCO), Torino (TRN), Bologna (BLQ), ecc.
    - Carrier / ASN di appartenenza
    """
    if not hostname:
        return {
            "hostname": None,
            "carrier": None,
            "asn": None,
            "node_role": None,
            "metro_code": None,
            "city": None
        }
    h = hostname.lower().strip().rstrip(".")

    carrier = None
    asn = None
    for pattern, c_name, c_asn in CARRIER_DOMAINS:
        if re.search(pattern, h):
            carrier = c_name
            asn = c_asn
            break

    role = None
    parts = re.split(r"[\.\-_]", h)
    for p in parts:
        for pat, r_name in ROLE_PATTERNS:
            if re.match(f"^{pat}$", p):
                role = r_name
                break
        if role:
            break
    if not role:
        for pattern, r_name in ROLE_PATTERNS:
            if re.search(pattern, h):
                role = r_name
                break
    if not role and carrier:
        role = "Backbone / Transit Node"

    metro_code = None
    city = None
    tokens = re.split(r"[^a-z0-9]+", h)
    for tok in tokens:
        clean = re.sub(r"\d+", "", tok)
        if clean in CITY_TOKEN_MAP:
            metro_code = CITY_TOKEN_MAP[clean]
            city = ANYCAST_COLO_HUBS.get(metro_code, {}).get("city") or clean.capitalize()
            break
        if tok in CITY_TOKEN_MAP:
            metro_code = CITY_TOKEN_MAP[tok]
            city = ANYCAST_COLO_HUBS.get(metro_code, {}).get("city") or tok.capitalize()
            break

    pop_token = None
    access_province = None
    if h.endswith(".garr.net") or h.endswith(".garr.it"):
        # Nearest subdomain is authoritative; link names contain both endpoints.
        match = re.search(r"\.([a-z]{2}\d{2})\.garr\.(?:net|it)$", h)
        candidates = [match.group(1)] if match else re.findall(r"(?:^|[.\-_])([a-z]{2}\d{2})(?=$|[.\-_])", h)[-1:]
        if candidates and candidates[0][:2] in CITY_TOKEN_MAP:
            pop_token = candidates[0]
            metro_code = CITY_TOKEN_MAP[pop_token[:2]]
            city = ANYCAST_COLO_HUBS[metro_code]["city"]
            if pop_token.startswith("pd"):
                city = "Padova"
            elif pop_token.startswith("ve"):
                city = "Venezia"
        access = re.search(r"(?:^|\.)aggr-scuole-([a-z]{2})-", h)
        if access:
            access_province = access.group(1).upper()
            role = "Access Aggregator"

    return {
        "pop_token": pop_token,
        "access_province": access_province,
        "location_confidence": 0.98 if pop_token else (0.9 if city else None),
        "hostname": hostname,
        "carrier": carrier,
        "asn": asn,
        "node_role": role,
        "metro_code": metro_code,
        "city": city
    }


def resolve_datacenter_facility(
    ip: Optional[str] = None,
    rdns: Optional[str] = None,
    ixp_id: Optional[str] = None,
    metro_code: Optional[str] = None,
    anycast_colo: Optional[str] = None,
    city: Optional[str] = None,
    hops: Optional[List[Dict[str, Any]]] = None
) -> Optional[Dict[str, Any]]:
    """
    Risolve con precisione ingegneristica la specifica struttura di colocation/campus fisico
    (es. Campus Caldera, NaMeX Tiburtina, Data4, Equinix, TOP-IX, ecc.)
    a partire da IP di transito/peering, reverse DNS, subnet IXP, codice PoP o metropoli.
    """
    candidate_ips = []
    if ip and ip != "*":
        candidate_ips.append(ip)
    if hops:
        for h in hops:
            hip = h.get("ip")
            if hip and hip != "*" and hip not in candidate_ips:
                candidate_ips.append(hip)

    # 1. Match diretto su subnet verificata
    for cand_ip in candidate_ips:
        try:
            ip_obj = ipaddress.ip_address(cand_ip)
            for fac, net_list in _COMPILED_FACILITY_NETWORKS:
                for net in net_list:
                    if ip_obj in net:
                        res = dict(fac)
                        res["matched_via"] = "ip_subnet_match"
                        res["matched_ip"] = cand_ip
                        res["matched_subnet"] = str(net)
                        return res
        except ValueError:
            pass

    # 2. Match su pattern/token rDNS
    candidate_rdns = []
    if rdns:
        candidate_rdns.append(rdns.lower())
    if hops:
        for h in hops:
            hrdns = (h.get("rdns") or "").lower()
            if hrdns and hrdns not in candidate_rdns:
                candidate_rdns.append(hrdns)

    for cand_rdns in candidate_rdns:
        for fac in DATACENTER_FACILITIES:
            for tok in fac.get("rdns_tokens", []):
                if re.search(r"(?:^|[\.\-_])" + re.escape(tok) + r"(?:$|[\.\-_0-9])", cand_rdns):
                    res = dict(fac)
                    res["matched_via"] = "rdns_token_match"
                    res["matched_rdns"] = cand_rdns
                    return res

    # 3. Match su ixp_id
    if ixp_id:
        ixp_id_low = ixp_id.lower()
        if "mix" in ixp_id_low or "minap" in ixp_id_low:
            res = dict(DATACENTER_FACILITIES[0])
            res["matched_via"] = "ixp_id"
            return res
        elif "namex" in ixp_id_low:
            res = dict(DATACENTER_FACILITIES[4])
            res["matched_via"] = "ixp_id"
            return res
        elif "top-ix" in ixp_id_low or "topix" in ixp_id_low:
            res = dict(DATACENTER_FACILITIES[6])
            res["matched_via"] = "ixp_id"
            return res
        elif "vsix" in ixp_id_low:
            res = dict(DATACENTER_FACILITIES[7])
            res["matched_via"] = "ixp_id"
            return res
        elif "tix" in ixp_id_low:
            res = dict(DATACENTER_FACILITIES[8])
            res["matched_via"] = "ixp_id"
            return res
        elif "de-cix" in ixp_id_low:
            res = dict(DATACENTER_FACILITIES[10])
            res["matched_via"] = "ixp_id"
            return res

    # 4. Match su codice PoP Anycast / IATA metro code
    code = (anycast_colo or metro_code or "").strip().upper()
    if code:
        if code in ("MXP", "LIN", "MIL"):
            res = dict(DATACENTER_FACILITIES[0])
            res["matched_via"] = "anycast_pop_metro"
            return res
        elif code in ("FCO", "CIA", "ROM"):
            res = dict(DATACENTER_FACILITIES[4])
            res["matched_via"] = "anycast_pop_metro"
            return res
        elif code in ("TRN", "TUR"):
            res = dict(DATACENTER_FACILITIES[6])
            res["matched_via"] = "anycast_pop_metro"
            return res
        elif code in ("PDV", "VCE"):
            res = dict(DATACENTER_FACILITIES[7])
            res["matched_via"] = "anycast_pop_metro"
            return res
        elif code in ("FLR",):
            res = dict(DATACENTER_FACILITIES[8])
            res["matched_via"] = "anycast_pop_metro"
            return res
        elif code in ("PMO", "CTA"):
            res = dict(DATACENTER_FACILITIES[9])
            res["matched_via"] = "anycast_pop_metro"
            return res
        elif code in ("FRA",):
            res = dict(DATACENTER_FACILITIES[10])
            res["matched_via"] = "anycast_pop_metro"
            return res

    # 5. Match su città (default cluster) solo in presenza di segnale di rete o hop
    has_network_signal = bool(candidate_ips or candidate_rdns or ixp_id or anycast_colo or metro_code)
    if city and has_network_signal:
        city_low = city.lower()
        if "milan" in city_low:
            res = dict(DATACENTER_FACILITIES[0])
            res["matched_via"] = "city_cluster"
            return res
        elif "rom" in city_low:
            res = dict(DATACENTER_FACILITIES[4])
            res["matched_via"] = "city_cluster"
            return res
        elif "torin" in city_low or "turin" in city_low:
            res = dict(DATACENTER_FACILITIES[6])
            res["matched_via"] = "city_cluster"
            return res
        elif "padov" in city_low or "venez" in city_low:
            res = dict(DATACENTER_FACILITIES[7])
            res["matched_via"] = "city_cluster"
            return res
        elif "firenz" in city_low or "floren" in city_low:
            res = dict(DATACENTER_FACILITIES[8])
            res["matched_via"] = "city_cluster"
            return res
        elif "palerm" in city_low or "catan" in city_low:
            res = dict(DATACENTER_FACILITIES[9])
            res["matched_via"] = "city_cluster"
            return res
        elif "frankfurt" in city_low or "francofort" in city_low:
            res = dict(DATACENTER_FACILITIES[10])
            res["matched_via"] = "city_cluster"
            return res

    return None

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


def probe_multi_cdn_pops(timeout_s: float = 1.5) -> Dict[str, Any]:
    """
    Sonda leggera in parallelo verso molteplici Edge CDN:
    - Cloudflare trace (colo IATA)
    - Fastly (X-Served-By / X-Cache)
    - AWS CloudFront (x-amz-cf-pop)
    Combina i segnali per verificare deterministicamente la metro area di uscita.
    """
    res = {
        "cloudflare": {},
        "fastly": {},
        "cloudfront": {},
        "verified_metro": None,
        "verified_metro_code": None,
        "consensus": False,
        "responding_providers": []
    }

    def _query_cf():
        return probe_cloudflare_trace(timeout_s=timeout_s)

    def _query_fastly():
        urls = ["https://www.fastly.com", "https://fastly.net"]
        for u in urls:
            try:
                req = urllib.request.Request(
                    u,
                    headers={"User-Agent": "Mozilla/5.0 NetProbe/2.0 (CDN PoP Inspection)"}
                )
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    served = resp.headers.get("X-Served-By", "")
                    cache = resp.headers.get("X-Cache", "")
                    m = re.findall(r"(?:cache-)?([a-z]{3})\d*-(?:[A-Z0-9]+)", served, re.IGNORECASE)
                    pop = None
                    if m:
                        pop = m[-1].upper()
                    else:
                        m2 = re.findall(r"\b([A-Z]{3})\b", served)
                        if m2:
                            pop = m2[-1].upper()
                    if pop or served:
                        return {"pop": pop, "served_by": served, "cache": cache}
            except Exception:
                pass
        return {}

    def _query_cloudfront():
        urls = ["https://aws.amazon.com", "https://d1.awsstatic.com"]
        for u in urls:
            try:
                req = urllib.request.Request(
                    u,
                    headers={"User-Agent": "Mozilla/5.0 NetProbe/2.0 (CDN PoP Inspection)"}
                )
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    pop_hdr = resp.headers.get("x-amz-cf-pop", "")
                    m = re.match(r"^([a-zA-Z]{3})", pop_hdr)
                    metro = m.group(1).upper() if m else None
                    if pop_hdr:
                        return {"pop": pop_hdr, "metro_code": metro}
            except Exception:
                pass
        return {}

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f_cf = pool.submit(_query_cf)
            f_fastly = pool.submit(_query_fastly)
            f_cfpop = pool.submit(_query_cloudfront)

            try:
                res["cloudflare"] = f_cf.result(timeout=timeout_s + 0.5)
            except Exception:
                pass
            try:
                res["fastly"] = f_fastly.result(timeout=timeout_s + 0.5)
            except Exception:
                pass
            try:
                res["cloudfront"] = f_cfpop.result(timeout=timeout_s + 0.5)
            except Exception:
                pass
    except Exception:
        pass

    metro_candidates = []
    cf_colo = res["cloudflare"].get("colo")
    if cf_colo:
        res["responding_providers"].append("cloudflare")
        norm = CITY_TOKEN_MAP.get(cf_colo.lower(), cf_colo.upper())
        metro_candidates.append(norm)

    fastly_pop = res["fastly"].get("pop")
    if fastly_pop:
        res["responding_providers"].append("fastly")
        norm = CITY_TOKEN_MAP.get(fastly_pop.lower(), fastly_pop.upper())
        metro_candidates.append(norm)

    cf_pop_metro = res["cloudfront"].get("metro_code")
    if cf_pop_metro:
        res["responding_providers"].append("cloudfront")
        norm = CITY_TOKEN_MAP.get(cf_pop_metro.lower(), cf_pop_metro.upper())
        metro_candidates.append(norm)

    if metro_candidates:
        from collections import Counter
        counts = Counter(metro_candidates)
        top_code, top_count = counts.most_common(1)[0]
        res["verified_metro_code"] = top_code
        res["verified_metro"] = ANYCAST_COLO_HUBS.get(top_code, {}).get("city") or top_code
        res["consensus"] = bool(top_count >= 2 or len(res["responding_providers"]) == 1)

    return res


def merge_multi_target_paths(target_paths: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Fonde i traceroute paralleli eseguiti verso i target divergenti ed estrae:
    - common_path: percorso comune dall'origine
    - divergence_hop: numero di hop in cui avviene lo split dei percorsi
    - common_ancestor_ip: router comune precedente la divergenza
    - targets: sintesi prestazionale e topologica per target
    - transit_carriers: carrier di transito identificati
    """
    valid_paths = {k: hops for k, hops in target_paths.items() if hops and any(h.get("ip") and h.get("ip") != "*" for h in hops)}
    if not valid_paths:
        return {
            "common_path": [],
            "divergence_hop": None,
            "common_ancestor_ip": None,
            "divergence_description": "Nessun percorso responsivo rilevato",
            "targets": {},
            "transit_carriers": []
        }

    sorted_paths = {k: sorted(hops, key=lambda x: x.get("hop", 0)) for k, hops in valid_paths.items()}
    max_len = max(len(h) for h in sorted_paths.values())

    common_hops = []
    divergence_hop_num = None
    common_ancestor_ip = None

    for i in range(max_len):
        step_ips = {}
        for t_name, hops in sorted_paths.items():
            if i < len(hops):
                hip = hops[i].get("ip")
                if hip and hip != "*":
                    step_ips[t_name] = hip

        distinct_ips = set(step_ips.values())
        if len(step_ips) >= 2:
            if len(distinct_ips) == 1:
                sample_hop = list(sorted_paths.values())[0][i]
                common_hops.append(sample_hop)
                common_ancestor_ip = list(distinct_ips)[0]
            else:
                divergence_hop_num = i + 1
                break
        elif len(step_ips) == 1 and len(valid_paths) == 1:
            common_hops.append(list(sorted_paths.values())[0][i])
        else:
            if common_ancestor_ip:
                divergence_hop_num = i + 1
                break

    if divergence_hop_num is None and len(valid_paths) > 1 and common_hops:
        divergence_hop_num = len(common_hops) + 1

    transit_carriers = set()
    targets_summary = {}

    TIER1_ASNS = {
        6762: "Telecom Italia Sparkle",
        1299: "Telia / Arelion",
        3356: "Lumen / Level3",
        3257: "GTT Communications",
        174: "Cogent Communications",
        6453: "Tata Communications",
        1273: "Vodafone Carrier",
        13335: "Cloudflare (Peering Fabric)",
        15169: "Google Network",
        16509: "Amazon Web Services"
    }

    for t_name, hops in sorted_paths.items():
        exit_pop = None
        handoff_asn = None
        handoff_carrier = None

        public_hops = []
        for h in hops:
            try:
                if ipaddress.ip_address(h.get("ip", "*")).is_global:
                    public_hops.append(h)
            except ValueError:
                continue
        terminal = next((h for h in reversed(public_hops)
                         if min_rtt(h) is not None), {})
        terminal_rtt = terminal.get("effective_rtt_ms")
        if terminal_rtt is None:
            terminal_rtt = min_rtt(terminal)
        destination_asns = {"cloudflare": 13335, "1.1.1.1": 13335,
                            "google": 15169, "8.8.8.8": 15169,
                            "aws": 16509, "13.248.118.1": 16509}
        dest_asn = destination_asns.get(t_name, terminal.get("asn"))
        for h in public_hops:
            if dest_asn and h.get("asn") == dest_asn:
                break
            parsed = h.get("rdns_parsed") or parse_rdns_metro_and_role(h.get("rdns"))
            exit_pop = parsed.get("metro_code")

        for h in hops:
            hasn = h.get("asn")
            if hasn and hasn in TIER1_ASNS:
                transit_carriers.add(f"{TIER1_ASNS[hasn]} (AS{hasn})")
                handoff_asn = hasn
                handoff_carrier = TIER1_ASNS[hasn]

        last_hop = hops[-1] if hops else {}
        target_ip = last_hop.get("ip")
        if not handoff_carrier:
            handoff_carrier = last_hop.get("asn_name") or (f"AS{last_hop.get('asn')}" if last_hop.get("asn") else "Direct PNI")

        targets_summary[t_name] = {
            "target_ip": target_ip,
            "hop_count": len(hops),
            "min_rtt_ms": round(terminal_rtt, 2) if terminal_rtt is not None else None,
            "exit_pop": exit_pop or "MXP",
            "handoff_carrier": handoff_carrier,
            "handoff_asn": handoff_asn
        }

    div_desc = "Rilevata divergenza topologica"
    if any("217.29.66" in str(t.get("target_ip")) for t in targets_summary.values()):
        div_desc = "Split tra Peering Domestico (MIX Peering LAN) e Transito Internazionale / Edge Anycast"

    return {
        "common_path": common_hops,
        "divergence_hop": divergence_hop_num,
        "common_ancestor_ip": common_ancestor_ip,
        "divergence_description": div_desc,
        "targets": targets_summary,
        "transit_carriers": sorted(list(transit_carriers))
    }


def build_topological_flow(
    hops: List[Dict[str, Any]],
    facility: Optional[Dict[str, Any]] = None,
    colo: Optional[str] = None,
    target: Optional[str] = None
) -> Dict[str, Any]:
    """
    Costruisce il diagramma di flusso infrastrutturale end-to-end:
    [Client Locale] ──> [Accesso BRAS/DSLAM] ──> [Core Regionale] ──> [Carrier Transit Tier-1] ──> [Hub / Datacenter Campus] ──> [Edge Anycast]
    """
    client_ip = "192.168.1.x"
    bng_ip = None
    bng_rtt = None
    core_ip = None
    core_desc = None
    carrier_name = None
    carrier_ip = None

    sorted_hops = sorted(hops, key=lambda x: x.get("hop", 0))
    for h in sorted_hops:
        hop_num = h.get("hop", 0)
        hip = h.get("ip") or "*"
        rtts = h.get("rtts") or ([h.get("rtt_ms")] if h.get("rtt_ms") is not None else [])
        min_r = round(min(rtts), 2) if rtts else None

        if hop_num == 1:
            client_ip = hip
        elif hop_num >= 2 and bng_ip is None and hip != "*":
            bng_ip = hip
            bng_rtt = min_r
        elif bng_ip and core_ip is None and hip != "*":
            core_ip = hip
            hrdns = parse_rdns_metro_and_role(h.get("rdns"))
            core_desc = hrdns.get("carrier") or h.get("asn_name") or "Backbone ISP"
        hasn = h.get("asn")
        if hasn in (6762, 1299, 3356, 3257, 174):
            carrier_name = h.get("asn_name") or f"AS{hasn}"
            carrier_ip = hip

    fac_name = facility.get("facility_name") if facility else "Hub di Interconnessione PNI"
    fac_city = facility.get("city") if facility else "Milano"
    exit_colo = colo or (facility.get("metro_code") if facility else "MXP")

    stages = [
        {"role": "Client Locale", "label": "Client Locale", "node": client_ip or "Host Locale"},
        {"role": "Accesso BRAS/DSLAM", "label": "Accesso BRAS/DSLAM", "node": f"{bng_ip or 'Primo Gateway ISP'}" + (f" ({bng_rtt}ms)" if bng_rtt else "")},
        {"role": "Core Regionale", "label": "Core Regionale", "node": f"{core_ip or 'Rete di Raccolta'} [{core_desc or 'Backbone'}]"},
        {"role": "Carrier Transit Tier-1", "label": "Carrier Transit Tier-1", "node": f"{carrier_name or 'Handoff Diretto / PNI'}" + (f" ({carrier_ip})" if carrier_ip else "")},
        {"role": "Hub / Datacenter Campus", "label": "Hub / Datacenter Campus", "node": f"{fac_name} ({fac_city})"},
        {"role": "Edge Anycast", "label": "Edge Anycast", "node": f"{target or 'Edge'} [{exit_colo}]"}
    ]

    breadcrumb = " ──> ".join(f"[{s['role']}]" for s in stages)

    return {
        "breadcrumb": breadcrumb,
        "stages": stages
    }


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
            "subnets": ["217.29.66.0/23", "217.29.68.0/24", "185.1.226.0/23", "2001:7f8:15::/64"],
            "rdns_patterns": [r"(?:^|\.)mix\-it\.net\.?$"]
        },
        {
            "id": "namex",
            "name": "NAMEX - Nautilus Mediterranean eXchange",
            "facility": "Via dei Tizii 6 / Cineca",
            "city": "Roma",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 41.8988, "lon": 12.5186},
            "subnets": ["193.201.28.0/23", "185.1.193.0/24", "185.1.40.0/23", "2001:7f8:1b::/64"],
            "rdns_patterns": [r"(?:^|\.)namex\.it\.?$"]
        },
        {
            "id": "top-ix",
            "name": "TOP-IX - Torino Piemonte Internet eXchange",
            "facility": "CSI Piemonte, Corso Unione Sovietica 216",
            "city": "Torino",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 45.0392, "lon": 7.6496},
            "subnets": ["194.116.86.0/24", "194.116.96.0/22", "2001:7f8:53::/64"],
            "rdns_patterns": [r"(?:^|\.)top\-ix\.org\.?$"]
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
            "rdns_patterns": [r"(?:^|\.)minap\.it\.?$"]
        },
        {
            "id": "vsix",
            "name": "VSIX - Venice / Padua Internet eXchange",
            "facility": "Università di Padova, Viale Trieste",
            "city": "Padova",
            "country": "Italia",
            "country_code": "IT",
            "coordinates": {"lat": 45.4064, "lon": 11.8768},
            "subnets": ["194.242.224.0/24", "195.69.148.0/24", "185.1.201.0/24", "2001:7f8:56::/64"],
            "rdns_patterns": [r"(?:^|\.)vsix\.it\.?$"]
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
            "subnets": ["80.81.192.0/21", "2001:7f8::/64"],
            "rdns_patterns": [r"(?:^|\.)de\-cix\.net\.?$", r"(?:^|\.)decix\.net\.?$"]
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
            "rdns_patterns": [r"(?:^|\.)ams\-ix\.net\.?$"]
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
            "subnets": ["195.66.224.0/22", "2001:7f8:4::/64"],
            "rdns_patterns": [r"(?:^|\.)linx\.net\.?$"]
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

    def probe_parallel_targets(
        self,
        targets: Optional[List[Dict[str, str]]] = None,
        timeout_s: float = 12.0
    ) -> Dict[str, Any]:
        """
        Esegue traceroute rootless paralleli verso 4 target divergenti con un tetto rigido di timeout (12.0s).
        """
        if targets is None:
            targets = [
                {"id": "cloudflare", "label": "Cloudflare Anycast", "ip": "1.1.1.1"},
                {"id": "google", "label": "Google Edge Anycast", "ip": "8.8.8.8"},
                {"id": "aws", "label": "AWS Global Edge", "ip": "13.248.118.1"},
                {"id": "domestic_ixp", "label": "Domestic IXP Anchor (MIX / NaMeX)", "ip": "217.29.66.1"}
            ]

        results = {}
        futures_map = {}

        is_test_env = bool(os.environ.get("NETPROBE_SPEED_HOST") or os.environ.get("NETPROBE_QUICK_TRACEROUTE"))
        max_hops = 3 if is_test_env else 12
        probes = 1 if is_test_env else (1 if is_windows() else 3)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(targets))) as pool:
            for t in targets:
                fut = pool.submit(self.measure_access_profile, t["ip"], max_hops=max_hops, probes=probes)
                futures_map[fut] = t

            done, not_done = concurrent.futures.wait(futures_map.keys(), timeout=timeout_s)
            for fut in not_done:
                fut.cancel()

            for fut in done:
                t_info = futures_map[fut]
                try:
                    prof = fut.result()
                    hops = prof.get("hops") or []
                    for h in hops:
                        hip = h.get("ip")
                        if hip and hip != "*":
                            try:
                                ip_obj = ipaddress.ip_address(hip)
                                if not ip_obj.is_private and not ip_obj.is_loopback:
                                    if h.get("asn") is None:
                                        h_asn, h_name = lookup_ip_asn(hip)
                                        h["asn"] = h_asn
                                        h["asn_name"] = h_name
                                    if h.get("rdns") is None:
                                        h["rdns"] = lookup_ip_rdns(hip, timeout_s=0.5)
                            except ValueError:
                                pass
                        if h.get("rdns"):
                            h["rdns_parsed"] = parse_rdns_metro_and_role(h.get("rdns"))
                    results[t_info["id"]] = hops
                except Exception:
                    results[t_info["id"]] = []

        merged = merge_multi_target_paths(results)
        merged["raw_paths"] = results
        return merged

    def analyze_ixp_and_bng(
        self,
        wan_data: Dict[str, Any],
        progress_cb=None,
        anycast_colo: Optional[str] = None,
        full_scan: bool = True
    ) -> Dict[str, Any]:
        """
        Esegue l'analisi completa:
        1. Query Anycast PoP & Multi-CDN inspection (Cloudflare, Fastly, CloudFront)
        2. In modalità full_scan: traceroute paralleli a 4 target divergenti con timeout 12.0s
        3. Risoluzione dinamica ASN & rDNS profondo (ruoli router e metro grammar)
        4. Burst ping dell'Hop 2 (BNG / First Provider Hop)
        5. Match deterministico subnet IXP Peering LAN
        6. Mappatura campus datacenter e colocation fisica (Campus Caldera, NaMeX, Data4, Equinix, ecc.)
        7. Classificazione e sintesi del flusso infrastrutturale
        """
        is_test_env = bool(os.environ.get("NETPROBE_SPEED_HOST") or os.environ.get("NETPROBE_QUICK_TRACEROUTE"))
        multi_cdn = {}

        # 1. Anycast Trace PoP & Multi-CDN Inspection
        if anycast_colo is None:
            anycast_colo = wan_data.get("colo") or (wan_data.get("cloudflare_trace") or {}).get("colo")
            if not anycast_colo and (wan_data.get("asn") or wan_data.get("public_ipv4") or wan_data.get("probe_anycast")):
                if progress_cb:
                    progress_cb("Verifica PoP Anycast Edge CDN (Cloudflare, Fastly, AWS)...", 10)
                if not is_test_env:
                    multi_cdn = probe_multi_cdn_pops(timeout_s=1.5)
                    anycast_colo = multi_cdn.get("verified_metro_code") or (multi_cdn.get("cloudflare") or {}).get("colo")
                if not anycast_colo:
                    cf_trace = probe_cloudflare_trace(timeout_s=1.5)
                    anycast_colo = cf_trace.get("colo")
                    if cf_trace and not multi_cdn:
                        multi_cdn = {"cloudflare": cf_trace, "verified_metro_code": anycast_colo}

        # 2. Multi-target Divergent Paths in Full Scan mode
        multi_target_analysis = {}
        if full_scan and not is_test_env:
            if progress_cb:
                progress_cb("Esecuzione traceroute multi-target paralleli (Cloudflare, Google, AWS, IXP)...", 15)
            multi_target_analysis = self.probe_parallel_targets(timeout_s=12.0)

        # 3. Access Profile Primary Traceroute
        if progress_cb:
            progress_cb("Esecuzione traceroute multi-probe per profilo di accesso...", 20)

        max_hops = 3 if is_test_env else 12
        probes = 1 if is_test_env else 8
        target = "1.1.1.1"

        if multi_target_analysis.get("raw_paths", {}).get("cloudflare"):
            hops = multi_target_analysis["raw_paths"]["cloudflare"]
            access_profile = build_access_profile_from_hops(hops, target=target)
        else:
            access_profile = self.measure_access_profile(target, max_hops=max_hops, probes=probes)
            hops = access_profile.get("hops") or []
            if not is_test_env and (not hops or len([h for h in hops if h.get("flags", {}).get("responds_to_ping")]) < 2):
                target = "8.8.8.8"
                access_profile = self.measure_access_profile(target, max_hops=12, probes=8)
                hops = access_profile.get("hops") or []

        # Risoluzione dinamica ASN, rDNS e parsing profondo grammatica hostnames
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
            if h.get("rdns"):
                rdns_parsed = parse_rdns_metro_and_role(h.get("rdns"))
                h["rdns_parsed"] = rdns_parsed
                if rdns_parsed.get("carrier") and not h.get("asn_name"):
                    h["asn_name"] = rdns_parsed["carrier"]

        # 4. Individuazione e Burst Ping di Hop 2 (BNG / First Hop Provider)
        hop2_ip, hop2_metrics = self._probe_hop2_bng(hops, progress_cb=progress_cb)
        path_mtu = self.probe_path_mtu()

        # 5. Match Subnet Peering LAN IXP
        matched_ixp, match_evidence = self._find_ixp_in_hops(hops)

        # 6. PeeringDB lookup per ASN utente
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

        # 7. Classificazione IXP / PNI
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

        # 8. Mappatura Facility Datacenter Campus
        facility = resolve_datacenter_facility(
            ip=egress_ip,
            rdns=match_evidence.get("rdns") if match_evidence else None,
            ixp_id=matched_ixp.get("id") if matched_ixp else None,
            metro_code=classification.get("metro_code") or anycast_colo,
            anycast_colo=anycast_colo,
            city=classification.get("city"),
            hops=hops
        )
        if facility:
            if not classification.get("facility"):
                classification["facility"] = facility["facility_name"]
            if not classification.get("coordinates") and facility.get("coordinates"):
                classification["coordinates"] = facility["coordinates"]

        # 9. Costruzione del flusso topologico e metro egress
        topo_flow = build_topological_flow(hops, facility=facility, colo=anycast_colo, target=target)
        metro_city = classification.get("city") or (facility.get("city") if facility else None)
        metro_code = (classification.get("metro_code") or (facility.get("metro_code") if facility else anycast_colo))
        metro_egress = {
            "metro_city": metro_city,
            "metro_code": metro_code,
            "exit_router_ip": egress_ip or (hops[-1].get("ip") if hops else None),
            "transit_carrier": classification.get("peering_type") or "Direct PNI / Transit",
            "facility_name": facility.get("facility_name") if facility else None,
            "verified_via": classification.get("detection_method") or "Anycast PoP / AS-Boundary"
        }

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

        transit_carriers = multi_target_analysis.get("transit_carriers", [])
        if not transit_carriers:
            for h in hops:
                hasn = h.get("asn")
                if hasn in (6762, 1299, 3356, 3257, 174):
                    carrier_tag = h.get("asn_name") or f"AS{hasn}"
                    if carrier_tag not in transit_carriers:
                        transit_carriers.append(carrier_tag)

        result = {
            "detected_ixp": classification.get("ixp_name"),
            "ixp_city": classification.get("city"),
            "ixp_facility": classification.get("facility") if is_identified else None,
            "peering_type": classification.get("peering_type") if is_identified else None,
            "detection_method": classification.get("detection_method") if is_identified else None,
            "confidence": classification.get("confidence") if is_identified else None,
            "matched_hop_ip": classification.get("matched_hop_ip"),
            "matched_subnet": classification.get("matched_subnet"),
            "rtt_to_ixp_ms": classification.get("rtt_to_ixp_ms"),
            "coordinates": classification.get("coordinates") or (facility.get("coordinates") if facility else None),
            "anycast_colo": anycast_colo,
            "traceroute_hops": hops,
            "access_profile": access_profile,
            "hop2_bng": ({"ip": hop2_ip, **hop2_metrics} if hop2_ip else None),
            "path_mtu": path_mtu,
            "hop2_skipped_hops": hop2_metrics.get("skipped_hops", []),
            "peeringdb_facilities": peeringdb_info.get("facilities", []),
            "analysis_notes": classification.get("notes", []),
            "hypothesis": classification.get("hypothesis"),
            "is_identified": is_identified,
            "datacenter_facility": facility,
            "metro_egress": metro_egress,
            "multi_cdn_inspection": multi_cdn,
            "multi_target_analysis": multi_target_analysis,
            "topological_flow": topo_flow,
            "transit_carriers": transit_carriers
        }
        return self._reconcile_egress(result, wan_data, peeringdb_info, multi_target_analysis, multi_cdn, target)


    @staticmethod
    def _parse_multiprobe_traceroute(raw: str) -> List[Dict[str, Any]]:
        hops = []
        hop_chunks = []
        curr_hop = None
        curr_lines = []

        for line in raw.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("traceroute") or line_str.startswith("Tracing") or line_str.startswith("over a maximum") or line_str.startswith("Trace complete") or line_str.startswith("Traccia"):
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

    def _icmp_ttl_stepping_traceroute(self, target: str, max_hops: int = 20) -> List[Dict[str, Any]]:
        """
        Fallback traceroute non-privilegiato (userspace e zero root) tramite loop di TTL stepping ICMP.
        Invia pacchetti ping incrementando il TTL da 1 a max_hops (max 20).
        Si arresta al raggiungimento dell'IP target o dopo 3 hop consecutivi non responsivi oltre l'hop 3.
        """
        hops = []
        consec_silent = 0
        use_m_flag = is_macos()
        reply_re = re.compile(r"(?:bytes from|From|Reply from|Risposta da)\s+(?:[^\s(]+\s+\()?([0-9\.]+)", re.IGNORECASE)
        time_re = re.compile(r"(?:time|tempo|durata)?\s*[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)

        for ttl in range(1, max_hops + 1):
            t0 = time.perf_counter()
            if is_windows():
                cmd = ["ping", "-n", "1", "-w", "800", "-i", str(ttl), target]
            elif is_macos():
                if use_m_flag:
                    cmd = ["ping", "-n", "-c", "1", "-m", str(ttl), "-W", "500", "-t", "1", target]
                else:
                    cmd = ["ping", "-n", "-c", "1", "-t", str(ttl), "-W", "500", target]
            else:  # Linux iputils
                cmd = ["ping", "-n", "-c", "1", "-t", str(ttl), "-W", "1", target]

            proc = None
            router_ip = None
            rtt_val = None
            raw_buf = ""

            if is_windows():
                try:
                    c, out, _ = run_cmd(cmd, timeout=1.2)
                    out_lower = out.lower()
                    if "request timed out" in out_lower or "richiesta scaduta" in out_lower:
                        router_ip = None
                    else:
                        m = reply_re.search(out)
                        if m:
                            cand_ip = m.group(1).rstrip(":")
                            try:
                                ipaddress.ip_address(cand_ip)
                                router_ip = cand_ip
                                tm = time_re.search(out)
                                if tm:
                                    rtt_val = round(float(tm.group(1)), 2)
                            except ValueError:
                                pass
                except Exception:
                    pass
            else:
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT
                    )
                    fd = proc.stdout.fileno()
                    has_sb = False
                    if hasattr(os, "set_blocking"):
                        try:
                            os.set_blocking(fd, False)
                            has_sb = True
                        except Exception:
                            has_sb = False

                    start_wait = time.perf_counter()
                    timeout_hop = 0.35  # max 350ms per hop non responsivo

                    while (time.perf_counter() - start_wait) < timeout_hop:
                        chunk = b""
                        if has_sb:
                            try:
                                chunk = os.read(fd, 4096)
                            except (BlockingIOError, InterruptedError):
                                pass
                        else:
                            if proc.poll() is not None:
                                chunk = proc.stdout.read()

                        if chunk:
                            raw_buf += chunk.decode("utf-8", "replace")
                            if is_macos() and use_m_flag and ("illegal option" in raw_buf.lower() or "usage:" in raw_buf.lower()):
                                use_m_flag = False
                                break

                            m = reply_re.search(raw_buf)
                            if m:
                                cand_ip = m.group(1).rstrip(":")
                                try:
                                    ipaddress.ip_address(cand_ip)
                                    router_ip = cand_ip
                                    tm = time_re.search(raw_buf)
                                    if tm:
                                        rtt_val = round(float(tm.group(1)), 2)
                                    break
                                except ValueError:
                                    pass
                        time.sleep(0.005)
                except Exception:
                    pass
                finally:
                    if proc:
                        try:
                            if proc.stdout:
                                proc.stdout.close()
                        except Exception:
                            pass
                        try:
                            proc.terminate()
                            proc.wait(timeout=0.05)
                        except Exception:
                            try:
                                proc.kill()
                                proc.wait(timeout=0.05)
                            except Exception:
                                pass

            dt = round((time.perf_counter() - t0) * 1000.0, 2)
            if rtt_val is None:
                rtt_val = dt

            if router_ip:
                consec_silent = 0
                hops.append({
                    "hop": ttl,
                    "ip": router_ip,
                    "ips": [router_ip],
                    "rtts": [rtt_val],
                    "rtt_ms": rtt_val
                })
                if router_ip == target:
                    break
            else:
                hops.append({
                    "hop": ttl,
                    "ip": "*",
                    "ips": [],
                    "rtts": [],
                    "rtt_ms": None
                })
                if ttl > 3:
                    consec_silent += 1
                    if consec_silent >= 3:
                        break

        return hops

    def measure_access_profile(self, target: str = "1.1.1.1", max_hops: int = 10, probes: int = 8) -> Dict[str, Any]:
        """
        Esegue un traceroute rootless multi-probe con waterfall a 2 stadi:
        1. Primario: traceroute di sistema (/usr/sbin/traceroute con verifica TCP probe senza root su macOS)
        2. Fallback: ICMP TTL-stepping rapido tramite ping se il primario restituisce 0 hop o timeout <= 3s.
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

        tcp_permitted = False
        if is_macos():
            c, t_out, t_err = run_cmd(["traceroute", "-P", "TCP", "-p", "80", "-n", "-m", "1", "-w", "1", target], timeout=1.0)
            if c == 0 and "pcap_activate" not in t_out and "pcap_activate" not in t_err:
                tcp_permitted = True

        if is_windows():
            cmd = ["tracert", "-d", "-w", "800", "-h", str(max_hops), target]
        elif is_macos():
            if tcp_permitted:
                cmd = ["traceroute", "-P", "TCP", "-p", "80", "-n", "-m", str(max_hops), "-q", str(probes), "-w", "1", target]
            else:
                cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", str(probes), "-w", "1", target]
        else:  # Linux
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", str(probes), "-w", "1", target]

        tracert_timeout = min(max_hops * 1.0 + 3.0, 15.0) if is_windows() else 3.0
        code, out, _ = run_cmd(cmd, timeout=tracert_timeout)
        parsed_hops = self._parse_multiprobe_traceroute(out)
        responsive = [h for h in parsed_hops if h.get("ip") and h.get("ip") != "*"]

        # Se il traceroute standard ha fallito (firewall UDP o timeout <= 3s), attiva il fallback ICMP TTL-stepping
        if not responsive:
            parsed_hops = self._icmp_ttl_stepping_traceroute(target, max_hops=min(max_hops, 20))
            out = "\n".join(f" {h['hop']}  {h['ip']}  {h.get('rtt_ms') or '*'} ms" for h in parsed_hops)

        profile = build_access_profile_from_hops(parsed_hops, target=target)
        profile["target"] = target
        profile["raw"] = out
        return profile

    def run_traceroute(self, target: str, max_hops: int = 16) -> Dict[str, Any]:
        """
        Esegue un traceroute verso il target.
        Cross-platform con waterfall a 2 stadi: non richiede privilegi di root.
        """
        hops = []
        raw_output = ""

        tcp_permitted = False
        if is_macos():
            c, t_out, t_err = run_cmd(["traceroute", "-P", "TCP", "-p", "80", "-n", "-m", "1", "-w", "1", target], timeout=1.0)
            if c == 0 and "pcap_activate" not in t_out and "pcap_activate" not in t_err:
                tcp_permitted = True

        if is_windows():
            cmd = ["tracert", "-d", "-w", "800", "-h", str(max_hops), target]
        elif is_macos():
            if tcp_permitted:
                cmd = ["traceroute", "-P", "TCP", "-p", "80", "-n", "-m", str(max_hops), "-q", "1", "-w", "1", target]
            else:
                cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", "1", "-w", "1", target]
        else:  # Linux
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", "1", "-w", "1", target]
            # Se traceroute non c'è, tenta tracepath
            code, _, _ = run_cmd(["which", "traceroute"])
            if code != 0:
                cmd = ["tracepath", "-n", "-m", str(max_hops), target]

        tracert_timeout = min(max_hops * 1.0 + 3.0, 15.0) if is_windows() else 3.0
        code, out, _ = run_cmd(cmd, timeout=tracert_timeout)
        raw_output = out

        # Parsing output riga per riga
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("traceroute") or line.startswith("Tracing") or line.startswith("over a maximum") or line.startswith("Trace complete") or line.startswith("Traccia"):
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

        responsive = [h for h in hops if h.get("ip") and h.get("ip") != "*"]
        if not responsive:
            # Fallback ICMP TTL-stepping
            ttl_hops = self._icmp_ttl_stepping_traceroute(target, max_hops=min(max_hops, 20))
            hops = []
            for th in ttl_hops:
                ip_str = th.get("ip", "*")
                rdns_val = None
                if ip_str != "*" and not ip_str.startswith("10.") and not ip_str.startswith("192.168."):
                    try:
                        rdns_val = socket.getnameinfo((ip_str, 0), 0)[0]
                        if rdns_val == ip_str:
                            rdns_val = None
                    except Exception:
                        rdns_val = None
                hops.append({
                    "hop": th["hop"],
                    "ip": ip_str,
                    "rtt_ms": th.get("rtt_ms"),
                    "rdns": rdns_val
                })
            raw_output = "\n".join(f" {h['hop']}  {h['ip']}  {h.get('rtt_ms') or '*'} ms" for h in hops)

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
            m = re.search(r"(?:time|tempo|durata)?\s*[=<]\s*([\d\.]+)\s*ms", line, re.IGNORECASE)
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
            cmd = ["ping", "-f", "-l", str(payload), "-n", "1", "-w", "800", host]
        elif is_macos():
            cmd = ["ping", "-D", "-s", str(payload), "-c", "1", "-t", str(int(timeout_s)), host]
        else:
            cmd = ["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", str(int(timeout_s)), host]
        _, out, err = run_cmd(cmd, timeout=timeout_s + 2.0)
        text = (out + "\n" + err).lower()
        if self._parse_ping_times(out):
            return "ok", None
        if re.search(r"too long|frag|needs to be fragmented|frammentare|frammentazione", text):
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

    def _find_ixp_in_hops(self, hops):
        for h in hops:
            try:
                addr = ipaddress.ip_address(h.get("ip", "*"))
            except ValueError:
                continue
            for ixp, networks in self._compiled_networks:
                for network in networks:
                    if addr in network:
                        return ixp, {"type": "peering_subnet_match", "hop": h.get("hop"),
                            "ip": str(addr), "subnet": str(network), "rtt_ms": min_rtt(h)}
        for h in hops:
            for ixp, _ in self._compiled_networks:
                for pattern in ixp.get("rdns_patterns", []):
                    if re.search(pattern, h.get("rdns") or "", re.IGNORECASE):
                        return ixp, {"type": "rdns_match", "hop": h.get("hop"), "ip": h.get("ip"),
                            "rdns": h.get("rdns"), "rtt_ms": min_rtt(h)}
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
            if (now - entry.get("timestamp", 0)) < (7 * 86400) and entry.get("data", {}).get("schema_version") == 2:
                return entry.get("data", {})

        def fetch(endpoint, query):
            req = urllib.request.Request(f"https://www.peeringdb.com/api/{endpoint}?{query}",
                headers={"User-Agent": "NetProbe/2.0 (Network Peering Intelligence)"})
            with urllib.request.urlopen(req, timeout=3.0) as response:
                return json.loads(response.read().decode("utf-8")).get("data", [])

        def optional_fetch(endpoint, query):
            try:
                return fetch(endpoint, query)
            except Exception:
                return []

        try:
            netixlan = fetch("netixlan", f"asn={asn}&depth=2")
            netfac = optional_fetch("netfac", f"asn={asn}&depth=2")
            ix_ids = sorted({str(item["ix_id"]) for item in netixlan if item.get("ix_id")})
            exchanges = optional_fetch("ix", "id__in=" + ",".join(ix_ids)) if ix_ids else []
            by_id = {item["id"]: item for item in exchanges}
            prefixes = optional_fetch("ixpfx", "ix__in=" + ",".join(ix_ids)) if ix_ids else []
            for item in netixlan:
                ix = by_id.get(item.get("ix_id"), {})
                item["city"] = item.get("city") or ix.get("city")
                item["prefixes"] = [p["prefix"] for p in prefixes
                                    if p.get("ix_id", p.get("ixlan_id")) == item.get("ix_id")
                                    and p.get("status", "ok") == "ok"]
            for item in netfac:
                facility = item.get("fac") or {}
                item["city"] = item.get("city") or facility.get("city")
                item["name"] = item.get("name") or facility.get("name")
            # Retain the original list/key for existing JSON consumers.
            facilities = [{k: item.get(k) for k in ("name", "ix_id", "ipaddr4", "ipaddr6", "speed", "city")}
                          for item in netixlan]
            result = {"asn": asn, "facilities": facilities, "netixlan": netixlan,
                      "netfac": netfac, "schema_version": 2}
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
                    "confidence": "90%",
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
        for h in reversed(hops):
            parsed = parse_rdns_metro_and_role(h.get("rdns"))
            if parsed.get("metro_code"):
                rdns_hub_code = parsed["metro_code"]
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
                ixp_name = hub_def.get("ixp_name") or f"PNI / Direct Handoff at {hub_def['city']}"
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
                parsed_border = parse_rdns_metro_and_role(last_egress.get("rdns"))
                if parsed_border.get("metro_code") in ANYCAST_COLO_HUBS:
                    verified_hub_code = parsed_border["metro_code"]
                    hub_def = ANYCAST_COLO_HUBS[verified_hub_code]
                    ixp_name = f"PNI / Direct Handoff at {parsed_border['city']}"
                    det_method = "Reverse DNS Geolocation + Analisi AS-Boundary"
                notes.append(f"Router di handoff / egress identificato su hop {last_egress.get('hop')} ({matched_egress_ip}).")

            notes.append(f"Interconnessione PNI / Transito verificata su hub di {hub_def['city']} via {det_method}.")
            return {
                "ixp_name": ixp_name,
                "city": hub_def["city"],
                "facility": hub_def.get("facility"),
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
        polo_name = None  # Subscriber GeoIP does not locate a border router.

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

    @staticmethod
    def _city_key(city):
        city = str(city or '').strip().lower()
        aliases = {'milan': 'milano', 'rome': 'roma', 'turin': 'torino',
                   'florence': 'firenze', 'naples': 'napoli', 'venice': 'venezia',
                   'padua': 'padova', 'frankfurt': 'francoforte', 'london': 'londra'}
        return aliases.get(city, city)

    def _city_presence(self, info, city):
        """Presence is supporting evidence, never proof of switch traversal."""
        key = self._city_key(city)
        return [entry for kind in ('facilities', 'netixlan', 'netfac')
                for entry in info.get(kind, [])
                if key and self._city_key(entry.get('city')) == key]

    def _dynamic_ixp(self, hops, info):
        # netixlan participant addresses alone do NOT establish a LAN prefix.
        for h in hops:
            try:
                addr = ipaddress.ip_address(h.get('ip', '*'))
            except ValueError:
                continue
            for entry in info.get('netixlan', []):
                for prefix in entry.get('prefixes', []):
                    prefix = prefix.get('prefix') if isinstance(prefix, dict) else prefix
                    try:
                        network = ipaddress.ip_network(prefix)
                    except (ValueError, TypeError):
                        continue
                    if addr in network:
                        return ({'name': entry.get('name'), 'city': entry.get('city'),
                                 'facility': None, 'coordinates': entry.get('coordinates')},
                                {'type': 'peering_subnet_match', 'hop': h.get('hop'),
                                 'ip': str(addr), 'subnet': str(network), 'rtt_ms': min_rtt(h)})
        return None, None

    def _resolve_exit_path(self, target, hops, wan, info, colo, hop2, target_rtt=None):
        """Resolve a border and its metadata as one inseparable observation."""
        hops = sorted(hops, key=lambda h: h.get('hop', 0))
        ixp, evidence = self._find_ixp_in_hops(hops)
        dynamic_ixp, dynamic_evidence = self._dynamic_ixp(hops, info)
        if dynamic_ixp and (not evidence or evidence['type'] != 'peering_subnet_match'):
            ixp, evidence = dynamic_ixp, dynamic_evidence
        dest_asn = {'1.1.1.1': 13335, '8.8.8.8': 15169, '13.248.118.1': 16509}.get(target)
        candidates = []
        for h in hops:
            if h.get('ip') == target or target in (h.get('ips') or []) or (dest_asn and h.get('asn') == dest_asn):
                break
            try:
                addr = ipaddress.ip_address(h.get('ip', '*'))
            except ValueError:
                continue
            if addr.is_global and min_rtt(h) is not None:
                candidates.append(h)
        border = next((h for h in hops if evidence and h.get('ip') == evidence['ip']), None)
        border = border or (candidates[-1] if candidates else None)
        if not border:
            return None
        try:
            if not ipaddress.ip_address(border['ip']).is_global:
                return None
        except ValueError:
            return None
        parsed = parse_rdns_metro_and_role(border.get('rdns'))
        # HTTP observations may suggest a city only when the hop has no city token.
        path_colo = parsed.get('metro_code') or colo
        classification = self._classify_exchange(ixp, evidence, hops, info, wan, {}, path_colo, target)
        city = parsed.get('city') or (classification.get('city')
                if classification.get('is_identified') and (ixp or colo) else None)
        code = parsed.get('metro_code') or next((k for k, v in ANYCAST_COLO_HUBS.items()
                   if self._city_key(v.get('city')) == self._city_key(city)), None)
        presence = self._city_presence(info, city)
        public = bool(ixp and evidence)
        method = ('CIDR_EXACT' if evidence['type'] == 'peering_subnet_match' else 'RDNS_SIGNATURE') if public else (
            'PEERINGDB_CITY_INTERSECTION' if presence else 'HEURISTIC_FALLBACK')
        interconnect = 'PUBLIC_IXP_LAN' if public else ('PNI_OR_COLO_FACILITY' if city and classification.get('is_identified') else 'BACKBONE_TRANSIT')
        dedicated = {hop2['ip']: hop2} if hop2 and hop2.get('ip') else {}
        bounded = bound_path_rtts(hops, dedicated, target=target, target_rtt=target_rtt)
        effective = next(h.get('effective_rtt_ms') for h in bounded if h.get('ip') == border['ip'])
        if parsed.get('city') and not public:
            # Do not invent a building from a city code or other hops in this path.
            classification.update(city=city, metro_code=code,
                ixp_name=f'PNI / Direct Handoff at {city}', facility=None,
                coordinates=ANYCAST_COLO_HUBS.get(code, {}).get('coordinates'),
                matched_hop_ip=border['ip'], rtt_to_ixp_ms=min_rtt(border),
                confidence='75% (PeeringDB city presence)' if presence else '65% (rDNS metro handoff inference)',
                peering_type=f'PNI / Direct Handoff at {city}',
                is_identified=True, detection_method='Reverse DNS Geolocation + Analisi AS-Boundary')
        return {'target': target, 'border_ip': border['ip'], 'border_rdns': border.get('rdns'),
                'city': city, 'metro_code': code, 'asn': border.get('asn') or parsed.get('asn'),
                'raw_rtt_ms': min_rtt(border), 'effective_rtt_ms': effective,
                'copp_detected': any(h['copp_detected'] for h in bounded),
                'interconnect_type': interconnect, 'ixp_match_method': method,
                'confidence': (1.0 if method == 'CIDR_EXACT' else 0.90 if public else 0.75 if presence else 0.65),
                'colocated_peering_presence': presence, '_classification': classification,
                '_hops': hops, '_authoritative_location': bool(parsed.get('city'))}

    def _reconcile_egress(self, result, wan, info, multi, cdn, target):
        primary = result.get('traceroute_hops') or []
        result['access_profile']['target'] = target
        colo = result.get('anycast_colo')
        primary_exit = self._resolve_exit_path(target, primary, wan, info, colo, result.get('hop2_bng'))
        exits = [primary_exit] if primary_exit else []
        target_ips = {'cloudflare': '1.1.1.1', 'google': '8.8.8.8', 'aws': '13.248.118.1',
                      'domestic_ixp': '217.29.66.1'}
        for name, path in multi.get('raw_paths', {}).items():
            dest = target_ips.get(name, (multi.get('targets', {}).get(name) or {}).get('target_ip') or name)
            target_rtt = (multi.get('targets', {}).get(name) or {}).get('min_rtt_ms')
            node = self._resolve_exit_path(dest, path, wan, info, None, result.get('hop2_bng'),
                                           target_rtt=target_rtt)
            if node and not any(e['target'] == dest and e['border_ip'] == node['border_ip'] for e in exits):
                exits.append(node)
        # CDN consensus selects an observed border; it cannot relocate any border.
        wanted = ANYCAST_COLO_HUBS.get(cdn.get('verified_metro_code'), {}).get('city')
        matching = [e for e in exits if e is not primary_exit and wanted
                    and self._city_key(e['city']) == self._city_key(wanted)]
        # Prefer the observed route with the tightest downstream RTT bound.
        selected = min(matching, key=lambda e: e['effective_rtt_ms'] if e['effective_rtt_ms'] is not None else float('inf')) if matching else primary_exit
        if primary_exit is None and exits:
            selected = min(exits, key=lambda e: (-e['confidence'],
                e['effective_rtt_ms'] if e['effective_rtt_ms'] is not None else float('inf')))
        metro = result['metro_egress']
        if selected:
            cl = selected['_classification']
            changed = selected is not primary_exit or selected['_authoritative_location'] or selected['ixp_match_method'] == 'CIDR_EXACT'
            if changed:
                for old, new in [('detected_ixp', 'ixp_name'), ('ixp_city', 'city'),
                                 ('ixp_facility', 'facility'), ('peering_type', 'peering_type'),
                                 ('detection_method', 'detection_method'), ('confidence', 'confidence'),
                                 ('matched_subnet', 'matched_subnet'), ('coordinates', 'coordinates')]:
                    result[old] = cl.get(new)
                result['matched_hop_ip'] = selected['border_ip']
                result['rtt_to_ixp_ms'] = selected['raw_rtt_ms']
                result['is_identified'] = cl.get('is_identified', False)
                result['datacenter_facility'] = None
                result['ixp_facility'] = cl.get('facility')
            metro.update(metro_city=selected['city'], metro_code=selected['metro_code'],
                         exit_router_ip=selected['border_ip'], exit_router_rdns=selected['border_rdns'],
                         interconnect_type=selected['interconnect_type'], ixp_match_method=selected['ixp_match_method'],
                         interconnect_confidence=selected['confidence'],
                         colocated_peering_presence=selected['colocated_peering_presence'],
                         facility_name=result.get('ixp_facility'), verified_via=result.get('detection_method'),
                         transit_carrier=result.get('peering_type'))
            result['egress_latency_path'] = {'target': selected['target'], 'hops': selected['_hops']}
        else:
            result.update(detected_ixp='IXP non identificato', is_identified=False,
                          ixp_city=None, ixp_facility=None, peering_type=None, coordinates=None,
                          matched_hop_ip=None, matched_subnet=None, rtt_to_ixp_ms=None,
                          datacenter_facility=None, detection_method=None, confidence=None)
            result.pop('egress_latency_path', None)
            metro.update(metro_city=None, metro_code=None, exit_router_ip=None,
                         exit_router_rdns=None, facility_name=None, transit_carrier=None,
                         verified_via=None, interconnect_confidence=None, colocated_peering_presence=[],
                         interconnect_type='BACKBONE_TRANSIT', ixp_match_method='HEURISTIC_FALLBACK')
        if selected and selected['interconnect_type'] != 'PUBLIC_IXP_LAN':
            facility = result.get('datacenter_facility') or {}
            if (facility.get('matched_ip') != selected['border_ip']
                    or self._city_key(facility.get('city')) != self._city_key(selected['city'])):
                result['datacenter_facility'] = None
                result['ixp_facility'] = None
                metro['facility_name'] = None
        if not selected or not selected['city']:
            if selected:
                result['detected_ixp'] = 'IXP non identificato'
                result['is_identified'] = False
                result['peering_type'] = None
                metro['facility_name'] = None
            result['datacenter_facility'] = None
            result['coordinates'] = None
            result['ixp_city'] = None
            result['ixp_facility'] = None
        documented = [{k: v for k, v in e.items() if not k.startswith('_')} for e in exits]
        cities = {self._city_key(e['city']) for e in exits if e['city']}
        if wanted:
            cities.add(self._city_key(wanted))
        metro.update(routing_topology='MULTI_EXIT_SPLIT' if len(cities) > 1 else 'SINGLE_EXIT', exit_paths=documented)
        result['egress_paths'] = documented
        result['multi_target_analysis'] = multi
        result['multi_cdn_inspection'] = cdn
        # Render the primary route with its own hub even if the summary selects another.
        result['topological_flow'] = build_topological_flow(primary, facility=None,
            colo=primary_exit['metro_code'] if primary_exit else None, target=target)
        return result

    def reclassify_offline(
        self,
        wan_data: Dict[str, Any],
        hops: List[Dict[str, Any]],
        hop2_metrics: Optional[Dict[str, Any]] = None,
        anycast_colo: Optional[str] = None,
        target: Optional[str] = "1.1.1.1",
        multi_target_analysis: Optional[Dict[str, Any]] = None,
        multi_cdn_inspection: Optional[Dict[str, Any]] = None,
        peeringdb_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Rivaluta la classificazione IXP/PNI e l'access profile in modalità 100% offline
        a partire da traceroute_hops memorizzati (senza eseguire chiamate di rete live).
        """
        hop2_metrics = hop2_metrics or {}
        matched_ixp, match_evidence = self._find_ixp_in_hops(hops)

        user_asn = wan_data.get("asn") or ""
        asn_clean = re.sub(r"[^\d]", "", str(user_asn))
        supplied_peeringdb = peeringdb_info
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

        if supplied_peeringdb is not None:
            peeringdb_info = supplied_peeringdb

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

        for h in hops:
            if h.get("rdns"):
                rdns_parsed = parse_rdns_metro_and_role(h.get("rdns"))
                h["rdns_parsed"] = rdns_parsed
                if rdns_parsed.get("carrier") and not h.get("asn_name"):
                    h["asn_name"] = rdns_parsed["carrier"]

        facility = resolve_datacenter_facility(
            ip=egress_ip,
            rdns=match_evidence.get("rdns") if match_evidence else None,
            ixp_id=matched_ixp.get("id") if matched_ixp else None,
            metro_code=classification.get("metro_code") or anycast_colo,
            anycast_colo=anycast_colo,
            city=classification.get("city"),
            hops=hops
        )
        if facility:
            if not classification.get("facility"):
                classification["facility"] = facility["facility_name"]
            if not classification.get("coordinates") and facility.get("coordinates"):
                classification["coordinates"] = facility["coordinates"]

        topo_flow = build_topological_flow(hops, facility=facility, colo=anycast_colo, target=target)
        metro_city = classification.get("city") or (facility.get("city") if facility else None)
        metro_code = (classification.get("metro_code") or (facility.get("metro_code") if facility else anycast_colo))
        metro_egress = {
            "metro_city": metro_city,
            "metro_code": metro_code,
            "exit_router_ip": egress_ip or (hops[-1].get("ip") if hops else None),
            "transit_carrier": classification.get("peering_type") or "Direct PNI / Transit",
            "facility_name": facility.get("facility_name") if facility else None,
            "verified_via": classification.get("detection_method") or "Offline Topology Replay"
        }
        multi_cdn = {"verified_metro": metro_city, "verified_metro_code": metro_code, "cloudflare": {"colo": anycast_colo}} if anycast_colo else {}

        if multi_cdn_inspection is not None:
            multi_cdn = multi_cdn_inspection

        transit_carriers = []
        for h in hops:
            hasn = h.get("asn")
            if hasn in (6762, 1299, 3356, 3257, 174):
                carrier_tag = h.get("asn_name") or f"AS{hasn}"
                if carrier_tag not in transit_carriers:
                    transit_carriers.append(carrier_tag)

        access_profile = build_access_profile_from_hops(
            hops,
            target=target,
            egress_ip=egress_ip,
            wan_asn=wan_asn_val,
            dest_asn=dest_asn_val,
            ixp_evidence=match_evidence,
            matched_ixp=matched_ixp
        )

        result = {
            "detected_ixp": classification.get("ixp_name"),
            "ixp_city": classification.get("city"),
            "ixp_facility": classification.get("facility") if is_identified else None,
            "peering_type": classification.get("peering_type") if is_identified else None,
            "detection_method": classification.get("detection_method") if is_identified else None,
            "confidence": classification.get("confidence") if is_identified else None,
            "matched_hop_ip": classification.get("matched_hop_ip"),
            "matched_subnet": classification.get("matched_subnet"),
            "rtt_to_ixp_ms": classification.get("rtt_to_ixp_ms"),
            "coordinates": classification.get("coordinates") or (facility.get("coordinates") if facility else None),
            "anycast_colo": anycast_colo,
            "traceroute_hops": hops,
            "access_profile": access_profile,
            "hop2_bng": ({"ip": hop2_metrics.get("ip") or hops[1].get("ip"), **hop2_metrics} if len(hops) > 1 and hop2_metrics else None),
            "peeringdb_facilities": peeringdb_info.get("facilities", []),
            "analysis_notes": classification.get("notes", []),
            "hypothesis": classification.get("hypothesis"),
            "is_identified": is_identified,
            "datacenter_facility": facility,
            "metro_egress": metro_egress,
            "multi_cdn_inspection": multi_cdn,
            "multi_target_analysis": {},
            "topological_flow": topo_flow,
            "transit_carriers": transit_carriers
        }
        return self._reconcile_egress(result, wan_data, peeringdb_info, (multi_target_analysis or {}), multi_cdn, target)
