# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.
All notable changes to this project are documented in this file.

---

## [1.0.0] - 2026-10-19

### 🇮🇹 Italiano

#### Funzionalità Principali
- **Ispezione Hardware LAN & Wi-Fi**:
  - Supporto esteso a Wi-Fi 7 (802.11be), Wi-Fi 6E (6 GHz), Wi-Fi 6 (802.11ax), Wi-Fi 5 (802.11ac) e schede Ethernet fino a 10G.
  - Parser binario `sysctl` per tabelle di routing e ARP su macOS Darwin (compatibile Darwin 27.x arm64 e x86_64).
  - Database OUI IEEE embedded con risoluzione vendor per interfacce LAN, gateway e vicinato.
- **Riconoscimento Switch di Rete Ethernet**:
  - Discovery passiva L2 su frame Ethernet via BPF per LLDP (`0x88cc`) e CDP (`0x2000`).
  - Scansione attiva L3/L4 zero-root tramite SNMP v1/v2c (`sysName.0`, `sysDescr.0`), mDNS e HTTP title grabber.
  - Diagnosi trasparente per switch unmanaged.
- **WAN, NAT & STUN RFC 5389**:
  - Mappatura completa WAN: rilevamento CGNAT, tipologia NAT (Endpoint-Independent, Address-Restricted, Symmetric).
  - Test binding STUN multi-server senza permessi di root.
  - Verifica supporto UPnP / NAT-PMP.
- **Performance & Bufferbloat**:
  - Test latenza multi-target con calcolo RFC 3550 Interarrival Jitter, dispersioni IQR e percentili p95.
  - Graduazione Bufferbloat (da A+ a F) con baseline idle unificata e misurazione RTT sotto carico bidirezionale (download e upload).
  - Test velocità HTTP/HTTPS multi-thread adattivo con chunking da 5 MB e compensazione overhead di protocollo L2/IP/TCP.
- **Intelligence Peering IXP & Routing Ottico**:
  - Riconoscimento a 3 livelli: Tier 1 Peering LAN IXP (MIX Milano, NaMeX Roma, VSIX, TOP-IX, DE-CIX, AMS-IX, ecc.), Tier 2 Direct PNI (Private Network Interconnect) verificato tramite Anycast PoP Cloudflare `cdn-cgi/trace` e reverse DNS AS-boundary, Tier 3 Unidentified.
  - Risoluzione autonoma ASN per ogni hop via query DNS origin Team Cymru (`origin.asn.cymru.com`).
  - Calcolo efficienza del percorso ottico con separazione dinamica tra accesso locale e dorsale di trasporto, velocità di propagazione nel dielettrico ($204.000\text{ km/s}$) e ratio geodetico.
- **Classificatore Mezzo Fisico Ultimo Miglio**:
  - Modello probabilistico Bayesiano/euristico per FTTH (GPON/XGS-PON), FTTC / VDSL2, FWA, 4G/5G Hotspot e Satellite (Starlink/GEO).
  - Veto deterministici (es. upload > 35 Mbps o download > 250 Mbps escludono fisicamente FTTC).
  - Access profile multi-probe zero-root (burst Hop 2 / BNG, analisi Path MTU 1492 PPPoE vs 1500 IPoE vs 1420 GTP).
- **Interfaccia Utente**:
  - CLI avanzata con output a colori ANSI e tabelle formattate.
  - Web UI fluida con dashboard stile dark glassmorphism, grafici vettoriali SVG ed export HTML/JSON autonomo.
  - Replay tool diagnostico (`tools/replay.py`) per test su catture offline e validazione ground truth.

#### Correzioni e Compatibilità
- Risolto import `Tuple` in `core/adapters/macos.py` per piena compatibilità su Python 3.10/3.11/3.12 multi-OS.
- Pin di `dnspython` alla versione 2.8.0 per supportare Python 3.10 nei runner CI (Linux, macOS, Windows).
- Pulizia completa e gestione conforme `.gitignore` per artefatti di sistema macOS e cache Python.

---

### 🇬🇧 English

#### Core Features
- **LAN Hardware & Wi-Fi Inspection**:
  - Comprehensive support for Wi-Fi 7 (802.11be), Wi-Fi 6E (6 GHz), Wi-Fi 6 (802.11ax), Wi-Fi 5 (802.11ac), and Ethernet up to 10G.
  - Native binary `sysctl` routing and ARP table parser for macOS Darwin (compatible with Darwin 27.x arm64 & x86_64).
  - Embedded IEEE OUI database for vendor MAC resolution on interfaces, default gateways, and LAN neighbors.
- **Connected Ethernet Switch Discovery**:
  - Passive Layer-2 discovery via BPF sniffer for LLDP (`0x88cc`) and CDP (`0x2000`).
  - Active zero-root Layer-3/4 scanning via SNMP v1/v2c (`sysName.0`, `sysDescr.0`), mDNS, and HTTP banner grabber.
  - Transparent diagnostics for unmanaged switches.
- **WAN, NAT & STUN RFC 5389 Mapping**:
  - Complete WAN mapping: CGNAT detection, NAT classification (Endpoint-Independent, Address-Restricted, Port-Restricted, Symmetric).
  - Multi-server STUN binding tests without root permissions.
  - UPnP / NAT-PMP gateway mapping validation.
- **Performance & Bufferbloat Analysis**:
  - Multi-target ping with RFC 3550 Interarrival Jitter, IQR dispersion, and p95 latency percentiles.
  - Bufferbloat grading (A+ through F) using unified idle baselines and bidirectional loaded latency (DL/UL).
  - Multi-threaded adaptive speed test with 5 MB chunking and L2/IP/TCP protocol overhead compensation.
- **IXP Peering Intelligence & Optical Routing**:
  - 3-Tier interconnection hub classification: Tier 1 On-wire IXP Peering LAN (MIX, NaMeX, VSIX, TOP-IX, DE-CIX, AMS-IX, etc.), Tier 2 Direct PNI (Private Network Interconnect) verified via Anycast PoP Cloudflare `cdn-cgi/trace` and boundary rDNS PTR, Tier 3 Unidentified.
  - Autonomous hop ASN resolution via Team Cymru DNS (`origin.asn.cymru.com`).
  - Optical path efficiency estimation with dynamic local access / core transport split, dielectric fiber speed ($204,000\text{ km/s}$), and geodetic ratios.
- **Physical Medium Classification Engine**:
  - Explainable Bayesian/heuristic engine classifying FTTH (GPON/XGS-PON), FTTC / VDSL2, FWA, 4G/5G Hotspot, and Satellite (Starlink/GEO).
  - Deterministic vetoes (e.g., upload > 35 Mbps or download > 250 Mbps strictly veto FTTC).
  - Zero-root multi-probe Access Profile (Hop 2 / BNG burst analysis, Path MTU 1492 PPPoE vs 1500 IPoE vs 1420 GTP).
- **User Interfaces**:
  - Terminal CLI with rich ANSI colors and Unicode table layouts.
  - Web GUI with dark glassmorphism dashboard, inline SVG visualizations, and standalone HTML/JSON export.
  - Diagnostic offline replay tool (`tools/replay.py`) with ground truth validation.

#### Bug Fixes & Cross-Platform Compatibility
- Added missing `Tuple` typing import in `core/adapters/macos.py` for Python 3.10/3.11/3.12 compatibility across all OSes.
- Pinned `dnspython` to version 2.8.0 to ensure native compatibility with Python 3.10 runners in CI.
- Configured clean `.gitignore` to strictly exclude macOS artifacts (`.DS_Store`) and test caches.
