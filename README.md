# NetProbe

**Network intelligence a colpo d'occhio nel tuo terminale.**  
Analizza hardware LAN, switch connessi, peering IXP/PNI, bufferbloat e stima il mezzo fisico dell'ultimo miglio (FTTH, FTTC, FWA, 5G, Satellite) con modelli matematici e zero permessi di root.

[![NetProbe CI](https://github.com/hainetsoftware/netprobe/actions/workflows/tests.yml/badge.svg)](https://github.com/hainetsoftware/netprobe/actions/workflows/tests.yml)
[![Python Version](https://img.shields.io/badge/python-3.8.1%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/hainetsoftware/netprobe)
[![Runtime Bootstrap](https://img.shields.io/badge/dependencies-auto%20bootstrap-blue.svg)](requirements.txt)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*Lingue / Languages:*  **[Italiano](#-italiano)** | **[English](#-english)**

---

<a name="-italiano"></a>
# Italiano

NetProbe trasforma la diagnostica di rete in un'esperienza interattiva da terminale (**TUI**), fluida e immediata come strumenti moderni alla *Claude Code* o *htop*. Non serve imparare decine di comandi complessi: basta avviarlo e navigare con le freccette e il tasto Tab.

Funziona senza permessi di root (`rootless`) e sfrutta la libreria standard di Python.

```bash
# Avvio immediato della dashboard interattiva
./netprobe.py
```

---

## Cosa fa NetProbe

-  **Hardware LAN & Wi-Fi**: Riconosce schede Wi-Fi 7/6E/6/5 ed Ethernet fino a 10G. Legge RSSI, canali radio, SNR, MCS Index, duplex e risolve i vendor MAC tramite database IEEE OUI embedded.
-  **Switch Discovery**: Trova lo switch di rete collegato tramite frame LLDP/CDP o scansione attiva SNMP/mDNS (con diagnosi trasparente se lo switch è unmanaged).
-  **WAN, NAT & STUN RFC 5389**: Verifica connettività IPv4/IPv6 dual-stack, rileva la presenza di CGNAT (RFC 6598) e classifica la natura del NAT (Full Cone / Symmetric).
-  **Bufferbloat & Latenza Sotto Carico**: Misura la latenza a riposo e sotto saturazione bidirezionale assegnando il voto standard da **A+ a F**.
-  **Peering IXP & PNI**: Riconosce i punti di interscambio internet (MIX Milano, NaMeX Roma, VSIX, DE-CIX, AMS-IX) e i Direct PNI (Private Network Interconnect) verso reti Anycast (Cloudflare, Google, Sparkle AS6762).
-  **Efficienza Routing Ottico**: Calcola il ritardo dielettrico teorico della luce in fibra ($204.000\text{ km/s}$) confrontandolo con il percorso reale verso l'hub metropolitano.
-  **Stima Mezzo Fisico Ultimo Miglio**: Classificatore probabilistico ed euristico spiegabile che distingue **FTTH GPON/XGS-PON**, **FTTC / VDSL2**, **FWA**, **4G/5G Hotspot** e **Satellite** (Starlink/GEO), con veti deterministici sulle barriere fisiche di upload e download.

---

## Navigazione da Tastiera (TUI)

All'avvio, NetProbe attende un comando nella dashboard suddivisa in 9 schede:

| Tasto | Azione |
|---|---|
| `1` .. `9` | Seleziona una scheda |
| `←` / `→` (o `h` / `l`) | Scheda precedente / successiva |
| `↑` / `↓` (o `k` / `j`) | Scorri la scheda |
| `Spazio` / `s` | Scansione completa |
| `r` | Scansione rapida |
| `m` / `M` | Gestione cache, export JSONL e selezione tema |
| `t` | Scorri i quattro temi (salvataggio immediato) |
| `e` | Esporta il report diagnostico |
| `q` | Esci |

---

## Utilizzo

### Requisiti
- Python 3.8.1 o successivo (Python 3.10+ consigliato).
- Le dipendenze runtime vengono rilevate e installate automaticamente; in ambienti PEP 668 viene creato un virtualenv utente. `hypothesis` serve solo ai test.

```bash
# Clone della repository
git clone https://github.com/hainetsoftware/netprobe.git
cd netprobe

# 1. Avvio interfaccia interattiva TUI (consigliato)
./netprobe.py

# 2. Modalità non-interattiva da terminale (per log o terminali headless)
./netprobe.py --non-interactive --quick
./netprobe.py --non-interactive --full

# 3. Output JSON puro per script e pipeline
./netprobe.py --json | jq '{isp: .wan.isp, medium: .estimations.physical_medium.predicted_medium}'

# 4. Esportazione su file JSON
./netprobe.py --non-interactive --export diagnosi.json
```

---

## Suite di Test

NetProbe include una suite automatizzata con **136 test unitari** che verificano la classificazione su catture reali (`tests/fixtures/`) e la compatibilità multipiattaforma.

```bash
# Esegui tutti i test
python3 -m unittest discover -s tests

# Rigioca una cattura reale e valida il ground truth
python3 tools/replay.py tests/fixtures/real_ethernet_run1.json
```

---

<a name="-english"></a>
# English

**NetProbe** is an interactive, rootless network intelligence and diagnostics suite designed for modern terminals. Inspired by tools like *Claude Code* and *htop*, it brings deep network insights right to your screen with zero required configuration.

```bash
# Launch interactive TUI directly
./netprobe.py
```

---

## Features at a Glance

-  **LAN & Wi-Fi Hardware Inspection**: Wi-Fi 7/6E/6/5 and 10G Ethernet support. Real-time RSSI, channel, SNR, MCS index, link speed, and MAC vendor resolution via embedded IEEE OUI database.
-  **Connected Ethernet Switch Discovery**: Discovers upstream managed switches via passive LLDP/CDP sniffing or active SNMP/mDNS queries, with unmanaged switch detection.
-  **WAN, NAT & STUN RFC 5389**: Verifies public IPv4/IPv6 dual-stack routing, detects Carrier-Grade NAT (RFC 6598 CGNAT), and maps NAT behavior (Endpoint-Independent / Symmetric).
-  **Bufferbloat & Loaded Latency Grading**: Measures baseline idle latency vs. loaded download/upload latency, providing standard **A+ to F** grades.
-  **IXP & Direct PNI Intelligence**: Pinpoints major interconnection hubs (MIX Milan, NaMeX Rome, DE-CIX, AMS-IX) and Private Network Interconnects (PNI) to Anycast networks (Cloudflare, Google, Sparkle AS6762).
-  **Optical Path Efficiency**: Estimates the theoretical speed-of-light delay in dielectric fiber ($204,000\text{ km/s}$) and compares it to real routing hops.
-  **Physical Transmission Medium Classifier**: Explainable Bayesian/heuristic engine distinguishing **FTTH GPON/XGS-PON**, **FTTC / VDSL2**, **FWA**, **4G/5G Hotspots**, and **Satellite** (Starlink/GEO), enforced with deterministic physical rate vetoes.

---

## Interactive Keyboard Controls (TUI)

| Key | Action |
|---|---|
| `1` .. `9` | Select a tab |
| `left` / `right` (or `h` / `l`) | Previous / next tab |
| `up` / `down` (or `k` / `j`) | Scroll the active tab |
| `Space` / `s` | Full scan |
| `r` | Quick scan |
| `m` / `M` | Cache management, JSONL export and theme selection |
| `t` | Cycle the four themes (saved immediately) |
| `e` | Export diagnostic report |
| `q` | Exit |

---

## Quickstart

```bash
git clone https://github.com/hainetsoftware/netprobe.git
cd netprobe

# Interactive TUI mode (default)
./netprobe.py

# Headless / script mode
./netprobe.py --non-interactive --quick

# Automation & JSON pipelines
./netprobe.py --json | jq .
```

---

## Testing

```bash
# Run the test suite
python3 -m unittest discover -s tests

# Replay offline captures against ground truth
python3 tools/replay.py tests/fixtures/real_ethernet_run1.json
```

---

## License

Licensed under the [MIT License](LICENSE).

### Path-specific egress diagnostics

The existing IXP JSON keys are retained. `metro_egress` also reports
`routing_topology` (`SINGLE_EXIT` / `MULTI_EXIT_SPLIT`), `interconnect_type`,
`ixp_match_method`, and `exit_paths`. Each exit keeps its own target, border
IP/rDNS, ASN, city, metro code, raw RTT and effective RTT. A CDN metro can select
a matching observed secondary border; it cannot relocate a router with a city
in its rDNS. GARR's authoritative PoP subdomain takes priority over both endpoints
in a link hostname; school aggregators also expose `access_province` and `pop_token`.

Public IXP traversal requires a peering LAN prefix match or an explicit IXP domain
signature. PeeringDB city intersections describe co-located presence, not confirmed
switch traversal. Unresolved locations and buildings remain null. PeeringDB cache
schema v2 retains `facilities` and adds `netixlan` prefixes and `netfac` city records;
API relationships follow the [PeeringDB API documentation](https://www.peeringdb.com/apidocs/).

`optical_routing.copp_clamped` flags RTT inversions sanitized with dedicated pings
and downstream bounds from the selected path. `raw_hub_rtt_ms` preserves the original
measurement, and `latency_target` identifies the path used. A primary Cloudflare
ping cannot bound a secondary Google/AWS exit. RTT inversions suggest ICMP response
delays; asymmetric return paths can also contribute. Verified BNG ping RTT takes
priority over private intermediate hops for access latency separation.

For offline replay, `IXPAnalyzer.reclassify_offline` accepts optional
`multi_target_analysis`, `multi_cdn_inspection`, and `peeringdb_info` dictionaries
in addition to its original parameters. Pass the recorded `hop2_bng` dictionary
as `hop2_metrics` to preserve the dedicated probe's IP association.

Exported diagnostic reports (`netprobe_report_*.json`) stay local and are ignored by Git.

### Persistent cache and ingestion policy

`m` / `M` opens management while idle or viewing results. Select one of
`midnight-slate`, `monochrome-light`, `oled-black`, or `nordic-frost`; the choice
is saved immediately. Ctrl+P is disabled. Cache resets require repeating the
selected action; telemetry reset keeps settings, while factory reset clears both.

SQLite uses WAL, NORMAL synchronization, foreign keys, private directory/file
permissions on POSIX, and connections scoped to each operation. The database is
`netprobe.db` under `$XDG_DATA_HOME/netprobe` (Linux, default
`~/.local/share/netprobe`), `~/Library/Application Support/NetProbe` (macOS), or
`%LOCALAPPDATA%/NetProbe` (Windows), with `~/.netprobe` as fallback. Cache failures
produce a warning and diagnostics continue.

Ingestion always stores the BNG minimum RTT as `bng_floor_ms`. Congestion is
flagged above 45 ms bufferbloat delta, 8 ms gateway IQR, 15 ms BNG IQR, or 20%
BNG spikes. Missing BNG measurements, invalid transfers and worker errors exclude
a run from training. Quick scans may omit throughput. `baseline_runs()` returns
only valid, uncongested observations; the existing estimator does not train on
historical runs yet. After ten runs from a public /24 or /48 in seven days,
subsequent rows receive weight `10 / (prior_count + 1)`.

Host identifiers use SHA-256 with a local random salt. JSONL exports omit host
hashes, addresses, ISP names and exact timestamps; ASN and diagnostic metrics
remain. Exports are written beside the database. Reports, databases, WAL files,
logs and datasets are ignored by Git.

Windows 7 SP1 uses the Python 3.8 dependency profile (dnspython 2.6.1, psutil
5.9.8, zeroconf 0.130.0, Textual 0.89.1). Legacy Windows requires a compatible
Python installation and terminal; if the TUI cannot initialize, diagnostics use
CLI tables. OS labels are covered by mocked cross-platform tests; native Windows
7 execution is not verified by this change. Python 3.8 is end-of-life:
<https://www.python.org/downloads/release/python-3810/>.
