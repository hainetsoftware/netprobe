# ⚡ NetProbe

**Network intelligence a colpo d'occhio nel tuo terminale.**  
Analizza hardware LAN, switch connessi, peering IXP/PNI, bufferbloat e stima il mezzo fisico dell'ultimo miglio (FTTH, FTTC, FWA, 5G, Satellite) con modelli matematici e zero permessi di root.

[![NetProbe CI](https://github.com/hainetsoftware/netprobe/actions/workflows/tests.yml/badge.svg)](https://github.com/hainetsoftware/netprobe/actions/workflows/tests.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/hainetsoftware/netprobe)
[![Zero Mandatory Dependencies](https://img.shields.io/badge/dependencies-zero%20pip%20mandatory-success.svg)](requirements.txt)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*Lingue / Languages:* 👉 **[🇮🇹 Italiano](#-italiano)** | **[🇬🇧 English](#-english)**

---

<a name="-italiano"></a>
# 🇮🇹 Italiano

NetProbe trasforma la diagnostica di rete in un'esperienza interattiva da terminale (**TUI**), fluida e immediata come strumenti moderni alla *Claude Code* o *htop*. Non serve imparare decine di comandi complessi: basta avviarlo e navigare con le freccette e il tasto Tab.

Funziona senza permessi di root (`rootless`) e sfrutta la libreria standard di Python.

```bash
# Avvio immediato della dashboard interattiva
./netprobe.py
```

---

## ✨ Cosa fa NetProbe

- 🖥️ **Hardware LAN & Wi-Fi**: Riconosce schede Wi-Fi 7/6E/6/5 ed Ethernet fino a 10G. Legge RSSI, canali radio, SNR, MCS Index, duplex e risolve i vendor MAC tramite database IEEE OUI embedded.
- 🔌 **Switch Discovery**: Trova lo switch di rete collegato tramite frame LLDP/CDP o scansione attiva SNMP/mDNS (con diagnosi trasparente se lo switch è unmanaged).
- 🌐 **WAN, NAT & STUN RFC 5389**: Verifica connettività IPv4/IPv6 dual-stack, rileva la presenza di CGNAT (RFC 6598) e classifica la natura del NAT (Full Cone / Symmetric).
- 🚦 **Bufferbloat & Latenza Sotto Carico**: Misura la latenza a riposo e sotto saturazione bidirezionale assegnando il voto standard da **A+ a F**.
- 🏢 **Peering IXP & PNI**: Riconosce i punti di interscambio internet (MIX Milano, NaMeX Roma, VSIX, DE-CIX, AMS-IX) e i Direct PNI (Private Network Interconnect) verso reti Anycast (Cloudflare, Google, Sparkle AS6762).
- ⚡ **Efficienza Routing Ottico**: Calcola il ritardo dielettrico teorico della luce in fibra ($204.000\text{ km/s}$) confrontandolo con il percorso reale verso l'hub metropolitano.
- 🔬 **Stima Mezzo Fisico Ultimo Miglio**: Classificatore probabilistico ed euristico spiegabile che distingue **FTTH GPON/XGS-PON**, **FTTC / VDSL2**, **FWA**, **4G/5G Hotspot** e **Satellite** (Starlink/GEO), con veti deterministici sulle barriere fisiche di upload e download.

---

## 🕹️ Navigazione da Tastiera (TUI)

All'avvio, NetProbe esegue una scansione in background e apre la dashboard suddivisa in 5 schede:

| Tasto | Azione |
|---|---|
| `Tab` / `Shift-Tab` | Passa alla scheda successiva o precedente |
| `1` .. `5` | Vai direttamente alla scheda desiderata |
| `↑` / `↓` (o `k` / `j`) | Scorri il testo verso l'alto o verso il basso |
| `PgUp` / `PgDn` | Salto rapido di pagina |
| `g` / `G` | Salta all'inizio o alla fine |
| `r` | Riavvia una scansione completa (con test di banda) |
| `s` | Esegui una scansione rapida (solo latenze e BNG) |
| `e` | Salva il dump dei dati in `scan.json` |
| `?` / `h` | Mostra la guida rapida a schermo |
| `q` / `ESC` | Esci da NetProbe e torna alla shell |

---

## 🚀 Utilizzo

### Requisiti
- Python 3.10 o successivo.
- Nessun pacchetto pip obbligatorio per l'uso base. Opzionali: `psutil` (per contabilità traffico di altri processi) o `scapy`.

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

## 🧪 Suite di Test

NetProbe include una suite automatizzata con **136 test unitari** che verificano la classificazione su catture reali (`tests/fixtures/`) e la compatibilità multipiattaforma.

```bash
# Esegui tutti i test
python3 -m unittest discover -s tests

# Rigioca una cattura reale e valida il ground truth
python3 tools/replay.py tests/fixtures/real_ethernet_run1.json
```

---

<a name="-english"></a>
# 🇬🇧 English

**NetProbe** is an interactive, rootless network intelligence and diagnostics suite designed for modern terminals. Inspired by tools like *Claude Code* and *htop*, it brings deep network insights right to your screen with zero required configuration.

```bash
# Launch interactive TUI directly
./netprobe.py
```

---

## ✨ Features at a Glance

- 🖥️ **LAN & Wi-Fi Hardware Inspection**: Wi-Fi 7/6E/6/5 and 10G Ethernet support. Real-time RSSI, channel, SNR, MCS index, link speed, and MAC vendor resolution via embedded IEEE OUI database.
- 🔌 **Connected Ethernet Switch Discovery**: Discovers upstream managed switches via passive LLDP/CDP sniffing or active SNMP/mDNS queries, with unmanaged switch detection.
- 🌐 **WAN, NAT & STUN RFC 5389**: Verifies public IPv4/IPv6 dual-stack routing, detects Carrier-Grade NAT (RFC 6598 CGNAT), and maps NAT behavior (Endpoint-Independent / Symmetric).
- 🚦 **Bufferbloat & Loaded Latency Grading**: Measures baseline idle latency vs. loaded download/upload latency, providing standard **A+ to F** grades.
- 🏢 **IXP & Direct PNI Intelligence**: Pinpoints major interconnection hubs (MIX Milan, NaMeX Rome, DE-CIX, AMS-IX) and Private Network Interconnects (PNI) to Anycast networks (Cloudflare, Google, Sparkle AS6762).
- ⚡ **Optical Path Efficiency**: Estimates the theoretical speed-of-light delay in dielectric fiber ($204,000\text{ km/s}$) and compares it to real routing hops.
- 🔬 **Physical Transmission Medium Classifier**: Explainable Bayesian/heuristic engine distinguishing **FTTH GPON/XGS-PON**, **FTTC / VDSL2**, **FWA**, **4G/5G Hotspots**, and **Satellite** (Starlink/GEO), enforced with deterministic physical rate vetoes.

---

## 🕹️ Interactive Keyboard Controls (TUI)

| Key | Action |
|---|---|
| `Tab` / `Shift-Tab` | Next or previous tab |
| `1` .. `5` | Switch directly to tab 1-5 |
| `↑` / `↓` (or `k` / `j`) | Scroll up / down |
| `PgUp` / `PgDn` | Scroll page up / down |
| `g` / `G` | Jump to top / bottom |
| `r` | Re-run full network scan (including speed test) |
| `s` | Run quick scan (latencies and BNG burst) |
| `e` | Export structured data to `scan.json` |
| `?` / `h` | Toggle keyboard shortcuts modal |
| `q` / `ESC` | Exit NetProbe cleanly |

---

## 🚀 Quickstart

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

## 🧪 Testing

```bash
# Run the 136-test suite
python3 -m unittest discover -s tests

# Replay offline captures against ground truth
python3 tools/replay.py tests/fixtures/real_ethernet_run1.json
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).
