# GitHub Copilot Instructions for NetProbe

NetProbe is an advanced, rootless network intelligence and diagnostic tool written in Python 3.10+.
It analyzes LAN hardware (Wi-Fi 7/6E/Ethernet), discovers connected switches (LLDP/CDP/SNMP), maps WAN/NAT (STUN RFC 5389), grades Bufferbloat, identifies IXP & Optical Routing hubs (Team Cymru DNS ASN + rDNS + PeeringDB), and estimates the physical transmission medium (FTTH, FTTC, FWA, 4G/5G, Satellite) via an explainable Bayesian/heuristic model.

---

## 1. Architectural Invariants (Strict)

1. **No Overfitting & No Hard-Coded Network Artifacts**:
   - NEVER hard-code specific traceroute IPs, fixed hop indices, or magic millisecond offsets tailored to a single line or provider.
   - All routing, IXP, AS-boundary, and latency deductions must be dynamically derived via live protocol queries (Team Cymru DNS, rDNS PTR, PeeringDB cache, Cloudflare `cdn-cgi/trace`, or statistical distributions).
   - The engine must work seamlessly across any ISP (TIM, Vodafone, Fastweb, WindTre, Iliad, Sky WiFi, Eolo, Starlink, etc.) and any medium (FTTH, FTTC, FWA, 4G/5G, Satellite).

2. **Standard Library Philosophy**:
   - Core functionality must run with the Python 3.10+ standard library without mandatory third-party pip dependencies.
   - Optional packages (`psutil`, `scapy`) must be treated as graceful progressive enhancements with standard library fallbacks.

3. **Never Edit Captured Fixtures**:
   - Captured test fixtures in `tests/fixtures/` (`*.json`) represent immutable real-world captures.
   - Never edit raw capture files to make tests pass; any derived fields must be computed dynamically in code.

4. **Preserve Classifier Stability**:
   - Do NOT alter score weights, thresholds, or Bayesian priors in `core/estimators.py` unless explicitly requested.

5. **Bilingual Documentation**:
   - All user-facing documentation in `README.md` must be maintained in both 🇮🇹 **Italiano** and 🇬🇧 **English**.

---

## 2. Testing and Validation Requirements

Before proposing or committing changes, ensure:
1. **Full Test Suite**:
   ```bash
   python3 -m unittest discover -s tests
   ```
   All 136+ unit tests must pass with 0 failures and 0 errors.

2. **Fixture Replay Validation**:
   ```bash
   python3 tools/replay.py tests/fixtures/real_ethernet_run*.json
   ```
   Must produce 100% PASS for expected media and noise flags.

3. **Git Hygiene**:
   - Ensure `.gitignore` is respected (no `.DS_Store`, `__pycache__`, `.hypothesis`, or local scan dumps).
