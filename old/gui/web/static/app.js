/**
 * NetProbe Pro - Frontend Logic & Live Updates
 */

let currentData = null;
let pollTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupButtons();
  loadInitialData();
});

function setupTabs() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");

      tabButtons.forEach(b => b.classList.remove("active"));
      tabPanels.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }
    });
  });
}

function setupButtons() {
  document.getElementById("btn-quick-scan").addEventListener("click", () => triggerScan(true));
  document.getElementById("btn-full-scan").addEventListener("click", () => triggerScan(false));
  document.getElementById("btn-export-json").addEventListener("click", exportJSON);
  document.getElementById("btn-copy-json").addEventListener("click", copyJSON);
  document.getElementById("btn-retry").addEventListener("click", () => triggerScan(false));
}

const STEP_ORDER = ["lan", "wan", "ixp", "latency", "download", "upload", "estimation"];

async function getJSON(url, opts) {
  const ctl = new AbortController();
  const to = setTimeout(() => ctl.abort(), 15000);
  try {
    const res = await fetch(url, { ...(opts || {}), signal: ctl.signal, cache: "no-store" });
    let body = null;
    try { body = await res.json(); } catch (e) { /* corpo non JSON */ }
    return { status: res.status, body };
  } finally {
    clearTimeout(to);
  }
}

async function loadInitialData() {
  // Report esportato: dati incorporati, nessun server
  if (window.PRELOADED_NETPROBE_DATA) {
    currentData = window.PRELOADED_NETPROBE_DATA;
    renderAll(currentData);
    updateStatus(`Report del ${currentData.formatted_time || ""}`, false);
    setButtonsState(false);
    return;
  }
  updateStatus("Caricamento dati di rete...", true);
  try {
    const { status, body } = await getJSON("/api/data");
    if (status === 200 && body) {
      currentData = body;
      renderAll(body);
      updateStatus(`Ultima scansione: ${body.formatted_time || "adesso"}`, false);
    } else {
      // La scansione rapida iniziale e' ancora in corso: mostra il progresso
      showScanPanel(true);
      setButtonsState(false);
      pollStatus();
    }
  } catch (err) {
    showScanError("Impossibile contattare il server locale.");
  }
}

async function triggerScan(quick = false) {
  hideScanError();
  setButtonsState(false);
  showScanPanel(true);
  updateScanUI({ progress: 0, phase: "lan", message: "Avvio scansione...", live: {} });
  try {
    const { status, body } = await getJSON(`/api/scan?quick=${quick}`);
    if (status !== 200 && status !== 409) throw new Error(`HTTP ${status}`);
    pollStatus();   // se 409 una scansione e' gia' in corso: ci si aggancia
  } catch (err) {
    showScanError("Avvio della scansione non riuscito: " + err.message);
    setButtonsState(true);
  }
}

function pollStatus() {
  if (pollTimer) clearTimeout(pollTimer);
  let failures = 0;
  const tick = async () => {
    try {
      const { body } = await getJSON("/api/status");
      failures = 0;
      if (body) updateScanUI(body);
      if (body && body.scanning) {
        pollTimer = setTimeout(tick, 400);
        return;
      }
      if (body && body.error) {
        showScanError(body.error);
        setButtonsState(true);
        return;
      }
      const { body: data } = await getJSON("/api/data");
      if (data && !data.pending) {
        currentData = data;
        renderAll(data);
        updateStatus(`Scansione completata: ${data.formatted_time}`, false);
        showScanPanel(false);
      }
      setButtonsState(true);
    } catch (err) {
      if (++failures >= 5) {
        showScanError("Connessione al server persa. Controlla che NetProbe sia ancora in esecuzione.");
        setButtonsState(true);
        return;
      }
      pollTimer = setTimeout(tick, 800);
    }
  };
  tick();
}

function showScanPanel(on) {
  document.getElementById("scan-panel").classList.toggle("active", on);
}
function showScanError(msg) {
  showScanPanel(true);
  document.getElementById("scan-error-msg").textContent = msg;
  document.getElementById("scan-error").classList.add("active");
  updateStatus("Errore", false);
}
function hideScanError() {
  document.getElementById("scan-error").classList.remove("active");
}

function updateScanUI(st) {
  const pct = Math.max(0, Math.min(100, st.progress || 0));
  document.getElementById("scan-fill").style.width = pct + "%";
  document.getElementById("scan-phase").textContent = `${st.message || ""} (${pct}%)`;
  const live = st.live || {};
  const valEl = document.getElementById("scan-live-val");
  if (live.dir && live.mbps !== undefined) {
    valEl.textContent = live.mbps.toFixed(1);
    document.getElementById("scan-live-unit").textContent = live.dir === "down" ? "Mbps ↓" : "Mbps ↑";
  } else {
    valEl.textContent = "--";
  }
  const idx = STEP_ORDER.indexOf(st.phase);
  document.querySelectorAll("#scan-steps span").forEach(el => {
    const i = STEP_ORDER.indexOf(el.dataset.step);
    el.classList.toggle("on", i === idx);
    el.classList.toggle("done", idx >= 0 && i < idx || st.phase === "done");
  });
  if (st.scanning) updateStatus(st.message || "Scansione in corso...", true);
}

function setButtonsState(enabled) {
  document.getElementById("btn-quick-scan").disabled = !enabled;
  document.getElementById("btn-full-scan").disabled = !enabled;
}

function updateStatus(message, isScanning) {
  const pulse = document.getElementById("pulse-indicator");
  const text = document.getElementById("status-text");

  text.textContent = message;
  if (isScanning) {
    pulse.classList.add("scanning");
  } else {
    pulse.classList.remove("scanning");
  }
}

function renderAll(data) {
  if (!data) return;

  const lan = data.lan || {};
  const wan = data.wan || {};
  const perf = data.performance || {};
  const est = data.estimations || {};
  const sys = data.system || {};

  // 1. Meta sistema
  const savedOs = sys.os === "Darwin" ? "macOS" : [sys.os, sys.os_release].filter(Boolean).join(" ");
  const prettyOs = sys.pretty_os || `${savedOs || "N/D"}${sys.machine ? ` (${sys.machine})` : ""}`;
  const activeInterface = lan.primary_interface || {};
  document.getElementById("system-meta").textContent =
    `Host: ${sys.hostname || "N/D"} | OS: ${prettyOs} | Python: ${sys.python_version || sys.python || "N/D"} | Interfaccia: ${activeInterface.name || lan.primary_interface_name || "N/D"} (${lan.interface_type || activeInterface.type || "N/D"})`;

  // 2. Quick Metrics Top Cards
  const speed = perf.speed || {};
  document.getElementById("metric-download").textContent = speed.download_mbps ? speed.download_mbps.toFixed(1) : "--";
  document.getElementById("metric-download-sub").textContent = speed.download_peak_mbps ? 
    `Picco: ${speed.download_peak_mbps.toFixed(1)} Mbps • Stabilità: ${speed.download_stability_pct || "--"}%` : 
    "Test streaming su CDN";

  document.getElementById("metric-upload").textContent = speed.upload_mbps ? speed.upload_mbps.toFixed(1) : "--";
  document.getElementById("metric-upload-sub").textContent = speed.upload_peak_mbps ? 
    `Picco: ${speed.upload_peak_mbps.toFixed(1)} Mbps • Stabilità: ${speed.upload_stability_pct || "--"}%` : 
    "Upload continuo su edge";

  const primLat = perf.primary_latency || {};
  document.getElementById("metric-ping").textContent = primLat.min_ms !== undefined ? primLat.min_ms.toFixed(1) : "--";
  document.getElementById("metric-jitter-sub").textContent = `Jitter: ${primLat.jitter_ms !== undefined ? primLat.jitter_ms.toFixed(2) : "--"} ms (RFC 3550)`;

  const bb = perf.bufferbloat || {};
  const bbElem = document.getElementById("metric-bufferbloat");
  bbElem.textContent = bb.grade ? `Grado ${bb.grade}` : "--";
  bbElem.style.color = getGradeColor(bb.grade);
  const dlDeltaStr = (bb.download_delta_ms != null) ? `+${bb.download_delta_ms}ms` : "--";
  const ulDeltaStr = (bb.upload_delta_ms != null) ? `+${bb.upload_delta_ms}ms` : "--";
  document.getElementById("metric-bufferbloat-sub").textContent = 
    `DL: ${dlDeltaStr} • UL: ${ulDeltaStr}`;

  const mos = est.voice_quality_mos || {};
  const mosElem = document.getElementById("metric-mos");
  const mosOk = typeof mos.mos_score === "number";
  mosElem.textContent = mosOk ? mos.mos_score.toFixed(2) : "N/D";
  mosElem.style.color = !mosOk ? "var(--text-secondary, inherit)" : mos.mos_score >= 4.0 ? "var(--accent-emerald)" : (mos.mos_score >= 3.5 ? "var(--accent-amber)" : "var(--accent-rose)");
  document.getElementById("metric-mos-sub").textContent = mos.quality_rating || "Qualità VoIP / Audio";

  const med = est.physical_medium || {};
  const medShort = (med.predicted_medium || "--").split("(")[0].trim();
  document.getElementById("metric-medium").textContent = medShort;
  document.getElementById("metric-medium-sub").textContent = `Confidenza modello: ${med.confidence_pct == null ? "N/D" : med.confidence_pct + "%"}`;

  // 3. Topology Chain
  renderTopology(lan, wan, est, sys);

  // 4. Tab 1: LAN & Hardware
  renderLAN(lan);

  // 5. Tab 2: WAN & Internet
  renderWAN(wan, data.ixp || {});

  // 6. Tab 3: NAT & Routing
  renderNAT(lan, wan, est);

  // 7. Tab 4: Performance & Bufferbloat
  renderPerformance(perf);

  // 8. Tab 5: Modelli & Stime ITU-T
  renderModels(est, data.ixp || {});

  // 9. Tab 6: Dispositivi LAN
  renderDevices(lan.lan_devices || lan.arp_table || [], lan.this_device, lan.permissions_warning);

  // 10. Tab 7: Raw JSON
  document.getElementById("raw-json-output").textContent = JSON.stringify(data, null, 2);
}

function renderTopology(lan, wan, est, sys) {
  const pIface = lan.primary_interface || {};
  document.getElementById("topo-host-name").textContent = sys.hostname || "Host Locale";
  document.getElementById("topo-host-ip").textContent = pIface.ipv4 || "127.0.0.1";
  document.getElementById("topo-host-meta").textContent = `${lan.primary_interface_name || "iface"} (${pIface.type || "LAN"})`;

  const gw = lan.gateway || {};
  document.getElementById("topo-gw-name").textContent = gw.vendor && gw.vendor !== "Sconosciuto" ? `${gw.vendor.split("/")[0].trim()}${gw.model ? " " + gw.model : ""}` : "Default Gateway";
  document.getElementById("topo-gw-ip").textContent = gw.ipv4 || "Router";
  document.getElementById("topo-gw-meta").textContent = gw.mac || "Layer 2 Bridge";

  document.getElementById("topo-isp-name").textContent = wan.isp || "Operatore ISP";
  document.getElementById("topo-isp-ip").textContent = wan.public_ipv4 || "IP Pubblico";
  document.getElementById("topo-isp-meta").textContent = wan.asn || "Autonomous System";

  const opt = est.optical_routing || {};
  document.getElementById("topo-edge-name").textContent = opt.nearest_ixp_name || "Anycast Core";
  document.getElementById("topo-edge-city").textContent = wan.city ? `${wan.city}, ${wan.country}` : "Global Internet";
  document.getElementById("topo-edge-meta").textContent = `Efficienza: ${opt.routing_efficiency_pct == null ? "N/D" : opt.routing_efficiency_pct + "%"}`;
}

function renderLAN(lan) {
  const pIface = lan.primary_interface || {};
  document.getElementById("lan-iface-name").textContent = lan.primary_interface_name || "--";
  document.getElementById("lan-iface-type").textContent = pIface.type || "--";
  document.getElementById("lan-mac").textContent = pIface.mac || "--";
  document.getElementById("lan-vendor").textContent = pIface.vendor || "--";
  document.getElementById("lan-ipv4").textContent = pIface.ipv4 || "--";
  document.getElementById("lan-mask").textContent = pIface.netmask || "--";
  document.getElementById("lan-bcast").textContent = pIface.broadcast || "--";
  document.getElementById("lan-mtu").textContent = pIface.mtu ? `${pIface.mtu} bytes` : "--";

  const ip6List = pIface.ipv6_list || [];
  if (ip6List.length > 0) {
    document.getElementById("lan-ipv6").innerHTML = ip6List.map(x => `<div>${x.address}/${x.prefix} <span class="badge badge-cyan">${x.type}</span></div>`).join("");
  } else {
    document.getElementById("lan-ipv6").textContent = "Nessun indirizzo IPv6";
  }

  // Link Params (Wi-Fi o Ethernet o altro)
  const wifi = lan.wifi || {};
  const eth = lan.ethernet || {};
  const table = document.getElementById("table-link-params");
  table.innerHTML = "";

  const ifName = pIface.name || "";
  const isWifi = (wifi && (wifi.connected || wifi.ssid || wifi.rssi_dbm !== null)) || (pIface && pIface.type === "Wi-Fi");
  const isEth = !isWifi && ((eth && (eth.active || eth.cable_connected || eth.speed_mbps !== null)) || (pIface && pIface.type === "Ethernet"));

  if (isWifi) {
    addRow(table, "Modalità Link", `<span class="badge badge-cyan">Wi-Fi Wireless (${ifName})</span>`);
    addRow(table, "SSID Rete", wifi.ssid || (wifi.ssid_hidden_by_os ? "Nascosto dal sistema (serve il permesso Posizione)" : "--"));
    addRow(table, "BSSID (Access Point)", `${wifi.bssid || "--"} (${wifi.bssid_vendor || "Sconosciuto"})`);
    addRow(table, "Standard Generazione", `${wifi.wifi_generation || "--"} [${wifi.phy_mode || ""}]`);
    addRow(table, "Banda & Canale", `${wifi.frequency_ghz || "--"} (Canale ${wifi.channel || "--"})`);
    addRow(table, "Potenza Segnale (RSSI)", `${wifi.rssi_dbm !== null ? wifi.rssi_dbm + " dBm" : "--"}`);
    addRow(table, "Rumore di Fondo (Noise)", `${wifi.noise_dbm !== null ? wifi.noise_dbm + " dBm" : "--"}`);
    addRow(table, "Rapporto Segnale/Rumore (SNR)", `${wifi.snr_db !== null ? wifi.snr_db + " dB" : "--"}`);
    addRow(table, "Qualità Segnale", `${wifi.signal_quality_pct !== null ? wifi.signal_quality_pct + "%" : "--"}`);
    addRow(table, "Link Speed (Tx Rate)", `${wifi.tx_rate_mbps !== null ? wifi.tx_rate_mbps + " Mbps" : "--"}`);
    addRow(table, "MCS Index (Modulazione)", `${wifi.mcs_index !== null ? wifi.mcs_index : "--"}`);
    addRow(table, "Sicurezza / Crittografia", wifi.security || "--");
  } else if (isEth) {
    addRow(table, "Modalità Link", `<span class="badge badge-success">Cablata Ethernet (${ifName})</span>`);
    addRow(table, "Velocità Link Negoziata", eth.speed_mbps ? `${eth.speed_mbps} Mbps` : "--");
    addRow(table, "Modalità Duplex", eth.duplex || "--");
    addRow(table, "Descrizione Media", eth.media_description || "--");
    addRow(table, "Stato Collegamento Cavo", eth.cable_connected ? `<span class="badge badge-success">Attivo</span>` : "Inattivo");

    // Switch Discovery Info
    const sw = eth.switch_info;
    if (sw) {
      if (sw.detected) {
        if (sw.switch_name) addRow(table, "Switch Collegato", `<span class="badge badge-cyan">${sw.switch_name}</span>`);
        if (sw.switch_model) addRow(table, "Modello Switch", sw.switch_model);
        if (sw.port_id) addRow(table, "Porta Switch", `<span class="badge badge-purple">${sw.port_id}</span>`);
        if (sw.vlan) addRow(table, "VLAN Porta", sw.vlan);
        if (sw.management_ip) addRow(table, "IP Gestione Switch", sw.management_ip);
        if (sw.protocol) addRow(table, "Protocollo Rilevato", sw.protocol);
      } else {
        addRow(table, "Apparato Switch", `<span class="badge badge-outline">${sw.switch_type || "Switch L2 Unmanaged"}</span>`);
        if (sw.description) addRow(table, "Diagnosi Switch", `<span style="font-size:11px;color:var(--text-dim);">${sw.description}</span>`);
      }
    }
  } else {
    addRow(table, "Modalità Link", `<span class="badge badge-purple">${(pIface && pIface.type) || "Interfaccia Virtuale / VPN"} (${ifName})</span>`);
    addRow(table, "Nome Dispositivo", ifName || "--");
    addRow(table, "MTU", (pIface && pIface.mtu) ? `${pIface.mtu} byte` : "--");
    addRow(table, "Stato Operativo", (pIface && pIface.is_up) ? `<span class="badge badge-success">UP</span>` : `<span class="badge badge-warning">DOWN</span>`);
  }
}

function renderWAN(wan, ixp) {
  document.getElementById("wan-ipv4").textContent = wan.public_ipv4 || "--";
  document.getElementById("wan-ipv6").textContent = wan.public_ipv6 || "Non rilevato";
  document.getElementById("wan-dualstack").innerHTML = wan.dual_stack_enabled ? 
    `<span class="badge badge-success">Attivo (IPv4 + IPv6)</span>` : 
    `<span class="badge badge-warning">IPv4-Only</span>`;

  document.getElementById("wan-rdns").textContent = wan.reverse_dns || "--";
  document.getElementById("wan-isp").textContent = wan.isp || "--";
  document.getElementById("wan-asn").textContent = `${wan.asn || ""} (${wan.org || ""})`;

  const priv = wan.privacy_and_routing || {};
  document.getElementById("wan-vpn").innerHTML = priv.is_vpn_or_proxy ? 
    `<span class="badge badge-warning">${priv.type}</span>` : 
    `<span class="badge badge-success">${priv.type}</span>`;

  const pathMtuEl = document.getElementById("wan-path-mtu");
  if (pathMtuEl) {
    pathMtuEl.textContent = (ixp && ixp.path_mtu != null) ? `${ixp.path_mtu} byte` : "N/D";
  }

  document.getElementById("wan-city").textContent = wan.city || "--";
  document.getElementById("wan-region").textContent = wan.region || "--";
  document.getElementById("wan-country").textContent = `${wan.country || ""} (${wan.country_code || ""})`;
  document.getElementById("wan-postal").textContent = wan.postal || "--";
  
  const coords = wan.coordinates || {};
  if (coords.latitude && coords.longitude) {
    document.getElementById("wan-coords").innerHTML = 
      `<a href="https://www.openstreetmap.org/?mlat=${coords.latitude}&mlon=${coords.longitude}" target="_blank" style="color: var(--accent-cyan); text-decoration: none;">
        ${coords.latitude}, ${coords.longitude} ↗
      </a>`;
  } else {
    document.getElementById("wan-coords").textContent = "--";
  }

  document.getElementById("wan-timezone").textContent = wan.timezone || "--";

  // Card IXP & Peering Architecture
  const ixpData = ixp || {};
  const isUnidentifiedIxp = !ixpData.detected_ixp || ixpData.detected_ixp === "IXP non identificato";
  const ixpNameEl = document.getElementById("wan-ixp-name");
  if (ixpNameEl) ixpNameEl.textContent = ixpData.detected_ixp || "N/D";

  const ixpFacEl = document.getElementById("wan-ixp-facility");
  if (ixpFacEl) ixpFacEl.textContent = (!isUnidentifiedIxp && ixpData.ixp_facility) ? ixpData.ixp_facility : "N/D";

  const ixpTypeEl = document.getElementById("wan-ixp-type");
  if (ixpTypeEl) ixpTypeEl.innerHTML = (!isUnidentifiedIxp && ixpData.peering_type) ? `<span class="badge badge-cyan">${ixpData.peering_type}</span>` : "N/D";

  const ixpMethEl = document.getElementById("wan-ixp-method");
  if (ixpMethEl) ixpMethEl.textContent = (!isUnidentifiedIxp && ixpData.detection_method) ? `${ixpData.detection_method} (${ixpData.confidence || ""})` : "N/D";

  const ixpHopEl = document.getElementById("wan-ixp-hop");
  if (ixpHopEl) {
    if (!isUnidentifiedIxp && ixpData.matched_hop_ip) {
      ixpHopEl.textContent = `${ixpData.matched_hop_ip}${ixpData.matched_subnet ? ' (' + ixpData.matched_subnet + ')' : ''}`;
    } else {
      ixpHopEl.textContent = "N/D";
    }
  }

  const ixpRttEl = document.getElementById("wan-ixp-rtt");
  if (ixpRttEl) ixpRttEl.textContent = (!isUnidentifiedIxp && ixpData.rtt_to_ixp_ms) ? `${ixpData.rtt_to_ixp_ms} ms` : "N/D";

  const ixpPdbEl = document.getElementById("wan-ixp-peeringdb");
  if (ixpPdbEl) {
    const pdbFacs = ixpData.peeringdb_facilities || [];
    if (pdbFacs.length > 0) {
      ixpPdbEl.textContent = pdbFacs.slice(0, 4).map(f => f.name).join(", ");
    } else {
      ixpPdbEl.textContent = "Nessuna struttura IXP pubblica registrata per l'ASN (Transito PNI diretto)";
    }
  }
}

function renderNAT(lan, wan, est) {
  const nat = wan.nat || {};
  document.getElementById("nat-type").innerHTML = `<span class="badge badge-cyan">${nat.nat_type || "--"}</span>`;
  document.getElementById("nat-behavior").textContent = nat.mapping_behavior || "--";
  document.getElementById("nat-port").textContent = nat.mapped_external_port || "--";

  const pm = (est && est.physical_medium) || {};
  const predMed = (pm.predicted_medium || "").toLowerCase();
  const confVal = pm.confidence_pct;
  const confNum = confVal != null ? Number(confVal) : 100.0;
  const isAmbiguous = !!pm.ambiguous;
  const isMobile = predMed.includes("mobile") || predMed.includes("cellular");
  const isMobileConfident = isMobile && confNum >= 60.0 && !isAmbiguous;
  const wanIpOk = !!wan.public_ipv4;

  let cgnatHtml = "";
  if (nat.cgnat_detected) {
    cgnatHtml = `<span class="badge badge-danger">Rilevato (RFC 6598)</span>`;
  } else if (isMobileConfident) {
    cgnatHtml = `<span class="badge badge-warning">non rilevabile (su rete mobile il CGNAT è probabile)</span>`;
  } else if (!wanIpOk) {
    cgnatHtml = `<span class="badge badge-warning">non rilevabile (IP pubblico assente)</span>`;
  } else {
    cgnatHtml = `<span class="badge badge-success">non rilevabile (nessun indizio di CGNAT: IP pubblico fuori da 100.64.0.0/10)</span>`;
  }
  document.getElementById("nat-cgnat").innerHTML = cgnatHtml;

  const serv = wan.router_services || {};
  const upnpTxt = serv.upnp_status_text || (serv.upnp_igd_available ? "Attivo" : "Nessuna risposta (UPnP non rilevato)");
  document.getElementById("nat-upnp").innerHTML = serv.upnp_igd_available ? 
    `<span class="badge badge-warning">Attivo</span>` : 
    `<span class="badge" style="background: rgba(255,255,255,0.08); color: var(--text-dim);">${upnpTxt}</span>`;

  const pmpTxt = serv.nat_pmp_status_text || (serv.nat_pmp_available ? "Attivo" : "Nessuna risposta (NAT-PMP non rilevato)");
  document.getElementById("nat-pmp").innerHTML = serv.nat_pmp_available ? 
    `<span class="badge badge-warning">Attivo</span>` : 
    `<span class="badge" style="background: rgba(255,255,255,0.08); color: var(--text-dim);">${pmpTxt}</span>`;

  document.getElementById("nat-details").textContent = nat.details || "--";

  // Gateway & DHCP
  const gw = lan.gateway || {};
  document.getElementById("gw-ip").textContent = gw.ipv4 || "--";
  document.getElementById("gw-vendor").textContent = (gw.vendor && gw.vendor !== "Sconosciuto") ? gw.vendor : "Non identificato";
  document.getElementById("gw-model").textContent = gw.model || "--";
  document.getElementById("gw-mac").textContent = gw.mac ? `${gw.mac}${gw.identified_by ? "  [" + gw.identified_by.join(", ") + "]" : ""}` : "--";

  const dhcp = lan.dhcp || {};
  document.getElementById("dhcp-server").textContent = dhcp.server_ip || "--";
  document.getElementById("dhcp-lease").textContent = dhcp.lease_time_human || "--";

  const dns = lan.dns || {};
  document.getElementById("dns-resolvers").textContent = (dns.resolvers || []).join(", ") || "Default OS";
  
  const dnsBm = lan.dns_benchmark || {};
  document.getElementById("dns-latency").textContent = dnsBm.system_resolver_latency_ms ? `${dnsBm.system_resolver_latency_ms} ms` : "--";
  const resDnssec = dnsBm.resolvers_dnssec || [];
  if (resDnssec.length > 0) {
    document.getElementById("dns-dnssec").innerHTML = resDnssec.map(r => {
      const cls = r.status === "validante" ? "badge-success" : (r.status === "non validante" ? "badge-warning" : "badge-neutral");
      return `<span class="badge ${cls}" style="margin-right: 4px;">${r.ip}: ${r.status}</span>`;
    }).join("");
  } else {
    document.getElementById("dns-dnssec").innerHTML = dnsBm.dnssec_validation_active ? 
      `<span class="badge badge-success">Validante</span>` : 
      `<span class="badge badge-warning">Non Validante</span>`;
  }
}

function renderPerformance(perf) {
  const tbody = document.getElementById("table-perf-targets");
  tbody.innerHTML = "";

  const targets = perf.latency_targets || {};
  for (const [name, t] of Object.entries(targets)) {
    const tr = document.createElement("tr");
    if (t.reachable) {
      tr.innerHTML = `
        <td class="label" style="color: #fff; font-weight: 600;">${name} <span style="font-size: 10px; color: var(--text-dim);">(${t.host || ""})</span></td>
        <td class="value">${t.min_ms.toFixed(2)} ms</td>
        <td class="value" style="color: var(--accent-cyan);">${t.median_ms.toFixed(2)} ms</td>
        <td class="value">${t.max_ms.toFixed(2)} ms</td>
        <td class="value">${t.jitter_ms.toFixed(2)} ms</td>
        <td class="value" style="color: ${t.packet_loss_pct === 0 ? 'var(--accent-emerald)' : 'var(--accent-rose)'};">${t.packet_loss_pct}%</td>
      `;
    } else {
      tr.innerHTML = `
        <td class="label" style="color: #fff;">${name}</td>
        <td colspan="5" style="color: var(--text-dim); font-style: italic;">Non raggiungibile / Filtrato</td>
      `;
    }
    tbody.appendChild(tr);
  }

  // Bufferbloat Bidirezionale
  const bb = perf.bufferbloat || {};
  const bbGradeElem = document.getElementById("bb-grade");
  if (bb.grade) {
    bbGradeElem.innerHTML = `<span class="badge" style="background: ${getGradeColor(bb.grade)}20; color: ${getGradeColor(bb.grade)}; border: 1px solid ${getGradeColor(bb.grade)}40; font-size: 14px;">Grado ${bb.grade}</span>`;
  } else {
    bbGradeElem.innerHTML = `<span class="badge" style="font-size: 14px;">--</span>`;
  }
  document.getElementById("bb-idle").textContent = bb.idle_latency_ms != null ? `${bb.idle_latency_ms} ms` : "--";
  document.getElementById("bb-loaded-dl").textContent = bb.download_loaded_ms != null 
    ? `${bb.download_loaded_ms} ms${bb.download_delta_ms != null ? ` (+${bb.download_delta_ms} ms)` : ''}` 
    : "--";
  document.getElementById("bb-loaded-ul").textContent = bb.upload_loaded_ms != null 
    ? `${bb.upload_loaded_ms} ms${bb.upload_delta_ms != null ? ` (+${bb.upload_delta_ms} ms)` : ''}` 
    : "--";
  document.getElementById("bb-delta").textContent = bb.max_delta_ms != null ? `+${bb.max_delta_ms} ms` : "--";
  document.getElementById("bb-desc").textContent = bb.description || "--";

  // Speed Streaming Continuo
  const sp = perf.speed || {};
  const dlInfo = sp.download || {};
  const ulInfo = sp.upload || {};
  const dlValid = dlInfo.valid !== undefined ? dlInfo.valid : (sp.download_mbps != null);
  const ulValid = ulInfo.valid !== undefined ? ulInfo.valid : (sp.upload_mbps != null);

  if (dlValid && sp.download_mbps != null) {
    document.getElementById("speed-down").textContent = `${sp.download_mbps.toFixed(2)} Mbps`;
    document.getElementById("speed-down-meta").textContent = sp.download_peak_mbps ? 
      `Picco: ${sp.download_peak_mbps.toFixed(2)} Mbps • Stabilità: ${sp.download_stability_pct || "--"}%` : "--";
  } else {
    const dlReason = dlInfo.invalid_reason || sp.invalid_reason || "N/D";
    document.getElementById("speed-down").textContent = "N/D";
    document.getElementById("speed-down-meta").textContent = dlReason;
  }

  if (ulValid && sp.upload_mbps != null) {
    document.getElementById("speed-up").textContent = `${sp.upload_mbps.toFixed(2)} Mbps`;
    document.getElementById("speed-up-meta").textContent = sp.upload_peak_mbps ? 
      `Picco: ${sp.upload_peak_mbps.toFixed(2)} Mbps • Stabilità: ${sp.upload_stability_pct || "--"}%` : "--";
  } else {
    const ulReason = ulInfo.invalid_reason || sp.invalid_reason || "N/D";
    document.getElementById("speed-up").textContent = "N/D";
    document.getElementById("speed-up-meta").textContent = ulReason;
  }

  const dlMb = ((sp.bytes_downloaded || 0) / (1024 * 1024)).toFixed(1);
  const ulMb = ((sp.bytes_uploaded || 0) / (1024 * 1024)).toFixed(1);
  const totMb = ((sp.bytes_transferred || 0) / (1024 * 1024)).toFixed(1);
  document.getElementById("speed-bytes").textContent = `DL: ${dlMb} MB • UL: ${ulMb} MB (Tot: ${totMb} MB)`;
  document.getElementById("speed-duration").textContent = `${sp.test_duration_s || 0} secondi (DL: ${sp.download_duration_s || 0}s, UL: ${sp.upload_duration_s || 0}s)`;
}

function renderModels(est, ixp) {
  // Mezzo Fisico
  const med = est.physical_medium || {};
  const displayMedium = med.verdict_label || med.predicted_medium || "--";
  document.getElementById("model-medium-name").innerHTML = `<span class="badge badge-cyan" style="font-size: 13px;">${displayMedium}</span>`;
  document.getElementById("model-medium-conf").textContent = med.confidence_pct == null ? "N/D" : `${med.confidence_pct}% di affidabilità`;

  const altsEl = document.getElementById("model-medium-alternatives");
  if (altsEl) {
    const alts = med.alternatives || [];
    let parts = [];
    if (alts.length > 0) {
      parts.push(alts.map(a => `<span class="badge badge-purple" style="font-size: 11px;">${a.medium}</span> <span style="font-size: 11px; color: var(--text-muted);">${a.score} pt (${a.confidence_share_pct}%)</span>`).join(" • "));
    }
    if (med.unassigned_pct != null) {
      parts.push(`<span style="font-size: 11px; color: var(--text-muted);">Non attribuito: ${med.unassigned_pct}%</span>`);
    }
    altsEl.innerHTML = parts.length > 0 ? parts.join(" • ") : "Nessuna alternativa significativa";
  }

  // Warning misura disturbata
  const mq = med.measurement_quality || est.measurement_quality || {};
  let noisyWarningEl = document.getElementById("model-medium-noisy-warning");
  if (mq.noisy) {
    if (!noisyWarningEl) {
      noisyWarningEl = document.createElement("div");
      noisyWarningEl.id = "model-medium-noisy-warning";
      noisyWarningEl.className = "alert alert-warning";
      noisyWarningEl.style.marginTop = "8px";
      noisyWarningEl.style.fontSize = "12px";
      noisyWarningEl.style.padding = "6px 10px";
      noisyWarningEl.style.borderRadius = "4px";
      noisyWarningEl.style.backgroundColor = "rgba(234, 179, 8, 0.15)";
      noisyWarningEl.style.color = "#eab308";
      noisyWarningEl.textContent = "[WARN] Misura disturbata: possibile traffico concorrente sulla linea (streaming, backup). Ripetere a linea libera per una stima più affidabile.";
      const containerMed = document.getElementById("model-medium-name").parentElement;
      if (containerMed) containerMed.appendChild(noisyWarningEl);
    }
  } else if (noisyWarningEl) {
    noisyWarningEl.remove();
  }

  // BNG Hop 2 metrics
  const bng = med.bng_hop || {};
  const bngIpEl = document.getElementById("model-bng-ip");
  if (bngIpEl) {
    if (bng.ip) {
      const cgnatBadge = bng.cgnat_hop ? ` <span class="badge badge-warning" style="font-size: 10px;">CGNAT RFC 6598</span>` : "";
      bngIpEl.innerHTML = `${bng.ip}${cgnatBadge}`;
    } else {
      bngIpEl.textContent = "Non rilevato";
    }
  }

  const bngMetricsEl = document.getElementById("model-bng-metrics");
  if (bngMetricsEl) {
    if (bng.min_ms !== null && bng.min_ms !== undefined) {
      let bngStr = `Min: ${bng.min_ms} ms • Med: ${bng.median_ms} ms • Jitter: ${bng.jitter_ms} ms`;
      if (bng.tail_variance_ms) bngStr += ` • Coda p95: +${bng.tail_variance_ms} ms`;
      bngMetricsEl.textContent = bngStr;
    } else {
      bngMetricsEl.textContent = "Non risponde a ICMP echo diretto (filtrato da ACL operatore)";
    }
  }

  const rationaleList = document.getElementById("model-medium-rationale");
  rationaleList.innerHTML = "";
  (med.rationale || []).forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    rationaleList.appendChild(li);
  });

  // Routing Ottico
  const opt = est.optical_routing || {};
  const isUnidOpt = !opt.nearest_ixp_name || opt.nearest_ixp_name.toLowerCase().includes("non identificato");
  document.getElementById("opt-ixp").textContent = opt.nearest_ixp_name || "N/D";
  const optFacEl = document.getElementById("opt-facility");
  if (optFacEl) optFacEl.textContent = (!isUnidOpt && opt.ixp_facility) ? opt.ixp_facility : "N/D";
  const optPeerEl = document.getElementById("opt-peering-type");
  if (optPeerEl) optPeerEl.innerHTML = (!isUnidOpt && opt.peering_type) ? `<span class="badge badge-cyan">${opt.peering_type}</span>` : "N/D";
  document.getElementById("opt-dist").textContent = opt.straight_line_distance_km != null
    ? `~${opt.straight_line_distance_km} km verso ${opt.ixp_city || "hub"}`
    : "N/D";
  document.getElementById("opt-fiber").textContent = opt.estimated_fiber_path_km != null
    ? `~${opt.estimated_fiber_path_km} km (con fattore di posa terrestre)`
    : "N/D";
  document.getElementById("opt-min-rtt").textContent = opt.theoretical_optical_min_rtt_ms != null
    ? `${opt.theoretical_optical_min_rtt_ms} ms (Velocità luce nella fibra)`
    : "N/D";
  document.getElementById("opt-eff").innerHTML = opt.routing_efficiency_pct == null
    ? `<span class="badge badge-cyan">N/D</span> (${opt.not_applicable_reason || "dati insufficienti"})`
    : `<span class="badge badge-success">${opt.routing_efficiency_pct}%</span> (${opt.detour_rating || ""})`;
  document.getElementById("opt-delay").textContent = opt.switching_and_queuing_delay_ms == null ? "N/D" : `${opt.switching_and_queuing_delay_ms} ms`;

  // Access Profile
  const accProf = (data.ixp && data.ixp.access_profile) || {};
  const profHops = accProf.hops || [];
  const tbodyProf = document.getElementById("table-access-profile");
  if (tbodyProf) {
    tbodyProf.innerHTML = "";
    if (profHops.length === 0) {
      tbodyProf.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding: 12px;">Profilo di accesso non disponibile per questa scansione</td></tr>`;
    } else {
      profHops.forEach(h => {
        const tr = document.createElement("tr");
        const minStr = (h.min_ms !== null && h.min_ms !== undefined) ? `${h.min_ms.toFixed(2)} ms` : "-";
        const medStr = (h.median_ms !== null && h.median_ms !== undefined) ? `${h.median_ms.toFixed(2)} ms` : "-";
        const iqrStr = (h.iqr_ms !== null && h.iqr_ms !== undefined) ? `${h.iqr_ms.toFixed(2)} ms` : "-";
        const incStr = (h.floor_increment_ms !== null && h.floor_increment_ms !== undefined) ? `+${h.floor_increment_ms.toFixed(2)} ms` : "-";
        tr.innerHTML = `
          <td><strong>${h.hop}</strong></td>
          <td><code>${h.ip || "*"}</code></td>
          <td>${h.role_note || h.role || "-"}</td>
          <td>${minStr}</td>
          <td>${medStr}</td>
          <td>${iqrStr}</td>
          <td><strong>${incStr}</strong></td>
        `;
        tbodyProf.appendChild(tr);
      });
    }
  }

  // BDP
  const bdp = est.bandwidth_delay_product || {};
  document.getElementById("bdp-val").textContent = `${bdp.bdp_kb || "--"} KB (${bdp.bdp_bytes || "--"} bytes)`;
  document.getElementById("bdp-tcp").textContent = `${bdp.recommended_tcp_window_kb || "--"} KB`;
  document.getElementById("bdp-desc").textContent = bdp.pipe_capacity_description || "--";

  // Suitability
  const container = document.getElementById("app-suitability-container");
  container.innerHTML = "";

  const apps = est.application_suitability || {};
  const appMapping = [
    { key: "competitive_gaming", label: "Gaming Competitivo / Esport (Tick-rate)" },
    { key: "video_streaming", label: "Streaming Video 4K HDR & 8K" },
    { key: "video_conferencing", label: "Videoconferenze (Zoom, Teams, Meet)" },
    { key: "cloud_gaming", label: "Cloud Gaming (GeForce NOW, Parsec)" }
  ];

  appMapping.forEach(item => {
    const app = apps[item.key] || {};
    const score = app.score || 0;
    const col = score >= 80 ? "var(--accent-emerald)" : (score >= 60 ? "var(--accent-amber)" : "var(--accent-rose)");

    const row = document.createElement("div");
    row.className = "rating-row";
    row.innerHTML = `
      <div class="rating-header">
        <span style="font-weight: 600; color: #fff;">${item.label}</span>
        <span style="font-weight: 700; color: ${col};">${app.status || "--"} (${score}/100)</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" style="width: ${score}%; background: ${col};"></div>
      </div>
      <div style="font-size: 11px; color: var(--text-dim); margin-top: 3px;">${app.desc || ""}</div>
    `;
    container.appendChild(row);
  });
}

function renderDevices(devices, thisDevice, permissionsWarning) {
  const tbody = document.getElementById("table-lan-devices");
  tbody.innerHTML = "";

  if (permissionsWarning) {
    const warnTr = document.createElement("tr");
    warnTr.innerHTML = `
      <td colspan="5" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; padding: 12px; font-weight: 600; border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 4px;">
        [WARN] ${permissionsWarning}
      </td>
    `;
    tbody.appendChild(warnTr);
  }

  if (thisDevice && thisDevice.ip) {
    const tr = document.createElement("tr");
    tr.style.backgroundColor = "rgba(16, 185, 129, 0.08)";
    tr.innerHTML = `
      <td class="value" style="color: var(--accent-emerald); font-weight: 700;">${thisDevice.ip}</td>
      <td class="value">${thisDevice.mac || "N/D"}</td>
      <td style="color: #fff; font-weight: 600;">${thisDevice.vendor || "Questo dispositivo"}</td>
      <td style="color: var(--text-muted);">${thisDevice.hostname || "--"}</td>
      <td><span class="badge badge-success">Questo dispositivo (${thisDevice.type || "LAN"})</span></td>
    `;
    tbody.appendChild(tr);
  }

  if (!devices || devices.length === 0) {
    if (!thisDevice) {
      tbody.innerHTML = `<tr><td colspan="5" style="color: var(--text-dim); text-align: center; padding: 20px;">Nessun dispositivo in cache ARP o rilevato.</td></tr>`;
    }
    return;
  }

  devices.forEach(d => {
    const macStr = (d.mac && d.mac !== "N/D" && d.mac !== "Non in cache ARP") ? d.mac : "N/D";
    const vendorStr = (d.vendor && d.vendor !== "N/D" && d.vendor !== "Host attivo rilevato" && d.vendor !== "Sconosciuto") ? d.vendor : "N/D";
    const srcStr = d.how_found || d.source || "ARP";
    const v6Str = (d.ipv6_addresses && d.ipv6_addresses.length > 0)
      ? `<br><small style="color: var(--text-dim); font-size: 11px;">${d.ipv6_addresses.join(", ")}</small>`
      : "";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="value" style="color: var(--accent-cyan);">${d.ip}${v6Str}</td>
      <td class="value">${macStr}</td>
      <td style="color: #fff;">${vendorStr}</td>
      <td style="color: var(--text-muted);">${d.hostname || "--"}</td>
      <td><span class="badge badge-cyan">${srcStr}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function addRow(table, label, valueHtml) {
  const tr = document.createElement("tr");
  tr.innerHTML = `<td class="label">${label}</td><td class="value">${valueHtml}</td>`;
  table.appendChild(tr);
}

function getGradeColor(grade) {
  switch (grade) {
    case "A+":
    case "A":
      return "var(--accent-emerald)";
    case "B":
      return "#22c55e";
    case "C":
      return "var(--accent-amber)";
    case "D":
    case "F":
      return "var(--accent-rose)";
    default:
      return "var(--text-main)";
  }
}

function exportJSON() {
  if (!currentData) return;
  const str = JSON.stringify(currentData, null, 2);
  const blob = new Blob([str], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `netprobe_report_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function copyJSON() {
  if (!currentData) return;
  navigator.clipboard.writeText(JSON.stringify(currentData, null, 2)).then(() => {
    alert("JSON copiato negli appunti!");
  });
}
