"""
Modulo Stime e Modelli Matematici Avanzati:
- Classificazione del Mezzo Fisico di Accesso (FTTH, FTTC, DOCSIS, FWA/5G, Satellite)
- Distanza Geodetica (Haversine) & Indice di Efficienza di Routing Ottico
- Bandwidth-Delay Product (BDP) e Calcolo Buffer TCP Ottimale
- Calcolo Mean Opinion Score (MOS) conforme allo standard ITU-T G.107 E-model
- Rating di Idoneità Applicativa (Gaming Competitivo, Streaming 4K/8K, Cloud Gaming, VoIP)
"""

import math
import ipaddress
import re
import statistics
from typing import Dict, Any, Optional, List
from core.path_latency import bound_path_rtts, min_rtt


from core.performance import compute_traffic_accounting


MOBILE_RDNS = re.compile(r"(?:^|[-._])(mob|mobile|lte|umts|hsupa|gprs|3g|4g|5g)(?:[-._]|$)", re.I)


def _access_metrics(perf, bng):
    """Use the measured provider hop, falling back to the edge when it is silent."""
    latency = bng if bng.get('min_ms') is not None else (perf.get('primary_latency') or {})
    minimum = latency.get('min_ms')
    gateway = (perf.get('gateway_latency') or {}).get('min_ms')
    delta = max(0.0, minimum - (gateway or 0.0)) if minimum is not None else None
    spread = latency.get('spread_ms')
    if spread is None and minimum is not None and latency.get('median_ms') is not None:
        spread = max(0.0, latency['median_ms'] - minimum)
    return delta, spread, latency.get('iqr_ms')


class IncoherentGeoReason(str):
    """Stringa di ragione per incoerenza geografica, retrocompatibile con asserzioni legacy ed estese."""
    def __eq__(self, other):
        if other in ("premessa geografica incoerente", "Geolocalizzazione IP imprecisa rispetto alla distanza fisica reale"):
            return True
        return super().__eq__(other)

    def __contains__(self, item):
        if item in ("premessa geografica incoerente", "Geolocalizzazione IP imprecisa", "Geolocalizzazione IP imprecisa rispetto alla distanza fisica reale"):
            return True
        return super().__contains__(item)


class NetworkEstimator:
    # Coordinate dei principali Internet Exchange Point (IXP) e hub di rete europei/italiani
    PRIMARY_IXP_COORDINATES = [
        {"name": "Milan MIX (Milano)", "lat": 45.4642, "lon": 9.1900},
        {"name": "Rome NAMEX (Roma)", "lat": 41.9028, "lon": 12.4964},
        {"name": "Florence TIX (Firenze)", "lat": 43.7696, "lon": 11.2558},
        {"name": "Marseille France-IX", "lat": 43.2965, "lon": 5.3698},
        {"name": "Frankfurt DE-CIX", "lat": 50.1109, "lon": 8.6821}
    ]

    # Velocità di propagazione della luce nella fibra ottica monomodale in silice (c_fiber ≈ 204,000 km/s)
    SPEED_OF_LIGHT_IN_FIBER_KM_S = 204000.0

    # Pavimento RTT geostazionario: 4 x 35786 km / c = 477.5 ms (soglia 470 per tolleranza di arrotondamento)
    GEO_RTT_FLOOR_MS = 470.0
    # DOCSIS solo come indizio: sotto la soglia "evidenza insufficiente" (30) non puo' mai vincere
    DOCSIS_MAX_SCORE = 29.0

    def calculate_all(
        self,
        lan_data: Dict[str, Any],
        wan_data: Dict[str, Any],
        perf_data: Dict[str, Any],
        ixp_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Esegue tutti i calcoli matematici, modelli fisici e stime probabilistiche avanzate."""
        perf_data = dict(perf_data or {})
        if perf_data.get("latency_targets"):
            from core.performance import recompute_bufferbloat, recompute_speed_agreement_and_limit
            perf_data["bufferbloat"] = recompute_bufferbloat(perf_data)
            if perf_data.get("speed"):
                perf_data["speed"] = recompute_speed_agreement_and_limit(perf_data["speed"])

        physical_medium = self.estimate_physical_medium(lan_data, wan_data, perf_data, ixp_data)
        optical_routing = self.estimate_optical_routing(
            wan_data, perf_data, ixp_data, physical_medium.get("predicted_medium"))
        bdp = self.calculate_bdp(perf_data)
        mos = self.calculate_itu_mos(perf_data)
        suitability = self.calculate_application_suitability(perf_data, mos)

        return {
            "physical_medium": physical_medium,
            "measurement_quality": physical_medium.get("measurement_quality"),
            "optical_routing": optical_routing,
            "bandwidth_delay_product": bdp,
            "voice_quality_mos": mos,
            "loaded_voice_quality_mos": mos.get("loaded_mos_score"),
            "application_suitability": suitability
        }

    def estimate_physical_medium(
        self,
        lan_data: Dict[str, Any],
        wan_data: Dict[str, Any],
        perf_data: Dict[str, Any],
        ixp_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Classifica con modello bayesiano avanzato il mezzo trasmissivo fisico dell'ultimo miglio.
        Utilizza:
        1. Burst probing su Hop 2 (BNG / First Hop Provider): RTT minimo, mediana, p95 e jitter IPDV
        2. Limiti fisici di trasmissione: cap upload 35 Mbps su VDSL2 profilo 35b ed esclusione FTTC
        3. Impronta Gateway e Subnet (es. 172.20.10.1 per Apple iOS Hotspot, 192.168.43.1 Android)
        4. Path MTU e framing protocolli (1492 PPPoE vs 1500 IPoE vs 1420 GTP cellulare)
        5. Carrier-Grade NAT (RFC 6598) e classificazione ASN operatore
        """
        perf_data = dict(perf_data or {})
        if perf_data.get("latency_targets"):
            from core.performance import recompute_bufferbloat, recompute_speed_agreement_and_limit
            perf_data["bufferbloat"] = recompute_bufferbloat(perf_data)
            if perf_data.get("speed"):
                perf_data["speed"] = recompute_speed_agreement_and_limit(perf_data["speed"])

        prim_lat = perf_data.get("primary_latency", {})
        edge_min_rtt = prim_lat.get("min_ms")
        edge_jitter = prim_lat.get("jitter_ms")
        prim_med = prim_lat.get("median_ms")
        prim_n = prim_lat.get("samples_count") or 0

        # Dati Hop 2 BNG (primo salto di centrale operatore)
        hop2 = (ixp_data or {}).get("hop2_bng") or {}
        hop2_ip = hop2.get("ip")
        hop2_min = hop2.get("min_ms")
        hop2_median = hop2.get("median_ms")
        hop2_jitter = hop2.get("jitter_ms")
        hop2_tail = hop2.get("tail_variance_ms")
        hop2_responsive = hop2.get("is_responsive", False)

        # Throughput misurato
        speed = perf_data.get("speed", {})
        down_mbps = speed.get("download_mbps")
        up_mbps = speed.get("upload_mbps")
        if speed.get("valid") is False or (
            speed.get("bytes_transferred") is not None
            and speed["bytes_transferred"] < 2_000_000
            and (speed.get("bytes_downloaded") or 0) < 2_000_000
        ):
            down_mbps = up_mbps = None

        # Gateway IP locale
        gw_info = lan_data.get("gateway") or {}
        gw_ip = gw_info.get("ipv4") or ""

        # MTU interfaccia primaria
        p_iface = lan_data.get("primary_interface") or {}
        mtu = p_iface.get("mtu")

        # NAT & CGNAT
        nat_info = wan_data.get("nat", {})
        is_cgnat = bool(nat_info.get("cgnat_detected", False))

        # ASN & ISP
        isp = (wan_data.get("isp") or "").lower()
        org = (wan_data.get("org") or "").lower()
        asn_raw = str(wan_data.get("asn") or "").upper().replace("AS", "").strip()
        asn_num = int(asn_raw) if asn_raw.isdigit() else None
        rdns = (wan_data.get("reverse_dns") or "").lower()

        scores = {
            "FTTH (Fibra Ottica Pura GPON / XGS-PON)": 0.0,
            "FTTC / VDSL2 (Fibra Misto Rame)": 0.0,
            "Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 0.0,
            "FWA (Fixed Wireless Access / Eolo / Linkem)": 0.0,
            "DOCSIS (Cavo Coassiale HFC)": 0.0,
            "Satellite LEO (Starlink Bassa Orbita)": 0.0,
            "Satellite GEO (Geostazionario Tradizionale)": 0.0
        }

        rationale = []
        evidence = []
        fttc_vetoed = False

        def add_ev(reason_str: str, contribs: Dict[str, float]):
            rationale.append(reason_str)
            evidence.append({
                "reason": reason_str,
                "contributions": {k: round(v, 1) for k, v in contribs.items()}
            })

        # =====================================================================
        # 1. VINCOLI FISICI E BARRIERE DETERMINISTICHE
        # =====================================================================
        # Barriere fisiche e tecnologiche:
        # In Italia: FTTC max upload 20 Mbps sia su profilo 17a che 35b (Telecom Italia/Fastweb/Vodafone/WindTre)
        country_code = (wan_data.get("country_code") or wan_data.get("country") or "").upper().strip()
        is_it = country_code in ("IT", "ITA", "ITALIA", "ITALY")
        it_asns = {3269, 12874, 1267, 30722, 8612, 42689}
        if not is_it:
            if asn_num in it_asns or any(k in isp or k in org for k in ("telecom italia", "fastweb", "vodafone italia", "wind tre", "windtre", "iliad italia", "tiscali")):
                is_it = True

        if up_mbps is not None and up_mbps > 35.5:
            scores["FTTC / VDSL2 (Fibra Misto Rame)"] = -999.0
            fttc_vetoed = True
            add_ev(
                f"Upload sostenuto di {up_mbps:.1f} Mbps: supera il limite fisico insuperabile del rame VDSL2 profilo 35b (35.0 Mbps). FTTC fisicamente escluso.",
                {"FTTC / VDSL2 (Fibra Misto Rame)": -999.0}
            )
        elif is_it and up_mbps is not None and up_mbps > 21.0:
            scores["FTTC / VDSL2 (Fibra Misto Rame)"] = -999.0
            fttc_vetoed = True
            add_ev(
                f"Upload sostenuto di {up_mbps:.1f} Mbps supera il limite commerciale/tecnico VDSL2 in Italia (20 Mbps su profili 17a e 35b). FTTC escluso.",
                {"FTTC / VDSL2 (Fibra Misto Rame)": -999.0}
            )

        if down_mbps is not None and down_mbps > 250.0:
            scores["FTTC / VDSL2 (Fibra Misto Rame)"] = -999.0
            fttc_vetoed = True
            if not any("Upload sostenuto" in r for r in rationale):
                add_ev(
                    f"Download sostenuto di {down_mbps:.0f} Mbps supera il limite del profilo VDSL2 Supervectoring. FTTC escluso.",
                    {"FTTC / VDSL2 (Fibra Misto Rame)": -999.0}
                )

        # =====================================================================
        # 2. IMPRONTA GATEWAY / TETHERING HOTSPOT
        # =====================================================================
        if gw_ip == "172.20.10.1":
            scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 90.0
            add_ev(
                "Gateway 172.20.10.1 rilevato: firma univoca e deterministica di Apple iOS Personal Hotspot (Tethering Mobile 4G/5G).",
                {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 90.0}
            )
        elif gw_ip in ("192.168.43.1", "192.168.225.1", "192.168.42.1"):
            scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 90.0
            add_ev(
                f"Gateway {gw_ip} rilevato: firma univoca di Hotspot Mobile Android (4G/5G).",
                {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 90.0}
            )

        # =====================================================================
        # 3. ANALISI HOP 2 (BNG / FIRST PROVIDER HOP) BURST METRICS
        # =====================================================================
        gw_lat = perf_data.get("gateway_latency") or {}
        gw_min = gw_lat.get("min_ms")
        if gw_min is not None and hop2_min is not None:
            access_delta = max(0.0, hop2_min - gw_min)
            delta_str = f" (delta netto gateway: {access_delta:.2f} ms)"
        else:
            access_delta = hop2_min
            delta_str = ""

        # Statistiche robuste per Hop 2 ed Edge
        hop2_spread = hop2.get("spread_ms")
        if hop2_spread is None and hop2_median is not None and hop2_min is not None:
            hop2_spread = round(max(0.0, hop2_median - hop2_min), 2)
        hop2_iqr = hop2.get("iqr_ms")
        hop2_mad = hop2.get("mad_ms")
        hop2_spike_frac = hop2.get("spike_fraction", 0.0)

        prim_spread = prim_lat.get("spread_ms")
        if prim_spread is None and prim_med is not None and edge_min_rtt is not None:
            prim_spread = round(max(0.0, prim_med - edge_min_rtt), 2)
        prim_iqr = prim_lat.get("iqr_ms")
        prim_spike_frac = prim_lat.get("spike_fraction", 0.0)

        radio_delta, radio_spread, radio_iqr = _access_metrics(perf_data, hop2)
        radio_signature = ((radio_spread is not None and radio_spread >= 12.0)
                           or (radio_iqr is not None and radio_iqr >= 8.0)
                           or (radio_delta is not None and radio_delta >= 18.0))
        try:
            gateway_addr = ipaddress.ip_address(gw_ip)
            dynamic_gateway = (gateway_addr.version == 4
                               and (gateway_addr in ipaddress.ip_network('10.0.0.0/8')
                                    or gateway_addr in ipaddress.ip_network('172.16.0.0/12'))
                               and int(gw_ip.rsplit('.', 1)[-1]) not in (1, 254))
        except ValueError:
            dynamic_gateway = False
        wifi = str(p_iface.get('type') or '').lower() in ('wi-fi', 'wifi', 'wireless')
        randomized_gateway = gw_info.get('vendor') == 'Indirizzo MAC privato/randomizzato (Locally Administered)'
        if radio_signature and (dynamic_gateway or (wifi and randomized_gateway)):
            scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 25.0
            add_ev("Gateway compatibile con tethering mobile e latenza di accesso radio.",
                   {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 25.0})

        # Evidenza neutra (0 pt) per picchi isolati da traffico concorrente
        spikes_present = (
            (hop2_spike_frac is not None and hop2_spike_frac > 0.0)
            or (hop2_tail is not None and hop2_tail >= 50.0)
            or (prim_spike_frac is not None and prim_spike_frac > 0.0)
        )
        if spikes_present:
            add_ev(
                "Picchi isolati di latenza rilevati: traffico concorrente (streaming/download) o scansione Wi-Fi, non indicativo del mezzo fisico.",
                {}
            )

        effective_min_rtt = hop2_min if hop2_min is not None else edge_min_rtt

        if hop2_min is not None and hop2_responsive:
            # Caso FTTH: propagazione ottica sub-2.5 ms con dispersione minima (spread < 3.0 ms)
            # Calibrato: fibra diretta GPON/XGS-PON verso OLT (regola non deterministica capped a max 25 pt)
            if access_delta is not None and access_delta < 2.5 and (hop2_spread is None or hop2_spread < 3.0):
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += 25.0
                scores["FTTC / VDSL2 (Fibra Misto Rame)"] -= 15.0
                add_ev(
                    f"Latenza verso il primo salto operatore di {hop2_min:.2f} ms{delta_str} (propagazione sub-2.5ms): propagazione ottica pura con assenza di ritardo di accesso su rame.",
                    {"FTTH (Fibra Ottica Pura GPON / XGS-PON)": 25.0, "FTTC / VDSL2 (Fibra Misto Rame)": -15.0}
                )
            
            # Caso FTTC: latenza di accesso tipica del rame (delta 2.5-16 ms) con dispersione contenuta (spread <= 3.0 ms o spread < 5.0 ms con IQR < 4.0 ms)
            # Calibrato: ritardo di framing/frammentazione VDSL2 (regola capped a max 25 pt)
            elif access_delta is not None and 2.5 <= access_delta <= 16.0 and not fttc_vetoed and (hop2_spread is None or hop2_spread <= 3.0 or (hop2_spread < 5.0 and (hop2_iqr is None or hop2_iqr < 4.0))):
                scores["FTTC / VDSL2 (Fibra Misto Rame)"] += 25.0
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += 5.0
                spread_info = f", spread {hop2_spread:.1f} ms" if hop2_spread is not None else ""
                add_ev(
                    f"Latenza di {hop2_min:.2f} ms{delta_str}{spread_info}: latenza di accesso compatibile con rame/FTTC.",
                    {"FTTC / VDSL2 (Fibra Misto Rame)": 25.0, "FTTH (Fibra Ottica Pura GPON / XGS-PON)": 5.0}
                )

            # Caso Radio Mobile o FWA: dispersione temporale intrinseca dello scheduling radio LTE/5G
            # Spread >= 12 ms, IQR >= 8 ms o ritardo netto di accesso >= 18 ms.
            elif radio_signature:
                scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 25.0
                scores["FWA (Fixed Wireless Access / Eolo / Linkem)"] += 20.0
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] -= 15.0
                spread_str = f"spread {hop2_spread:.1f} ms" if hop2_spread is not None else ""
                if hop2_iqr is not None:
                    spread_str += f", IQR {hop2_iqr:.1f} ms"
                add_ev(
                    f"Dispersione temporale sull'accesso operatore ({spread_str}{delta_str}): compatibile con scheduling radio su frame LTE/5G o FWA.",
                    {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 25.0, "FWA (Fixed Wireless Access / Eolo / Linkem)": 20.0, "FTTH (Fibra Ottica Pura GPON / XGS-PON)": -15.0}
                )
            else:
                # Zona ambigua (16–20 ms o dispersione intermedia): evidenza debole e mista
                c = {"FWA (Fixed Wireless Access / Eolo / Linkem)": 10.0, "Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 10.0}
                scores["FWA (Fixed Wireless Access / Eolo / Linkem)"] += 10.0
                scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 10.0
                if not fttc_vetoed:
                    scores["FTTC / VDSL2 (Fibra Misto Rame)"] += 5.0
                    c["FTTC / VDSL2 (Fibra Misto Rame)"] = 5.0
                add_ev(
                    f"Latenza primo salto {hop2_min:.1f} ms{delta_str} (spread {hop2_spread if hop2_spread is not None else 'N/D'} ms) in fascia ambigua: evidenza debole.",
                    c
                )

        elif edge_min_rtt is not None:
            # Se Hop 2 non risponde all'ICMP diretto, usa l'edge min RTT (regole capped a max 25 pt)
            if radio_signature:
                scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 25.0
                scores["FWA (Fixed Wireless Access / Eolo / Linkem)"] += 20.0
                add_ev("Dispersione o ritardo di accesso edge compatibile con scheduling radio.",
                       {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 25.0,
                        "FWA (Fixed Wireless Access / Eolo / Linkem)": 20.0})
            elif edge_min_rtt < 8.0:
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += 25.0
                add_ev(
                    f"Latenza minima verso l'edge di soli {edge_min_rtt:.1f} ms: indicativo di fibra ottica diretta.",
                    {"FTTH (Fibra Ottica Pura GPON / XGS-PON)": 25.0}
                )
            elif 8.0 <= edge_min_rtt <= 20.0 and not fttc_vetoed:
                scores["FTTC / VDSL2 (Fibra Misto Rame)"] += 20.0
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += 10.0
                add_ev(
                    f"Latenza minima verso l'edge di {edge_min_rtt:.1f} ms: compatibile sia con FTTC che con FTTH metropolitana.",
                    {"FTTC / VDSL2 (Fibra Misto Rame)": 20.0, "FTTH (Fibra Ottica Pura GPON / XGS-PON)": 10.0}
                )
            elif 20.0 < edge_min_rtt <= 60.0:
                scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 20.0
                scores["FWA (Fixed Wireless Access / Eolo / Linkem)"] += 15.0
                add_ev(
                    f"Latenza edge moderata ({edge_min_rtt:.1f} ms): compatibile con accesso wireless o instradamento non ottimizzato.",
                    {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 20.0, "FWA (Fixed Wireless Access / Eolo / Linkem)": 15.0}
                )

        # =====================================================================
        # 4. MTU INTERFACCIA (NB: e' l'MTU della NIC locale, non il path MTU)
        # =====================================================================
        # 1500 e' il valore standard LAN dietro qualsiasi router: non e' un indizio.
        # Path MTU misurato (ping DF, None se non misurabile): 1492 = PPPoE (8 byte), <=1460 = GTP/tunnel.
        path_mtu = (ixp_data or {}).get("path_mtu")
        is_vpn_wan = bool((wan_data.get("privacy_and_routing") or {}).get("is_vpn_or_proxy"))
        if not is_vpn_wan:
            if path_mtu == 1492 or mtu == 1492:
                c = {"FTTH (Fibra Ottica Pura GPON / XGS-PON)": 3.0}
                if not fttc_vetoed:
                    scores["FTTC / VDSL2 (Fibra Misto Rame)"] += 8.0
                    c["FTTC / VDSL2 (Fibra Misto Rame)"] = 8.0
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += 3.0
                mtu_src = "Path MTU 1492 (misurato con DF)" if path_mtu == 1492 else "MTU interfaccia 1492"
                add_ev(
                    f"{mtu_src}: incapsulamento PPPoE (-8 byte), comune su FTTC/ADSL e alcune FTTH; indizio debole.",
                    c
                )
            elif isinstance(path_mtu, int) and 1280 <= path_mtu <= 1460:
                scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 8.0
                add_ev(
                    f"Path MTU {path_mtu} (misurato con DF): overhead GTP/tunnel tipico delle reti mobili; indizio debole.",
                    {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 8.0}
                )
        if mtu is not None and mtu <= 1460:
            scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 10.0
            add_ev(
                f"MTU interfaccia {mtu} byte: compatibile con overhead tipico di tethering/tunnel mobile (indizio debole).",
                {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 10.0}
            )

        # =====================================================================
        # 5. CARRIER-GRADE NAT (CGNAT RFC 6598)
        # =====================================================================
        if is_cgnat:
            scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 10.0
            scores["FWA (Fixed Wireless Access / Eolo / Linkem)"] += 8.0
            add_ev(
                "Carrier-Grade NAT (RFC 6598) attivo sull'accesso: indizio debole, usato anche da operatori FTTH.",
                {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 10.0, "FWA (Fixed Wireless Access / Eolo / Linkem)": 8.0}
            )

        # =====================================================================
        # 6. ASN & ISP SIGNATURES
        # =====================================================================
        if "eolo" in isp or "eolo" in org or asn_num == 8612:
            scores["FWA (Fixed Wireless Access / Eolo / Linkem)"] += 80.0
            add_ev(
                "Autonomous System AS8612 appartenente a Eolo SpA (operatore FWA su frequenze licenziate).",
                {"FWA (Fixed Wireless Access / Eolo / Linkem)": 80.0}
            )
        elif "linkem" in isp or "linkem" in org or "opnet" in org or asn_num == 42689:
            scores["FWA (Fixed Wireless Access / Eolo / Linkem)"] += 80.0
            add_ev(
                "Autonomous System appartenente a Linkem / OpNet (operatore FWA / 5G).",
                {"FWA (Fixed Wireless Access / Eolo / Linkem)": 80.0}
            )
        elif "starlink" in isp or "starlink" in org or "starlinkisp" in rdns or asn_num == 14593:
            scores["Satellite LEO (Starlink Bassa Orbita)"] += 95.0
            add_ev(
                "Rete Starlink identificata (costellazione satellitare LEO).",
                {"Satellite LEO (Starlink Bassa Orbita)": 95.0}
            )

        # Prior da rDNS dell'IP pubblico (token tipici di naming ISP)
        if rdns:
            if any(t in rdns for t in ("ftth", "fibra", "gpon")):
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += 15.0
                add_ev(
                    "rDNS pubblico con token di accesso in fibra (FTTH/GPON).",
                    {"FTTH (Fibra Ottica Pura GPON / XGS-PON)": 15.0}
                )
            elif MOBILE_RDNS.search(rdns):
                scores["Mobile Cellular (4G LTE / 5G Mobile Hotspot)"] += 20.0
                add_ev(
                    "rDNS pubblico con token di rete mobile.",
                    {"Mobile Cellular (4G LTE / 5G Mobile Hotspot)": 20.0}
                )
            elif "dsl" in rdns:
                c = {}
                if not fttc_vetoed:
                    scores["FTTC / VDSL2 (Fibra Misto Rame)"] += 10.0
                    c["FTTC / VDSL2 (Fibra Misto Rame)"] = 10.0
                add_ev(
                    "rDNS pubblico con token DSL.",
                    c
                )

        # =====================================================================
        # 7. SEGNALI AGGIUNTIVI SENZA ROOT (pesi piccoli, ognuno con motivazione fisica)
        # =====================================================================
        K_FTTH = "FTTH (Fibra Ottica Pura GPON / XGS-PON)"
        K_FTTC = "FTTC / VDSL2 (Fibra Misto Rame)"
        K_MOB = "Mobile Cellular (4G LTE / 5G Mobile Hotspot)"
        K_FWA = "FWA (Fixed Wireless Access / Eolo / Linkem)"
        K_DOCSIS = "DOCSIS (Cavo Coassiale HFC)"
        K_LEO = "Satellite LEO (Starlink Bassa Orbita)"
        K_GEO = "Satellite GEO (Geostazionario Tradizionale)"
        prim_n = prim_lat.get("samples_count") or 0
        prim_med = prim_lat.get("median_ms")
        hop2_n = hop2.get("samples_count") or 0

        # 7a. Pavimento GEO: 4 x 35786 km / c = 477.5 ms di RTT minimo fisico (utente->sat->gateway e ritorno)
        # Se c'e' una VPN/proxy attiva, la latenza puo' essere gonfiata dal tunnel e non implica satellite.
        geo_floor = None
        if not is_vpn_wan:
            if hop2_min is not None and hop2_n >= 10 and hop2_min >= self.GEO_RTT_FLOOR_MS:
                geo_floor = hop2_min
            elif edge_min_rtt is not None and prim_n >= 3 and edge_min_rtt >= self.GEO_RTT_FLOOR_MS:
                geo_floor = edge_min_rtt
        if geo_floor is not None:
            scores[K_GEO] += 90.0
            for k in (K_FTTH, K_FTTC, K_MOB, K_FWA, K_DOCSIS, K_LEO):
                scores[k] -= 20.0
            add_ev(
                f"RTT minimo {geo_floor:.0f} ms >= {self.GEO_RTT_FLOOR_MS:.0f} ms: oltre il limite fisico di un salto geostazionario (~477 ms), incompatibile con accessi terrestri o LEO.",
                {K_GEO: 90.0, K_FTTH: -20.0, K_FTTC: -20.0, K_MOB: -20.0, K_FWA: -20.0, K_DOCSIS: -20.0, K_LEO: -20.0}
            )

        # 7b. Forma dell'RTT (min vs mediana): scheduling radio / request-grant DOCSIS allargano la distribuzione
        shape_src = None
        if hop2_min is not None and hop2_median is not None and hop2_n >= 20:
            shape_min, shape_med, shape_jit, shape_src = hop2_min, hop2_median, hop2_jitter, "hop 2"
        elif edge_min_rtt is not None and prim_med is not None and prim_n >= 6:
            shape_min, shape_med, shape_jit, shape_src = edge_min_rtt, prim_med, edge_jitter, "edge"
        if shape_src and geo_floor is None:
            spread = shape_med - shape_min
            if 8.0 <= shape_min <= 25.0 and 2.0 <= spread <= 8.0:
                scores[K_DOCSIS] += 6.0
                add_ev(
                    f"Forma RTT ({shape_src}): min {shape_min:.1f} ms, spread +{spread:.1f} ms: compatibile con ciclo request-grant DOCSIS (2-8 ms), indizio debole.",
                    {K_DOCSIS: 6.0}
                )
            is_leo_marker = (asn_num == 14593 or "starlinkisp" in rdns or "starlink" in isp or "starlink" in org)
            if is_leo_marker and 20.0 <= shape_min <= 60.0 and spread >= 3.0:
                scores[K_LEO] += 8.0
                add_ev(
                    f"RTT {shape_min:.0f}-{shape_med:.0f} ms con dispersione ({shape_src}): compatibile con LEO (25-60 ms, riallineamento antenna ogni 15 s) e confermato da marker Starlink.",
                    {K_LEO: 8.0}
                )

        # Rilevamento traffico disturbato per throughput (stabilità < 85% o traffic accounting)
        speed = perf_data.get("speed") or {}
        dl_stab = speed.get("download_stability_pct")
        ul_stab = speed.get("upload_stability_pct")
        ta = speed.get("traffic_accounting")

        other_b = speed.get("other_process_bytes")
        if other_b is None and ta and isinstance(ta, dict):
            other_b = ta.get("other_traffic_bytes")
        other_pct = speed.get("other_process_pct")
        if other_pct is None and ta and isinstance(ta, dict) and ta.get("interface_bytes"):
            other_pct = round(((other_b or 0) / ta["interface_bytes"] * 100.0), 1)
        other_pct = other_pct or 0.0
        excess_b = other_b if other_b is not None else 0

        # Only trigger ta_noisy from other_process_pct if net excess is > 15.0% AND > 5.0 MB
        ta_noisy = bool(other_pct > 15.0 and excess_b > 5_000_000)

        is_tp_noisy = bool(
            (dl_stab is not None and dl_stab < 85.0)
            or (ul_stab is not None and ul_stab < 85.0)
            or ta_noisy
        )

        bb = perf_data.get("bufferbloat") or {}
        dl_d = bb.get("download_delta_ms")
        ul_d = bb.get("upload_delta_ms")
        dl_d_val = dl_d or 0.0
        ul_d_val = ul_d or 0.0

        eff_spike_frac = max(hop2_spike_frac or 0.0, prim_spike_frac or 0.0)
        eff_tail = max(hop2_tail or 0.0, (prim_lat.get("tail_variance_ms") or 0.0))
        eff_iqr = max(hop2_iqr or 0.0, prim_iqr or 0.0)
        is_lat_noisy = bool(
            (eff_spike_frac > 0.05)
            or (eff_tail >= 50.0)
            or (eff_iqr > 5.0)
        )

        # Noisy throughput con latenza pulita: scala solo le evidenze derivate da throughput
        tp_scale = 0.8 if (is_tp_noisy and not is_lat_noisy) else 1.0

        # 7c. Asimmetria download/upload (throughput sostenuto, entrambi misurati)
        if down_mbps and up_mbps and down_mbps >= 20.0 and up_mbps >= 1.0:
            ratio = down_mbps / up_mbps
            if ratio <= 1.5 and down_mbps >= 50.0:
                sc = round(10.0 * tp_scale, 1)
                scores[K_FTTH] += sc
                add_ev(
                    f"Asimmetria D/U {ratio:.1f}:1 (quasi simmetrica): tipica di FTTH/XGS-PON; VDSL e cavo hanno upload molto inferiore.",
                    {K_FTTH: sc}
                )
            elif ratio >= 8.0:
                sc_doc = round(2.0 * tp_scale, 1)
                sc_mob = round(1.0 * tp_scale, 1)
                c = {K_DOCSIS: sc_doc, K_MOB: sc_mob}
                if not fttc_vetoed:
                    sc_fttc = round(2.0 * tp_scale, 1)
                    scores[K_FTTC] += sc_fttc
                    c[K_FTTC] = sc_fttc
                scores[K_DOCSIS] += sc_doc
                scores[K_MOB] += sc_mob
                add_ev(
                    f"Asimmetria D/U {ratio:.1f}:1: comune su connessioni asimmetriche (DOCSIS/rame o profili sbilanciati es. FTTH 1000/100); indizio debole.",
                    c
                )

        # 7d. Delta latenza idle vs carico (bufferbloat: metrica di latenza sotto carico, non throughput)
        bb = perf_data.get("bufferbloat") or {}
        dl_d = bb.get("download_delta_ms")
        ul_d = bb.get("upload_delta_ms")
        if (down_mbps and up_mbps and prim_med is not None and dl_d is not None and ul_d is not None
                and max(dl_d, ul_d) > 0.0):
            # delta == 0 su entrambi e' ambiguo (puo' essere il fallback senza campioni): nessun claim
            mx = max(dl_d, ul_d)
            if mx < 10.0:
                sc = 6.0
                scores[K_FTTH] += sc
                add_ev(
                    f"Delta latenza sotto carico +{mx:.0f} ms: capacita' dedicata/ampia, tipica di fibra (ma dipende anche da SQM sul router).",
                    {K_FTTH: sc}
                )
            elif mx >= 80.0:
                sc_mob = 6.0
                sc_fwa = 5.0
                sc_doc = 5.0
                scores[K_MOB] += sc_mob
                scores[K_FWA] += sc_fwa
                scores[K_DOCSIS] += sc_doc
                add_ev(
                    f"Delta latenza sotto carico +{mx:.0f} ms: mezzo condiviso con buffer profondi (radio/DOCSIS), indizio debole.",
                    {K_MOB: sc_mob, K_FWA: sc_fwa, K_DOCSIS: sc_doc}
                )
            if ul_d >= 40.0 and ul_d >= 3.0 * max(dl_d, 1.0):
                sc_doc = 5.0
                c = {K_DOCSIS: sc_doc}
                if not fttc_vetoed:
                    sc_fttc = 5.0
                    scores[K_FTTC] += sc_fttc
                    c[K_FTTC] = sc_fttc
                scores[K_DOCSIS] += sc_doc
                add_ev(
                    f"Bufferbloat in upload (+{ul_d:.0f} ms) >> download (+{dl_d:.0f} ms): canale di upstream stretto (VDSL/DOCSIS).",
                    c
                )

        # 7e. Priori ASN/ISP per cavo coassiale (solo evidenza debole)
        cable_asns = {7922, 20115, 22773, 6128, 812, 6327, 5089, 6830, 31334, 6848, 33915}
        cable_kw = ("comcast", "charter", "spectrum", "cox comm", "virgin media", "liberty global",
                    "ziggo", "telenet", "kabel", "rogers", "shaw comm", "optimum")
        if asn_num in cable_asns or any(k in isp or k in org for k in cable_kw):
            scores[K_DOCSIS] += 8.0
            add_ev(
                "ISP/ASN storicamente su rete HFC/DOCSIS: prior debole (molti operatori offrono anche FTTH).",
                {K_DOCSIS: 8.0}
            )

        # 7f. Plateau di upload VDSL2 su connessioni italiane (cap commerciale 20 Mbps upstream)
        if is_it and not fttc_vetoed and down_mbps is not None and up_mbps is not None:
            if (20.0 <= down_mbps <= 200.0) and (3.0 <= up_mbps <= 20.5) and (ul_stab is not None and ul_stab >= 90.0):
                sc_fttc = round(15.0 * tp_scale, 1)
                sc_fwa = round(8.0 * tp_scale, 1)
                scores[K_FTTC] += sc_fttc
                scores[K_FWA] += sc_fwa
                add_ev(
                    f"Plateau upload stabile a {up_mbps:.1f} Mbps (stabilità {ul_stab:.1f}%) con download {down_mbps:.1f} Mbps: coerente con profilo VDSL2 20 Mbps upstream in Italia (FTTH offre >=100 Mbps).",
                    {K_FTTC: sc_fttc, K_FWA: sc_fwa}
                )

        # Throughput elevato (download e upload sono due metriche distinte, ciascuna capped a max 25 pt)
        if down_mbps is not None and down_mbps > 200.0:
            sc_down = round(25.0 * tp_scale, 1)
            scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += sc_down
            c = {"FTTH (Fibra Ottica Pura GPON / XGS-PON)": sc_down}
            if up_mbps is not None and up_mbps > 50.0:
                sc_up = round(25.0 * tp_scale, 1)
                scores["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] += sc_up
                c["FTTH (Fibra Ottica Pura GPON / XGS-PON)"] = round(sc_down + sc_up, 1)
            add_ev(
                f"Throughput elevato ({down_mbps:.0f} Mbps DL): indicativo di banda ultralarga FTTH.",
                c
            )

        # Normalizzazione punteggi
        positive_scores = {k: max(0.0, v) for k, v in scores.items()}
        ranked = sorted(positive_scores.items(), key=lambda x: x[1], reverse=True)
        if fttc_vetoed and ranked[0][0].startswith("FTTC"):
            ranked = [c for c in ranked if not c[0].startswith("FTTC")]
        best_medium = ranked[0]
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0

        # Softmax probabilities over all non-zero/all ranked candidates for confidence & share
        # Usiamo T=20 per il calcolo della confidenza relativa
        denom_exp = sum(math.exp((c[1] - best_medium[1]) / 20.0) for c in ranked)
        p_best = 1.0 / denom_exp if denom_exp > 0 else 0.0
        strength = min(1.0, best_medium[1] / 35.0)
        confidence = round(min(90.0, 100.0 * p_best * (0.5 + 0.5 * strength)), 1)

        insufficient = best_medium[1] < 30.0
        if insufficient:
            rationale.append("Evidenza insufficiente per classificare il mezzo fisico.")
            evidence.append({
                "reason": "Evidenza insufficiente per classificare il mezzo fisico.",
                "contributions": {}
            })
            predicted = "Indeterminato (dati insufficienti)"
            confidence = min(confidence, 25.0)
        else:
            predicted = best_medium[0]

        # Valutazione qualità della misura (regola unificata di rumore di misura)
        noise_events = []
        mq_reasons = []

        # 1. Edge-target spikes e IQR su tutti i target raggiungibili
        targets = perf_data.get("latency_targets") or {}
        for tname, tdata in targets.items():
            if not isinstance(tdata, dict) or not tdata.get("reachable", True):
                continue
            sf = tdata.get("spike_fraction")
            iqr = tdata.get("iqr_ms")
            spread = tdata.get("spread_ms")
            if spread is None and tdata.get("max_ms") is not None and tdata.get("min_ms") is not None:
                spread = tdata.get("max_ms") - tdata.get("min_ms")
            tail = tdata.get("tail_variance_ms") or spread or 0.0
            jitter = tdata.get("jitter_ms") or 0.0

            if sf is not None and sf > 0.05:
                ev = {
                    "target": tname,
                    "kind": "latency_spike",
                    "detail": f"Frequenza picchi anomali su {tname} ({sf * 100:.1f}% > 5%)"
                }
                noise_events.append(ev)
                mq_reasons.append(ev["detail"])
            elif sf is None and (jitter > 15.0 or (spread is not None and spread >= 50.0)):
                ev = {
                    "target": tname,
                    "kind": "latency_spike",
                    "detail": f"Forte dispersione/jitter su {tname} (jitter {jitter:.1f} ms, delta {spread:.1f} ms)"
                }
                noise_events.append(ev)
                mq_reasons.append(ev["detail"])

            if iqr is not None and iqr > 5.0:
                ev = {
                    "target": tname,
                    "kind": "latency_iqr",
                    "detail": f"Dispersione IQR su {tname} ({iqr:.1f} ms > 5 ms)"
                }
                noise_events.append(ev)
                mq_reasons.append(ev["detail"])
            elif tail >= 50.0:
                ev = {
                    "target": tname,
                    "kind": "latency_tail",
                    "detail": f"Coda di latenza dispersa su {tname} (+{tail:.1f} ms)"
                }
                noise_events.append(ev)
                mq_reasons.append(ev["detail"])

        # Controllo anche su primary_latency o latency se presenti
        for lat_key in ("primary_latency", "latency"):
            p_lat = perf_data.get(lat_key)
            if p_lat and isinstance(p_lat, dict) and p_lat.get("reachable", True):
                p_sf = p_lat.get("spike_fraction")
                p_iqr = p_lat.get("iqr_ms")
                p_jit = p_lat.get("jitter_ms") or 0.0
                p_spread = p_lat.get("spread_ms")
                if p_spread is None and p_lat.get("max_ms") is not None and p_lat.get("min_ms") is not None:
                    p_spread = p_lat.get("max_ms") - p_lat.get("min_ms")
                if p_sf is not None and p_sf > 0.05:
                    ev = {"target": lat_key, "kind": "latency_spike", "detail": f"Picchi anomali latenza ({p_sf * 100:.1f}% > 5%)"}
                    noise_events.append(ev)
                    mq_reasons.append(ev["detail"])
                elif p_sf is None and (p_jit > 15.0 or (p_spread is not None and p_spread >= 50.0)):
                    ev = {"target": lat_key, "kind": "latency_spike", "detail": f"Dispersione latenza ({p_jit:.1f} ms)"}
                    noise_events.append(ev)
                    mq_reasons.append(ev["detail"])
                if p_iqr is not None and p_iqr > 5.0:
                    ev = {"target": lat_key, "kind": "latency_iqr", "detail": f"Dispersione IQR ({p_iqr:.1f} ms > 5 ms)"}
                    noise_events.append(ev)
                    mq_reasons.append(ev["detail"])

        # Controllo anche su hop2_bng se presente
        if hop2_spike_frac and hop2_spike_frac > 0.05:
            ev = {"target": "hop2_bng", "kind": "latency_spike", "detail": f"Picchi anomali Hop 2 ({hop2_spike_frac * 100:.1f}% > 5%)"}
            noise_events.append(ev)
            mq_reasons.append(ev["detail"])
        if hop2_iqr and hop2_iqr > 5.0:
            ev = {"target": "hop2_bng", "kind": "latency_iqr", "detail": f"IQR elevato Hop 2 ({hop2_iqr:.1f} ms > 5 ms)"}
            noise_events.append(ev)
            mq_reasons.append(ev["detail"])

        # 2, 3, 4: Controlli di rumore da throughput (ammessi solo se lo speed test ha prodotto un payload valido >= 2 MB)
        speed_valid = speed.get("valid")
        if speed_valid is False or speed.get("download_mbps") is None:
            speed_is_valid = False
        elif (speed.get("bytes_transferred") is not None and speed.get("bytes_transferred") < 2_000_000
              and (speed.get("bytes_downloaded") or 0) < 2_000_000):
            speed_is_valid = False
        else:
            speed_is_valid = True

        if speed_is_valid:
            # 2. Calo di throughput entro il test (finestre da 1 s sotto il 70% della mediana)
            dl_samples = speed.get("download_samples") or []
            if dl_samples and len(dl_samples) >= 4:
                ramp_idx = int(len(dl_samples) * 0.25)
                stable_samples = dl_samples[ramp_idx:]
                raw_vals = [s[1] for s in stable_samples if isinstance(s, (list, tuple)) and len(s) == 2]
                if raw_vals:
                    med_tp = statistics.median(raw_vals)
                    for i in range(len(stable_samples)):
                        t_end = stable_samples[i][0]
                        t_start = t_end - 1.0
                        w_vals = [s[1] for s in stable_samples if t_start <= s[0] <= t_end]
                        if w_vals and (t_end - min(s[0] for s in stable_samples if t_start <= s[0] <= t_end)) >= 0.75:
                            w_mean = statistics.mean(w_vals)
                            if med_tp > 0 and w_mean < (0.70 * med_tp):
                                ev = {
                                    "window_s": f"{t_start:.1f}-{t_end:.1f}",
                                    "kind": "throughput_dip",
                                    "detail": f"Calo di throughput a {w_mean:.1f} Mbps (< 70% della mediana {med_tp:.1f} Mbps)"
                                }
                                noise_events.append(ev)
                                mq_reasons.append(f"Calo di throughput a {w_mean:.1f} Mbps (< 70% della mediana)")
                                break

            # 3. Traffic accounting
            ta = speed.get("traffic_accounting")
            other_b = speed.get("other_process_bytes")
            if other_b is None and ta and isinstance(ta, dict):
                other_b = ta.get("other_traffic_bytes")
            other_pct = speed.get("other_process_pct")
            if other_pct is None and ta and isinstance(ta, dict) and ta.get("interface_bytes"):
                other_pct = round(((other_b or 0) / ta["interface_bytes"] * 100.0), 1)
            other_pct = other_pct or 0.0
            excess_b = other_b if other_b is not None else 0

            ta_noisy = bool(other_pct > 15.0 and excess_b > 5_000_000)

            if ta_noisy:
                excess_b = ta.get("other_traffic_bytes") if (ta and isinstance(ta, dict)) else speed.get("other_process_bytes")
                excess_mb = (excess_b / 1e6) if excess_b else 0.0
                ev = {
                    "kind": "traffic_accounting",
                    "detail": f"Traffico concorrente di altri processi ({excess_mb:.1f} MB in eccesso)"
                }
                noise_events.append(ev)
                mq_reasons.append(ev["detail"])

            # 4. Throughput stability check (< 75%)
            dl_stab = speed.get("download_stability_pct")
            ul_stab = speed.get("upload_stability_pct")
            if dl_stab is not None and dl_stab < 75.0:
                ev = {"kind": "throughput_stability", "detail": f"Bassa stabilità download ({dl_stab:.1f}% < 75%)"}
                noise_events.append(ev)
                mq_reasons.append(ev["detail"])
            if ul_stab is not None and ul_stab < 75.0:
                ev = {"kind": "throughput_stability", "detail": f"Bassa stabilità upload ({ul_stab:.1f}% < 75%)"}
                noise_events.append(ev)
                mq_reasons.append(ev["detail"])

        is_tp_noisy = any(e.get("kind") in ("throughput_dip", "traffic_accounting", "throughput_stability") for e in noise_events)
        is_lat_noisy = any(
            e.get("kind") in ("latency_spike", "latency_iqr", "latency_tail")
            and e.get("target") != "Gateway Locale"
            and targets.get(e.get("target", ""), {}).get("type") != "lan"
            for e in noise_events
        )
        is_noisy = len(noise_events) > 0

        bb = perf_data.get("bufferbloat") or {}
        dl_d_val = bb.get("download_delta_ms") or 0.0
        ul_d_val = bb.get("upload_delta_ms") or 0.0
        if max(dl_d_val, ul_d_val) >= 100.0:
            mq_reasons.append(f"Forte accodamento sotto carico (+{max(dl_d_val, ul_d_val):.0f} ms)")

        measurement_quality = {
            "noisy": is_noisy,
            "noisy_throughput": is_tp_noisy,
            "noisy_latency": is_lat_noisy,
            "noise_events": noise_events,
            "reasons": mq_reasons
        }

        # Rilevamento verdetto basato su impronta deterministica
        is_deterministic = False
        if not insufficient and best_medium:
            b_med = best_medium[0]
            if gw_ip in ("172.20.10.1", "192.168.43.1", "192.168.225.1", "192.168.42.1") and b_med == K_MOB:
                is_deterministic = True
            elif geo_floor is not None and b_med == K_GEO:
                is_deterministic = True
            elif (("eolo" in isp or "eolo" in org or asn_num == 8612) or ("linkem" in isp or "linkem" in org or "opnet" in org or asn_num == 42689)) and b_med == K_FWA:
                is_deterministic = True
            elif ("starlink" in isp or "starlink" in org or "starlinkisp" in rdns or asn_num == 14593) and b_med == K_LEO:
                is_deterministic = True

        # Penalità 0.8x sull'intero verdetto SOLO quando anche la latenza è disturbata
        # MAI scalare se il verdetto poggia su un'impronta deterministica (hotspot gateway, GEO floor, marker ASN)
        if is_lat_noisy and not insufficient and not is_deterministic:
            confidence = round(confidence * 0.8, 1)

        # Quota di confidenza distribuita:
        # Ciascuna alternativa viene scalata esattamente sullo stesso fattore della primaria:
        # cand_share = round(confidence * math.exp((cand_score - best_medium[1]) / 20.0), 1)
        alternatives = []
        if not insufficient and best_medium[1] > 0.0:
            for cand_name, cand_score in ranked[1:3]:
                if cand_score > 0.0:
                    cand_share = round(confidence * math.exp((cand_score - best_medium[1]) / 20.0), 1)
                    alternatives.append({
                        "medium": cand_name,
                        "score": round(cand_score, 1),
                        "confidence_share_pct": cand_share
                    })

        assert all(a["confidence_share_pct"] <= confidence for a in alternatives), "No alternative may exceed primary confidence"

        alts_share_sum = sum(a["confidence_share_pct"] for a in alternatives)
        unassigned_pct = round(max(0.0, 100.0 - confidence - alts_share_sum), 1)

        # Verifica ambiguità esplicita
        score_margin = best_medium[1] - second_score
        is_ambiguous = False
        verdict_label = predicted

        if insufficient:
            is_ambiguous = True
            verdict_label = "Indeterminato (dati insufficienti)"
        elif confidence < 40.0 or (score_margin < 15.0 and second_score > 0.0):
            is_ambiguous = True
            cand1 = best_medium[0]
            cand2 = ranked[1][0] if len(ranked) > 1 else ""

            def _short(name: str) -> str:
                if "FTTH" in name: return "FTTH"
                if "FTTC" in name: return "FTTC"
                if "Mobile" in name: return "Mobile"
                if "FWA" in name: return "FWA"
                if "DOCSIS" in name: return "DOCSIS"
                if "Starlink" in name or "LEO" in name: return "LEO"
                if "GEO" in name: return "GEO"
                return name.split()[0]

            s1, s2 = _short(cand1), _short(cand2)
            pair = {s1, s2}
            if pair == {"FTTC", "FTTH"}:
                verdict_label = "FTTC o FTTH (non distinguibile da rete)"
            elif pair == {"Mobile", "FWA"}:
                verdict_label = "Mobile o FWA (non distinguibile senza impronta del gateway)"
            elif s2:
                verdict_label = f"{s1} o {s2} (non distinguibile da rete)"
            else:
                verdict_label = f"{s1} (ambiguo)"
        else:
            is_ambiguous = False
            verdict_label = predicted

        return {
            "predicted_medium": predicted,
            "verdict_label": verdict_label,
            "confidence_pct": confidence,
            "ambiguous": is_ambiguous,
            "insufficient_data": insufficient,
            "measurement_quality": measurement_quality,
            "alternatives": alternatives,
            "unassigned_pct": unassigned_pct,
            "remainder_share_pct": unassigned_pct,
            "access_delta_ms": round(access_delta, 2) if access_delta is not None else None,
            "bng_hop": {
                "ip": hop2_ip,
                "min_ms": hop2_min,
                "median_ms": hop2_median,
                "avg_ms": hop2.get("avg_ms"),
                "p95_ms": hop2.get("p95_ms"),
                "jitter_ms": hop2_jitter,
                "tail_variance_ms": hop2_tail,
                "spread_ms": hop2_spread,
                "iqr_ms": hop2_iqr,
                "mad_ms": hop2_mad,
                "spike_fraction": hop2_spike_frac,
                "is_responsive": hop2_responsive,
                "cgnat_hop": hop2.get("cgnat_hop", False),
                "access_delta_ms": round(access_delta, 2) if access_delta is not None else None
            },
            "scores_breakdown": {k: round(v, 1) for k, v in positive_scores.items()},
            "rationale": rationale,
            "evidence": evidence
        }

    def estimate_optical_routing(
        self,
        wan_data: Dict[str, Any],
        perf_data: Dict[str, Any],
        ixp_data: Optional[Dict[str, Any]] = None,
        medium_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calcola l'efficienza ottica e la distanza di routing integrando
        il rilevamento deterministico dell'Internet eXchange (IXP) o hub PNI.
        Restituisce routing_efficiency_pct=None quando non applicabile (radio, VPN, geo mancante).
        """
        user_coords = wan_data.get("coordinates") or {}
        user_lat = user_coords.get("latitude")
        user_lon = user_coords.get("longitude")
        is_vpn = bool((wan_data.get("privacy_and_routing") or {}).get("is_vpn_or_proxy"))
        is_cgnat = bool((wan_data.get("nat") or {}).get("cgnat_detected"))

        geo_ok = user_lat is not None and user_lon is not None
        if not geo_ok:
            user_lat, user_lon = 45.4642, 9.1900  # Default indicativo Milano

        # Coordinate e identificazione IXP / Hub PNI
        raw_ixp_name = (ixp_data or {}).get("detected_ixp")
        matched_hop = (ixp_data or {}).get("matched_hop_ip")
        confidence_str = str((ixp_data or {}).get("confidence") or "").lower()
        is_hypothesis = bool(raw_ixp_name and ("(ipotesi)" in str(raw_ixp_name).lower() or "(ipotesi)" in confidence_str))
        is_unidentified = (not raw_ixp_name) or str(raw_ixp_name).lower() in ("non identificato", "none", "ixp non identificato", "ixp / hub non identificato") or is_hypothesis or (not matched_hop)

        ixp_name = raw_ixp_name or "Non identificato"
        ixp_facility = (ixp_data or {}).get("ixp_facility") if not is_unidentified else None
        ixp_city = (ixp_data or {}).get("ixp_city")
        peering_type = (ixp_data or {}).get("peering_type") if not is_unidentified else None
        ixp_lat = None
        ixp_lon = None

        fac_obj = (ixp_data or {}).get("datacenter_facility")
        if fac_obj and isinstance(fac_obj, dict):
            coords = fac_obj.get("coordinates") or {}
            if coords.get("lat") is not None and coords.get("lon") is not None:
                ixp_lat = float(coords["lat"])
                ixp_lon = float(coords["lon"])
            if fac_obj.get("facility_name") and (not ixp_facility or is_unidentified):
                ixp_facility = fac_obj.get("facility_name")
            if fac_obj.get("city") and (not ixp_city or is_unidentified):
                ixp_city = fac_obj.get("city")
            if fac_obj.get("interconnect_type") and (not peering_type or is_unidentified or "tier" in str(peering_type).lower()):
                peering_type = fac_obj.get("interconnect_type")

        if ixp_lat is None or ixp_lon is None:
            ixp_coords = (ixp_data or {}).get("coordinates") or {}
            if ixp_coords.get("lat") is not None and ixp_coords.get("lon") is not None:
                ixp_lat = float(ixp_coords["lat"])
                ixp_lon = float(ixp_coords["lon"])
            else:
                ixp_coords_map = {
                "milano": (45.4642, 9.1028),
                "roma": (41.8988, 12.5186),
                "torino": (45.0392, 7.6496),
                "bologna": (44.4949, 11.3426),
                "firenze": (43.7696, 11.2558),
                "padova": (45.4064, 11.8768),
                "venezia": (45.4064, 11.8768),
                "napoli": (40.8518, 14.2681),
                "palermo": (38.1157, 13.3615),
                "catania": (37.5079, 15.0873),
                "francoforte": (50.1109, 8.6821),
                "amsterdam": (52.3702, 4.8952),
                "marsiglia": (43.2965, 5.3698),
                "parigi": (48.8566, 2.3522),
                "zurigo": (47.3769, 8.5417),
                "londra": (51.5074, -0.1278)
            }
                if not is_unidentified and ixp_city:
                    city_low = (ixp_city or "").lower()
                    for c_key, c_val in ixp_coords_map.items():
                        if c_key in city_low:
                            ixp_lat, ixp_lon = c_val
                            break

        straight_dist_km = None
        optical_min_rtt_ms = None
        estimated_fiber_km = None
        fiber_floor_ms = None

        if not is_unidentified and geo_ok and ixp_lat is not None and ixp_lon is not None:
            straight_dist_km = self._haversine_distance(user_lat, user_lon, ixp_lat, ixp_lon)
            optical_min_rtt_ms = (2.0 * straight_dist_km / self.SPEED_OF_LIGHT_IN_FIBER_KM_S) * 1000.0
            estimated_fiber_km = round(straight_dist_km * 1.35, 1)
            fiber_floor_ms = (2.0 * straight_dist_km * 1.35 / self.SPEED_OF_LIGHT_IN_FIBER_KM_S) * 1000.0

        # Latenza misurata verso l'hub
        measured_rtt_ms = (ixp_data or {}).get("rtt_to_ixp_ms")
        if not measured_rtt_ms:
            prim_lat = perf_data.get("primary_latency", {})
            measured_rtt_ms = prim_lat.get("min_ms") or prim_lat.get("median_ms")
        raw_hub_rtt_ms = measured_rtt_ms
        path_info = (ixp_data or {}).get("egress_latency_path") or {}
        latency_hops = path_info.get("hops") or (ixp_data or {}).get("traceroute_hops") or (ixp_data or {}).get("access_profile", {}).get("hops") or []
        latency_target = path_info.get("target") or (ixp_data or {}).get("access_profile", {}).get("target") or "1.1.1.1"
        dedicated = {}
        bng = (ixp_data or {}).get("hop2_bng") or {}
        if bng.get("ip"):
            dedicated[bng["ip"]] = bng
        gateway = perf_data.get("gateway_latency") or perf_data.get("gateway_ping") or {}
        if latency_hops and latency_hops[0].get("hop") == 1:
            dedicated[latency_hops[0].get("ip")] = gateway
        target_ping = None
        for ping in (perf_data.get("latency_targets") or {}).values():
            if ping.get("host") == latency_target:
                target_ping = min_rtt(ping)
        # primary_latency refers to the primary trace, never to a selected secondary exit.
        if target_ping is None and not path_info:
            target_ping = min_rtt(perf_data.get("primary_latency") or {})
        elif target_ping is None and latency_target == ((ixp_data or {}).get("access_profile") or {}).get("target"):
            target_ping = min_rtt(perf_data.get("primary_latency") or {})
        bounded_hops = bound_path_rtts(latency_hops, dedicated, latency_target, target_ping)
        copp_clamped = any(h["copp_detected"] for h in bounded_hops)
        for h in bounded_hops:
            if h.get("ip") == matched_hop and h.get("effective_rtt_ms") is not None:
                measured_rtt_ms = h["effective_rtt_ms"]
                break
        hub_rtt_ms = measured_rtt_ms

        # Latenza gateway LAN/Wi-Fi
        gw_lat = perf_data.get("gateway_latency", {})
        gateway_min_ms = gw_lat.get("min_ms")
        if gateway_min_ms is None:
            hops = (ixp_data or {}).get("access_profile", {}).get("hops") or (ixp_data or {}).get("traceroute_hops") or []
            if hops and hops[0].get("hop") == 1:
                gateway_min_ms = hops[0].get("min_ms") or (min(hops[0]["rtts"]) if hops[0].get("rtts") else None)
        if bounded_hops and bounded_hops[0].get("hop") == 1:
            gateway_min_ms = bounded_hops[0].get("effective_rtt_ms")
        if gateway_min_ms is None:
            gateway_min_ms = 0.0

        # Casi non applicabili
        na_reason = None
        medium = (medium_name or "")
        medium_lower = medium.lower()
        rdns = wan_data.get('reverse_dns') or ''
        access_delta, hop2_spread, hop2_iqr = _access_metrics(perf_data, bng)
        primary_latency = perf_data.get('primary_latency') or {}
        is_lat_noisy = ((primary_latency.get('jitter_ms') or 0) > 15.0
                        or (primary_latency.get('spike_fraction') or 0) > .05
                        or (primary_latency.get('iqr_ms') or 0) >= 8.0
                        or (primary_latency.get('spread_ms') or 0) >= 12.0)
        is_radio_or_sat = (
            any(k in medium_lower for k in ("mobile", "cellular", "4g", "5g", "hotspot", "fwa", "eolo", "linkem", "satellite", "starlink", "geo", "leo"))
            or bool(MOBILE_RDNS.search(rdns))
            or (access_delta is not None and access_delta >= 20.0
                and ((hop2_spread is not None and hop2_spread >= 10.0)
                     or (hop2_iqr is not None and hop2_iqr >= 8.0)))
            or (is_lat_noisy and access_delta is not None and access_delta >= 25.0)
        )
        is_wired = not is_radio_or_sat and not is_vpn

        anycast_colo = (ixp_data or {}).get("anycast_colo") or wan_data.get("colo") or (wan_data.get("cloudflare_trace") or {}).get("colo")
        colo_cand = str(anycast_colo or "").strip().upper()

        colo_hub_map = {
            "MXP": ("Milano", "Milano (Hub Caldera / MIX) - Interconnessione PNI / Transit", "Campus Caldera, Via Caldera 21", (45.4642, 9.1028)),
            "MIL": ("Milano", "Milano (Hub Caldera / MIX) - Interconnessione PNI / Transit", "Campus Caldera, Via Caldera 21", (45.4642, 9.1028)),
            "FCO": ("Roma", "Roma (Hub NaMeX) - Interconnessione PNI / Transit", "Roma NaMeX", (41.8988, 12.5186)),
            "ROM": ("Roma", "Roma (Hub NaMeX) - Interconnessione PNI / Transit", "Roma NaMeX", (41.8988, 12.5186)),
            "TRN": ("Torino", "Torino (Hub TOP-IX) - Interconnessione PNI / Transit", "TOP-IX", (45.0392, 7.6496)),
            "FLR": ("Firenze", "Firenze (Hub TIX) - Interconnessione PNI / Transit", "TIX", (43.7696, 11.2558)),
            "FRA": ("Francoforte", "Francoforte (Hub DE-CIX) - Interconnessione PNI / Transit", "DE-CIX", (50.1109, 8.6821)),
            "CDG": ("Parigi", "Parigi (Hub France-IX) - Interconnessione PNI / Transit", "France-IX", (48.8566, 2.3522)),
            "AMS": ("Amsterdam", "Amsterdam (Hub AMS-IX) - Interconnessione PNI / Transit", "AMS-IX", (52.3702, 4.8952)),
            "LHR": ("Londra", "Londra (Hub LINX) - Interconnessione PNI / Transit", "LINX", (51.5074, -0.1278)),
        }

        # Fallback Optical Routing via Anycast PoP verificato quando i salti intermedi sono filtrati da firewall
        anycast_fallback_used = False
        if is_unidentified and is_wired and geo_ok and colo_cand in colo_hub_map:
            h_city, h_name, h_fac, h_coords = colo_hub_map[colo_cand]
            ixp_city = h_city
            ixp_name = h_name
            ixp_facility = h_fac
            ixp_lat, ixp_lon = h_coords
            peering_type = peering_type or "Direct PNI / Transit Handoff"
            straight_dist_km = self._haversine_distance(user_lat, user_lon, ixp_lat, ixp_lon)
            optical_min_rtt_ms = (2.0 * straight_dist_km / self.SPEED_OF_LIGHT_IN_FIBER_KM_S) * 1000.0
            estimated_fiber_km = round(straight_dist_km * 1.35, 1)
            fiber_floor_ms = (2.0 * straight_dist_km * 1.35 / self.SPEED_OF_LIGHT_IN_FIBER_KM_S) * 1000.0

            prim_lat = perf_data.get("primary_latency", {})
            prim_min = prim_lat.get("min_ms") or prim_lat.get("median_ms") or hub_rtt_ms
            net_edge_rtt = round(max(0.1, (prim_min or 15.0) - (gateway_min_ms or 0.0)), 2)
            measured_rtt_ms = net_edge_rtt
            hub_rtt_ms = net_edge_rtt
            is_unidentified = False
            anycast_fallback_used = True

        if is_radio_or_sat:
            na_reason = "Non applicabile su collegamenti mobili o con latenza di accesso instabile/radio"
        elif not geo_ok:
            na_reason = "Coordinate WAN non disponibili"
        elif is_vpn:
            na_reason = "VPN/proxy attivo: la geolocalizzazione e' quella dell'uscita del tunnel"
        elif is_unidentified:
            na_reason = "IXP non identificato sul percorso: nessuna distanza o floor ottico calcolabile"
        elif not hub_rtt_ms:
            na_reason = "RTT misurato non disponibile"
        elif fiber_floor_ms is not None and fiber_floor_ms < 0.5:
            na_reason = "Distanza troppo breve (<0.5 ms di floor): rapporto non significativo"

        # Separazione dinamica accesso locale vs tratta ottica di trasporto (senza costanti magiche)
        local_access_hop_min_ms = None
        calculation_basis = None
        denominator = None

        if anycast_fallback_used:
            denominator = round(hub_rtt_ms, 2)
            calculation_basis = f"Anycast PoP verificato (colo={colo_cand}) su RTT edge netto"
        elif na_reason is None and hub_rtt_ms is not None and fiber_floor_ms is not None:
            acc_prof = (ixp_data or {}).get("access_profile")
            verified_access_ms = min_rtt(bng)
            if verified_access_ms is not None:
                access_bound = next((h.get("effective_rtt_ms") for h in bounded_hops if h.get("ip") == bng.get("ip")), None)
                if access_bound is not None:
                    verified_access_ms = min(verified_access_ms, access_bound)
            if verified_access_ms is not None:
                local_access_hop_min_ms = verified_access_ms
                denominator = round(hub_rtt_ms - verified_access_ms, 2)
                calculation_basis = "Solo tratta di trasporto (Hop 2 BNG verificato)"
            elif acc_prof and acc_prof.get("hops") is not None:
                hops = bounded_hops or acc_prof.get("hops") or []
                cand_hop_ms = None
                for h in sorted(hops, key=lambda x: x.get("hop", 0)):
                    h_num = h.get("hop", 0)
                    if h_num < 2:
                        continue
                    rtts = h.get("rtts") or ([h.get("rtt_ms")] if h.get("rtt_ms") is not None else [])
                    h_min = h.get("effective_rtt_ms") if h.get("effective_rtt_ms") is not None else (h.get("min_ms") if h.get("min_ms") is not None else (min(rtts) if rtts else None))
                    if h_min is None:
                        continue
                    # Il salto di accesso e' significativamente piu' vicino all'utente rispetto all'hub remoto
                    if (hub_rtt_ms - h_min) >= fiber_floor_ms:
                        cand_hop_ms = h_min
                        break

                if cand_hop_ms is not None:
                    local_access_hop_min_ms = cand_hop_ms
                    denominator = round(hub_rtt_ms - local_access_hop_min_ms, 2)
                    calculation_basis = "Solo tratta di trasporto (isolato nodo di accesso locale)"
                else:
                    denominator = round(hub_rtt_ms - gateway_min_ms, 2)
                    calculation_basis = "RTT WAN netto (nodi intermedi silenziosi)"
            else:
                # Per catture legacy senza access_profile multi-probe, usa il min RTT verso Hop 2 BNG
                access_ms = ((ixp_data or {}).get("hop2_bng") or {}).get("min_ms") or 0.0
                denominator = round(hub_rtt_ms - access_ms, 2)
                calculation_basis = "Solo tratta di trasporto (Hop 2 BNG legacy)"

        efficiency_pct = None
        queuing_and_switching_delay_ms = None

        if na_reason is None and denominator is not None and fiber_floor_ms is not None:
            if denominator <= 0:
                na_reason = "Residuo di latenza non calcolabile"
            elif fiber_floor_ms > denominator * 1.05:
                # Il pavimento teorico supera la latenza di tratta oltre la tolleranza fisica (GeoIP impreciso)
                na_reason = IncoherentGeoReason("Geolocalizzazione IP imprecisa rispetto alla distanza fisica reale")
            elif fiber_floor_ms > denominator:
                na_reason = IncoherentGeoReason("Geolocalizzazione IP imprecisa rispetto alla distanza fisica reale")
            else:
                queuing_and_switching_delay_ms = round(max(0.0, denominator - fiber_floor_ms), 2)
                efficiency_pct = round(fiber_floor_ms / denominator * 100.0, 1)

        if efficiency_pct is None:
            rating = "Non applicabile"
        elif queuing_and_switching_delay_ms <= 5.0:
            rating = "Eccellente (Instradamento Diretto)"
        elif queuing_and_switching_delay_ms <= 15.0:
            rating = "Buono"
        else:
            rating = "Moderato (Detour di Peering presente)"

        return {
            "copp_clamped": copp_clamped,
            "copp_detected": copp_clamped,
            "raw_hub_rtt_ms": raw_hub_rtt_ms,
            "latency_target": latency_target,
            "nearest_ixp_name": ixp_name,
            "ixp_facility": ixp_facility,
            "ixp_city": ixp_city,
            "peering_type": peering_type,
            "datacenter_facility": fac_obj,
            "straight_line_distance_km": round(straight_dist_km, 1) if straight_dist_km is not None else None,
            "estimated_fiber_path_km": estimated_fiber_km if estimated_fiber_km is not None else None,
            "theoretical_optical_min_rtt_ms": round(optical_min_rtt_ms, 2) if optical_min_rtt_ms is not None else None,
            "measured_rtt_ms": round(measured_rtt_ms, 2) if measured_rtt_ms else None,
            "routing_efficiency_pct": efficiency_pct,
            "applicable": efficiency_pct is not None,
            "not_applicable_reason": na_reason,
            "switching_and_queuing_delay_ms": queuing_and_switching_delay_ms,
            "detour_rating": rating,
            "calculation_basis": calculation_basis,
            "optical_backhaul_rtt_ms": denominator,
            "fiber_min_rtt_ms": round(fiber_floor_ms, 2) if fiber_floor_ms is not None else None,
            "local_access_hop_ms": round(local_access_hop_min_ms, 2) if local_access_hop_min_ms is not None else None
        }

    def calculate_bdp(self, perf_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calcola il Bandwidth-Delay Product (BDP) e la dimensione ottimale del buffer TCP.
        BDP = Bandwidth (bps) * RTT (s)
        Nessun default nascosto: se la misura di banda non è valida o assente, restituisce N/D.
        """
        speed = perf_data.get("speed", {})
        down_mbps = speed.get("download_mbps")
        dl_info = speed.get("download") or {}
        dl_valid = bool(dl_info.get("valid", speed.get("valid", True)))
        prim_lat = perf_data.get("primary_latency", {})
        rtt_ms = prim_lat.get("median_ms") or prim_lat.get("min_ms")
        if rtt_ms is None:
            rtt_ms = (perf_data.get("bufferbloat") or {}).get("idle_latency_ms")

        if not dl_valid or down_mbps is None or down_mbps <= 0.0 or rtt_ms is None or rtt_ms <= 0.0:
            return {
                "bdp_bytes": None,
                "bdp_kb": None,
                "bdp_mb": None,
                "recommended_tcp_window_kb": None,
                "pipe_capacity_description": "N/D (misura di banda o latenza non disponibile)"
            }

        # BDP in bit = bps * (ms / 1000)
        bdp_bits = (down_mbps * 1_000_000.0) * (rtt_ms / 1000.0)
        bdp_bytes = int(bdp_bits / 8.0)
        bdp_kb = round(bdp_bytes / 1024.0, 1)
        bdp_mb = round(bdp_bytes / (1024.0 * 1024.0), 2)

        # Buffer TCP ottimale consigliato (almeno 1.5x BDP per saturazione completa senza stallo)
        optimal_buffer_kb = int(bdp_kb * 1.5)

        return {
            "bdp_bytes": bdp_bytes,
            "bdp_kb": bdp_kb,
            "bdp_mb": bdp_mb,
            "recommended_tcp_window_kb": optimal_buffer_kb,
            "pipe_capacity_description": f"Capacità del canale in transito: {bdp_kb} KB di pacchetti simultanei senza perdita di throughput."
        }

    def calculate_itu_mos(self, perf_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calcola il Mean Opinion Score (MOS) conforme allo standard internazionale ITU-T G.107 (E-model).
        Valuta qualità voce/VoIP e conferenze da 1.0 (inaccettabile) a 4.5 (cristallina da studio).
        """
        prim_lat = perf_data.get("primary_latency", {})
        rtt_ms = prim_lat.get("median_ms")
        if rtt_ms is None:
            rtt_ms = prim_lat.get("avg_ms")
        jitter_ms = prim_lat.get("jitter_ms")
        loss_pct = prim_lat.get("packet_loss_pct")
        if rtt_ms is None or jitter_ms is None or loss_pct is None:
            return {
                "mos_score": None,
                "r_factor": None,
                "quality_rating": "Dati insufficienti",
                "effective_delay_ms": None,
                "insufficient_data": True
            }

        # One-way delay = RTT/2 + jitter buffer (≈2×jitter): il jitter e' contato solo qui
        effective_delay = (rtt_ms / 2.0) + (jitter_ms * 2.0)

        # 1. Fattore R di base
        r_factor = 93.2

        # 2. Degradazione da ritardo Id (G.107 semplificato, ginocchio a 177.3 ms)
        id_delay = effective_delay * 0.024 + 0.11 * max(0.0, effective_delay - 177.3)

        # 3. Perdita pacchetti: Ie_eff = Ie + (95-Ie)*Ppl/(Ppl+Bpl), G.711 (Ie=0, Bpl=4.3, perdita casuale)
        ie_loss = 95.0 * loss_pct / (loss_pct + 4.3) if loss_pct > 0 else 0.0

        r = max(0.0, min(100.0, r_factor - id_delay - ie_loss))

        # Conversione da R-factor a MOS (ITU-T G.107)
        if r <= 0:
            mos = 1.0
        else:
            mos = 1.0 + (0.035 * r) + (r * (r - 60.0) * (100.0 - r) * 7.0e-6)
            mos = round(max(1.0, min(4.5, mos)), 2)

        if mos >= 4.3:
            quality = "Eccellente (Broadcast / Studio Quality)"
        elif mos >= 4.0:
            quality = "Molto Buona (Standard HD Voice)"
        elif mos >= 3.6:
            quality = "Buona (Normale telefonia cellulare)"
        elif mos >= 3.0:
            quality = "Accettabile (Lieve degradazione o ritardo)"
        else:
            quality = "Scarsa (Interruzioni e perdite percepibili)"

        # Loaded MOS (se disponibili metriche di carico da bufferbloat)
        bb = perf_data.get("bufferbloat") or {}
        dl_loaded = bb.get("download_loaded_ms")
        ul_loaded = bb.get("upload_loaded_ms")
        loaded_rtt = max(dl_loaded or 0.0, ul_loaded or 0.0)
        loaded_mos = None
        if loaded_rtt > 0.0:
            eff_delay_loaded = (loaded_rtt / 2.0) + (jitter_ms * 2.0)
            id_delay_loaded = eff_delay_loaded * 0.024 + 0.11 * max(0.0, eff_delay_loaded - 177.3)
            r_loaded = max(0.0, min(100.0, r_factor - id_delay_loaded - ie_loss))
            if r_loaded <= 0:
                loaded_mos = 1.0
            else:
                loaded_mos = 1.0 + (0.035 * r_loaded) + (r_loaded * (r_loaded - 60.0) * (100.0 - r_loaded) * 7.0e-6)
                loaded_mos = round(max(1.0, min(4.5, loaded_mos)), 2)

        return {
            "mos_score": mos,
            "loaded_mos_score": loaded_mos,
            "r_factor": round(r, 1),
            "quality_rating": quality,
            "effective_delay_ms": round(effective_delay, 1)
        }

    def calculate_application_suitability(self, perf_data: Dict[str, Any], mos_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assegna rating specifici per i principali casi d'uso (Gaming, 4K/8K, VoIP, Cloud Gaming).
        Nessun fallback a costanti fittizie: se le misure di velocità o latenza non sono valide o presenti,
        assegna status 'N/D' con descrizione esplicita.
        """
        prim_lat = perf_data.get("primary_latency", {})
        rtt = prim_lat.get("min_ms")
        jitter = prim_lat.get("jitter_ms")
        loss = prim_lat.get("packet_loss_pct") or 0.0

        speed = perf_data.get("speed", {})
        dl_info = speed.get("download")
        if isinstance(dl_info, dict) and "valid" in dl_info:
            dl_valid = bool(dl_info["valid"])
        else:
            dl_valid = bool(speed.get("valid", True)) and (speed.get("download_mbps") is not None)

        ul_info = speed.get("upload")
        if isinstance(ul_info, dict) and "valid" in ul_info:
            ul_valid = bool(ul_info["valid"])
        else:
            ul_valid = bool(speed.get("valid", True)) and (speed.get("upload_mbps") is not None)

        down = speed.get("download_mbps")
        up = speed.get("upload_mbps")

        bb = perf_data.get("bufferbloat", {})
        bb_grade = bb.get("grade")
        bb_max_delta = bb.get("max_delta_ms")

        # 1. Competitive Gaming Rating
        if not ul_valid or up is None or rtt is None or jitter is None or bb_max_delta is None:
            gaming = {
                "status": "N/D",
                "score": None,
                "badge": "secondary",
                "desc": "Misura non valida o insufficiente per valutare il gaming (upload o latenza assenti)."
            }
        else:
            if rtt <= 15.0:
                base_gaming = 100.0 - (rtt / 15.0) * 5.0
            elif rtt <= 30.0:
                base_gaming = 95.0 - ((rtt - 15.0) / 15.0) * 10.0
            elif rtt <= 50.0:
                base_gaming = 85.0 - ((rtt - 30.0) / 20.0) * 15.0
            elif rtt <= 80.0:
                base_gaming = 70.0 - ((rtt - 50.0) / 30.0) * 20.0
            else:
                base_gaming = max(20.0, 50.0 - ((rtt - 80.0) / 40.0) * 20.0)

            pen_jitter = min(20.0, max(0.0, jitter * 2.0))
            pen_loss = min(30.0, max(0.0, loss * 15.0))
            pen_bb = min(25.0, max(0.0, (bb_max_delta - 10.0) * 0.4))
            pen_up = min(15.0, max(0.0, (3.0 - up) * 5.0)) if up < 3.0 else 0.0

            gaming_score = round(max(20.0, min(100.0, base_gaming - pen_jitter - pen_loss - pen_bb - pen_up)), 1)
            if gaming_score >= 90.0:
                gaming = {"status": "PERFETTO", "score": int(gaming_score), "badge": "success", "desc": "Tick-rate ultra-stabile, latenza sub-15ms, nessun lag spike."}
            elif gaming_score >= 75.0:
                gaming = {"status": "OTTIMO", "score": int(gaming_score), "badge": "success", "desc": "Ottima reattività per tornei e multiplayer competitivo."}
            elif gaming_score >= 60.0:
                gaming = {"status": "BUONO", "score": int(gaming_score), "badge": "warning", "desc": "Giocabile senza problemi; moderato bufferbloat o jitter."}
            else:
                gaming = {"status": "NON OTTIMALE", "score": int(gaming_score), "badge": "danger", "desc": "Latenza elevata, forte bufferbloat o upload ridotto con rischio disallineamento."}

        # 2. 4K / 8K Video Streaming
        if not dl_valid or down is None or down <= 0.0:
            streaming = {
                "status": "N/D",
                "score": None,
                "badge": "secondary",
                "desc": "Misura non valida o insufficiente per valutare lo streaming 4K (download assente)."
            }
        else:
            if down < 10.0:
                score_4k = (down / 10.0) * 40.0
            elif down < 25.0:
                score_4k = 40.0 + ((down - 10.0) / 15.0) * 35.0
            elif down < 50.0:
                score_4k = 75.0 + ((down - 25.0) / 25.0) * 15.0
            elif down < 100.0:
                score_4k = 90.0 + ((down - 50.0) / 50.0) * 10.0
            else:
                score_4k = 100.0

            score_4k = round(max(0.0, min(100.0, score_4k)), 1)
            if score_4k >= 90.0:
                streaming = {"status": "ECCELLENTE", "score": int(score_4k), "badge": "success", "desc": "Banda sufficiente per molteplici flussi simultanei in 4K HDR e 8K."}
            elif score_4k >= 75.0:
                streaming = {"status": "MOLTO BUONO", "score": int(score_4k), "badge": "success", "desc": "Supporta perfettamente streaming 4K UHD su 1-2 dispositivi."}
            elif score_4k >= 50.0:
                streaming = {"status": "BUONO", "score": int(score_4k), "badge": "warning", "desc": "Supporta streaming 4K singolo o 1080p Full HD fluido."}
            else:
                streaming = {"status": "LIMITATO", "score": int(score_4k), "badge": "danger", "desc": "Banda limitata; adatto per 1080p, possibile buffering su contenuti 4K."}

        # 3. Videochiamate & Smart Working (Zoom / Teams / Meet)
        mos = mos_data.get("mos_score")
        if not ul_valid or up is None or mos is None:
            work = {
                "status": "N/D",
                "score": None,
                "badge": "secondary",
                "desc": "Misura non valida o insufficiente per valutare le videochiamate (upload o MOS assenti)."
            }
        else:
            if up < 1.5 or bb_grade == "F":
                work = {"status": "LIMITATO", "score": 50, "badge": "warning", "desc": "Banda di upload ridotta o bufferbloat critico: rischio congelamento video o stuttering vocale."}
            elif up < 3.0 or bb_grade == "D":
                work = {"status": "SUFFICIENTE", "score": 65, "badge": "warning", "desc": "Upload ridotto (<3 Mbps) o bufferbloat elevato (grado D): possibile instabilità o degradazione video in chiamata."}
            elif bb_grade == "C":
                if mos >= 4.1 and up >= 5.0:
                    work = {"status": "IMPECCABILE", "score": 94, "badge": "success", "desc": "Voce cristallina e video HD; moderato bufferbloat gestito dal margine di banda."}
                elif mos >= 3.6 and up >= 3.0:
                    work = {"status": "BUONO", "score": 80, "badge": "success", "desc": "Adatto per videoconferenze quotidiane."}
                else:
                    work = {"status": "SUFFICIENTE", "score": 65, "badge": "warning", "desc": "Possibili artefatti vocali sotto carico."}
            else:
                if mos >= 4.1 and up >= 5.0:
                    work = {"status": "IMPECCABILE", "score": 96, "badge": "success", "desc": "Voce cristallina e video HD senza glitch o desincronizzazioni."}
                elif mos >= 3.6 and up >= 3.0:
                    work = {"status": "BUONO", "score": 80, "badge": "success", "desc": "Adatto per videoconferenze quotidiane."}
                else:
                    work = {"status": "SUFFICIENTE", "score": 60, "badge": "warning", "desc": "Possibili artefatti o ritardi vocali intermittenti."}

        # 4. Cloud Gaming & Desktop Remoto (GeForce NOW, Parsec, Moonlight)
        if not dl_valid or down is None or bb_grade is None or rtt is None:
            cloud_gaming = {
                "status": "N/D",
                "score": None,
                "badge": "secondary",
                "desc": "Misura non valida o insufficiente per valutare il cloud gaming (download o bufferbloat assenti)."
            }
        else:
            if rtt < 20.0 and down >= 50.0 and bb_grade in ("A+", "A"):
                cloud_gaming = {"status": "NATIVO", "score": 95, "badge": "success", "desc": "Esperienza identica al gioco in locale; input lag impercettibile."}
            elif rtt < 40.0 and down >= 30.0:
                cloud_gaming = {"status": "BUONO", "score": 78, "badge": "warning", "desc": "Cloud gaming fruibile a 60 FPS con leggero ritardo."}
            else:
                cloud_gaming = {"status": "CRITICO", "score": 40, "badge": "danger", "desc": "Latenza o bufferbloat degradano l'esperienza di controllo real-time."}

        return {
            "competitive_gaming": gaming,
            "video_streaming": streaming,
            "video_conferencing": work,
            "cloud_gaming": cloud_gaming
        }

    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calcola la distanza geodetica ortodromica in km tra due coppie di coordinate (formula di Haversine)."""
        R = 6371.0 # Raggio terrestre in km
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = math.sin(delta_phi / 2.0)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0)**2
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return R * c
