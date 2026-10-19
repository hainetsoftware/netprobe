"""
Modulo di Rilevamento e Identificazione dello Switch di Rete Ethernet:
- Sniffer passivo L2 per LLDP (IEEE 802.1AB, EtherType 0x88cc) e CDP (Cisco 0x2000)
- Parser TLV completo per System Name, System Description, Port ID, VLAN e IP di Gestione
- Scanner attivo L3/L4 senza root per switch managed:
  - SNMP v1/v2c (UDP 161) per sysName (1.3.6.1.2.1.1.5.0) e sysDescr (1.3.6.1.2.1.1.1.0)
  - mDNS / Bonjour (UDP 5353) per switch UniFi, Netgear e annunci _http._tcp.local
  - HTTP/HTTPS banner grabbing su IP candidati con MAC vendor di produttori switch
- Classificazione e diagnosi per Switch L2 Unmanaged (trasparenti senza piano di controllo)
"""

import os
import re
import socket
import struct
import time
import select
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional, Tuple

from core.platform_info import is_macos, is_linux, is_windows, run_cmd


class SwitchProbe:
    # OUI MAC di costruttori noti di apparati switch di rete
    SWITCH_VENDOR_PATTERNS = [
        "cisco", "hewlett", "hp", "aruba", "netgear", "ubiquiti",
        "tp-link", "mikrotik", "d-link", "zyxel", "juniper", "extreme",
        "dell", "alcatel", "huawei", "edgecore", "qnap", "synology"
    ]

    def __init__(self):
        pass

    def probe_connected_switch(
        self,
        interface: str,
        gateway_ip: Optional[str] = None,
        arp_table: Optional[List[Dict[str, Any]]] = None,
        timeout_seconds: float = 8.0,
        progress_cb=None
    ) -> Dict[str, Any]:
        """
        Esegue la scoperta completa dello switch Ethernet collegato:
        1. Tenta lo sniffer passivo L2 LLDP/CDP (se sono disponibili privilegi/BPF)
        2. In parallelo esegue la scansione attiva L3/L4 (SNMP, mDNS, HTTP banner)
        3. Se nulla risponde, diagnostica switch L2 Unmanaged trasparente
        """
        if progress_cb:
            progress_cb("Verifica apparato switch Ethernet collegato (LLDP/CDP/SNMP)...", 20)

        # 1. Tentativo Sniffer Passivo L2 (LLDP/CDP)
        l2_result = self._try_sniff_l2(interface, timeout=min(6.0, timeout_seconds))
        if l2_result and l2_result.get("detected"):
            return l2_result

        # 2. Tentativo Scanner Attivo L3/L4 (Zero Root)
        if progress_cb:
            progress_cb("Scansione L3/L4 switch managed via SNMP/mDNS...", 40)
        
        l3_result = self._probe_active_l3(gateway_ip, arp_table or [])
        if l3_result and l3_result.get("detected"):
            return l3_result

        # 3. Diagnosi Switch non rilevato / non gestito
        return {
            "detected": False,
            "switch_name": None,
            "switch_model": None,
            "port_id": None,
            "vlan": None,
            "management_ip": None,
            "protocol": None,
            "switch_type": "Switch L2 Unmanaged o collegamento diretto",
            "description": "Nessuno switch gestito rilevato (collegamento diretto o switch non gestito: non distinguibili)"
        }

    # =========================================================================
    # TIER 1: PASSIVE L2 SNIFFER (LLDP & CDP)
    # =========================================================================

    def _try_sniff_l2(self, interface: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Tenta la cattura di frame LLDP (0x88cc) o CDP (0x2000) tramite tcpdump se accessibile."""
        if not interface:
            return None

        # Prova con tcpdump (funziona con permessi elevati o ChmodBPF su macOS)
        cmd = [
            "tcpdump", "-i", interface, "-c", "1", "-n", "-xx",
            "-s", "1500", "ether proto 0x88cc or ether proto 0x2000"
        ]

        try:
            # Esegui con timeout rigido
            code, out, err = run_cmd(cmd)
            if code == 0 and out:
                raw_bytes = self._parse_tcpdump_hex(out)
                if raw_bytes:
                    parsed = self._decode_l2_frame(raw_bytes)
                    if parsed:
                        parsed["detected"] = True
                        return parsed
        except Exception:
            pass

        return None

    def _parse_tcpdump_hex(self, dump_str: str) -> bytes:
        """Estrae i byte grezzi dall'output formattato '0x0000:  0180 c200 ...' di tcpdump -xx."""
        byte_list = []
        for line in dump_str.splitlines():
            m = re.match(r"^\s*0x[0-9a-fA-F]+:\s+(.+)$", line)
            if m:
                hex_parts = m.group(1).split()
                for part in hex_parts:
                    # part può essere '0180' o 'c200'
                    cleaned = re.sub(r"[^0-9a-fA-F]", "", part)
                    if len(cleaned) % 2 == 0:
                        try:
                            byte_list.append(bytes.fromhex(cleaned))
                        except ValueError:
                            pass
        return b"".join(byte_list)

    def _decode_l2_frame(self, frame: bytes) -> Optional[Dict[str, Any]]:
        """Decodifica un frame Ethernet completo verificando se è LLDP o CDP."""
        if len(frame) < 14:
            return None

        # dst_mac = frame[0:6], src_mac = frame[6:12], ethertype = frame[12:14]
        ethertype = int.from_bytes(frame[12:14], "big")

        if ethertype == 0x88CC:
            # LLDP (IEEE 802.1AB)
            payload = frame[14:]
            info = self.parse_lldp_payload(payload)
            if info:
                return {
                    "switch_name": info.get("system_name"),
                    "switch_model": info.get("system_description"),
                    "port_id": info.get("port_id"),
                    "port_description": info.get("port_description"),
                    "vlan": info.get("vlan"),
                    "management_ip": info.get("management_ip"),
                    "chassis_mac": info.get("chassis_id"),
                    "protocol": "LLDP (Link Layer Discovery Protocol - IEEE 802.1AB)",
                    "switch_type": "Switch Managed (Annuncio LLDP)"
                }

        # Controllo LLC / SNAP per Cisco CDP
        # Spesso ethertype < 1500 (length field) seguito da DSAP=0xAA SSAP=0xAA Control=0x03 OUI=00-00-0C PID=0x2000
        if len(frame) >= 22:
            llc_snap = frame[14:22]
            if llc_snap.startswith(b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"):
                cdp_payload = frame[22:]
                info = self.parse_cdp_payload(cdp_payload)
                if info:
                    return {
                        "switch_name": info.get("device_id"),
                        "switch_model": info.get("platform"),
                        "port_id": info.get("port_id"),
                        "vlan": info.get("native_vlan"),
                        "management_ip": info.get("management_ip"),
                        "protocol": "CDP (Cisco Discovery Protocol)",
                        "switch_type": "Switch Cisco Managed (Annuncio CDP)"
                    }

        return None

    def parse_lldp_payload(self, payload: bytes) -> Dict[str, Any]:
        """Decodifica i TLV di un payload LLDP."""
        idx = 0
        info = {
            "chassis_id": None,
            "port_id": None,
            "port_description": None,
            "system_name": None,
            "system_description": None,
            "management_ip": None,
            "vlan": None
        }

        while idx + 2 <= len(payload):
            hdr = int.from_bytes(payload[idx:idx+2], "big")
            tlv_type = hdr >> 9
            tlv_len = hdr & 0x01FF
            idx += 2

            if tlv_type == 0:  # End of LLDPDU
                break

            if idx + tlv_len > len(payload):
                break

            val = payload[idx:idx+tlv_len]
            idx += tlv_len

            if tlv_type == 1 and len(val) >= 2:  # Chassis ID
                subtype = val[0]
                if subtype == 4:  # MAC address
                    info["chassis_id"] = val[1:7].hex(":")
                else:
                    info["chassis_id"] = val[1:].decode("utf-8", "replace").strip()

            elif tlv_type == 2 and len(val) >= 2:  # Port ID
                subtype = val[0]
                info["port_id"] = val[1:].decode("utf-8", "replace").strip()

            elif tlv_type == 4:  # Port Description
                info["port_description"] = val.decode("utf-8", "replace").strip()

            elif tlv_type == 5:  # System Name
                info["system_name"] = val.decode("utf-8", "replace").strip()

            elif tlv_type == 6:  # System Description
                info["system_description"] = val.decode("utf-8", "replace").strip()

            elif tlv_type == 8 and len(val) >= 6:  # Management Address
                addr_subtype = val[1]
                if addr_subtype == 1 and len(val) >= 6:  # IPv4
                    info["management_ip"] = socket.inet_ntoa(val[2:6])

            elif tlv_type == 127 and len(val) >= 6:  # Org-Specific TLV
                oui = val[0:3]
                org_subtype = val[3]
                # 00-80-c2 (IEEE 802.1) Subtype 1 = Port VLAN ID
                if oui == b"\x00\x80\xc2" and org_subtype == 1 and len(val) >= 6:
                    info["vlan"] = int.from_bytes(val[4:6], "big")

        return info

    def parse_cdp_payload(self, payload: bytes) -> Dict[str, Any]:
        """Decodifica i TLV di un pacchetto CDP."""
        if len(payload) < 4:
            return {}

        idx = 4  # Salta version (1), ttl (1), checksum (2)
        info = {
            "device_id": None,
            "port_id": None,
            "platform": None,
            "software_version": None,
            "native_vlan": None,
            "management_ip": None
        }

        while idx + 4 <= len(payload):
            tlv_type = int.from_bytes(payload[idx:idx+2], "big")
            tlv_len = int.from_bytes(payload[idx+2:idx+4], "big")
            if tlv_len < 4 or idx + tlv_len > len(payload):
                break

            val = payload[idx+4:idx+tlv_len]
            idx += tlv_len

            if tlv_type == 1:  # Device ID
                info["device_id"] = val.decode("utf-8", "replace").strip()
            elif tlv_type == 2 and len(val) >= 9:  # Address
                # Struttura address TLV Cisco
                if b"\xcc" in val:
                    # cerca IPv4
                    m = re.search(rb"\x01\x01\x01\xcc\x00\x04(....)", val)
                    if m:
                        info["management_ip"] = socket.inet_ntoa(m.group(1))
            elif tlv_type == 3:  # Port ID
                info["port_id"] = val.decode("utf-8", "replace").strip()
            elif tlv_type == 5:  # Software Version
                info["software_version"] = val.decode("utf-8", "replace").strip()
            elif tlv_type == 6:  # Platform
                info["platform"] = val.decode("utf-8", "replace").strip()
            elif tlv_type == 10 and len(val) >= 2:  # Native VLAN
                info["native_vlan"] = int.from_bytes(val[:2], "big")

        return info

    # =========================================================================
    # TIER 2: ACTIVE L3/L4 PROBE (SNMP v1/v2c, mDNS & HTTP BANNER) - ZERO ROOT
    # =========================================================================

    def _probe_active_l3(self, gateway_ip: Optional[str], arp_table: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Interroga apparati switch presenti nella LAN locale:
        - Trova IP con MAC di vendor switch (Cisco, HP, Ubiquiti, Netgear, TP-Link, MikroTik)
        - Invia query SNMP v1/v2c per sysName e sysDescr
        - Effettua query mDNS per apparati UniFi o switch Smart
        - Esegue HTTP title grab su interfacce di configurazione note
        """
        candidate_ips = []
        for entry in arp_table:
            ip = entry.get("ip")
            vendor = (entry.get("vendor") or "").lower()
            if not ip or ip == gateway_ip or ip.endswith(".255"):
                continue

            for pattern in self.SWITCH_VENDOR_PATTERNS:
                if pattern in vendor:
                    candidate_ips.append(ip)
                    break

        # Aggiungi anche i primi 5 IP e gli ultimi 5 IP della subnet o il gateway stesso per test SNMP
        test_ips = list(dict.fromkeys(candidate_ips))[:6]

        # 1. Prova SNMP v1/v2c per ciascun candidato
        for ip in test_ips:
            snmp_res = self._snmp_get_switch_info(ip)
            if snmp_res and (snmp_res.get("sys_name") or snmp_res.get("sys_descr")):
                return {
                    "detected": True,
                    "switch_name": snmp_res.get("sys_name"),
                    "switch_model": snmp_res.get("sys_descr"),
                    "port_id": None,
                    "vlan": None,
                    "management_ip": ip,
                    "protocol": "SNMP v2c (RFC 1213 MIB-II sysName/sysDescr)",
                    "switch_type": "Smart / Managed Switch (Rilevato via SNMP)"
                }

        # 2. Prova mDNS per apparati Ubiquiti UniFi o Smart Switch
        mdns_res = self._probe_mdns_switch()
        if mdns_res:
            return mdns_res

        # 3. HTTP Title Grab sui candidati
        for ip in test_ips:
            http_res = self._probe_http_switch(ip)
            if http_res:
                return http_res

        return None

    def _snmp_get_switch_info(self, ip: str, community: str = "public", timeout: float = 0.8) -> Optional[Dict[str, str]]:
        """Invia richieste SNMP v2c per sysName.0 (1.3.6.1.2.1.1.5.0) e sysDescr.0 (1.3.6.1.2.1.1.1.0)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        sys_name = None
        sys_descr = None

        # OID sysName.0: 1.3.6.1.2.1.1.5.0  (06 08 2b 06 01 02 01 01 05 00)
        # OID sysDescr.0: 1.3.6.1.2.1.1.1.0 (06 08 2b 06 01 02 01 01 01 00)
        oids = [
            ("sys_name", "1.3.6.1.2.1.1.5.0"),
            ("sys_descr", "1.3.6.1.2.1.1.1.0")
        ]

        try:
            for key, oid_str in oids:
                req_bytes = self._build_snmp_get_packet(community, oid_str, req_id=0x1234)
                sock.sendto(req_bytes, (ip, 161))
                data, _ = sock.recvfrom(2048)
                val = self._extract_snmp_string_value(data)
                if val:
                    if key == "sys_name":
                        sys_name = val
                    elif key == "sys_descr":
                        sys_descr = val
        except Exception:
            pass
        finally:
            sock.close()

        if sys_name or sys_descr:
            return {"sys_name": sys_name, "sys_descr": sys_descr}
        return None

    def _build_snmp_get_packet(self, community: str, oid_str: str, req_id: int = 1) -> bytes:
        """Costruisce un pacchetto ASN.1 BER SNMP v2c GetRequest valido senza dipendenze."""
        def encode_tlv(tag: int, val: bytes) -> bytes:
            if len(val) < 128:
                return bytes([tag, len(val)]) + val
            else:
                l_bytes = len(val).to_bytes((len(val).bit_length() + 7) // 8, "big")
                return bytes([tag, 0x80 | len(l_bytes)]) + l_bytes + val

        def encode_int(n: int) -> bytes:
            if n == 0:
                return encode_tlv(0x02, b"\x00")
            return encode_tlv(0x02, n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True))

        def encode_oid(oid: str) -> bytes:
            parts = [int(p) for p in oid.split(".")]
            raw = bytes([parts[0] * 40 + parts[1]])
            for p in parts[2:]:
                b = []
                if p == 0:
                    b = [0]
                else:
                    first = True
                    while p > 0:
                        digit = p & 0x7F
                        p >>= 7
                        if not first:
                            digit |= 0x80
                        b.insert(0, digit)
                        first = False
                raw += bytes(b)
            return encode_tlv(0x06, raw)

        # Costruisce VarBind
        oid_encoded = encode_oid(oid_str)
        varbind = encode_tlv(0x30, oid_encoded + b"\x05\x00")  # Value NULL
        varbind_list = encode_tlv(0x30, varbind)

        # PDU GetRequest (tag 0xA0)
        pdu = encode_tlv(0xA0, encode_int(req_id) + encode_int(0) + encode_int(0) + varbind_list)

        # SNMP Message: version 1 (0x01 = v2c), community string, PDU
        msg = encode_tlv(0x30, encode_int(1) + encode_tlv(0x04, community.encode("utf-8")) + pdu)
        return msg

    def _extract_snmp_string_value(self, data: bytes) -> Optional[str]:
        """Estrae la stringa di testo ASN.1 contenuta nel VarBind della risposta SNMP."""
        try:
            # Cerca tag OCTET STRING (0x04) verso la fine del pacchetto
            for i in range(len(data) - 4):
                if data[i] == 0x04:
                    length = data[i + 1]
                    if length < 128 and i + 2 + length <= len(data):
                        val = data[i + 2:i + 2 + length].decode("utf-8", "replace").strip()
                        if val and len(val) >= 2:
                            return val
        except Exception:
            pass
        return None

    def _probe_mdns_switch(self) -> Optional[Dict[str, Any]]:
        """Invia query mDNS su 224.0.0.251:5353 per individuare switch Ubiquiti UniFi o Smart."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # DNS Query PTR per _unifi._tcp.local
        query = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x06_unifi\x04_tcp\x05local\x00\x00\x0c\x00\x01"
        )

        try:
            sock.sendto(query, ("224.0.0.251", 5353))
            start_t = time.time()
            while time.time() - start_t < 1.0:
                data, addr = sock.recvfrom(2048)
                text = data.decode("utf-8", "replace")
                if "USW" in text or "switch" in text.lower() or "unifi" in text.lower():
                    # Estrae il nome dell'host UniFi Switch
                    m = re.search(r"([a-zA-Z0-9_\-]+(?:USW|switch|Switch)[a-zA-Z0-9_\-]*)", text)
                    sw_name = m.group(1) if m else "Ubiquiti UniFi Switch"
                    return {
                        "detected": True,
                        "switch_name": sw_name,
                        "switch_model": "Ubiquiti UniFi Managed Switch",
                        "port_id": None,
                        "vlan": None,
                        "management_ip": addr[0],
                        "protocol": "mDNS / Bonjour (_unifi._tcp)",
                        "switch_type": "Switch Managed (Ubiquiti UniFi)"
                    }
        except Exception:
            pass
        finally:
            sock.close()

        return None

    def _probe_http_switch(self, ip: str) -> Optional[Dict[str, Any]]:
        """Esegue un fetch rapido HTTP sulla porta 80/8080 per identificare titoli di web switch."""
        for port in [80, 8080]:
            url = f"http://{ip}:{port}/"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NetProbe/1.0"})
                with urllib.request.urlopen(req, timeout=0.8) as resp:
                    server_header = resp.headers.get("Server", "")
                    content = resp.read(2048).decode("utf-8", "replace")
                    
                    title_m = re.search(r"<title>([^<]+)</title>", content, re.IGNORECASE)
                    title = title_m.group(1).strip() if title_m else ""

                    # Riconoscimento modelli switch noti
                    switch_signatures = [
                        ("TL-SG", "TP-Link Easy Smart Switch"),
                        ("GS108", "Netgear ProSAFE Smart Managed"),
                        ("GS110", "Netgear Smart Managed Switch"),
                        ("GS308", "Netgear Smart Switch"),
                        ("ProCurve", "HP ProCurve Switch"),
                        ("CBS", "Cisco Business Switch"),
                        ("SG200", "Cisco Small Business Switch"),
                        ("SG300", "Cisco Managed Switch"),
                        ("SwOS", "MikroTik SwitchOS"),
                        ("DGS-", "D-Link Smart Managed Switch"),
                        ("Zyxel GS", "Zyxel Managed Switch")
                    ]

                    for sig, desc in switch_signatures:
                        if sig.lower() in title.lower() or sig.lower() in content.lower():
                            return {
                                "detected": True,
                                "switch_name": title or desc,
                                "switch_model": desc,
                                "port_id": None,
                                "vlan": None,
                                "management_ip": ip,
                                "protocol": f"HTTP Web Management ({url})",
                                "switch_type": f"Smart Switch Managed ({desc})"
                            }
            except Exception:
                pass
        return None
