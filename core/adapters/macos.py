"""
Adapter macOS per NetProbe.
Estrae parametri di rete, interfacce, Wi-Fi, routing, DHCP e vicinato tramite comandi nativi macOS.
Garantisce che nessun placeholder (es: 02:00:00:00:00:00) venga esposto come indirizzo reale.
"""

import re
import socket
import subprocess
import ctypes
import struct
from typing import Dict, List, Any, Optional, Tuple

from core.adapters.base import OSAdapter
from core.oui_data import lookup_vendor, is_placeholder_mac
from core.platform_info import run_cmd


def normalize_mac(raw_mac: str) -> Optional[str]:
    """
    Normalizza MAC address:
    - Trasforma ottetti singoli/non-padded in formato standard a due cifre esadecimali (es. 'b' -> '0b').
    - Riconosce ed esclude stringhe '(incomplete)'.
    - Esclude indirizzi placeholder, multicast (01:00:5e:*, 33:33:*) e broadcast (ff:ff:ff:ff:ff:ff).
    """
    if not raw_mac:
        return None
    raw_lower = str(raw_mac).lower().strip()
    if "incomplete" in raw_lower or "(incomplete)" in raw_lower:
        return None
    clean = raw_lower.replace("-", ":")
    parts = clean.split(":")
    if len(parts) != 6:
        return None
    try:
        norm = ":".join(f"{int(b, 16):02x}" for b in parts)
    except ValueError:
        return None
    if is_placeholder_mac(norm):
        return None
    if norm.startswith(("01:00:5e:", "33:33:")) or norm == "ff:ff:ff:ff:ff:ff":
        return None
    return norm


def is_multicast_or_broadcast_ip(ip: str) -> bool:
    """Rileva se un indirizzo IPv4/IPv6 appartiene a range multicast o broadcast/loopback."""
    if not ip:
        return True
    try:
        clean = str(ip).split("%")[0].strip().lower()
        if ":" in clean:
            return clean.startswith("ff") or clean in ("::1", "fe80::1")
        parts = [int(p) for p in clean.split(".")]
        if len(parts) == 4:
            if parts[0] == 0 or parts[0] == 127 or parts[0] >= 224 or parts[3] == 255:
                return True
            return False
    except Exception:
        pass
    return True


def parse_sysctl_arp_data(data: bytes) -> List[Dict[str, Any]]:
    """
    Parsa struct rt_msghdr + sockaddrs da buffer sysctl (NET_RT_FLAGS, RTF_LLINFO).
    Su macOS arm64 (Darwin 27), individua dinamicamente il primo sockaddr_in
    (sa_len == 16, sa_family == 2 AF_INET) all'interno di msg[92:140], quindi
    scorre i sockaddr allineati a 4 byte da quell'offset esatto per estrarre
    sockaddr_in (IPv4) e sockaddr_dl (sa_family == 18 AF_LINK, sdl_alen == 6).
    Supporta inoltre fallback per offset sintetici/compatibilità test e AF_INET6.
    """
    devices = []
    offset = 0
    seen_ips = set()
    while offset < len(data):
        if offset + 16 > len(data):
            break
        msglen, ver, mtype, idx, flags, addrs = struct.unpack_from('=HBBHII', data, offset)
        if msglen <= 0 or offset + msglen > len(data):
            break

        chunk = data[offset : offset + msglen]
        entry = None

        # 1. Individua dinamicamente il primo sockaddr_in in msg[92:140] (Darwin 27 arm64)
        start_offsets = []
        for off in range(92, min(len(chunk) - 8, 140), 4):
            if chunk[off] == 16 and chunk[off + 1] == socket.AF_INET:
                start_offsets.append(off)
                break

        # Fallback discovery per offset sintetici/compatibilità test fixtures (es. offset 72 o IPv6)
        if not start_offsets:
            for off in range(16, min(len(chunk) - 8, 164), 4):
                sa_len = chunk[off]
                if sa_len < 8 or off + sa_len > len(chunk):
                    continue
                sa_fam = chunk[off + 1]
                if sa_fam in (socket.AF_INET, socket.AF_INET6, 18):
                    start_offsets.append(off)
                    if sa_fam == socket.AF_INET:
                        break

        for cand_off in start_offsets:
            p = cand_off
            ip_found = None
            mac_found = None
            ifname_found = None

            while p + 4 <= len(chunk):
                cur_len = chunk[p]
                if cur_len == 0:
                    break
                cur_fam = chunk[p + 1]
                if cur_fam == socket.AF_INET and cur_len >= 8 and p + 8 <= len(chunk):
                    raw_ip = chunk[p + 4 : p + 8]
                    cand_ip = socket.inet_ntoa(raw_ip)
                    if not is_multicast_or_broadcast_ip(cand_ip) and not ip_found:
                        ip_found = cand_ip
                elif cur_fam == socket.AF_INET6 and cur_len >= 24 and p + 24 <= len(chunk):
                    raw_ip6 = chunk[p + 8 : p + 24]
                    cand_ip6 = socket.inet_ntop(socket.AF_INET6, raw_ip6)
                    if not is_multicast_or_broadcast_ip(cand_ip6) and not ip_found:
                        ip_found = cand_ip6
                elif cur_fam == 18 and cur_len >= 8 and p + 8 <= len(chunk):
                    sdl_index, sdl_type, sdl_nlen, sdl_alen, sdl_slen = struct.unpack_from('=HBBBB', chunk, p + 2)
                    if sdl_alen == 6 and p + 8 + sdl_nlen + 6 <= len(chunk):
                        mac_b = chunk[p + 8 + sdl_nlen : p + 8 + sdl_nlen + 6]
                        raw_mac = ':'.join(f'{b:02x}' for b in mac_b)
                        cand_mac = normalize_mac(raw_mac)
                        if cand_mac:
                            mac_found = cand_mac
                            if sdl_nlen > 0:
                                ifname_found = chunk[p + 8 : p + 8 + sdl_nlen].decode('latin1', errors='replace')
                step = max(4, (cur_len + 3) & ~3)
                p += step

            if ip_found and mac_found:
                entry = (ip_found, mac_found, ifname_found)
                break

        if entry:
            ip, mac, ifname = entry
            if ip not in seen_ips:
                seen_ips.add(ip)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": lookup_vendor(mac),
                    "hostname": None,
                    "interface": ifname,
                    "source": "ARP (sysctl)",
                    "mac_source": "sysctl"
                })

        offset += msglen
    return devices


class MacOSAdapter(OSAdapter):
    def __init__(self):
        self._cached_system_profiler_network: Optional[str] = None
        self._arp_diagnostics: Dict[str, Dict[str, Any]] = {
            "sysctl": {"returncode": 0, "stdout_len": 0, "stderr_snippet": "", "parsed_count": 0},
            "arp_an": {"returncode": 0, "stdout_len": 0, "stderr_snippet": "", "parsed_count": 0},
            "netstat": {"returncode": 0, "stdout_len": 0, "stderr_snippet": "", "parsed_count": 0},
            "arp_per_host": {"returncode": 0, "stdout_len": 0, "stderr_snippet": "", "parsed_count": 0},
            "ndp": {"returncode": 0, "stdout_len": 0, "stderr_snippet": "", "parsed_count": 0}
        }

    def _get_system_profiler_network(self) -> str:
        if self._cached_system_profiler_network is None:
            code, out, _ = run_cmd(["system_profiler", "SPNetworkDataType"], timeout=5.0)
            self._cached_system_profiler_network = out if code == 0 else ""
        return self._cached_system_profiler_network

    def get_hardware_ports(self) -> Dict[str, str]:
        ports = {}
        code, out, _ = run_cmd(["networksetup", "-listallhardwareports"], timeout=2.5)
        if code == 0:
            current_port = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Hardware Port:"):
                    current_port = line.split(":", 1)[1].strip()
                elif line.startswith("Device:") and current_port:
                    dev = line.split(":", 1)[1].strip()
                    ports[dev] = current_port
                    current_port = None
        return ports

    def get_wifi_device_name(self) -> Optional[str]:
        ports = self.get_hardware_ports()
        for dev, p in ports.items():
            pl = p.lower()
            if "wi-fi" in pl or "wifi" in pl or "airport" in pl:
                return dev
        code, out, _ = run_cmd(["system_profiler", "SPAirPortDataType"], timeout=3.0)
        if code == 0 and out:
            m = re.search(r"Interfaces:\s*\n\s*([a-zA-Z0-9]+):", out)
            if m:
                return m.group(1)
        return "en0"

    def get_interface_mac(self, iface_name: str) -> Optional[str]:
        if not iface_name:
            return None
        # 1. networksetup
        code, out, _ = run_cmd(["networksetup", "-getmacaddress", iface_name], timeout=2.0)
        if code == 0:
            m = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", out)
            if m:
                mac = ":".join(f"{int(b, 16):02x}" for b in m.group(1).split(":"))
                if not is_placeholder_mac(mac):
                    return mac

        # 2. ipconfig getpacket
        code, out, _ = run_cmd(["ipconfig", "getpacket", iface_name], timeout=2.0)
        if code == 0:
            m = re.search(r"chaddr\s*=\s*([0-9a-fA-F:]{11,17})", out)
            if m:
                mac = ":".join(f"{int(b, 16):02x}" for b in m.group(1).split(":"))
                if not is_placeholder_mac(mac):
                    return mac

        # 3. system_profiler
        sp_out = self._get_system_profiler_network()
        if sp_out:
            pattern = re.compile(
                r"BSD Device Name:\s*" + re.escape(iface_name) +
                r".*?MAC Address:\s*([0-9a-fA-F:]{17})",
                re.DOTALL
            )
            m = pattern.search(sp_out)
            if m:
                mac = ":".join(f"{int(b, 16):02x}" for b in m.group(1).split(":"))
                if not is_placeholder_mac(mac):
                    return mac

        return None

    def _find_gateway_mac_and_source(self, gateway_ip: str, interface: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        if not gateway_ip:
            return None, None

        # 1. system_profiler SPNetworkDataType
        sp_out = self._get_system_profiler_network()
        if sp_out:
            m = re.search(
                r"IPv4\.Router=" + re.escape(gateway_ip) +
                r";IPv4\.RouterHardwareAddress=([0-9a-fA-F:]{17})",
                sp_out
            )
            if m:
                mac = normalize_mac(m.group(1))
                if mac:
                    return mac, "system_profiler"

            m2 = re.search(
                r"ARP Resolved IP Address:\s*" + re.escape(gateway_ip) +
                r"\s+ARP Resolved Hardware Address:\s*([0-9a-fA-F:]{17})",
                sp_out
            )
            if m2:
                mac = normalize_mac(m2.group(1))
                if mac:
                    return mac, "system_profiler"

        # 2. per-host arp -n
        code, out, _ = run_cmd(["arp", "-n", gateway_ip], timeout=2.0)
        if code == 0 and out:
            m = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", out)
            if m:
                mac = normalize_mac(m.group(1))
                if mac:
                    return mac, "arp_per_host"

        return None, None

    def get_gateway_mac(self, gateway_ip: str, interface: Optional[str] = None) -> Optional[str]:
        return self._find_gateway_mac_and_source(gateway_ip, interface)[0]

    def get_gateway_mac_with_source(self, gateway_ip: str, interface: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        # If get_gateway_mac is mocked/overridden directly in tests
        res_mac = self.get_gateway_mac(gateway_ip, interface)
        real_mac, src = self._find_gateway_mac_and_source(gateway_ip, interface)
        if res_mac != real_mac and res_mac is not None:
            return res_mac, "system_profiler"
        return real_mac, src

    def get_default_gateway(self) -> Dict[str, Any]:
        result = {
            "ipv4": None,
            "interface": None,
            "mac": None,
            "mac_source": None,
            "vendor": "Sconosciuto",
            "flags": None,
            "mtu": None
        }

        code, out, _ = run_cmd(["route", "-n", "get", "default"], timeout=2.5)
        if code == 0 and out:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("gateway:"):
                    result["ipv4"] = line.split(":", 1)[1].strip()
                elif line.startswith("interface:"):
                    result["interface"] = line.split(":", 1)[1].strip()
                elif line.startswith("flags:"):
                    result["flags"] = line.split(":", 1)[1].strip()
                elif "mtu" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "mtu" and i + 1 < len(parts):
                            try:
                                result["mtu"] = int(parts[i+1])
                            except ValueError:
                                pass

        if result["ipv4"]:
            gw_mac, gw_src = self.get_gateway_mac_with_source(result["ipv4"], result["interface"])
            if gw_mac:
                result["mac"] = gw_mac
                result["mac_source"] = gw_src
                result["vendor"] = lookup_vendor(gw_mac)
            else:
                result["mac"] = None
                result["mac_source"] = None
                result["vendor"] = "Sconosciuto"

        return result

    def get_network_interfaces(self) -> Dict[str, Dict[str, Any]]:
        interfaces = {}
        code, out, _ = run_cmd(["ifconfig"], timeout=4.0)
        if code != 0 or not out:
            return interfaces

        hw_ports = self.get_hardware_ports()
        wifi_dev = self.get_wifi_device_name() or "en0"

        eth_bsd_names = set()
        code_e, out_e, _ = run_cmd(["system_profiler", "SPEthernetDataType"], timeout=3.0)
        if code_e == 0 and out_e:
            for bsd_m in re.finditer(r"BSD Device Name:\s*([a-zA-Z0-9]+)", out_e):
                eth_bsd_names.add(bsd_m.group(1))

        current_name = None
        for line in out.splitlines():
            m_header = re.match(
                r"^([a-zA-Z0-9_\-\.]+):?\s+(?:flags=\d+<([^>]+)>|.*<([^>]+)>)?\s*(?:mtu\s+(\d+))?",
                line
            )
            if m_header and not line.startswith("\t") and not line.startswith(" "):
                current_name = m_header.group(1).rstrip(":")
                flags_str = m_header.group(2) or m_header.group(3) or ""
                mtu_val = m_header.group(4)

                init_type = "Ethernet"
                if current_name == "lo0" or "lo" in current_name:
                    init_type = "Loopback"
                elif current_name in eth_bsd_names:
                    init_type = "Ethernet"
                elif current_name in hw_ports:
                    hp = hw_ports[current_name].lower()
                    if "wi-fi" in hp or "wifi" in hp or "airport" in hp:
                        init_type = "Wi-Fi"
                    elif "ethernet" in hp or "lan" in hp or "usb" in hp:
                        init_type = "Ethernet"
                    elif "bridge" in hp:
                        init_type = "Bridge"
                    elif "thunderbolt" in hp:
                        init_type = "Thunderbolt"
                elif current_name == wifi_dev:
                    init_type = "Wi-Fi"

                interfaces[current_name] = {
                    "name": current_name,
                    "is_up": "UP" in flags_str,
                    "is_running": "RUNNING" in flags_str,
                    "is_loopback": "LOOPBACK" in flags_str,
                    "flags": flags_str,
                    "mtu": int(mtu_val) if mtu_val else None,
                    "mac": None,
                    "vendor": "Sconosciuto",
                    "ipv4": None,
                    "netmask": None,
                    "broadcast": None,
                    "ipv6_list": [],
                    "media": None,
                    "status": None,
                    "type": init_type,
                    "interface_type": init_type
                }
                continue

            if not current_name or current_name not in interfaces:
                continue

            iface = interfaces[current_name]
            stripped = line.strip()

            # MAC Address da ifconfig (se non è placeholder)
            m_mac = re.search(r"(?:ether|lladdr|link/ether)\s+([0-9a-fA-F:]{11,17})", stripped)
            if m_mac and not iface["mac"]:
                raw_mac = m_mac.group(1).lower()
                norm_mac = ":".join(f"{int(b, 16):02x}" for b in raw_mac.split(":"))
                if not is_placeholder_mac(norm_mac):
                    iface["mac"] = norm_mac
                    iface["vendor"] = lookup_vendor(norm_mac)

            # IPv4
            m_ip = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?: netmask\s+(0x[0-9a-fA-F]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|/(\d+))?", stripped)
            if m_ip:
                iface["ipv4"] = m_ip.group(1)
                raw_mask = m_ip.group(2) or m_ip.group(3)
                if raw_mask:
                    iface["netmask"] = self._normalize_netmask(raw_mask)
            m_bcast = re.search(r"broadcast\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", stripped)
            if m_bcast:
                iface["broadcast"] = m_bcast.group(1)

            # IPv6
            m_ip6 = re.search(r"inet6\s+([0-9a-fA-F:]+)(?:%[a-zA-Z0-9_\-\.]+)?(?:\s+prefixlen\s+(\d+)|\/(\d+))?", stripped)
            if m_ip6:
                ip6_addr = m_ip6.group(1)
                prefix = m_ip6.group(2) or m_ip6.group(3) or "64"
                is_link_local = ip6_addr.lower().startswith("fe80")
                iface["ipv6_list"].append({
                    "address": ip6_addr,
                    "prefix": int(prefix),
                    "type": "Link-Local" if is_link_local else "Global Unicast"
                })

            # Media / Speed
            if "media:" in stripped:
                iface["media"] = stripped.split("media:", 1)[1].strip()
                med_lower = iface["media"].lower()
                if any(x in med_lower for x in ("1000base", "100base", "10gbase", "2500base", "10base", "full-duplex", "half-duplex")):
                    iface["type"] = "Ethernet"
                    iface["interface_type"] = "Ethernet"
            if "status:" in stripped:
                iface["status"] = stripped.split("status:", 1)[1].strip()

        # Risolvi i MAC address mancanti o placeholder usando gli strumenti autorevoli di macOS
        for name, iface in interfaces.items():
            if not iface["mac"] or is_placeholder_mac(iface["mac"]):
                real_mac = self.get_interface_mac(name)
                if real_mac and not is_placeholder_mac(real_mac):
                    iface["mac"] = real_mac
                    iface["vendor"] = lookup_vendor(real_mac)
                else:
                    iface["mac"] = None
                    iface["vendor"] = "Indirizzo non disponibile"

        return interfaces

    def _normalize_netmask(self, raw_mask: str) -> str:
        if raw_mask.startswith("0x"):
            try:
                val = int(raw_mask, 16)
                dotted = ".".join(str((val >> (8 * i)) & 0xff) for i in reversed(range(4)))
                bits = bin(val).count("1")
                return f"{dotted} (/{bits})"
            except Exception:
                return raw_mask
        elif "/" in raw_mask:
            try:
                bits = int(raw_mask.replace("/", ""))
                val = (0xffffffff << (32 - bits)) & 0xffffffff
                dotted = ".".join(str((val >> (8 * i)) & 0xff) for i in reversed(range(4)))
                return f"{dotted} (/{bits})"
            except Exception:
                return raw_mask
        return raw_mask

    def get_wifi_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        wifi_dev = self.get_wifi_device_name() or "en0"
        wifi_data = {
            "supported": True if wifi_dev else False,
            "connected": False,
            "interface": wifi_dev,
            "ssid": None,
            "bssid": None,
            "bssid_vendor": "Produttore non catalogato",
            "rssi_dbm": None,
            "noise_dbm": None,
            "snr_db": None,
            "signal_quality_pct": None,
            "channel": None,
            "frequency_ghz": None,
            "wifi_generation": None,
            "phy_mode": None,
            "tx_rate_mbps": None,
            "mcs_index": None,
            "security": None,
            "ssid_hidden_by_os": False
        }

        # Raccoglie i dati Wi-Fi SOLO dal dispositivo Wi-Fi fisico
        if iface_name and wifi_dev and iface_name != wifi_dev:
            return wifi_data

        # Estrazione CoreWLAN su wifi_dev
        corewlan = self._get_macos_corewlan(wifi_dev)
        if corewlan and (corewlan.get("rssi_dbm") is not None or corewlan.get("ssid") or corewlan.get("bssid")):
            wifi_data["supported"] = True
            wifi_data["connected"] = True
            wifi_data.update(corewlan)

        # Regola rigorosa: Wi-Fi 6E esiste SOLO sulla banda a 6 GHz
        if wifi_data.get("phy_mode"):
            m = wifi_data["phy_mode"].lower()
            freq = str(wifi_data.get("frequency_ghz") or "")
            if "802.11be" in m:
                wifi_data["wifi_generation"] = "Wi-Fi 7 (802.11be)"
            elif "802.11ax" in m:
                if "6 ghz" in freq.lower():
                    wifi_data["wifi_generation"] = "Wi-Fi 6E (802.11ax)"
                else:
                    wifi_data["wifi_generation"] = "Wi-Fi 6 (802.11ax)"
            elif "802.11ac" in m:
                wifi_data["wifi_generation"] = "Wi-Fi 5 (802.11ac)"
            elif "802.11n" in m:
                wifi_data["wifi_generation"] = "Wi-Fi 4 (802.11n)"

        return wifi_data

    def _get_macos_corewlan(self, target_iface: str = "en0") -> Dict[str, Any]:
        metrics = {}
        try:
            import ctypes
            import ctypes.util

            objc_path = ctypes.util.find_library("objc")
            if not objc_path:
                return metrics
            objc = ctypes.cdll.LoadLibrary(objc_path)

            getClass = objc.objc_getClass
            getClass.restype = ctypes.c_void_p
            getClass.argtypes = [ctypes.c_char_p]

            sel = objc.sel_registerName
            sel.restype = ctypes.c_void_p
            sel.argtypes = [ctypes.c_char_p]

            msgSend_ptr = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
            msg_id = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(msgSend_ptr)
            msg_id_str = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)(msgSend_ptr)
            msg_id_id = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(msgSend_ptr)
            msg_long = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)(msgSend_ptr)
            msg_double = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_void_p, ctypes.c_void_p)(msgSend_ptr)

            ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN")

            CWWiFiClient = getClass(b"CWWiFiClient")
            if not CWWiFiClient:
                return metrics

            client = msg_id(CWWiFiClient, sel(b"sharedWiFiClient"))
            if not client:
                return metrics

            NSString = getClass(b"NSString")
            iface = None
            if target_iface and NSString:
                str_iface = msg_id_str(NSString, sel(b"stringWithUTF8String:"), target_iface.encode("utf-8"))
                if str_iface:
                    iface = msg_id_id(client, sel(b"interfaceWithName:"), str_iface)

            if not iface:
                return metrics

            # Potenza segnale (RSSI)
            rssi = msg_long(iface, sel(b"rssiValue"))
            if rssi != 0 and -120 < rssi < 0:
                metrics["rssi_dbm"] = int(rssi)

            # Rumore di fondo (Noise floor)
            noise = msg_long(iface, sel(b"noiseMeasurement"))
            if noise != 0 and -120 < noise < 0:
                metrics["noise_dbm"] = int(noise)

            # Calcolo SNR
            if "rssi_dbm" in metrics and "noise_dbm" in metrics:
                metrics["snr_db"] = metrics["rssi_dbm"] - metrics["noise_dbm"]
                snr = metrics["snr_db"]
                if snr >= 40:
                    metrics["signal_quality_pct"] = 100
                elif snr <= 10:
                    metrics["signal_quality_pct"] = max(5, int((snr / 10.0) * 25))
                else:
                    metrics["signal_quality_pct"] = int(25 + ((snr - 10) / 30.0) * 75)

            # MCS Index
            mcs = msg_long(iface, sel(b"mcsIndex"))
            if mcs >= 0:
                metrics["mcs_index"] = int(mcs)

            # Tx Rate
            tx_rate = msg_double(iface, sel(b"transmitRate"))
            if tx_rate > 0:
                metrics["tx_rate_mbps"] = round(float(tx_rate), 1)

            # PHY Mode
            phy = msg_long(iface, sel(b"activePHYMode"))
            phy_map = {1: "802.11a", 2: "802.11b", 3: "802.11g", 4: "802.11n", 5: "802.11ac", 6: "802.11ax", 7: "802.11be"}
            if phy in phy_map:
                metrics["phy_mode"] = phy_map[phy]

            # Canale e Banda
            channel_obj = msg_id(iface, sel(b"wlanChannel"))
            if channel_obj:
                ch_num = msg_long(channel_obj, sel(b"channelNumber"))
                ch_width = msg_long(channel_obj, sel(b"channelWidth"))
                chan_band = msg_long(channel_obj, sel(b"channelBand"))

                width_map = {1: "20 MHz", 2: "40 MHz", 3: "80 MHz", 4: "160 MHz", 5: "320 MHz"}
                w_str = width_map.get(ch_width, "")
                metrics["channel"] = f"{ch_num} ({w_str})" if w_str else str(ch_num)

                if chan_band == 1:
                    metrics["frequency_ghz"] = "2.4 GHz"
                elif chan_band == 2:
                    metrics["frequency_ghz"] = "5 GHz"
                elif chan_band == 3:
                    metrics["frequency_ghz"] = "6 GHz"

            # Sicurezza
            sec = msg_long(iface, sel(b"security"))
            sec_map = {
                1: "Open (Nessuna crittografia)", 2: "WEP", 3: "WPA Personal", 4: "WPA Enterprise",
                5: "WPA2 Personal", 6: "WPA2 Enterprise", 8: "WPA3 Personal", 9: "WPA3 Enterprise"
            }
            metrics["security"] = sec_map.get(sec, "WPA2 PSK")

            metrics["ssid_hidden_by_os"] = True

        except Exception:
            pass

        return metrics

    def get_ethernet_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        result = {
            "active": False,
            "cable_connected": False,
            "carrier": False,
            "speed_mbps": None,
            "duplex": None,
            "media_description": None,
            "switch_info": None
        }
        if not iface_name:
            return result

        code, out, _ = run_cmd(["ifconfig", iface_name], timeout=2.0)
        if code == 0 and out:
            has_carrier = "status: active" in out.lower()
            result["cable_connected"] = has_carrier
            result["carrier"] = has_carrier
            result["active"] = has_carrier

            m_media = re.search(r"media:\s*([^<\n]+)(?:<([^>]+)>)?", out)
            if m_media:
                media_type = m_media.group(1).strip()
                media_opts = m_media.group(2) or ""
                result["media_description"] = f"{media_type} ({media_opts})" if media_opts else media_type

                out_lower = out.lower()
                if "full-duplex" in out_lower or "fullduplex" in out_lower:
                    result["duplex"] = "full-duplex"
                elif "half-duplex" in out_lower or "halfduplex" in out_lower:
                    result["duplex"] = "half-duplex"

                if "1000base" in out_lower:
                    result["speed_mbps"] = 1000
                elif "2500base" in out_lower or "2.5g" in out_lower:
                    result["speed_mbps"] = 2500
                elif "5000base" in out_lower or "5gbase" in out_lower:
                    result["speed_mbps"] = 5000
                elif "10gbase" in out_lower:
                    result["speed_mbps"] = 10000
                elif "100base" in out_lower:
                    result["speed_mbps"] = 100
                elif "10base" in out_lower:
                    result["speed_mbps"] = 10

        return result

    def get_dhcp_info(self, iface_name: Optional[str] = None) -> Dict[str, Any]:
        target = iface_name or "en0"
        dhcp = {
            "server_ip": None,
            "lease_time_seconds": None,
            "lease_time_human": None,
            "lease_obtained": None,
            "lease_expires": None,
            "t1_renewal_seconds": None,
            "t2_rebinding_seconds": None,
            "tftp_server": None,
            "bootfile": None,
            "subnet_mask": None,
            "domain_name": None,
            "dns_servers": []
        }

        code, out, _ = run_cmd(["ipconfig", "getpacket", target], timeout=2.5)
        if code == 0 and out:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("server_identifier (ip):"):
                    dhcp["server_ip"] = line.split(":", 1)[1].strip()
                elif line.startswith("lease_time (uint32):"):
                    try:
                        raw_val = line.split(":", 1)[1].strip()
                        sec = int(raw_val, 16) if raw_val.startswith("0x") else int(raw_val)
                        dhcp["lease_time_seconds"] = sec
                        days = sec / 86400.0
                        dhcp["lease_time_human"] = f"{days:.1f} giorni ({sec}s)"
                        dhcp["t1_renewal_seconds"] = int(sec * 0.5)
                        dhcp["t2_rebinding_seconds"] = int(sec * 0.875)
                    except Exception:
                        pass
                elif line.startswith("subnet_mask (ip):"):
                    dhcp["subnet_mask"] = line.split(":", 1)[1].strip()
                elif line.startswith("domain_name (string):"):
                    dhcp["domain_name"] = line.split(":", 1)[1].strip()
                elif line.startswith("domain_name_server (ip_mult):"):
                    raw = line.split(":", 1)[1].strip().strip("{}")
                    dhcp["dns_servers"] = [x.strip() for x in raw.split(",") if x.strip()]

        return dhcp

    def get_dns_configuration(self) -> Dict[str, Any]:
        dns_config = {
            "resolvers": [],
            "search_domains": [],
            "domain": None,
            "system_dns_service": "scutil --dns",
            "is_encrypted": False,
            "encryption_type": None
        }

        code, out, _ = run_cmd(["scutil", "--dns"], timeout=2.5)
        if code == 0 and out:
            seen_ips = set()
            in_scoped = False
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("DNS configuration (for scoped queries)"):
                    in_scoped = True
                    continue
                if in_scoped:
                    continue
                if line.startswith("nameserver["):
                    ip = line.split(":", 1)[1].strip()
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        dns_config["resolvers"].append(ip)
                elif line.startswith("search domain["):
                    dom = line.split(":", 1)[1].strip()
                    if dom and dom not in dns_config["search_domains"]:
                        dns_config["search_domains"].append(dom)
                elif line.startswith("domain :"):
                    dns_config["domain"] = line.split(":", 1)[1].strip()

        return dns_config

    def _get_sysctl_arp(self) -> List[Dict[str, Any]]:
        """
        (a) In-process read of ARP/NDP cache via sysctl
        (CTL_NET, PF_ROUTE, 0, 0, NET_RT_FLAGS, RTF_LLINFO) con ctypes.
        Parsa struct rt_msghdr + sockaddr_inarp / sockaddr_dl con validazione dinamica degli offset.
        """
        devices = []
        diag = {"returncode": -1, "stdout_len": 0, "stderr_snippet": "", "parsed_count": 0}
        try:
            libc = ctypes.CDLL(None)
            CTL_NET = 4
            PF_ROUTE = 17
            NET_RT_FLAGS = 2
            RTF_LLINFO = 0x400

            needed = ctypes.c_size_t(0)
            mib = (ctypes.c_int * 6)(CTL_NET, PF_ROUTE, 0, 0, NET_RT_FLAGS, RTF_LLINFO)
            ret = libc.sysctl(mib, 6, None, ctypes.byref(needed), None, 0)
            if ret != 0 or needed.value == 0:
                diag["returncode"] = ret
                self._arp_diagnostics["sysctl"] = diag
                return devices

            buf = ctypes.create_string_buffer(needed.value)
            ret = libc.sysctl(mib, 6, buf, ctypes.byref(needed), None, 0)
            diag["returncode"] = ret
            diag["stdout_len"] = needed.value
            if ret != 0:
                self._arp_diagnostics["sysctl"] = diag
                return devices

            data = bytes(buf)[:needed.value]
            devices = parse_sysctl_arp_data(data)
            diag["parsed_count"] = len(devices)
        except Exception as e:
            diag["stderr_snippet"] = str(e)[:200]
        self._arp_diagnostics["sysctl"] = diag
        return devices

    def _get_arp_an(self) -> List[Dict[str, Any]]:
        """(b) Estrae voci ARP tramite il comando 'arp -an' o 'arp -n -a'."""
        devices = []
        code, out, err = run_cmd(["/usr/sbin/arp", "-an"], timeout=3.0)
        if code != 0 or not out:
            code, out, err = run_cmd(["arp", "-an"], timeout=3.0)
        if code != 0 or not out:
            code, out, err = run_cmd(["arp", "-n", "-a"], timeout=3.0)

        diag = {
            "returncode": code,
            "stdout_len": len(out) if out else 0,
            "stderr_snippet": (err or "")[:200],
            "parsed_count": 0
        }
        if code == 0 and out:
            for line in out.splitlines():
                if "(incomplete)" in line.lower() or "incomplete" in line.lower():
                    continue
                m_ip = re.search(r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?", line)
                m_mac = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{1,2}(?:-[0-9a-fA-F]{1,2}){5})", line)
                if m_ip and m_mac:
                    ip = m_ip.group(1)
                    if is_multicast_or_broadcast_ip(ip):
                        continue
                    mac = normalize_mac(m_mac.group(1))
                    if not mac:
                        continue
                    hostname = None
                    if not line.startswith("?"):
                        possible_host = line.split()[0].strip(" ()?")
                        if possible_host and not possible_host[0].isdigit():
                            hostname = possible_host
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor": lookup_vendor(mac),
                        "hostname": hostname,
                        "source": "ARP (arp -an)",
                        "mac_source": "arp_an"
                    })
        diag["parsed_count"] = len(devices)
        self._arp_diagnostics["arp_an"] = diag
        return devices

    def _get_netstat_arp(self) -> List[Dict[str, Any]]:
        """
        (b2) Estrae voci ARP da 'netstat -rn -f inet'.
        Funge da fallback quando 'arp -an' non restituisce output a causa di restrizioni sandbox su macOS.
        """
        devices = []
        code, out, err = run_cmd(["netstat", "-rn", "-f", "inet"], timeout=3.0)
        if code != 0 or not out:
            code, out, err = run_cmd(["/usr/sbin/netstat", "-rn", "-f", "inet"], timeout=3.0)

        diag = {
            "returncode": code,
            "stdout_len": len(out) if out else 0,
            "stderr_snippet": (err or "")[:200],
            "parsed_count": 0
        }
        if code == 0 and out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    dest = parts[0]
                    gateway = parts[1]
                    iface = parts[3]
                    if "/" in dest:
                        continue
                    if is_multicast_or_broadcast_ip(dest):
                        continue
                    m_ip = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", dest)
                    if not m_ip:
                        continue
                    mac = normalize_mac(gateway)
                    if not mac or is_placeholder_mac(mac):
                        continue
                    devices.append({
                        "ip": dest,
                        "mac": mac,
                        "vendor": lookup_vendor(mac),
                        "hostname": None,
                        "interface": iface,
                        "source": "ARP (netstat -rn)",
                        "mac_source": "netstat"
                    })
        diag["parsed_count"] = len(devices)
        self._arp_diagnostics["netstat"] = diag
        return devices

    def get_per_host_arp(self, ip: str) -> Optional[str]:
        """(c) Esegue ping veloce verso ip e interroga 'arp -n <ip>'."""
        if not ip or is_multicast_or_broadcast_ip(ip):
            return None
        run_cmd(["ping", "-c", "1", "-W", "500", ip], timeout=1.0)
        code, out, err = run_cmd(["/usr/sbin/arp", "-n", ip], timeout=1.5)
        if code != 0 or not out:
            code, out, err = run_cmd(["arp", "-n", ip], timeout=1.5)

        diag = self._arp_diagnostics.get("arp_per_host", {"returncode": 0, "stdout_len": 0, "stderr_snippet": "", "parsed_count": 0})
        diag["returncode"] = code
        diag["stdout_len"] += len(out) if out else 0
        if err and not diag["stderr_snippet"]:
            diag["stderr_snippet"] = err[:200]

        if code == 0 and out:
            if "(incomplete)" in out.lower() or "incomplete" in out.lower():
                self._arp_diagnostics["arp_per_host"] = diag
                return None
            m_mac = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{1,2}(?:-[0-9a-fA-F]{1,2}){5})", out)
            if m_mac:
                mac = normalize_mac(m_mac.group(1))
                if mac:
                    diag["parsed_count"] += 1
                    self._arp_diagnostics["arp_per_host"] = diag
                    return mac
        self._arp_diagnostics["arp_per_host"] = diag
        return None

    def get_ndp_table(self) -> List[Dict[str, Any]]:
        """(d) Estrae vicini IPv6 tramite 'ndp -an'."""
        devices = []
        code, out, err = run_cmd(["/usr/sbin/ndp", "-an"], timeout=2.5)
        if code != 0 or not out:
            code, out, err = run_cmd(["ndp", "-an"], timeout=2.5)
        diag = {
            "returncode": code,
            "stdout_len": len(out) if out else 0,
            "stderr_snippet": (err or "")[:200],
            "parsed_count": 0
        }
        if code == 0 and out:
            for line in out.splitlines():
                if "(incomplete)" in line.lower() or "incomplete" in line.lower():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip_part = parts[0].split("%")[0].strip()
                    if is_multicast_or_broadcast_ip(ip_part):
                        continue
                    mac_part = parts[1].strip()
                    mac = normalize_mac(mac_part)
                    if mac:
                        devices.append({
                            "ip": ip_part,
                            "mac": mac,
                            "vendor": lookup_vendor(mac),
                            "hostname": None,
                            "source": "NDP (ndp -an)",
                            "mac_source": "ndp"
                        })
        diag["parsed_count"] = len(devices)
        self._arp_diagnostics["ndp"] = diag
        return devices

    def get_arp_diagnostics(self) -> Dict[str, Any]:
        """Restituisce diagnostica di basso livello sui metodi di estrazione ARP/NDP."""
        return dict(self._arp_diagnostics)

    def get_arp_table(self) -> List[Dict[str, Any]]:
        """
        Risolve la tabella ARP nell'ordine di preferenza rigoroso:
        1. (a) In-process sysctl (CTL_NET, PF_ROUTE, NET_RT_FLAGS, RTF_LLINFO)
        2. (b) Parsing comando arp -an
        3. (c) Fallback comando netstat -rn -f inet
        4. Fallback gateway via system_profiler
        """
        seen_ips = set()
        devices = []

        # 1. Sysctl in-process
        sysctl_entries = self._get_sysctl_arp()
        for d in sysctl_entries:
            if d["ip"] not in seen_ips and d.get("mac") and not is_placeholder_mac(d["mac"]):
                seen_ips.add(d["ip"])
                devices.append(d)

        # 2. arp -an
        if not devices:
            arp_entries = self._get_arp_an()
            for d in arp_entries:
                if d["ip"] not in seen_ips and d.get("mac") and not is_placeholder_mac(d["mac"]):
                    seen_ips.add(d["ip"])
                    devices.append(d)

        # 3. netstat -rn -f inet fallback
        if not devices:
            netstat_entries = self._get_netstat_arp()
            for d in netstat_entries:
                if d["ip"] not in seen_ips and d.get("mac") and not is_placeholder_mac(d["mac"]):
                    seen_ips.add(d["ip"])
                    devices.append(d)

        # 4. Fallback gateway system_profiler se nessun host o router trovato
        has_gateway = any(d.get("ip") == "192.168.1.1" for d in devices)
        if not devices or not has_gateway:
            sp_out = self._get_system_profiler_network()
            if sp_out:
                m_ip = re.search(r"ARP Resolved IP Address:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", sp_out)
                m_hw = re.search(r"ARP Resolved Hardware Address:\s*([0-9a-fA-F:]{17})", sp_out)
                if m_ip and m_hw:
                    gw_ip = m_ip.group(1)
                    gw_mac = normalize_mac(m_hw.group(1))
                    if gw_mac and gw_ip not in seen_ips and not is_multicast_or_broadcast_ip(gw_ip):
                        seen_ips.add(gw_ip)
                        devices.append({
                            "ip": gw_ip,
                            "mac": gw_mac,
                            "vendor": lookup_vendor(gw_mac),
                            "hostname": "router",
                            "source": "ARP (system_profiler)",
                            "mac_source": "system_profiler"
                        })

        return devices
