"""
Scanner avanzato per rete locale (LAN), schede di rete, Wi-Fi/Ethernet,
routing, DHCP, DNS, vicinato ARP e sweep dispositivi attivi.
Supporta macOS, Linux e Windows con risoluzione vendor OUI.
"""

import socket
import re
import time
import os
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple

from core.platform_info import is_macos, is_linux, is_windows, run_cmd, run_cmd_shell
from core.oui_data import lookup_vendor, is_placeholder_mac
from core.router_id import identify_router, resolve_vendor
from core.adapters import get_os_adapter
from core.dnssec_validator import validate_dnssec_resolvers
from core.validators import compute_network_and_broadcast


def extract_eui64_mac(ipv6_addr: str) -> Optional[str]:
    """
    Estrae il MAC address hardware da un indirizzo IPv6 link-local o SLAAC generato via EUI-64.
    Formula: verifica che l'IID contenga 0xff:0xfe nei byte centrali e inverte il bit 7 (universal/local, bit 1 = 0x02).
    """
    if not ipv6_addr:
        return None
    try:
        clean_ip = str(ipv6_addr).split("%")[0].strip()
        packed = socket.inet_pton(socket.AF_INET6, clean_ip)
        iid = packed[8:16]
        if iid[3] == 0xff and iid[4] == 0xfe:
            b0 = iid[0] ^ 0x02
            mac_bytes = bytes([b0, iid[1], iid[2], iid[5], iid[6], iid[7]])
            cand_mac = ':'.join(f'{b:02x}' for b in mac_bytes)
            if not is_placeholder_mac(cand_mac) and not cand_mac.startswith(('01:00:5e', '33:33', 'ff:ff:ff')):
                return cand_mac
    except Exception:
        pass
MAC_SOURCE_PRIORITY: Dict[Optional[str], int] = {
    "sysctl": 1,
    "arp_an": 2,
    "arp_per_host": 3,
    "ndp": 4,
    "netbios": 5,
    "eui64": 6,
    "system_profiler": 7,
    None: 99
}


class LanScanner:
    def __init__(self):
        self.adapter = get_os_adapter()
        self.hardware_ports = self._get_hardware_ports()
        self.permissions_warning: Optional[str] = None

    def _get_hardware_ports(self) -> Dict[str, str]:
        """Mappa su macOS e Linux il device name (en0, eth0) alla porta hardware reale."""
        ports = {}
        if is_macos():
            code, out, _ = run_cmd(["networksetup", "-listallhardwareports"], timeout=2.0)
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

    def scan_all(self, quick_scan: bool = False, progress_cb=None) -> Dict[str, Any]:
        """Esegue una scansione esaustiva di tutti i parametri LAN."""
        gateway_info = self.get_default_gateway()
        active_iface = gateway_info.get("interface")
        try:
            router = identify_router(gateway_info.get("ipv4"), gateway_info.get("mac"))
            gateway_info["mac"] = router.get("mac") or gateway_info.get("mac")
            gateway_info["vendor"] = router.get("vendor") or gateway_info.get("vendor")
            gateway_info["model"] = router.get("model")
            gateway_info["identified_by"] = router.get("sources")
            gateway_info["http_server"] = router.get("http_server")
        except Exception:
            pass
        
        interfaces = self.get_network_interfaces()
        
        # Identifica interfaccia primaria attiva
        primary_iface = None
        if active_iface and active_iface in interfaces:
            primary_iface = interfaces[active_iface]
        else:
            # Fallback: prima interfaccia con IPv4 e UP
            for name, iface in interfaces.items():
                if iface.get("ipv4") and "127.0.0.1" not in iface.get("ipv4"):
                    primary_iface = iface
                    active_iface = name
                    break

        wifi_dev = getattr(self.adapter, "get_wifi_device_name", lambda: None)() or "en0"
        active_type = primary_iface.get("type") if primary_iface else self._guess_interface_type(active_iface or "")

        # Collect Wi-Fi data only from the Wi-Fi device
        wifi_info = self.get_wifi_details(wifi_dev, iface_type="Wi-Fi" if active_iface == wifi_dev else None)

        if active_iface == wifi_dev and (wifi_info.get("connected") or wifi_info.get("rssi_dbm") is not None or wifi_info.get("ssid")):
            active_type = "Wi-Fi"
            if primary_iface:
                primary_iface["type"] = "Wi-Fi"
                primary_iface["interface_type"] = "Wi-Fi"
            ethernet_info = self.get_ethernet_details(active_iface, iface_type="Wi-Fi")
            ethernet_info["active"] = False
            ethernet_info["cable_connected"] = False
            ethernet_info["speed_mbps"] = None
            ethernet_info["duplex"] = None
            ethernet_info["media_description"] = None
        else:
            # Active interface is NOT Wi-Fi (e.g. Ethernet, USB LAN, Thunderbolt)
            wifi_info["connected"] = False
            if primary_iface and (primary_iface.get("type") == "Wi-Fi" or active_type == "Wi-Fi"):
                active_type = self._guess_interface_type(active_iface or "")
                if active_type == "Wi-Fi":
                    active_type = "Ethernet"
                primary_iface["type"] = active_type
                primary_iface["interface_type"] = active_type
            elif primary_iface:
                primary_iface["interface_type"] = active_type

            ethernet_info = self.get_ethernet_details(active_iface, iface_type=active_type)
            if active_type == "Ethernet":
                ethernet_info["interface"] = active_iface
                if primary_iface and primary_iface.get("status") == "active":
                    ethernet_info["active"] = True
                    ethernet_info["cable_connected"] = True
                    ethernet_info["carrier"] = True
                if not ethernet_info.get("speed_mbps") and primary_iface and primary_iface.get("media"):
                    med = primary_iface["media"].lower()
                    if "1000base" in med:
                        ethernet_info["speed_mbps"] = 1000
                    elif "2500base" in med or "2.5g" in med:
                        ethernet_info["speed_mbps"] = 2500
                    elif "100base" in med:
                        ethernet_info["speed_mbps"] = 100
                    elif "10gbase" in med:
                        ethernet_info["speed_mbps"] = 10000
                    if "full-duplex" in med:
                        ethernet_info["duplex"] = "full-duplex"
                    ethernet_info["media_description"] = primary_iface["media"]

        dhcp_info = self.get_dhcp_info(active_iface)
        dns_info = self.get_dns_configuration()
        dns_benchmark = self.benchmark_dns(dns_info.get("resolvers", []))
        
        # 5. Scoperta esaustiva dispositivi LAN: ARP, Gateway, DNS, DHCP, mDNS, Sweep TCP, NetBIOS
        this_device, lan_devices = self.discover_lan_devices(
            primary_iface=primary_iface,
            gateway_info=gateway_info,
            dhcp_info=dhcp_info,
            dns_info=dns_info,
            quick_scan=quick_scan,
            progress_cb=progress_cb
        )

        # Tabella ARP per compatibilità con consumer legacy
        arp_devices = [d for d in lan_devices if d.get("mac") and d["mac"] != "N/D"]
        if not arp_devices:
            arp_devices = self.get_arp_table()

        # Switch Discovery su interfaccia cablata Ethernet
        if ethernet_info.get("active") or ethernet_info.get("cable_connected") or (primary_iface and primary_iface.get("type") == "Ethernet"):
            try:
                from core.switch_probe import SwitchProbe
                sp = SwitchProbe()
                gw_ip = gateway_info.get("ipv4")
                ethernet_info["switch_info"] = sp.probe_connected_switch(
                    interface=active_iface,
                    gateway_ip=gw_ip,
                    arp_table=arp_devices,
                    timeout_seconds=4.0 if quick_scan else 8.0,
                    progress_cb=progress_cb
                )
            except Exception as e:
                ethernet_info["switch_info"] = {
                    "detected": False,
                    "switch_type": "Switch L2 Unmanaged o collegamento diretto",
                    "description": "Nessuno switch gestito rilevato (collegamento diretto o switch non gestito: non distinguibili)"
                }
        else:
            ethernet_info["switch_info"] = None

        diagnostics_arp = {}
        if hasattr(self.adapter, "get_arp_diagnostics"):
            diagnostics_arp = self.adapter.get_arp_diagnostics()
        nb_count = sum(1 for d in lan_devices if d.get("mac_source") == "netbios")
        eui_count = sum(1 for d in lan_devices if d.get("mac_source") == "eui64")
        diagnostics_arp["netbios"] = {
            "returncode": 0,
            "stdout_len": 0,
            "stderr_snippet": "",
            "parsed_count": nb_count
        }
        diagnostics_arp["eui64"] = {
            "returncode": 0,
            "stdout_len": 0,
            "stderr_snippet": "",
            "parsed_count": eui_count
        }

        return {
            "interface_type": active_type,
            "primary_interface_name": active_iface,
            "primary_interface": primary_iface,
            "all_interfaces": interfaces,
            "gateway": gateway_info,
            "wifi": wifi_info,
            "ethernet": ethernet_info,
            "dhcp": dhcp_info,
            "dns": dns_info,
            "dns_benchmark": dns_benchmark,
            "arp_table": arp_devices,
            "this_device": this_device,
            "lan_devices": lan_devices,
            "devices_discovered_count": len(lan_devices),
            "permissions_warning": self.permissions_warning,
            "diagnostics": {"arp": diagnostics_arp},
            "diagnostics_arp": diagnostics_arp
        }

    def get_default_gateway(self) -> Dict[str, Any]:
        """Rileva l'indirizzo IP, MAC e interfaccia del default gateway."""
        if hasattr(self, "adapter") and self.adapter:
            try:
                gw = self.adapter.get_default_gateway()
                if gw and gw.get("ipv4"):
                    return gw
            except Exception:
                pass

        result = {
            "ipv4": None,
            "interface": None,
            "mac": None,
            "vendor": "Sconosciuto",
            "flags": None,
            "mtu": None
        }

        if is_macos():
            code, out, _ = run_cmd(["route", "-n", "get", "default"])
            if code == 0:
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

        elif is_linux():
            code, out, _ = run_cmd(["ip", "route", "show", "default"])
            if code == 0 and out:
                # default via 192.168.1.1 dev eth0 proto dhcp metric 100
                parts = out.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        result["ipv4"] = parts[idx + 1]
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        result["interface"] = parts[idx + 1]
            if not result["ipv4"]:
                # fallback netstat
                code, out, _ = run_cmd(["netstat", "-rn"])
                for line in out.splitlines():
                    if line.startswith("0.0.0.0") or line.startswith("default"):
                        parts = line.split()
                        if len(parts) >= 2:
                            result["ipv4"] = parts[1]
                            if len(parts) >= 8:
                                result["interface"] = parts[-1]
                            break

        elif is_windows():
            # PowerShell Get-NetRoute
            code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", 
                                   "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 NextHop, InterfaceAlias | ConvertTo-Csv -NoTypeInformation"])
            if code == 0 and out:
                lines = out.strip().splitlines()
                if len(lines) >= 2:
                    parts = [p.strip(' "\'') for p in lines[1].split(",")]
                    if len(parts) >= 2:
                        result["ipv4"] = parts[0]
                        result["interface"] = parts[1]
            if not result["ipv4"]:
                code, out, _ = run_cmd_shell("route print 0.0.0.0")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] == "0.0.0.0":
                        result["ipv4"] = parts[2]
                        result["interface"] = parts[3]
                        break

        # Cerca MAC e vendor del Gateway tramite tabella ARP o adapter OS
        if result["ipv4"]:
            arp_table = self.get_arp_table()
            for entry in arp_table:
                if entry.get("ip") == result["ipv4"]:
                    result["mac"] = entry.get("mac")
                    result["vendor"] = entry.get("vendor", lookup_vendor(result["mac"]))
                    break
            if not result.get("mac") or is_placeholder_mac(result.get("mac")):
                gw_mac = self.adapter.get_gateway_mac(result["ipv4"])
                if gw_mac and not is_placeholder_mac(gw_mac):
                    result["mac"] = gw_mac
                    result["vendor"] = lookup_vendor(gw_mac)

        return result

    def get_network_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Estrae tutte le interfacce di rete fisiche e virtuali."""
        if hasattr(self, "adapter") and self.adapter:
            try:
                adapter_ifaces = self.adapter.get_network_interfaces()
                if adapter_ifaces:
                    return adapter_ifaces
            except Exception:
                pass
        interfaces = {}

        if is_macos() or is_linux():
            code, out, _ = run_cmd(["ifconfig"])
            if code != 0:
                code, out, _ = run_cmd(["ip", "addr"])
            
            if code == 0:
                current_name = None
                for line in out.splitlines():
                    # Intestazione interfaccia (es: "en5: flags=8863<UP,...> mtu 1500" o "eth0: <BROADCAST,...>")
                    m_header = re.match(r"^([a-zA-Z0-9_\-\.]+):?\s+(?:flags=\d+<([^>]+)>|.*<([^>]+)>)?\s*(?:mtu\s+(\d+))?", line)
                    if m_header and not line.startswith("\t") and not line.startswith(" "):
                        current_name = m_header.group(1).rstrip(":")
                        flags_str = m_header.group(2) or m_header.group(3) or ""
                        mtu_val = m_header.group(4)
                        
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
                            "type": self._guess_interface_type(current_name)
                        }
                        continue

                    if not current_name or current_name not in interfaces:
                        continue

                    iface = interfaces[current_name]
                    stripped = line.strip()

                    # MAC Address
                    m_mac = re.search(r"(?:ether|lladdr|link/ether)\s+([0-9a-fA-F:]{17}|[0-9a-fA-F:]{11,17})", stripped)
                    if m_mac:
                        iface["mac"] = m_mac.group(1).lower()
                        iface["vendor"] = lookup_vendor(iface["mac"])

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
                    if "status:" in stripped:
                        iface["status"] = stripped.split("status:", 1)[1].strip()

        elif is_windows():
            # PowerShell Get-NetAdapter + Get-NetIPAddress
            ps_script = """
            Get-NetAdapter | ForEach-Object {
                $alias = $_.Name
                $mac = $_.MacAddress
                $status = $_.Status
                $speed = $_.LinkSpeed
                $ips = Get-NetIPAddress -InterfaceAlias $alias -ErrorAction SilentlyContinue
                $v4 = ($ips | Where-Object AddressFamily -eq 'IPv4').IPAddress
                $mask = ($ips | Where-Object AddressFamily -eq 'IPv4').PrefixLength
                $v6 = ($ips | Where-Object AddressFamily -eq 'IPv6').IPAddress
                [PSCustomObject]@{
                    Name = $alias
                    Mac = $mac
                    Status = $status
                    Speed = $speed
                    IPv4 = ($v4 -join ';')
                    Prefix = ($mask -join ';')
                    IPv6 = ($v6 -join ';')
                }
            } | ConvertTo-Json
            """
            code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_script])
            if code == 0 and out:
                import json
                try:
                    data = json.loads(out)
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        name = item.get("Name", "unknown")
                        mac = (item.get("Mac") or "").replace("-", ":").lower()
                        interfaces[name] = {
                            "name": name,
                            "is_up": item.get("Status") == "Up",
                            "is_running": item.get("Status") == "Up",
                            "is_loopback": "loopback" in name.lower(),
                            "flags": item.get("Status"),
                            "mtu": 1500,
                            "mac": mac if mac else None,
                            "vendor": lookup_vendor(mac) if mac else "Sconosciuto",
                            "ipv4": item.get("IPv4", "").split(";")[0] if item.get("IPv4") else None,
                            "netmask": f"/{item.get('Prefix', '').split(';')[0]}" if item.get("Prefix") else None,
                            "broadcast": None,
                            "ipv6_list": [{"address": x, "type": "Link-Local" if x.startswith("fe80") else "Global"} 
                                          for x in item.get("IPv6", "").split(";") if x],
                            "media": item.get("Speed"),
                            "status": item.get("Status"),
                            "type": self._guess_interface_type(name)
                        }
                except Exception:
                    pass

        return interfaces

    def _is_hardware_ethernet(self, iface_name: Optional[str]) -> bool:
        if not iface_name:
            return False
        if hasattr(self, "hardware_ports") and iface_name in self.hardware_ports:
            hp = self.hardware_ports[iface_name].lower()
            return "ethernet" in hp or "lan" in hp
        return False

    def _get_macos_corewlan(self, target_iface: str = "en0") -> Dict[str, Any]:
        """Estrae metriche radio fisiche Wi-Fi su macOS in <0.002s tramite CoreWLAN.framework (zero dipendenze pip)."""
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

            # MCS Index (Modulation and Coding Scheme)
            mcs = msg_long(iface, sel(b"mcsIndex"))
            if mcs >= 0:
                metrics["mcs_index"] = int(mcs)

            # Link Speed (Transmit Rate)
            tx_rate = msg_double(iface, sel(b"transmitRate"))
            if tx_rate > 0:
                metrics["tx_rate_mbps"] = round(float(tx_rate), 1)

            # Active PHY Mode (Standard 802.11)
            phy_mode_int = msg_long(iface, sel(b"activePHYMode"))
            phy_map = {
                1: "802.11a",
                2: "802.11b",
                3: "802.11g",
                4: "802.11n",
                5: "802.11ac",
                6: "802.11ax",
                7: "802.11be"
            }
            if phy_mode_int in phy_map:
                metrics["phy_mode"] = phy_map[phy_mode_int]

            # WLAN Channel & Larghezza di banda
            chan_obj = msg_id(iface, sel(b"wlanChannel"))
            if chan_obj:
                chan_num = msg_long(chan_obj, sel(b"channelNumber"))
                chan_width = msg_long(chan_obj, sel(b"channelWidth"))
                chan_band = msg_long(chan_obj, sel(b"channelBand"))
                
                if chan_num > 0:
                    width_map = {1: "20 MHz", 2: "40 MHz", 3: "80 MHz", 4: "160 MHz", 5: "320 MHz"}
                    w_text = width_map.get(chan_width)
                    metrics["channel"] = f"{chan_num} ({w_text})" if w_text else str(chan_num)

                if chan_band == 1:
                    metrics["frequency_ghz"] = "2.4 GHz"
                elif chan_band == 2:
                    metrics["frequency_ghz"] = "5 GHz"
                elif chan_band == 3:
                    metrics["frequency_ghz"] = "6 GHz (Wi-Fi 6E/7)"
        except Exception:
            pass
        return metrics

    def get_wifi_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        """Raccoglie metriche radio fisiche Wi-Fi (SSID, BSSID, RSSI, Noise, SNR, MCS, Canale, Banda, Standard)."""
        if is_windows() and hasattr(self, "adapter") and hasattr(self.adapter, "get_wifi_details"):
            try:
                ad_wifi = self.adapter.get_wifi_details(iface_name=iface_name, iface_type=iface_type)
                if ad_wifi:
                    return ad_wifi
            except Exception:
                pass
        wifi_dev = getattr(self.adapter, "get_wifi_device_name", lambda: None)() or "en0"
        wifi_data = {
            "supported": True if wifi_dev else False,
            "connected": False,
            "interface": wifi_dev,
            "ssid": None,
            "bssid": None,
            "bssid_vendor": "Sconosciuto",
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

        if is_macos():
            target_iface = wifi_dev
            # 1. Native CoreWLAN via ctypes (istantaneo, <0.002s)
            cw_info = self._get_macos_corewlan(target_iface)
            if cw_info and (cw_info.get("rssi_dbm") is not None or cw_info.get("ssid") or cw_info.get("bssid")):
                wifi_data["supported"] = True
                wifi_data["connected"] = True
                wifi_data["interface"] = target_iface
                for k, v in cw_info.items():
                    if v is not None:
                        wifi_data[k] = v

            # 2. Informazioni SSID, BSSID e Security tramite ipconfig getsummary <iface> (~5ms)
            code, out, _ = run_cmd(["ipconfig", "getsummary", target_iface], timeout=1.5)
            if code == 0 and out:
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("InterfaceType :") and "WiFi" in line:
                        wifi_data["supported"] = True
                    elif line.startswith("SSID :"):
                        val = line.split(":", 1)[1].strip()
                        if val:
                            wifi_data["ssid"] = val
                            wifi_data["connected"] = True
                            wifi_data["supported"] = True
                    elif line.startswith("BSSID :"):
                        val = line.split(":", 1)[1].strip().lower()
                        if val:
                            wifi_data["bssid"] = val
                            wifi_data["bssid_vendor"] = lookup_vendor(val)
                            wifi_data["connected"] = True
                    elif line.startswith("Security :"):
                        wifi_data["security"] = line.split(":", 1)[1].strip().replace("_", " ")

            # 3. Solo se mancano metriche essenziali e CoreWLAN non ha risposto, fallback su system_profiler
            if not wifi_data.get("phy_mode") and not wifi_data.get("rssi_dbm"):
                code_sp, out_sp, _ = run_cmd(["system_profiler", "SPAirPortDataType"], timeout=3.5)
                if code_sp == 0 and out_sp:
                    in_iface = False
                    in_current = False
                    for line in out_sp.splitlines():
                        stripped = line.strip()
                        if f"{target_iface}:" in line and not in_iface:
                            in_iface = True
                            continue
                        if in_iface:
                            if "Current Network Information:" in line:
                                in_current = True
                                wifi_data["supported"] = True
                                wifi_data["connected"] = True
                                continue
                            if in_current:
                                if stripped.startswith("PHY Mode:"):
                                    wifi_data["phy_mode"] = stripped.split(":", 1)[1].strip()
                                elif stripped.startswith("Channel:"):
                                    wifi_data["channel"] = stripped.split(":", 1)[1].strip()
                                elif stripped.startswith("Security:") and not wifi_data["security"]:
                                    wifi_data["security"] = stripped.split(":", 1)[1].strip()
                                elif stripped.startswith("Signal / Noise:"):
                                    parts = stripped.split(":", 1)[1].strip().split("/")
                                    if len(parts) == 2:
                                        try:
                                            wifi_data["rssi_dbm"] = int(parts[0].replace("dBm", "").strip())
                                            wifi_data["noise_dbm"] = int(parts[1].replace("dBm", "").strip())
                                        except ValueError:
                                            pass
                                elif stripped.startswith("Transmit Rate:"):
                                    try:
                                        wifi_data["tx_rate_mbps"] = float(stripped.split(":", 1)[1].strip())
                                    except ValueError:
                                        pass
                                elif stripped.startswith("MCS Index:"):
                                    try:
                                        wifi_data["mcs_index"] = int(stripped.split(":", 1)[1].strip())
                                    except ValueError:
                                        pass
                                elif "Other Local Wi-Fi Networks:" in line or "Interfaces:" in line:
                                    break
                            elif line.startswith("      Interfaces:") or ("Interfaces:" in line and target_iface not in line):
                                break

            # 3. Fallback airport per vecchie versioni macOS
            if not wifi_data["connected"]:
                airport_bin = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if os.path.exists(airport_bin):
                    code, out, _ = run_cmd([airport_bin, "-I"])
                    if code == 0 and out and "AirPort" not in out and "not associated" not in out:
                        wifi_data["supported"] = True
                        wifi_data["connected"] = True
                        wifi_data["interface"] = target_iface
                        for line in out.splitlines():
                            parts = [p.strip() for p in line.split(":", 1)]
                            if len(parts) == 2:
                                k, v = parts[0], parts[1]
                                if k == "SSID":
                                    wifi_data["ssid"] = v
                                elif k == "BSSID":
                                    wifi_data["bssid"] = v.lower()
                                    wifi_data["bssid_vendor"] = lookup_vendor(wifi_data["bssid"])

        elif is_linux():
            # Prova nmcli dev wifi
            code, out, _ = run_cmd(["nmcli", "-t", "-f", "active,ssid,bssid,chan,freq,signal,bars,security", "dev", "wifi"])
            if code == 0 and out:
                wifi_data["supported"] = True
                for line in out.splitlines():
                    if line.startswith("yes:"):
                        parts = line.split(":")
                        if len(parts) >= 8:
                            wifi_data["connected"] = True
                            wifi_data["ssid"] = parts[1]
                            wifi_data["bssid"] = parts[2].lower()
                            wifi_data["bssid_vendor"] = lookup_vendor(wifi_data["bssid"])
                            wifi_data["channel"] = parts[3]
                            wifi_data["frequency_ghz"] = parts[4]
                            try:
                                wifi_data["signal_quality_pct"] = int(parts[5])
                                # Stima RSSI da percentuale: RSSI = (signal/2) - 100
                                wifi_data["rssi_dbm"] = int((int(parts[5]) / 2) - 100)
                            except ValueError:
                                pass
                            wifi_data["security"] = parts[7]
                            break
            # Fallback iwconfig
            if not wifi_data["connected"]:
                code, out, _ = run_cmd(["iwconfig"])
                if code == 0 and "ESSID:" in out:
                    wifi_data["supported"] = True
                    m_essid = re.search(r'ESSID:"([^"]+)"', out)
                    if m_essid:
                        wifi_data["connected"] = True
                        wifi_data["ssid"] = m_essid.group(1)
                    m_sig = re.search(r'Signal level=(-?\d+)\s*dBm', out)
                    if m_sig:
                        wifi_data["rssi_dbm"] = int(m_sig.group(1))

        elif is_windows():
            code, out, _ = run_cmd_shell("netsh wlan show interfaces")
            if code == 0 and "SSID" in out:
                wifi_data["supported"] = True
                wifi_data["connected"] = True
                for line in out.splitlines():
                    if ":" in line:
                        k, v = [x.strip() for x in line.split(":", 1)]
                        if k == "SSID":
                            wifi_data["ssid"] = v
                        elif k == "BSSID":
                            wifi_data["bssid"] = v.lower()
                            wifi_data["bssid_vendor"] = lookup_vendor(wifi_data["bssid"])
                        elif k == "Radio type":
                            wifi_data["phy_mode"] = v
                        elif k == "Signal":
                            sig_pct = v.replace("%", "").strip()
                            try:
                                wifi_data["signal_quality_pct"] = int(sig_pct)
                                wifi_data["rssi_dbm"] = int((int(sig_pct) / 2) - 100)
                            except ValueError:
                                pass
                        elif k == "Channel":
                            wifi_data["channel"] = v
                        elif k == "Receive rate (Mbps)":
                            try:
                                wifi_data["tx_rate_mbps"] = float(v)
                            except ValueError:
                                pass
                        elif k == "Authentication":
                            wifi_data["security"] = v

        # macOS >= 14.4 oscura l'SSID senza permesso di Localizzazione
        ssid = (wifi_data.get("ssid") or "").strip()
        if not ssid or "redacted" in ssid.lower() or ssid in ("<hidden>", "(null)"):
            wifi_data["ssid"] = None
            wifi_data["ssid_hidden_by_os"] = bool(wifi_data["connected"] and is_macos())
        if wifi_data.get("bssid") and "redacted" in wifi_data["bssid"].lower():
            wifi_data["bssid"] = None
        if wifi_data.get("bssid"):
            wifi_data["bssid_vendor"] = resolve_vendor(wifi_data["bssid"])

        # Calcolo derivato: SNR e Signal Quality
        if wifi_data["rssi_dbm"] is not None:
            if wifi_data["noise_dbm"] is not None:
                wifi_data["snr_db"] = wifi_data["rssi_dbm"] - wifi_data["noise_dbm"]
            
            if wifi_data["signal_quality_pct"] is None:
                # Normalizza da -100 dBm (0%) a -45 dBm (100%)
                rssi = wifi_data["rssi_dbm"]
                quality = max(0, min(100, int(2 * (rssi + 100))))
                wifi_data["signal_quality_pct"] = quality

        # Determina banda e generazione Wi-Fi
        if wifi_data["channel"]:
            try:
                ch = int(str(wifi_data["channel"]).split()[0])
                if 1 <= ch <= 14:
                    wifi_data["frequency_ghz"] = "2.4 GHz"
                elif 32 <= ch <= 177:
                    wifi_data["frequency_ghz"] = "5 GHz"
                elif ch >= 180:
                    wifi_data["frequency_ghz"] = "6 GHz (Wi-Fi 6E/7)"
            except ValueError:
                pass

        if wifi_data["phy_mode"]:
            m = wifi_data["phy_mode"].lower()
            if "802.11be" in m:
                wifi_data["wifi_generation"] = "Wi-Fi 7 (802.11be)"
            elif "802.11ax" in m:
                if wifi_data.get("frequency_ghz") and "6 GHz" in wifi_data["frequency_ghz"]:
                    wifi_data["wifi_generation"] = "Wi-Fi 6E (802.11ax)"
                else:
                    wifi_data["wifi_generation"] = "Wi-Fi 6 (802.11ax)"
            elif "802.11ac" in m:
                wifi_data["wifi_generation"] = "Wi-Fi 5 (802.11ac)"
            elif "802.11n" in m:
                wifi_data["wifi_generation"] = "Wi-Fi 4 (802.11n)"
            else:
                wifi_data["wifi_generation"] = wifi_data["phy_mode"]

        return wifi_data

    def get_ethernet_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        """Raccoglie metriche del collegamento cablato Ethernet (velocità negoziata, duplex, stato)."""
        if is_windows() and hasattr(self, "adapter") and hasattr(self.adapter, "get_ethernet_details"):
            try:
                ad_eth = self.adapter.get_ethernet_details(iface_name=iface_name, iface_type=iface_type)
                if ad_eth:
                    return ad_eth
            except Exception:
                pass

        eth_data = {
            "active": False,
            "interface": iface_name,
            "speed_mbps": None,
            "duplex": None,
            "media_description": None,
            "cable_connected": False
        }

        # Se l'interfaccia attiva è Wi-Fi o Loopback o Tunnel, non è un cavo Ethernet
        if iface_type and iface_type.lower() in ("wi-fi", "wifi", "loopback", "vpn / tunnel", "tunnel"):
            return eth_data

        if iface_name and hasattr(self, "hardware_ports") and iface_name in self.hardware_ports:
            hp = self.hardware_ports[iface_name].lower()
            if "wi-fi" in hp or "wifi" in hp or "airport" in hp:
                return eth_data

        if is_macos() and iface_name:
            code, out, _ = run_cmd(["ifconfig", iface_name])
            if code == 0:
                raw_media = None
                raw_status = None
                for line in out.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("media:"):
                        raw_media = stripped.split("media:", 1)[1].strip()
                        if "1000baseT" in stripped:
                            eth_data["speed_mbps"] = 1000
                        elif "10Gbase" in stripped:
                            eth_data["speed_mbps"] = 10000
                        elif "5000base" in stripped or "5Gbase" in stripped:
                            eth_data["speed_mbps"] = 5000
                        elif "2500base" in stripped or "2.5G" in stripped:
                            eth_data["speed_mbps"] = 2500
                        elif "100baseTX" in stripped:
                            eth_data["speed_mbps"] = 100
                        elif "10baseT" in stripped:
                            eth_data["speed_mbps"] = 10
                        
                        if "full-duplex" in stripped:
                            eth_data["duplex"] = "Full-Duplex"
                        elif "half-duplex" in stripped:
                            eth_data["duplex"] = "Half-Duplex"
                    elif stripped.startswith("status:"):
                        raw_status = stripped.split("status:", 1)[1].strip()

                # CRITICO: Su macOS le schede Wi-Fi mostrano 'media: autoselect' e 'status: active'!
                # Un cavo Ethernet reale è attivo SE E SOLO SE c'è un link negoziato reale
                # (es. 1000baseT) o l'interfaccia è hardware ethernet con status active.
                is_eth_hw = self._is_hardware_ethernet(iface_name)
                has_eth_speed = eth_data["speed_mbps"] is not None
                if raw_status == "active" and (has_eth_speed or (is_eth_hw and "none" not in (raw_media or ""))):
                    eth_data["active"] = True
                    eth_data["cable_connected"] = True
                    eth_data["media_description"] = raw_media
                else:
                    eth_data["active"] = False
                    eth_data["cable_connected"] = False
                    eth_data["media_description"] = None

        elif is_linux() and iface_name:
            speed_path = f"/sys/class/net/{iface_name}/speed"
            duplex_path = f"/sys/class/net/{iface_name}/duplex"
            carrier_path = f"/sys/class/net/{iface_name}/carrier"
            
            if os.path.exists(carrier_path):
                try:
                    with open(carrier_path, "r") as f:
                        eth_data["cable_connected"] = f.read().strip() == "1"
                        eth_data["active"] = eth_data["cable_connected"]
                except Exception:
                    pass

            if os.path.exists(speed_path):
                try:
                    with open(speed_path, "r") as f:
                        eth_data["speed_mbps"] = int(f.read().strip())
                except Exception:
                    pass

            if os.path.exists(duplex_path):
                try:
                    with open(duplex_path, "r") as f:
                        eth_data["duplex"] = f.read().strip().capitalize()
                except Exception:
                    pass

        return eth_data

    def get_dhcp_info(self, iface_name: Optional[str] = None) -> Dict[str, Any]:
        """Estrae i dettagli della concessione DHCP (server DHCP, lease time, scadenza, opzioni)."""
        if is_windows() and hasattr(self, "adapter") and hasattr(self.adapter, "get_dhcp_info"):
            try:
                ad_dhcp = self.adapter.get_dhcp_info(iface_name)
                if ad_dhcp and ad_dhcp.get("server_ip"):
                    return ad_dhcp
            except Exception:
                pass

        dhcp_data = {
            "server_ip": None,
            "lease_time_seconds": None,
            "lease_time_human": None,
            "renewal_time_seconds": None,
            "rebinding_time_seconds": None,
            "tftp_server": None,
            "bootfile": None,
            "domain_search": None
        }

        if is_macos() and iface_name:
            code, out, _ = run_cmd(["ipconfig", "getpacket", iface_name])
            if code == 0 and out:
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("server_identifier (ip):"):
                        dhcp_data["server_ip"] = line.split(":", 1)[1].strip()
                    elif line.startswith("lease_time (uint32):"):
                        raw = line.split(":", 1)[1].strip()
                        try:
                            val = int(raw, 16) if raw.startswith("0x") else int(raw)
                            dhcp_data["lease_time_seconds"] = val
                            dhcp_data["lease_time_human"] = self._format_seconds(val)
                        except ValueError:
                            pass
                    elif line.startswith("renewal_t1_time_value (uint32):"):
                        raw = line.split(":", 1)[1].strip()
                        try:
                            val = int(raw, 16) if raw.startswith("0x") else int(raw)
                            dhcp_data["renewal_time_seconds"] = val
                        except ValueError:
                            pass
                    elif line.startswith("rebinding_t2_time_value (uint32):"):
                        raw = line.split(":", 1)[1].strip()
                        try:
                            val = int(raw, 16) if raw.startswith("0x") else int(raw)
                            dhcp_data["rebinding_time_seconds"] = val
                        except ValueError:
                            pass
                    elif line.startswith("siaddr =") and "0.0.0.0" not in line:
                        dhcp_data["tftp_server"] = line.split("=", 1)[1].strip()
                    elif line.startswith("bootfile_name (string):"):
                        dhcp_data["bootfile"] = line.split(":", 1)[1].strip()
                    elif line.startswith("domain_name (string):"):
                        dhcp_data["domain_search"] = line.split(":", 1)[1].strip()

        return dhcp_data

    def get_dns_configuration(self) -> Dict[str, Any]:
        """Estrae i server DNS configurati nel sistema operativo."""
        if is_windows() and hasattr(self, "adapter") and hasattr(self.adapter, "get_dns_configuration"):
            try:
                ad_dns = self.adapter.get_dns_configuration()
                if ad_dns and ad_dns.get("resolvers"):
                    return ad_dns
            except Exception:
                pass

        dns_data = {
            "resolvers": [],
            "search_domains": [],
            "scoped_resolvers": []
        }

        if is_macos():
            code, out, _ = run_cmd(["scutil", "--dns"])
            if code == 0:
                is_scoped = False
                for line in out.splitlines():
                    line = line.strip()
                    if "DNS configuration (for scoped queries)" in line:
                        is_scoped = True
                        continue
                    m_ns = re.match(r"nameserver\[\d+\]\s*:\s*([0-9a-fA-F:\.]+)", line)
                    if m_ns:
                        ns = m_ns.group(1)
                        if is_scoped:
                            if ns not in dns_data["scoped_resolvers"]:
                                dns_data["scoped_resolvers"].append(ns)
                        else:
                            if ns not in dns_data["resolvers"]:
                                dns_data["resolvers"].append(ns)
                    m_dom = re.match(r"search domain\[\d+\]\s*:\s*([a-zA-Z0-9_\-\.]+)", line)
                    if m_dom:
                        dom = m_dom.group(1)
                        if dom not in dns_data["search_domains"]:
                            dns_data["search_domains"].append(dom)

        elif is_linux():
            # Leggi /etc/resolv.conf
            if os.path.exists("/etc/resolv.conf"):
                try:
                    with open("/etc/resolv.conf", "r") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("nameserver"):
                                parts = line.split()
                                if len(parts) >= 2 and parts[1] not in dns_data["resolvers"]:
                                    dns_data["resolvers"].append(parts[1])
                            elif line.startswith("search") or line.startswith("domain"):
                                parts = line.split()
                                for dom in parts[1:]:
                                    if dom not in dns_data["search_domains"]:
                                        dns_data["search_domains"].append(dom)
                except Exception:
                    pass

        elif is_windows():
            code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command",
                                   "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses | Select-Object -Unique"])
            if code == 0 and out:
                for line in out.splitlines():
                    ip = line.strip()
                    if ip and ip not in dns_data["resolvers"]:
                        dns_data["resolvers"].append(ip)

        return dns_data

    def benchmark_dns(self, configured_resolvers: List[str]) -> Dict[str, Any]:
        """Misura la latenza di risoluzione DNS locale vs provider Anycast globali e testa DNSSEC."""
        test_domains = ["google.com", "cloudflare.com", "apple.com", "wikipedia.org"]
        public_benchmarks = {
            "Cloudflare (1.1.1.1)": "1.1.1.1",
            "Google (8.8.8.8)": "8.8.8.8",
            "Quad9 (9.9.9.9)": "9.9.9.9"
        }

        results = {
            "system_resolver_latency_ms": None,
            "tested_servers": [],
            "dnssec_validation_active": False,
            "fastest_resolver": None
        }

        # 1. Benchmark System Resolver nativo (socket.getaddrinfo) in parallelo
        durations = []
        def probe_domain(dom: str) -> Optional[float]:
            t0 = time.perf_counter()
            try:
                socket.getaddrinfo(dom, 80, socket.AF_INET, socket.SOCK_STREAM)
                return (time.perf_counter() - t0) * 1000.0
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(test_domains)) as executor:
            raw_durations = list(executor.map(probe_domain, test_domains))
        durations = [d for d in raw_durations if d is not None]
        
        if durations:
            results["system_resolver_latency_ms"] = round(sum(durations) / len(durations), 2)
            results["tested_servers"].append({
                "name": "DNS di Sistema Locale",
                "ip": configured_resolvers[0] if configured_resolvers else "Default OS",
                "avg_ms": results["system_resolver_latency_ms"]
            })

        # 2. Test validazione DNSSEC con dnspython e controllo runtime di coerenza
        dnssec_res = validate_dnssec_resolvers(configured_resolvers)
        results["dnssec_report"] = dnssec_res
        results["dnssec_validation_active"] = dnssec_res.get("dnssec_validation_active", False)
        results["resolvers_dnssec"] = dnssec_res.get("resolvers", [])

        return results

    def get_arp_table(self) -> List[Dict[str, Any]]:
        """Estrae la tabella ARP di sistema (dispositivi fisici noti nella LAN)."""
        if is_windows() and hasattr(self, "adapter") and hasattr(self.adapter, "get_arp_table"):
            try:
                ad_arp = self.adapter.get_arp_table()
                if ad_arp:
                    return ad_arp
            except Exception:
                pass

        devices = []
        seen_ips = set()

        if is_macos():
            code, out, _ = run_cmd(["arp", "-n", "-a"], timeout=3.0)
        elif is_linux():
            code, out, _ = run_cmd(["arp", "-n"], timeout=3.0)
            if code != 0:
                code, out, _ = run_cmd(["ip", "neighbor"], timeout=3.0)
        else:
            code, out, _ = run_cmd(["arp", "-a"], timeout=3.0)

        if code == 0 and out:
            for line in out.splitlines():
                # Formato tipico macOS: ? (172.16.4.1) at 14:49:bc:13:aa:38 on en5 ifscope [ethernet]
                # Formato Linux: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
                # Formato Windows:   192.168.1.1           00-11-22-33-44-55     dynamic
                m_ip = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                m_mac = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{1,2}(?:-[0-9a-fA-F]{1,2}){5})", line)
                
                if m_ip and m_mac:
                    ip = m_ip.group(1)
                    raw_mac = m_mac.group(1).replace("-", ":").lower()
                    # Normalizza i byte singoli (es: 0:1c -> 00:1c)
                    try:
                        mac = ":".join(f"{int(b, 16):02x}" for b in raw_mac.split(":"))
                    except ValueError:
                        mac = raw_mac

                    if ip not in seen_ips and mac != "ff:ff:ff:ff:ff:ff":
                        seen_ips.add(ip)
                        vendor = lookup_vendor(mac)
                        hostname = None
                        if not line.startswith("?"):
                            possible_host = line.split()[0].strip(" ()?")
                            if possible_host and not possible_host[0].isdigit():
                                hostname = possible_host

                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": vendor,
                            "hostname": hostname,
                            "source": "ARP Cache"
                        })

        return devices

    def _query_netbios_node_status(self, ip: str, timeout: float = 0.15) -> Tuple[Optional[str], Optional[str]]:
        """Invia una query NetBIOS Name Service (RFC 1002) su UDP 137 per estrarre l'hostname e il MAC address hardware."""
        query = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        hostname = None
        mac = None
        try:
            s.sendto(query, (ip, 137))
            data, _ = s.recvfrom(1024)
            if len(data) > 56:
                num_names = data[56]
                offset = 57
                for _ in range(num_names):
                    if offset + 15 <= len(data) and not hostname:
                        name = data[offset:offset+15].decode('ascii', errors='ignore').strip()
                        if name and not name.startswith(('\x00', '\x01', '__')):
                            hostname = name
                    offset += 18
                # RFC 1002: dopo i nomi c'è il blocco STATISTICS; i primi 6 byte sono lo UNIT ID (MAC hardware)
                if offset + 6 <= len(data):
                    unit_id = data[offset:offset+6]
                    if unit_id != b'\x00' * 6:
                        cand_mac = ':'.join(f'{b:02x}' for b in unit_id)
                        if not is_placeholder_mac(cand_mac) and not cand_mac.startswith(('01:00:5e', '33:33', 'ff:ff:ff')):
                            mac = cand_mac
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return hostname, mac

    def _query_netbios_name(self, ip: str, timeout: float = 0.15) -> Optional[str]:
        """Invia una query NetBIOS Name Service (RFC 1002) su UDP 137 per estrarre l'hostname."""
        return self._query_netbios_node_status(ip, timeout)[0]

    def _fast_reverse_dns(self, ip: str, timeout: float = 0.3) -> Optional[str]:
        """Tenta la risoluzione PTR rapida con dnspython (sub-millisecondi), con fallback a socket.gethostbyaddr se dnspython non e' presente."""
        if not ip:
            return None
        try:
            import dns.resolver, dns.reversename
            rev = dns.reversename.from_address(ip)
            r = dns.resolver.Resolver()
            r.timeout = timeout
            r.lifetime = timeout
            ans = r.resolve(rev, "PTR")
            for a in ans:
                val = str(a).rstrip(".")
                if val:
                    return val
            return None
        except ImportError:
            pass
        except Exception:
            # dnspython ha risposto con NXDOMAIN / NoAnswer / timeout: nessun record PTR esiste nel server DNS
            return None

        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _discover_mdns_services(self, timeout: float = 0.6) -> Dict[str, str]:
        """Usa zeroconf per scoprire host e nomi di servizio mDNS / Bonjour sulla LAN."""
        found: Dict[str, str] = {}
        try:
            import zeroconf
            zc = zeroconf.Zeroconf()
            services = [
                '_http._tcp.local.', '_smb._tcp.local.', '_googlecast._tcp.local.',
                '_airplay._tcp.local.', '_spotify-connect._tcp.local.', '_ipp._tcp.local.',
                '_workstation._tcp.local.', '_companion-link._tcp.local.'
            ]
            class Listener:
                def add_service(self, zc_obj, type_, name):
                    try:
                        info = zc_obj.get_service_info(type_, name, timeout=300)
                        if info:
                            for addr in info.parsed_scoped_addresses():
                                if addr not in found or not found[addr]:
                                    host = info.server.rstrip('.').replace('.local', '') if info.server else name.split('.')[0]
                                    found[addr] = host
                    except Exception:
                        pass
                def update_service(self, *args): pass
                def remove_service(self, *args): pass

            browser = zeroconf.ServiceBrowser(zc, services, Listener())
            time.sleep(timeout)
            zc.close()
        except Exception:
            pass
        return found

    def sweep_local_subnet(self, local_ip: str, netmask: Optional[str]) -> List[Dict[str, Any]]:
        """
        Esegue uno sweep multithreaded non invasivo della subnet locale (/24 completa)
        per popolare l'ARP table e scoprire i dispositivi online.
        """
        discovered = []
        if not local_ip:
            return discovered

        parts = local_ip.split(".")
        if len(parts) != 4:
            return discovered

        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
        target_ips = [f"{prefix}.{octet}" for octet in range(1, 255) if f"{prefix}.{octet}" != local_ip]

        def probe_host(ip: str):
            for port in (80, 443, 53, 445, 8080, 22):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.12)
                try:
                    res = s.connect_ex((ip, port))
                    s.close()
                    if res == 0:
                        return ip
                except Exception:
                    pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            active_ips = list(filter(None, executor.map(probe_host, target_ips)))

        def _resolve_sweep_ip(ip_addr: str) -> Dict[str, Any]:
            name = self._fast_reverse_dns(ip_addr)
            return {
                "ip": ip_addr,
                "hostname": name,
                "source": "Sweep TCP"
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(len(active_ips), 1))) as executor:
            discovered = list(executor.map(_resolve_sweep_ip, active_ips))

        return discovered

    def _merge_sweep_into_arp(self, arp_list: List[Dict[str, Any]], sweep_list: List[Dict[str, Any]]):
        known_ips = {d["ip"]: d for d in arp_list}
        for s in sweep_list:
            ip = s["ip"]
            if ip in known_ips:
                if not known_ips[ip].get("hostname") and s.get("hostname"):
                    known_ips[ip]["hostname"] = s.get("hostname")
            else:
                arp_list.append({
                    "ip": ip,
                    "mac": "N/D",
                    "vendor": "N/D",
                    "hostname": s.get("hostname"),
                    "source": "Sweep TCP"
                })

    def discover_lan_devices(
        self,
        primary_iface: Optional[Dict[str, Any]],
        gateway_info: Dict[str, Any],
        dhcp_info: Dict[str, Any],
        dns_info: Dict[str, Any],
        quick_scan: bool = False,
        progress_cb=None
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Unione esaustiva di tutte le fonti LAN: ARP, Gateway, DNS, DHCP, mDNS, Sweep TCP, NetBIOS.
        Separa autoritativamente 'Questo dispositivo'.
        """
        p_if = primary_iface or {}
        this_ip = p_if.get("ipv4")
        this_mac = p_if.get("mac")
        this_vendor = p_if.get("vendor") or (lookup_vendor(this_mac) if this_mac and not is_placeholder_mac(this_mac) else "N/D")
        this_device = {
            "ip": this_ip or "127.0.0.1",
            "mac": this_mac if (this_mac and not is_placeholder_mac(this_mac)) else "N/D",
            "vendor": this_vendor,
            "hostname": socket.gethostname(),
            "interface": p_if.get("name") or "en0",
            "type": p_if.get("type") or "LAN",
            "role": "Questo dispositivo"
        }

        device_map: Dict[str, Dict[str, Any]] = {}
        MAC_SOURCE_PRIORITY = {
            "sysctl": 1,
            "arp_an": 2,
            "arp_per_host": 3,
            "ndp": 4,
            "netbios": 5,
            "eui64": 6,
            "system_profiler": 7,
            None: 99
        }

        def record_candidate(ip: str, source: str, mac: Optional[str] = None, hostname: Optional[str] = None, mac_source: Optional[str] = None):
            if not ip or ip == this_ip or ip in ("127.0.0.1", "::1", "fe80::1") or ip.startswith("127.") or ip.startswith("169.254."):
                return
            valid_mac = mac if (mac and not is_placeholder_mac(mac)) else None
            effective_src = mac_source if valid_mac else None

            if ip not in device_map:
                device_map[ip] = {
                    "ip": ip,
                    "mac": valid_mac,
                    "mac_source": effective_src,
                    "vendor": lookup_vendor(valid_mac) if valid_mac else None,
                    "hostname": hostname,
                    "discovery_sources": [source],
                    "how_found": source,
                    "is_gateway": False,
                    "is_dns": False,
                    "is_dhcp": False
                }
            else:
                entry = device_map[ip]
                if source not in entry["discovery_sources"]:
                    entry["discovery_sources"].append(source)
                    entry["how_found"] = ", ".join(entry["discovery_sources"])
                if valid_mac:
                    cur_prio = MAC_SOURCE_PRIORITY.get(entry.get("mac_source"), 99)
                    new_prio = MAC_SOURCE_PRIORITY.get(effective_src, 99)
                    if not entry.get("mac") or entry.get("mac") == "N/D" or new_prio < cur_prio:
                        entry["mac"] = valid_mac
                        entry["mac_source"] = effective_src
                        entry["vendor"] = lookup_vendor(valid_mac)
                if not entry["hostname"] and hostname:
                    entry["hostname"] = hostname

        # 1. Default Gateway
        gw_ip = (gateway_info or {}).get("ipv4")
        gw_mac = (gateway_info or {}).get("mac")
        gw_mac_src = (gateway_info or {}).get("mac_source") or ("system_profiler" if gw_mac else None)
        if gw_ip:
            record_candidate(gw_ip, "Default Gateway", mac=gw_mac, mac_source=gw_mac_src)
            if gw_ip in device_map:
                device_map[gw_ip]["is_gateway"] = True

        # 2. Configured DNS Resolvers
        for dns_ip in ((dns_info or {}).get("resolvers", []) or []):
            record_candidate(dns_ip, "DNS Configurato")
            if dns_ip in device_map:
                device_map[dns_ip]["is_dns"] = True

        # 3. DHCP Server
        dhcp_ip = (dhcp_info or {}).get("server_ip")
        if dhcp_ip:
            record_candidate(dhcp_ip, "DHCP Server")
            if dhcp_ip in device_map:
                device_map[dhcp_ip]["is_dhcp"] = True

        # 4. Tabella ARP iniziale (sysctl o arp -an)
        initial_arp = self.get_arp_table()
        for d in initial_arp:
            record_candidate(d.get("ip"), "ARP Cache", mac=d.get("mac"), hostname=d.get("hostname"), mac_source=d.get("mac_source", "arp_an"))

        # 5. mDNS (zeroconf)
        if progress_cb:
            progress_cb("Scansione servizi mDNS / Bonjour (zeroconf)...", 25)
        mdns_results = self._discover_mdns_services(timeout=0.6)
        for m_ip, m_host in mdns_results.items():
            record_candidate(m_ip, "mDNS (zeroconf)", hostname=m_host)

        # 6. Sweep TCP subnet locale
        if not quick_scan and this_ip and p_if.get("netmask"):
            if progress_cb:
                progress_cb("Sweep TCP porte standard su subnet locale...", 30)
            sweep_hosts = self.sweep_local_subnet(this_ip, p_if.get("netmask"))
            for s in sweep_hosts:
                record_candidate(s.get("ip"), "Sweep TCP", hostname=s.get("hostname"))

        # 7. Seconda lettura ARP post-traffico
        post_arp = self.get_arp_table()
        for d in post_arp:
            record_candidate(d.get("ip"), "ARP Cache", mac=d.get("mac"), hostname=d.get("hostname"), mac_source=d.get("mac_source", "arp_an"))

        # 7b. (c) Per-host ARP lookup per candidati IPv4 che non hanno ancora un MAC
        if hasattr(self.adapter, "get_per_host_arp"):
            for ip, entry in list(device_map.items()):
                if (not entry.get("mac") or entry.get("mac") == "N/D") and ":" not in ip:
                    p_mac = self.adapter.get_per_host_arp(ip)
                    if p_mac and not is_placeholder_mac(p_mac):
                        entry["mac"] = p_mac
                        entry["mac_source"] = "arp_per_host"
                        entry["vendor"] = lookup_vendor(p_mac)
                        if "ARP (per-host ping)" not in entry["discovery_sources"]:
                            entry["discovery_sources"].append("ARP (per-host ping)")
                            entry["how_found"] = ", ".join(entry["discovery_sources"])

        # 7c. (d) Tabella vicini IPv6 NDP
        if hasattr(self.adapter, "get_ndp_table"):
            ndp_entries = self.adapter.get_ndp_table()
            for n in ndp_entries:
                record_candidate(n.get("ip"), "NDP (ndp -an)", mac=n.get("mac"), hostname=n.get("hostname"), mac_source="ndp")

        # 8. (e) Risoluzione hostname mancanti tramite reverse DNS o NetBIOS node status (con estrazione MAC) in parallelo
        def _resolve_candidate(entry_item: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
            c_ip = entry_item.get("ip", "")
            c_nb_host, c_nb_mac = None, None
            if ":" not in c_ip:
                c_nb_host, c_nb_mac = self._query_netbios_node_status(c_ip)

            c_rdns_host = None
            if not entry_item.get("hostname") and not c_nb_host:
                c_rdns_host = self._fast_reverse_dns(c_ip)
            return c_ip, c_nb_host, c_nb_mac, c_rdns_host

        entries_to_resolve = list(device_map.values())
        if entries_to_resolve:
            max_workers = min(32, max(len(entries_to_resolve), 1))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                resolved_results = list(executor.map(_resolve_candidate, entries_to_resolve))

            for c_ip, c_nb_host, c_nb_mac, c_rdns_host in resolved_results:
                e = device_map.get(c_ip)
                if not e:
                    continue
                if c_nb_host and not e.get("hostname"):
                    e["hostname"] = c_nb_host
                    if "NetBIOS" not in e["discovery_sources"]:
                        e["discovery_sources"].append("NetBIOS")
                        e["how_found"] = ", ".join(e["discovery_sources"])
                if c_nb_mac and (not e.get("mac") or e.get("mac") == "N/D"):
                    e["mac"] = c_nb_mac
                    e["mac_source"] = "netbios"
                    e["vendor"] = lookup_vendor(c_nb_mac)
                    if "NetBIOS (node-status)" not in e["discovery_sources"]:
                        e["discovery_sources"].append("NetBIOS (node-status)")
                        e["how_found"] = ", ".join(e["discovery_sources"])
                if c_rdns_host and not e.get("hostname"):
                    e["hostname"] = c_rdns_host

        # 8b. (f) Estrazione MAC via EUI-64 per indirizzi IPv6 link-local/SLAAC
        for ip, entry in list(device_map.items()):
            if ":" in ip and (not entry.get("mac") or entry.get("mac") == "N/D"):
                cand_eui = extract_eui64_mac(ip)
                if cand_eui:
                    entry["mac"] = cand_eui
                    entry["mac_source"] = "eui64"
                    entry["vendor"] = lookup_vendor(cand_eui)
                    if "EUI-64" not in entry["discovery_sources"]:
                        entry["discovery_sources"].append("EUI-64")
                        entry["how_found"] = ", ".join(entry["discovery_sources"])

        # 9. Fusione dispositivi duplicati (stesso MAC o stesso hostname mDNS/NetBIOS/DNS tra IPv4 e IPv6)
        merged_devices = self._merge_duplicate_devices(list(device_map.values()))

        # 10. Normalizzazione finale valori mancanti
        for entry in merged_devices:
            if not entry.get("mac"):
                entry["mac"] = "N/D"
            if not entry.get("mac_source"):
                entry["mac_source"] = "N/D" if entry.get("mac") == "N/D" else entry.get("mac_source")
            if not entry.get("vendor"):
                entry["vendor"] = "N/D"
            if not entry.get("hostname"):
                entry["hostname"] = "N/D"

        # 11. Controllo permessi Rete Locale macOS (TCC / Privacy)
        alive_non_gw = [d for d in merged_devices if not d.get("is_gateway")]
        has_any_mac = any(d.get("mac") and d.get("mac") != "N/D" and not is_placeholder_mac(d["mac"]) for d in alive_non_gw)
        if len(alive_non_gw) > 0 and not has_any_mac:
            self.permissions_warning = (
                "Possibile permesso Rete locale mancante o limitazione dell'ambiente Python: controlla "
                "Impostazioni di Sistema → Privacy e sicurezza → Rete locale per l'app che lancia NetProbe"
            )
        else:
            self.permissions_warning = None

        def _ip_key(d):
            try:
                parts = [int(x) for x in d["ip"].split(".")]
                return (0, parts)
            except Exception:
                return (1, [d.get("ip", "")])

        sorted_devices = sorted(merged_devices, key=_ip_key)
        return this_device, sorted_devices

    def _merge_duplicate_devices(self, raw_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Unisce record appartenenti allo stesso dispositivo fisico:
        - Stesso MAC valido (non placeholder, non nullo)
        - O stesso hostname normalizzato (mDNS / NetBIOS / DNS) attraverso IPv4 e IPv6.
        Mantiene un'unica riga con IPv4 primario e indirizzi IPv6 secondari.
        """
        if not raw_devices:
            return []

        def _norm_host(h):
            if not h or h in ("N/D", "router", "unknown", "localhost"):
                return None
            clean = str(h).lower().strip().rstrip(".")
            for suffix in (".local", ".lan", ".home"):
                if clean.endswith(suffix):
                    clean = clean[:-len(suffix)]
            clean = re.sub(r"\._[a-z0-9\-]+(\._[a-z0-9\-]+)*$", "", clean)
            clean = clean.strip()
            return clean if len(clean) >= 3 else None

        clusters: List[List[Dict[str, Any]]] = []

        for d in raw_devices:
            d_mac = d.get("mac")
            d_valid_mac = d_mac if (d_mac and d_mac != "N/D" and not is_placeholder_mac(d_mac)) else None
            d_norm_h = _norm_host(d.get("hostname"))
            d_ip = d.get("ip")

            matched_cluster = None
            for c in clusters:
                for other in c:
                    o_mac = other.get("mac")
                    o_valid_mac = o_mac if (o_mac and o_mac != "N/D" and not is_placeholder_mac(o_mac)) else None
                    o_norm_h = _norm_host(other.get("hostname"))
                    o_ip = other.get("ip")

                    if d_ip and o_ip and d_ip == o_ip:
                        matched_cluster = c
                        break
                    if d_valid_mac and o_valid_mac and d_valid_mac.lower() == o_valid_mac.lower():
                        matched_cluster = c
                        break
                    if d_norm_h and o_norm_h and d_norm_h == o_norm_h:
                        matched_cluster = c
                        break
                if matched_cluster is not None:
                    break

            if matched_cluster is not None:
                matched_cluster.append(d)
            else:
                clusters.append([d])

        merged_list = []
        for c in clusters:
            all_ips = []
            seen_ips = set()
            for x in c:
                ip = x.get("ip")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    all_ips.append(ip)
                for sec_ip in x.get("all_ips", []):
                    if sec_ip and sec_ip not in seen_ips:
                        seen_ips.add(sec_ip)
                        all_ips.append(sec_ip)

            v4_ips = [ip for ip in all_ips if ":" not in ip]
            v6_ips = [ip for ip in all_ips if ":" in ip]

            primary_ip = v4_ips[0] if v4_ips else (v6_ips[0] if v6_ips else "N/D")
            secondary_v6 = v6_ips if v4_ips else v6_ips[1:]

            # Priorità per la selezione del MAC: sysctl (1) > arp_an (2) > arp_per_host (3) > ndp (4) > netbios (5) > eui64 (6)
            c_macs = [x for x in c if x.get("mac") and x.get("mac") != "N/D" and not is_placeholder_mac(x["mac"])]
            if c_macs:
                c_macs.sort(key=lambda x: MAC_SOURCE_PRIORITY.get(x.get("mac_source"), 50))
                best_cand = c_macs[0]
                mac_val = best_cand["mac"]
                mac_source_val = best_cand.get("mac_source") or "arp_an"
            else:
                eui_cand = next((extract_eui64_mac(ip6) for ip6 in v6_ips if extract_eui64_mac(ip6)), None)
                if eui_cand:
                    mac_val = eui_cand
                    mac_source_val = "eui64"
                else:
                    mac_val = "N/D"
                    mac_source_val = "N/D"

            valid_mac = mac_val if (mac_val != "N/D" and not is_placeholder_mac(mac_val)) else None
            vendor_val = lookup_vendor(valid_mac) if valid_mac else next((x.get("vendor") for x in c if x.get("vendor") and x.get("vendor") != "N/D"), "N/D")
            best_host = next((x.get("hostname") for x in c if x.get("hostname") and x.get("hostname") != "N/D"), None) or "N/D"

            sources = []
            for x in c:
                for s in x.get("discovery_sources", []):
                    if s and s not in sources:
                        sources.append(s)

            merged_entry = {
                "ip": primary_ip,
                "all_ips": all_ips,
                "ipv6_addresses": secondary_v6,
                "mac": mac_val,
                "mac_source": mac_source_val,
                "vendor": vendor_val,
                "hostname": best_host,
                "discovery_sources": sources,
                "how_found": ", ".join(sources) if sources else "N/D",
                "is_gateway": any(x.get("is_gateway") for x in c),
                "is_dns": any(x.get("is_dns") for x in c),
                "is_dhcp": any(x.get("is_dhcp") for x in c)
            }
            merged_list.append(merged_entry)

        return merged_list

    def _guess_interface_type(self, name: str) -> str:
        # 1. Mappatura autoritativa da sistema operativo
        if hasattr(self, "hardware_ports") and name in self.hardware_ports:
            hp = self.hardware_ports[name].lower()
            if "wi-fi" in hp or "wifi" in hp or "airport" in hp:
                return "Wi-Fi"
            elif "ethernet" in hp or "lan" in hp:
                return "Ethernet"
            elif "thunderbolt bridge" in hp or "bridge" in hp:
                return "Bridge"
            elif "thunderbolt" in hp:
                return "Thunderbolt"

        n = name.lower()
        if "lo" in n or "loopback" in n:
            return "Loopback"
        elif "en0" in n or "wl" in n or "wlan" in n or "wifi" in n:
            return "Wi-Fi"
        elif "en" in n or "eth" in n or "ethernet" in n:
            return "Ethernet"
        elif "utun" in n or "tun" in n or "tap" in n or "ppp" in n or "wg" in n:
            return "VPN / Tunnel"
        elif "bridge" in n or "br" in n:
            return "Bridge"
        return "Adattatore di Rete"

    def _normalize_netmask(self, mask: str) -> str:
        if mask.startswith("0x"):
            # Hex netmask (es: 0xfffffc00)
            try:
                val = int(mask, 16)
                b1 = (val >> 24) & 0xFF
                b2 = (val >> 16) & 0xFF
                b3 = (val >> 8) & 0xFF
                b4 = val & 0xFF
                cidr = bin(val).count("1")
                return f"{b1}.{b2}.{b3}.{b4} (/{cidr})"
            except Exception:
                return mask
        elif mask.isdigit():
            return f"/{mask}"
        return mask

    def _format_seconds(self, seconds: int) -> str:
        if seconds < 60:
            return f"{seconds} secondi"
        elif seconds < 3600:
            return f"{seconds // 60} minuti ({seconds}s)"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f} ore ({seconds}s)"
        else:
            days = seconds / 86400
            return f"{days:.1f} giorni ({seconds}s)"
