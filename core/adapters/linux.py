"""
Adapter Linux per NetProbe.
Estrae parametri di rete, interfacce, Wi-Fi, routing, DHCP e vicinato tramite comandi nativi Linux (ip, /proc, resolv.conf).
"""

import os
import re
from typing import Dict, List, Any, Optional

from core.adapters.base import OSAdapter
from core.oui_data import lookup_vendor, is_placeholder_mac
from core.platform_info import run_cmd


class LinuxAdapter(OSAdapter):
    def get_hardware_ports(self) -> Dict[str, str]:
        ports = {}
        # Leggi /sys/class/net
        if os.path.exists("/sys/class/net"):
            for dev in os.listdir("/sys/class/net"):
                if dev == "lo":
                    continue
                dev_type = "Wireless" if os.path.exists(f"/sys/class/net/{dev}/wireless") else "Ethernet"
                ports[dev] = dev_type
        return ports

    def get_interface_mac(self, iface_name: str) -> Optional[str]:
        if not iface_name:
            return None
        # /sys/class/net/<iface>/address
        sys_path = f"/sys/class/net/{iface_name}/address"
        if os.path.exists(sys_path):
            try:
                with open(sys_path, "r") as f:
                    raw = f.read().strip().lower()
                    norm = ":".join(f"{int(b, 16):02x}" for b in raw.split(":"))
                    if not is_placeholder_mac(norm):
                        return norm
            except Exception:
                pass
        return None

    def get_gateway_mac(self, gateway_ip: str, interface: Optional[str] = None) -> Optional[str]:
        if not gateway_ip:
            return None
        # 1. /proc/net/arp
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == gateway_ip:
                            norm = parts[3].lower()
                            if not is_placeholder_mac(norm):
                                return norm
            except Exception:
                pass
        # 2. ip neigh show
        code, out, _ = run_cmd(["ip", "neigh", "show", gateway_ip], timeout=2.0)
        if code == 0 and out:
            m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
            if m:
                norm = m.group(1).lower()
                if not is_placeholder_mac(norm):
                    return norm
        return None

    def get_default_gateway(self) -> Dict[str, Any]:
        result = {
            "ipv4": None,
            "interface": None,
            "mac": None,
            "vendor": "Sconosciuto",
            "flags": None,
            "mtu": None
        }
        code, out, _ = run_cmd(["ip", "route", "show", "default"], timeout=2.0)
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

        if result["ipv4"]:
            gw_mac = self.get_gateway_mac(result["ipv4"], result["interface"])
            if gw_mac and not is_placeholder_mac(gw_mac):
                result["mac"] = gw_mac
                result["vendor"] = lookup_vendor(gw_mac)
        return result

    def get_network_interfaces(self) -> Dict[str, Dict[str, Any]]:
        interfaces = {}
        code, out, _ = run_cmd(["ip", "addr"], timeout=3.0)
        if code != 0 or not out:
            return interfaces

        current_name = None
        for line in out.splitlines():
            # 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
            m_header = re.match(r"^\d+:\s+([a-zA-Z0-9_\-\.]+):?\s+<([^>]+)>\s+mtu\s+(\d+)", line)
            if m_header:
                current_name = m_header.group(1).rstrip(":")
                flags_str = m_header.group(2)
                mtu_val = int(m_header.group(3))
                interfaces[current_name] = {
                    "name": current_name,
                    "is_up": "UP" in flags_str,
                    "is_running": "LOWER_UP" in flags_str or "UP" in flags_str,
                    "is_loopback": "LOOPBACK" in flags_str,
                    "flags": flags_str,
                    "mtu": mtu_val,
                    "mac": None,
                    "vendor": "Sconosciuto",
                    "ipv4": None,
                    "netmask": None,
                    "broadcast": None,
                    "ipv6_list": [],
                    "media": None,
                    "status": "active" if "UP" in flags_str else "inactive",
                    "type": "Loopback" if "lo" in current_name else ("Wi-Fi" if "wl" in current_name else "Ethernet")
                }
                continue

            if not current_name or current_name not in interfaces:
                continue

            iface = interfaces[current_name]
            stripped = line.strip()

            m_mac = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", stripped)
            if m_mac:
                mac = m_mac.group(1).lower()
                if not is_placeholder_mac(mac):
                    iface["mac"] = mac
                    iface["vendor"] = lookup_vendor(mac)

            m_ip = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)", stripped)
            if m_ip:
                iface["ipv4"] = m_ip.group(1)
                bits = int(m_ip.group(2))
                val = (0xffffffff << (32 - bits)) & 0xffffffff
                dotted = ".".join(str((val >> (8 * i)) & 0xff) for i in reversed(range(4)))
                iface["netmask"] = f"{dotted} (/{bits})"

            m_bcast = re.search(r"brd\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", stripped)
            if m_bcast:
                iface["broadcast"] = m_bcast.group(1)

            m_ip6 = re.search(r"inet6\s+([0-9a-fA-F:]+)/(\d+)", stripped)
            if m_ip6:
                addr = m_ip6.group(1)
                prefix = int(m_ip6.group(2))
                iface["ipv6_list"].append({
                    "address": addr,
                    "prefix": prefix,
                    "type": "Link-Local" if addr.lower().startswith("fe80") else "Global Unicast"
                })

        return interfaces

    def get_wifi_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        return {
            "supported": False,
            "connected": False,
            "interface": iface_name or "wlan0",
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

    def get_ethernet_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        return {
            "active": False,
            "cable_connected": False,
            "speed_mbps": None,
            "duplex": None,
            "media_description": None,
            "switch_info": None
        }

    def get_dhcp_info(self, iface_name: Optional[str] = None) -> Dict[str, Any]:
        return {
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

    def get_dns_configuration(self) -> Dict[str, Any]:
        dns_config = {
            "resolvers": [],
            "search_domains": [],
            "domain": None,
            "system_dns_service": "/etc/resolv.conf",
            "is_encrypted": False,
            "encryption_type": None
        }
        if os.path.exists("/etc/resolv.conf"):
            try:
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2 and parts[1] not in dns_config["resolvers"]:
                                dns_config["resolvers"].append(parts[1])
                        elif line.startswith("search"):
                            dns_config["search_domains"].extend(line.split()[1:])
                        elif line.startswith("domain"):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_config["domain"] = parts[1]
            except Exception:
                pass
        return dns_config

    def get_arp_table(self) -> List[Dict[str, Any]]:
        devices = []
        seen_ips = set()
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 6:
                            ip = parts[0]
                            mac = parts[3].lower()
                            if not is_placeholder_mac(mac) and ip not in seen_ips:
                                seen_ips.add(ip)
                                devices.append({
                                    "ip": ip,
                                    "mac": mac,
                                    "vendor": lookup_vendor(mac),
                                    "hostname": None,
                                    "source": "ARP Cache"
                                })
            except Exception:
                pass
        return devices
