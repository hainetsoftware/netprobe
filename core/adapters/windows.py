"""
Adapter Windows per NetProbe.
Estrae parametri di rete, interfacce, Wi-Fi, routing, DHCP e vicinato tramite comandi nativi Windows (PowerShell, netsh, arp).
"""

import json
import re
from typing import Dict, List, Any, Optional

from core.adapters.base import OSAdapter
from core.oui_data import lookup_vendor, is_placeholder_mac
from core.platform_info import run_cmd, run_cmd_shell


class WindowsAdapter(OSAdapter):
    def get_hardware_ports(self) -> Dict[str, str]:
        return {}

    def get_interface_mac(self, iface_name: str) -> Optional[str]:
        if not iface_name:
            return None
        ps_cmd = f"Get-NetAdapter -Name '{iface_name}' | Select-Object -ExpandProperty MacAddress"
        code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=2.5)
        if code == 0 and out:
            norm = out.strip().replace("-", ":").lower()
            if not is_placeholder_mac(norm):
                return norm
        return None

    def get_gateway_mac(self, gateway_ip: str, interface: Optional[str] = None) -> Optional[str]:
        if not gateway_ip:
            return None
        code, out, _ = run_cmd(["arp", "-a", gateway_ip], timeout=2.5)
        if code == 0 and out:
            m = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
            if m:
                norm = m.group(1).replace("-", ":").lower()
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
        ps_cmd = "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 NextHop, InterfaceAlias | ConvertTo-Csv -NoTypeInformation"
        code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=3.0)
        if code == 0 and out:
            lines = out.strip().splitlines()
            if len(lines) >= 2:
                parts = [p.strip(' "\'') for p in lines[1].split(",")]
                if len(parts) >= 2:
                    result["ipv4"] = parts[0]
                    result["interface"] = parts[1]

        if result["ipv4"]:
            gw_mac = self.get_gateway_mac(result["ipv4"], result["interface"])
            if gw_mac and not is_placeholder_mac(gw_mac):
                result["mac"] = gw_mac
                result["vendor"] = lookup_vendor(gw_mac)

        return result

    def get_network_interfaces(self) -> Dict[str, Dict[str, Any]]:
        interfaces = {}
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
        code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_script], timeout=5.0)
        if code == 0 and out:
            try:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("Name", "unknown")
                    mac = (item.get("Mac") or "").replace("-", ":").lower()
                    if is_placeholder_mac(mac):
                        mac = None
                    interfaces[name] = {
                        "name": name,
                        "is_up": item.get("Status") == "Up",
                        "is_running": item.get("Status") == "Up",
                        "is_loopback": "loopback" in name.lower(),
                        "flags": item.get("Status"),
                        "mtu": 1500,
                        "mac": mac,
                        "vendor": lookup_vendor(mac) if mac else "Sconosciuto",
                        "ipv4": item.get("IPv4", "").split(";")[0] if item.get("IPv4") else None,
                        "netmask": f"/{item.get('Prefix', '').split(';')[0]}" if item.get("Prefix") else None,
                        "broadcast": None,
                        "ipv6_list": [{"address": x, "prefix": 64, "type": "Link-Local" if x.startswith("fe80") else "Global Unicast"}
                                      for x in item.get("IPv6", "").split(";") if x],
                        "media": item.get("Speed"),
                        "status": item.get("Status"),
                        "type": "Wi-Fi" if "wi-fi" in name.lower() or "wireless" in name.lower() else "Ethernet"
                    }
            except Exception:
                pass
        return interfaces

    def get_wifi_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        return {
            "supported": False,
            "connected": False,
            "interface": iface_name or "Wi-Fi",
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
        return {
            "resolvers": [],
            "search_domains": [],
            "domain": None,
            "system_dns_service": "Windows DNS Client",
            "is_encrypted": False,
            "encryption_type": None
        }

    def get_arp_table(self) -> List[Dict[str, Any]]:
        devices = []
        seen_ips = set()
        code, out, _ = run_cmd(["arp", "-a"], timeout=3.0)
        if code == 0 and out:
            for line in out.splitlines():
                m_ip = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                m_mac = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", line)
                if m_ip and m_mac:
                    ip = m_ip.group(1)
                    mac = m_mac.group(1).replace("-", ":").lower()
                    if not is_placeholder_mac(mac) and ip not in seen_ips:
                        seen_ips.add(ip)
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": lookup_vendor(mac),
                            "hostname": None,
                            "source": "ARP Cache"
                        })
        return devices
