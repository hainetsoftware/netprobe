"""
Interfaccia base per adapter di sistema operativo (macOS, Linux, Windows).
Isola le chiamate a comandi di sistema, parsing e accesso hardware dietro un'interfaccia unificata.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


class OSAdapter(ABC):
    @abstractmethod
    def get_hardware_ports(self) -> Dict[str, str]:
        """Mappa il device name (es. en0, eth0) alla porta hardware fisica."""
        pass

    @abstractmethod
    def get_default_gateway(self) -> Dict[str, Any]:
        """Rileva default gateway (IP, interfaccia, MAC, flags, MTU)."""
        pass

    @abstractmethod
    def get_network_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Estrae tutte le interfacce di rete fisiche e virtuali."""
        pass

    @abstractmethod
    def get_interface_mac(self, iface_name: str) -> Optional[str]:
        """Restituisce il MAC address reale (non placeholder) dell'interfaccia specificata."""
        pass

    @abstractmethod
    def get_gateway_mac(self, gateway_ip: str, interface: Optional[str] = None) -> Optional[str]:
        """Restituisce il MAC address reale del gateway."""
        pass

    @abstractmethod
    def get_wifi_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        """Estrae dettagli e metriche radio Wi-Fi."""
        pass

    @abstractmethod
    def get_ethernet_details(self, iface_name: Optional[str] = None, iface_type: Optional[str] = None) -> Dict[str, Any]:
        """Estrae dettagli connessione Ethernet cablata."""
        pass

    @abstractmethod
    def get_dhcp_info(self, iface_name: Optional[str] = None) -> Dict[str, Any]:
        """Estrae informazioni DHCP (server, lease time, timer T1/T2)."""
        pass

    @abstractmethod
    def get_dns_configuration(self) -> Dict[str, Any]:
        """Estrae configurazione DNS di sistema."""
        pass

    @abstractmethod
    def get_arp_table(self) -> List[Dict[str, Any]]:
        """Estrae tabella ARP / vicinato di rete."""
        pass

    def get_per_host_arp(self, ip: str) -> Optional[str]:
        """Esegue ping veloce e interroga la voce ARP per l'host specificato."""
        return None

    def get_ndp_table(self) -> List[Dict[str, Any]]:
        """Estrae tabella vicini IPv6 (NDP)."""
        return []

    def get_arp_diagnostics(self) -> Dict[str, Any]:
        """Restituisce diagnostica di basso livello sui metodi di estrazione ARP/NDP."""
        return {}

    def get_wifi_device_name(self) -> Optional[str]:
        """Restituisce il nome device dell'interfaccia Wi-Fi fisica (es: en0)."""
        return None
