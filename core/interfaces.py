"""Interface eligibility shared by active discovery and OS adapters."""
import ipaddress


def is_virtual_or_secondary_interface(name: str, desc: str, ip: str) -> bool:
    text = f'{name or ""} {desc or ""}'.lower()
    return any(word in text for word in (
        'virtualbox', 'vmware', 'hyper-v', 'vethernet', 'host-only', 'wsl',
        'tap-windows', 'wireguard', 'tailscale', 'loopback', 'pseudo-interface',
    )) or (ip or '').startswith(('169.254.', '127.'))


def interface_is_eligible(name, iface):
    return bool(iface.get('ipv4')) and not (
        iface.get('is_loopback') or iface.get('is_up') is False or
        is_virtual_or_secondary_interface(name, iface.get('description'), iface.get('ipv4')))


def local_network(ip, netmask):
    """Return the actual IPv4 subnet, never guess a /24."""
    try:
        return ipaddress.IPv4Network(f'{ip}/{str(netmask).lstrip("/")}', strict=False)
    except (ValueError, TypeError):
        return None
