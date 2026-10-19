"""
Database compatto di prefissi OUI (Organizationally Unique Identifier) dei MAC address.
Consente di identificare il produttore di schede di rete e router senza dipendenze esterne.
"""

from typing import Optional

OUI_DATABASE = {

    # Apple
    "00:1c:c2": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
    "ac:de:48": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "70:35:60": "Apple, Inc.",
    "3c:22:fb": "Apple, Inc.",
    "88:66:5a": "Apple, Inc.",
    "bc:d0:74": "Apple, Inc.",
    "18:65:90": "Apple, Inc.",
    "dc:a9:04": "Apple, Inc.",
    "e0:b9:ba": "Apple, Inc.",
    "14:7d:da": "Apple, Inc.",
    "28:cf:e9": "Apple, Inc.",
    "38:f9:d3": "Apple, Inc.",
    "40:6c:8f": "Apple, Inc.",
    "48:d7:05": "Apple, Inc.",
    "50:bc:96": "Apple, Inc.",
    "54:e4:3a": "Apple, Inc.",
    "60:f8:1d": "Apple, Inc.",
    "78:4f:43": "Apple, Inc.",
    "80:e6:50": "Apple, Inc.",
    "90:9c:4a": "Apple, Inc.",
    "9c:20:7b": "Apple, Inc.",
    "a8:51:ab": "Apple, Inc.",
    "b8:78:2e": "Apple, Inc.",
    "c8:89:f3": "Apple, Inc.",
    "d0:81:7a": "Apple, Inc.",
    "f4:5c:89": "Apple, Inc.",
    "fc:fc:48": "Apple, Inc.",
    "a8:8f:d9": "Apple, Inc.",


    # Router & Access Point Vendors (AVM, Telecom Italia/TIM, Sercomm, Sagemcom, Technicolor, ZTE, Huawei)
    "14:49:bc": "Telecom Italia / TIM Hub / Technicolor",
    "34:08:04": "AVM GmbH (FRITZ!Box)",
    "38:10:d5": "AVM GmbH (FRITZ!Box)",
    "c8:0e:14": "AVM GmbH (FRITZ!Box)",
    "9c:c7:a6": "AVM GmbH (FRITZ!Box)",
    "dc:39:6f": "AVM GmbH (FRITZ!Box)",
    "08:96:d7": "AVM GmbH (FRITZ!Box)",
    "2c:91:ab": "AVM GmbH (FRITZ!Box)",
    "e0:28:6d": "AVM GmbH (FRITZ!Box)",
    "bc:05:43": "AVM GmbH (FRITZ!Box)",
    "00:1f:3f": "AVM GmbH (FRITZ!Box)",
    "20:b0:01": "Sagemcom Broadband",
    "58:98:35": "Sagemcom Broadband",
    "78:81:02": "Sagemcom Broadband",
    "e4:5d:51": "Sagemcom Broadband",
    "00:26:44": "Sercomm Corporation",
    "04:a2:22": "Sercomm Corporation",
    "70:70:8b": "Sercomm Corporation",
    "b0:46:fc": "Sercomm Corporation",
    "00:0e:50": "Technicolor",
    "00:19:70": "Technicolor",
    "00:24:d4": "Technicolor",
    "00:26:24": "Technicolor",
    "08:76:ff": "Technicolor",
    "30:91:8f": "Technicolor",
    "74:b5:7e": "Technicolor",
    "88:f7:c7": "Technicolor",
    "a4:b1:e9": "Technicolor",
    "cc:03:fa": "Technicolor",
    "e4:81:84": "Technicolor",
    "f4:ca:e5": "Technicolor",
    "d8:b6:b7": "ZTE Corporation",
    "e8:9d:87": "ZTE Corporation",
    "70:9f:26": "ZTE Corporation",
    "34:e1:2d": "ZTE Corporation",
    "78:90:a2": "ZTE Corporation",
    "dc:a6:32": "Raspberry Pi Trading Ltd",

    "00:19:e0": "TP-Link Corporation",
    "14:cc:20": "TP-Link Corporation",
    "1c:3b:f3": "TP-Link Corporation",
    "30:de:4b": "TP-Link Corporation",
    "50:c7:bf": "TP-Link Corporation",
    "70:4f:57": "TP-Link Corporation",
    "98:48:27": "TP-Link Corporation",
    "b0:4e:26": "TP-Link Corporation",
    "c0:06:c3": "TP-Link Corporation",
    "ec:08:6b": "TP-Link Corporation",
    "f4:f2:6d": "TP-Link Corporation",

    # Ubiquiti Networks
    "04:18:d6": "Ubiquiti Networks",
    "24:a4:3c": "Ubiquiti Networks",
    "68:d7:9a": "Ubiquiti Networks",
    "70:a7:41": "Ubiquiti Networks",
    "78:8a:20": "Ubiquiti Networks",
    "80:2a:a8": "Ubiquiti Networks",
    "b4:fb:e4": "Ubiquiti Networks",
    "dc:9f:db": "Ubiquiti Networks",
    "f0:9f:c2": "Ubiquiti Networks",

    # MikroTik
    "00:0c:42": "MikroTik",
    "48:8f:5a": "MikroTik",
    "64:d1:54": "MikroTik",
    "cc:2d:e0": "MikroTik",
    "d4:ca:6d": "MikroTik",
    "e4:8d:8c": "MikroTik",

    # Cisco / Linksys
    "00:00:0c": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:05:31": "Cisco Systems",
    "00:1b:53": "Cisco Systems",
    "00:23:eb": "Cisco Systems",
    "00:04:5a": "Linksys",
    "00:06:25": "Linksys",
    "00:14:bf": "Linksys",
    "20:aa:4b": "Linksys",

    # Netgear
    "00:09:5b": "Netgear",
    "00:0f:b5": "Netgear",
    "00:14:6c": "Netgear",
    "00:18:4d": "Netgear",
    "00:1e:2a": "Netgear",
    "00:24:b2": "Netgear",
    "20:e5:2a": "Netgear",
    "28:c6:8e": "Netgear",
    "74:44:01": "Netgear",
    "84:1b:5e": "Netgear",
    "9c:3d:cf": "Netgear",
    "c0:ff:d4": "Netgear",

    # Asus
    "00:11:d8": "ASUSTek Computer",
    "04:d9:f5": "ASUSTek Computer",
    "08:62:66": "ASUSTek Computer",
    "10:bf:48": "ASUSTek Computer",
    "1c:87:2c": "ASUSTek Computer",
    "2c:fd:a1": "ASUSTek Computer",
    "38:2c:4a": "ASUSTek Computer",
    "40:16:7e": "ASUSTek Computer",

    # Huawei
    "00:1e:10": "Huawei Technologies",
    "00:25:9e": "Huawei Technologies",
    "00:46:4b": "Huawei Technologies",
    "04:25:48": "Huawei Technologies",
    "0c:96:bf": "Huawei Technologies",
    "24:db:ac": "Huawei Technologies",
    "48:46:fb": "Huawei Technologies",
    "70:7b:e8": "Huawei Technologies",

    # Intel
    "00:15:00": "Intel Corporation",
    "00:1b:21": "Intel Corporation",
    "00:21:6a": "Intel Corporation",
    "08:11:96": "Intel Corporation",
    "28:11:a8": "Intel Corporation",
    "34:13:e8": "Intel Corporation",
    "3c:f0:11": "Intel Corporation",
    "48:51:b7": "Intel Corporation",
    "68:05:ca": "Intel Corporation",
    "80:86:f2": "Intel Corporation",
    "a4:4e:31": "Intel Corporation",

    # Realtek & Raspberry Pi
    "00:e0:4c": "Realtek Semiconductor",
    "52:54:00": "Realtek / QEMU Virtual",
    "00:10:dc": "Realtek Semiconductor",
    "2c:56:dc": "Realtek Semiconductor",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "28:cd:c1": "Raspberry Pi Foundation",

    # Google / Nest / Chromecast
    "00:1a:11": "Google, Inc.",
    "3c:5a:37": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "64:16:66": "Google, Inc.",
    "94:eb:cd": "Google, Inc.",
    "f4:f5:d8": "Google, Inc.",

    # Amazon
    "00:fc:8b": "Amazon Technologies",
    "0c:47:c9": "Amazon Technologies",
    "38:f7:3d": "Amazon Technologies",
    "40:b4:cd": "Amazon Technologies",
    "44:65:0d": "Amazon Technologies",
    "68:37:e9": "Amazon Technologies",
    "74:c2:46": "Amazon Technologies",
    "ac:63:be": "Amazon Technologies",

    # Samsung
    "00:07:ab": "Samsung Electronics",
    "00:12:fb": "Samsung Electronics",
    "00:1e:e1": "Samsung Electronics",
    "14:bb:6e": "Samsung Electronics",
    "34:23:87": "Samsung Electronics",
    "50:01:d9": "Samsung Electronics",
    "64:b3:10": "Samsung Electronics",
    "84:25:19": "Samsung Electronics",
    "bc:44:86": "Samsung Electronics",

    # Synology & QNAP
    "00:11:32": "Synology Incorporated",
    "00:08:9b": "QNAP Systems",
    "24:5e:be": "QNAP Systems",

    # Virtualization (VMware, VirtualBox, Hyper-V, Parallels, Docker)
    "00:05:69": "VMware, Inc.",
    "00:0c:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5d": "Microsoft Hyper-V",
    "00:1c:42": "Parallels, Inc.",
    "02:42:ac": "Docker Container Bridge",
}

def is_placeholder_mac(mac_address: Optional[str]) -> bool:
    """Verifica se il MAC address è un placeholder fittizio, all-zero, o broadcast/multicast."""
    if not mac_address:
        return True
    clean_mac = mac_address.lower().replace("-", ":").strip()
    parts = clean_mac.split(":")
    if len(parts) != 6:
        return True
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return True

    # Tutto zero: 00:00:00:00:00:00
    if all(o == 0 for o in octets):
        return True

    # Placeholder macOS / Darwin sysctl mask: 02:00:00:00:00:00
    if octets[0] == 2 and all(o == 0 for o in octets[1:]):
        return True

    # Tutto uno (Broadcast): ff:ff:ff:ff:ff:ff
    if all(o == 0xff for o in octets):
        return True

    # Multicast IPv4 / IPv6
    if octets[0] == 0x01 and octets[1] == 0x00 and octets[2] == 0x5e:
        return True
    if octets[0] == 0x33 and octets[1] == 0x33:
        return True

    return False


def is_locally_administered_mac(mac_address: Optional[str]) -> bool:
    """Verifica se l'indirizzo è un vero MAC privato/randomizzato (Locally Administered) e non un placeholder."""
    if is_placeholder_mac(mac_address):
        return False
    clean_mac = mac_address.lower().replace("-", ":").strip()
    parts = clean_mac.split(":")
    try:
        return bool(int(parts[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


_IEEE_OUI_MAP = None


def _get_ieee_oui_map() -> dict:
    """Carica l'intero registro IEEE OUI da file compresso locale in memoria (lazy-loaded)."""
    global _IEEE_OUI_MAP
    if _IEEE_OUI_MAP is None:
        import os
        import gzip
        import json
        pkg_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(pkg_dir, "data", "ieee_oui.json.gz")
        if os.path.exists(data_path):
            try:
                with gzip.open(data_path, "rt", encoding="utf-8") as f:
                    _IEEE_OUI_MAP = json.load(f)
            except Exception:
                _IEEE_OUI_MAP = {}
        else:
            _IEEE_OUI_MAP = {}
    return _IEEE_OUI_MAP


def lookup_vendor(mac_address: Optional[str]) -> str:
    """Restituisce il produttore hardware associato al MAC address specificato interrogando prima il database custom e poi il registro completo IEEE."""
    if not mac_address:
        return "Sconosciuto"
    if is_placeholder_mac(mac_address):
        clean_mac = mac_address.lower().replace("-", ":").strip()
        if clean_mac == "ff:ff:ff:ff:ff:ff":
            return "Broadcast Layer 2"
        if clean_mac.startswith("01:00:5e") or clean_mac.startswith("33:33"):
            return "Multicast Layer 2"
        return "Indirizzo non disponibile"

    clean_mac = mac_address.lower().replace("-", ":").strip()
    parts = clean_mac.split(":")
    if len(parts) >= 3:
        prefix = f"{parts[0]:0>2}:{parts[1]:0>2}:{parts[2]:0>2}"
        if prefix in OUI_DATABASE:
            return OUI_DATABASE[prefix]
        ieee = _get_ieee_oui_map()
        if prefix in ieee:
            return ieee[prefix]

    if is_locally_administered_mac(clean_mac):
        return "Indirizzo MAC privato/randomizzato (Locally Administered)"

    return "Produttore non catalogato"

