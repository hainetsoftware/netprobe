#!/usr/bin/env python3
"""
tools/arp_diag.py - Standalone ARP / Neighbor Diagnostics Tool for macOS

Esegue in sequenza e diagnostica ciascun metodo di estrazione del vicinato di rete (ARP/NDP):
1. In-process sysctl (CTL_NET, PF_ROUTE, 0, 0, NET_RT_FLAGS, RTF_LLINFO) con ctypes
2. /usr/sbin/arp -an da sottoprocesso
3. arp -n <gateway_ip> mirato
4. /usr/sbin/ndp -an per vicini IPv6
5. Query NetBIOS Node Status (RFC 1002, UDP 137) con estrazione UNIT ID
6. Estrazione EUI-64 da indirizzi IPv6 link-local

Stampa ambiente di esecuzione (sys.executable, sys.version, parent process),
codici di uscita, byte di output, snippet di errore e numero di voci interpretate.
"""

import sys
import os
import re
import socket
import struct
import subprocess
import ctypes
from typing import Dict, List, Any, Optional, Tuple


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.adapters.macos import normalize_mac, parse_sysctl_arp_data
from core.oui_data import lookup_vendor


def get_parent_process_name() -> str:
    """Restituisce il nome dell'applicazione / processo padre (es. Terminal.app, iTerm2, zsh, Python)."""
    ppid = os.getppid()
    try:
        p = subprocess.run(["ps", "-o", "comm=", "-p", str(ppid)], capture_output=True, text=True, timeout=2.0)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    except Exception:
        pass
    return f"PID {ppid}"


def parse_sysctl_arp_buffer(data: bytes) -> List[Dict[str, str]]:
    """Usa il parser ufficiale condiviso con MacOSAdapter."""
    raw_devices = parse_sysctl_arp_data(data)
    return [{"ip": d["ip"], "mac": d["mac"]} for d in raw_devices]


def test_sysctl() -> Dict[str, Any]:
    res = {"method": "sysctl", "returncode": -1, "stdout_len": 0, "stderr": "", "entries": []}
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
            res["returncode"] = ret
            return res

        buf = ctypes.create_string_buffer(needed.value)
        ret = libc.sysctl(mib, 6, buf, ctypes.byref(needed), None, 0)
        res["returncode"] = ret
        res["stdout_len"] = needed.value
        if ret == 0:
            data = bytes(buf)[:needed.value]
            res["entries"] = parse_sysctl_arp_buffer(data)
    except Exception as e:
        res["stderr"] = str(e)
    return res


def test_arp_an() -> Dict[str, Any]:
    res = {"method": "arp -an", "returncode": -1, "stdout_len": 0, "stderr": "", "entries": []}
    cmd = ["/usr/sbin/arp", "-an"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
        res["returncode"] = p.returncode
        res["stdout_len"] = len(p.stdout)
        res["stderr"] = p.stderr.strip()[:200]
        if p.returncode == 0 and p.stdout:
            for line in p.stdout.splitlines():
                if "(incomplete)" in line.lower():
                    continue
                m_ip = re.search(r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?", line)
                m_mac = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{1,2}(?:-[0-9a-fA-F]{1,2}){5})", line)
                if m_ip and m_mac:
                    ip = m_ip.group(1)
                    mac = normalize_mac(m_mac.group(1))
                    if mac:
                        res["entries"].append({"ip": ip, "mac": mac})
    except Exception as e:
        res["stderr"] = str(e)
    return res


def test_arp_per_host(ip: str) -> Dict[str, Any]:
    res = {"method": f"arp -n {ip}", "returncode": -1, "stdout_len": 0, "stderr": "", "entries": []}
    try:
        subprocess.run(["ping", "-c", "1", "-W", "500", ip], capture_output=True, timeout=1.0)
        p = subprocess.run(["/usr/sbin/arp", "-n", ip], capture_output=True, text=True, timeout=2.0)
        res["returncode"] = p.returncode
        res["stdout_len"] = len(p.stdout)
        res["stderr"] = p.stderr.strip()[:200]
        if p.returncode == 0 and p.stdout and "(incomplete)" not in p.stdout.lower():
            m_mac = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", p.stdout)
            if m_mac:
                mac = normalize_mac(m_mac.group(1))
                if mac:
                    res["entries"].append({"ip": ip, "mac": mac})
    except Exception as e:
        res["stderr"] = str(e)
    return res


def test_ndp() -> Dict[str, Any]:
    res = {"method": "ndp -an", "returncode": -1, "stdout_len": 0, "stderr": "", "entries": []}
    try:
        p = subprocess.run(["/usr/sbin/ndp", "-an"], capture_output=True, text=True, timeout=2.5)
        res["returncode"] = p.returncode
        res["stdout_len"] = len(p.stdout)
        res["stderr"] = p.stderr.strip()[:200]
        if p.returncode == 0 and p.stdout:
            for line in p.stdout.splitlines():
                if "(incomplete)" in line.lower():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip_p = parts[0].split("%")[0].strip()
                    mac = normalize_mac(parts[1].strip())
                    if mac:
                        res["entries"].append({"ip": ip_p, "mac": mac})
    except Exception as e:
        res["stderr"] = str(e)
    return res


def test_netbios(ip: str) -> Dict[str, Any]:
    res = {"method": f"netbios (UDP 137) {ip}", "returncode": 0, "stdout_len": 0, "stderr": "", "entries": []}
    query = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
        res["stdout_len"] = len(data)
        if len(data) > 56:
            num_names = data[56]
            offset = 57 + (num_names * 18)
            if offset + 6 <= len(data):
                mac_bytes = data[offset : offset + 6]
                cand_mac = normalize_mac(':'.join(f'{b:02x}' for b in mac_bytes))
                if cand_mac:
                    res["entries"].append({"ip": ip, "mac": cand_mac})
    except Exception as e:
        res["stderr"] = str(e)
    finally:
        s.close()
    return res


def test_eui64() -> Dict[str, Any]:
    res = {"method": "eui64 (local IPv6)", "returncode": 0, "stdout_len": 0, "stderr": "", "entries": []}
    try:
        p = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=2.0)
        if p.returncode == 0:
            for line in p.stdout.splitlines():
                m = re.search(r"inet6\s+([0-9a-fA-F:]+)(?:%\w+)?", line)
                if m:
                    ip6 = m.group(1)
                    try:
                        packed = socket.inet_pton(socket.AF_INET6, ip6)
                        iid = packed[8:16]
                        if iid[3] == 0xff and iid[4] == 0xfe:
                            b0 = iid[0] ^ 0x02
                            mac = ':'.join(f'{b:02x}' for b in [b0, iid[1], iid[2], iid[5], iid[6], iid[7]])
                            res["entries"].append({"ip": ip6, "mac": mac})
                    except Exception:
                        pass
    except Exception as e:
        res["stderr"] = str(e)
    return res


def find_default_gateway_ip() -> str:
    try:
        p = subprocess.run(["/sbin/route", "-n", "get", "default"], capture_output=True, text=True, timeout=2.0)
        if p.returncode == 0:
            for line in p.stdout.splitlines():
                if line.strip().startswith("gateway:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "192.168.1.1"


def main():
    print("=" * 78)
    print("NETPROBE ARP & NEIGHBOR DIAGNOSTICS (STANDALONE)")
    print("=" * 78)
    print(f"  • sys.executable : {sys.executable}")
    print(f"  • sys.version    : {sys.version.splitlines()[0]}")
    print(f"  • Parent Process : {get_parent_process_name()}")
    gw_ip = find_default_gateway_ip()
    print(f"  • Default Gateway: {gw_ip}")
    print("-" * 78)

    methods = [
        test_sysctl(),
        test_arp_an(),
        test_arp_per_host(gw_ip),
        test_ndp(),
        test_netbios(gw_ip),
        test_eui64()
    ]

    print(f"{'METODO':<28} | {'RET':<5} | {'STDOUT LEN':<12} | {'ENTRIES':<8} | {'SNIPPET / NOTE'}")
    print("-" * 78)
    for m in methods:
        ret_s = str(m["returncode"])
        out_s = f"{m['stdout_len']} B"
        cnt_s = str(len(m["entries"]))
        note = m["stderr"] if m["stderr"] else (f"Esempi: {[e['mac'] for e in m['entries'][:2]]}" if m["entries"] else "")
        print(f"{m['method']:<28} | {ret_s:<5} | {out_s:<12} | {cnt_s:<8} | {note}")

    print("=" * 78)


if __name__ == "__main__":
    main()
