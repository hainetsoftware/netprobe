# OS Parser Fixtures

This directory contains command output fixtures used to test OS-specific adapters and parsers.

## macOS (`tests/fixtures/os/macos/`) - **VERIFIED**
Captured live from this macOS development machine (Apple Silicon M-series, macOS Sequoia 15 / Darwin 24+):
- `ifconfig.txt`: Real output of `/sbin/ifconfig`
- `arp_an.txt`: Real output of `/usr/sbin/arp -an`
- `route_get_default.txt`: Real output of `/sbin/route -n get default`
- `scutil_dns.txt`: Real output of `/usr/sbin/scutil --dns`
- `ipconfig_getpacket.txt`: Real output of `/usr/sbin/ipconfig getpacket en0`
- `networksetup.txt`: Real output of `networksetup -listallhardwareports`
- `networksetup_getmacaddress.txt`: Real output of `networksetup -getmacaddress en0`
- `system_profiler.txt`: Real output of `/usr/sbin/system_profiler SPNetworkDataType`

## Linux (`tests/fixtures/os/linux/`) - **UNVERIFIED**
Synthesized from documented Linux formats (iproute2, procfs, NetworkManager resolv.conf).
Status: `unverified` (no native Linux dev machine available; tested in CI).

## Windows (`tests/fixtures/os/windows/`) - **UNVERIFIED**
Synthesized from documented Windows PowerShell (`Get-NetRoute`, `Get-NetAdapter`) and `arp -a` formats.
Status: `unverified` (no native Windows dev machine available; tested in CI).
