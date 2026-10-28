"""Human-readable platform names and shared report header bindings."""

import os
import platform
import plistlib
import subprocess
import sys


def _macos_version():
    version = platform.mac_ver()[0]
    if not version:
        try:
            version = subprocess.run(
                ['/usr/bin/sw_vers', '-productVersion'], capture_output=True,
                text=True, timeout=3, check=True,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    if not version:
        try:
            with open('/System/Library/CoreServices/SystemVersion.plist', 'rb') as source:
                version = plistlib.load(source).get('ProductVersion', '')
        except (OSError, ValueError, plistlib.InvalidFileException):
            pass
    return version


def _linux_name():
    try:
        release = platform.freedesktop_os_release()
    except (AttributeError, OSError):
        release = {}
        try:
            with open('/etc/os-release', encoding='utf-8') as source:
                for line in source:
                    key, separator, value = line.strip().partition('=')
                    if separator and key in ('PRETTY_NAME', 'NAME', 'VERSION_ID'):
                        release[key] = value.strip().strip('\"\'')
        except OSError:
            pass
    return release.get('PRETTY_NAME') or ' '.join(
        value for value in (release.get('NAME', 'Linux'), release.get('VERSION_ID')) if value
    )


def _windows_name(major, minor, build, service_pack=''):
    version = {(6, 1): '7', (6, 2): '8', (6, 3): '8.1'}.get((major, minor))
    if major >= 10:
        version = '11' if build >= 22000 else '10'
    name = 'Windows' + (f' {version}' if version else '')
    if service_pack:
        name += f' {service_pack}'
    if build:
        name += f' Build {build}'
    return name


def get_pretty_os_info(system_info=None):
    """Resolve the local OS, or format saved metadata without probing this host."""
    if system_info is not None:
        if system_info.get('pretty_os'):
            return system_info['pretty_os']
        system = system_info.get('os') or ''
        arch = system_info.get('machine') or system_info.get('arch') or ''
        release = system_info.get('os_release') or ''
        if system == 'Darwin':
            name = ' '.join(x for x in ('macOS', system_info.get('macos_version')) if x)
        elif system == 'Linux':
            name = system_info.get('distro') or 'Linux'
            arch = ' '.join(x for x in (release, arch) if x)
        else:
            name = ' '.join(x for x in (system, release) if x) or 'N/D'
        return f'{name} ({arch})' if arch else name

    system = platform.system()
    arch = platform.machine() or os.environ.get('PROCESSOR_ARCHITEW6432') or os.environ.get('PROCESSOR_ARCHITECTURE', '')
    if system == 'Darwin':
        name = ' '.join(x for x in ('macOS', _macos_version()) if x)
    elif system == 'Linux':
        name = _linux_name()
        arch = ' '.join(x for x in (platform.release(), arch) if x)
    elif system == 'Windows':
        release, version, service_pack, _ = platform.win32_ver()
        parts = [int(p) for p in version.split('.') if p.isdigit()]
        major, minor, build = (parts + [0, 0, 0])[:3]
        try:
            windows = sys.getwindowsversion()
            major, minor, build = getattr(windows, 'platform_version', None) or (
                windows.major, windows.minor, windows.build)
            service_pack = windows.service_pack or service_pack
        except (AttributeError, OSError):
            pass
        name = _windows_name(major, minor, build, service_pack)
        if not major and release:
            name = f'Windows {release}'
    else:
        name = system or 'N/D'
    return f'{name} ({arch})' if arch else name


def format_system_header(system, lan=None):
    """Bind the same canonical fields in CLI, TUI and report summaries."""
    header = (f"Host: {system.get('hostname') or 'N/D'} | OS: {get_pretty_os_info(system)}"
              f" | Python: {system.get('python_version') or system.get('python') or 'N/D'}")
    if lan is not None:
        interface = lan.get('primary_interface') or {}
        name = interface.get('name') or lan.get('primary_interface_name') or 'N/D'
        kind = lan.get('interface_type') or interface.get('type') or 'N/D'
        header += f' | Interfaccia: {name} ({kind})'
    return header
