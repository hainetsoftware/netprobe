"""Privilege inspection; network probes always use bounded native commands."""
import os
import sys


def is_elevated():
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def announce_restrictions():
    if not is_elevated():
        print('[NetProbe] Avviso: esecuzione senza privilegi di amministratore/root.', file=sys.stderr)
        print('[NetProbe] Le operazioni di rete a basso livello utilizzeranno i tool di sistema non privilegiati.', file=sys.stderr)
