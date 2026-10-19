"""
Factory per l'adapter OS appropriato alla piattaforma di esecuzione.
"""

from core.platform_info import is_macos, is_windows, is_linux
from core.adapters.base import OSAdapter
from core.adapters.macos import MacOSAdapter
from core.adapters.linux import LinuxAdapter
from core.adapters.windows import WindowsAdapter

_ADAPTER_INSTANCE = None


def get_os_adapter() -> OSAdapter:
    global _ADAPTER_INSTANCE
    if _ADAPTER_INSTANCE is None:
        if is_macos():
            _ADAPTER_INSTANCE = MacOSAdapter()
        elif is_windows():
            _ADAPTER_INSTANCE = WindowsAdapter()
        else:
            _ADAPTER_INSTANCE = LinuxAdapter()
    return _ADAPTER_INSTANCE
