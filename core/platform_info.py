"""
Utility per rilevamento sistema operativo, esecuzione sicura comandi di sistema
e compatibilità multipiattaforma (macOS, Windows, Linux).
"""

import sys
import os
import subprocess
import shutil
import platform
from typing import Optional, List, Tuple
from core.system_info import get_pretty_os_info

def get_os_type() -> str:
    """Restituisce 'macos', 'windows', o 'linux'."""
    s = sys.platform.lower()
    if "darwin" in s:
        return "macos"
    elif "win" in s:
        return "windows"
    else:
        return "linux"

def is_macos() -> bool:
    return get_os_type() == "macos"

def is_windows() -> bool:
    return get_os_type() == "windows"

def is_linux() -> bool:
    return get_os_type() == "linux"

def is_root() -> bool:
    """Verifica se l'applicazione è in esecuzione con privilegi elevati (root/admin)."""
    from core.privileges import is_elevated
    return is_elevated()


def has_command(cmd_name: str) -> bool:
    """Verifica se un comando o binario è disponibile nel PATH di sistema."""
    return shutil.which(cmd_name) is not None

def _kill_and_reap(proc):
    """Bound cleanup even if a descendant inherited the subprocess pipes."""
    proc.kill()
    try:
        proc.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        for stream in (proc.stdout, proc.stderr):
            if stream:
                stream.close()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass


def run_cmd(args: List[str], timeout: float = 6.0) -> Tuple[int, str, str]:
    """
    Esegue un comando di sistema in modo sicuro e sincrono con timeout.
    Ritorna (returncode, stdout_text, stderr_text).
    """
    try:
        kwargs = {}
        if is_windows():
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        _kill_and_reap(proc)
        return -1, "", "Timeout scaduto"
    except FileNotFoundError:
        return 127, "", f"Comando '{args[0]}' non trovato"
    except Exception as e:
        return -2, "", str(e)

def run_cmd_shell(cmd_str: str, timeout: float = 6.0) -> Tuple[int, str, str]:
    """
    Esegue una stringa di comando tramite shell (utile per pipeline o comandi complessi).
    """
    try:
        kwargs = {}
        if is_windows():
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        proc = subprocess.Popen(
            cmd_str,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        _kill_and_reap(proc)
        return -1, "", "Timeout scaduto"
    except Exception as e:
        return -2, "", str(e)

def get_system_summary() -> dict:
    """Restituisce informazioni sommarie sull'host locale."""
    return {
        "os": platform.system(),
        "pretty_os": get_pretty_os_info(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "python_version": sys.version.split()[0],
        "is_root": is_root()
    }
