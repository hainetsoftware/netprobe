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
    if is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def has_command(cmd_name: str) -> bool:
    """Verifica se un comando o binario è disponibile nel PATH di sistema."""
    return shutil.which(cmd_name) is not None

def run_cmd(args: List[str], timeout: float = 6.0) -> Tuple[int, str, str]:
    """
    Esegue un comando di sistema in modo sicuro e sincrono con timeout.
    Ritorna (returncode, stdout_text, stderr_text).
    """
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        proc.kill()
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
        proc = subprocess.Popen(
            cmd_str,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Timeout scaduto"
    except Exception as e:
        return -2, "", str(e)

def get_system_summary() -> dict:
    """Restituisce informazioni sommarie sull'host locale."""
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "is_root": is_root()
    }
