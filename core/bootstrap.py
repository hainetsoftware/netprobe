"""Standard-library-only runtime dependency provisioning before application imports."""
import importlib.util
from importlib import metadata
import re
import os
import platform
import subprocess
import sys

# Distribution names and import names differ for dnspython.
REQUIRED = {'dns': 'dnspython>=2.6.0', 'psutil': 'psutil>=5.9.0',
            'zeroconf': 'zeroconf>=0.130.0', 'textual': 'textual>=0.89.1'}

# Last compatible runtime line for Windows 7 / Python 3.8.
if sys.version_info < (3, 9):
    REQUIRED.update({'dns': 'dnspython==2.6.1', 'psutil': 'psutil==5.9.8',
                     'zeroconf': 'zeroconf==0.130.0', 'textual': 'textual==0.89.1'})


def missing_packages():
    missing = []
    for module, package in REQUIRED.items():
        try:
            available = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            available = False
        if available:
            distribution, operator, minimum = re.split(r'(>=|==)', package)
            try:
                installed = metadata.version(distribution)
                def parts(version):
                    match = re.match(r'\d+(?:\.\d+)*', version)
                    return tuple(int(part) for part in match[0].split('.')) if match else ()
                current = (parts(installed) + (0, 0, 0))[:3]
                required = (parts(minimum) + (0, 0, 0))[:3]
                available = current == required if operator == '==' else current >= required
            except metadata.PackageNotFoundError:
                # A source checkout without distribution metadata can still work.
                pass
        if not available:
            missing.append(package)
    return missing


def _run(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            print('[NetProbe] ' + (result.stderr or result.stdout or 'Comando fallito')[-1600:].strip(), file=sys.stderr)
        return result.returncode == 0, (result.stderr or '')
    except (OSError, subprocess.SubprocessError) as error:
        print('[NetProbe] ' + str(error), file=sys.stderr)
        return False, str(error)


def _manual_help(packages):
    names = [package.split('>=')[0].split('==')[0] for package in packages]
    print('[NetProbe] Installazione automatica non riuscita. Comandi suggeriti:', file=sys.stderr)
    if platform.system() == 'Windows':
        commands = ['py -m pip install ' + ' '.join(names)]
    elif platform.system() == 'Darwin':
        commands = ['brew install python', 'python3 -m venv ~/.netprobe/venv',
                    '~/.netprobe/venv/bin/python -m pip install ' + ' '.join(names)]
    else:
        # Package-manager names aren't always equal to PyPI distribution names.
        debian = {'dnspython': 'dnspython', 'textual': 'textual'}
        arch = {'dnspython': 'dnspython'}
        commands = ['sudo apt install ' + ' '.join('python3-' + debian.get(n, n) for n in names),
                    'sudo pacman -S ' + ' '.join('python-' + arch.get(n, n) for n in names)]
    for command in commands:
        print('  ' + command, file=sys.stderr)


def ensure_dependencies():
    packages = missing_packages()
    if not packages:
        return
    print('[NetProbe] Configurazione iniziale: rilevate dipendenze mancanti.', file=sys.stderr)
    print('[NetProbe] Pacchetti richiesti: ' + ', '.join(packages), file=sys.stderr)
    print('[NetProbe] Tentativo di installazione automatica tramite pip...', file=sys.stderr)
    in_venv = sys.prefix != sys.base_prefix
    command = [sys.executable, '-m', 'pip', 'install', '--quiet']
    if not in_venv:
        command.append('--user')
    success, error = _run(command + packages)
    if not success and ('No module named pip' in error or 'No module named' in error and 'pip' in error):
        print('[NetProbe] pip assente: inizializzazione tramite ensurepip...', file=sys.stderr)
        provisioned, _ = _run([sys.executable, '-m', 'ensurepip', '--default-pip'] + ([] if in_venv else ['--user']))
        if provisioned:
            success, error = _run(command + packages)
    if success:
        importlib.invalidate_caches()
        # Refresh user site paths: pip may have just created the directory.
        import site
        if site.ENABLE_USER_SITE:
            site.addsitedir(site.getusersitepackages())
        if not missing_packages():
            print('[NetProbe] Dipendenze installate. Avvio diagnostica.', file=sys.stderr)
            return
    # A private user venv is the PEP 668-safe fallback. Never mutate system Python.
    if not os.environ.get('NETPROBE_BOOTSTRAPPED'):
        from core.storage import data_directory
        env_dir = data_directory() / 'runtime-venv'
        print('[NetProbe] Tentativo tramite ambiente virtuale utente: ' + str(env_dir), file=sys.stderr)
        try:
            env_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            created, _ = _run([sys.executable, '-m', 'venv', str(env_dir)])
        except OSError as error:
            print('[NetProbe] Ambiente utente non disponibile: ' + str(error), file=sys.stderr)
            created = False
        executable = env_dir / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        if created:
            installed, _ = _run([str(executable), '-m', 'pip', 'install', '--quiet', *REQUIRED.values()])
            if installed:
                environment = dict(os.environ, NETPROBE_BOOTSTRAPPED='1')
                print('[NetProbe] Riavvio con le dipendenze nell’ambiente utente.', file=sys.stderr)
                try:
                    os.execve(str(executable), [str(executable), *sys.argv], environment)
                except OSError as error:
                    print('[NetProbe] Riavvio fallito: ' + str(error), file=sys.stderr)
    _manual_help(packages)
    raise SystemExit(1)
