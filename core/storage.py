"""Private, transactional SQLite cache. Connections never cross worker threads."""
import json
import os
from pathlib import Path
import platform
import secrets
import sqlite3
from contextlib import contextmanager

THEMES = ('midnight-slate', 'monochrome-light', 'oled-black', 'nordic-frost')


def data_directory():
    home = Path.home()
    family = platform.system()
    if family == 'Linux':
        base = Path(os.environ.get('XDG_DATA_HOME') or home / '.local/share')
        return (base if base.is_absolute() else home / '.local/share') / 'netprobe'
    if family == 'Darwin':
        return home / 'Library/Application Support/NetProbe'
    if family == 'Windows' and os.environ.get('LOCALAPPDATA'):
        return Path(os.environ['LOCALAPPDATA']) / 'NetProbe'
    return home / '.netprobe'


SCHEMA = '''
CREATE TABLE IF NOT EXISTS app_config (
 key TEXT PRIMARY KEY, value TEXT NOT NULL,
 updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS telemetry_runs (
 run_id INTEGER PRIMARY KEY AUTOINCREMENT,
 timestamp REAL NOT NULL, formatted_time TEXT NOT NULL,
 host_hash TEXT NOT NULL, os_family TEXT NOT NULL, kernel_release TEXT,
 interface_name TEXT NOT NULL, interface_type TEXT NOT NULL,
 public_asn INTEGER, public_isp TEXT, subnet_prefix TEXT, gateway_ip TEXT,
 gateway_min_ms REAL, gateway_iqr_ms REAL,
 bng_ip TEXT, bng_floor_ms REAL, bng_spread_ms REAL, bng_iqr_ms REAL,
 bng_spike_fraction REAL, download_mbps REAL, upload_mbps REAL,
 bufferbloat_grade TEXT, bufferbloat_delta_ms REAL,
 is_congested INTEGER NOT NULL, is_valid INTEGER NOT NULL,
 predicted_medium TEXT NOT NULL, confidence_pct REAL NOT NULL,
 statistical_weight REAL NOT NULL DEFAULT 1.0,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_telemetry_asn_medium ON telemetry_runs(public_asn, predicted_medium);
CREATE INDEX IF NOT EXISTS idx_telemetry_subnet ON telemetry_runs(subnet_prefix, timestamp);
'''


class StorageManager:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else data_directory() / 'netprobe.db'
        try:
            self._prepare_path(restrict_parent=db_path is None)
        except OSError:
            if db_path is not None or self.db_path == Path.home() / '.netprobe/netprobe.db':
                raise
            self.db_path = Path.home() / '.netprobe/netprobe.db'
            self._prepare_path(restrict_parent=True)
        with self.connection() as db:
            db.executescript(SCHEMA)
            columns = {row[1] for row in db.execute('PRAGMA table_info(telemetry_runs)')}
            if 'statistical_weight' not in columns:
                db.execute('ALTER TABLE telemetry_runs ADD COLUMN statistical_weight REAL NOT NULL DEFAULT 1.0')
            db.execute('INSERT OR IGNORE INTO app_config(key,value) VALUES (?,?)',
                       ('host_salt', json.dumps(secrets.token_hex(32))))

    def _prepare_path(self, restrict_parent):
        parent_existed = self.db_path.parent.exists()
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != 'nt' and (restrict_parent or not parent_existed):
            self.db_path.parent.chmod(0o700)
        # Pre-create privately so the WAL and SHM inherit restrictive access.
        fd = os.open(str(self.db_path), os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        if os.name != 'nt':
            self.db_path.chmod(0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(str(self.db_path), timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=NORMAL')
            db.execute('PRAGMA foreign_keys=ON')
            with db:
                yield db
        finally:
            db.close()

    def get_setting(self, key, default=None):
        with self.connection() as db:
            row = db.execute('SELECT value FROM app_config WHERE key=?', (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except (ValueError, TypeError):
            return default

    def set_setting(self, key, value):
        encoded = json.dumps(value, allow_nan=False)
        with self.connection() as db:
            db.execute('INSERT OR REPLACE INTO app_config(key,value,updated_at) VALUES (?,?,CURRENT_TIMESTAMP)',
                       (key, encoded))

    def get_theme(self, default='midnight-slate'):
        theme = self.get_setting('theme', default)
        return theme if theme in THEMES else default

    def set_theme(self, theme_name):
        if theme_name not in THEMES:
            raise ValueError('Unknown theme: ' + str(theme_name))
        self.set_setting('theme', theme_name)

    def store_telemetry_run(self, run_dict):
        from core.ingestion import prepare_telemetry
        with self.connection() as db:
            # Serialize salt resolution, subnet counting and insertion across processes.
            db.execute('BEGIN IMMEDIATE')
            salt_row = db.execute("SELECT value FROM app_config WHERE key='host_salt'").fetchone()
            salt = json.loads(salt_row[0]) if salt_row else secrets.token_hex(32)
            if salt_row is None:
                db.execute('INSERT INTO app_config(key,value) VALUES (?,?)', ('host_salt', json.dumps(salt)))
            run = prepare_telemetry(run_dict, salt)
            count = db.execute('SELECT COUNT(*) FROM telemetry_runs WHERE subnet_prefix=? AND timestamp BETWEEN ? AND ?',
                               (run['subnet_prefix'], run['timestamp'] - 7 * 86400, run['timestamp'])).fetchone()[0]
            # First ten observations retain full weight; later observations are capped.
            run['statistical_weight'] = min(1.0, 10.0 / (count + 1)) if run['subnet_prefix'] else 1.0
            columns = ','.join(run)
            placeholders = ','.join('?' for _ in run)
            cursor = db.execute(f'INSERT INTO telemetry_runs ({columns}) VALUES ({placeholders})', tuple(run.values()))
            return cursor.lastrowid

    def baseline_runs(self):
        """Only these observations may train future baseline models."""
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                'SELECT * FROM telemetry_runs WHERE is_valid=1 AND is_congested=0 AND bng_floor_ms IS NOT NULL')]

    def status(self):
        with self.connection() as db:
            row = db.execute('SELECT COUNT(*), COALESCE(SUM(is_valid=1 AND is_congested=0),0), COALESCE(SUM(is_congested),0) FROM telemetry_runs').fetchone()
        size = sum(p.stat().st_size for p in (self.db_path, Path(str(self.db_path)+'-wal'), Path(str(self.db_path)+'-shm')) if p.exists())
        return dict(path=str(self.db_path), size_kb=round(size/1024, 1), total=row[0], clean=row[1], congested=row[2], theme=self.get_theme())

    def clean_invalids(self):
        with self.connection() as db:
            return db.execute('DELETE FROM telemetry_runs WHERE is_valid=0').rowcount

    def reset_telemetry(self):
        with self.connection() as db:
            db.execute('DELETE FROM telemetry_runs')

    def factory_reset(self):
        with self.connection() as db:
            db.execute('DELETE FROM telemetry_runs')
            db.execute('DELETE FROM app_config')

    def export_anonymized(self, path):
        # Deliberately omit stable host IDs, network addresses, ISP and exact times.
        fields = ('os_family', 'interface_type', 'public_asn', 'gateway_min_ms',
                  'gateway_iqr_ms', 'bng_floor_ms', 'bng_spread_ms', 'bng_iqr_ms',
                  'bng_spike_fraction', 'download_mbps', 'upload_mbps', 'bufferbloat_grade',
                  'bufferbloat_delta_ms', 'is_congested', 'is_valid', 'predicted_medium',
                  'confidence_pct', 'statistical_weight')
        with self.connection() as db:
            rows = db.execute('SELECT ' + ','.join(fields) + ' FROM telemetry_runs').fetchall()
        # Exclusive creation prevents accidental overwrite of existing files.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as target:
            for row in rows:
                target.write(json.dumps(dict(row), allow_nan=False) + '\n')
        return len(rows)
