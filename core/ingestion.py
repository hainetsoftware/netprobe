"""Convert diagnostic reports to bounded, semantic training observations."""
import hashlib
import ipaddress
import logging
import math
import re
import time


logger = logging.getLogger(__name__)


def ingest_report(report, storage=None):
    """Persist one completed scan, returning its row ID or None on cache failure.

    This is a best-effort finalization boundary: failures must never alter the
    diagnostic report or escape into the CLI/TUI. Exporting an existing report
    does not call this function again.
    """
    try:
        if storage is None:
            from core.storage import StorageManager
            storage = StorageManager()
        return storage.store_telemetry_run(report)
    except Exception as error:
        logger.debug("[NetProbe] Avviso: salvataggio telemetry in cache locale fallito: %s", error)
        return None


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def prepare_telemetry(report, salt):
    system = report.get('system') or {}
    lan = report.get('lan') or {}
    wan = report.get('wan') or {}
    perf = report.get('performance') or {}
    interface = lan.get('primary_interface') or {}
    gateway = perf.get('gateway_latency') or {}
    buffer = perf.get('bufferbloat') or {}
    speed = perf.get('speed') or {}
    physical = (report.get('estimations') or {}).get('physical_medium') or {}
    bng = physical.get('bng_hop') or (report.get('ixp') or {}).get('hop2_bng') or {}

    def throughput(direction):
        transfer = speed.get(direction) or {}
        return number(transfer.get('mbps') if 'mbps' in transfer else speed.get(direction + '_mbps'))

    floor = number(bng.get('min_ms'))
    valid = bool(bng) and floor is not None and bool(bng.get('ip'))
    # Quick scans deliberately skip throughput. Full scans need both directions.
    if not report.get('quick_scan', False):
        valid = valid and throughput('download') is not None and throughput('upload') is not None
    for direction in ('download', 'upload'):
        transfer = speed.get(direction) or {}
        if transfer.get('valid') is False or transfer.get('complete') is False:
            valid = False
        if transfer.get('error') or transfer.get('timed_out') or transfer.get('incomplete'):
            valid = False
    if speed.get('valid') is False or speed.get('errors') or speed.get('error') or speed.get('timed_out') or speed.get('incomplete'):
        valid = False
    limits = ((buffer.get('download_delta_ms'), 35), (buffer.get('upload_delta_ms'), 45),
              (gateway.get('iqr_ms'), 8), (bng.get('iqr_ms'), 15), (bng.get('spike_fraction'), .20))
    congested = any(number(value) is not None and number(value) > limit for value, limit in limits)
    # Malformed supplied metrics must never silently become clean training data.
    for source, keys in ((bng, ('min_ms', 'iqr_ms', 'spread_ms', 'spike_fraction')),
                         (gateway, ('min_ms', 'iqr_ms')), (buffer, ('download_delta_ms', 'upload_delta_ms'))):
        if any(source.get(key) is not None and number(source[key]) is None for key in keys):
            valid = False
    if number(bng.get('spike_fraction')) is not None and bng['spike_fraction'] > 1:
        valid = False
    prefix = None
    try:
        # Prefer the scanned LAN subnet, preserving its configured prefix length.
        address = interface.get('ipv4')
        if address:
            cidr = str(address) if '/' in str(address) else '{}/{}'.format(
                address, interface.get('netmask') or interface.get('prefix_length') or 24)
            prefix = str(ipaddress.ip_network(cidr, strict=False))
        else:
            # Compatibility with captures predating LAN subnet metadata.
            address = ipaddress.ip_address(wan.get('public_ipv4') or wan.get('public_ipv6') or wan.get('public_ip'))
            prefix = str(ipaddress.ip_network(f'{address}/{24 if address.version == 4 else 48}', strict=False))
    except (ValueError, TypeError):
        pass
    asn_match = re.fullmatch(r'(?:AS)?(\d+)', str(wan.get('asn') or ''), re.IGNORECASE)
    asn = int(asn_match[1]) if asn_match else None
    if asn is not None and not 0 < asn <= 4294967295:
        asn = None
    timestamp = number(report.get('timestamp'))
    timestamp = timestamp if timestamp is not None else time.time()
    return dict(timestamp=timestamp,
                formatted_time=str(report.get('formatted_time') or time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))),
                host_hash=hashlib.sha256((str(system.get('hostname') or '') + salt).encode()).hexdigest(),
                os_family=str(system.get('os') or 'unknown'), kernel_release=system.get('pretty_os') or system.get('os_release'),
                interface_name=str(lan.get('primary_interface_name') or interface.get('name') or 'unknown'),
                interface_type=str(lan.get('interface_type') or interface.get('type') or 'unknown'),
                public_asn=asn, public_isp=wan.get('isp'), subnet_prefix=prefix,
                gateway_ip=(lan.get('gateway') or {}).get('ipv4'), gateway_min_ms=number(gateway.get('min_ms')),
                gateway_vendor=(lan.get('gateway') or {}).get('vendor'),
                gateway_model=(lan.get('gateway') or {}).get('model'),
                gateway_http_server=(lan.get('gateway') or {}).get('http_server'),
                gateway_iqr_ms=number(gateway.get('iqr_ms')), bng_ip=bng.get('ip'), bng_floor_ms=floor,
                bng_spread_ms=number(bng.get('spread_ms')), bng_iqr_ms=number(bng.get('iqr_ms')),
                bng_spike_fraction=number(bng.get('spike_fraction')),
                download_mbps=throughput('download'), upload_mbps=throughput('upload'),
                bufferbloat_grade=buffer.get('grade'), bufferbloat_delta_ms=number(buffer.get('download_delta_ms')),
                is_congested=int(congested), is_valid=int(valid),
                predicted_medium=str(physical.get('predicted_medium') or 'unknown'),
                confidence_pct=min(100.0, number(physical.get('confidence_pct')) or 0.0))
