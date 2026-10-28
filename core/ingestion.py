"""Convert diagnostic reports to bounded, semantic training observations."""
import hashlib
import ipaddress
import math
import re
import time


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
    bng = (report.get('ixp') or {}).get('hop2_bng') or {}
    buffer = perf.get('bufferbloat') or {}
    speed = perf.get('speed') or {}
    physical = (report.get('estimations') or {}).get('physical_medium') or {}
    floor = number(bng.get('min_ms'))
    valid = bool(bng) and floor is not None and bool(bng.get('ip'))
    # Quick scans deliberately skip throughput. Full scans need both directions.
    if not report.get('quick_scan', False):
        valid = valid and number(speed.get('download_mbps')) is not None and number(speed.get('upload_mbps')) is not None
    for direction in ('download', 'upload'):
        transfer = speed.get(direction) or {}
        if transfer.get('valid') is False or transfer.get('complete') is False:
            valid = False
        if transfer.get('error') or transfer.get('timed_out') or transfer.get('incomplete'):
            valid = False
    if speed.get('valid') is False or speed.get('errors') or speed.get('error') or speed.get('timed_out') or speed.get('incomplete'):
        valid = False
    limits = ((buffer.get('download_delta_ms'), 45), (buffer.get('upload_delta_ms'), 45),
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
        address = ipaddress.ip_address(wan.get('public_ipv4') or wan.get('public_ipv6') or wan.get('public_ip'))
        prefix = str(ipaddress.ip_network(f'{address}/{24 if address.version == 4 else 48}', strict=False))
    except (ValueError, TypeError):
        pass
    asn_match = re.fullmatch(r'(?:AS)?(\d+)', str(wan.get('asn') or ''), re.IGNORECASE)
    asn = int(asn_match[1]) if asn_match else None
    if asn is not None and not 0 < asn <= 4294967295:
        asn = None
    deltas = [number(buffer.get(key)) for key in ('download_delta_ms', 'upload_delta_ms')]
    deltas = [value for value in deltas if value is not None]
    timestamp = number(report.get('timestamp'))
    timestamp = timestamp if timestamp is not None else time.time()
    return dict(timestamp=timestamp,
                formatted_time=str(report.get('formatted_time') or time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))),
                host_hash=hashlib.sha256((str(system.get('hostname') or '') + salt).encode()).hexdigest(),
                os_family=str(system.get('os') or 'unknown'), kernel_release=system.get('os_release'),
                interface_name=str(interface.get('name') or 'unknown'),
                interface_type=str(lan.get('interface_type') or interface.get('type') or 'unknown'),
                public_asn=asn, public_isp=wan.get('isp'), subnet_prefix=prefix,
                gateway_ip=(lan.get('gateway') or {}).get('ipv4'), gateway_min_ms=number(gateway.get('min_ms')),
                gateway_iqr_ms=number(gateway.get('iqr_ms')), bng_ip=bng.get('ip'), bng_floor_ms=floor,
                bng_spread_ms=number(bng.get('spread_ms')), bng_iqr_ms=number(bng.get('iqr_ms')),
                bng_spike_fraction=number(bng.get('spike_fraction')),
                download_mbps=number(speed.get('download_mbps')), upload_mbps=number(speed.get('upload_mbps')),
                bufferbloat_grade=buffer.get('grade'), bufferbloat_delta_ms=max(deltas) if deltas else None,
                is_congested=int(congested), is_valid=int(valid),
                predicted_medium=str(physical.get('predicted_medium') or 'unknown'),
                confidence_pct=min(100.0, number(physical.get('confidence_pct')) or 0.0))
