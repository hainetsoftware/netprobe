"""Path-scoped latency bounds; raw ICMP measurements are never modified."""
import math


def min_rtt(metrics):
    values = [metrics.get(k) for k in ('min_ms', 'rtt_ms')]
    values.extend(metrics.get('rtts') or [])
    valid = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)
             and math.isfinite(v) and v >= 0]
    if not valid:
        median = metrics.get('median_ms')
        return median if isinstance(median, (int, float)) and math.isfinite(median) and median >= 0 else None
    return min(valid)


def bound_path_rtts(hops, dedicated=None, target=None, target_rtt=None):
    """Return copies with effective RTTs bounded only by downstream observations.

    A target ping is eligible only if the target was actually reached in this
    trace. Asymmetric routes can also cause inversions: CoPP is a diagnostic
    inference, not proof of the router's policing configuration.
    """
    dedicated = dedicated or {}
    downstream = None
    result = []
    for hop in reversed(sorted(hops, key=lambda h: h.get('hop', 0))):
        raw = min_rtt(hop)
        ping = min_rtt(dedicated.get(hop.get('ip'), {}))
        candidates = [v for v in (raw, ping, downstream) if v is not None]
        if target and hop.get('ip') == target and target_rtt is not None:
            candidates.append(target_rtt)
        effective = min(candidates) if candidates else None
        clamped = raw is not None and effective is not None and effective < raw
        result.append(dict(hop, effective_rtt_ms=effective, copp_detected=clamped))
        downstream = effective
    return list(reversed(result))
