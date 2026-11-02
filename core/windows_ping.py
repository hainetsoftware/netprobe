"""Bounded, unprivileged Windows echo bursts without ping.exe's one-second gap."""
import time


def echo_burst(host, count, deadline_s, run_cmd):
    """Return individual command outputs and the actual number of probes sent."""
    deadline = time.monotonic() + deadline_s
    outputs = []
    for _ in range(count):
        started = time.monotonic()
        remaining = deadline - started
        if remaining <= 0:
            break
        timeout = min(0.5, remaining)
        _, output, _ = run_cmd(
            ['ping', '-n', '1', '-w', str(max(1, int(timeout * 1000))), host],
            timeout=timeout)
        outputs.append(output)
        pause = min(0.1 - (time.monotonic() - started), deadline - time.monotonic())
        if pause > 0 and len(outputs) < count:
            time.sleep(pause)
    return outputs, len(outputs)
