"""
Feature engineering for IDS events.
Converts raw event dicts into numeric vectors for ML models.
"""
from collections import defaultdict, deque
import time

# Risk mappings
HIGH_RISK_PORTS = {22, 23, 3389, 4444, 5900, 6666, 31337, 1337, 8888}
KNOWN_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443}
PROTO_MAP = {"TCP": 1.0, "UDP": 0.5, "ICMP": 0.3}
EVENT_RISK = {
    "ssh_failed": 0.9, "port_scan": 0.95, "firewall_block": 0.7,
    "http_error": 0.5, "dns_query": 0.2, "ssh_accepted": 0.1,
    "http_request": 0.1, "raw": 0.3,
}

# Per-IP sliding window for sequence features (last 60s)
_ip_windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

FEATURE_DIM = 12  # must match extract_features output length


def extract_features(event: dict) -> list[float]:
    """Return a fixed-length numeric feature vector from an event dict."""
    src_ip = event.get("source_ip", "")
    dst_port = int(event.get("dest_port") or 0)
    src_port = int(event.get("source_port") or 0)
    proto = event.get("protocol", "")
    etype = event.get("event_type", "raw")
    now = time.time()

    # Update per-IP window
    win = _ip_windows[src_ip]
    win.append({"t": now, "port": dst_port, "type": etype})

    # Sequence features over last 60s
    recent = [e for e in win if now - e["t"] <= 60]
    recent_count = len(recent)
    unique_ports = len({e["port"] for e in recent})
    ssh_fail_count = sum(1 for e in recent if e["type"] == "ssh_failed")

    return [
        float(dst_port),
        float(src_port),
        1.0 if dst_port in HIGH_RISK_PORTS else 0.0,
        1.0 if dst_port not in KNOWN_PORTS and dst_port > 0 else 0.0,
        EVENT_RISK.get(etype, 0.3),
        PROTO_MAP.get(proto, 0.0),
        float(min(recent_count, 100)) / 100.0,   # normalized burst rate
        float(min(unique_ports, 50)) / 50.0,      # port diversity (scan indicator)
        float(min(ssh_fail_count, 20)) / 20.0,    # brute-force indicator
        1.0 if etype == "ssh_failed" else 0.0,
        1.0 if etype == "port_scan" else 0.0,
        1.0 if etype == "firewall_block" else 0.0,
    ]
