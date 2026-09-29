from datetime import datetime
from collections import defaultdict
from schemas import Alert

_windows = defaultdict(list)
WINDOW_SIZE = 50

def _window(ip, event):
    if ip:
        _windows[ip].append(event)
        _windows[ip] = _windows[ip][-WINDOW_SIZE:]
        return _windows[ip]
    return [event]

def _alert(rule_name, severity, description, source_ip, event_ids):
    return Alert(
        timestamp=datetime.utcnow().isoformat(),
        rule_name=rule_name, severity=severity,
        description=description, source_ip=source_ip,
        event_ids=",".join(str(i) for i in event_ids) if event_ids else None,
    )

def rule_brute_force(event, window):
    if event.get("event_type") != "ssh_failed":
        return None
    failures = [e for e in window if e.get("event_type") == "ssh_failed"]
    if len(failures) >= 5:
        return _alert("Brute Force Detected", "critical",
            f"SSH brute force: {len(failures)} failed logins from {event.get('source_ip')}",
            event.get("source_ip"), [e.get("id") for e in failures[-5:]])
    return None

def rule_port_scan(event, window):
    ports = {e.get("dest_port") for e in window if e.get("dest_port")}
    if len(ports) >= 10:
        return _alert("Port Scan Detected", "high",
            f"Port scan: {len(ports)} ports probed from {event.get('source_ip')}",
            event.get("source_ip"), None)
    return None

def rule_http_flood(event, window):
    if event.get("event_type") not in ("http_request", "http_error"):
        return None
    http_events = [e for e in window if e.get("event_type") in ("http_request", "http_error")]
    if len(http_events) >= 30:
        return _alert("HTTP Flood Detected", "high",
            f"HTTP flood: {len(http_events)} requests from {event.get('source_ip')}",
            event.get("source_ip"), None)
    return None

def rule_firewall_block(event, window):
    if event.get("event_type") == "firewall" and event.get("severity") == "high":
        return _alert("Firewall Block", "medium",
            f"Firewall blocked traffic from {event.get('source_ip')} to port {event.get('dest_port')}",
            event.get("source_ip"), [event.get("id")])
    return None

def rule_ai_anomaly(event, window):
    """Fire alert when AI model flags an event as a critical anomaly."""
    if event.get("threat_score", 0) >= 80 and event.get("is_anomaly"):
        return _alert(
            "AI Anomaly Detected", "critical",
            f"AI model flagged suspicious activity from {event.get('source_ip')} "
            f"(threat score: {event.get('threat_score')}, label: {event.get('ai_label')})",
            event.get("source_ip"), [event.get("id")]
        )
    return None

RULES = [rule_brute_force, rule_port_scan, rule_http_flood, rule_firewall_block, rule_ai_anomaly]

def evaluate(event):
    ip = event.get("source_ip")
    window = _window(ip, event)
    alerts = []
    for rule in RULES:
        try:
            result = rule(event, window)
            if result:
                alerts.append(result)
        except Exception:
            pass
    return alerts
