import re
from datetime import datetime
from schemas import LogEvent

# Regex patterns for common log formats
PATTERNS = {
    "apache": re.compile(
        r'(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\S+)'
    ),
    "syslog": re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\d+:\d+:\d+) (?P<host>\S+) '
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<message>.+)'
    ),
    "ssh": re.compile(
        r'(?P<status>Failed|Accepted|Invalid) (?:password|publickey|user) '
        r'(?:for(?: invalid user)? )?(?P<user>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)'
    ),
    "iptables": re.compile(
        r'SRC=(?P<source_ip>\S+) DST=(?P<dest_ip>\S+) .*?'
        r'PROTO=(?P<protocol>\S+)(?: SPT=(?P<source_port>\d+))?(?: DPT=(?P<dest_port>\d+))?'
    ),
}

def _classify_severity(event_type: str, parsed: dict) -> str:
    if event_type in ("ssh_failed", "brute_force", "port_scan"):
        return "high"
    if event_type == "ssh_accepted":
        return "low"
    status = parsed.get("status", "")
    if str(status).startswith("5"):
        return "high"
    if str(status).startswith("4"):
        return "medium"
    return "info"

def parse_apache(line: str) -> dict:
    m = PATTERNS["apache"].search(line)
    if not m:
        return {}
    d = m.groupdict()
    try:
        ts = datetime.strptime(d["timestamp"], "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except Exception:
        ts = datetime.utcnow().isoformat()
    event_type = "http_error" if int(d["status"]) >= 400 else "http_request"
    return {
        "timestamp": ts, "source_ip": d["source_ip"],
        "dest_port": 80, "protocol": "TCP",
        "event_type": event_type,
        "parsed_data": f"method={d['method']} path={d['path']} status={d['status']}",
    }

def parse_syslog(line: str) -> dict:
    ssh_m = PATTERNS["ssh"].search(line)
    if ssh_m:
        d = ssh_m.groupdict()
        event_type = "ssh_failed" if d["status"] == "Failed" else "ssh_accepted"
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": d["source_ip"],
            "dest_port": int(d["port"]),
            "protocol": "TCP",
            "event_type": event_type,
            "parsed_data": f"user={d['user']} status={d['status']}",
        }
    m = PATTERNS["syslog"].search(line)
    if not m:
        return {}
    d = m.groupdict()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "syslog",
        "parsed_data": f"host={d['host']} process={d['process']} msg={d['message'][:100]}",
    }

def parse_iptables(line: str) -> dict:
    m = PATTERNS["iptables"].search(line)
    if not m:
        return {}
    d = m.groupdict()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": d.get("source_ip"),
        "dest_ip": d.get("dest_ip"),
        "source_port": int(d["source_port"]) if d.get("source_port") else None,
        "dest_port": int(d["dest_port"]) if d.get("dest_port") else None,
        "protocol": d.get("protocol"),
        "event_type": "firewall",
        "parsed_data": line[:200],
    }

PARSERS = {
    "apache": parse_apache,
    "syslog": parse_syslog,
    "iptables": parse_iptables,
}

def normalize(source: str, line: str) -> LogEvent:
    parser = PARSERS.get(source, lambda l: {})
    parsed = parser(line)
    event_type = parsed.get("event_type", "raw")
    severity = _classify_severity(event_type, parsed)
    return LogEvent(
        timestamp=parsed.get("timestamp", datetime.utcnow().isoformat()),
        source_ip=parsed.get("source_ip"),
        dest_ip=parsed.get("dest_ip"),
        source_port=parsed.get("source_port"),
        dest_port=parsed.get("dest_port"),
        protocol=parsed.get("protocol"),
        event_type=event_type,
        severity=severity,
        raw_log=line,
        parsed_data=parsed.get("parsed_data"),
    )
