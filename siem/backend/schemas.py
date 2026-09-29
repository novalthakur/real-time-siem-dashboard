from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class LogEvent(BaseModel):
    timestamp: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str
    severity: str = "info"
    raw_log: str
    parsed_data: Optional[str] = None

class Alert(BaseModel):
    timestamp: str
    rule_name: str
    severity: str
    description: str
    source_ip: Optional[str] = None
    event_ids: Optional[str] = None
    acknowledged: bool = False

class LogIngest(BaseModel):
    source: str          # "syslog" | "apache" | "windows" | "raw"
    log_line: str

class AlertAck(BaseModel):
    alert_id: int
