import asyncio, os
from fastapi import APIRouter
from database import get_db
from parser import normalize
from rules import evaluate
from schemas import LogIngest
from ai_engine import score_event

router = APIRouter()

def save_event(event_dict):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO events (timestamp, source_ip, dest_ip, source_port, dest_port,
           protocol, event_type, severity, raw_log, parsed_data)
           VALUES (:timestamp,:source_ip,:dest_ip,:source_port,:dest_port,
                   :protocol,:event_type,:severity,:raw_log,:parsed_data)""",
        event_dict,
    )
    conn.commit()
    event_id = cur.lastrowid
    conn.close()
    return event_id

def save_alert(alert_dict):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO alerts (timestamp, rule_name, severity, description, source_ip, event_ids)
           VALUES (:timestamp,:rule_name,:severity,:description,:source_ip,:event_ids)""",
        alert_dict,
    )
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()
    return alert_id

_broadcast_fn = None

def set_broadcast(fn):
    global _broadcast_fn
    _broadcast_fn = fn

async def process_log(source, line, broadcast_fn=None):
    event = normalize(source, line)
    event_dict = event.model_dump()

    # AI scoring
    ai_result = score_event(event_dict)
    event_dict["parsed_data"] = (
        f"{event_dict.get('parsed_data') or ''} | "
        f"AI score={ai_result['threat_score']} label={ai_result['ai_label']}"
    ).strip(" |")

    # Upgrade severity if AI says it's critical
    if ai_result["threat_score"] >= 80 and event_dict["severity"] not in ("critical", "high"):
        event_dict["severity"] = "high"

    event_id = save_event(event_dict)
    event_dict["id"] = event_id
    event_dict["threat_score"] = ai_result["threat_score"]
    event_dict["is_anomaly"] = ai_result["is_anomaly"]
    event_dict["ai_label"] = ai_result["ai_label"]

    alerts = evaluate(event_dict)
    for alert in alerts:
        alert_dict = alert.model_dump()
        alert_id = save_alert(alert_dict)
        alert_dict["id"] = alert_id
        if broadcast_fn:
            await broadcast_fn({"type": "alert", "data": alert_dict})

    if broadcast_fn:
        await broadcast_fn({"type": "event", "data": event_dict})

    return event_dict, alerts

@router.post("/ingest")
async def ingest_log(payload: LogIngest):
    event_dict, alerts = await process_log(payload.source, payload.log_line, _broadcast_fn)
    return {
        "event_id": event_dict["id"],
        "alerts": len(alerts),
        "threat_score": event_dict["threat_score"],
        "ai_label": event_dict["ai_label"],
    }

@router.post("/ingest/batch")
async def ingest_batch(payloads: list[LogIngest]):
    results = []
    for p in payloads:
        event_dict, alerts = await process_log(p.source, p.log_line, _broadcast_fn)
        results.append({
            "event_id": event_dict["id"],
            "alerts": len(alerts),
            "threat_score": event_dict["threat_score"],
        })
    return results

async def redis_consumer():
    try:
        import redis.asyncio as aioredis
        REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
        r = aioredis.from_url(REDIS_URL)
        last_id = "$"
        while True:
            try:
                messages = await r.xread({"siem:logs": last_id}, block=1000, count=10)
                for _, entries in messages:
                    for msg_id, fields in entries:
                        source = fields.get(b"source", b"raw").decode()
                        line = fields.get(b"line", b"").decode()
                        await process_log(source, line, _broadcast_fn)
                        last_id = msg_id
            except Exception:
                await asyncio.sleep(2)
    except ImportError:
        pass
