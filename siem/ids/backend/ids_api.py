"""
IDS FastAPI backend — port 8001.
Completely separate from the SIEM (port 8000).
"""
import json, asyncio
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ids_db import init_db, get_db, save_detection, maybe_create_incident
from ids_model import score_event, get_model_stats

app = FastAPI(title="AI-IDS", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── WebSocket broadcast ───────────────────────────────────────────────────────
_clients: list[WebSocket] = []


async def _broadcast(msg: dict):
    data = json.dumps(msg, default=str)
    dead = []
    for ws in _clients:
        try:
            await ws.send_text(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.remove(ws)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    _clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _clients.remove(ws)


# ── Schemas ───────────────────────────────────────────────────────────────────
class EventIn(BaseModel):
    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    protocol: str | None = None
    event_type: str = "raw"
    raw_log: str | None = None


class ResolveIn(BaseModel):
    incident_id: int


# ── Ingest ────────────────────────────────────────────────────────────────────
@app.post("/api/analyze")
async def analyze(event: EventIn):
    ev = event.model_dump()
    result = score_event(ev)
    det_id = save_detection(ev, result)
    maybe_create_incident(ev, result, det_id)

    payload = {**ev, **result, "id": det_id, "timestamp": datetime.utcnow().isoformat()}
    asyncio.create_task(_broadcast({"type": "detection", "data": payload}))
    return payload


@app.post("/api/analyze/batch")
async def analyze_batch(events: list[EventIn]):
    return [await analyze(e) for e in events]


# ── Query endpoints ───────────────────────────────────────────────────────────
@app.get("/api/detections")
def get_detections(limit: int = 100, label: str = None, anomaly_only: bool = False):
    conn = get_db()
    q = "SELECT * FROM detections"
    params: list = []
    filters = []
    if label:
        filters.append("ai_label=?"); params.append(label)
    if anomaly_only:
        filters.append("is_anomaly=1")
    if filters:
        q += " WHERE " + " AND ".join(filters)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/incidents")
def get_incidents(limit: int = 50, unresolved_only: bool = False):
    conn = get_db()
    q = "SELECT * FROM incidents"
    if unresolved_only:
        q += " WHERE resolved=0"
    q += " ORDER BY id DESC LIMIT ?"
    rows = conn.execute(q, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/incidents/resolve")
def resolve_incident(payload: ResolveIn):
    conn = get_db()
    conn.execute("UPDATE incidents SET resolved=1 WHERE id=?", (payload.incident_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/stats")
def get_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    anomalies = conn.execute("SELECT COUNT(*) FROM detections WHERE is_anomaly=1").fetchone()[0]
    by_label = conn.execute(
        "SELECT ai_label, COUNT(*) as count FROM detections GROUP BY ai_label"
    ).fetchall()
    top_ips = conn.execute(
        "SELECT source_ip, COUNT(*) as count FROM detections WHERE source_ip IS NOT NULL "
        "GROUP BY source_ip ORDER BY count DESC LIMIT 10"
    ).fetchall()
    avg_score = conn.execute("SELECT AVG(threat_score) FROM detections").fetchone()[0] or 0
    open_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE resolved=0").fetchone()[0]
    conn.close()
    return {
        "total_detections": total,
        "anomaly_count": anomalies,
        "avg_threat_score": round(avg_score, 1),
        "open_incidents": open_incidents,
        "by_label": [dict(r) for r in by_label],
        "top_ips": [dict(r) for r in top_ips],
    }


@app.get("/api/timeline")
def get_timeline():
    conn = get_db()
    rows = conn.execute(
        """SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
           COUNT(*) as total,
           SUM(is_anomaly) as anomalies,
           AVG(threat_score) as avg_score
           FROM detections GROUP BY hour ORDER BY hour DESC LIMIT 48"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/model/stats")
def model_stats():
    return get_model_stats()


@app.on_event("startup")
async def startup():
    init_db()
