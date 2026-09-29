import json, asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from database import init_db, get_db
from ingestion import router as ingest_router, set_broadcast, redis_consumer
from schemas import AlertAck
from ai_engine import get_ai_stats
from auth import router as auth_router, verify_token

app = FastAPI(title="SIEM Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ConnectionManager:
    def __init__(self):
        self.active = []
    async def connect(self, ws):
        await ws.accept()
        self.active.append(ws)
    def disconnect(self, ws):
        self.active.remove(ws)
    async def broadcast(self, message):
        data = json.dumps(message, default=str)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)

# Public routes
app.include_router(auth_router, prefix="/api")

# Protected ingestion
app.include_router(ingest_router, prefix="/api", dependencies=[Depends(verify_token)])

@app.get("/api/events", dependencies=[Depends(verify_token)])
def get_events(limit: int = 100, offset: int = 0, severity: str = None):
    conn = get_db()
    if severity:
        rows = conn.execute("SELECT * FROM events WHERE severity=? ORDER BY id DESC LIMIT ? OFFSET ?", (severity, limit, offset)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/alerts", dependencies=[Depends(verify_token)])
def get_alerts(limit: int = 50, unacked_only: bool = False):
    conn = get_db()
    if unacked_only:
        rows = conn.execute("SELECT * FROM alerts WHERE acknowledged=0 ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/alerts/ack", dependencies=[Depends(verify_token)])
def ack_alert(payload: AlertAck):
    conn = get_db()
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (payload.alert_id,))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/api/stats", dependencies=[Depends(verify_token)])
def get_stats():
    conn = get_db()
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    unacked = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
    by_severity = conn.execute("SELECT severity, COUNT(*) as count FROM events GROUP BY severity").fetchall()
    by_type = conn.execute("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type ORDER BY count DESC LIMIT 10").fetchall()
    top_ips = conn.execute("SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC LIMIT 10").fetchall()
    conn.close()
    return {
        "total_events": total_events, "total_alerts": total_alerts, "unacked_alerts": unacked,
        "by_severity": [dict(r) for r in by_severity],
        "by_type": [dict(r) for r in by_type],
        "top_ips": [dict(r) for r in top_ips],
    }

@app.get("/api/events/timeline", dependencies=[Depends(verify_token)])
def get_timeline():
    conn = get_db()
    rows = conn.execute(
        """SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
           COUNT(*) as count, severity FROM events
           GROUP BY hour, severity ORDER BY hour DESC LIMIT 48"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/ai/stats", dependencies=[Depends(verify_token)])
def ai_stats():
    return get_ai_stats()

@app.on_event("startup")
async def startup():
    init_db()
    set_broadcast(manager.broadcast)
    asyncio.create_task(redis_consumer())
