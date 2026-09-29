"""Separate SQLite database for the IDS (never touches the SIEM DB)."""
import sqlite3, os

DB_PATH = os.getenv("IDS_DB_PATH", "./data/ids.db")


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS detections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
            source_ip   TEXT,
            dest_port   INTEGER,
            protocol    TEXT,
            event_type  TEXT,
            threat_score INTEGER NOT NULL,
            is_anomaly  INTEGER NOT NULL DEFAULT 0,
            ai_label    TEXT,
            if_score    INTEGER,
            seq_score   INTEGER,
            raw_event   TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            source_ip   TEXT,
            incident_type TEXT,
            severity    TEXT,
            description TEXT,
            detection_ids TEXT,
            resolved    INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_det_ts    ON detections(timestamp);
        CREATE INDEX IF NOT EXISTS idx_det_ip    ON detections(source_ip);
        CREATE INDEX IF NOT EXISTS idx_det_label ON detections(ai_label);
        CREATE INDEX IF NOT EXISTS idx_inc_ip    ON incidents(source_ip);
    """)
    conn.commit()
    conn.close()


def save_detection(event: dict, score_result: dict) -> int:
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO detections
           (source_ip, dest_port, protocol, event_type,
            threat_score, is_anomaly, ai_label, if_score, seq_score, raw_event)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            event.get("source_ip"),
            event.get("dest_port"),
            event.get("protocol"),
            event.get("event_type"),
            score_result["threat_score"],
            int(score_result["is_anomaly"]),
            score_result["ai_label"],
            score_result["model_scores"]["isolation_forest"],
            score_result["model_scores"]["sequence"],
            str(event),
        ),
    )
    conn.commit()
    det_id = cur.lastrowid
    conn.close()
    return det_id


def maybe_create_incident(event: dict, score_result: dict, det_id: int):
    """Auto-create an incident for critical/suspicious detections."""
    label = score_result["ai_label"]
    if label not in ("critical", "suspicious"):
        return
    severity = "high" if label == "critical" else "medium"
    src = event.get("source_ip", "unknown")
    etype = event.get("event_type", "unknown")
    conn = get_db()
    conn.execute(
        """INSERT INTO incidents
           (source_ip, incident_type, severity, description, detection_ids)
           VALUES (?,?,?,?,?)""",
        (src, etype, severity,
         f"AI detected {label} activity from {src} (score={score_result['threat_score']})",
         str(det_id)),
    )
    conn.commit()
    conn.close()
