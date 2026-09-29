"""
AI-based anomaly detection engine using Isolation Forest.
Scores every event 0-100 (higher = more anomalous/threatening).
No labelled training data required.
"""
import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest

# Feature extraction constants
KNOWN_PORTS = {22, 80, 443, 3306, 5432, 8080, 21, 25, 53, 3389}
HIGH_RISK_PORTS = {22, 23, 3389, 4444, 5900, 6666, 31337}
EVENT_TYPE_RISK = {
    "ssh_failed": 0.9, "firewall": 0.7, "http_error": 0.5,
    "ssh_accepted": 0.2, "http_request": 0.1, "syslog": 0.1, "raw": 0.3,
}

# Rolling window of recent feature vectors for online learning
_feature_buffer = deque(maxlen=500)
_model = None
_min_samples = 50  # minimum events before AI kicks in

def _extract_features(event: dict) -> list:
    """Convert event dict to numeric feature vector."""
    dest_port = event.get("dest_port") or 0
    src_port = event.get("source_port") or 0
    event_type = event.get("event_type", "raw")
    protocol = event.get("protocol", "")

    return [
        float(dest_port),
        float(src_port),
        1.0 if dest_port in HIGH_RISK_PORTS else 0.0,
        1.0 if dest_port not in KNOWN_PORTS and dest_port > 0 else 0.0,
        EVENT_TYPE_RISK.get(event_type, 0.3),
        1.0 if protocol == "TCP" else (0.5 if protocol == "UDP" else 0.0),
        1.0 if event_type == "ssh_failed" else 0.0,
        1.0 if event_type == "firewall" else 0.0,
        1.0 if event_type in ("http_error",) else 0.0,
    ]

def _train():
    global _model
    if len(_feature_buffer) < _min_samples:
        return
    X = np.array(list(_feature_buffer))
    _model = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # assume 10% of traffic is anomalous
        random_state=42,
        warm_start=False,
    )
    _model.fit(X)

def score_event(event: dict) -> dict:
    """
    Score an event. Returns:
      - threat_score: 0-100 (higher = more anomalous)
      - is_anomaly: bool
      - ai_label: human readable label
    """
    features = _extract_features(event)
    _feature_buffer.append(features)

    # Retrain every 50 new events
    if len(_feature_buffer) % 50 == 0:
        _train()

    if _model is None or len(_feature_buffer) < _min_samples:
        # Fall back to rule-based scoring before model is ready
        base_score = int(EVENT_TYPE_RISK.get(event.get("event_type", "raw"), 0.3) * 60)
        port = event.get("dest_port") or 0
        if port in HIGH_RISK_PORTS:
            base_score = min(100, base_score + 25)
        return {
            "threat_score": base_score,
            "is_anomaly": base_score >= 70,
            "ai_label": "rule_based",
        }

    x = np.array([features])
    # decision_function: negative = anomalous, positive = normal
    raw_score = _model.decision_function(x)[0]
    prediction = _model.predict(x)[0]  # -1 = anomaly, 1 = normal

    # Normalize to 0-100 (invert so higher = more anomalous)
    # Typical range is roughly -0.5 to 0.5
    normalized = float(np.clip((-raw_score + 0.5) * 100, 0, 100))
    threat_score = int(normalized)
    is_anomaly = prediction == -1

    if threat_score >= 80:
        label = "critical_anomaly"
    elif threat_score >= 60:
        label = "suspicious"
    elif threat_score >= 40:
        label = "unusual"
    else:
        label = "normal"

    return {
        "threat_score": threat_score,
        "is_anomaly": is_anomaly,
        "ai_label": label,
    }

def get_ai_stats() -> dict:
    return {
        "model_ready": _model is not None,
        "events_seen": len(_feature_buffer),
        "min_samples_needed": _min_samples,
        "training_progress": min(100, int(len(_feature_buffer) / _min_samples * 100)),
    }
