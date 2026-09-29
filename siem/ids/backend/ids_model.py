"""
IDS ML engine — two complementary detectors:
  1. IsolationForest  — point anomaly detection on feature vectors
  2. SequenceDetector — sliding-window deviation (LSTM-like, no torch needed)
"""
import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest
from ids_features import extract_features, FEATURE_DIM

# ── Isolation Forest ──────────────────────────────────────────────────────────
_if_buffer: deque = deque(maxlen=1000)
_if_model: IsolationForest | None = None
_IF_MIN = 80          # events before first fit
_IF_RETRAIN = 100     # retrain every N new events
_if_counter = 0


def _train_if():
    global _if_model
    X = np.array(list(_if_buffer))
    _if_model = IsolationForest(
        n_estimators=150, contamination=0.08, random_state=42
    )
    _if_model.fit(X)


def _if_score(features: list[float]) -> tuple[float, bool]:
    """Return (0-100 threat score, is_anomaly)."""
    global _if_counter
    _if_buffer.append(features)
    _if_counter += 1

    if len(_if_buffer) >= _IF_MIN and _if_counter % _IF_RETRAIN == 0:
        _train_if()

    if _if_model is None or len(_if_buffer) < _IF_MIN:
        # rule-based fallback: use feature[4] (event risk) as proxy
        score = int(features[4] * 70 + features[2] * 20)
        return min(score, 100), score >= 60

    x = np.array([features])
    raw = _if_model.decision_function(x)[0]
    score = int(np.clip((-raw + 0.5) * 100, 0, 100))
    return score, _if_model.predict(x)[0] == -1


# ── Sequence Detector ─────────────────────────────────────────────────────────
# Maintains a rolling mean/std of feature vectors; flags deviations > k*sigma
_seq_buffer: deque = deque(maxlen=200)
_SEQ_MIN = 30
_SEQ_K = 2.5          # z-score threshold


def _seq_score(features: list[float]) -> tuple[float, bool]:
    """Return (0-100 threat score, is_anomaly) based on sequence deviation."""
    _seq_buffer.append(features)
    if len(_seq_buffer) < _SEQ_MIN:
        return 0, False

    arr = np.array(list(_seq_buffer))
    mu = arr[:-1].mean(axis=0)
    sigma = arr[:-1].std(axis=0) + 1e-6
    z = np.abs((np.array(features) - mu) / sigma)
    max_z = float(z.max())
    score = int(np.clip((max_z / _SEQ_K) * 60, 0, 100))
    return score, max_z > _SEQ_K


# ── Public API ────────────────────────────────────────────────────────────────
def score_event(event: dict) -> dict:
    """
    Score an event using both detectors.
    Returns threat_score (0-100), is_anomaly, ai_label, model_scores.
    """
    features = extract_features(event)
    if_score, if_anom = _if_score(features)
    seq_score, seq_anom = _seq_score(features)

    # Ensemble: weighted average (IF carries more weight when trained)
    if _if_model is not None:
        combined = int(0.65 * if_score + 0.35 * seq_score)
    else:
        combined = int(0.4 * if_score + 0.6 * seq_score) if seq_score else if_score

    is_anomaly = if_anom or seq_anom

    if combined >= 80:
        label = "critical"
    elif combined >= 60:
        label = "suspicious"
    elif combined >= 35:
        label = "unusual"
    else:
        label = "normal"

    return {
        "threat_score": combined,
        "is_anomaly": is_anomaly,
        "ai_label": label,
        "model_scores": {"isolation_forest": if_score, "sequence": seq_score},
        "model_ready": _if_model is not None,
    }


def get_model_stats() -> dict:
    return {
        "if_model_ready": _if_model is not None,
        "if_events_seen": len(_if_buffer),
        "if_min_samples": _IF_MIN,
        "seq_events_seen": len(_seq_buffer),
        "seq_min_samples": _SEQ_MIN,
        "training_progress": min(100, int(len(_if_buffer) / _IF_MIN * 100)),
    }
