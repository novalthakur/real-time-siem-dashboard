import React, { useState, useEffect, useCallback } from "react";
import IDSDashboard from "./IDSDashboard";

const API = process.env.REACT_APP_IDS_API || "http://localhost:8001";
const WS  = API.replace("http", "ws") + "/ws";

export default function IDSApp() {
  const [stats, setStats]           = useState(null);
  const [detections, setDetections] = useState([]);
  const [incidents, setIncidents]   = useState([]);
  const [timeline, setTimeline]     = useState([]);
  const [modelStats, setModelStats] = useState(null);
  const [connected, setConnected]   = useState(false);

  const fetchAll = useCallback(async () => {
    try {
      const [s, d, i, t, m] = await Promise.all([
        fetch(`${API}/api/stats`).then(r => r.json()),
        fetch(`${API}/api/detections?limit=60`).then(r => r.json()),
        fetch(`${API}/api/incidents?limit=30`).then(r => r.json()),
        fetch(`${API}/api/timeline`).then(r => r.json()),
        fetch(`${API}/api/model/stats`).then(r => r.json()),
      ]);
      setStats(s); setDetections(d); setIncidents(i);
      setTimeline(t.reverse()); setModelStats(m);
    } catch (_) {}
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 10000);
    let ws;
    const connect = () => {
      ws = new WebSocket(WS);
      ws.onopen  = () => setConnected(true);
      ws.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "detection") {
          setDetections(prev => [msg.data, ...prev].slice(0, 100));
          setStats(prev => prev ? {
            ...prev,
            total_detections: (prev.total_detections || 0) + 1,
            anomaly_count: msg.data.is_anomaly
              ? (prev.anomaly_count || 0) + 1
              : prev.anomaly_count,
          } : prev);
        }
      };
    };
    connect();
    return () => { clearInterval(interval); ws?.close(); };
  }, [fetchAll]);

  const resolveIncident = async (id) => {
    await fetch(`${API}/api/incidents/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: id }),
    });
    setIncidents(prev => prev.map(i => i.id === id ? { ...i, resolved: 1 } : i));
  };

  return (
    <IDSDashboard
      stats={stats}
      detections={detections}
      incidents={incidents}
      timeline={timeline}
      modelStats={modelStats}
      connected={connected}
      onResolve={resolveIncident}
    />
  );
}
