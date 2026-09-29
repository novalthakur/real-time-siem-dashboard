import React, { useState, useEffect, useCallback } from "react";
import Dashboard from "./Dashboard";
import Login from "./Login";
import Register from "./Register";

const API = process.env.REACT_APP_API_URL || "";
const WS_URL = (window.location.protocol === "https:" ? "wss:" : "ws:") + "//" + window.location.host + "/ws";

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("siem_token"));
  const [page, setPage] = useState("login"); // "login" | "register"
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [aiStats, setAiStats] = useState(null);
  const [connected, setConnected] = useState(false);

  const authHeaders = { Authorization: `Bearer ${token}` };

  const logout = () => {
    localStorage.removeItem("siem_token");
    setToken(null);
  };

  const fetchAll = useCallback(async () => {
    if (!token) return;
    try {
      const [s, a, e, t, ai] = await Promise.all([
        fetch(`${API}/api/stats`, { headers: authHeaders }).then(r => { if (r.status === 401) logout(); return r.json(); }),
        fetch(`${API}/api/alerts?limit=20`, { headers: authHeaders }).then(r => r.json()),
        fetch(`${API}/api/events?limit=50`, { headers: authHeaders }).then(r => r.json()),
        fetch(`${API}/api/events/timeline`, { headers: authHeaders }).then(r => r.json()),
        fetch(`${API}/api/ai/stats`, { headers: authHeaders }).then(r => r.json()),
      ]);
      setStats(s); setAlerts(a); setEvents(e); setTimeline(t); setAiStats(ai);
    } catch (_) {}
  }, [token]);

  useEffect(() => {
    if (!token) return;
    fetchAll();
    const interval = setInterval(fetchAll, 15000);
    let ws;
    const connect = () => {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "alert") {
          setAlerts(prev => [msg.data, ...prev].slice(0, 50));
          setStats(prev => prev ? { ...prev, unacked_alerts: (prev.unacked_alerts || 0) + 1 } : prev);
        } else if (msg.type === "event") {
          setEvents(prev => [msg.data, ...prev].slice(0, 100));
          setStats(prev => prev ? { ...prev, total_events: (prev.total_events || 0) + 1 } : prev);
        }
      };
    };
    connect();
    return () => { clearInterval(interval); ws?.close(); };
  }, [token, fetchAll]);

  const ackAlert = async (id) => {
    await fetch(`${API}/api/alerts/ack`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify({ alert_id: id }),
    });
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, acknowledged: 1 } : a));
    setStats(prev => prev ? { ...prev, unacked_alerts: Math.max(0, (prev.unacked_alerts || 1) - 1) } : prev);
  };

  if (!token) {
    if (page === "register")
      return <Register onLogin={setToken} onBack={() => setPage("login")} />;
    return <Login onLogin={setToken} onRegister={() => setPage("register")} />;
  }

  return (
    <Dashboard
      stats={stats} alerts={alerts} events={events}
      timeline={timeline} connected={connected}
      onAck={ackAlert} aiStats={aiStats} onLogout={logout}
    />
  );
}
