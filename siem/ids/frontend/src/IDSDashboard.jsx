import React from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from "recharts";

const LABEL_COLOR = { critical: "#ef4444", suspicious: "#f97316", unusual: "#eab308", normal: "#22c55e" };
const PIE_COLORS  = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6"];

const Badge = ({ label }) => (
  <span style={{
    background: LABEL_COLOR[label] || "#6b7280",
    color: "#fff", padding: "2px 8px", borderRadius: 9999,
    fontSize: 11, fontWeight: 700, textTransform: "uppercase",
  }}>{label}</span>
);

const Card = ({ title, value, sub, color = "#3b82f6" }) => (
  <div style={{ background: "#1e293b", borderRadius: 10, padding: "18px 22px", flex: 1, minWidth: 140 }}>
    <div style={{ color: "#94a3b8", fontSize: 12, marginBottom: 4 }}>{title}</div>
    <div style={{ color, fontSize: 28, fontWeight: 700 }}>{value ?? "—"}</div>
    {sub && <div style={{ color: "#64748b", fontSize: 11, marginTop: 2 }}>{sub}</div>}
  </div>
);

// Threat score gauge bar
const ScoreBar = ({ score }) => {
  const color = score >= 80 ? "#ef4444" : score >= 60 ? "#f97316" : score >= 35 ? "#eab308" : "#22c55e";
  return (
    <div style={{ background: "#0f172a", borderRadius: 4, height: 6, width: "100%", overflow: "hidden" }}>
      <div style={{ width: `${score}%`, height: "100%", background: color, transition: "width .3s" }} />
    </div>
  );
};

// Model confidence ring (simple CSS)
const ConfidenceRing = ({ pct }) => (
  <div style={{ position: "relative", width: 90, height: 90 }}>
    <svg viewBox="0 0 36 36" style={{ transform: "rotate(-90deg)", width: 90, height: 90 }}>
      <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1e293b" strokeWidth="3" />
      <circle cx="18" cy="18" r="15.9" fill="none" stroke="#3b82f6" strokeWidth="3"
        strokeDasharray={`${pct} ${100 - pct}`} strokeLinecap="round" />
    </svg>
    <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center",
      justifyContent: "center", color: "#e2e8f0", fontWeight: 700, fontSize: 16 }}>
      {pct}%
    </div>
  </div>
);

export default function IDSDashboard({
  stats, detections, incidents, timeline, modelStats, connected, onResolve,
}) {
  const byLabel = stats?.by_label || [];

  return (
    <div style={{ background: "#0f172a", minHeight: "100vh", color: "#e2e8f0", fontFamily: "system-ui, sans-serif", padding: 24 }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#f1f5f9" }}>
            🛡️ AI Intrusion Detection System
          </h1>
          <div style={{ color: "#64748b", fontSize: 12, marginTop: 2 }}>
            Isolation Forest + Sequence Anomaly Detection · Port 8001
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: connected ? "#22c55e" : "#ef4444" }} />
          <span style={{ fontSize: 12, color: connected ? "#22c55e" : "#ef4444" }}>
            {connected ? "Live" : "Reconnecting…"}
          </span>
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 24 }}>
        <Card title="Total Detections"  value={stats?.total_detections}  color="#3b82f6" />
        <Card title="Anomalies"         value={stats?.anomaly_count}      color="#ef4444" />
        <Card title="Avg Threat Score"  value={stats?.avg_threat_score}   color="#f97316"
              sub="0 = benign · 100 = critical" />
        <Card title="Open Incidents"    value={stats?.open_incidents}     color="#eab308" />
      </div>

      {/* Model status + label pie */}
      <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>

        {/* Model confidence */}
        <div style={{ background: "#1e293b", borderRadius: 10, padding: 20, flex: "0 0 260px" }}>
          <div style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 14 }}>
            Model Status
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
            <ConfidenceRing pct={modelStats?.training_progress ?? 0} />
            <div style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.8 }}>
              <div>IF ready: <b style={{ color: modelStats?.if_model_ready ? "#22c55e" : "#ef4444" }}>
                {modelStats?.if_model_ready ? "Yes" : "No"}</b></div>
              <div>Events seen: <b style={{ color: "#e2e8f0" }}>{modelStats?.if_events_seen ?? 0}</b></div>
              <div>Min needed: <b style={{ color: "#e2e8f0" }}>{modelStats?.if_min_samples ?? 80}</b></div>
              <div>Seq events: <b style={{ color: "#e2e8f0" }}>{modelStats?.seq_events_seen ?? 0}</b></div>
            </div>
          </div>
        </div>

        {/* Label distribution pie */}
        <div style={{ background: "#1e293b", borderRadius: 10, padding: 20, flex: 1, minWidth: 260 }}>
          <div style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
            Detection Labels
          </div>
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie data={byLabel} dataKey="count" nameKey="ai_label" cx="50%" cy="50%"
                   outerRadius={55} label={({ ai_label, percent }) =>
                     `${ai_label} ${(percent * 100).toFixed(0)}%`}>
                {byLabel.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Top IPs */}
        <div style={{ background: "#1e293b", borderRadius: 10, padding: 20, flex: 1, minWidth: 260 }}>
          <div style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
            Top Source IPs
          </div>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={(stats?.top_ips || []).slice(0, 6)} layout="vertical">
              <XAxis type="number" tick={{ fill: "#64748b", fontSize: 10 }} />
              <YAxis type="category" dataKey="source_ip" width={100}
                     tick={{ fill: "#94a3b8", fontSize: 10 }} />
              <Tooltip contentStyle={{ background: "#1e293b", border: "none" }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Anomaly timeline */}
      <div style={{ background: "#1e293b", borderRadius: 10, padding: 20, marginBottom: 24 }}>
        <div style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 12 }}>
          Anomaly Timeline (hourly)
        </div>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={timeline}>
            <defs>
              <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gAnom" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.5} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="hour" tick={{ fill: "#64748b", fontSize: 10 }}
                   tickFormatter={v => v?.slice(11, 16)} />
            <YAxis tick={{ fill: "#64748b", fontSize: 10 }} />
            <Tooltip contentStyle={{ background: "#1e293b", border: "none" }}
                     labelFormatter={v => v?.slice(0, 16)} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Area type="monotone" dataKey="total"    name="Total"    stroke="#3b82f6"
                  fill="url(#gTotal)" strokeWidth={2} />
            <Area type="monotone" dataKey="anomalies" name="Anomalies" stroke="#ef4444"
                  fill="url(#gAnom)"  strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Detections + Incidents side by side */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>

        {/* Recent detections */}
        <div style={{ background: "#1e293b", borderRadius: 10, padding: 20, flex: 2, minWidth: 340 }}>
          <div style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 12 }}>
            Recent Detections
          </div>
          <div style={{ overflowY: "auto", maxHeight: 340 }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ color: "#64748b", textAlign: "left" }}>
                  {["Time", "Source IP", "Type", "Score", "Label"].map(h => (
                    <th key={h} style={{ padding: "4px 8px", borderBottom: "1px solid #334155" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {detections.map((d, i) => (
                  <tr key={d.id ?? i} style={{ borderBottom: "1px solid #1e293b" }}>
                    <td style={{ padding: "5px 8px", color: "#64748b" }}>
                      {d.timestamp?.slice(11, 19) ?? "—"}
                    </td>
                    <td style={{ padding: "5px 8px" }}>{d.source_ip ?? "—"}</td>
                    <td style={{ padding: "5px 8px", color: "#94a3b8" }}>{d.event_type}</td>
                    <td style={{ padding: "5px 8px", minWidth: 80 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <span style={{ color: LABEL_COLOR[d.ai_label] || "#e2e8f0", fontWeight: 700 }}>
                          {d.threat_score}
                        </span>
                        <ScoreBar score={d.threat_score} />
                      </div>
                    </td>
                    <td style={{ padding: "5px 8px" }}><Badge label={d.ai_label} /></td>
                  </tr>
                ))}
                {detections.length === 0 && (
                  <tr><td colSpan={5} style={{ padding: 16, color: "#475569", textAlign: "center" }}>
                    No detections yet — send events to /api/analyze
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Incidents */}
        <div style={{ background: "#1e293b", borderRadius: 10, padding: 20, flex: 1, minWidth: 280 }}>
          <div style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 12 }}>
            Incidents
          </div>
          <div style={{ overflowY: "auto", maxHeight: 340 }}>
            {incidents.length === 0 && (
              <div style={{ color: "#475569", fontSize: 12, textAlign: "center", paddingTop: 20 }}>
                No incidents
              </div>
            )}
            {incidents.map(inc => (
              <div key={inc.id} style={{
                background: "#0f172a", borderRadius: 8, padding: "10px 14px",
                marginBottom: 8, borderLeft: `3px solid ${inc.severity === "high" ? "#ef4444" : "#f97316"}`,
                opacity: inc.resolved ? 0.45 : 1,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: 12, fontWeight: 600 }}>{inc.source_ip ?? "unknown"}</span>
                  <Badge label={inc.severity} />
                </div>
                <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 4 }}>{inc.description}</div>
                <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8 }}>
                  <span style={{ fontSize: 10, color: "#475569" }}>{inc.created_at?.slice(0, 16)}</span>
                  {!inc.resolved && (
                    <button onClick={() => onResolve(inc.id)} style={{
                      background: "#1e3a5f", color: "#93c5fd", border: "none",
                      borderRadius: 4, padding: "2px 10px", fontSize: 11, cursor: "pointer",
                    }}>Resolve</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
