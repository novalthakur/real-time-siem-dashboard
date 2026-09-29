import React, { useState } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, RadialBarChart, RadialBar,
} from "recharts";

const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6" };
const COLORS = ["#3b82f6", "#8b5cf6", "#06b6d4", "#10b981", "#f59e0b", "#ef4444"];

const Card = ({ title, children, style }) => (
  <div style={{ background: "#1a1d27", borderRadius: 10, padding: 16, ...style }}>
    {title && <h3 style={{ fontSize: 13, color: "#94a3b8", marginBottom: 12, textTransform: "uppercase", letterSpacing: 1 }}>{title}</h3>}
    {children}
  </div>
);

const Badge = ({ severity }) => (
  <span style={{
    background: SEV_COLOR[severity] + "33", color: SEV_COLOR[severity],
    padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600,
  }}>{severity?.toUpperCase()}</span>
);

const StatBox = ({ label, value, color }) => (
  <div style={{ background: "#1a1d27", borderRadius: 10, padding: "16px 20px", flex: 1 }}>
    <div style={{ fontSize: 28, fontWeight: 700, color: color || "#e2e8f0" }}>{value ?? "—"}</div>
    <div style={{ fontSize: 12, color: "#64748b", marginTop: 4 }}>{label}</div>
  </div>
);

const ThreatGauge = ({ score }) => {
  const color = score >= 80 ? "#ef4444" : score >= 60 ? "#f97316" : score >= 40 ? "#eab308" : "#22c55e";
  const data = [{ value: score, fill: color }, { value: 100 - score, fill: "#1e2235" }];
  return (
    <div style={{ textAlign: "center" }}>
      <ResponsiveContainer width="100%" height={120}>
        <RadialBarChart cx="50%" cy="80%" innerRadius="60%" outerRadius="90%"
          startAngle={180} endAngle={0} data={data}>
          <RadialBar dataKey="value" cornerRadius={4} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div style={{ marginTop: -30, fontSize: 28, fontWeight: 700, color }}>{score}</div>
      <div style={{ fontSize: 11, color: "#64748b" }}>Avg Threat Score</div>
    </div>
  );
};

function buildTimeline(timeline) {
  const map = {};
  timeline.forEach(({ hour, count, severity }) => {
    if (!map[hour]) map[hour] = { hour: hour.slice(11, 16) };
    map[hour][severity] = (map[hour][severity] || 0) + count;
  });
  return Object.values(map).slice(-24).reverse();
}

export default function Dashboard({ stats, alerts, events, timeline, connected, onAck, aiStats, onLogout }) {
  const [tab, setTab] = useState("events");
  const timelineData = buildTimeline(timeline || []);

  const avgThreatScore = events.length
    ? Math.round(events.slice(0, 20).reduce((s, e) => s + (e.threat_score || 0), 0) / Math.min(events.length, 20))
    : 0;

  const anomalyData = events.slice(0, 30).reverse().map((e, i) => ({
    i, score: e.threat_score || 0,
    fill: (e.threat_score || 0) >= 80 ? "#ef4444" : (e.threat_score || 0) >= 60 ? "#f97316" : "#3b82f6",
  }));

  return (
    <div style={{ minHeight: "100vh", padding: 20 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>🛡️ SIEM Dashboard</h1>
          <span style={{ fontSize: 12, color: "#64748b" }}>Security Information & Event Management</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {aiStats && (
            <div style={{ fontSize: 12, color: "#64748b", background: "#1a1d27", padding: "4px 10px", borderRadius: 6 }}>
              🤖 AI {aiStats.model_ready ? "Active" : `Training ${aiStats.training_progress}%`}
            </div>
          )}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: connected ? "#22c55e" : "#ef4444" }} />
            <span style={{ fontSize: 12, color: "#64748b" }}>{connected ? "Live" : "Reconnecting..."}</span>
          </div>
          <button onClick={onLogout} style={{
            background: "#1e2235", border: "1px solid #2d3148", color: "#94a3b8",
            borderRadius: 6, padding: "5px 12px", cursor: "pointer", fontSize: 12,
          }}>Logout</button>
        </div>
      </div>

      {/* Stat boxes */}
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        <StatBox label="Total Events" value={stats?.total_events?.toLocaleString()} color="#3b82f6" />
        <StatBox label="Total Alerts" value={stats?.total_alerts?.toLocaleString()} color="#f97316" />
        <StatBox label="Unacknowledged" value={stats?.unacked_alerts} color="#ef4444" />
        <StatBox label="Active Sources" value={stats?.by_type?.length} color="#8b5cf6" />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
        <Card title="Event Timeline (last 24h)">
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={timelineData}>
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "#64748b" }} />
              <YAxis tick={{ fontSize: 10, fill: "#64748b" }} />
              <Tooltip contentStyle={{ background: "#0f1117", border: "1px solid #3a3f55", fontSize: 12 }} />
              {["critical", "high", "medium", "info"].map(s => (
                <Area key={s} type="monotone" dataKey={s} stackId="1"
                  stroke={SEV_COLOR[s]} fill={SEV_COLOR[s] + "55"} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="AI Threat Score (last 30 events)">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={anomalyData}>
              <XAxis hide />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#64748b" }} />
              <Tooltip
                contentStyle={{ background: "#0f1117", border: "1px solid #3a3f55", fontSize: 12 }}
                formatter={(v) => [`Score: ${v}`, "Threat"]}
              />
              <Bar dataKey="score" radius={[2, 2, 0, 0]}>
                {anomalyData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Avg Threat Score">
          <ThreatGauge score={avgThreatScore} />
        </Card>
      </div>

      {/* Second charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
        <Card title="Events by Severity">
          <ResponsiveContainer width="100%" height={150}>
            <PieChart>
              <Pie data={stats?.by_severity || []} dataKey="count" nameKey="severity"
                cx="50%" cy="50%" outerRadius={55}
                label={({ severity, percent }) => `${severity} ${(percent * 100).toFixed(0)}%`}
                labelLine={false} style={{ fontSize: 10 }}>
                {(stats?.by_severity || []).map((entry, i) => (
                  <Cell key={i} fill={SEV_COLOR[entry.severity] || COLORS[i % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#0f1117", border: "1px solid #3a3f55", fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Top Event Types">
          <ResponsiveContainer width="100%" height={150}>
            <BarChart data={(stats?.by_type || []).slice(0, 6)} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 10, fill: "#64748b" }} />
              <YAxis dataKey="event_type" type="category" tick={{ fontSize: 10, fill: "#94a3b8" }} width={90} />
              <Tooltip contentStyle={{ background: "#0f1117", border: "1px solid #3a3f55", fontSize: 12 }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {(stats?.by_type || []).map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 12 }}>
        {["events", "alerts", "top_ips"].map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: "6px 16px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 13,
            background: tab === t ? "#3b82f6" : "#1a1d27", color: tab === t ? "#fff" : "#94a3b8",
          }}>
            {t === "top_ips" ? "Top IPs" : t.charAt(0).toUpperCase() + t.slice(1)}
            {t === "alerts" && stats?.unacked_alerts > 0 && (
              <span style={{ marginLeft: 6, background: "#ef4444", color: "#fff", borderRadius: 10, padding: "1px 6px", fontSize: 11 }}>
                {stats.unacked_alerts}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Events table */}
      {tab === "events" && (
        <Card>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ color: "#64748b", borderBottom: "1px solid #2d3148" }}>
                  {["Time", "Source IP", "Port", "Type", "Severity", "AI Score", "AI Label", "Details"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => {
                  const score = e.threat_score || 0;
                  const scoreColor = score >= 80 ? "#ef4444" : score >= 60 ? "#f97316" : score >= 40 ? "#eab308" : "#22c55e";
                  return (
                    <tr key={e.id || i} style={{ borderBottom: "1px solid #1e2235" }}>
                      <td style={{ padding: "7px 12px", color: "#64748b", whiteSpace: "nowrap" }}>{e.timestamp?.slice(11, 19)}</td>
                      <td style={{ padding: "7px 12px", fontFamily: "monospace" }}>{e.source_ip || "—"}</td>
                      <td style={{ padding: "7px 12px" }}>{e.dest_port || "—"}</td>
                      <td style={{ padding: "7px 12px" }}>{e.event_type}</td>
                      <td style={{ padding: "7px 12px" }}><Badge severity={e.severity} /></td>
                      <td style={{ padding: "7px 12px", fontWeight: 700, color: scoreColor }}>{score}</td>
                      <td style={{ padding: "7px 12px", color: "#94a3b8", fontSize: 11 }}>{e.ai_label || "—"}</td>
                      <td style={{ padding: "7px 12px", color: "#94a3b8", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {e.parsed_data || e.raw_log?.slice(0, 50)}
                      </td>
                    </tr>
                  );
                })}
                {events.length === 0 && (
                  <tr><td colSpan={8} style={{ padding: 24, textAlign: "center", color: "#64748b" }}>No events yet. Send logs to /api/ingest</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Alerts table */}
      {tab === "alerts" && (
        <Card>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ color: "#64748b", borderBottom: "1px solid #2d3148" }}>
                  {["Time", "Rule", "Severity", "Source IP", "Description", "Action"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map((a, i) => (
                  <tr key={a.id || i} style={{ borderBottom: "1px solid #1e2235", opacity: a.acknowledged ? 0.4 : 1 }}>
                    <td style={{ padding: "7px 12px", color: "#64748b", whiteSpace: "nowrap" }}>{a.timestamp?.slice(11, 19)}</td>
                    <td style={{ padding: "7px 12px", fontWeight: 600 }}>
                      {a.rule_name === "AI Anomaly Detected" ? "🤖 " : ""}{a.rule_name}
                    </td>
                    <td style={{ padding: "7px 12px" }}><Badge severity={a.severity} /></td>
                    <td style={{ padding: "7px 12px", fontFamily: "monospace" }}>{a.source_ip || "—"}</td>
                    <td style={{ padding: "7px 12px", color: "#94a3b8", maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.description}</td>
                    <td style={{ padding: "7px 12px" }}>
                      {!a.acknowledged && (
                        <button onClick={() => onAck(a.id)} style={{
                          background: "#22c55e22", color: "#22c55e", border: "1px solid #22c55e44",
                          borderRadius: 4, padding: "3px 10px", cursor: "pointer", fontSize: 12,
                        }}>Ack</button>
                      )}
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr><td colSpan={6} style={{ padding: 24, textAlign: "center", color: "#64748b" }}>No alerts triggered yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Top IPs */}
      {tab === "top_ips" && (
        <Card title="Top Source IPs by Event Count">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats?.top_ips || []}>
              <XAxis dataKey="source_ip" tick={{ fontSize: 11, fill: "#94a3b8" }} />
              <YAxis tick={{ fontSize: 11, fill: "#64748b" }} />
              <Tooltip contentStyle={{ background: "#0f1117", border: "1px solid #3a3f55", fontSize: 12 }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {(stats?.top_ips || []).map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}
    </div>
  );
}
