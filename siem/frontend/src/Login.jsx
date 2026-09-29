import React, { useState } from "react";

const API = process.env.REACT_APP_API_URL || "";

export default function Login({ onLogin, onRegister }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        setError("Invalid username or password");
        return;
      }
      const data = await res.json();
      localStorage.setItem("siem_token", data.access_token);
      onLogin(data.access_token);
    } catch {
      setError("Cannot connect to server");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: "100vh", background: "#0f1117",
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div style={{ background: "#1a1d27", borderRadius: 12, padding: 40, width: 360 }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 40 }}>🛡️</div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: "#e2e8f0", marginTop: 8 }}>SIEM Dashboard</h1>
          <p style={{ fontSize: 13, color: "#64748b", marginTop: 4 }}>Sign in to continue</p>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 12, color: "#94a3b8", display: "block", marginBottom: 6 }}>Username</label>
            <input
              type="text" value={username} onChange={e => setUsername(e.target.value)}
              required autoFocus
              style={{
                width: "100%", padding: "10px 12px", borderRadius: 6,
                background: "#0f1117", border: "1px solid #2d3148",
                color: "#e2e8f0", fontSize: 14, outline: "none",
              }}
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={{ fontSize: 12, color: "#94a3b8", display: "block", marginBottom: 6 }}>Password</label>
            <input
              type="password" value={password} onChange={e => setPassword(e.target.value)}
              required
              style={{
                width: "100%", padding: "10px 12px", borderRadius: 6,
                background: "#0f1117", border: "1px solid #2d3148",
                color: "#e2e8f0", fontSize: 14, outline: "none",
              }}
            />
          </div>

          {error && (
            <div style={{ background: "#ef444422", border: "1px solid #ef444444", borderRadius: 6,
              padding: "8px 12px", marginBottom: 16, fontSize: 13, color: "#ef4444" }}>
              {error}
            </div>
          )}

          <button type="submit" disabled={loading} style={{
            width: "100%", padding: "11px", borderRadius: 6, border: "none",
            background: loading ? "#1e3a5f" : "#3b82f6", color: "#fff",
            fontSize: 14, fontWeight: 600, cursor: loading ? "not-allowed" : "pointer",
          }}>
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <p style={{ textAlign: "center", fontSize: 13, color: "#64748b", marginTop: 24 }}>
          Don't have an account?{" "}
          <span onClick={onRegister} style={{ color: "#3b82f6", cursor: "pointer" }}>Register</span>
        </p>
      </div>
    </div>
  );
}
