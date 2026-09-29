# 🛡️ Real-Time SIEM System

A fully functional Security Information and Event Management (SIEM) system with real-time log ingestion, threat detection, WebSocket alerting, and a live React dashboard.

## Architecture

```
Log Sources ──► POST /api/ingest ──► Parser ──► SQLite
                                         │
                                    Rules Engine
                                         │
                                    WebSocket Broadcast ──► React Dashboard
                                         │
                                    Redis Stream (optional)
```

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI |
| Real-time | WebSockets, Redis Streams |
| Storage | SQLite |
| Frontend | React 18, Recharts |
| Container | Docker, Docker Compose |

## Quick Start

### With Docker (recommended)

```bash
cd siem
docker-compose up --build
```

- Dashboard: http://localhost:3000
- API docs: http://localhost:8000/docs

### Without Docker

**Backend:**
```bash
cd backend
pip install -r requirements.txt
mkdir -p data
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
REACT_APP_API_URL=http://localhost:8000 npm start
```

## Sending Logs

### Single log
```bash
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"source": "syslog", "log_line": "Jan 1 12:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"}'
```

### Batch logs
```bash
curl -X POST http://localhost:8000/api/ingest/batch \
  -H "Content-Type: application/json" \
  -d '[
    {"source": "apache", "log_line": "192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] \"GET /admin HTTP/1.1\" 404 512"},
    {"source": "syslog", "log_line": "Jan 1 12:00:01 server sshd[1]: Failed password for admin from 10.0.0.5 port 22"}
  ]'
```

### Via Redis Stream
```bash
redis-cli XADD siem:logs '*' source syslog line "Jan 1 12:00:00 server sshd[1]: Failed password for root from 1.2.3.4 port 22"
```

## Supported Log Sources

| Source | Format |
|--------|--------|
| `apache` | Apache/Nginx combined access log |
| `syslog` | Linux syslog (auto-detects SSH events) |
| `iptables` | iptables/netfilter log lines |
| `raw` | Any raw text (stored as-is) |

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute Force | 5+ SSH failures from same IP | Critical |
| Port Scan | 10+ distinct ports from same IP | High |
| HTTP Flood | 30+ HTTP requests from same IP | High |
| Firewall Block | Any high-severity firewall event | Medium |

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ingest` | Ingest single log |
| POST | `/api/ingest/batch` | Ingest multiple logs |
| GET | `/api/events` | List events (supports `?limit=&severity=`) |
| GET | `/api/alerts` | List alerts (supports `?unacked_only=true`) |
| POST | `/api/alerts/ack` | Acknowledge alert `{"alert_id": 1}` |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/events/timeline` | Hourly event counts |
| WS | `/ws` | WebSocket for real-time events/alerts |

## Dashboard Features

- **Live event feed** — updates in real time via WebSocket
- **Alert management** — acknowledge alerts with one click
- **Timeline chart** — stacked area chart by severity (last 24h)
- **Severity pie chart** — distribution of event severities
- **Top event types** — horizontal bar chart
- **Top source IPs** — bar chart of most active IPs
- **Connection indicator** — shows live/reconnecting status

## Project Structure

```
siem/
├── backend/
│   ├── main.py          # FastAPI app, WebSocket, REST API
│   ├── ingestion.py     # Log ingestion endpoints + Redis consumer
│   ├── parser.py        # Log parsers (Apache, syslog, iptables)
│   ├── rules.py         # Detection rules engine
│   ├── database.py      # SQLite setup and helpers
│   ├── schemas.py       # Pydantic models
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx      # WebSocket + data fetching
│   │   ├── Dashboard.jsx # Charts and tables
│   │   └── index.jsx
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```
