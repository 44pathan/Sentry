# Mapper Vulnerability Scanner — Testing Guide

## Architecture

```
┌─────────────────┐     HTTP/REST     ┌──────────────────┐
│  Frontend (UI)  │ ◄──────────────►  │  Backend (Flask)  │
│  Port 8081      │                   │  Port 5001        │
│  index.html     │                   │  app.py           │
└─────────────────┘                   └──────┬───────────┘
                                             │ (optional)
                                     ┌───────▼────────┐
                                     │ Elasticsearch   │
                                     │ Port 9200       │
                                     └────────────────┘
```

---

## Step 1: Install Dependencies

```bash
cd /home/halalhacker/mapper/backend
pip install -r requirements.txt
```

---

## Step 2: Start the Backend (Port 5001)

```bash
cd /home/halalhacker/mapper/backend
python3 app.py
```

On first startup, it will:
- Detect the placeholder admin hash and **auto-reset** it
- Log: `[Init] Reset admin password to 'admin123'`
- Start on `http://0.0.0.0:5001`

> **Default credentials:** `admin` / `admin123`

Leave this terminal running and open a **second terminal** for the next steps.

---

## Step 3: Start the Frontend (Port 8081)

```bash
cd /home/halalhacker/mapper/frontend
python3 -m http.server 8081
```

Open your browser: **http://localhost:8081**

---

## Step 4: Test via the UI

1. **Login** — Enter `admin` / `admin123`
2. **Dashboard** — See stats (all zeros initially)
3. **New Scan** — Enter a URL like `https://example.com`, check all options, confirm authorization, click "Start Scan"
4. **Watch progress** — The progress bar updates every 2 seconds
5. **View Report** — Automatically redirects when scan completes. Shows risk gauge, severity breakdown, OWASP coverage, and findings

---

## Step 5: Test via curl (API reference)

Open a **third terminal**.

### Health Check (no auth)
```bash
curl http://127.0.0.1:5001/api/health
```

### Login
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "Token: $TOKEN"
```

### Submit a Scan
```bash
SCAN_ID=$(curl -s -X POST http://127.0.0.1:5001/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url":"https://example.com","authorized":true}' | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")

echo "Scan ID: $SCAN_ID"
```

### Check Scan Status
```bash
curl -s http://127.0.0.1:5001/api/scan/$SCAN_ID \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Get Full Report
```bash
curl -s http://127.0.0.1:5001/api/scan/$SCAN_ID/report \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### List All Scans
```bash
curl -s http://127.0.0.1:5001/api/scans \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### View Rules
```bash
curl -s http://127.0.0.1:5001/api/rules \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Get Stats
```bash
curl -s http://127.0.0.1:5001/api/stats \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Step 6: (Optional) Install Nuclei Templates

This adds ~200 curated detection rules from ProjectDiscovery's Nuclei:

```bash
cd /home/halalhacker/mapper/data
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git
```

Then restart the backend — it will auto-import templates on startup.

---

## Step 7: (Optional) Install Wappalyzer Data

For technology fingerprinting via Wappalyzer:

```bash
cd /home/halalhacker/mapper/data
mkdir -p wappalyzer
# Download from: https://github.com/wappalyzer/wappalyzer
# Copy src/technologies/*.json into data/wappalyzer/
```

---

## Port Summary

| Service | Port | Command |
|---|---|---|
| WatchLogs Backend | 5000 | (already running) |
| **Mapper Backend** | **5001** | `cd backend && python3 app.py` |
| Filebeat | 5044 | (already running) |
| WatchLogs UI | 8080 | (already running) |
| **Mapper UI** | **8081** | `cd frontend && python3 -m http.server 8081` |
| Elasticsearch | 9200 | (already running) |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Address already in use :5001` | Kill existing process: `lsof -ti:5001 \| xargs kill` |
| ES connection warning | Normal — backend works in memory-only mode without ES |
| Login fails | Backend auto-resets admin hash on first run. Restart backend. |
| CORS errors in browser | Make sure backend is running on 5001 and you access UI via localhost |
| Scan stuck at "fetching" | Target might be unreachable. Check backend terminal for errors. |
