<div align="center">
##This project was first named Mapper, but Sentry sounded better, so it was renamed. Just FYI.

    
#  SENTRY
### AI-Powered Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=flat-square&logo=elasticsearch)](https://elastic.co)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?style=flat-square&logo=googlechrome)](https://developer.chrome.com/docs/extensions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Sentry** is an open-source web vulnerability scanner with a Chrome extension, web dashboard, AI-powered analysis (Groq / Gemini / OpenAI), Elasticsearch-backed storage, and a full active + passive scanning engine.


</div>

---

## Features

| Capability | Details |
|---|---|
| **Passive Scanning** | Header analysis, cookie flags, mixed content, missing HSTS/CSP/X-Frame-Options |
| **Active Scanning** | XSS, SQL injection, open redirect, SSRF, path traversal probes |
| **345 Detection Rules** | Curated Nuclei-based ruleset, pre-screened for performance |
| **AI Analysis** | Executive summaries, OWASP coverage, prioritized remediation via Groq / Gemini / OpenAI |
| **Chrome Extension** | Side-panel AI chat, live scan monitoring, one-click scan from any tab |
| **Web Dashboard** | Full scan history, findings explorer, CVSS scores, export (JSON / HTML) |
| **Elasticsearch** | Persistent scan storage, full-text search across findings |

---

## Architecture

```
mapper/
├── backend/          # Flask API + scanning engine
│   ├── scanner/
│   │   ├── orchestrator.py   # Scan pipeline (fetch → normalize → match → probe)
│   │   ├── fetcher.py        # requests-based async HTTP (Python 3.14 safe)
│   │   ├── normalizer.py     # HTML parsing, snapshot building (lxml)
│   │   ├── matcher.py        # 345-rule pattern engine
│   │   └── active_checks.py  # XSS / SQLi / redirect probes
│   ├── engine/               # CVSS scoring, risk grading
│   ├── storage/              # Elasticsearch + local JSON storage
│   ├── export/               # HTML / JSON report generation
│   └── app.py                # Flask routes + AI proxy
├── frontend/         # Web dashboard (vanilla HTML/CSS/JS)
├── extension/        # Chrome extension (MV3)
│   ├── sidepanel/    # AI chat panel
│   ├── popup/        # Quick scan popup
│   ├── dashboard/    # Extension dashboard
│   └── options/      # Settings page
└── data/
    ├── nuclei_cache.json     # Pre-screened detection rules
    └── safe_versions.json    # Known-safe library versions
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Elasticsearch 8.x running on `https://localhost:9200`
- A Groq API key (free at [console.groq.com](https://console.groq.com)) **or** Gemini API key

### 1. Clone & install

```bash
git clone https://github.com/YOUR_USERNAME/sentry.git
cd sentry
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 3. Start Elasticsearch

```bash
# Using Docker:
docker run -d --name es \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -p 9200:9200 \
  elasticsearch:8.13.0
```

### 4. Start the backend

```bash
cd backend
source ../venv/bin/activate
python app.py
# Backend runs on http://127.0.0.1:5001
```

### 5. Open the web dashboard

Navigate to `http://127.0.0.1:5001` in your browser.

Default credentials: `admin` / `admin123` *(change after first login)*

### 6. Load the Chrome extension (optional)

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`:

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | Groq / OpenAI compatible key | — |
| `OPENAI_BASE_URL` | API base URL | `https://api.groq.com/openai/v1` |
| `OPENAI_MODEL` | Model name | `llama-3.3-70b-versatile` |
| `GEMINI_API_KEY` | Google Gemini key (fallback) | — |
| `ES_HOST` | Elasticsearch URL | `https://localhost:9200` |
| `ES_VERIFY_CERTS` | Verify ES TLS certs | `false` |
| `FLASK_SECRET_KEY` | Flask session secret | auto-generated |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Authenticate, get JWT |
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/scan/:id` | Get scan status + progress |
| `GET` | `/api/scan/:id/report` | Get full report with findings |
| `GET` | `/api/scans` | List all scans |
| `DELETE` | `/api/scan/:id` | Delete scan |
| `GET` | `/api/health` | Health check (ES + rules status) |
| `POST` | `/api/ai/analyze` | AI analysis proxy |

---

## Scan Modes

| Mode | Description |
|---|---|
| `passive` | Headers, cookies, body patterns only — no requests sent to the target beyond the initial fetch |
| `full_active` | Passive + active injection probes (XSS, SQLi, open redirect, path traversal) |

> ⚠️ **Only scan targets you own or have explicit written permission to test.**

---

## Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit: `git commit -m 'feat: add my feature'`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
Built with ♥ for security researchers and developers.
</div>
