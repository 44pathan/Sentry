# SENTRY — Complete Project Guide

> AI-Powered Web Vulnerability Scanner | Backend · Web Dashboard · Chrome Extension

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Backend](#3-backend)
   - [Flask API Layer](#31-flask-api-layer)
   - [Authentication System](#32-authentication-system)
   - [Configuration](#33-configuration)
4. [Scanner Engine](#4-scanner-engine)
   - [Orchestrator Pipeline](#41-orchestrator-pipeline)
   - [Fetcher](#42-fetcher)
   - [Normalizer](#43-normalizer)
   - [Matcher (Passive Rules)](#44-matcher-passive-rules)
   - [Active Checks](#45-active-checks)
   - [Passive Checks](#46-passive-checks)
5. [Storage Layer](#5-storage-layer)
6. [Engine — Scoring & Enrichment](#6-engine--scoring--enrichment)
7. [Export System](#7-export-system)
8. [AI Integration](#8-ai-integration)
9. [Web Dashboard (Frontend)](#9-web-dashboard-frontend)
10. [Chrome Extension](#10-chrome-extension)
    - [Popup](#101-popup)
    - [Side Panel](#102-side-panel)
    - [Dashboard](#103-dashboard)
    - [Options Page](#104-options-page)
11. [Data Files](#11-data-files)
12. [Security Model](#12-security-model)
13. [Performance Optimizations](#13-performance-optimizations)
14. [API Reference](#14-api-reference)
15. [Tech Stack Summary](#15-tech-stack-summary)

---

## 1. Project Overview

**Sentry** is a full-stack, open-source web vulnerability scanner built for security researchers, penetration testers, and developers. It combines:

- A **Python/Flask backend** that runs a multi-stage scanning pipeline
- A **web dashboard** (vanilla JS) for reviewing findings, managing scans, and generating reports
- A **Chrome Extension (MV3)** that lets you scan the current tab directly from your browser with an AI-powered side panel

**Core capabilities:**

| Capability | Description |
|---|---|
| Passive Scanning | Inspects HTTP headers, cookies, page content without sending any extra requests |
| Active Scanning | Injects payloads (XSS, SQLi, open redirect, path traversal) into discovered parameters |
| AI Analysis | Executive summaries, OWASP coverage, prioritized remediation via Groq |
| Risk Scoring | CVSS 3.1-based risk grade (A–F) with overall risk score 0–100 |
| Elasticsearch Storage | Full scan history, findings search, persistent across restarts |
| Report Export | HTML and JSON reports, downloadable per scan |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                              │
│                                                                  │
│   ┌──────────────────┐    ┌──────────────────────────────────┐  │
│   │  Chrome Extension│    │       Web Dashboard              │  │
│   │  (MV3)           │    │  (frontend/ — Vanilla JS/CSS)    │  │
│   │                  │    │                                  │  │
│   │  popup/          │    │  index.html + app.js + style.css │  │
│   │  sidepanel/      │    │                                  │  │
│   │  dashboard/      │    └──────────────┬───────────────────┘  │
│   │  options/        │                   │                       │
│   └────────┬─────────┘                   │                       │
│            │  REST API (JWT)             │                       │
└────────────┼─────────────────────────────┼───────────────────────┘
             │                             │
             ▼                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FLASK BACKEND  :5001                           │
│                                                                  │
│  app.py ─── REST routes ──┬── auth.py (JWT)                     │
│                           ├── config.py (env vars)              │
│                           ├── Scanner Engine                    │
│                           │    orchestrator.py                  │
│                           │    fetcher.py                       │
│                           │    normalizer.py                    │
│                           │    matcher.py (345 rules)           │
│                           │    active_checks.py                 │
│                           │    passive_checks.py                │
│                           │    surface_extractor.py             │
│                           │                                     │
│                           ├── engine/                           │
│                           │    risk_scorer.py                   │
│                           │    cvss_enricher.py                 │
│                           │    owasp_mapper.py                  │
│                           │                                     │
│                           ├── storage/__init__.py               │
│                           ├── export/report_exporter.py         │
│                           └── AI Proxy ── Groq API              │
│                                                                  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
             ┌─────────────────┼───────────────────┐
             ▼                 ▼                   ▼
    ┌─────────────────┐  ┌──────────┐   ┌─────────────────┐
    │  Elasticsearch  │  │  Local   │   │   Groq API      │
    │  (port 9200)    │  │  JSON    │   │ (api.groq.com)  │
    │  Scan storage   │  │  Fallback│   │ qwen3-8b model  │
    └─────────────────┘  └──────────┘   └─────────────────┘
```

---

## 3. Backend

### 3.1 Flask API Layer

**File:** `backend/app.py` (~960 lines)

The central hub. Responsibilities:
- Defines all REST routes under `/api/`
- Manages the scan job queue (in-memory `_jobs` dict, persisted to ES)
- Spawns scanner tasks in a `ThreadPoolExecutor`
- Proxies AI requests to Groq
- Handles CORS for the extension and web dashboard

**Key design decisions:**
- Uses Python's `asyncio` + `run_in_executor` so the async scanner runs inside a sync Flask thread pool
- Each scan is assigned a UUID `scan_id` at submission time
- Scan progress is stored in-memory during the scan and persisted to Elasticsearch on completion

**Route groups:**

| Prefix | Purpose |
|---|---|
| `/api/auth/*` | Login, logout, verify, change password |
| `/api/scan` | Submit scan, get status, get report, delete, list |
| `/api/stats` | Dashboard summary stats |
| `/api/rules` | View/reload detection rules |
| `/api/ai/*` | AI analysis proxy (analyze, stream, status) |
| `/api/export/*` | Download HTML/JSON reports |
| `/api/health` | ES connection + rules count check |
| `/api/debug/*` | Restart, logs (admin only) |

---

### 3.2 Authentication System

**File:** `backend/auth.py`

JWT-based authentication with:
- `handle_login()` — verifies bcrypt password hash, issues a signed JWT (24h expiry)
- `handle_logout()` — client-side token discard (stateless JWT)
- `require_auth` decorator — validates `Authorization: Bearer <token>` on protected routes; returns `401` if missing/invalid
- `require_scan_permission` decorator — checks user role or `can_scan` flag

**User storage:** `backend/users.json` (gitignored). Passwords are bcrypt-hashed via Werkzeug.

**JWT payload:**
```json
{ "sub": "admin", "role": "admin", "iat": 1726425600, "exp": 1726512000 }
```

---

### 3.3 Configuration

**File:** `backend/config.py` — all settings from environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | — | Groq API key |
| `OPENAI_BASE_URL` | `https://api.groq.com/openai/v1` | AI endpoint |
| `OPENAI_MODEL` | `qwen/qwen3.8-27b` | Model name |
| `ES_HOST` | `https://localhost:9200` | Elasticsearch URL |
| `FLASK_HOST` | `127.0.0.1` | Bind address |
| `SENTRY_PORT` | `5001` | Listen port |
| `MAX_BODY_SIZE` | `200000` | Max body to fetch (200KB) |
| `RATE_LIMIT` | `10` | Requests/sec for active scans |

---

## 4. Scanner Engine

Lives in `backend/scanner/`. A **5-stage pipeline** coordinated by the orchestrator.

### 4.1 Orchestrator Pipeline

**File:** `backend/scanner/orchestrator.py`

```
Stage 1: FETCH
  └── GET target URL, follow redirects, capture headers + body

Stage 2: NORMALIZE
  └── Parse HTML with lxml, extract forms/links/scripts/cookies
  └── Build PageSnapshot dataclass

Stage 3: ANALYZE (Passive)
  └── Run 345 Nuclei-based rules against snapshot
  └── Check 9 exposed paths concurrently (/.git/config, /.env, etc.)
  └── Run passive_checks.py (headers, cookies, mixed content)

Stage 4: ACTIVE PROBING (full_active mode only)
  └── Extract injectable parameters from forms + URL query strings
  └── Run XSS, SQLi, open redirect, path traversal, SSRF probes

Stage 5: CORRELATE
  └── Deduplicate findings, CVSS scoring, OWASP mapping
  └── Calculate risk score and grade
  └── Persist to Elasticsearch
```

**Progress:** Each stage updates `job.progress` (0–100%) and `job.status`:
`queued → fetching → analyzing → active_probing → correlating → completed/failed`

---

### 4.2 Fetcher

**File:** `backend/scanner/fetcher.py`

- Wraps `requests` library, usable from async code via `run_in_executor`
- **Timeout:** `(5, 8)` — 5s connect, 8s read
- **Body cap:** Reads up to `MAX_BODY_SIZE` (200KB)
- **SSL:** `verify=False` — handles self-signed certs on scan targets

> **Why not aiohttp?** Python 3.14's ssl module has a cancellation bug causing SIGKILL on certain TLS handshakes. `requests` is synchronous but stable.

---

### 4.3 Normalizer

**File:** `backend/scanner/normalizer.py`

Parses raw HTTP response into a `PageSnapshot` using **lxml** (3x faster than `html.parser`):

```
PageSnapshot fields:
  url, final_url, status_code, headers
  body (raw HTML, capped 200KB), body_lower
  title, scripts, inline_scripts
  forms [{action, method, inputs [{name, type}]}]
  links, cookies, meta_tags, tech_hints
```

---

### 4.4 Matcher (Passive Rules)

**File:** `backend/scanner/matcher.py`

Applies 345 rules from `data/nuclei_cache.json`. Rule types:

| Matcher Type | Method |
|---|---|
| `word` | Fast substring search on `body_lower` |
| `regex` | Compiled `re.search` on body (capped at 100KB) |
| `status` | HTTP status code check |
| `header` | Response header check |

**Performance guard:** Rules pre-screened to remove catastrophic backtracking patterns (`(?=.*X)` lookaheads that caused SIGKILL on large pages).

---

### 4.5 Active Checks

**File:** `backend/scanner/active_checks.py`

| Probe Type | Payload | Detection |
|---|---|---|
| Reflected XSS | `"><script>alert(1)</script>` | Payload reflected in body |
| SQL Injection | `' OR '1'='1` | Error strings in response |
| Blind SQLi | `'; WAITFOR DELAY '0:0:5'--` | Response time > sleep duration |
| Open Redirect | `//evil.com` | `Location:` header check |
| Path Traversal | `../../etc/passwd` | `root:x:0:0` in response |
| SSRF | `http://169.254.169.254/` | Internal metadata endpoint |

Each probe has a **6-second timeout**. All probes run concurrently via `asyncio.gather`.

---

### 4.6 Passive Checks

**File:** `backend/scanner/passive_checks.py`

Checks run without sending additional requests:

| Check | What it looks for |
|---|---|
| Missing HSTS | No `Strict-Transport-Security` header |
| Missing CSP | No `Content-Security-Policy` header |
| Missing X-Frame-Options | No clickjacking protection |
| Cookie flags | `HttpOnly`, `Secure`, `SameSite` missing |
| Mixed Content | HTTP resources on HTTPS page |
| Info disclosure | `Server`, `X-Powered-By` leaking version info |
| Outdated libraries | jQuery/Bootstrap/WP vs `safe_versions.json` |

---

## 5. Storage Layer

**File:** `backend/storage/__init__.py` — dual-mode: Elasticsearch primary, JSON fallback.

```
save_job() ──► _memory_jobs (in-memory, thread-safe)
                     │ on completion
                     ▼
              Elasticsearch  OR  scans_db.json (fallback)

get_all_jobs() merges ES history + in-memory running scans
```

**ES Indices:** `sentry-scans` (one doc per scan) + `sentry-findings` (individual findings for full-text search)

---

## 6. Engine — Scoring & Enrichment

### Risk Scorer (`backend/engine/risk_scorer.py`)

```
score = critical×25 + high×15 + medium×8 + low×3 + info×0.5  (capped 100)

Grade:  0–20 → A   21–40 → B   41–60 → C   61–80 → D   81–100 → F
```

### CVSS Enricher (`backend/engine/cvss_enricher.py`)

| Vulnerability | CVSS Score |
|---|---|
| SQL Injection (confirmed) | 9.8 |
| Reflected XSS (confirmed) | 6.1 |
| Path Traversal | 7.5 |
| Open Redirect | 6.1 |
| Missing HSTS | 4.3 |
| Exposed .env | 9.1 |

### OWASP Mapper (`backend/engine/owasp_mapper.py`)

Maps each finding to **OWASP Top 10 2021** (A01–A10) and **OWASP Top 10 2025**.

---

## 7. Export System

**File:** `backend/export/report_exporter.py`

- **HTML Report** — Self-contained single-file HTML (embedded CSS). Executive summary, findings with severity badges, CVSS scores, evidence, remediation steps.
- **JSON Report** — Full structured JSON with all metadata, findings, OWASP coverage, risk score, active probe log.

---

## 8. AI Integration

```
User clicks "Executive Summary"
         │
frontend/_buildPrompt() ── compacts scan data, injects real scan date
         │
POST /api/ai/analyze ── authenticated
         │
_ai_generate() ── calls Groq with OPENAI_API_KEY
         │
Groq → qwen/qwen3-8b ── max 2000 tokens
         │
Markdown response rendered in UI
```

**Available AI actions:**

| Action | Output |
|---|---|
| Executive Summary | Management overview, risk grade, business impact, priority actions |
| Prioritize Fixes | Ordered remediation plan with effort estimates |
| OWASP Analysis | Coverage against OWASP Top 10, gap analysis |
| Explain Finding | Plain-English explanation with attack scenarios |
| Free-form chat | Open questions about scan results |

Extension side panel uses **streaming SSE** (`/api/ai/stream`) for token-by-token display.

---

## 9. Web Dashboard (Frontend)

**Files:** `frontend/index.html`, `frontend/app.js`, `frontend/style.css`

Single-page vanilla JS app. All state in one `App` object.

| Page | Content |
|---|---|
| Dashboard | Stats summary, recent 5 scans |
| New Scan | URL input, scan mode, live progress ring |
| All Scans | Full history table with risk grade, findings count |
| Report | Findings list, filter/sort/group, AI panel, export |
| Rules | All 345 detection rules, reload button |
| Settings | Backend URL, rate limit, defaults |

**Performance features:**
- Findings render in chunks of 20 via `requestAnimationFrame`
- `content-visibility: auto` on finding cards
- Polling only when active scans exist (5s interval)
- Specific CSS transitions instead of `transition: all`

---

## 10. Chrome Extension

MV3 extension with 4 UI surfaces + shared utilities.

### 10.1 Popup

Click the Sentry toolbar icon:
- Connection status dot
- Current tab URL
- Scan mode selector + Authorization checkbox
- Scan button → live progress ring → risk score gauge
- Recent 5 scans list

### 10.2 Side Panel

Persistent side panel (Chrome `sidePanel` API):

**AI Analysis tab:** Scan selector → Quick actions (Summary / Prioritize / OWASP) → Streaming chat area → Input box

**Live Scans tab:** Real-time scan list with progress bars, status badges, View/Download/Delete per scan

### 10.3 Dashboard

Opens as a new tab — full scan management:
- All scans table
- Detailed report view (findings, CVSS, evidence, active probe log)
- AI analysis panel
- HTML/JSON export

### 10.4 Options Page

Settings stored in `chrome.storage.local`:
- Backend URL, default scan mode, rate limit
- Auto-scan on popup open
- Notification preferences
- Login / Logout

---

## 11. Data Files

| File | Size | Purpose |
|---|---|---|
| `data/nuclei_cache.json` | ~335KB | 345 pre-screened detection rules |
| `data/safe_versions.json` | ~10KB | Known-safe library versions |
| `data/nuclei-templates/` | gitignored | Raw Nuclei YAML source templates |
| `data/wappalyzer/` | gitignored | Tech fingerprinting database |
| `data/scans_db.json` | gitignored | Local JSON fallback for scan results |

---

## 12. Security Model

| Aspect | Implementation |
|---|---|
| Authentication | JWT, 24h expiry, signed with auto-generated random secret |
| Protected routes | `@require_auth` decorator, returns 401 for invalid/missing tokens |
| CORS | Restricted to `localhost:5001`, `localhost:3000`, `chrome-extension://` |
| SSRF protection | Block list: `localhost`, `127.0.0.1`, `::1`, `metadata.google.internal` |
| XSS prevention | `esc()` helper in all JS files, escapes all server data before `innerHTML` |
| Server binding | `127.0.0.1` by default (LAN exposure requires explicit `FLASK_HOST=0.0.0.0`) |
| Secrets | All API keys via env vars, never hardcoded; `.jwt_secret` auto-generated |

---

## 13. Performance Optimizations

| Optimization | Impact |
|---|---|
| lxml over html.parser | 3x faster HTML parsing |
| Body cap at 100KB in matcher | Halves regex search space |
| Pre-screened rules (no lookaheads) | Prevents SIGKILL from backtracking |
| 9 parallel workers for path checks | All paths checked simultaneously |
| `content-visibility: auto` on cards | Browser skips off-screen paint |
| Chunked findings rendering (20/frame) | No main thread blocking |
| Poll only during active scans (5s) | Zero traffic when idle |
| Tuple `(connect, read)` timeouts | Faster failure on SSL hangs |

---

## 14. API Reference

All endpoints require `Authorization: Bearer <token>` unless marked *(public)*.

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Get JWT — body: `{username, password}` |
| GET | `/api/auth/verify` | Check token validity |
| POST | `/api/auth/logout` | Logout |
| POST | `/api/auth/change-password` | Change password |

### Scans
| Method | Path | Description |
|---|---|---|
| POST | `/api/scan` | Start scan — body: `{url, authorized, scan_mode, rate_limit}` |
| GET | `/api/scan/:id` | Status + progress |
| GET | `/api/scan/:id/report` | Full report with findings |
| DELETE | `/api/scan/:id` | Delete scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/stats` | Dashboard summary |

### AI
| Method | Path | Description |
|---|---|---|
| POST | `/api/ai/analyze` | AI analysis — body: `{prompt, systemPrompt, temperature, maxTokens}` |
| POST | `/api/ai/stream` | Streaming AI (SSE) — same body |
| GET | `/api/ai/status` | AI config info *(public)* |

### Misc
| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | ES status + rules count *(public)* |
| GET | `/api/rules` | List detection rules |
| POST | `/api/rules/reload` | Reload rules from disk |
| GET | `/api/export/html/:id` | Download HTML report |
| GET | `/api/export/json/:id` | Download JSON report |

---

## 15. Tech Stack Summary

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.x, Werkzeug |
| HTTP scanning | `requests` (sync, Python 3.14 safe) |
| HTML parsing | BeautifulSoup4 + lxml |
| Storage | Elasticsearch 8.x + JSON fallback |
| Authentication | JWT (PyJWT), bcrypt (Werkzeug) |
| AI | Groq API, `qwen/qwen3-8b` model |
| Frontend | Vanilla HTML/CSS/JS — no frameworks |
| Extension | Chrome MV3, `sidePanel` API |
| Detection rules | 345 pre-screened Nuclei rules |
| Scoring | CVSS 3.1, OWASP Top 10 2021 + 2025 |

---

*Sentry v1.0.0 — September 2026*
