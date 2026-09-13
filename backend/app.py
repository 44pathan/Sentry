"""
app.py — Main Flask API for the Vulnerability Scanner
Adapted from the WatchLogs SIEM backend (app.py).
Provides REST endpoints for scan submission, results retrieval,
risk scoring, rule management, and CVE enrichment.
"""

import os
import sys
import json
import logging
import threading
import uuid as uuid_mod
import requests as http_requests

from flask import Flask, jsonify, request
try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False

# Ensure backend/ is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    ES_HOST, ES_USER, ES_PASS, ES_VERIFY_CERTS,
    SCAN_RULES_PATH, SAFE_VERSIONS_PATH,
    WAPPALYZER_DATA_PATH, NUCLEI_TEMPLATES_PATH,
    MAPPER_PORT, USERS_PATH, ALLOWED_ORIGINS,
    GEMINI_API_KEY, GEMINI_MODEL
)
from auth import (
    require_auth, require_scan_permission, handle_login, handle_verify,
    handle_logout, handle_change_password, handle_register
)
from scanner.orchestrator import ScanOrchestrator
from engine.risk_scorer import RiskScorer
from enrichment.cve_enricher import CVEEnricher

# ── Logging ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ── Flask App ──────────────────────────────────────────────
app = Flask(__name__)

if HAS_CORS:
    CORS(app, resources={r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }})


@app.after_request
def add_headers(response):
    origin = request.headers.get("Origin", "")
    allowed = [o.strip() for o in ALLOWED_ORIGINS]

    # If "*" is in allowed list, accept any origin but echo back the actual
    # origin (browsers reject credentials with literal "*")
    # This also handles chrome-extension:// origins from the browser extension
    if "*" in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin if origin else "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    elif origin in allowed or origin.startswith("chrome-extension://"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


# ── Elasticsearch (optional) ──────────────────────────────
es = None
if ES_PASS:  # Only attempt ES connection if password is configured
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(
            ES_HOST,
            basic_auth=(ES_USER, ES_PASS),
            verify_certs=ES_VERIFY_CERTS
        )
        if es.ping():
            logger.info("[ES] Connected to Elasticsearch")
        else:
            logger.warning("[ES] Elasticsearch not reachable — running without ES")
            es = None
    except ImportError:
        logger.warning("[ES] elasticsearch package not installed — running in memory-only mode")
    except Exception as e:
        logger.warning(f"[ES] Elasticsearch unavailable: {e} — running in memory-only mode")
        es = None
else:
    logger.info("[ES] No ES_PASS configured — running in memory-only mode")

# ── Initialize components ─────────────────────────────────
orchestrator = ScanOrchestrator(es_client=es)
cve_enricher = CVEEnricher()

# ── Thread-safe rules management ──────────────────────────
_rules_lock = threading.Lock()
_rules = []


def load_all_rules():
    """Load scan rules from JSON + optional imported data."""
    all_rules = []

    # 1. Load curated scan rules
    if os.path.exists(SCAN_RULES_PATH):
        try:
            with open(SCAN_RULES_PATH, "r") as f:
                curated = json.load(f)
            all_rules.extend(curated)
            logger.info(f"Loaded {len(curated)} curated scan rules")
        except Exception as e:
            logger.error(f"Failed to load scan rules: {e}")

    # 2. Import Wappalyzer data if available
    safe_versions = {}
    if os.path.exists(SAFE_VERSIONS_PATH):
        try:
            with open(SAFE_VERSIONS_PATH, "r") as f:
                safe_versions = json.load(f)
        except Exception:
            pass

    if os.path.exists(WAPPALYZER_DATA_PATH):
        try:
            from importers.wappalyzer_importer import import_wappalyzer_data
            wap_rules = import_wappalyzer_data(WAPPALYZER_DATA_PATH, safe_versions)
            all_rules.extend(wap_rules)
            logger.info(f"Imported {len(wap_rules)} Wappalyzer rules")
        except Exception as e:
            logger.warning(f"Wappalyzer import failed: {e}")

    # 3. Import Nuclei templates if available
    if os.path.exists(NUCLEI_TEMPLATES_PATH):
        try:
            from importers.nuclei_importer import import_nuclei_templates
            nuc_rules = import_nuclei_templates(NUCLEI_TEMPLATES_PATH)
            all_rules.extend(nuc_rules)
            logger.info(f"Imported {len(nuc_rules)} Nuclei rules")
        except Exception as e:
            logger.warning(f"Nuclei import failed: {e}")

    return all_rules


def _init_rules():
    global _rules
    with _rules_lock:
        _rules = load_all_rules()
        orchestrator.load_rules(_rules)
    logger.info(f"[Init] Total detection rules loaded: {len(_rules)}")

_init_rules()


# ── Helpers ────────────────────────────────────────────────

def _is_valid_uuid(val: str) -> bool:
    """Validate UUID format to prevent injection."""
    try:
        uuid_mod.UUID(val, version=4)
        return True
    except (ValueError, AttributeError):
        return False


# ═══════════════════════════════════════════════════════════
#  AUTH ENDPOINTS (ported from SIEM)
# ═══════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def login():
    return handle_login()

@app.route("/api/auth/register", methods=["POST"])
def register():
    return handle_register()

@app.route("/api/auth/verify", methods=["GET"])
def verify():
    return handle_verify()

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    return handle_logout()

@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def change_password():
    return handle_change_password()


# ═══════════════════════════════════════════════════════════
#  SCAN ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
@require_auth
@require_scan_permission
def submit_scan():
    """Submit a URL for vulnerability scanning."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    target_url = (data.get("url") or "").strip()
    if not target_url:
        return jsonify({"status": "error", "message": "URL is required"}), 400

    # Basic URL validation
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # SSRF protection — block internal IPs
    import ipaddress
    from urllib.parse import urlparse
    import socket

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        return jsonify({"status": "error", "message": "Invalid URL"}), 400

    # Block obviously dangerous hostnames (only when debug is False)
    if not app.debug:
        blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"}
        if hostname.lower() in blocked_hosts:
            return jsonify({
                "status": "error",
                "message": "Scanning internal/private addresses is not allowed"
            }), 403

        try:
            resolved = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(resolved)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                return jsonify({
                    "status": "error",
                    "message": "Scanning internal/private addresses is not allowed"
                }), 403
        except (socket.gaierror, ValueError):
            pass  # Allow if DNS resolution fails (might be a CDN)

    # Authorization attestation
    authorized = data.get("authorized", False)
    if not authorized:
        return jsonify({
            "status": "error",
            "message": "You must confirm authorization to scan this target"
        }), 403

    options = {
        "deep_scan": data.get("deep_scan", True),
        "check_headers": data.get("check_headers", True),
        "check_tls": data.get("check_tls", True),
        "scan_mode": data.get("scan_mode", "passive"),  # "passive" | "light_active" | "full_active"
        "submitted_by": request.auth_user,
        "auth_cookies": data.get("auth_cookies", ""),    # e.g. "session=abc123; csrf=xyz"
        "auth_headers": data.get("auth_headers", ""),    # e.g. "Authorization: Bearer eyJ..."
        "rate_limit": int(data.get("rate_limit", 0)),    # requests per second (0 = unlimited)
    }

    # Validate scan_mode
    valid_modes = {"passive", "light_active", "full_active"}
    if options["scan_mode"] not in valid_modes:
        options["scan_mode"] = "passive"

    job = orchestrator.submit_scan(target_url, options)

    logger.info(f"[Scan] User '{request.auth_user}' submitted scan for {target_url} (ID: {job.scan_id[:8]})")

    return jsonify({
        "status": "ok",
        "scan_id": job.scan_id,
        "target_url": target_url,
        "message": "Scan submitted successfully"
    }), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
@require_auth
def get_scan_status(scan_id):
    """Get scan job status and progress."""
    if not _is_valid_uuid(scan_id):
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400

    job = orchestrator.get_job(scan_id)
    if not job:
        return jsonify({"status": "error", "message": "Scan not found"}), 404

    return jsonify({
        "status": "ok",
        "scan": job.to_dict()
    })


@app.route("/api/scan/<scan_id>/results", methods=["GET"])
@require_auth
def get_scan_results(scan_id):
    """Get scan findings."""
    if not _is_valid_uuid(scan_id):
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400

    job = orchestrator.get_job(scan_id)
    if not job:
        return jsonify({"status": "error", "message": "Scan not found"}), 404

    if job.status not in ("completed", "failed"):
        return jsonify({
            "status": "ok",
            "scan_status": job.status,
            "progress": job.progress,
            "message": "Scan is still in progress",
            "findings": []
        })

    findings = orchestrator.get_findings(scan_id)

    # Optional severity filter
    severity = request.args.get("severity", "")
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]

    # Optional OWASP category filter
    owasp = request.args.get("owasp", "")
    if owasp:
        findings = [f for f in findings if owasp.lower() in f.get("owasp_category", "").lower()]

    return jsonify({
        "status": "ok",
        "scan_id": scan_id,
        "target_url": job.target_url,
        "scan_status": job.status,
        "total_findings": len(findings),
        "findings": findings
    })


@app.route("/api/scan/<scan_id>/report", methods=["GET"])
@require_auth
def get_scan_report(scan_id):
    """Get full scan report with risk score, findings, and recommendations."""
    if not _is_valid_uuid(scan_id):
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400

    job = orchestrator.get_job(scan_id)
    if not job:
        return jsonify({"status": "error", "message": "Scan not found"}), 404

    if job.status == "failed":
        return jsonify({
            "status": "error",
            "scan_status": "failed",
            "message": f"Scan failed: {job.error or 'Unknown error'}",
            "error": job.error or "Unknown error"
        })

    if job.status != "completed":
        return jsonify({
            "status": "ok",
            "scan_status": job.status,
            "progress": job.progress,
            "message": "Scan not yet completed"
        })

    findings = orchestrator.get_findings(scan_id)

    # Enrich CVE findings
    cve_enricher.enrich_findings(findings)

    # Recalculate risk with enriched data
    risk = orchestrator.risk_scorer.calculate(findings)

    # Guard against stale/empty findings after service restart:
    # If the job recorded findings but storage returned none (e.g. ES
    # index unavailable after restart), fall back to the job's stored
    # risk data so we never show A+ for a site that actually had vulns.
    if not findings and job.findings_count > 0:
        logger.warning(
            f"[Report] Findings lost for scan {scan_id[:8]} "
            f"(job says {job.findings_count}, storage returned 0). "
            f"Using stored risk data."
        )
        risk["score"] = job.risk_score
        risk["grade"] = job.risk_grade
        # Rebuild grade_label from stored grade
        from engine.risk_scorer import GRADE_THRESHOLDS
        risk["grade_label"] = next(
            (label for lo, hi, g, label in GRADE_THRESHOLDS if g == job.risk_grade),
            "Unknown"
        )
        risk["breakdown"] = job.severity_breakdown or risk["breakdown"]
        risk["summary"] = (
            f"This scan originally found {job.findings_count} findings "
            f"with a risk score of {job.risk_score}/100 (Grade {job.risk_grade}). "
            f"Detailed findings are no longer available — the backend was restarted "
            f"and Elasticsearch may not have persisted them. Re-scan the target to "
            f"get full details."
        )

    return jsonify({
        "status": "ok",
        "report": {
            "scan_id": scan_id,
            "target_url": job.target_url,
            "scanned_at": job.started_at,
            "completed_at": job.completed_at,
            "scan_duration_ms": job.scan_duration_ms,
            "technologies": job.technologies,
            "risk_score": risk["score"],
            "risk_grade": risk["grade"],
            "risk_grade_label": risk["grade_label"],
            "summary": risk["summary"],
            "vulnerability_summary": risk["vulnerability_summary"],
            "risk_formula": risk["risk_formula"],
            "severity_breakdown": risk["breakdown"],
            "top_fixes": risk["top_fixes"],
            "owasp_coverage": risk["owasp_coverage"],
            "owasp_2025_coverage": risk.get("owasp_2025_coverage", {}),
            "total_findings": len(findings),
            "findings": findings,
            "active_probes_log": getattr(job, "active_probes_log", []) or job.to_dict().get("active_probes_log", []),
        }
    })


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
@require_auth
def delete_scan(scan_id):
    """Delete a scan job and its findings."""
    if not _is_valid_uuid(scan_id):
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400

    removed = orchestrator.delete_scan(scan_id)
    if not removed:
        return jsonify({"status": "error", "message": "Scan not found"}), 404

    logger.info(f"[Scan] User '{request.auth_user}' deleted scan {scan_id[:8]}")
    return jsonify({"status": "ok", "message": "Scan deleted"})

@app.route("/api/scan/<scan_id>/export", methods=["GET"])
@require_auth
def export_scan_report(scan_id):
    """Export scan report in JSON or HTML format."""
    if not _is_valid_uuid(scan_id):
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400

    job = orchestrator.get_job(scan_id)
    if not job:
        return jsonify({"status": "error", "message": "Scan not found"}), 404

    if job.status != "completed":
        return jsonify({"status": "error", "message": "Scan not yet completed"}), 400

    findings = orchestrator.get_findings(scan_id)
    cve_enricher.enrich_findings(findings)
    risk = orchestrator.risk_scorer.calculate(findings)

    # Same stale-findings guard as report endpoint
    if not findings and job.findings_count > 0:
        risk["score"] = job.risk_score
        risk["grade"] = job.risk_grade
        from engine.risk_scorer import GRADE_THRESHOLDS
        risk["grade_label"] = next(
            (label for lo, hi, g, label in GRADE_THRESHOLDS if g == job.risk_grade),
            "Unknown"
        )
        risk["breakdown"] = job.severity_breakdown or risk["breakdown"]

    fmt = request.args.get("format", "json").lower()

    report_data = {
        "scan_id": scan_id,
        "target_url": job.target_url,
        "scanned_at": job.started_at,
        "completed_at": job.completed_at,
        "scan_duration_ms": job.scan_duration_ms,
        "technologies": job.technologies,
        "risk_score": risk["score"],
        "risk_grade": risk["grade"],
        "risk_grade_label": risk["grade_label"],
        "summary": risk["summary"],
        "vulnerability_summary": risk["vulnerability_summary"],
        "risk_formula": risk["risk_formula"],
        "severity_breakdown": risk["breakdown"],
        "top_fixes": risk["top_fixes"],
        "owasp_coverage": risk["owasp_coverage"],
        "owasp_2025_coverage": risk.get("owasp_2025_coverage", {}),
        "total_findings": len(findings),
        "findings": findings,
        "active_probes_log": getattr(job, "active_probes_log", []) or job.to_dict().get("active_probes_log", []),
    }

    if fmt == "html":
        try:
            from export.report_exporter import generate_html_report
            html = generate_html_report(report_data)
            return html, 200, {"Content-Type": "text/html", "Content-Disposition": f"attachment; filename=mapper-report-{scan_id[:8]}.html"}
        except ImportError:
            return jsonify({"status": "error", "message": "HTML export not available"}), 501

    # Default: JSON
    from flask import Response
    return Response(
        json.dumps(report_data, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=mapper-report-{scan_id[:8]}.json"}
    )


@app.route("/api/scans", methods=["GET"])
@require_auth
def list_scans():
    """List all scans."""
    jobs = orchestrator.get_all_jobs()
    # Sort by created_at descending
    jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)

    return jsonify({
        "status": "ok",
        "total": len(jobs),
        "scans": jobs
    })


# ═══════════════════════════════════════════════════════════
#  RULES ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/rules", methods=["GET"])
@require_auth
def get_rules():
    """List active detection rules."""
    with _rules_lock:
        rules_snapshot = _rules[:100]
        total = len(_rules)
    return jsonify({
        "status": "ok",
        "total": total,
        "rules": rules_snapshot
    })


@app.route("/api/rules/reload", methods=["POST"])
@require_auth
def reload_rules():
    """Hot-reload detection rules from disk."""
    global _rules
    with _rules_lock:
        _rules = load_all_rules()
        orchestrator.load_rules(_rules)
        total = len(_rules)
    return jsonify({
        "status": "ok",
        "total": total,
        "message": "Rules reloaded successfully"
    })


# ═══════════════════════════════════════════════════════════
#  CVE ENRICHMENT ENDPOINT
# ═══════════════════════════════════════════════════════════

@app.route("/api/cve/<cve_id>", methods=["GET"])
@require_auth
def lookup_cve(cve_id):
    """Look up CVE details."""
    # Validate CVE ID format
    import re
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        return jsonify({"status": "error", "message": "Invalid CVE ID format"}), 400

    data = cve_enricher.enrich(cve_id)
    if not data:
        return jsonify({"status": "error", "message": f"CVE {cve_id} not found"}), 404
    return jsonify({"status": "ok", "cve": data})


# ═══════════════════════════════════════════════════════════
#  STATS ENDPOINT
# ═══════════════════════════════════════════════════════════

@app.route("/api/stats", methods=["GET"])
@require_auth
def get_stats():
    """Dashboard statistics."""
    jobs = orchestrator.get_all_jobs()

    total_scans = len(jobs)
    completed = sum(1 for j in jobs if j.get("status") == "completed")
    running = sum(1 for j in jobs if j.get("status") in ("queued", "fetching", "analyzing", "active_probing", "correlating"))
    failed = sum(1 for j in jobs if j.get("status") == "failed")

    # Aggregate findings across all scans
    total_findings = sum(j.get("findings_count", 0) for j in jobs)
    avg_risk = 0
    if completed > 0:
        avg_risk = round(
            sum(j.get("risk_score", 0) for j in jobs if j.get("status") == "completed") / completed
        )

    return jsonify({
        "status": "ok",
        "total_scans": total_scans,
        "completed_scans": completed,
        "running_scans": running,
        "failed_scans": failed,
        "total_findings": total_findings,
        "average_risk_score": avg_risk,
    })


# ═══════════════════════════════════════════════════════════
#  HEALTH CHECK
# ═══════════════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint (no auth required)."""
    es_status = "disconnected"
    if es:
        try:
            es_status = "connected" if es.ping() else "disconnected"
        except Exception:
            es_status = "disconnected"
    with _rules_lock:
        rules_count = len(_rules)
    return jsonify({
        "status": "ok",
        "elasticsearch": es_status,
        "rules_loaded": rules_count,
    })


@app.route("/api/debug/restart", methods=["GET"])
@require_auth
def debug_restart():
    if getattr(request, 'auth_role', '') != 'admin':
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    import os
    os._exit(0)


@app.route("/api/debug/logs", methods=["GET"])
@require_auth
def debug_logs():
    if getattr(request, 'auth_role', '') != 'admin':
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    import subprocess
    try:
        output = subprocess.check_output("journalctl -u mapper --no-pager -n 100", shell=True, stderr=subprocess.STDOUT)
        return output.decode("utf-8", errors="replace"), 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return f"Error: {e}", 500, {"Content-Type": "text/plain"}


# ═══════════════════════════════════════════════════════════
#  AUTO-CREATE ADMIN USER (if users.json has placeholder hash)
# ═══════════════════════════════════════════════════════════

def ensure_admin_user():
    """Create a working admin user if the existing hash is a placeholder."""
    from werkzeug.security import generate_password_hash
    try:
        with open(USERS_PATH, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        users = []

    # Check if admin exists with a working hash
    admin = None
    for u in users:
        if u["username"] == "admin":
            admin = u
            break

    # If no admin or hash looks like the placeholder (not a real pbkdf2 hash),
    # regenerate it with password "admin123"
    needs_reset = False
    if not admin:
        needs_reset = True
    elif admin:
        h = admin.get("password_hash", "")
        # Real pbkdf2 hashes from werkzeug have 3 '$' parts with proper hex
        parts = h.split("$")
        if len(parts) != 3 or len(parts[2]) < 64:
            needs_reset = True
        # Also check if the hash is the known placeholder
        if "8a5f3e2b1c9d4a7f6e5b8c3d2a1f9e8b" in h:
            needs_reset = True

    if needs_reset:
        real_hash = generate_password_hash("admin123", method="pbkdf2:sha256", salt_length=16)
        if admin:
            admin["password_hash"] = real_hash
            logger.info("[Init] Reset admin password to 'admin123' (placeholder hash detected)")
        else:
            users.append({
                "username": "admin",
                "password_hash": real_hash,
                "role": "admin"
            })
            logger.info("[Init] Created admin user with password 'admin123'")

        with open(USERS_PATH, "w") as f:
            json.dump(users, f, indent=4)


# ═══════════════════════════════════════════════════════════
#  AUTO-INIT: Ensure admin user on any startup (WSGI or direct)
# ═══════════════════════════════════════════════════════════

ensure_admin_user()

# ═══════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════
#  AI PROXY — Gemini API (so users never need an API key)
# ═══════════════════════════════════════════════════════════

GEMINI_BASE_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}"

@app.route("/api/ai/analyze", methods=["POST", "OPTIONS"])
@require_auth
def ai_analyze():
    """Proxy a Gemini generateContent request — non-streaming."""
    if not GEMINI_API_KEY:
        return jsonify({"error": "AI not configured. Set GEMINI_API_KEY on the server."}), 503

    data = request.get_json()
    prompt = data.get("prompt", "")
    system_prompt = data.get("systemPrompt", "")
    temperature = data.get("temperature", 0.7)
    max_tokens = data.get("maxTokens", 4096)

    if not prompt:
        return jsonify({"error": "prompt is required"}), 400

    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        }
    }
    if system_prompt:
        body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    try:
        resp = http_requests.post(
            f"{GEMINI_BASE_URL}:generateContent?key={GEMINI_API_KEY}",
            json=body, timeout=60
        )
        if resp.status_code != 200:
            return jsonify({"error": f"Gemini API error: {resp.status_code}", "details": resp.text}), 502

        result = resp.json()
        text = ""
        if result.get("candidates") and result["candidates"][0].get("content"):
            text = "".join(p.get("text", "") for p in result["candidates"][0]["content"]["parts"])

        return jsonify({"text": text})
    except Exception as e:
        logger.error(f"AI proxy error: {e}")
        return jsonify({"error": str(e)}), 500


from flask import Response, stream_with_context

@app.route("/api/ai/stream", methods=["POST", "OPTIONS"])
@require_auth
def ai_stream():
    """Proxy a Gemini streamGenerateContent request — Server-Sent Events."""
    if not GEMINI_API_KEY:
        return jsonify({"error": "AI not configured. Set GEMINI_API_KEY on the server."}), 503

    data = request.get_json()
    prompt = data.get("prompt", "")
    system_prompt = data.get("systemPrompt", "")
    temperature = data.get("temperature", 0.7)
    max_tokens = data.get("maxTokens", 4096)

    if not prompt:
        return jsonify({"error": "prompt is required"}), 400

    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        }
    }
    if system_prompt:
        body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    def generate():
        try:
            resp = http_requests.post(
                f"{GEMINI_BASE_URL}:streamGenerateContent?alt=sse&key={GEMINI_API_KEY}",
                json=body, stream=True, timeout=120
            )
            if resp.status_code != 200:
                yield f"data: {json.dumps({'error': f'Gemini API error: {resp.status_code}'})}\n\n"
                return

            for line in resp.iter_lines(decode_unicode=True):
                if line and line.startswith("data: "):
                    yield line + "\n\n"
        except Exception as e:
            logger.error(f"AI stream proxy error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route("/api/ai/status", methods=["GET", "OPTIONS"])
def ai_status():
    """Check if AI is configured on the server."""
    return jsonify({
        "configured": bool(GEMINI_API_KEY),
        "model": GEMINI_MODEL if GEMINI_API_KEY else None
    })


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  Sentry Vulnerability Scanner Backend Starting")
    logger.info(f"  Port: {MAPPER_PORT}")
    with _rules_lock:
        logger.info(f"  Rules loaded: {len(_rules)}")
    logger.info(f"  Elasticsearch: {'connected' if es else 'memory-only mode'}")
    logger.info("=" * 60)

    app.run(host="0.0.0.0", port=MAPPER_PORT, debug=True, use_reloader=False)
