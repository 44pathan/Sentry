"""
active_checks.py — Active Vulnerability Probes
Non-destructive active probes that verify vulnerabilities by injecting
safe canary payloads into discovered parameters.

Probe Types:
  1. Reflected XSS Canary — detects unescaped parameter reflection
  2. Error-Based SQLi     — detects database error on quote injection
  3. Time-Based Blind SQLi— detects blind injection via response delay
  4. Local File Inclusion  — detects path traversal on file-like params
  5. CRLF / Header Inject — detects header injection via CRLF sequences

All probes are rate-limited and use the existing async Fetcher.
Supports both GET query parameter injection and POST body form injection.
"""

import re
import uuid
import time
import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from scanner.fetcher import Fetcher
from scanner.matcher import Finding
from scanner.surface_extractor import AttackSurface, ParamTarget

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    ACTIVE_REQUEST_DELAY,
    MAX_ACTIVE_PROBES_PER_TARGET,
    ACTIVE_XSS_CANARY,
    BLIND_SQLI_SLEEP_SECONDS,
    BLIND_SQLI_THRESHOLD,
)

logger = logging.getLogger(__name__)


# ═══ Blind SQLi Payloads ═════════════════════════════════════
# Only test MySQL (most common DB). Testing all 3 serialises probes and triples scan time.
BLIND_SQLI_PAYLOADS = [
    ("' OR SLEEP({sleep})-- ", "MySQL SLEEP"),
]


# ── SQL Error Signatures (reused from passive_checks) ─────
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"mysql_",
    r"pg_query",
    r"pg_exec",
    r"ora-\d{5}",
    r"microsoft ole db provider",
    r"sqlite3\.operationalerror",
    r"sqlstate\[",
    r"syntax error at or near",
    r"unterminated quoted string",
    r"quoted string not properly terminated",
]

# ── LFI Success Patterns ──────────────────────────────────
LFI_INDICATORS = [
    r"root:x:0:0:",              # /etc/passwd
    r"\[fonts\]",                # win.ini
    r"\[extensions\]",           # win.ini
    r";\s*for\s+16-bit\s+app",   # win.ini comment
    r"localhost",                 # /etc/hosts
]

# LFI payloads
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
]


async def run_active_probes(
    fetcher: Fetcher,
    surface: AttackSurface,
    scan_id: str,
    scan_mode: str = "full_active",
) -> tuple:
    """
    Run active probes against discovered attack surface.
    Returns a tuple: (findings: list, probe_logs: list)
    """
    findings = []
    probe_logs = []

    if not surface.params:
        logger.info(f"[Active {scan_id[:8]}] No parameters found — skipping active probes")
        return findings, probe_logs

    logger.info(
        f"[Active {scan_id[:8]}] Running {scan_mode} probes against "
        f"{len(surface.params)} parameters"
    )

    async def _probe_param(param):
        param_findings = []
        param_logs = []

        is_post = (param.source == "form_post")

        async def _safe_probe(coro):
            """Run a single probe with a hard 10s wall-clock timeout."""
            try:
                return await asyncio.wait_for(coro, timeout=6)
            except asyncio.TimeoutError:
                logger.debug(f"[Active] Probe timed out on {param.param_name}")
                return None, None
            except Exception as e:
                logger.debug(f"[Active] Probe error on {param.param_name}: {e}")
                return None, None

        # Probe 1: XSS
        res_finding, log_item = await _safe_probe(_probe_xss(fetcher, param, scan_id, use_post=is_post))
        if log_item: param_logs.append(log_item)
        if res_finding: param_findings.append(res_finding)

        # Probe 2: SQLi
        res_finding, log_item = await _safe_probe(_probe_sqli(fetcher, param, scan_id, use_post=is_post))
        if log_item: param_logs.append(log_item)
        if res_finding: param_findings.append(res_finding)

        if scan_mode == "full_active":
            # Probe 3: Blind SQLi (time-based) — has its own internal 1.5s sleep
            res_finding, log_item = await _safe_probe(_probe_blind_sqli(fetcher, param, scan_id, use_post=is_post))
            if log_item: param_logs.append(log_item)
            if res_finding: param_findings.append(res_finding)

            # Probe 4: LFI
            if param.is_file_param:
                res_finding, log_item = await _safe_probe(_probe_lfi(fetcher, param, scan_id, use_post=is_post))
                if log_item: param_logs.append(log_item)
                if res_finding: param_findings.append(res_finding)

            # Probe 5: CRLF
            res_finding, log_item = await _safe_probe(_probe_crlf(fetcher, param, scan_id, use_post=is_post))
            if log_item: param_logs.append(log_item)
            if res_finding: param_findings.append(res_finding)

        return param_findings, param_logs

    params_to_probe = surface.params[:MAX_ACTIVE_PROBES_PER_TARGET]
    results = await asyncio.gather(
        *[_probe_param(p) for p in params_to_probe],
        return_exceptions=True
    )

    for item in results:
        if isinstance(item, tuple) and len(item) == 2:
            p_findings, p_logs = item
            findings.extend(p_findings)
            probe_logs.extend(p_logs)

    logger.info(
        f"[Active {scan_id[:8]}] Completed probes on {len(params_to_probe)} params, "
        f"executed {len(probe_logs)} probes, found {len(findings)} active findings"
    )

    return findings, probe_logs


# ═══════════════════════════════════════════════════════════
#  PROBE IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════

async def _probe_xss(fetcher: Fetcher, param: ParamTarget, scan_id: str, use_post: bool = False):
    canary = f"{ACTIVE_XSS_CANARY}_{uuid.uuid4().hex[:8]}'\"><"
    probe_url, post_data = _prepare_injection(param, canary, use_post=use_post)
    if not probe_url:
        return None, None

    method_str = "POST" if use_post else "GET"
    finding = None
    log_item = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "param_name": param.param_name,
        "probe_type": f"Reflected XSS Canary ({method_str})",
        "target_url": probe_url,
        "payload": canary,
        "status_code": 0,
        "vulnerable": False,
        "details": "Input sanitized or omitted from HTML body (Safe)"
    }

    try:
        if use_post:
            result = await fetcher.fetch_post(probe_url, data=post_data, timeout=3)
        else:
            result = await fetcher.fetch(probe_url, timeout=3)

        log_item["status_code"] = result.status_code
        if result.body and canary in result.body:
            log_item["vulnerable"] = True
            log_item["details"] = "Unescaped Canary string reflected verbatim in HTML response body"
            evidence_log = (
                f"[ACTIVE PROBE EXECUTION LOG]\n"
                f"METHOD & TARGET : {method_str} {probe_url}\n"
                f"POST DATA       : {post_data if use_post else 'N/A'}\n"
                f"PAYLOAD INJECTED: {canary}\n"
                f"HTTP STATUS     : {result.status_code}\n"
                f"VERIFICATION    : Unescaped Canary string reflected verbatim in HTML response body."
            )
            finding = _make_finding(
                scan_id=scan_id,
                target_url=probe_url,
                title=f"Reflected XSS — Parameter '{param.param_name}' ({method_str})",
                description=(
                    f"The parameter '{param.param_name}' ({method_str}) reflects user input without "
                    f"HTML encoding. The injected canary string '{canary}' appeared "
                    f"verbatim in the response body, confirming a Cross-Site Scripting "
                    f"(XSS) vulnerability."
                ),
                severity="high",
                owasp="A03:2021-Injection",
                cwe="CWE-79",
                evidence=evidence_log,
                remediation=(
                    "Encode all user input before rendering in HTML output. "
                    "Use context-aware output encoding (HTML entity, URL, JS encoding). "
                    "Implement Content-Security-Policy header as defense-in-depth."
                ),
            )
    except Exception as e:
        logger.debug(f"[XSS Probe] Error on {param.param_name}: {e}")
        log_item["details"] = f"Network/Timeout error: {e}"

    return finding, log_item


async def _probe_sqli(fetcher: Fetcher, param: ParamTarget, scan_id: str, use_post: bool = False):
    payload = param.param_value + "'"
    probe_url, post_data = _prepare_injection(param, payload, use_post=use_post)
    if not probe_url:
        return None, None

    method_str = "POST" if use_post else "GET"
    finding = None
    log_item = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "param_name": param.param_name,
        "probe_type": f"Error-Based SQLi ({method_str})",
        "target_url": probe_url,
        "payload": payload,
        "status_code": 0,
        "vulnerable": False,
        "details": "No database error signature detected in response (Safe)"
    }

    try:
        if use_post:
            result = await fetcher.fetch_post(probe_url, data=post_data, timeout=3)
        else:
            result = await fetcher.fetch(probe_url, timeout=3)

        if result:
            log_item["status_code"] = result.status_code
        if result and result.body:
            body_lower = result.body.lower()
            for pattern in SQL_ERROR_PATTERNS:
                match = re.search(pattern, body_lower)
                if match:
                    log_item["vulnerable"] = True
                    log_item["details"] = f"Database error matched signature: '{match.group(0)[:100]}'"
                    evidence_log = (
                        f"[ACTIVE PROBE EXECUTION LOG]\n"
                        f"METHOD & TARGET : {method_str} {probe_url}\n"
                        f"POST DATA       : {post_data if use_post else 'N/A'}\n"
                        f"PAYLOAD INJECTED: {payload}\n"
                        f"HTTP STATUS     : {result.status_code}\n"
                        f"VERIFICATION    : Database error matched signature: '{match.group(0)[:120]}'"
                    )
                    finding = _make_finding(
                        scan_id=scan_id,
                        target_url=probe_url,
                        title=f"SQL Injection — Parameter '{param.param_name}' ({method_str})",
                        description=(
                            f"Appending a single quote (') to the '{param.param_name}' parameter ({method_str}) "
                            f"triggered a database error in the response, confirming a SQL injection "
                            f"vulnerability. Error signature: {match.group(0)[:100]}"
                        ),
                        severity="critical",
                        owasp="A03:2021-Injection",
                        cwe="CWE-89",
                        evidence=evidence_log,
                        remediation=(
                            "Use parameterized queries (prepared statements) for ALL database operations. "
                            "Never concatenate user input into SQL strings. "
                            "Apply input validation and use an ORM where possible."
                        ),
                    )
                    break
    except Exception as e:
        logger.debug(f"[SQLi Probe] Error on {param.param_name}: {e}")
        log_item["details"] = f"Network/Timeout error: {e}"

    return finding, log_item


async def _probe_blind_sqli(fetcher: Fetcher, param: ParamTarget, scan_id: str, use_post: bool = False):
    """
    Time-Based Blind SQL Injection probe.
    Injects SLEEP/pg_sleep/WAITFOR payloads and measures if response is
    significantly delayed compared to a baseline request.
    """
    method_str = "POST" if use_post else "GET"
    finding = None
    last_log = None

    # Step 1: Establish baseline response time with a benign value
    baseline_url, baseline_post = _prepare_injection(param, "sentry_baseline_1", use_post=use_post)
    if not baseline_url:
        return None, None

    baseline_time = 0.0
    try:
        t_start = time.monotonic()
        if use_post:
            await fetcher.fetch_post(baseline_url, data=baseline_post, timeout=3)
        else:
            await fetcher.fetch(baseline_url, timeout=3)
        baseline_time = time.monotonic() - t_start
    except Exception:
        baseline_time = 0.5  # conservative fallback

    # Step 2: Test each blind SQLi payload
    for payload_template, db_label in BLIND_SQLI_PAYLOADS:
        payload = payload_template.format(sleep=BLIND_SQLI_SLEEP_SECONDS)
        probe_url, post_data = _prepare_injection(param, payload, use_post=use_post)
        if not probe_url:
            continue

        log_item = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "param_name": param.param_name,
            "probe_type": f"Time-Based Blind SQLi ({db_label}) ({method_str})",
            "target_url": probe_url,
            "payload": payload,
            "status_code": 0,
            "vulnerable": False,
            "details": f"Baseline: {baseline_time:.2f}s — No significant delay detected (Safe)",
        }
        last_log = log_item

        try:
            t_start = time.monotonic()
            max_timeout = BLIND_SQLI_SLEEP_SECONDS + 1.5
            if use_post:
                result = await fetcher.fetch_post(probe_url, data=post_data, timeout=max_timeout)
            else:
                result = await fetcher.fetch(probe_url, timeout=max_timeout)
            elapsed = time.monotonic() - t_start

            if result:
                log_item["status_code"] = result.status_code

            delay_delta = elapsed - baseline_time

            if delay_delta >= BLIND_SQLI_THRESHOLD:
                log_item["vulnerable"] = True
                log_item["details"] = (
                    f"RESPONSE DELAYED {elapsed:.2f}s (baseline {baseline_time:.2f}s, "
                    f"delta +{delay_delta:.2f}s) — Blind SQLi ({db_label}) CONFIRMED"
                )
                now = datetime.now(timezone.utc).isoformat()
                finding = Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    target_url=probe_url,
                    timestamp=now,
                    source_tool="active_probe",
                    type="vulnerability",
                    severity="critical",
                    title=f"Time-Based Blind SQL Injection ({db_label}) ({method_str})",
                    description=(
                        f"Parameter '{param.param_name}' ({method_str}) is vulnerable to time-based blind "
                        f"SQL injection. Injecting '{payload}' caused a response delay of {elapsed:.2f}s "
                        f"(baseline: {baseline_time:.2f}s)."
                    ),
                    owasp_category="A03:2021-Injection",
                    cwe="CWE-89",
                    evidence_snippet=(
                        f"[ACTIVE PROBE EXECUTION LOG]\n"
                        f"Probe Type: Time-Based Blind SQLi ({db_label}) ({method_str})\n"
                        f"Target: {probe_url}\n"
                        f"POST Data: {post_data if use_post else 'N/A'}\n"
                        f"Payload: {payload}\n"
                        f"Baseline Response: {baseline_time:.2f}s\n"
                        f"Probed Response:   {elapsed:.2f}s\n"
                        f"Delta:             +{delay_delta:.2f}s (threshold: {BLIND_SQLI_THRESHOLD}s)\n"
                        f"Verdict:           VULNERABLE — Significant delay confirms blind injection"
                    ),
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                )
                break
            else:
                log_item["details"] = (
                    f"Response: {elapsed:.2f}s (baseline {baseline_time:.2f}s, "
                    f"delta +{delay_delta:.2f}s) — Below threshold {BLIND_SQLI_THRESHOLD}s (Safe)"
                )

        except asyncio.TimeoutError:
            log_item["vulnerable"] = True
            log_item["details"] = (
                f"REQUEST TIMED OUT after {BLIND_SQLI_SLEEP_SECONDS + 5}s "
                f"(baseline {baseline_time:.2f}s) — Possible Blind SQLi ({db_label})"
            )
            now = datetime.now(timezone.utc).isoformat()
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                target_url=probe_url,
                timestamp=now,
                source_tool="active_probe",
                type="vulnerability",
                severity="high",
                title=f"Possible Time-Based Blind SQL Injection ({db_label}) ({method_str})",
                description=(
                    f"Parameter '{param.param_name}' ({method_str}) caused a request timeout when injecting "
                    f"a {db_label} sleep payload, suggesting time-based blind SQLi."
                ),
                owasp_category="A03:2021-Injection",
                cwe="CWE-89",
                evidence_location="response_time",
                evidence_snippet=f"Timeout on payload ({method_str}): {payload}",
                remediation="Use parameterized queries / prepared statements.",
            )
            break

        except Exception as e:
            logger.debug(f"[Blind SQLi] Error on {param.param_name}: {e}")
            log_item["details"] = f"Network error: {e}"

    return finding, last_log


async def _probe_lfi(fetcher: Fetcher, param: ParamTarget, scan_id: str, use_post: bool = False):
    method_str = "POST" if use_post else "GET"
    finding = None
    last_log = None

    for payload in LFI_PAYLOADS:
        probe_url, post_data = _prepare_injection(param, payload, use_post=use_post)
        if not probe_url:
            continue

        log_item = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "param_name": param.param_name,
            "probe_type": f"Path Traversal (LFI) ({method_str})",
            "target_url": probe_url,
            "payload": payload,
            "status_code": 0,
            "vulnerable": False,
            "details": "System file patterns not included in response (Safe)"
        }
        last_log = log_item

        try:
            if use_post:
                result = await fetcher.fetch_post(probe_url, data=post_data, timeout=3)
            else:
                result = await fetcher.fetch(probe_url, timeout=3)

            if result:
                log_item["status_code"] = result.status_code
            if result and result.body:
                body_lower = result.body.lower()
                for pattern in LFI_INDICATORS:
                    match = re.search(pattern, body_lower)
                    if match:
                        log_item["vulnerable"] = True
                        log_item["details"] = f"Path traversal matched indicator: '{match.group(0)[:100]}'"
                        evidence_log = (
                            f"[ACTIVE PROBE EXECUTION LOG]\n"
                            f"METHOD & TARGET : {method_str} {probe_url}\n"
                            f"POST DATA       : {post_data if use_post else 'N/A'}\n"
                            f"PAYLOAD INJECTED: {payload}\n"
                            f"HTTP STATUS     : {result.status_code}\n"
                            f"VERIFICATION    : Path traversal matched indicator: '{match.group(0)[:120]}'"
                        )
                        finding = _make_finding(
                            scan_id=scan_id,
                            target_url=probe_url,
                            title=f"Local File Inclusion — Parameter '{param.param_name}' ({method_str})",
                            description=(
                                f"The parameter '{param.param_name}' ({method_str}) is vulnerable to path traversal. "
                                f"The payload '{payload}' caused the server to include a local system "
                                f"file in its response. Matched indicator: {match.group(0)[:100]}"
                            ),
                            severity="critical",
                            owasp="A01:2021-Broken Access Control",
                            cwe="CWE-22",
                            evidence=evidence_log,
                            remediation=(
                                "Never use user input directly in file system operations. "
                                "Use a whitelist of allowed file paths. "
                                "Apply chroot or sandboxed file access. "
                                "Remove directory traversal sequences (../, ..\\ ) from input."
                            ),
                        )
                        return finding, log_item
        except Exception as e:
            logger.debug(f"[LFI Probe] Error on {param.param_name}: {e}")
            log_item["details"] = f"Network/Timeout error: {e}"

    return finding, last_log


async def _probe_crlf(fetcher: Fetcher, param: ParamTarget, scan_id: str, use_post: bool = False):
    method_str = "POST" if use_post else "GET"
    marker = "X-Sentry-Injected"
    payload = f"{param.param_value}%0d%0a{marker}:1"
    probe_url, post_data = _prepare_injection(param, payload, use_post=use_post)
    if not probe_url:
        return None, None

    finding = None
    log_item = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "param_name": param.param_name,
        "probe_type": f"CRLF / Header Injection ({method_str})",
        "target_url": probe_url,
        "payload": payload,
        "status_code": 0,
        "vulnerable": False,
        "details": "CRLF headers not injected (Safe)"
    }

    try:
        if use_post:
            result = await fetcher.fetch_post(probe_url, data=post_data, timeout=3)
        else:
            result = await fetcher.fetch(probe_url, timeout=3)

        if result:
            log_item["status_code"] = result.status_code
        response_headers = (result.headers if result else {}) or {}
        if marker.lower() in response_headers:
            log_item["vulnerable"] = True
            log_item["details"] = f"Injected header '{marker}: 1' appeared in response headers"
            evidence_log = (
                f"[ACTIVE PROBE EXECUTION LOG]\n"
                f"METHOD & TARGET : {method_str} {probe_url}\n"
                f"POST DATA       : {post_data if use_post else 'N/A'}\n"
                f"PAYLOAD INJECTED: {payload}\n"
                f"HTTP STATUS     : {result.status_code}\n"
                f"VERIFICATION    : Injected header '{marker}: 1' appeared in response headers."
            )
            finding = _make_finding(
                scan_id=scan_id,
                target_url=probe_url,
                title=f"CRLF / Header Injection — Parameter '{param.param_name}' ({method_str})",
                description=(
                    f"The parameter '{param.param_name}' ({method_str}) is vulnerable to CRLF injection. "
                    f"Injecting a carriage return + line feed sequence caused a custom header "
                    f"('{marker}: 1') to appear in the HTTP response headers."
                ),
                severity="high",
                owasp="A03:2021-Injection",
                cwe="CWE-113",
                evidence=evidence_log,
                remediation=(
                    "Strip or encode CR (\\r) and LF (\\n) characters from ALL user input "
                    "before including it in HTTP headers or redirect URLs. "
                    "Use framework-level header setting functions that auto-sanitize."
                ),
            )
            return finding, log_item

        if result and result.body and marker.lower() in result.body.lower():
            log_item["vulnerable"] = True
            log_item["details"] = f"CRLF marker '{marker}' reflected in response body"
            evidence_log = (
                f"[ACTIVE PROBE EXECUTION LOG]\n"
                f"METHOD & TARGET : {method_str} {probe_url}\n"
                f"POST DATA       : {post_data if use_post else 'N/A'}\n"
                f"PAYLOAD INJECTED: {payload}\n"
                f"HTTP STATUS     : {result.status_code}\n"
                f"VERIFICATION    : CRLF marker '{marker}' reflected in response body."
            )
            finding = _make_finding(
                scan_id=scan_id,
                target_url=probe_url,
                title=f"CRLF Injection Indicator — Parameter '{param.param_name}' ({method_str})",
                description=(
                    f"The parameter '{param.param_name}' ({method_str}) may be vulnerable to CRLF injection. "
                    f"The injected marker '{marker}' appeared in the response body."
                ),
                severity="medium",
                owasp="A03:2021-Injection",
                cwe="CWE-113",
                evidence=evidence_log,
                remediation=(
                    "Sanitize CR/LF characters from user input used in HTTP headers or responses."
                ),
            )
            return finding, log_item
    except Exception as e:
        logger.debug(f"[CRLF Probe] Error on {param.param_name}: {e}")
        log_item["details"] = f"Network/Timeout error: {e}"

    return finding, log_item


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════

def _prepare_injection(param: ParamTarget, payload: str, use_post: bool = False) -> tuple:
    """
    Returns (probe_url, post_data_dict) for injection.
    If use_post is True: target URL is param.url, post_data_dict has injected field.
    If use_post is False: probe_url has injected query string, post_data_dict is None.
    """
    if use_post:
        # Build form post payload dictionary
        # We start with basic default parameters if form inputs were captured
        post_data = {param.param_name: payload}
        return param.url, post_data
    else:
        probe_url = _inject_param(param, payload)
        return probe_url, None


def _inject_param(param: ParamTarget, payload: str) -> str:
    """
    Build a URL with the payload injected into the target query parameter.
    """
    try:
        parsed = urlparse(param.url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # If param exists in the URL, replace its value
        if param.param_name in query_params:
            query_params[param.param_name] = [payload]
        else:
            # Add it as a new query parameter
            query_params[param.param_name] = [payload]

        # Rebuild URL with modified query
        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        return new_url
    except Exception as e:
        logger.debug(f"[Inject] Failed to build probe URL: {e}")
        return ""


def _make_finding(
    scan_id: str, target_url: str, title: str, description: str,
    severity: str, owasp: str, cwe: str, evidence: str, remediation: str
) -> Finding:
    """Create a Finding from active probe results."""
    return Finding(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        target_url=target_url,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_tool="active_probe",
        type="vulnerability",
        severity=severity,
        title=title,
        description=description,
        owasp_category=owasp,
        cwe=cwe,
        evidence_location="parameter",
        evidence_snippet=evidence[:500],
        remediation=remediation,
    )
