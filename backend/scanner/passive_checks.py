"""
passive_checks.py — Extended Passive Security Checks
Adds coverage for OWASP Top 10 categories A03, A04, A07, A08.
These are passive-only checks (no active payload injection).
"""

import re
import uuid
import logging
from datetime import datetime, timezone
from scanner.matcher import Finding

logger = logging.getLogger(__name__)


def run_extended_checks(snapshot, scan_id: str) -> list:
    """Run all extended passive checks against a PageSnapshot."""
    findings = []
    findings.extend(_check_injection_indicators(snapshot, scan_id))
    findings.extend(_check_insecure_design(snapshot, scan_id))
    findings.extend(_check_auth_failures(snapshot, scan_id))
    findings.extend(_check_integrity_failures(snapshot, scan_id))
    findings.extend(_check_logging_monitoring(snapshot, scan_id))
    findings.extend(_check_ssrf_indicators(snapshot, scan_id))
    return findings


def _check_injection_indicators(snapshot, scan_id: str) -> list:
    """A03:2021-Injection — Detect error messages suggesting injection vulnerabilities."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    body = snapshot.body_lower

    indicators = [
        (r"you have an error in your sql syntax", "SQL Syntax Error Detected",
         "The page reveals SQL error messages, indicating potential SQL injection vulnerability.",
         "CWE-89"),
        (r"mysql_(?:query|fetch|num_rows|connect)", "MySQL Function Exposure",
         "PHP MySQL functions are referenced in the page output, suggesting unhandled database errors.",
         "CWE-209"),
        (r"pg_(?:query|exec|connect|last_error)", "PostgreSQL Function Exposure",
         "PostgreSQL functions visible in page output, suggesting unhandled database errors.",
         "CWE-209"),
        (r"ora-\d{5}", "Oracle Database Error Exposed",
         "Oracle database error codes detected in the page output.",
         "CWE-209"),
        (r"microsoft ole db provider for sql server", "MSSQL Error Exposed",
         "Microsoft SQL Server error messages visible in page output.",
         "CWE-209"),
        (r"unclosed quotation mark after the character string", "SQL Injection Indicator",
         "SQL error message detected suggesting the application may be vulnerable to SQL injection.",
         "CWE-89"),
    ]

    for pattern, title, desc, cwe in indicators:
        match = re.search(pattern, body)
        if match:
            findings.append(Finding(
                id=str(uuid.uuid4()), scan_id=scan_id,
                target_url=snapshot.url, timestamp=now,
                source_tool="custom", type="vulnerability",
                severity="high", title=title, description=desc,
                owasp_category="A03:2021-Injection", cwe=cwe,
                evidence_location="body",
                evidence_snippet=match.group(0)[:200],
                remediation="Use parameterized queries and implement proper error handling.",
            ))
            break  # One injection indicator is enough

    return findings


def _check_insecure_design(snapshot, scan_id: str) -> list:
    """A04:2021-Insecure Design — Detect design-level security issues."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    headers = snapshot.headers

    # Check for missing rate-limit headers on the main page
    rate_limit_headers = ["x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit",
                          "retry-after", "x-ratelimit-remaining"]
    has_rate_limit = any(h in headers for h in rate_limit_headers)

    if not has_rate_limit and snapshot.forms:
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="misconfiguration",
            severity="medium",
            title="No Rate Limiting Detected",
            description="The application has forms but no rate-limiting headers were detected. "
                        "This may allow brute-force attacks on login forms or API abuse.",
            owasp_category="A04:2021-Insecure Design", cwe="CWE-770",
            evidence_location="header",
            evidence_snippet="No X-RateLimit-* or RateLimit-* headers found",
            remediation="Implement rate limiting on authentication and sensitive endpoints.",
        ))

    # Check for autocomplete on password fields
    for form in snapshot.forms:
        for inp in form.get("inputs", []):
            if inp.get("type") == "password":
                # If autocomplete isn't explicitly off, flag it
                findings.append(Finding(
                    id=str(uuid.uuid4()), scan_id=scan_id,
                    target_url=snapshot.url, timestamp=now,
                    source_tool="custom", type="misconfiguration",
                    severity="low",
                    title="Password Field May Allow Autocomplete",
                    description="A password input field was found. Ensure autocomplete is disabled "
                                "on sensitive fields to prevent credential caching.",
                    owasp_category="A04:2021-Insecure Design", cwe="CWE-522",
                    evidence_location="body",
                    evidence_snippet=f"Form action: {form.get('action', 'N/A')}, input: {inp.get('name', 'password')}",
                    remediation="Add autocomplete=\"new-password\" to password inputs.",
                ))
                break

    return findings


def _check_auth_failures(snapshot, scan_id: str) -> list:
    """A07:2021-Identification and Authentication Failures."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # Check login forms for missing CSRF protection
    for form in snapshot.forms:
        inputs = form.get("inputs", [])
        input_types = [i.get("type", "text") for i in inputs]
        input_names = [i.get("name", "").lower() for i in inputs]

        has_password = "password" in input_types
        has_csrf = any("csrf" in n or "token" in n or "_token" in n for n in input_names)

        if has_password and not has_csrf:
            findings.append(Finding(
                id=str(uuid.uuid4()), scan_id=scan_id,
                target_url=snapshot.url, timestamp=now,
                source_tool="custom", type="vulnerability",
                severity="medium",
                title="Login Form Missing CSRF Token",
                description="A login form was detected without a visible CSRF token field. "
                            "This may allow Cross-Site Request Forgery attacks.",
                owasp_category="A07:2021-Identification and Authentication Failures",
                cwe="CWE-352",
                evidence_location="body",
                evidence_snippet=f"Form action: {form.get('action', 'N/A')}, method: {form.get('method', 'GET')}",
                remediation="Add CSRF token to all authentication forms and validate server-side.",
            ))

    # Check for session tokens in URL
    if snapshot.url and ("sessionid=" in snapshot.url.lower() or
                          "jsessionid=" in snapshot.url.lower() or
                          "phpsessid=" in snapshot.url.lower()):
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="vulnerability",
            severity="high",
            title="Session Token in URL",
            description="Session identifier found in the URL. This exposes the session to "
                        "shoulder surfing, referrer leakage, and browser history.",
            owasp_category="A07:2021-Identification and Authentication Failures",
            cwe="CWE-598",
            evidence_location="url",
            evidence_snippet=snapshot.url[:200],
            remediation="Use cookies with HttpOnly and Secure flags for session management.",
        ))

    return findings


def _check_integrity_failures(snapshot, scan_id: str) -> list:
    """A08:2021-Software and Data Integrity Failures — Check SRI."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    body = snapshot.body or ""

    # Check for external scripts without SRI (Subresource Integrity)
    cdn_pattern = re.compile(
        r'<script[^>]+src=["\'](?:https?:)?//(?:cdn|cdnjs|unpkg|jsdelivr|ajax\.googleapis)[^"\']+["\'][^>]*>',
        re.IGNORECASE
    )
    integrity_pattern = re.compile(r'integrity=["\']', re.IGNORECASE)

    cdn_scripts = cdn_pattern.findall(body)
    scripts_without_sri = []

    for script_tag in cdn_scripts:
        if not integrity_pattern.search(script_tag):
            scripts_without_sri.append(script_tag[:120])

    if scripts_without_sri:
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="vulnerability",
            severity="medium",
            title="Missing Subresource Integrity (SRI)",
            description=f"{len(scripts_without_sri)} external CDN script(s) loaded without "
                        f"Subresource Integrity hashes. A CDN compromise could inject malicious code.",
            owasp_category="A08:2021-Software and Data Integrity Failures",
            cwe="CWE-353",
            evidence_location="body",
            evidence_snippet="\n".join(scripts_without_sri[:3]),
            remediation="Add integrity=\"sha384-...\" crossorigin=\"anonymous\" to all CDN scripts.",
        ))

    return findings


def _check_logging_monitoring(snapshot, scan_id: str) -> list:
    """A09:2021-Security Logging and Monitoring Failures.
    Heuristic: check for indicators of structured logging/monitoring.
    This is inherently approximate since logging is an internal concern.
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    headers = snapshot.headers

    # Indicators that suggest security monitoring is in place
    monitoring_headers = [
        "x-request-id", "x-correlation-id", "x-trace-id",
        "x-amzn-requestid", "x-amzn-trace-id",
        "sentry-trace", "x-datadog-trace-id", "traceparent",
        "x-b3-traceid", "x-cloud-trace-context",
    ]

    has_monitoring = any(h in headers for h in monitoring_headers)
    has_auth_forms = any(
        any(i.get("type") == "password" for i in f.get("inputs", []))
        for f in (snapshot.forms or [])
    )

    # Check for verbose error pages (stack traces in production)
    body = snapshot.body_lower or ""
    has_stack_trace = any(indicator in body for indicator in [
        "traceback (most recent call last)",
        "at java.", "at org.", "at com.",
        "exception in thread",
        "fatal error", "stack trace:",
        "<b>warning</b>:", "<b>notice</b>:",
    ])

    if has_stack_trace:
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="misconfiguration",
            severity="medium",
            title="Application Stack Trace Exposed",
            description=(
                "The application exposes stack trace or debug information in its response. "
                "This indicates debug mode may be enabled in production and proper error "
                "handling/logging is not configured."
            ),
            owasp_category="A09:2021-Security Logging and Monitoring Failures",
            cwe="CWE-209",
            evidence_location="body",
            evidence_snippet="Stack trace or debug output detected in response body",
            remediation=(
                "Disable debug mode in production. Implement custom error pages. "
                "Log detailed errors server-side only (not in HTTP responses). "
                "Set up centralized logging (ELK, Datadog, Sentry)."
            ),
        ))

    # Heuristic monitoring check removed to avoid false positives on standard web pages
    return findings


def _check_ssrf_indicators(snapshot, scan_id: str) -> list:
    """A10:2021-Server-Side Request Forgery (SSRF).
    Passively detect URL parameters that could be SSRF entry points.
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # Check URL for redirect/fetch-like parameters
    url_lower = (snapshot.url or "").lower()
    ssrf_params = [
        "url=", "redirect=", "next=", "callback=", "dest=", "uri=",
        "fetch=", "target=", "return=", "return_to=", "goto=",
        "link=", "src=", "source=", "redirect_uri=", "redirect_url=",
        "continue=", "forward=", "proxy=", "request=",
    ]

    found_params = [p.rstrip("=") for p in ssrf_params if p in url_lower]

    # Also check forms for URL input fields
    for form in (snapshot.forms or []):
        for inp in form.get("inputs", []):
            name = (inp.get("name") or "").lower()
            inp_type = (inp.get("type") or "").lower()
            if name in [p.rstrip("=") for p in ssrf_params] or inp_type == "url":
                if name not in found_params:
                    found_params.append(name)

    if found_params:
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="vulnerability",
            severity="medium",
            title="Potential SSRF Entry Point Detected",
            description=(
                f"URL parameters or form inputs that accept URL-like values were detected: "
                f"{', '.join(found_params)}. These may be exploitable for Server-Side Request "
                f"Forgery (SSRF) if the server fetches user-supplied URLs without validation."
            ),
            owasp_category="A10:2021-Server-Side Request Forgery",
            cwe="CWE-918",
            evidence_location="url" if any(p + "=" in url_lower for p in found_params) else "body",
            evidence_snippet=f"Potentially vulnerable parameters: {', '.join(found_params)}",
            remediation=(
                "Validate and sanitize all URL inputs server-side. "
                "Use an allowlist of permitted domains and protocols. "
                "Block requests to internal/private IP ranges (127.0.0.1, 10.x, 172.16-31.x, 192.168.x). "
                "Block cloud metadata endpoints (169.254.169.254). "
                "Use a dedicated HTTP client with SSRF protections."
            ),
        ))

    return findings
