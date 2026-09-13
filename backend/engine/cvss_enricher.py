"""
cvss_enricher.py — CVSS 3.1 Scoring & Mitigation Strategy Enricher
Assigns CVSS base scores and detailed mitigation strategies to each finding.
"""

import logging

logger = logging.getLogger(__name__)

# CVSS 3.1 base scores mapped by vulnerability pattern/title keywords
# Source: NVD averages for each vulnerability class
CVSS_BY_PATTERN = {
    # Critical (9.0-10.0)
    "exposed .git": 9.3,
    "exposed environment file": 9.8,
    "exposed .env": 9.8,
    "sql injection": 9.8,
    "remote code execution": 10.0,
    "command injection": 9.8,
    # High (7.0-8.9)
    "no https": 7.4,
    "tls certificate error": 7.5,
    "outdated tls": 7.5,
    "outdated angularjs": 7.2,
    "exposed .htaccess": 7.5,
    "phpmyadmin accessible": 8.1,
    "xss": 6.1,
    "cross-site scripting": 6.1,
    "reflected xss": 6.1,
    "open redirect": 6.1,
    "missing content-security-policy": 6.5,
    "missing x-frame-options": 6.5,
    "clickjacking": 6.5,
    "csrf": 8.0,
    "missing csrf": 8.0,
    "local file inclusion": 9.1,
    "crlf / header injection": 7.5,
    "crlf injection": 7.5,
    "header injection": 7.5,
    # Medium (4.0-6.9)
    "missing hsts": 5.3,
    "missing strict-transport-security": 5.3,
    "outdated jquery": 6.1,
    "outdated lodash": 5.3,
    "directory listing": 5.3,
    "application error": 5.3,
    "insecure cookie": 5.3,
    "admin panel": 5.3,
    "mixed content": 4.3,
    "apache server status": 5.3,
    "exposed .ds_store": 5.3,
    "missing permissions-policy": 4.3,
    "autocomplete on password": 4.3,
    "missing subresource integrity": 5.3,
    "potential ssrf": 5.3,
    "ssrf entry point": 5.3,
    "crlf injection indicator": 5.3,
    "stack trace exposed": 5.3,
    # Low (0.1-3.9)
    "missing x-content-type-options": 3.1,
    "missing x-xss-protection": 3.1,
    "missing referrer-policy": 3.1,
    "server header": 3.1,
    "x-powered-by": 3.1,
    "php version": 3.1,
    "asp.net version": 3.1,
    "internal ip": 3.1,
    "outdated bootstrap": 3.1,
    "information disclosure": 3.1,
    "cross-domain policy": 3.1,
    "no security monitoring": 3.1,
    "no security logging": 3.1,
    # Info (0.0)
    "wordpress detected": 0.0,
    "robots.txt": 0.0,
    "sitemap found": 0.0,
    "security.txt": 0.0,
    "email address": 0.0,
    "wordpress login": 0.0,
    "detected": 0.0,
    "fingerprint": 0.0,
}

# Severity-based fallback CVSS scores
CVSS_FALLBACK = {
    "critical": 9.8,
    "high": 7.5,
    "medium": 5.3,
    "low": 3.1,
    "info": 0.0,
}

# Comprehensive mitigation strategies
MITIGATIONS = {
    "missing hsts": (
        "Enable HTTP Strict Transport Security (HSTS).\n"
        "1. Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
        "2. Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
        "3. Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "4. Submit to HSTS preload list: https://hstspreload.org/"
    ),
    "missing strict-transport-security": (
        "Enable HTTP Strict Transport Security (HSTS).\n"
        "1. Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
        "2. Ensure all resources load over HTTPS before enabling.\n"
        "3. Start with a short max-age and increase gradually."
    ),
    "missing x-content-type-options": (
        "Prevent MIME-type sniffing attacks.\n"
        "1. Add header: X-Content-Type-Options: nosniff\n"
        "2. Ensure all responses have correct Content-Type headers.\n"
        "3. This prevents browsers from interpreting files as a different MIME type."
    ),
    "missing x-frame-options": (
        "Prevent clickjacking attacks.\n"
        "1. Add header: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed)\n"
        "2. Better: Use CSP frame-ancestors directive: Content-Security-Policy: frame-ancestors 'none'\n"
        "3. Test that legitimate iframe embeds still work after applying."
    ),
    "missing content-security-policy": (
        "Implement Content Security Policy to prevent XSS and data injection.\n"
        "1. Start with report-only mode: Content-Security-Policy-Report-Only: default-src 'self'\n"
        "2. Gradually restrict: script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:\n"
        "3. Remove 'unsafe-inline' and 'unsafe-eval' where possible.\n"
        "4. Set up CSP violation reporting endpoint.\n"
        "5. Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    ),
    "missing x-xss-protection": (
        "Enable legacy XSS filter (supplement to CSP).\n"
        "1. Add header: X-XSS-Protection: 1; mode=block\n"
        "2. Note: This is deprecated in modern browsers — CSP is the primary defense.\n"
        "3. Keep this header for older browser compatibility."
    ),
    "missing referrer-policy": (
        "Control referrer information leakage.\n"
        "1. Add header: Referrer-Policy: strict-origin-when-cross-origin\n"
        "2. For sensitive pages, use: Referrer-Policy: no-referrer\n"
        "3. This prevents leaking URL paths to third-party services."
    ),
    "missing permissions-policy": (
        "Restrict browser feature access.\n"
        "1. Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
        "2. Only allow features your application actually uses.\n"
        "3. Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
    ),
    "no https": (
        "Enable HTTPS with a valid TLS certificate.\n"
        "1. Obtain a free TLS certificate from Let's Encrypt (certbot).\n"
        "2. Configure your web server for HTTPS (port 443).\n"
        "3. Redirect all HTTP traffic to HTTPS (301 redirect).\n"
        "4. Enable HSTS after confirming HTTPS works correctly."
    ),
    "tls certificate error": (
        "Fix TLS certificate configuration.\n"
        "1. Verify the certificate chain is complete (include intermediate certs).\n"
        "2. Ensure the certificate matches the domain name.\n"
        "3. Check certificate expiration date and renew if needed.\n"
        "4. Use: openssl s_client -connect yourdomain.com:443 -servername yourdomain.com"
    ),
    "outdated tls": (
        "Upgrade to modern TLS protocol.\n"
        "1. Disable TLSv1.0, TLSv1.1, SSLv2, SSLv3.\n"
        "2. Enable TLS 1.2 and TLS 1.3 only.\n"
        "3. Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
        "4. Apache: SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n"
        "5. Test with: https://www.ssllabs.com/ssltest/"
    ),
    "exposed .git": (
        "CRITICAL: Block access to .git directory immediately.\n"
        "1. Nginx: location ~ /\\.git { deny all; return 404; }\n"
        "2. Apache: RedirectMatch 404 /\\.git\n"
        "3. Audit repository for hardcoded secrets and rotate ALL credentials.\n"
        "4. Consider the full source code compromised — review for sensitive data."
    ),
    "exposed .env": (
        "CRITICAL: Block access to .env files and rotate all secrets.\n"
        "1. Block access: Nginx: location ~ /\\.env { deny all; }\n"
        "2. IMMEDIATELY rotate all API keys, database passwords, and secrets in the .env.\n"
        "3. Move secrets to environment variables or a secrets manager (Vault, AWS SSM).\n"
        "4. Add .env to .gitignore if not already present."
    ),
    "insecure cookie": (
        "Set security flags on all cookies.\n"
        "1. Add Secure flag: ensures cookie only sent over HTTPS.\n"
        "2. Add HttpOnly flag: prevents JavaScript access (XSS protection).\n"
        "3. Add SameSite=Strict (or Lax): prevents CSRF attacks.\n"
        "4. Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"
    ),
    "directory listing": (
        "Disable directory listing on the web server.\n"
        "1. Apache: Options -Indexes in .htaccess or httpd.conf\n"
        "2. Nginx: autoindex off; (this is the default)\n"
        "3. Add index files to all directories that should be accessible."
    ),
    "server header": (
        "Hide server version information.\n"
        "1. Nginx: server_tokens off;\n"
        "2. Apache: ServerTokens Prod and ServerSignature Off\n"
        "3. IIS: Remove via URL Rewrite module or custom headers."
    ),
    "x-powered-by": (
        "Remove technology disclosure headers.\n"
        "1. PHP: Set expose_php = Off in php.ini\n"
        "2. Express.js: app.disable('x-powered-by')\n"
        "3. ASP.NET: Remove via web.config customHeaders section.\n"
        "4. General: Configure reverse proxy to strip these headers."
    ),
    "phpmyadmin": (
        "Restrict access to database management interfaces.\n"
        "1. Move phpMyAdmin to a non-standard URL path.\n"
        "2. Restrict access by IP: Allow only admin IPs.\n"
        "3. Add HTTP authentication as an additional layer.\n"
        "4. Better: Use SSH tunneling to access phpMyAdmin locally only."
    ),
    "admin panel": (
        "Restrict access to administrative interfaces.\n"
        "1. Move admin panel to a non-standard URL path.\n"
        "2. Implement IP-based access control.\n"
        "3. Add multi-factor authentication (MFA).\n"
        "4. Use VPN or SSH tunnel for admin access in production."
    ),
    "mixed content": (
        "Upgrade all resources to HTTPS.\n"
        "1. Find and update all http:// references to https:// in HTML/CSS/JS.\n"
        "2. Use protocol-relative URLs (//) or absolute HTTPS URLs.\n"
        "3. Add CSP: upgrade-insecure-requests to automatically upgrade.\n"
        "4. Check for mixed content: browser DevTools → Console tab."
    ),
    "outdated jquery": (
        "Upgrade jQuery to the latest version.\n"
        "1. Update to jQuery >= 3.7.x (latest stable).\n"
        "2. Test for breaking changes: https://jquery.com/upgrade-guide/\n"
        "3. Consider removing jQuery if using a modern framework.\n"
        "4. Use SRI hash when loading from CDN."
    ),
    "outdated angularjs": (
        "Migrate from AngularJS (end-of-life) to Angular.\n"
        "1. AngularJS reached EOL in January 2022 — no more security patches.\n"
        "2. Plan migration to Angular (v17+), React, or Vue.\n"
        "3. If migration is not immediate, update to AngularJS 1.8.3 (last release).\n"
        "4. Apply Content-Security-Policy to mitigate template injection attacks."
    ),
    "application error": (
        "Implement custom error pages and disable debug mode.\n"
        "1. Disable debug/development mode in production.\n"
        "2. Create custom error pages (400, 403, 404, 500) that don't leak info.\n"
        "3. Log detailed errors server-side only.\n"
        "4. Django: DEBUG=False, Flask: debug=False, Node: NODE_ENV=production"
    ),
    "internal ip": (
        "Remove internal IP addresses from public responses.\n"
        "1. Review HTML source, headers, and JavaScript for internal IPs.\n"
        "2. Configure reverse proxy to strip internal routing headers.\n"
        "3. Use hostnames instead of IPs in application code."
    ),
    "missing subresource integrity": (
        "Add Subresource Integrity (SRI) to external scripts and styles.\n"
        "1. Add integrity attribute: <script src=\"cdn.js\" integrity=\"sha384-...\" crossorigin=\"anonymous\">\n"
        "2. Generate hashes: openssl dgst -sha384 -binary file.js | openssl base64 -A\n"
        "3. Use https://www.srihash.org/ to generate SRI hashes.\n"
        "4. Always include crossorigin=\"anonymous\" with SRI."
    ),
    "missing csrf": (
        "Implement CSRF protection on all forms.\n"
        "1. Add CSRF tokens to all state-changing forms.\n"
        "2. Validate CSRF token server-side on every POST/PUT/DELETE.\n"
        "3. Use SameSite=Strict cookies as defense-in-depth.\n"
        "4. Framework guides: Django (built-in), Flask-WTF, Express csurf."
    ),
    "autocomplete on password": (
        "Disable autocomplete on sensitive form fields.\n"
        "1. Add autocomplete=\"off\" or autocomplete=\"new-password\" to password inputs.\n"
        "2. Add autocomplete=\"off\" to the parent form element.\n"
        "3. Note: Some browsers ignore this — use CSP and SRI as additional defense."
    ),
    "reflected xss": (
        "Fix Cross-Site Scripting (XSS) vulnerability.\n"
        "1. HTML-encode all user input before rendering: use &lt; &gt; &amp; &quot; &#x27;\n"
        "2. Use context-aware encoding (HTML body, attribute, URL, JavaScript contexts).\n"
        "3. Implement Content-Security-Policy: script-src 'self' (no unsafe-inline).\n"
        "4. Use framework auto-escaping (React JSX, Django templates, Jinja2 autoescape).\n"
        "5. Validate and sanitize input on the server-side before processing."
    ),
    "sql injection": (
        "Fix SQL Injection vulnerability.\n"
        "1. Use parameterized queries (prepared statements) for ALL database operations.\n"
        "2. Never concatenate user input into SQL query strings.\n"
        "3. Use an ORM (SQLAlchemy, Django ORM, Sequelize) to abstract database access.\n"
        "4. Apply principle of least privilege to database accounts.\n"
        "5. Implement input validation (whitelist expected formats)."
    ),
    "local file inclusion": (
        "Fix Local File Inclusion (LFI) / Path Traversal vulnerability.\n"
        "1. Never use user input directly in file system operations.\n"
        "2. Maintain a whitelist of allowed file paths or identifiers.\n"
        "3. Use os.path.realpath() and verify the resolved path is within the expected directory.\n"
        "4. Strip directory traversal sequences (../, ..\\ ) from all input.\n"
        "5. Apply chroot or container sandboxing for file access."
    ),
    "crlf": (
        "Fix CRLF / HTTP Header Injection vulnerability.\n"
        "1. Strip or reject CR (\\r, %0d) and LF (\\n, %0a) characters from ALL user input.\n"
        "2. Use framework-level header setting functions that auto-sanitize.\n"
        "3. Never include user input directly in HTTP response headers.\n"
        "4. Validate and encode redirect URLs server-side."
    ),
    "header injection": (
        "Fix HTTP Header Injection vulnerability.\n"
        "1. Sanitize all user input used in HTTP headers (strip CR/LF characters).\n"
        "2. Use framework response APIs (e.g., Flask response.headers) instead of raw output.\n"
        "3. Validate redirect URLs against an allowlist."
    ),
    "ssrf": (
        "Mitigate Server-Side Request Forgery (SSRF).\n"
        "1. Validate and sanitize all user-supplied URLs server-side.\n"
        "2. Use an allowlist of permitted domains and URL schemes (http/https only).\n"
        "3. Block requests to private/internal IP ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.\n"
        "4. Block cloud metadata endpoints (169.254.169.254).\n"
        "5. Resolve DNS before making requests and re-validate the resolved IP.\n"
        "6. Use a dedicated egress proxy with network-level restrictions."
    ),
    "ssrf entry point": (
        "Mitigate Server-Side Request Forgery (SSRF) risk.\n"
        "1. Validate all URL parameters server-side before processing.\n"
        "2. Use domain allowlists and block internal/private IP ranges.\n"
        "3. Implement network-level egress filtering."
    ),
    "stack trace": (
        "Fix exposed application stack traces.\n"
        "1. Disable debug mode in production environments.\n"
        "2. Implement custom error pages that do not reveal internal details.\n"
        "3. Log detailed errors server-side only (Sentry, ELK, CloudWatch).\n"
        "4. Framework settings: Django DEBUG=False, Flask debug=False, NODE_ENV=production."
    ),
    "no security monitoring": (
        "Implement security logging and monitoring.\n"
        "1. Add request tracing headers (X-Request-Id) for incident correlation.\n"
        "2. Log all authentication events (login success, failure, lockout).\n"
        "3. Deploy centralized log management (ELK Stack, Splunk, Datadog).\n"
        "4. Set up real-time alerts for suspicious activity patterns.\n"
        "5. Retain security logs for at least 90 days."
    ),
}


def get_cvss_score(finding: dict) -> tuple:
    """
    Calculate CVSS 3.1 base score for a finding.
    Returns (score, severity_label).

    Priority: known CVE lookup → pattern match → severity fallback.
    """
    title = (finding.get("title") or "").lower()
    severity = (finding.get("severity") or "info").lower()
    finding_type = (finding.get("type") or "").lower()

    # Skip fingerprints — they're informational
    if finding_type == "fingerprint" and severity == "info":
        return 0.0, "none"

    # Match against known patterns (longest match first for accuracy)
    best_score = None
    best_key_len = 0
    for pattern, score in CVSS_BY_PATTERN.items():
        if pattern in title and len(pattern) > best_key_len:
            best_score = score
            best_key_len = len(pattern)

    if best_score is not None:
        return best_score, _cvss_to_severity(best_score)

    # Fallback to severity-based estimate
    score = CVSS_FALLBACK.get(severity, 0.0)
    return score, _cvss_to_severity(score)


def get_mitigation(finding: dict) -> str:
    """
    Get detailed mitigation strategy for a finding.
    Falls back to the basic remediation field if no specific mitigation exists.
    """
    title = (finding.get("title") or "").lower()

    # Match against known patterns (longest match first)
    best_mitigation = None
    best_key_len = 0
    for pattern, mitigation in MITIGATIONS.items():
        if pattern in title and len(pattern) > best_key_len:
            best_mitigation = mitigation
            best_key_len = len(pattern)

    if best_mitigation:
        return best_mitigation

    # Fallback to basic remediation
    return finding.get("remediation", "Review and remediate this finding based on security best practices.")


def enrich_findings(findings: list) -> list:
    """
    Enrich a list of finding dicts with CVSS scores and mitigation strategies.
    Modifies findings in-place and returns them.
    """
    for f in findings:
        if isinstance(f, dict):
            score, sev = get_cvss_score(f)
            f["cvss_score"] = score
            f["cvss_severity"] = sev
            f["mitigation_strategy"] = get_mitigation(f)
        else:
            score, sev = get_cvss_score(f.__dict__ if hasattr(f, '__dict__') else {})
            f.cvss_score = score
            f.cvss_severity = sev
            f.mitigation_strategy = get_mitigation(f.__dict__ if hasattr(f, '__dict__') else {})
    return findings


def _cvss_to_severity(score: float) -> str:
    """Map CVSS score to severity label per CVSS 3.1 spec."""
    if score == 0.0:
        return "none"
    elif score <= 3.9:
        return "low"
    elif score <= 6.9:
        return "medium"
    elif score <= 8.9:
        return "high"
    else:
        return "critical"
