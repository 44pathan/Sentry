"""
orchestrator.py — Scan Orchestrator
Coordinates all scan stages: fetch → normalize → match → correlate → score → store.
Manages scan lifecycle (queued → running → completed/failed).
"""

import uuid
import asyncio
import logging
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

from scanner.fetcher import Fetcher, FetchResult
from scanner.normalizer import Normalizer, PageSnapshot
from scanner.matcher import Matcher, Finding
from scanner.passive_checks import run_extended_checks
from scanner.surface_extractor import extract_surface
from scanner.active_checks import run_active_probes
from engine.rule_engine import ScanRuleEngine
from engine.correlator import FindingCorrelator
from engine.risk_scorer import RiskScorer
from engine.cvss_enricher import enrich_findings as enrich_cvss
from storage import ScanStorage

logger = logging.getLogger(__name__)


@dataclass
class ScanJob:
    """Represents a scan job with its lifecycle state."""
    scan_id: str = ""
    target_url: str = ""
    status: str = "queued"          # queued | fetching | analyzing | active_probing | correlating | completed | failed
    progress: int = 0
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    error: str = ""

    # Results (populated when completed)
    findings_count: int = 0
    risk_score: int = 0
    risk_grade: str = ""
    severity_breakdown: dict = field(default_factory=dict)
    technologies: list = field(default_factory=list)
    scan_duration_ms: float = 0.0
    active_probes_log: list = field(default_factory=list)

    # Options
    options: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class ScanOrchestrator:
    """
    Coordinates the full scan pipeline:
    1. Fetch target pages
    2. Normalize responses into structured snapshots
    3. Run pattern matcher with loaded rules
    4. Correlate and deduplicate findings
    5. Calculate risk score
    6. Store results
    """

    def __init__(self, es_client=None, storage: ScanStorage = None):
        self.normalizer = Normalizer()
        self.matcher = Matcher()
        self.rule_engine = ScanRuleEngine()
        self.correlator = FindingCorrelator()
        self.risk_scorer = RiskScorer()
        self.es_client = es_client
        self.storage = storage or ScanStorage(es_client)

        # Default fetcher (replaced per-scan with auth/rate config)
        self.fetcher = Fetcher(concurrency=10)

        # In-memory scan job tracking
        self._jobs = {}
        self._jobs_lock = threading.Lock()

    def load_rules(self, rules: list):
        """Load detection rules into the matcher."""
        self.matcher.load_rules(rules)
        logger.info(f"[Orchestrator] Loaded {len(rules)} detection rules")

    def submit_scan(self, target_url: str, options: dict = None) -> ScanJob:
        """
        Submit a new scan job. Returns the ScanJob immediately.
        Scan runs in a background thread.
        """
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        job = ScanJob(
            scan_id=scan_id,
            target_url=target_url,
            status="queued",
            progress=0,
            created_at=now,
            options=options or {},
        )

        with self._jobs_lock:
            self._jobs[scan_id] = job
        self.storage.store_job(job.to_dict())

        # Run scan in background thread
        thread = threading.Thread(
            target=self._run_scan_sync,
            args=(scan_id, target_url, options or {}),
            daemon=True
        )
        thread.start()

        return job

    def get_job(self, scan_id: str) -> ScanJob:
        """Get the current state of a scan job."""
        with self._jobs_lock:
            job = self._jobs.get(scan_id)
            if job:
                return job

        job_dict = self.storage.get_job(scan_id)
        if job_dict:
            valid_fields = ScanJob.__dataclass_fields__.keys()
            filtered = {k: v for k, v in job_dict.items() if k in valid_fields}
            return ScanJob(**filtered)
        return None

    def get_all_jobs(self) -> list:
        """Get all scan jobs."""
        # storage.get_all_jobs() always returns a list (from ES or memory).
        # We merge with any in-memory jobs that haven't been persisted yet.
        stored = self.storage.get_all_jobs()
        stored_ids = {j.get("scan_id") for j in stored}

        with self._jobs_lock:
            # Add any in-flight jobs not yet in storage
            for scan_id, job in self._jobs.items():
                if scan_id not in stored_ids:
                    stored.append(job.to_dict())

        stored.sort(key=lambda j: j.get("created_at", ""), reverse=True)
        return stored

    def get_findings(self, scan_id: str) -> list:
        """Get findings for a completed scan."""
        return self.storage.get_findings(scan_id)

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan job and its findings."""
        with self._jobs_lock:
            self._jobs.pop(scan_id, None)
        return self.storage.delete_job(scan_id)

    def _update_job(self, scan_id: str, **kwargs):
        """Thread-safe job state update."""
        with self._jobs_lock:
            job = self._jobs.get(scan_id)
            if job:
                for k, v in kwargs.items():
                    setattr(job, k, v)
                self.storage.store_job(job.to_dict())

    def _run_scan_sync(self, scan_id: str, target_url: str, options: dict):
        """Synchronous wrapper to run async scan pipeline in a thread.
        Creates a fresh event loop, runs the full pipeline, then tears it
        down cleanly — cancelling every pending task so nothing leaks into
        the next scan's event loop.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                self._run_scan_pipeline(scan_id, target_url, options)
            )
        except BaseException as e:
            # Catch BaseException so CancelledError (Python 3.8+ BaseException subclass)
            # and other non-Exception failures are also handled
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                raise  # Let process-level signals propagate normally
            logger.error(f"[Scan {scan_id[:8]}] Unhandled pipeline error: {type(e).__name__}: {e}", exc_info=True)
            self._update_job(
                scan_id,
                status="failed",
                error=str(e),
                completed_at=datetime.now(timezone.utc).isoformat()
            )
        finally:
            # ── Proper loop teardown ────────────────────────────
            # Cancel every pending task so they don't linger or crash
            # the next scan that reuses this thread.
            try:
                pending = asyncio.all_tasks(loop)
                if pending:
                    for task in pending:
                        task.cancel()
                    # Let the cancelled tasks run their cleanup (CancelledError)
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except Exception:
                pass
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                loop.close()
                asyncio.set_event_loop(None)


    async def _run_scan_pipeline(self, scan_id: str, target_url: str, options: dict):
        """Main async scanning pipeline."""
        start_time = time.monotonic()
        now = datetime.now(timezone.utc).isoformat()

        self._update_job(
            scan_id,
            status="fetching",
            progress=5,
            started_at=now
        )

        logger.info(f"[Scan {scan_id[:8]}] Starting scan against {target_url}")

        # Extract per-scan rate limit
        rate_limit = options.get("rate_limit", 0)

        # Parse auth_cookies from string format "key=val; key2=val2" into dict
        auth_cookies_raw = options.get("auth_cookies", "")
        auth_cookies = {}
        if isinstance(auth_cookies_raw, dict):
            auth_cookies = auth_cookies_raw
        elif isinstance(auth_cookies_raw, str) and auth_cookies_raw.strip():
            for pair in auth_cookies_raw.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    auth_cookies[k.strip()] = v.strip()

        # Parse auth_headers from string format "Header: Value" into dict
        auth_headers_raw = options.get("auth_headers", "")
        auth_headers = {}
        if isinstance(auth_headers_raw, dict):
            auth_headers = auth_headers_raw
        elif isinstance(auth_headers_raw, str) and auth_headers_raw.strip():
            for line in auth_headers_raw.split("\n"):
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    auth_headers[k.strip()] = v.strip()

        # Instantiate dedicated Fetcher for this scan run
        fetcher = Fetcher(
            concurrency=10,
            extra_cookies=auth_cookies if auth_cookies else None,
            extra_headers=auth_headers if auth_headers else None,
            rate_limit=rate_limit
        )

        # ── Stage 1: Fetch main target page ───────────────────
        fetch_result = await fetcher.fetch(target_url)

        if fetch_result.error and fetch_result.status_code == 0:
            logger.error(f"[Scan {scan_id[:8]}] Fetch failed: {fetch_result.error}")
            self._update_job(
                scan_id,
                status="failed",
                error=f"Could not reach target: {fetch_result.error}",
                completed_at=datetime.now(timezone.utc).isoformat()
            )
            return

        self._update_job(scan_id, progress=20)

        # ── Stage 2: Normalize response ───────────────────────
        snapshot = self.normalizer.normalize(fetch_result)
        self._update_job(scan_id, status="analyzing", progress=30)

        # ── Stage 3: Deep Scan (common paths check) ───────────
        scan_mode = options.get("scan_mode", "passive")
        deep_scan = options.get("deep_scan", scan_mode != "passive")
        common_path_findings = []
        if deep_scan:
            try:
                # Hard cap: common paths check must finish in 20s (slow servers can hang forever)
                common_path_findings = await asyncio.wait_for(
                    self._check_common_paths(target_url, scan_id, fetcher=fetcher),
                    timeout=12
                )
            except asyncio.TimeoutError:
                logger.warning(f"[Scan {scan_id[:8]}] Common paths check timed out after 20s — skipping")
                common_path_findings = []

        self._update_job(scan_id, progress=45)

        # ── Stage 4: Run rule matching ────────────────────────
        findings = []
        findings.extend(common_path_findings)

        logger.info(f"[Scan {scan_id[:8]}] Stage 4: Running {len(self.matcher.rules)} detection rules against snapshot")
        rule_findings = self.matcher.match_snapshot(snapshot, scan_id=scan_id)
        logger.info(f"[Scan {scan_id[:8]}] Stage 4 done: {len(rule_findings)} rule matches found")
        findings.extend(rule_findings)

        self._update_job(scan_id, progress=60)

        # ── Stage 5: Header security checks ───────────────────
        header_findings = self._check_security_headers(snapshot, scan_id)
        findings.extend(header_findings)

        # ── Stage 6: Cookie security checks ───────────────────
        cookie_findings = self._check_cookie_security(snapshot, scan_id)
        findings.extend(cookie_findings)

        # ── Stage 6b: Extended passive checks (A03/A04/A07/A08/A09/A10) ──
        extended_findings = run_extended_checks(snapshot, scan_id)
        findings.extend(extended_findings)

        # ── Stage 6c: Attack Surface Discovery ────────────────
        scan_mode = options.get("scan_mode", "passive")
        logger.info(f"[Scan {scan_id[:8]}] Scan mode: {scan_mode}")
        surface = extract_surface(snapshot, target_url)
        logger.info(
            f"[Scan {scan_id[:8]}] Surface: {surface.total_params} params, "
            f"{surface.total_forms} forms, {surface.total_links} internal links"
        )

        self._update_job(scan_id, progress=62)

        active_probes_log = []
        if scan_mode in ("light_active", "full_active"):
            logger.info(f"[Scan {scan_id[:8]}] Running active probes ({scan_mode})")
            self._update_job(scan_id, status="active_probing", progress=65)
            try:
                active_findings, active_probes_log = await asyncio.wait_for(
                    run_active_probes(fetcher, surface, scan_id, scan_mode),
                    timeout=300
                )
                findings.extend(active_findings)
                logger.info(
                    f"[Scan {scan_id[:8]}] Active probes executed {len(active_probes_log)} checks, "
                    f"found {len(active_findings)} findings"
                )
            except asyncio.TimeoutError:
                logger.warning(f"[Scan {scan_id[:8]}] Active scan timed out after 5 minutes, continuing with whatever findings were collected")
        else:
            logger.info(f"[Scan {scan_id[:8]}] Skipping active probes (passive mode)")

        # ── Stage 7: TLS checks ───────────────────────────────
        tls_findings = self._check_tls(snapshot, scan_id)
        findings.extend(tls_findings)

        self._update_job(scan_id, status="correlating", progress=75)

        # ── Stage 8: Correlate / deduplicate ──────────────────
        logger.info(f"[Scan {scan_id[:8]}] Correlating {len(findings)} findings")
        findings = self.correlator.correlate(findings)

        self._update_job(scan_id, progress=85)

        # ── Stage 9: Risk scoring ─────────────────────────────
        logger.info(f"[Scan {scan_id[:8]}] Calculating risk score")
        risk_result = self.risk_scorer.calculate(findings)

        self._update_job(scan_id, progress=88)

        # ── Stage 10: CVSS + Mitigation enrichment ───────────
        logger.info(f"[Scan {scan_id[:8]}] Enriching with CVSS scores and mitigations")
        findings_dicts = [f.to_dict() for f in findings]
        enrich_cvss(findings_dicts)

        # ── Stage 10b: OWASP 2025 cross-mapping ──────────────
        from engine.owasp_mapper import enrich_finding_owasp_2025
        for fd in findings_dicts:
            enrich_finding_owasp_2025(fd)

        self._update_job(scan_id, progress=92)

        # ── Stage 11: Store results ───────────────────────────
        self.storage.store_findings(scan_id, findings_dicts)

        elapsed = (time.monotonic() - start_time) * 1000

        # ── Complete ──────────────────────────────────────────
        self._update_job(
            scan_id,
            status="completed",
            progress=100,
            completed_at=datetime.now(timezone.utc).isoformat(),
            findings_count=len(findings),
            risk_score=risk_result["score"],
            risk_grade=risk_result["grade"],
            severity_breakdown=risk_result["breakdown"],
            technologies=[t for t in snapshot.technologies_hints],
            scan_duration_ms=round(elapsed, 2),
            active_probes_log=active_probes_log,
        )

        logger.info(
            f"[Scan {scan_id[:8]}] Completed — "
            f"{len(findings)} findings, risk score {risk_result['score']}/100 "
            f"({risk_result['grade']}), {elapsed:.0f}ms"
        )

    async def _check_common_paths(self, base_url: str, scan_id: str, fetcher: Fetcher = None) -> list:
        """Check for exposed sensitive files/paths.

        Uses synchronous requests in a ThreadPoolExecutor instead of async aiohttp
        to avoid Python 3.14 + aiohttp SSL-cancellation SIGKILL crashes that occur
        when asyncio.wait_for cancels in-flight SSL handshakes.
        """
        import requests as _requests
        import urllib3
        from urllib.parse import urljoin
        from concurrent.futures import ThreadPoolExecutor, wait as cf_wait

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        now = datetime.now(timezone.utc).isoformat()
        sensitive_paths = [
            ("/.git/config", "Exposed Git Repository", "critical",
             "Git configuration file is publicly accessible, potentially exposing source code and credentials.",
             "A05:2021-Security Misconfiguration"),
            ("/.env", "Exposed Environment File", "critical",
             "Environment file with potential secrets (API keys, DB passwords) is publicly accessible.",
             "A05:2021-Security Misconfiguration"),
            ("/robots.txt", "Robots.txt Found", "info",
             "Robots.txt file found — may reveal hidden paths.",
             "A01:2021-Broken Access Control"),
            ("/.htaccess", "Exposed .htaccess", "high",
             "Apache .htaccess file is publicly accessible.",
             "A05:2021-Security Misconfiguration"),
            ("/wp-login.php", "WordPress Login Page", "info",
             "WordPress login page is accessible — confirms WordPress installation.",
             "A07:2021-Identification and Authentication Failures"),
            ("/admin", "Admin Panel Accessible", "medium",
             "Administrative interface is publicly accessible without authentication.",
             "A01:2021-Broken Access Control"),
            ("/crossdomain.xml", "Cross-Domain Policy", "low",
             "Cross-domain policy file found.",
             "A05:2021-Security Misconfiguration"),
            ("/sitemap.xml", "Sitemap Found", "info",
             "Sitemap.xml found — reveals site structure.",
             ""),
            ("/.well-known/security.txt", "Security.txt Found", "info",
             "Security contact information found.",
             ""),
        ]

        def _sync_check(path_info):
            """Sync check — runs in a thread, safe to abandon."""
            path, title, severity, description, owasp = path_info
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = _requests.get(
                    url,
                timeout=(3, 3),       # (connect, read) — 3s each; GLS is slow but not that slow
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 Sentry-Scanner/1.0"},
                    stream=False,
                )
                if resp.status_code == 200:
                    body = resp.text[:2000]
                    body_lower = body.lower()
                    is_soft_404 = any(x in body_lower for x in [
                        "404", "not found", "page not found",
                        "does not exist", "error page"
                    ])
                    if not is_soft_404 and len(body) > 10:
                        if path == "/.git/config" and "[core]" not in body:
                            return None
                        if path == "/.env" and "=" not in body:
                            return None
                        return Finding(
                            id=str(uuid.uuid4()),
                            scan_id=scan_id,
                            target_url=url,
                            timestamp=now,
                            source_tool="custom",
                            type="misconfiguration",
                            severity=severity,
                            title=title,
                            description=description,
                            owasp_category=owasp,
                            evidence_location="path",
                            evidence_snippet=body[:200],
                            remediation=f"Remove or restrict access to {path}",
                        )
            except Exception:
                pass
            return None

        findings = []

        # Run all path checks concurrently in a thread pool (max 4 concurrent SSL handshakes)
        # Using sync requests avoids the Python 3.14 + aiohttp SSL-cancellation SIGKILL bug
        with ThreadPoolExecutor(max_workers=9, thread_name_prefix="pathcheck") as pool:
            future_to_path = {pool.submit(_sync_check, p): p for p in sensitive_paths}
            # All 9 paths run simultaneously; wait up to 9s (3s timeout × 1 round + buffer)
            done, _ = cf_wait(future_to_path, timeout=9)
            for future in done:
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                except Exception:
                    pass

        return findings



    def _check_security_headers(self, snapshot: PageSnapshot, scan_id: str) -> list:
        """Check for missing security headers."""
        findings = []
        headers = snapshot.headers
        url = snapshot.url
        now = datetime.now(timezone.utc).isoformat()

        required_headers = [
            ("strict-transport-security", "Missing HSTS Header", "medium",
             "Strict-Transport-Security header is not set. Communication may be vulnerable to SSL stripping.",
             "A05:2021-Security Misconfiguration", "CWE-523",
             "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."),

            ("content-security-policy", "Missing Content-Security-Policy", "medium",
             "Content-Security-Policy (CSP) header is not set. Site lacks defense-in-depth against XSS.",
             "A05:2021-Security Misconfiguration", "CWE-1021",
             "Implement a restrictive CSP header (e.g. default-src 'self')."),

            ("x-frame-options", "Missing X-Frame-Options", "low",
             "X-Frame-Options header is not set. Page may be vulnerable to Clickjacking.",
             "A05:2021-Security Misconfiguration", "CWE-1021",
             "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),

            ("x-content-type-options", "Missing X-Content-Type-Options", "low",
             "X-Content-Type-Options header is missing. Browsers may MIME-sniff response types.",
             "A05:2021-Security Misconfiguration", "CWE-116",
             "Set 'X-Content-Type-Options: nosniff'."),

            ("referrer-policy", "Missing Referrer-Policy", "info",
             "Referrer-Policy header is not configured.",
             "A05:2021-Security Misconfiguration", "CWE-200",
             "Set 'Referrer-Policy: strict-origin-when-cross-origin'."),

            ("permissions-policy", "Missing Permissions-Policy", "info",
             "Permissions-Policy header is missing. Browser features are not restricted.",
             "A05:2021-Security Misconfiguration", "",
             "Configure Permissions-Policy header."),
        ]

        for header_name, title, severity, desc, owasp, cwe, remediation in required_headers:
            if header_name not in headers:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    target_url=url,
                    timestamp=now,
                    source_tool="custom",
                    type="missing_header",
                    severity=severity,
                    title=title,
                    description=desc,
                    owasp_category=owasp,
                    cwe=cwe,
                    evidence_location="headers",
                    evidence_snippet=f"Header '{header_name}' missing from response headers",
                    remediation=remediation,
                ))

        return findings

    def _check_cookie_security(self, snapshot: PageSnapshot, scan_id: str) -> list:
        """Check cookies for Secure and HttpOnly flags."""
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        for cname, cinfo in snapshot.cookies.items():
            if isinstance(cinfo, dict):
                is_secure = cinfo.get("secure", False)
                is_httponly = cinfo.get("httponly", False)

                if not is_secure and snapshot.url.startswith("https"):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        target_url=snapshot.url,
                        timestamp=now,
                        source_tool="custom",
                        type="insecure_cookie",
                        severity="medium",
                        title=f"Cookie '{cname}' Missing Secure Flag",
                        description=f"The cookie '{cname}' is transmitted over HTTPS but lacks the Secure flag.",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe="CWE-614",
                        evidence_location="cookies",
                        evidence_snippet=f"Cookie: {cname}={cinfo.get('value', '')[:20]}",
                        remediation="Set the 'Secure' attribute on all cookies served over HTTPS.",
                    ))

                if not is_httponly and any(s in cname.lower() for s in ["sess", "auth", "token", "id"]):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        target_url=snapshot.url,
                        timestamp=now,
                        source_tool="custom",
                        type="insecure_cookie",
                        severity="medium",
                        title=f"Session Cookie '{cname}' Missing HttpOnly Flag",
                        description=f"Session cookie '{cname}' lacks HttpOnly flag, making it accessible via JavaScript.",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe="CWE-1004",
                        evidence_location="cookies",
                        evidence_snippet=f"Cookie: {cname}={cinfo.get('value', '')[:20]}",
                        remediation="Set the 'HttpOnly' attribute on sensitive session cookies.",
                    ))

        return findings

    def _check_tls(self, snapshot: PageSnapshot, scan_id: str) -> list:
        """Check TLS configuration."""
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        if not snapshot.url.startswith("https://"):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                target_url=snapshot.url,
                timestamp=now,
                source_tool="custom",
                type="unencrypted_transport",
                severity="high",
                title="Target Uses Unencrypted HTTP",
                description="Target website is served over unencrypted HTTP. All data in transit can be intercepted.",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe="CWE-319",
                evidence_location="scheme",
                evidence_snippet=f"URL: {snapshot.url}",
                remediation="Enforce HTTPS across all pages and redirect HTTP traffic to HTTPS.",
            ))
            return findings

        if snapshot.tls_error:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                target_url=snapshot.url,
                timestamp=now,
                source_tool="custom",
                type="tls_issue",
                severity="medium",
                title="TLS Inspection Error",
                description=f"Failed to inspect TLS configuration: {snapshot.tls_error}",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe="CWE-295",
                evidence_location="tls",
                evidence_snippet=snapshot.tls_error,
                remediation="Ensure valid SSL/TLS certificate is installed.",
            ))

        if snapshot.tls_protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                target_url=snapshot.url,
                timestamp=now,
                source_tool="custom",
                type="deprecated_tls",
                severity="high",
                title=f"Deprecated TLS Protocol ({snapshot.tls_protocol})",
                description=f"Server supports deprecated protocol {snapshot.tls_protocol}.",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe="CWE-326",
                evidence_location="tls",
                evidence_snippet=f"Protocol: {snapshot.tls_protocol}",
                remediation="Disable TLS 1.0/1.1 and enable TLS 1.2 and TLS 1.3.",
            ))

        return findings
