"""
fetcher.py — Layer 1: Raw HTTP Fetcher
Uses synchronous `requests` via asyncio.run_in_executor to avoid Python 3.14 +
aiohttp SSL-cancellation SIGKILL crashes. The public async API is preserved so
all callers (orchestrator, active_checks) continue to work unchanged.

NOTE: TLS certificate / cipher inspection is intentionally omitted.
Opening a second raw SSL socket for TLS info crashes Python 3.14's ssl module
on certain servers (e.g. slow TLS handshakes). The scanner still detects
unencrypted HTTP via the URL scheme — the most critical TLS finding.
"""

import asyncio
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests as _requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import FETCH_TIMEOUT, MAX_REDIRECTS, USER_AGENT, MAX_BODY_SIZE, DEFAULT_RPS_LIMIT

logger = logging.getLogger(__name__)

# Shared thread pool for running sync requests without blocking the event loop.
# 10 workers = same as the default aiohttp concurrency limit.
_FETCH_POOL = ThreadPoolExecutor(max_workers=10, thread_name_prefix="fetcher")


class AsyncRateLimiter:
    """Token-bucket rate limiter for controlling requests per second."""

    def __init__(self, rps: float = 10):
        self.rps = max(0.1, rps) if rps and rps > 0 else 0
        self._interval = 1.0 / self.rps if self.rps else 0
        self._last_request = 0.0
        self._lock = None
        self._lock_loop = None

    def _get_lock(self):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    async def acquire(self):
        if not self._interval:
            return
        async with self._get_lock():
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self._interval:
                await asyncio.sleep(self._interval - elapsed)
            self._last_request = time.monotonic()


@dataclass
class TLSInfo:
    """TLS/SSL certificate information."""
    protocol: str = ""
    cipher: str = ""
    cert_subject: dict = field(default_factory=dict)
    cert_issuer: dict = field(default_factory=dict)
    cert_expiry: str = ""
    cert_not_before: str = ""
    serial_number: str = ""
    has_valid_cert: bool = False
    error: str = ""


@dataclass
class FetchResult:
    """Complete result of fetching a URL."""
    url: str
    final_url: str = ""
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    redirect_chain: list = field(default_factory=list)
    tls_info: Optional[TLSInfo] = None
    response_time_ms: float = 0.0
    cookies: dict = field(default_factory=dict)
    error: Optional[str] = None
    content_type: str = ""
    server: str = ""



def _sync_fetch(url: str, method: str = "GET",
                timeout: float = FETCH_TIMEOUT,
                max_redirects: int = MAX_REDIRECTS,
                user_agent: str = USER_AGENT,
                extra_cookies: dict = None,
                extra_headers: dict = None,
                data: dict = None) -> FetchResult:
    """
    Synchronous HTTP fetch using requests. Called from a thread pool.
    Never blocks the asyncio event loop.
    """
    result = FetchResult(url=url)
    start_time = time.monotonic()

    session = _requests.Session()
    session.max_redirects = max_redirects
    session.headers.update({"User-Agent": user_agent})
    if extra_headers:
        session.headers.update(extra_headers)
    if extra_cookies:
        session.cookies.update(extra_cookies)

    try:
        resp = session.request(
            method,
            url,
            timeout=(5, min(timeout, 8)),  # (connect+SSL, read); keeps slow servers from hanging forever
            verify=False,
            allow_redirects=True,
            data=data,
            stream=True,                   # stream to avoid reading huge bodies into RAM
        )

        elapsed = (time.monotonic() - start_time) * 1000

        # Capture redirect chain
        redirect_chain = []
        for r in resp.history:
            redirect_chain.append({
                "url": str(r.url),
                "status": r.status_code,
                "location": r.headers.get("Location", ""),
            })

        headers = {k.lower(): v for k, v in resp.headers.items()}
        content_type = headers.get("content-type", "")

        # Read body with size cap
        body = ""
        if ("text" in content_type or "json" in content_type
                or "xml" in content_type or "html" in content_type
                or not content_type):
            raw = resp.raw.read(MAX_BODY_SIZE + 1, decode_content=True)
            if len(raw) > MAX_BODY_SIZE:
                raw = raw[:MAX_BODY_SIZE]
            body = raw.decode("utf-8", errors="replace")

        resp.close()

        # Extract cookies
        cookies = {}
        for cname, cval in resp.cookies.items():
            cookies[cname] = {
                "value": cval,
                "domain": resp.cookies.get_dict().get(cname, ""),
                "path": "",
                "secure": False,
                "httponly": False,
                "samesite": "",
            }

        result.final_url = str(resp.url)
        result.status_code = resp.status_code
        result.headers = headers
        result.body = body
        result.redirect_chain = redirect_chain
        result.response_time_ms = round(elapsed, 2)
        result.cookies = cookies
        result.content_type = content_type
        result.server = headers.get("server", "")

        # TLS protocol inspection intentionally skipped — opening a second SSL
        # socket to inspect cipher/cert crashes Python 3.14 on certain servers.
        # Unencrypted-HTTP detection still works via the URL scheme check.

    except _requests.exceptions.Timeout:
        result.error = f"Timeout after {timeout}s"
    except _requests.exceptions.SSLError as e:
        result.error = f"SSL error: {e}"
    except _requests.exceptions.ConnectionError as e:
        result.error = f"Connection error: {e}"
    except Exception as e:
        result.error = f"Fetch error: {e}"
    finally:
        session.close()

    if not result.final_url:
        result.final_url = url

    return result


class Fetcher:
    """
    HTTP fetcher with rate limiting and concurrency control.
    Async API preserved for compatibility with orchestrator/active_checks callers.
    Internally uses synchronous requests via run_in_executor.
    """

    def __init__(self, concurrency=10, timeout=FETCH_TIMEOUT,
                 max_redirects=MAX_REDIRECTS, user_agent=USER_AGENT,
                 extra_cookies=None, extra_headers=None, rate_limit=0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.extra_cookies = extra_cookies or {}
        self.extra_headers = extra_headers or {}
        self.rate_limiter = AsyncRateLimiter(rate_limit) if rate_limit else None
        self._semaphore = None
        self._semaphore_loop = None

    def _get_semaphore(self):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if self._semaphore is None or self._semaphore_loop is not loop:
            self._semaphore = asyncio.Semaphore(self.concurrency)
            self._semaphore_loop = loop
        return self._semaphore

    async def fetch(self, url: str, method: str = "GET",
                    follow_redirects: bool = True, timeout: float = None,
                    data: dict = None) -> FetchResult:
        """
        Async fetch — runs _sync_fetch in the shared thread pool.
        asyncio.wait_for timeouts work correctly (cancel the executor future).
        """
        if self.rate_limiter:
            await self.rate_limiter.acquire()

        async with self._get_semaphore():
            loop = asyncio.get_event_loop()
            effective_timeout = timeout if timeout is not None else self.timeout
            result = await loop.run_in_executor(
                _FETCH_POOL,
                lambda: _sync_fetch(
                    url=url,
                    method=method,
                    timeout=effective_timeout,
                    max_redirects=self.max_redirects if follow_redirects else 0,
                    user_agent=self.user_agent,
                    extra_cookies=self.extra_cookies,
                    extra_headers=self.extra_headers,
                    data=data,
                )
            )
            return result

    async def fetch_post(self, url: str, data: dict,
                         timeout: float = None) -> FetchResult:
        """Convenience wrapper for POST requests with form data."""
        return await self.fetch(url, method="POST", data=data, timeout=timeout)

    async def fetch_multiple(self, urls: list, method: str = "GET") -> list:
        """Fetch multiple URLs concurrently."""
        tasks = [self.fetch(url, method) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)


# ── Synchronous wrapper for non-async contexts ───────────

def fetch_url(url: str, **kwargs) -> FetchResult:
    """Synchronous wrapper — calls _sync_fetch directly."""
    return _sync_fetch(url, **kwargs)
