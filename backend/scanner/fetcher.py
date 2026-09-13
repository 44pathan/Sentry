"""
fetcher.py — Layer 1: Raw HTTP Fetcher
Handles async HTTP requests with redirect tracking, TLS inspection,
timeout/retry logic, and concurrency limiting.
"""

import asyncio
import socket
import ssl
import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import FETCH_TIMEOUT, MAX_REDIRECTS, USER_AGENT, MAX_BODY_SIZE, DEFAULT_RPS_LIMIT

logger = logging.getLogger(__name__)


class AsyncRateLimiter:
    """Token-bucket rate limiter for controlling requests per second."""

    def __init__(self, rps: float = 10):
        self.rps = max(0.1, rps) if rps and rps > 0 else 0
        self._interval = 1.0 / self.rps if self.rps else 0
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until a request slot is available."""
        if not self._interval:
            return  # unlimited
        async with self._lock:
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


class Fetcher:
    """
    Async HTTP fetcher with redirect tracking, TLS inspection,
    and concurrency control.
    """

    def __init__(self, concurrency=10, timeout=FETCH_TIMEOUT,
                 max_redirects=MAX_REDIRECTS, user_agent=USER_AGENT,
                 extra_cookies=None, extra_headers=None, rate_limit=0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.extra_cookies = extra_cookies or {}   # {"session": "abc123"}
        self.extra_headers = extra_headers or {}   # {"Authorization": "Bearer ..."}
        self.rate_limiter = AsyncRateLimiter(rate_limit) if rate_limit else None
        self._semaphore = None  # Lazily created inside event loop

    def _get_semaphore(self):
        """Get or create semaphore inside the running event loop."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    async def fetch(self, url: str, method: str = "GET",
                     follow_redirects: bool = True, timeout: float = None,
                     data: dict = None) -> FetchResult:
        """
        Fetch a URL with full redirect chain tracking and TLS inspection.
        Respects rate limiting and injects auth cookies/headers if configured.

        Args:
            data: Optional dict of form fields to send as POST body
                  (application/x-www-form-urlencoded).
        """
        if self.rate_limiter:
            await self.rate_limiter.acquire()
        async with self._get_semaphore():
            return await self._do_fetch(url, method, follow_redirects,
                                        timeout=timeout, data=data)

    async def fetch_post(self, url: str, data: dict,
                         timeout: float = None) -> FetchResult:
        """Convenience wrapper for POST requests with form data."""
        return await self.fetch(url, method="POST", data=data, timeout=timeout)

    async def _do_fetch(self, url: str, method: str,
                        follow_redirects: bool, timeout: float = None,
                        data: dict = None) -> FetchResult:
        result = FetchResult(url=url)
        redirect_chain = []
        current_url = url
        start_time = time.monotonic()

        # Create SSL context that captures cert info
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=self.concurrency,
            family=socket.AF_INET
        )

        effective_timeout = timeout if timeout is not None else self.timeout
        client_timeout = aiohttp.ClientTimeout(
            total=effective_timeout,
            connect=min(10.0, effective_timeout),
            sock_read=min(10.0, effective_timeout)
        )

        try:
            # Merge base headers with any auth headers
            session_headers = {"User-Agent": self.user_agent}
            if self.extra_headers:
                session_headers.update(self.extra_headers)

            # Build cookie jar from auth cookies
            cookie_jar = aiohttp.CookieJar(unsafe=True)
            if self.extra_cookies:
                for cname, cval in self.extra_cookies.items():
                    cookie_jar.update_cookies({cname: cval})

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=client_timeout,
                headers=session_headers,
                cookie_jar=cookie_jar,
            ) as session:

                # Run TLS inspection concurrently if HTTPS to eliminate sequential blocking delay
                tls_task = None
                if url.startswith("https://"):
                    tls_task = asyncio.create_task(self._get_tls_info(url))

                # Manual redirect following to capture chain
                for i in range(self.max_redirects + 1):
                    try:
                        # Build request kwargs — include form data for POST
                        req_kwargs = {
                            "allow_redirects": False,
                            "max_line_size": 8190,
                            "max_field_size": 8190,
                        }
                        if data and method.upper() == "POST":
                            req_kwargs["data"] = data

                        async with session.request(
                            method, current_url, **req_kwargs
                        ) as resp:
                            status = resp.status
                            headers = {
                                k.lower(): v for k, v in resp.headers.items()
                            }

                            # Check for redirect
                            if status in (301, 302, 303, 307, 308) and follow_redirects:
                                location = headers.get("location", "")
                                if location:
                                    redirect_chain.append({
                                        "url": current_url,
                                        "status": status,
                                        "location": location
                                    })
                                    # Handle relative redirects
                                    if location.startswith("/"):
                                        parsed = urlparse(current_url)
                                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                                    current_url = location
                                    continue

                            # Read body (with size cap)
                            body = ""
                            content_type = headers.get("content-type", "")
                            if "text" in content_type or "json" in content_type or "xml" in content_type or "html" in content_type or not content_type:
                                raw = await resp.read()
                                if len(raw) <= MAX_BODY_SIZE:
                                    body = raw.decode("utf-8", errors="replace")
                                else:
                                    body = raw[:MAX_BODY_SIZE].decode("utf-8", errors="replace")

                            # Extract cookies
                            cookies = {}
                            for cookie_name, cookie_morsel in resp.cookies.items():
                                cookies[cookie_name] = {
                                    "value": cookie_morsel.value,
                                    "domain": cookie_morsel.get("domain", ""),
                                    "path": cookie_morsel.get("path", ""),
                                    "secure": bool(cookie_morsel.get("secure")),
                                    "httponly": bool(cookie_morsel.get("httponly")),
                                    "samesite": cookie_morsel.get("samesite", ""),
                                }

                            elapsed = (time.monotonic() - start_time) * 1000

                            result.final_url = current_url
                            result.status_code = status
                            result.headers = headers
                            result.body = body
                            result.redirect_chain = redirect_chain
                            result.response_time_ms = round(elapsed, 2)
                            result.cookies = cookies
                            result.content_type = content_type
                            result.server = headers.get("server", "")

                            break

                    except aiohttp.ClientError as e:
                        if i < self.max_redirects:
                            redirect_chain.append({
                                "url": current_url,
                                "status": 0,
                                "error": str(e)
                            })
                        result.error = f"HTTP error: {str(e)}"
                        break

                if tls_task:
                    try:
                        result.tls_info = await asyncio.wait_for(tls_task, timeout=5.0)
                    except Exception as e:
                        logger.debug(f"[Fetcher] Concurrent TLS info task failed: {e}")

        except asyncio.TimeoutError:
            result.error = f"Timeout after {self.timeout}s"
        except Exception as e:
            result.error = f"Fetch error: {str(e)}"

        if not result.final_url:
            result.final_url = current_url

        result.redirect_chain = redirect_chain
        return result

    async def _get_tls_info(self, url: str) -> TLSInfo:
        """Extract TLS certificate information from a URL."""
        tls = TLSInfo()
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=10
            )

            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object:
                tls.protocol = ssl_object.version() or ""
                cipher_info = ssl_object.cipher()
                if cipher_info:
                    tls.cipher = cipher_info[0]

                cert = ssl_object.getpeercert()
                if cert:
                    tls.has_valid_cert = True
                    tls.cert_subject = dict(
                        x[0] for x in cert.get("subject", ())
                    ) if cert.get("subject") else {}
                    tls.cert_issuer = dict(
                        x[0] for x in cert.get("issuer", ())
                    ) if cert.get("issuer") else {}
                    tls.cert_expiry = cert.get("notAfter", "")
                    tls.cert_not_before = cert.get("notBefore", "")
                    tls.serial_number = cert.get("serialNumber", "")
                else:
                    # Try with verification to get cert
                    tls.has_valid_cert = False

            writer.close()
            await writer.wait_closed()

        except ssl.SSLCertVerificationError as e:
            tls.error = f"Certificate verification failed: {e}"
            tls.has_valid_cert = False
        except Exception as e:
            tls.error = f"TLS inspection error: {e}"

        return tls

    async def fetch_multiple(self, urls: list, method: str = "GET") -> list:
        """Fetch multiple URLs concurrently."""
        tasks = [self.fetch(url, method) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)


# ── Synchronous wrapper for non-async contexts ───────────

def fetch_url(url: str, **kwargs) -> FetchResult:
    """Synchronous wrapper around the async fetcher."""
    fetcher = Fetcher(**kwargs)
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(fetcher.fetch(url))
    finally:
        loop.close()
