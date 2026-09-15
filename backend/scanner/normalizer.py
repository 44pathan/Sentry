"""
normalizer.py — Layer 2: Response Normalizer
Transforms a raw FetchResult into a structured PageSnapshot
that the matcher engine can query efficiently.
Extracts scripts, meta tags, forms, comments, inline JS,
technology hints from headers, and more.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from bs4 import BeautifulSoup

from scanner.fetcher import FetchResult

logger = logging.getLogger(__name__)


@dataclass
class PageSnapshot:
    """Structured, queryable representation of a fetched page."""
    url: str
    final_url: str = ""
    status_code: int = 0
    response_time_ms: float = 0.0

    # Parsed from HTML body
    scripts: list = field(default_factory=list)          # external <script src="...">
    inline_scripts: list = field(default_factory=list)   # inline <script> content
    meta_tags: dict = field(default_factory=dict)         # name -> content
    forms: list = field(default_factory=list)              # [{action, method, inputs}]
    comments: list = field(default_factory=list)           # HTML comments
    links: list = field(default_factory=list)              # <a href="...">
    iframes: list = field(default_factory=list)            # <iframe src="...">
    title: str = ""

    # From headers
    headers: dict = field(default_factory=dict)            # lowercased
    cookies: dict = field(default_factory=dict)
    server: str = ""
    content_type: str = ""
    technologies_hints: list = field(default_factory=list)

    # Redirect info
    redirect_chain: list = field(default_factory=list)

    # TLS info
    tls_protocol: str = ""
    tls_cipher: str = ""
    cert_expiry: str = ""
    cert_issuer: dict = field(default_factory=dict)
    has_valid_cert: bool = False
    tls_error: str = ""

    # Raw body (for regex matching)
    body: str = ""
    body_lower: str = ""

    # Error
    error: Optional[str] = None


class Normalizer:
    """
    Normalizes a FetchResult into a PageSnapshot by parsing
    the HTML body and extracting structured data.
    """

    # Patterns for tech detection from headers
    HEADER_TECH_PATTERNS = {
        "x-powered-by": None,       # value is the tech itself
        "x-aspnet-version": "ASP.NET",
        "x-aspnetmvc-version": "ASP.NET MVC",
        "x-drupal-cache": "Drupal",
        "x-generator": None,        # value is the tech
        "x-shopify-stage": "Shopify",
        "x-wix-request-id": "Wix",
        "x-fw-hash": "Flywheel",
        "x-litespeed-cache": "LiteSpeed",
        "x-varnish": "Varnish",
        "x-cache": None,            # CDN hint
    }

    # Server header patterns
    SERVER_PATTERNS = [
        (r"apache[/ ]*(\d[\d.]*)?", "Apache"),
        (r"nginx[/ ]*(\d[\d.]*)?", "Nginx"),
        (r"microsoft-iis[/ ]*(\d[\d.]*)?", "Microsoft IIS"),
        (r"litespeed", "LiteSpeed"),
        (r"cloudflare", "Cloudflare"),
        (r"openresty[/ ]*(\d[\d.]*)?", "OpenResty"),
        (r"caddy", "Caddy"),
        (r"envoy", "Envoy"),
        (r"gunicorn[/ ]*(\d[\d.]*)?", "Gunicorn"),
    ]

    def normalize(self, fetch_result: FetchResult) -> PageSnapshot:
        """Transform a FetchResult into a structured PageSnapshot."""
        snapshot = PageSnapshot(
            url=fetch_result.url,
            final_url=fetch_result.final_url,
            status_code=fetch_result.status_code,
            response_time_ms=fetch_result.response_time_ms,
            headers=fetch_result.headers,
            cookies=fetch_result.cookies,
            server=fetch_result.server,
            content_type=fetch_result.content_type,
            redirect_chain=fetch_result.redirect_chain,
            body=fetch_result.body,
            body_lower=fetch_result.body.lower() if fetch_result.body else "",
            error=fetch_result.error,
        )

        # TLS info
        if fetch_result.tls_info:
            tls = fetch_result.tls_info
            snapshot.tls_protocol = tls.protocol
            snapshot.tls_cipher = tls.cipher
            snapshot.cert_expiry = tls.cert_expiry
            snapshot.cert_issuer = tls.cert_issuer
            snapshot.has_valid_cert = tls.has_valid_cert
            snapshot.tls_error = tls.error

        # Parse HTML body
        if fetch_result.body and ("html" in snapshot.content_type or not snapshot.content_type):
            self._parse_html(fetch_result.body, snapshot)

        # Extract technology hints from headers
        self._extract_header_hints(snapshot)

        return snapshot

    def _parse_html(self, html: str, snapshot: PageSnapshot):
        """Parse HTML and extract structured data."""
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception as e:
                logger.warning(f"HTML parsing failed for {snapshot.url}: {e}")
                return

        # Title
        title_tag = soup.find("title")
        if title_tag:
            snapshot.title = title_tag.get_text(strip=True)

        # Scripts
        for script in soup.find_all("script"):
            src = script.get("src", "").strip()
            if src:
                snapshot.scripts.append(src)
            else:
                content = script.string or script.get_text()
                if content and content.strip():
                    # Cap inline script content to avoid huge snapshots
                    snapshot.inline_scripts.append(content.strip()[:5000])

        # Meta tags
        for meta in soup.find_all("meta"):
            name = meta.get("name", meta.get("property", "")).strip().lower()
            content = meta.get("content", "").strip()
            if name and content:
                snapshot.meta_tags[name] = content
            # Generator meta tag is especially valuable
            if name == "generator":
                snapshot.technologies_hints.append(f"Generator: {content}")

        # Forms
        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": (form.get("method", "get")).upper(),
                "inputs": []
            }
            for inp in form.find_all(["input", "textarea", "select"]):
                form_data["inputs"].append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            snapshot.forms.append(form_data)

        # HTML comments (often leak version info, internal paths)
        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        for match in comment_pattern.finditer(html):
            comment = match.group(1).strip()
            if comment and len(comment) > 3:  # skip trivial comments
                snapshot.comments.append(comment[:500])

        # Links
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                snapshot.links.append(href)

        # Iframes
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "").strip()
            if src:
                snapshot.iframes.append(src)

    def _extract_header_hints(self, snapshot: PageSnapshot):
        """Extract technology hints from response headers."""
        headers = snapshot.headers

        # Direct header → tech mappings
        for header_name, tech_name in self.HEADER_TECH_PATTERNS.items():
            if header_name in headers:
                value = headers[header_name]
                if tech_name:
                    snapshot.technologies_hints.append(f"{tech_name}: {value}")
                else:
                    snapshot.technologies_hints.append(f"{header_name}: {value}")

        # Server header parsing
        server = headers.get("server", "").lower()
        if server:
            for pattern, tech in self.SERVER_PATTERNS:
                m = re.search(pattern, server, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex and m.group(1) else ""
                    hint = f"{tech} {version}".strip()
                    snapshot.technologies_hints.append(hint)

        # Cookie-based hints
        for cookie_name in snapshot.cookies:
            cn = cookie_name.lower()
            if "phpsessid" in cn:
                snapshot.technologies_hints.append("PHP")
            elif "jsessionid" in cn:
                snapshot.technologies_hints.append("Java")
            elif "asp.net" in cn or "aspnet" in cn:
                snapshot.technologies_hints.append("ASP.NET")
            elif "laravel" in cn:
                snapshot.technologies_hints.append("Laravel")
            elif "wordpress" in cn or "wp-" in cn:
                snapshot.technologies_hints.append("WordPress")
            elif "django" in cn or "csrftoken" in cn:
                snapshot.technologies_hints.append("Django")

        # Set-Cookie header analysis
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            if "PHPSESSID" in set_cookie:
                if "PHP" not in snapshot.technologies_hints:
                    snapshot.technologies_hints.append("PHP")
            if "JSESSIONID" in set_cookie:
                if "Java" not in snapshot.technologies_hints:
                    snapshot.technologies_hints.append("Java")

        # Deduplicate
        snapshot.technologies_hints = list(dict.fromkeys(snapshot.technologies_hints))
