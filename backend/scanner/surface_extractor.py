"""
surface_extractor.py — Lightweight Attack Surface Discovery
Extracts injectable parameters from URLs, HTML forms, and internal links
without deep crawling. Reuses data already parsed by the Normalizer.
"""

import re
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urljoin

logger = logging.getLogger(__name__)

# Parameter names that suggest file/path handling (for LFI probes)
FILE_PARAM_NAMES = {
    "file", "path", "page", "doc", "template", "include", "dir",
    "document", "folder", "root", "pg", "style", "pdf", "img",
    "filename", "filepath", "load", "read", "download", "view",
}

# Parameter names that suggest URL/redirect handling (for SSRF probes)
URL_PARAM_NAMES = {
    "url", "redirect", "next", "callback", "dest", "uri", "fetch",
    "target", "return", "return_to", "goto", "link", "src", "source",
    "redirect_uri", "redirect_url", "continue", "ref", "forward",
}


@dataclass
class ParamTarget:
    """A single injectable parameter target."""
    url: str                    # Full URL to probe
    param_name: str             # Parameter name
    param_value: str            # Original parameter value
    source: str = "url"         # "url" | "form_get" | "form_post"
    form_action: str = ""       # Form action URL (for form params)
    form_method: str = "GET"    # HTTP method
    is_file_param: bool = False # Suggests file/path handling
    is_url_param: bool = False  # Suggests URL/redirect handling


@dataclass
class AttackSurface:
    """Discovered attack surface for a target."""
    target_url: str
    params: list = field(default_factory=list)          # list[ParamTarget]
    internal_urls: list = field(default_factory=list)    # Same-origin URLs for deeper probing
    total_params: int = 0
    total_forms: int = 0
    total_links: int = 0


def extract_surface(snapshot, target_url: str, max_internal_links: int = 5) -> AttackSurface:
    """
    Extract attack surface from a PageSnapshot.
    Returns injectable parameters from the URL, HTML forms, and internal links.
    """
    surface = AttackSurface(target_url=target_url)
    params = []

    # ── 1. URL Query Parameters ────────────────────────
    url_params = _extract_url_params(target_url)
    params.extend(url_params)

    # Also check the final URL (after redirects)
    if snapshot.final_url and snapshot.final_url != target_url:
        params.extend(_extract_url_params(snapshot.final_url))

    # ── 2. HTML Form Inputs ────────────────────────────
    form_params = _extract_form_params(snapshot, target_url)
    params.extend(form_params)
    surface.total_forms = len(snapshot.forms) if hasattr(snapshot, 'forms') else 0

    # ── 3. Internal Links (same-origin) ────────────────
    internal_urls = _extract_internal_links(snapshot, target_url, max_internal_links)
    surface.internal_urls = internal_urls
    surface.total_links = len(internal_urls)

    # Extract params from discovered internal URLs too
    for link_url in internal_urls:
        link_params = _extract_url_params(link_url)
        params.extend(link_params)

    # If no parameters discovered from URL or forms, add common synthetic target parameters
    if not params:
        logger.info(f"[Surface] No parameters found in target DOM — adding default attack surface parameters")
        common_test_params = ["q", "id", "search", "page", "file", "redirect"]
        for p_name in common_test_params:
            p_lower = p_name.lower()
            params.append(ParamTarget(
                url=target_url,
                param_name=p_name,
                param_value="1",
                source="synthetic",
                is_file_param=p_lower in FILE_PARAM_NAMES,
                is_url_param=p_lower in URL_PARAM_NAMES,
            ))

    # Deduplicate params by (url, param_name)
    seen = set()
    deduped = []
    for p in params:
        key = (p.url, p.param_name, p.source)
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    surface.params = deduped
    surface.total_params = len(deduped)

    logger.info(
        f"[Surface] Discovered {surface.total_params} params, "
        f"{surface.total_forms} forms, {surface.total_links} internal links"
    )

    return surface


def _extract_url_params(url: str) -> list:
    """Extract query parameters from a URL."""
    params = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    for name, values in query_params.items():
        value = values[0] if values else ""
        name_lower = name.lower()
        params.append(ParamTarget(
            url=url,
            param_name=name,
            param_value=value,
            source="url",
            is_file_param=name_lower in FILE_PARAM_NAMES,
            is_url_param=name_lower in URL_PARAM_NAMES,
        ))

    return params


def _extract_form_params(snapshot, target_url: str) -> list:
    """Extract injectable parameters from HTML forms."""
    params = []
    forms = getattr(snapshot, 'forms', []) or []

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Resolve relative form actions
        if action:
            if action.startswith("/") or not action.startswith("http"):
                action = urljoin(target_url, action)
        else:
            action = target_url

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue

            inp_type = inp.get("type", "text").lower()

            # Skip submit buttons, hidden CSRF tokens, etc.
            if inp_type in ("submit", "button", "image", "reset"):
                continue

            value = inp.get("value", "test")
            name_lower = name.lower()

            params.append(ParamTarget(
                url=action,
                param_name=name,
                param_value=value if value else "test",
                source=f"form_{method.lower()}",
                form_action=action,
                form_method=method,
                is_file_param=name_lower in FILE_PARAM_NAMES,
                is_url_param=name_lower in URL_PARAM_NAMES,
            ))

    return params


def _extract_internal_links(snapshot, target_url: str, max_links: int) -> list:
    """Extract same-origin internal links from the page."""
    links = getattr(snapshot, 'links', []) or []
    parsed_target = urlparse(target_url)
    target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

    internal = []
    seen = {target_url.rstrip("/")}

    for href in links:
        # Resolve relative URLs
        if href.startswith("/"):
            full_url = urljoin(target_url, href)
        elif href.startswith("http"):
            full_url = href
        else:
            full_url = urljoin(target_url, href)

        # Check same-origin
        parsed_link = urlparse(full_url)
        link_origin = f"{parsed_link.scheme}://{parsed_link.netloc}"

        if link_origin != target_origin:
            continue

        normalized = full_url.rstrip("/")
        if normalized in seen:
            continue

        # Skip non-page resources
        path = parsed_link.path.lower()
        skip_extensions = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                          ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf"}
        if any(path.endswith(ext) for ext in skip_extensions):
            continue

        seen.add(normalized)
        internal.append(full_url)

        if len(internal) >= max_links:
            break

    return internal
