"""
wappalyzer_importer.py — Wappalyzer Data Importer
Parses Wappalyzer's technologies.json fingerprint data into
the unified rule schema for the custom scan engine's matcher.
Converts Wappalyzer's \\;version:\\1 syntax into Python regex groups.
"""

import json
import re
import os
import logging

logger = logging.getLogger(__name__)


def _convert_wappalyzer_pattern(pattern_str: str) -> tuple:
    """
    Convert a Wappalyzer pattern to a Python regex.
    Wappalyzer uses: pattern\\;version:\\1\\;confidence:50
    Returns: (regex_pattern, has_version_capture)
    """
    parts = pattern_str.split("\\;")
    regex_part = parts[0]
    has_version = False

    # Check if there's a version capture group reference
    for part in parts[1:]:
        if part.startswith("version:"):
            has_version = True

    # Escape special regex chars that Wappalyzer doesn't intend as regex
    # but keep actual regex patterns
    try:
        re.compile(regex_part)
    except re.error:
        # If the pattern doesn't compile, escape it
        regex_part = re.escape(regex_part)

    return regex_part, has_version


def import_wappalyzer_data(data_path: str, safe_versions: dict = None) -> list:
    """
    Import Wappalyzer technologies.json data into the unified rule schema.

    Args:
        data_path: Path to directory containing technologies/*.json or a single technologies.json
        safe_versions: Dict of {tech_name: {min_safe: "x.y.z"}} for version comparison

    Returns:
        List of unified rule schema dicts
    """
    safe_versions = safe_versions or {}
    rules = []

    tech_data = _load_tech_data(data_path)
    if not tech_data:
        logger.warning("[WappalyzerImporter] No technology data loaded")
        return rules

    for tech_name, tech_info in tech_data.items():
        try:
            tech_rules = _convert_technology(tech_name, tech_info, safe_versions)
            rules.extend(tech_rules)
        except Exception as e:
            logger.warning(f"[WappalyzerImporter] Error converting {tech_name}: {e}")

    logger.info(f"[WappalyzerImporter] Imported {len(rules)} rules from {len(tech_data)} technologies")
    return rules


def _load_tech_data(data_path: str) -> dict:
    """Load technology data from Wappalyzer format."""
    all_techs = {}

    if os.path.isfile(data_path):
        # Single file
        try:
            with open(data_path, "r") as f:
                data = json.load(f)
            if "technologies" in data:
                all_techs = data["technologies"]
            else:
                all_techs = data
        except Exception as e:
            logger.error(f"[WappalyzerImporter] Failed to load {data_path}: {e}")
    elif os.path.isdir(data_path):
        # Directory with alphabetical JSON files (a.json, b.json, ...)
        for filename in sorted(os.listdir(data_path)):
            if filename.endswith(".json"):
                filepath = os.path.join(data_path, filename)
                try:
                    with open(filepath, "r") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        all_techs.update(data)
                except Exception as e:
                    logger.warning(f"[WappalyzerImporter] Failed to load {filepath}: {e}")

    return all_techs


def _convert_technology(tech_name: str, tech_info: dict, safe_versions: dict) -> list:
    """Convert a single Wappalyzer technology entry into unified rules."""
    rules = []
    base_id = re.sub(r'[^a-z0-9]', '-', tech_name.lower()).strip('-')

    # Determine if this tech has known vulnerabilities
    safe_info = safe_versions.get(tech_name.lower(), {})
    has_vuln_data = bool(safe_info.get("min_safe"))

    # ── HTML body patterns ────────────────────────────────
    html_patterns = tech_info.get("html", [])
    if isinstance(html_patterns, str):
        html_patterns = [html_patterns]

    for i, pattern in enumerate(html_patterns):
        regex, has_version = _convert_wappalyzer_pattern(pattern)
        rule = {
            "id": f"wap-{base_id}-html-{i}",
            "enabled": True,
            "type": "fingerprint" if not has_vuln_data else "vulnerability",
            "target_location": "body",
            "match_type": "version_range" if (has_version and has_vuln_data) else "regex",
            "pattern": regex,
            "technology": tech_name,
            "severity": "medium" if has_vuln_data else "info",
            "title": f"{tech_name} Detected" + (" (Outdated)" if has_vuln_data else ""),
            "description": f"Technology '{tech_name}' was detected via HTML pattern matching.",
            "owasp_category": "A06:2021-Vulnerable Components" if has_vuln_data else "",
            "remediation": f"Keep {tech_name} updated to the latest stable version.",
            "source": "wappalyzer",
        }
        if has_vuln_data:
            rule["min_safe_version"] = safe_info.get("min_safe", "")
        rules.append(rule)

    # ── Header patterns ───────────────────────────────────
    headers = tech_info.get("headers", {})
    for header_name, pattern in headers.items():
        regex, has_version = _convert_wappalyzer_pattern(str(pattern))
        rules.append({
            "id": f"wap-{base_id}-header-{header_name.lower()}",
            "enabled": True,
            "type": "fingerprint",
            "target_location": "header",
            "match_type": "regex",
            "pattern": f"{header_name.lower()}:.*{regex}",
            "technology": tech_name,
            "severity": "info",
            "title": f"{tech_name} Detected (Header: {header_name})",
            "description": f"Technology '{tech_name}' detected via {header_name} header.",
            "remediation": f"Consider hiding the {header_name} header to reduce information disclosure.",
            "source": "wappalyzer",
        })

    # ── Script src patterns ───────────────────────────────
    scripts = tech_info.get("scripts", tech_info.get("script", []))
    if isinstance(scripts, str):
        scripts = [scripts]

    for i, pattern in enumerate(scripts):
        regex, has_version = _convert_wappalyzer_pattern(pattern)
        rule = {
            "id": f"wap-{base_id}-script-{i}",
            "enabled": True,
            "type": "fingerprint" if not has_vuln_data else "vulnerability",
            "target_location": "script",
            "match_type": "version_range" if (has_version and has_vuln_data) else "regex",
            "pattern": regex,
            "technology": tech_name,
            "severity": "medium" if has_vuln_data else "info",
            "title": f"{tech_name} Detected (Script)",
            "description": f"Technology '{tech_name}' detected via script source pattern.",
            "owasp_category": "A06:2021-Vulnerable Components" if has_vuln_data else "",
            "remediation": f"Keep {tech_name} updated to the latest stable version.",
            "source": "wappalyzer",
        }
        if has_vuln_data:
            rule["min_safe_version"] = safe_info.get("min_safe", "")
        rules.append(rule)

    # ── Meta tag patterns ─────────────────────────────────
    meta = tech_info.get("meta", {})
    for meta_name, pattern in meta.items():
        regex, _ = _convert_wappalyzer_pattern(str(pattern))
        rules.append({
            "id": f"wap-{base_id}-meta-{meta_name.lower()}",
            "enabled": True,
            "type": "fingerprint",
            "target_location": "meta",
            "match_type": "regex",
            "pattern": f"{meta_name.lower()}:.*{regex}",
            "technology": tech_name,
            "severity": "info",
            "title": f"{tech_name} Detected (Meta: {meta_name})",
            "description": f"Technology '{tech_name}' detected via <meta name='{meta_name}'> tag.",
            "source": "wappalyzer",
        })

    # ── Cookie patterns ───────────────────────────────────
    cookies = tech_info.get("cookies", {})
    for cookie_name, pattern in cookies.items():
        rules.append({
            "id": f"wap-{base_id}-cookie-{cookie_name.lower()}",
            "enabled": True,
            "type": "fingerprint",
            "target_location": "cookie",
            "match_type": "string",
            "pattern": cookie_name.lower(),
            "technology": tech_name,
            "severity": "info",
            "title": f"{tech_name} Detected (Cookie: {cookie_name})",
            "description": f"Technology '{tech_name}' detected via cookie '{cookie_name}'.",
            "source": "wappalyzer",
        })

    return rules
