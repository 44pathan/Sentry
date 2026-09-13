"""
nuclei_importer.py — Nuclei Template Importer
Parses selected Nuclei YAML templates into the unified rule schema.
Extracts: id, info.severity, info.classification.cve-id,
requests[].matchers[] — and converts into rules the custom matcher can evaluate.
"""

import os
import re
import logging

import yaml

logger = logging.getLogger(__name__)

# Map Nuclei severity to our severity levels
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# Nuclei matcher type → our match_type
MATCHER_TYPE_MAP = {
    "word": "string",
    "regex": "regex",
    "status": "status_code",
    "binary": "string",
    "dsl": "dsl",
}

# Tags we want to import (broadened subset for better coverage)
IMPORT_TAGS = {
    "cve", "tech", "misconfig", "exposure", "config",
    "default-login", "xss", "sqli", "lfi", "rfi",
    "ssrf", "redirect", "disclosure", "token",
    "unauth", "takeover", "panel", "iot",
    "wordpress", "joomla", "drupal", "apache", "nginx",
    "jenkins", "docker", "kubernetes", "cloud",
    "aws", "azure", "gcp", "git", "backup",
    "debug", "api", "graphql", "swagger",
    "phpmyadmin", "adminer", "login", "rce",
    "deserialization", "ssti", "xxe", "cors",
    "crlf", "header-injection", "open-redirect",
}


def import_nuclei_templates(templates_dir: str, max_templates: int = 500) -> list:
    """
    Import curated Nuclei YAML templates into unified rule schema.

    Args:
        templates_dir: Path to nuclei-templates directory
        max_templates: Maximum number of templates to import

    Returns:
        List of unified rule schema dicts
    """
    rules = []

    if not os.path.isdir(templates_dir):
        logger.warning(f"[NucleiImporter] Templates dir not found: {templates_dir}")
        return rules

    # Walk the templates directory
    yaml_files = []
    for root, dirs, files in os.walk(templates_dir):
        for f in files:
            if f.endswith((".yaml", ".yml")):
                yaml_files.append(os.path.join(root, f))

    logger.info(f"[NucleiImporter] Found {len(yaml_files)} YAML templates")

    imported = 0
    for filepath in yaml_files:
        if imported >= max_templates:
            break

        try:
            template_rules = _parse_template(filepath)
            if template_rules:
                rules.extend(template_rules)
                imported += 1
        except Exception as e:
            logger.debug(f"[NucleiImporter] Skipping {filepath}: {e}")

    logger.info(f"[NucleiImporter] Imported {len(rules)} rules from {imported} templates")
    return rules


def _should_import(info: dict) -> bool:
    """Check if a template should be imported based on its tags."""
    tags = info.get("tags", "")
    if isinstance(tags, str):
        tag_set = set(t.strip().lower() for t in tags.split(","))
    elif isinstance(tags, list):
        tag_set = set(t.lower() for t in tags)
    else:
        return False

    return bool(tag_set & IMPORT_TAGS)


def _parse_template(filepath: str) -> list:
    """Parse a single Nuclei YAML template into unified rules."""
    with open(filepath, "r", errors="replace") as f:
        try:
            template = yaml.safe_load(f)
        except yaml.YAMLError:
            return []

    if not template or not isinstance(template, dict):
        return []

    template_id = template.get("id", "")
    info = template.get("info", {})

    if not template_id or not info:
        return []

    # Filter by tags
    if not _should_import(info):
        return []

    severity = SEVERITY_MAP.get(
        info.get("severity", "info").lower(), "info"
    )

    # Extract CVE and CWE
    classification = info.get("classification", {}) or {}
    cve_id = ""
    cwe_id = ""

    cve_ids = classification.get("cve-id", [])
    if isinstance(cve_ids, list) and cve_ids:
        cve_id = cve_ids[0]
    elif isinstance(cve_ids, str):
        cve_id = cve_ids

    cwe_ids = classification.get("cwe-id", [])
    if isinstance(cwe_ids, list) and cwe_ids:
        cwe_id = cwe_ids[0]
    elif isinstance(cwe_ids, str):
        cwe_id = cwe_ids

    # Extract OWASP category from tags
    owasp = _infer_owasp_category(info)

    # Extract description and remediation
    description = info.get("description", f"Nuclei template: {info.get('name', template_id)}")
    remediation = info.get("remediation", "")
    references = info.get("reference", [])
    if isinstance(references, str):
        references = [references]

    # Parse matchers from HTTP requests
    rules = []
    http_reqs = template.get("http", template.get("requests", []))

    if not isinstance(http_reqs, list):
        return []

    for req in http_reqs:
        matchers = req.get("matchers", [])
        matchers_condition = req.get("matchers-condition", "or").lower()

        # Collect all match patterns from all matchers in this request
        combined_patterns = []

        for matcher in matchers:
            matcher_type = matcher.get("type", "word")
            our_match_type = MATCHER_TYPE_MAP.get(matcher_type, "string")
            condition = matcher.get("condition", "or").lower()

            # Handle status code matchers
            if matcher_type == "status":
                status_codes = matcher.get("status", [])
                for sc in status_codes:
                    combined_patterns.append({
                        "match_type": "status_code",
                        "pattern": str(sc),
                        "part": "status",
                    })
                continue

            # Handle DSL matchers — convert simple DSL to regex/string where possible
            if matcher_type == "dsl":
                dsl_exprs = matcher.get("dsl", [])
                if isinstance(dsl_exprs, str):
                    dsl_exprs = [dsl_exprs]
                for expr in dsl_exprs:
                    converted = _convert_dsl_to_pattern(expr)
                    if converted:
                        combined_patterns.append(converted)
                continue

            # Handle word and regex matchers
            words = matcher.get("words", matcher.get("regex", []))
            if isinstance(words, str):
                words = [words]

            part = matcher.get("part", "body").lower()
            target_location = _map_part_to_location(part)

            if condition == "and" and len(words) > 1:
                # AND condition — combine all words into one rule with regex alternation
                escaped = [re.escape(w) for w in words]
                combo_pattern = "(?=.*" + ")(?=.*".join(escaped) + ")"
                combined_patterns.append({
                    "match_type": "regex",
                    "pattern": combo_pattern,
                    "part": part,
                })
            else:
                # OR condition (default) — each word is a separate pattern
                for word in words:
                    combined_patterns.append({
                        "match_type": our_match_type,
                        "pattern": word,
                        "part": part,
                    })

        # Create a rule for each collected pattern
        for pat_info in combined_patterns:
            rule_id = f"nuclei-{template_id}-{len(rules)}"
            target_location = _map_part_to_location(pat_info.get("part", "body"))
            rules.append({
                "id": rule_id,
                "enabled": True,
                "type": "vulnerability" if cve_id else "misconfiguration",
                "target_location": target_location,
                "match_type": pat_info["match_type"],
                "pattern": pat_info["pattern"],
                "severity": severity,
                "title": info.get("name", template_id),
                "description": description,
                "cve": cve_id,
                "cwe": cwe_id,
                "owasp_category": owasp,
                "remediation": remediation,
                "references": references,
                "source": "nuclei",
                "nuclei_template_id": template_id,
            })

    return rules


def _map_part_to_location(part: str) -> str:
    """Map Nuclei 'part' field to our target_location."""
    mapping = {
        "body": "body",
        "header": "header",
        "response": "body",
        "all": "all",
        "status": "status_code",
        "interactsh_protocol": "body",
    }
    return mapping.get(part, "body")


def _convert_dsl_to_pattern(dsl_expr: str) -> dict:
    """
    Convert simple Nuclei DSL expressions into regex/string patterns.
    Handles common patterns like:
      - contains(body, "string")
      - status_code == 200
      - contains(all_headers, "string")
    Returns None for unsupported/complex DSL.
    """
    if not isinstance(dsl_expr, str):
        return None

    # Match: contains(body, "string") or contains(all_headers, "string")
    m = re.match(r'contains\(\s*(body|all_headers|header|response)\s*,\s*["\'](.+?)["\']\s*\)', dsl_expr)
    if m:
        part_name = m.group(1)
        search_str = m.group(2)
        part_map = {"body": "body", "all_headers": "header", "header": "header", "response": "body"}
        return {
            "match_type": "string",
            "pattern": search_str,
            "part": part_map.get(part_name, "body"),
        }

    # Match: status_code == 200
    m = re.match(r'status_code\s*==\s*(\d+)', dsl_expr)
    if m:
        return {
            "match_type": "status_code",
            "pattern": m.group(1),
            "part": "status",
        }

    # Match: contains(body, "a") && contains(body, "b")
    parts = re.findall(r'contains\(\s*(?:body|response)\s*,\s*["\'](.+?)["\']\s*\)', dsl_expr)
    if len(parts) >= 2 and "&&" in dsl_expr:
        escaped = [re.escape(p) for p in parts]
        combo_pattern = "(?=.*" + ")(?=.*".join(escaped) + ")"
        return {
            "match_type": "regex",
            "pattern": combo_pattern,
            "part": "body",
        }

    # Unsupported DSL — skip
    return None


def _infer_owasp_category(info: dict) -> str:
    """Infer OWASP Top 10 category from Nuclei template tags."""
    tags = info.get("tags", "")
    if isinstance(tags, str):
        tags = tags.lower()
    elif isinstance(tags, list):
        tags = ",".join(tags).lower()
    else:
        tags = ""

    if any(x in tags for x in ["sqli", "sql-injection"]):
        return "A03:2021-Injection"
    if any(x in tags for x in ["xss", "cross-site"]):
        return "A03:2021-Injection"
    if any(x in tags for x in ["ssrf"]):
        return "A10:2021-Server-Side Request Forgery"
    if any(x in tags for x in ["misconfig", "config", "default-login"]):
        return "A05:2021-Security Misconfiguration"
    if any(x in tags for x in ["exposure", "disclosure"]):
        return "A01:2021-Broken Access Control"
    if any(x in tags for x in ["cve", "tech"]):
        return "A06:2021-Vulnerable Components"
    if any(x in tags for x in ["unauth", "auth", "login"]):
        return "A07:2021-Identification and Authentication Failures"
    if any(x in tags for x in ["lfi", "rfi", "traversal"]):
        return "A01:2021-Broken Access Control"
    if any(x in tags for x in ["redirect", "open-redirect"]):
        return "A01:2021-Broken Access Control"
    if any(x in tags for x in ["takeover"]):
        return "A05:2021-Security Misconfiguration"

    return ""
