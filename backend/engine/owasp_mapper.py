"""
owasp_mapper.py — OWASP Top 10 Cross-Version Mapping (2021 <-> 2025)
Maps findings tagged with OWASP 2021 categories to their 2025 equivalents.
"""

# OWASP Top 10 2025 official categories
OWASP_2025 = {
    "A01:2025-Broken Access Control": 0,
    "A02:2025-Security Misconfiguration": 0,
    "A03:2025-Software Supply Chain Failures": 0,
    "A04:2025-Cryptographic Failures": 0,
    "A05:2025-Injection": 0,
    "A06:2025-Insecure Design": 0,
    "A07:2025-Authentication Failures": 0,
    "A08:2025-Software or Data Integrity Failures": 0,
    "A09:2025-Security Logging and Alerting Failures": 0,
    "A10:2025-Mishandling of Exceptional Conditions": 0,
}

# Mapping: 2021 category key -> 2025 category key
_MAP_2021_TO_2025 = {
    "A01:2021-Broken Access Control":
        "A01:2025-Broken Access Control",
    "A02:2021-Cryptographic Failures":
        "A04:2025-Cryptographic Failures",
    "A03:2021-Injection":
        "A05:2025-Injection",
    "A04:2021-Insecure Design":
        "A06:2025-Insecure Design",
    "A05:2021-Security Misconfiguration":
        "A02:2025-Security Misconfiguration",
    "A06:2021-Vulnerable Components":
        "A03:2025-Software Supply Chain Failures",
    "A07:2021-Identification and Authentication Failures":
        "A07:2025-Authentication Failures",
    "A08:2021-Software and Data Integrity Failures":
        "A08:2025-Software or Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures":
        "A09:2025-Security Logging and Alerting Failures",
    "A10:2021-Server-Side Request Forgery":
        "A01:2025-Broken Access Control",  # SSRF merged into BAC in 2025
}


_MAP_PREFIX_TO_2025 = {
    "A01": "A01:2025-Broken Access Control",
    "A02": "A04:2025-Cryptographic Failures",
    "A03": "A05:2025-Injection",
    "A04": "A06:2025-Insecure Design",
    "A05": "A02:2025-Security Misconfiguration",
    "A06": "A03:2025-Software Supply Chain Failures",
    "A07": "A07:2025-Authentication Failures",
    "A08": "A08:2025-Software or Data Integrity Failures",
    "A09": "A09:2025-Security Logging and Alerting Failures",
    "A10": "A01:2025-Broken Access Control",
}

def map_2021_to_2025(owasp_2021: str) -> str:
    """Convert an OWASP 2021 category string to its 2025 equivalent."""
    if not owasp_2021:
        return ""
    if owasp_2021 in _MAP_2021_TO_2025:
        return _MAP_2021_TO_2025[owasp_2021]
    # Check by prefix (e.g. "A05" or "A05: Security Misconfiguration")
    prefix = owasp_2021[:3].upper()
    return _MAP_PREFIX_TO_2025.get(prefix, "")


def get_2025_coverage(findings: list) -> dict:
    """
    Build an OWASP 2025 coverage dictionary from findings
    that already carry owasp_category (2021) tags.
    """
    coverage = dict(OWASP_2025)  # fresh copy
    for f in findings:
        cat_2021 = f.get("owasp_category", "") if isinstance(f, dict) else getattr(f, "owasp_category", "")
        cat_2025 = map_2021_to_2025(cat_2021)
        if cat_2025 in coverage:
            coverage[cat_2025] += 1
    return coverage


def enrich_finding_owasp_2025(finding: dict) -> dict:
    """Add owasp_2025 field to a finding dict based on its owasp_category (2021)."""
    cat_2021 = finding.get("owasp_category", "")
    finding["owasp_2025"] = map_2021_to_2025(cat_2021)
    return finding
