"""
matcher.py — Pattern Matching Engine
Consumes the unified rule schema and matches rules against a PageSnapshot.
Supports regex, string, and version_range match types across
body, headers, scripts, cookies, and meta tags.
"""

import re
import uuid
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

from packaging.version import Version, InvalidVersion

from scanner.normalizer import PageSnapshot

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single vulnerability or fingerprint finding."""
    id: str = ""
    scan_id: str = ""
    target_url: str = ""
    timestamp: str = ""

    # Finding details
    source_tool: str = "custom"             # "custom" | "nuclei" | "zap"
    type: str = "vulnerability"              # "vulnerability" | "fingerprint" | "misconfiguration"
    severity: str = "info"                   # "critical" | "high" | "medium" | "low" | "info"
    title: str = ""
    description: str = ""
    rule_id: str = ""

    # Classification
    cve: str = ""
    cwe: str = ""
    owasp_category: str = ""

    # Evidence
    evidence_location: str = ""              # "body" | "header" | "script" | "cookie" | "meta"
    evidence_pattern: str = ""
    evidence_snippet: str = ""
    detected_version: str = ""
    detected_technology: str = ""

    # CVSS Scoring
    cvss_score: float = 0.0                  # CVSS 3.1 base score (0.0-10.0)
    cvss_severity: str = ""                  # "none" | "low" | "medium" | "high" | "critical"

    # Remediation
    remediation: str = ""
    mitigation_strategy: str = ""            # Detailed mitigation steps
    reference_urls: list = field(default_factory=list)

    # Correlation
    correlated: bool = False
    correlation_sources: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class Matcher:
    """
    Matches unified rules against a PageSnapshot.
    Each rule defines a pattern, target location, match type,
    and metadata about what the match means.
    """

    def __init__(self, rules: list = None):
        self.rules = rules or []
        self._compiled_patterns = {}

    def load_rules(self, rules: list):
        """Load or replace the rule set."""
        self.rules = rules
        self._compiled_patterns = {}
        for rule in rules:
            pattern = rule.get("pattern", "")
            if pattern and rule.get("match_type") in ("regex", "version_range"):
                try:
                    self._compiled_patterns[rule["id"]] = re.compile(
                        pattern, re.IGNORECASE | re.DOTALL
                    )
                except re.error as e:
                    logger.warning(
                        f"Invalid regex in rule {rule['id']}: {e}"
                    )

    def match_snapshot(self, snapshot: PageSnapshot, scan_id: str) -> list:
        """
        Run all rules against a PageSnapshot.
        Returns a list of Finding objects for matched rules.
        """
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            try:
                matches = self._evaluate_rule(rule, snapshot)
                for match_info in matches:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        target_url=snapshot.url,
                        timestamp=now,
                        source_tool="custom",
                        type=rule.get("type", "vulnerability"),
                        severity=rule.get("severity", "info"),
                        title=rule.get("title", rule.get("id", "")),
                        description=rule.get("description", ""),
                        rule_id=rule.get("id", ""),
                        cve=rule.get("cve", ""),
                        cwe=rule.get("cwe", ""),
                        owasp_category=rule.get("owasp_category", ""),
                        evidence_location=match_info.get("location", ""),
                        evidence_pattern=rule.get("pattern", ""),
                        evidence_snippet=match_info.get("snippet", "")[:500],
                        detected_version=match_info.get("version", ""),
                        detected_technology=match_info.get("technology", ""),
                        remediation=rule.get("remediation", ""),
                        reference_urls=rule.get("references", []),
                    )
                    findings.append(finding)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.get('id')}: {e}")

        return findings

    def _evaluate_rule(self, rule: dict, snapshot: PageSnapshot) -> list:
        """
        Evaluate a single rule against the snapshot.
        Returns a list of match info dicts (may be empty).
        """
        target = rule.get("target_location", "body")
        match_type = rule.get("match_type", "string")
        pattern = rule.get("pattern", "")

        if not pattern:
            return []

        # Get the content to search based on target_location
        targets = self._get_target_content(target, snapshot)

        matches = []
        for location_name, content in targets:
            if not content:
                continue

            if match_type == "string":
                result = self._match_string(pattern, content)
            elif match_type == "regex":
                result = self._match_regex(rule, pattern, content)
            elif match_type == "version_range":
                result = self._match_version(rule, pattern, content)
            elif match_type == "status_code":
                result = self._match_status(pattern, snapshot.status_code)
            elif match_type == "absent":
                result = self._match_absent(pattern, content)
            else:
                continue

            if result:
                result["location"] = location_name
                matches.append(result)

        return matches

    def _get_target_content(self, target: str, snapshot: PageSnapshot) -> list:
        """
        Returns list of (location_name, content) tuples to search.
        """
        if target == "body":
            return [("body", snapshot.body_lower)]
        elif target == "header":
            # Flatten headers into searchable string
            header_str = "\n".join(
                f"{k}: {v}" for k, v in snapshot.headers.items()
            )
            return [("header", header_str.lower())]
        elif target == "header_key":
            # Return individual headers for checking presence/absence
            return [
                (f"header:{k}", v.lower())
                for k, v in snapshot.headers.items()
            ]
        elif target == "script":
            results = [("script_src", " ".join(snapshot.scripts).lower())]
            for i, js in enumerate(snapshot.inline_scripts):
                results.append((f"inline_script_{i}", js.lower()))
            return results
        elif target == "cookie":
            cookie_str = "\n".join(
                f"{k}: {v}" for k, v in snapshot.cookies.items()
            )
            return [("cookie", cookie_str.lower())]
        elif target == "meta":
            meta_str = "\n".join(
                f"{k}: {v}" for k, v in snapshot.meta_tags.items()
            )
            return [("meta", meta_str.lower())]
        elif target == "comment":
            return [("comment", " ".join(snapshot.comments).lower())]
        elif target == "server":
            return [("server", snapshot.server.lower())]
        elif target == "all":
            # Search everywhere
            all_content = []
            all_content.append(("body", snapshot.body_lower))
            header_str = "\n".join(
                f"{k}: {v}" for k, v in snapshot.headers.items()
            )
            all_content.append(("header", header_str.lower()))
            all_content.append(("script_src", " ".join(snapshot.scripts).lower()))
            for i, js in enumerate(snapshot.inline_scripts):
                all_content.append((f"inline_script_{i}", js.lower()))
            return all_content
        else:
            return [("body", snapshot.body_lower)]

    def _match_string(self, pattern: str, content: str) -> Optional[dict]:
        """Simple case-insensitive substring match."""
        pattern_lower = pattern.lower()
        idx = content.find(pattern_lower)
        if idx >= 0:
            # Extract snippet around match
            start = max(0, idx - 50)
            end = min(len(content), idx + len(pattern_lower) + 50)
            return {
                "snippet": content[start:end],
                "matched": True
            }
        return None

    def _match_regex(self, rule: dict, pattern: str, content: str) -> Optional[dict]:
        """Regex match with optional capture groups."""
        compiled = self._compiled_patterns.get(rule["id"])
        if not compiled:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                self._compiled_patterns[rule["id"]] = compiled
            except re.error:
                return None

        match = compiled.search(content)
        if match:
            result = {
                "snippet": match.group(0)[:200],
                "matched": True,
            }
            # Extract version from capture group if present
            if match.lastindex and match.lastindex >= 1:
                result["version"] = match.group(1)
                result["technology"] = rule.get("technology", "")
            return result
        return None

    def _match_version(self, rule: dict, pattern: str, content: str) -> Optional[dict]:
        """
        Version-aware matching: extract version via regex,
        then compare against min_safe_version or affected_versions.
        """
        # First, extract the version using the pattern
        compiled = self._compiled_patterns.get(rule["id"])
        if not compiled:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_patterns[rule["id"]] = compiled
            except re.error:
                return None

        match = compiled.search(content)
        if not match:
            return None

        detected_version = ""
        if match.lastindex and match.lastindex >= 1:
            detected_version = match.group(1)
        else:
            detected_version = match.group(0)

        if not detected_version:
            return None

        # Compare against min_safe_version
        min_safe = rule.get("min_safe_version", "")
        if min_safe and detected_version:
            try:
                if Version(detected_version) < Version(min_safe):
                    return {
                        "snippet": match.group(0)[:200],
                        "version": detected_version,
                        "technology": rule.get("technology", ""),
                        "matched": True,
                    }
            except InvalidVersion:
                # If we can't parse the version, still report the detection
                return {
                    "snippet": match.group(0)[:200],
                    "version": detected_version,
                    "technology": rule.get("technology", ""),
                    "matched": True,
                }

        # If no version comparison needed, just finding the tech is enough
        if rule.get("type") == "fingerprint":
            return {
                "snippet": match.group(0)[:200],
                "version": detected_version,
                "technology": rule.get("technology", ""),
                "matched": True,
            }

        return None

    def _match_status(self, pattern: str, status_code: int) -> Optional[dict]:
        """Match against HTTP status code."""
        try:
            expected = int(pattern)
            if status_code == expected:
                return {
                    "snippet": f"Status code: {status_code}",
                    "matched": True,
                }
        except ValueError:
            pass
        return None

    def _match_absent(self, pattern: str, content: str) -> Optional[dict]:
        """Match when a pattern is ABSENT (for missing headers, etc.)."""
        if pattern.lower() not in content.lower():
            return {
                "snippet": f"Missing: {pattern}",
                "matched": True,
            }
        return None
