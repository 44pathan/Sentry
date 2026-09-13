"""
rule_engine.py — Scan Rule Engine
Adapted from the WatchLogs SIEM rule_engine.py.
Instead of evaluating rules against Elasticsearch log events,
this evaluates scan findings for threshold/match patterns.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class RuleAlert:
    """Alert fired by the scan rule engine."""
    id: str
    rule_id: str
    rule_name: str
    description: str
    severity: str
    owasp_category: str
    cwe: str
    pattern: str
    matched_count: int
    timestamp: str
    type: str = "rule"
    matched_findings: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class ScanRuleEngine:
    """
    Evaluates threshold and match rules against scan findings.
    Adapted from the SIEM's RuleEngine pattern:
    - threshold: fires if N+ findings match a pattern
    - match: fires if any finding matches a pattern
    """

    def __init__(self, rules_path: str = None):
        self.rules_path = rules_path
        self.rules = []
        if rules_path:
            self._load_rules()

    def _load_rules(self):
        """Load rules from JSON file."""
        try:
            with open(self.rules_path, "r") as f:
                all_rules = json.load(f)
            self.rules = [r for r in all_rules if r.get("enabled", True)]
            logger.info(
                f"[ScanRuleEngine] Loaded {len(self.rules)} enabled rules"
            )
        except Exception as e:
            logger.error(f"[ScanRuleEngine] Failed to load rules: {e}")
            self.rules = []

    def reload_rules(self):
        """Hot-reload rules from disk."""
        self._load_rules()

    def get_rules(self) -> list:
        """Returns the raw rule definitions."""
        return self.rules

    def evaluate(self, findings: list) -> list:
        """
        Evaluate all rules against a list of findings.
        Returns a list of RuleAlert objects.
        """
        fired = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            try:
                if rule.get("rule_type") == "threshold":
                    alerts = self._evaluate_threshold(rule, findings)
                elif rule.get("rule_type") == "match":
                    alerts = self._evaluate_match(rule, findings)
                else:
                    continue
                fired.extend(alerts)
            except Exception as e:
                logger.error(
                    f"[ScanRuleEngine] Error evaluating rule '{rule.get('id')}': {e}"
                )

        logger.info(f"[ScanRuleEngine] {len(fired)} rule alert(s) fired")
        return fired

    def _evaluate_threshold(self, rule: dict, findings: list) -> list:
        """Fires if N+ findings match the rule's criteria."""
        threshold = rule.get("threshold", 1)
        category = rule.get("match_category", "")
        severity_filter = rule.get("match_severity", "")

        matched = []
        for f in findings:
            finding = f if isinstance(f, dict) else f.to_dict()
            if category and finding.get("owasp_category", "") != category:
                continue
            if severity_filter and finding.get("severity", "") != severity_filter:
                continue
            matched.append(finding)

        if len(matched) >= threshold:
            return [RuleAlert(
                id=str(uuid.uuid4()),
                rule_id=rule["id"],
                rule_name=rule["name"],
                description=rule.get("description", ""),
                severity=rule.get("severity", "high"),
                owasp_category=rule.get("owasp_category", ""),
                cwe=rule.get("cwe", ""),
                pattern=f"category={category}, severity={severity_filter}",
                matched_count=len(matched),
                timestamp=datetime.now(timezone.utc).isoformat(),
                matched_findings=[m.get("id", "") for m in matched[:10]],
            )]

        return []

    def _evaluate_match(self, rule: dict, findings: list) -> list:
        """Fires once if any finding matches the rule's criteria."""
        pattern = rule.get("match_pattern", "").lower()
        field = rule.get("match_field", "title")

        for f in findings:
            finding = f if isinstance(f, dict) else f.to_dict()
            value = finding.get(field, "").lower()
            if pattern and pattern in value:
                return [RuleAlert(
                    id=str(uuid.uuid4()),
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    description=rule.get("description", ""),
                    severity=rule.get("severity", "high"),
                    owasp_category=rule.get("owasp_category", ""),
                    cwe=rule.get("cwe", ""),
                    pattern=pattern,
                    matched_count=1,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    matched_findings=[finding.get("id", "")],
                )]

        return []
