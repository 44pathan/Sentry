"""
risk_scorer.py — Risk Score Calculator
Adapted from the WatchLogs SIEM endpoint risk formula:
    score = min(100, critical×20 + high×10 + medium×3 + low×1)
Produces a composite 0-100 score per scan with letter grade,
severity breakdown, and top-5 fixes ranked by impact.
"""

import logging

logger = logging.getLogger(__name__)

# Severity weights — same formula as SIEM endpoint risk
SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}

# Grade thresholds
GRADE_THRESHOLDS = [
    (0, 10, "A+", "Excellent"),
    (11, 25, "A", "Very Good"),
    (26, 40, "B", "Good"),
    (41, 55, "C", "Fair"),
    (56, 70, "D", "Poor"),
    (71, 85, "E", "Very Poor"),
    (86, 100, "F", "Critical"),
]


class RiskScorer:
    """
    Calculates a composite risk score (0-100) per scan.
    Formula ported from the SIEM's endpoint risk scoring.
    """

    def calculate(self, findings: list) -> dict:
        """
        Calculate risk score from a list of findings.

        Returns:
        {
            "score": 0-100,
            "grade": "A" to "F",
            "grade_label": "Excellent" to "Critical",
            "breakdown": {"critical": N, "high": N, "medium": N, "low": N, "info": N},
            "top_fixes": [...],        # Top 5 fixes ranked by risk reduction
            "owasp_coverage": {...},    # OWASP category breakdown
            "summary": "..."           # Plain-English summary
        }
        """
        # Count by severity
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info") if isinstance(f, dict) else getattr(f, "severity", "info")
            if sev in breakdown:
                breakdown[sev] += 1

        # Calculate score
        raw_score = sum(
            count * SEVERITY_WEIGHTS.get(sev, 0)
            for sev, count in breakdown.items()
        )
        score = min(100, raw_score)

        # Determine grade
        grade, grade_label = self._get_grade(score)

        # Top fixes (ranked by severity weight — highest impact first)
        top_fixes = self._get_top_fixes(findings)

        # OWASP category coverage
        owasp_coverage = self._get_owasp_coverage(findings)

        # Plain-English summary
        summary = self._generate_summary(score, grade, breakdown, len(findings))

        # Structured vulnerability summary
        vuln_summary = self._generate_vuln_summary(findings, breakdown, owasp_coverage)

        # OWASP 2025 coverage (cross-mapped from 2021 tags)
        from engine.owasp_mapper import get_2025_coverage, enrich_finding_owasp_2025
        owasp_2025_coverage = get_2025_coverage(findings)

        # Risk formula documentation
        risk_formula = {
            "formula": "risk_score = min(100, critical*20 + high*10 + medium*3 + low*1 + info*0)",
            "weights": SEVERITY_WEIGHTS,
            "raw_score": raw_score,
            "capped_score": score,
            "note": "Custom weighted sum capped at 100. Individual findings also carry CVSS 3.1 base scores."
        }

        return {
            "score": score,
            "grade": grade,
            "grade_label": grade_label,
            "breakdown": breakdown,
            "top_fixes": top_fixes,
            "owasp_coverage": owasp_coverage,
            "owasp_2025_coverage": owasp_2025_coverage,
            "summary": summary,
            "vulnerability_summary": vuln_summary,
            "risk_formula": risk_formula,
        }

    def _get_grade(self, score: int) -> tuple:
        """Map score to letter grade."""
        for low, high, grade, label in GRADE_THRESHOLDS:
            if low <= score <= high:
                return grade, label
        return "F", "Critical"

    def _get_top_fixes(self, findings: list, limit: int = 5) -> list:
        """
        Get top fixes ranked by risk score reduction.
        Fixing a critical finding reduces score by 20 pts,
        fixing a high by 10 pts, etc.
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        # Sort findings by severity (most impactful first)
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                f.get("severity", "info") if isinstance(f, dict) else getattr(f, "severity", "info"),
                5
            )
        )

        top_fixes = []
        seen_titles = set()

        for f in sorted_findings:
            if len(top_fixes) >= limit:
                break

            fd = f if isinstance(f, dict) else f.to_dict()
            title = fd.get("title", "")
            if title in seen_titles:
                continue
            seen_titles.add(title)

            severity = fd.get("severity", "info")
            weight = SEVERITY_WEIGHTS.get(severity, 0)

            top_fixes.append({
                "title": title,
                "severity": severity,
                "risk_reduction": weight,
                "remediation": fd.get("remediation", ""),
                "owasp_category": fd.get("owasp_category", ""),
                "cve": fd.get("cve", ""),
            })

        return top_fixes

    def _get_owasp_coverage(self, findings: list) -> dict:
        """
        Group findings by OWASP Top 10 category.
        Shows which categories have findings and how many.
        """
        owasp_categories = {
            "A01:2021-Broken Access Control": 0,
            "A02:2021-Cryptographic Failures": 0,
            "A03:2021-Injection": 0,
            "A04:2021-Insecure Design": 0,
            "A05:2021-Security Misconfiguration": 0,
            "A06:2021-Vulnerable Components": 0,
            "A07:2021-Identification and Authentication Failures": 0,
            "A08:2021-Software and Data Integrity Failures": 0,
            "A09:2021-Security Logging and Monitoring Failures": 0,
            "A10:2021-Server-Side Request Forgery": 0,
        }

        for f in findings:
            cat = f.get("owasp_category", "") if isinstance(f, dict) else getattr(f, "owasp_category", "")
            if not cat:
                continue
            if cat in owasp_categories:
                owasp_categories[cat] += 1
            else:
                # Match by prefix (e.g. "A01", "A05")
                prefix = cat[:3].upper()
                for key in owasp_categories:
                    if key.startswith(prefix):
                        owasp_categories[key] += 1
                        break

        return owasp_categories

    def _generate_summary(self, score, grade, breakdown, total_findings) -> str:
        """Generate a plain-English summary for the report."""
        if total_findings == 0:
            return "No vulnerabilities were detected in this scan. The target appears to have a good security posture."

        parts = []

        if score <= 10:
            parts.append(f"This target has an excellent security posture (Grade {grade}).")
        elif score <= 40:
            parts.append(f"This target has a generally good security posture (Grade {grade}) with some areas for improvement.")
        elif score <= 70:
            parts.append(f"This target has several security concerns that should be addressed (Grade {grade}).")
        else:
            parts.append(f"This target has significant security vulnerabilities requiring immediate attention (Grade {grade}).")

        parts.append(f"A total of {total_findings} findings were identified across the scan.")

        if breakdown["critical"] > 0:
            parts.append(
                f"{breakdown['critical']} critical issue(s) require immediate remediation."
            )
        if breakdown["high"] > 0:
            parts.append(
                f"{breakdown['high']} high-severity issue(s) should be addressed promptly."
            )

        return " ".join(parts)

    def _generate_vuln_summary(self, findings: list, breakdown: dict, owasp_coverage: dict) -> dict:
        """
        Generate a structured vulnerability summary with per-finding one-liners.
        This powers the 'Summary' column in the frontend.
        """
        # Build per-finding summaries (deduplicated by title)
        seen = {}
        for f in findings:
            fd = f if isinstance(f, dict) else f.__dict__
            title = fd.get("title", "Unknown")
            sev = fd.get("severity", "info")
            cvss = fd.get("cvss_score", 0.0)
            owasp = fd.get("owasp_category", "")

            if title not in seen:
                one_liner = f"[{sev.upper()}] {title}"
                if cvss > 0:
                    one_liner += f" — CVSS {cvss}"
                seen[title] = {
                    "title": title,
                    "severity": sev,
                    "count": 1,
                    "cvss_score": cvss,
                    "owasp_category": owasp,
                    "one_liner": one_liner,
                }
            else:
                seen[title]["count"] += 1

        # Aggregate narrative
        total = sum(breakdown.values())
        affected_categories = sum(1 for v in owasp_coverage.values() if v > 0)

        narrative = (
            f"Scan identified {total} total findings across {affected_categories} "
            f"OWASP Top 10 categories. "
        )
        if breakdown["critical"] > 0 or breakdown["high"] > 0:
            narrative += (
                f"Immediate attention required for {breakdown['critical']} critical "
                f"and {breakdown['high']} high-severity issues. "
            )
        if breakdown["medium"] > 0:
            narrative += f"{breakdown['medium']} medium-severity issues need planned remediation. "
        if breakdown["low"] > 0 or breakdown["info"] > 0:
            narrative += f"{breakdown['low']} low and {breakdown['info']} informational findings noted."

        return {
            "narrative": narrative.strip(),
            "unique_findings": list(seen.values()),
            "total_unique": len(seen),
            "total_findings": total,
            "affected_owasp_categories": affected_categories,
        }
