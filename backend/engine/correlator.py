"""
correlator.py — Finding Correlator
Adapted from the WatchLogs SIEM correlator.py.
Instead of correlating log events across time windows,
this deduplicates and merges findings from multiple scan sources
(custom engine, Nuclei, ZAP) that flag the same underlying issue.
"""

import logging
from typing import List
from scanner.matcher import Finding

logger = logging.getLogger(__name__)


class FindingCorrelator:
    """
    Deduplicates and merges findings from multiple scan sources.
    When Nuclei and ZAP both flag the same XSS on the same URL,
    merge into one finding with sources: ["nuclei", "zap"].

    Adapted from the SIEM's Correlator.evaluate_all_rules() pattern
    but operates on in-memory findings instead of ES queries.
    """

    def correlate(self, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate and merge findings.
        Two findings are considered duplicates if they share:
        - Same target_url (or same path)
        - Same CVE (if both have one)
        - OR same title + same evidence_location
        """
        if not findings:
            return []

        # Group findings by dedup key
        groups = {}
        for finding in findings:
            key = self._dedup_key(finding)
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)

        # Merge groups
        merged = []
        for key, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                merged_finding = self._merge_findings(group)
                merged.append(merged_finding)

        deduped_count = len(findings) - len(merged)
        if deduped_count > 0:
            logger.info(
                f"[Correlator] Deduplicated {deduped_count} findings "
                f"({len(findings)} → {len(merged)})"
            )

        return merged

    def _dedup_key(self, finding) -> str:
        """Generate a deduplication key for a finding."""
        f = finding if isinstance(finding, dict) else finding.__dict__

        # Primary: CVE-based dedup (strongest signal)
        cve = f.get("cve", "")
        url = f.get("target_url", "")

        if cve:
            return f"cve:{cve}@{url}"

        # Secondary: title + location based dedup
        title = f.get("title", "").lower().strip()
        location = f.get("evidence_location", "")
        return f"title:{title}@{location}@{url}"

    def _merge_findings(self, group: List[Finding]) -> Finding:
        """
        Merge multiple findings into one, keeping:
        - Highest severity
        - All source tools
        - Most detailed description
        - All evidence snippets
        """
        # Sort by severity (critical > high > medium > low > info)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        group.sort(
            key=lambda f: severity_order.get(
                f.severity if hasattr(f, 'severity') else f.get('severity', 'info'),
                5
            )
        )

        primary = group[0]  # Highest severity finding

        # Collect all source tools
        sources = set()
        for f in group:
            src = f.source_tool if hasattr(f, 'source_tool') else f.get('source_tool', 'custom')
            sources.add(src)

        # Update primary with merged info
        if hasattr(primary, 'correlated'):
            primary.correlated = True
            primary.correlation_sources = list(sources)
        elif isinstance(primary, dict):
            primary['correlated'] = True
            primary['correlation_sources'] = list(sources)

        # Take longest description
        longest_desc = max(
            group,
            key=lambda f: len(
                f.description if hasattr(f, 'description') else f.get('description', '')
            )
        )
        if hasattr(primary, 'description'):
            primary.description = (
                longest_desc.description if hasattr(longest_desc, 'description')
                else longest_desc.get('description', '')
            )

        return primary
