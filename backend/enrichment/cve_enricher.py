"""
cve_enricher.py — CVE Enrichment via OSV.dev API
Looks up CVE details and caches results.
Same pattern as the SIEM's AbuseIPDB threat-intel integration.
"""

import logging
import time
import requests

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/vulns"
CVE_CACHE_TTL = 86400


class CVEEnricher:
    def __init__(self):
        self._cache = {}

    def enrich(self, cve_id: str) -> dict:
        if not cve_id or not cve_id.startswith("CVE-"):
            return {}
        cached = self._cache.get(cve_id)
        if cached and (time.time() - cached["ts"]) < CVE_CACHE_TTL:
            return cached["data"]
        # Cache the result immediately (even if empty/failed) to avoid retrying on network issues
        data = self._lookup_osv(cve_id) or {}
        self._cache[cve_id] = {"data": data, "ts": time.time()}
        return data

    def enrich_findings(self, findings: list) -> list:
        from concurrent.futures import ThreadPoolExecutor

        # Collect unique CVEs that are not in the cache yet
        cves_to_fetch = set()
        for f in findings:
            fd = f if isinstance(f, dict) else f.__dict__
            cve = fd.get("cve", "")
            if cve and cve.startswith("CVE-") and cve not in self._cache:
                cves_to_fetch.add(cve)

        # Lookup in parallel
        if cves_to_fetch:
            with ThreadPoolExecutor(max_workers=15) as executor:
                executor.map(self.enrich, cves_to_fetch)

        # Assign enriched details
        for f in findings:
            fd = f if isinstance(f, dict) else f.__dict__
            cve = fd.get("cve", "")
            if cve:
                fd["cve_details"] = self.enrich(cve)
        return findings

    def _lookup_osv(self, cve_id: str) -> dict:
        try:
            resp = requests.get(f"{OSV_API_URL}/{cve_id}", timeout=0.5)
            if resp.status_code == 200:
                d = resp.json()
                return {
                    "cve_id": cve_id,
                    "summary": d.get("summary", ""),
                    "details": d.get("details", "")[:500],
                    "published": d.get("published", ""),
                    "references": [r.get("url", "") for r in d.get("references", [])[:5]],
                }
        except Exception as e:
            logger.debug(f"OSV lookup failed for {cve_id}: {e}")
        return None
