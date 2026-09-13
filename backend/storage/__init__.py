"""
storage/__init__.py — Elasticsearch & In-Memory Persistence Layer
Provides unified interface for storing and retrieving scan metadata & findings.
Supports Elasticsearch 8.x indexing with automatic fallback to thread-safe in-memory storage.
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

INDEX_METADATA = "scan-metadata"
INDEX_RESULTS_PREFIX = "scan-results-"


class ScanStorage:
    """
    Unified storage manager for Mapper scans and findings.
    Uses Elasticsearch if provided and healthy; otherwise falls back to in-memory dict.
    """

    def __init__(self, es_client=None):
        self.es = es_client
        self._lock = threading.Lock()
        self._memory_jobs: Dict[str, dict] = {}
        self._memory_findings: Dict[str, list] = {}

        if self.es:
            self._ensure_indices()

    def _ensure_indices(self):
        """Create Elasticsearch index templates/mappings if ES is available."""
        try:
            if not self.es.indices.exists(index=INDEX_METADATA):
                self.es.indices.create(
                    index=INDEX_METADATA,
                    body={
                        "mappings": {
                            "properties": {
                                "scan_id": {"type": "keyword"},
                                "target_url": {"type": "keyword"},
                                "status": {"type": "keyword"},
                                "scan_mode": {"type": "keyword"},
                                "created_at": {"type": "date"},
                                "completed_at": {"type": "date"},
                                "risk_score": {"type": "integer"},
                                "risk_grade": {"type": "keyword"},
                                "total_findings": {"type": "integer"},
                            }
                        }
                    }
                )
                logger.info(f"[ES] Created index '{INDEX_METADATA}'")
        except Exception as e:
            logger.warning(f"[ES] Could not initialize indices: {e}")

    def store_job(self, job_data: dict):
        """Store or update scan job metadata."""
        scan_id = job_data.get("scan_id")
        if not scan_id:
            return

        with self._lock:
            self._memory_jobs[scan_id] = job_data.copy()

        if self.es:
            try:
                self.es.index(
                    index=INDEX_METADATA,
                    id=scan_id,
                    body=job_data,
                    refresh=True
                )
                logger.debug(f"[ES] Indexed job {scan_id}")
            except Exception as e:
                logger.warning(f"[ES] Failed to index job {scan_id}: {e}")

    def store_findings(self, scan_id: str, findings: list):
        """Store findings for a scan job."""
        if not scan_id:
            return

        # Prepare dict-serializable findings
        serializable_findings = []
        for f in findings:
            if hasattr(f, "to_dict"):
                serializable_findings.append(f.to_dict())
            elif isinstance(f, dict):
                serializable_findings.append(f)
            elif hasattr(f, "__dict__"):
                serializable_findings.append(f.__dict__)

        with self._lock:
            self._memory_findings[scan_id] = serializable_findings

        if self.es and serializable_findings:
            date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            index_name = f"{INDEX_RESULTS_PREFIX}{date_str}"
            try:
                for fdict in serializable_findings:
                    fdict["scan_id"] = scan_id
                    fdict["indexed_at"] = datetime.now(timezone.utc).isoformat()
                    doc_id = fdict.get("id") or f"{scan_id}_{hash(str(fdict))}"
                    self.es.index(
                        index=index_name,
                        id=doc_id,
                        body=fdict
                    )
                logger.info(f"[ES] Indexed {len(serializable_findings)} findings into '{index_name}'")
            except Exception as e:
                logger.warning(f"[ES] Failed to index findings into ES: {e}")

    def get_job(self, scan_id: str) -> Optional[dict]:
        """Retrieve scan job metadata by scan_id."""
        with self._lock:
            if scan_id in self._memory_jobs:
                return self._memory_jobs[scan_id].copy()

        if self.es:
            try:
                res = self.es.get(index=INDEX_METADATA, id=scan_id)
                if res and res.get("found"):
                    return res.get("_source")
            except Exception as e:
                logger.debug(f"[ES] Job {scan_id} not found in ES: {e}")

        return None

    def get_all_jobs(self) -> List[dict]:
        """Retrieve all scan jobs, merging ES and in-memory sources."""
        merged = {}

        # First, load from ES if available
        if self.es:
            try:
                res = self.es.search(
                    index=INDEX_METADATA,
                    body={"query": {"match_all": {}}, "sort": [{"created_at": {"order": "desc"}}]},
                    size=100
                )
                hits = res.get("hits", {}).get("hits", [])
                for h in hits:
                    src = h["_source"]
                    sid = src.get("scan_id")
                    if sid:
                        merged[sid] = src
                        # Hydrate in-memory cache so get_job() can find them
                        with self._lock:
                            if sid not in self._memory_jobs:
                                self._memory_jobs[sid] = src
            except Exception as e:
                logger.warning(f"[ES] Search failed: {e}")

        # Overlay in-memory jobs (may have fresher state than ES)
        with self._lock:
            for sid, job in self._memory_jobs.items():
                merged[sid] = job

        result = list(merged.values())
        result.sort(key=lambda j: j.get("created_at", ""), reverse=True)
        return result

    def get_findings(self, scan_id: str) -> List[dict]:
        """Retrieve findings for a scan_id."""
        with self._lock:
            if scan_id in self._memory_findings:
                return self._memory_findings[scan_id].copy()

        if self.es:
            try:
                res = self.es.search(
                    index=f"{INDEX_RESULTS_PREFIX}*",
                    body={"query": {"term": {"scan_id": scan_id}}},
                    size=500
                )
                hits = res.get("hits", {}).get("hits", [])
                if hits:
                    findings = [h["_source"] for h in hits]
                    # Cache ES results in memory so future lookups are instant
                    with self._lock:
                        self._memory_findings[scan_id] = findings
                    logger.info(f"[ES] Loaded {len(findings)} findings for {scan_id[:8]} from ES into memory")
                    return findings.copy()
            except Exception as e:
                logger.warning(f"[ES] Findings search failed for {scan_id}: {e}")

        return []

    def delete_job(self, scan_id: str) -> bool:
        """Delete a scan job and its findings."""
        deleted = False
        with self._lock:
            if scan_id in self._memory_jobs:
                del self._memory_jobs[scan_id]
                deleted = True
            if scan_id in self._memory_findings:
                del self._memory_findings[scan_id]

        if self.es:
            try:
                self.es.delete(index=INDEX_METADATA, id=scan_id, ignore=[404])
                self.es.delete_by_query(
                    index=f"{INDEX_RESULTS_PREFIX}*",
                    body={"query": {"term": {"scan_id": scan_id}}},
                    ignore=[404]
                )
                deleted = True
            except Exception as e:
                logger.warning(f"[ES] Delete failed for {scan_id}: {e}")

        return deleted
