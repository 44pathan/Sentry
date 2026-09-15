"""
storage/__init__.py — Elasticsearch & In-Memory Persistence Layer
Provides unified interface for storing and retrieving scan metadata & findings.
Supports Elasticsearch 8.x indexing with automatic fallback to thread-safe in-memory storage.
"""

import os
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

INDEX_METADATA = "scan-metadata"
INDEX_RESULTS_PREFIX = "scan-results-"


class ScanStorage:
    """
    Unified storage manager for Sentry scans and findings.
    Uses Elasticsearch if provided and healthy; otherwise falls back to persistent disk storage (data/scans_db.json).
    """

    def __init__(self, es_client=None):
        self.es = es_client
        self._lock = threading.Lock()
        self._memory_jobs: Dict[str, dict] = {}
        self._memory_findings: Dict[str, list] = {}
        self._dirty = False  # flag: in-memory state has unsaved changes

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._db_file = os.path.abspath(os.path.join(base_dir, "..", "data", "scans_db.json"))

        self._load_local_db()

        if self.es:
            self._ensure_indices()

        # Background thread: flush to disk every 2 seconds if dirty
        self._flush_thread = threading.Thread(target=self._background_flush, daemon=True)
        self._flush_thread.start()

    def _background_flush(self):
        """Periodically flush dirty in-memory state to disk."""
        while True:
            time.sleep(2.0)
            if self._dirty:
                self._save_local_db()
                self._dirty = False

    def _load_local_db(self):
        """Load persistent jobs and findings from local JSON file."""
        if not os.path.exists(self._db_file):
            return
        try:
            with open(self._db_file, "r") as f:
                data = json.load(f)
            with self._lock:
                self._memory_jobs = data.get("jobs", {})
                self._memory_findings = data.get("findings", {})
                # Clean up any jobs left running across restarts
                stale_statuses = {"queued", "fetching", "analyzing", "active_probing", "correlating"}
                now_str = datetime.now(timezone.utc).isoformat()
                for job in self._memory_jobs.values():
                    if job.get("status") in stale_statuses:
                        job["status"] = "failed"
                        job["error"] = "Scan interrupted by backend server restart"
                        job["completed_at"] = now_str
            logger.info(f"[Storage] Loaded {len(self._memory_jobs)} jobs from disk: {self._db_file}")
            self._save_local_db()
        except Exception as e:
            logger.warning(f"[Storage] Failed to load local DB: {e}")

    def _save_local_db(self):
        """Save in-memory jobs and findings to disk JSON file."""
        try:
            os.makedirs(os.path.dirname(self._db_file), exist_ok=True)
            with self._lock:
                payload = {
                    "jobs": self._memory_jobs,
                    "findings": self._memory_findings
                }
            with open(self._db_file, "w") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            logger.warning(f"[Storage] Failed to save local DB: {e}")

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
            self._dirty = True  # mark dirty; background thread will flush

        if self.es:
            try:
                self.es.index(
                    index=INDEX_METADATA,
                    id=scan_id,
                    body=job_data,
                    request_timeout=1.5
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
            self._dirty = True
        # Force immediate flush for findings (important data)
        self._save_local_db()

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
        """Retrieve all scan jobs — always merges ES + in-memory so historical scans appear."""
        merged = {}

        # Pull all persisted scans from Elasticsearch first
        if self.es:
            try:
                res = self.es.search(
                    index=INDEX_METADATA,
                    body={"query": {"match_all": {}}, "sort": [{"created_at": {"order": "desc"}}]},
                    size=200,
                    request_timeout=3.0
                )
                hits = res.get("hits", {}).get("hits", [])
                for h in hits:
                    src = h["_source"]
                    sid = src.get("scan_id")
                    if sid:
                        merged[sid] = src
            except Exception as e:
                logger.warning(f"[ES] Search failed: {e}")

        # Overlay with in-memory jobs (more up-to-date for active/recent scans)
        with self._lock:
            for sid, job in self._memory_jobs.items():
                merged[sid] = job  # memory wins for freshness

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

        if deleted:
            self._save_local_db()
            if self.es:
                try:
                    self.es.delete(index=INDEX_METADATA, id=scan_id, ignore=[404])
                    self.es.delete_by_query(
                        index=f"{INDEX_RESULTS_PREFIX}*",
                        body={"query": {"term": {"scan_id": scan_id}}},
                        ignore=[404]
                    )
                except Exception as e:
                    logger.warning(f"[ES] Delete failed for {scan_id}: {e}")

        return deleted
