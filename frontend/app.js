/**
 * app.js — Sentry Vulnerability Scanner Frontend
 * API client, auth flow, scan management, and dynamic rendering.
 * Includes: CVSS scores, mitigation strategies, vulnerability summary,
 *           risk formula display, and JSON/HTML export.
 */

const API_BASE = (() => {
  const loc = window.location;
  if (loc.protocol === "file:") {
    return "http://127.0.0.1:5001/api";
  }
  // Route to port 5001 if backend is running separately
  if (loc.port && loc.port !== "5001") {
    return `${loc.protocol}//${loc.hostname}:5001/api`;
  }
  return `${loc.origin}/api`;
})();

const App = {
  token: null,
  username: null,
  currentPage: "dashboard",
  pollTimers: {},

  formatDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return '—';
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yyyy = d.getFullYear();
    const hh = String(d.getHours()).padStart(2, '0');
    const min = String(d.getMinutes()).padStart(2, '0');
    return `${dd}/${mm}/${yyyy} ${hh}:${min}`;
  },

  // ── Init ──────────────────────────────────────────
  init() {
    this.token = localStorage.getItem("sentry_token");
    this.username = localStorage.getItem("sentry_user");

    if (this.token) {
      this.verifyToken();
    } else {
      this.showLogin();
    }

    this.bindEvents();
  },

  bindEvents() {
    document.getElementById("login-form").addEventListener("submit", e => {
      e.preventDefault();
      this.login();
    });

    document.getElementById("scan-form").addEventListener("submit", e => {
      e.preventDefault();
      this.submitScan();
    });

    document.getElementById("btn-logout").addEventListener("click", () => this.logout());
    document.getElementById("btn-reload-rules").addEventListener("click", () => this.reloadRules());

    // Findings Filter Tabs
    const tabsContainer = document.getElementById("findings-tabs");
    if (tabsContainer) {
      tabsContainer.addEventListener("click", e => {
        const btn = e.target.closest(".filter-tab");
        if (!btn) return;
        document.querySelectorAll("#findings-tabs .filter-tab").forEach(t => t.classList.remove("active"));
        btn.classList.add("active");
        this.applyFindingsFilter();
      });
    }

    // Findings Search Bar
    const searchInput = document.getElementById("findings-search");
    if (searchInput) {
      searchInput.addEventListener("input", () => this.applyFindingsFilter());
    }

    // Scan mode warning toggle
    const scanModeSelect = document.getElementById("scan-mode");
    if (scanModeSelect) {
      scanModeSelect.addEventListener("change", () => {
        const warn = document.getElementById("active-warning");
        if (warn) warn.style.display = scanModeSelect.value !== "passive" ? "block" : "none";
      });
    }

    document.querySelectorAll(".nav-item[data-page]").forEach(btn => {
      btn.addEventListener("click", () => this.navigate(btn.dataset.page));
    });
  },

  // ── Auth ──────────────────────────────────────────
  async login() {
    const user = document.getElementById("login-user").value.trim();
    const pass = document.getElementById("login-pass").value;
    const btn = document.getElementById("login-btn");
    const alert = document.getElementById("login-alert");

    btn.innerHTML = '<span class="spinner"></span> Signing in...';
    btn.disabled = true;
    alert.style.display = "none";

    try {
      const res = await this.api("POST", "/auth/login", { username: user, password: pass }, false);
      this.token = res.token;
      this.username = res.username;
      localStorage.setItem("sentry_token", res.token);
      localStorage.setItem("sentry_user", res.username);
      this.showApp();
    } catch (err) {
      alert.textContent = err.message || "Login failed";
      alert.style.display = "block";
    } finally {
      btn.innerHTML = "Sign In";
      btn.disabled = false;
    }
  },

  async verifyToken() {
    try {
      const res = await this.api("GET", "/auth/verify");
      this.username = res.username;
      this.showApp();
    } catch {
      this.token = null;
      localStorage.removeItem("sentry_token");
      this.showLogin();
    }
  },

  async logout() {
    try { await this.api("POST", "/auth/logout"); } catch {}
    this.token = null;
    this.username = null;
    localStorage.removeItem("sentry_token");
    localStorage.removeItem("sentry_user");
    Object.values(this.pollTimers).forEach(clearInterval);
    this.pollTimers = {};
    this.showLogin();
  },

  showLogin() {
    document.getElementById("login-page").classList.remove("hidden");
    document.getElementById("app-page").classList.add("hidden");
  },

  showApp() {
    document.getElementById("login-page").classList.add("hidden");
    document.getElementById("app-page").classList.remove("hidden");
    document.getElementById("user-display").textContent = this.username;
    document.getElementById("user-avatar").textContent = (this.username || "U")[0].toUpperCase();
    // Load AI provider info and update UI label
    this.api("GET", "/ai/status", null, false).then(s => {
      const providerLabel = s.provider === 'groq' ? '⚡ Groq' : s.provider === 'gemini' ? '✦ Gemini' : '🤖 OpenAI';
      const modelShort = (s.model || '').split('/').pop();
      const el = document.getElementById('ai-provider-badge');
      if (el) el.textContent = `${providerLabel} · ${modelShort}`;
    }).catch(() => {});
    this.navigate("dashboard");
  },

  // ── Navigation ────────────────────────────────────
  navigate(page) {
    this.currentPage = page;
    document.querySelectorAll(".page-section").forEach(s => s.classList.add("hidden"));
    document.querySelectorAll(".nav-item[data-page]").forEach(b => b.classList.remove("active"));

    const section = document.getElementById("page-" + page);
    if (section) section.classList.remove("hidden");

    const navBtn = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (navBtn) navBtn.classList.add("active");

    // Show instant skeleton so the page never looks blank while data loads
    if (page === "dashboard") {
      const t = document.getElementById("recent-scans-table");
      if (t && !t.children.length) t.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px">Loading…</td></tr>';
    }
    if (page === "scans") {
      const t = document.getElementById("all-scans-table");
      if (t && !t.children.length) t.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px">Loading…</td></tr>';
    }

    if (page === "dashboard") this.loadDashboard();
    if (page === "scans") this.loadAllScans();
    if (page === "rules") this.loadRules();
    if (page === "ai-analysis") this.populateAiScanSelector();
  },

  // ── API Client ────────────────────────────────────
  async api(method, path, body = null, auth = true) {
    const headers = { "Content-Type": "application/json" };
    if (auth && this.token) headers["Authorization"] = "Bearer " + this.token;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(API_BASE + path, opts);
    const data = await res.json();

    if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
    return data;
  },

  // ── Dashboard ─────────────────────────────────────
  async loadDashboard() {
    try {
      const stats = await this.api("GET", "/stats");
      document.getElementById("stat-total").textContent = stats.total_scans;
      document.getElementById("stat-completed").textContent = stats.completed_scans;
      document.getElementById("stat-running").textContent = stats.running_scans;
      document.getElementById("stat-risk").textContent = stats.average_risk_score + "/100";
    } catch {
      document.getElementById("stat-total").textContent = "—";
    }

    try {
      const data = await this.api("GET", "/scans");
      this.renderScansTable("recent-scans-table", (data.scans || []).slice(0, 5), true);
    } catch {}
  },

  // ── All Scans ─────────────────────────────────────
  async loadAllScans() {
    try {
      const data = await this.api("GET", "/scans");
      this.renderScansTable("all-scans-table", data.scans || [], false);
    } catch (err) {
      this.showError("all-scans-table", err);
    }
  },

  showError(containerId, err) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML =
      `<div class="empty-state"><div class="icon">!</div><h3>Error</h3><p>${this.esc(err.message)}</p></div>`;
  },

  _hasActiveScans: false,
  startLiveUpdates() {
    if (this._liveTimer) return;
    this._liveTimer = setInterval(async () => {
      // Only hit the server if we're on a data page AND there are active scans (or dashboard first load)
      if (this.currentPage === "dashboard" && this._hasActiveScans) {
        await this.loadDashboard(true);
      } else if (this.currentPage === "scans" && this._hasActiveScans) {
        await this.loadAllScans(true);
      }
    }, 5000);  // 5s instead of 2s — reduces API calls 60%, eliminates polling jank
  },

  stopLiveUpdates() {
    if (this._liveTimer) {
      clearInterval(this._liveTimer);
      this._liveTimer = null;
    }
  },

  renderScansTable(containerId, scans, isRecent = false) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const hasRunning = scans.some(s => s.status !== 'completed' && s.status !== 'failed');
    this._hasActiveScans = hasRunning;
    if (hasRunning) {
      this.startLiveUpdates();
    } else {
      this.stopLiveUpdates();
    }

    if (!scans.length) {
      container.innerHTML = `<div class="empty-state"><div class="icon">i</div><h3>No scans yet</h3><p>Submit your first scan to get started.</p></div>`;
      return;
    }

    let html = `<div class="table-wrapper"><table><thead><tr>
      <th>Target</th><th>Status</th><th>Risk</th><th>Findings</th><th>Date</th><th></th>
    </tr></thead><tbody>`;

    for (const s of scans) {
      const status = this.statusBadge(s);
      const risk = s.status === "completed" ? `<span style="font-weight:600">${s.risk_score}/100</span>` : "—";
      const date = s.created_at ? this.formatDate(s.created_at) : "—";
      const shortUrl = this.esc((s.target_url || "—").substring(0, 40));

      html += `<tr>
        <td title="${this.esc(s.target_url || '')}">${shortUrl}${(s.target_url || '').length > 40 ? '…' : ''}</td>
        <td>${status}</td>
        <td>${risk}</td>
        <td>${s.findings_count || 0}</td>
        <td style="color:var(--text-muted);font-size:13px">${date}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="App.viewReport('${this.esc(s.scan_id)}')">View</button>
          <button class="btn btn-secondary btn-sm" style="color:var(--critical);border-color:rgba(239,68,68,0.3);margin-left:4px;" onclick="App.deleteScan('${this.esc(s.scan_id)}')">Delete</button>
        </td>
      </tr>`;
    }

    html += "</tbody></table></div>";
    container.innerHTML = html;
  },

  async deleteScan(scanId) {
    if (!confirm("Are you sure you want to delete this scan?")) return;
    try {
      await this.api("DELETE", `/scan/${scanId}`);
      if (this.currentPage === "dashboard") this.loadDashboard();
      else if (this.currentPage === "scans") this.loadAllScans();
    } catch (err) {
      alert("Failed to delete scan: " + err.message);
    }
  },

  statusBadge(scan) {
    const status = typeof scan === 'object' ? scan.status : scan;
    const progress = typeof scan === 'object' ? (scan.progress || 0) : 0;

    if (status === 'completed') return '<span class="badge badge-success">COMPLETED</span>';
    if (status === 'failed') return '<span class="badge badge-critical">FAILED</span>';

    const labelMap = {
      queued: "QUEUED",
      fetching: "FETCHING",
      analyzing: "ANALYZING",
      active_probing: "PROBING",
      correlating: "CORRELATING",
    };
    const label = labelMap[status] || status.toUpperCase();

    return `<span class="badge badge-active" style="display:inline-flex;align-items:center;gap:4px;"><span class="spinner" style="width:10px;height:10px;border-width:2px;"></span> ${label} (${progress}%)</span>`;
  },

  // ── Submit Scan ───────────────────────────────────
  async submitScan() {
    const url = document.getElementById("scan-url").value.trim();
    const btn = document.getElementById("scan-submit-btn");
    const alertEl = document.getElementById("scan-alert");

    btn.innerHTML = '<span class="spinner"></span> Submitting...';
    btn.disabled = true;
    alertEl.style.display = "none";

    try {
      const res = await this.api("POST", "/scan", {
        url,
        authorized: document.getElementById("opt-authorized").checked,
        deep_scan: document.getElementById("opt-deep").checked,
        check_headers: document.getElementById("opt-headers").checked,
        check_tls: document.getElementById("opt-tls").checked,
        scan_mode: (document.getElementById("scan-mode") || {}).value || "passive",
        rate_limit: parseInt((document.getElementById("opt-rate-limit") || {}).value || "10", 10),
        auth_cookies: ((document.getElementById("opt-auth-cookies") || {}).value || "").trim(),
        auth_headers: ((document.getElementById("opt-auth-headers") || {}).value || "").trim(),
      });

      document.getElementById("scan-progress").classList.remove("hidden");
      document.getElementById("scan-id-display").textContent = "Scan ID: " + res.scan_id;
      this.pollScanStatus(res.scan_id);
    } catch (err) {
      alertEl.className = "alert alert-error";
      alertEl.textContent = err.message;
      alertEl.style.display = "block";
    } finally {
      btn.innerHTML = "Start Scan";
      btn.disabled = false;
    }
  },

  pollScanStatus(scanId) {
    if (this.pollTimers[scanId]) clearInterval(this.pollTimers[scanId]);

    let iterations = 0;
    const poll = async () => {
      if (++iterations > 150) {
        clearInterval(this.pollTimers[scanId]);
        delete this.pollTimers[scanId];
        const alertEl = document.getElementById("scan-alert");
        if (alertEl) {
          alertEl.textContent = "Scan timed out after 5 minutes.";
          alertEl.className = "alert alert-error";
          alertEl.style.display = "block";
        }
        return;
      }
      try {
        const data = await this.api("GET", `/scan/${scanId}`);
        const scan = data.scan;
        const pct = scan.progress || 0;

        document.getElementById("scan-status-text").textContent = scan.status;
        document.getElementById("scan-progress-pct").textContent = pct + "%";
        document.getElementById("scan-progress-fill").style.width = pct + "%";

        if (scan.status === "completed" || scan.status === "failed") {
          clearInterval(this.pollTimers[scanId]);
          delete this.pollTimers[scanId];

          setTimeout(() => this.viewReport(scanId), 500);
        }
      } catch {}
    };

    poll();
    this.pollTimers[scanId] = setInterval(poll, 2000);
  },

  // ── Report View ───────────────────────────────────
  _currentFindings: [],
  _currentScanId: null,

  async viewReport(scanId) {
    this._currentScanId = scanId;
    this.currentPage = "report";
    document.querySelectorAll(".page-section").forEach(s => s.classList.add("hidden"));
    document.querySelectorAll(".nav-item[data-page]").forEach(b => b.classList.remove("active"));
    document.getElementById("page-report").classList.remove("hidden");

    try {
      const data = await this.api("GET", `/scan/${scanId}/report`);

      if (data.status === "error" || data.scan_status === "failed") {
        document.getElementById("report-title").textContent = "Scan Failed";
        document.getElementById("report-subtitle").textContent = data.message || data.error || "The scan failed to complete.";
        
        // Reset and show clean blank/error status in the components
        document.getElementById("report-summary").textContent = "Error: " + (data.error || data.message || "Target was unreachable or scan failed.");
        this.renderGauge(0, "F");
        this.renderBreakdown({});
        this.renderRiskFormula({});
        this.renderTopFixes([]);
        this.renderOWASP({});
        this._currentFindings = [];
        this.renderFindings([]);
        this.renderActiveProbesLog([]);
        return;
      }

      if (data.scan_status && data.scan_status !== "completed") {
        document.getElementById("report-title").textContent = "Scan In Progress";
        document.getElementById("report-subtitle").textContent = `Status: ${data.scan_status} (${data.progress || 0}%)`;
        return;
      }

      const r = data.report;
      document.getElementById("report-title").textContent = "Scan Report";
      document.getElementById("report-subtitle").textContent = r.target_url + " — " + this.formatDate(r.scanned_at);

      // Risk gauge
      this.renderGauge(r.risk_score, r.risk_grade);

      // Severity breakdown
      this.renderBreakdown(r.severity_breakdown);

      // Summary
      document.getElementById("report-summary").textContent = r.summary;

      // Risk formula
      this.renderRiskFormula(r.risk_formula || {});

      // Top fixes
      this.renderTopFixes(r.top_fixes || []);

      // OWASP chart (store both, default to 2025)
      this._owaspCoverage2021 = r.owasp_coverage || {};
      this._owaspCoverage2025 = r.owasp_2025_coverage || {};
      this._currentOwaspVersion = "2025";
      this.renderOWASP(this._owaspCoverage2025);

      // Severity summary strip
      this.renderSeverityStrip(r.severity_breakdown || {});

      // Findings
      this._currentFindings = r.findings || [];
      this.updateTabCounts(this._currentFindings);
      this.applyFindingsFilter();

      // Active Probes Log
      this.renderActiveProbesLog(r.active_probes_log || []);
    } catch (err) {
      document.getElementById("report-title").textContent = "Error";
      document.getElementById("report-subtitle").textContent = err.message;
      document.getElementById("report-summary").textContent = "Failed to load report: " + err.message;
      this.renderGauge(0, "F");
      this.renderBreakdown({});
      this.renderRiskFormula({});
      this.renderTopFixes([]);
      this.renderOWASP({});
      this.renderSeverityStrip({});
      this._currentFindings = [];
      this.updateTabCounts([]);
      this.renderFindings([]);
      this.renderActiveProbesLog([]);
    }
  },

  renderGauge(score, grade) {
    const circumference = 2 * Math.PI * 60; // r=60
    const offset = circumference - (score / 100) * circumference;

    let color = "var(--success)";
    if (score > 70) color = "var(--critical)";
    else if (score > 40) color = "var(--medium)";
    else if (score > 10) color = "var(--low)";

    const circle = document.getElementById("gauge-circle");
    circle.style.stroke = color;
    circle.style.strokeDasharray = circumference;
    setTimeout(() => { circle.style.strokeDashoffset = offset; }, 100);

    document.getElementById("gauge-score").textContent = score;
    document.getElementById("gauge-score").style.color = color;
    document.getElementById("gauge-grade").textContent = grade;
  },

  renderBreakdown(breakdown) {
    breakdown = breakdown || {};
    const container = document.getElementById("severity-breakdown");
    const sevs = ["critical", "high", "medium", "low", "info"];
    container.innerHTML = sevs.map(s => {
      const count = breakdown[s] || 0;
      return `<div style="text-align:center;min-width:70px">
        <div class="badge badge-${s}" style="font-size:20px;padding:8px 16px;font-weight:700">${count}</div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:6px;text-transform:uppercase">${s}</div>
      </div>`;
    }).join("");
  },

  renderRiskFormula(formula) {
    const el = document.getElementById("risk-formula");
    if (!el) return;
    if (!formula.formula) { el.innerHTML = ''; return; }
    el.innerHTML = `
      <div class="formula-display">
        <code>${this.esc(formula.formula)}</code>
      </div>
      <div style="display:flex;gap:16px;margin-top:12px;font-size:13px;color:var(--text-muted)">
        <span>Raw: ${formula.raw_score || 0}</span>
        <span>Capped: ${formula.capped_score || 0}</span>
      </div>
      <p style="font-size:12px;color:var(--text-muted);margin-top:8px">${this.esc(formula.note || '')}</p>
    `;
  },

  cvssClass(score) {
    if (score >= 9.0) return "cvss-critical";
    if (score >= 7.0) return "cvss-high";
    if (score >= 4.0) return "cvss-medium";
    if (score > 0) return "cvss-low";
    return "cvss-none";
  },

  renderTopFixes(fixes) {
    const container = document.getElementById("top-fixes");
    if (!fixes.length) {
      container.innerHTML = '<p style="color:var(--text-muted);font-size:14px">No fixes needed — excellent!</p>';
      return;
    }
    container.innerHTML = fixes.map((f, i) => `
      <div class="fix-item">
        <div class="fix-num">${i + 1}</div>
        <div class="fix-content">
          <h4>${this.esc(f.title)}</h4>
          <p>${this.esc(f.remediation)}</p>
        </div>
        <div class="fix-impact"><span class="badge badge-${f.severity}">${this.esc(f.severity)}</span> −${f.risk_reduction}pts</div>
      </div>
    `).join("");
  },

  renderOWASP(coverage) {
    const container = document.getElementById("owasp-chart");
    const entries = Object.entries(coverage);
    const max = Math.max(1, ...entries.map(([,v]) => v));

    container.innerHTML = entries.map(([cat, count]) => {
      const pct = (count / max) * 100;
      const shortCat = cat.split("-").slice(0, 1).join("") + " " + cat.split("-").slice(1).join("-");
      const hasFindings = count > 0;
      return `<div class="owasp-bar${hasFindings ? ' owasp-hit' : ''}">
        <div class="label" title="${this.esc(cat)}">${this.esc(shortCat)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <div class="count">${count}</div>
      </div>`;
    }).join("");
  },

  switchOwaspVersion(version) {
    this._currentOwaspVersion = version;
    document.querySelectorAll("#owasp-version-toggle .filter-tab").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.ver === version);
    });
    if (version === "2025") {
      this.renderOWASP(this._owaspCoverage2025 || {});
    } else {
      this.renderOWASP(this._owaspCoverage2021 || {});
    }
  },

  renderSeverityStrip(breakdown) {
    const strip = document.getElementById("severity-strip");
    if (!strip) return;
    const sevs = [
      { key: "critical", label: "CRITICAL", color: "#ff3b3b", bg: "rgba(255,59,59,0.12)" },
      { key: "high", label: "HIGH", color: "#ff8c42", bg: "rgba(255,140,66,0.12)" },
      { key: "medium", label: "MEDIUM", color: "#eab308", bg: "rgba(234,179,8,0.12)" },
      { key: "low", label: "LOW", color: "#22d3ee", bg: "rgba(34,211,238,0.12)" },
      { key: "info", label: "INFO", color: "#a78bfa", bg: "rgba(167,139,250,0.12)" },
    ];
    strip.innerHTML = sevs.map(s => {
      const count = (breakdown || {})[s.key] || 0;
      return `<div class="strip-item" style="background:${s.bg};border:1px solid ${s.color}30;border-radius:4px;padding:8px 14px;display:flex;align-items:center;gap:8px;min-width:100px">
        <span style="font-size:20px;font-weight:700;color:${s.color};font-family:'JetBrains Mono',monospace">${count}</span>
        <span style="font-size:10px;font-weight:700;color:${s.color};text-transform:uppercase;letter-spacing:0.5px">${s.label}</span>
      </div>`;
    }).join("");
  },

  updateTabCounts(findings) {
    const counts = { all: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => {
      const sev = (f.severity || "info").toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    });
    Object.entries(counts).forEach(([k, v]) => {
      const el = document.getElementById(`tab-count-${k}`);
      if (el) el.textContent = v;
    });
  },

  applyFindingsFilter() {
    const activeTab = document.querySelector("#findings-tabs .filter-tab.active");
    const selectedSev = activeTab ? activeTab.dataset.sev : "all";
    const searchVal = (document.getElementById("findings-search") || {}).value || "";
    const query = searchVal.toLowerCase().trim();
    const sortBy = (document.getElementById("findings-sort") || {}).value || "severity";
    const groupBy = (document.getElementById("findings-group") || {}).value || "none";

    let filtered = this._currentFindings || [];

    if (selectedSev && selectedSev !== "all") {
      filtered = filtered.filter(f => (f.severity || "").toLowerCase() === selectedSev);
    }

    if (query) {
      filtered = filtered.filter(f => {
        const title = (f.title || "").toLowerCase();
        const desc = (f.description || "").toLowerCase();
        const cve = (f.cve || "").toLowerCase();
        const loc = (f.evidence_location || "").toLowerCase();
        const owasp = (f.owasp_category || "").toLowerCase();
        return title.includes(query) || desc.includes(query) || cve.includes(query) || loc.includes(query) || owasp.includes(query);
      });
    }

    // Sort
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    if (sortBy === "severity") {
      filtered.sort((a, b) => (sevOrder[(a.severity || '').toLowerCase()] ?? 5) - (sevOrder[(b.severity || '').toLowerCase()] ?? 5));
    } else if (sortBy === "cvss") {
      filtered.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
    } else if (sortBy === "location") {
      filtered.sort((a, b) => (a.evidence_location || "").localeCompare(b.evidence_location || ""));
    }

    const countEl = document.getElementById("findings-count");
    if (countEl) countEl.textContent = `(${filtered.length} of ${(this._currentFindings || []).length})`;

    // Group by OWASP or render flat
    if (groupBy === "owasp") {
      this.renderFindingsGrouped(filtered);
    } else {
      this.renderFindings(filtered);
    }
  },

  toggleAllFindings(expand) {
    document.querySelectorAll("#findings-list .finding-card").forEach(card => {
      if (expand) card.classList.add("expanded");
      else card.classList.remove("expanded");
    });
  },

  _renderFindingCard(f) {
    const score = f.cvss_score || 0;
    const cvssClass = this.cvssClass(score);
    const cvssBadge = score > 0 
      ? `<span class="cvss-badge ${cvssClass}" title="CVSS 3.1 Base Score">CVSS ${score.toFixed(1)}</span>`
      : '';
    const cvssMeta = score > 0 ? `<span>CVSS: ${score.toFixed(1)}</span>` : '';
    const mitigation = f.mitigation_strategy || f.remediation || '';

    const isActive = f.source_tool === "active_probe";
    const sourceBadge = isActive 
      ? `<span class="badge badge-active" style="font-size:11px">ACTIVE PROBE</span>` 
      : `<span class="badge badge-passive" style="font-size:11px">PASSIVE</span>`;

    // OWASP dual display
    let owaspMeta = "";
    if (f.owasp_2025) {
      owaspMeta += `<span>OWASP 2025: ${this.esc(f.owasp_2025)}</span>`;
    }
    if (f.owasp_category) {
      owaspMeta += `<span style="color:var(--text-muted)">2021: ${this.esc(f.owasp_category)}</span>`;
    }

    return `
    <div class="finding-card" onclick="this.classList.toggle('expanded')">
      <div class="finding-header">
        <span class="badge badge-${f.severity}">${this.esc(f.severity)}</span>
        ${sourceBadge}
        <span class="finding-title">${this.esc(f.title)}</span>
        ${cvssBadge}
        <span class="expand-chevron">▼</span>
      </div>
      <div class="finding-card-details">
        <div class="finding-desc">${this.esc(f.description)}</div>
        <div class="finding-meta">
          ${cvssMeta}
          ${owaspMeta}
          <span>Location: ${this.esc(f.evidence_location || "body")}</span>
        </div>
        ${f.evidence_snippet ? `<div class="evidence-block"><strong>Evidence / Snippet:</strong>\n${this.esc(f.evidence_snippet)}</div>` : ""}
        ${mitigation ? `<div class="evidence-block mitigation-block"><strong>Mitigation Strategy:</strong>\n${this.esc(mitigation)}</div>` : ""}
        <div style="margin-top:12px;display:flex;gap:8px;">
          <button class="btn btn-secondary btn-sm ai-action-btn" onclick="event.stopPropagation();App.runFindingAi('${this.esc(f.id)}','explain')">Explain with AI</button>
        </div>
        <div id="ai-finding-${this.esc(f.id)}" class="ai-response-area hidden" style="margin-top:12px;"></div>
      </div>
    </div>`;
  },

  renderFindings(findings) {
    const container = document.getElementById("findings-list");
    container.innerHTML = "";
    if (!findings.length) {
      container.innerHTML = '<div class="empty-state"><div class="icon">i</div><h3>No findings</h3><p>No vulnerabilities detected matching current filter or search criteria.</p></div>';
      return;
    }
    // Render first 20 immediately (above the fold), then stream the rest in chunks
    // so the main thread is never blocked for more than ~16ms at a time
    const CHUNK = 20;
    container.innerHTML = findings.slice(0, CHUNK).map(f => this._renderFindingCard(f)).join("");
    if (findings.length > CHUNK) {
      let i = CHUNK;
      const renderChunk = () => {
        if (i >= findings.length) return;
        const frag = document.createDocumentFragment();
        const tmp = document.createElement("div");
        tmp.innerHTML = findings.slice(i, i + CHUNK).map(f => this._renderFindingCard(f)).join("");
        while (tmp.firstChild) frag.appendChild(tmp.firstChild);
        container.appendChild(frag);
        i += CHUNK;
        requestAnimationFrame(renderChunk);
      };
      requestAnimationFrame(renderChunk);
    }
  },

  renderFindingsGrouped(findings) {
    const container = document.getElementById("findings-list");
    if (!findings.length) {
      container.innerHTML = '<div class="empty-state"><div class="icon">i</div><h3>No findings</h3><p>No vulnerabilities detected matching current filter or search criteria.</p></div>';
      return;
    }

    // Group by OWASP 2025 category (fall back to 2021, then "Uncategorized")
    const groups = {};
    findings.forEach(f => {
      const cat = f.owasp_2025 || f.owasp_category || "Uncategorized";
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(f);
    });

    // Sort groups by finding count descending
    const sortedGroups = Object.entries(groups).sort((a, b) => b[1].length - a[1].length);

    let html = "";
    sortedGroups.forEach(([cat, items]) => {
      const groupId = "grp-" + cat.replace(/[^a-zA-Z0-9]/g, "_");
      html += `
      <div class="finding-group">
        <div class="finding-group-header" onclick="document.getElementById('${groupId}').classList.toggle('collapsed')">
          <span class="expand-chevron" style="margin-right:8px">▼</span>
          <span style="font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">${this.esc(cat)}</span>
          <span style="margin-left:auto;font-size:12px;color:var(--text-muted)">${items.length} finding${items.length !== 1 ? 's' : ''}</span>
        </div>
        <div class="finding-group-body" id="${groupId}">
          ${items.map(f => this._renderFindingCard(f)).join("")}
        </div>
      </div>`;
    });

    container.innerHTML = html;
  },

  renderActiveProbesLog(logs) {
    const container = document.getElementById("active-probes-list");
    const countEl = document.getElementById("active-probes-count");
    if (!container) return;

    if (!logs || !logs.length) {
      container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;padding:12px">No active probes executed (Passive Mode or zero injectable parameters).</p>';
      if (countEl) countEl.textContent = "(0)";
      return;
    }

    if (countEl) countEl.textContent = `(${logs.length} probes executed)`;

    container.innerHTML = `
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Probe Type</th>
              <th>Target Param</th>
              <th>Payload Injected</th>
              <th>HTTP Code</th>
              <th>Execution Proof / Verification</th>
            </tr>
          </thead>
          <tbody>
            ${logs.map(l => {
              const badgeClass = l.vulnerable ? "badge-critical" : "badge-success";
              const badgeText = l.vulnerable ? "VULNERABLE" : "SAFE / CLEARED";
              return `
                <tr>
                  <td><span class="badge ${badgeClass}">${badgeText}</span></td>
                  <td><strong>${this.esc(l.probe_type || '')}</strong></td>
                  <td><code>${this.esc(l.param_name || '')}</code></td>
                  <td><code style="color:#ffffff">${this.esc(l.payload || '')}</code></td>
                  <td><strong>${l.status_code || 0}</strong></td>
                  <td style="font-size:12px">${this.esc(l.details || '')}</td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;
  },

  // ── Export ────────────────────────────────────────
  async exportReport(format) {
    if (!this._currentScanId) return;
    const url = `${API_BASE}/scan/${this._currentScanId}/export?format=${format}`;
    const headers = { "Authorization": "Bearer " + this.token };

    try {
      const res = await fetch(url, { headers });
      if (!res.ok) { this.showAlert('Export failed: ' + res.statusText, 'error'); return; }
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `sentry-report-${this._currentScanId.substring(0, 8)}.${format}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (err) {
      alert("Export failed: " + err.message);
    }
  },

  // ── Rules ─────────────────────────────────────────
  async loadRules() {
    try {
      const data = await this.api("GET", "/rules");
      document.getElementById("rules-count").textContent = `Rules (${data.total})`;

      const rules = data.rules || [];
      if (!rules.length) {
        document.getElementById("rules-table").innerHTML = '<div class="empty-state"><h3>No rules loaded</h3></div>';
        return;
      }

      let html = `<table><thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Severity</th><th>Source</th></tr></thead><tbody>`;
      for (const r of rules) {
        html += `<tr>
          <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${this.esc(r.id)}</td>
          <td>${this.esc(r.title || r.id)}</td>
          <td><span class="badge badge-info">${this.esc(r.type || "—")}</span></td>
          <td><span class="badge badge-${r.severity || 'info'}">${this.esc(r.severity || "—")}</span></td>
          <td style="color:var(--text-muted)">${this.esc(r.source || "custom")}</td>
        </tr>`;
      }
      html += "</tbody></table>";
      document.getElementById("rules-table").innerHTML = html;
    } catch (err) {
      document.getElementById("rules-table").innerHTML = `<div class="empty-state"><h3>Error</h3><p>${this.esc(err.message)}</p></div>`;
    }
  },

  async reloadRules() {
    try {
      const data = await this.api("POST", "/rules/reload");
      alert(`Rules reloaded: ${data.total} rules loaded`);
      this.loadRules();
    } catch (err) {
      alert("Reload failed: " + err.message);
    }
  },

  // ── Utils ─────────────────────────────────────────
  esc(str) {
    if (!str) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  },

  // ── AI Analysis ──────────────────────────────────
  _aiSystemPrompt: `You are a defensive cybersecurity educator and application security consultant. Analyze scan results to provide clear remediation guidance. Format responses in markdown. Focus on defensive strategies and risk mitigation.`,

  _parseMd(md) {
    if (!md) return '';
    return md
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/\n{2,}/g, '</p><p>')
      .replace(/\n/g, '<br>')
      .replace(/^/, '<p>').replace(/$/, '</p>');
  },

  _compactReport(report) {
    const r = report || {};
    const findings = r.findings || [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const sorted = [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    const top = sorted.slice(0, 15).map(f => ({
      title: f.title, severity: f.severity, cvss: f.cvss_score || '',
      owasp: f.owasp_category || '', cve: f.cve || '', location: f.evidence_location || '',
    }));
    // Use scan completion date; fall back to today
    const rawDate = r.completed_at || r.created_at || new Date().toISOString();
    const scanDate = new Date(rawDate).toLocaleDateString('en-GB', {
      day: '2-digit', month: 'long', year: 'numeric'
    });
    return { target: r.target_url || '', scan_date: scanDate,
      risk_score: r.risk_score || 0, risk_grade: r.risk_grade || '?',
      total_findings: findings.length, severity_counts: counts, top_findings: top };
  },

  _buildPrompt(action, report) {
    if (action === 'executive_summary') {
      const compact = this._compactReport(report);
      return `Generate an executive summary for this vulnerability scan:\n\n${JSON.stringify(compact, null, 2)}\n\nInclude:\n1. Non-technical overview for management.\n2. Key risk areas with business impact.\n3. Prioritized action items.\n4. Comparison against industry standards.`;
    }
    if (action === 'prioritize_fixes') {
      const findings = (report.findings || []).slice(0, 15).map(f => ({
        title: f.title, severity: f.severity, cvss: f.cvss_score || '',
        owasp: f.owasp_category || '', remediation: (f.remediation || '').slice(0, 80),
      }));
      return `Create a prioritized remediation plan.\n\nRisk Score: ${report.risk_score || 0}/100\nTop Findings:\n${JSON.stringify(findings, null, 2)}\n\nProvide:\n1. Ordered remediation plan (fix first → fix later).\n2. Effort per fix (Low/Medium/High).\n3. Expected risk reduction per fix.\n4. Quick wins vs long-term improvements.`;
    }
    if (action === 'owasp_analysis') {
      return `Analyze the OWASP Top 10 coverage:\n\n${JSON.stringify(report.owasp_coverage || report.owasp_2025_coverage || {}, null, 2)}\n\nInclude:\n1. Current coverage assessment against OWASP Top 10.\n2. Coverage gaps and missed categories.\n3. Recommendations for improving security testing.`;
    }
    return '';
  },

  _buildFindingPrompt(finding, type) {
    const f = {
      title: finding.title, severity: finding.severity,
      description: (finding.description || '').slice(0, 200),
      cvss: finding.cvss_score || '', cve: finding.cve || '', cwe: finding.cwe || '',
      evidence: (finding.evidence_snippet || '').slice(0, 100),
      location: finding.evidence_location || '',
    };
    if (type === 'explain') {
      return `Explain this vulnerability finding:\n${JSON.stringify(f, null, 2)}\n\nProvide:\n1. What the vulnerability is in plain English.\n2. Real-world impact and attack scenarios.\n3. Step-by-step remediation with code examples.\n4. CVSS severity justification.`;
    }
    return `Perform a detailed technical analysis on this finding:\n${JSON.stringify(f, null, 2)}\n\nInclude:\n1. Attack vector analysis.\n2. Exploitation difficulty and prerequisites.\n3. Potential for chaining with other vulnerabilities.\n4. Defense-in-depth recommendations.`;
  },

  async _aiCall(prompt) {
    const res = await this.api("POST", "/ai/analyze", {
      prompt,
      systemPrompt: this._aiSystemPrompt,
      temperature: 0.7,
      maxTokens: 4096,
    });
    if (res.error) throw new Error(res.error);
    return res.text || '';
  },

  async populateAiScanSelector() {
    const selector = document.getElementById('ai-scan-selector');
    if (!selector) return;
    try {
      const data = await this.api('GET', '/scans');
      const completed = (data.scans || []).filter(s => s.status === 'completed');
      let html = '<option value="">-- Select a completed scan --</option>';
      completed.forEach(s => {
        const date = this.formatDate(s.created_at);
        html += `<option value="${this.esc(s.scan_id)}">${this.esc(s.target_url)} (${date})</option>`;
      });
      selector.innerHTML = html;
    } catch (err) {
      console.error('Failed to load scans for AI selector:', err);
    }
  },

  askAiReport() {
    this.navigate('ai-analysis');
    setTimeout(() => {
      this.populateAiScanSelector().then(() => {
        const sel = document.getElementById('ai-scan-selector');
        if (sel && this._currentScanId) sel.value = this._currentScanId;
        this.runAiAction('executive_summary');
      });
    }, 100);
  },

  async runAiAction(action) {
    const scanId = document.getElementById('ai-scan-selector').value;
    if (!scanId) { alert('Please select a scan first'); return; }

    const container = document.getElementById('ai-response-container');
    const content = document.getElementById('ai-response-content');
    const loader = document.getElementById('ai-loading-indicator');

    container.classList.remove('hidden');
    content.innerHTML = '';
    loader.classList.remove('hidden');

    try {
      const res = await this.api('GET', `/scan/${scanId}/report`);
      const report = res.report;
      const prompt = this._buildPrompt(action, report);
      const result = await this._aiCall(prompt);
      content.innerHTML = this._parseMd(result);
    } catch (err) {
      content.innerHTML = `<div class="alert alert-error" style="display:block">Error generating AI analysis: ${this.esc(err.message)}</div>`;
    } finally {
      loader.classList.add('hidden');
    }
  },

  async runFindingAi(findingId, type) {
    const finding = (this._currentFindings || []).find(f => f.id === findingId);
    if (!finding) return;

    const container = document.getElementById(`ai-finding-${findingId}`);
    if (!container) return;

    container.classList.remove('hidden');
    container.innerHTML = '<div class="ai-loading">Thinking<span class="dots">...</span></div>';

    try {
      const prompt = this._buildFindingPrompt(finding, type);
      const result = await this._aiCall(prompt);
      container.innerHTML = this._parseMd(result);
    } catch (err) {
      container.innerHTML = `<div style="color:var(--critical)">Error: ${this.esc(err.message)}</div>`;
    }
  },
};

// Boot
document.addEventListener("DOMContentLoaded", () => App.init());
