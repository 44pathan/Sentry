"""
report_exporter.py — HTML Report Generator
Produces a self-contained, styled HTML report matching the Mapper dark UI.
"""


def generate_html_report(report: dict) -> str:
    """Generate a self-contained HTML report from report data without dropping details."""
    findings = report.get("findings", [])
    formula = report.get("risk_formula", {})
    breakdown = report.get("severity_breakdown", {})
    owasp = report.get("owasp_coverage", {})
    top_fixes = report.get("top_fixes", [])

    def _g(item, key, default=""):
        if isinstance(item, dict):
            val = item.get(key, default)
            return default if val is None else val
        val = getattr(item, key, default)
        return default if val is None else val

    # Build findings rows
    findings_html = ""
    for f in findings:
        sev = _g(f, "severity", "info")
        cvss = _g(f, "cvss_score", 0.0)
        tool = _g(f, "source_tool", "custom")
        cve = _g(f, "cve", "")
        cwe = _g(f, "cwe", "")
        owasp_cat = _g(f, "owasp_category", "")
        location = _g(f, "evidence_location", "body")
        snippet = _g(f, "evidence_snippet", "")
        tech = _g(f, "detected_technology", "")
        ver = _g(f, "detected_version", "")
        remediation = _g(f, "remediation", "")
        mitigation = _g(f, "mitigation_strategy", "") or remediation
        refs = _g(f, "reference_urls", [])
        correlated = _g(f, "correlated", False)
        corr_sources = _g(f, "correlation_sources", [])

        tool_label = "ACTIVE PROBE" if tool == "active_probe" else tool.upper()
        tool_class = "badge-active" if tool == "active_probe" else "badge-passive"
        sev_class = f"badge-{sev}"
        cvss_cell = f'<span class="cvss-badge {_cvss_class(cvss)}">CVSS {cvss}</span>' if cvss > 0 else '<span class="text-muted">—</span>'

        meta_spans = []
        if cvss > 0: meta_spans.append(f'<span>CVSS: {cvss}</span>')
        if cve: meta_spans.append(f'<span>CVE: {_esc(cve)}</span>')
        if cwe: meta_spans.append(f'<span>CWE: {_esc(cwe)}</span>')
        if owasp_cat: meta_spans.append(f'<span>OWASP: {_esc(owasp_cat)}</span>')
        if location: meta_spans.append(f'<span>Location: {_esc(location)}</span>')
        if tech: meta_spans.append(f'<span>Tech: {_esc(tech)} {_esc(ver)}</span>'.strip())
        if correlated and corr_sources: meta_spans.append(f'<span>Correlated: {_esc(", ".join(corr_sources))}</span>')

        meta_html = "".join(meta_spans)

        refs_html = ""
        if refs:
            ref_links = [f'<a href="{_esc(r)}" target="_blank" style="color:#60a5fa">{_esc(r)}</a>' for r in refs if r]
            if ref_links:
                refs_html = f'<div class="evidence-block refs-block"><strong>References:</strong><br>{"<br>".join(ref_links)}</div>'

        findings_html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <span class="{sev_class}">{_esc(sev).upper()}</span>
                <span class="{tool_class}">{tool_label}</span>
                <span class="finding-title">{_esc(_g(f, "title", ""))}</span>
                {cvss_cell}
            </div>
            <div class="finding-desc">{_esc(_g(f, "description", ""))}</div>
            <div class="finding-meta">
                {meta_html}
            </div>
            {f'<div class="evidence-block"><strong>Evidence:</strong><br>{_esc(snippet)}</div>' if snippet else ''}
            {f'<div class="evidence-block mitigation-block"><strong>Mitigation Strategy:</strong><br>{_esc(mitigation)}</div>' if mitigation else ''}
            {refs_html}
        </div>"""

    # Build OWASP rows
    owasp_html = ""
    max_owasp = max(1, max(owasp.values())) if owasp else 1
    for cat, count in owasp.items():
        bar_pct = (count / max_owasp) * 100 if count > 0 else 0
        owasp_html += f"""
        <div class="owasp-bar">
            <div class="owasp-label">{_esc(cat)}</div>
            <div class="bar-track"><div class="bar-fill" style="width:{bar_pct}%"></div></div>
            <div class="owasp-count">{count}</div>
        </div>"""

    # Build top fixes
    fixes_html = ""
    for i, fix in enumerate(top_fixes, 1):
        fixes_html += f"""
        <div class="fix-item">
            <div class="fix-num">{i}</div>
            <div class="fix-content">
                <h4>{_esc(fix.get('title', ''))}</h4>
                <p>{_esc(fix.get('remediation', ''))}</p>
            </div>
            <div class="fix-impact">
                <span class="badge-{fix.get('severity', 'info')}">{_esc(fix.get('severity', '').upper())}</span>
                −{fix.get('risk_reduction', 0)}pts
            </div>
        </div>"""

    # Build active probes log
    active_logs = report.get("active_probes_log", [])
    active_logs_html = ""
    for log_entry in active_logs:
        status_class = "vuln-true" if log_entry.get("vulnerable") else "vuln-false"
        status_text = "VULNERABLE" if log_entry.get("vulnerable") else "SAFE"
        active_logs_html += f"""
        <tr>
            <td><span class="{status_class}">{status_text}</span></td>
            <td><strong>{_esc(log_entry.get('probe_type', ''))}</strong></td>
            <td><code>{_esc(log_entry.get('param_name', ''))}</code></td>
            <td><code class="payload">{_esc(log_entry.get('payload', ''))}</code></td>
            <td>{log_entry.get('status_code', 0)}</td>
            <td class="details-cell">{_esc(log_entry.get('details', ''))}</td>
        </tr>"""

    risk_score = report.get('risk_score', 0)
    grade = report.get('risk_grade', '')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mapper Scan Report — {_esc(report.get('target_url', ''))}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=JetBrains+Mono:wght@400;700&display=swap');

:root {{
    --bg-primary: #000000;
    --bg-card: #121212;
    --bg-card-hover: #1c1c1c;
    --border: #2a2a2a;
    --text-primary: #ffffff;
    --text-secondary: #cccccc;
    --text-muted: #888888;
    --critical: #ff3b3b;
    --critical-bg: rgba(255, 59, 59, 0.15);
    --high: #ffffff;
    --high-bg: rgba(255, 255, 255, 0.1);
    --medium: #e0e0e0;
    --medium-bg: rgba(224, 224, 224, 0.1);
    --low: #aaaaaa;
    --low-bg: rgba(170, 170, 170, 0.1);
    --info: #777777;
    --info-bg: rgba(119, 119, 119, 0.1);
    --success: #4caf50;
    --accent: #ffffff;
}}

*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
    font-family: 'Space Mono', 'JetBrains Mono', monospace;
    background: var(--bg-primary);
    color: var(--text-primary);
    padding: 40px 32px;
    line-height: 1.6;
    letter-spacing: 0.5px;
}}

.container {{ max-width: 1100px; margin: 0 auto; }}

h1 {{
    font-size: 22px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px;
    margin-bottom: 32px;
}}

h2 {{
    font-size: 15px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-primary);
    margin-top: 32px;
    margin-bottom: 16px;
}}

.card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 24px;
    margin-bottom: 16px;
}}

/* Risk gauge */
.risk-section {{
    display: flex;
    gap: 24px;
    margin-bottom: 16px;
}}

.gauge-card {{
    display: flex;
    align-items: center;
    justify-content: center;
    min-width: 180px;
}}

.gauge-score {{
    font-size: 48px;
    font-weight: 800;
    color: {_score_color(risk_score)};
    text-align: center;
    line-height: 1;
}}

.gauge-grade {{
    font-size: 14px;
    color: var(--text-muted);
    text-align: center;
    margin-top: 4px;
}}

/* Stats */
.stats-grid {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
}}

.stat-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px 24px;
    text-align: center;
}}

.stat-value {{ font-size: 28px; font-weight: 700; line-height: 1.2; }}
.stat-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 700; }}

/* Severity colors */
.stat-critical {{ color: var(--critical); }}
.stat-high {{ color: var(--high); }}
.stat-medium {{ color: var(--medium); }}
.stat-low {{ color: var(--low); }}
.stat-info {{ color: var(--info); }}

/* Badges */
.badge-critical {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background: #1a0000; color: #ff3b3b; border: 1px solid #ff3b3b; }}
.badge-high {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background: #1a1a1a; color: #ffffff; border: 1px solid #ffffff; }}
.badge-medium {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background: #181818; color: #e0e0e0; border: 1px solid #666666; }}
.badge-low {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background: #121212; color: #aaaaaa; border: 1px solid #444444; }}
.badge-info {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background: #0a0a0a; color: #888888; border: 1px solid #333333; }}
.badge-active {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }}
.badge-passive {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: rgba(59,130,246,0.15); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }}

/* CVSS badges */
.cvss-badge {{ display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 700; font-family: 'JetBrains Mono', monospace; margin-left: auto; }}
.cvss-critical {{ background: var(--critical-bg); color: var(--critical); }}
.cvss-high {{ background: var(--high-bg); color: var(--high); }}
.cvss-medium {{ background: var(--medium-bg); color: var(--medium); }}
.cvss-low {{ background: var(--low-bg); color: var(--low); }}
.cvss-none {{ background: var(--info-bg); color: var(--info); }}

/* Formula */
.formula {{
    font-family: 'JetBrains Mono', monospace;
    background: rgba(0,0,0,0.3);
    padding: 14px 20px;
    border-radius: 4px;
    border-left: 3px solid var(--accent);
    font-size: 14px;
    color: var(--success);
    letter-spacing: 0.5px;
}}

/* Findings */
.finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 16px 20px;
    margin-bottom: 12px;
}}

.finding-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
    flex-wrap: wrap;
}}

.finding-title {{ font-size: 15px; font-weight: 600; color: var(--text-primary); }}
.finding-desc {{ font-size: 13px; color: var(--text-secondary); line-height: 1.5; }}

.finding-meta {{
    display: flex;
    gap: 16px;
    margin-top: 10px;
    font-size: 12px;
    color: var(--text-muted);
    flex-wrap: wrap;
}}

.evidence-block {{
    margin-top: 10px;
    padding: 10px 14px;
    background: rgba(0,0,0,0.3);
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-all;
}}

.mitigation-block {{
    border-left: 3px solid var(--success);
    background: rgba(34, 197, 94, 0.04);
    line-height: 1.6;
}}

.mitigation-block strong {{ color: var(--success); }}

/* OWASP */
.owasp-bar {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }}
.owasp-label {{ font-size: 12px; color: var(--text-secondary); width: 280px; flex-shrink: 0; }}
.bar-track {{ flex: 1; height: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; overflow: hidden; }}
.bar-fill {{ height: 100%; background: var(--accent); border-radius: 4px; }}
.owasp-count {{ font-size: 12px; font-weight: 600; color: var(--text-muted); min-width: 24px; text-align: right; }}

/* Top fixes */
.fix-item {{
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px;
    background: rgba(0,0,0,0.15);
    border-radius: 4px;
    margin-bottom: 8px;
}}

.fix-num {{
    width: 28px; height: 28px; border-radius: 50%;
    background: rgba(255,255,255,0.08);
    display: flex; align-items: center; justify-content: center;
    font-size: 13px; font-weight: 700; color: var(--accent); flex-shrink: 0;
}}

.fix-content h4 {{ font-size: 14px; font-weight: 600; margin-bottom: 4px; }}
.fix-content p {{ font-size: 12px; color: var(--text-secondary); line-height: 1.4; }}
.fix-impact {{ margin-left: auto; font-size: 12px; font-weight: 600; color: var(--success); white-space: nowrap; }}

/* Active probes table */
table {{ width: 100%; border-collapse: collapse; }}
th {{ background: #0a0a0a; color: #ffffff; text-align: left; padding: 12px 14px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid var(--border); }}
td {{ padding: 12px 14px; border-bottom: 1px solid var(--border); font-size: 13px; color: var(--text-secondary); }}
tr:hover td {{ background: var(--bg-card-hover); }}
code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; }}
.payload {{ color: #60a5fa; }}
.details-cell {{ font-size: 12px; }}
.vuln-true {{ color: var(--critical); font-weight: 700; text-transform: uppercase; }}
.vuln-false {{ color: var(--success); font-weight: 700; text-transform: uppercase; }}
.text-muted {{ color: var(--text-muted); }}

/* Footer */
.footer {{
    margin-top: 40px;
    text-align: center;
    color: var(--text-muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    padding-top: 20px;
}}

/* Meta info */
.meta-info p {{ font-size: 13px; margin: 4px 0; color: var(--text-secondary); }}
.meta-info strong {{ color: var(--text-primary); }}
</style>
</head>
<body>
<div class="container">
<h1>Sentry — Vulnerability Scan Report</h1>

<div class="card meta-info">
    <p><strong>Target:</strong> {_esc(report.get('target_url', ''))}</p>
    <p><strong>Scanned:</strong> {_esc(report.get('scanned_at', ''))}</p>
    <p><strong>Duration:</strong> {report.get('scan_duration_ms', 0):.0f}ms</p>
    <p><strong>Total Findings:</strong> {report.get('total_findings', 0)}</p>
    <p><strong>Technologies:</strong> {_esc(', '.join(report.get('technologies', []))) or 'None'}</p>
</div>

<h2>Risk Score</h2>
<div class="risk-section">
    <div class="card gauge-card">
        <div>
            <div class="gauge-score">{risk_score}</div>
            <div class="gauge-grade">{_esc(grade)} — {_esc(report.get('risk_grade_label', ''))}</div>
        </div>
    </div>
    <div class="card" style="flex:1">
        <h2 style="margin-top:0">Severity Breakdown</h2>
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value stat-critical">{breakdown.get('critical', 0)}</div><div class="stat-label">Critical</div></div>
            <div class="stat-card"><div class="stat-value stat-high">{breakdown.get('high', 0)}</div><div class="stat-label">High</div></div>
            <div class="stat-card"><div class="stat-value stat-medium">{breakdown.get('medium', 0)}</div><div class="stat-label">Medium</div></div>
            <div class="stat-card"><div class="stat-value stat-low">{breakdown.get('low', 0)}</div><div class="stat-label">Low</div></div>
            <div class="stat-card"><div class="stat-value stat-info">{breakdown.get('info', 0)}</div><div class="stat-label">Info</div></div>
        </div>
        <p style="margin-top:16px;font-size:13px;color:var(--text-secondary)">{_esc(report.get('summary', ''))}</p>
    </div>
</div>

<h2>Risk Score Formula</h2>
<div class="card">
    <div class="formula">{_esc(formula.get('formula', ''))}</div>
    <p style="margin-top:8px;font-size:13px;color:var(--text-muted)">Raw score: {formula.get('raw_score', 0)} → Capped: {formula.get('capped_score', 0)}</p>
    <p style="font-size:12px;color:var(--text-muted)">{_esc(formula.get('note', ''))}</p>
</div>

<h2>Top Priority Fixes</h2>
<div class="card">
    {fixes_html if fixes_html else '<p style="color:var(--text-muted);font-size:14px">No fixes needed — excellent!</p>'}
</div>

<h2>OWASP Top 10 Coverage</h2>
<div class="card">
    {owasp_html if owasp_html else '<p style="color:var(--text-muted)">No OWASP data available.</p>'}
</div>

<h2>All Findings ({report.get('total_findings', 0)})</h2>
{findings_html if findings_html else '<div class="card"><p style="color:var(--text-muted)">No findings detected.</p></div>'}

<h2>Active Probe Execution Log ({len(active_logs)})</h2>
<div class="card" style="overflow-x:auto">
<table>
<thead><tr><th>Status</th><th>Probe Type</th><th>Target Param</th><th>Payload Injected</th><th>HTTP Code</th><th>Execution Details</th></tr></thead>
<tbody>{active_logs_html or '<tr><td colspan="6" style="color:var(--text-muted)">No active probes executed (Passive Mode).</td></tr>'}</tbody>
</table>
</div>

<div class="footer">
    <p>Generated by Sentry Vulnerability Scanner</p>
</div>
</div>
</body>
</html>"""


def _esc(s):
    """HTML escape."""
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")


def _score_color(score):
    if score > 70: return "#ff3b3b"
    if score > 40: return "#ffffff"
    if score > 10: return "#e0e0e0"
    return "#4caf50"


def _cvss_class(score):
    if score >= 9.0: return "cvss-critical"
    if score >= 7.0: return "cvss-high"
    if score >= 4.0: return "cvss-medium"
    if score > 0: return "cvss-low"
    return "cvss-none"
