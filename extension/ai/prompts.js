/**
 * Prompts Module
 * Curated prompt templates for vulnerability analysis.
 * Data is trimmed to stay within AI token limits (~7000 tokens).
 */

// ── Helper: compress a report to essential data only ──
function _compactReport(report) {
  const r = report || {};
  const findings = r.findings || [];

  // Count severities
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  // Take top 15 findings by severity, strip to essentials
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const top = sorted.slice(0, 15).map(f => ({
    title: f.title,
    severity: f.severity,
    cvss: f.cvss_score || '',
    owasp: f.owasp_category || '',
    cve: f.cve || '',
    location: f.evidence_location || '',
  }));

  return {
    target: r.target_url || '',
    risk_score: r.risk_score || 0,
    risk_grade: r.risk_grade || '?',
    total_findings: findings.length,
    severity_counts: counts,
    top_findings: top,
  };
}

// ── Helper: compress findings list ──
function _compactFindings(findings) {
  const list = findings || [];
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...list].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return sorted.slice(0, 15).map(f => ({
    title: f.title,
    severity: f.severity,
    cvss: f.cvss_score || '',
    owasp: f.owasp_category || '',
    remediation: (f.remediation || '').slice(0, 80),
  }));
}

export const PROMPTS = {
  SYSTEM_PROMPT: `You are a defensive cybersecurity educator and application security consultant. Analyze scan results to provide clear remediation guidance. Format responses in markdown. Focus on defensive strategies and risk mitigation.`,

  EXPLAIN_FINDING: (finding) => {
    // Single finding — keep it compact
    const f = {
      title: finding.title,
      severity: finding.severity,
      description: (finding.description || '').slice(0, 200),
      cvss: finding.cvss_score || '',
      cve: finding.cve || '',
      cwe: finding.cwe || '',
      evidence: (finding.evidence_snippet || '').slice(0, 100),
      location: finding.evidence_location || '',
    };
    return `Explain this vulnerability finding:
${JSON.stringify(f, null, 2)}

Provide:
1. What the vulnerability is in plain English.
2. Real-world impact and attack scenarios.
3. Step-by-step remediation with code examples.
4. CVSS severity justification.`;
  },

  EXECUTIVE_SUMMARY: (report) => {
    const compact = _compactReport(report);
    return `Generate an executive summary for this vulnerability scan:

${JSON.stringify(compact, null, 2)}

Include:
1. Non-technical overview for management.
2. Key risk areas with business impact.
3. Prioritized action items.
4. Comparison against industry standards.`;
  },

  PRIORITIZE_FIXES: (findings, riskScore) => {
    const compact = _compactFindings(findings);
    return `Create a prioritized remediation plan.

Risk Score: ${riskScore}/100
Top Findings:
${JSON.stringify(compact, null, 2)}

Provide:
1. Ordered remediation plan (fix first → fix later).
2. Effort per fix (Low/Medium/High).
3. Expected risk reduction per fix.
4. Quick wins vs long-term improvements.`;
  },

  DEEP_DIVE: (finding) => {
    const f = {
      title: finding.title,
      severity: finding.severity,
      description: (finding.description || '').slice(0, 300),
      cvss: finding.cvss_score || '',
      cve: finding.cve || '',
      evidence: (finding.evidence_snippet || '').slice(0, 150),
    };
    return `Perform a detailed technical analysis on this finding:
${JSON.stringify(f, null, 2)}

Include:
1. Attack vector analysis.
2. Exploitation difficulty and prerequisites.
3. Potential for chaining with other vulnerabilities.
4. Defense-in-depth recommendations.`;
  },

  SECURITY_CHAT: (question, context) => {
    // Trim context heavily
    const compact = typeof context === 'object' ? _compactReport(context) : context;
    const ctxStr = typeof compact === 'string' ? compact : JSON.stringify(compact, null, 2);
    return `Based on this scan context, answer the question.

Context:
${ctxStr.slice(0, 1500)}

Question: ${question}

Provide a clear, technical answer.`;
  },

  OWASP_ANALYSIS: (owaspCoverage) => `Analyze the OWASP Top 10 coverage:

${JSON.stringify(owaspCoverage, null, 2)}

Include:
1. Current coverage assessment against OWASP Top 10.
2. Coverage gaps and missed categories.
3. Recommendations for improving security testing.`
};
