/**
 * Prompts Module
 * Curated prompt templates for vulnerability analysis.
 */

export const PROMPTS = {
  SYSTEM_PROMPT: `You are a senior cybersecurity analyst specializing in web application security. You analyze vulnerability scan results and provide clear, actionable security guidance. Format responses in markdown. Be specific, technical, and practical.`,

  EXPLAIN_FINDING: (finding) => `
Please explain the following vulnerability finding:

Vulnerability Details:
${JSON.stringify(finding, null, 2)}

Provide a comprehensive explanation including:
1. What the vulnerability is in plain English.
2. Real-world impact and possible attack scenarios.
3. Step-by-step remediation guidance with practical code examples.
4. CVSS context and severity justification (if applicable).
  `,

  EXECUTIVE_SUMMARY: (report) => `
Please generate an executive summary for the following vulnerability scan report:

Report Summary:
${JSON.stringify(report, null, 2)}

Your summary should include:
1. A non-technical overview suitable for management.
2. Key risk areas highlighting the business impact.
3. Prioritized action items for the team.
4. Comparison of the findings against industry standards.
  `,

  PRIORITIZE_FIXES: (findings, riskScore) => `
Please create a prioritized remediation plan for these findings.

Overall Risk Score: ${riskScore}
Findings:
${JSON.stringify(findings, null, 2)}

Provide a plan that includes:
1. An ordered remediation plan (what to fix first).
2. Estimated effort required per fix (Low/Medium/High).
3. The expected risk reduction per fix.
4. Identification of quick wins versus long-term security improvements.
  `,

  DEEP_DIVE: (finding) => `
Perform a detailed technical analysis on this specific finding:

Finding Details:
${JSON.stringify(finding, null, 2)}

Include the following in your deep dive:
1. Attack vector analysis (how an attacker would exploit this).
2. Exploitation difficulty and prerequisites.
3. Potential for chaining this with other vulnerabilities.
4. Defense-in-depth recommendations to prevent similar issues.
  `,

  SECURITY_CHAT: (question, context) => `
Based on the following scan context, please answer the question.

Scan Context:
${JSON.stringify(context, null, 2)}

User Question: ${question}

Provide a clear, technical, and accurate answer based on the provided context.
  `,

  OWASP_ANALYSIS: (owaspCoverage) => `
Please analyze the OWASP Top 10 coverage for this application.

OWASP Coverage Data:
${JSON.stringify(owaspCoverage, null, 2)}

Provide an analysis that includes:
1. An assessment of current coverage against the OWASP Top 10.
2. Identification of coverage gaps and missed categories.
3. Recommendations for improving security testing for the gaps.
  `
};
