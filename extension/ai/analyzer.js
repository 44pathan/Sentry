/**
 * AI Analyzer
 * Orchestrator for analyzing vulnerabilities using the Gemini API.
 */

import { generateContent, streamContent } from './gemini-client.js';
import { PROMPTS } from './prompts.js';

// Simple in-memory cache
const analysisCache = new Map();

// Helper to generate a simple hash for cache keys
async function generateHash(str) {
  const msgBuffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Clear the cache
export function clearCache() {
  analysisCache.clear();
}

// Manage cache size (keep last 10)
function manageCacheSize() {
  if (analysisCache.size > 10) {
    const oldestKey = analysisCache.keys().next().value;
    analysisCache.delete(oldestKey);
  }
}

// Generic execution function
async function executeAnalysis(prompt, onChunk) {
  const cacheKey = await generateHash(prompt);
  
  if (analysisCache.has(cacheKey)) {
    const cachedResult = analysisCache.get(cacheKey);
    if (onChunk) {
      onChunk(cachedResult, cachedResult);
    }
    return cachedResult;
  }

  const options = {
    systemPrompt: PROMPTS.SYSTEM_PROMPT
  };

  try {
    let result;
    if (onChunk) {
      result = await streamContent(prompt, options, onChunk);
    } else {
      result = await generateContent(prompt, options);
    }
    
    analysisCache.set(cacheKey, result);
    manageCacheSize();
    
    return result;
  } catch (error) {
    console.error('Error during AI analysis:', error);
    throw error;
  }
}

export async function analyzeFindings(report, onChunk = null) {
  const prompt = PROMPTS.EXECUTIVE_SUMMARY(report);
  return executeAnalysis(prompt, onChunk);
}

export async function explainFinding(finding, onChunk = null) {
  const prompt = PROMPTS.EXPLAIN_FINDING(finding);
  return executeAnalysis(prompt, onChunk);
}

export async function prioritizeFixes(findings, riskScore, onChunk = null) {
  const prompt = PROMPTS.PRIORITIZE_FIXES(findings, riskScore);
  return executeAnalysis(prompt, onChunk);
}

export async function deepDiveFinding(finding, onChunk = null) {
  const prompt = PROMPTS.DEEP_DIVE(finding);
  return executeAnalysis(prompt, onChunk);
}

export async function askQuestion(question, scanContext, onChunk = null) {
  const prompt = PROMPTS.SECURITY_CHAT(question, scanContext);
  return executeAnalysis(prompt, onChunk);
}

export async function analyzeOwasp(owaspCoverage, onChunk = null) {
  const prompt = PROMPTS.OWASP_ANALYSIS(owaspCoverage);
  return executeAnalysis(prompt, onChunk);
}

// Namespace export for dashboard compatibility
export const AIAnalyzer = {
  generateExecutiveSummary: analyzeFindings,
  explainFinding,
  prioritizeFixes: (findings, onChunk) => prioritizeFixes(findings, 0, onChunk),
  deepDiveFinding: deepDiveFinding,
  analyzeOwaspCoverage: analyzeOwasp,
  askQuestion,
  clearCache,
};
