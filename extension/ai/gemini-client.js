/**
 * Gemini AI Client — Backend Proxy Mode
 * All AI calls go through the Flask backend at /api/ai/*
 * Users never need an API key — it's stored server-side.
 */

import { api, getBackendUrl, getToken } from '../shared/api-client.js';

/**
 * Check if AI is available on the backend.
 * @returns {Promise<{configured: boolean, model: string|null}>}
 */
export async function getAiStatus() {
  try {
    const result = await api('GET', '/api/ai/status', null, false);
    return result;
  } catch {
    return { configured: false, model: null };
  }
}

/**
 * Generate content via the backend proxy (non-streaming).
 * @param {string} prompt - The user prompt
 * @param {object} options - { systemPrompt, temperature, maxTokens }
 * @returns {Promise<string>} The generated text
 */
export async function generateContent(prompt, options = {}) {
  const result = await api('POST', '/api/ai/analyze', {
    prompt,
    systemPrompt: options.systemPrompt || '',
    temperature: options.temperature ?? 0.7,
    maxTokens: options.maxTokens ?? 4096,
  });

  if (result.error) {
    throw new Error(result.error);
  }

  return result.text || '';
}

/**
 * Stream content via the backend proxy (Server-Sent Events).
 * @param {string} prompt - The user prompt
 * @param {object} options - { systemPrompt, temperature, maxTokens }
 * @param {function} onChunk - Callback called with (chunk, fullText) for each chunk
 * @returns {Promise<string>} The full accumulated text
 */
export async function streamContent(prompt, options = {}, onChunk = null) {
  const baseUrl = await getBackendUrl();
  const token = await getToken();
  const url = `${baseUrl}/api/ai/stream`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      prompt,
      systemPrompt: options.systemPrompt || '',
      temperature: options.temperature ?? 0.7,
      maxTokens: options.maxTokens ?? 4096,
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`AI stream error: ${response.status} - ${errText}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let fullText = '';
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop(); // Keep incomplete line in buffer

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const dataStr = line.substring(6).trim();
        if (dataStr === '[DONE]') continue;

        try {
          const data = JSON.parse(dataStr);

          // Check for error from proxy
          if (data.error) {
            throw new Error(data.error);
          }

          if (data.candidates && data.candidates.length > 0 && data.candidates[0].content) {
            const textChunk = data.candidates[0].content.parts
              .map(part => part.text)
              .join('');
            fullText += textChunk;
            if (onChunk) {
              onChunk(textChunk, fullText);
            }
          }
        } catch (e) {
          if (e.message.startsWith('AI') || e.message.startsWith('Gemini')) throw e;
          // Ignore JSON parse errors on partial chunks
        }
      }
    }
  }

  return fullText;
}
