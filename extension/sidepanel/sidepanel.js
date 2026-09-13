import { listScans, deleteScan, exportReport } from '../shared/api-client.js';
import { analyzeFindings, prioritizeFixes, analyzeOwasp, askQuestion } from '../ai/analyzer.js';
import { getAiStatus } from '../ai/gemini-client.js';

function formatDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return '—';
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yyyy = d.getFullYear();
    const hh = String(d.getHours()).padStart(2, '0');
    const min = String(d.getMinutes()).padStart(2, '0');
    return `${dd}/${mm}/${yyyy} ${hh}:${min}`;
}

async function downloadReport(scanId, format) {
    try {
        const result = await exportReport(scanId, format);
        const blob = new Blob([typeof result === 'string' ? result : JSON.stringify(result, null, 2)], 
            { type: format === 'html' ? 'text/html' : 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sentry-report-${scanId.slice(0, 8)}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (err) {
        console.error('Download failed:', err);
    }
}

// Elements
const tabs = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const aiSetupBanner = document.getElementById('ai-setup-banner');
const contextSelector = document.getElementById('context-selector');
const chatArea = document.getElementById('chat-area');
const chatInput = document.getElementById('chat-input');
const btnSend = document.getElementById('btn-send');
const scanListContainer = document.getElementById('scan-list');

// Quick Actions
const btnExecSummary = document.getElementById('btn-exec-summary');
const btnPrioritize = document.getElementById('btn-prioritize');
const btnOwasp = document.getElementById('btn-owasp');

let activeScanInterval = null;
let currentScans = [];

// Markdown simple parser
function parseMarkdown(text) {
  if (!text) return '';
  let html = text;
  
  // Code blocks
  html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Bold
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Headings
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
  // Lists
  html = html.replace(/^\- (.*$)/gim, '<ul><li>$1</li></ul>');
  html = html.replace(/<\/ul>\n<ul>/g, '\n');
  // Paragraphs (simple)
  html = html.split('\n\n').map(p => {
    if (p.startsWith('<pre') || p.startsWith('<h') || p.startsWith('<ul')) return p;
    return `<p>${p}</p>`;
  }).join('');
  
  return html;
}

function scrollToBottom() {
  chatArea.scrollTop = chatArea.scrollHeight;
}

function appendUserMessage(text) {
  const div = document.createElement('div');
  div.className = 'message-bubble user';
  div.textContent = text;
  chatArea.appendChild(div);
  scrollToBottom();
}

function createAiMessage() {
  const div = document.createElement('div');
  div.className = 'message-bubble ai';
  
  const indicator = document.createElement('div');
  indicator.className = 'streaming-indicator';
  indicator.innerHTML = '<div class="dot"></div><div class="dot"></div><div class="dot"></div>';
  
  div.appendChild(indicator);
  chatArea.appendChild(div);
  scrollToBottom();
  
  let fullContent = '';
  
  return {
    update: (chunk) => {
      if (div.contains(indicator)) {
        div.removeChild(indicator);
      }
      fullContent += chunk;
      div.innerHTML = parseMarkdown(fullContent);
      scrollToBottom();
    },
    done: () => {
      if (div.contains(indicator)) {
        div.removeChild(indicator);
      }
      if (!fullContent) {
        div.innerHTML = '<em>Finished but no response received.</em>';
      }
      scrollToBottom();
    }
  };
}

// Init AI Tab
async function initAiTab() {
  const status = await getAiStatus();
  if (!status.configured) {
    aiSetupBanner.classList.remove('hidden');
  } else {
    aiSetupBanner.classList.add('hidden');
  }
  
  await populateContextSelector();
}

async function populateContextSelector() {
  try {
    const data = await listScans();
    currentScans = data.scans || [];
    const completedScans = currentScans.filter(s => s.status === 'completed');
    
    contextSelector.innerHTML = '<option value="">Select a scan to analyze...</option>';
    completedScans.forEach(scan => {
      const option = document.createElement('option');
      option.value = scan.scan_id;
      const date = formatDate(scan.created_at || Date.now());
      option.textContent = `${scan.target_url} (${date})`;
      contextSelector.appendChild(option);
    });
  } catch (e) {
    console.error("Failed to populate context selector", e);
  }
}

function getSelectedContext() {
  const val = contextSelector.value;
  if (!val) return null;
  return currentScans.find(s => s.scan_id === val);
}

// Actions
btnExecSummary.addEventListener('click', async () => {
  const ctx = getSelectedContext();
  if (!ctx) return alert("Please select a scan context first.");
  
  appendUserMessage("Generate an executive summary for this scan.");
  const aiMsg = createAiMessage();
  
  try {
    await analyzeFindings(ctx.report || {}, (chunk) => aiMsg.update(chunk));
    aiMsg.done();
  } catch (e) {
    aiMsg.update("\n\n**Error:** " + e.message);
    aiMsg.done();
  }
});

btnPrioritize.addEventListener('click', async () => {
  const ctx = getSelectedContext();
  if (!ctx) return alert("Please select a scan context first.");
  
  appendUserMessage("Prioritize the fixes for this scan.");
  const aiMsg = createAiMessage();
  
  try {
    await prioritizeFixes(ctx.report?.findings || [], ctx.report?.riskScore || 0, (chunk) => aiMsg.update(chunk));
    aiMsg.done();
  } catch (e) {
    aiMsg.update("\n\n**Error:** " + e.message);
    aiMsg.done();
  }
});

btnOwasp.addEventListener('click', async () => {
  const ctx = getSelectedContext();
  if (!ctx) return alert("Please select a scan context first.");
  
  appendUserMessage("Analyze OWASP coverage for this scan.");
  const aiMsg = createAiMessage();
  
  try {
    await analyzeOwasp(ctx.report?.owaspCoverage || {}, (chunk) => aiMsg.update(chunk));
    aiMsg.done();
  } catch (e) {
    aiMsg.update("\n\n**Error:** " + e.message);
    aiMsg.done();
  }
});

// Chat input handling
async function handleSend() {
  const text = chatInput.value.trim();
  if (!text) return;
  
  chatInput.value = '';
  chatInput.style.height = 'auto'; // reset height
  btnSend.disabled = true;
  
  appendUserMessage(text);
  const ctx = getSelectedContext();
  const aiMsg = createAiMessage();
  
  try {
    await askQuestion(text, ctx, (chunk) => aiMsg.update(chunk));
    aiMsg.done();
  } catch (e) {
    aiMsg.update("\n\n**Error:** " + e.message);
    aiMsg.done();
  } finally {
    btnSend.disabled = false;
  }
}

btnSend.addEventListener('click', handleSend);
chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    handleSend();
  }
});

chatInput.addEventListener('input', function() {
  this.style.height = 'auto';
  this.style.height = (this.scrollHeight) + 'px';
});



// Live Scans Tab
async function refreshLiveScans() {
  try {
    const data = await listScans();
    currentScans = data.scans || [];
    
    scanListContainer.innerHTML = '';
    
    if (!currentScans || currentScans.length === 0) {
      scanListContainer.innerHTML = '<div style="color:var(--text-secondary); text-align:center; padding:20px;">No scans found.</div>';
      return;
    }
    
    currentScans.forEach(scan => {
      const item = document.createElement('div');
      item.className = 'scan-list-item';
      
      const progressHtml = scan.status === 'completed' || scan.status === 'failed' ? '' : `
        <div class="scan-progress">
          <div class="scan-progress-bar" style="width: ${scan.progress || 0}%"></div>
        </div>
      `;
      
      const scoreHtml = scan.status === 'completed' && scan.risk_score !== undefined ? `
        <div class="risk-score">Risk: ${scan.risk_score}/100</div>
      ` : '<div></div>';
      
      const viewHtml = scan.status === 'completed' ? `
        <button class="btn-view" data-id="${scan.scan_id}">View Report</button>
        <button class="btn-download" data-id="${scan.scan_id}" data-format="html" title="Download HTML report">⬇ HTML</button>
        <button class="btn-download" data-id="${scan.scan_id}" data-format="json" title="Download JSON report">⬇ JSON</button>
      ` : '';
      
      item.innerHTML = `
        <div class="scan-header">
          <div class="scan-url" title="${scan.target_url}">${scan.target_url}</div>
          <div class="status-badge ${scan.status}">${scan.status}</div>
        </div>
        ${progressHtml}
        <div class="scan-footer">
          ${scoreHtml}
          <div class="scan-actions">
            ${viewHtml}
            <button class="btn-delete" data-id="${scan.scan_id}" title="Delete scan">✕</button>
          </div>
        </div>
      `;
      
      const viewBtn = item.querySelector('.btn-view');
      if (viewBtn) {
        viewBtn.addEventListener('click', () => {
          chrome.tabs.create({ url: chrome.runtime.getURL(`dashboard/dashboard.html?scan=${scan.scan_id}`) });
        });
      }

      const deleteBtn = item.querySelector('.btn-delete');
      if (deleteBtn) {
        deleteBtn.addEventListener('click', async () => {
          try {
            await deleteScan(scan.scan_id);
            refreshLiveScans();
          } catch (e) {
            console.error('Delete failed:', e);
          }
        });
      }

      const downloadBtns = item.querySelectorAll('.btn-download');
      downloadBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          const format = btn.getAttribute('data-format');
          downloadReport(scan.scan_id, format);
        });
      });
      
      scanListContainer.appendChild(item);
    });
    
  } catch (e) {
    console.error("Failed to list scans", e);
  }
}

// Tabs Logic
tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));
    
    tab.classList.add('active');
    const target = document.getElementById(`${tab.dataset.tab}-tab`);
    target.classList.add('active');
    
    if (tab.dataset.tab === 'live-scans') {
      refreshLiveScans();
      activeScanInterval = setInterval(refreshLiveScans, 8000);
    } else {
      if (activeScanInterval) clearInterval(activeScanInterval);
      populateContextSelector(); // Refresh dropdown
    }
  });
});

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  initAiTab();
});
