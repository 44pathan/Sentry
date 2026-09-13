import * as api from '../shared/api-client.js';

// Setup defaults on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['backendUrl'], (result) => {
    if (!result.backendUrl) {
      chrome.storage.local.set({ backendUrl: 'http://127.0.0.1:5001' });
    }
  });
});

// Allow side panel to open on action click
if (chrome.sidePanel) {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false })
    .catch((error) => console.error(error));
}

// Active scan polling state
const activePolls = new Map();

// Message routing
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch((error) => {
    sendResponse({ error: error.message });
  });
  return true; // Keep the message channel open for async response
});

async function handleMessage(message, sender) {
  switch (message.type) {
    case 'SUBMIT_SCAN':
      return handleSubmitScan(message);
    case 'GET_SCAN_STATUS':
      return api.getScanStatus(message.scanId);
    case 'LOGIN':
      return api.login(message.username, message.password);
    case 'LOGOUT':
      return api.logout();
    case 'CHECK_AUTH':
      return handleCheckAuth();
    case 'OPEN_DASHBOARD':
      return openDashboard();
    case 'OPEN_DASHBOARD_REPORT':
      return openDashboard(`?scan=${message.scanId}`);
    default:
      throw new Error(`Unknown message type: ${message.type}`);
  }
}

async function handleCheckAuth() {
  try {
    const token = await api.getToken();
    if (!token) return { authenticated: false };
    const result = await api.verifyToken();
    return { authenticated: true, user: { username: result.username } };
  } catch {
    return { authenticated: false };
  }
}

async function handleSubmitScan(message) {
  try {
    const data = await api.submitScan(message.url, message.options);
    if (data && data.scan_id) {
      startPolling(data.scan_id);

      // Store in session storage
      const session = await chrome.storage.session.get(['activeScans']);
      const activeScans = session.activeScans || [];
      if (!activeScans.includes(data.scan_id)) {
        activeScans.push(data.scan_id);
        await chrome.storage.session.set({ activeScans });
      }
    }
    return data;
  } catch (err) {
    console.error('Scan submission failed:', err);
    throw err;
  }
}

function startPolling(scanId) {
  if (activePolls.has(scanId)) return;

  const pollInterval = setInterval(async () => {
    try {
      const statusData = await api.getScanStatus(scanId);
      const scan = statusData.scan || statusData;

      if (scan.status === 'completed' || scan.status === 'failed') {
        stopPolling(scanId);

        if (scan.status === 'completed') {
          handleScanCompletion(scanId, scan);
        }
      }
    } catch (err) {
      console.error(`Error polling scan ${scanId}:`, err);
    }
  }, 2000);

  activePolls.set(scanId, pollInterval);
}

function stopPolling(scanId) {
  const intervalId = activePolls.get(scanId);
  if (intervalId) {
    clearInterval(intervalId);
    activePolls.delete(scanId);
  }
}

function handleScanCompletion(scanId, scan) {
  const grade = scan.risk_grade || 'F';
  let color = '#777777';

  if (['A+', 'A', 'A-'].includes(grade)) color = '#4caf50';
  else if (['B+', 'B', 'B-'].includes(grade)) color = '#eab308';
  else if (['C+', 'C', 'C-'].includes(grade)) color = '#ff9800';
  else color = '#ff3b3b';

  chrome.action.setBadgeText({ text: grade });
  chrome.action.setBadgeBackgroundColor({ color });

  chrome.notifications.create(`scan_complete_${scanId}`, {
    type: 'basic',
    iconUrl: '../icons/icon-128.png',
    title: 'Sentry — Scan Completed',
    message: `Scan for ${scan.target_url || 'target'} completed with grade ${grade}.`,
  });
}

// Notification click listener
chrome.notifications.onClicked.addListener((notificationId) => {
  if (notificationId.startsWith('scan_complete_')) {
    const scanId = notificationId.replace('scan_complete_', '');
    openDashboard(`?scan=${scanId}`);
    chrome.notifications.clear(notificationId);
  }
});

function openDashboard(query = '') {
  // Open the extension's own dashboard page, NOT the backend URL
  const url = chrome.runtime.getURL(`dashboard/dashboard.html${query}`);
  chrome.tabs.create({ url });
  return { success: true };
}
