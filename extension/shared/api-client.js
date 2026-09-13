export async function getBackendUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['backendUrl'], (result) => {
      resolve(result.backendUrl || 'http://127.0.0.1:5001');
    });
  });
}

export async function getToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['jwtToken'], (result) => {
      resolve(result.jwtToken || null);
    });
  });
}

export async function setToken(token) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ jwtToken: token }, () => {
      resolve();
    });
  });
}

export async function clearToken() {
  return new Promise((resolve) => {
    chrome.storage.local.remove(['jwtToken'], () => {
      resolve();
    });
  });
}

export async function api(method, path, body = null, auth = true) {
  const baseUrl = await getBackendUrl();
  const url = `${baseUrl}${path}`;
  
  const headers = {
    'Content-Type': 'application/json'
  };

  if (auth) {
    const token = await getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  const options = {
    method,
    headers,
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  
  if (!response.ok) {
    let errorMsg = response.statusText;
    try {
      const errorData = await response.json();
      errorMsg = errorData.error || errorData.message || errorMsg;
    } catch (e) {}
    throw new Error(errorMsg);
  }

  return response.json();
}

// Authentication
export async function login(username, password) {
  const data = await api('POST', '/api/auth/login', { username, password }, false);
  if (data && data.token) {
    await setToken(data.token);
  }
  return data;
}

export async function verifyToken() {
  return api('GET', '/api/auth/verify');
}

export async function logout() {
  try {
    await api('POST', '/api/auth/logout');
  } catch (e) {
    console.error('Logout error:', e);
  } finally {
    await clearToken();
  }
}

// Scanning Operations
export async function submitScan(url, options = {}) {
  return api('POST', '/api/scan', { url, ...options });
}

export async function getScanStatus(scanId) {
  return api('GET', `/api/scan/${scanId}`);
}

export async function getScanReport(scanId) {
  return api('GET', `/api/scan/${scanId}/report`);
}

export async function listScans() {
  return api('GET', '/api/scans');
}

export async function deleteScan(scanId) {
  return api('DELETE', `/api/scan/${scanId}`);
}

// Stats & Rules
export async function getStats() {
  return api('GET', '/api/stats');
}

export async function getRules() {
  return api('GET', '/api/rules');
}

export async function reloadRules() {
  return api('POST', '/api/rules/reload');
}

// Reporting
export async function exportReport(scanId, format = 'json') {
  const baseUrl = await getBackendUrl();
  const token = await getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  
  const res = await fetch(`${baseUrl}/api/scan/${scanId}/export?format=${format}`, { headers });
  if (!res.ok) throw new Error(`Export failed: ${res.statusText}`);
  
  if (format === 'html') {
    return res.text();
  }
  return res.json();
}

// Health Check
export async function healthCheck() {
  return api('GET', '/api/health', null, false);
}

// ── Namespace Export ──────────────────────────────────────
// Used by dashboard.js which expects an APIClient object with a request() method
export const APIClient = {
  async request(path, method = 'GET', body = null, auth = true) {
    return api(method, `/api${path}`, body, auth);
  },
  getToken,
  setToken,
  clearToken,
  getBackendUrl,
};

