// @ts-check
import * as apiClient from '../shared/api-client.js';
import { getAiStatus } from '../ai/gemini-client.js';

// Configuration Defaults
const DEFAULT_SETTINGS = {
    backendUrl: 'http://127.0.0.1:5001',
    defaultScanMode: 'passive',
    rateLimit: 10,
    autoScan: false,
    notifyCompletion: true,
    showBadge: true
};

// DOM Elements
const elements = {
    backendUrl: /** @type {HTMLInputElement} */ (document.getElementById('backend-url')),
    testConnectionBtn: /** @type {HTMLButtonElement} */ (document.getElementById('test-connection-btn')),
    connectionStatus: document.getElementById('connection-status'),
    backendDetails: document.getElementById('backend-details'),
    rulesCount: document.getElementById('rules-count'),
    esStatus: document.getElementById('es-status'),

    aiStatus: document.getElementById('ai-status'),
    aiModelBadge: document.getElementById('ai-model-badge'),

    defaultScanMode: /** @type {HTMLSelectElement} */ (document.getElementById('default-scan-mode')),
    rateLimit: /** @type {HTMLInputElement} */ (document.getElementById('rate-limit')),
    autoScan: /** @type {HTMLInputElement} */ (document.getElementById('auto-scan')),
    
    notifyCompletion: /** @type {HTMLInputElement} */ (document.getElementById('notify-completion')),
    showBadge: /** @type {HTMLInputElement} */ (document.getElementById('show-badge')),

    authLoggedIn: document.getElementById('auth-logged-in'),
    authLoggedOut: document.getElementById('auth-logged-out'),
    currentUsername: document.getElementById('current-username'),
    logoutBtn: /** @type {HTMLButtonElement} */ (document.getElementById('logout-btn')),
    loginForm: /** @type {HTMLFormElement} */ (document.getElementById('login-form')),
    loginUsername: /** @type {HTMLInputElement} */ (document.getElementById('login-username')),
    loginPassword: /** @type {HTMLInputElement} */ (document.getElementById('login-password')),
    loginError: document.getElementById('login-error'),
    
    extensionVersion: document.getElementById('extension-version')
};

let saveTimeout;

/**
 * Initialize Options Page
 */
async function init() {
    // Set version
    const manifest = chrome.runtime.getManifest();
    if (elements.extensionVersion && manifest.version) {
        elements.extensionVersion.textContent = manifest.version;
    }

    await loadSettings();
    attachEventListeners();
    
    // Initial checks
    checkConnection();
    checkAuthStatus();
    checkAiStatus();
}

/**
 * Load settings from storage
 */
async function loadSettings() {
    return new Promise((resolve) => {
        chrome.storage.sync.get(DEFAULT_SETTINGS, (syncItems) => {
            elements.backendUrl.value = syncItems.backendUrl;
            elements.defaultScanMode.value = syncItems.defaultScanMode;
            elements.rateLimit.value = syncItems.rateLimit.toString();
            elements.autoScan.checked = syncItems.autoScan;
            elements.notifyCompletion.checked = syncItems.notifyCompletion;
            elements.showBadge.checked = syncItems.showBadge;
            resolve(null);
        });
    });
}

/**
 * Save settings to storage with debounce
 */
function debouncedSave() {
    clearTimeout(saveTimeout);
    saveTimeout = setTimeout(saveSettings, 500);
}

async function saveSettings() {
    const syncSettings = {
        backendUrl: elements.backendUrl.value,
        defaultScanMode: elements.defaultScanMode.value,
        rateLimit: parseInt(elements.rateLimit.value, 10),
        autoScan: elements.autoScan.checked,
        notifyCompletion: elements.notifyCompletion.checked,
        showBadge: elements.showBadge.checked
    };

    // Also save backendUrl to local storage for the API client
    chrome.storage.local.set({ backendUrl: elements.backendUrl.value });

    chrome.storage.sync.set(syncSettings, () => {
        console.log('Settings saved');
    });
}

/**
 * Attach UI event listeners
 */
function attachEventListeners() {
    const inputs = [
        elements.backendUrl, elements.defaultScanMode, elements.rateLimit,
        elements.autoScan, elements.notifyCompletion, elements.showBadge,
    ];

    inputs.forEach(input => {
        input.addEventListener('change', debouncedSave);
        if (input.type === 'text' || input.type === 'number') {
            input.addEventListener('input', debouncedSave);
        }
    });

    elements.testConnectionBtn.addEventListener('click', checkConnection);
    
    // Auth actions
    elements.loginForm.addEventListener('submit', handleLogin);
    elements.logoutBtn.addEventListener('click', handleLogout);
}

/**
 * Test Connection to Backend
 */
async function checkConnection() {
    elements.testConnectionBtn.disabled = true;
    elements.testConnectionBtn.textContent = 'Testing...';
    
    setIndicatorStatus(elements.connectionStatus, 'yellow', 'Connecting...');
    
    try {
        const health = await apiClient.healthCheck();
        
        if (health && health.status === 'ok') {
            setIndicatorStatus(elements.connectionStatus, 'green', 'Connected');
            
            if (elements.backendDetails) {
                elements.backendDetails.classList.remove('hidden');
                if (elements.rulesCount) elements.rulesCount.textContent = health.rules_loaded || 'N/A';
                if (elements.esStatus) elements.esStatus.textContent = health.elasticsearch || 'N/A';
            }
        } else {
            throw new Error('Invalid response');
        }
    } catch (error) {
        setIndicatorStatus(elements.connectionStatus, 'red', 'Disconnected');
        if (elements.backendDetails) {
            elements.backendDetails.classList.add('hidden');
        }
    } finally {
        elements.testConnectionBtn.disabled = false;
        elements.testConnectionBtn.textContent = 'Test Connection';
    }
}

/**
 * Check AI status from backend (no user config needed)
 */
async function checkAiStatus() {
    setIndicatorStatus(elements.aiStatus, 'yellow', 'Checking...');
    
    try {
        const status = await getAiStatus();
        
        if (status.configured) {
            setIndicatorStatus(elements.aiStatus, 'green', 'Active');
            if (elements.aiModelBadge) {
                // Show correct provider name from backend
                const providerName = status.provider === 'groq' ? '⚡ Groq'
                    : status.provider === 'gemini' ? '✦ Gemini'
                    : '🤖 OpenAI';
                const modelShort = (status.model || '').split('/').pop() || status.model || '';
                elements.aiModelBadge.textContent = `${providerName} · ${modelShort}`;
            }
        } else {
            setIndicatorStatus(elements.aiStatus, 'red', 'Not Available');
            if (elements.aiModelBadge) elements.aiModelBadge.textContent = 'AI Not Configured';
        }
    } catch {
        setIndicatorStatus(elements.aiStatus, 'red', 'Unable to check');
    }
}

/**
 * Update UI Status Indicators
 */
function setIndicatorStatus(container, color, text) {
    if (!container) return;
    const dot = container.querySelector('.dot');
    const statusText = container.querySelector('.status-text');
    
    if (dot) {
        dot.className = `dot ${color}`;
    }
    if (statusText) {
        statusText.textContent = text;
    }
}

/**
 * Authentication: Check Status
 */
async function checkAuthStatus() {
    try {
        const token = await apiClient.getToken();
        if (!token) {
            showLoggedOut();
            return;
        }
        
        const res = await apiClient.verifyToken();
        if (res && res.username) {
            showLoggedIn(res.username);
        } else {
            showLoggedOut();
        }
    } catch {
        showLoggedOut();
    }
}

function showLoggedIn(username) {
    if (elements.authLoggedIn) elements.authLoggedIn.classList.remove('hidden');
    if (elements.authLoggedOut) elements.authLoggedOut.classList.add('hidden');
    if (elements.currentUsername) elements.currentUsername.textContent = username;
}

function showLoggedOut() {
    if (elements.authLoggedIn) elements.authLoggedIn.classList.add('hidden');
    if (elements.authLoggedOut) elements.authLoggedOut.classList.remove('hidden');
}

/**
 * Authentication: Login
 */
async function handleLogin(e) {
    e.preventDefault();
    if (elements.loginError) elements.loginError.classList.add('hidden');
    
    const btn = elements.loginForm.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
        const result = await apiClient.login(
            elements.loginUsername.value,
            elements.loginPassword.value
        );
        
        if (result && result.token) {
            showLoggedIn(result.username || elements.loginUsername.value);
        } else {
            throw new Error('Invalid credentials');
        }
    } catch (error) {
        if (elements.loginError) {
            elements.loginError.textContent = error.message || 'Login failed';
            elements.loginError.classList.remove('hidden');
        }
    } finally {
        btn.disabled = false;
        btn.textContent = 'Login';
    }
}

/**
 * Authentication: Logout
 */
async function handleLogout() {
    try {
        await apiClient.logout();
    } catch {}
    showLoggedOut();
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', init);
