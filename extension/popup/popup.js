// popup.js
import * as apiClient from '../shared/api-client.js';

// DOM Elements
const loginSection = document.getElementById('login-section');
const mainSection = document.getElementById('main-section');
const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginError = document.getElementById('login-error');
const connectionStatusDot = document.getElementById('connection-status-dot');

const currentUrlDisplay = document.getElementById('current-url');
const modeBtns = document.querySelectorAll('.mode-btn');
const authCheckbox = document.getElementById('auth-checkbox');
const scanBtn = document.getElementById('scan-btn');
const scanError = document.getElementById('scan-error');

const progressSection = document.getElementById('scan-progress-section');
const progressStatusText = document.getElementById('progress-status-text');
const progressPercentage = document.getElementById('progress-percentage');
const progressBar = document.getElementById('progress-bar');

const quickResultsSection = document.getElementById('quick-results-section');
const gaugeFill = document.getElementById('gauge-fill');
const riskScoreDisplay = document.getElementById('risk-score');
const riskGradeDisplay = document.getElementById('risk-grade');
const severityBreakdown = document.getElementById('severity-breakdown');

const aiAnalyzeBtn = document.getElementById('ai-analyze-btn');
const viewReportBtn = document.getElementById('view-report-btn');
const recentScansList = document.getElementById('recent-scans-list');

const openDashboardLink = document.getElementById('open-dashboard-link');
const openSettingsLink = document.getElementById('open-settings-link');
const loggedInUserDisplay = document.getElementById('logged-in-user');

let currentTabUrl = '';
let selectedMode = 'passive';
let isScanning = false;
let pollingInterval = null;

// Initialization
async function init() {
    setupEventListeners();
    await checkAuthStatus();
    startHealthCheck();
}

async function checkAuthStatus() {
    try {
        const token = await apiClient.getToken();
        if (!token) {
            showLoginSection();
            return;
        }
        
        const response = await apiClient.verifyToken();
        if (response && response.username) {
            showMainSection({ username: response.username });
        } else {
            showLoginSection();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        showLoginSection();
    }
}

// UI State Management
function showLoginSection() {
    loginSection.classList.remove('hidden');
    mainSection.classList.add('hidden');
    loggedInUserDisplay.classList.add('hidden');
}

function showMainSection(user) {
    loginSection.classList.add('hidden');
    mainSection.classList.remove('hidden');
    
    if (user && user.username) {
        loggedInUserDisplay.textContent = user.username;
        loggedInUserDisplay.classList.remove('hidden');
    }

    getCurrentTab();
    loadRecentScans();
}

// Data Fetching
function getCurrentTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].url) {
            currentTabUrl = tabs[0].url;
            currentUrlDisplay.value = currentTabUrl;
            updateScanButtonState();
        }
    });
}

async function loadRecentScans() {
    try {
        const data = await apiClient.listScans();
        const scans = (data.scans || []).slice(0, 3);
        
        recentScansList.innerHTML = '';
        if (!scans.length) {
            recentScansList.innerHTML = '<li class="recent-scan-item" style="color:var(--text-muted);text-align:center;">No scans yet</li>';
            return;
        }
        scans.forEach(scan => {
            const li = document.createElement('li');
            li.className = 'recent-scan-item';
            
            let colorClass = 'success';
            const score = scan.risk_score || 0;
            if (score > 70) colorClass = 'critical';
            else if (score > 40) colorClass = 'high';
            else if (score > 20) colorClass = 'medium';

            const shortUrl = (scan.target_url || '—').substring(0, 35);
            li.innerHTML = `
                <div class="recent-scan-url" title="${scan.target_url}">${shortUrl}${(scan.target_url || '').length > 35 ? '…' : ''}</div>
                <div class="recent-scan-meta">
                    <span class="scan-badge ${scan.status}">${scan.status}</span>
                    ${scan.status === 'completed' ? `<span style="color: var(--${colorClass})">${score}</span>` : ''}
                </div>
            `;
            recentScansList.appendChild(li);
        });
    } catch (e) {
        recentScansList.innerHTML = '<li class="recent-scan-item" style="color:var(--text-muted);text-align:center;">Unable to load scans</li>';
    }
}

// Event Listeners
function setupEventListeners() {
    loginForm.addEventListener('submit', handleLogin);
    
    modeBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            if (isScanning) return;
            modeBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            selectedMode = e.target.dataset.mode;
        });
    });

    authCheckbox.addEventListener('change', updateScanButtonState);
    currentUrlDisplay.addEventListener('input', () => {
        currentTabUrl = currentUrlDisplay.value.trim();
        updateScanButtonState();
    });
    scanBtn.addEventListener('click', startScan);
    
    aiAnalyzeBtn.addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab) chrome.sidePanel.open({ tabId: tab.id });
    });

    viewReportBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD_REPORT' });
    });

    openDashboardLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD' });
    });

    openSettingsLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (chrome.runtime.openOptionsPage) {
            chrome.runtime.openOptionsPage();
        } else {
            window.open(chrome.runtime.getURL('options.html'));
        }
    });
}

function updateScanButtonState() {
    const url = currentUrlDisplay.value.trim();
    scanBtn.disabled = !authCheckbox.checked || !url || url.startsWith('chrome://');
}

// Actions
async function handleLogin(e) {
    e.preventDefault();
    loginError.classList.add('hidden');
    const btn = loginForm.querySelector('button');
    btn.disabled = true;
    btn.textContent = 'Authenticating...';

    try {
        const username = usernameInput.value;
        const password = passwordInput.value;
        
        const result = await apiClient.login(username, password);
        
        if (result && result.token) {
            chrome.storage.local.set({ mapper_user: result.username || username });
            showMainSection({ username: result.username || username });
        } else {
            throw new Error('Invalid credentials');
        }
    } catch (error) {
        loginError.textContent = error.message || 'Login failed';
        loginError.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Sign In';
    }
}

function startScan() {
    currentTabUrl = currentUrlDisplay.value.trim();
    if (!currentTabUrl || !authCheckbox.checked) return;
    
    isScanning = true;
    scanBtn.disabled = true;
    authCheckbox.disabled = true;
    modeBtns.forEach(b => b.disabled = true);
    
    quickResultsSection.classList.add('hidden');
    progressSection.classList.remove('hidden');
    scanError.classList.add('hidden');
    
    progressBar.style.width = '5%';
    progressStatusText.textContent = 'Submitting...';
    progressPercentage.textContent = '5%';

    // Submit scan via API client
    apiClient.submitScan(currentTabUrl, {
        authorized: true,
        scan_mode: selectedMode,
        deep_scan: true,
        check_headers: true,
        check_tls: true,
    }).then(response => {
        if (response && response.scan_id) {
            pollScanStatus(response.scan_id);
        } else {
            handleScanError('Failed to start scan');
        }
    }).catch(err => {
        handleScanError(err.message || 'Failed to submit scan');
    });
}

function pollScanStatus(scanId) {
    pollingInterval = setInterval(async () => {
        try {
            const data = await apiClient.getScanStatus(scanId);
            const scan = data.scan;
            const pct = scan.progress || 0;

            progressBar.style.width = `${pct}%`;
            progressPercentage.textContent = `${pct}%`;
            progressStatusText.textContent = scan.status;

            if (scan.status === 'completed' || scan.status === 'failed') {
                clearInterval(pollingInterval);
                
                if (scan.status === 'completed') {
                    // Fetch the report for quick results
                    try {
                        const reportData = await apiClient.getScanReport(scanId);
                        if (reportData.report) {
                            finishScan(reportData.report);
                        } else {
                            finishScan({ risk_score: scan.risk_score || 0, risk_grade: scan.risk_grade || 'N/A', severity_breakdown: {} });
                        }
                    } catch {
                        finishScan({ risk_score: scan.risk_score || 0, risk_grade: scan.risk_grade || 'N/A', severity_breakdown: {} });
                    }
                } else {
                    handleScanError('Scan failed: ' + (scan.error || 'Unknown error'));
                }
            }
        } catch (err) {
            // Keep polling on transient errors
        }
    }, 2000);
}

function finishScan(report) {
    isScanning = false;
    scanBtn.disabled = false;
    authCheckbox.disabled = false;
    modeBtns.forEach(b => b.disabled = false);
    authCheckbox.checked = false;
    updateScanButtonState();
    
    setTimeout(() => {
        progressSection.classList.add('hidden');
        renderGauge(report.risk_score || 0, report.risk_grade || 'N/A');
        renderSeverityBreakdown(report.severity_breakdown || {});
        quickResultsSection.classList.remove('hidden');
        loadRecentScans();
    }, 500);
}

function handleScanError(errMessage) {
    isScanning = false;
    scanBtn.disabled = false;
    authCheckbox.disabled = false;
    modeBtns.forEach(b => b.disabled = false);
    
    progressSection.classList.add('hidden');
    scanError.textContent = errMessage;
    scanError.classList.remove('hidden');
}

// Result Rendering

function renderGauge(score, grade) {
    riskScoreDisplay.textContent = score;
    riskGradeDisplay.textContent = `Grade ${grade}`;
    
    // Set color based on score
    let color = 'var(--success)';
    if (score > 75) color = 'var(--critical)';
    else if (score > 50) color = 'var(--high)';
    else if (score > 25) color = 'var(--medium)';
    
    riskScoreDisplay.style.color = color;
    gaugeFill.style.stroke = color;
    
    // Animate gauge (total length is roughly 125)
    // 0 score = offset 125, 100 score = offset 0
    setTimeout(() => {
        const offset = 125 - (score / 100) * 125;
        gaugeFill.style.strokeDashoffset = offset;
    }, 100);
}

function renderSeverityBreakdown(breakdown) {
    severityBreakdown.innerHTML = '';
    const severities = [
        { key: 'critical', label: 'CRIT', color: 'var(--critical)' },
        { key: 'high', label: 'HIGH', color: 'var(--high)' },
        { key: 'medium', label: 'MED', color: 'var(--medium)' },
        { key: 'low', label: 'LOW', color: 'var(--low)' },
        { key: 'info', label: 'INFO', color: 'var(--info)' }
    ];
    
    severities.forEach(sev => {
        const count = breakdown[sev.key] || 0;
        const div = document.createElement('div');
        div.className = 'severity-mini';
        div.innerHTML = `
            <span class="count" style="color: ${count > 0 ? sev.color : 'var(--text-muted)'}">${count}</span>
            <span class="label">${sev.label}</span>
        `;
        severityBreakdown.appendChild(div);
    });
}

// Health Check
function startHealthCheck() {
    checkHealth();
    setInterval(checkHealth, 10000);
}

async function checkHealth() {
    try {
        const result = await apiClient.healthCheck();
        const isHealthy = result && result.status === 'ok';
        
        if (isHealthy) {
            connectionStatusDot.classList.remove('disconnected');
            connectionStatusDot.classList.add('connected');
            connectionStatusDot.parentElement.title = 'Backend Connected';
        } else {
            connectionStatusDot.classList.add('disconnected');
            connectionStatusDot.classList.remove('connected');
            connectionStatusDot.parentElement.title = 'Backend Disconnected';
        }
    } catch (e) {
        connectionStatusDot.classList.add('disconnected');
        connectionStatusDot.classList.remove('connected');
        connectionStatusDot.parentElement.title = 'Backend Disconnected';
    }
}

document.addEventListener('DOMContentLoaded', init);
