/**
 * cveResponderAI - Application JavaScript
 * Handles page interactions, API communication, and LLM analysis
 */

// ===================================
// Configuration
// ===================================

const API_BASE = (typeof window !== 'undefined' && window.location.origin && window.location.origin.startsWith('http'))
    ? window.location.origin
    : 'http://localhost:5001';
const MODEL_STORAGE_KEY = 'cve-analyzer-model';
const TOTAL_ANALYSES_KEY = 'cve-analyzer-total-count';

const CVE_PATTERN = /^CVE-(1999|20\d{2})-\d{4,}$/i;
const CVE_PARTIAL = /^(\d{4})-(\d{4,})$/;

function normalizeCveId(raw) {
    const s = (raw || '').trim().toUpperCase();
    if (!s) return '';
    if (s.startsWith('CVE-')) return s;
    const m = s.match(CVE_PARTIAL);
    if (m) return `CVE-${m[1]}-${m[2]}`;
    return `CVE-${s}`;
}

function validateCveFormat(raw) {
    const s = (raw || '').trim();
    if (!s) return { valid: false, error: 'CVE ID is required.', normalized: '' };
    const normalized = normalizeCveId(s);
    if (!CVE_PATTERN.test(normalized)) {
        return { valid: false, error: `Invalid CVE format. Use CVE-YYYY-NNNNN (e.g. CVE-2024-3094). You entered: ${s.substring(0, 50)}`, normalized: '' };
    }
    return { valid: true, error: '', normalized };
}

let currentModel = localStorage.getItem(MODEL_STORAGE_KEY) || '';
let availableModels = [];

// ===================================
// Theme Management
// ===================================

function initTheme() {
    // Get saved theme or default to dark
    const savedTheme = localStorage.getItem('cve-analyzer-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);

    // Add event listener to theme toggle button
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('cve-analyzer-theme', newTheme);
    updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
    const themeIcon = document.getElementById('theme-icon');
    if (themeIcon) {
        // Show sun icon in dark mode (to switch to light)
        // Show moon icon in light mode (to switch to dark)
        themeIcon.textContent = theme === 'dark' ? 'light_mode' : 'dark_mode';
    }
}


// ===================================
// API Service
// ===================================

const ApiService = {
    async checkHealth() {
        try {
            const response = await fetch(`${API_BASE}/api/health`);
            return await response.json();
        } catch (error) {
            return { status: 'error', ollama: 'disconnected', error: error.message };
        }
    },

    async getModels() {
        try {
            const response = await fetch(`${API_BASE}/api/models`);
            const data = await response.json();

            availableModels = data.models || [];

            // User chooses model: use saved if still in list, otherwise first available
            const saved = localStorage.getItem(MODEL_STORAGE_KEY);
            if (saved && availableModels.some(m => m.name === saved)) {
                currentModel = saved;
            } else if (availableModels.length > 0) {
                currentModel = availableModels[0].name;
            }

            return { ...data, models: availableModels };
        } catch (error) {
            console.error('Failed to fetch models:', error);
            return { models: [], error: error.message };
        }
    },

    async fetchCVE(cveId) {
        const response = await fetch(`${API_BASE}/api/fetch-cve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cveId })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || 'CVE fetch failed');
        }
        return await response.json();
    },

    async warmup(model = currentModel) {
        const response = await fetch(`${API_BASE}/api/warmup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model })
        });
        if (!response.ok) return;
        return response.json();
    },

    async fetchIRPlan(cveData, model = currentModel, pocStatus = null, mitreTechniques = null, newsContext = null) {
        const response = await fetch(`${API_BASE}/api/ir-plan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cveData, model, pocStatus, mitreTechniques, newsContext })
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || 'IR Plan failed');
        }
        return response.json();
    },

    async mapMitre(cveData, model = currentModel, _unused = null, pocStatus = null, newsContext = null) {
        const response = await fetch(`${API_BASE}/api/map-mitre`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cveData, model, pocStatus, newsContext })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || 'MITRE mapping failed');
        }
        return await response.json();
    },

    async searchPoc(cveId) {
        const response = await fetch(`${API_BASE}/api/search-poc`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cveId })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || 'PoC search failed');
        }
        return await response.json();
    },

    async searchNews(cveId, limitPerSource = 3) {
        const response = await fetch(`${API_BASE}/api/search-news`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cveId, limitPerSource })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || 'News search failed');
        }
        return await response.json();
    },

    async fetchRepoFile(fullName) {
        const response = await fetch(`${API_BASE}/api/repo-file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ full_name: fullName })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || 'Could not load file from GitHub');
        }
        return data;
    },

    async analyzeExploit(code, cveData, model = currentModel) {
        const response = await fetch(`${API_BASE}/api/analyze-exploit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, cveData, model })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || 'Exploit analysis failed');
        }
        return await response.json();
    },


};

// ===================================
// Model Selector UI
// ===================================

function initModelSelector() {
    const toggle = document.getElementById('model-selector-toggle');
    const dropdown = document.getElementById('model-dropdown');

    if (!toggle || !dropdown) return;

    // Toggle dropdown open/close
    toggle.addEventListener('click', (e) => {
        e.stopPropagation();
        if (dropdown.style.display === 'none' || dropdown.style.display === '') {
            renderModelDropdown();
            dropdown.style.display = 'block';
        } else {
            dropdown.style.display = 'none';
        }
    });

    // Close when clicking outside
    document.addEventListener('click', () => {
        if (dropdown) dropdown.style.display = 'none';
    });

    // Prevent closing when clicking inside dropdown
    dropdown.addEventListener('click', (e) => e.stopPropagation());
}

function renderModelDropdown() {
    const dropdown = document.getElementById('model-dropdown');
    if (!dropdown) return;

    if (!availableModels || availableModels.length === 0) {
        dropdown.innerHTML = '<div class="model-option" style="opacity:0.7;">No local models found</div>';
        return;
    }

    const bytesToGB = (bytes) => {
        if (!bytes) return '';
        const gb = bytes / (1024 * 1024 * 1024);
        return `${gb.toFixed(1)} GB`;
    };

    dropdown.innerHTML = availableModels.map(model => {
        const isActive = model.name === currentModel;
        return `
            <div class="model-option ${isActive ? 'active' : ''}" data-model="${model.name}">
                <span>${formatModelName(model.name)}</span>
                <small>${bytesToGB(model.size)}</small>
            </div>
        `;
    }).join('');

    dropdown.querySelectorAll('.model-option').forEach(opt => {
        const modelName = opt.getAttribute('data-model');
        if (!modelName) return;

        opt.addEventListener('click', () => {
            setCurrentModel(modelName);
            dropdown.style.display = 'none';
        });
    });
}

function setCurrentModel(modelName) {
    currentModel = modelName;
    try {
        localStorage.setItem(MODEL_STORAGE_KEY, modelName);
    } catch (e) {
        console.warn('Failed to persist model selection:', e);
    }

    const dashboardName = document.getElementById('current-model-name');
    if (dashboardName) {
        dashboardName.textContent = formatModelName(modelName);
    }

    const workflowName = document.getElementById('workflow-model-name');
    if (workflowName) {
        workflowName.textContent = `Model: ${formatModelName(modelName)}`;
    }
}

// ===================================
// Utility Functions
// ===================================

function getUrlParameter(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

function getSeverityFromScore(score) {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
}

function getSeverityClass(severity) {
    const map = {
        'critical': 'badge-critical',
        'high': 'badge-high',
        'medium': 'badge-medium',
        'low': 'badge-low',
        'CRITICAL': 'badge-critical',
        'HIGH': 'badge-high',
        'MEDIUM': 'badge-medium',
        'LOW': 'badge-low'
    };
    return map[severity] || 'badge-medium';
}


function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    } catch {
        return dateString;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===================================
// Markdown Renderer (simple)
// ===================================

function renderMarkdown(text) {
    if (!text) return '';

    // Safety check: If 'text' is an array (common with some models like Qwen), join it
    if (Array.isArray(text)) {
        text = text.join('\n');
    }

    // Ensure it's a string
    text = String(text);

    // Pre-clean: replace <br> tags with newlines, strip stray HTML
    let cleaned = text.replace(/<br\s*\/?>/gi, '\n');
    cleaned = cleaned.replace(/<\/?(?:b|strong|em|i|code|u|span)[^>]*>/gi, '');

    // Normalize bullet prefixes before escaping:
    // Convert * , •, –, —, ▪, ▸, ►, ➤, ➜ to standard "- "
    cleaned = cleaned.replace(/^[*•–—▪▸►➤➜]\s+/gm, '- ');
    // Convert numbered lists: "1. ", "1) ", "1] " (with optional bold **1.** )
    cleaned = cleaned.replace(/^\*{0,2}\d+[.):\]]\*{0,2}\s+/gm, '- ');

    let html = escapeHtml(cleaned);

    // Headers
    html = html.replace(/^## (.+)$/gm, '<h3 class="analysis-h2">$1</h3>');
    html = html.replace(/^### (.+)$/gm, '<h4 class="analysis-h3">$1</h4>');
    html = html.replace(/^# (.+)$/gm, '<h2 class="analysis-h1">$1</h2>');

    // Bold
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

    // Italic  
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

    // Unordered lists: convert runs of "- item" into <ul>
    html = html.replace(/(?:^- (.+)$\n?)+/gm, (match) => {
        const items = match.trim().split('\n').map(line =>
            '<li>' + line.replace(/^- /, '') + '</li>'
        ).join('');
        return '<ul class="analysis-list">' + items + '</ul>';
    });

    // Ordered lists: convert runs of "1. item" into <ol> (fallback if any still exist)
    html = html.replace(/(?:^\d+\. (.+)$\n?)+/gm, (match) => {
        const items = match.trim().split('\n').map(line =>
            '<li>' + line.replace(/^\d+\.\s*/, '') + '</li>'
        ).join('');
        return '<ol class="analysis-list">' + items + '</ol>';
    });

    // Line breaks to paragraphs
    html = html.split('\n\n').map(para => {
        if (para.startsWith('<h') || para.startsWith('<ul') || para.startsWith('<ol') || para.startsWith('<li')) {
            return para;
        }
        return `<p>${para}</p>`;
    }).join('');

    return html;
}


// ===================================
// Dashboard Page Functions
// ===================================

function initDashboard() {
    const searchForm = document.getElementById('cve-search-form');

    if (searchForm) {
        searchForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const cveInput = document.getElementById('cve-input');
            const errEl = document.getElementById('cve-format-error');
            const cveId = cveInput.value.trim();

            if (errEl) errEl.style.display = 'none';
            if (!cveId) return;

            const { valid, error, normalized } = validateCveFormat(cveId);
            if (!valid) {
                if (errEl) {
                    errEl.textContent = error;
                    errEl.style.display = 'block';
                }
                cveInput.focus();
                return;
            }
            window.location.href = `workflow.html?cve=${encodeURIComponent(normalized)}`;
        });
    }

    // FAB click handler
    const fab = document.getElementById('fab');
    if (fab) {
        fab.addEventListener('click', function () {
            document.getElementById('cve-input').focus();
        });
    }

    // Initialize theme
    initTheme();

    // Check backend status and load model name
    checkBackendStatus();
    fetchAndDisplayModel().then(() => {
        initModelSelector();
    });

    // Populate live stat cards
    updateTotalAnalysesStat();

    // Render dynamic recent analyses
    renderRecentAnalyses();
}

async function fetchAndDisplayModel() {
    try {
        await ApiService.getModels();
        setCurrentModel(currentModel);
        updateActiveModelsStat(availableModels.length);
    } catch (error) {
        console.error('Failed to fetch model:', error);
        const modelNameEl = document.getElementById('current-model-name');
        if (modelNameEl) modelNameEl.textContent = 'Unknown';
        updateActiveModelsStat(0);
    }
}

function updateActiveModelsStat(count) {
    const countEl = document.getElementById('stat-active-models');
    const totalEl = document.getElementById('stat-total-models');
    if (!countEl) return;

    if (count === 0) {
        countEl.textContent = '0';
        if (totalEl) totalEl.textContent = ' offline';
        countEl.style.color = 'var(--text-muted)';
    } else {
        countEl.textContent = count;
        if (totalEl) totalEl.textContent = ` loaded`;
        countEl.style.color = '';
    }
}

function formatModelName(modelName) {
    // Format model names for better display
    const modelMap = {
        'mistral': 'Mistral',
        'qwen3': 'Qwen3',
        'llama3.1': 'Llama 3.1',
        'llama3': 'Llama 3',
        'gemma': 'Gemma'
    };

    return modelMap[modelName] || modelName.charAt(0).toUpperCase() + modelName.slice(1);
}


async function checkBackendStatus() {
    const health = await ApiService.checkHealth();
    const badge = document.querySelector('.hero-badge');

    if (badge) {
        if (health.status === 'running' && health.ollama === 'connected') {
            badge.innerHTML = `
                <span class="pulse-indicator">
                    <span class="ring"></span>
                    <span class="dot"></span>
                </span>
                Local AI Engine Active
            `;
            badge.style.borderColor = 'rgba(0, 221, 255, 0.2)';
        } else if (health.status === 'running') {
            badge.innerHTML = `
                <span class="material-symbols-outlined" style="font-size: 14px; color: #facc15;">warning</span>
                Ollama Disconnected
            `;
            badge.style.borderColor = 'rgba(234, 179, 8, 0.3)';
            badge.style.background = 'rgba(234, 179, 8, 0.1)';
            badge.style.color = '#facc15';
        } else {
            badge.innerHTML = `
                <span class="material-symbols-outlined" style="font-size: 14px; color: #ef4444;">error</span>
                Backend Offline
            `;
            badge.style.borderColor = 'rgba(239, 68, 68, 0.3)';
            badge.style.background = 'rgba(239, 68, 68, 0.1)';
            badge.style.color = '#f87171';
        }
    }
}

// ===================================
// Recent Analyses History (Dashboard)
// ===================================

// Default CVEs chosen to showcase all tool features: CISA KEV, PoC Explainer, Affected/Inventory, IR Plan, MITRE
const DEFAULT_HISTORY = [
    {
        cveId: "CVE-2021-44228",
        severity: "CRITICAL",
        title: "Log4Shell RCE in Apache Log4j 2",
        description: "Critical RCE in Apache Log4j 2; massive global impact; public PoCs — perfect for deep analysis and IR planning.",
        timestamp: new Date().getTime() - 120000
    },
    {
        cveId: "CVE-2024-3094",
        severity: "CRITICAL",
        title: "XZ Utils Malicious Backdoor",
        description: "Supply chain backdoor in XZ Utils; public PoCs — great for PoC Explainer and IR Plan analysis.",
        timestamp: new Date().getTime() - 900000
    },
    {
        cveId: "CVE-2023-46604",
        severity: "CRITICAL",
        title: "Microsoft MSMQ RCE (QueueJumper)",
        description: "Windows MSMQ RCE, CISA KEV; public exploit code — strong MITRE ATT&CK mapping and investigation use case.",
        timestamp: new Date().getTime() - 3600000
    }
];

function getRecentAnalyses() {
    try {
        const stored = localStorage.getItem('cve-analyzer-recent');
        if (stored) {
            return JSON.parse(stored);
        }
    } catch (e) {
        console.error("Error reading recent analyses:", e);
    }
    // Return copy of defaults if none found
    return [...DEFAULT_HISTORY];
}

function saveRecentAnalysis(cveData) {
    if (!cveData || !cveData.id) return;

    let history = getRecentAnalyses();
    const isNew = !history.some(item => item.cveId.toUpperCase() === cveData.id.toUpperCase());

    // Remove if already exists to move it to the front
    history = history.filter(item => item.cveId.toUpperCase() !== cveData.id.toUpperCase());

    // Add to front
    history.unshift({
        cveId: cveData.id,
        severity: (cveData.cvss && cveData.cvss.severity) ? cveData.cvss.severity : 'UNKNOWN',
        title: `Vulnerability ${cveData.id}`,
        description: cveData.description || 'No description available',
        timestamp: new Date().getTime()
    });

    // Keep max 6 items
    if (history.length > 6) {
        history = history.slice(0, 6);
    }

    localStorage.setItem('cve-analyzer-recent', JSON.stringify(history));

    // Increment persistent total counter only for genuinely new CVE IDs
    if (isNew) {
        const prev = parseInt(localStorage.getItem(TOTAL_ANALYSES_KEY) || '0', 10);
        localStorage.setItem(TOTAL_ANALYSES_KEY, prev + 1);
        updateTotalAnalysesStat();
    }
}

function getTotalAnalysesCount() {
    const stored = parseInt(localStorage.getItem(TOTAL_ANALYSES_KEY) || '0', 10);
    // Floor is the number of unique CVEs we can see in recent history
    const floor = getRecentAnalyses().length;
    return Math.max(stored, floor);
}

function updateTotalAnalysesStat() {
    const el = document.getElementById('stat-total-analyses');
    if (!el) return;
    const count = getTotalAnalysesCount();
    el.textContent = count.toLocaleString();
}

function getRelativeTimeString(timestamp) {
    const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
    const elapsed = timestamp - new Date().getTime();

    const minutes = Math.round(elapsed / 60000);
    if (Math.abs(minutes) < 60) return rtf.format(minutes, 'minute');

    const hours = Math.round(elapsed / 3600000);
    if (Math.abs(hours) < 24) return rtf.format(hours, 'hour');

    const days = Math.round(elapsed / 86400000);
    return rtf.format(days, 'day');
}

function renderRecentAnalyses() {
    const grid = document.getElementById('recent-analyses-grid');
    if (!grid) return;

    const history = getRecentAnalyses();

    if (history.length === 0) {
        grid.innerHTML = '<p style="color: var(--text-muted); grid-column: 1 / -1;">No recent analyses found. Try searching for a CVE above.</p>';
        return;
    }

    let html = '';

    history.forEach(item => {
        const severityClass = getSeverityClass(item.severity);
        const timeAgo = getRelativeTimeString(item.timestamp);

        // Define color combinations for the glow effect based on severity
        let glowColor = 'rgba(255, 255, 255, 0.1)';
        if (item.severity === 'CRITICAL') glowColor = 'rgba(239, 68, 68, 0.1)';
        else if (item.severity === 'HIGH') glowColor = 'rgba(249, 115, 22, 0.1)';
        else if (item.severity === 'MEDIUM') glowColor = 'rgba(234, 179, 8, 0.1)';
        else if (item.severity === 'LOW') glowColor = 'rgba(34, 197, 94, 0.1)';

        let displayTitle = item.title;
        // Basic heuristic to generate a nicer title if it's just the ID
        if (displayTitle === `Vulnerability ${item.cveId}` && item.description.length > 10) {
            displayTitle = item.description.split('.')[0]; // Take first sentence
        }

        html += `
            <a href="workflow.html?cve=${encodeURIComponent(item.cveId)}" class="glass-panel cve-card">
                <div class="severity-glow"
                    style="background: linear-gradient(225deg, ${glowColor} 0%, transparent 100%);"></div>
                <div class="flex justify-between items-center" style="margin-bottom: 16px;">
                    <span class="font-mono text-sm"
                        style="background: rgba(255,255,255,0.05); padding: 4px 12px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.1); color: var(--text-primary);">${escapeHtml(item.cveId)}</span>
                    <span class="badge ${severityClass}">${escapeHtml(item.severity)}</span>
                </div>
                <h3 class="font-medium"
                    style="color: var(--text-primary); margin-bottom: 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    ${escapeHtml(displayTitle)}</h3>
                <p class="text-sm"
                    style="color: var(--text-muted); margin-bottom: 24px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; height: 40px;">
                    ${escapeHtml(item.description)}
                </p>
                <div class="flex justify-between items-center"
                    style="padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.05);">
                    <div class="flex items-center gap-2">
                        <span class="material-symbols-outlined"
                            style="color: #4ade80; font-size: 18px;">check_circle</span>
                        <span class="text-xs" style="color: var(--text-secondary);">Saved</span>
                    </div>
                    <span class="text-xs font-mono" style="color: var(--text-muted);">${timeAgo}</span>
                </div>
            </a>
        `;
    });

    grid.innerHTML = html;
}

// ===================================
// Workflow Page Functions
// ===================================

const workflowMessages = {
    step1: [
        'Connecting to NVD API...',
        'Fetching CVE metadata...',
        'Checking CISA KEV catalog...',
        'Parsing vulnerability data...'
    ],
    step2: [
        'Searching GitHub for PoC repositories...',
        'Checking exploit availability...'
    ],
    step3: [
        'Analyzing attack patterns...',
        'Mapping to MITRE ATT&CK framework...',
        'Identifying relevant techniques...',
        'Validating technique mappings...'
    ],
    step4: [
        'Generating IR Plan...',
        'Analyzing detection strategies...',
        'Compiling mitigation steps...',
        'Finalizing incident response plan...'
    ],
    step5: []
};

async function initWorkflow() {
    const raw = getUrlParameter('cve') || 'CVE-2024-38077';
    const { valid, error, normalized } = validateCveFormat(raw);
    const cveId = valid ? normalized : raw;

    // Initialize theme
    initTheme();

    // Initialize UI
    initTabs(cveId);

    // Set initial CVE ID display
    const cveIdEl = document.getElementById('cve-id');
    if (cveIdEl) cveIdEl.textContent = cveId.toUpperCase();

    // Fetch and display model name
    fetchWorkflowModel();

    // Reset all steps to pending
    resetWorkflowSteps();

    if (!valid) {
        const steps = document.querySelectorAll('.workflow-step');
        if (steps[0]) {
            steps[0].classList.remove('pending');
            steps[0].classList.add('error');
            const desc = steps[0].querySelector('.description');
            if (desc) {
                desc.textContent = error.substring(0, 80);
                desc.style.color = '#f87171';
            }
        }
        showErrorState(error);
        updateProcessingBadge('error');
        return;
    }

    // Start animated analysis process
    await runAnimatedAnalysis(cveId);
}

async function fetchWorkflowModel() {
    try {
        await ApiService.getModels();
        setCurrentModel(currentModel);
    } catch (error) {
        console.error('Failed to fetch model:', error);
    }
}


function resetWorkflowSteps() {
    const steps = document.querySelectorAll('.workflow-step');
    steps.forEach(step => {
        step.classList.remove('completed', 'active', 'error');
        step.classList.add('pending');

        const desc = step.querySelector('.description');
        if (desc) {
            desc.textContent = 'Waiting...';
            desc.style.color = 'var(--text-muted)';
        }

        const progressBar = step.querySelector('.progress-bar');
        if (progressBar) progressBar.style.visibility = 'hidden';

        const fill = step.querySelector('.progress-bar .fill');
        if (fill) fill.style.width = '0%';
    });
}

const MAX_RETRIES = 3;


function isMitreValid(techniques) {
    return Array.isArray(techniques) && techniques.length > 0;
}

async function retryUntilValid(apiCall, validator, label, maxRetries = MAX_RETRIES) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const result = await apiCall();
            if (validator(result)) return result;
            console.warn(`${label}: attempt ${attempt}/${maxRetries} returned insufficient data, retrying…`);
        } catch (err) {
            console.warn(`${label}: attempt ${attempt}/${maxRetries} failed (${err.message}), retrying…`);
        }
        if (attempt < maxRetries) await sleep(500);
    }
    return apiCall();
}

function setStepActive(stepEl, descriptionText) {
    if (!stepEl) return;
    stepEl.classList.remove('pending');
    stepEl.classList.add('active');
    const desc = stepEl.querySelector('.description');
    if (desc) {
        desc.textContent = descriptionText;
        desc.style.color = 'var(--primary)';
    }
    const progressBar = stepEl.querySelector('.progress-bar');
    if (progressBar) progressBar.style.visibility = 'visible';
    const fill = stepEl.querySelector('.progress-bar .fill');
    if (fill) fill.style.width = '50%';
}

function setStepCompleted(stepEl, descriptionText) {
    if (!stepEl) return;
    stepEl.classList.remove('active');
    stepEl.classList.add('completed');
    const desc = stepEl.querySelector('.description');
    if (desc) {
        desc.textContent = descriptionText;
        desc.style.color = 'var(--text-secondary)';
    }
    const progressBar = stepEl.querySelector('.progress-bar');
    if (progressBar) progressBar.style.visibility = 'hidden';
    const fill = stepEl.querySelector('.progress-bar .fill');
    if (fill) fill.style.width = '100%';
}

/** Build pocStatus from PoC search result for IR Plan and MITRE context */
function buildPocStatus(searchResult) {
    const total = searchResult && (searchResult.total ?? (searchResult.repos && searchResult.repos.length));
    const hasPoc = !!(total && total > 0);
    return { hasPublicPoc: hasPoc, repoCount: hasPoc ? (total || 0) : 0 };
}

// ===================================
// Workflow Context Helpers
// ===================================

/**
 * Build a compact news context string (≤400 chars) from news results.
 * Format: "[source] title. snippet. [source2] …"
 * Used to feed real-world exploit intelligence into MITRE and IR Plan LLMs.
 */
function buildNewsContext(newsResult) {
    if (!newsResult || !Array.isArray(newsResult.news) || !newsResult.news.length) return null;
    const parts = [];
    let total = 0;
    for (const item of newsResult.news.slice(0, 5)) {
        const src = item.source ? `[${item.source}]` : '';
        const title = (item.title || '').slice(0, 60);
        const snippet = (item.summary || '').slice(0, 60);
        const piece = `${src} ${title}${snippet ? '. ' + snippet : ''}`.trim();
        if (total + piece.length > 400) break;
        parts.push(piece);
        total += piece.length + 1;
    }
    return parts.length ? parts.join(' | ') : null;
}

/**
 * Build a compact MITRE summary string from a techniques array.
 * Format: "T1190: Exploit Public-Facing App; T1068: Priv Esc"
 * Used as extra context for IR Plan prompt.
 */
function buildMitreSummary(techniques) {
    if (!Array.isArray(techniques) || !techniques.length) return null;
    return techniques.slice(0, 5)
        .map(t => `${t.id}: ${(t.name || '').slice(0, 40)}`)
        .join('; ');
}


/** Sequential workflow: NVD → (PoC ∥ News) → MITRE → IR Plan */
async function runSequentialAnalysis(steps, cveData, workflowMessages) {
    const stepPoc = steps[1];
    const stepNews = steps[2];
    const stepMitre = steps[3];
    const stepIR = steps[4];
    const stepComplete = steps[5];
    if (!stepPoc || !stepNews || !stepMitre || !stepIR || !stepComplete) return;

    let pocStatus = { hasPublicPoc: false, repoCount: 0 };
    let newsResult = null;
    let mitreResult = null;

    // ── Step 2+3: PoC Search & News Search — PARALLEL ──────────────────────────
    // Both are pure HTTP (no LLM). Running them together saves ~7-15 seconds.
    const NEWS_STEP_MESSAGES = [
        'Querying cybersecurity news sources...',
        'Searching thehackernews, bleepingcomputer, darkreading...',
        'Scanning securityweek, threatpost, krebsonsecurity...',
        'Deduplicating and ranking results...',
    ];

    // Kick off both in parallel; animate them concurrently  
    const [pocSettled, newsSettled] = await Promise.all([
        animateStep(stepPoc, workflowMessages.step2, async () => {
            try {
                const searchResult = await ApiService.searchPoc(cveData.id);
                pocStatus = buildPocStatus(searchResult);
                window.__pocSearchResult = { cveId: cveData.id, ...searchResult };
                return pocStatus.hasPublicPoc
                    ? `Found ${pocStatus.repoCount} PoC repo(s).`
                    : 'No public PoC found.';
            } catch {
                return 'PoC search skipped (API error).';
            }
        }),
        animateStep(stepNews, NEWS_STEP_MESSAGES, async () => {
            try {
                newsResult = await ApiService.searchNews(cveData.id);
                window.__newsSearchResult = newsResult;
                if (newsResult && Array.isArray(newsResult.news) && newsResult.news.length > 0) {
                    updateNewsContent(newsResult);
                    revealSections('news-content');
                    const srcCount = newsResult.sourcesFound
                        || new Set(newsResult.news.map(n => n.source)).size;
                    return `Found ${newsResult.news.length} article(s) across ${srcCount} source(s).`;
                }
                updateNewsContent({ news: [], sourcesSearched: newsResult?.sourcesSearched });
                revealSections('news-content');
                return 'No news articles found for this CVE.';
            } catch (err) {
                updateNewsContent({ error: err.message, news: [] });
                revealSections('news-content');
                return 'News search skipped (API error).';
            }
        }),
    ]);

    // Build news context for LLMs — compact string of titles + snippets
    const newsContext = buildNewsContext(newsResult);

    // ── Step 4: MITRE ATT&CK — runs BEFORE IR Plan ─────────────────────────────
    // Context: CVE desc + CVSS + Affected Products + PoC + News snippets
    const mitreResult_ = await retryUntilValid(
        async () => {
            setStepActive(stepMitre, 'Mapping MITRE ATT&CK techniques...');
            return ApiService.mapMitre(cveData, currentModel, null, pocStatus, newsContext);
        },
        r => isMitreValid(r && r.mitreTechniques),
        'MITRE mapping',
    );
    mitreResult = mitreResult_;
    if (mitreResult && mitreResult.mitreTechniques) {
        updateMitreContent(mitreResult.mitreTechniques);
        revealSections('mitre-content');
    }
    setStepCompleted(stepMitre, `Mapped ${mitreResult?.mitreTechniques?.length ?? 0} MITRE ATT&CK technique(s).`);
    await sleep(200);

    // ── Step 5: IR Plan — runs LAST with maximum context ───────────────────────
    // Context: CVE + Affected Products + PoC + News snippets + MITRE techniques
    const mitreTechniques = mitreResult?.mitreTechniques || [];
    setStepActive(stepIR, 'Generating IR Plan (Detection & Mitigation)...');
    const irPlanResult = await ApiService.fetchIRPlan(
        cveData, currentModel, pocStatus, mitreTechniques, newsContext
    ).catch((err) => {
        const msg = err?.message || 'IR Plan could not be generated.';
        return { detectionSummary: `Error: ${msg}`, mitigationSummary: '' };
    });
    if (irPlanResult && (irPlanResult.detectionSummary || irPlanResult.mitigationSummary)) {
        updateIRPlanContent(irPlanResult);
        revealSections('irplan-content');
    }
    setStepCompleted(stepIR, 'IR Plan (Detection & Mitigation) ready.');
    await sleep(250);
}


async function runAnimatedAnalysis(cveId) {
    const steps = document.querySelectorAll('.workflow-step');
    if (!steps || steps.length < 6) {
        throw new Error('Workflow UI not ready. Please refresh the page.');
    }
    let cveData = null;
    let kevStatus = null;

    try {
        const health = await ApiService.checkHealth();
        if (health.status !== 'running' && health.ollama === 'disconnected') {
            throw new Error('Backend unreachable. Ensure the server is running: python server.py');
        }
    } catch (e) {
        throw new Error(e.message || 'Cannot connect to backend. Is the server running?');
    }

    ApiService.warmup(currentModel).catch(() => { });

    try {
        // Step 1: NVD Data Retrieval
        await animateStep(steps[0], workflowMessages.step1, async () => {
            const result = await retryUntilValid(
                () => ApiService.fetchCVE(cveId),
                r => r && r.cveData && r.cveData.id,
                'NVD fetch',
            );
            cveData = result.cveData;
            kevStatus = result.kevStatus;
            window.__currentCveData = cveData;

            updateCVEMetadata(cveData);
            saveRecentAnalysis(cveData);

            renderAnalysisNVD(cveData, kevStatus);
            revealSections('analysis-content');

            updateAffectedContent(cveData);
            revealSections('affected-content');

            const count = cveData.affected ? cveData.affected.length : 0;
            return `Fetched CVE data — ${count} affected product(s).`;
        }, null, true);

        // Step 2–4: PoC Search → IR Plan → MITRE (sequential, each uses prior context)
        await runSequentialAnalysis(steps, cveData, workflowMessages);

        // Step 6: Report Complete
        await animateStep(steps[5], [], async () => {
            await sleep(300);
            return 'All reports ready.';
        }, null);

        updateProcessingBadge('complete');

    } catch (error) {
        console.error('Analysis error:', error);
        markCurrentStepError(error.message);
        showErrorState(error.message);
        updateProcessingBadge('error');
    }
}

async function animateStep(stepEl, messages, action, completionMessage, concurrent = false) {
    if (!stepEl) return;

    stepEl.classList.remove('pending');
    stepEl.classList.add('active');

    const desc = stepEl.querySelector('.description');
    const progressBar = stepEl.querySelector('.progress-bar');
    const fill = stepEl.querySelector('.progress-bar .fill');

    const showProgress = concurrent || messages.length === 0;
    if (progressBar && showProgress) progressBar.style.visibility = 'visible';
    if (fill) { fill.style.width = '0%'; fill.style.transition = 'width 0.5s ease'; }

    let actionResult;

    if (concurrent && messages.length > 0) {
        const actionPromise = action();

        for (let i = 0; i < messages.length; i++) {
            if (desc) { desc.textContent = messages[i]; desc.style.color = 'var(--primary)'; }
            if (fill) fill.style.width = `${((i + 1) / messages.length) * 70}%`;
            await sleep(700);
        }

        if (desc) desc.textContent = 'Processing...';
        actionResult = await actionPromise;
        if (fill) fill.style.width = '100%';
        await sleep(200);

    } else if (messages.length > 0) {
        for (let i = 0; i < messages.length; i++) {
            if (desc) { desc.textContent = messages[i]; desc.style.color = 'var(--primary)'; }
            if (fill) { fill.style.width = `${((i + 1) / messages.length) * 100}%`; fill.style.transition = 'width 0.5s ease'; }
            await sleep(400);
        }
        actionResult = await action();

    } else {
        if (progressBar) progressBar.style.visibility = 'visible';
        if (desc) desc.style.color = 'var(--primary)';
        actionResult = await action();
    }

    if (progressBar) progressBar.style.visibility = 'hidden';
    stepEl.classList.remove('active');
    stepEl.classList.add('completed');

    if (desc) {
        const msg = (typeof actionResult === 'string') ? actionResult : completionMessage;
        desc.textContent = msg || 'Complete';
        desc.style.color = 'var(--text-secondary)';
    }

    await sleep(250);
}

function markCurrentStepError(message) {
    const activeStep = document.querySelector('.workflow-step.active');
    if (activeStep) {
        activeStep.classList.remove('active');
        activeStep.classList.add('error');

        const desc = activeStep.querySelector('.description');
        if (desc) {
            desc.textContent = 'Failed: ' + message.substring(0, 50);
            desc.style.color = '#f87171';
        }
    }
}

function updateProcessingBadge(status) {
    const badge = document.querySelector('.badge-processing');
    if (!badge) return;

    if (status === 'complete') {
        badge.textContent = 'Complete';
        badge.classList.remove('badge-processing');
        badge.classList.add('badge-low');
        badge.style.background = 'rgba(34, 197, 94, 0.1)';
        badge.style.color = '#4ade80';
        badge.style.borderColor = 'rgba(34, 197, 94, 0.2)';
    } else if (status === 'error') {
        badge.textContent = 'Error';
        badge.classList.remove('badge-processing');
        badge.style.background = 'rgba(239, 68, 68, 0.1)';
        badge.style.color = '#f87171';
        badge.style.borderColor = 'rgba(239, 68, 68, 0.2)';
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function showErrorState(errorMessage) {
    const analysisContent = document.getElementById('analysis-content');
    if (analysisContent) {
        const cveParam = getUrlParameter('cve') || 'CVE-2024-38077';
        analysisContent.innerHTML = `
            <div class="error-state">
                <span class="material-symbols-outlined" style="font-size: 48px; color: #ef4444;">error</span>
                <h3>Analysis Failed</h3>
                <p>${escapeHtml(errorMessage)}</p>
                <div class="error-hints">
                    <p><strong>Troubleshooting:</strong></p>
                    <ul>
                        <li>Ensure the backend server is running: <code>python server.py</code></li>
                        <li>Check if Ollama is running: <code>ollama serve</code></li>
                        <li>Verify the CVE ID format (e.g., CVE-2024-3094)</li>
                    </ul>
                </div>
                <div style="margin-top: 20px; display: flex; gap: 12px; flex-wrap: wrap;">
                    <button type="button" class="btn btn-primary" id="btn-retry-analysis">
                        <span class="material-symbols-outlined" style="font-size: 18px;">refresh</span>
                        Retry Analysis
                    </button>
                    <a href="index.html" class="btn btn-ghost">Try Different CVE</a>
                </div>
            </div>
        `;
        document.getElementById('btn-retry-analysis')?.addEventListener('click', () => {
            window.location.href = `workflow.html?cve=${encodeURIComponent(cveParam)}`;
        });
    }
}

function updateCVEMetadata(data) {
    if (!data) return;

    // Update CVE ID
    const cveIdEl = document.getElementById('cve-id');
    if (cveIdEl) cveIdEl.textContent = data.id || 'Unknown';

    // Update description
    const descEl = document.getElementById('cve-description');
    if (descEl) {
        const desc = data.description || 'No description available';
        descEl.textContent = desc.length > 150 ? desc.substring(0, 150) + '...' : desc;
        descEl.title = desc;
    }

    // Update published date
    const dateEl = document.getElementById('cve-date');
    if (dateEl) dateEl.textContent = `Published: ${formatDate(data.published)}`;

    // Get CVSS data
    const cvss = data.cvss || {};
    const hasCVSS = cvss.score !== undefined && cvss.score !== null && cvss.score !== 'N/A';
    const score = hasCVSS ? parseFloat(cvss.score) : null;
    const severity = hasCVSS ? (cvss.severity || getSeverityFromScore(score)) : null;

    // Update severity badge
    const severityEl = document.getElementById('cve-severity');
    if (severityEl) {
        if (severity) {
            severityEl.textContent = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
            severityEl.className = `badge ${getSeverityClass(severity)}`;
        } else {
            severityEl.textContent = 'Awaiting';
            severityEl.className = 'badge badge-awaiting';
        }
    }

    // Update CVSS score
    const cvssScoreEl = document.getElementById('cvss-score');
    if (cvssScoreEl) cvssScoreEl.textContent = hasCVSS ? score.toFixed(1) : '—';

    // Update CVSS gauge
    const cvssProgress = document.getElementById('cvss-progress');
    if (cvssProgress) {
        if (hasCVSS) {
            const percentage = (score / 10) * 100;
            cvssProgress.setAttribute('stroke-dasharray', `${percentage}, 100`);
            const colors = {
                'critical': '#ef4444',
                'high': '#f97316',
                'medium': '#eab308',
                'low': '#22c55e'
            };
            cvssProgress.style.stroke = colors[severity.toLowerCase()] || '#94a3b8';
        } else {
            cvssProgress.setAttribute('stroke-dasharray', '0, 100');
            cvssProgress.style.stroke = '#475569';
        }
    }

    // Update metric cards
    const notScored = 'Not scored';
    const vectorEl = document.getElementById('metric-vector');
    if (vectorEl) vectorEl.textContent = (hasCVSS && cvss.vector && cvss.vector !== 'N/A') ? cvss.vector : notScored;

    const complexityEl = document.getElementById('metric-complexity');
    if (complexityEl) complexityEl.textContent = (hasCVSS && cvss.complexity && cvss.complexity !== 'N/A') ? cvss.complexity : notScored;

    const privilegesEl = document.getElementById('metric-privileges');
    if (privilegesEl) privilegesEl.textContent = (hasCVSS && cvss.privileges && cvss.privileges !== 'N/A') ? cvss.privileges : notScored;

    const epssEl = document.getElementById('metric-epss');
    if (epssEl) epssEl.textContent = (hasCVSS && cvss.userInteraction && cvss.userInteraction !== 'N/A') ? cvss.userInteraction : notScored;
}

// Phase 1: Render NVD data (called when /api/fetch-cve returns)
function renderAnalysisNVD(cveData, kevStatus) {
    const container = document.getElementById('analysis-content');
    if (!container) return;

    if (!cveData) {
        container.innerHTML = '<p class="no-data">No CVE data available.</p>';
        return;
    }

    const scrollTop = container.scrollTop;

    let content = '';

    if (kevStatus && kevStatus.is_in_kev) {
        const isRansomware = kevStatus.ransomware_use === 'Known';
        const bannerColor = isRansomware ? '#dc2626' : '#f59e0b';
        const bannerBg = isRansomware ? 'rgba(220, 38, 38, 0.15)' : 'rgba(245, 158, 11, 0.15)';

        content += `
            <div class="kev-alert section-reveal" style="background: ${bannerBg}; border: 1px solid ${bannerColor}; border-radius: 12px; padding: 16px 20px; margin-bottom: 24px;">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 24px; color: ${bannerColor};">warning</span>
                    <h3 style="margin: 0; color: ${bannerColor}; font-size: 16px; font-weight: 600;">
                        CISA Known Exploited Vulnerability
                        ${isRansomware ? '<span style="background: #dc2626; color: white; font-size: 10px; padding: 2px 8px; border-radius: 4px; margin-left: 8px;">RANSOMWARE</span>' : ''}
                    </h3>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; color: var(--text-secondary); font-size: 13px;">
                    <div><strong>Vendor:</strong> ${escapeHtml(kevStatus.vendor || 'N/A')}</div>
                    <div><strong>Product:</strong> ${escapeHtml(kevStatus.product || 'N/A')}</div>
                    <div><strong>Added to KEV:</strong> ${escapeHtml(kevStatus.date_added || 'N/A')}</div>
                    <div><strong>Due Date:</strong> ${escapeHtml(kevStatus.due_date || 'N/A')}</div>
                </div>
                ${kevStatus.required_action ? `
                    <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.1);">
                        <strong style="color: ${bannerColor};">Required Action:</strong>
                        <p style="margin: 4px 0 0 0; font-size: 12px; color: var(--text-muted);">${escapeHtml(kevStatus.required_action)}</p>
                    </div>
                ` : ''}
            </div>
        `;
    }

    content += `
        <div class="cve-data-section section-reveal">
            <h3 class="data-section-title">
                <span class="material-symbols-outlined">description</span>
                Description
            </h3>
            <p class="cve-description">${escapeHtml(cveData.description || 'No description available')}</p>
        </div>
    `;

    const cvss = cveData.cvss || {};
    const hasCvssScore = cvss.score !== undefined && cvss.score !== null && cvss.score !== 'N/A';
    if (hasCvssScore) {
        content += `
            <div class="cve-data-section section-reveal" style="padding: 16px; margin-bottom: 24px;">
                <h3 class="data-section-title" style="margin-bottom: 12px; font-size: 14px;">
                    <span class="material-symbols-outlined" style="font-size: 18px;">analytics</span>
                    CVSS Metrics
                </h3>
                <div style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center;">
                    <span class="badge ${getSeverityClass(cvss.severity)} cvss-badge">Score: ${cvss.score} (${cvss.severity})</span>
                    <span class="cvss-detail"><strong>Vector:</strong> ${cvss.vector || 'N/A'}</span>
                    <span class="cvss-detail"><strong>Complexity:</strong> ${cvss.complexity || 'N/A'}</span>
                    <span class="cvss-detail"><strong>Privileges:</strong> ${cvss.privileges || 'N/A'}</span>
                    <span class="cvss-detail"><strong>User Interaction:</strong> ${cvss.userInteraction || 'N/A'}</span>
                </div>
            </div>
        `;
    } else {
        content += `
            <div class="cve-data-section section-reveal" style="padding: 16px; margin-bottom: 24px;">
                <h3 class="data-section-title" style="margin-bottom: 12px; font-size: 14px;">
                    <span class="material-symbols-outlined" style="font-size: 18px;">analytics</span>
                    CVSS Metrics
                </h3>
                <p style="color: var(--text-muted); font-size: 13px; margin: 0;">
                    <span class="material-symbols-outlined" style="font-size: 14px; vertical-align: middle; margin-right: 4px;">schedule</span>
                    CVSS score not yet assigned by NVD. This is common for recently published CVEs.
                </p>
            </div>
        `;
    }

    if (cveData.weaknesses && cveData.weaknesses.length > 0) {
        content += `
            <div class="cve-data-section section-reveal">
                <h3 class="data-section-title">
                    <span class="material-symbols-outlined">bug_report</span>
                    Weaknesses (CWE)
                </h3>
                <div class="cwe-list">
                    ${cveData.weaknesses.map(cwe => `<span class="cwe-badge">${escapeHtml(cwe)}</span>`).join('')}
                </div>
            </div>
        `;
    }

    if (cveData.references && cveData.references.length > 0) {
        content += `
            <div class="cve-data-section section-reveal" style="margin-top: 32px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 24px;">
                <h3 class="data-section-title">
                    <span class="material-symbols-outlined">link</span>
                    References
                </h3>
                <div class="reference-list">
                    ${cveData.references.map(ref => `
                        <a href="${escapeHtml(ref.url)}" target="_blank" class="reference-link">
                            <span class="material-symbols-outlined">open_in_new</span>
                            ${escapeHtml(ref.url)}
                        </a>
                    `).join('')}
                </div>
            </div>
        `;
    }

    container.innerHTML = content;
    container.scrollTop = scrollTop;
}

function updateMitreContent(techniques) {
    const mitreContent = document.getElementById('mitre-content');
    if (!mitreContent) return;

    if (!techniques || techniques.length === 0) {
        mitreContent.innerHTML = `
            <div class="empty-state section-reveal" style="text-align: center; padding: 48px;">
                <span class="material-symbols-outlined" style="font-size: 48px; color: var(--text-muted); margin-bottom: 16px;">neurology</span>
                <h3 style="color: var(--text-secondary); margin-bottom: 8px;">No MITRE Techniques Identified</h3>
                <p style="color: var(--text-muted);">The AI could not map this vulnerability to specific MITRE ATT&CK techniques.</p>
            </div>
        `;
        return;
    }

    let content = `
        <div class="section-reveal" style="margin-bottom: 24px;">
            <h2 style="color: var(--text-primary); font-size: 18px; margin-bottom: 4px;">
                <span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px; color: var(--primary);">neurology</span>
                MITRE ATT&CK Mapping
            </h2>
            <p style="color: var(--text-muted); font-size: 13px;">${techniques.length} Techniques identified with AI-driven relationship analysis.</p>
        </div>
        <div class="mitre-techniques-grid">
    `;

    techniques.forEach(tech => {
        const tacticsHtml = tech.tactics && tech.tactics.length > 0
            ? tech.tactics.map(t => `<span class="tactic-badge">${escapeHtml(t.replace(/-/g, ' '))}</span>`).join('')
            : '<span class="tactic-badge">Unknown</span>';

        const mitreUrl = `https://attack.mitre.org/techniques/${tech.id.replace(/\./g, '/')}/`;

        content += `
            <div class="mitre-technique-card section-reveal">
                <div class="technique-header">
                    <a href="${mitreUrl}" target="_blank" class="technique-id-link" title="View on MITRE ATT&CK">
                        ${escapeHtml(tech.id)}
                        <span class="material-symbols-outlined" style="font-size: 12px; vertical-align: middle; margin-left: 2px;">open_in_new</span>
                    </a>
                    <span class="confidence-badge confidence-${tech.confidence || 'high'}">${tech.confidence || 'high'}</span>
                </div>
                <h3 class="technique-name">
                    <a href="${mitreUrl}" target="_blank" style="color: inherit; text-decoration: none;">${escapeHtml(tech.name)}</a>
                </h3>
                <div class="technique-tactics">${tacticsHtml}</div>
                
                <div class="ai-analysis-box">
                    <div class="ai-analysis-header">
                        <span class="material-symbols-outlined">psychology</span>
                        AI Relationship Analysis
                    </div>
                    <p class="technique-reason">${escapeHtml(tech.reason || 'Relationship identified via vulnerability pattern matching.')}</p>
                </div>

                <a href="${mitreUrl}" target="_blank" class="mitre-doc-link">
                    Official Documentation
                    <span class="material-symbols-outlined">arrow_forward</span>
                </a>
            </div>
        `;
    });

    content += '</div>';
    mitreContent.innerHTML = content;
}


function initTabs(cveId) {
    const tabs = document.querySelectorAll('.tab[data-tab]');
    const tabContents = {
        'analysis': document.getElementById('tab-content-analysis'),
        'affected': document.getElementById('tab-content-affected'),
        'news': document.getElementById('tab-content-news'),
        'irplan': document.getElementById('tab-content-irplan'),
        'mitre': document.getElementById('tab-content-mitre'),
        'poc': document.getElementById('tab-content-poc')
    };

    let pocInitialized = false;

    tabs.forEach(tab => {
        tab.addEventListener('click', function () {
            const tabName = this.dataset.tab;

            if (tabName === 'poc' && !pocInitialized) {
                pocInitialized = true;
                PocExplainer.init(cveId);
            }

            tabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');

            Object.keys(tabContents).forEach(key => {
                const content = tabContents[key];
                if (content) {
                    content.style.display = key === tabName ? 'flex' : 'none';
                }
            });
        });
    });
}


// ===================================
// Inventory ↔ Affected Products Matcher
// ===================================

function parseVersion(v) {
    if (!v || typeof v !== 'string') return [];
    // Strip leading non-numeric chars (e.g. "v1.2.3" → [1,2,3])
    return v.replace(/^[^0-9]*/, '').split(/[.\-_]/).map(p => parseInt(p, 10) || 0);
}

function compareVersions(a, b) {
    const va = parseVersion(a);
    const vb = parseVersion(b);
    const len = Math.max(va.length, vb.length);
    for (let i = 0; i < len; i++) {
        const na = va[i] || 0;
        const nb = vb[i] || 0;
        if (na < nb) return -1;
        if (na > nb) return 1;
    }
    return 0;
}

function versionInAffectedRange(assetVersion, affItem) {
    if (!assetVersion) return false;

    const { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, version } = affItem;
    const hasRange = versionStartIncluding || versionStartExcluding || versionEndIncluding || versionEndExcluding;

    if (!hasRange) {
        // Exact version field or "All versions"
        if (!version || version === 'All versions' || version === '*') return true;
        return compareVersions(assetVersion, version) === 0;
    }

    if (versionStartIncluding && compareVersions(assetVersion, versionStartIncluding) < 0) return false;
    if (versionStartExcluding && compareVersions(assetVersion, versionStartExcluding) <= 0) return false;
    if (versionEndIncluding && compareVersions(assetVersion, versionEndIncluding) > 0) return false;
    if (versionEndExcluding && compareVersions(assetVersion, versionEndExcluding) >= 0) return false;
    return true;
}

function normalizeForMatch(s) {
    return (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function tokenOverlap(a, b) {
    if (!a || !b) return false;
    if (a === b) return true; // Exact match, bypass length limits
    const minLen = 4;
    if (a.length < minLen || b.length < minLen) return false;
    return a.includes(b) || b.includes(a);
}

/**
 * Match only when the same PRODUCT is involved: inventory product must match the affected product.
 * We do NOT match on vendor alone (e.g. "Cisco"): otherwise "Cisco FTD" would wrongly match
 * CVEs that affect "Catalyst SD-WAN Manager" or other Cisco products.
 * Exception: when CPE uses vendor-as-product (e.g. wordpress:wordpress), inv product may match aff vendor.
 */
function productNamesMatch(invProduct, invVendor, affProduct, affVendor) {
    const ip = normalizeForMatch(invProduct);
    const ap = normalizeForMatch(affProduct);
    const av = normalizeForMatch(affVendor);

    if (!ip || !ap) return false;

    const productVsProduct = tokenOverlap(ip, ap);
    const vendorIsProductName = av && ap && av === ap;
    const productVsAffVendor = vendorIsProductName && tokenOverlap(ip, av);
    return productVsProduct || productVsAffVendor;
}

function matchInventoryToAffected(affectedItems, inventoryAssets) {
    const byAssetId = new Map();

    inventoryAssets.forEach(asset => {
        affectedItems.forEach(affItem => {
            if (!productNamesMatch(asset.product, asset.vendor, affItem.product, affItem.vendor)) return;
            if (!versionInAffectedRange(asset.version, affItem)) return;

            let rangeLabel = '';
            const parts = [];
            if (affItem.versionStartIncluding) parts.push(`>= ${affItem.versionStartIncluding}`);
            if (affItem.versionStartExcluding) parts.push(`> ${affItem.versionStartExcluding}`);
            if (affItem.versionEndIncluding) parts.push(`<= ${affItem.versionEndIncluding}`);
            if (affItem.versionEndExcluding) parts.push(`< ${affItem.versionEndExcluding}`);
            rangeLabel = parts.length ? parts.join(' and ') : (affItem.version || 'All versions');

            if (!byAssetId.has(asset.id)) {
                byAssetId.set(asset.id, { asset, ranges: [] });
            }
            const entry = byAssetId.get(asset.id);
            if (!entry.ranges.some(r => r.rangeLabel === rangeLabel)) {
                entry.ranges.push({ rangeLabel, affProduct: affItem.product });
            }
        });
    });

    return Array.from(byAssetId.values());
}

function buildInventoryMatchBanner(affectedItems) {
    const inventory = InventoryManager.getAll();

    if (inventory.length === 0) {
        return `
            <div class="inv-match-banner inv-match-info section-reveal visible">
                <div class="inv-match-banner-header">
                    <span class="material-symbols-outlined inv-match-icon">info</span>
                    <div>
                        <span class="inv-match-title">Inventory Not Configured</span>
                        <span class="inv-match-sub">No assets in your inventory to cross-reference.</span>
                    </div>
                    <a href="index.html" class="inv-match-action-link">
                        <span class="material-symbols-outlined" style="font-size:15px;">add</span>
                        Add Assets
                    </a>
                </div>
            </div>`;
    }

    const matches = matchInventoryToAffected(affectedItems, inventory);

    if (matches.length === 0) {
        return `
            <div class="inv-match-banner inv-match-safe section-reveal visible">
                <div class="inv-match-banner-header">
                    <span class="material-symbols-outlined inv-match-icon">verified_user</span>
                    <div>
                        <span class="inv-match-title">No Inventory Matches Found</span>
                        <span class="inv-match-sub">None of your ${inventory.length} tracked asset${inventory.length !== 1 ? 's' : ''} match the affected product versions for this CVE.</span>
                    </div>
                    <a href="inventory.html" class="inv-match-action-link">
                        <span class="material-symbols-outlined" style="font-size:15px;">table_view</span>
                        View Inventory
                    </a>
                </div>
            </div>`;
    }

    const rows = matches.map(({ asset, ranges }) => {
        const rangeText = ranges.length === 1
            ? `in range <code class="inv-match-range">${escapeHtml(ranges[0].rangeLabel)}</code>`
            : ranges.map(r => `<code class="inv-match-range">${escapeHtml(r.rangeLabel)}</code>`).join(', ');
        const rangeSub = ranges.length === 1 ? '' : ` <span class="inv-match-multi-range">(${ranges.length} ranges)</span>`;
        return `
        <div class="inv-match-row">
            <div class="inv-match-asset-id">${escapeHtml(asset.id)}</div>
            <div class="inv-match-product">
                <span class="inv-match-product-name">${escapeHtml(asset.product)}</span>
                <span class="inv-match-vendor">${escapeHtml(asset.vendor)}</span>
            </div>
            <div class="inv-match-version-cell">
                <code class="inv-match-version-asset">${escapeHtml(asset.version)}</code>
                <span class="inv-match-in-range">${ranges.length === 1 ? 'in range ' : ''}${rangeText}${rangeSub}</span>
            </div>
            <div class="inv-match-env">
                <span class="inv-env-badge inv-env-${(asset.environment || 'unknown').toLowerCase().replace(/[\/ ]/g, '-')}">${escapeHtml(asset.environment || '—')}</span>
            </div>
            <div class="inv-match-owner">${escapeHtml(asset.owner || '—')}</div>
        </div>`;
    }).join('');

    return `
        <div class="inv-match-banner inv-match-warning section-reveal visible">
            <div class="inv-match-banner-header">
                <span class="material-symbols-outlined inv-match-icon">warning</span>
                <div>
                    <span class="inv-match-title">${matches.length} Inventory Asset${matches.length !== 1 ? 's' : ''} at Risk</span>
                    <span class="inv-match-sub">The following tracked assets run versions that fall within this CVE's affected range.</span>
                </div>
                <a href="inventory.html" class="inv-match-action-link">
                    <span class="material-symbols-outlined" style="font-size:15px;">open_in_new</span>
                    View Inventory
                </a>
            </div>
            <div class="inv-match-table-wrap">
                <div class="inv-match-table-head">
                    <span>Asset ID</span>
                    <span>Product / Vendor</span>
                    <span>Installed Version</span>
                    <span>Environment</span>
                    <span>Owner</span>
                </div>
                <div class="inv-match-table-body">${rows}</div>
            </div>
        </div>`;
}


// ===================================
// Affected Products Content
// ===================================

function updateAffectedContent(cveData) {
    const container = document.getElementById('affected-content');
    if (!container) return;

    const affected = cveData && cveData.affected;

    if (!affected || affected.length === 0) {
        container.innerHTML =
            buildInventoryMatchBanner([]) +
            `<div class="empty-state section-reveal" style="text-align: center; padding: 48px;">
                <span class="material-symbols-outlined" style="font-size: 48px; color: var(--text-muted); margin-bottom: 16px;">devices</span>
                <h3 style="color: var(--text-secondary); margin-bottom: 8px;">No Affected Products Found</h3>
                <p style="color: var(--text-muted);">NVD does not list specific affected products or CPE configurations for this vulnerability.</p>
            </div>`;
        return;
    }

    const byVendor = {};
    affected.forEach(item => {
        const vendor = item.vendor || 'Unknown Vendor';
        if (!byVendor[vendor]) byVendor[vendor] = [];
        byVendor[vendor].push(item);
    });

    let content = buildInventoryMatchBanner(affected);

    content += `
        <div class="section-reveal" style="margin-bottom: 16px;">
            <h2 style="color: var(--text-primary); font-size: 18px; margin-bottom: 4px;">
                <span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px; color: var(--primary);">devices</span>
                Affected Products
            </h2>
            <p style="color: var(--text-muted); font-size: 13px;">${affected.length} affected configuration(s) from NVD</p>
        </div>
    `;

    Object.keys(byVendor).forEach(vendor => {
        const products = byVendor[vendor];
        content += `
            <div class="affected-vendor-group section-reveal">
                <div class="affected-vendor-header">
                    <span class="material-symbols-outlined" style="font-size: 18px; color: var(--primary);">business</span>
                    <span>${escapeHtml(vendor)}</span>
                    <span class="badge badge-processing" style="font-size: 10px;">${products.length}</span>
                </div>
                <div class="affected-products-list">
        `;

        products.forEach(item => {
            let versionRange = '';
            if (item.versionStartIncluding || item.versionEndIncluding || item.versionStartExcluding || item.versionEndExcluding) {
                const parts = [];
                if (item.versionStartIncluding) parts.push(`>= ${item.versionStartIncluding}`);
                if (item.versionStartExcluding) parts.push(`> ${item.versionStartExcluding}`);
                if (item.versionEndIncluding) parts.push(`<= ${item.versionEndIncluding}`);
                if (item.versionEndExcluding) parts.push(`< ${item.versionEndExcluding}`);
                versionRange = parts.join(' and ');
            } else if (item.version && item.version !== 'All versions') {
                versionRange = item.version;
            } else {
                versionRange = 'All versions';
            }

            const typeIcon = item.type === 'Operating System' ? 'computer' : item.type === 'Hardware' ? 'memory' : 'apps';

            content += `
                <div class="affected-product-card">
                    <div class="affected-product-info">
                        <span class="material-symbols-outlined affected-type-icon">${typeIcon}</span>
                        <div>
                            <div class="affected-product-name">${escapeHtml(item.product || 'Unknown Product')}</div>
                            <div class="affected-product-type">${escapeHtml(item.type || 'Unknown')}</div>
                        </div>
                    </div>
                    <div class="affected-version-range">
                        <span class="material-symbols-outlined" style="font-size: 14px; color: var(--text-muted);">sell</span>
                        <span>${escapeHtml(versionRange)}</span>
                    </div>
                    <div class="affected-cpe-string" title="${escapeHtml(item.criteria)}">${escapeHtml(item.criteria)}</div>
                </div>
            `;
        });

        content += '</div></div>';
    });

    container.innerHTML = content;
}


// ===================================
// IR Plan Content
// ===================================

function updateIRPlanContent(analysis) {
    const container = document.getElementById('irplan-content');
    if (!container) return;

    if (!analysis || (typeof analysis !== 'object')) {
        container.innerHTML = '<p class="no-data section-reveal">No IR plan data available.</p>';
        return;
    }

    const detection = analysis.detectionSummary || '';
    const mitigation = analysis.mitigationSummary || '';
    const hasError = detection.startsWith('Error:');

    if (hasError) {
        const msg = detection;
        container.innerHTML = `
            <div class="cve-data-section section-reveal">
                <h3 class="data-section-title" style="color: #facc15;">
                    <span class="material-symbols-outlined">warning</span>
                    IR Plan Unavailable
                </h3>
                <p style="color: var(--text-muted);">${escapeHtml(msg)}</p>
            </div>
        `;
        return;
    }

    if (!detection && !mitigation) {
        container.innerHTML = '<p class="no-data section-reveal">No detection or mitigation data available.</p>';
        return;
    }

    let content = `
        <div class="section-reveal" style="margin-bottom: 24px;">
            <h2 style="color: var(--text-primary); font-size: 18px; margin-bottom: 4px;">
                <span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px; color: var(--primary);">emergency</span>
                Incident Response Plan
            </h2>
            <p style="color: var(--text-muted); font-size: 13px;">AI-generated detection and response guidance</p>
        </div>

        <div class="cve-data-section ai-summary ir-plan-section section-reveal">
            <h3 class="data-section-title">
                <span class="material-symbols-outlined">search</span>
                Detection Strategy
            </h3>
            <div class="ai-summary-content ir-plan-content">
                ${renderMarkdown(detection || 'No detection strategy available.')}
            </div>
        </div>
        
        <div class="cve-data-section ai-summary ir-plan-section section-reveal">
            <h3 class="data-section-title">
                <span class="material-symbols-outlined">shield</span>
                Mitigation Steps
            </h3>
            <div class="ai-summary-content ir-plan-content">
                ${renderMarkdown(mitigation || 'No mitigation steps available.')}
            </div>
        </div>

    `;

    container.innerHTML = content;
}


// ===================================
// News Content
// ===================================

function updateNewsContent(result) {
    const container = document.getElementById('news-content');
    if (!container) return;

    const news = result && Array.isArray(result.news) ? result.news : [];
    const error = result && result.error;

    if (error && !news.length) {
        container.innerHTML = `
            <div class="news-discovery-card section-reveal">
                <div class="news-discovery-header">
                    <div class="news-discovery-title">
                        <span class="material-symbols-outlined" style="color: #facc15;">warning</span>
                        <h3>News Lookup Failed</h3>
                    </div>
                </div>
                <p style="color:var(--text-muted); font-size:13px; padding-top: 12px;">${escapeHtml(error)}</p>
            </div>
        `;
        return;
    }

    if (!news.length) {
        container.innerHTML = `
            <div class="news-discovery-card section-reveal">
                <div class="news-discovery-header">
                    <div class="news-discovery-title">
                        <span class="material-symbols-outlined" style="color: var(--primary);">newspaper</span>
                        <h3>News & Advisories</h3>
                    </div>
                </div>
                <div class="news-meta-grid" style="border-bottom: none; margin-bottom: 0;">
                    <div class="news-meta-item">
                        <span class="news-meta-label">ARTICLES FOUND</span>
                        <span class="news-meta-value">0</span>
                    </div>
                    <div class="news-meta-item">
                        <span class="news-meta-label">SOURCES SEARCHED</span>
                        <span class="news-meta-value">${result && result.sourcesSearched || 9} sites</span>
                    </div>
                </div>
                <p class="no-data" style="color:var(--text-muted); font-size:13px; margin-top: 20px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.06);">
                    No news articles were found for this CVE across the configured cybersecurity news sources.
                </p>
            </div>
        `;
        return;
    }

    // Source breakdown
    const bySource = {};
    news.forEach(n => {
        const src = n.source || 'Unknown';
        bySource[src] = (bySource[src] || 0) + 1;
    });
    const sortedSources = Object.entries(bySource).sort((a, b) => b[1] - a[1]);
    const distinctSources = sortedSources.length;

    let content = `
        <div class="news-discovery-card section-reveal">
            <div class="news-discovery-header">
                <div class="news-discovery-title">
                    <span class="material-symbols-outlined" style="color: var(--primary);">newspaper</span>
                    <h3>News & Advisories</h3>
                </div>
                <div class="news-discovery-badge">
                    <span class="material-symbols-outlined" style="font-size: 14px;">auto_awesome</span>
                    Auto-discovered
                </div>
            </div>

            <div class="news-meta-grid">
                <div class="news-meta-item">
                    <span class="news-meta-label">ARTICLES FOUND</span>
                    <span class="news-meta-value news-meta-highlight">${news.length}</span>
                </div>
                <div class="news-meta-item">
                    <span class="news-meta-label">SOURCES SEARCHED</span>
                    <span class="news-meta-value">${result.sourcesSearched || 9} sites</span>
                </div>
                <div class="news-meta-item">
                    <span class="news-meta-label">SOURCES WITH HITS</span>
                    <span class="news-meta-value news-meta-found">${result.sourcesFound || distinctSources}</span>
                </div>
                <div class="news-meta-item">
                    <span class="news-meta-label">SEARCH METHOD</span>
                    <span class="news-meta-value">DuckDuckGo + Direct</span>
                </div>
            </div>

            <div class="news-source-breakdown">
                ${sortedSources.map(([src, count]) =>
        `<div class="news-source-chip">
                        <span class="material-symbols-outlined" style="font-size:12px;">rss_feed</span>
                        <span class="news-source-chip-name">${escapeHtml(src)}</span>
                        <span class="news-source-chip-count">${count}</span>
                    </div>`
    ).join('')}
            </div>

            <div class="news-articles-list">
    `;

    news.forEach((item, idx) => {
        const source = item.source || 'Unknown source';
        const title = item.title || 'News article';
        const url = item.url || '#';
        const rawSummary = item.summary || '';
        // Hard-truncate summary as a defensive fallback (server should also limit, but belt-and-suspenders)
        const summary = rawSummary.length > 120 ? rawSummary.slice(0, 117) + '…' : rawSummary;
        content += `
            <article class="news-card section-reveal">
                <div class="news-card-inner">
                    <div class="news-card-left">
                        <div class="news-card-num">${String(idx + 1).padStart(2, '0')}</div>
                    </div>
                    <div class="news-card-body">
                        <a href="${escapeHtml(url)}" target="_blank" rel="noopener" class="news-card-title">
                            <span class="news-card-title-text">${escapeHtml(title)}</span>
                            <span class="material-symbols-outlined news-card-open-icon">open_in_new</span>
                        </a>
                        ${summary ? `<p class="news-card-summary">${escapeHtml(summary)}</p>` : ''}
                        <div class="news-card-footer">
                            <span class="news-source-pill">
                                <span class="material-symbols-outlined" style="font-size:11px;">rss_feed</span>
                                ${escapeHtml(source)}
                            </span>
                            <a href="${escapeHtml(url)}" target="_blank" rel="noopener" class="news-read-btn">
                                Read Article
                                <span class="material-symbols-outlined" style="font-size: 13px;">arrow_forward</span>
                            </a>
                        </div>
                    </div>
                </div>
            </article>
        `;
    });

    content += `
            </div>
        </div>
    `;

    container.innerHTML = content;
}




// ===================================
// Section Reveal Animation Helper
// ===================================

function revealSections(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.querySelectorAll('.section-reveal:not(.visible)').forEach(s => s.classList.add('visible'));
}

// ===================================
// Inventory Manager Module
// ===================================

const InventoryManager = (() => {
    const STORAGE_KEY = 'cve-analyzer-inventory';
    const PAGE_SIZE = 20;

    // --- Storage ---
    function getAll() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
        catch { return []; }
    }

    function saveAll(assets) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(assets));
        window.dispatchEvent(new CustomEvent('inventory-changed', { detail: { count: assets.length } }));
    }

    function addAsset(asset) {
        const assets = getAll();
        asset.addedAt = asset.addedAt || Date.now();
        assets.push(asset);
        saveAll(assets);
        return asset;
    }

    function updateAsset(index, asset) {
        const assets = getAll();
        if (index >= 0 && index < assets.length) {
            assets[index] = { ...assets[index], ...asset };
            saveAll(assets);
        }
    }

    function deleteAsset(index) {
        const assets = getAll();
        assets.splice(index, 1);
        saveAll(assets);
    }

    function clearAll() {
        saveAll([]);
    }

    function getCount() { return getAll().length; }

    // --- CSV Parser ---
    function parseCSV(text) {
        const lines = text.trim().split('\n');
        if (lines.length < 2) return [];
        const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, '').toLowerCase());
        const colMap = {
            id: headers.findIndex(h => h.includes('id') || h.includes('asset')),
            product: headers.findIndex(h => h.includes('product')),
            vendor: headers.findIndex(h => h.includes('vendor')),
            version: headers.findIndex(h => h.includes('version')),
            environment: headers.findIndex(h => h.includes('env') || h.includes('environment')),
            owner: headers.findIndex(h => h.includes('owner'))
        };

        const assets = [];
        for (let i = 1; i < lines.length; i++) {
            const raw = lines[i].trim();
            if (!raw) continue;
            const cols = raw.split(',').map(c => c.trim().replace(/^"|"$/g, ''));
            const product = colMap.product >= 0 ? cols[colMap.product] : '';
            const version = colMap.version >= 0 ? cols[colMap.version] : '';
            assets.push({
                id: colMap.id >= 0 ? cols[colMap.id] : `ASSET-${String(i).padStart(3, '0')}`,
                product,
                vendor: colMap.vendor >= 0 ? cols[colMap.vendor] : '',
                version,
                environment: colMap.environment >= 0 ? cols[colMap.environment] : 'Unknown',
                owner: colMap.owner >= 0 ? cols[colMap.owner] : '',
                addedAt: Date.now()
            });
        }
        return assets;
    }

    function importAssets(newAssets, merge = true) {
        const existing = merge ? getAll() : [];
        const existingIds = new Set(existing.map(a => a.id.toLowerCase()));
        let added = 0;
        for (const asset of newAssets) {
            if (!existingIds.has(asset.id.toLowerCase())) {
                existing.push(asset);
                added++;
            }
        }
        saveAll(existing);
        return added;
    }

    // --- CSV Export ---
    function exportCSV() {
        const assets = getAll();
        if (!assets.length) return;
        const header = 'Asset ID,Product Name,Vendor,Version,Environment,Owner\n';
        const rows = assets.map(a =>
            [a.id, a.product, a.vendor, a.version, a.environment, a.owner]
                .map(v => `"${(v || '').replace(/"/g, '""')}"`)
                .join(',')
        ).join('\n');
        const blob = new Blob([header + rows], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'cve-analyzer-inventory.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 100);
    }

    // --- Dashboard Card Initialization ---
    function initDashboardCard() {
        const card = document.getElementById('inventory-stat-card');
        if (!card) return;

        updateDashboardCount();

        card.addEventListener('click', openModal);

        window.addEventListener('inventory-changed', () => {
            updateDashboardCount();
        });
    }

    function updateDashboardCount() {
        const count = getCount();
        const countEl = document.getElementById('inventory-count');
        const ctaEl = document.getElementById('inventory-cta');
        if (countEl) countEl.textContent = count.toLocaleString();
        if (ctaEl) ctaEl.style.display = count === 0 ? 'block' : 'none';
    }

    // --- Modal (dashboard page) ---
    let _pendingImport = [];

    function openModal() {
        const overlay = document.getElementById('inventory-modal-overlay');
        if (!overlay) { window.location.href = 'inventory.html'; return; }
        overlay.classList.add('active');
        overlay.setAttribute('aria-hidden', 'false');
        document.body.style.overflow = 'hidden';
        switchModalTab('import');
    }

    function closeModal() {
        const overlay = document.getElementById('inventory-modal-overlay');
        if (!overlay) return;
        overlay.classList.remove('active');
        overlay.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
        _pendingImport = [];
        resetImportUI('inv-drop-zone', 'inv-csv-preview', 'inv-import-actions');
    }

    function switchModalTab(name) {
        document.querySelectorAll('.inv-tab').forEach(t => t.classList.toggle('active', t.dataset.invTab === name));
        ['import', 'manual', 'sample'].forEach(tab => {
            const el = document.getElementById(`inv-tab-${tab}`);
            if (el) el.style.display = tab === name ? 'block' : 'none';
        });
    }

    function bindModalEvents() {
        const overlay = document.getElementById('inventory-modal-overlay');
        if (!overlay) return;

        document.getElementById('inv-modal-close')?.addEventListener('click', closeModal);
        overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });

        document.querySelectorAll('.inv-tab[data-inv-tab]').forEach(btn => {
            btn.addEventListener('click', () => switchModalTab(btn.dataset.invTab));
        });

        bindDropZone('inv-drop-zone', 'inv-file-input', 'inv-csv-preview', 'inv-import-actions', 'inv-import-count', (parsed) => { _pendingImport = parsed; });

        document.getElementById('inv-confirm-import')?.addEventListener('click', () => {
            if (_pendingImport.length) {
                const added = importAssets(_pendingImport);
                closeModal();
                showToast(`${added} assets imported successfully.`);
                if (window.location.pathname.includes('inventory')) InventoryPage.refresh();
            }
        });

        document.getElementById('inv-cancel-import')?.addEventListener('click', () => {
            _pendingImport = [];
            resetImportUI('inv-drop-zone', 'inv-csv-preview', 'inv-import-actions');
        });

        document.getElementById('inv-manual-form')?.addEventListener('submit', e => {
            e.preventDefault();
            const asset = {
                id: document.getElementById('inv-f-id').value.trim(),
                product: document.getElementById('inv-f-product').value.trim(),
                vendor: document.getElementById('inv-f-vendor').value.trim(),
                version: document.getElementById('inv-f-version').value.trim(),
                environment: document.getElementById('inv-f-env').value,
                owner: document.getElementById('inv-f-owner').value.trim(),
            };
            addAsset(asset);
            document.getElementById('inv-manual-form').reset();
            const successEl = document.getElementById('inv-manual-success');
            if (successEl) {
                successEl.textContent = `✓ "${asset.product} ${asset.version}" added successfully`;
                successEl.style.display = 'block';
                setTimeout(() => { successEl.style.display = 'none'; }, 3500);
            }
        });

        document.getElementById('inv-load-sample')?.addEventListener('click', async () => {
            try {
                const btn = document.getElementById('inv-load-sample');
                btn.disabled = true;
                btn.innerHTML = '<span class="material-symbols-outlined" style="animation:spin .9s linear infinite; font-size:16px;">sync</span> Loading…';
                const resp = await fetch('data/sample-assets.csv');
                const text = await resp.text();
                const parsed = parseCSV(text);
                const added = importAssets(parsed, true);
                closeModal();
                showToast(`${added} sample assets loaded.`);
                if (window.location.pathname.includes('inventory')) InventoryPage.refresh();
            } catch (err) {
                showToast('Failed to load sample data. Try downloading and importing the CSV.', true);
            }
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closeModal();
        });
    }

    // --- Generic Drop Zone Binding ---
    function bindDropZone(zoneId, inputId, previewId, actionsId, countId, onParsed) {
        const zone = document.getElementById(zoneId);
        const input = document.getElementById(inputId);
        if (!zone || !input) return;

        const highlight = () => zone.classList.add('dragover');
        const unhighlight = () => zone.classList.remove('dragover');

        zone.addEventListener('dragover', e => { e.preventDefault(); highlight(); });
        zone.addEventListener('dragleave', unhighlight);
        zone.addEventListener('drop', e => {
            e.preventDefault(); unhighlight();
            const file = e.dataTransfer.files[0];
            if (file) processFile(file, previewId, actionsId, countId, onParsed);
        });

        input.addEventListener('change', () => {
            if (input.files[0]) processFile(input.files[0], previewId, actionsId, countId, onParsed);
        });
    }

    function processFile(file, previewId, actionsId, countId, onParsed) {
        const reader = new FileReader();
        reader.onload = e => {
            const parsed = parseCSV(e.target.result);
            onParsed(parsed);
            renderCSVPreview(parsed, previewId);
            const actions = document.getElementById(actionsId);
            const countEl = document.getElementById(countId);
            if (actions) actions.style.display = 'flex';
            if (countEl) countEl.textContent = `Import ${parsed.length} Asset${parsed.length !== 1 ? 's' : ''}`;
        };
        reader.readAsText(file);
    }

    function renderCSVPreview(assets, previewId) {
        const el = document.getElementById(previewId);
        if (!el) return;
        const max = 5;
        el.style.display = 'block';
        el.innerHTML = `
            <div class="inv-preview-header">
                <span class="material-symbols-outlined" style="font-size:16px; color:var(--primary);">table_view</span>
                Preview (${assets.length} rows detected${assets.length > max ? `, showing first ${max}` : ''})
            </div>
            <div class="inv-preview-table-wrap">
            <table class="inv-preview-table">
                <thead><tr>
                    <th>Asset ID</th><th>Product</th><th>Vendor</th><th>Version</th><th>Environment</th><th>Owner</th>
                </tr></thead>
                <tbody>
                ${assets.slice(0, max).map(a => `
                    <tr>
                        <td class="font-mono">${escapeHtml(a.id)}</td>
                        <td>${escapeHtml(a.product)}</td>
                        <td>${escapeHtml(a.vendor)}</td>
                        <td class="font-mono">${escapeHtml(a.version)}</td>
                        <td>${escapeHtml(a.environment)}</td>
                        <td>${escapeHtml(a.owner || '—')}</td>
                    </tr>`).join('')}
                </tbody>
            </table>
            </div>`;
    }

    function resetImportUI(...ids) {
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            if (id.includes('preview')) { el.style.display = 'none'; el.innerHTML = ''; }
            else if (id.includes('actions')) el.style.display = 'none';
        });
    }

    // --- Toast ---
    function showToast(message, isError = false) {
        const existing = document.getElementById('inv-toast');
        if (existing) existing.remove();
        const toast = document.createElement('div');
        toast.id = 'inv-toast';
        toast.className = 'inv-toast' + (isError ? ' inv-toast-error' : '');
        toast.innerHTML = `<span class="material-symbols-outlined">${isError ? 'error' : 'check_circle'}</span>${escapeHtml(message)}`;
        document.body.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('visible'));
        setTimeout(() => { toast.classList.remove('visible'); setTimeout(() => toast.remove(), 400); }, 3000);
    }

    return {
        getAll, addAsset, updateAsset, deleteAsset, clearAll, getCount,
        parseCSV, importAssets, exportCSV,
        initDashboardCard, openModal, closeModal, bindModalEvents,
        bindDropZone, processFile, showToast
    };
})();


// ===================================
// Inventory Page Controller
// ===================================

const InventoryPage = (() => {
    let _allAssets = [];
    let _filtered = [];
    let _sortCol = 'id';
    let _sortDir = 'asc';
    let _page = 1;
    const PAGE_SIZE = 20;
    let _editIndex = -1;
    let _pendingPageImport = [];

    function init() {
        initTheme();
        refresh();
        bindEvents();
    }

    function refresh(keepPage) {
        const shouldKeepPage = keepPage === true;
        _allAssets = InventoryManager.getAll();
        applyFilterSort(shouldKeepPage);
        renderSummary();
    }

    function applyFilterSort(keepPage = false) {
        const search = (document.getElementById('inv-search')?.value || '').toLowerCase();
        const envFilter = document.getElementById('inv-filter-env')?.value || '';

        _filtered = _allAssets.filter(a => {
            const matchSearch = !search ||
                (a.id || '').toLowerCase().includes(search) ||
                (a.product || '').toLowerCase().includes(search) ||
                (a.vendor || '').toLowerCase().includes(search) ||
                (a.version || '').toLowerCase().includes(search) ||
                (a.owner || '').toLowerCase().includes(search);
            const matchEnv = !envFilter || a.environment === envFilter;
            return matchSearch && matchEnv;
        });

        _filtered.sort((a, b) => {
            const va = (a[_sortCol] || '').toString().toLowerCase();
            const vb = (b[_sortCol] || '').toString().toLowerCase();
            const cmp = va.localeCompare(vb);
            return _sortDir === 'asc' ? cmp : -cmp;
        });

        if (!keepPage) {
            _page = 1;
        } else {
            const maxPage = Math.ceil(_filtered.length / PAGE_SIZE) || 1;
            if (_page > maxPage) _page = maxPage;
        }

        renderTable();
        renderPagination();
    }

    function renderSummary() {
        const all = _allAssets;
        const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
        setText('inv-stat-total', all.length.toLocaleString());
        setText('inv-stat-prod', all.filter(a => a.environment === 'Production').length);

        const subtitle = document.getElementById('inv-page-subtitle');
        if (subtitle) subtitle.textContent = all.length === 0
            ? 'No assets yet — import or add your first asset'
            : `${all.length} asset${all.length !== 1 ? 's' : ''} tracked across ${new Set(all.map(a => a.environment)).size} environment(s)`;
    }

    function renderTable() {
        const tbody = document.getElementById('inv-table-body');
        const emptyEl = document.getElementById('inv-empty-state');
        const noResultsEl = document.getElementById('inv-no-results');
        const resultCountEl = document.getElementById('inv-result-count');

        if (!tbody) return;

        if (resultCountEl) resultCountEl.textContent = `${_filtered.length} asset${_filtered.length !== 1 ? 's' : ''}`;

        if (_allAssets.length === 0) {
            tbody.innerHTML = '';
            if (emptyEl) emptyEl.style.display = 'flex';
            if (noResultsEl) noResultsEl.style.display = 'none';
            return;
        }

        if (_filtered.length === 0) {
            tbody.innerHTML = '';
            if (emptyEl) emptyEl.style.display = 'none';
            if (noResultsEl) noResultsEl.style.display = 'flex';
            return;
        }

        if (emptyEl) emptyEl.style.display = 'none';
        if (noResultsEl) noResultsEl.style.display = 'none';

        const start = (_page - 1) * PAGE_SIZE;
        const pageItems = _filtered.slice(start, start + PAGE_SIZE);

        tbody.innerHTML = pageItems.map((a) => {
            const globalIdx = _allAssets.indexOf(a);
            const envClass = `inv-env-${(a.environment || 'unknown').toLowerCase().replace(/[\/ ]/g, '-')}`;
            return `
                <tr class="inv-row" data-index="${globalIdx}">
                    <td class="inv-td inv-td-id">
                        <span class="font-mono" style="color:var(--primary); font-size:12px;">${escapeHtml(a.id || '—')}</span>
                    </td>
                    <td class="inv-td">
                        <div class="inv-product-cell">
                            <span class="inv-product-name">${escapeHtml(a.product || '—')}</span>
                            <span class="inv-vendor-name">${escapeHtml(a.vendor || '')}</span>
                        </div>
                    </td>
                    <td class="inv-td">
                        <code class="inv-version-code">${escapeHtml(a.version || '—')}</code>
                    </td>
                    <td class="inv-td">
                        <span class="inv-env-badge ${envClass}">${escapeHtml(a.environment || '—')}</span>
                    </td>
                    <td class="inv-td" style="color:var(--text-muted); font-size:13px;">${escapeHtml(a.owner || '—')}</td>
                    <td class="inv-td inv-td-actions">
                        <button class="inv-row-action inv-edit-btn" data-index="${globalIdx}" title="Edit">
                            <span class="material-symbols-outlined">edit</span>
                        </button>
                        <button class="inv-row-action inv-delete-btn" data-index="${globalIdx}" title="Delete">
                            <span class="material-symbols-outlined">delete</span>
                        </button>
                    </td>
                </tr>`;
        }).join('');

        tbody.querySelectorAll('.inv-edit-btn').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                openEditModal(parseInt(btn.dataset.index));
            });
        });

        tbody.querySelectorAll('.inv-delete-btn').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                try {
                    const idx = parseInt(btn.dataset.index);
                    // Temporarily bypass confirm() for testing
                    // if (confirm('Delete this asset?')) {
                    if (typeof InventoryManager !== 'undefined') {
                        InventoryManager.deleteAsset(idx);
                        refresh(true);
                        InventoryManager.showToast('Asset deleted successfully');
                    }
                    // }
                } catch (err) {
                    if (typeof InventoryManager !== 'undefined') {
                        InventoryManager.showToast('Delete error: ' + err.message, true);
                    }
                }
            });
        });
    }

    function renderPagination() {
        const el = document.getElementById('inv-pagination');
        const info = document.getElementById('inv-page-info');
        const prev = document.getElementById('inv-prev-page');
        const next = document.getElementById('inv-next-page');
        const totalPages = Math.ceil(_filtered.length / PAGE_SIZE);

        if (!el) return;
        el.style.display = totalPages > 1 ? 'flex' : 'none';
        if (info) info.textContent = `Page ${_page} of ${totalPages}`;
        if (prev) prev.disabled = _page <= 1;
        if (next) next.disabled = _page >= totalPages;
    }

    function openAddModal() {
        _editIndex = -1;
        const titleEl = document.getElementById('inv-page-modal-title');
        const subtitleEl = document.getElementById('inv-page-modal-subtitle');
        const iconEl = document.getElementById('inv-page-modal-icon');
        if (titleEl) titleEl.textContent = 'Add Asset';
        if (subtitleEl) subtitleEl.textContent = 'Fill in asset details below';
        if (iconEl) iconEl.textContent = 'add_circle';
        clearPageForm();
        openPageModal();
    }

    function openEditModal(idx) {
        _editIndex = idx;
        const asset = _allAssets[idx];
        if (!asset) return;
        const titleEl = document.getElementById('inv-page-modal-title');
        const subtitleEl = document.getElementById('inv-page-modal-subtitle');
        const iconEl = document.getElementById('inv-page-modal-icon');
        if (titleEl) titleEl.textContent = 'Edit Asset';
        if (subtitleEl) subtitleEl.textContent = `Editing ${asset.id}`;
        if (iconEl) iconEl.textContent = 'edit';
        document.getElementById('inv-pf-id').value = asset.id || '';
        document.getElementById('inv-pf-product').value = asset.product || '';
        document.getElementById('inv-pf-vendor').value = asset.vendor || '';
        document.getElementById('inv-pf-version').value = asset.version || '';
        document.getElementById('inv-pf-env').value = asset.environment || 'Production';
        document.getElementById('inv-pf-owner').value = asset.owner || '';
        openPageModal();
    }

    function openPageModal() {
        const overlay = document.getElementById('inv-page-modal-overlay');
        if (!overlay) return;
        overlay.classList.add('active');
        overlay.setAttribute('aria-hidden', 'false');
        document.body.style.overflow = 'hidden';
    }

    function closePageModal() {
        const overlay = document.getElementById('inv-page-modal-overlay');
        if (!overlay) return;
        overlay.classList.remove('active');
        overlay.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
        clearPageForm();
    }

    function clearPageForm() {
        ['inv-pf-id', 'inv-pf-product', 'inv-pf-vendor', 'inv-pf-version', 'inv-pf-owner'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        const envEl = document.getElementById('inv-pf-env');
        if (envEl) envEl.value = 'Production';
    }

    function openImportModal() {
        const overlay = document.getElementById('inv-page-import-overlay');
        if (!overlay) return;
        _pendingPageImport = [];
        resetPageImportUI();
        overlay.classList.add('active');
        overlay.setAttribute('aria-hidden', 'false');
        document.body.style.overflow = 'hidden';
    }

    function closeImportModal() {
        const overlay = document.getElementById('inv-page-import-overlay');
        if (!overlay) return;
        overlay.classList.remove('active');
        overlay.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
    }

    function resetPageImportUI() {
        const preview = document.getElementById('inv-page-csv-preview');
        const actions = document.getElementById('inv-page-import-actions');
        if (preview) { preview.style.display = 'none'; preview.innerHTML = ''; }
        if (actions) actions.style.display = 'none';
    }

    function bindEvents() {
        document.getElementById('inv-add-asset-btn')?.addEventListener('click', openAddModal);
        document.getElementById('inv-import-btn')?.addEventListener('click', openImportModal);
        document.getElementById('inv-export-btn')?.addEventListener('click', InventoryManager.exportCSV);

        document.getElementById('inv-clear-btn')?.addEventListener('click', () => {
            try {
                // Temporarily bypass confirm() for testing
                // if (confirm('Clear all assets from inventory? This cannot be undone.')) {
                InventoryManager.clearAll();
                refresh(true);
                InventoryManager.showToast('All assets cleared');
                // }
            } catch (err) {
                InventoryManager.showToast('Clear error: ' + err.message, true);
            }
        });

        document.getElementById('inv-page-modal-close')?.addEventListener('click', closePageModal);
        document.getElementById('inv-page-modal-cancel')?.addEventListener('click', closePageModal);
        document.getElementById('inv-page-modal-overlay')?.addEventListener('click', e => {
            if (e.target === document.getElementById('inv-page-modal-overlay')) closePageModal();
        });

        document.getElementById('inv-page-form')?.addEventListener('submit', e => {
            e.preventDefault();
            const asset = {
                id: document.getElementById('inv-pf-id').value.trim(),
                product: document.getElementById('inv-pf-product').value.trim(),
                vendor: document.getElementById('inv-pf-vendor').value.trim(),
                version: document.getElementById('inv-pf-version').value.trim(),
                environment: document.getElementById('inv-pf-env').value,
                owner: document.getElementById('inv-pf-owner').value.trim(),
            };
            if (_editIndex >= 0) {
                InventoryManager.updateAsset(_editIndex, asset);
                InventoryManager.showToast(`Asset "${asset.id}" updated.`);
            } else {
                InventoryManager.addAsset(asset);
                InventoryManager.showToast(`Asset "${asset.id}" added.`);
            }
            closePageModal();
            refresh();
        });

        document.getElementById('inv-page-import-close')?.addEventListener('click', closeImportModal);
        document.getElementById('inv-page-import-overlay')?.addEventListener('click', e => {
            if (e.target === document.getElementById('inv-page-import-overlay')) closeImportModal();
        });

        InventoryManager.bindDropZone(
            'inv-page-drop-zone', 'inv-page-file-input',
            'inv-page-csv-preview', 'inv-page-import-actions', 'inv-page-import-count',
            (parsed) => { _pendingPageImport = parsed; }
        );

        document.getElementById('inv-page-confirm-import')?.addEventListener('click', () => {
            if (_pendingPageImport.length) {
                const added = InventoryManager.importAssets(_pendingPageImport);
                closeImportModal();
                InventoryManager.showToast(`${added} assets imported.`);
                refresh();
            }
        });

        document.getElementById('inv-page-cancel-import')?.addEventListener('click', () => {
            _pendingPageImport = [];
            resetPageImportUI();
        });

        document.getElementById('inv-search')?.addEventListener('input', () => applyFilterSort(false));
        document.getElementById('inv-filter-env')?.addEventListener('change', () => applyFilterSort(false));

        document.querySelectorAll('.inv-th-sortable').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.dataset.col;
                if (_sortCol === col) { _sortDir = _sortDir === 'asc' ? 'desc' : 'asc'; }
                else { _sortCol = col; _sortDir = 'asc'; }
                document.querySelectorAll('.inv-th-sortable').forEach(t => t.classList.remove('sort-asc', 'sort-desc'));
                th.classList.add(_sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
                applyFilterSort();
            });
        });

        document.getElementById('inv-prev-page')?.addEventListener('click', () => {
            if (_page > 1) { _page--; renderTable(); renderPagination(); }
        });

        document.getElementById('inv-next-page')?.addEventListener('click', () => {
            const totalPages = Math.ceil(_filtered.length / PAGE_SIZE);
            if (_page < totalPages) { _page++; renderTable(); renderPagination(); }
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') { closePageModal(); closeImportModal(); }
        });

        window.addEventListener('inventory-changed', () => {
            if (window.location.pathname.includes('inventory')) refresh(true);
        });
    }

    return { init, refresh };
})();


// ===================================
// PoC Explainer Module
// ===================================

const PocExplainer = (() => {
    let _cveId = null;
    let _cveData = null;
    let _currentRepos = [];

    const LANG_DETECT_MAP = {
        'python': ['import ', 'def ', 'print(', 'requests.', '#!', 'subprocess', 'os.system'],
        'php': ['<?php', 'echo ', '$_', 'mysqli', 'shell_exec'],
        'javascript': ['const ', 'require(', 'fetch(', 'function ', 'console.log', '=>', 'async '],
        'bash': ['#!/bin/bash', 'curl ', 'wget ', 'echo ', 'chmod', 'sudo '],
        'ruby': ['require ', 'puts ', 'def ', '.rb', 'gem'],
        'java': ['import java', 'public class', 'System.out', '.java'],
        'go': ['package main', 'import (', 'func main', 'fmt.'],
        'c': ['#include', 'int main', 'printf', 'malloc', 'struct '],
        'powershell': ['Invoke-', 'Get-', 'Set-', 'New-', '.ps1', '$env:', 'Write-Host'],
        'perl': ['#!/usr/bin/perl', 'use strict', 'my $', 'print "', 'chomp'],
    };

    function detectLanguage(code) {
        if (!code || code.trim().length < 10) return 'plaintext';
        const lower = code.toLowerCase();
        let best = { lang: 'plaintext', score: 0 };
        for (const [lang, signals] of Object.entries(LANG_DETECT_MAP)) {
            let score = 0;
            signals.forEach(s => { if (lower.includes(s.toLowerCase())) score++; });
            if (score > best.score) best = { lang, score };
        }
        return best.lang;
    }

    function formatTimeAgo(dateStr) {
        if (!dateStr) return '';
        const date = new Date(dateStr);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);
        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
        if (diff < 86400 * 365) return `${Math.floor(diff / (86400 * 30))} mo ago`;
        return `${Math.floor(diff / (86400 * 365))}y ago`;
    }

    function getLangColor(lang) {
        const colors = {
            'Python': '#3b82f6', 'python': '#3b82f6',
            'JavaScript': '#facc15', 'javascript': '#facc15',
            'PHP': '#a855f7', 'php': '#a855f7',
            'Shell': '#4ade80', 'shell': '#4ade80',
            'Ruby': '#f87171', 'ruby': '#f87171',
            'Go': '#67e8f9', 'go': '#67e8f9',
            'C': '#94a3b8', 'c': '#94a3b8',
            'Java': '#fb923c', 'java': '#fb923c',
            'PowerShell': '#818cf8', 'powershell': '#818cf8',
            'Perl': '#6ee7b7', 'perl': '#6ee7b7',
        };
        return colors[lang] || '#94a3b8';
    }

    function updateLineNumbers(textarea, container) {
        const lines = textarea.value.split('\n');
        const count = Math.max(lines.length, 1);
        container.innerHTML = Array.from({ length: count }, (_, i) => `<span>${i + 1}</span>`).join('');
        container.scrollTop = textarea.scrollTop;
    }

    function updateLangBadge(code) {
        const langBadge = document.getElementById('poc-lang-detect');
        if (!langBadge) return;
        const lang = detectLanguage(code);
        const displayNames = {
            python: 'Python', php: 'PHP', javascript: 'JavaScript',
            bash: 'Shell/Bash', ruby: 'Ruby', java: 'Java',
            go: 'Go', c: 'C/C++', powershell: 'PowerShell', perl: 'Perl', plaintext: 'Plain Text'
        };
        langBadge.textContent = displayNames[lang] || lang;
    }

    function renderDiscoveryMeta(repos, cveData) {
        const avail = document.getElementById('poc-availability');
        const source = document.getElementById('poc-source');
        const lang = document.getElementById('poc-language');
        const type = document.getElementById('poc-exploit-type');
        const maturity = document.getElementById('poc-maturity');

        if (avail) {
            avail.innerHTML = repos.length > 0
                ? '<span class="poc-dot"></span> Public'
                : '<span style="color:var(--text-muted)">—</span> None found';
            avail.className = 'poc-meta-value ' + (repos.length > 0 ? 'poc-availability-public' : '');
        }

        if (source) {
            source.innerHTML = `<span class="material-symbols-outlined" style="font-size:13px;">hub</span> GitHub`;
            source.className = 'poc-meta-value poc-source-link';
        }

        if (lang && repos.length > 0) {
            const langCounts = {};
            repos.forEach(r => { if (r.language) langCounts[r.language] = (langCounts[r.language] || 0) + 1; });
            const topLang = Object.entries(langCounts).sort((a, b) => b[1] - a[1])[0];
            lang.textContent = topLang ? topLang[0] : '—';
        } else if (lang) {
            lang.textContent = '—';
        }

        const desc = (cveData && cveData.description || '').toLowerCase();
        let exploitType = '—', typeClass = '', maturityText = '—', maturityClass = '';

        if (desc.includes('remote code') || desc.includes('rce') || desc.includes('command execution')) {
            exploitType = 'Remote Code Execution (RCE)'; typeClass = 'poc-type-rce';
        } else if (desc.includes('sql') || desc.includes('injection')) {
            exploitType = 'SQL Injection (SQLi)'; typeClass = 'poc-type-sqli';
        } else if (desc.includes('file upload') || desc.includes('upload')) {
            exploitType = 'File Upload'; typeClass = 'poc-type-upload';
        } else if (desc.includes('path traversal') || desc.includes('local file') || desc.includes('lfi')) {
            exploitType = 'Local File Inclusion (LFI)'; typeClass = 'poc-type-lfi';
        } else if (desc.includes('deserialization') || desc.includes('deserializ')) {
            exploitType = 'Deserialization'; typeClass = '';
        } else if (desc.includes('privilege') || desc.includes('escalation')) {
            exploitType = 'Privilege Escalation'; typeClass = 'poc-type-upload';
        } else if (desc.includes('xss') || desc.includes('cross-site script')) {
            exploitType = 'Cross-Site Scripting (XSS)'; typeClass = 'poc-type-sqli';
        } else if (desc.includes('overflow') || desc.includes('buffer')) {
            exploitType = 'Buffer Overflow'; typeClass = 'poc-type-rce';
        }

        if (type) { type.textContent = exploitType; type.className = 'poc-meta-value ' + typeClass; }

        if (repos.length >= 3) { maturityText = 'Functional'; maturityClass = 'poc-maturity-functional'; }
        else if (repos.length >= 1) { maturityText = 'PoC'; maturityClass = 'poc-maturity-poc'; }
        else { maturityText = '—'; maturityClass = ''; }

        if (maturity) {
            maturity.textContent = maturityText;
            maturity.className = 'poc-maturity-badge ' + maturityClass;
        }
    }

    function renderRepos(repos) {
        const container = document.getElementById('poc-repos-container');
        if (!container) return;

        if (!repos || repos.length === 0) {
            container.innerHTML = `
                <div class="poc-no-results">
                    <span class="material-symbols-outlined" style="font-size:36px; color:var(--text-muted); display:block; margin-bottom:12px;">search_off</span>
                    <p>No public PoC repositories found for this CVE.</p>
                    <p style="margin-top:6px; font-size:12px;">You can still paste code manually in the editor below.</p>
                </div>`;
            return;
        }

        container.innerHTML = `
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px; display:flex; align-items:center; gap:6px;">
                <span class="material-symbols-outlined" style="font-size:14px;">hub</span>
                ${repos.length} public exploit repository${repos.length !== 1 ? 'ies' : 'y'} found on GitHub
            </div>
            ${repos.map((repo, idx) => renderRepoCard(repo, idx)).join('')}`;

        container.querySelectorAll('.poc-load-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const idx = parseInt(btn.dataset.idx, 10);
                if (_currentRepos[idx]) await loadRepoIntoEditor(_currentRepos[idx], idx);
            });
        });
    }

    function renderRepoCard(repo, idx) {
        const langColor = getLangColor(repo.language || '');
        const tags = (repo.topics || []).slice(0, 5);
        const timeAgo = formatTimeAgo(repo.updated_at);

        return `
            <div class="poc-repo-card">
                <div class="poc-repo-header">
                    <a href="${escapeHtml(repo.html_url || repo.url || '#')}" target="_blank" rel="noopener" class="poc-repo-name">
                        <span class="material-symbols-outlined" style="font-size:15px;">code_blocks</span>
                        ${escapeHtml(repo.full_name || repo.name || 'Unknown')}
                        <span class="material-symbols-outlined" style="font-size:13px; color:var(--text-muted);">open_in_new</span>
                    </a>
                    <div class="poc-repo-stats">
                        ${repo.stargazers_count !== undefined ? `
                        <span class="poc-repo-stat">
                            <span class="material-symbols-outlined">star</span>
                            ${repo.stargazers_count}
                        </span>` : ''}
                        ${repo.forks_count !== undefined ? `
                        <span class="poc-repo-stat">
                            <span class="material-symbols-outlined">fork_right</span>
                            ${repo.forks_count}
                        </span>` : ''}
                        ${timeAgo ? `
                        <span class="poc-update-time">
                            <span class="material-symbols-outlined">update</span>
                            ${escapeHtml(timeAgo)}
                        </span>` : ''}
                    </div>
                </div>
                ${repo.description ? `<div class="poc-repo-description">${escapeHtml(repo.description)}</div>` : ''}
                <div class="poc-repo-footer">
                    <div class="poc-repo-tags">
                        ${repo.language ? `<span class="poc-repo-lang" style="background:${langColor}22; color:${langColor}; border-color:${langColor}44;">${escapeHtml(repo.language)}</span>` : ''}
                        ${tags.map(t => `<span class="poc-repo-tag">${escapeHtml(t)}</span>`).join('')}
                    </div>
                    <div class="poc-repo-actions">
                        <button class="poc-btn-small poc-load-btn" data-idx="${idx}" title="Load into editor">
                            <span class="material-symbols-outlined">download</span>
                            Load Code
                        </button>
                        <a href="${escapeHtml(repo.html_url || repo.url || '#')}" target="_blank" rel="noopener" class="poc-btn-small">
                            <span class="material-symbols-outlined">open_in_new</span>
                            GitHub
                        </a>
                    </div>
                </div>
            </div>`;
    }
    const showLoadBanner = (type, message, hint) => {
        const container = document.getElementById('poc-load-banner-container');
        if (!container) return;
        const icon = type === 'success' ? 'check_circle' : 'warning';
        container.innerHTML = `
            <div class="poc-load-banner ${type}" style="display: flex;">
                <span class="material-symbols-outlined poc-load-banner-icon">${icon}</span>
                <div class="poc-load-banner-content">
                    <div>${message}</div>
                    ${hint ? `<div class="banner-hint">${hint}</div>` : ''}
                </div>
                <button class="poc-load-banner-close" onclick="this.parentElement.remove()" title="Close">
                    <span class="material-symbols-outlined">close</span>
                </button>
            </div>
        `;
        setTimeout(() => {
            const b = container.querySelector('.poc-load-banner');
            if (b) b.remove();
        }, 15000);
    };

    async function loadRepoIntoEditor(repo, btnIndex) {
        if (!repo || typeof repo !== 'object') return;
        const textarea = document.getElementById('poc-code-input');
        const filenameBadge = document.getElementById('poc-filename-badge');
        if (!textarea) return;

        const repoName = repo.full_name || repo.name || 'repo';
        const setPlaceholder = () => {
            const placeholder = `# Source: ${repoName}\n# URL: ${repo.html_url || repo.url || ''}\n# Stars: ${repo.stargazers_count || 0}\n# Language: ${repo.language || 'Unknown'}\n#\n# ${repo.description || 'No description'}\n#\n# Could not load file from GitHub. Paste exploit code here or open the repo link above.\n`;
            textarea.value = placeholder;
            if (filenameBadge) {
                filenameBadge.textContent = '—';
                filenameBadge.style.display = 'inline-flex';
            }
            updateLineNumbers(textarea, document.getElementById('poc-line-numbers'));
            updateLangBadge(textarea.value);
        };

        const btn = typeof btnIndex === 'number' ? document.querySelector(`.poc-load-btn[data-idx="${btnIndex}"]`) : null;
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = 'Loading…';
        }
        try {
            const data = await ApiService.fetchRepoFile(repoName);
            const content = (data.content != null) ? String(data.content) : '';
            const path = data.path || 'file';
            textarea.value = content;
            if (filenameBadge) {
                filenameBadge.textContent = path;
                filenameBadge.style.display = 'inline-flex';
            }
            updateLineNumbers(textarea, document.getElementById('poc-line-numbers'));
            updateLangBadge(textarea.value);

            showLoadBanner(
                'success',
                `Loaded <strong>${escapeHtml(path)}</strong> from <a href="https://github.com/${escapeHtml(repoName)}" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline;">${escapeHtml(repoName)}</a>`,
                'The system automatically selects the most probable exploit/PoC file from the repository root. If this is not the right file, you can manually copy and paste the correct code.'
            );
        } catch (err) {
            console.warn('Load code from GitHub failed:', err.message);
            setPlaceholder();
            if (filenameBadge) filenameBadge.title = err.message || 'Load failed';

            showLoadBanner(
                'warning',
                `Could not automatically load code from <strong>${escapeHtml(repoName)}</strong>.`,
                `${escapeHtml(err.message || 'No suitable file found in repo root')}. Please open the repository link and manually copy/paste the exploit code.`
            );
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<span class="material-symbols-outlined">download</span> Load Code';
            }
        }
        textarea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        textarea.focus();
    }

    function showAILoading() {
        const panel = document.getElementById('poc-ai-content');
        if (!panel) return;
        panel.innerHTML = `
            <div class="poc-ai-loading">
                <div class="poc-ai-loading-spinner"></div>
                <div class="poc-ai-loading-text">
                    AI is analyzing the exploit code
                    <span class="poc-ai-loading-dots"><span>.</span><span>.</span><span>.</span></span>
                </div>
                <div style="font-size: 12px; color: var(--text-muted); text-align: center; margin-top: 4px;">
                    Examining payload structure, attack mechanics,<br>detection opportunities and mitigations
                </div>
            </div>`;
    }

    function renderAIAnalysis(analysis) {
        const panel = document.getElementById('poc-ai-content');
        if (!panel || !analysis) return;

        // If backend returned raw JSON string inside overview, try re-parsing
        if (typeof analysis.overview === 'string' && analysis.overview.trim().startsWith('{')) {
            let raw = analysis.overview.trim();
            try {
                const parsed = JSON.parse(raw);
                if (parsed && typeof parsed === 'object') analysis = parsed;
            } catch (_) {
                // Truncated JSON — try common suffixes
                const suffixes = ['"}', '"}]}', '"]}', '"}]}'];
                for (const s of suffixes) {
                    try {
                        const parsed = JSON.parse(raw + s);
                        if (parsed && typeof parsed === 'object') { analysis = parsed; break; }
                    } catch (_2) { /* keep trying */ }
                }
            }
        }

        const sections = [
            {
                key: 'overview', title: 'Exploit Overview', icon: 'travel_explore', iconClass: 'overview',
                render: (v) => `<div class="poc-analysis-section-body">${renderMarkdown(v)}</div>`
            },
            {
                key: 'cve_relationship', title: 'CVE Relationship', icon: 'link', iconClass: 'overview',
                render: (v) => `<div class="poc-analysis-section-body">${renderMarkdown(v)}</div>`
            },
            {
                key: 'mechanics', title: 'Exploit Mechanics', icon: 'settings', iconClass: 'mechanics',
                render: (v) => `<div class="poc-analysis-section-body">${renderMarkdown(v)}</div>`
            },
            {
                key: 'code_flow', title: 'Code Execution Flow', icon: 'account_tree', iconClass: 'mechanics',
                render: (v) => `<div class="poc-analysis-section-body">${renderMarkdown(v)}</div>`
            },
            {
                key: 'key_functions', title: 'Key Functions', icon: 'functions', iconClass: 'payload',
                render: (v) => {
                    const items = Array.isArray(v) ? v : [];
                    if (items.length === 0) return '';
                    return `<div class="poc-analysis-section-body">
                        <ul style="margin: 8px 0 0 0; padding-left: 20px; color: var(--text-secondary); line-height: 1.6;">
                            ${items.map(f => `<li style="margin-bottom:8px;"><strong style="color:var(--text-primary); font-family:var(--font-mono); font-size:12px; background:rgba(255,255,255,0.05); padding:2px 6px; border-radius:4px;">${escapeHtml(f.name || 'Function')}</strong><br>${escapeHtml(f.description || '')}</li>`).join('')}
                        </ul>
                    </div>`;
                }
            },
            {
                key: 'payload', title: 'Payload Analysis', icon: 'code', iconClass: 'payload',
                render: (v) => `<div class="poc-analysis-section-body">${renderMarkdown(v)}</div>`
            },
            {
                key: 'steps', title: 'Exploitation Steps', icon: 'format_list_numbered', iconClass: 'steps',
                render: (v) => {
                    const items = Array.isArray(v) ? v : (typeof v === 'string' ? v.split('\n').filter(Boolean) : []);
                    return `<ol class="poc-analysis-steps-list">
                        ${items.map((s, i) => `
                            <li class="poc-analysis-step-item">
                                <span class="poc-step-number">${i + 1}</span>
                                <span class="poc-step-text">${escapeHtml(String(s).replace(/^\d+\.\s*/, ''))}</span>
                            </li>`).join('')}
                    </ol>`;
                }
            },
            {
                key: 'detection', title: 'Detection Opportunities', icon: 'manage_search', iconClass: 'detection',
                render: (v) => `<div class="poc-analysis-section-body">${renderMarkdown(v)}</div>`
            },
            {
                key: 'mitigation', title: 'Mitigation Suggestions', icon: 'shield', iconClass: 'mitigation',
                render: (v) => `<div class="poc-analysis-section-body">${renderMarkdown(v)}</div>`
            }
        ];

        let html = '';
        sections.forEach(s => {
            const value = analysis[s.key];
            if (!value || (Array.isArray(value) && value.length === 0)) return;
            html += `
                <div class="poc-analysis-section">
                    <div class="poc-analysis-section-header">
                        <div class="poc-analysis-section-icon ${s.iconClass}">
                            <span class="material-symbols-outlined" style="font-size:15px;">${s.icon}</span>
                        </div>
                        <span class="poc-analysis-section-title">${s.title}</span>
                    </div>
                    ${s.render(value)}
                </div>`;
        });

        if (analysis.highlighted_line) {
            html += `
                <div class="poc-analysis-section">
                    <div class="poc-highlighted-line-label">Key Line Identified</div>
                    <div class="poc-highlighted-line">${escapeHtml(analysis.highlighted_line)}</div>
                    ${analysis.highlighted_explanation ? `<div style="font-size:12px; color:var(--text-muted); margin-top:6px;">${escapeHtml(analysis.highlighted_explanation)}</div>` : ''}
                </div>`;
        }

        panel.innerHTML = html || `<div class="poc-ai-placeholder"><p style="color:var(--text-muted); text-align:center;">No analysis data returned.</p></div>`;
    }

    const ATTACK_NODE_ICONS = {
        attacker: 'person', endpoint: 'dns', exploit: 'bug_report',
        payload: 'upload_file', delivery: 'send', execution: 'terminal',
        persistence: 'manage_accounts', exfiltration: 'cloud_upload',
        pivoting: 'device_hub', cleanup: 'cleaning_services'
    };

    function renderAttackPath(attackPath) {
        const section = document.getElementById('poc-attack-path-section');
        const container = document.getElementById('poc-attack-path-nodes');
        if (!section || !container || !attackPath || attackPath.length === 0) return;

        const defaultSteps = [
            { type: 'attacker', title: 'Attacker', description: 'Initiates attack' },
            { type: 'endpoint', title: 'Vulnerable Endpoint', description: 'Target identified' },
            { type: 'exploit', title: 'Exploit Trigger', description: 'Vulnerability triggered' },
            { type: 'payload', title: 'Payload Delivery', description: 'Malicious payload sent' },
            { type: 'execution', title: 'Code Execution', description: 'Remote command executed' },
            { type: 'persistence', title: 'Post Exploitation', description: 'Attacker gains control' }
        ];

        const steps = (attackPath.length > 0 ? attackPath : defaultSteps);
        let html = '';
        steps.forEach((step, idx) => {
            const iconName = ATTACK_NODE_ICONS[step.type] || 'arrow_forward';
            const delay = idx * 80;
            html += `
                <div class="poc-attack-node" style="animation-delay: ${delay}ms;">
                    <div class="poc-attack-node-icon ${step.type || 'generic'}">
                        <span class="material-symbols-outlined">${iconName}</span>
                    </div>
                    <div class="poc-attack-node-info">
                        <div class="poc-attack-node-title">${escapeHtml(step.title || '')}</div>
                        <div class="poc-attack-node-desc">${escapeHtml(step.description || '')}</div>
                    </div>
                </div>`;
            if (idx < steps.length - 1) {
                html += `
                    <div class="poc-attack-arrow">
                        <svg width="28" height="20" viewBox="0 0 28 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M2 10 L22 10 M16 4 L22 10 L16 16" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </div>`;
            }
        });

        container.innerHTML = html;
        section.style.display = 'block';
        section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    async function runSearch(cveId) {
        const loading = document.getElementById('poc-repos-loading');
        const container = document.getElementById('poc-repos-container');

        if (container) container.innerHTML = `<div class="poc-repos-loading" id="poc-repos-loading">
            <div class="skeleton-block" style="height:80px; border-radius:10px; margin-bottom:12px;"></div>
            <div class="skeleton-block" style="height:80px; border-radius:10px; margin-bottom:12px;"></div>
            <div class="skeleton-block" style="height:80px; border-radius:10px;"></div>
        </div>`;

        let data;
        const cached = window.__pocSearchResult;
        if (cached && cached.cveId === cveId) {
            data = { repos: cached.repos || [], total: cached.total ?? (cached.repos && cached.repos.length) };
        } else {
            try {
                data = await ApiService.searchPoc(cveId);
            } catch (err) {
                if (container) container.innerHTML = `
                    <div class="poc-no-results">
                        <span class="material-symbols-outlined" style="font-size:32px; color:#f87171; display:block; margin-bottom:10px;">wifi_off</span>
                        <p>GitHub search unavailable: ${escapeHtml(err.message)}</p>
                        <p style="margin-top:6px; font-size:12px; color:var(--text-muted);">You can still paste code manually in the editor.</p>
                    </div>`;
                return;
            }
        }
        _currentRepos = data.repos || [];
        renderDiscoveryMeta(_currentRepos, _cveData);
        renderRepos(_currentRepos);
    }

    async function runAnalysis() {
        const textarea = document.getElementById('poc-code-input');
        const analyzeBtn = document.getElementById('poc-analyze-btn');
        if (!textarea) return;

        const code = textarea.value.trim();
        if (!code) {
            textarea.focus();
            textarea.style.borderColor = '#f87171';
            setTimeout(() => { textarea.style.borderColor = ''; }, 2000);
            return;
        }

        if (analyzeBtn) {
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = `<span class="material-symbols-outlined" style="font-size:16px; animation:spin 0.9s linear infinite;">sync</span> Analyzing...`;
        }

        showAILoading();

        const attackSection = document.getElementById('poc-attack-path-section');
        if (attackSection) attackSection.style.display = 'none';

        try {
            const result = await ApiService.analyzeExploit(code, _cveData, currentModel);
            const analysis = result.analysis || {};
            renderAIAnalysis(analysis);
            if (analysis.attack_path && analysis.attack_path.length > 0) {
                renderAttackPath(analysis.attack_path);
            }
        } catch (err) {
            const panel = document.getElementById('poc-ai-content');
            if (panel) panel.innerHTML = `
                <div class="poc-ai-placeholder">
                    <span class="material-symbols-outlined" style="font-size:40px; color:#f87171; display:block; margin-bottom:12px;">error</span>
                    <p style="color:#f87171; font-size:13px; text-align:center;">${escapeHtml(err.message)}</p>
                </div>`;
        } finally {
            if (analyzeBtn) {
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = `<span class="material-symbols-outlined" style="font-size:16px;">psychology</span> Analyze with AI`;
            }
        }
    }

    function bindEditorEvents() {
        const textarea = document.getElementById('poc-code-input');
        const lineNums = document.getElementById('poc-line-numbers');
        const clearBtn = document.getElementById('poc-clear-btn');
        const copyBtn = document.getElementById('poc-copy-btn');
        const analyzeBtn = document.getElementById('poc-analyze-btn');
        const searchBtn = document.getElementById('poc-search-btn');

        if (textarea && lineNums) {
            textarea.addEventListener('input', () => {
                updateLineNumbers(textarea, lineNums);
                updateLangBadge(textarea.value);
            });
            textarea.addEventListener('scroll', () => { lineNums.scrollTop = textarea.scrollTop; });
            textarea.addEventListener('keydown', (e) => {
                if (e.key === 'Tab') {
                    e.preventDefault();
                    const start = textarea.selectionStart;
                    const end = textarea.selectionEnd;
                    textarea.value = textarea.value.substring(0, start) + '    ' + textarea.value.substring(end);
                    textarea.selectionStart = textarea.selectionEnd = start + 4;
                    updateLineNumbers(textarea, lineNums);
                }
            });
            textarea.addEventListener('paste', () => {
                setTimeout(() => {
                    updateLineNumbers(textarea, lineNums);
                    updateLangBadge(textarea.value);
                }, 10);
            });
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                if (textarea) { textarea.value = ''; updateLineNumbers(textarea, lineNums); updateLangBadge(''); }
                const filenameBadge = document.getElementById('poc-filename-badge');
                if (filenameBadge) filenameBadge.style.display = 'none';
                const panel = document.getElementById('poc-ai-content');
                if (panel) panel.innerHTML = `<div class="poc-ai-placeholder">
                    <span class="material-symbols-outlined" style="font-size:48px; color:var(--text-muted); display:block; margin-bottom:16px;">psychology</span>
                    <p style="color:var(--text-muted); font-size:14px; line-height:1.7; text-align:center;">
                        Paste or load exploit code,<br>then click <strong style="color:var(--text-secondary);">Analyze with AI</strong> to get a<br>structured breakdown.
                    </p></div>`;
                const attackSection = document.getElementById('poc-attack-path-section');
                if (attackSection) attackSection.style.display = 'none';
            });
        }

        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                if (textarea && textarea.value) {
                    navigator.clipboard.writeText(textarea.value).then(() => {
                        copyBtn.innerHTML = '<span class="material-symbols-outlined" style="color:#4ade80;">check</span>';
                        setTimeout(() => { copyBtn.innerHTML = '<span class="material-symbols-outlined">content_copy</span>'; }, 1500);
                    });
                }
            });
        }

        if (analyzeBtn) analyzeBtn.addEventListener('click', runAnalysis);

        if (searchBtn) searchBtn.addEventListener('click', () => { if (_cveId) runSearch(_cveId); });
    }

    function init(cveId) {
        _cveId = cveId;
        _cveData = window.__currentCveData || null;

        bindEditorEvents();

        const lineNums = document.getElementById('poc-line-numbers');
        const textarea = document.getElementById('poc-code-input');
        if (textarea && lineNums) updateLineNumbers(textarea, lineNums);

        // Trigger reveal animation for static sections
        setTimeout(() => {
            document.querySelectorAll('#poc-content .section-reveal').forEach(el => {
                el.classList.add('visible');
            });
        }, 80);

        if (cveId) runSearch(cveId);
    }

    return { init };
})();


// ===================================
// Initialize on DOM Ready
// ===================================

document.addEventListener('DOMContentLoaded', function () {
    const path = window.location.pathname;
    const isWorkflow = path.includes('workflow');
    const isInventory = path.includes('inventory');

    if (isWorkflow) {
        initWorkflow().catch(err => {
            console.error('Workflow init error:', err);
            showErrorState(err.message || 'Analysis failed to start.');
            updateProcessingBadge('error');
        });
    } else if (isInventory) {
        InventoryPage.init();
    } else {
        initDashboard();
        InventoryManager.initDashboardCard();
        InventoryManager.bindModalEvents();
    }
});
