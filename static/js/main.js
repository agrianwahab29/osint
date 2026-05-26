/**
 * OSINT TOOL v3.0 — Progress-Tracked Scanner
 * Real-time progress bar, module-by-module status, polling.
 */

const API_BASE = '';
let currentReportId = null;
let pollingInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    checkServerHealth();
    setupNavigation();
    setupQuickSearch();
    setupFullScan();
    setupModuleSearches();
    setupReportModal();
    setupMobileMenu();
});

// ============================================================
// SERVER HEALTH
// ============================================================

async function checkServerHealth() {
    const statusEl = document.getElementById('serverStatus');
    try {
        const res = await fetch(`${API_BASE}/api/health`);
        const data = await res.json();
        if (data.status === 'online') {
            statusEl.innerHTML = `<span class="status-dot online"></span><span class="status-text">v3.0 — ${data.total_modules} modules</span>`;
            const badge = document.getElementById('activeModules');
            if (badge) badge.textContent = `${data.total_modules || 9} Modules`;
        }
    } catch {
        statusEl.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Offline</span>';
    }
}

// ============================================================
// NAVIGATION
// ============================================================

function setupNavigation() {
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            document.querySelectorAll('.nav-item[data-page]').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
            const target = document.getElementById(page === 'dashboard' ? 'dashboard' : page + '-page');
            if (target) target.classList.add('active');
            document.getElementById('sidebar').classList.remove('open');
        });
    });
}

function setupMobileMenu() {
    const btn = document.getElementById('mobileMenuBtn');
    const sb = document.getElementById('sidebar');
    if (btn && sb) btn.addEventListener('click', () => sb.classList.toggle('open'));
}

// ============================================================
// QUICK SEARCH
// ============================================================

function setupQuickSearch() {
    const input = document.getElementById('quickSearch');
    const btn = document.getElementById('quickSearchBtn');
    if (!input || !btn) return;

    const execute = () => {
        const q = input.value.trim();
        if (!q) return showToast('Masukkan target', 'error');
        const payload = {};
        if (q.includes('@')) payload.email = q;
        else if (q.includes('.') && !q.includes(' ') && !q.match(/^[\d+]/)) payload.domain = q;
        else if (q.match(/^\+?\d{7,15}$/)) payload.phone = q;
        else payload.name = q;
        startScan(payload);
    };
    btn.addEventListener('click', execute);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') execute(); });
}

// ============================================================
// FULL SCAN WITH PROGRESS
// ============================================================

function setupFullScan() {
    const btn = document.getElementById('runAllModules');
    if (!btn) return;
    btn.addEventListener('click', () => {
        const name = document.getElementById('targetName')?.value.trim() || '';
        const email = document.getElementById('targetEmail')?.value.trim() || '';
        const domain = document.getElementById('targetDomain')?.value.trim() || '';
        const phone = document.getElementById('targetPhone')?.value.trim() || '';
        if (!name && !email && !domain && !phone) return showToast('Minimal isi satu field', 'error');
        startScan({ name, email, domain, phone });
    });
}

async function startScan(payload) {
    const overlay = document.getElementById('loadingOverlay');
    const resultsContainer = document.getElementById('resultsContainer');

    // Clear previous
    if (pollingInterval) { clearInterval(pollingInterval); pollingInterval = null; }
    resultsContainer.style.display = 'none';
    resultsContainer.innerHTML = '';

    // Show overlay with progress UI
    overlay.classList.remove('hidden');
    overlay.innerHTML = `
        <div class="scan-progress-container">
            <h2>Running OSINT Scan</h2>
            <div class="progress-bar-wrapper">
                <div class="progress-bar" id="progressBar" style="width: 0%"></div>
            </div>
            <div class="progress-text" id="progressText">0% — Starting...</div>
            <div class="module-status-list" id="moduleStatusList">
                <div class="module-status-item"><span class="status-spinner"></span> Initializing modules...</div>
            </div>
            <div class="progress-errors" id="progressErrors" style="display:none"></div>
        </div>
    `;

    const scanBtn = document.getElementById('runAllModules');
    if (scanBtn) scanBtn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.success) {
            currentReportId = data.report_id;
            // Start polling progress
            startPolling(currentReportId);
        } else {
            overlay.classList.add('hidden');
            showToast('Error: ' + (data.error || 'Unknown'), 'error');
            if (scanBtn) scanBtn.disabled = false;
        }
    } catch (err) {
        overlay.classList.add('hidden');
        showToast('Connection error: ' + err.message, 'error');
        if (scanBtn) scanBtn.disabled = false;
    }
}

function startPolling(reportId) {
    const moduleNames = {
        'name_search': 'Web & Name Search',
        'social_media': 'Social Media Scan',
        'email_finder': 'Email Intelligence',
        'people_search': 'People Search Aggregator',
        'breach_checker': 'Breach Database Check',
        'darkweb_intel': 'Dark Web Intelligence',
        'domain_checker': 'Domain Intelligence',
        'phone_finder': 'Phone Intelligence',
    };

    let seenModules = new Set();

    pollingInterval = setInterval(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/progress/${reportId}`);
            const progress = await res.json();

            // Update progress bar
            const pct = progress.percent || 0;
            const bar = document.getElementById('progressBar');
            const text = document.getElementById('progressText');
            if (bar) bar.style.width = pct + '%';
            if (text) text.textContent = `${pct}% — ${progress.current_module ? moduleNames[progress.current_module] || progress.current_module : 'Processing...'}`;

            // Update module status list
            const listEl = document.getElementById('moduleStatusList');
            const modules = progress.modules || [];
            const errors = progress.errors || [];

            if (listEl && modules.length > 0) {
                let html = '';
                modules.forEach(mod => {
                    const modName = moduleNames[mod] || mod;
                    if (seenModules.has(mod)) {
                        // Module already done
                        const hasError = errors.some(e => e.includes(mod));
                        html += `<div class="module-status-item ${hasError ? 'error' : 'done'}">
                            <span class="status-icon">${hasError ? '⚠️' : '✅'}</span> ${modName}
                        </div>`;
                    } else {
                        // Still running or pending
                        const isCurrent = progress.current_module === mod;
                        html += `<div class="module-status-item ${isCurrent ? 'running' : 'pending'}">
                            <span class="status-icon">${isCurrent ? '🔄' : '⏳'}</span> ${modName}
                        </div>`;
                    }
                });
                listEl.innerHTML = html;
            }

            // Mark completed modules
            const doneCount = progress.modules_done || 0;
            for (let i = 0; i < doneCount && i < modules.length; i++) {
                seenModules.add(modules[i]);
            }

            // Check if complete
            if (progress.status === 'completed') {
                clearInterval(pollingInterval);
                pollingInterval = null;

                // Show errors if any
                if (errors.length > 0) {
                    const errEl = document.getElementById('progressErrors');
                    if (errEl) {
                        errEl.style.display = 'block';
                        errEl.innerHTML = '<h4>Errors:</h4><ul>' + errors.map(e => `<li>${e}</li>`).join('') + '</ul>';
                    }
                    showToast(`Scan complete with ${errors.length} module error(s)`, 'warning');
                } else {
                    showToast('Scan complete! All modules successful.', 'success');
                }

                // Fetch results and render
                setTimeout(async () => {
                    try {
                        const resultsRes = await fetch(`${API_BASE}/api/results/${reportId}`);
                        const resultsData = await resultsRes.json();
                        if (resultsData.success) {
                            const loadingOverlay = document.getElementById('loadingOverlay');
                            loadingOverlay.classList.add('hidden');
                            renderResults(resultsData.results);
                            updateStats(resultsData.results);
                        }
                    } catch (err) {
                        document.getElementById('loadingOverlay').classList.add('hidden');
                        showToast('Failed to load results: ' + err.message, 'error');
                    }
                    const scanBtn = document.getElementById('runAllModules');
                    if (scanBtn) scanBtn.disabled = false;
                }, 800);
            }
        } catch (err) {
            // polling error — ignore, retry next interval
        }
    }, 600);
}

// ============================================================
// RENDER RESULTS
// ============================================================

function renderResults(results) {
    const container = document.getElementById('resultsContainer');
    container.style.display = 'block';
    let html = '<div class="results-wrapper">';

    // Name Search
    const nd = results.name_search;
    if (nd && !nd.error) {
        const webCount = (nd.web_results || []).length;
        const ghCount = (nd.github_profiles || []).length;
        const wikiCount = (nd.wikipedia_mentions || []).length;
        html += `<div class="card"><h3>🌐 Web & Name Intelligence <span class="badge badge-info">${webCount + ghCount + wikiCount} results</span></h3>`;

        if (webCount > 0) {
            html += '<div class="results-scroll">';
            nd.web_results.slice(0, 20).forEach(r => {
                html += `<div class="result-card">
                    <h4>${esc(r.title || 'Untitled')}</h4>
                    <a href="${r.url || '#'}" target="_blank" class="url">${r.display_url || r.url || ''}</a>
                    <span class="tag tag-info">${r.source || ''}</span>
                </div>`;
            });
            html += '</div>';
        } else {
            html += '<p class="text-muted">No web results found. Try a different name format.</p>';
        }

        if (ghCount > 0) {
            html += '<h4 class="mt-2 mb-1">💻 GitHub Profiles</h4>';
            nd.github_profiles.slice(0, 8).forEach(g => {
                html += `<div class="result-card"><div class="profile-row">
                    <div><strong>${esc(g.username || '')}</strong>
                    <span class="badge badge-info">${g.type || 'User'}</span>
                    <br><a href="${g.url || '#'}" target="_blank">${g.url || ''}</a></div>
                </div></div>`;
            });
        }

        if (wikiCount > 0) {
            html += '<h4 class="mt-2 mb-1">📚 Wikipedia</h4>';
            nd.wikipedia_mentions.slice(0, 5).forEach(w => {
                html += `<div class="result-card">
                    <h4>${esc(w.title || '')}</h4>
                    <p class="snippet">${esc((w.snippet || '').substring(0, 250))}</p>
                    <a href="${w.url || '#'}" target="_blank">Open</a>
                </div>`;
            });
        }

        html += '</div>';
    }

    // Social Media
    const sd = results.social_media;
    if (sd && !sd.error) {
        const found = sd.profiles_found || [];
        const nfCount = (sd.profiles_not_found || []).length;
        html += `<div class="card mt-2"><h3>👤 Social Media Scan <span class="badge badge-success">${found.length} found</span> <span class="badge">${nfCount} not found</span></h3>`;

        if (found.length > 0) {
            html += '<table class="osint-table"><tr><th>Platform</th><th>Username</th><th>Confidence</th><th>Category</th></tr>';
            found.forEach(p => {
                const confBadge = p.confidence === 'high' ? 'badge-success' : p.confidence === 'medium' ? 'badge-warning' : 'badge-info';
                html += `<tr>
                    <td><strong>${cap(p.platform || '')}</strong></td>
                    <td><a href="${p.url || '#'}" target="_blank">${p.username || ''}</a></td>
                    <td><span class="badge ${confBadge}">${p.confidence || 'low'}</span></td>
                    <td><span class="tag">${p.category || ''}</span></td>
                </tr>`;
            });
            html += '</table>';
        } else {
            html += '<p class="text-muted">No social profiles found with generated usernames.</p>';
        }
        html += '</div>';
    }

    // People Search
    const pd = results.people_search;
    if (pd && !pd.error) {
        const agg = pd.aggregated || {};
        html += `<div class="card mt-2"><h3>🔎 People Search Aggregator <span class="badge badge-info">${agg.sites_with_results || 0} sites with data</span></h3>`;

        if ((agg.all_emails || []).length > 0) {
            html += '<p><strong>📧 Emails:</strong> ';
            agg.all_emails.forEach(e => { html += `<span class="tag tag-danger">${e}</span> `; });
            html += '</p>';
        }
        if ((agg.all_phones || []).length > 0) {
            html += '<p><strong>📱 Phones:</strong> ';
            agg.all_phones.forEach(p => { html += `<span class="tag tag-warning">${p}</span> `; });
            html += '</p>';
        }
        if ((agg.all_profiles || []).length > 0) {
            html += '<p><strong>🔗 Profiles:</strong> ';
            agg.all_profiles.forEach(p => { html += `<span class="tag tag-found">${p.platform}:${p.username}</span> `; });
            html += '</p>';
        }
        if ((pd.direct_search_links || []).length > 0) {
            html += '<p class="mt-2"><strong>Direct Links:</strong> ';
            pd.direct_search_links.forEach(l => {
                html += `<a href="${l.url}" target="_blank" class="tag tag-info" style="margin:2px">${l.name}</a> `;
            });
            html += '</p>';
        }
        if (!agg.all_emails?.length && !agg.all_phones?.length && !agg.all_profiles?.length) {
            html += '<p class="text-muted">No data found from people search aggregators.</p>';
        }
        html += '</div>';
    }

    // Email Finder
    const ed = results.email_finder;
    if (ed && !ed.error && ed.total_generated > 0) {
        html += `<div class="card mt-2"><h3>📧 Email Intelligence <span class="badge">${ed.total_generated} permutations</span></h3>`;
        html += `<p>Valid: <strong>${(ed.valid_emails || []).length}</strong> | Breached: <strong class="text-danger">${(ed.breached_emails || []).length}</strong></p>`;

        (ed.breached_emails || []).forEach(b => {
            html += `<div class="breach-card">
                <h4>⚠️ ${esc(b.email || '')}</h4>
                <p>Breaches: <strong>${b.total_breaches}</strong> | Risk: <span class="text-danger">${b.risk_level || '?'}</span></p>
            </div>`;
        });
        html += '</div>';
    }

    // Breach Check
    const bd = results.breach_checker;
    if (bd && !bd.error) {
        const hibp = bd.hibp_breaches || {};
        const sum = bd.summary || {};
        html += `<div class="card mt-2"><h3>🔓 Breach Database</h3>`;

        if (hibp.breached) {
            html += `<p><strong class="text-danger">${hibp.total_breaches} breaches found</strong> | Risk: <span class="badge badge-danger">${hibp.risk_level || sum.risk_level || '?'}</span></p>`;
            (hibp.breaches || []).slice(0, 8).forEach(b => {
                html += `<div class="breach-card">
                    <h4>${esc(b.title || b.name || '')}</h4>
                    <p>${b.breach_date || '?'} | ${(b.pwn_count || 0).toLocaleString()} records</p>
                    <p class="snippet">${esc((b.description || '').substring(0, 250))}</p>
                    <div>${(b.data_classes || []).slice(0,5).map(c => `<span class="tag tag-danger">${c}</span>`).join('')}</div>
                </div>`;
            });
        } else {
            html += '<p class="text-success">No known breaches found.</p>';
        }

        if ((sum.recommendations || []).length > 0) {
            html += '<p class="mt-2"><strong>🔒 Recommendations:</strong></p><ul>';
            sum.recommendations.forEach(r => { html += `<li>${r}</li>`; });
            html += '</ul>';
        }
        html += '</div>';
    }

    // Dark Web
    const dd = results.darkweb_intel;
    if (dd && !dd.error) {
        html += `<div class="card mt-2"><h3>🕶️ Dark Web Intel</h3>`;
        html += `<p>Matches: <strong>${dd.total_matches || 0}</strong></p>`;

        const exp = dd.breach_exposure || {};
        if (exp.level && exp.level !== 'UNKNOWN') {
            html += `<p>Exposure: <span class="badge badge-${exp.level === 'ELEVATED' ? 'danger' : 'warning'}">${exp.level}</span></p>`;
        }
        if ((dd.recommendations || []).length > 0) {
            dd.recommendations.slice(0, 3).forEach(r => {
                html += `<div class="result-card"><strong>[${r.priority}]</strong> ${r.action}<br><small>${r.detail}</small></div>`;
            });
        }
        html += '</div>';
    }

    // Domain
    const dod = results.domain_checker;
    if (dod && !dod.error && dod.clean_domain) {
        html += `<div class="card mt-2"><h3>🏢 Domain: ${dod.clean_domain}</h3>`;
        const ssl = dod.ssl_info || {};
        html += `<p>SSL: ${ssl.valid ? '<span class="text-success">Valid</span>' : '<span class="text-danger">Invalid</span>'}`;
        if (ssl.days_remaining > 0) html += ` | ${ssl.days_remaining} days left`;
        html += '</p>';

        const secH = dod.security_headers || {};
        html += `<p>Security: ${secH.score || 0}/${secH.total || 10} | Grade: <span class="badge badge-${(secH.grade || 'F')[0] === 'A' ? 'success' : 'warning'}">${secH.grade || 'F'}</span></p>`;
        html += '</div>';
    }

    // Phone
    const phd = results.phone_finder;
    if (phd && !phd.error && phd.cleaned) {
        html += `<div class="card mt-2"><h3>📱 Phone: ${phd.cleaned}</h3>`;
        const ci = phd.country_info || {};
        const pi = phd.provider_info || {};
        html += `<p>Country: ${ci.country || '?'} | Provider: ${pi.provider || '?'} — ${pi.product || ''}</p>`;
        if ((phd.variants || []).length > 0) {
            phd.variants.forEach(v => {
                html += `<a href="${v.value}" target="_blank" class="tag tag-info" style="margin:2px">${v.format}</a> `;
            });
        }
        html += '</div>';
    }

    // Risk Summary
    const risks = (nd && nd.risk_indicators) ? nd.risk_indicators : [];
    if (risks.length > 0) {
        html += '<div class="card mt-2"><h3>⚠️ Risk Summary</h3>';
        risks.forEach(r => {
            const cls = (r.level === 'HIGH' || r.level === 'MEDIUM') ? 'danger' : r.level === 'LOW' ? 'warning' : 'info';
            html += `<div class="result-card">
                <span class="badge badge-${cls}">${r.level}</span>
                <strong>${r.type || r.indicator || ''}</strong>
                <p class="snippet">${r.detail || ''}</p>
            </div>`;
        });
        html += '</div>';
    }

    // Errors summary
    if (results.errors && results.errors.length > 0) {
        html += '<div class="card mt-2"><h3>❌ Module Errors</h3><ul>';
        results.errors.forEach(e => {
            html += `<li class="text-danger">${e.module || ''}: ${e.error || e}</li>`;
        });
        html += '</ul></div>';
    }

    html += '</div>';
    container.innerHTML = html;
    container.scrollIntoView({ behavior: 'smooth' });
}

// ============================================================
// STATS
// ============================================================

function updateStats(results) {
    const nd = results.name_search || {};
    const sd = results.social_media || {};
    const ed = results.email_finder || {};
    const bd = results.breach_checker || {};

    setStat('statWeb', (nd.web_results || []).length);
    setStat('statSocial', (sd.summary || {}).total_found || (sd.profiles_found || []).length);
    setStat('statEmail', ed.total_generated || 0);
    setStat('statBreach', ((bd.hibp_breaches || {}).total_breaches || (bd.summary || {}).total_unique_breaches || 0));
    setStat('statGithub', (nd.github_profiles || []).length);
    setStat('statRisk', (bd.hibp_breaches || {}).risk_level || (bd.summary || {}).risk_level || '—');
}

function setStat(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ============================================================
// MODULE SEARCHES (individual pages)
// ============================================================

function setupModuleSearches() {
    bindSearch('nameSearchBtn', 'nameSearchInput', 'nameSearchResults', '/api/name', 'name');
    bindSearch('socialSearchBtn', 'socialSearchInput', 'socialSearchResults', '/api/social', 'name');
    bindSearch('emailSearchBtn', 'emailSearchInput', 'emailSearchResults', '/api/email', 'name');
    bindSearch('domainSearchBtn', 'domainSearchInput', 'domainSearchResults', '/api/domain', 'domain');
    bindSearch('breachSearchBtn', 'breachSearchInput', 'breachSearchResults', '/api/breach', 'email');
    bindSearch('phoneSearchBtn', 'phoneSearchInput', 'phoneSearchResults', '/api/phone', 'phone');
    bindSearch('peopleSearchBtn', 'peopleSearchInput', 'peopleSearchResults', '/api/people', 'name');
    bindSearch('darkwebSearchBtn', 'darkwebSearchInput', 'darkwebSearchResults', '/api/darkweb', 'query');
    bindSearch('whoisSearchBtn', 'whoisSearchInput', 'whoisSearchResults', '/api/whois', 'domain');
    bindSearch('dorksSearchBtn', 'dorksSearchInput', 'dorksSearchResults', '/api/dorks', 'target');
    bindSearch('shodanSearchBtn', 'shodanSearchInput', 'shodanSearchResults', '/api/shodan', 'target');
    bindSearch('vtSearchBtn', 'vtSearchInput', 'vtSearchResults', '/api/virustotal', 'target');
    bindSearch('hunterSearchBtn', 'hunterSearchInput', 'hunterSearchResults', '/api/hunter', 'domain');
    bindSearch('intelxSearchBtn', 'intelxSearchInput', 'intelxSearchResults', '/api/intelx', 'query');
    bindSearch('telegramSearchBtn', 'telegramSearchInput', 'telegramSearchResults', '/api/telegram', 'target');
}

function bindSearch(btnId, inputId, resultId, endpoint, field) {
    const btn = document.getElementById(btnId);
    const inp = document.getElementById(inputId);
    const div = document.getElementById(resultId);
    if (!btn || !inp || !div) return;

    btn.addEventListener('click', async () => {
        const val = inp.value.trim();
        if (!val) return showToast('Field wajib diisi', 'error');
        div.innerHTML = '<div class="spinner"></div>';
        try {
            const payload = {};
            payload[field] = val;
            const res = await fetch(`${API_BASE}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            div.innerHTML = `<pre class="result-card" style="overflow-x:auto;font-size:0.8em;max-height:500px;overflow-y:auto;">${JSON.stringify(data, null, 2)}</pre>`;
        } catch (err) {
            div.innerHTML = `<p class="text-danger">Error: ${err.message}</p>`;
        }
    });
}

// ============================================================
// REPORT
// ============================================================

function setupReportModal() {
    const modal = document.getElementById('reportModal');
    const openBtn = document.getElementById('generateReportBtn');
    const closeBtn = document.getElementById('closeModal');
    const content = document.getElementById('reportContent');

    if (!openBtn || !modal) return;

    openBtn.addEventListener('click', async () => {
        modal.classList.remove('hidden');
        content.innerHTML = '<div class="text-center"><div class="spinner"></div><p>Generating...</p></div>';

        try {
            const name = document.getElementById('targetName')?.value || document.getElementById('quickSearch')?.value || 'Unknown';
            const payload = { name };
            if (currentReportId) payload.report_id = currentReportId;

            const res = await fetch(`${API_BASE}/api/report/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.success) {
                const r = data.report;
                content.innerHTML = `
                    <p class="text-success">✅ Report generated!</p>
                    <p>ID: <code>${r.report_id}</code></p>
                    <p>Files:</p>
                    <ul><li>HTML</li><li>JSON</li><li>Text</li></ul>`;
                document.getElementById('downloadJsonBtn').onclick = () => window.open(`${API_BASE}/api/report/download/${r.report_id}/json`);
                document.getElementById('downloadHtmlBtn').onclick = () => window.open(`${API_BASE}/api/report/download/${r.report_id}/html`);
                document.getElementById('downloadTxtBtn').onclick = () => window.open(`${API_BASE}/api/report/download/${r.report_id}/text`);
            } else {
                content.innerHTML = `<p class="text-danger">${data.error}</p>`;
            }
        } catch (err) {
            content.innerHTML = `<p class="text-danger">${err.message}</p>`;
        }
    });

    closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    modal.addEventListener('click', e => { if (e.target === modal) modal.classList.add('hidden'); });
}

// ============================================================
// UTILS
// ============================================================

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function cap(s) {
    if (!s) return '';
    return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function showToast(msg, type) {
    const ct = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    ct.appendChild(t);
    setTimeout(() => {
        t.style.opacity = '0';
        t.style.transition = 'opacity 0.3s';
        setTimeout(() => t.remove(), 300);
    }, 4000);
}
