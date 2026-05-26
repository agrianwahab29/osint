/**
 * OSINT TOOL v3.0 — Main JavaScript
 * 9 modules, aggressive search, real results
 */

const API_BASE = '';
let currentReportId = null;
let lastResults = null;

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
    const status = document.getElementById('serverStatus');
    try {
        const res = await fetch(`${API_BASE}/api/health`);
        const data = await res.json();
        if (data.status === 'online') {
            status.innerHTML = `<span class="status-dot online"></span><span class="status-text">v3.0 — ${data.total_modules} modules</span>`;
        }
        document.getElementById('activeModules').textContent = `${data.total_modules || 9} Modules`;
    } catch {
        status.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Offline</span>';
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
        runOSINT(payload);
    };
    btn.addEventListener('click', execute);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') execute(); });
}

// ============================================================
// FULL SCAN
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
        runOSINT({ name, email, domain, phone });
    });
}

async function runOSINT(payload) {
    const overlay = document.getElementById('loadingOverlay');
    const container = document.getElementById('resultsContainer');
    const detail = document.getElementById('loadingDetail');

    overlay.classList.remove('hidden');
    container.style.display = 'none';
    container.innerHTML = '';

    const steps = [
        'Scanning web sources (Google, DDG, Bing)...',
        'Checking 40+ social media platforms...',
        'Generating email permutations...',
        'Searching people databases...',
        'Checking breach databases & dark web...',
        'Aggregating results...',
    ];
    let i = 0;
    const iv = setInterval(() => { if (i < steps.length) { detail.textContent = steps[i]; i++; } }, 1200);

    btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        clearInterval(iv);

        if (data.success) {
            currentReportId = data.report_id;
            lastResults = data.results;
            showToast('Scan complete! Results loaded.', 'success');
            renderResults(data.results);
            updateStats(data.results);
        } else {
            showToast('Error: ' + (data.error || 'Unknown'), 'error');
        }
    } catch (err) {
        clearInterval(iv);
        showToast('Connection error: ' + err.message, 'error');
    } finally {
        overlay.classList.add('hidden');
        btn.disabled = false;
    }
}

// ============================================================
// RENDER RESULTS
// ============================================================

function renderResults(results) {
    const container = document.getElementById('resultsContainer');
    container.style.display = 'block';
    let html = '';

    // Name Search
    const nd = results.name_search;
    if (nd && !nd.error) {
        html += sectionHeader('Web & Name Intelligence', (nd.web_results || []).length + (nd.github_profiles || []).length + (nd.wikipedia_mentions || []).length);

        if ((nd.web_results || []).length > 0) {
            html += '<h4 class="mb-2">Search Results</h4>';
            nd.web_results.slice(0, 20).forEach(r => {
                html += `<div class="result-card">
                    <h4>${esc(r.title || 'Untitled')}</h4>
                    <a href="${r.url || '#'}" target="_blank" class="url">${r.display_url || r.url || ''}</a>
                    <span class="tag tag-info">${r.source || ''}</span>
                </div>`;
            });
        } else {
            html += '<p class="text-muted">No search results. Try different name format.</p>';
        }

        if ((nd.github_profiles || []).length > 0) {
            html += '<h4 class="mt-4 mb-2">GitHub Profiles</h4>';
            nd.github_profiles.slice(0, 8).forEach(g => {
                html += `<div class="result-card"><div class="profile-row">
                    <img src="${g.avatar || ''}" onerror="this.style.display='none'" width="32" height="32" style="border-radius:50%">
                    <div><strong>${esc(g.username || '')}</strong> <span class="badge badge-info">${g.type || 'User'}</span>
                    <br><a href="${g.url || '#'}" target="_blank">${g.url || ''}</a></div>
                </div></div>`;
            });
        }

        if ((nd.wikipedia_mentions || []).length > 0) {
            html += '<h4 class="mt-4 mb-2">Wikipedia</h4>';
            nd.wikipedia_mentions.slice(0, 5).forEach(w => {
                html += `<div class="result-card">
                    <h4>${esc(w.title || '')}</h4>
                    <p class="snippet">${esc((w.snippet || '').substring(0, 250))}</p>
                    <a href="${w.url || '#'}" target="_blank">Open</a>
                </div>`;
            });
        }
    }

    // Social Media
    const sd = results.social_media;
    if (sd && !sd.error) {
        const found = sd.profiles_found || [];
        const summary = sd.summary || {};
        html += sectionHeader(`Social Media (${summary.total_found || found.length} found / ${(sd.profiles_not_found || []).length} not found)`);

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
            html += '<p class="text-muted">No social profiles found with generated usernames. Try a specific username search.</p>';
        }
    }

    // People Search
    const pd = results.people_search;
    if (pd && !pd.error) {
        const agg = pd.aggregated || {};
        html += sectionHeader('People Search Aggregator');

        if ((agg.all_emails || []).length > 0) {
            html += '<p><strong>Emails Found:</strong> ';
            agg.all_emails.forEach(e => { html += `<span class="tag tag-danger">${e}</span> `; });
            html += '</p>';
        }
        if ((agg.all_phones || []).length > 0) {
            html += '<p><strong>Phones:</strong> ';
            agg.all_phones.forEach(p => { html += `<span class="tag tag-warning">${p}</span> `; });
            html += '</p>';
        }
        if ((agg.all_profiles || []).length > 0) {
            html += '<p><strong>Linked Profiles:</strong> ';
            agg.all_profiles.forEach(p => { html += `<span class="tag tag-found">${p.platform}: ${p.username}</span> `; });
            html += '</p>';
        }
        if (agg.sites_with_results > 0) {
            html += `<p class="text-success">Found results on ${agg.sites_with_results} people search sites</p>`;
        } else {
            html += '<p class="text-muted">No data from people search aggregators.</p>';
        }

        if ((pd.direct_search_links || []).length > 0) {
            html += '<p class="mt-2"><strong>Direct Search Links:</strong></p>';
            pd.direct_search_links.forEach(l => {
                html += `<a href="${l.url}" target="_blank" class="tag tag-info" style="margin:2px">${l.name}</a> `;
            });
        }
    }

    // Email Finder
    const ed = results.email_finder;
    if (ed && !ed.error && ed.total_generated > 0) {
        html += sectionHeader(`Email Intelligence (${ed.total_generated} permutations)`);
        html += `<p>Valid: <strong>${(ed.valid_emails || []).length}</strong> | Breached: <strong class="text-danger">${(ed.breached_emails || []).length}</strong></p>`;

        (ed.breached_emails || []).forEach(b => {
            html += `<div class="breach-card">
                <h4>${esc(b.email || '')}</h4>
                <p>Breaches: <strong>${b.total_breaches}</strong> | Risk: <span class="text-danger">${b.risk_level || '?'}</span></p>
            </div>`;
        });
    }

    // Breach Check
    const bd = results.breach_checker;
    if (bd && !bd.error) {
        const hibp = bd.hibp_breaches || {};
        const sum = bd.summary || {};
        html += sectionHeader('Breach Database Check');

        if (hibp.breached) {
            html += `<p>Total: <strong class="text-danger">${hibp.total_breaches}</strong> breaches | Risk: <span class="badge badge-danger">${hibp.risk_level || sum.risk_level || '?'}</span></p>`;
            (hibp.breaches || []).slice(0, 8).forEach(b => {
                html += `<div class="breach-card">
                    <h4>${esc(b.title || b.name || '')}</h4>
                    <p>Date: ${b.breach_date || '?'} | Records: ${(b.pwn_count || 0).toLocaleString()}</p>
                    <p class="snippet">${esc((b.description || '').substring(0, 250))}</p>
                    <div class="mt-2">${(b.data_classes || []).slice(0,5).map(c => `<span class="tag tag-danger">${c}</span>`).join('')}</div>
                </div>`;
            });
        } else {
            html += '<p class="text-success">No known breaches for this query.</p>';
        }

        if ((sum.recommendations || []).length > 0) {
            html += '<p class="mt-2"><strong>Recommendations:</strong></p><ul>';
            sum.recommendations.forEach(r => { html += `<li>${r}</li>`; });
            html += '</ul>';
        }
    }

    // Dark Web
    const dd = results.darkweb_intel;
    if (dd && !dd.error) {
        html += sectionHeader('Dark Web Intelligence');
        html += `<p>Matches across breach databases: <strong>${dd.total_matches || 0}</strong></p>`;

        const exp = dd.breach_exposure || {};
        if (exp.level && exp.level !== 'UNKNOWN') {
            html += `<p>Exposure: <span class="badge badge-${exp.level === 'ELEVATED' ? 'danger' : 'warning'}">${exp.level}</span></p>`;
        }

        if ((dd.recommendations || []).length > 0) {
            dd.recommendations.slice(0, 3).forEach(r => {
                html += `<div class="result-card"><strong>[${r.priority}]</strong> ${r.action}<br><span class="snippet">${r.detail}</span></div>`;
            });
        }
    }

    // Domain Intel
    const dod = results.domain_checker;
    if (dod && !dod.error && dod.clean_domain) {
        html += sectionHeader('Domain Intelligence');
        html += `<p><strong>Domain:</strong> ${dod.clean_domain}</p>`;
        const ssl = dod.ssl_info || {};
        html += `<p><strong>SSL:</strong> ${ssl.valid ? '<span class="text-success">Valid</span>' : '<span class="text-danger">Invalid</span>'}`;
        if (ssl.days_remaining > 0) html += ` | ${ssl.days_remaining} days remaining`;
        html += '</p>';

        if ((dod.subdomains_found || []).length > 0) {
            html += '<p><strong>Subdomains:</strong> ';
            dod.subdomains_found.forEach(s => { html += `<span class="tag tag-found">${s.subdomain || ''}</span> `; });
            html += '</p>';
        }

        const sech = dod.security_headers || {};
        html += `<p><strong>Security Headers:</strong> ${sech.score || 0}/${sech.total || 10} | Grade: <span class="badge badge-${(sech.grade || 'F')[0] === 'A' ? 'success' : 'warning'}">${sech.grade || 'F'}</span></p>`;
    }

    // Phone
    const phd = results.phone_finder;
    if (phd && !phd.error && phd.cleaned) {
        html += sectionHeader('Phone Intelligence');
        const ci = phd.country_info || {};
        const pi = phd.provider_info || {};
        html += `<p><strong>Number:</strong> ${phd.cleaned} | Country: ${ci.country || '?'}</p>`;
        if (pi.provider) html += `<p><strong>Provider:</strong> ${pi.provider} — ${pi.product || ''} (${pi.type || ''})</p>`;
        if ((phd.variants || []).length > 0) {
            html += '<p><strong>Links:</strong> ';
            phd.variants.forEach(v => { html += `<a href="${v.value}" target="_blank" class="tag tag-info">${v.format}</a> `; });
            html += '</p>';
        }
    }

    // Risk Summary
    const riskIndicators = [];
    if (nd && nd.risk_indicators) riskIndicators.push(...nd.risk_indicators);
    if (riskIndicators.length > 0) {
        html += sectionHeader('Risk Summary');
        riskIndicators.forEach(r => {
            const cls = r.level === 'HIGH' || r.level === 'MEDIUM' ? 'danger' : r.level === 'LOW' ? 'warning' : 'info';
            html += `<div class="result-card"><span class="badge badge-${cls}">${r.level}</span> <strong>${r.type || r.indicator || ''}</strong><br><span class="snippet">${r.detail || ''}</span></div>`;
        });
    }

    container.innerHTML = html;
    container.scrollIntoView({ behavior: 'smooth' });
}

function sectionHeader(title, count) {
    return `<div class="card mt-2"><h3>${title}</h3>`;
}

// ============================================================
// STATS
// ============================================================

function updateStats(results) {
    const nd = results.name_search || {};
    const sd = results.social_media || {};
    const ed = results.email_finder || {};
    const bd = results.breach_checker || {};
    const pd = results.people_search || {};

    setStat('statWeb', (nd.web_results || []).length);
    setStat('statSocial', (sd.summary || {}).total_found || (sd.profiles_found || []).length);
    setStat('statEmail', ed.total_generated || 0);
    setStat('statBreach', (bd.summary || {}).total_unique_breaches || (bd.hibp_breaches || {}).total_breaches || 0);
    setStat('statGithub', (nd.github_profiles || []).length);
    setStat('statRisk', (bd.hibp_breaches || {}).risk_level || (bd.summary || {}).risk_level || '—');
}

function setStat(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ============================================================
// MODULE SEARCHES
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
}

function bindSearch(btnId, inputId, resultId, endpoint, field) {
    const btn = document.getElementById(btnId);
    const inp = document.getElementById(inputId);
    const div = document.getElementById(resultId);
    if (!btn || !inp || !div) return;

    btn.addEventListener('click', async () => {
        const val = inp.value.trim();
        if (!val) return showToast('Field wajib diisi', 'error');
        try {
            const payload = {};
            payload[field] = val;
            const res = await fetch(`${API_BASE}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            div.innerHTML = `<pre class="result-card" style="overflow-x:auto;font-family:monospace;font-size:0.8em;max-height:500px;overflow-y:auto;">${JSON.stringify(data, null, 2)}</pre>`;
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
        content.innerHTML = '<div class="text-center"><div class="spinner"></div><p>Generating report...</p></div>';

        try {
            const name = document.getElementById('targetName')?.value || document.getElementById('quickSearch')?.value || 'Unknown';
            const res = await fetch(`${API_BASE}/api/report/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await res.json();
            if (data.success) {
                const r = data.report;
                content.innerHTML = `
                    <p class="text-success">Report generated!</p>
                    <p>ID: <code>${r.report_id}</code></p>
                    <p><strong>Files:</strong></p>
                    <ul><li>HTML: <code>${r.files.html}</code></li><li>JSON: <code>${r.files.json}</code></li><li>Text: <code>${r.files.text}</code></li></ul>`;
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

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function cap(s) { if (!s) return ''; return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()); }

function showToast(msg, type) {
    const ct = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    ct.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; setTimeout(() => t.remove(), 300); }, 4000);
}
