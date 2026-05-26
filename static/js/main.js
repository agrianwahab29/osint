/**
 * OSINT TOOL v6.0 — Forensic Intelligence Dashboard
 * Evidence-based, confidence-scored, forensic-ready.
 */
const API = '';
let reportId = null;
let pollTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    health();
    tabs();
    scanForm();
    historyTab();
    reportTab();
    document.getElementById('serverStatus').addEventListener('click', toggleApiStatus);
    // Advanced input toggle
    const advBtn = document.getElementById('toggleAdvanced');
    if (advBtn) advBtn.addEventListener('click', toggleAdvanced);
});

// ============================================================
// HEALTH — now shows version + module count consistently
// ============================================================
async function health() {
    const el = document.getElementById('serverStatus');
    try {
        const r = await fetch(`${API}/api/health`);
        const d = await r.json();
        const modCount = d.modules || '?';
        const ver = d.version || '6.0';
        el.innerHTML = `<span class="status-dot on"></span><span>v${ver} — ${modCount} modules — Free Mode</span>`;
        // Update header version
        const hv = document.getElementById('headerVersion');
        if (hv) hv.textContent = `v${ver}`;
    } catch {
        el.innerHTML = '<span class="status-dot off"></span><span>Offline</span>';
    }
}

// ============================================================
// API STATUS PANEL
// ============================================================
async function toggleApiStatus() {
    const panel = document.getElementById('apiStatusPanel');
    if (panel.classList.contains('hidden')) {
        await loadApiStatus();
        panel.classList.remove('hidden');
    } else {
        panel.classList.add('hidden');
    }
}

async function loadApiStatus() {
    const grid = document.getElementById('apiStatusGrid');
    grid.innerHTML = '<div class="text-center"><div class="spin"></div></div>';
    try {
        const r = await fetch(`${API}/api/status`);
        const d = await r.json();
        const services = d.services || {};

        let html = '';
        for (const [key, svc] of Object.entries(services)) {
            const enabled = svc.enabled;
            const cls = enabled ? 'api-item ok' : 'api-item disabled';
            const icon = enabled ? '✅' : '⛔';
            html += `<div class="${cls}">
                <span class="api-icon">${icon}</span>
                <span class="api-label">${esc(svc.label)}</span>
                <span class="api-badge badge-${enabled ? 'ok' : 'gray'}">${enabled ? 'Active' : 'Disabled'}</span>
                ${!enabled && svc.reason ? `<small class="api-reason">${esc(svc.reason)}</small>` : ''}
            </div>`;
        }
        grid.innerHTML = html || '<p class="text-muted">No services configured.</p>';
    } catch {
        grid.innerHTML = '<p class="text-danger">Failed to load API status.</p>';
    }
}

// ============================================================
// TABS
// ============================================================
function tabs() {
    document.querySelectorAll('.tab[data-tab]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            const target = document.getElementById('tab-' + btn.dataset.tab);
            if (target) target.classList.add('active');
            if (btn.dataset.tab === 'history') loadHistory();
            if (btn.dataset.tab === 'report') {
                const inp = document.getElementById('reportIdInput');
                if (reportId && !inp.value) inp.value = reportId;
            }
        });
    });
}

// ============================================================
// TOGGLE ADVANCED INPUTS
// ============================================================
function toggleAdvanced() {
    const row = document.getElementById('advancedInputs');
    const btn = document.getElementById('toggleAdvanced');
    const isClosed = row.classList.contains('collapse-row');
    if (isClosed || row.classList.contains('closed')) {
        row.classList.remove('collapse-row', 'closed');
        row.classList.add('open');
        if (btn) btn.textContent = '- Advanced';
    } else {
        row.classList.add('collapse-row', 'closed');
        row.classList.remove('open');
        if (btn) btn.textContent = '+ Advanced';
    }
}

// ============================================================
// SCAN FORM
// ============================================================
function scanForm() {
    const inputs = ['targetName', 'targetEmail', 'targetDomain', 'targetPhone'];
    const btn = document.getElementById('runScan');

    const check = () => {
        const hasVal = inputs.some(id => document.getElementById(id).value.trim());
        btn.disabled = !hasVal;
    };
    inputs.forEach(id => document.getElementById(id).addEventListener('input', check));

    btn.addEventListener('click', () => {
        const name = document.getElementById('targetName').value.trim();
        const email = document.getElementById('targetEmail').value.trim();
        const domain = document.getElementById('targetDomain').value.trim();
        const phone = document.getElementById('targetPhone').value.trim();
        const username = document.getElementById('targetUsername').value.trim();
        const country = document.getElementById('targetCountry').value;
        const scanMode = document.getElementById('scanMode').value;
        if (!name && !email && !domain && !phone) return toast('Isi minimal 1 field', 'error');
        runScan({ name, email, domain, phone, username, country, scan_mode: scanMode });
    });
}

async function runScan(payload) {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

    const findings = document.getElementById('findings');
    findings.style.display = 'none';
    findings.innerHTML = '';

    const btn = document.getElementById('runScan');
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> Scanning...';

    const panel = document.getElementById('progressPanel');
    panel.classList.remove('hidden');

    try {
        const r = await fetch(`${API}/api/search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const d = await r.json();
        if (d.success) {
            reportId = d.report_id;
            document.getElementById('reportIdInput').value = reportId;
            pollProgress(d.report_id);
        } else {
            panel.classList.add('hidden');
            toast(d.error || 'Scan failed', 'error');
            resetBtn();
        }
    } catch (e) {
        panel.classList.add('hidden');
        toast('Connection error', 'error');
        resetBtn();
    }
}

// ============================================================
// PROGRESS POLLING
// ============================================================
const MOD_NAMES = {
    name_search: 'Web & Name', social_media: 'Social Media', email_finder: 'Email Intel',
    people_search: 'People Search', darkweb_intel: 'Exposure Intel',
    domain_checker: 'Domain Intel', phone_finder: 'Phone Intel', whois_recon: 'WHOIS/DNS',
    google_dorks: 'Google Dorks', shodan_intel: 'Shodan', virustotal_intel: 'VirusTotal',
    hunter_io: 'Hunter.io', intelx_search: 'IntelX', telegram_osint: 'Telegram',
    github_intel: 'GitHub Intel', public_email_extractor: 'Public Email', password_exposure: 'Password Check'
};

function pollProgress(rid) {
    const done = new Set();
    let seen = [];

    pollTimer = setInterval(async () => {
        try {
            const r = await fetch(`${API}/api/progress/${rid}`);
            const p = await r.json();

            const pct = p.percent || 0;
            const fill = document.getElementById('progressFill');
            const pctEl = document.getElementById('progressPct');
            const modEl = document.getElementById('progressMod');
            const modsEl = document.getElementById('progressModules');

            if (fill) fill.style.width = pct + '%';
            if (pctEl) pctEl.textContent = pct + '%';
            if (modEl) modEl.textContent = p.current_module ? (MOD_NAMES[p.current_module] || p.current_module) : 'Processing...';

            const modules = p.modules || [];
            const errors = p.errors || [];
            if (modules.length > 0 && !seen.length) seen = [...modules];

            if (modsEl && seen.length) {
                const doneCount = p.modules_done || 0;
                let html = '';
                seen.forEach((m, i) => {
                    const nm = MOD_NAMES[m] || m;
                    const isDone = i < doneCount;
                    const isCurrent = p.current_module === m && !isDone;
                    const isErr = errors.some(e => e.includes(m));
                    let cls = 'pending', ico = '⏳';
                    if (isDone && isErr) { cls = 'error'; ico = '⚠️'; }
                    else if (isDone) { cls = 'done'; ico = '✅'; }
                    else if (isCurrent) { cls = 'running'; ico = '🔄'; }
                    html += `<div class="pm-item ${cls}"><span>${ico}</span> ${nm}</div>`;
                });
                modsEl.innerHTML = html;
            }

            updatePills(seen, p.modules_done || 0, errors);

            if (p.status === 'completed') {
                clearInterval(pollTimer); pollTimer = null;
                toast('Scan selesai!', 'success');
                setTimeout(() => fetchResults(rid), 500);
            }
        } catch {}
    }, 600);
}

function updatePills(modules, doneCount, errors) {
    const pills = document.querySelectorAll('.module-pill');
    const pillMap = {
        '🌐 Web': 'name_search', '👤 Social': 'social_media', '📧 Email': 'email_finder',
        '💻 GitHub': 'github_intel', '🛡️ Domain': 'domain_checker',
        '📱 Phone': 'phone_finder', '🔎 People': 'people_search',
        '🕶️ Exposure': 'darkweb_intel', '🎯 Dorks': 'google_dorks',
        '🔍 WHOIS': 'whois_recon'
    };
    pills.forEach(pill => {
        const txt = pill.textContent.trim();
        const mod = pillMap[txt];
        if (!mod || !modules.includes(mod)) return;
        const idx = modules.indexOf(mod);
        pill.className = 'module-pill';
        if (idx < doneCount) {
            const isErr = errors.some(e => e.includes(mod));
            pill.classList.add(isErr ? 'error' : 'done');
        } else if (idx === doneCount) {
            pill.classList.add('running');
        }
    });
}

async function fetchResults(rid) {
    try {
        const r = await fetch(`${API}/api/results/${rid}`);
        const d = await r.json();
        if (d.success) {
            document.getElementById('progressPanel').classList.add('hidden');
            renderFindings(d.results, d.findings_summary);
            updateStats(d.results, d.findings);
        }
    } catch (e) {
        document.getElementById('progressPanel').classList.add('hidden');
        toast('Failed to load results', 'error');
    }
    resetBtn();
}

function resetBtn() {
    const btn = document.getElementById('runScan');
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-scan-icon">🚀</span><span>SCAN ALL MODULES</span>';
    document.querySelectorAll('.module-pill').forEach(p => p.className = 'module-pill');
}

// ============================================================
// RENDER FINDINGS — FORENSIC GRADE
// ============================================================
function renderFindings(r, findingsSummary) {
    const c = document.getElementById('findings');
    c.style.display = 'flex';
    let html = '';

    // ===== Web & Name Intelligence =====
    const nd = r.name_search;
    if (nd && !nd.error) {
        const wc = (nd.web_results || []).length;
        const gc = (nd.github_profiles || []).length;
        const wk = (nd.wikipedia_mentions || []).length;
        const total = wc + gc + wk;
        const hasContent = total > 0;
        html += cardPanel('🌐 Web & Name Intelligence', total, 'verified', 'public_web_search', hasContent, () => {
            let h = '';
            if (wc) {
                h += '<h4 class="result-subtitle">Web Results</h4>';
                nd.web_results.slice(0, 20).forEach(x => {
                    const confBadge = confidenceBadge(60, 'Medium');
                    h += `<div class="r-item">
                        <h4>${esc(x.title||'')}</h4>
                        <a href="${safeUrl(x.url)}" target="_blank" class="url">${esc(x.display_url||x.url||'')}</a>
                        <div class="r-meta">
                            <span class="tag tag-source">${esc(x.source||'web')}</span>
                            ${confBadge}
                        </div>
                    </div>`;
                });
            }
            if (gc) {
                h += '<h4 class="result-subtitle">💻 GitHub Profiles</h4>';
                nd.github_profiles.slice(0, 8).forEach(g => {
                    h += `<div class="r-item">
                        <strong>${esc(g.username||'')}</strong>
                        <span class="badge badge-info">${g.type||'User'}</span>
                        <br><a href="${safeUrl(g.url)}" target="_blank" class="url">${esc(g.url||'')}</a>
                    </div>`;
                });
            }
            if (wk) {
                h += '<h4 class="result-subtitle">📚 Wikipedia</h4>';
                nd.wikipedia_mentions.slice(0, 5).forEach(w => {
                    h += `<div class="r-item">
                        <h4>${esc(w.title||'')}</h4>
                        <p class="snippet">${esc((w.snippet||'').substring(0,200))}</p>
                    </div>`;
                });
            }
            return h;
        });
    }

    // ===== Social Media =====
    const sd = r.social_media;
    if (sd && !sd.error) {
        const found = sd.profiles_found || [];
        html += cardPanel('👤 Social Media Discovery', found.length, 'candidate', 'social_scan', found.length > 0, () => {
            let h = '<table class="o-table"><tr><th>Platform</th><th>Username</th><th>Confidence</th><th>Status</th></tr>';
            found.forEach(p => {
                const conf = p.confidence_score || (p.confidence === 'high' ? 80 : p.confidence === 'medium' ? 55 : 30);
                h += `<tr>
                    <td><strong>${cap(p.platform||'')}</strong></td>
                    <td><a href="${safeUrl(p.url)}" target="_blank">${esc(p.username||'')}</a></td>
                    <td>${confidenceBadge(conf)}</td>
                    <td>${statusBadge(p.status||'candidate')}</td>
                </tr>`;
            });
            h += '</table>';
            if (!found.length) h += emptyState('social', 'No social media profiles found. Name may not match known platforms or profiles are private.');
            return h;
        });
    }

    // ===== GitHub Intelligence =====
    const ghd = r.github_intel;
    if (ghd && !ghd.error && ghd.status !== 'disabled') {
        const profs = ghd.profiles_found || [];
        const emails = ghd.emails_from_profiles || [];
        const commits = ghd.emails_from_commits || [];
        const noreply = ghd.noreply_emails || [];
        const total = profs.length + emails.length + commits.length;
        html += cardPanel('💻 GitHub Intelligence', total, 'verified', 'github_public_api', total > 0, () => {
            let h = '';
            profs.forEach(p => {
                h += `<div class="r-item">
                    <h4>${esc(p.name||p.username||'')} <span class="badge badge-ok">GitHub</span></h4>
                    <a href="${safeUrl(p.profile_url)}" target="_blank" class="url">${esc(p.profile_url||'')}</a>
                    ${p.bio ? `<p class="snippet">${esc(p.bio.substring(0,200))}</p>` : ''}
                    ${p.blog ? `<p>🌐 Blog: <a href="${safeUrl(p.blog.startsWith('http')?p.blog:'https://'+p.blog)}" target="_blank" class="url">${esc(p.blog)}</a></p>` : ''}
                    <div class="r-meta">
                        <span class="tag">Repos: ${p.public_repos||0}</span>
                        <span class="tag">Followers: ${p.followers||0}</span>
                        ${p.company ? `<span class="tag">${esc(p.company)}</span>` : ''}
                        ${confidenceBadge(p.confidence||85)}
                    </div>
                </div>`;
            });
            if (emails.length) {
                h += '<h4 class="result-subtitle text-found">📧 Public GitHub Emails</h4>';
                emails.forEach(e => {
                    h += `<div class="r-item found-item">
                        <code>${esc(e.email)}</code>
                        ${confidenceBadge(e.confidence||85)}
                        <span class="badge badge-ok">Publicly Found</span>
                        <br><span class="text-muted small">Source: GitHub profile</span>
                    </div>`;
                });
            }
            if (commits.length) {
                h += '<h4 class="result-subtitle text-warn">📝 Emails from Repos</h4>';
                commits.forEach(e => {
                    h += `<div class="r-item">
                        <code>${esc(e.email)}</code>
                        ${confidenceBadge(e.confidence||50)}
                        <span class="badge badge-warn">Candidate</span>
                        <br><span class="text-muted small">Repo: ${esc(e.repo||'')}</span>
                    </div>`;
                });
            }
            if (noreply.length) {
                h += '<h4 class="result-subtitle">🔕 Noreply Emails</h4>';
                noreply.forEach(e => {
                    h += `<div class="r-item"><code>${esc(e.email)}</code> <span class="badge badge-gray">Noreply</span></div>`;
                });
            }
            if (!profs.length && !emails.length) {
                h += emptyState('github', 'No GitHub profile found. Username may be different or profile is private.');
            }
            return h;
        });
    }

    // ===== Email Intelligence =====
    const ed = r.email_finder;
    if (ed && !ed.error) {
        const pubFound = ed.publicly_found_emails || [];
        const candidates = ed.candidate_emails || [];
        const breached = ed.breached_emails || [];
        const summary = ed.summary || {};
        const total = pubFound.length + candidates.length;

        html += cardPanel('📧 Email Intelligence',
            `${summary.publicly_found||0} public, ${summary.candidates||0} candidates`,
            pubFound.length > 0 ? 'verified' : 'candidate',
            'email_intel',
            total > 0 || breached.length > 0,
            () => {
                let h = '';

                // Publicly found emails
                if (pubFound.length) {
                    h += '<h4 class="result-subtitle text-found">✅ Publicly Found Emails</h4>';
                    pubFound.forEach(e => {
                        h += `<div class="r-item found-item">
                            <code>${esc(e.email)}</code>
                            ${confidenceBadge(e.confidence||85)}
                            <span class="badge badge-ok">Publicly Observed</span>
                            <br><a href="${safeUrl(e.source_url)}" target="_blank" class="url small">${esc(e.source_url||'')}</a>
                            <br><span class="text-muted small">${esc(e.reason||'')}</span>
                        </div>`;
                    });
                }

                // Candidate emails
                if (candidates.length) {
                    h += `<h4 class="result-subtitle text-warn">📋 Candidate Emails <span class="badge badge-warn">Candidate only — not verified</span></h4>`;
                    h += '<p class="text-muted small">These are generated from name patterns. Not verified as active or belonging to target.</p>';
                    candidates.slice(0, 20).forEach(e => {
                        const tags = [];
                        if (e.is_free_provider) tags.push('<span class="tag tag-info">Free</span>');
                        if (e.is_role_based) tags.push('<span class="tag tag-warn">Role-based</span>');
                        if (e.is_disposable) tags.push('<span class="tag tag-danger">Disposable</span>');
                        h += `<div class="r-item">
                            <code>${esc(e.email)}</code>
                            ${confidenceBadge(e.confidence||45)}
                            <span class="badge badge-warn">Candidate Only</span>
                            ${tags.join(' ')}
                        </div>`;
                    });
                }

                // Breached emails
                if (breached.length) {
                    h += '<h4 class="result-subtitle text-danger">⚠️ Breached Emails</h4>';
                    breached.forEach(b => {
                        h += `<div class="breach-item">
                            <h4>⚠️ ${esc(b.email||'')}</h4>
                            <p>Breaches: <strong>${b.total_breaches}</strong> | Risk: <span class="badge badge-bad">${b.risk_level||'?'}</span></p>
                            ${b.status === 'disabled' ? `<p class="text-muted">${esc(b.reason||'HIBP API key not configured')}</p>` : ''}
                        </div>`;
                    });
                }

                // Intel
                const intel = ed.intel || {};
                if (intel.most_likely_format) {
                    h += `<div class="intel-box">
                        <p><strong>Most likely format:</strong> <code>${esc(intel.most_likely_format)}</code></p>
                        <p><strong>HIBP Status:</strong> <span class="badge ${intel.hibp_status==='enabled'?'badge-ok':'badge-gray'}">${intel.hibp_status||'disabled'}</span></p>
                    </div>`;
                }

                if (!pubFound.length && !candidates.length) {
                    h += emptyState('email', ed.empty_state_reason || 'No emails generated. Provide first and last name.');
                }
                return h;
            });
    }

    // ===== Exposure Intelligence (was Dark Web) =====
    const dd = r.darkweb_intel;
    if (dd && !dd.error) {
        const matches = dd.total_matches || 0;
        html += cardPanel('🕶️ Exposure Intelligence', `${matches} matches`, 'candidate', 'exposure', dd.status !== 'disabled', () => {
            let h = '';
            if (dd.disclaimer) {
                h += `<div class="disclaimer-box"><p>⚠️ ${esc(dd.disclaimer)}</p></div>`;
            }
            if (dd.status === 'disabled') {
                h += emptyState('exposure', dd.disclaimer || 'No verified exposure source configured. Showing defensive recommendations only.');
            } else {
                h += `<p>Public paste/breach matches: <strong>${matches}</strong></p>`;
            }
            (dd.recommendations||[]).slice(0, 5).forEach(rc => {
                h += `<div class="r-item">
                    <strong>[${rc.priority}]</strong> ${esc(rc.action)}
                    <br><small>${esc(rc.detail)}</small>
                </div>`;
            });
            return h;
        });
    }

    // ===== People Search =====
    const pd = r.people_search;
    if (pd && !pd.error) {
        const agg = pd.aggregated || {};
        const phones = agg.all_phones || [];
        const emails = agg.all_emails || [];
        const profiles = agg.all_profiles || [];
        const total = phones.length + emails.length + profiles.length;

        html += cardPanel('🔎 People Search', `${agg.sites_with_results||0} sites`, 'unverified', 'people_search', total > 0, () => {
            let h = '';

            // Region warnings
            if ((pd.region_warnings||[]).length) {
                pd.region_warnings.forEach(w => {
                    h += `<div class="warning-box"><p>⚠️ ${esc(w)}</p></div>`;
                });
            }

            if (phones.length) {
                h += '<h4 class="result-subtitle text-warn">📱 Phone-like Values <span class="badge badge-warn">Unverified</span></h4>';
                phones.forEach(p => {
                    h += `<div class="r-item">
                        <code>${esc(p.value)}</code>
                        ${confidenceBadge(p.confidence||15)}
                        ${statusBadge(p.status||'unverified')}
                        <br><span class="text-muted small">Source: ${esc(p.source)} (${p.region||'US'})</span>
                    </div>`;
                });
            }

            if (emails.length) {
                h += '<h4 class="result-subtitle">📧 Emails</h4>';
                emails.forEach(e => {
                    h += `<div class="r-item">
                        <code>${esc(e.value)}</code>
                        ${confidenceBadge(e.confidence||30)}
                        <br><span class="text-muted small">Source: ${esc(e.source)}</span>
                    </div>`;
                });
            }

            if (profiles.length) {
                h += '<h4 class="result-subtitle">🔗 Profiles</h4>';
                profiles.forEach(p => {
                    h += `<span class="tag tag-found">${esc(p.platform)}:${esc(p.username)}</span> `;
                });
            }

            if ((pd.direct_search_links||[]).length) {
                h += '<p class="mt-2"><strong>Direct Links:</strong> ';
                pd.direct_search_links.forEach(l => {
                    h += `<a href="${safeUrl(l.url)}" target="_blank" class="tag tag-found" style="margin:2px">${esc(l.name)}</a> `;
                });
                h += '</p>';
            }

            if (!total) {
                h += emptyState('people', pd.empty_state_reason || 'No data found from people aggregators for this target.');
            }
            return h;
        });
    }

    // ===== Domain Intel =====
    const dod = r.domain_checker;
    if (dod && !dod.error && dod.clean_domain) {
        const ssl = dod.ssl_info || {};
        const sec = dod.security_headers || {};
        html += cardPanel('🛡️ Domain Intelligence', dod.clean_domain, 'verified', 'domain_checker', true, () => {
            let h = `<p>SSL: ${ssl.valid?'<span class="text-success">✅ Valid</span>':'<span class="text-danger">❌ Invalid</span>'}`;
            if (ssl.days_remaining > 0) h += ` | ${ssl.days_remaining} days`;
            h += `</p><p>Security Headers: ${sec.score||0}/${sec.total||10} | Grade: <span class="badge badge-${(sec.grade||'F')[0]==='A'?'ok':'warn'}">${sec.grade||'F'}</span></p>`;
            if ((dod.subdomains_found||[]).length) {
                h += '<p class="mt-2"><strong>Subdomains:</strong> ';
                dod.subdomains_found.slice(0,15).forEach(s => h += `<span class="tag">${esc(s.subdomain||s)}</span> `);
                h += '</p>';
            }
            return h;
        });
    }

    // ===== Phone =====
    const phd = r.phone_finder;
    if (phd && !phd.error && phd.cleaned) {
        const ci = phd.country_info || {};
        const pi = phd.provider_info || {};
        html += cardPanel('📱 Phone Intelligence', phd.cleaned, 'verified', 'phone', true, () => {
            let h = `<p>Country: ${esc(ci.country||'?')} | Provider: ${esc(pi.provider||'?')} ${esc(pi.product||'')}</p>`;
            if ((phd.variants||[]).length) {
                h += '<div class="meta mt-2">';
                phd.variants.forEach(v => h += `<a href="${safeUrl(v.value)}" target="_blank" class="tag tag-found">${esc(v.format)}</a> `);
                h += '</div>';
            }
            return h;
        });
    }

    // ===== WHOIS =====
    const wd = r.whois_recon;
    if (wd && !wd.error && wd.domain) {
        html += cardPanel('🔍 WHOIS / DNS', wd.domain, 'verified', 'whois', true, () => {
            let h = '';
            if (wd.registrar) h += `<p>Registrar: <strong>${esc(wd.registrar)}</strong></p>`;
            if (wd.creation_date) h += `<p>Created: ${wd.creation_date}</p>`;
            if (wd.expiration_date) h += `<p>Expires: ${wd.expiration_date}</p>`;
            if (wd.name_servers) h += `<p>NS: ${(wd.name_servers||[]).slice(0,4).map(n=>`<span class="tag">${esc(n)}</span>`).join(' ')}</p>`;
            if ((wd.dns_records||[]).length) {
                h += '<table class="o-table mt-2"><tr><th>Type</th><th>Value</th></tr>';
                wd.dns_records.slice(0,10).forEach(rec => h += `<tr><td>${esc(rec.type||'')}</td><td class="monospace">${esc(rec.value||'')}</td></tr>`);
                h += '</table>';
            }
            return h || '<p class="text-muted">No WHOIS data available.</p>';
        });
    }

    // ===== Google Dorks =====
    const gd = r.google_dorks;
    if (gd && !gd.error) {
        const dc = (gd.dork_results||[]).length;
        html += cardPanel('🎯 Google Dorks', `${dc} results`, 'info', 'google_dorks', dc > 0, () => {
            let h = '';
            (gd.dork_results||[]).slice(0, 15).forEach(x => {
                h += `<div class="r-item">
                    <h4>${esc(x.title||'')}</h4>
                    <a href="${safeUrl(x.url)}" target="_blank" class="url">${esc(x.url||'')}</a>
                    <span class="tag">${esc(x.dork_type||'')}</span>
                </div>`;
            });
            if (!dc) h = '<p class="text-muted">No dork results found.</p>';
            return h;
        });
    }

    // ===== Errors =====
    if (r.errors && r.errors.length) {
        html += cardPanel('❌ Module Errors', `${r.errors.length} errors`, 'high_risk', 'errors', true, () => {
            return '<ul>' + r.errors.map(e => `<li class="text-danger">${esc(e.module||'')}: ${esc(e.error||e)}</li>`).join('') + '</ul>';
        });
    }

    c.innerHTML = html;
    c.scrollIntoView({ behavior: 'smooth' });

    // Setup collapsible
    document.querySelectorAll('.finding-head').forEach(h => {
        h.addEventListener('click', () => {
            h.classList.toggle('open');
            const body = h.nextElementSibling;
            body.classList.toggle('open');
        });
    });
}

// ============================================================
// CARD PANEL — forensic grade
// ============================================================
function cardPanel(title, subtitle, statusType, source, hasContent, bodyFn) {
    const statusConfig = {
        verified: { cls: 'status-verified', label: 'Verified / Public Source' },
        candidate: { cls: 'status-candidate', label: 'Candidate / Unverified' },
        unverified: { cls: 'status-unverified', label: 'Unverified / Low Confidence' },
        high_risk: { cls: 'status-highrisk', label: 'High Risk Finding' },
        info: { cls: 'status-info', label: 'Informational' },
        disabled: { cls: 'status-disabled', label: 'Disabled / No API' },
    };
    const st = statusConfig[statusType] || statusConfig.info;
    const body = bodyFn ? bodyFn() : '<p class="text-muted">No data available.</p>';
    const openClass = hasContent ? 'open' : '';

    return `
    <div class="finding-card">
        <div class="finding-head ${openClass} ${st.cls}">
            <div class="finding-head-left">
                <h3>${title}</h3>
                <div class="finding-badges">
                    <span class="badge badge-${statusType==='verified'?'ok':statusType==='candidate'?'warn':statusType==='high_risk'?'bad':statusType==='unverified'?'warn':'info'}">${st.label}</span>
                    <span class="badge badge-sub">${esc(subtitle)}</span>
                </div>
            </div>
            <span class="arrow">▶</span>
        </div>
        <div class="finding-body ${openClass}">${body}</div>
    </div>`;
}

// ============================================================
// CONFIDENCE & STATUS BADGES
// ============================================================
function confidenceBadge(score, label) {
    if (score === undefined && label) score = label === 'High' ? 85 : label === 'Medium' ? 60 : 30;
    if (!score && score !== 0) return '';
    let cls = 'badge-gray', lbl = '?';
    if (score >= 90) { cls = 'badge-ok'; lbl = 'Very High'; }
    else if (score >= 75) { cls = 'badge-ok'; lbl = 'High'; }
    else if (score >= 50) { cls = 'badge-info'; lbl = 'Medium'; }
    else if (score >= 25) { cls = 'badge-warn'; lbl = 'Low'; }
    else if (score > 0) { cls = 'badge-bad'; lbl = 'Very Low'; }
    else { cls = 'badge-gray'; lbl = 'Unknown'; }
    return `<span class="badge ${cls}" title="Confidence: ${score}%">🔍 ${lbl} (${score}%)</span>`;
}

function statusBadge(status) {
    const map = {
        publicly_found: ['badge-ok', '✅ Publicly Found'],
        publicly_observed: ['badge-ok', '✅ Observed'],
        candidate: ['badge-warn', '⚠️ Candidate'],
        format_valid: ['badge-info', 'Format Valid'],
        unverified: ['badge-warn', '❓ Unverified'],
        source_matched: ['badge-ok', 'Source Matched'],
        disabled: ['badge-gray', '⛔ Disabled'],
        verified: ['badge-ok', '✅ Verified'],
        noreply: ['badge-gray', '🔕 Noreply'],
    };
    const [cls, label] = map[status] || ['badge-info', status];
    return `<span class="badge ${cls}">${label}</span>`;
}

function emptyState(module, reason) {
    return `<div class="empty-state">
        <p class="text-muted">No results found for this module.</p>
        ${reason ? `<p class="text-muted small">${esc(reason)}</p>` : ''}
        <p class="text-muted small">Possible reasons:
            <br>- Data is not publicly exposed
            <br>- Source was blocked or rate-limited
            <br>- API key is not configured
            <br>- Search query needs refinement
        </p>
    </div>`;
}

// ============================================================
// FORENSIC STATS
// ============================================================
function updateStats(r, findings) {
    let publicFindings = 0;
    let candidates = 0;
    let verifiedSources = 0;
    let evidenceItems = 0;

    // Count from email_finder
    const ed = r.email_finder || {};
    const summary = ed.summary || {};
    publicFindings += summary.publicly_found || 0;
    candidates += summary.candidates || 0;

    // Count from github
    const ghd = r.github_intel || {};
    publicFindings += (ghd.emails_from_profiles || []).length;
    candidates += (ghd.emails_from_commits || []).length;

    // Verified sources: count modules that returned actual data
    for (const [key, val] of Object.entries(r)) {
        if (val && !val.error && typeof val === 'object') {
            if ((val.web_results || []).length > 0) verifiedSources++;
            if ((val.profiles_found || []).length > 0) verifiedSources++;
            if ((val.publicly_found_emails || []).length > 0) verifiedSources++;
            if ((val.profiles_found || []).length > 0) verifiedSources++;
        }
    }

    // Evidence items: findings from DB
    evidenceItems = (findings || []).length || 0;

    // Risk score
    let riskScore = 0;
    if (publicFindings > 0) riskScore += 15;
    if (candidates > 10) riskScore += 10;

    s('sPublicFindings', publicFindings);
    s('sCandidates', candidates);
    s('sVerifiedSources', verifiedSources);
    s('sEvidence', evidenceItems);
    s('sReportReady', verifiedSources > 0 ? '✅' : '—');

    const riskEl = document.getElementById('sRiskScore');
    if (riskEl) {
        const rl = riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : riskScore > 0 ? 'LOW' : 'NONE';
        riskEl.textContent = `${rl} (${riskScore})`;
        riskEl.className = 'stat-num risk ' + (riskScore >= 50 ? 'high' : riskScore >= 25 ? 'med' : 'low');
    }
}

function s(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }

// ============================================================
// HISTORY
// ============================================================
function historyTab() {
    document.getElementById('refreshHistory').addEventListener('click', loadHistory);
    document.getElementById('historyFilter').addEventListener('change', loadHistory);
    const clearBtn = document.getElementById('clearHistory');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            if (!confirm('Hapus semua history scan? Data tidak bisa dikembalikan.')) return;
            try {
                const r = await fetch(`${API}/api/history?limit=200`);
                const d = await r.json();
                if (d.scans) {
                    for (const s of d.scans) {
                        await fetch(`${API}/api/history/${s.report_id}`, { method: 'DELETE' });
                    }
                }
                toast('History cleared', 'info');
                loadHistory();
            } catch { toast('Failed to clear history', 'error'); }
        });
    }
}

async function loadHistory() {
    const status = document.getElementById('historyFilter').value;
    const el = document.getElementById('historyList');
    el.innerHTML = '<div class="text-center"><div class="spin"></div></div>';

    try {
        const r = await fetch(`${API}/api/history?limit=50&status=${status||''}`);
        const d = await r.json();
        if (!d.scans || !d.scans.length) {
            el.innerHTML = '<p class="text-muted">Belum ada scan.</p>';
            return;
        }
        el.innerHTML = d.scans.map(sc => {
            const target = sc.target_name || sc.target_email || sc.target_domain || sc.target_phone || 'Unknown';
            const sevCls = sc.severity==='HIGH'||sc.severity==='CRITICAL'?'badge-bad':sc.severity==='MEDIUM'?'badge-warn':'badge-ok';
            return `<div class="history-item" data-rid="${sc.report_id}">
                <div class="history-info">
                    <span class="h-target">${esc(target)}</span>
                    <span class="h-meta">${sc.report_id} | ${sc.started_at?.substring(0,19)||''} | ${sc.status} | ${sc.total_findings||0} findings | <span class="badge ${sevCls}">${sc.severity||'?'}</span></span>
                </div>
                <div class="history-actions">
                    <button class="btn-icon view-btn" title="View">👁️</button>
                    <button class="btn-icon del del-btn" title="Delete">🗑️</button>
                </div>
            </div>`;
        }).join('');

        el.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const rid = btn.closest('.history-item').dataset.rid;
                viewHistory(rid);
            });
        });
        el.querySelectorAll('.del-btn').forEach(btn => {
            btn.addEventListener('click', async e => {
                e.stopPropagation();
                const rid = btn.closest('.history-item').dataset.rid;
                await fetch(`${API}/api/history/${rid}`, { method: 'DELETE' });
                toast('Deleted', 'info');
                loadHistory();
            });
        });
        el.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', () => viewHistory(item.dataset.rid));
        });
    } catch {
        el.innerHTML = '<p class="text-danger">Failed to load history.</p>';
    }
}

async function viewHistory(rid) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector('.tab[data-tab="scan"]').classList.add('active');
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('tab-scan').classList.add('active');
    reportId = rid;
    document.getElementById('reportIdInput').value = rid;
    await fetchResults(rid);
}

// ============================================================
// REPORT
// ============================================================
function reportTab() {
    document.getElementById('genReport').addEventListener('click', async () => {
        const rid = document.getElementById('reportIdInput').value.trim();
        const resultEl = document.getElementById('reportResult');
        if (!rid) return toast('Masukkan Report ID', 'error');

        resultEl.style.display = 'block';
        resultEl.innerHTML = '<div class="text-center"><div class="spin"></div><p>Generating forensic report...</p></div>';

        try {
            const r = await fetch(`${API}/api/report/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ report_id: rid, name: 'OSINT Forensic Report' })
            });
            const d = await r.json();
            if (d.success) {
                resultEl.innerHTML = `
                    <p class="text-success">✅ Forensic report generated!</p>
                    <p class="mt-2">ID: <code>${esc(d.report.report_id)}</code></p>
                    <p>Severity: <span class="badge badge-bad">${esc(d.report.severity||'?')}</span> | Confidence: <strong>${d.report.confidence||'?'}%</strong></p>
                    <div class="mt-2">
                        <a href="${API}/api/report/${rid}/json" class="dl-link" target="_blank">📥 JSON</a>
                        <a href="${API}/api/report/${rid}/html" class="dl-link" target="_blank">📥 HTML</a>
                        <a href="${API}/api/report/${rid}/csv" class="dl-link" target="_blank">📥 CSV</a>
                        <a href="${API}/api/report/${rid}/text" class="dl-link" target="_blank">📥 Text</a>
                    </div>`;
            } else {
                resultEl.innerHTML = `<p class="text-danger">${esc(d.error||'Failed')}</p>`;
            }
        } catch (e) {
            resultEl.innerHTML = `<p class="text-danger">${esc(e.message)}</p>`;
        }
    });
}

// ============================================================
// UTILS
// ============================================================
function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = typeof s === 'string' ? s : String(s);
    return d.innerHTML;
}

function safeUrl(url) {
    if (!url || typeof url !== 'string') return '#';
    try {
        const p = new URL(url, window.location.origin);
        if (['http:','https:'].includes(p.protocol)) return p.href.replace(/"/g,'%22').replace(/'/g,'%27');
    } catch {}
    return '#';
}

function cap(s) {
    if (!s) return '';
    return s.replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase());
}

function toast(msg, type) {
    const ct = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = `toast ${type||'info'}`;
    t.textContent = msg;
    ct.appendChild(t);
    setTimeout(() => {
        t.style.opacity = '0';
        t.style.transition = 'opacity .3s';
        setTimeout(() => t.remove(), 300);
    }, 4000);
}
