/**
 * OSINT TOOL v5.0 — Clean Dashboard
 * Tab-based: Scan, History, Report
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
});

// ============================================================
// HEALTH
// ============================================================
async function health() {
    const el = document.getElementById('serverStatus');
    try {
        const r = await fetch(`${API}/api/health`);
        const d = await r.json();
        const modCount = Array.isArray(d.modules) ? d.modules.length : (d.modules || d.total_modules || '?');
        el.innerHTML = `<span class="status-dot on"></span><span>v${d.version} — ${modCount} modules</span>`;
    } catch {
        el.innerHTML = '<span class="status-dot off"></span><span>Offline</span>';
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
// SCAN
// ============================================================
function scanForm() {
    const inputs = ['targetName', 'targetEmail', 'targetDomain', 'targetPhone'];
    const btn = document.getElementById('runScan');

    // Enable/disable button
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
        if (!name && !email && !domain && !phone) return toast('Isi minimal 1 field', 'error');
        runScan({ name, email, domain, phone });
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

    // Show progress
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
    people_search: 'People Search', breach_checker: 'Breach Check', darkweb_intel: 'Dark Web',
    domain_checker: 'Domain Intel', phone_finder: 'Phone Intel', whois_recon: 'WHOIS/DNS',
    google_dorks: 'Google Dorks', shodan_intel: 'Shodan', virustotal_intel: 'VirusTotal',
    hunter_io: 'Hunter.io', intelx_search: 'IntelX', telegram_osint: 'Telegram'
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

            // Update module pills in hero
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
        '🔓 Breach': 'breach_checker', '📱 Phone': 'phone_finder', '🔎 People': 'people_search',
        '🕶️ Darkweb': 'darkweb_intel', '🏢 Domain': 'domain_checker', '🎯 Dorks': 'google_dorks',
        '🛰️ Shodan': 'shodan_intel', '🛡️ VirusTotal': 'virustotal_intel', '✉️ Hunter': 'hunter_io',
        '📊 IntelX': 'intelx_search', '💬 Telegram': 'telegram_osint', '🔍 WHOIS': 'whois_recon'
    };
    pills.forEach(pill => {
        const mod = pillMap[pill.textContent.trim()];
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
            renderFindings(d.results);
            updateStats(d.results);
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
    // Reset pills
    document.querySelectorAll('.module-pill').forEach(p => p.className = 'module-pill');
}

// ============================================================
// RENDER FINDINGS
// ============================================================
function renderFindings(r) {
    const c = document.getElementById('findings');
    c.style.display = 'flex';
    let html = '';

    // Web & Name
    const nd = r.name_search;
    if (nd && !nd.error) {
        const wc = (nd.web_results || []).length;
        const gc = (nd.github_profiles || []).length;
        const wk = (nd.wikipedia_mentions || []).length;
        html += card('🌐 Web & Name Intelligence', `${wc + gc + wk} results`, nd && (wc || gc || wk), () => {
            let h = '';
            if (wc) {
                h += '<h4 class="mt-2" style="color:var(--cyn)">Web Results</h4>';
                nd.web_results.slice(0, 20).forEach(x => {
                    h += `<div class="r-item"><h4>${esc(x.title||'')}</h4><a href="${safeUrl(x.url)}" target="_blank" class="url">${esc(x.display_url||x.url||'')}</a><div class="meta"><span class="tag">${x.source||''}</span></div></div>`;
                });
            }
            if (gc) {
                h += '<h4 class="mt-2" style="color:var(--pur)">💻 GitHub</h4>';
                nd.github_profiles.slice(0, 8).forEach(g => {
                    h += `<div class="r-item"><strong>${esc(g.username||'')}</strong> <span class="badge badge-info">${g.type||'User'}</span><br><a href="${safeUrl(g.url)}" target="_blank" class="url">${esc(g.url||'')}</a></div>`;
                });
            }
            if (wk) {
                h += '<h4 class="mt-2">📚 Wikipedia</h4>';
                nd.wikipedia_mentions.slice(0, 5).forEach(w => {
                    h += `<div class="r-item"><h4>${esc(w.title||'')}</h4><p class="snippet">${esc((w.snippet||'').substring(0,200))}</p></div>`;
                });
            }
            return h;
        });
    }

    // Social Media
    const sd = r.social_media;
    if (sd && !sd.error) {
        const found = sd.profiles_found || [];
        html += card('👤 Social Media', `${found.length} found`, found.length > 0, () => {
            let h = '<table class="o-table"><tr><th>Platform</th><th>Username</th><th>Confidence</th><th>Category</th></tr>';
            found.forEach(p => {
                const bc = p.confidence==='high'?'badge-ok':p.confidence==='medium'?'badge-warn':'badge-info';
                h += `<tr><td><strong>${cap(p.platform||'')}</strong></td><td><a href="${safeUrl(p.url)}" target="_blank">${esc(p.username||'')}</a></td><td><span class="badge ${bc}">${p.confidence||'low'}</span></td><td><span class="tag">${p.category||''}</span></td></tr>`;
            });
            h += '</table>';
            return h;
        });
    }

    // People Search
    const pd = r.people_search;
    if (pd && !pd.error) {
        const agg = pd.aggregated || {};
        const total = (agg.all_emails||[]).length + (agg.all_phones||[]).length + (agg.all_profiles||[]).length;
        html += card('🔎 People Search Aggregator', `${agg.sites_with_results||0} sites`, total > 0 || (pd.direct_search_links||[]).length > 0, () => {
            let h = '';
            if ((agg.all_emails||[]).length) {
                h += '<p><strong>📧 Emails:</strong> ';
                agg.all_emails.forEach(e => h += `<span class="tag tag-danger">${esc(e)}</span> `);
                h += '</p>';
            }
            if ((agg.all_phones||[]).length) {
                h += '<p class="mt-2"><strong>📱 Phones:</strong> ';
                agg.all_phones.forEach(p => h += `<span class="tag tag-warn">${esc(p)}</span> `);
                h += '</p>';
            }
            if ((agg.all_profiles||[]).length) {
                h += '<p class="mt-2"><strong>🔗 Profiles:</strong> ';
                agg.all_profiles.forEach(p => h += `<span class="tag tag-found">${esc(p.platform)}:${esc(p.username)}</span> `);
                h += '</p>';
            }
            if ((pd.direct_search_links||[]).length) {
                h += '<p class="mt-2"><strong>Direct Links:</strong> ';
                pd.direct_search_links.forEach(l => h += `<a href="${safeUrl(l.url)}" target="_blank" class="tag tag-found" style="margin:2px">${esc(l.name)}</a> `);
                h += '</p>';
            }
            if (!total) h = '<p class="text-muted">No data found from people aggregators.</p>';
            return h;
        });
    }

    // Email Intel
    const ed = r.email_finder;
    if (ed && !ed.error && ed.total_generated > 0) {
        const vc = (ed.valid_emails||[]).length;
        const bc = (ed.breached_emails||[]).length;
        html += card('📧 Email Intelligence', `${ed.total_generated} permutations, ${vc} valid, ${bc} breached`, true, () => {
            let h = '';
            (ed.breached_emails||[]).forEach(b => {
                h += `<div class="breach-item"><h4>⚠️ ${esc(b.email||'')}</h4><p>Breaches: <strong>${b.total_breaches}</strong> | Risk: <span class="text-danger">${b.risk_level||'?'}</span></p></div>`;
            });
            if (!bc) h += '<p class="text-success">No breached emails detected.</p>';
            return h;
        });
    }

    // Breach
    const bd = r.breach_checker;
    if (bd && !bd.error) {
        const hibp = bd.hibp_breaches || {};
        const sm = bd.summary || {};
        html += card('🔓 Breach Database', `${hibp.total_breaches||sm.total_unique_breaches||0} breaches`, hibp.breached || sm.total_unique_breaches > 0, () => {
            let h = '';
            if (hibp.breached) {
                h += `<p class="text-danger"><strong>${hibp.total_breaches} breaches found</strong> | Risk: <span class="badge badge-bad">${hibp.risk_level||sm.risk_level||'?'}</span></p>`;
                (hibp.breaches||[]).slice(0, 8).forEach(b => {
                    h += `<div class="breach-item"><h4>${esc(b.title||b.name||'')}</h4><p>${b.breach_date||'?'} | ${(b.pwn_count||0).toLocaleString()} records</p><p class="snippet">${esc((b.description||'').substring(0,200))}</p><div class="meta">${(b.data_classes||[]).slice(0,5).map(c=>`<span class="tag tag-danger">${esc(c)}</span>`).join('')}</div></div>`;
                });
            } else {
                h += '<p class="text-success">No known breaches found.</p>';
            }
            if ((sm.recommendations||[]).length) {
                h += '<p class="mt-2"><strong>🔒 Recommendations:</strong></p><ul>';
                sm.recommendations.forEach(x => h += `<li>${esc(x)}</li>`);
                h += '</ul>';
            }
            return h;
        });
    }

    // Dark Web
    const dd = r.darkweb_intel;
    if (dd && !dd.error) {
        html += card('🕶️ Dark Web Intel', `${dd.total_matches||0} matches`, (dd.total_matches||0) > 0 || (dd.recommendations||[]).length > 0, () => {
            let h = `<p>Matches: <strong>${dd.total_matches||0}</strong></p>`;
            const exp = dd.breach_exposure || {};
            if (exp.level && exp.level !== 'UNKNOWN') {
                h += `<p>Exposure: <span class="badge badge-${exp.level==='ELEVATED'?'bad':'warn'}">${exp.level}</span></p>`;
            }
            (dd.recommendations||[]).slice(0,5).forEach(rc => {
                h += `<div class="r-item"><strong>[${rc.priority}]</strong> ${esc(rc.action)}<br><small>${esc(rc.detail)}</small></div>`;
            });
            return h;
        });
    }

    // Domain
    const dod = r.domain_checker;
    if (dod && !dod.error && dod.clean_domain) {
        const ssl = dod.ssl_info || {};
        const sec = dod.security_headers || {};
        html += card('🏢 Domain Intel', dod.clean_domain, true, () => {
            let h = `<p>SSL: ${ssl.valid?'<span class="text-success">Valid</span>':'<span class="text-danger">Invalid</span>'}`;
            if (ssl.days_remaining > 0) h += ` | ${ssl.days_remaining} days left`;
            h += `</p><p>Security: ${sec.score||0}/${sec.total||10} | Grade: <span class="badge badge-${(sec.grade||'F')[0]==='A'?'ok':'warn'}">${sec.grade||'F'}</span></p>`;
            if ((dod.subdomains_found||[]).length) {
                h += '<p class="mt-2"><strong>Subdomains:</strong> ';
                dod.subdomains_found.slice(0,15).forEach(s => h += `<span class="tag">${esc(s.subdomain||s)}</span> `);
                h += '</p>';
            }
            return h;
        });
    }

    // Phone
    const phd = r.phone_finder;
    if (phd && !phd.error && phd.cleaned) {
        const ci = phd.country_info || {};
        const pi = phd.provider_info || {};
        html += card('📱 Phone Intel', phd.cleaned, true, () => {
            let h = `<p>Country: ${esc(ci.country||'?')} | Provider: ${esc(pi.provider||'?')} ${esc(pi.product||'')}</p>`;
            if ((phd.variants||[]).length) {
                h += '<div class="meta mt-2">';
                phd.variants.forEach(v => h += `<a href="${safeUrl(v.value)}" target="_blank" class="tag tag-found">${esc(v.format)}</a> `);
                h += '</div>';
            }
            return h;
        });
    }

    // WHOIS
    const wd = r.whois_recon;
    if (wd && !wd.error && wd.domain) {
        html += card('🔍 WHOIS / DNS', wd.domain, true, () => {
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

    // Google Dorks
    const gd = r.google_dorks;
    if (gd && !gd.error) {
        const dc = (gd.dork_results||[]).length;
        html += card('🎯 Google Dorks', `${dc} dork results`, dc > 0, () => {
            let h = '';
            (gd.dork_results||[]).slice(0, 15).forEach(x => {
                h += `<div class="r-item"><h4>${esc(x.title||'')}</h4><a href="${safeUrl(x.url)}" target="_blank" class="url">${esc(x.url||'')}</a><span class="tag">${esc(x.dork_type||'')}</span></div>`;
            });
            if (!dc) h = '<p class="text-muted">No dork results found.</p>';
            return h;
        });
    }

    // Shodan
    const shd = r.shodan_intel;
    if (shd && !shd.error && !shd.message) {
        html += card('🛰️ Shodan Intel', shd.ip||'', true, () => {
            let h = '';
            if (shd.ports) h += `<p>Open Ports: ${(shd.ports||[]).map(p=>`<span class="tag tag-warn">${p}</span>`).join(' ')}</p>`;
            if (shd.os) h += `<p>OS: <strong>${esc(shd.os)}</strong></p>`;
            if (shd.org) h += `<p>Org: ${esc(shd.org)}</p>`;
            if ((shd.vulns||[]).length) h += `<p class="mt-2">Vulns: ${shd.vulns.slice(0,8).map(v=>`<span class="tag tag-danger">${esc(v)}</span>`).join(' ')}</p>`;
            return h || '<p class="text-muted">No Shodan data.</p>';
        });
    }

    // VirusTotal
    const vtd = r.virustotal_intel;
    if (vtd && !vtd.error) {
        const stats = vtd.detection_stats || {};
        html += card('🛡️ VirusTotal', `${stats.malicious||0}/${stats.total||0} detections`, true, () => {
            let h = `<p>Malicious: <span class="text-danger">${stats.malicious||0}</span> | Suspicious: <span class="text-warning">${stats.suspicious||0}</span> | Clean: <span class="text-success">${stats.clean||0}</span></p>`;
            if (vtd.reputation !== undefined) h += `<p>Reputation: <strong>${vtd.reputation}</strong></p>`;
            if ((vtd.categories||[]).length) h += `<div class="meta mt-2">${vtd.categories.map(c=>`<span class="tag">${esc(c)}</span>`).join(' ')}</div>`;
            return h;
        });
    }

    // Hunter.io
    const htd = r.hunter_io;
    if (htd && !htd.error) {
        const ec = (htd.emails||[]).length;
        html += card('✉️ Hunter.io Email', `${ec} emails found`, ec > 0, () => {
            let h = '';
            (htd.emails||[]).slice(0,10).forEach(e => {
                h += `<div class="r-item"><strong>${esc(e.email||'')}</strong> <span class="badge badge-${e.verified?'ok':'warn'}">${e.verified?'Verified':'Unverified'}</span><br><span class="tag">${esc(e.type||'')}</span></div>`;
            });
            if (!ec) h = '<p class="text-muted">No emails found.</p>';
            return h;
        });
    }

    // IntelX
    const ixd = r.intelx_search;
    if (ixd && !ixd.error) {
        const ic = (ixd.results||[]).length;
        html += card('📊 IntelX / Leak Search', `${ic} results`, ic > 0, () => {
            let h = '';
            (ixd.results||[]).slice(0,10).forEach(x => {
                h += `<div class="r-item"><h4>${esc(x.title||'')}</h4><p class="snippet">${esc((x.description||'').substring(0,200))}</p><span class="tag">${esc(x.source||'')}</span></div>`;
            });
            if (!ic) h = '<p class="text-muted">No IntelX results.</p>';
            return h;
        });
    }

    // Telegram
    const tgd = r.telegram_osint;
    if (tgd && !tgd.error) {
        const tc = (tgd.channels||[]).length + (tgd.users||[]).length;
        html += card('💬 Telegram OSINT', `${tc} results`, tc > 0 || (tgd.search_links||[]).length > 0, () => {
            let h = '';
            (tgd.channels||[]).slice(0,5).forEach(ch => {
                h += `<div class="r-item"><strong>${esc(ch.title||'')}</strong> <span class="badge badge-info">${ch.members||0} members</span><br><a href="${safeUrl(ch.link)}" target="_blank" class="url">${esc(ch.link||'')}</a></div>`;
            });
            (tgd.users||[]).slice(0,5).forEach(u => {
                h += `<div class="r-item"><strong>@${esc(u.username||'')}</strong><br><span class="tag">${esc(u.name||'')}</span></div>`;
            });
            if ((tgd.search_links||[]).length) {
                h += '<p class="mt-2"><strong>Links:</strong> ';
                tgd.search_links.forEach(l => h += `<a href="${safeUrl(l.url)}" target="_blank" class="tag tag-found">${esc(l.name)}</a> `);
                h += '</p>';
            }
            if (!tc && !(tgd.search_links||[]).length) h = '<p class="text-muted">No Telegram results.</p>';
            return h;
        });
    }

    // Errors
    if (r.errors && r.errors.length) {
        html += card('❌ Module Errors', `${r.errors.length} errors`, true, () => {
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

function card(title, subtitle, hasContent, bodyFn) {
    const body = hasContent ? bodyFn() : '<p class="text-muted">No data found.</p>';
    const openClass = hasContent ? 'open' : '';
    return `
    <div class="finding-card">
        <div class="finding-head ${openClass}">
            <h3>${title} <span class="badge badge-info">${esc(subtitle)}</span></h3>
            <span class="arrow">▶</span>
        </div>
        <div class="finding-body ${openClass}">${body}</div>
    </div>`;
}

// ============================================================
// STATS
// ============================================================
function updateStats(r) {
    const nd = r.name_search||{};
    const sd = r.social_media||{};
    const ed = r.email_finder||{};
    const bd = r.breach_checker||{};
    s('sWeb', (nd.web_results||[]).length);
    s('sSocial', (sd.summary||{}).total_found||(sd.profiles_found||[]).length);
    s('sEmail', ed.total_generated||0);
    s('sBreach', ((bd.hibp_breaches||{}).total_breaches||(bd.summary||{}).total_unique_breaches||0));
    s('sGithub', (nd.github_profiles||[]).length);
    const rl = (bd.hibp_breaches||{}).risk_level||(bd.summary||{}).risk_level||'—';
    const el = document.getElementById('sRisk');
    if (el) { el.textContent = rl; el.className = 'stat-num risk'; }
}
function s(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }

// ============================================================
// HISTORY
// ============================================================
function historyTab() {
    document.getElementById('refreshHistory').addEventListener('click', loadHistory);
    document.getElementById('historyFilter').addEventListener('change', loadHistory);
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

        // Events
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
    // Switch to scan tab, load results
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
        resultEl.innerHTML = '<div class="text-center"><div class="spin"></div><p>Generating...</p></div>';

        try {
            const r = await fetch(`${API}/api/report/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ report_id: rid, name: 'OSINT Report' })
            });
            const d = await r.json();
            if (d.success) {
                resultEl.innerHTML = `
                    <p class="text-success">✅ Report generated!</p>
                    <p class="mt-2">ID: <code>${d.report.report_id}</code></p>
                    <div class="mt-2">
                        <a href="${API}/api/report/${rid}/json" class="dl-link" target="_blank">📥 JSON</a>
                        <a href="${API}/api/report/${rid}/html" class="dl-link" target="_blank">📥 HTML</a>
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
    d.textContent = s;
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
