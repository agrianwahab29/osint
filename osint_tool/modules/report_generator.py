"""
Report Generator Module - Generate comprehensive OSINT reports
Formats: JSON, HTML, TEXT
"""
import json
import os
from datetime import datetime
from typing import Optional


def generate_html_report(name: str, results: dict) -> str:
    """Generate a beautiful HTML report from OSINT results."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = datetime.now().strftime("%Y%m%d%H%M%S")

    # Aggregate results
    name_data = results.get("name_search", {})
    email_data = results.get("email_finder", {})
    social_data = results.get("social_media", {})
    domain_data = results.get("domain_checker", {})
    breach_data = results.get("breach_checker", {})
    phone_data = results.get("phone_finder", {})

    # Stats
    web_total = len(name_data.get("web_results", []))
    github_total = len(name_data.get("github_profiles", []))
    wiki_total = len(name_data.get("wikipedia_mentions", []))
    social_found = social_data.get("summary", {}).get("total_found", 0)
    breach_total = breach_data.get("summary", {}).get("total_unique_breaches", 0)
    emails_gen = email_data.get("total_generated", 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report - {name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; background: #0a0e17; color: #e0e6ed; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1f35, #0d1117); border: 1px solid #2d3748; border-radius: 12px; padding: 30px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 2em; color: #58a6ff; margin-bottom: 8px; }}
        .header .subtitle {{ color: #8b949e; font-size: 0.9em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: #161b22; border: 1px solid #2d3748; border-radius: 10px; padding: 20px; text-align: center; }}
        .stat-card .value {{ font-size: 2em; font-weight: 700; color: #58a6ff; }}
        .stat-card .label {{ color: #8b949e; font-size: 0.85em; margin-top: 4px; }}
        .section {{ background: #161b22; border: 1px solid #2d3748; border-radius: 10px; padding: 24px; margin-bottom: 20px; }}
        .section h2 {{ color: #58a6ff; font-size: 1.3em; margin-bottom: 16px; border-bottom: 1px solid #2d3748; padding-bottom: 10px; }}
        .result-item {{ background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 14px; margin-bottom: 10px; }}
        .result-item:hover {{ border-color: #58a6ff33; }}
        .result-item h4 {{ color: #e0e6ed; font-size: 0.95em; }}
        .result-item a {{ color: #58a6ff; text-decoration: none; font-size: 0.85em; }}
        .result-item a:hover {{ text-decoration: underline; }}
        .result-item .snippet {{ color: #8b949e; font-size: 0.85em; margin-top: 6px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; margin-right: 4px; }}
        .badge-danger {{ background: #da36331a; color: #f85149; border: 1px solid #da3633; }}
        .badge-warning {{ background: #d299221a; color: #d29922; border: 1px solid #d29922; }}
        .badge-success {{ background: #2386361a; color: #3fb950; border: 1px solid #238636; }}
        .badge-info {{ background: #58a6ff1a; color: #58a6ff; border: 1px solid #58a6ff; }}
        .risk-high {{ color: #f85149; }}
        .risk-medium {{ color: #d29922; }}
        .risk-low {{ color: #3fb950; }}
        .footer {{ text-align: center; color: #484f58; font-size: 0.8em; padding: 20px; }}
        .profile-row {{ display: flex; align-items: center; gap: 10px; padding: 8px; }}
        .profile-row img {{ width: 32px; height: 32px; border-radius: 50%; }}
        .tag {{ display: inline-block; background: #21262d; border-radius: 4px; padding: 2px 8px; font-size: 0.75em; margin: 2px; }}
        .breach-card {{ background: #0d1117; border-left: 3px solid #f85149; padding: 12px; margin-bottom: 10px; border-radius: 0 8px 8px 0; }}
        .breach-card h4 {{ color: #f85149; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.9em; }}
        th {{ color: #58a6ff; font-weight: 600; }}
        .platform-icon {{ display: inline-flex; align-items: center; gap: 6px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 OSINT Intelligence Report</h1>
            <p class="subtitle">Target: <strong>{name}</strong> | Generated: {timestamp} | Report ID: OSINT-{report_id}</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="value">{web_total}</div>
                <div class="label">Web Results</div>
            </div>
            <div class="stat-card">
                <div class="value">{social_found}</div>
                <div class="label">Social Profiles</div>
            </div>
            <div class="stat-card">
                <div class="value">{emails_gen}</div>
                <div class="label">Email Permutations</div>
            </div>
            <div class="stat-card">
                <div class="value">{breach_total}</div>
                <div class="label">Breaches Found</div>
            </div>
            <div class="stat-card">
                <div class="value">{github_total}</div>
                <div class="label">GitHub Profiles</div>
            </div>
            <div class="stat-card">
                <div class="value">{wiki_total}</div>
                <div class="label">Wiki Mentions</div>
            </div>
        </div>
"""

    # Web Results Section
    web_results = name_data.get("web_results", [])
    if web_results:
        html += '<div class="section"><h2>🌐 Web Search Results</h2>'
        for r in web_results[:20]:
            html += f"""
        <div class="result-item">
            <h4>{r.get('title', 'Untitled')[:200]}</h4>
            <a href="{r.get('url', '#')}" target="_blank">{r.get('url', '')[:100]}</a>
            <div class="snippet">Source: {r.get('source', 'unknown')}</div>
        </div>"""
        html += '</div>'

    # Social Media Section
    profiles = social_data.get("profiles_found", [])
    if profiles:
        html += '<div class="section"><h2>👤 Social Media Profiles Found</h2><table><tr><th>Platform</th><th>Username</th><th>Category</th><th>Status</th></tr>'
        for p in profiles:
            status_badge = '<span class="badge badge-success">Found</span>' if p.get('exists') else '<span class="badge badge-info">Checked</span>'
            html += f"""
            <tr>
                <td class="platform-icon"><strong>{p.get('platform', 'Unknown').replace('_', ' ').title()}</strong></td>
                <td><a href="{p.get('url', '#')}" target="_blank">{p.get('username', '')}</a></td>
                <td><span class="tag">{p.get('category', 'unknown')}</span></td>
                <td>{status_badge}</td>
            </tr>"""
        html += '</table></div>'

    # Email Section
    breached_emails = email_data.get("breached_emails", [])
    if breached_emails:
        html += '<div class="section"><h2>📧 Email Breach Intelligence</h2>'
        for e in breached_emails[:10]:
            html += f"""
        <div class="breach-card">
            <h4>⚠️ {e.get('email', 'Unknown')}</h4>
            <p>Total Breaches: <strong>{e.get('total_breaches', 0)}</strong> | Risk: <span class="risk-high">{e.get('risk_level', 'UNKNOWN')}</span></p>
        </div>"""
        html += '</div>'

    # Breach Details
    breach_list = breach_data.get("hibp_breaches", {}).get("breaches", [])
    if breach_list:
        html += '<div class="section"><h2>🔓 Data Breach Details</h2>'
        for b in breach_list[:10]:
            classes = ' '.join([f'<span class="tag">{c}</span>' for c in b.get('data_classes', [])[:5]])
            html += f"""
        <div class="breach-card">
            <h4>{b.get('title', b.get('name', 'Unknown'))}</h4>
            <p>Date: {b.get('breach_date', 'Unknown')} | Records: {b.get('pwn_count', 0):,}</p>
            <p>{b.get('description', '')[:300]}</p>
            <div style="margin-top: 8px;">{classes}</div>
        </div>"""
        html += '</div>'

    # GitHub Profiles
    github = name_data.get("github_profiles", [])
    if github:
        html += '<div class="section"><h2>💻 GitHub Profiles</h2>'
        for g in github[:10]:
            html += f"""
        <div class="result-item">
            <div class="profile-row">
                <img src="{g.get('avatar', '')}" alt="avatar" loading="lazy">
                <div>
                    <h4>{g.get('username', 'Unknown')}</h4>
                    <a href="{g.get('profile_url', '#')}" target="_blank">{g.get('profile_url', '')}</a>
                    <span class="badge badge-info">{g.get('type', 'User')}</span>
                </div>
            </div>
        </div>"""
        html += '</div>'

    # Wikipedia Mentions
    wiki = name_data.get("wikipedia_mentions", [])
    if wiki:
        html += '<div class="section"><h2>📚 Wikipedia Mentions</h2>'
        for w in wiki[:10]:
            html += f"""
        <div class="result-item">
            <h4>{w.get('title', 'Untitled')}</h4>
            <div class="snippet">{w.get('snippet', '')[:300]}</div>
            <a href="{w.get('url', '#')}" target="_blank">Read on Wikipedia</a>
        </div>"""
        html += '</div>'

    # Risk Indicators
    risks = name_data.get("risk_indicators", [])
    if risks:
        html += '<div class="section"><h2>⚠️ Risk Indicators</h2>'
        for r in risks:
            level_class = f"risk-{r.get('level', 'low').lower()}"
            html += f"""
        <div class="result-item">
            <h4 class="{level_class}">[{r.get('level', 'INFO')}] {r.get('indicator', '')}</h4>
            <div class="snippet">{r.get('detail', '')}</div>
        </div>"""
        html += '</div>'

    html += f"""
        <div class="footer">
            <p>OSINT Intelligence Report | Generated by OSINT-Tool v1.0 | {timestamp}</p>
            <p style="color: #da3633; margin-top: 8px;">⚠️ For authorized security research and investigation only. Misuse is prohibited.</p>
        </div>
    </div>
</body>
</html>"""

    return html


def generate_text_report(name: str, results: dict) -> str:
    """Generate a plain text report."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"OSINT INTELLIGENCE REPORT")
    lines.append(f"Target: {name}")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    # Name Search
    name_data = results.get("name_search", {})
    lines.append(f"\n--- WEB RESULTS ({len(name_data.get('web_results', []))}) ---")
    for r in name_data.get("web_results", [])[:10]:
        lines.append(f"  * {r.get('title', 'N/A')[:100]}")
        lines.append(f"    {r.get('url', 'N/A')}")

    # Social
    social = results.get("social_media", {})
    lines.append(f"\n--- SOCIAL PROFILES ({social.get('summary', {}).get('total_found', 0)} found) ---")
    for p in social.get("profiles_found", []):
        lines.append(f"  * {p.get('platform', 'N/A')}: {p.get('url', 'N/A')}")

    # Email
    email_data = results.get("email_finder", {})
    lines.append(f"\n--- EMAIL INTELLIGENCE ---")
    lines.append(f"  Generated: {email_data.get('total_generated', 0)} permutations")
    lines.append(f"  Breached: {email_data.get('total_breached', 0)} emails")

    # Breaches
    breach_data = results.get("breach_checker", {})
    lines.append(f"\n--- BREACH STATUS ---")
    summary = breach_data.get("summary", {})
    lines.append(f"  Breaches: {summary.get('total_unique_breaches', 0)}")
    lines.append(f"  Risk: {summary.get('risk_level', 'UNKNOWN')}")

    lines.append("\n" + "=" * 60)
    lines.append("END OF REPORT - FOR AUTHORIZED USE ONLY")
    return "\n".join(lines)


def save_report(report_id: str, name: str, results: dict, report_dir: str = "reports") -> dict:
    """Save report in multiple formats and return file paths."""
    os.makedirs(report_dir, exist_ok=True)

    files = {}

    # JSON report
    json_path = os.path.join(report_dir, f"{report_id}_data.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    files["json"] = json_path

    # HTML report
    html_path = os.path.join(report_dir, f"{report_id}_report.html")
    html_content = generate_html_report(name, results)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    files["html"] = html_path

    # Text report
    txt_path = os.path.join(report_dir, f"{report_id}_summary.txt")
    txt_content = generate_text_report(name, results)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(txt_content)
    files["text"] = txt_path

    return {
        "report_id": report_id,
        "files": files,
        "generated_at": datetime.now().isoformat(),
        "target": name
    }
