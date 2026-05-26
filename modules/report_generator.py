"""
Report Generator v5 — Forensic-grade multi-format OSINT reports
Includes: Executive Summary, Methodology, Evidence Table, Confidence Scoring,
Risk Matrix, Timeline, Limitations, Recommendations, Appendix JSON.
"""
import json
import csv
import os
import io
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from modules.database import record_export

REPORT_DIR = Path(__file__).parent.parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# Report version
REPORT_VERSION = "6.0.0"


def _calc_overall_severity(results: dict) -> str:
    """Calculate overall severity from all module results."""
    scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}

    sev_levels = []
    for key, data in results.items():
        if not data or not isinstance(data, dict):
            continue
        # Try to find severity
        sev = data.get("severity") or data.get("risk_level") or \
              (data.get("summary", {}) or {}).get("risk_level") or \
              (data.get("hibp_breaches", {}) or {}).get("risk_level") or \
              (data.get("risk_assessment", {}) or {}).get("risk_level")
        if sev:
            sev_levels.append(sev)

    if not sev_levels:
        return "UNKNOWN"

    max_score = max(scores.get(s, 0) for s in sev_levels)
    for k, v in scores.items():
        if v == max_score:
            return k
    return "UNKNOWN"


def _calc_confidence(results: dict) -> int:
    """Calculate overall confidence score (0-100)."""
    confidences = []
    for key, data in results.items():
        if not data or not isinstance(data, dict):
            continue
        confs = [data.get("confidence"), data.get("confidence_score"),
                 (data.get("summary", {}) or {}).get("confidence")]
        for c in confs:
            if isinstance(c, (int, float)):
                confidences.append(int(c))

    if confidences:
        return int(sum(confidences) / len(confidences))
    return 50


def _count_total_findings(results: dict) -> int:
    """Count total findings across all modules."""
    count = 0
    for key, data in results.items():
        if not data or not isinstance(data, dict):
            continue
        # Count from various possible fields
        count += len(data.get("web_results", []))
        count += len(data.get("profiles_found", []))
        count += len(data.get("github_profiles", []))
        count += len(data.get("wikipedia_mentions", []))
        count += len(data.get("generated_emails", []))
        count += len(data.get("breached_emails", []))
        count += (data.get("total_results", 0))
        count += (data.get("total_generated", 0))
        sum_data = data.get("summary", {}) or data.get("aggregated", {}) or {}
        count += sum_data.get("total_found", 0)
        count += sum_data.get("total_unique_breaches", 0)
        count += sum_data.get("total_matches", 0)
        count += sum_data.get("sites_with_results", 0)
    return count


# ============================================================
# JSON
# ============================================================

def _build_forensic_report(report_id: str, name: str, results: dict) -> dict:
    """Build a complete forensic report structure."""
    severity = _calc_overall_severity(results)
    confidence = _calc_confidence(results)
    total = _count_total_findings(results)
    ts = datetime.now().isoformat()
    query = results.get("query", {})
    scan_meta = results.get("scan_metadata", {})

    # Source inventory
    source_inventory = []
    for mod_name, data in results.items():
        if not data or not isinstance(data, dict):
            continue
        if mod_name in ("query", "errors", "report_id", "_progress", "scan_metadata"):
            continue
        status = "completed" if not data.get("error") else "error"
        source_inventory.append({
            "module": mod_name,
            "status": status,
            "findings_count": _count_findings_for_module(data),
        })

    # Build findings
    findings = []
    for mod_name, data in results.items():
        if not data or not isinstance(data, dict) or mod_name in ("query", "errors", "report_id", "_progress", "scan_metadata"):
            continue
        findings.extend(_extract_findings(mod_name, data))

    # Evidence items
    evidence = []
    for f in findings[:50]:
        ev_hash = hashlib.sha256(json.dumps(f, default=str, sort_keys=True).encode()).hexdigest()[:16]
        evidence.append({
            "evidence_id": f"EVD-{ev_hash[:8].upper()}",
            "finding_id": f.get("finding_id", ""),
            "source_url": f.get("source_url", ""),
            "captured_at": ts,
            "content_hash_sha256": ev_hash,
        })

    # Risk matrix
    risk = _calculate_risk_matrix(findings)

    # Recommendations
    recommendations = _generate_recommendations(results, findings)

    return {
        "report_metadata": {
            "report_id": report_id,
            "report_version": REPORT_VERSION,
            "target": name,
            "generated_at": ts,
            "scan_mode": scan_meta.get("scan_mode", "standard"),
            "country": scan_meta.get("country", "ID"),
            "severity": severity,
            "confidence_score": confidence,
            "total_findings": total,
            "modules_used": [s["module"] for s in source_inventory],
        },
        "executive_summary": {
            "overview": f"OSINT forensic scan completed for target: {name}. Found {total} total findings across {len(source_inventory)} modules.",
            "risk_level": severity,
            "confidence": confidence,
            "key_findings": risk.get("risk_reasons", [])[:5],
        },
        "scope": {
            "target_name": query.get("name", name),
            "target_email": query.get("email", ""),
            "target_domain": query.get("domain", ""),
            "target_phone": query.get("phone", ""),
            "country": query.get("country", scan_meta.get("country", "ID")),
            "scan_mode": scan_meta.get("scan_mode", "standard"),
            "scan_date": query.get("timestamp", ts),
        },
        "methodology": (
            "Public OSINT data collection from open web sources, public APIs, "
            "DNS records, breach databases, and social platforms. "
            "No illegal access, credential stuffing, or private scraping performed. "
            "All findings based on publicly available information."
        ),
        "source_inventory": source_inventory,
        "findings": findings,
        "evidence_table": evidence,
        "confidence_scoring": {
            "overall_confidence": confidence,
            "scale": "0-100 (Very Low: 0-24, Low: 25-49, Medium: 50-74, High: 75-89, Very High: 90-100)",
            "methodology": "Confidence based on source reliability, name matching, and verification level",
        },
        "risk_matrix": risk,
        "timeline": {
            "scan_started": query.get("timestamp", ts),
            "scan_completed": ts,
        },
        "limitations": [
            "Email candidates are generated from name patterns and NOT verified as active",
            "People search sources are US-centric; confidence lowered for non-US targets",
            "Dark web/exposure checks are limited to public paste searches",
            "API-dependent modules (HIBP, Hunter, Shodan) are disabled without API keys",
            "Social media results may include profiles not belonging to target",
            "Breach data may be incomplete without HIBP API key",
            "Phone numbers from aggregators are unverified",
        ],
        "recommendations": recommendations,
        "appendix_json": {
            "modules": {k: v for k, v in results.items()
                        if k not in ("query", "errors", "report_id", "_progress", "scan_metadata")},
        },
    }


def _extract_findings(mod_name: str, data: dict) -> list:
    """Extract structured findings from module data."""
    findings = []
    sev = data.get("severity", "INFO")
    ts = data.get("timestamp", datetime.now().isoformat())

    for r in data.get("web_results", [])[:10]:
        findings.append({
            "finding_id": f"FND-{hashlib.md5(r.get('url','').encode()).hexdigest()[:8].upper()}",
            "category": "web_result",
            "type": "public_web_mention",
            "value": r.get("url", ""),
            "source_url": r.get("url", ""),
            "source_name": r.get("source", "web"),
            "confidence": 60,
            "risk": "LOW",
            "status": "publicly_observed",
            "timestamp": ts,
            "notes": r.get("title", ""),
        })

    for p in data.get("profiles_found", [])[:10]:
        findings.append({
            "finding_id": f"FND-{hashlib.md5(p.get('url','').encode()).hexdigest()[:8].upper()}",
            "category": "social_profile",
            "type": "social_media_profile",
            "value": p.get("url", ""),
            "source_url": p.get("url", ""),
            "source_name": p.get("platform", ""),
            "confidence": 80 if p.get("confidence") == "high" else 50,
            "risk": "LOW",
            "status": "source_matched",
            "timestamp": ts,
            "notes": f"Username: {p.get('username', '')}",
        })

    for e in data.get("publicly_found_emails", [])[:10]:
        findings.append({
            "finding_id": f"FND-{hashlib.md5(e.get('email','').encode()).hexdigest()[:8].upper()}",
            "category": "email",
            "type": "publicly_found_email",
            "value": e.get("email", ""),
            "source_url": e.get("source_url", ""),
            "source_name": "Public Web Page",
            "confidence": e.get("confidence", 85),
            "risk": "MEDIUM",
            "status": "publicly_observed",
            "timestamp": ts,
            "notes": e.get("reason", ""),
        })

    for b in data.get("breached_emails", [])[:5]:
        findings.append({
            "finding_id": f"FND-{hashlib.md5(b.get('email','').encode()).hexdigest()[:8].upper()}",
            "category": "breach",
            "type": "breached_email",
            "value": b.get("email", ""),
            "source_url": "https://haveibeenpwned.com",
            "source_name": "HIBP",
            "confidence": 95,
            "risk": "HIGH",
            "status": "verified",
            "timestamp": ts,
            "notes": f"{b.get('total_breaches', 0)} breaches found",
        })

    return findings


def _calculate_risk_matrix(findings: list) -> dict:
    """Calculate risk matrix from findings."""
    risk_score = 0
    reasons = []
    for f in findings:
        ftype = f.get("type", "")
        if ftype == "publicly_found_email":
            risk_score += 15
            reasons.append("Public email address found")
        elif ftype == "breached_email":
            risk_score += 25
            reasons.append("Email found in data breach")
        elif ftype == "social_media_profile":
            risk_score += 5
        elif ftype == "public_web_mention":
            risk_score += 2

    if risk_score >= 70: level = "CRITICAL"
    elif risk_score >= 50: level = "HIGH"
    elif risk_score >= 30: level = "MEDIUM"
    elif risk_score >= 10: level = "LOW"
    else: level = "NONE"

    return {
        "risk_score": min(100, risk_score),
        "risk_level": level,
        "risk_reasons": reasons if reasons else ["No significant risk factors detected"],
    }


def _generate_recommendations(results: dict, findings: list) -> list:
    """Generate actionable recommendations."""
    recs = []
    for f in findings:
        ftype = f.get("type", "")
        if ftype == "breached_email":
            recs.append("Change passwords for all breached accounts immediately")
            recs.append("Enable 2FA on accounts linked to breached email")
        elif ftype == "publicly_found_email":
            recs.append("Consider removing public email from web pages")
            recs.append("Use contact forms instead of exposing email addresses")

    has_domain = any(f.get("category") == "domain" for f in findings)
    if has_domain:
        recs.append("Configure SPF, DMARC, and DKIM for email security")
        recs.append("Enable HSTS and security headers on web server")

    recs.append("Use unique passwords per service")
    recs.append("Monitor breach notifications via HIBP")
    recs.append("Regularly audit digital footprint")

    return list(set(recs))[:10]


def save_json(report_id: str, name: str, results: dict) -> str:
    """Save forensic JSON report."""
    report = _build_forensic_report(report_id, name, results)
    filepath = REPORT_DIR / f"{report_id}_report.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str, ensure_ascii=False)
    record_export(report_id, "json", str(filepath), os.path.getsize(filepath))
    return str(filepath)


# ============================================================
# CSV
# ============================================================

def save_csv(report_id: str, name: str, results: dict) -> str:
    filepath = REPORT_DIR / f"{report_id}_findings.csv"

    rows = []
    timestamp = datetime.now().isoformat()

    for module_name, data in results.items():
        if not data or not isinstance(data, dict) or module_name in ("query", "errors", "report_id", "_progress"):
            continue

        sev = data.get("severity", "INFO")
        conf = data.get("confidence", data.get("confidence_score", 50))

        # Web results
        for r in data.get("web_results", []):
            rows.append([module_name, "web_result", r.get("title", ""), r.get("url", ""), sev, conf, r.get("source", ""), timestamp])

        # Profiles
        for p in data.get("profiles_found", []):
            rows.append([module_name, "social_profile", p.get("platform", ""), p.get("url", ""), sev, conf, p.get("category", ""), timestamp])

        # GitHub
        for g in data.get("github_profiles", []):
            rows.append([module_name, "github_profile", g.get("username", ""), g.get("url", ""), sev, conf, "github", timestamp])

        # Wikipedia
        for w in data.get("wikipedia_mentions", []):
            rows.append([module_name, "wiki_mention", w.get("title", ""), w.get("url", ""), sev, conf, "wikipedia", timestamp])

        # Emails
        for e in data.get("breached_emails", []):
            rows.append([module_name, "breached_email", e.get("email", ""), str(e.get("total_breaches", "")), "HIGH" if e.get("risk_level") in ("CRITICAL", "HIGH") else "MEDIUM", conf, "hibp", timestamp])

        # Phones
        if data.get("cleaned"):
            pi = data.get("provider_info", {})
            ci = data.get("country_info", {})
            rows.append([module_name, "phone", data.get("cleaned", ""), f"{pi.get('provider', '')} - {ci.get('country', '')}", sev, conf, "phone_analysis", timestamp])

        # Breaches
        for b in (data.get("hibp_breaches", {}) or {}).get("breaches", []):
            rows.append([module_name, "data_breach", b.get("title", b.get("name", "")), str(b.get("pwn_count", "")), "HIGH", conf, b.get("domain", ""), timestamp])

        # Dark web
        dd = data.get("breach_exposure", {}) or {}
        for b in dd.get("likely_breaches", []):
            rows.append([module_name, "breach_exposure", b.get("breach", ""), b.get("records", ""), "HIGH", conf, "darkweb", timestamp])

        # Subdomains
        for s in data.get("subdomains_found", []):
            rows.append([module_name, "subdomain", s.get("subdomain", ""), str(s.get("status", "")), "LOW", conf, "dns_enum", timestamp])

    # Write CSV
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Module", "Finding Type", "Value", "Details", "Severity", "Confidence", "Source", "Timestamp"])
        writer.writerows(rows)

    record_export(report_id, "csv", str(filepath), os.path.getsize(filepath))
    return str(filepath)


# ============================================================
# PDF
# ============================================================

def save_pdf(report_id: str, name: str, results: dict) -> str:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        return ""

    filepath = REPORT_DIR / f"{report_id}_report.pdf"
    severity = _calc_overall_severity(results)
    confidence = _calc_confidence(results)
    total_findings = _count_total_findings(results)

    doc = SimpleDocTemplate(str(filepath), pagesize=A4, leftMargin=15*mm, rightMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=22, textColor=HexColor("#1a56db"), spaceAfter=6)
    story.append(Paragraph(f"OSINT Intelligence Report", title_style))
    story.append(Paragraph(f"Target: {name}", styles["Heading2"]))
    story.append(Paragraph(f"Report ID: {report_id} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    story.append(Spacer(1, 8*mm))

    # Severity badge
    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb", "INFO": "#6b7280", "UNKNOWN": "#9ca3af"}
    sev_style = ParagraphStyle("Sev", parent=styles["Normal"], fontSize=11, textColor=HexColor(sev_colors.get(severity, "#000")))
    story.append(Paragraph(f"Severity: <b>{severity}</b> | Confidence: <b>{confidence}%</b> | Findings: <b>{total_findings}</b>", sev_style))
    story.append(Spacer(1, 6*mm))

    # Summary table
    table_data = [
        ["Module", "Status", "Findings", "Severity"],
    ]
    for mod_name, data in results.items():
        if not data or not isinstance(data, dict) or mod_name in ("query", "errors", "report_id", "_progress"):
            continue
        m_sev = data.get("severity", "INFO")
        m_count = _count_findings_for_module(data)
        status = "Error" if data.get("error") else "OK"
        table_data.append([mod_name.replace("_", " ").title(), status, str(m_count), m_sev])

    if len(table_data) > 1:
        t = Table(table_data, colWidths=[120, 60, 60, 60])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a56db")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#f9fafb"), HexColor("#ffffff")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 6*mm))

    # Module sections
    for mod_name, data in results.items():
        if not data or not isinstance(data, dict) or mod_name in ("query", "errors", "report_id", "_progress"):
            continue
        if data.get("error"):
            continue

        story.append(Paragraph(f"{mod_name.replace('_', ' ').title()}", styles["Heading3"]))
        story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#d1d5db")))

        # Extract text details
        details = _extract_module_text(mod_name, data)
        for line in details[:15]:
            story.append(Paragraph(line, styles["Normal"]))

        story.append(Spacer(1, 3*mm))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#9ca3af")))
    story.append(Paragraph("<i>Generated by OSINT Framework v4.0 — For authorized security research only</i>", styles["Normal"]))

    doc.build(story)

    record_export(report_id, "pdf", str(filepath), os.path.getsize(filepath))
    return str(filepath)


def _count_findings_for_module(data: dict) -> int:
    cnt = 0
    cnt += len(data.get("web_results", []))
    cnt += len(data.get("profiles_found", []))
    cnt += len(data.get("github_profiles", []))
    cnt += len(data.get("wikipedia_mentions", []))
    cnt += len(data.get("breached_emails", []))
    cnt += len(data.get("generated_emails", []))
    cnt += len(data.get("breaches", (data.get("hibp_breaches", {}) or {}).get("breaches", [])))
    cnt += len(data.get("subdomains_found", []))
    cnt += data.get("total_results", 0)
    cnt += data.get("total_generated", 0)
    sm = data.get("summary", {}) or {}
    cnt += sm.get("total_found", 0)
    cnt += sm.get("total_unique_breaches", 0)
    cnt += sm.get("total_matches", 0)
    return cnt


def _extract_module_text(mod_name: str, data: dict) -> list:
    lines = []
    for r in data.get("web_results", [])[:5]:
        lines.append(f"• {r.get('title', '')[:120]}")
    for p in data.get("profiles_found", [])[:5]:
        lines.append(f"• [{p.get('platform', '')}] {p.get('url', '')}")
    for g in data.get("github_profiles", [])[:3]:
        lines.append(f"• GitHub: {g.get('username', '')} — {g.get('url', '')}")
    for b in (data.get("hibp_breaches", {}) or {}).get("breaches", [])[:3]:
        lines.append(f"• Breach: {b.get('title', b.get('name', ''))} ({b.get('breach_date', '')})")
    for e in data.get("breached_emails", [])[:3]:
        lines.append(f"• Breached Email: {e.get('email', '')}")
    if data.get("cleaned"):
        ci = data.get("country_info", {}) or {}
        pi = data.get("provider_info", {}) or {}
        lines.append(f"• Phone: {data.get('cleaned', '')} — {ci.get('country', '')} / {pi.get('provider', '')}")
    for s in data.get("subdomains_found", [])[:5]:
        lines.append(f"• Subdomain: {s.get('subdomain', '')}")
    sm = data.get("summary", {}) or data.get("risk_assessment", {}) or {}
    if sm.get("risk_level"):
        lines.append(f"Risk Level: {sm['risk_level']}")
    if sm.get("risk_score"):
        lines.append(f"Risk Score: {sm['risk_score']}")
    return lines


# ============================================================
# HTML
# ============================================================

def generate_html_report(report_id: str, name: str, results: dict) -> str:
    """Generate enhanced forensic HTML report."""
    report = _build_forensic_report(report_id, name, results)
    severity = report["report_metadata"]["severity"]
    confidence = report["report_metadata"]["confidence_score"]
    total = report["report_metadata"]["total_findings"]
    timestamp = report["report_metadata"]["generated_at"]
    risk = report["risk_matrix"]

    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb", "INFO": "#6b7280"}

    findings_html = ""
    for f in report["findings"][:30]:
        risk_cls = "tag-danger" if f.get("risk") in ("HIGH", "CRITICAL") else "tag-warn" if f.get("risk") == "MEDIUM" else "tag-success"
        findings_html += f'''
        <div class="item">
            <span class="tag {risk_cls}">{f.get("risk","LOW")}</span>
            <strong>{f.get("category","").replace("_"," ").title()}</strong> —
            {f.get("value","")[:80]}
            <br><small>Source: {f.get("source_url","")[:80]} | Confidence: {f.get("confidence",0)}%</small>
        </div>'''

    limitations_html = "".join(f"<li>{l}</li>" for l in report["limitations"])
    recs_html = "".join(f"<li>{r}</li>" for r in report["recommendations"])
    sources_html = "".join(
        f'<tr><td>{s["module"]}</td><td>{s["status"]}</td><td>{s["findings_count"]}</td></tr>'
        for s in report["source_inventory"]
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>OSINT Forensic Report — {name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
.container{{max-width:1000px;margin:0 auto;padding:20px}}
.header{{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px}}
.header h1{{color:#3b82f6;font-size:1.6em}}.header .meta{{color:#94a3b8;font-size:.85em;margin-top:6px}}
.severity{{display:inline-block;padding:4px 12px;border-radius:6px;font-weight:700;color:#fff;background:{sev_colors.get(severity,'#6b7280')}}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;text-align:center}}
.card .value{{font-size:1.8em;font-weight:800;color:#3b82f6}}.card .label{{color:#94a3b8;font-size:.8em}}
.section{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:16px}}
.section h2{{color:#3b82f6;font-size:1.2em;margin-bottom:12px;border-bottom:1px solid #334155;padding-bottom:8px}}
.item{{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:10px;margin-bottom:8px}}
.item h4{{font-size:.9em;margin-bottom:4px}}.item a{{color:#3b82f6;font-size:.8em;word-break:break-all}}
.item .snippet{{color:#94a3b8;font-size:.8em;margin-top:4px}}
.tag{{display:inline-block;background:#334155;border-radius:4px;padding:2px 6px;font-size:.7em;margin:2px;color:#cbd5e1}}
.tag-danger{{background:#7f1d1d33;color:#f87171;border:1px solid #7f1d1d}}
.tag-success{{background:#064e3b33;color:#34d399;border:1px solid #064e3b}}
.tag-warn{{background:#78350f33;color:#fbbf24;border:1px solid #78350f}}
table{{width:100%;border-collapse:collapse;font-size:.85em}}th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid #334155}}
th{{color:#3b82f6;font-weight:600}}.footer{{text-align:center;color:#475569;font-size:.75em;padding:16px}}
ul{{padding-left:20px}}li{{margin-bottom:4px;font-size:.85em}}
</style></head><body><div class="container">
<div class="header">
    <h1>🔍 OSINT Forensic Intelligence Report</h1>
    <p>Target: <strong>{name}</strong> | ID: {report_id}</p>
    <p>Scan Mode: {report['report_metadata']['scan_mode']} | Country: {report['report_metadata']['country']}</p>
    <p class="meta">Generated: {timestamp} | Report v{REPORT_VERSION}</p>
    <p style="margin-top:8px"><span class="severity">{severity}</span> Confidence: {confidence}% | Findings: {total}</p>
</div>

<div class="grid">
    <div class="card"><div class="value">{len(report['source_inventory'])}</div><div class="label">Modules</div></div>
    <div class="card"><div class="value">{total}</div><div class="label">Total Findings</div></div>
    <div class="card"><div class="value">{severity}</div><div class="label">Risk Level</div></div>
    <div class="card"><div class="value">{confidence}%</div><div class="label">Confidence</div></div>
</div>

<div class="section"><h2>📋 Executive Summary</h2>
    <p>{report['executive_summary']['overview']}</p>
    <p style="margin-top:8px"><strong>Key Findings:</strong></p>
    <ul>{''.join(f'<li>{k}</li>' for k in report['executive_summary']['key_findings'])}</ul>
</div>

<div class="section"><h2>🎯 Scope</h2>
    <p>Target: {report['scope']['target_name']}</p>
    <p>Scan Date: {report['scope']['scan_date']} | Mode: {report['scope']['scan_mode']} | Country: {report['scope']['country']}</p>
</div>

<div class="section"><h2>📊 Source Inventory</h2>
    <table><tr><th>Module</th><th>Status</th><th>Findings</th></tr>{sources_html}</table>
</div>

<div class="section"><h2>🔍 Findings ({len(report['findings'])} total)</h2>{findings_html}</div>

<div class="section"><h2>⚠️ Risk Matrix</h2>
    <p>Risk Score: <strong>{risk['risk_score']}</strong> | Level: <span class="severity">{risk['risk_level']}</span></p>
    <ul>{''.join(f'<li>{r}</li>' for r in risk['risk_reasons'])}</ul>
</div>

<div class="section"><h2>🛡️ Recommendations</h2><ul>{recs_html}</ul></div>

<div class="section"><h2>⚠️ Limitations</h2><ul>{limitations_html}</ul></div>

<div class="footer">OSINTTool v{REPORT_VERSION} — Forensic Intelligence Platform<br>For authorized security research & self-assessment only</div>
</div></body></html>"""


# ============================================================
# Save all formats
# ============================================================

def save_report(report_id: str, name: str, results: dict) -> dict:
    """Generate and save forensic reports in all formats."""
    files = {}
    forensic = _build_forensic_report(report_id, name, results)

    files["json"] = save_json(report_id, name, results)
    files["csv"] = save_csv(report_id, name, results)
    pdf_path = save_pdf(report_id, name, results)
    if pdf_path:
        files["pdf"] = pdf_path

    # HTML (forensic format)
    html_path = REPORT_DIR / f"{report_id}_report.html"
    html_content = generate_html_report(report_id, name, results)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    files["html"] = str(html_path)
    record_export(report_id, "html", str(html_path), os.path.getsize(html_path))

    return {
        "report_id": report_id,
        "files": {k: str(v) for k, v in files.items()},
        "severity": forensic["report_metadata"]["severity"],
        "confidence": forensic["report_metadata"]["confidence_score"],
        "total_findings": forensic["report_metadata"]["total_findings"],
        "risk_level": forensic["risk_matrix"]["risk_level"],
        "generated_at": datetime.now().isoformat(),
    }
