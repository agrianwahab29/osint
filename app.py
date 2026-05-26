"""
OSINT FRAMEWORK v4.0 — Professional OSINT Backend
16 modules, SQLite persistence, progress tracking, multi-format export.
"""
import json
import asyncio
import threading
import traceback
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS

# Database
from modules.database import (
    create_scan, update_scan_progress, complete_scan, get_scan, list_scans,
    delete_scan, save_module_result, get_module_results,
    add_finding, get_findings, get_findings_summary,
    upsert_session, increment_session_scans, get_global_stats
)

# All 16 OSINT modules
from modules.name_search import search_name
from modules.email_finder import find_emails, check_single_email
from modules.social_media import scan_social_media, check_specific_username
from modules.domain_checker import scan_domain
from modules.breach_checker import check_breaches
from modules.phone_finder import analyze_phone
from modules.people_search import search_people
from modules.darkweb_intel import darkweb_intel
from modules.whois_recon import whois_recon
from modules.google_dorks import google_dorks
from modules.shodan_intel import shodan_intel
from modules.virustotal_intel import virustotal_intel
from modules.hunter_io import hunter_search
from modules.intelx_search import intelx_search
from modules.telegram_osint import telegram_osint
from modules.report_generator import save_report, generate_html_report

app = Flask(__name__)
app.secret_key = "osint-framework-v4-2026"
CORS(app)

PROGRESS_STORE = {}
PROGRESS_LOCK = threading.Lock()

ALL_MODULES = [
    "name_search", "email_finder", "social_media", "domain_checker",
    "breach_checker", "phone_finder", "people_search", "darkweb_intel",
    "whois_recon", "google_dorks", "shodan_intel", "virustotal_intel",
    "hunter_io", "intelx_search", "telegram_osint",
]


def _update_progress(rid: str, **kw):
    with PROGRESS_LOCK:
        PROGRESS_STORE.setdefault(rid, {}).update(kw)


def _get_progress(rid: str) -> dict:
    with PROGRESS_LOCK:
        return PROGRESS_STORE.get(rid, {}).copy()


# ============================================================
# PAGES
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# FULL SCAN (background thread)
# ============================================================

def _run_full_scan(rid: str, name: str, email: str, domain: str, phone: str,
                   session_id: str, modules_selected=None):
    """Run all modules in background thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if modules_selected is None:
        modules_selected = ALL_MODULES.copy()

    # Determine modules based on input
    active = []
    if name:
        active.extend(["name_search", "social_media", "email_finder", "people_search", "telegram_osint", "hunter_io"])
    if email or name:
        active.extend(["breach_checker", "darkweb_intel", "intelx_search"])
    if domain:
        active.extend(["whois_recon", "google_dorks", "shodan_intel", "virustotal_intel", "domain_checker"])
    if phone:
        active.extend(["phone_finder"])
    # Filter to selected
    active = [m for m in active if m in modules_selected]
    active = list(dict.fromkeys(active))

    total = len(active) or 1
    done = 0
    results = {"query": {"name": name, "email": email, "domain": domain, "phone": phone, "timestamp": datetime.now().isoformat()}, "report_id": rid}
    errors = []
    all_findings = 0

    _update_progress(rid, modules_total=total, modules=active, modules_done=0, percent=0, current_module="init")
    update_scan_progress(rid, modules_total=total, current_module="init")

    def _done(mod: str, ok: bool, err: str = "", findings: int = 0):
        nonlocal done, all_findings
        done += 1
        all_findings += findings
        pct = int((done / total) * 100)
        _update_progress(rid, modules_done=done, percent=pct, current_module=mod,
                         status="running" if done < total else "completed",
                         finished_at=datetime.now().isoformat() if done >= total else None)
        update_scan_progress(rid, modules_done=done, percent=pct,
                             current_module=mod if done < total else None)
        if not ok:
            with PROGRESS_LOCK:
                PROGRESS_STORE.setdefault(rid, {}).setdefault("errors", []).append(f"{mod}: {err}")

    def _run_async(mod: str, coro, sev: str = "INFO", conf: int = 50):
        _update_progress(rid, current_module=mod)
        update_scan_progress(rid, current_module=mod)
        try:
            data = loop.run_until_complete(coro)
            results[mod] = data
            fc = _count_findings(data)
            save_module_result(rid, mod, data, severity=sev, confidence=conf, findings_count=fc)
            _add_module_findings(rid, mod, data)
            _done(mod, True, "", fc)
        except Exception as e:
            err = str(e)[:150]
            results[mod] = {"error": err}
            errors.append({"module": mod, "error": err})
            save_module_result(rid, mod, {}, severity="INFO", confidence=0, findings_count=0, error=err)
            _done(mod, False, err, 0)

    # Execute
    if "name_search" in active:
        _run_async("name_search", search_name(name), "INFO", 60)
    if "social_media" in active:
        _run_async("social_media", scan_social_media(name), "INFO", 50)
    if "email_finder" in active:
        _run_async("email_finder", find_emails(name), "MEDIUM", 60)
    if "people_search" in active:
        _run_async("people_search", search_people(name), "MEDIUM", 50)
    if "breach_checker" in active:
        target_email = email if email else None
        _run_async("breach_checker", check_breaches(email=target_email), "HIGH", 70)
    if "darkweb_intel" in active:
        target = email or name
        qtype = "email" if "@" in target else "name"
        _run_async("darkweb_intel", darkweb_intel(target, qtype), "HIGH", 40)
    if "intelx_search" in active:
        target2 = email or name or domain
        _run_async("intelx_search", intelx_search(target2), "HIGH", 40)
    if "whois_recon" in active:
        _run_async("whois_recon", whois_recon(domain), "INFO", 80)
    if "google_dorks" in active:
        _run_async("google_dorks", google_dorks(domain or name), "MEDIUM", 50)
    if "shodan_intel" in active:
        _run_async("shodan_intel", shodan_intel(domain or ""), "MEDIUM", 60)
    if "virustotal_intel" in active:
        _run_async("virustotal_intel", virustotal_intel(domain or ""), "MEDIUM", 60)
    if "hunter_io" in active:
        _run_async("hunter_io", hunter_search(name=name, domain=domain), "LOW", 40)
    if "telegram_osint" in active:
        _run_async("telegram_osint", telegram_osint(name), "LOW", 30)
    if "domain_checker" in active:
        _run_async("domain_checker", scan_domain(domain), "INFO", 70)
    if "phone_finder" in active:
        _run_async("phone_finder", analyze_phone(phone), "MEDIUM", 60)

    loop.close()

    results["errors"] = errors if errors else None
    sev = _calc_severity(results)
    conf = _calc_confidence(results)

    complete_scan(rid, results, severity=sev, confidence=conf, total_findings=all_findings,
                  error_log=json.dumps(errors) if errors else "")
    _update_progress(rid, status="completed", percent=100, finished_at=datetime.now().isoformat(),
                     severity=sev, confidence=conf, total_findings=all_findings)


@app.route("/api/search", methods=["POST"])
def api_search():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    domain = (data.get("domain") or "").strip()
    phone = (data.get("phone") or "").strip()
    modules_sel = data.get("modules")  # optional filter

    if not any([name, email, domain, phone]):
        return jsonify({"error": "Minimal masukkan satu: name, email, domain, atau phone"}), 400

    rid = datetime.now().strftime("%Y%m%d%H%M%S")
    session_id = session.get("session_id", "default")
    upsert_session(session_id, request.remote_addr or "", str(request.user_agent or ""))
    increment_session_scans(session_id)
    session["session_id"] = session_id

    create_scan(rid, name, email, domain, phone, session_id)
    _update_progress(rid, status="starting", percent=0)

    t = threading.Thread(target=_run_full_scan, args=(rid, name, email, domain, phone, session_id, modules_sel), daemon=True)
    t.start()

    session["last_report_id"] = rid
    return jsonify({"success": True, "report_id": rid, "progress_url": f"/api/progress/{rid}"})


@app.route("/api/progress/<rid>")
def api_progress(rid):
    return jsonify(_get_progress(rid))


@app.route("/api/results/<rid>")
def api_results(rid):
    scan = get_scan(rid)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    results = scan.get("results", {})
    module_results = get_module_results(rid)
    findings = get_findings(rid)
    summary = get_findings_summary(rid)
    return jsonify({
        "success": True,
        "scan": {k: v for k, v in scan.items() if k != "results_json"},
        "results": results,
        "module_results": module_results,
        "findings": findings,
        "findings_summary": summary,
    })


# ============================================================
# HISTORY
# ============================================================

@app.route("/api/history")
def api_history():
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    status = request.args.get("status")
    session_id = request.args.get("session_id")
    scans = list_scans(limit=limit, offset=offset, status=status, session_id=session_id)
    return jsonify({"success": True, "scans": scans, "count": len(scans)})


@app.route("/api/history/<rid>", methods=["DELETE"])
def api_delete_scan(rid):
    ok = delete_scan(rid)
    return jsonify({"success": ok, "deleted": ok})


@app.route("/api/stats")
def api_stats():
    stats = get_global_stats()
    return jsonify({"success": True, "stats": stats})


# ============================================================
# INDIVIDUAL MODULES (15 endpoints)
# ============================================================

@app.route("/api/name", methods=["POST"])
def api_name():
    d = request.get_json() or {}
    n = (d.get("name") or "").strip()
    if not n: return jsonify({"error": "Name required"}), 400
    try: return jsonify({"success": True, "results": asyncio.run(search_name(n))})
    except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/email", methods=["POST"])
def api_email():
    d = request.get_json() or {}; n = (d.get("name") or "").strip(); e = (d.get("email") or "").strip()
    try: r = asyncio.run(check_single_email(e) if e else find_emails(n))
    except Exception as ex: return jsonify({"error": str(ex)}), 500
    return jsonify({"success": True, "results": r})

@app.route("/api/social", methods=["POST"])
def api_social():
    d = request.get_json() or {}; n = (d.get("name") or "").strip(); u = (d.get("username") or "").strip()
    try: r = asyncio.run(check_specific_username(u) if u else scan_social_media(n))
    except Exception as ex: return jsonify({"error": str(ex)}), 500
    return jsonify({"success": True, "results": r})

@app.route("/api/domain", methods=["POST"])
def api_domain():
    d = request.get_json() or {}; dom = (d.get("domain") or "").strip()
    if not dom: return jsonify({"error": "Domain required"}), 400
    try: return jsonify({"success": True, "results": asyncio.run(scan_domain(dom))})
    except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/breach", methods=["POST"])
def api_breach():
    d = request.get_json() or {}; e = (d.get("email") or "").strip(); dom = (d.get("domain") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(check_breaches(email=e or None, domain=dom or None))})
    except Exception as ex: return jsonify({"error": str(ex)}), 500

@app.route("/api/phone", methods=["POST"])
def api_phone():
    d = request.get_json() or {}; p = (d.get("phone") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(analyze_phone(p))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/people", methods=["POST"])
def api_people():
    d = request.get_json() or {}; n = (d.get("name") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(search_people(n))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/darkweb", methods=["POST"])
def api_darkweb():
    d = request.get_json() or {}; q = (d.get("query") or "").strip(); t = (d.get("type") or "auto").strip()
    try: return jsonify({"success": True, "results": asyncio.run(darkweb_intel(q, t))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/whois", methods=["POST"])
def api_whois():
    d = request.get_json() or {}; dom = (d.get("domain") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(whois_recon(dom))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/dorks", methods=["POST"])
def api_dorks():
    d = request.get_json() or {}; t = (d.get("target") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(google_dorks(t))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/shodan", methods=["POST"])
def api_shodan():
    d = request.get_json() or {}; t = (d.get("target") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(shodan_intel(t))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/virustotal", methods=["POST"])
def api_virustotal():
    d = request.get_json() or {}; t = (d.get("target") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(virustotal_intel(t))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/hunter", methods=["POST"])
def api_hunter():
    d = request.get_json() or {}; n = (d.get("name") or "").strip(); dom = (d.get("domain") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(hunter_search(name=n, domain=dom))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/intelx", methods=["POST"])
def api_intelx():
    d = request.get_json() or {}; q = (d.get("query") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(intelx_search(q))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/telegram", methods=["POST"])
def api_telegram():
    d = request.get_json() or {}; t = (d.get("target") or "").strip()
    try: return jsonify({"success": True, "results": asyncio.run(telegram_osint(t))})
    except Exception as e: return jsonify({"error": str(e)}), 500


# ============================================================
# REPORT
# ============================================================

@app.route("/api/report/generate", methods=["POST"])
def api_report_generate():
    d = request.get_json() or {}
    name = (d.get("name") or "Unknown").strip()
    rid = d.get("report_id")
    results = None
    if rid:
        scan = get_scan(rid)
        results = scan.get("results") if scan else None
    if not results:
        progress = _get_progress(rid) if rid else {}
        results = progress.get("results", {})
    if not results:
        return jsonify({"error": "No results found"}), 400
    try:
        info = save_report(rid or datetime.now().strftime("%Y%m%d%H%M%S"), name, results)
        return jsonify({"success": True, "report": info})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/report/<rid>/<fmt>")
def api_download(rid, fmt):
    if fmt not in ("json", "csv", "pdf", "html", "text"):
        return jsonify({"error": "Format: json, csv, pdf, html"}), 400
    from modules.database import get_exports
    exports = get_exports(rid)
    for exp in exports:
        if exp["format"] == fmt:
            fp = Path(exp["file_path"])
            if fp.exists():
                mime = {"json": "application/json", "csv": "text/csv", "pdf": "application/pdf", "html": "text/html", "text": "text/plain"}[fmt]
                return send_file(fp, mimetype=mime, as_attachment=True, download_name=fp.name)
    return jsonify({"error": "Export not found"}), 404


@app.route("/api/health")
def health():
    return jsonify({"status": "online", "version": "4.0.0", "modules": len(ALL_MODULES), "modules_list": ALL_MODULES, "timestamp": datetime.now().isoformat()})


@app.errorhandler(404)
def nf(e): return jsonify({"error": "Not found"}), 404
@app.errorhandler(500)
def se(e): return jsonify({"error": "Internal error"}), 500


# ============================================================
# UTILS
# ============================================================

def _count_findings(data: dict) -> int:
    if not data or not isinstance(data, dict): return 0
    c = 0
    for k in ["web_results", "profiles_found", "github_profiles", "wikipedia_mentions", "breached_emails", "subdomains_found"]:
        c += len(data.get(k, []))
    c += data.get("total_results", 0) + data.get("total_generated", 0) + data.get("total_matches", 0)
    sm = data.get("summary", {}) or {}
    c += sm.get("total_found", 0) + sm.get("total_unique_breaches", 0) + sm.get("total_findings", 0)
    return c


def _calc_severity(results: dict) -> str:
    scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    best = 0
    for v in results.values():
        if not v or not isinstance(v, dict): continue
        sev = v.get("severity") or v.get("risk_level") or (v.get("summary", {}) or {}).get("risk_level") or \
              (v.get("hibp_breaches", {}) or {}).get("risk_level") or (v.get("risk_assessment", {}) or {}).get("risk_level")
        if sev and scores.get(sev, 0) > best:
            best = scores.get(sev, 0)
    for k, s in scores.items():
        if s == best: return k
    return "UNKNOWN"


def _calc_confidence(results: dict) -> int:
    confs = []
    for v in results.values():
        if not v or not isinstance(v, dict): continue
        for k in ["confidence", "confidence_score"]:
            if k in v and isinstance(v[k], (int, float)):
                confs.append(int(v[k]))
        sm = v.get("summary", {}) or {}
        if isinstance(sm.get("confidence"), (int, float)):
            confs.append(int(sm["confidence"]))
    return int(sum(confs) / len(confs)) if confs else 50


def _add_module_findings(rid: str, mod: str, data: dict):
    if not data or not isinstance(data, dict): return
    sev = data.get("severity", "INFO")
    conf = data.get("confidence", data.get("confidence_score", 50))
    ts = datetime.now().isoformat()
    for r in data.get("web_results", [])[:20]:
        add_finding(rid, mod, "web_result", r.get("url", ""), {"title": r.get("title", "")}, sev, conf, r.get("source", ""))
    for p in data.get("profiles_found", [])[:20]:
        add_finding(rid, mod, "social_profile", p.get("url", ""), {"platform": p.get("platform", ""), "username": p.get("username", "")}, sev, conf, p.get("platform", ""))
    for e in data.get("breached_emails", [])[:10]:
        add_finding(rid, mod, "breached_email", e.get("email", ""), {"total_breaches": e.get("total_breaches", 0)}, "HIGH", conf, "hibp")
    for s in data.get("subdomains_found", [])[:10]:
        add_finding(rid, mod, "subdomain", s.get("subdomain", ""), {"status": s.get("status", 0)}, "LOW", conf, "dns")
    if data.get("cleaned"):
        add_finding(rid, mod, "phone", data["cleaned"], {"country": (data.get("country_info", {}) or {}).get("country", "")}, "MEDIUM", conf, "phone")


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    print(f"\n    OSINT FRAMEWORK v4.0 — {len(ALL_MODULES)} Modules — http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
