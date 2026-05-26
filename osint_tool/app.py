"""
OSINT TOOL v3.0 — Flask Backend with Progress Tracking
9 modules + real-time progress via polling endpoint.
"""
import json
import asyncio
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS

from modules.name_search import search_name
from modules.email_finder import find_emails, check_single_email
from modules.social_media import scan_social_media, check_specific_username
from modules.domain_checker import scan_domain
from modules.breach_checker import check_breaches
from modules.phone_finder import analyze_phone
from modules.people_search import search_people
from modules.darkweb_intel import darkweb_intel
from modules.report_generator import save_report, generate_html_report

app = Flask(__name__)
app.secret_key = "osint-tool-v3-research-2026"
CORS(app)

# Global progress store — keyed by report_id
_progress_store: Dict[str, Dict[str, Any]] = {}
_progress_lock = threading.Lock()


def _update_progress(report_id: str, **kwargs):
    """Thread-safe progress update."""
    with _progress_lock:
        if report_id not in _progress_store:
            _progress_store[report_id] = {
                "status": "running", "percent": 0, "modules_total": 0,
                "modules_done": 0, "modules": [], "errors": [],
                "current_module": "", "started_at": datetime.now().isoformat(),
                "finished_at": None,
            }
        _progress_store[report_id].update(kwargs)


def _get_progress(report_id: str) -> dict:
    with _progress_lock:
        return _progress_store.get(report_id, {"status": "not_found"}).copy()


# ============================================================
# PAGES
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# PROGRESS ENDPOINT
# ============================================================

@app.route("/api/progress/<report_id>")
def api_progress(report_id):
    return jsonify(_get_progress(report_id))


# ============================================================
# FULL OSINT SEARCH — background thread with progress
# ============================================================

def _run_scan_thread(report_id: str, name: str, email: str, domain: str, phone: str):
    """Background scan thread — updates progress as modules complete."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Define all possible modules
    all_modules = []
    if name:
        all_modules.extend(["name_search", "social_media", "email_finder", "people_search"])
    if email or name:
        all_modules.extend(["breach_checker", "darkweb_intel"])
    if domain:
        all_modules.append("domain_checker")
    if phone:
        all_modules.append("phone_finder")

    # Deduplicate
    all_modules = list(dict.fromkeys(all_modules))
    total = len(all_modules)
    done = 0

    _update_progress(report_id, modules_total=total, modules=all_modules,
                     modules_done=0, percent=0, current_module="initializing")

    results = {
        "query": {"name": name, "email": email, "domain": domain, "phone": phone,
                   "timestamp": datetime.now().isoformat()},
        "report_id": report_id,
    }
    errors_list = []

    def module_done(module_name: str, success: bool, error_msg: str = ""):
        nonlocal done
        done += 1
        pct = int((done / total) * 100)
        _update_progress(report_id, modules_done=done, percent=pct,
                         current_module=module_name,
                         status="running" if done < total else "completed",
                         finished_at=datetime.now().isoformat() if done >= total else None)
        if not success:
            with _progress_lock:
                _progress_store[report_id]["errors"].append(f"{module_name}: {error_msg}")

    # --- Name Search ---
    if "name_search" in all_modules:
        _update_progress(report_id, current_module="name_search")
        try:
            results["name_search"] = loop.run_until_complete(search_name(name))
            module_done("name_search", True)
        except Exception as e:
            results["name_search"] = {"error": str(e), "web_results": []}
            errors_list.append({"module": "name_search", "error": str(e)})
            module_done("name_search", False, str(e)[:100])

    # --- Social Media ---
    if "social_media" in all_modules:
        _update_progress(report_id, current_module="social_media")
        try:
            results["social_media"] = loop.run_until_complete(scan_social_media(name))
            module_done("social_media", True)
        except Exception as e:
            results["social_media"] = {"error": str(e), "profiles_found": []}
            errors_list.append({"module": "social_media", "error": str(e)})
            module_done("social_media", False, str(e)[:100])

    # --- Email Finder ---
    if "email_finder" in all_modules:
        _update_progress(report_id, current_module="email_finder")
        try:
            results["email_finder"] = loop.run_until_complete(find_emails(name))
            module_done("email_finder", True)
        except Exception as e:
            results["email_finder"] = {"error": str(e), "total_generated": 0}
            errors_list.append({"module": "email_finder", "error": str(e)})
            module_done("email_finder", False, str(e)[:100])

    # --- People Search ---
    if "people_search" in all_modules:
        _update_progress(report_id, current_module="people_search")
        try:
            results["people_search"] = loop.run_until_complete(search_people(name))
            module_done("people_search", True)
        except Exception as e:
            results["people_search"] = {"error": str(e)}
            errors_list.append({"module": "people_search", "error": str(e)})
            module_done("people_search", False, str(e)[:100])

    # --- Breach Checker ---
    if "breach_checker" in all_modules:
        _update_progress(report_id, current_module="breach_checker")
        try:
            results["breach_checker"] = loop.run_until_complete(check_breaches(email=email or None))
            module_done("breach_checker", True)
        except Exception as e:
            results["breach_checker"] = {"error": str(e)}
            errors_list.append({"module": "breach_checker", "error": str(e)})
            module_done("breach_checker", False, str(e)[:100])

    # --- Dark Web Intel ---
    if "darkweb_intel" in all_modules:
        _update_progress(report_id, current_module="darkweb_intel")
        try:
            target = email or name
            qtype = "email" if "@" in target else "name"
            results["darkweb_intel"] = loop.run_until_complete(darkweb_intel(target, qtype))
            module_done("darkweb_intel", True)
        except Exception as e:
            results["darkweb_intel"] = {"error": str(e)}
            errors_list.append({"module": "darkweb_intel", "error": str(e)})
            module_done("darkweb_intel", False, str(e)[:100])

    # --- Domain Checker ---
    if "domain_checker" in all_modules:
        _update_progress(report_id, current_module="domain_checker")
        try:
            results["domain_checker"] = loop.run_until_complete(scan_domain(domain))
            module_done("domain_checker", True)
        except Exception as e:
            results["domain_checker"] = {"error": str(e)}
            errors_list.append({"module": "domain_checker", "error": str(e)})
            module_done("domain_checker", False, str(e)[:100])

    # --- Phone Finder ---
    if "phone_finder" in all_modules:
        _update_progress(report_id, current_module="phone_finder")
        try:
            results["phone_finder"] = loop.run_until_complete(analyze_phone(phone))
            module_done("phone_finder", True)
        except Exception as e:
            results["phone_finder"] = {"error": str(e)}
            errors_list.append({"module": "phone_finder", "error": str(e)})
            module_done("phone_finder", False, str(e)[:100])

    loop.close()

    results["errors"] = errors_list if errors_list else None
    results["_progress"] = _get_progress(report_id)

    # Store completed results
    with _progress_lock:
        _progress_store[report_id]["results"] = results
        _progress_store[report_id]["status"] = "completed"
        _progress_store[report_id]["percent"] = 100
        _progress_store[report_id]["finished_at"] = datetime.now().isoformat()


@app.route("/api/search", methods=["POST"])
def api_full_search():
    """Start full OSINT scan in background thread. Poll /api/progress/<id> for status."""
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    domain = (data.get("domain") or "").strip()
    phone = (data.get("phone") or "").strip()

    if not any([name, email, domain, phone]):
        return jsonify({"error": "Minimal masukkan satu: name, email, domain, atau phone"}), 400

    report_id = datetime.now().strftime("%Y%m%d%H%M%S")

    # Initialize progress
    _update_progress(report_id, status="starting", percent=0, modules_total=0,
                     modules_done=0, modules=[], errors=[],
                     current_module="initializing",
                     started_at=datetime.now().isoformat())

    # Start background scan
    thread = threading.Thread(
        target=_run_scan_thread,
        args=(report_id, name, email, domain, phone),
        daemon=True
    )
    thread.start()

    # Cache in session
    session["last_report_id"] = report_id
    session["last_target"] = name or email or domain or phone

    return jsonify({
        "success": True,
        "report_id": report_id,
        "message": "Scan started. Poll /api/progress/" + report_id + " for status.",
        "progress_url": f"/api/progress/{report_id}"
    })


@app.route("/api/results/<report_id>")
def api_get_results(report_id):
    """Get completed scan results."""
    progress = _get_progress(report_id)
    if progress.get("status") != "completed":
        return jsonify({"error": "Scan belum selesai", "progress": progress}), 202
    results = progress.get("results", {})
    return jsonify({"success": True, "results": results})


# ============================================================
# INDIVIDUAL MODULES
# ============================================================

@app.route("/api/name", methods=["POST"])
def api_name():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name: return jsonify({"error": "Nama wajib diisi"}), 400
    try:
        return jsonify({"success": True, "results": asyncio.run(search_name(name))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/email", methods=["POST"])
def api_email():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    try:
        if email: result = asyncio.run(check_single_email(email))
        elif name: result = asyncio.run(find_emails(name))
        else: return jsonify({"error": "Nama atau email wajib diisi"}), 400
        return jsonify({"success": True, "results": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/social", methods=["POST"])
def api_social():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    username = (data.get("username") or "").strip()
    try:
        if username: result = asyncio.run(check_specific_username(username))
        elif name: result = asyncio.run(scan_social_media(name))
        else: return jsonify({"error": "Nama atau username wajib diisi"}), 400
        return jsonify({"success": True, "results": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/domain", methods=["POST"])
def api_domain():
    data = request.get_json() or {}
    domain = (data.get("domain") or "").strip()
    if not domain: return jsonify({"error": "Domain wajib diisi"}), 400
    try:
        return jsonify({"success": True, "results": asyncio.run(scan_domain(domain))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/breach", methods=["POST"])
def api_breach():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    domain = (data.get("domain") or "").strip()
    try:
        return jsonify({"success": True, "results": asyncio.run(check_breaches(email=email or None, domain=domain or None))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/phone", methods=["POST"])
def api_phone():
    data = request.get_json() or {}
    phone = (data.get("phone") or "").strip()
    if not phone: return jsonify({"error": "Nomor telepon wajib diisi"}), 400
    try:
        return jsonify({"success": True, "results": asyncio.run(analyze_phone(phone))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/people", methods=["POST"])
def api_people():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name: return jsonify({"error": "Nama wajib diisi"}), 400
    try:
        return jsonify({"success": True, "results": asyncio.run(search_people(name))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/darkweb", methods=["POST"])
def api_darkweb():
    data = request.get_json() or {}
    query = (data.get("query") or "").strip()
    qtype = (data.get("type") or "auto").strip()
    if not query: return jsonify({"error": "Query wajib diisi"}), 400
    try:
        return jsonify({"success": True, "results": asyncio.run(darkweb_intel(query, qtype))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# REPORT
# ============================================================

@app.route("/api/report/generate", methods=["POST"])
def api_generate_report():
    data = request.get_json() or {}
    name = (data.get("name") or "Unknown").strip()
    report_id = data.get("report_id") or session.get("last_report_id", "")

    # Get results from progress store or session
    results = None
    if report_id:
        progress = _get_progress(report_id)
        results = progress.get("results")

    if not results:
        results = session.get("last_results", {})

    if not results:
        return jsonify({"error": "Tidak ada data. Lakukan search dulu."}), 400

    try:
        rid = datetime.now().strftime("%Y%m%d%H%M%S")
        report_info = save_report(rid, name, results)
        return jsonify({"success": True, "report": report_info})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/report/<report_id>", methods=["GET"])
def api_get_report(report_id):
    html_path = Path(f"reports/{report_id}_report.html")
    if html_path.exists():
        return send_file(html_path, mimetype="text/html")
    progress = _get_progress(report_id)
    results = progress.get("results", {})
    if results:
        return generate_html_report(report_id, results)
    return jsonify({"error": "Report not found"}), 404


@app.route("/api/report/download/<report_id>/<fmt>", methods=["GET"])
def api_download_report(report_id, fmt):
    if fmt not in ("json", "html", "text"):
        return jsonify({"error": "Format: json, html, atau text"}), 400
    filename = {"json": f"{report_id}_data.json", "html": f"{report_id}_report.html", "text": f"{report_id}_summary.txt"}[fmt]
    filepath = Path(f"reports/{filename}")
    if filepath.exists():
        mime = {"json": "application/json", "html": "text/html", "text": "text/plain"}[fmt]
        return send_file(filepath, mimetype=mime, as_attachment=True, download_name=filename)
    return jsonify({"error": "File not found"}), 404


@app.route("/api/health")
def health():
    return jsonify({
        "status": "online", "version": "3.0.0",
        "total_modules": 9,
        "modules": ["name_search","email_finder","social_media","domain_checker","breach_checker","phone_finder","people_search","darkweb_intel","report_generator"],
        "timestamp": datetime.now().isoformat(),
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    print(f"""
    ================================================
       OSINT TOOL v3.0 — PROGRESS TRACKING
       9 Modules | http://localhost:{port}
    ================================================
    """)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
