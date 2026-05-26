"""
Database Layer — SQLite for OSINT Tool
Stores: scans, results, progress, sessions, history, exports
"""
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Any
from contextlib import contextmanager
from threading import Lock

DB_PATH = Path(__file__).parent.parent / "osint.db"
_lock = Lock()


def init_db():
    """Initialize database schema."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Scans table — main scan history
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            target_name TEXT,
            target_email TEXT,
            target_domain TEXT,
            target_phone TEXT,
            status TEXT DEFAULT 'pending',
            percent INTEGER DEFAULT 0,
            modules_total INTEGER DEFAULT 0,
            modules_done INTEGER DEFAULT 0,
            current_module TEXT,
            severity TEXT DEFAULT 'UNKNOWN',
            confidence_score INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            user_session TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            duration_seconds REAL DEFAULT 0,
            results_json TEXT,
            error_log TEXT
        )
        """)

        # Results table — individual module results per scan
        cur.execute("""
        CREATE TABLE IF NOT EXISTS module_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT NOT NULL,
            module_name TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            severity TEXT DEFAULT 'INFO',
            confidence INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            data_json TEXT,
            error TEXT,
            started_at TEXT,
            finished_at TEXT,
            FOREIGN KEY (report_id) REFERENCES scans(report_id) ON DELETE CASCADE
        )
        """)

        # Findings table — granular findings (emails, phones, profiles, etc)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT NOT NULL,
            module_name TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            value TEXT NOT NULL,
            metadata_json TEXT,
            severity TEXT DEFAULT 'INFO',
            confidence INTEGER DEFAULT 50,
            source TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (report_id) REFERENCES scans(report_id) ON DELETE CASCADE
        )
        """)

        # Sessions table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_label TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            last_active TEXT NOT NULL,
            scan_count INTEGER DEFAULT 0
        )
        """)

        # Exports table — track exported reports
        cur.execute("""
        CREATE TABLE IF NOT EXISTS exports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT NOT NULL,
            format TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            generated_at TEXT NOT NULL,
            downloaded_count INTEGER DEFAULT 0,
            FOREIGN KEY (report_id) REFERENCES scans(report_id) ON DELETE CASCADE
        )
        """)

        # Indexes for query speed
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_name, target_email, target_domain)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(user_session)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_results_report ON module_results(report_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_report ON findings(report_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")

        conn.commit()
        conn.close()


@contextmanager
def get_db():
    """Get DB connection with lock."""
    with _lock:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


# ============================================================
# SCAN OPERATIONS
# ============================================================

def create_scan(report_id: str, name: str = "", email: str = "", domain: str = "",
                phone: str = "", session_id: str = "") -> int:
    """Create a new scan record."""
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO scans (report_id, target_name, target_email, target_domain,
               target_phone, user_session, started_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'running')""",
            (report_id, name, email, domain, phone, session_id, datetime.now().isoformat())
        )
        return cur.lastrowid or 0


def update_scan_progress(report_id: str, **kwargs):
    """Update scan progress fields."""
    if not kwargs:
        return
    fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [report_id]
    with get_db() as conn:
        conn.execute(f"UPDATE scans SET {fields} WHERE report_id = ?", values)


def complete_scan(report_id: str, results: dict, severity: str = "INFO",
                  confidence: int = 50, total_findings: int = 0, error_log: str = ""):
    """Mark scan as complete."""
    with get_db() as conn:
        scan = conn.execute("SELECT started_at FROM scans WHERE report_id = ?", (report_id,)).fetchone()
        duration = 0
        if scan:
            try:
                started = datetime.fromisoformat(scan["started_at"])
                duration = (datetime.now() - started).total_seconds()
            except Exception:
                duration = 0

        conn.execute(
            """UPDATE scans SET status = 'completed', percent = 100,
               finished_at = ?, duration_seconds = ?, severity = ?, confidence_score = ?,
               total_findings = ?, results_json = ?, error_log = ?
               WHERE report_id = ?""",
            (datetime.now().isoformat(), duration, severity, confidence,
             total_findings, json.dumps(results, default=str), error_log, report_id)
        )


def get_scan(report_id: str) -> Optional[dict]:
    """Get scan by report_id."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE report_id = ?", (report_id,)).fetchone()
        if not row:
            return None
        scan = dict(row)
        if scan.get("results_json"):
            try:
                scan["results"] = json.loads(scan["results_json"])
            except Exception:
                scan["results"] = {}
        return scan


def list_scans(limit: int = 50, offset: int = 0, session_id: Optional[str] = None,
               status: Optional[str] = None) -> list:
    """List scans with optional filters."""
    query = "SELECT id, report_id, target_name, target_email, target_domain, target_phone, status, severity, confidence_score, total_findings, started_at, finished_at, duration_seconds FROM scans WHERE 1=1"
    params = []
    if session_id:
        query += " AND user_session = ?"
        params.append(session_id)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def delete_scan(report_id: str) -> bool:
    """Delete scan and its findings."""
    with get_db() as conn:
        result = conn.execute("DELETE FROM scans WHERE report_id = ?", (report_id,))
        return result.rowcount > 0


# ============================================================
# MODULE RESULTS
# ============================================================

def save_module_result(report_id: str, module_name: str, data: dict,
                       severity: str = "INFO", confidence: int = 50,
                       findings_count: int = 0, error: str = "") -> int:
    """Save individual module result."""
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO module_results (report_id, module_name, status, severity,
               confidence, findings_count, data_json, error, started_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (report_id, module_name, "completed" if not error else "error",
             severity, confidence, findings_count,
             json.dumps(data, default=str), error,
             datetime.now().isoformat(), datetime.now().isoformat())
        )
        return cur.lastrowid or 0


def get_module_results(report_id: str) -> list:
    """Get all module results for a scan."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM module_results WHERE report_id = ? ORDER BY id",
            (report_id,)
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get("data_json"):
                try:
                    d["data"] = json.loads(d["data_json"])
                except Exception:
                    d["data"] = {}
            results.append(d)
        return results


# ============================================================
# FINDINGS
# ============================================================

def add_finding(report_id: str, module_name: str, finding_type: str, value: str,
                metadata: Optional[dict] = None, severity: str = "INFO",
                confidence: int = 50, source: str = ""):
    """Add a discrete finding."""
    with get_db() as conn:
        conn.execute(
            """INSERT INTO findings (report_id, module_name, finding_type, value,
               metadata_json, severity, confidence, source, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (report_id, module_name, finding_type, value,
             json.dumps(metadata or {}, default=str), severity, confidence,
             source, datetime.now().isoformat())
        )


def get_findings(report_id: str, finding_type: Optional[str] = None,
                 severity: Optional[str] = None) -> list:
    """Get findings for a scan, optionally filtered."""
    query = "SELECT * FROM findings WHERE report_id = ?"
    params: list = [report_id]
    if finding_type:
        query += " AND finding_type = ?"
        params.append(finding_type)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY confidence DESC, id"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("metadata_json"):
                try:
                    d["metadata"] = json.loads(d["metadata_json"])
                except Exception:
                    d["metadata"] = {}
            result.append(d)
        return result


def get_findings_summary(report_id: str) -> dict:
    """Aggregated findings summary."""
    with get_db() as conn:
        # By type
        by_type = conn.execute(
            "SELECT finding_type, COUNT(*) as count FROM findings WHERE report_id = ? GROUP BY finding_type",
            (report_id,)
        ).fetchall()
        # By severity
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE report_id = ? GROUP BY severity",
            (report_id,)
        ).fetchall()
        # Total
        total = conn.execute(
            "SELECT COUNT(*) as count FROM findings WHERE report_id = ?",
            (report_id,)
        ).fetchone()

    return {
        "total": total["count"] if total else 0,
        "by_type": {r["finding_type"]: r["count"] for r in by_type},
        "by_severity": {r["severity"]: r["count"] for r in by_severity},
    }


# ============================================================
# SESSIONS
# ============================================================

def upsert_session(session_id: str, ip: str = "", user_agent: str = "",
                   user_label: str = ""):
    """Create or update session."""
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM sessions WHERE session_id = ?",
                                 (session_id,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE sessions SET last_active = ? WHERE session_id = ?",
                (datetime.now().isoformat(), session_id)
            )
        else:
            conn.execute(
                """INSERT INTO sessions (session_id, ip_address, user_agent,
                   user_label, created_at, last_active)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (session_id, ip, user_agent, user_label,
                 datetime.now().isoformat(), datetime.now().isoformat())
            )


def increment_session_scans(session_id: str):
    """Increment scan count for session."""
    with get_db() as conn:
        conn.execute(
            "UPDATE sessions SET scan_count = scan_count + 1, last_active = ? WHERE session_id = ?",
            (datetime.now().isoformat(), session_id)
        )


# ============================================================
# EXPORTS
# ============================================================

def record_export(report_id: str, fmt: str, file_path: str, file_size: int = 0):
    """Record an exported report file."""
    with get_db() as conn:
        conn.execute(
            """INSERT INTO exports (report_id, format, file_path, file_size, generated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (report_id, fmt, file_path, file_size, datetime.now().isoformat())
        )


def get_exports(report_id: str) -> list:
    """Get exports for a scan."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM exports WHERE report_id = ? ORDER BY generated_at DESC",
            (report_id,)
        ).fetchall()
        return [dict(r) for r in rows]


# ============================================================
# STATS
# ============================================================

def get_global_stats() -> dict:
    """Global stats across all scans."""
    with get_db() as conn:
        total_scans = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
        completed = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='completed'").fetchone()["c"]
        running = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='running'").fetchone()["c"]
        total_findings = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
        total_sessions = conn.execute("SELECT COUNT(*) as c FROM sessions").fetchone()["c"]

        # Severity distribution
        sev = conn.execute(
            "SELECT severity, COUNT(*) as c FROM scans WHERE status='completed' GROUP BY severity"
        ).fetchall()

        return {
            "total_scans": total_scans,
            "completed_scans": completed,
            "running_scans": running,
            "total_findings": total_findings,
            "total_sessions": total_sessions,
            "severity_distribution": {r["severity"]: r["c"] for r in sev},
        }


# Initialize DB on import
init_db()
