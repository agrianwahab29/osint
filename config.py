"""
OSINTTool v6.0 — Central Configuration
Loads from .env with sensible defaults for free-first mode.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
ENV_PATH = Path(__file__).parent / ".env"
load_dotenv(ENV_PATH)

# ============================================================
# APP
# ============================================================
APP_VERSION = os.getenv("APP_VERSION", "6.0.0")
APP_ENV = os.getenv("APP_ENV", "production")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", os.urandom(24).hex())
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
PORT = int(os.getenv("PORT", "5000"))

# ============================================================
# FEATURE FLAGS
# ============================================================
ENABLE_FREE_MODE = os.getenv("ENABLE_FREE_MODE", "true").lower() == "true"

ENABLE_HIBP_EMAIL_CHECK = os.getenv("ENABLE_HIBP_EMAIL_CHECK", "false").lower() == "true"
ENABLE_HIBP_PASSWORD_CHECK = os.getenv("ENABLE_HIBP_PASSWORD_CHECK", "true").lower() == "true"
ENABLE_BREACH_CATALOG = os.getenv("ENABLE_BREACH_CATALOG", "true").lower() == "true"
ENABLE_HUNTER = os.getenv("ENABLE_HUNTER", "false").lower() == "true"
ENABLE_SHODAN = os.getenv("ENABLE_SHODAN", "false").lower() == "true"
ENABLE_VIRUSTOTAL = os.getenv("ENABLE_VIRUSTOTAL", "false").lower() == "true"
ENABLE_INTELX = os.getenv("ENABLE_INTELX", "false").lower() == "true"
ENABLE_GITHUB_INTEL = os.getenv("ENABLE_GITHUB_INTEL", "true").lower() == "true"
ENABLE_PUBLIC_EMAIL_DISCOVERY = os.getenv("ENABLE_PUBLIC_EMAIL_DISCOVERY", "true").lower() == "true"
ENABLE_DOMAIN_FORENSIC = os.getenv("ENABLE_DOMAIN_FORENSIC", "true").lower() == "true"
ENABLE_TELEGRAM_OSINT = os.getenv("ENABLE_TELEGRAM_OSINT", "true").lower() == "true"
ENABLE_DARKWEB_INTEL = os.getenv("ENABLE_DARKWEB_INTEL", "false").lower() == "true"
ENABLE_PEOPLE_SEARCH = os.getenv("ENABLE_PEOPLE_SEARCH", "false").lower() == "true"
ENABLE_GOOGLE_DORKS = os.getenv("ENABLE_GOOGLE_DORKS", "true").lower() == "true"
ENABLE_PASSWORD_EXPOSURE = os.getenv("ENABLE_PASSWORD_EXPOSURE", "true").lower() == "true"

# ============================================================
# API KEYS (empty = disabled gracefully)
# ============================================================
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "") or os.getenv("INTELX_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ============================================================
# DATABASE
# ============================================================
DATABASE_PATH = os.getenv("DATABASE_PATH", str(Path(__file__).parent / "osint.db"))

# ============================================================
# MODULE COUNT (actual, dynamic)
# ============================================================
def get_active_module_count() -> int:
    """Count modules that are currently enabled via feature flags."""
    count = 6  # always-on: name_search, social_media, email_finder, breach_checker, phone_finder, domain_checker
    if ENABLE_GITHUB_INTEL: count += 1
    if ENABLE_PUBLIC_EMAIL_DISCOVERY: count += 1
    if ENABLE_DOMAIN_FORENSIC: count += 1
    if ENABLE_PEOPLE_SEARCH: count += 1
    if ENABLE_DARKWEB_INTEL: count += 1
    if ENABLE_GOOGLE_DORKS: count += 1
    if ENABLE_HUNTER: count += 1
    if ENABLE_SHODAN: count += 1
    if ENABLE_VIRUSTOTAL: count += 1
    if ENABLE_INTELX: count += 1
    if ENABLE_TELEGRAM_OSINT: count += 1
    return count


def get_api_status() -> dict:
    """Return status of all API-dependent services."""
    return {
        "hibp_email": {
            "enabled": ENABLE_HIBP_EMAIL_CHECK and bool(HIBP_API_KEY),
            "label": "HIBP Email Breach Check",
            "has_key": bool(HIBP_API_KEY),
            "reason": None if (ENABLE_HIBP_EMAIL_CHECK and HIBP_API_KEY) else "API key not configured — use free alternatives"
        },
        "pwned_passwords": {
            "enabled": ENABLE_HIBP_PASSWORD_CHECK,
            "label": "Pwned Passwords (k-anonymity)",
            "has_key": True,
            "reason": None if ENABLE_HIBP_PASSWORD_CHECK else "Disabled by feature flag"
        },
        "breach_catalogue": {
            "enabled": ENABLE_BREACH_CATALOG,
            "label": "Breach Catalogue",
            "has_key": True,
            "reason": None if ENABLE_BREACH_CATALOG else "Disabled by feature flag"
        },
        "hunter_io": {
            "enabled": ENABLE_HUNTER and bool(HUNTER_API_KEY),
            "label": "Hunter.io Email Finder",
            "has_key": bool(HUNTER_API_KEY),
            "reason": None if (ENABLE_HUNTER and HUNTER_API_KEY) else "API key not configured"
        },
        "shodan": {
            "enabled": ENABLE_SHODAN and bool(SHODAN_API_KEY),
            "label": "Shodan Internet Scanner",
            "has_key": bool(SHODAN_API_KEY),
            "reason": None if (ENABLE_SHODAN and SHODAN_API_KEY) else "API key not configured"
        },
        "virustotal": {
            "enabled": ENABLE_VIRUSTOTAL and bool(VIRUSTOTAL_API_KEY),
            "label": "VirusTotal Domain Intel",
            "has_key": bool(VIRUSTOTAL_API_KEY),
            "reason": None if (ENABLE_VIRUSTOTAL and VIRUSTOTAL_API_KEY) else "API key not configured"
        },
        "intelx": {
            "enabled": ENABLE_INTELX and bool(INTELX_API_KEY),
            "label": "IntelX Dark Web Search",
            "has_key": bool(INTELX_API_KEY),
            "reason": None if (ENABLE_INTELX and INTELX_API_KEY) else "API key not configured"
        },
        "github_public_api": {
            "enabled": ENABLE_GITHUB_INTEL,
            "label": "GitHub Public API",
            "has_key": True,
            "reason": None if ENABLE_GITHUB_INTEL else "Disabled by feature flag"
        },
        "public_web_search": {
            "enabled": True,
            "label": "Public Web Search (DuckDuckGo/Bing)",
            "has_key": True,
            "reason": None
        },
        "domain_forensic": {
            "enabled": ENABLE_DOMAIN_FORENSIC,
            "label": "Domain Forensic (DNS/SPF/DMARC/TLS)",
            "has_key": True,
            "reason": None if ENABLE_DOMAIN_FORENSIC else "Disabled by feature flag"
        }
    }


# ============================================================
# CONFIDENCE LABELS
# ============================================================
CONFIDENCE_LABELS = {
    (90, 100): ("Very High", "🟢"),
    (75, 89): ("High", "🟢"),
    (50, 74): ("Medium", "🔵"),
    (25, 49): ("Low", "🟡"),
    (0, 24): ("Very Low", "🔴"),
}

RISK_LABELS = {
    "NONE": ("None", "🟢", "green"),
    "LOW": ("Low", "🔵", "blue"),
    "MEDIUM": ("Medium", "🟡", "yellow"),
    "HIGH": ("High", "🟠", "orange"),
    "CRITICAL": ("Critical", "🔴", "red"),
}

FINDING_STATUS_LABELS = {
    "publicly_found": "Publicly Found",
    "publicly_observed": "Publicly Observed",
    "candidate": "Candidate Only",
    "format_valid": "Format Valid",
    "unverified": "Unverified",
    "source_matched": "Source Matched",
    "disabled": "Disabled",
    "verified": "Verified",
}
