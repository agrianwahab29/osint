"""
Breach Checker Module - Data breach intelligence
Checks emails/domains against known breach databases (HIBP API, breach directory).
"""
import re
import hashlib
import asyncio
from datetime import datetime
from typing import Optional
import httpx

USER_AGENT = "OSINT-Tool/1.0"

# HIBP API endpoints
HIBP_BREACHED_ACCOUNT = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PASTE_ACCOUNT = "https://haveibeenpwned.com/api/v3/pasteaccount/{}"
HIBP_ALL_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"

# Dehashed API (requires key, but we can check format)
DEHASHED_API = "https://api.dehashed.com/search?query=email:{}"

# Breach directory - known major breaches
KNOWN_MAJOR_BREACHES = {
    "Collection #1": {"year": 2019, "records": 773000000, "type": "credential_stuffing"},
    "Adobe": {"year": 2013, "records": 153000000, "type": "hack"},
    "AdultFriendFinder": {"year": 2016, "records": 412000000, "type": "hack"},
    "Canva": {"year": 2019, "records": 137000000, "type": "hack"},
    "Dubsmash": {"year": 2018, "records": 162000000, "type": "hack"},
    "Facebook": {"year": 2019, "records": 533000000, "type": "scraping"},
    "LinkedIn": {"year": 2012, "records": 165000000, "type": "hack"},
    "Marriott": {"year": 2018, "records": 500000000, "type": "hack"},
    "MySpace": {"year": 2013, "records": 360000000, "type": "hack"},
    "Twitter": {"year": 2023, "records": 220000000, "type": "scraping"},
    "Yahoo": {"year": 2013, "records": 3000000000, "type": "hack"},
    "Zynga": {"year": 2019, "records": 218000000, "type": "hack"},
    "Dropbox": {"year": 2012, "records": 68000000, "type": "hack"},
    "Equifax": {"year": 2017, "records": 147000000, "type": "hack"},
    "Experian": {"year": 2015, "records": 15000000, "type": "hack"},
    "Target": {"year": 2013, "records": 110000000, "type": "hack"},
    "eBay": {"year": 2014, "records": 145000000, "type": "hack"},
    "Sony PSN": {"year": 2011, "records": 77000000, "type": "hack"},
    "Capital One": {"year": 2019, "records": 106000000, "type": "hack"},
    "T-Mobile": {"year": 2021, "records": 54000000, "type": "hack"},
}

# Data classes commonly exposed in breaches
DATA_CLASS_DESCRIPTIONS = {
    "Email addresses": "Email address was exposed",
    "Passwords": "Password (hashed or plaintext) was exposed",
    "Names": "Full name was exposed",
    "Phone numbers": "Phone number was exposed",
    "Physical addresses": "Physical/home address was exposed",
    "IP addresses": "IP address was exposed",
    "Dates of birth": "Date of birth was exposed",
    "Genders": "Gender information was exposed",
    "Geographic locations": "Location data was exposed",
    "Social media profiles": "Social media profile data was exposed",
    "Usernames": "Username was exposed",
    "Passport numbers": "Passport/ID number was exposed",
    "Credit cards": "Credit card information was exposed",
    "Bank account numbers": "Bank account number was exposed",
    "Device information": "Device information was exposed",
    "Browser user agent details": "Browser fingerprint was exposed",
    "Employers": "Employment information was exposed",
    "Education levels": "Education history was exposed",
    "Income levels": "Income information was exposed",
    "Health insurance information": "Health insurance data was exposed",
    "Medical records": "Medical records were exposed",
    "Biometric data": "Biometric/fingerprint data was exposed",
    "Security questions and answers": "Security Q&A was exposed",
    "Private messages": "Private messages were exposed",
    "Photos": "Private photos were exposed",
}


def _hash_email(email: str) -> str:
    """SHA-1 hash email for k-anonymity API calls."""
    return hashlib.sha1(email.strip().lower().encode()).hexdigest().upper()


async def _check_hibp_account(client: httpx.AsyncClient, email: str) -> dict:
    """Check HIBP for email breaches."""
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = await client.get(
            HIBP_BREACHED_ACCOUNT.format(email),
            headers=headers,
            timeout=15.0
        )
        if resp.status_code == 200:
            breaches = resp.json()
            detailed = []
            for b in breaches[:25]:
                data_classes = b.get("DataClasses", [])
                detailed.append({
                    "name": b.get("Name", "Unknown"),
                    "title": b.get("Title", ""),
                    "domain": b.get("Domain", ""),
                    "breach_date": b.get("BreachDate", ""),
                    "added_date": b.get("AddedDate", ""),
                    "data_classes": data_classes,
                    "data_descriptions": [
                        DATA_CLASS_DESCRIPTIONS.get(d, d) for d in data_classes
                    ],
                    "pwn_count": b.get("PwnCount", 0),
                    "description": (b.get("Description", "") or "")[:400],
                    "is_verified": b.get("IsVerified", False),
                    "is_sensitive": b.get("IsSensitive", False),
                    "is_retired": b.get("IsRetired", False),
                    "is_fabricated": b.get("IsFabricated", False),
                    "logo": b.get("LogoPath", ""),
                })
            return {
                "breached": True,
                "total_breaches": len(detailed),
                "breaches": detailed,
                "risk_level": _calculate_risk(detailed)
            }
        elif resp.status_code == 404:
            return {"breached": False, "total_breaches": 0, "breaches": [], "risk_level": "NONE"}
        else:
            return {"breached": False, "total_breaches": 0, "breaches": [], "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"breached": False, "total_breaches": 0, "breaches": [], "error": str(e)[:200]}


async def _check_hibp_pastes(client: httpx.AsyncClient, email: str) -> dict:
    """Check HIBP for email pastes (Pastebin etc)."""
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = await client.get(
            HIBP_PASTE_ACCOUNT.format(email),
            headers=headers,
            timeout=15.0
        )
        if resp.status_code == 200:
            pastes = resp.json()
            paste_list = []
            for p in pastes[:20]:
                paste_list.append({
                    "source": p.get("Source", "Unknown"),
                    "id": p.get("Id", ""),
                    "title": p.get("Title", ""),
                    "date": p.get("Date", ""),
                    "email_count": p.get("EmailCount", 0),
                })
            return {"found_in_pastes": True, "paste_count": len(paste_list), "pastes": paste_list}
        elif resp.status_code == 404:
            return {"found_in_pastes": False, "paste_count": 0, "pastes": []}
        else:
            return {"found_in_pastes": False, "paste_count": 0, "pastes": []}
    except Exception:
        return {"found_in_pastes": False, "paste_count": 0, "pastes": []}


def _calculate_risk(breaches: list) -> str:
    """Calculate risk level from breach data."""
    if not breaches:
        return "NONE"

    sensitive_count = sum(1 for b in breaches if b.get("is_sensitive"))
    total_pwn = sum(b.get("pwn_count", 0) for b in breaches)
    has_passwords = any("Passwords" in b.get("data_classes", []) for b in breaches)
    has_financial = any(
        any(c in b.get("data_classes", []) for c in ["Credit cards", "Bank account numbers"])
        for b in breaches
    )

    score = 0
    if sensitive_count > 0:
        score += 30
    if total_pwn > 1000000:
        score += 20
    if has_passwords:
        score += 25
    if has_financial:
        score += 25

    if score >= 70: return "CRITICAL"
    if score >= 40: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"


async def check_breaches(email: Optional[str] = None, domain: Optional[str] = None) -> dict:
    """
    Check data breach status for email or domain.
    Uses HIBP API and known breach directory.
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "query_type": "email" if email else "domain",
        "query": email or domain,
        "hibp_breaches": {},
        "hibp_pastes": {},
        "known_major_breaches": [],
        "summary": {},
    }

    async with httpx.AsyncClient() as client:
        if email:
            # HIBP check
            results["hibp_breaches"] = await _check_hibp_account(client, email)
            results["hibp_pastes"] = await _check_hibp_pastes(client, email)

    # Cross-reference with known major breaches
    if domain:
        domain_lower = domain.lower()
        for breach_name, info in KNOWN_MAJOR_BREACHES.items():
            if domain_lower in breach_name.lower():
                results["known_major_breaches"].append({
                    "breach": breach_name,
                    **info
                })

    # Generate summary
    hibp = results["hibp_breaches"]
    pastes = results["hibp_pastes"]
    results["summary"] = {
        "total_unique_breaches": hibp.get("total_breaches", 0),
        "total_pastes": pastes.get("paste_count", 0),
        "risk_level": hibp.get("risk_level", "NONE"),
        "data_classes_exposed": _aggregate_data_classes(hibp.get("breaches", [])),
        "recommendations": _generate_recommendations(hibp, pastes),
    }

    return results


def _aggregate_data_classes(breaches: list) -> list:
    """Aggregate all unique data classes across breaches."""
    classes = set()
    for b in breaches:
        for dc in b.get("data_classes", []):
            classes.add(dc)
    return sorted(classes)


def _generate_recommendations(hibp: dict, pastes: dict) -> list:
    """Generate security recommendations based on breach data."""
    recs = []

    if hibp.get("breached"):
        recs.append("Segera ganti password untuk akun yang terlibat breach")
        recs.append("Aktifkan 2FA/MFA di semua akun yang memungkinkan")
        recs.append("Gunakan password manager untuk password unik per akun")

    breaches = hibp.get("breaches", [])
    has_passwords = any("Passwords" in b.get("data_classes", []) for b in breaches)
    if has_passwords:
        recs.append("WARNING: Password Anda ditemukan di breach - SEGERA ganti SEMUA password")

    has_financial = any(
        any(c in b.get("data_classes", []) for c in ["Credit cards", "Bank account numbers"])
        for b in breaches
    )
    if has_financial:
        recs.append("CRITICAL: Data finansial terekspos - hubungi bank dan pantau transaksi")

    if pastes.get("found_in_pastes"):
        recs.append("Email Anda muncul di paste sites - data mungkin tersebar di dark web")

    if hibp.get("total_breaches", 0) > 3:
        recs.append("Akun Anda mengalami banyak breach - pertimbangkan membuat email baru")

    return recs
