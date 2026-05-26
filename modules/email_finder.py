"""
EMAIL FINDER v3 — Advanced email discovery, validation, and breach intelligence.
Pattern generation, HIBP integration, MX validation, disposable detection.
"""
import re
import hashlib
import asyncio
from datetime import datetime
from typing import Optional
import httpx
import dns.resolver

USER_AGENT = "OSINT-Tool/3.0"

# Common email patterns for name→email generation
EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}_{last}@{domain}",
    "{f}.{last}@{domain}",
    "{first}.{l}@{domain}",
    "{first}@{domain}",
    "{last}@{domain}",
    "{first}{l}@{domain}",
    "{f}{last}@{domain}",
    "{first}-{last}@{domain}",
    "{last}.{first}@{domain}",
    "{l}.{first}@{domain}",
]

# Major email providers with MX verified
COMMON_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "icloud.com", "mail.com", "aol.com",
    "zoho.com", "yandex.com", "gmx.com", "fastmail.com",
    "live.com", "me.com", "mac.com", "msn.com",
    "ymail.com", "rocketmail.com", "inbox.com", "tutanota.com",
]

# Business email domains (common corporate patterns)
BUSINESS_DOMAINS = [
    "company.com", "corp.com", "inc.com", "ltd.com",
]

# Disposable email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwaway.email", "yopmail.com", "sharklasers.com",
    "trashmail.com", "temp-mail.org", "fakeinbox.com", "maildrop.cc",
    "getnada.com", "tempinbox.com", "dispostable.com", "moakt.com",
    "mailnesia.com", "spamgourmet.com", "mytrashmail.com", "trashmail.de",
}

# Role-based prefixes
ROLE_PREFIXES = {
    "admin", "info", "support", "sales", "contact", "hello",
    "noreply", "no-reply", "help", "billing", "abuse", "postmaster",
    "webmaster", "hostmaster", "team", "marketing", "office", "careers",
    "jobs", "hr", "press", "media", "legal", "privacy", "security",
}

# HIBP API
HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"


def _generate_email_permutations(first: str, last: str, domains: Optional[list] = None) -> list:
    """Generate email permutations from name + domain list."""
    if domains is None:
        domains = COMMON_DOMAINS

    f = first.lower().replace(" ", "").replace("-", "").replace("'", "").replace(".", "")
    l = last.lower().replace(" ", "").replace("-", "").replace("'", "").replace(".", "")

    if not f or not l:
        return []

    emails = []
    for domain in domains:
        for pattern in EMAIL_PATTERNS:
            email = pattern.format(f=f, l=l, first=f, last=l, domain=domain)
            emails.append(email)

    return list(set(emails))


def _check_mx(domain: str) -> dict:
    """Check MX records for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        records = []
        for rdata in answers:
            records.append({
                "priority": rdata.preference,
                "server": str(rdata.exchange).rstrip('.')
            })
        return {
            "has_mx": True,
            "records": sorted(records, key=lambda x: x['priority']),
            "primary_server": records[0]['server'] if records else None,
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return {"has_mx": False, "records": [], "primary_server": None}
    except Exception as e:
        return {"has_mx": False, "records": [], "error": str(e)[:100]}


def _validate_email(email: str) -> dict:
    """Validate email format and characteristics."""
    match = re.match(r'^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', email)
    if not match:
        return {"valid": False, "reason": "Invalid format"}

    local, domain = match.groups()

    result = {
        "valid": True,
        "local_part": local,
        "domain": domain,
        "is_disposable": domain.lower() in DISPOSABLE_DOMAINS,
        "is_role_based": local.lower() in ROLE_PREFIXES,
        "is_free_provider": domain.lower() in [d.split('.')[0] for d in COMMON_DOMAINS],
        "length": len(email),
    }

    # Check for suspicious patterns
    if len(local) > 64:
        result["valid"] = False
        result["reason"] = "Local part too long (>64 chars)"
    if len(email) > 254:
        result["valid"] = False
        result["reason"] = "Email too long (>254 chars)"
    if ".." in local:
        result["valid"] = False
        result["reason"] = "Consecutive dots in local part"
    if local.startswith('.') or local.endswith('.'):
        result["valid"] = False
        result["reason"] = "Leading/trailing dot"
    if re.search(r'[^a-zA-Z0-9._%+-]', local):
        result["valid"] = False
        result["reason"] = "Invalid characters in local part"

    return result


async def _check_hibp(client: httpx.AsyncClient, email: str) -> dict:
    """Check HIBP for email breaches."""
    headers = {
        "User-Agent": USER_AGENT,
        "hibp-api-key": "",
    }
    try:
        resp = await client.get(
            HIBP_API.format(email),
            headers=headers,
            timeout=12.0
        )
        if resp.status_code == 200:
            breaches = resp.json()
            breach_list = []
            for b in breaches[:30]:
                breach_list.append({
                    "name": b.get("Name", ""),
                    "title": b.get("Title", ""),
                    "domain": b.get("Domain", ""),
                    "date": b.get("BreachDate", ""),
                    "data_classes": b.get("DataClasses", []),
                    "description": (b.get("Description", "") or "")[:400],
                    "pwn_count": b.get("PwnCount", 0),
                    "is_verified": b.get("IsVerified", False),
                    "is_sensitive": b.get("IsSensitive", False),
                })

            # Calculate risk
            risk = _calc_risk(breach_list)

            return {
                "breached": True,
                "total_breaches": len(breach_list),
                "breaches": breach_list,
                "risk_level": risk["level"],
                "risk_score": risk["score"],
            }
        elif resp.status_code == 404:
            return {"breached": False, "total_breaches": 0, "breaches": [], "risk_level": "CLEAN"}
        else:
            return {"breached": False, "total_breaches": 0, "breaches": [], "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"breached": False, "total_breaches": 0, "breaches": [], "error": str(e)[:150]}


def _calc_risk(breaches: list) -> dict:
    """Calculate risk from breach data."""
    score = 0
    sensitive_count = sum(1 for b in breaches if b.get("is_sensitive"))
    verified_count = sum(1 for b in breaches if b.get("is_verified"))
    has_passwords = any("Passwords" in b.get("data_classes", []) for b in breaches)
    has_financial = any(
        c in str(b.get("data_classes", []))
        for b in breaches
        for c in ["Credit", "Bank", "Financial"]
    )
    total_pwn = sum(b.get("pwn_count", 0) for b in breaches)

    if sensitive_count > 0:
        score += 30
    if has_passwords:
        score += 25
    if has_financial:
        score += 25
    if total_pwn > 1000000:
        score += 15
    if verified_count > 2:
        score += 10

    return {
        "score": min(100, score),
        "level": "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW",
    }


async def find_emails(full_name: str, custom_domains: Optional[list] = None) -> dict:
    """
    Find possible emails from a person's name.
    Generates permutations, validates, checks HIBP for top candidates.
    """
    parts = full_name.strip().split()
    if len(parts) < 2:
        return {
            "query": full_name,
            "error": "Need first AND last name for email generation",
        }

    first = parts[0]
    last = parts[-1]

    domains = (custom_domains or []) + COMMON_DOMAINS[:10]

    all_emails = _generate_email_permutations(first, last, domains)

    results = {
        "query_name": full_name,
        "first_name": first,
        "last_name": last,
        "timestamp": datetime.now().isoformat(),
        "total_generated": len(all_emails),
        "valid_emails": [],
        "disposable_emails": [],
        "role_based_emails": [],
        "free_provider_emails": [],
        "breached_emails": [],
        "intel": {},
    }

    # Validate all emails
    for email in all_emails:
        validation = _validate_email(email)
        if validation.get("valid"):
            results["valid_emails"].append(email)
        if validation.get("is_disposable"):
            results["disposable_emails"].append(email)
        if validation.get("is_role_based"):
            results["role_based_emails"].append(email)
        if validation.get("is_free_provider"):
            results["free_provider_emails"].append(email)

    # Check domains for MX records
    unique_domains = set()
    for email in all_emails:
        domain = email.split('@')[-1]
        if domain not in unique_domains and domain not in [d for d in COMMON_DOMAINS]:
            unique_domains.add(domain)

    mx_results = {d: _check_mx(d) for d in unique_domains}

    # Check HIBP for top 15 permutations
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(12.0)) as client:
        check_emails = results["valid_emails"][:15]
        for email in check_emails:
            breach_result = await _check_hibp(client, email)
            if breach_result.get("breached"):
                results["breached_emails"].append({
                    "email": email,
                    **breach_result
                })

    # Intelligence
    results["intel"] = {
        "most_likely_format": f"{first}.{last}@<domain>",
        "alternative_formats": [
            f"{first}{last}@<domain>",
            f"{first[0]}{last}@<domain>",
            f"{first}@{last}.com",
        ],
        "custom_domain_mx": mx_results,
        "recommendation": "Use HIBP API key for comprehensive breach checking",
        "total_breached": len(results["breached_emails"]),
    }

    return results


async def check_single_email(email: str) -> dict:
    """Deep-check a single email address."""
    result = {
        "email": email,
        "validation": _validate_email(email),
        "timestamp": datetime.now().isoformat(),
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(12.0)) as client:
        result["hibp"] = await _check_hibp(client, email)

    domain = email.split('@')[-1] if '@' in email else None
    if domain:
        result["mx_check"] = _check_mx(domain)

    return result
