"""
EMAIL FINDER v4 — Forensic-grade email discovery.
Generates patterns, validates format, checks MX, extracts from public sources.
Confidence-scored. No SMTP probing. No overclaim.
"""
import re
import asyncio
from datetime import datetime
from typing import Optional
import httpx
import dns.resolver

from config import HIBP_API_KEY, ENABLE_HIBP_EMAIL_CHECK, ENABLE_PUBLIC_EMAIL_DISCOVERY
from services.confidence_scoring import score_email, extract_emails_from_text

USER_AGENT = "OSINT-Tool/4.0"

# Common email patterns for name->email generation
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

# Major email providers
COMMON_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "icloud.com", "mail.com", "aol.com",
    "zoho.com", "yandex.com", "gmx.com", "fastmail.com",
    "live.com", "me.com", "mac.com", "msn.com",
    "ymail.com", "rocketmail.com", "inbox.com", "tutanota.com",
]

# Disposable email domains (exact match)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwaway.email", "yopmail.com", "sharklasers.com",
    "trashmail.com", "temp-mail.org", "fakeinbox.com", "maildrop.cc",
    "getnada.com", "tempinbox.com", "dispostable.com", "moakt.com",
    "mailnesia.com", "spamgourmet.com", "mytrashmail.com", "trashmail.de",
}

# Role-based local-part prefixes
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


def _validate_email_format(email: str) -> dict:
    """Validate email format only — NO SMTP probing."""
    match = re.match(r'^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', email)
    if not match:
        return {"format_valid": False, "reason": "Invalid format"}

    local, domain = match.groups()
    domain_lower = domain.lower()

    result = {
        "format_valid": True,
        "local_part": local,
        "domain": domain_lower,
        "is_disposable": domain_lower in DISPOSABLE_DOMAINS,
        "is_role_based": local.lower() in ROLE_PREFIXES,
        # FIX: compare full domain string, not just first part
        "is_free_provider": domain_lower in COMMON_DOMAINS,
        "length": len(email),
    }

    # RFC 5321 checks
    if len(local) > 64:
        result["format_valid"] = False
        result["reason"] = "Local part too long (>64 chars)"
    if len(email) > 254:
        result["format_valid"] = False
        result["reason"] = "Email too long (>254 chars)"
    if ".." in local:
        result["format_valid"] = False
        result["reason"] = "Consecutive dots in local part"
    if local.startswith('.') or local.endswith('.'):
        result["format_valid"] = False
        result["reason"] = "Leading/trailing dot"
    if re.search(r'[^a-zA-Z0-9._%+-]', local):
        result["format_valid"] = False
        result["reason"] = "Invalid characters in local part"

    return result


async def _check_hibp(client: httpx.AsyncClient, email: str) -> dict:
    """Check HIBP for email breaches — requires API key."""
    if not HIBP_API_KEY or not ENABLE_HIBP_EMAIL_CHECK:
        return {
            "breached": False, "total_breaches": 0, "breaches": [],
            "status": "disabled",
            "reason": "HIBP API key not configured — enable in .env"
        }

    headers = {
        "User-Agent": USER_AGENT,
        "hibp-api-key": HIBP_API_KEY,
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
            risk = _calc_risk(breach_list)
            return {
                "breached": True,
                "total_breaches": len(breach_list),
                "breaches": breach_list,
                "risk_level": risk["level"],
                "risk_score": risk["score"],
                "status": "enabled",
            }
        elif resp.status_code == 404:
            return {"breached": False, "total_breaches": 0, "breaches": [],
                    "risk_level": "NONE", "status": "enabled"}
        else:
            return {"breached": False, "total_breaches": 0, "breaches": [],
                    "error": f"HTTP {resp.status_code}", "status": "enabled"}
    except Exception as e:
        return {"breached": False, "total_breaches": 0, "breaches": [],
                "error": str(e)[:150], "status": "error"}


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

    if sensitive_count > 0: score += 30
    if has_passwords: score += 25
    if has_financial: score += 25
    if total_pwn > 1000000: score += 15
    if verified_count > 2: score += 10

    return {
        "score": min(100, score),
        "level": "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW",
    }


async def _extract_from_public_pages(client: httpx.AsyncClient, target_name: str,
                                     urls: list) -> list:
    """Extract emails from public pages found via name search."""
    if not ENABLE_PUBLIC_EMAIL_DISCOVERY:
        return []

    found = []
    name_lower = target_name.lower()
    name_parts = set(name_lower.split())

    for url_info in urls[:10]:
        url = url_info.get("url", "") if isinstance(url_info, dict) else str(url_info)
        if not url or not url.startswith("http"):
            continue
        try:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                                   timeout=8.0, follow_redirects=True)
            text = resp.text[:200000]  # first 200KB
            emails = extract_emails_from_text(text)

            for email in emails:
                domain = email.split("@")[-1] if "@" in email else ""
                # Check if name parts appear in page
                name_on_page = any(p in text.lower() for p in name_parts if len(p) > 2)

                conf = score_email(
                    source_type="public_page",
                    name_match=name_on_page,
                    source_url=url,
                )
                found.append({
                    "email": email,
                    "source_url": url,
                    "source_type": "public_page",
                    "confidence": conf["score"],
                    "confidence_label": conf["label"],
                    "confidence_icon": conf["icon"],
                    "reason": "Email extracted from public page" +
                              (" — name also found on page" if name_on_page else ""),
                    "status": "publicly_observed",
                })
        except Exception:
            continue

    # Deduplicate by email
    seen = set()
    unique = []
    for f in found:
        if f["email"] not in seen:
            seen.add(f["email"])
            unique.append(f)
    return unique


async def find_emails(full_name: str, custom_domains: Optional[list] = None,
                      public_urls: Optional[list] = None) -> dict:
    """
    Find possible emails from a person's name.
    Generates candidates, extracts from public pages, checks HIBP.
    Uses clear terminology: publicly_found vs candidate.
    """
    parts = full_name.strip().split()
    if len(parts) < 2:
        return {
            "query": full_name,
            "error": "Need first AND last name for email generation",
            "status": "error",
        }

    first = parts[0]
    last = parts[-1]
    domain_list = (custom_domains or []) + COMMON_DOMAINS[:10]

    all_emails = _generate_email_permutations(first, last, domain_list)
    ts = datetime.now().isoformat()

    results = {
        "query_name": full_name,
        "first_name": first,
        "last_name": last,
        "timestamp": ts,
        "total_generated": len(all_emails),
        # NEW: renamed from valid_emails
        "publicly_found_emails": [],
        "candidate_emails": [],
        "disposable_emails": [],
        "role_based_emails": [],
        "free_provider_emails": [],
        "breached_emails": [],
        "intel": {},
        "empty_state_reason": None,
    }

    # Validate all emails and classify
    for email in all_emails:
        validation = _validate_email_format(email)
        domain = email.split("@")[-1].lower() if "@" in email else ""

        if validation.get("format_valid"):
            pattern_conf = score_email(
                source_type="pattern_generated",
                domain_provided=(domain not in COMMON_DOMAINS),
            )
            results["candidate_emails"].append({
                "email": email,
                "domain": domain,
                "confidence": pattern_conf["score"],
                "confidence_label": pattern_conf["label"],
                "confidence_icon": pattern_conf["icon"],
                "reason": "Generated from name pattern — candidate only, not verified",
                "status": "candidate",
                "is_free_provider": validation.get("is_free_provider", False),
                "is_role_based": validation.get("is_role_based", False),
                "is_disposable": validation.get("is_disposable", False),
                "format_valid": True,
            })
        if validation.get("is_disposable"):
            results["disposable_emails"].append(email)
        if validation.get("is_role_based"):
            results["role_based_emails"].append(email)
        if validation.get("is_free_provider"):
            results["free_provider_emails"].append(email)

    # Check MX for custom domains
    unique_domains = set()
    for email in all_emails:
        domain = email.split('@')[-1].lower()
        if domain not in COMMON_DOMAINS:
            unique_domains.add(domain)

    mx_results = {d: _check_mx(d) for d in unique_domains}

    # Extract from public pages if URLs provided
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(12.0)) as client:
        if public_urls:
            public_emails = await _extract_from_public_pages(client, full_name, public_urls)
            results["publicly_found_emails"] = public_emails

        # Check HIBP for top candidates (only if API key)
        check_emails = [e["email"] for e in results["candidate_emails"][:15]]
        # Also check publicly found
        for pe in results["publicly_found_emails"]:
            if pe["email"] not in check_emails:
                check_emails.append(pe["email"])
        check_emails = check_emails[:20]

        for email in check_emails:
            breach_result = await _check_hibp(client, email)
            if breach_result.get("breached") or breach_result.get("error"):
                results["breached_emails"].append({
                    "email": email,
                    **breach_result
                })

    # Intelligence summary
    results["intel"] = {
        "most_likely_format": f"{first}.{last}@<domain>",
        "alternative_formats": [
            f"{first}{last}@<domain>",
            f"{first[0]}{last}@<domain>",
            f"{first}@{last}.com",
        ],
        "custom_domain_mx": mx_results,
        "total_breached": len(results["breached_emails"]),
        "total_publicly_found": len(results["publicly_found_emails"]),
        "total_candidates": len(results["candidate_emails"]),
        "hibp_status": "enabled" if (HIBP_API_KEY and ENABLE_HIBP_EMAIL_CHECK) else "disabled",
    }

    # Empty state explanation
    if not results["publicly_found_emails"] and not results["candidate_emails"]:
        results["empty_state_reason"] = (
            "No emails generated. Possible reasons:\n"
            "- Name is too short or incomplete\n"
            "- Domain list is empty\n"
            "- Internal generation error"
        )
    elif not results["publicly_found_emails"]:
        results["empty_state_reason"] = (
            "No public email found.\n"
            "Possible reasons:\n"
            "- Email is not publicly exposed on web pages\n"
            "- Name is too common for precise matching\n"
            "- No URLs provided for extraction\n"
            "- Source was blocked or rate-limited"
        )

    # Summary for UI
    results["summary"] = {
        "publicly_found": len(results["publicly_found_emails"]),
        "candidates": len(results["candidate_emails"]),
        "format_valid": len(results["candidate_emails"]),
        "breached": len(results["breached_emails"]),
        "disposable": len(results["disposable_emails"]),
        "role_based": len(results["role_based_emails"]),
        "highest_confidence": max(
            [e["confidence"] for e in results["publicly_found_emails"] + results["candidate_emails"]],
            default=0
        ),
    }

    return results


async def check_single_email(email: str) -> dict:
    """Deep-check a single email address."""
    validation = _validate_email_format(email)
    result = {
        "email": email,
        "validation": validation,
        "timestamp": datetime.now().isoformat(),
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(12.0)) as client:
        result["hibp"] = await _check_hibp(client, email)

    domain = email.split('@')[-1] if '@' in email else None
    if domain:
        result["mx_check"] = _check_mx(domain)

    return result
