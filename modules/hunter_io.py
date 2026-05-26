"""
Hunter.io Module — Email discovery and verification.
Uses Hunter.io public search + pattern inference.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/3.0)"


async def _hunter_public_search(client: httpx.AsyncClient, domain: str) -> dict:
    """Search Hunter.io public pages for domain email patterns."""
    try:
        resp = await client.get(
            f"https://hunter.io/search/{quote_plus(domain)}",
            headers={"User-Agent": USER_AGENT}, timeout=12.0, follow_redirects=True
        )
        html = resp.text[:30000]
        text = html.lower()

        # Extract pattern info
        pattern_match = re.findall(r'pattern[:\s]+([a-z.{}_\-+]+@' + re.escape(domain) + r')', text)
        emails_found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), html)
        count_match = re.findall(r'(\d[\d,]*)\s+email[s]?\s+(?:address|found)', text)

        return {
            "domain": domain,
            "url": f"https://hunter.io/search/{domain}",
            "pattern": pattern_match[0] if pattern_match else None,
            "emails_sample": list(set(emails_found))[:10],
            "count_estimate": int(count_match[0].replace(',', '')) if count_match else None,
            "source": "hunter_web",
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)[:100], "source": "hunter_web"}


async def _common_patterns(client: httpx.AsyncClient, domain: str, first: str, last: str) -> list:
    """Infer common email patterns by checking permutations."""
    patterns = [
        f"{first}.{last}@{domain}",
        f"{first}{last}@{domain}",
        f"{first}_{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first[0]}.{last}@{domain}",
        f"{first}@{domain}",
        f"{last}@{domain}",
    ]

    results = []
    for email in patterns:
        basic_check = {
            "email": email,
            "format": email.split('@')[0],
            "valid_format": bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)),
        }
        results.append(basic_check)

    return results


async def hunter_search(name: str = "", domain: str = "") -> dict:
    """Hunter.io email intelligence."""
    parts = name.strip().split() if name else []
    first = parts[0] if len(parts) >= 1 else ""
    last = parts[-1] if len(parts) >= 2 else ""

    results = {
        "query_name": name,
        "query_domain": domain,
        "timestamp": datetime.now().isoformat(),
        "hunter_web": {},
        "pattern_inference": [],
        "summary": {},
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        if domain:
            results["hunter_web"] = await _hunter_public_search(client, domain)

        if first and last and domain:
            results["pattern_inference"] = await _common_patterns(client, domain, first, last)

    hw = results["hunter_web"]
    results["summary"] = {
        "pattern_found": hw.get("pattern"),
        "emails_public": len(hw.get("emails_sample", [])),
        "count_estimate": hw.get("count_estimate"),
        "inferred_patterns": len(results["pattern_inference"]),
    }

    return results
