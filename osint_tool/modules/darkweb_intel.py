"""
DARK WEB INTEL MODULE v1 — Intelligence from public dark web mirrors and breach aggregators.
Searches public breach databases, paste sites, and dark web search engines.
No actual dark web access needed — uses public APIs and mirrors.
"""
import re
import hashlib
import asyncio
from datetime import datetime
from typing import Optional
from urllib.parse import quote_plus
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/3.0; Security Research)"

# Public breach/paste search APIs
DARKWEB_SOURCES = {
    "leakcheck": {
        "url": "https://leakcheck.io/api/public?check={query}",
        "type": "breach_db",
        "note": "Public breach database"
    },
    "psbdmp": {
        "url": "https://psbdmp.ws/api/v3/search/{query}",
        "type": "paste_search",
        "note": "Pastebin dump search"
    },
    "scylla": {
        "url": "https://scylla.sh/search?q={query}",
        "type": "breach_db",
        "note": "Public breach aggregator"
    },
    "snusbase": {
        "url": "https://api.snusbase.com/data/search?terms={query}",
        "type": "breach_search",
        "note": "Breach data search (public endpoint)"
    },
    "dehashed_public": {
        "url": "https://www.dehashed.com/search?query={query}",
        "type": "breach_db",
        "note": "Dehashed public search"
    },
}

# Known dark web paste sites (accessible via clearnet mirrors)
PASTE_SITES = [
    "https://pastebin.com/search?q={query}",
    "https://rentry.co/search?q={query}",
    "https://justpaste.it/search?q={query}",
    "https://privatebin.net/?search={query}",
]

# Public breach database directory
KNOWN_BREACHES = {
    "Collection #1-5": {"records": "2.7B+", "year": "2019", "type": "Credential Stuffing List"},
    "Yahoo (2013-2016)": {"records": "3B", "year": "2016", "type": "Data Breach"},
    "LinkedIn (2021)": {"records": "700M", "year": "2021", "type": "Data Scraping"},
    "Facebook (2019)": {"records": "533M", "year": "2019", "type": "Data Scraping"},
    "Twitter (2023)": {"records": "220M", "year": "2023", "type": "Data Scraping"},
    "Dubsmash (2018)": {"records": "162M", "year": "2019", "type": "Data Breach"},
    "Adobe (2013)": {"records": "153M", "year": "2013", "type": "Data Breach"},
    "MyFitnessPal (2018)": {"records": "151M", "year": "2018", "type": "Data Breach"},
    "Canva (2019)": {"records": "137M", "year": "2019", "type": "Data Breach"},
    "Marriott (2018)": {"records": "500M", "year": "2018", "type": "Data Breach"},
    "Equifax (2017)": {"records": "147M", "year": "2017", "type": "Data Breach"},
    "Capital One (2019)": {"records": "106M", "year": "2019", "type": "Data Breach"},
    "Dropbox (2012)": {"records": "68M", "year": "2012", "type": "Data Breach"},
    "eBay (2014)": {"records": "145M", "year": "2014", "type": "Data Breach"},
    "Zynga (2019)": {"records": "218M", "year": "2019", "type": "Data Breach"},
    "T-Mobile (2021)": {"records": "54M", "year": "2021", "type": "Data Breach"},
    "Experian (2015)": {"records": "15M", "year": "2015", "type": "Data Breach"},
    "MySpace (2013)": {"records": "360M", "year": "2013", "type": "Data Breach"},
    "Sony PSN (2011)": {"records": "77M", "year": "2011", "type": "Data Breach"},
    "AdultFriendFinder (2016)": {"records": "412M", "year": "2016", "type": "Data Breach"},
}

# Dark web forums/markets (for reference — clearnet accessible mirrors)
DARKWEB_MARKETS = [
    {"name": "Dread Forum (Dark Net Reddit)", "url": "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jcpox3s4k4zobm3uad.onion", "type": "forum"},
    {"name": "Torch Search Engine", "url": "xmh57jrknzkhv6y3ls3ubitfg2isg3o7d2hhqm7qg3gj4q3md3c3noyd.onion", "type": "search"},
    {"name": "Ahmia Dark Web Search", "url": "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion", "type": "search"},
    {"name": "The Hidden Wiki", "url": "zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgqbuj2x4id.onion", "type": "directory"},
]

# Common password hashing patterns for identification
HASH_PATTERNS = {
    "MD5": r'^[a-f0-9]{32}$',
    "SHA1": r'^[a-f0-9]{40}$',
    "SHA256": r'^[a-f0-9]{64}$',
    "BCrypt": r'^\$2[aby]\$\d+\$[./A-Za-z0-9]{53}$',
    "NTLM": r'^[a-f0-9]{32}$',  # same as MD5 length but NTLM context
}


async def _search_source(client: httpx.AsyncClient, source_name: str, source_info: dict, query: str) -> dict:
    """Search a single dark web source."""
    url = source_info["url"].format(query=quote_plus(query))
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/html"}

    try:
        resp = await client.get(url, headers=headers, timeout=15.0, follow_redirects=True)

        result = {
            "source": source_name,
            "url": url,
            "type": source_info["type"],
            "note": source_info["note"],
            "status_code": resp.status_code,
            "has_data": False,
            "matches": 0,
        }

        if resp.status_code == 200:
            text = resp.text[:50000]
            text_lower = text.lower()

            # Count potential matches (mentions of the query)
            query_lower = query.lower()
            matches = text_lower.count(query_lower)
            result["matches"] = matches
            result["has_data"] = matches > 0 or (
                "found" in text_lower and "result" in text_lower
            )

            # Extract any email addresses found
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = list(set(re.findall(email_pattern, text)))
            result["emails_found"] = emails[:10]

        return result

    except Exception as e:
        return {
            "source": source_name,
            "url": url,
            "type": source_info["type"],
            "note": source_info["note"],
            "error": str(e)[:100],
            "has_data": False,
        }


async def _search_paste_site(client: httpx.AsyncClient, paste_url_template: str, query: str) -> dict:
    """Search a paste site."""
    url = paste_url_template.format(query=quote_plus(query))
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=12.0, follow_redirects=True)
        text = resp.text[:30000]
        text_lower = text.lower()
        query_lower = query.lower()

        return {
            "url": url,
            "status": resp.status_code,
            "match_count": text_lower.count(query_lower),
            "has_results": text_lower.count(query_lower) > 0,
        }
    except Exception as e:
        return {"url": url, "status": 0, "error": str(e)[:80], "has_results": False}


async def darkweb_intel(query: str, query_type: str = "auto") -> dict:
    """
    Dark web intelligence gathering.
    Searches public breach databases, paste sites, and dark web aggregators.
    query_type: "auto", "email", "username", "domain", or "name"
    """
    if query_type == "auto":
        if "@" in query:
            query_type = "email"
        elif "." in query and " " not in query:
            query_type = "domain"
        elif " " in query:
            query_type = "name"
        else:
            query_type = "username"

    results = {
        "query": query,
        "query_type": query_type,
        "timestamp": datetime.now().isoformat(),
        "sources_checked": [],
        "paste_results": [],
        "total_matches": 0,
        "breach_exposure": {},
        "recommendations": [],
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        # Search breach databases
        source_tasks = [
            _search_source(client, name, info, query)
            for name, info in DARKWEB_SOURCES.items()
        ]
        source_results = await asyncio.gather(*source_tasks, return_exceptions=True)

        for r in source_results:
            if isinstance(r, BaseException) or not isinstance(r, dict):
                continue
            results["sources_checked"].append(r)
            if r.get("has_data"):
                results["total_matches"] += r.get("matches", 0)

        # Search paste sites
        paste_tasks = [
            _search_paste_site(client, template, query)
            for template in PASTE_SITES
        ]
        paste_results = await asyncio.gather(*paste_tasks, return_exceptions=True)

        for r in paste_results:
            if isinstance(r, BaseException) or not isinstance(r, dict):
                continue
            if r.get("has_results"):
                results["paste_results"].append(r)
                results["total_matches"] += r.get("match_count", 0)

    # Breach exposure assessment
    results["breach_exposure"] = _assess_breach_exposure(query, query_type)
    results["recommendations"] = _generate_darkweb_recommendations(results)

    return results


def _assess_breach_exposure(query: str, query_type: str) -> dict:
    """Assess likely breach exposure based on query characteristics."""
    query_lower = query.lower()

    # Check against known breach patterns
    exposure = {
        "level": "UNKNOWN",
        "likely_breaches": [],
        "total_possible_exposure": 0,
    }

    for breach_name, breach_info in KNOWN_BREACHES.items():
        # Check if query domain matches breach
        breach_lower = breach_name.lower()
        if query_type == "domain":
            domain = query_lower.split('@')[-1] if '@' in query_lower else query_lower
            if domain in breach_lower:
                exposure["likely_breaches"].append({
                    "breach": breach_name,
                    "records": breach_info["records"],
                    "year": breach_info["year"],
                    "type": breach_info["type"],
                })

    if not exposure["likely_breaches"]:
        # Provide general guidance
        exposure["note"] = "No direct breach matches found. Check HIBP for email-specific results."
    else:
        exposure["level"] = "ELEVATED" if len(exposure["likely_breaches"]) > 1 else "POSSIBLE"
        exposure["total_possible_exposure"] = len(exposure["likely_breaches"])

    return exposure


def _generate_darkweb_recommendations(results: dict) -> list:
    """Generate security recommendations based on dark web findings."""
    recs = []

    if results["total_matches"] > 0:
        recs.append({
            "priority": "CRITICAL",
            "action": "Data found on dark web sources — immediately change all passwords",
            "detail": f"Found {results['total_matches']} potential matches across breach databases and paste sites"
        })

    recs.append({
        "priority": "HIGH",
        "action": "Check HaveIBeenPwned for full breach history",
        "detail": "Visit https://haveibeenpwned.com for comprehensive breach checking"
    })

    recs.append({
        "priority": "MEDIUM",
        "action": "Enable 2FA on all accounts",
        "detail": "Two-factor authentication prevents unauthorized access even if credentials are leaked"
    })

    recs.append({
        "priority": "MEDIUM",
        "action": "Use unique passwords per service",
        "detail": "Password managers prevent credential stuffing across services"
    })

    return recs
