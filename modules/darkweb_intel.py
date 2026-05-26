"""
EXPOSURE INTELLIGENCE v2 — Repositioned from "Dark Web Intel".
Checks public breach databases, paste sites, and known exposure sources.
Does NOT claim full dark web coverage — honest about limitations.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

from config import ENABLE_DARKWEB_INTEL

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/4.0; Security Research)"

# Public breach/paste search APIs — limited but free
EXPOSURE_SOURCES = {
    "psbdmp": {
        "url": "https://psbdmp.ws/api/v3/search/{query}",
        "type": "paste_search",
        "note": "Pastebin dump search (public)"
    },
}

PASTE_SITES = [
    "https://pastebin.com/search?q={query}",
    "https://rentry.co/search?q={query}",
]

# Known major breaches for reference
KNOWN_BREACHES = {
    "Collection #1-5": {"records": "2.7B+", "year": "2019", "type": "Credential Stuffing List"},
    "Yahoo (2013-2016)": {"records": "3B", "year": "2016", "type": "Data Breach"},
    "LinkedIn (2021)": {"records": "700M", "year": "2021", "type": "Data Scraping"},
    "Facebook (2019)": {"records": "533M", "year": "2019", "type": "Data Scraping"},
    "Twitter (2023)": {"records": "220M", "year": "2023", "type": "Data Scraping"},
    "Marriott (2018)": {"records": "500M", "year": "2018", "type": "Data Breach"},
    "Equifax (2017)": {"records": "147M", "year": "2017", "type": "Data Breach"},
    "Adobe (2013)": {"records": "153M", "year": "2013", "type": "Data Breach"},
    "Canva (2019)": {"records": "137M", "year": "2019", "type": "Data Breach"},
    "Capital One (2019)": {"records": "106M", "year": "2019", "type": "Data Breach"},
    "Dropbox (2012)": {"records": "68M", "year": "2012", "type": "Data Breach"},
    "eBay (2014)": {"records": "145M", "year": "2014", "type": "Data Breach"},
    "Zynga (2019)": {"records": "218M", "year": "2019", "type": "Data Breach"},
    "T-Mobile (2021)": {"records": "54M", "year": "2021", "type": "Data Breach"},
    "MySpace (2013)": {"records": "360M", "year": "2013", "type": "Data Breach"},
}


async def _search_source(client: httpx.AsyncClient, source_name: str,
                         source_info: dict, query: str) -> dict:
    """Search a single exposure source."""
    url = source_info["url"].format(query=quote_plus(query))
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                               timeout=15.0, follow_redirects=True)
        result = {
            "source": source_name,
            "url": url,
            "type": source_info["type"],
            "status_code": resp.status_code,
            "has_data": False,
            "matches": 0,
        }
        if resp.status_code == 200:
            text = resp.text[:50000]
            query_lower = query.lower()
            matches = text.lower().count(query_lower)
            result["matches"] = matches
            result["has_data"] = matches > 0
        return result
    except Exception as e:
        return {
            "source": source_name, "url": url, "type": source_info["type"],
            "error": str(e)[:100], "has_data": False,
        }


async def _search_paste_site(client: httpx.AsyncClient, template: str, query: str) -> dict:
    """Search a paste site."""
    url = template.format(query=quote_plus(query))
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                               timeout=12.0, follow_redirects=True)
        text = resp.text[:30000]
        return {
            "url": url, "status": resp.status_code,
            "match_count": text.lower().count(query.lower()),
            "has_results": text.lower().count(query.lower()) > 0,
        }
    except Exception as e:
        return {"url": url, "status": 0, "error": str(e)[:80], "has_results": False}


async def darkweb_intel(query: str, query_type: str = "auto") -> dict:
    """
    Exposure Intelligence — honest about limitations.
    Checks public paste/breach sources only.
    Does NOT claim full dark web coverage.
    """
    # Honest disclaimer
    if not ENABLE_DARKWEB_INTEL:
        return {
            "status": "disabled",
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "disclaimer": (
                "No verified dark web source configured. "
                "This module is disabled by feature flag. "
                "Showing defensive recommendations only."
            ),
            "recommendations": _defensive_recommendations(),
            "total_matches": 0,
        }

    if query_type == "auto":
        if "@" in query: query_type = "email"
        elif "." in query and " " not in query: query_type = "domain"
        elif " " in query: query_type = "name"
        else: query_type = "username"

    results = {
        "status": "completed",
        "query": query,
        "query_type": query_type,
        "timestamp": datetime.now().isoformat(),
        "disclaimer": (
            "⚠️ Limited exposure check only. This does NOT scan the entire dark web. "
            "Verified dark web sources are not configured. "
            "For full coverage, use HIBP and dedicated threat intelligence platforms."
        ),
        "sources_checked": [],
        "paste_results": [],
        "total_matches": 0,
        "breach_exposure": {"level": "LIMITED", "note": "Limited to public paste search only"},
        "recommendations": [],
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        source_tasks = [
            _search_source(client, name, info, query)
            for name, info in EXPOSURE_SOURCES.items()
        ]
        source_results = await asyncio.gather(*source_tasks, return_exceptions=True)

        for r in source_results:
            if isinstance(r, BaseException) or not isinstance(r, dict):
                continue
            results["sources_checked"].append(r)
            if r.get("has_data"):
                results["total_matches"] += r.get("matches", 0)

        paste_tasks = [
            _search_paste_site(client, t, query) for t in PASTE_SITES
        ]
        paste_results = await asyncio.gather(*paste_tasks, return_exceptions=True)

        for r in paste_results:
            if isinstance(r, BaseException) or not isinstance(r, dict):
                continue
            if r.get("has_results"):
                results["paste_results"].append(r)
                results["total_matches"] += r.get("match_count", 0)

    # Check against known breach patterns
    results["breach_exposure"] = _assess_exposure(query, query_type)

    # Always provide defensive recommendations
    results["recommendations"] = (
        _specific_recommendations(results) if results["total_matches"] > 0
        else _defensive_recommendations()
    )

    return results


def _assess_exposure(query: str, query_type: str) -> dict:
    """Assess against known breach patterns — educational only."""
    query_lower = query.lower()
    exposure = {
        "level": "LIMITED",
        "disclaimer": "Based on known public breach metadata only. Not a real-time dark web scan.",
        "likely_breaches": [],
    }

    for breach_name, breach_info in KNOWN_BREACHES.items():
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
        exposure["note"] = "No known breach matches from local catalogue."

    return exposure


def _defensive_recommendations() -> list:
    """General defensive recommendations."""
    return [
        {"priority": "HIGH", "action": "Use unique passwords per service",
         "detail": "Password managers prevent credential stuffing across services"},
        {"priority": "HIGH", "action": "Enable 2FA on all accounts",
         "detail": "Two-factor authentication prevents unauthorized access even if credentials leak"},
        {"priority": "MEDIUM", "action": "Check password exposure with Pwned Passwords",
         "detail": "Use the password exposure check feature to verify if passwords appear in breaches"},
        {"priority": "MEDIUM", "action": "Monitor breach catalogue",
         "detail": "Regularly check HIBP for new breaches affecting your accounts"},
        {"priority": "LOW", "action": "Use email aliases",
         "detail": "Separate emails for different services limits exposure impact"},
    ]


def _specific_recommendations(results: dict) -> list:
    """Specific recommendations when matches found."""
    recs = [
        {"priority": "CRITICAL", "action": "Data found on public paste/breach sources",
         "detail": f"Found {results['total_matches']} potential matches. Change all passwords immediately."},
    ]
    recs.extend(_defensive_recommendations())
    return recs
