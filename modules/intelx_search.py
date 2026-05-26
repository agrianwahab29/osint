"""
IntelX Search Module — Intelligence X public search for leaked data.
Searches public databases, paste sites, document leaks.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/3.0; Security Research)"

INTELX_SOURCES = {
    "intelx_web": {
        "url": "https://intelx.io/?s={query}",
        "type": "leak_search",
        "note": "Intelligence X public search"
    },
    "psbdmp": {
        "url": "https://psbdmp.ws/api/v3/search/{query}",
        "type": "paste_search",
        "note": "Pastebin Dump"
    },
    "leakcheck": {
        "url": "https://leakcheck.io/search?q={query}",
        "type": "breach_db",
        "note": "LeakCheck public"
    },
    "dehashed": {
        "url": "https://dehashed.com/search?query={query}",
        "type": "breach_db",
        "note": "DeHashed public"
    },
    "snusbase": {
        "url": "https://snusbase.com/search?q={query}",
        "type": "breach_db",
        "note": "SnusBase search"
    },
}


async def _search_source(client: httpx.AsyncClient, name: str, info: dict, query: str) -> dict:
    """Search an IntelX source."""
    url = info["url"].format(query=quote_plus(query))
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=12.0, follow_redirects=True)
        html = resp.text[:30000]
        text = html.lower()

        # Find result indicators
        result_patterns = [
            (r'(\d[\d,]*)\s+results?', 'result_count'),
            (r'found[\s:]+(\d+)', 'found_count'),
            (r'total[\s:]+(\d+)', 'total_count'),
        ]
        findings = {}
        for pattern, name_key in result_patterns:
            match = re.search(pattern, text)
            if match:
                findings[name_key] = int(match.group(1).replace(',', ''))

        # Find emails in page
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)[:10]))

        return {
            "source": name,
            "url": url,
            "type": info["type"],
            "note": info["note"],
            "status_code": resp.status_code,
            "has_results": any(findings.values()) or len(emails) > 0,
            "findings": findings,
            "emails_sample": emails[:5],
        }
    except Exception as e:
        return {"source": name, "url": url, "error": str(e)[:100], "has_results": False}


async def _search_paste_sites(client: httpx.AsyncClient, query: str) -> list:
    """Search common paste sites."""
    paste_urls = [
        f"https://pastebin.com/search?q={quote_plus(query)}",
        f"https://rentry.co/search?q={quote_plus(query)}",
        f"https://justpaste.it/search?q={quote_plus(query)}",
        f"https://privatebin.net/?search={quote_plus(query)}",
    ]
    results = []
    for url in paste_urls:
        try:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=10.0, follow_redirects=True)
            html = resp.text[:15000]
            match_count = len(re.findall(r'(?:title|href).*?({})'.format(re.escape(query[:10])), html, re.IGNORECASE))
            if match_count > 0:
                results.append({"url": url, "match_count": match_count, "status": resp.status_code})
        except Exception:
            pass
    return results


async def intelx_search(query: str) -> dict:
    """Intelligence X + breach database search."""
    results = {
        "query": query,
        "timestamp": datetime.now().isoformat(),
        "sources_checked": [],
        "paste_results": [],
        "total_potential_matches": 0,
        "summary": {},
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        # Search all breach sources
        tasks = [_search_source(client, name, info, query) for name, info in INTELX_SOURCES.items()]
        source_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in source_results:
            if isinstance(r, BaseException) or not isinstance(r, dict):
                continue
            results["sources_checked"].append(r)
            if r.get("has_results"):
                results["total_potential_matches"] += sum(r.get("findings", {}).values())

        # Search paste sites
        results["paste_results"] = await _search_paste_sites(client, query)

    results["summary"] = {
        "sources_searched": len(INTELX_SOURCES),
        "sources_with_data": sum(1 for s in results["sources_checked"] if s.get("has_results")),
        "paste_matches": len(results["paste_results"]),
        "total_potential_matches": results["total_potential_matches"],
        "recommendation": "Gunakan IntelX API key untuk hasil lebih komprehensif",
    }

    return results
