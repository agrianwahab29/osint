"""
Telegram OSINT Module — Search Telegram channels, users, and groups.
Uses public Telegram web search and tgstat.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/3.0)"

TELEGRAM_SOURCES = {
    "telegram_web": {
        "url": "https://t.me/s/{}",
        "type": "channel_preview",
        "note": "Telegram public channel"
    },
    "tgstat": {
        "url": "https://tgstat.com/search?q={}",
        "type": "channel_search",
        "note": "Tgstat channel search"
    },
    "telemetrio": {
        "url": "https://telemetr.io/en/search?q={}",
        "type": "channel_search",
        "note": "Telemetr analytics"
    },
    "lyzem": {
        "url": "https://lyzem.com/search?q={}",
        "type": "channel_search",
        "note": "Lyzem Telegram search"
    },
}

TELEGRAM_DORKS = [
    "site:t.me {}",
    "site:telegram.me {}",
    "{} telegram channel",
    "{} telegram group",
    "{} t.me",
]


async def _check_channel(client: httpx.AsyncClient, username: str) -> dict:
    """Check if a Telegram channel/user exists."""
    url = f"https://t.me/s/{username}"
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=10.0, follow_redirects=True)
        html = resp.text.lower()[:30000]
        not_found = any(p in html for p in ["not found", "doesn't exist", "no messages", "channel not found"])
        has_content = any(p in html for p in ["tgme_widget_message", "message", "forward"])
        return {
            "username": username,
            "url": f"https://t.me/{username}",
            "exists": has_content and not not_found,
            "has_messages": has_content,
            "status_code": resp.status_code,
        }
    except Exception as e:
        return {"username": username, "url": f"https://t.me/{username}", "exists": False, "error": str(e)[:80]}


async def _search_telegram_sources(client: httpx.AsyncClient, query: str) -> list:
    """Search Telegram analytics/search sites."""
    results = []
    for name, info in TELEGRAM_SOURCES.items():
        if name == "telegram_web":
            continue  # handled separately
        url = info["url"].format(quote_plus(query))
        try:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=12.0, follow_redirects=True)
            html = resp.text[:20000]
            text = html.lower()
            # Extract channel names
            channels = list(set(re.findall(r'(?:t\.me/|telegram\.me/)([a-zA-Z0-9_]+)', html)))
            channels += list(set(re.findall(r'@([a-zA-Z0-9_]{5,})', html)))
            if channels:
                results.append({
                    "source": name,
                    "type": info["type"],
                    "note": info["note"],
                    "url": url,
                    "channels_found": channels[:15],
                    "total": len(channels),
                })
        except Exception:
            pass
    return results


async def _generate_telegram_usernames(name: str) -> list:
    """Generate possible Telegram usernames from a name."""
    parts = name.lower().strip().split()
    usernames = set()
    if len(parts) >= 2:
        f, l = parts[0], parts[-1]
        usernames.update([f"{f}{l}", f"{f}_{l}", f"{f}.{l}", f"{l}{f}", f, l])
    else:
        usernames.add(parts[0])
    return sorted(usernames)


async def telegram_osint(target: str) -> dict:
    """Telegram OSINT — channel/user search and enumeration."""
    results = {
        "query": target,
        "timestamp": datetime.now().isoformat(),
        "channel_checks": [],
        "source_searches": [],
        "search_dorks": [],
        "summary": {},
    }

    # Generate usernames to check
    usernames = await _generate_telegram_usernames(target)
    # Also try direct username if target looks like one
    if re.match(r'^[a-zA-Z0-9_]{5,}$', target.strip()):
        usernames.insert(0, target.strip())

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        # Check generated usernames on Telegram
        check_usernames = usernames[:5]
        channel_tasks = [_check_channel(client, u) for u in check_usernames]
        channel_results = await asyncio.gather(*channel_tasks, return_exceptions=True)

        for r in channel_results:
            if isinstance(r, BaseException) or not isinstance(r, dict):
                continue
            results["channel_checks"].append(r)

        # Search Telegram sources
        results["source_searches"] = await _search_telegram_sources(client, target)

        # Generate dork links
        for dork in TELEGRAM_DORKS:
            q = dork.format(target)
            results["search_dorks"].append({
                "dork": q,
                "url": f"https://www.google.com/search?q={quote_plus(q)}",
            })

    found_channels = [c for c in results["channel_checks"] if c.get("exists")]
    all_found = []
    for s in results["source_searches"]:
        all_found.extend(s.get("channels_found", []))

    results["summary"] = {
        "channels_checked": len(results["channel_checks"]),
        "channels_found_direct": len(found_channels),
        "channels_found_search": len(set(all_found)),
        "found_usernames": [c["username"] for c in found_channels],
        "sources_with_results": sum(1 for s in results["source_searches"] if s.get("channels_found")),
    }

    return results
