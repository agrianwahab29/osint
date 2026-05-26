"""
NAME SEARCH v3 — Aggressive multi-engine name intelligence
Uses Google dorks, DuckDuckGo API, GitHub API, Wikipedia API,
plus people search engines — returns REAL results.
"""
import re
import json
import asyncio
from datetime import datetime
from urllib.parse import quote_plus, urlencode
import httpx

SEARCH_ENGINES = {
    "duckduckgo": "https://api.duckduckgo.com/?q={query}&format=json&no_html=1&skip_disambig=1",
    "duckduckgo_html": "https://html.duckduckgo.com/html/?q={query}",
    "bing": "https://www.bing.com/search?q={query}&setlang=en",
    "google_news": "https://news.google.com/search?q={query}&hl=en",
}

# Google dorks for name search
GOOGLE_DORKS = [
    '"{name}"',  # exact match
    '"{name}" site:linkedin.com',  # LinkedIn profiles
    '"{name}" site:facebook.com',  # Facebook
    '"{name}" site:twitter.com OR site:x.com',  # Twitter/X
    '"{name}" site:instagram.com',  # Instagram
    '"{name}" site:github.com',  # GitHub
    '"{name}" site:medium.com',  # Medium blog
    '"{name}" intitle:"resume" OR intitle:"cv"',  # Resume/CV
    '"{name}" filetype:pdf',  # PDF documents
    '"{name}" "email" OR "contact"',  # Contact info
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


def _is_valid_url(url: str) -> bool:
    """Check if URL is a valid external URL (not internal/tracking)."""
    if not url:
        return False
    # Block relative URLs (starting with / or //)
    if url.startswith('/') or url.startswith('//'):
        return False
    # Block DuckDuckGo internal tracking URLs
    if any(skip in url.lower() for skip in ['/l/', '/h/', '/gethtml/', '/client_']):
        return False
    # Must have proper scheme
    if not (url.startswith('http://') or url.startswith('https://')):
        return False
    return True


def _extract_links_from_html(html: str) -> list:
    """Extract title + URL pairs from search result HTML."""
    results = []
    seen_urls = set()

    # Pattern 1: Standard search result links
    patterns = [
        # DuckDuckGo HTML
        r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        # Generic <a> with href in search results
        r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
        # Bing style
        r'<h2[^>]*>.*?<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
        # Yahoo style
        r'<a[^>]*class="[^"]*" href="(https?://[^"]+)"[^>]*>(.*?)</a>',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        for url, title in matches:
            url = url.strip()
            title = re.sub(r'<[^>]+>', '', title).strip()
            title = re.sub(r'\s+', ' ', title)

            # 🔒 FILTER: Skip invalid/tracking/internal URLs
            if not _is_valid_url(url):
                continue
            if not title or len(title) < 3:
                continue
            if any(skip in url.lower() for skip in ['google.com', 'bing.com', 'yandex', '/search', '/login']):
                continue
            if url in seen_urls:
                continue

            seen_urls.add(url)
            results.append({
                "title": title[:200],
                "url": url,
                "display_url": url.split('//')[-1].split('/')[0][:60] if '//' in url else url[:60],
            })

    return results


def _generate_search_queries(name: str) -> list:
    """Generate diverse search queries from a name."""
    parts = name.strip().split()
    queries = []

    quoted = f'"{name}"'
    queries.append(quoted)

    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        queries.append(f'"{first} {last}"')
        queries.append(f'"{last}, {first}"')
        queries.append(f'{first} {last} linkedin')
        queries.append(f'{first} {last} facebook')
        queries.append(f'{first} {last} twitter')
        queries.append(f'{first} {last} github')
        queries.append(f'{first} {last} contact email')
        queries.append(f'{first} {last} location')
        queries.append(f'{first} {last} resume cv')
        queries.append(f'"{first}" "{last}"')
    else:
        queries.append(f'{name} linkedin')
        queries.append(f'{name} social media')
        queries.append(f'{name} contact')

    return queries[:15]


async def _fetch_search(client: httpx.AsyncClient, url: str, headers: dict) -> str:
    """Fetch search page."""
    try:
        resp = await client.get(url, headers=headers, timeout=12.0, follow_redirects=True)
        return resp.text[:80000]
    except Exception:
        return ""


async def search_name(full_name: str) -> dict:
    """
    Multi-engine name search — returns REAL aggregated results.
    Searches DuckDuckGo, Google News, GitHub, Wikipedia simultaneously.
    """
    queries = _generate_search_queries(full_name)

    results = {
        "query": full_name,
        "timestamp": datetime.now().isoformat(),
        "queries_used": queries,
        "total_results": 0,
        "web_results": [],
        "github_profiles": [],
        "wikipedia_mentions": [],
        "ddg_related": [],
        "ddg_abstract": {},
        "name_variations": [],
        "possible_locations": [],
        "risk_indicators": [],
        "dork_results": [],
    }

    headers = {"User-Agent": USER_AGENTS[0], "Accept-Language": "en-US,en;q=0.9"}

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        tasks = []

        # DuckDuckGo API (instant answers)
        ddg_query = quote_plus(full_name)
        ddg_url = SEARCH_ENGINES["duckduckgo"].format(query=ddg_query)
        tasks.append(("ddg_api", _fetch_search(client, ddg_url, headers)))

        # DuckDuckGo HTML search
        ddg_html_url = SEARCH_ENGINES["duckduckgo_html"].format(query=ddg_query)
        tasks.append(("ddg_html", _fetch_search(client, ddg_html_url, headers)))

        # Google News
        gn_url = SEARCH_ENGINES["google_news"].format(query=ddg_query)
        tasks.append(("google_news", _fetch_search(client, gn_url, headers)))

        # GitHub API
        gh_url = f"https://api.github.com/search/users?q={ddg_query}&per_page=20"
        tasks.append(("github", _fetch_search(client, gh_url, headers)))

        # Wikipedia
        wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={ddg_query}&format=json&srlimit=15"
        tasks.append(("wiki", _fetch_search(client, wiki_url, headers)))

        # Bing
        bing_url = SEARCH_ENGINES["bing"].format(query=ddg_query)
        tasks.append(("bing", _fetch_search(client, bing_url, headers)))

        responses = {}
        for name, task in tasks:
            try:
                responses[name] = await task
            except Exception:
                responses[name] = ""

    # Parse DuckDuckGo API
    if responses.get("ddg_api"):
        try:
            ddg_data = json.loads(responses["ddg_api"])
            if ddg_data.get("AbstractText") and ddg_data["AbstractText"].strip():
                results["ddg_abstract"] = {
                    "text": ddg_data["AbstractText"][:500],
                    "source": ddg_data.get("AbstractURL", ""),
                    "source_name": ddg_data.get("AbstractSource", ""),
                }
            for topic in ddg_data.get("RelatedTopics", []):
                if isinstance(topic, dict) and topic.get("Text"):
                    results["ddg_related"].append({
                        "text": topic["Text"][:400],
                        "url": topic.get("FirstURL", ""),
                    })
                elif isinstance(topic, dict) and topic.get("Topics"):
                    for subtopic in topic.get("Topics", []):
                        if subtopic.get("Text"):
                            results["ddg_related"].append({
                                "text": subtopic["Text"][:400],
                                "url": subtopic.get("FirstURL", ""),
                            })
        except (json.JSONDecodeError, Exception):
            pass

    # Parse DuckDuckGo HTML results
    ddg_links = _extract_links_from_html(responses.get("ddg_html", ""))
    for link in ddg_links[:20]:
        results["web_results"].append({
            **link,
            "source": "duckduckgo",
        })

    # Parse Google News
    gn_links = _extract_links_from_html(responses.get("google_news", ""))
    for link in gn_links[:10]:
        results["web_results"].append({
            **link,
            "source": "google_news",
        })

    # Parse Bing
    bing_links = _extract_links_from_html(responses.get("bing", ""))
    for link in bing_links[:10]:
        results["web_results"].append({
            **link,
            "source": "bing",
        })

    # Deduplicate web results
    seen = set()
    unique_results = []
    for r in results["web_results"]:
        key = r["url"]
        if key not in seen:
            seen.add(key)
            unique_results.append(r)
    results["web_results"] = unique_results[:50]

    # Parse GitHub
    if responses.get("github"):
        try:
            gh_data = json.loads(responses["github"])
            for user in gh_data.get("items", [])[:20]:
                results["github_profiles"].append({
                    "username": user.get("login", ""),
                    "avatar": user.get("avatar_url", ""),
                    "url": user.get("html_url", ""),
                    "type": user.get("type", "User"),
                    "score": user.get("score", 0),
                })
        except (json.JSONDecodeError, Exception):
            pass

    # Parse Wikipedia
    if responses.get("wiki"):
        try:
            wiki_data = json.loads(responses["wiki"])
            for page in wiki_data.get("query", {}).get("search", [])[:15]:
                pid = page.get("pageid", 0)
                results["wikipedia_mentions"].append({
                    "title": page.get("title", ""),
                    "page_id": pid,
                    "snippet": re.sub(r'<[^>]+>', '', page.get("snippet", "")),
                    "url": f"https://en.wikipedia.org/?curid={pid}",
                    "word_count": page.get("wordcount", 0),
                })
        except (json.JSONDecodeError, Exception):
            pass

    # Name variations
    parts = full_name.strip().split()
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        results["name_variations"] = [
            f"{first} {last}",
            f"{last}, {first}",
            f"{first} {last[0]}.",
            f"{first[0]}. {last}",
            full_name.upper(),
            full_name.lower(),
        ]

    # Location hints from name patterns
    surname_regions = {
        "putra": "Indonesia", "wijaya": "Indonesia", "santoso": "Indonesia",
        "chen": "China/Taiwan", "wang": "China", "li": "China",
        "smith": "English-speaking", "johnson": "US/UK",
        "kumar": "India", "singh": "India", "patel": "India",
        "gonzalez": "Hispanic", "rodriguez": "Hispanic", "lopez": "Hispanic",
        "rossi": "Italy", "bianchi": "Italy",
        "mueller": "Germany", "schmidt": "Germany",
        "sato": "Japan", "tanaka": "Japan", "yamamoto": "Japan",
        "kim": "Korea", "park": "Korea", "lee": "Korea/Chinese",
        "nguyen": "Vietnam", "tran": "Vietnam",
        "petrov": "Russia", "ivanov": "Russia",
    }
    last_lower = parts[-1].lower() if parts else ""
    for surname, region in surname_regions.items():
        if surname in last_lower:
            results["possible_locations"].append(region)

    # Risk indicators
    total = len(results["web_results"]) + len(results["github_profiles"]) + len(results["wikipedia_mentions"])
    results["total_results"] = total

    if total == 0:
        results["risk_indicators"].append({
            "level": "LOW", "type": "no_footprint",
            "detail": "Zero digital footprint — possible alias, very private individual, or name too common"
        })
    elif total < 10:
        results["risk_indicators"].append({
            "level": "LOW", "type": "minimal_footprint",
            "detail": f"Minimal footprint ({total} results) — limited online presence"
        })
    elif total < 50:
        results["risk_indicators"].append({
            "level": "INFO", "type": "moderate_footprint",
            "detail": f"Moderate footprint ({total} results) — average online presence"
        })
    else:
        results["risk_indicators"].append({
            "level": "MEDIUM", "type": "high_visibility",
            "detail": f"High visibility ({total} results) — likely public figure or active online"
        })

    if results["github_profiles"]:
        results["risk_indicators"].append({
            "level": "INFO", "type": "developer",
            "detail": f"{len(results['github_profiles'])} GitHub profile(s) — technical/developer background"
        })
    if results["wikipedia_mentions"]:
        results["risk_indicators"].append({
            "level": "INFO", "type": "notable",
            "detail": "Wikipedia presence — potentially notable individual"
        })

    return results
