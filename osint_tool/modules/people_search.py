"""
PEOPLE SEARCH AGGREGATOR v1 — Cross-source people data aggregation
Searches across people search engines, public records, and data aggregators.
Uses web scraping of free people search sites.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# Free people search engines — no API key needed
PEOPLE_SEARCH_SITES = {
    "fastpeoplesearch": {
        "url": "https://www.fastpeoplesearch.com/name/{name}",
        "type": "people_search",
    },
    "thatsthem": {
        "url": "https://thatsthem.com/name/{first}-{last}",
        "type": "people_search",
    },
    "truepeoplesearch": {
        "url": "https://www.truepeoplesearch.com/results?name={name_encoded}",
        "type": "people_search",
    },
    "usphonebook": {
        "url": "https://www.usphonebook.com/{first}-{last}",
        "type": "people_search",
    },
    "whitepages": {
        "url": "https://www.whitepages.com/name/{first}-{last}",
        "type": "people_search",
    },
    "publicrecordsnow": {
        "url": "https://publicrecordsnow.com/search/?name={name_encoded}",
        "type": "public_records",
    },
    "searchpeoplefree": {
        "url": "https://www.searchpeoplefree.com/find/{first}-{last}",
        "type": "people_search",
    },
    "peoplesearchnow": {
        "url": "https://www.peoplesearchnow.com/person/{first}-{last}",
        "type": "people_search",
    },
}

# Social media profile patterns to extract from pages
PROFILE_PATTERNS = [
    (r'(?:linkedin\.com/in/)([a-zA-Z0-9_-]+)', 'linkedin'),
    (r'(?:facebook\.com/)([a-zA-Z0-9.]+)', 'facebook'),
    (r'(?:twitter\.com|x\.com/)([a-zA-Z0-9_]+)', 'twitter'),
    (r'(?:instagram\.com/)([a-zA-Z0-9_.]+)', 'instagram'),
    (r'(?:github\.com/)([a-zA-Z0-9_-]+)', 'github'),
    (r'(?:medium\.com/@)([a-zA-Z0-9_]+)', 'medium'),
]

# Email pattern
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Phone pattern (US and international)
PHONE_PATTERNS = [
    r'\+?1?[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}',
    r'\+?\d{1,3}[ -]?\d{7,14}',
]

# Address patterns
ADDRESS_PATTERN = r'\d{1,6}\s+[A-Za-z0-9\s.,]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Way|Place|Pl|Circle|Cir)[,.\s]+[A-Za-z\s]+[,.\s]+[A-Z]{2}\s+\d{5}'


async def _search_site(client: httpx.AsyncClient, site_name: str, site_info: dict, first: str, last: str) -> dict:
    """Search a single people search site."""
    name_encoded = quote_plus(f"{first} {last}")
    url = site_info["url"].format(
        name=name_encoded,
        name_encoded=name_encoded,
        first=first,
        last=last
    )

    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=15.0, follow_redirects=True)
        html = resp.text[:100000]
        text_lower = html.lower()

        emails = list(set(re.findall(EMAIL_PATTERN, html, re.IGNORECASE)))
        phones = []
        for pp in PHONE_PATTERNS:
            phones.extend(re.findall(pp, html))
        phones = list(set(phones))[:10]

        addresses = re.findall(ADDRESS_PATTERN, html, re.IGNORECASE)

        profiles = []
        for pattern, platform in PROFILE_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in set(matches):
                if len(m) > 1 and m not in ['share', 'in', 'pub', 'login', 'signup']:
                    profiles.append({"platform": platform, "username": m})

        # Check if page has meaningful results
        no_result_indicators = [
            "no results", "not found", "no matches", "couldn't find",
            "0 results", "try again", "no records"
        ]
        has_results = not any(ind in text_lower for ind in no_result_indicators)

        return {
            "site": site_name,
            "url": url,
            "status_code": resp.status_code,
            "has_results": has_results,
            "emails_found": emails[:5],
            "phones_found": phones[:5],
            "addresses_found": addresses[:3],
            "profiles_found": profiles[:10],
            "page_size": len(html),
        }
    except Exception as e:
        return {
            "site": site_name,
            "url": url,
            "status_code": 0,
            "has_results": False,
            "error": str(e)[:100],
        }


async def search_people(full_name: str) -> dict:
    """
    Aggregate people search results from multiple free sources.
    Extracts emails, phones, addresses, and social profiles found.
    """
    parts = full_name.strip().split()
    if len(parts) < 2:
        return {
            "query": full_name,
            "error": "Need at least first and last name",
            "timestamp": datetime.now().isoformat(),
        }

    first = parts[0]
    last = parts[-1]

    results = {
        "query": full_name,
        "first_name": first,
        "last_name": last,
        "timestamp": datetime.now().isoformat(),
        "searches": [],
        "aggregated": {
            "all_emails": [],
            "all_phones": [],
            "all_addresses": [],
            "all_profiles": [],
            "sites_with_results": 0,
        }
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        tasks = [
            _search_site(client, site_name, site_info, first, last)
            for site_name, site_info in PEOPLE_SEARCH_SITES.items()
        ]
        site_results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in site_results:
        if isinstance(r, BaseException) or not isinstance(r, dict):
            continue
        results["searches"].append(r)

        if r.get("has_results"):
            results["aggregated"]["sites_with_results"] += 1
            results["aggregated"]["all_emails"].extend(r.get("emails_found", []))
            results["aggregated"]["all_phones"].extend(r.get("phones_found", []))
            results["aggregated"]["all_addresses"].extend(r.get("addresses_found", []))
            results["aggregated"]["all_profiles"].extend(r.get("profiles_found", []))

    # Deduplicate
    for key in ["all_emails", "all_phones", "all_addresses"]:
        results["aggregated"][key] = list(set(results["aggregated"][key]))

    # Deduplicate profiles by platform+username
    seen_profiles = set()
    unique_profiles = []
    for p in results["aggregated"]["all_profiles"]:
        key = f"{p['platform']}:{p['username']}"
        if key not in seen_profiles:
            seen_profiles.add(key)
            unique_profiles.append(p)
    results["aggregated"]["all_profiles"] = unique_profiles

    results["aggregated"]["total_found"] = (
        len(results["aggregated"]["all_emails"]) +
        len(results["aggregated"]["all_phones"]) +
        len(results["aggregated"]["all_profiles"])
    )

    # Generate clickable search links
    results["direct_search_links"] = _generate_direct_links(first, last)

    return results


def _generate_direct_links(first: str, last: str) -> list:
    """Generate direct links to people search sites."""
    name = f"{first} {last}"
    encoded = quote_plus(name)
    return [
        {"name": "FastPeopleSearch", "url": f"https://www.fastpeoplesearch.com/name/{encoded}"},
        {"name": "ThatsThem", "url": f"https://thatsthem.com/name/{first}-{last}"},
        {"name": "TruePeopleSearch", "url": f"https://www.truepeoplesearch.com/results?name={encoded}"},
        {"name": "USPhoneBook", "url": f"https://www.usphonebook.com/{first}-{last}"},
        {"name": "WhitePages", "url": f"https://www.whitepages.com/name/{first}-{last}"},
        {"name": "Google People Search", "url": f"https://www.google.com/search?q=%22{encoded}%22+phone+OR+email+OR+address"},
        {"name": "Pipl (Archive)", "url": f"https://pipl.com/search/?q={encoded}"},
    ]
