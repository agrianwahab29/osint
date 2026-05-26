"""
PEOPLE SEARCH AGGREGATOR v2 — Region-aware, evidence-based.
Cross-source people data aggregation with confidence scoring.
US sources get lowered confidence for non-US targets.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

from services.confidence_scoring import score_phone, score_email

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Free people search engines — all US-centric
PEOPLE_SEARCH_SITES = {
    "fastpeoplesearch": {
        "url": "https://www.fastpeoplesearch.com/name/{name}",
        "type": "people_search",
        "region": "US",
    },
    "thatsthem": {
        "url": "https://thatsthem.com/name/{first}-{last}",
        "type": "people_search",
        "region": "US",
    },
    "truepeoplesearch": {
        "url": "https://www.truepeoplesearch.com/results?name={name_encoded}",
        "type": "people_search",
        "region": "US",
    },
    "usphonebook": {
        "url": "https://www.usphonebook.com/{first}-{last}",
        "type": "people_search",
        "region": "US",
    },
    "whitepages": {
        "url": "https://www.whitepages.com/name/{first}-{last}",
        "type": "people_search",
        "region": "US",
    },
    "searchpeoplefree": {
        "url": "https://www.searchpeoplefree.com/find/{first}-{last}",
        "type": "people_search",
        "region": "US",
    },
    "peoplesearchnow": {
        "url": "https://www.peoplesearchnow.com/person/{first}-{last}",
        "type": "people_search",
        "region": "US",
    },
}

PROFILE_PATTERNS = [
    (r'(?:linkedin\.com/in/)([a-zA-Z0-9_-]+)', 'linkedin'),
    (r'(?:facebook\.com/)([a-zA-Z0-9.]+)', 'facebook'),
    (r'(?:twitter\.com|x\.com/)([a-zA-Z0-9_]+)', 'twitter'),
    (r'(?:instagram\.com/)([a-zA-Z0-9_.]+)', 'instagram'),
    (r'(?:github\.com/)([a-zA-Z0-9_-]+)', 'github'),
    (r'(?:medium\.com/@)([a-zA-Z0-9_]+)', 'medium'),
]

EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
PHONE_PATTERNS = [
    r'\+?1?[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}',
    r'\+?\d{1,3}[ -]?\d{7,14}',
]
ADDRESS_PATTERN = r'\d{1,6}\s+[A-Za-z0-9\s.,]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Way|Place|Pl|Circle|Cir)[,.\s]+[A-Za-z\s]+[,.\s]+[A-Z]{2}\s+\d{5}'


async def _search_site(client: httpx.AsyncClient, site_name: str, site_info: dict,
                       first: str, last: str, country: str) -> dict:
    """Search a single people search site with region awareness."""
    name_encoded = quote_plus(f"{first} {last}")
    url = site_info["url"].format(
        name=name_encoded, name_encoded=name_encoded, first=first, last=last
    )

    region = site_info.get("region", "US")
    is_us_source = region == "US"
    target_not_us = country.upper() != "US"

    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                               timeout=15.0, follow_redirects=True)
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
                if len(m) > 1 and m not in ('share', 'in', 'pub', 'login', 'signup'):
                    profiles.append({"platform": platform, "username": m})

        no_result_indicators = [
            "no results", "not found", "no matches", "couldn't find",
            "0 results", "try again", "no records"
        ]
        has_results = not any(ind in text_lower for ind in no_result_indicators)

        # Apply region-aware confidence for non-US targets
        region_warning = None
        if is_us_source and target_not_us:
            region_warning = "This source is US-centric. Confidence lowered for non-US target."

        return {
            "site": site_name,
            "url": url,
            "status_code": resp.status_code,
            "has_results": has_results,
            "region": region,
            "region_warning": region_warning,
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
            "region": region,
        }


async def search_people(full_name: str, country: str = "ID") -> dict:
    """
    Aggregate people search results from multiple free sources.
    Region-aware: US sources get lowered confidence for non-US targets.
    """
    parts = full_name.strip().split()
    if len(parts) < 2:
        return {
            "query": full_name,
            "error": "Need at least first and last name",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
        }

    first = parts[0]
    last = parts[-1]
    country_upper = country.upper()
    is_us_target = country_upper == "US"

    results = {
        "query": full_name,
        "first_name": first,
        "last_name": last,
        "country": country_upper,
        "is_us_target": is_us_target,
        "timestamp": datetime.now().isoformat(),
        "searches": [],
        "aggregated": {
            "all_emails": [],
            "all_phones": [],
            "all_addresses": [],
            "all_profiles": [],
            "sites_with_results": 0,
        },
        "region_warnings": [],
        "status": "completed",
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        tasks = [
            _search_site(client, site_name, site_info, first, last, country_upper)
            for site_name, site_info in PEOPLE_SEARCH_SITES.items()
        ]
        site_results = await asyncio.gather(*tasks, return_exceptions=True)

    region_warnings = []
    for r in site_results:
        if isinstance(r, BaseException) or not isinstance(r, dict):
            continue
        results["searches"].append(r)

        if r.get("has_results"):
            results["aggregated"]["sites_with_results"] += 1

            # Score each finding with region awareness
            for email in r.get("emails_found", []):
                source_type = "aggregator_us" if r.get("region") == "US" else "aggregator"
                conf = score_email(source_type=source_type, name_match=False)
                results["aggregated"]["all_emails"].append({
                    "value": email,
                    "source": r["site"],
                    "source_url": r["url"],
                    "region": r.get("region", "US"),
                    "confidence": conf["score"],
                    "confidence_label": conf["label"],
                    "status": "unverified" if r.get("region") == "US" and not is_us_target else "candidate",
                })

            for phone in r.get("phones_found", []):
                source_type = "aggregator_us" if r.get("region") == "US" else "aggregator"
                conf = score_phone(
                    source_reliability=source_type,
                    region_match=is_us_target or r.get("region") != "US",
                    country=country_upper,
                )
                results["aggregated"]["all_phones"].append({
                    "value": phone,
                    "source": r["site"],
                    "source_url": r["url"],
                    "region": r.get("region", "US"),
                    "confidence": conf["score"],
                    "confidence_label": conf["label"],
                    "status": "unverified",
                })

            for profile in r.get("profiles_found", []):
                results["aggregated"]["all_profiles"].append({
                    "platform": profile["platform"],
                    "username": profile["username"],
                    "source": r["site"],
                    "region": r.get("region", "US"),
                    "confidence": 30 if r.get("region") == "US" and not is_us_target else 50,
                    "status": "candidate",
                })

            for addr in r.get("addresses_found", []):
                results["aggregated"]["all_addresses"].append({
                    "value": addr,
                    "source": r["site"],
                    "region": r.get("region", "US"),
                    "confidence": 20,
                    "status": "unverified",
                })

        # Collect region warnings
        if r.get("region_warning"):
            region_warnings.append(r["region_warning"])

    # Deduplicate warnings
    results["region_warnings"] = list(set(region_warnings))

    # Calculate totals
    agg = results["aggregated"]
    agg["total_found"] = (len(agg["all_emails"]) + len(agg["all_phones"]) +
                          len(agg["all_profiles"]) + len(agg["all_addresses"]))

    # Generate clickable search links
    results["direct_search_links"] = _generate_direct_links(first, last)

    # Empty state explanation
    if agg["total_found"] == 0:
        results["empty_state_reason"] = (
            f"No data found from people aggregators for target in {country_upper}.\n"
            "Possible reasons:\n"
            "- Target not in US-centric databases\n"
            "- Name is uncommon or not in public records\n"
            "- Sources blocked or rate-limited\n"
            "- People search is US-focused by nature"
        )

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
    ]
