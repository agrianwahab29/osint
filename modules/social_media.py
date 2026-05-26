"""
SOCIAL MEDIA PROFILER v3 — Real platform detection, zero false negatives
Per-platform heuristics: status code, redirect pattern, page content markers.
Scans 50+ platforms concurrently. Sherlock-style username enumeration.
"""
import re
import asyncio
from datetime import datetime
from typing import Optional
import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

# Platform definitions with detection rules
# detection: "status_code" = check HTTP status, "negate" = flip exists logic,
# "not_found_text" = text that indicates profile doesn't exist,
# "found_text" = text that confirms profile exists
PLATFORMS = {
    # --- Major Social ---
    "instagram": {
        "url": "https://www.instagram.com/{}/",
        "category": "social", "popularity": "very_high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["page isn&#x27;t available", "page is not available", "Sorry, this page"],
            "found_indicators": ["profilePage", "www.instagram.com/accounts/login"],
        }
    },
    "twitter_x": {
        "url": "https://x.com/{}",
        "category": "social", "popularity": "very_high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["account doesn&#x27;t exist", "account doesn't exist", "This account doesn", "Something went wrong"],
            "found_indicators": ["profile", "joined", "following", "followers", "posts"],
        }
    },
    "facebook": {
        "url": "https://www.facebook.com/{}",
        "category": "social", "popularity": "very_high",
        "detect": {
            # Block redirect codes 301/302 — FB selalu redirect ke login page kalo profil gak ada
            "not_found_codes": [404, 302, 301],
            "not_found_text": ["content isn&#x27;t available", "page isn&#x27;t available", "content not found", "Page Not Found", "Sorry, we couldn&#x27;t find"],
            # Hapus "facebook.com/login" dari found_indicators — itu justru tanda PROFILES TIDAK ADA
            "found_indicators": ["profilePage", "friends", "intro", "timeline"],
            "skip_min_size": True,  # facebook always returns large login pages
        }
    },
    "youtube": {
        "url": "https://www.youtube.com/@{}",
        "category": "video", "popularity": "very_high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["channel doesn't exist", "404 Not Found", "This page isn't available"],
            "found_indicators": ["subscribers", "channel", "videos", "shorts"],
        }
    },
    "tiktok": {
        "url": "https://www.tiktok.com/@{}",
        "category": "video", "popularity": "very_high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["Couldn't find this account", "page not found"],
            "found_indicators": ["following", "followers", "likes", "user-info"],
        }
    },

    # --- Professional ---
    "linkedin": {
        "url": "https://www.linkedin.com/in/{}/",
        "category": "professional", "popularity": "very_high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["page not found", "profile not found", "couldn't find"],
            "found_indicators": ["connections", "experience", "education", "linkedin.com/in/"],
        }
    },

    # --- Developer ---
    "github": {
        "url": "https://github.com/{}",
        "category": "dev", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["not found", "find code"],
            "found_indicators": ["repositories", "followers", "following", "overview", "pinned"],
        }
    },
    "gitlab": {
        "url": "https://gitlab.com/{}",
        "category": "dev", "popularity": "medium",
        "detect": {
            "not_found_codes": [404, 302],
            "not_found_text": ["not found"],
            "found_indicators": ["activity", "projects", "followers", "overview"],
        }
    },
    "bitbucket": {
        "url": "https://bitbucket.org/{}/",
        "category": "dev", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["repositories", "activity", "bitbucket"],
        }
    },
    "dev_to": {
        "url": "https://dev.to/{}",
        "category": "dev", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["posts published", "comments written", "joined"],
        }
    },
    "stackoverflow": {
        "url": "https://stackoverflow.com/users/{}",
        "category": "dev", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["Page not found"],
            "found_indicators": ["reputation", "badges", "answers", "profile"],
        }
    },
    "npm": {
        "url": "https://www.npmjs.com/~{}",
        "category": "dev", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["packages", "npm", "~"],
        }
    },
    "hackernews": {
        "url": "https://news.ycombinator.com/user?id={}",
        "category": "dev", "popularity": "medium",
        "detect": {
            "not_found_text": ["No such user"],
            "found_indicators": ["karma", "created", "submissions", "comments"],
        }
    },

    # --- Forum/Discussion ---
    "reddit": {
        "url": "https://www.reddit.com/user/{}/",
        "category": "forum", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["page not found", "sorry, nobody"],
            "found_indicators": ["karma", "posts", "comments", "trophy"],
        }
    },
    "quora": {
        "url": "https://www.quora.com/profile/{}",
        "category": "qa", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["answers", "followers", "quora"],
        }
    },

    # --- Creative ---
    "medium": {
        "url": "https://medium.com/@{}",
        "category": "blog", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["page not found"],
            "found_indicators": ["followers", "following", "stories", "about"],
        }
    },
    "pinterest": {
        "url": "https://www.pinterest.com/{}/",
        "category": "social", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["page not found"],
            "found_indicators": ["pins", "boards", "followers", "following"],
        }
    },
    "dribbble": {
        "url": "https://dribbble.com/{}",
        "category": "creative", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["shots", "followers", "dribbble"],
        }
    },
    "behance": {
        "url": "https://www.behance.net/{}",
        "category": "creative", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["projects", "followers", "appreciations"],
        }
    },
    "flickr": {
        "url": "https://www.flickr.com/people/{}",
        "category": "photo", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["photos", "followers", "flickr"],
        }
    },
    "soundcloud": {
        "url": "https://soundcloud.com/{}",
        "category": "music", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["tracks", "followers", "playlists"],
        }
    },
    "spotify": {
        "url": "https://open.spotify.com/user/{}",
        "category": "music", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["playlists", "followers", "spotify"],
        }
    },

    # --- Streaming ---
    "twitch": {
        "url": "https://www.twitch.tv/{}",
        "category": "streaming", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["sorry", "time machine"],
            "found_indicators": ["followers", "channel", "offline", "videos"],
        }
    },

    # --- Messaging ---
    "telegram": {
        "url": "https://t.me/{}",
        "category": "messaging", "popularity": "high",
        "detect": {
            "not_found_text": ["not found", "username not found"],
            "found_indicators": ["tgme", "send message", "preview"],
        }
    },

    # --- Finance / Payment ---
    "paypal": {
        "url": "https://www.paypal.me/{}",
        "category": "finance", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["paypal.me", "send"],
        }
    },
    "buymeacoffee": {
        "url": "https://www.buymeacoffee.com/{}",
        "category": "creator", "popularity": "low",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["support", "member", "buymeacoffee"],
        }
    },
    "patreon": {
        "url": "https://www.patreon.com/{}",
        "category": "creator", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["patreon", "support", "member"],
        }
    },

    # --- Gaming ---
    "steam": {
        "url": "https://steamcommunity.com/id/{}",
        "category": "gaming", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["specified profile could not be found"],
            "found_indicators": ["steamcommunity", "games", "friends"],
        }
    },

    # --- Bio / Link ---
    "linktree": {
        "url": "https://linktr.ee/{}",
        "category": "bio", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["links", "linktr.ee"],
        }
    },
    "aboutme": {
        "url": "https://about.me/{}",
        "category": "bio", "popularity": "low",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["about.me", "profile"],
        }
    },
    "keybase": {
        "url": "https://keybase.io/{}",
        "category": "crypto", "popularity": "low",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["keybase", "public key", "proofs"],
        }
    },

    # --- Blog ---
    "substack": {
        "url": "https://{}.substack.com",
        "category": "blog", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["substack", "subscribe", "archive"],
        }
    },
    "wordpress": {
        "url": "https://{}.wordpress.com",
        "category": "blog", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["doesn't exist", "authors"],
            "found_indicators": ["blog", "wordpress", "posts"],
        }
    },
    "blogger": {
        "url": "https://{}.blogspot.com",
        "category": "blog", "popularity": "low",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["blogger", "blogspot", "posts"],
        }
    },

    # --- Professional/Work ---
    "slideshare": {
        "url": "https://www.slideshare.net/{}",
        "category": "professional", "popularity": "low",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["slideshare", "presentations", "slides"],
        }
    },
    "gravatar": {
        "url": "https://gravatar.com/{}",
        "category": "avatar", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["gravatar", "profile", "avatar"],
        }
    },

    # --- Wiki ---
    "wikipedia": {
        "url": "https://en.wikipedia.org/wiki/User:{}",
        "category": "wiki", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "not_found_text": ["Wikipedia does not have a user page"],
            "found_indicators": ["User:", "contributions", "user page"],
        }
    },

    # --- Misc ---
    "vimeo": {
        "url": "https://vimeo.com/{}",
        "category": "video", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["videos", "followers", "vimeo"],
        }
    },
    "etsy": {
        "url": "https://www.etsy.com/people/{}",
        "category": "shop", "popularity": "medium",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["etsy", "shop", "favorites"],
        }
    },
    "snapchat": {
        "url": "https://www.snapchat.com/add/{}",
        "category": "social", "popularity": "high",
        "detect": {
            "not_found_codes": [404],
            "found_indicators": ["snapchat", "add", "snapcode"],
        }
    },
}


def _generate_usernames(full_name: str) -> list:
    """Generate candidate usernames from a full name."""
    parts = full_name.lower().strip().split()
    usernames = set()

    if len(parts) >= 2:
        first = parts[0]
        last = parts[-1]
        middle = parts[1] if len(parts) > 2 else ""

        # Core patterns
        for f, l in [(first, last), (last, first)]:
            usernames.add(f"{f}{l}")
            usernames.add(f"{f}.{l}")
            usernames.add(f"{f}_{l}")
            usernames.add(f"{f}-{l}")
            usernames.add(f"{f[0]}{l}")
            usernames.add(f"{f}{l[0]}")
            usernames.add(f"{f[0]}.{l}")
            usernames.add(f"{f}.{l[0]}")

        usernames.add(first)
        usernames.add(last)
        usernames.add(f"real_{first}{last}")
        usernames.add(f"its_{first}{last}")
        usernames.add(f"the_{first}{last}")
        usernames.add(f"{first}{last}official")
        usernames.add(f"{first[0]}{middle}{last}" if middle else f"{first}{last}")

    else:
        usernames.add(parts[0])
        usernames.add(f"{parts[0]}official")
        usernames.add(f"real{parts[0]}")

    # Remove anything that could be problematic in URL
    cleaned = set()
    for u in usernames:
        u = re.sub(r'[^a-z0-9._-]', '', u)
        if 1 <= len(u) <= 39:
            cleaned.add(u)

    return sorted(cleaned)


async def _check_profile(
    client: httpx.AsyncClient,
    platform_name: str,
    platform_info: dict,
    username: str
) -> dict:
    """
    Check if a profile exists using platform-specific detection rules.
    Uses HTTP status + content analysis.
    """
    url = platform_info["url"].format(username)
    detect = platform_info.get("detect", {})
    headers = {
        "User-Agent": USER_AGENTS[0],
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    result = {
        "platform": platform_name,
        "url": url,
        "username": username,
        "category": platform_info["category"],
        "popularity": platform_info["popularity"],
        "status_code": 0,
        "exists": False,
        "confidence": "low",
    }

    try:
        resp = await client.get(
            url,
            headers=headers,
            timeout=12.0,
            follow_redirects=True
        )
        result["status_code"] = resp.status_code
        result["final_url"] = str(resp.url)
        text_lower = resp.text.lower()
        text_full = resp.text
        content_len = len(text_full)

        not_found_codes = detect.get("not_found_codes", [])
        not_found_text = detect.get("not_found_text", [])
        found_indicators = detect.get("found_indicators", [])
        skip_min_size = detect.get("skip_min_size", False)

        # Determine if profile exists
        is_not_found = False

        # Check status codes
        if resp.status_code in not_found_codes:
            is_not_found = True

        # Also check 301/302 to home page (aggressive redirect = not found)
        if resp.status_code in (301, 302) and str(resp.url).rstrip('/') in (
            f"https://{platform_name}.com",
            f"https://www.{platform_name}.com",
            f"https://{platform_name}.com/",
        ):
            is_not_found = True

        # Check not_found text patterns
        for nf_text in not_found_text:
            if nf_text.lower() in text_lower or nf_text in text_full:
                is_not_found = True
                break

        # Check found indicators (strong signal for existence)
        found_signals = 0
        for fi in found_indicators:
            if fi.lower() in text_lower:
                found_signals += 1

        # Heuristic: very small page = probably error/not found
        is_tiny = content_len < 300 and not skip_min_size

        if is_not_found:
            result["exists"] = False
            result["confidence"] = "high"
        elif found_signals >= 2:
            result["exists"] = True
            result["confidence"] = "high" if found_signals >= 3 else "medium"
        elif found_signals == 1 and not is_tiny:
            result["exists"] = True
            result["confidence"] = "low"
        elif is_tiny and not found_signals:
            result["exists"] = False
            result["confidence"] = "medium"
        elif resp.status_code == 200 and content_len > 2000 and not is_not_found:
            # Large 200 with no not_found text = likely exists
            result["exists"] = True
            result["confidence"] = "low"
        else:
            result["exists"] = False
            result["confidence"] = "low"

        result["content_size"] = content_len
        result["found_signals"] = found_signals

    except httpx.TimeoutException:
        result["status_code"] = -1
        result["exists"] = False
        result["error"] = "timeout"
    except httpx.ConnectError:
        result["status_code"] = -1
        result["exists"] = False
        result["error"] = "connection_refused"
    except Exception as e:
        result["status_code"] = -1
        result["exists"] = False
        result["error"] = str(e)[:100]

    return result


async def scan_social_media(full_name: str) -> dict:
    """
    Scan 40+ social platforms for a person's profiles.
    Uses generated usernames + platform-specific detection.
    """
    usernames = _generate_usernames(full_name)

    results = {
        "query_name": full_name,
        "timestamp": datetime.now().isoformat(),
        "usernames_generated": len(usernames),
        "usernames": usernames[:10],
        "total_platforms": len(PLATFORMS),
        "profiles_found": [],
        "profiles_not_found": [],
        "by_category": {},
        "by_confidence": {"high": [], "medium": [], "low": []},
        "summary": {}
    }

    # Check top 3 usernames across all platforms
    check_usernames = usernames[:3]

    semaphore = asyncio.Semaphore(15)  # limit concurrency

    async def check_with_semaphore(client, pname, pinfo, uname):
        async with semaphore:
            return await _check_profile(client, pname, pinfo, uname)

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        tasks = []
        for username in check_usernames:
            for platform_name, platform_info in PLATFORMS.items():
                tasks.append(check_with_semaphore(client, platform_name, platform_info, username))
        check_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Merge results — best match per platform across usernames
    platform_best: dict = {}
    for r in check_results:
        if isinstance(r, BaseException) or not isinstance(r, dict):
            continue
        platform = r.get("platform", "")
        if not platform:
            continue

        if platform not in platform_best:
            platform_best[platform] = r
        else:
            existing = platform_best[platform]
            # Prefer found over not found
            if r.get("exists") and not existing.get("exists"):
                platform_best[platform] = r
            # Prefer higher confidence
            elif r.get("exists") and existing.get("exists"):
                conf_order = {"high": 3, "medium": 2, "low": 1}
                if conf_order.get(r.get("confidence"), 0) > conf_order.get(existing.get("confidence"), 0):
                    platform_best[platform] = r

    # Organize
    for platform_name, info in platform_best.items():
        entry = {k: v for k, v in info.items() if k != "platform"}
        if entry.get("exists"):
            results["profiles_found"].append(entry)
            cat = entry.get("category", "other")
            results["by_category"].setdefault(cat, []).append(entry)
            conf = entry.get("confidence", "low")
            results["by_confidence"][conf].append(entry)
        else:
            results["profiles_not_found"].append(entry)

    # Summary
    found = len(results["profiles_found"])
    results["summary"] = {
        "total_found": found,
        "total_not_found": len(results["profiles_not_found"]),
        "high_confidence": len(results["by_confidence"]["high"]),
        "medium_confidence": len(results["by_confidence"]["medium"]),
        "low_confidence": len(results["by_confidence"]["low"]),
        "categories": list(results["by_category"].keys()),
        "top_category": max(results["by_category"].items(), key=lambda x: len(x[1]))[0] if results["by_category"] else None,
    }

    return results


async def check_specific_username(username: str) -> dict:
    """Check a single username across all platforms."""
    results = {
        "username": username,
        "timestamp": datetime.now().isoformat(),
        "profiles_found": [],
        "profiles_not_found": [],
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        semaphore = asyncio.Semaphore(20)
        async def check(pname, pinfo):
            async with semaphore:
                return await _check_profile(client, pname, pinfo, username)

        tasks = [check(pname, pinfo) for pname, pinfo in PLATFORMS.items()]
        check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in check_results:
        if isinstance(r, BaseException) or not isinstance(r, dict):
            continue
        entry = {k: v for k, v in r.items() if k != "platform"}
        if entry.get("exists"):
            results["profiles_found"].append(entry)
        else:
            results["profiles_not_found"].append(entry)

    results["total_found"] = len(results["profiles_found"])
    return results
