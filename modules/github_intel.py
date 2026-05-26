"""
GITHUB INTELLIGENCE v1 — Public GitHub profile & commit analysis.
Finds public emails, blog links, tech stack, activity, and noreply emails.
No authentication required — uses public GitHub API only.
"""
import re
import asyncio
from datetime import datetime
from typing import Optional
import httpx

from config import ENABLE_GITHUB_INTEL
from services.confidence_scoring import score_email, score_social_profile

USER_AGENT = "OSINT-Tool/4.0"
GITHUB_API = "https://api.github.com"


async def search_github(query: str) -> dict:
    """
    Search GitHub for a user and extract intelligence.
    Takes a username or full name.
    """
    if not ENABLE_GITHUB_INTEL:
        return {
            "status": "disabled",
            "reason": "GitHub intelligence disabled by feature flag",
            "users_found": [],
            "timestamp": datetime.now().isoformat(),
        }

    # Determine if query looks like a username or full name
    is_username = " " not in query and len(query) >= 2

    results = {
        "query": query,
        "is_username_search": is_username,
        "timestamp": datetime.now().isoformat(),
        "profiles_found": [],
        "emails_from_profiles": [],
        "emails_from_commits": [],
        "noreply_emails": [],
        "technology_stacks": [],
        "total_repos_scanned": 0,
        "status": "completed",
    }

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github.v3+json"},
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
    ) as client:

        if is_username:
            # Direct username lookup
            profile = await _get_github_user(client, query)
            if profile:
                results["profiles_found"].append(profile)
        else:
            # Search users by name
            search_results = await _search_github_users(client, query)
            results["profiles_found"] = search_results[:5]

        # For each found profile, extract intelligence
        for profile in results["profiles_found"]:
            username = profile.get("username", "")
            if not username:
                continue

            # Get detailed profile
            detail = await _get_github_user(client, username)
            if detail:
                profile.update(detail)

            # Extract public email
            pub_email = profile.get("email")
            if pub_email:
                conf = score_email(source_type="github", name_match=True)
                results["emails_from_profiles"].append({
                    "email": pub_email,
                    "username": username,
                    "source": "github_profile",
                    "confidence": conf["score"],
                    "confidence_label": conf["label"],
                    "confidence_icon": conf["icon"],
                    "status": "publicly_observed",
                })

            # Extract blog/website
            blog = profile.get("blog", "")
            if blog and blog not in ("", "null", "None"):
                profile["website_extracted"] = blog

            # Scan recent repos for commit metadata
            repos = await _get_user_repos(client, username)
            results["total_repos_scanned"] += len(repos)

            # Extract tech stack
            langs = set()
            for repo in repos:
                lang = repo.get("language")
                if lang:
                    langs.add(lang)
            if langs:
                results["technology_stacks"].append({
                    "username": username,
                    "languages": sorted(langs),
                })

            # Scan README and commit metadata (public only)
            for repo in repos[:5]:
                readme_emails = await _scan_readme(client, username, repo.get("name", ""))
                for e in readme_emails:
                    if "noreply" in e.lower() or "users.noreply" in e.lower():
                        results["noreply_emails"].append({
                            "email": e,
                            "repo": repo.get("name", ""),
                            "source": "readme",
                            "status": "noreply",
                        })
                    else:
                        conf = score_email(source_type="github", name_match=False)
                        results["emails_from_commits"].append({
                            "email": e,
                            "repo": repo.get("name", ""),
                            "source": "readme",
                            "confidence": conf["score"],
                            "confidence_label": conf["label"],
                            "status": "candidate",
                        })

    # Deduplicate emails
    seen = set()
    for key in ["emails_from_profiles", "emails_from_commits"]:
        unique = []
        for item in results[key]:
            if item.get("email", "") not in seen:
                seen.add(item.get("email", ""))
                unique.append(item)
        results[key] = unique

    # Summary
    results["summary"] = {
        "profiles_found": len(results["profiles_found"]),
        "public_emails": len(results["emails_from_profiles"]),
        "repo_emails": len(results["emails_from_commits"]),
        "noreply_emails": len(results["noreply_emails"]),
        "repos_scanned": results["total_repos_scanned"],
        "tech_stacks": [t["languages"] for t in results["technology_stacks"]],
    }

    return results


async def _get_github_user(client: httpx.AsyncClient, username: str) -> Optional[dict]:
    """Get a GitHub user by username."""
    try:
        resp = await client.get(f"{GITHUB_API}/users/{username}")
        if resp.status_code == 200:
            data = resp.json()
            return {
                "username": data.get("login", username),
                "name": data.get("name", ""),
                "bio": data.get("bio", "")[:300] if data.get("bio") else "",
                "email": data.get("email"),
                "blog": data.get("blog", ""),
                "company": data.get("company", ""),
                "location": data.get("location", ""),
                "followers": data.get("followers", 0),
                "following": data.get("following", 0),
                "public_repos": data.get("public_repos", 0),
                "public_gists": data.get("public_gists", 0),
                "profile_url": data.get("html_url", f"https://github.com/{username}"),
                "avatar_url": data.get("avatar_url", ""),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
                "twitter_username": data.get("twitter_username", ""),
                "confidence": 85 if data.get("name") else 60,
                "confidence_label": "High" if data.get("name") else "Medium",
                "status": "profile_found",
            }
    except Exception:
        pass
    return None


async def _search_github_users(client: httpx.AsyncClient, query: str) -> list:
    """Search GitHub users by name."""
    try:
        resp = await client.get(
            f"{GITHUB_API}/search/users",
            params={"q": query, "per_page": 5}
        )
        if resp.status_code == 200:
            data = resp.json()
            users = []
            for item in data.get("items", [])[:5]:
                users.append({
                    "username": item.get("login", ""),
                    "profile_url": item.get("html_url", ""),
                    "avatar_url": item.get("avatar_url", ""),
                    "score": item.get("score", 0),
                    "confidence": 60,
                    "confidence_label": "Medium",
                    "status": "search_result",
                })
            return users
    except Exception:
        pass
    return []


async def _get_user_repos(client: httpx.AsyncClient, username: str) -> list:
    """Get public repos for a user."""
    try:
        resp = await client.get(
            f"{GITHUB_API}/users/{username}/repos",
            params={"per_page": 10, "sort": "updated"}
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


async def _scan_readme(client: httpx.AsyncClient, username: str, repo: str) -> list:
    """Scan README for email addresses."""
    emails = []
    for readme_name in ["README.md", "readme.md", "Readme.md", "README"]:
        try:
            url = f"https://raw.githubusercontent.com/{username}/{repo}/main/{readme_name}"
            resp = await client.get(url, timeout=8.0)
            if resp.status_code == 200:
                text = resp.text[:100000]
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                found = re.findall(email_pattern, text)
                emails.extend(found)
                break
        except Exception:
            continue
    return list(set(emails))
