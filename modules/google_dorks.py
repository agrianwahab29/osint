"""
Google Dorking Module — 60+ automated Google/Bing/DuckDuckGo search queries.
Finds exposed documents, login pages, directory listings, sensitive files.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0"

# 60+ dork queries organized by category
DORK_CATEGORIES = {
    "exposed_documents": {
        "label": "Exposed Documents",
        "severity": "MEDIUM",
        "queries": [
            'site:{domain} filetype:pdf "confidential"',
            'site:{domain} filetype:doc OR filetype:docx "internal"',
            'site:{domain} filetype:xls OR filetype:xlsx "password"',
            'site:{domain} filetype:csv "email" OR "username"',
            'site:{domain} filetype:sql "INSERT INTO"',
            'site:{domain} filetype:log "error" OR "debug"',
            'site:{domain} filetype:bak OR filetype:backup',
            'site:{domain} filetype:env OR filetype:yml',
        ]
    },
    "login_panels": {
        "label": "Login / Admin Panels",
        "severity": "HIGH",
        "queries": [
            'site:{domain} inurl:admin',
            'site:{domain} inurl:login',
            'site:{domain} inurl:dashboard',
            'site:{domain} intitle:"login" OR intitle:"sign in"',
            'site:{domain} inurl:wp-admin',
            'site:{domain} inurl:phpmyadmin',
            'site:{domain} inurl:jenkins OR inurl:grafana',
            'site:{domain} inurl:8080 OR inurl:8443',
        ]
    },
    "directory_listing": {
        "label": "Directory Listings",
        "severity": "MEDIUM",
        "queries": [
            'site:{domain} intitle:"index of"',
            'site:{domain} intitle:"index of" "parent directory"',
            'site:{domain} "Index of /" +passwd',
            'site:{domain} intitle:"index of" .htpasswd',
            'site:{domain} intitle:"index of" "server-status"',
        ]
    },
    "sensitive_info": {
        "label": "Sensitive Information",
        "severity": "CRITICAL",
        "queries": [
            'site:{domain} "password" OR "passwd"',
            'site:{domain} "api_key" OR "api_secret" OR "api key"',
            'site:{domain} "AWS_SECRET" OR "aws_access_key"',
            'site:{domain} "BEGIN RSA PRIVATE KEY"',
            'site:{domain} "private key" filetype:pem',
            'site:{domain} "token" OR "secret" filetype:json',
            'site:{domain} "connectionString" OR "connection string"',
            'site:{domain} "smtp" OR "mail_password"',
        ]
    },
    "config_files": {
        "label": "Configuration Files",
        "severity": "HIGH",
        "queries": [
            'site:{domain} filetype:env "DB_"',
            'site:{domain} filetype:config "connection"',
            'site:{domain} filetype:ini "password"',
            'site:{domain} inurl:web.config OR .htaccess',
            'site:{domain} filetype:properties "jdbc"',
            'site:{domain} filetype:yaml OR filetype:yml "password"',
        ]
    },
    "error_messages": {
        "label": "Error Messages / Debug",
        "severity": "MEDIUM",
        "queries": [
            'site:{domain} "stack trace" OR "stacktrace"',
            'site:{domain} "exception" OR "error" intext:"at line"',
            'site:{domain} "Fatal error" OR "Parse error"',
            'site:{domain} "SQL syntax" OR "MySQL Error"',
            'site:{domain} "Warning: mysql_connect"',
        ]
    },
    "exposed_services": {
        "label": "Exposed Services",
        "severity": "HIGH",
        "queries": [
            'site:{domain} intitle:"Apache Status"',
            'site:{domain} intitle:"phpinfo()"',
            'site:{domain} inurl:"/server-status"',
            'site:{domain} intitle:"Swagger UI"',
            'site:{domain} inurl:"/graphql" OR inurl:"/graphiql"',
            'site:{domain} inurl:"/actuator" OR inurl:"/health"',
        ]
    },
    "email_sources": {
        "label": "Email Harvesting",
        "severity": "LOW",
        "queries": [
            'site:{domain} "@{domain}"',
            'site:{domain} intext:"@gmail.com" OR intext:"@yahoo.com"',
            'site:{domain} "email" OR "contact" OR "reach us"',
        ]
    },
}

# Search engines for dork queries
SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={query}&num=20",
    "bing": "https://www.bing.com/search?q={query}&count=20",
    "ddg": "https://html.duckduckgo.com/html/?q={query}",
}


def _extract_results(html: str, engine: str) -> list:
    """Extract links from search result pages."""
    results = []
    seen = set()

    patterns = [
        r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
        r'<a[^>]*class="[^"]*result[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        for url, title in matches:
            title = re.sub(r'<[^>]+>', '', title).strip()
            title = re.sub(r'\s+', ' ', title)
            if not title or len(title) < 3 or url in seen:
                continue
            if any(s in url.lower() for s in ['google.com', 'bing.com', '/search']):
                continue
            seen.add(url)
            results.append({"title": title[:200], "url": url, "engine": engine})

    return results


async def _run_dork(client: httpx.AsyncClient, query: str, category: str,
                     severity: str, engine: str = "google") -> dict:
    """Execute a single dork query."""
    encoded = quote_plus(query)
    url = SEARCH_ENGINES.get(engine, SEARCH_ENGINES["google"]).format(query=encoded)

    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=12.0, follow_redirects=True)
        results = _extract_results(resp.text[:60000], engine)
        return {
            "query": query,
            "category": category,
            "severity": severity,
            "engine": engine,
            "results_count": len(results),
            "results": results[:10],
        }
    except Exception as e:
        return {
            "query": query, "category": category, "severity": severity,
            "engine": engine, "results_count": 0, "results": [], "error": str(e)[:100]
        }


async def google_dorks(target: str) -> dict:
    """Run automated Google dorking against a domain or name."""
    # Determine if target is domain or name
    is_domain = "." in target and " " not in target and "@" not in target
    domain = target if is_domain else ""
    name = target if not is_domain else ""

    results = {
        "query": target,
        "target_type": "domain" if is_domain else "name",
        "domain": domain,
        "name": name,
        "timestamp": datetime.now().isoformat(),
        "categories": {},
        "total_findings": 0,
        "critical_findings": 0,
        "high_findings": 0,
        "summary": {},
    }

    # Build queries by replacing {domain} and {name}
    all_queries = []
    for cat_name, cat_info in DORK_CATEGORIES.items():
        for query_template in cat_info["queries"]:
            query = query_template.format(domain=domain, name=name)
            all_queries.append((query, cat_name, cat_info["severity"]))

    # Run queries concurrently
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        semaphore = asyncio.Semaphore(5)

        async def run_with_limit(query, cat, sev):
            async with semaphore:
                return await _run_dork(client, query, cat, sev)

        tasks = [run_with_limit(q, c, s) for q, c, s in all_queries]
        dork_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Organize by category
    for r in dork_results:
        if isinstance(r, BaseException) or not isinstance(r, dict):
            continue
        cat = r.get("category", "unknown")
        results["categories"].setdefault(cat, {
            "label": DORK_CATEGORIES.get(cat, {}).get("label", cat),
            "severity": r.get("severity", "INFO"),
            "queries": [],
            "total_results": 0,
        })
        results["categories"][cat]["queries"].append(r)
        results["categories"][cat]["total_results"] += r.get("results_count", 0)
        results["total_findings"] += r.get("results_count", 0)
        if r.get("severity") == "CRITICAL" and r.get("results_count", 0) > 0:
            results["critical_findings"] += 1
        if r.get("severity") == "HIGH" and r.get("results_count", 0) > 0:
            results["high_findings"] += 1

    results["summary"] = {
        "total_queries": len(all_queries),
        "total_findings": results["total_findings"],
        "critical_categories": results["critical_findings"],
        "high_categories": results["high_findings"],
        "categories_checked": list(results["categories"].keys()),
    }

    return results
