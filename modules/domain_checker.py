"""
Domain Checker Module - Domain/website intelligence
WHOIS lookup, DNS records, subdomain enumeration, SSL info, technology stack detection.
"""
import re
import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/1.0; Security Research)"

COMMON_SUBDOMAINS = [
    "www", "mail", "blog", "shop", "api", "dev", "admin",
    "staging", "test", "portal", "cdn", "media", "static",
    "app", "docs", "support", "help", "status", "dashboard",
    "login", "signin", "account", "billing", "payments",
    "secure", "vpn", "remote", "webmail", "cpanel",
    "ftp", "mysql", "db", "ns1", "ns2", "backup",
]

TECH_PATTERNS = {
    "Google Analytics": [r"UA-\d+", r"ga\(.*\)", r"googletagmanager"],
    "Cloudflare": [r"cloudflare", r"__cfduid"],
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "React": [r"react\.", r"__REACT_DEVTOOLS"],
    "Vue.js": [r"vue\.", r"__VUE_DEVTOOLS"],
    "Angular": [r"ng-version", r"angular"],
    "jQuery": [r"jquery[.-]", r"jquery\.com"],
    "Bootstrap": [r"bootstrap[.-]", r"bootstrap\.css"],
    "Nginx": [r"nginx", r"nginx/"],
    "Apache": [r"apache", r"Apache/"],
    "PHP": [r"php", r"PHP/", r"\.php"],
    "Django": [r"django", r"__django"],
    "Laravel": [r"laravel", r"__laravel"],
    "Ruby on Rails": [r"rails", r"protect_from_forgery"],
    "ASP.NET": [r"asp\.net", r"__VIEWSTATE", r"\.aspx"],
    "Express": [r"express", r"x-powered-by.*express"],
    "Next.js": [r"__NEXT_DATA__", r"_next/"],
    "Nuxt.js": [r"__NUXT__", r"_nuxt/"],
    "Gatsby": [r"___gatsby", r"gatsby"],
    "Shopify": [r"shopify", r"myshopify"],
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def _extract_domain(url_or_domain: str) -> str:
    """Extract clean domain from URL or domain string."""
    url_or_domain = url_or_domain.strip().lower()
    if not url_or_domain.startswith(('http://', 'https://')):
        url_or_domain = 'https://' + url_or_domain
    parsed = urlparse(url_or_domain)
    domain = parsed.netloc or parsed.path
    # Remove www prefix
    domain = re.sub(r'^www\.', '', domain)
    # Remove port
    domain = domain.split(':')[0]
    return domain


def _check_ssl(domain: str) -> dict:
    """Check SSL/TLS certificate for a domain."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert.get('notAfter', '')
                issued_str = cert.get('notBefore', '')
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                sans = [x[1] for x in cert.get('subjectAltName', [])]

                # Parse expiry
                try:
                    from datetime import datetime as dt
                    expiry = dt.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    issued = dt.strptime(issued_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - dt.now()).days if expiry > dt.now() else 0
                except Exception:
                    days_left = -1

                return {
                    "valid": True,
                    "issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                    "issued_to": subject.get('commonName', 'Unknown'),
                    "issued_on": issued_str,
                    "expires_on": expiry_str,
                    "days_remaining": days_left,
                    "sans": sans[:20],
                    "version": cert.get('version', 0),
                }
    except ssl.SSLCertificateVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {str(e)[:200]}"}
    except ssl.SSLError as e:
        return {"valid": False, "error": f"SSL error: {str(e)[:200]}"}
    except socket.timeout:
        return {"valid": False, "error": "Connection timeout"}
    except ConnectionRefusedError:
        return {"valid": False, "error": "Connection refused (port 443 closed)"}
    except Exception as e:
        return {"valid": False, "error": str(e)[:200]}


async def _check_subdomain(client: httpx.AsyncClient, domain: str, subdomain: str) -> dict:
    """Check if a subdomain exists."""
    url = f"https://{subdomain}.{domain}"
    try:
        resp = await client.get(url, timeout=8.0, follow_redirects=True)
        return {
            "subdomain": f"{subdomain}.{domain}",
            "status": resp.status_code,
            "exists": resp.status_code < 500,
            "final_url": str(resp.url),
            "server": resp.headers.get("Server", ""),
        }
    except Exception:
        return {"subdomain": f"{subdomain}.{domain}", "status": 0, "exists": False, "final_url": "", "server": ""}


async def _analyze_tech_stack(client: httpx.AsyncClient, url: str) -> dict:
    """Analyze technology stack from response headers and content."""
    tech_found = {}
    try:
        resp = await client.get(url, timeout=15.0, follow_redirects=True)
        html = resp.text[:100000]
        headers = dict(resp.headers)

        # Check headers
        server = headers.get("Server", "")
        powered_by = headers.get("X-Powered-By", "")
        if server:
            tech_found["server_signature"] = server
        if powered_by:
            tech_found["powered_by"] = powered_by

        # Check HTML for tech patterns
        for tech, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if tech not in tech_found:
                        tech_found[tech] = "detected"
                    break

        return tech_found
    except Exception as e:
        return {"error": str(e)[:200]}


async def _check_security_headers(client: httpx.AsyncClient, url: str) -> dict:
    """Check security headers of a website."""
    try:
        resp = await client.head(url, timeout=10.0, follow_redirects=True)
        headers = dict(resp.headers)
        found = {}
        missing = []
        for header in SECURITY_HEADERS:
            if header.lower() in {k.lower(): k for k in headers}:
                found[header] = headers[header]
            else:
                missing.append(header)
        return {
            "present": found,
            "missing": missing,
            "score": len(found),
            "total": len(SECURITY_HEADERS),
            "grade": _security_grade(len(found), len(SECURITY_HEADERS))
        }
    except Exception as e:
        return {"error": str(e)[:200]}


def _security_grade(found: int, total: int) -> str:
    """Calculate security header grade."""
    ratio = found / total
    if ratio >= 0.9: return "A+"
    if ratio >= 0.8: return "A"
    if ratio >= 0.6: return "B"
    if ratio >= 0.4: return "C"
    if ratio >= 0.2: return "D"
    return "F"


async def scan_domain(domain_input: str) -> dict:
    """
    Comprehensive domain scan - SSL, subdomains, tech stack, security headers.
    """
    domain = _extract_domain(domain_input)
    url = f"https://{domain}"

    results = {
        "query": domain_input,
        "clean_domain": domain,
        "timestamp": datetime.now().isoformat(),
        "ssl_info": _check_ssl(domain),
        "subdomains_found": [],
        "tech_stack": {},
        "security_headers": {},
        "whois_hints": _whois_hints(domain),
        "risk_assessment": {},
    }

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, verify=False) as client:
        # Concurrent subdomain checks
        subdomain_tasks = [_check_subdomain(client, domain, sub) for sub in COMMON_SUBDOMAINS]
        sub_results = await asyncio.gather(*subdomain_tasks, return_exceptions=True)

        for r in sub_results:
            if isinstance(r, BaseException) or not isinstance(r, dict):
                continue
            if r.get("exists"):
                results["subdomains_found"].append(r)

        # Tech stack and security headers (sequential to avoid rate limiting)
        results["tech_stack"] = await _analyze_tech_stack(client, url)
        results["security_headers"] = await _check_security_headers(client, url)

    # Risk assessment
    results["risk_assessment"] = _domain_risk_assessment(results)

    return results


def _whois_hints(domain: str) -> dict:
    """Extract WHOIS-like hints from domain name patterns."""
    tld = domain.split('.')[-1] if '.' in domain else ''
    tld_info = {
        "com": "Commercial - Global TLD",
        "org": "Organization - Non-profit common",
        "net": "Network - Infrastructure common",
        "io": "British Indian Ocean Territory - Tech startups",
        "co": "Colombia - Often used as company alternative",
        "id": "Indonesia",
        "my": "Malaysia",
        "sg": "Singapore",
        "uk": "United Kingdom",
        "de": "Germany",
        "jp": "Japan",
        "cn": "China",
        "ru": "Russia",
        "br": "Brazil",
        "in": "India",
        "au": "Australia",
    }
    domain_age_hint = "Unknown (WHOIS lookup requires RDAP/WHOIS client)"
    return {
        "tld": tld,
        "tld_info": tld_info.get(tld, f"Country-code/Generic TLD: .{tld}"),
        "domain_age": domain_age_hint,
        "note": "Full WHOIS requires RDAP client or paid API. This is a domain pattern analysis."
    }


def _domain_risk_assessment(results: dict) -> dict:
    """Assess domain security risks."""
    risks = []
    score = 100

    ssl = results.get("ssl_info", {})
    sec_headers = results.get("security_headers", {})
    subdomains = results.get("subdomains_found", [])

    if not ssl.get("valid"):
        risks.append({"severity": "HIGH", "finding": "Invalid or missing SSL certificate"})
        score -= 30

    if ssl.get("days_remaining", 0) < 30 and ssl.get("days_remaining", 0) > 0:
        risks.append({"severity": "MEDIUM", "finding": f"SSL expiring soon ({ssl['days_remaining']} days)"})
        score -= 15

    missing_headers = sec_headers.get("missing", [])
    if len(missing_headers) > 5:
        risks.append({"severity": "MEDIUM", "finding": f"Missing {len(missing_headers)} security headers"})
        score -= 20
    elif len(missing_headers) > 2:
        risks.append({"severity": "LOW", "finding": f"Missing {len(missing_headers)} security headers"})
        score -= 10

    sensitive_subs = [s for s in subdomains if any(k in s.get("subdomain", "") for k in ["admin", "db", "mysql", "cpanel", "ftp", "backup"])]
    if sensitive_subs:
        risks.append({"severity": "HIGH", "finding": f"Potentially exposed admin subdomains: {len(sensitive_subs)}"})
        score -= 25

    return {
        "risk_score": max(0, score),
        "risk_level": "CRITICAL" if score < 30 else "HIGH" if score < 50 else "MEDIUM" if score < 70 else "LOW",
        "findings": risks,
        "total_findings": len(risks)
    }
