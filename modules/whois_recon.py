"""
WHOIS/DNS Reconnaissance Module
Domain intelligence: WHOIS lookup, DNS records, subdomain enumeration, zone transfer check.
"""
import re
import socket
import ssl
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/3.0; Security Research)"

SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "shop", "api", "dev", "admin", "portal",
    "cdn", "media", "static", "app", "docs", "support", "help", "status",
    "dashboard", "login", "signin", "account", "billing", "payments", "news",
    "secure", "vpn", "webmail", "cpanel", "ftp", "mysql", "db", "ns1", "ns2",
    "backup", "test", "staging", "uat", "demo", "m", "mobile", "monitor",
    "git", "wiki", "jira", "confluence", "jenkins", "grafana", "kibana",
    "prometheus", "registry", "docker", "k8s", "kubernetes", "traefik",
    "auth", "sso", "id", "oauth", "smtp", "imap", "pop3", "vpn2", "proxy",
    "gateway", "firewall", "dns", "dns1", "dns2", "nameserver", "whois",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA", "DMARC"]


def _clean_domain(target: str) -> str:
    """Extract clean domain from URL or domain string."""
    target = target.strip().lower()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split(':')[0]
    return domain


def _whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup using python-whois."""
    try:
        import whois
        w = whois.whois(domain)
        result = {
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "creation_date": _serialize_date(w.creation_date),
            "expiration_date": _serialize_date(w.expiration_date),
            "updated_date": _serialize_date(w.updated_date),
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if w.status else [],
            "emails": w.emails if w.emails else [],
            "org": w.org or "",
            "country": w.country or "",
            "raw_source": "python-whois",
        }
        return result
    except Exception as e:
        return {"domain": domain, "error": str(e)[:200], "available": "whois_failed"}


def _serialize_date(d):
    """Handle WHOIS date serialization (can be list or single)."""
    if not d:
        return None
    if isinstance(d, list):
        return [str(dt) for dt in d[:3] if dt]
    return str(d)


def _dns_lookup(domain: str) -> dict:
    """Perform DNS record lookups."""
    import dns.resolver
    results = {}
    for record_type in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=8)
            records = []
            for rdata in answers:
                records.append(str(rdata))
            if records:
                results[record_type] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.NoNameservers:
            results.setdefault("_errors", []).append(f"{record_type}: no nameservers")
        except Exception as e:
            results.setdefault("_errors", []).append(f"{record_type}: {str(e)[:80]}")
    return results


def _ssl_check(domain: str) -> dict:
    """Check SSL/TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"valid": False, "error": "No certificate returned"}
                subject = dict(x[0] for x in cert.get('subject', []) if x)
                issuer = dict(x[0] for x in cert.get('issuer', []) if x)
                sans = [x[1] for x in cert.get('subjectAltName', [])]
                not_after = cert.get('notAfter', '')
                not_before = cert.get('notBefore', '')

                try:
                    from datetime import datetime as dt
                    expiry = dt.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - dt.now()).days
                except Exception:
                    days_left = -1

                return {
                    "valid": True,
                    "subject_cn": subject.get('commonName', ''),
                    "subject_org": subject.get('organizationName', ''),
                    "issuer_cn": issuer.get('commonName', ''),
                    "issuer_org": issuer.get('organizationName', ''),
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_remaining": days_left,
                    "sans": sans[:20],
                    "sans_count": len(sans),
                }
    except ssl.SSLError as e:
        return {"valid": False, "error": f"SSL error: {str(e)[:150]}"}
    except socket.timeout:
        return {"valid": False, "error": "Connection timeout"}
    except Exception as e:
        return {"valid": False, "error": str(e)[:150]}


async def _check_subdomain(client: httpx.AsyncClient, domain: str, sub: str) -> dict:
    """Check if a subdomain exists."""
    url = f"https://{sub}.{domain}"
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=6.0, follow_redirects=True)
        return {
            "subdomain": f"{sub}.{domain}",
            "status": resp.status_code,
            "exists": resp.status_code < 500,
            "final_url": str(resp.url)[:120],
            "server": resp.headers.get("Server", "")[:80],
        }
    except Exception:
        return {"subdomain": f"{sub}.{domain}", "status": 0, "exists": False}


async def _check_reverse_ip(domain: str) -> dict:
    """Check reverse IP / shared hosting via HackerTarget API (free)."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={domain}",
                timeout=10.0
            )
            text = resp.text.strip()
            if "error" in text.lower() or "API count exceeded" in text:
                return {"sites": [], "count": 0, "note": text[:200]}
            sites = [s.strip() for s in text.split('\n') if s.strip() and not s.startswith('#')]
            return {"sites": sites[:50], "count": len(sites)}
    except Exception as e:
        return {"sites": [], "count": 0, "error": str(e)[:100]}


async def whois_recon(target: str) -> dict:
    """
    Comprehensive WHOIS/DNS reconnaissance.
    WHOIS + DNS records + SSL + subdomains + reverse IP.
    """
    domain = _clean_domain(target)
    results = {
        "query": target,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "whois": _whois_lookup(domain),
        "dns_records": _dns_lookup(domain),
        "ssl": _ssl_check(domain),
        "subdomains": [],
        "reverse_ip": {},
    }

    # Subdomain enumeration (concurrent)
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(8.0)) as client:
        tasks = [_check_subdomain(client, domain, sub) for sub in SUBDOMAIN_WORDLIST[:40]]
        sub_results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in sub_results:
        if isinstance(r, BaseException) or not isinstance(r, dict):
            continue
        if r.get("exists"):
            results["subdomains"].append(r)

    # Reverse IP
    results["reverse_ip"] = await _check_reverse_ip(domain)

    # Summary
    results["summary"] = {
        "total_subdomains": len(results["subdomains"]),
        "dns_record_types": [k for k in results["dns_records"].keys() if k != "_errors"],
        "ssl_valid": results["ssl"].get("valid", False),
        "ssl_days_left": results["ssl"].get("days_remaining", -1),
        "nameservers": len(results["whois"].get("name_servers", [])),
        "whois_available": "error" not in results["whois"],
    }

    return results
