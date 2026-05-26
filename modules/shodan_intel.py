"""
Shodan Intel Module — IoT/device search, open ports, banners.
Uses free Shodan search (no API key) and HackerTarget fallback.
"""
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx
import socket

USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Tool/3.0)"


def _get_ip(domain: str) -> str:
    """Resolve domain to IP."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def _shodan_free_search(ip: str) -> dict:
    """Shodan-style free scan using public sources."""

    ports_to_check = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                      3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]

    open_ports = []
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass

    return {
        "ip": ip,
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "common_services": _identify_services(open_ports),
        "method": "socket_scan",
    }


def _identify_services(ports: list) -> list:
    """Map ports to common services."""
    port_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
        995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        9200: "Elasticsearch", 27017: "MongoDB",
    }
    return [{"port": p, "service": port_map.get(p, "Unknown")} for p in ports]


async def _shodan_web_search(client: httpx.AsyncClient, query: str) -> dict:
    """Search Shodan via web interface (free, rate-limited)."""
    try:
        resp = await client.get(
            f"https://www.shodan.io/search?query={quote_plus(query)}",
            headers={"User-Agent": USER_AGENT}, timeout=12.0, follow_redirects=True
        )
        html = resp.text[:50000]
        # Extract result counts from HTML
        count_match = __import__('re').search(r'([\d,]+)\s+results?', html, __import__('re').IGNORECASE)
        count = int(count_match.group(1).replace(',', '')) if count_match else 0
        return {"query": query, "results_count": count, "source": "shodan_web"}
    except Exception as e:
        return {"query": query, "results_count": 0, "error": str(e)[:100]}


async def _hackertarget_scan(client: httpx.AsyncClient, domain: str) -> dict:
    """Scan domain using HackerTarget free API."""
    scans = {}
    endpoints = {
        "port_scan": f"https://api.hackertarget.com/nmap/?q={quote_plus(domain)}",
        "dns_lookup": f"https://api.hackertarget.com/dnslookup/?q={quote_plus(domain)}",
    }
    for name, url in endpoints.items():
        try:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=15.0)
            text = resp.text.strip()
            if "error" not in text.lower() and "count exceeded" not in text.lower():
                scans[name] = text[:2000]
            else:
                scans[name] = f"API: {text[:100]}"
        except Exception as e:
            scans[name] = f"Error: {str(e)[:100]}"
    return scans


async def shodan_intel(target: str) -> dict:
    """Shodan-style intelligence on target domain/IP."""
    import re as _re
    from urllib.parse import urlparse as _up

    # Clean target
    domain = target.strip().lower()
    if domain.startswith(('http://', 'https://')):
        domain = _up(domain).netloc or domain
    domain = domain.split(':')[0]
    domain = _re.sub(r'^www\.', '', domain)

    ip = _get_ip(domain)

    results = {
        "query": target,
        "domain": domain,
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "port_scan": {},
        "shodan_web": {},
        "hackertarget": {},
        "summary": {},
    }

    if ip:
        results["port_scan"] = _shodan_free_search(ip)

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        results["shodan_web"] = await _shodan_web_search(client, domain)
        results["hackertarget"] = await _hackertarget_scan(client, domain)

    ps = results["port_scan"]
    results["summary"] = {
        "open_ports": ps.get("total_open", 0),
        "services_exposed": len(ps.get("common_services", [])),
        "critical_ports": [p for p in ps.get("open_ports", []) if p in [22, 23, 3389, 3306, 6379, 9200, 27017]],
        "shodan_results": results["shodan_web"].get("results_count", 0),
    }

    return results
