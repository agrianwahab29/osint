"""
VirusTotal Intel Module — Domain/IP reputation check.
Uses free VirusTotal web search (no API key) + HackerTarget DNS health.
"""
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx
import socket
import re as _re

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0"


def _get_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


async def _vt_web_search(client: httpx.AsyncClient, domain: str) -> dict:
    """Search VirusTotal web interface for domain report."""
    try:
        resp = await client.get(
            f"https://www.virustotal.com/gui/domain/{domain}",
            headers={"User-Agent": USER_AGENT}, timeout=12.0, follow_redirects=True
        )
        html = resp.text[:40000]
        text = html.lower()

        # Extract detection ratio
        detections = _re.findall(r'(\d+)\s*/\s*(\d+)\s*security vendors', text)
        ratio = {"detected": int(detections[0][0]), "total": int(detections[0][1])} if detections else None

        return {
            "url": f"https://www.virustotal.com/gui/domain/{domain}",
            "detection_ratio": ratio,
            "has_results": resp.status_code == 200,
            "source": "virustotal_web",
        }
    except Exception as e:
        return {"error": str(e)[:100], "has_results": False, "source": "virustotal_web"}


async def _ip_reputation(client: httpx.AsyncClient, ip: str) -> dict:
    """Check IP reputation via AbuseIPDB web (free)."""
    try:
        resp = await client.get(
            f"https://www.abuseipdb.com/check/{ip}",
            headers={"User-Agent": USER_AGENT}, timeout=10.0, follow_redirects=True
        )
        html = resp.text[:30000]
        text = html.lower()
        score_match = _re.findall(r'confidence of abuse.*?(\d+)%', text)
        score = int(score_match[0]) if score_match else None
        return {"ip": ip, "abuse_score": score, "source": "abuseipdb_web"}
    except Exception:
        return {"ip": ip, "abuse_score": None, "source": "abuseipdb_web", "error": "unavailable"}


async def _check_blacklists(client: httpx.AsyncClient, domain: str) -> dict:
    """Check domain against public blacklists."""
    blacklists = {
        "Google Safe Browsing": f"https://transparencyreport.google.com/safe-browsing/search?url={quote_plus(domain)}",
        "PhishTank": f"https://www.phishtank.com/search.php?query={quote_plus(domain)}",
        "URLVoid": f"https://www.urlvoid.com/scan/{domain}",
    }
    results = {}
    for name, url in blacklists.items():
        try:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT}, timeout=10.0)
            text = resp.text.lower()[:10000]
            flagged = any(w in text for w in ["unsafe", "phishing", "malware", "blacklist", "reported", "flagged"])
            results[name] = {"flagged": flagged, "status": resp.status_code}
        except Exception as e:
            results[name] = {"flagged": False, "error": str(e)[:80]}
    return results


async def virustotal_intel(target: str) -> dict:
    """VirusTotal + blacklist intelligence for domain/IP."""
    domain = target.strip().lower()
    if domain.startswith(('http://', 'https://')):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc or domain
    domain = domain.split(':')[0]
    domain = _re.sub(r'^www\.', '', domain)
    ip = _get_ip(domain)

    results = {
        "query": target,
        "domain": domain,
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "virustotal": {},
        "abuseipdb": {},
        "blacklists": {},
        "summary": {},
    }

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0)) as client:
        results["virustotal"] = await _vt_web_search(client, domain)
        if ip:
            results["abuseipdb"] = await _ip_reputation(client, ip)
        results["blacklists"] = await _check_blacklists(client, domain)

    vt = results["virustotal"]
    bl = results["blacklists"]
    ab = results["abuseipdb"]

    results["summary"] = {
        "vt_detections": vt.get("detection_ratio", {}).get("detected", 0) if vt.get("detection_ratio") else None,
        "vt_total_engines": vt.get("detection_ratio", {}).get("total", 0) if vt.get("detection_ratio") else None,
        "abuse_score": ab.get("abuse_score"),
        "blacklists_flagged": sum(1 for v in bl.values() if v.get("flagged")),
        "blacklists_total": len(bl),
        "risk_level": _assess_risk(vt, bl, ab),
    }

    return results


def _assess_risk(vt: dict, bl: dict, ab: dict) -> str:
    score = 0
    if vt.get("detection_ratio"):
        score += min(vt["detection_ratio"].get("detected", 0) * 5, 50)
    if ab.get("abuse_score", 0):
        score += min(ab["abuse_score"], 100) // 5
    bl_flagged = sum(1 for v in bl.values() if v.get("flagged"))
    score += bl_flagged * 15
    if score >= 60: return "CRITICAL"
    if score >= 30: return "HIGH"
    if score >= 10: return "MEDIUM"
    return "LOW"
