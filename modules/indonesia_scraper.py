"""
INDONESIA PUBLIC DATA SCRAPER v1 — Public academic & government data.
Searches PDDikti, Garuda, SINTA, and Indonesian public sources.
Uses public web search (dork-style) — no private API, no login bypass.
"""
import re
import asyncio
from datetime import datetime
from urllib.parse import quote_plus
import httpx

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Public Indonesian data sources (search via web, no API key needed)
INDONESIA_SOURCES = {
    "pddikti": {
        "search_url": "https://api-frontend.kemdikbud.go.id/hit_mhs/{query}",
        "label": "PDDikti (Kemdikbud)",
        "type": "academic",
        "description": "Database mahasiswa & dosen Indonesia",
    },
    "garuda": {
        "search_url": "https://garuda.kemdikbud.go.id/author?q={query}",
        "label": "Garuda (Kemdikbud)",
        "type": "research",
        "description": "Portal jurnal ilmiah Indonesia",
    },
    "sinta": {
        "search_url": "https://sinta.kemdikbud.go.id/authors?q={query}",
        "label": "SINTA (Kemdikbud)",
        "type": "research",
        "description": "Science & Technology Index Indonesia",
    },
    "scholar": {
        "search_url": "https://scholar.google.co.id/scholar?q={query}",
        "label": "Google Scholar ID",
        "type": "academic",
        "description": "Google Scholar Indonesia",
    },
}

# Regex for Indonesian phone numbers
PHONE_REGEX_ID = [
    r'(?:\+62|62|0)8[1-9]\d{7,10}',  # Mobile: 08xx
    r'(?:\+62|62|0)2[1-9]\d{6,8}',   # Landline: 02x
    r'(?:\+62|62|0)3[1-9]\d{6,8}',   # Landline: 03x
]

# NIM pattern (8-14 digits, common in Indonesian universities)
NIM_PATTERN = r'\b\d{8,14}\b'


async def _search_pddikti(client: httpx.AsyncClient, name: str) -> dict:
    """Search PDDikti public API for student/lecturer data."""
    result = {
        "source": "pddikti",
        "label": "PDDikti (Kemdikbud)",
        "status": "ok",
        "results": [],
    }
    try:
        url = f"https://api-frontend.kemdikbud.go.id/hit_mhs/{quote_plus(name)}"
        resp = await client.get(url, timeout=12.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and data.get("mahasiswa"):
                for mhs in data["mahasiswa"][:10]:
                    result["results"].append({
                        "name": mhs.get("nama", ""),
                        "nim": mhs.get("nim", ""),
                        "university": mhs.get("nama_pt", ""),
                        "program": mhs.get("nama_prodi", ""),
                        "source_url": f"https://pddikti.kemdikbud.go.id/data_mahasiswa/{mhs.get('id', '')}",
                        "confidence": 75,
                        "status": "publicly_observed",
                    })
            elif isinstance(data, list):
                for mhs in data[:10]:
                    result["results"].append({
                        "name": mhs.get("nama", ""),
                        "nim": mhs.get("nim", ""),
                        "university": mhs.get("nama_pt", mhs.get("namapt", "")),
                        "program": mhs.get("nama_prodi", mhs.get("namaprodi", "")),
                        "source_url": f"https://pddikti.kemdikbud.go.id/data_mahasiswa/{mhs.get('id', '')}",
                        "confidence": 75,
                        "status": "publicly_observed",
                    })
        elif resp.status_code == 404:
            result["results"] = []
        else:
            result["status"] = "error"
            result["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:150]
    return result


async def _search_garuda(client: httpx.AsyncClient, name: str) -> dict:
    """Search Garuda for research publications."""
    result = {
        "source": "garuda",
        "label": "Garuda (Kemdikbud)",
        "status": "ok",
        "results": [],
    }
    try:
        url = f"https://garuda.kemdikbud.go.id/author?q={quote_plus(name)}"
        resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                               timeout=12.0, follow_redirects=True)
        if resp.status_code == 200:
            html = resp.text[:100000]
            # Extract author names and links
            author_pattern = r'<a[^>]*href="(/author/view/\d+)"[^>]*>(.*?)</a>'
            matches = re.findall(author_pattern, html, re.IGNORECASE)
            for path, author_name in matches[:10]:
                clean_name = re.sub(r'<[^>]+>', '', author_name).strip()
                if clean_name and len(clean_name) > 2:
                    result["results"].append({
                        "name": clean_name,
                        "source_url": f"https://garuda.kemdikbud.go.id{path}",
                        "type": "researcher",
                        "confidence": 60,
                        "status": "source_matched",
                    })
        else:
            result["status"] = "limited"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:150]
    return result


async def _search_sinta(client: httpx.AsyncClient, name: str) -> dict:
    """Search SINTA for researcher profiles."""
    result = {
        "source": "sinta",
        "label": "SINTA (Kemdikbud)",
        "status": "ok",
        "results": [],
    }
    try:
        url = f"https://sinta.kemdikbud.go.id/authors?q={quote_plus(name)}"
        resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                               timeout=12.0, follow_redirects=True)
        if resp.status_code == 200:
            html = resp.text[:100000]
            # Extract author cards
            name_pattern = r'<a[^>]*href="(https?://sinta\.kemdikbud\.go\.id/authors/profile/\d+)"[^>]*>(.*?)</a>'
            matches = re.findall(name_pattern, html, re.IGNORECASE)
            for url_match, name_match in matches[:10]:
                clean_name = re.sub(r'<[^>]+>', '', name_match).strip()
                if clean_name and len(clean_name) > 2:
                    result["results"].append({
                        "name": clean_name,
                        "source_url": url_match,
                        "type": "researcher",
                        "confidence": 65,
                        "status": "source_matched",
                    })
        else:
            result["status"] = "limited"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:150]
    return result


async def _search_scholar_id(client: httpx.AsyncClient, name: str) -> dict:
    """Search Google Scholar Indonesia."""
    result = {
        "source": "google_scholar_id",
        "label": "Google Scholar ID",
        "status": "ok",
        "results": [],
    }
    try:
        url = f"https://scholar.google.co.id/scholar?q={quote_plus(name)}&hl=id"
        resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                               timeout=12.0, follow_redirects=True)
        if resp.status_code == 200:
            html = resp.text[:100000]
            # Extract paper titles and links
            paper_pattern = r'<h3[^>]*class="gs_rt"[^>]*>.*?<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>'
            matches = re.findall(paper_pattern, html, re.DOTALL | re.IGNORECASE)
            for paper_url, title in matches[:10]:
                clean_title = re.sub(r'<[^>]+>', '', title).strip()
                if clean_title:
                    result["results"].append({
                        "title": clean_title[:200],
                        "source_url": paper_url if paper_url.startswith("http") else f"https://scholar.google.co.id{paper_url}",
                        "type": "publication",
                        "confidence": 50,
                        "status": "source_matched",
                    })
        else:
            result["status"] = "limited"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:150]
    return result


async def search_indonesia(full_name: str) -> dict:
    """
    Search Indonesian public databases for academic/professional data.
    Sources: PDDikti, Garuda, SINTA, Google Scholar ID.
    All public, no login required, no private scraping.
    """
    if not full_name or not full_name.strip():
        return {"status": "error", "error": "Name required",
                "timestamp": datetime.now().isoformat()}

    results = {
        "query": full_name,
        "timestamp": datetime.now().isoformat(),
        "status": "completed",
        "sources": [],
        "total_results": 0,
        "academic_profiles": [],
        "publications": [],
        "phone_numbers": [],
        "summary": {},
    }

    async with httpx.AsyncClient(
        verify=False,
        timeout=httpx.Timeout(15.0),
        headers={"User-Agent": USER_AGENT},
    ) as client:
        tasks = [
            _search_pddikti(client, full_name),
            _search_garuda(client, full_name),
            _search_sinta(client, full_name),
            _search_scholar_id(client, full_name),
        ]
        source_results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in source_results:
        if isinstance(r, BaseException):
            continue
        if not isinstance(r, dict):
            continue
        results["sources"].append({
            "source": r.get("source", ""),
            "label": r.get("label", ""),
            "status": r.get("status", "error"),
            "count": len(r.get("results", [])),
        })
        for item in r.get("results", []):
            if item.get("type") == "publication":
                results["publications"].append(item)
            else:
                results["academic_profiles"].append(item)

    results["total_results"] = len(results["academic_profiles"]) + len(results["publications"])

    results["summary"] = {
        "total_academic_profiles": len(results["academic_profiles"]),
        "total_publications": len(results["publications"]),
        "sources_checked": len(results["sources"]),
        "sources_with_results": sum(1 for s in results["sources"] if s["count"] > 0),
    }

    if results["total_results"] == 0:
        results["empty_state_reason"] = (
            "No results found from Indonesian academic databases.\n"
            "Possible reasons:\n"
            "- Name not registered in PDDikti/Garuda/SINTA\n"
            "- Name spelling differs from official records\n"
            "- Target is not in academic/research sector\n"
            "- Source temporarily unavailable"
        )

    return results
