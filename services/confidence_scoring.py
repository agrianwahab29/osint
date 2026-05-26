"""
CONFIDENCE SCORING SERVICE — Forensic-grade confidence scoring
Standardized scoring across all OSINT findings.
"""
import hashlib
import re
from datetime import datetime
from typing import Optional


def score_email(
    source_type: str,
    name_match: bool = False,
    domain_provided: bool = False,
    found_on_official_page: bool = False,
    source_url: Optional[str] = None,
) -> dict:
    """
    Score an email finding based on how it was discovered.

    source_type: 'public_page', 'github', 'pdf', 'pattern_generated', 'hunter_api'
    """
    if source_type == "public_page":
        if found_on_official_page and name_match:
            score = 92
        elif name_match:
            score = 85
        else:
            score = 75
    elif source_type == "github":
        score = 85 if name_match else 70
    elif source_type == "pdf":
        score = 75 if name_match else 60
    elif source_type == "pattern_generated":
        score = 45 if domain_provided else 25
    elif source_type == "hunter_api":
        score = 85 if name_match else 70
    else:
        score = 40

    return _build_confidence(score)


def score_social_profile(
    username_match: bool = False,
    name_match: bool = False,
    bio_match: bool = False,
    photo_match: bool = False,
    platform_confidence: str = "medium",
) -> dict:
    """Score a social media profile finding."""
    if username_match and name_match and (bio_match or photo_match):
        score = 95
    elif username_match and name_match:
        score = 80
    elif username_match:
        score = 60
    elif name_match:
        score = 40
    elif platform_confidence == "low":
        score = 20
    else:
        score = 30

    return _build_confidence(score)


def score_phone(
    source_reliability: str,
    region_match: bool = False,
    country: str = "ID",
) -> dict:
    """
    Score a phone number finding.

    source_reliability: 'official_page', 'public_document', 'aggregator_us', 'aggregator'
    """
    if source_reliability == "official_page":
        score = 95
    elif source_reliability == "public_document" and region_match:
        score = 75
    elif source_reliability == "aggregator" and region_match:
        score = 40
    elif source_reliability == "aggregator_us" and country != "US":
        score = 15
    elif source_reliability == "aggregator_us":
        score = 30
    else:
        score = 10

    return _build_confidence(score)


def score_domain(
    has_dmarc: bool = False,
    has_spf: bool = False,
    has_dkim: bool = False,
    has_hsts: bool = False,
    tls_valid: bool = False,
    security_headers_count: int = 0,
) -> dict:
    """Score domain security posture."""
    score = 50  # baseline
    if has_dmarc: score += 10
    if has_spf: score += 5
    if has_dkim: score += 5
    if has_hsts: score += 5
    if tls_valid: score += 10
    score += min(security_headers_count * 3, 15)
    return _build_confidence(min(100, score))


def score_breach(breach_count: int, is_sensitive: bool = False,
                has_passwords: bool = False) -> dict:
    """Score a breach finding."""
    if has_passwords:
        score = 95
    elif is_sensitive:
        score = 85
    elif breach_count > 5:
        score = 75
    elif breach_count > 0:
        score = 60
    else:
        score = 50
    return _build_confidence(score)


def _build_confidence(score: int) -> dict:
    """Build standard confidence object."""
    from config import CONFIDENCE_LABELS

    label = "Unknown"
    icon = "⚪"
    for (low, high), (lbl, ico) in CONFIDENCE_LABELS.items():
        if low <= score <= high:
            label = lbl
            icon = ico
            break

    return {
        "score": score,
        "label": label,
        "icon": icon,
        "scored_at": datetime.now().isoformat(),
    }


def generate_finding_id() -> str:
    """Generate a unique finding ID: FND-XXXXXX."""
    import uuid
    return f"FND-{uuid.uuid4().hex[:6].upper()}"


def generate_evidence_hash(content: str) -> str:
    """Generate SHA-256 hash of evidence content."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def extract_emails_from_text(text: str) -> list[str]:
    """Extract email addresses from text using regex."""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(pattern, text)
    # Filter out image asset patterns
    excluded = ['png@', 'jpg@', 'svg@', 'js@', 'css@', 'webp@', 'ico@',
                '@2x', '@3x', 'example.com', 'domain.com', 'email.com']
    filtered = []
    for e in emails:
        if any(ex in e.lower() for ex in excluded):
            continue
        filtered.append(e.lower())
    return list(set(filtered))
