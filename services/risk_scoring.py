"""
RISK SCORING SERVICE — Aggregates findings into a risk profile.
"""
from datetime import datetime
from typing import Optional
from config import RISK_LABELS


# Risk factor weights
RISK_WEIGHTS = {
    "public_email_found": 15,
    "github_email_exposed": 10,
    "phone_found_high_confidence": 20,
    "password_in_pwned": 30,
    "dmarc_missing": 10,
    "spf_weak": 10,
    "social_footprint_high": 10,
    "breach_confirmed": 25,
    "credential_leak": 30,
    "darkweb_mention": 20,
    "hsts_missing": 5,
    "tls_expiring": 8,
    "subdomain_exposure": 5,
    "candidate_email_count_high": 5,
}


def calculate_risk(findings: list, domain_data: Optional[dict] = None,
                   breach_data: Optional[dict] = None) -> dict:
    """
    Calculate overall risk score from findings.

    Returns: {risk_score, risk_level, risk_reasons, risk_factors}
    """
    score = 0
    reasons = []
    factors = {}

    # Analyze each finding
    for f in findings:
        ftype = f.get("finding_type", "")
        fstatus = f.get("status", "")
        conf = f.get("confidence", 0)

        if ftype == "publicly_found_email":
            if conf >= 75:
                score += RISK_WEIGHTS["public_email_found"]
                reasons.append("Public email found with high confidence")
                factors["public_email_found"] = True

        elif ftype == "github_commit_email":
            if conf >= 60:
                score += RISK_WEIGHTS["github_email_exposed"]
                reasons.append("GitHub commit email exposed")
                factors["github_email_exposed"] = True

        elif ftype == "phone":
            if conf >= 60:
                score += RISK_WEIGHTS["phone_found_high_confidence"]
                reasons.append("Phone number found with high confidence")
                factors["phone_found_high_confidence"] = True

        elif ftype == "breached_email":
            score += RISK_WEIGHTS["breach_confirmed"]
            reasons.append("Email found in known data breach")
            factors["breach_confirmed"] = True

        elif ftype == "pwned_password":
            score += RISK_WEIGHTS["password_in_pwned"]
            reasons.append("Password found in Pwned Passwords database")
            factors["password_in_pwned"] = True

        elif ftype == "social_profile" and conf >= 70:
            if factors.get("social_count", 0) < 3:
                factors["social_count"] = factors.get("social_count", 0) + 1
        elif ftype in ("darkweb_mention", "credential_leak"):
            score += RISK_WEIGHTS.get(ftype, 15)
            reasons.append(f"Potential exposure: {ftype}")

    # Check social footprint
    if factors.get("social_count", 0) >= 5:
        score += RISK_WEIGHTS["social_footprint_high"]
        reasons.append("High social media footprint detected")
        factors["social_footprint_high"] = True

    # Domain security analysis
    if domain_data:
        dmarc = domain_data.get("dmarc_record") or {}
        spf = domain_data.get("spf_record") or {}
        headers = domain_data.get("security_headers", {})

        if not dmarc.get("found"):
            score += RISK_WEIGHTS["dmarc_missing"]
            reasons.append("DMARC record missing on domain")
            factors["dmarc_missing"] = True

        if spf.get("too_permissive"):
            score += RISK_WEIGHTS["spf_weak"]
            reasons.append("SPF record is too permissive (+all)")
            factors["spf_weak"] = True

        if not headers.get("hsts"):
            score += RISK_WEIGHTS["hsts_missing"]
            reasons.append("HSTS header missing")
            factors["hsts_missing"] = True

        ssl = domain_data.get("ssl_info", {})
        if ssl.get("days_remaining", 365) < 30:
            score += RISK_WEIGHTS["tls_expiring"]
            reasons.append("TLS certificate expiring soon")
            factors["tls_expiring"] = True

    # Determine risk level
    if score >= 70:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "NONE"

    label_info = RISK_LABELS.get(level, ("Unknown", "⚪", "gray"))

    return {
        "risk_score": min(100, score),
        "risk_level": level,
        "risk_label": label_info[0],
        "risk_icon": label_info[1],
        "risk_color": label_info[2],
        "risk_reasons": reasons if reasons else ["No significant risk factors detected"],
        "risk_factors": factors,
        "scored_at": datetime.now().isoformat(),
    }
