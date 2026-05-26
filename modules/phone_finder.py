"""
Phone Finder Module - Phone number intelligence
Carrier lookup, number validation, country/region identification, VoIP detection.
"""
import re
from datetime import datetime
from typing import Optional

# Country calling codes
COUNTRY_CODES = {
    "1": {"country": "US/Canada", "name": "North American Numbering Plan"},
    "44": {"country": "UK", "name": "United Kingdom"},
    "62": {"country": "ID", "name": "Indonesia"},
    "60": {"country": "MY", "name": "Malaysia"},
    "65": {"country": "SG", "name": "Singapore"},
    "61": {"country": "AU", "name": "Australia"},
    "63": {"country": "PH", "name": "Philippines"},
    "66": {"country": "TH", "name": "Thailand"},
    "84": {"country": "VN", "name": "Vietnam"},
    "81": {"country": "JP", "name": "Japan"},
    "82": {"country": "KR", "name": "South Korea"},
    "86": {"country": "CN", "name": "China"},
    "91": {"country": "IN", "name": "India"},
    "92": {"country": "PK", "name": "Pakistan"},
    "7": {"country": "RU/KZ", "name": "Russia/Kazakhstan"},
    "49": {"country": "DE", "name": "Germany"},
    "33": {"country": "FR", "name": "France"},
    "39": {"country": "IT", "name": "Italy"},
    "34": {"country": "ES", "name": "Spain"},
    "31": {"country": "NL", "name": "Netherlands"},
    "46": {"country": "SE", "name": "Sweden"},
    "47": {"country": "NO", "name": "Norway"},
    "45": {"country": "DK", "name": "Denmark"},
    "358": {"country": "FI", "name": "Finland"},
    "48": {"country": "PL", "name": "Poland"},
    "380": {"country": "UA", "name": "Ukraine"},
    "55": {"country": "BR", "name": "Brazil"},
    "52": {"country": "MX", "name": "Mexico"},
    "54": {"country": "AR", "name": "Argentina"},
    "56": {"country": "CL", "name": "Chile"},
    "57": {"country": "CO", "name": "Colombia"},
    "20": {"country": "EG", "name": "Egypt"},
    "27": {"country": "ZA", "name": "South Africa"},
    "234": {"country": "NG", "name": "Nigeria"},
    "254": {"country": "KE", "name": "Kenya"},
    "971": {"country": "AE", "name": "UAE"},
    "966": {"country": "SA", "name": "Saudi Arabia"},
    "972": {"country": "IL", "name": "Israel"},
    "90": {"country": "TR", "name": "Turkey"},
    "98": {"country": "IR", "name": "Iran"},
    "880": {"country": "BD", "name": "Bangladesh"},
    "94": {"country": "LK", "name": "Sri Lanka"},
    "95": {"country": "MM", "name": "Myanmar"},
}

# Indonesia prefix/provider mapping
ID_PREFIXES = {
    "0811": ("Telkomsel", "Kartu Halo"),
    "0812": ("Telkomsel", "Simpati"),
    "0813": ("Telkomsel", "Simpati"),
    "0821": ("Telkomsel", "Simpati"),
    "0822": ("Telkomsel", "Simpati"),
    "0823": ("Telkomsel", "Simpati"),
    "0851": ("Telkomsel", "AS"),
    "0852": ("Telkomsel", "AS"),
    "0853": ("Telkomsel", "AS"),
    "0814": ("Indosat", "IM3"),
    "0815": ("Indosat", "IM3/Mentari"),
    "0816": ("Indosat", "IM3/Mentari"),
    "0855": ("Indosat", "IM3"),
    "0856": ("Indosat", "IM3"),
    "0857": ("Indosat", "IM3"),
    "0858": ("Indosat", "Mentari"),
    "0817": ("XL Axiata", "XL"),
    "0818": ("XL Axiata", "XL"),
    "0819": ("XL Axiata", "XL"),
    "0859": ("XL Axiata", "XL"),
    "0877": ("XL Axiata", "XL"),
    "0878": ("XL Axiata", "XL"),
    "0831": ("AXIS", "AXIS"),
    "0832": ("AXIS", "AXIS"),
    "0833": ("AXIS", "AXIS"),
    "0838": ("AXIS", "AXIS"),
    "0881": ("Smartfren", "Smartfren"),
    "0882": ("Smartfren", "Smartfren"),
    "0883": ("Smartfren", "Smartfren"),
    "0884": ("Smartfren", "Smartfren"),
    "0885": ("Smartfren", "Smartfren"),
    "0886": ("Smartfren", "Smartfren"),
    "0887": ("Smartfren", "Smartfren"),
    "0888": ("Smartfren", "Smartfren"),
    "0889": ("Smartfren", "Smartfren"),
    "0896": ("3 (Tri)", "Tri"),
    "0897": ("3 (Tri)", "Tri"),
    "0898": ("3 (Tri)", "Tri"),
    "0899": ("3 (Tri)", "Tri"),
    "0895": ("3 (Tri)", "Tri"),
    "0828": ("Ceria", "Ceria"),
    "0899": ("3 (Tri)", "Tri"),
}

# US area codes by region
US_AREA_CODES = {
    "201": "New Jersey (Jersey City)",
    "212": "New York (Manhattan)",
    "213": "California (Los Angeles)",
    "310": "California (Los Angeles)",
    "312": "Illinois (Chicago)",
    "404": "Georgia (Atlanta)",
    "415": "California (San Francisco)",
    "425": "Washington (Seattle)",
    "510": "California (Oakland)",
    "512": "Texas (Austin)",
    "602": "Arizona (Phoenix)",
    "617": "Massachusetts (Boston)",
    "702": "Nevada (Las Vegas)",
    "713": "Texas (Houston)",
    "718": "New York (Brooklyn/Queens)",
    "786": "Florida (Miami)",
    "818": "California (Los Angeles)",
    "917": "New York (NYC Mobile)",
}

# VoIP and virtual number prefixes
VOIP_PATTERNS = [
    r"^\+?1?[2-9]\d{2}555\d{4}$",  # 555 numbers (fictional/VoIP)
    r"^\+?44\d{2}4960\d+",  # UK VoIP ranges
]

# Premium/toll numbers
PREMIUM_PREFIXES = [
    "1900", "1976", "1977",  # US premium
    "0900", "0906", "0909",  # UK premium
    "0804",  # Indonesia premium
]


def _clean_phone(phone: str) -> str:
    """Clean phone number to digits only."""
    return re.sub(r'[^\d+]', '', phone.strip())


def _detect_country(phone: str) -> dict:
    """Detect country from phone number prefix."""
    clean = _clean_phone(phone)

    # Remove + if present
    if clean.startswith('+'):
        clean = clean[1:]

    for code, info in sorted(COUNTRY_CODES.items(), key=lambda x: len(x[0]), reverse=True):
        if clean.startswith(code):
            return {
                "country_code": f"+{code}",
                "country": info["country"],
                "country_name": info["name"],
                "national_number": clean[len(code):]
            }

    # Default - attempt to guess
    if clean.startswith('0'):
        return {"country_code": "unknown", "country": "Unknown (local format)", "country_name": "Unknown", "national_number": clean[1:]}
    return {"country_code": "unknown", "country": "Unknown", "country_name": "Unknown", "national_number": clean}


def _detect_id_provider(phone: str) -> dict:
    """Detect Indonesian mobile provider from prefix."""
    clean = _clean_phone(phone)

    # Remove country code if present
    if clean.startswith('+62'):
        clean = '0' + clean[3:]
    elif clean.startswith('62'):
        clean = '0' + clean[2:]

    for prefix, (provider, product) in sorted(ID_PREFIXES.items(), key=lambda x: len(x[0]), reverse=True):
        if clean.startswith(prefix):
            return {
                "provider": provider,
                "product": product,
                "prefix": prefix,
                "type": "Mobile"
            }

    # Landline detection for Indonesia
    if clean.startswith('021'):
        return {"provider": "Telkom Indonesia", "product": "Landline Jakarta", "prefix": "021", "type": "Landline"}
    if clean.startswith('031'):
        return {"provider": "Telkom Indonesia", "product": "Landline Surabaya", "prefix": "031", "type": "Landline"}
    if clean.startswith('022'):
        return {"provider": "Telkom Indonesia", "product": "Landline Bandung", "prefix": "022", "type": "Landline"}

    return {"provider": "Unknown", "product": "Unknown", "prefix": clean[:4] if len(clean) >= 4 else clean, "type": "Unknown"}


def _check_voip(phone: str) -> dict:
    """Check if phone number is likely VoIP/virtual."""
    for pattern in VOIP_PATTERNS:
        if re.match(pattern, phone):
            return {"is_voip": True, "confidence": "high", "note": "Pattern matches known VoIP range"}
    return {"is_voip": False, "confidence": "low", "note": "Not in known VoIP range"}


def _check_premium(phone: str) -> dict:
    """Check if phone number is premium/toll."""
    clean = _clean_phone(phone)
    for prefix in PREMIUM_PREFIXES:
        if prefix in clean:
            return {"is_premium": True, "prefix": prefix, "note": "Premium/toll number - high cost calls"}
    return {"is_premium": False}


def _validate_format(phone: str) -> dict:
    """Validate phone number format."""
    clean = _clean_phone(phone)
    digits_only = re.sub(r'\D', '', phone)

    issues = []
    if len(digits_only) < 7:
        issues.append("Too short (< 7 digits)")
    if len(digits_only) > 15:
        issues.append("Too long (> 15 digits)")
    if re.search(r'(.)\1{6,}', digits_only):
        issues.append("Repeated digit pattern (possible fake)")

    return {
        "valid": len(issues) == 0,
        "digit_count": len(digits_only),
        "issues": issues,
        "format": _identify_format(digits_only)
    }


def _identify_format(digits: str) -> str:
    """Identify phone number format type."""
    if re.match(r'^0\d{8,12}$', digits):
        return "Local format (leading 0)"
    if re.match(r'^\+?\d{10,15}$', digits):
        return "International format"
    if re.match(r'^\d{3}-\d{3}-\d{4}$', digits):
        return "US format (XXX-XXX-XXXX)"
    return "Unknown format"


def _us_area_code(phone: str) -> Optional[dict]:
    """Look up US area code."""
    clean = _clean_phone(phone)
    if clean.startswith('+1'):
        clean = clean[2:]
    elif clean.startswith('1'):
        clean = clean[1:]

    area = clean[:3]
    if area in US_AREA_CODES:
        return {"area_code": area, "region": US_AREA_CODES[area]}
    return None


def _generate_phone_variants(phone: str) -> list:
    """Generate possible phone number variants."""
    clean = _clean_phone(phone)
    variants = []
    digits = re.sub(r'\D', '', clean)

    if len(digits) >= 10:
        variants.append({
            "format": "WhatsApp Link",
            "value": f"https://wa.me/{digits}",
            "note": "Direct WhatsApp link"
        })
        variants.append({
            "format": "Telegram Link",
            "value": f"https://t.me/+{digits}",
            "note": "Direct Telegram link"
        })
        variants.append({
            "format": "Call Link",
            "value": f"tel:+{digits}",
            "note": "Direct call link"
        })

    return variants


async def analyze_phone(phone: str) -> dict:
    """
    Comprehensive phone number analysis.
    Detects country, provider, type, validity, and generates intelligence.
    """
    clean = _clean_phone(phone)

    results = {
        "query": phone,
        "cleaned": clean,
        "timestamp": datetime.now().isoformat(),
        "country_info": _detect_country(phone),
        "validation": _validate_format(phone),
        "voip_check": _check_voip(clean),
        "premium_check": _check_premium(clean),
        "provider_info": {},
        "area_info": {},
        "variants": _generate_phone_variants(phone),
        "risk_indicators": [],
        "osint_links": _generate_osint_links(clean),
    }

    # Provider detection based on country
    country = results["country_info"].get("country", "")
    if "ID" in country or "Indonesia" in country:
        results["provider_info"] = _detect_id_provider(phone)

    # US area code
    area = _us_area_code(phone)
    if area:
        results["area_info"] = area

    # Risk indicators
    if results["voip_check"]["is_voip"]:
        results["risk_indicators"].append({
            "level": "MEDIUM",
            "indicator": "VoIP/Virtual Number",
            "detail": "Number is likely virtual - harder to trace to physical location"
        })
    if results["premium_check"]["is_premium"]:
        results["risk_indicators"].append({
            "level": "LOW",
            "indicator": "Premium/Toll Number",
            "detail": "Calling this number may incur high charges"
        })
    if not results["validation"]["valid"]:
        results["risk_indicators"].append({
            "level": "HIGH",
            "indicator": "Invalid Format",
            "detail": f"Format issues: {', '.join(results['validation']['issues'])}"
        })

    return results


def _generate_osint_links(phone: str) -> list:
    """Generate OSINT search links for the phone number."""
    digits = re.sub(r'\D', '', phone)
    return [
        {
            "source": "Google Search",
            "url": f"https://www.google.com/search?q=%22{digits}%22",
            "note": "Search phone in quotes"
        },
        {
            "source": "Truecaller (Web)",
            "url": f"https://www.truecaller.com/search/id/{digits}",
            "note": "Truecaller lookup (ID region)"
        },
        {
            "source": "WhatsApp Check",
            "url": f"https://wa.me/{digits}",
            "note": "Check if number has WhatsApp"
        },
        {
            "source": "Signal Check",
            "url": f"https://signal.me/#p/+{digits}",
            "note": "Check if number has Signal"
        },
        {
            "source": "FaceCheck ID",
            "url": "https://facecheck.id",
            "note": "Reverse image/phone lookup"
        },
    ]
