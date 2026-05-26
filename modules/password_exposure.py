"""
PASSWORD EXPOSURE CHECK v1 — k-anonymity via HIBP Pwned Passwords API.
SHA-1 computed locally. Only first 5 chars of hash sent over network.
Suffix matching done locally. No password storage or logging.
"""
import hashlib
import asyncio
from datetime import datetime
import httpx

from config import ENABLE_HIBP_PASSWORD_CHECK

USER_AGENT = "OSINT-Tool/4.0"
# k-anonymity endpoint: send only first 5 chars of SHA-1 hash
PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range/{}"


async def check_password_exposure(password: str) -> dict:
    """
    Check if a password appears in HIBP Pwned Passwords database.
    Uses k-anonymity: only first 5 chars of SHA-1 hash sent to API.
    Password is NEVER stored or logged.
    """
    if not password or not password.strip():
        return {
            "status": "error",
            "error": "No password provided",
            "timestamp": datetime.now().isoformat(),
        }

    if not ENABLE_HIBP_PASSWORD_CHECK:
        return {
            "status": "disabled",
            "reason": "Password exposure check disabled by feature flag",
            "timestamp": datetime.now().isoformat(),
        }

    # Step 1: Compute SHA-1 hash LOCALLY
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]   # Only this goes over network
    suffix = sha1_hash[5:]   # Matched locally

    # Step 2: Send prefix to HIBP Range API
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
            timeout=httpx.Timeout(10.0),
        ) as client:
            resp = await client.get(PWNED_PASSWORDS_API.format(prefix))

            if resp.status_code != 200:
                return {
                    "status": "error",
                    "error": f"HIBP API returned status {resp.status_code}",
                    "timestamp": datetime.now().isoformat(),
                }

            # Step 3: Match suffix locally
            lines = resp.text.strip().split("\n")
            for line in lines:
                parts = line.strip().split(":")
                if len(parts) != 2:
                    continue
                hash_suffix, count = parts[0], parts[1]
                if hash_suffix.upper() == suffix:
                    try:
                        seen_count = int(count)
                    except ValueError:
                        seen_count = 1
                    return {
                        "status": "found",
                        "seen_count": seen_count,
                        "recommendation": (
                            f"This password has appeared {seen_count:,} times in known data breaches. "
                            "Do NOT use this password anywhere. Change it immediately."
                        ),
                        "timestamp": datetime.now().isoformat(),
                    }

            # No match found
            return {
                "status": "not_found",
                "seen_count": 0,
                "recommendation": (
                    "This password was not found in the Pwned Passwords database. "
                    "However, this does NOT guarantee it has never been exposed. "
                    "Always use unique passwords per service."
                ),
                "timestamp": datetime.now().isoformat(),
            }

    except Exception as e:
        return {
            "status": "error",
            "error": f"Failed to check password: {str(e)[:150]}",
            "timestamp": datetime.now().isoformat(),
        }


# DO NOT USE THIS FUNCTION FOR ANYTHING ELSE
# Password is processed only in memory and immediately discarded
