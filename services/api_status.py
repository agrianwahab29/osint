"""
API STATUS SERVICE — Returns current state of all API-dependent services.
"""
from datetime import datetime
from config import get_api_status


def get_status() -> dict:
    """Get full API status report."""
    apis = get_api_status()
    enabled_count = sum(1 for v in apis.values() if v["enabled"])
    total_count = len(apis)

    return {
        "timestamp": datetime.now().isoformat(),
        "enabled_services": enabled_count,
        "total_services": total_count,
        "free_mode_active": True,  # Always free-first
        "services": apis,
    }
