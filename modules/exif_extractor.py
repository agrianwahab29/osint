"""
EXIF METADATA EXTRACTOR v1 — Forensic image metadata analysis.
Extracts GPS, camera info, timestamps, software, and all EXIF tags.
Free, no API key needed. Uses Pillow.
"""
import re
from datetime import datetime
from io import BytesIO
from typing import Optional
import httpx

USER_AGENT = "OSINT-Tool/4.0 EXIF-Extractor"


def _convert_to_degrees(value) -> float:
    """Convert GPS coordinate from degrees/minutes/seconds tuple to decimal."""
    try:
        if not value or len(value) < 3:
            return 0.0
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return 0.0


def _parse_gps(gps_info: dict) -> dict:
    """Parse GPS info into Google Maps-friendly format."""
    if not gps_info:
        return {}
    result = {}
    try:
        lat = _convert_to_degrees(gps_info.get("GPSLatitude"))
        lon = _convert_to_degrees(gps_info.get("GPSLongitude"))
        lat_ref = gps_info.get("GPSLatitudeRef", "N")
        lon_ref = gps_info.get("GPSLongitudeRef", "E")

        if lat_ref == "S":
            lat = -lat
        if lon_ref == "W":
            lon = -lon

        if lat or lon:
            result["latitude"] = round(lat, 6)
            result["longitude"] = round(lon, 6)
            result["coordinates"] = f"{lat:.6f}, {lon:.6f}"
            result["google_maps_url"] = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
            result["openstreetmap_url"] = f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}&zoom=18"

        if gps_info.get("GPSAltitude"):
            try:
                alt = float(gps_info["GPSAltitude"])
                result["altitude_meters"] = round(alt, 2)
            except Exception:
                pass

        if gps_info.get("GPSTimeStamp"):
            result["gps_timestamp"] = str(gps_info["GPSTimeStamp"])
        if gps_info.get("GPSDateStamp"):
            result["gps_date"] = str(gps_info["GPSDateStamp"])
    except Exception as e:
        result["error"] = f"GPS parse error: {str(e)[:100]}"
    return result


def extract_exif_from_bytes(image_bytes: bytes, source_url: Optional[str] = None) -> dict:
    """Extract EXIF metadata from image bytes."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        return {
            "status": "error",
            "error": "Pillow not installed. Run: pip install Pillow",
            "timestamp": datetime.now().isoformat(),
        }

    result = {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "source_url": source_url,
        "image_info": {},
        "exif": {},
        "gps": {},
        "camera": {},
        "software": {},
        "all_tags": {},
        "warnings": [],
    }

    try:
        img = Image.open(BytesIO(image_bytes))
        result["image_info"] = {
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "size_bytes": len(image_bytes),
        }

        # Use _getexif for older API or getexif() for new
        try:
            exif_data = img._getexif()  # type: ignore
        except AttributeError:
            exif_data = None

        if not exif_data:
            try:
                exif_obj = img.getexif()
                exif_data = dict(exif_obj) if exif_obj else None
            except Exception:
                exif_data = None

        if not exif_data:
            result["status"] = "no_exif"
            result["warnings"].append("No EXIF metadata found. Image may have been stripped or never had metadata.")
            return result

        # Parse all tags
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            try:
                str_value = str(value)[:500]
            except Exception:
                str_value = "<unreadable>"
            result["all_tags"][tag_name] = str_value

        # Extract GPS
        if "GPSInfo" in result["all_tags"]:
            gps_dict = {}
            try:
                raw_gps = exif_data.get(34853)  # GPSInfo tag ID
                if raw_gps:
                    for gps_tag_id, gps_value in raw_gps.items():
                        gps_name = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                        gps_dict[gps_name] = gps_value
            except Exception:
                pass
            result["gps"] = _parse_gps(gps_dict)

        # Camera info
        camera_keys = ["Make", "Model", "LensModel", "LensMake", "FocalLength",
                       "FNumber", "ISOSpeedRatings", "ExposureTime"]
        for k in camera_keys:
            if k in result["all_tags"]:
                result["camera"][k] = result["all_tags"][k]

        # Software / processing
        sw_keys = ["Software", "ProcessingSoftware", "HostComputer", "Artist",
                   "Copyright", "ImageDescription"]
        for k in sw_keys:
            if k in result["all_tags"]:
                result["software"][k] = result["all_tags"][k]

        # Datetime
        dt_keys = ["DateTime", "DateTimeOriginal", "DateTimeDigitized"]
        for k in dt_keys:
            if k in result["all_tags"]:
                result["exif"][k] = result["all_tags"][k]

        # Privacy warnings
        if result["gps"].get("coordinates"):
            result["warnings"].append("⚠️ GPS coordinates exposed — image contains location data")
        if result["camera"].get("Make") or result["camera"].get("Model"):
            result["warnings"].append("Camera/device info exposed")
        if result["software"].get("Software"):
            result["warnings"].append("Editing software info exposed")

        return result

    except Exception as e:
        return {
            "status": "error",
            "error": f"Failed to parse image: {str(e)[:200]}",
            "timestamp": datetime.now().isoformat(),
        }


async def extract_exif_from_url(image_url: str) -> dict:
    """Download image from URL and extract EXIF."""
    if not image_url or not image_url.strip():
        return {"status": "error", "error": "No image URL provided",
                "timestamp": datetime.now().isoformat()}

    if not (image_url.startswith("http://") or image_url.startswith("https://")):
        return {"status": "error", "error": "Invalid URL — must start with http:// or https://",
                "timestamp": datetime.now().isoformat()}

    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=httpx.Timeout(15.0),
            follow_redirects=True,
        ) as client:
            resp = await client.get(image_url)
            if resp.status_code != 200:
                return {
                    "status": "error",
                    "error": f"HTTP {resp.status_code} — failed to download image",
                    "timestamp": datetime.now().isoformat(),
                }
            content_type = resp.headers.get("content-type", "")
            if "image" not in content_type.lower():
                return {
                    "status": "error",
                    "error": f"URL does not point to an image (Content-Type: {content_type})",
                    "timestamp": datetime.now().isoformat(),
                }
            return extract_exif_from_bytes(resp.content, source_url=image_url)
    except Exception as e:
        return {
            "status": "error",
            "error": f"Download failed: {str(e)[:200]}",
            "timestamp": datetime.now().isoformat(),
        }


def get_reverse_image_search_links(image_url: str) -> list:
    """Generate reverse image search links (manual links — no scraping)."""
    if not image_url or not image_url.strip():
        return []
    from urllib.parse import quote_plus
    encoded = quote_plus(image_url)
    return [
        {
            "name": "Google Images",
            "url": f"https://www.google.com/searchbyimage?image_url={encoded}",
            "icon": "🔍",
        },
        {
            "name": "Yandex Images",
            "url": f"https://yandex.com/images/search?rpt=imageview&url={encoded}",
            "icon": "🟡",
        },
        {
            "name": "TinEye",
            "url": f"https://tineye.com/search?url={encoded}",
            "icon": "👁️",
        },
        {
            "name": "Bing Visual Search",
            "url": f"https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl={encoded}",
            "icon": "🅱️",
        },
    ]
