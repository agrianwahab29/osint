"""
Unit tests for OSINT Framework modules.
Run: pytest tests/ -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestNameSearch:
    """Tests for name_search module."""

    def test_name_variations(self):
        from modules.name_search import search_name
        import asyncio

        async def _test():
            result = await search_name("John Smith")
            assert isinstance(result, dict)
            assert result["query"] == "John Smith"
            assert "web_results" in result
            assert "github_profiles" in result
            assert "wikipedia_mentions" in result
            assert "risk_indicators" in result
            assert isinstance(result["web_results"], list)
            assert isinstance(result["risk_indicators"], list)
        asyncio.run(_test())

    def test_single_name(self):
        from modules.name_search import search_name
        import asyncio

        async def _test():
            result = await search_name("Madonna")
            assert isinstance(result, dict)
            assert result["query"] == "Madonna"
            assert isinstance(result["ddg_related"], list)
        asyncio.run(_test())


class TestEmailFinder:
    """Tests for email_finder module."""

    def test_generate_permutations(self):
        from modules.email_finder import find_emails
        import asyncio

        async def _test():
            result = await find_emails("John Smith")
            assert isinstance(result, dict)
            assert result["total_generated"] > 0
            assert len(result.get("valid_emails", [])) > 0
            assert "valid_emails" in result
            assert "disposable_emails" in result
            assert "role_based_emails" in result
        asyncio.run(_test())

    def test_email_validation(self):
        from modules.email_finder import _validate_email
        assert _validate_email("test@example.com")["valid"]
        assert _validate_email("not-an-email")["valid"] is False
        assert _validate_email("")["valid"] is False


class TestSocialMedia:
    """Tests for social_media module."""

    def test_username_generation(self):
        from modules.social_media import _generate_usernames
        usernames = _generate_usernames("John Smith")
        assert isinstance(usernames, list)
        assert len(usernames) > 3
        assert "johnsmith" in usernames
        assert "john.smith" in usernames

    def test_scan_social_media(self):
        from modules.social_media import scan_social_media
        import asyncio

        async def _test():
            result = await scan_social_media("Test User Person")
            assert isinstance(result, dict)
            assert "profiles_found" in result
            assert "profiles_not_found" in result
            assert "summary" in result
            assert isinstance(result["summary"], dict)
            assert "total_found" in result["summary"]
        asyncio.run(_test())


class TestPhoneFinder:
    """Tests for phone_finder module."""

    def test_phone_cleaning(self):
        from modules.phone_finder import _clean_phone
        assert _clean_phone("+62 812-3456-7890") == "+6281234567890"
        assert _clean_phone("0812 3456 7890") == "081234567890"

    def test_country_detection(self):
        from modules.phone_finder import _detect_country
        result = _detect_country("+62812345678")
        assert result["country_code"] == "+62"
        assert "ID" in result["country"] or "Indonesia" in result["country"]

    def test_analyze_phone(self):
        from modules.phone_finder import analyze_phone
        import asyncio

        async def _test():
            result = await analyze_phone("+6281234567890")
            assert isinstance(result, dict)
            assert "country_info" in result
            assert "validation" in result
            assert "variants" in result
            assert "query" in result
        asyncio.run(_test())


class TestDomainChecker:
    """Tests for domain_checker module."""

    def test_domain_extraction(self):
        from modules.domain_checker import _extract_domain
        assert _extract_domain("example.com") == "example.com"
        assert _extract_domain("https://www.example.com") == "example.com"
        assert _extract_domain("www.example.com") == "example.com"


class TestDatabase:
    """Tests for database module."""

    def test_init_and_create_scan(self):
        from modules.database import create_scan, get_scan, delete_scan
        rid = "TEST_001"
        delete_scan(rid)  # cleanup
        scan_id = create_scan(rid, "Test User")
        assert scan_id > 0
        scan = get_scan(rid)
        assert scan is not None
        assert scan["status"] == "running"
        delete_scan(rid)

    def test_scan_complete(self):
        from modules.database import create_scan, complete_scan, get_scan, delete_scan
        rid = "TEST_002"
        delete_scan(rid)
        create_scan(rid, "Test")
        complete_scan(rid, {"test": True}, severity="HIGH", confidence=80, total_findings=5)
        scan = get_scan(rid)
        assert scan is not None
        assert scan["status"] == "completed"
        assert scan["severity"] == "HIGH"
        assert scan["confidence_score"] == 80
        assert scan["total_findings"] == 5
        delete_scan(rid)


class TestReportGenerator:
    """Tests for report_generator module."""

    def test_calc_severity(self):
        from modules.report_generator import _calc_overall_severity
        assert _calc_overall_severity({}) == "UNKNOWN"
        assert _calc_overall_severity({"mod": {"severity": "HIGH"}}) == "HIGH"
        assert _calc_overall_severity({"a": {"severity": "LOW"}, "b": {"severity": "CRITICAL"}}) == "CRITICAL"

    def test_calc_confidence(self):
        from modules.report_generator import _calc_confidence
        assert _calc_confidence({}) == 50
        assert _calc_confidence({"mod": {"confidence": 80}}) == 80

    def test_count_findings(self):
        from modules.report_generator import _count_total_findings
        assert _count_total_findings({}) == 0
        assert _count_total_findings({"mod": {"web_results": [1, 2, 3], "profiles_found": [1, 2]}}) == 5

    def test_save_report(self):
        from modules.report_generator import save_report
        import shutil
        rid = "TEST_RPT"
        results = {
            "name_search": {"web_results": [{"title": "Test", "url": "http://test.com"}], "severity": "LOW", "confidence": 60},
            "social_media": {"profiles_found": [{"platform": "github", "url": "http://github.com/user"}], "severity": "INFO"},
        }
        info = save_report(rid, "Test User", results)
        assert "report_id" in info
        assert "files" in info
        assert "json" in info["files"]
        assert "html" in info["files"]
        assert "csv" in info["files"]
        assert info["severity"] in ("LOW", "INFO", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")


class TestWhoisRecon:
    """Tests for whois_recon module."""

    def test_domain_clean(self):
        from modules.whois_recon import _clean_domain
        assert _clean_domain("google.com") == "google.com"
        assert _clean_domain("https://www.google.com/test") == "google.com"


class TestGoogleDorks:
    """Tests for google_dorks module."""

    def test_dorks_structure(self):
        from modules.google_dorks import DORK_CATEGORIES
        assert len(DORK_CATEGORIES) >= 5
        assert "sensitive_info" in DORK_CATEGORIES
        assert "exposed_documents" in DORK_CATEGORIES
        for cat, info in DORK_CATEGORIES.items():
            assert "label" in info
            assert "severity" in info
            assert "queries" in info
            assert len(info["queries"]) > 0
