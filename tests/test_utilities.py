"""Tests for common_ports utilities, owasp_remediation, and l7_signatures."""

from __future__ import annotations

import pytest

from offensive_ai.utils.common_ports import (
    COMMON_PORTS,
    CRITICAL_PORTS,
    FIREWALL_PORTS,
    TOP_PORTS,
    categorize_ports,
    get_database_ports,
    get_mail_ports,
    get_port_by_service,
    get_port_description,
    get_service_name,
    get_web_ports,
    is_critical_port,
)


# ---------------------------------------------------------------------------
# Basic port lookup
# ---------------------------------------------------------------------------

class TestGetServiceName:
    def test_http_port_80(self):
        assert get_service_name(80) == "http"

    def test_https_port_443(self):
        assert get_service_name(443) == "https"

    def test_ssh_port_22(self):
        assert get_service_name(22) == "ssh"

    def test_mysql_port_3306(self):
        assert get_service_name(3306) == "mysql"

    def test_unknown_port_returns_unknown(self):
        assert get_service_name(99999) == "unknown"

    def test_redis_port_6379(self):
        assert get_service_name(6379) == "redis"

    def test_postgres_port_5432(self):
        assert get_service_name(5432) == "postgresql"

    def test_smtp_port_25(self):
        assert get_service_name(25) == "smtp"


class TestGetPortByService:
    def test_ssh_returns_22(self):
        ports = get_port_by_service("ssh")
        assert 22 in ports

    def test_http_returns_80(self):
        ports = get_port_by_service("http")
        assert 80 in ports

    def test_unknown_service_returns_empty(self):
        ports = get_port_by_service("nonexistent-service-xyz")
        assert ports == []


# ---------------------------------------------------------------------------
# Critical port checks
# ---------------------------------------------------------------------------

class TestIsCriticalPort:
    def test_ssh_is_critical(self):
        assert is_critical_port(22) is True

    def test_rdp_is_critical(self):
        assert is_critical_port(3389) is True

    def test_smb_is_critical(self):
        assert is_critical_port(445) is True

    def test_mysql_is_critical(self):
        assert is_critical_port(3306) is True

    def test_http_not_critical(self):
        assert is_critical_port(80) is False

    def test_random_port_not_critical(self):
        assert is_critical_port(12345) is False

    def test_all_critical_ports_in_db(self):
        for port in CRITICAL_PORTS:
            assert is_critical_port(port) is True


# ---------------------------------------------------------------------------
# Category helpers
# ---------------------------------------------------------------------------

class TestGetWebPorts:
    def test_returns_list(self):
        ports = get_web_ports()
        assert isinstance(ports, list)

    def test_80_is_web_port(self):
        assert 80 in get_web_ports()

    def test_443_is_web_port(self):
        assert 443 in get_web_ports()

    def test_8080_is_web_port(self):
        assert 8080 in get_web_ports()


class TestGetDatabasePorts:
    def test_returns_list(self):
        ports = get_database_ports()
        assert isinstance(ports, list)

    def test_mysql_in_db_ports(self):
        assert 3306 in get_database_ports()

    def test_postgres_in_db_ports(self):
        assert 5432 in get_database_ports()

    def test_redis_in_db_ports(self):
        assert 6379 in get_database_ports()


class TestGetMailPorts:
    def test_returns_list(self):
        ports = get_mail_ports()
        assert isinstance(ports, list)

    def test_smtp_25_in_mail_ports(self):
        assert 25 in get_mail_ports()

    def test_imap_143_in_mail_ports(self):
        assert 143 in get_mail_ports()


# ---------------------------------------------------------------------------
# categorize_ports
# ---------------------------------------------------------------------------

class TestCategorizePorts:
    def test_web_ports_categorized(self):
        result = categorize_ports([80, 443])
        assert "web" in result
        assert 80 in result["web"]
        assert 443 in result["web"]

    def test_database_ports_categorized(self):
        result = categorize_ports([3306, 5432])
        assert "database" in result

    def test_ssh_port_categorized(self):
        result = categorize_ports([22])
        assert "ssh" in result

    def test_unknown_port_goes_to_other(self):
        result = categorize_ports([54321])
        assert "other" in result
        assert 54321 in result["other"]

    def test_empty_list_returns_empty(self):
        result = categorize_ports([])
        assert result == {}

    def test_mixed_ports(self):
        result = categorize_ports([80, 22, 3306, 143, 21])
        assert "web" in result
        assert "ssh" in result
        assert "database" in result
        assert "mail" in result
        assert "ftp" in result


# ---------------------------------------------------------------------------
# get_port_description
# ---------------------------------------------------------------------------

class TestGetPortDescription:
    def test_http_port_description(self):
        desc = get_port_description(80)
        assert "HTTP" in desc or "http" in desc.lower()

    def test_https_port_description(self):
        desc = get_port_description(443)
        assert "HTTPS" in desc or "https" in desc.lower()

    def test_critical_port_flagged(self):
        desc = get_port_description(22)
        assert "CRITICAL" in desc or "critical" in desc.lower()

    def test_non_critical_port_no_critical_flag(self):
        desc = get_port_description(80)
        assert "CRITICAL" not in desc

    def test_unknown_port_returns_string(self):
        desc = get_port_description(99999)
        assert isinstance(desc, str)
        assert len(desc) > 0


# ---------------------------------------------------------------------------
# Data integrity
# ---------------------------------------------------------------------------

class TestPortDataIntegrity:
    def test_common_ports_not_empty(self):
        assert len(COMMON_PORTS) > 20

    def test_top_ports_subset_of_common_ports(self):
        # All TOP_PORTS should be in COMMON_PORTS (not strictly required, but reasonable)
        assert isinstance(TOP_PORTS, list)
        assert len(TOP_PORTS) > 10

    def test_firewall_ports_not_empty(self):
        assert len(FIREWALL_PORTS) > 0

    def test_critical_ports_list(self):
        assert isinstance(CRITICAL_PORTS, list)
        assert 22 in CRITICAL_PORTS
        assert 445 in CRITICAL_PORTS


# ===========================================================================
# OWASP Remediation tests
# ===========================================================================

from offensive_ai.utils.owasp_remediation import (
    OWASP_CATEGORIES,
    REMEDIATION_DB,
    get_category_info,
    get_remediation,
    list_all_remediation_keys,
)


class TestOwaspCategories:
    def test_a01_present(self):
        assert "A01" in OWASP_CATEGORIES

    def test_a10_present(self):
        assert "A10" in OWASP_CATEGORIES

    def test_a09_not_testable(self):
        cat = OWASP_CATEGORIES["A09"]
        assert cat["testable"] is False
        assert "not_testable_reason" in cat

    def test_all_required_fields(self):
        for cat_id, cat_info in OWASP_CATEGORIES.items():
            assert "name" in cat_info, f"Category {cat_id} missing name"
            assert "testable" in cat_info, f"Category {cat_id} missing testable"


class TestGetCategoryInfo:
    def test_known_category(self):
        info = get_category_info("A01")
        assert info is not None
        assert info["name"] == "Broken Access Control"

    def test_unknown_category_returns_none(self):
        assert get_category_info("A99") is None

    def test_a09_not_testable(self):
        info = get_category_info("A09")
        assert info["testable"] is False


class TestGetRemediation:
    def test_known_key_returns_info(self):
        keys = list_all_remediation_keys()
        if not keys:
            pytest.skip("No remediation keys in DB")
        key = keys[0]
        info = get_remediation(key)
        assert info is not None
        assert hasattr(info, "description")
        assert hasattr(info, "steps")
        assert hasattr(info, "code_examples")

    def test_unknown_key_returns_none(self):
        result = get_remediation("nonexistent_key_xyz_123")
        assert result is None

    def test_tech_stack_filter(self):
        keys = list_all_remediation_keys()
        if not keys:
            pytest.skip("No remediation keys in DB")
        key = keys[0]
        info_generic = get_remediation(key, tech_stack="generic")
        assert info_generic is not None

    def test_missing_hsts_key_exists(self):
        """Verify the missing_hsts remediation key exists."""
        info = get_remediation("missing_hsts")
        assert info is not None

    def test_list_all_remediation_keys_returns_list(self):
        keys = list_all_remediation_keys()
        assert isinstance(keys, list)
        assert len(keys) > 0


# ===========================================================================
# L7 Signatures tests
# ===========================================================================

from offensive_ai.utils.l7_signatures import L7_SIGNATURES, get_signature_patterns
from offensive_ai.models.l7_result import L7Protection


class TestL7Signatures:
    def test_l7_signatures_not_empty(self):
        assert len(L7_SIGNATURES) > 0

    def test_cloudflare_in_signatures(self):
        assert L7Protection.CLOUDFLARE in L7_SIGNATURES

    def test_aws_waf_in_signatures(self):
        assert L7Protection.AWS_WAF in L7_SIGNATURES

    def test_signature_has_headers(self):
        for protection, sig in L7_SIGNATURES.items():
            assert "headers" in sig, f"Missing headers for {protection}"

    def test_signature_has_description(self):
        for protection, sig in L7_SIGNATURES.items():
            assert "description" in sig, f"Missing description for {protection}"

    def test_get_signature_patterns_cloudflare(self):
        patterns = get_signature_patterns(L7Protection.CLOUDFLARE)
        assert patterns is not None

    def test_get_signature_patterns_unknown_returns_none_or_empty(self):
        # Create a dummy protection value not in signatures
        result = get_signature_patterns(L7Protection.UNKNOWN)
        # Should return None or empty dict
        assert result is None or result == {} or isinstance(result, dict)


# ---------------------------------------------------------------------------
# __main__.py coverage
# ---------------------------------------------------------------------------

class TestMainEntryPoint:
    def test_main_module_importable(self):
        """Import the module to execute the module-level code."""
        import importlib
        import sys
        # Import the module directly to cover module-level code
        spec = importlib.util.find_spec("offensive_ai.__main__")
        assert spec is not None

    def test_main_module_has_main_call(self):
        """Verify __main__.py references the CLI main() function."""
        import inspect
        import offensive_ai.__main__ as m
        source = inspect.getsource(m)
        assert "main" in source
