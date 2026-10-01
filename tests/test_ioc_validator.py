import sys
from pathlib import Path

# Allow Python to find the backend package
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from backend.services.ioc_validator import validate_indicator


def test_valid_ipv4():
    result = validate_indicator("198.51.100.25")

    assert result["valid"] is True
    assert result["indicator_type"] == "IP ADDRESS"


def test_invalid_ipv4():
    result = validate_indicator("999.999.999.999")

    assert result["valid"] is False


def test_valid_ipv6():
    result = validate_indicator(
        "2001:db8::1"
    )

    assert result["valid"] is True
    assert result["indicator_type"] == "IP ADDRESS"


def test_valid_domain():
    result = validate_indicator(
        "login-check.invalid"
    )

    assert result["valid"] is True
    assert result["indicator_type"] == "DOMAIN"


def test_invalid_domain():
    result = validate_indicator(
        "invalid domain"
    )

    assert result["valid"] is False


def test_valid_url():
    result = validate_indicator(
        "https://login-check.invalid/verify"
    )

    assert result["valid"] is True
    assert result["indicator_type"] == "URL"


def test_valid_md5():
    result = validate_indicator(
        "d41d8cd98f00b204e9800998ecf8427e"
    )

    assert result["valid"] is True
    assert result["indicator_type"] == "FILE HASH"


def test_valid_sha1():
    result = validate_indicator(
        "a" * 40
    )

    assert result["valid"] is True
    assert result["indicator_type"] == "FILE HASH"


def test_valid_sha256():
    result = validate_indicator(
        "a" * 64
    )

    assert result["valid"] is True
    assert result["indicator_type"] == "FILE HASH"


def test_valid_cve():
    result = validate_indicator(
        "CVE-2026-1001"
    )

    assert result["valid"] is True
    assert result["indicator_type"] == "CVE ID"


def test_invalid_cve():
    result = validate_indicator(
        "CVE-INVALID"
    )

    assert result["valid"] is False


def test_empty_indicator():
    result = validate_indicator("")

    assert result["valid"] is False


def test_whitespace_indicator():
    result = validate_indicator("   ")

    assert result["valid"] is False


def test_domain_normalization():
    result = validate_indicator(
        "LOGIN-CHECK.INVALID"
    )

    assert result["valid"] is True
    assert result["normalized_value"] == "login-check.invalid"


def test_cve_normalization():
    result = validate_indicator(
        "cve-2026-1001"
    )

    assert result["valid"] is True
    assert result["normalized_value"] == "CVE-2026-1001"