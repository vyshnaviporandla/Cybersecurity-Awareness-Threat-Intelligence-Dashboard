import ipaddress
import re
from urllib.parse import urlparse


# ============================================================
# IOC VALIDATOR
# Defensive syntax validation only.
#
# This module does NOT:
# - contact IP addresses
# - visit domains
# - download URLs
# - execute files
# - query external threat-intelligence services
#
# It only validates the syntax of supplied indicators.
# ============================================================


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


MD5_PATTERN = re.compile(
    r"^[a-fA-F0-9]{32}$"
)

SHA1_PATTERN = re.compile(
    r"^[a-fA-F0-9]{40}$"
)

SHA256_PATTERN = re.compile(
    r"^[a-fA-F0-9]{64}$"
)

CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE
)


def validate_ip(value):
    """
    Validate IPv4 or IPv6 syntax.
    """

    try:
        ip = ipaddress.ip_address(value)

        return {
            "valid": True,
            "indicator_type": (
                "IP ADDRESS"
                if ip.version == 4
                else "IP ADDRESS"
            ),
            "normalized_value": str(ip),
            "validation_notes": (
                f"Valid IPv{ip.version} address syntax"
            ),
        }

    except ValueError:
        return None


def validate_url(value):
    """
    Validate basic URL syntax.

    This function NEVER contacts the URL.
    """

    try:
        parsed = urlparse(value)

        if parsed.scheme.lower() not in {
            "http",
            "https",
        }:
            return None

        if not parsed.netloc:
            return None

        return {
            "valid": True,
            "indicator_type": "URL",
            "normalized_value": value,
            "validation_notes": (
                "Valid HTTP/HTTPS URL syntax; "
                "URL was not contacted"
            ),
        }

    except ValueError:
        return None


def validate_domain(value):
    """
    Validate domain syntax.
    """

    if DOMAIN_PATTERN.fullmatch(value):
        return {
            "valid": True,
            "indicator_type": "DOMAIN",
            "normalized_value": value.lower(),
            "validation_notes": (
                "Valid domain syntax; "
                "domain was not contacted"
            ),
        }

    return None


def validate_hash(value):
    """
    Identify MD5, SHA-1, or SHA-256 syntax.
    """

    if MD5_PATTERN.fullmatch(value):
        return {
            "valid": True,
            "indicator_type": "FILE HASH",
            "normalized_value": value.lower(),
            "validation_notes": "Valid MD5 hash syntax",
        }

    if SHA1_PATTERN.fullmatch(value):
        return {
            "valid": True,
            "indicator_type": "FILE HASH",
            "normalized_value": value.lower(),
            "validation_notes": "Valid SHA-1 hash syntax",
        }

    if SHA256_PATTERN.fullmatch(value):
        return {
            "valid": True,
            "indicator_type": "FILE HASH",
            "normalized_value": value.lower(),
            "validation_notes": "Valid SHA-256 hash syntax",
        }

    return None


def validate_cve(value):
    """
    Validate CVE identifier syntax.

    This does NOT check whether the CVE actually exists.
    """

    if CVE_PATTERN.fullmatch(value):
        return {
            "valid": True,
            "indicator_type": "CVE ID",
            "normalized_value": value.upper(),
            "validation_notes": (
                "Valid CVE identifier syntax; "
                "existence was not verified"
            ),
        }

    return None


def validate_indicator(value):
    """
    Main IOC validation function.

    Returns a normalized validation result.
    """

    if value is None:
        return {
            "valid": False,
            "indicator_type": None,
            "normalized_value": None,
            "validation_notes": "Indicator cannot be empty",
        }

    value = str(value).strip()

    if not value:
        return {
            "valid": False,
            "indicator_type": None,
            "normalized_value": None,
            "validation_notes": "Indicator cannot be empty",
        }

    # CVE
    result = validate_cve(value)

    if result:
        return result

    # URL
    result = validate_url(value)

    if result:
        return result

    # IP
    result = validate_ip(value)

    if result:
        return result

    # Hash
    result = validate_hash(value)

    if result:
        return result

    # Domain
    result = validate_domain(value)

    if result:
        return result

    # Unknown / invalid
    return {
        "valid": False,
        "indicator_type": None,
        "normalized_value": value,
        "validation_notes": (
            "Indicator does not match supported "
            "IP, domain, URL, hash, or CVE syntax"
        ),
    }


if __name__ == "__main__":
    test_indicators = [
        "198.51.100.25",
        "login-check.invalid",
        "https://login-check.invalid/verify",
        "d41d8cd98f00b204e9800998ecf8427e",
        "CVE-2026-1001",
        "not-an-indicator",
    ]

    print("=" * 70)
    print("IOC Validator Test")
    print("=" * 70)

    for indicator in test_indicators:
        result = validate_indicator(indicator)

        print()
        print("Input:", indicator)
        print("Result:", result)

    print()
    print("=" * 70)
    print("Validation complete.")
    print("No external systems were contacted.")
    print("=" * 70)