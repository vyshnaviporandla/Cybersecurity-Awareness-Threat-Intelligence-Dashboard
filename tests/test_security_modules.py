import sys
from pathlib import Path
from datetime import datetime

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.ioc_validator import validate_indicator
from backend.services.enrichment_engine import enrich_indicator
from backend.services.risk_engine import (
    calculate_threat_risk,
    calculate_confidence_score,
)
from backend.services.correlation_engine import correlate_indicator
from backend.services.alert_engine import generate_alert_from_indicator
from backend.services.attack_mapper import map_indicator_to_attack
from backend.services.vulnerability_engine import analyze_cve


DATASET = PROJECT_ROOT / "data" / "threat_intelligence_dataset.csv"


# ============================================================
# IOC VALIDATOR
# ============================================================

def test_valid_ipv4():
    result = validate_indicator("198.51.100.25")
    assert result["valid"] is True
    assert result["indicator_type"] == "IP ADDRESS"


def test_invalid_ipv4():
    result = validate_indicator("999.999.999.999")
    assert result["valid"] is False


def test_valid_ipv6():
    result = validate_indicator("2001:db8::1")
    assert result["valid"] is True
    assert result["indicator_type"] == "IP ADDRESS"


def test_valid_domain():
    result = validate_indicator("login-check.invalid")
    assert result["valid"] is True
    assert result["indicator_type"] == "DOMAIN"


def test_invalid_domain():
    result = validate_indicator("not a domain")
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
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )
    assert result["valid"] is True
    assert result["indicator_type"] == "FILE HASH"


def test_valid_sha256():
    result = validate_indicator(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )
    assert result["valid"] is True
    assert result["indicator_type"] == "FILE HASH"


def test_valid_cve():
    result = validate_indicator("CVE-2026-1001")
    assert result["valid"] is True
    assert result["indicator_type"] == "CVE ID"


def test_invalid_cve():
    result = validate_indicator("CVE-INVALID")
    assert result["valid"] is False


# ============================================================
# THREAT ENRICHMENT
# ============================================================

def test_known_indicator_enrichment():
    result = enrich_indicator("203.0.113.250")

    assert result["found"] is True
    assert result["observation_count"] >= 1
    assert result["indicator"] == "203.0.113.250"


def test_unknown_indicator_enrichment():
    result = enrich_indicator(
        "this-indicator-does-not-exist.invalid"
    )

    assert result["found"] is False


def test_enrichment_contains_defensive_disclaimer():
    result = enrich_indicator("203.0.113.250")

    note = result["analyst_note"].lower()

    assert "synthetic demonstration dataset" in note
    assert "does not confirm compromise" in note


# ============================================================
# RISK ENGINE
# ============================================================

def test_risk_score_is_bounded():
    result = calculate_threat_risk(
        severity="HIGH",
        confidence_score=70,
        last_seen=datetime.now(),
        observation_count=5,
        source_name="Security Vendor",
        correlated_count=2,
    )

    assert isinstance(result, dict)
    assert 0 <= result["risk_score"] <= 100


def test_risk_result_contains_required_fields():
    result = calculate_threat_risk(
        severity="HIGH",
        confidence_score=70,
        last_seen=datetime.now(),
        observation_count=5,
        source_name="Security Vendor",
        correlated_count=2,
    )

    assert "risk_score" in result
    assert "risk_level" in result
    assert "components" in result
    assert "weights" in result
    assert "interpretation" in result


def test_critical_severity_has_high_weight():
    high = calculate_threat_risk(
        severity="HIGH",
        confidence_score=70,
        last_seen=datetime.now(),
        observation_count=5,
        source_name="Security Vendor",
        correlated_count=2,
    )

    critical = calculate_threat_risk(
        severity="CRITICAL",
        confidence_score=70,
        last_seen=datetime.now(),
        observation_count=5,
        source_name="Security Vendor",
        correlated_count=2,
    )

    assert critical["risk_score"] > high["risk_score"]


def test_risk_weights_sum_to_one():
    result = calculate_threat_risk(
        severity="HIGH",
        confidence_score=70,
        last_seen=datetime.now(),
        observation_count=5,
        source_name="Security Vendor",
        correlated_count=2,
    )

    total_weight = sum(result["weights"].values())

    assert abs(total_weight - 1.0) < 0.001


# ============================================================
# CONFIDENCE ENGINE
# ============================================================

def test_confidence_score_is_bounded():
    result = calculate_confidence_score(
        source_name="Security Vendor",
        observation_count=5,
        analyst_confirmed=True,
    )

    assert isinstance(result, dict)
    assert 0 <= result["confidence_score"] <= 100


def test_confidence_result_contains_required_fields():
    result = calculate_confidence_score(
        source_name="Security Vendor",
        observation_count=5,
        analyst_confirmed=True,
    )

    assert "confidence_score" in result
    assert "confidence_level" in result
    assert "components" in result
    assert "interpretation" in result


def test_confidence_increases_with_better_evidence():
    low = calculate_confidence_score(
        source_name="Unknown Source",
        observation_count=1,
        analyst_confirmed=False,
    )

    high = calculate_confidence_score(
        source_name="Security Vendor",
        observation_count=10,
        analyst_confirmed=True,
    )

    assert high["confidence_score"] > low["confidence_score"]


# ============================================================
# CORRELATION ENGINE
# ============================================================

def test_known_indicator_correlation():
    result = correlate_indicator("203.0.113.250")

    assert result["found"] is True
    assert result["observation_count"] >= 1


def test_correlation_score_is_bounded():
    result = correlate_indicator("203.0.113.250")

    assert 0 <= result["correlation_score"] <= 100


def test_correlation_level_is_valid():
    result = correlate_indicator("203.0.113.250")

    valid_levels = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "VERY HIGH",
    }

    assert result["correlation_level"] in valid_levels


def test_unknown_indicator_correlation():
    result = correlate_indicator(
        "unknown-indicator-does-not-exist.invalid"
    )

    assert result["found"] is False


# ============================================================
# SECURITY ALERT ENGINE
# ============================================================

def test_known_indicator_creates_alert():
    result = generate_alert_from_indicator("203.0.113.250")

    assert result["alert_generated"] is True


def test_alert_contains_risk_information():
    result = generate_alert_from_indicator("203.0.113.250")

    assert "risk_score" in result
    assert "severity" in result
    assert "confidence_score" in result


def test_alert_status_is_valid():
    result = generate_alert_from_indicator("203.0.113.250")

    valid_statuses = {
        "NEW",
        "INVESTIGATING",
        "MONITORING",
        "RESOLVED",
        "FALSE_POSITIVE",
    }

    assert result["status"] in valid_statuses


def test_unknown_indicator_creates_no_alert():
    result = generate_alert_from_indicator(
        "unknown-indicator-does-not-exist.invalid"
    )

    assert result["alert_generated"] is False


# ============================================================
# MITRE ATT&CK CONTEXT
# ============================================================

def test_known_indicator_has_attack_mapping():
    result = map_indicator_to_attack("203.0.113.250")

    assert result["found"] is True
    assert result["mapping_count"] >= 1


def test_attack_mapping_has_tactic_and_technique():
    result = map_indicator_to_attack("203.0.113.250")

    for mapping in result["mappings"]:
        assert mapping["tactic"]
        assert mapping["technique"]


def test_attack_mapping_is_demonstration_context():
    result = map_indicator_to_attack("203.0.113.250")

    for mapping in result["mappings"]:
        assert (
            mapping["mapping_type"]
            == "DEMONSTRATION_CONTEXT"
        )


def test_attack_mapping_has_interpretation():
    result = map_indicator_to_attack("203.0.113.250")

    for mapping in result["mappings"]:
        assert "interpretation" in mapping


# ============================================================
# VULNERABILITY ENGINE
# ============================================================

def test_cve_analysis():
    result = analyze_cve("CVE-2026-1005")

    assert result["found"] is True
    assert result["observation_count"] >= 1


def test_cve_priority_score_is_bounded():
    result = analyze_cve("CVE-2026-1005")

    assert 0 <= result["priority_score"] <= 100


def test_cve_priority_level_is_valid():
    result = analyze_cve("CVE-2026-1005")

    valid_levels = {
        "INFORMATIONAL",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    assert result["priority_level"] in valid_levels


def test_unknown_cve():
    result = analyze_cve("CVE-2099-99999")

    assert result["found"] is False


# ============================================================
# DATASET VALIDATION
# ============================================================

def test_dataset_exists():
    assert DATASET.exists()


def test_dataset_is_not_empty():
    df = pd.read_csv(DATASET)

    assert len(df) > 0


def test_dataset_has_required_columns():
    df = pd.read_csv(DATASET)

    required_columns = {
        "threat_id",
        "timestamp",
        "threat_name",
        "threat_category",
        "indicator_type",
        "indicator_value",
        "source_name",
        "confidence_score",
        "severity",
        "risk_score",
        "status",
    }

    assert required_columns.issubset(df.columns)


def test_dataset_contains_expected_indicator_types():
    df = pd.read_csv(DATASET)

    expected_types = {
        "IP ADDRESS",
        "DOMAIN",
        "URL",
        "FILE HASH",
        "EMAIL/SENDER DOMAIN",
        "CVE ID",
    }

    assert expected_types.issubset(
        set(df["indicator_type"].unique())
    )


def test_dataset_risk_scores_are_valid():
    df = pd.read_csv(DATASET)

    assert df["risk_score"].between(0, 100).all()


def test_dataset_confidence_scores_are_valid():
    df = pd.read_csv(DATASET)

    assert df["confidence_score"].between(0, 100).all()


def test_dataset_severity_values_are_valid():
    df = pd.read_csv(DATASET)

    valid_severities = {
        "INFORMATIONAL",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    assert set(df["severity"].unique()).issubset(
        valid_severities
    )


# ============================================================
# SAFETY / DESIGN VALIDATION
# ============================================================

def test_dataset_contains_ip_records():
    df = pd.read_csv(DATASET)

    assert (
        df["indicator_type"] == "IP ADDRESS"
    ).any()


def test_dataset_status_values_are_valid():
    df = pd.read_csv(DATASET)

    valid_statuses = {
        "NEW",
        "UNDER_REVIEW",
        "MONITORING",
        "CLOSED",
        "FALSE_POSITIVE",
    }

    assert set(df["status"].unique()).issubset(
        valid_statuses
    )


def test_dataset_has_synthetic_cve_records():
    df = pd.read_csv(DATASET)

    cve_rows = df[
        df["indicator_type"] == "CVE ID"
    ]

    assert len(cve_rows) > 0


def test_project_dataset_has_expected_record_volume():
    df = pd.read_csv(DATASET)

    assert len(df) >= 2000


def test_project_dataset_contains_threat_categories():
    df = pd.read_csv(DATASET)

    assert df["threat_category"].nunique() >= 8


# ============================================================
# FINAL PROJECT VALIDATION
# ============================================================

def test_project_dataset_has_unique_threat_ids():
    df = pd.read_csv(DATASET)

    assert df["threat_id"].is_unique


def test_project_dataset_contains_indicator_values():
    df = pd.read_csv(DATASET)

    assert (
        df["indicator_value"]
        .dropna()
        .astype(str)
        .str.len()
        .gt(0)
        .all()
    )