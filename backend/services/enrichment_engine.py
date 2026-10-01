import pandas as pd
from pathlib import Path


# ============================================================
# THREAT ENRICHMENT ENGINE
#
# Defensive/local analysis only.
#
# This module:
# - Reads the local synthetic threat dataset
# - Searches for indicators
# - Aggregates observations
# - Provides threat context
#
# This module does NOT:
# - Contact IP addresses
# - Visit domains
# - Request URLs
# - Download files
# - Query external threat-intelligence services
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    BASE_DIR
    / "data"
    / "threat_intelligence_dataset.csv"
)


def load_threat_data():
    """
    Load the local synthetic threat dataset.
    """

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Threat dataset not found: {DATASET_PATH}"
        )

    return pd.read_csv(DATASET_PATH)


def normalize_indicator(value):
    """
    Normalize an indicator for local searching.
    """

    if value is None:
        return ""

    return str(value).strip().lower()


def enrich_indicator(indicator):
    """
    Search the local dataset and return enrichment information.

    Important:
    Finding an indicator in this dataset does NOT prove compromise.
    """

    df = load_threat_data()

    search_value = normalize_indicator(indicator)

    if not search_value:
        return {
            "found": False,
            "indicator": indicator,
            "observation_count": 0,
            "message": "Indicator cannot be empty",
        }

    normalized_values = (
        df["indicator_value"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    matches = df[
        normalized_values == search_value
    ].copy()

    if matches.empty:
        return {
            "found": False,
            "indicator": indicator,
            "observation_count": 0,
            "message": (
                "Indicator was not found in the "
                "synthetic threat dataset"
            ),
        }

    categories = sorted(
        matches["threat_category"]
        .dropna()
        .unique()
        .tolist()
    )

    severities = sorted(
        matches["severity"]
        .dropna()
        .unique()
        .tolist()
    )

    statuses = sorted(
        matches["status"]
        .dropna()
        .unique()
        .tolist()
    )

    sources = sorted(
        matches["source_name"]
        .dropna()
        .unique()
        .tolist()
    )

    mitre_tactics = sorted(
        matches["mitre_tactic_optional"]
        .dropna()
        .astype(str)
        .loc[
            lambda series: series.str.strip() != ""
        ]
        .unique()
        .tolist()
    )

    mitre_techniques = sorted(
        matches["mitre_technique_optional"]
        .dropna()
        .astype(str)
        .loc[
            lambda series: series.str.strip() != ""
        ]
        .unique()
        .tolist()
    )

    first_seen = (
        pd.to_datetime(
            matches["first_seen"]
        ).min()
    )

    last_seen = (
        pd.to_datetime(
            matches["last_seen"]
        ).max()
    )

    average_confidence = round(
        matches["confidence_score"].mean(),
        2
    )

    average_risk = round(
        matches["risk_score"].mean(),
        2
    )

    maximum_risk = round(
        matches["risk_score"].max(),
        2
    )

    maximum_confidence = round(
        matches["confidence_score"].max(),
        2
    )

    highest_severity_order = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFORMATIONAL": 1,
    }

    highest_severity = max(
        severities,
        key=lambda value:
        highest_severity_order.get(value, 0)
    )

    related_indicators = (
        matches["indicator_value"]
        .astype(str)
        .unique()
        .tolist()
    )

    return {
        "found": True,
        "indicator": indicator,
        "normalized_indicator": search_value,
        "indicator_type": matches[
            "indicator_type"
        ].mode().iloc[0],
        "observation_count": len(matches),
        "categories": categories,
        "highest_severity": highest_severity,
        "severity_values": severities,
        "average_risk_score": average_risk,
        "maximum_risk_score": maximum_risk,
        "average_confidence_score": average_confidence,
        "maximum_confidence_score": maximum_confidence,
        "statuses": statuses,
        "sources": sources,
        "first_seen": first_seen.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "last_seen": last_seen.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "related_indicators": related_indicators,
        "analyst_note": (
            "This indicator was observed in the "
            "synthetic demonstration dataset. "
            "Dataset presence does not confirm "
            "compromise or malicious activity."
        ),
    }


if __name__ == "__main__":

    print("=" * 70)
    print("Threat Enrichment Engine Test")
    print("=" * 70)

    # Safe reserved documentation IP.
    test_indicator = "203.0.113.250"

    result = enrich_indicator(
        test_indicator
    )

    print()
    print("Search Indicator:", test_indicator)
    print()

    for key, value in result.items():
        print(f"{key}: {value}")

    print()
    print("=" * 70)
    print("Enrichment completed using local synthetic data.")
    print("No external systems were contacted.")
    print("=" * 70)