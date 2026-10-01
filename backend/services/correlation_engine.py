import pandas as pd
from pathlib import Path


# ============================================================
# THREAT CORRELATION ENGINE
#
# Defensive/local analysis only.
#
# This module:
# - Finds related threat observations
# - Groups observations by useful context
# - Creates synthetic correlation clusters
# - Counts repeated observations
#
# Correlation does NOT prove:
# - compromise
# - attacker attribution
# - malicious intent
#
# It only identifies potentially related observations
# within the local synthetic dataset.
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


def normalize_value(value):
    """
    Normalize a value for comparison.
    """

    if value is None:
        return ""

    return str(value).strip().lower()


def correlate_indicator(indicator):
    """
    Find observations related to one indicator.

    Correlation is based on:
    - Same indicator
    - Same threat category
    - Same source
    - Same MITRE tactic when available

    The result is a synthetic correlation cluster.
    """

    df = load_threat_data()

    search_value = normalize_value(
        indicator
    )

    if not search_value:
        return {
            "found": False,
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
                "Indicator was not found in "
                "the synthetic dataset"
            ),
        }

    categories = (
        matches["threat_category"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    sources = (
        matches["source_name"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    tactics = (
        matches["mitre_tactic_optional"]
        .dropna()
        .astype(str)
    )

    tactics = [
        value.strip()
        for value in tactics
        if value.strip()
    ]

    tactics = sorted(
        set(tactics)
    )

    statuses = (
        matches["status"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    severities = (
        matches["severity"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    first_seen = pd.to_datetime(
        matches["first_seen"],
        errors="coerce"
    ).min()

    last_seen = pd.to_datetime(
        matches["last_seen"],
        errors="coerce"
    ).max()

    # --------------------------------------------------------
    # Synthetic cluster ID
    # --------------------------------------------------------

    cluster_id = (
        "CLUSTER-"
        + search_value
        .replace(".", "-")
        .replace(":", "-")
        .replace("/", "-")
        .replace(" ", "-")
        .upper()
    )

    # --------------------------------------------------------
    # Observation IDs
    # --------------------------------------------------------

    observation_ids = (
        matches["threat_id"]
        .astype(str)
        .tolist()
    )

    # --------------------------------------------------------
    # Correlation confidence
    #
    # More common context increases the correlation
    # strength, but this is NOT attribution confidence.
    # --------------------------------------------------------

    correlation_score = 0

    if len(matches) >= 2:
        correlation_score += 30

    if len(categories) == 1:
        correlation_score += 20

    if len(sources) == 1:
        correlation_score += 20

    if len(tactics) == 1:
        correlation_score += 20

    if len(matches) >= 3:
        correlation_score += 10

    correlation_score = min(
        correlation_score,
        100
    )

    if correlation_score <= 20:
        correlation_level = "LOW"

    elif correlation_score <= 50:
        correlation_level = "MEDIUM"

    elif correlation_score <= 80:
        correlation_level = "HIGH"

    else:
        correlation_level = "VERY HIGH"

    return {
        "found": True,
        "cluster_id": cluster_id,
        "indicator": indicator,
        "observation_count": len(matches),
        "observation_ids": observation_ids,
        "categories": sorted(categories),
        "sources": sorted(sources),
        "mitre_tactics": tactics,
        "statuses": sorted(statuses),
        "severity_values": sorted(severities),
        "first_seen": (
            first_seen.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if not pd.isna(first_seen)
            else None
        ),
        "last_seen": (
            last_seen.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if not pd.isna(last_seen)
            else None
        ),
        "correlation_score": correlation_score,
        "correlation_level": correlation_level,
        "analyst_interpretation": (
            "These observations share common "
            "attributes in the synthetic dataset "
            "and may be related. Correlation does "
            "not prove attacker attribution, "
            "compromise, or malicious intent."
        ),
    }


def find_related_threats(
    threat_category=None,
    source_name=None,
    mitre_tactic=None,
):
    """
    Find potentially related observations using
    optional contextual filters.
    """

    df = load_threat_data()

    results = df.copy()

    if threat_category:
        results = results[
            results["threat_category"]
            .astype(str)
            .str.strip()
            .str.lower()
            == normalize_value(
                threat_category
            )
        ]

    if source_name:
        results = results[
            results["source_name"]
            .astype(str)
            .str.strip()
            .str.lower()
            == normalize_value(
                source_name
            )
        ]

    if mitre_tactic:
        results = results[
            results[
                "mitre_tactic_optional"
            ]
            .astype(str)
            .str.strip()
            .str.lower()
            == normalize_value(
                mitre_tactic
            )
        ]

    if results.empty:
        return {
            "found": False,
            "observation_count": 0,
            "message": (
                "No related observations found"
            ),
        }

    return {
        "found": True,
        "observation_count": len(results),
        "threat_ids": (
            results["threat_id"]
            .astype(str)
            .tolist()
        ),
        "categories": sorted(
            results["threat_category"]
            .dropna()
            .unique()
            .tolist()
        ),
        "sources": sorted(
            results["source_name"]
            .dropna()
            .unique()
            .tolist()
        ),
    }


if __name__ == "__main__":

    print("=" * 70)
    print("Threat Correlation Engine Test")
    print("=" * 70)

    test_indicator = "203.0.113.250"

    result = correlate_indicator(
        test_indicator
    )

    print()
    print("Indicator:")
    print(test_indicator)

    print()

    if result.get("found"):

        print("Cluster ID:")
        print(result["cluster_id"])

        print()
        print("Observation Count:")
        print(result["observation_count"])

        print()
        print("Observation IDs:")
        print(result["observation_ids"])

        print()
        print("Categories:")
        print(result["categories"])

        print()
        print("Sources:")
        print(result["sources"])

        print()
        print("MITRE Tactics:")
        print(result["mitre_tactics"])

        print()
        print("Severity Values:")
        print(result["severity_values"])

        print()
        print("First Seen:")
        print(result["first_seen"])

        print()
        print("Last Seen:")
        print(result["last_seen"])

        print()
        print("Correlation Score:")
        print(result["correlation_score"])

        print()
        print("Correlation Level:")
        print(result["correlation_level"])

        print()
        print("Analyst Interpretation:")
        print(result["analyst_interpretation"])

    else:

        print(result)

    print()
    print("=" * 70)
    print("Correlation completed using local synthetic data.")
    print("No external systems were contacted.")
    print("=" * 70)
