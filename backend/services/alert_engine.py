import pandas as pd
from pathlib import Path
from datetime import datetime


# ============================================================
# SECURITY ALERT ENGINE
#
# Defensive/local analysis only.
#
# This module:
# - Generates alerts from local threat observations
# - Uses risk and confidence thresholds
# - Detects repeated observations
# - Correlates repeated observations
# - Prevents unnecessary duplicate alerts
#
# Alerts do NOT prove compromise.
# They identify observations that deserve review.
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    BASE_DIR
    / "data"
    / "threat_intelligence_dataset.csv"
)


# Alert thresholds
RISK_ALERT_THRESHOLD = 60
CONFIDENCE_ALERT_THRESHOLD = 50
REPEATED_OBSERVATION_THRESHOLD = 3


ALERT_STATUSES = [
    "NEW",
    "INVESTIGATING",
    "MONITORING",
    "RESOLVED",
    "FALSE_POSITIVE",
]


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
    Normalize indicator values for comparison.
    """

    if value is None:
        return ""

    return str(value).strip().lower()


def determine_alert_type(
    risk_score,
    confidence_score,
    observation_count,
    correlated_count=0,
):
    """
    Determine why an alert should be generated.
    """

    reasons = []

    if risk_score >= RISK_ALERT_THRESHOLD:
        reasons.append(
            "HIGH_RISK"
        )

    if confidence_score >= CONFIDENCE_ALERT_THRESHOLD:
        reasons.append(
            "HIGH_CONFIDENCE"
        )

    if observation_count >= REPEATED_OBSERVATION_THRESHOLD:
        reasons.append(
            "REPEATED_OBSERVATIONS"
        )

    if correlated_count >= 2:
        reasons.append(
            "CORRELATED_INDICATORS"
        )

    if not reasons:
        return None

    return "+".join(reasons)


def determine_alert_severity(
    risk_score,
):
    """
    Convert risk score into alert severity.
    """

    if risk_score >= 81:
        return "CRITICAL"

    if risk_score >= 61:
        return "HIGH"

    if risk_score >= 41:
        return "MEDIUM"

    if risk_score >= 21:
        return "LOW"

    return "INFORMATIONAL"


def generate_alert_id(
    threat_id,
):
    """
    Generate a deterministic alert ID.
    """

    clean_id = (
        str(threat_id)
        .strip()
        .upper()
        .replace(" ", "-")
    )

    return f"ALT-{clean_id}"


def generate_threat_alert(
    threat_id,
    indicator,
    risk_score,
    confidence_score,
    observation_count,
    severity,
    correlated_count=0,
):
    """
    Generate a structured security alert.

    An alert is generated only when at least
    one alert condition is satisfied.
    """

    alert_type = determine_alert_type(
        risk_score=risk_score,
        confidence_score=confidence_score,
        observation_count=observation_count,
        correlated_count=correlated_count,
    )

    if alert_type is None:
        return {
            "alert_generated": False,
            "reason": (
                "Threat did not meet any configured "
                "alert threshold."
            ),
        }

    alert_severity = determine_alert_severity(
        risk_score
    )

    alert_id = generate_alert_id(
        threat_id
    )

    description_parts = []

    if risk_score >= RISK_ALERT_THRESHOLD:
        description_parts.append(
            f"Risk score {risk_score} "
            f"meets the alert threshold."
        )

    if confidence_score >= CONFIDENCE_ALERT_THRESHOLD:
        description_parts.append(
            f"Confidence score {confidence_score} "
            f"meets the alert threshold."
        )

    if observation_count >= REPEATED_OBSERVATION_THRESHOLD:
        description_parts.append(
            f"The indicator has "
            f"{observation_count} observations."
        )

    if correlated_count >= 2:
        description_parts.append(
            f"{correlated_count} related "
            f"observations were identified."
        )

    description = " ".join(
        description_parts
    )

    return {
        "alert_generated": True,
        "alert_id": alert_id,
        "threat_id": threat_id,
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "alert_type": alert_type,
        "severity": alert_severity,
        "risk_score": round(
            float(risk_score),
            2
        ),
        "confidence_score": round(
            float(confidence_score),
            2
        ),
        "indicator": indicator,
        "observation_count": observation_count,
        "correlated_count": correlated_count,
        "description": description,
        "status": "NEW",
        "analyst_guidance": (
            "Review the indicator using authorized "
            "internal telemetry and available "
            "security records. Do not treat this "
            "alert alone as proof of compromise."
        ),
    }


def generate_alert_from_indicator(
    indicator,
):
    """
    Search the local dataset and generate an alert
    for the latest observation of an indicator.
    """

    df = load_threat_data()

    search_value = normalize_indicator(
        indicator
    )

    if not search_value:
        return {
            "alert_generated": False,
            "message": (
                "Indicator cannot be empty."
            ),
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
            "alert_generated": False,
            "message": (
                "Indicator was not found in "
                "the synthetic dataset."
            ),
        }

    latest = matches.sort_values(
        "last_seen"
    ).iloc[-1]

    observation_count = len(matches)

    correlated_count = max(
        0,
        observation_count - 1
    )

    return generate_threat_alert(
        threat_id=latest["threat_id"],
        indicator=latest["indicator_value"],
        risk_score=latest["risk_score"],
        confidence_score=latest[
            "confidence_score"
        ],
        observation_count=observation_count,
        severity=latest["severity"],
        correlated_count=correlated_count,
    )


def correlate_alerts(alerts):
    """
    Combine alerts referring to the same indicator.

    This prevents alert overload when multiple
    observations represent the same underlying
    indicator.

    Input:
        List of alert dictionaries.

    Output:
        Correlated alert groups.
    """

    if not alerts:
        return []

    groups = {}

    for alert in alerts:

        indicator = normalize_indicator(
            alert.get("indicator")
        )

        if not indicator:
            continue

        if indicator not in groups:
            groups[indicator] = {
                "indicator": alert.get(
                    "indicator"
                ),
                "alert_ids": [],
                "threat_ids": [],
                "observation_count": 0,
                "highest_severity": (
                    alert.get("severity")
                ),
                "maximum_risk_score": 0,
                "maximum_confidence_score": 0,
                "status": "NEW",
            }

        group = groups[indicator]

        alert_id = alert.get(
            "alert_id"
        )

        threat_id = alert.get(
            "threat_id"
        )

        if alert_id:
            group["alert_ids"].append(
                alert_id
            )

        if threat_id:
            group["threat_ids"].append(
                threat_id
            )

        group[
            "observation_count"
        ] += int(
            alert.get(
                "observation_count",
                0
            )
        )

        group[
            "maximum_risk_score"
        ] = max(
            group["maximum_risk_score"],
            float(
                alert.get(
                    "risk_score",
                    0
                )
            ),
        )

        group[
            "maximum_confidence_score"
        ] = max(
            group["maximum_confidence_score"],
            float(
                alert.get(
                    "confidence_score",
                    0
                )
            ),
        )

    return list(
        groups.values()
    )


def generate_alerts_from_dataset():
    """
    Generate alerts from all unique indicators
    in the local dataset.

    The result is one candidate alert per
    indicator rather than one alert per row.
    """

    df = load_threat_data()

    indicators = (
        df["indicator_value"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    alerts = []

    for indicator in indicators:

        result = generate_alert_from_indicator(
            indicator
        )

        if result.get(
            "alert_generated"
        ):
            alerts.append(result)

    return alerts


if __name__ == "__main__":

    print("=" * 70)
    print("Security Alert Engine Test")
    print("=" * 70)

    test_indicator = "203.0.113.250"

    print()
    print(
        "Testing indicator:",
        test_indicator
    )

    result = generate_alert_from_indicator(
        test_indicator
    )

    print()

    for key, value in result.items():
        print(
            f"{key}: {value}"
        )

    print()
    print("-" * 70)
    print("Testing unknown indicator")
    print("-" * 70)

    unknown_result = (
        generate_alert_from_indicator(
            "unknown-indicator.invalid"
        )
    )

    print()

    for key, value in unknown_result.items():
        print(
            f"{key}: {value}"
        )

    print()
    print("-" * 70)
    print("Testing alert generation from dataset")
    print("-" * 70)

    alerts = generate_alerts_from_dataset()

    print()
    print(
        "Total generated alerts:",
        len(alerts)
    )

    if alerts:

        print()
        print("First 5 alerts:")

        for alert in alerts[:5]:

            print(
                alert["alert_id"],
                "|",
                alert["severity"],
                "|",
                alert["risk_score"],
                "|",
                alert["indicator"],
            )

    print()
    print("=" * 70)
    print("Alert engine completed.")
    print("Local synthetic data only.")
    print("No external systems were contacted.")
    print("=" * 70)
