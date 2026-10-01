import math
from datetime import datetime
from pathlib import Path

import pandas as pd


# ============================================================
# RISK & CONFIDENCE SCORING ENGINE
#
# Defensive/local analysis only.
#
# Risk score:
# - Severity: 30%
# - Confidence: 25%
# - Recency: 15%
# - Observation frequency: 10%
# - Source reliability: 10%
# - Context/correlation: 10%
#
# Risk represents potential concern.
# Confidence represents evidence quality.
#
# A high risk score does NOT automatically mean compromise.
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    BASE_DIR
    / "data"
    / "threat_intelligence_dataset.csv"
)


SEVERITY_VALUES = {
    "INFORMATIONAL": 20,
    "LOW": 40,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 100,
}


SOURCE_RELIABILITY = {
    "Internal SOC": 100,
    "Security Vendor": 90,
    "Public Threat Feed": 80,
    "Research Report": 75,
    "Community Submission": 55,
    "Unknown Source": 30,
}


def load_threat_data():
    """
    Load the local synthetic threat dataset.
    """
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Threat dataset not found: {DATASET_PATH}"
        )

    return pd.read_csv(DATASET_PATH)


def calculate_recency_score(last_seen):
    """
    Calculate a recency score from 0 to 100.

    More recent observations receive higher scores.

    This is a simple educational scoring model,
    not a production threat-intelligence formula.
    """

    if not last_seen:
        return 0.0

    try:
        observation_time = pd.to_datetime(
            last_seen,
            errors="coerce"
        )

        if pd.isna(observation_time):
            return 0.0

        now = pd.Timestamp.now()

        age_days = (
            now - observation_time
        ).total_seconds() / 86400

        if age_days < 0:
            age_days = 0

        # Exponential decay.
        score = 100 * math.exp(
            -age_days / 30
        )

        return round(
            max(0, min(100, score)),
            2
        )

    except Exception:
        return 0.0


def calculate_frequency_score(
    observation_count
):
    """
    Convert observation frequency into a
    0-100 score.

    More observations indicate stronger
    repeated visibility in the dataset.
    """

    try:
        count = int(observation_count)
    except (TypeError, ValueError):
        return 0.0

    if count <= 0:
        return 0.0

    # Logarithmic scaling prevents extremely
    # frequent indicators from dominating risk.
    score = 100 * (
        math.log1p(count)
        / math.log1p(100)
    )

    return round(
        max(0, min(100, score)),
        2
    )


def calculate_context_score(
    correlated_count=0
):
    """
    Convert the number of related observations
    into a context/correlation score.
    """

    try:
        count = int(correlated_count)
    except (TypeError, ValueError):
        return 0.0

    if count <= 0:
        return 0.0

    score = 100 * (
        math.log1p(count)
        / math.log1p(20)
    )

    return round(
        max(0, min(100, score)),
        2
    )


def get_source_reliability(source_name):
    """
    Return a source reliability score from 0 to 100.
    """

    if not source_name:
        return SOURCE_RELIABILITY[
            "Unknown Source"
        ]

    return SOURCE_RELIABILITY.get(
        str(source_name).strip(),
        SOURCE_RELIABILITY["Unknown Source"]
    )


def classify_risk(risk_score):
    """
    Convert a numerical risk score into
    a severity classification.
    """

    if risk_score <= 20:
        return "INFORMATIONAL"

    if risk_score <= 40:
        return "LOW"

    if risk_score <= 60:
        return "MEDIUM"

    if risk_score <= 80:
        return "HIGH"

    return "CRITICAL"


def calculate_threat_risk(
    severity,
    confidence_score,
    last_seen,
    observation_count,
    source_name,
    correlated_count=0,
):
    """
    Calculate a defensive threat risk score.

    Formula:

    Risk =
        Severity           * 30%
        Confidence         * 25%
        Recency            * 15%
        Frequency          * 10%
        Source Reliability * 10%
        Context            * 10%
    """

    severity_key = (
        str(severity)
        .strip()
        .upper()
    )

    severity_score = SEVERITY_VALUES.get(
        severity_key,
        0
    )

    try:
        confidence = float(
            confidence_score
        )
    except (TypeError, ValueError):
        confidence = 0.0

    confidence = max(
        0,
        min(100, confidence)
    )

    recency_score = calculate_recency_score(
        last_seen
    )

    frequency_score = calculate_frequency_score(
        observation_count
    )

    source_score = get_source_reliability(
        source_name
    )

    context_score = calculate_context_score(
        correlated_count
    )

    risk_score = (
        severity_score * 0.30
        + confidence * 0.25
        + recency_score * 0.15
        + frequency_score * 0.10
        + source_score * 0.10
        + context_score * 0.10
    )

    risk_score = round(
        max(0, min(100, risk_score)),
        2
    )

    risk_level = classify_risk(
        risk_score
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "components": {
            "severity_score": severity_score,
            "confidence_score": round(
                confidence,
                2
            ),
            "recency_score": recency_score,
            "frequency_score": frequency_score,
            "source_reliability_score": source_score,
            "context_score": context_score,
        },
        "weights": {
            "severity": 0.30,
            "confidence": 0.25,
            "recency": 0.15,
            "frequency": 0.10,
            "source_reliability": 0.10,
            "context": 0.10,
        },
        "interpretation": (
            "Risk score represents the estimated "
            "level of concern based on the defined "
            "scoring factors. It does not confirm "
            "compromise or malicious activity."
        ),
    }


def calculate_confidence_score(
    source_name,
    observation_count,
    analyst_confirmed=False,
):
    """
    Calculate an educational confidence score.

    Confidence represents evidence quality,
    not impact or severity.
    """

    source_score = get_source_reliability(
        source_name
    )

    frequency_score = calculate_frequency_score(
        observation_count
    )

    analyst_score = (
        100
        if analyst_confirmed
        else 0
    )

    confidence_score = (
        source_score * 0.50
        + frequency_score * 0.30
        + analyst_score * 0.20
    )

    confidence_score = round(
        max(
            0,
            min(
                100,
                confidence_score
            )
        ),
        2
    )

    if confidence_score <= 20:
        confidence_level = "VERY LOW"
    elif confidence_score <= 40:
        confidence_level = "LOW"
    elif confidence_score <= 60:
        confidence_level = "MEDIUM"
    elif confidence_score <= 80:
        confidence_level = "HIGH"
    else:
        confidence_level = "VERY HIGH"

    return {
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "components": {
            "source_reliability": source_score,
            "observation_frequency": frequency_score,
            "analyst_confirmation": analyst_score,
        },
        "interpretation": (
            "Confidence score represents the quality "
            "and strength of supporting evidence. "
            "It does not indicate business impact."
        ),
    }


def score_indicator(indicator):
    """
    Search the local dataset for an indicator
    and calculate risk and confidence.
    """

    df = load_threat_data()

    search_value = (
        str(indicator)
        .strip()
        .lower()
    )

    matches = df[
        df["indicator_value"]
        .astype(str)
        .str.strip()
        .str.lower()
        == search_value
    ].copy()

    if matches.empty:
        return {
            "found": False,
            "indicator": indicator,
            "message": (
                "Indicator was not found in "
                "the synthetic dataset."
            ),
        }

    latest_row = matches.sort_values(
        "last_seen"
    ).iloc[-1]

    observation_count = len(matches)

    correlated_count = max(
        0,
        len(matches) - 1
    )

    risk_result = calculate_threat_risk(
        severity=latest_row["severity"],
        confidence_score=latest_row[
            "confidence_score"
        ],
        last_seen=latest_row["last_seen"],
        observation_count=observation_count,
        source_name=latest_row["source_name"],
        correlated_count=correlated_count,
    )

    confidence_result = (
        calculate_confidence_score(
            source_name=latest_row[
                "source_name"
            ],
            observation_count=observation_count,
            analyst_confirmed=False,
        )
    )

    return {
        "found": True,
        "indicator": indicator,
        "indicator_type": latest_row[
            "indicator_type"
        ],
        "observation_count": observation_count,
        "severity": latest_row["severity"],
        "risk": risk_result,
        "confidence": confidence_result,
        "source": latest_row[
            "source_name"
        ],
        "status": latest_row["status"],
        "last_seen": latest_row["last_seen"],
        "analyst_note": (
            "This is a synthetic defensive "
            "demonstration. A risk score is not "
            "proof of compromise."
        ),
    }


if __name__ == "__main__":

    print("=" * 70)
    print("Risk & Confidence Scoring Engine Test")
    print("=" * 70)

    test_indicator = "203.0.113.250"

    result = score_indicator(
        test_indicator
    )

    print()
    print("Indicator:", test_indicator)
    print()

    print("Found:")
    print(result.get("found"))

    if result.get("found"):

        print()
        print("Indicator Type:")
        print(result["indicator_type"])

        print()
        print("Observation Count:")
        print(result["observation_count"])

        print()
        print("Severity:")
        print(result["severity"])

        print()
        print("Source:")
        print(result["source"])

        print()
        print("Risk Score:")
        print(
            result["risk"]["risk_score"]
        )

        print()
        print("Risk Level:")
        print(
            result["risk"]["risk_level"]
        )

        print()
        print("Risk Components:")

        for key, value in result[
            "risk"
        ]["components"].items():

            print(
                f"  {key}: {value}"
            )

        print()
        print("Confidence Score:")
        print(
            result["confidence"][
                "confidence_score"
            ]
        )

        print()
        print("Confidence Level:")
        print(
            result["confidence"][
                "confidence_level"
            ]
        )

        print()
        print("Confidence Components:")

        for key, value in result[
            "confidence"
        ]["components"].items():

            print(
                f"  {key}: {value}"
            )

    print()
    print("=" * 70)
    print("Risk scoring completed using local data.")
    print("No external systems were contacted.")
    print("=" * 70)