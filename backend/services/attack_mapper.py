"""
MITRE ATT&CK Mapping Engine

Defensive cybersecurity education module.

Important:
- Current project data contains synthetic tactic/technique names.
- This module does not invent ATT&CK technique IDs.
- Mappings are treated as demonstration/context mappings.
- A mapping does not prove attacker attribution or compromise.
"""

from pathlib import Path
import sys

import pandas as pd


# Allow imports when running this file directly.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


DATA_FILE = PROJECT_ROOT / "data" / "threat_intelligence_dataset.csv"


def load_threat_data():
    """Load the local synthetic threat intelligence dataset."""
    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Synthetic threat dataset not found: {DATA_FILE}"
        )

    return pd.read_csv(DATA_FILE)


def normalize_value(value):
    """Normalize an indicator or text value for matching."""
    if value is None:
        return ""

    return str(value).strip().lower()


def map_threat_to_attack(threat_row):
    """
    Create a defensive ATT&CK-context mapping from an observed threat row.

    The dataset's tactic and technique names are preserved as supplied.
    No ATT&CK technique IDs are invented.
    """

    if isinstance(threat_row, pd.Series):
        row = threat_row.to_dict()
    elif isinstance(threat_row, dict):
        row = threat_row
    else:
        raise TypeError("threat_row must be a pandas Series or dictionary.")

    tactic = str(row.get("mitre_tactic_optional", "")).strip()
    technique = str(row.get("mitre_technique_optional", "")).strip()

    if tactic.lower() in {"nan", "none"}:
        tactic = ""

    if technique.lower() in {"nan", "none"}:
        technique = ""

    if not tactic and not technique:
        return {
            "mapped": False,
            "mapping_type": "DEMONSTRATION_CONTEXT",
            "tactic": None,
            "technique": None,
            "technique_id": None,
            "reason": (
                "No tactic or technique context is available in the "
                "synthetic threat observation."
            ),
            "interpretation": (
                "No ATT&CK-context mapping was assigned."
            ),
        }

    return {
        "mapped": True,
        "mapping_type": "DEMONSTRATION_CONTEXT",
        "tactic": tactic or None,
        "technique": technique or None,
        "technique_id": None,
        "reason": (
            "The synthetic dataset contains tactic/technique context "
            "associated with this observation."
        ),
        "interpretation": (
            "This mapping describes behavior context only. It does not "
            "prove attacker attribution, compromise, or malicious intent."
        ),
    }


def map_indicator_to_attack(indicator):
    """
    Find observations for an indicator and return their ATT&CK-context
    mappings.
    """

    df = load_threat_data()

    target = normalize_value(indicator)

    if not target:
        return {
            "found": False,
            "indicator": indicator,
            "mapping_count": 0,
            "mappings": [],
            "message": "Indicator cannot be empty.",
        }

    matches = df[
        df["indicator_value"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
        == target
    ]

    if matches.empty:
        return {
            "found": False,
            "indicator": indicator,
            "mapping_count": 0,
            "mappings": [],
            "message": (
                "Indicator was not found in the synthetic threat dataset."
            ),
        }

    mappings = []

    for _, row in matches.iterrows():
        mapping = map_threat_to_attack(row)

        mappings.append(
            {
                "threat_id": row.get("threat_id"),
                "threat_name": row.get("threat_name"),
                "threat_category": row.get("threat_category"),
                "indicator_type": row.get("indicator_type"),
                "indicator_value": row.get("indicator_value"),
                "severity": row.get("severity"),
                "tactic": mapping["tactic"],
                "technique": mapping["technique"],
                "technique_id": mapping["technique_id"],
                "mapping_type": mapping["mapping_type"],
                "reason": mapping["reason"],
                "interpretation": mapping["interpretation"],
            }
        )

    return {
        "found": True,
        "indicator": indicator,
        "mapping_count": len(mappings),
        "mappings": mappings,
        "message": (
            "ATT&CK-context mappings were generated from the local "
            "synthetic dataset."
        ),
    }


def get_attack_summary():
    """
    Produce a summary of tactic and technique context found in the
    synthetic dataset.
    """

    df = load_threat_data()

    tactic_counts = (
        df["mitre_tactic_optional"]
        .dropna()
        .astype(str)
        .str.strip()
    )

    technique_counts = (
        df["mitre_technique_optional"]
        .dropna()
        .astype(str)
        .str.strip()
    )

    tactic_counts = tactic_counts[
        ~tactic_counts.str.lower().isin({"", "nan", "none"})
    ]

    technique_counts = technique_counts[
        ~technique_counts.str.lower().isin({"", "nan", "none"})
    ]

    return {
        "mapping_type": "DEMONSTRATION_CONTEXT",
        "total_threat_records": len(df),
        "records_with_tactic_context": int(tactic_counts.shape[0]),
        "records_with_technique_context": int(technique_counts.shape[0]),
        "unique_tactics": sorted(tactic_counts.unique().tolist()),
        "unique_techniques": sorted(technique_counts.unique().tolist()),
        "tactic_counts": tactic_counts.value_counts().to_dict(),
        "technique_counts": technique_counts.value_counts().to_dict(),
        "note": (
            "These names come from the project's synthetic dataset. "
            "They should not be interpreted as verified ATT&CK IDs."
        ),
    }


def find_by_tactic(tactic):
    """Find synthetic threat observations associated with a tactic name."""

    df = load_threat_data()

    target = normalize_value(tactic)

    if not target:
        return []

    matches = df[
        df["mitre_tactic_optional"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
        == target
    ]

    results = []

    for _, row in matches.iterrows():
        results.append(
            {
                "threat_id": row["threat_id"],
                "threat_name": row["threat_name"],
                "threat_category": row["threat_category"],
                "indicator": row["indicator_value"],
                "severity": row["severity"],
                "tactic": row["mitre_tactic_optional"],
                "technique": row["mitre_technique_optional"],
            }
        )

    return results


if __name__ == "__main__":
    print("=" * 70)
    print("MITRE ATT&CK CONTEXT MAPPING ENGINE")
    print("=" * 70)

    test_indicator = "203.0.113.250"

    print(f"\nTesting indicator: {test_indicator}")

    result = map_indicator_to_attack(test_indicator)

    print(f"Found: {result['found']}")
    print(f"Mapping count: {result['mapping_count']}")

    for mapping in result["mappings"]:
        print("\n--- Mapping ---")
        print(f"Threat ID: {mapping['threat_id']}")
        print(f"Threat name: {mapping['threat_name']}")
        print(f"Category: {mapping['threat_category']}")
        print(f"Severity: {mapping['severity']}")
        print(f"Tactic: {mapping['tactic']}")
        print(f"Technique: {mapping['technique']}")
        print(f"Technique ID: {mapping['technique_id']}")
        print(f"Mapping type: {mapping['mapping_type']}")
        print(f"Reason: {mapping['reason']}")
        print(f"Interpretation: {mapping['interpretation']}")

    print("\n" + "=" * 70)
    print("ATT&CK CONTEXT SUMMARY")
    print("=" * 70)

    summary = get_attack_summary()

    print(f"Total threat records: {summary['total_threat_records']}")
    print(
        "Records with tactic context: "
        f"{summary['records_with_tactic_context']}"
    )
    print(
        "Records with technique context: "
        f"{summary['records_with_technique_context']}"
    )

    print("\nTactics:")
    for tactic, count in summary["tactic_counts"].items():
        print(f"  {tactic}: {count}")

    print("\nTechniques:")
    for technique, count in summary["technique_counts"].items():
        print(f"  {technique}: {count}")

    print("\nSafety note:")
    print(summary["note"])