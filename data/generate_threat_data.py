import csv
import random
import hashlib
from datetime import datetime, timedelta
from pathlib import Path


# ============================================================
# CYBERSECURITY AWARENESS & THREAT INTELLIGENCE DASHBOARD
# Synthetic Threat Intelligence Dataset Generator
# ============================================================

OUTPUT_FILE = Path(__file__).parent / "threat_intelligence_dataset.csv"

TOTAL_RECORDS = 2500

random.seed(42)


THREAT_CATEGORIES = [
    "PHISHING",
    "MALWARE",
    "RANSOMWARE",
    "CREDENTIAL THREATS",
    "WEB THREATS",
    "NETWORK THREATS",
    "VULNERABILITY EXPOSURE",
    "SOCIAL ENGINEERING",
    "DATA EXPOSURE",
    "ACCOUNT SECURITY",
]

INDICATOR_TYPES = [
    "IP ADDRESS",
    "DOMAIN",
    "URL",
    "FILE HASH",
    "EMAIL/SENDER DOMAIN",
    "CVE ID",
]

SOURCES = [
    ("Internal SOC", "A"),
    ("Security Vendor", "A"),
    ("Public Threat Feed", "B"),
    ("Research Report", "B"),
    ("Community Submission", "C"),
    ("Unknown Source", "D"),
]

SEVERITIES = [
    "INFORMATIONAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

STATUSES = [
    "NEW",
    "UNDER_REVIEW",
    "MONITORING",
    "CLOSED",
    "FALSE_POSITIVE",
]

THREAT_NAMES = {
    "PHISHING": [
        "Synthetic Credential Phishing Campaign",
        "Fake Account Verification Activity",
        "Synthetic Login Impersonation Campaign",
        "Suspicious Credential Collection Pattern",
    ],
    "MALWARE": [
        "Synthetic Malware Indicator Cluster",
        "Suspicious File Hash Observation",
        "Synthetic Malicious File Pattern",
        "Endpoint Malware Indicator Cluster",
    ],
    "RANSOMWARE": [
        "Synthetic Ransomware Indicator Cluster",
        "File Encryption Threat Pattern",
        "Synthetic Ransomware Infrastructure",
        "Ransomware Awareness Simulation",
    ],
    "CREDENTIAL THREATS": [
        "Credential Exposure Indicator",
        "Synthetic Account Credential Threat",
        "Suspicious Authentication Pattern",
        "Credential Abuse Observation",
    ],
    "WEB THREATS": [
        "Suspicious Web Infrastructure",
        "Synthetic Web Threat Cluster",
        "Web Application Threat Observation",
        "Suspicious Web Resource Pattern",
    ],
    "NETWORK THREATS": [
        "Synthetic Network Threat Observation",
        "Suspicious Network Indicator Cluster",
        "Network Communication Anomaly",
        "Synthetic Network Infrastructure",
    ],
    "VULNERABILITY EXPOSURE": [
        "Synthetic Vulnerability Exposure",
        "Unpatched Software Awareness Record",
        "Synthetic Vulnerability Observation",
        "Vulnerability Risk Assessment",
    ],
    "SOCIAL ENGINEERING": [
        "Synthetic Social Engineering Campaign",
        "Impersonation Activity Observation",
        "Social Engineering Risk Pattern",
        "Synthetic Human-Factor Threat",
    ],
    "DATA EXPOSURE": [
        "Synthetic Data Exposure Observation",
        "Potential Data Exposure Pattern",
        "Sensitive Data Protection Alert",
        "Synthetic Information Exposure",
    ],
    "ACCOUNT SECURITY": [
        "Suspicious Account Activity",
        "Synthetic Account Security Event",
        "Authentication Risk Observation",
        "Account Protection Alert",
    ],
}


DESCRIPTIONS = {
    "PHISHING":
        "Synthetic defensive observation representing a possible phishing-related indicator.",
    "MALWARE":
        "Synthetic defensive observation representing a suspicious file or malware-related indicator.",
    "RANSOMWARE":
        "Synthetic defensive observation representing a ransomware-related risk pattern.",
    "CREDENTIAL THREATS":
        "Synthetic defensive observation representing a credential-related security risk.",
    "WEB THREATS":
        "Synthetic defensive observation representing a suspicious web-related indicator.",
    "NETWORK THREATS":
        "Synthetic defensive observation representing a network-related security risk.",
    "VULNERABILITY EXPOSURE":
        "Synthetic defensive observation representing potential vulnerability exposure.",
    "SOCIAL ENGINEERING":
        "Synthetic defensive observation representing a social-engineering-related risk.",
    "DATA EXPOSURE":
        "Synthetic defensive observation representing a possible data exposure concern.",
    "ACCOUNT SECURITY":
        "Synthetic defensive observation representing an account-security-related risk.",
}


MITRE_TACTICS = [
    "Initial Access",
    "Credential Access",
    "Execution",
    "Persistence",
    "Discovery",
    "Collection",
    "Command and Control",
    "Impact",
]


MITRE_TECHNIQUES = [
    "Phishing",
    "Valid Accounts",
    "User Execution",
    "Account Discovery",
    "Credential Dumping",
    "Data from Information Repositories",
    "Application Layer Protocol",
    "Data Encrypted for Impact",
]


def generate_ip(index):
    """
    Uses documentation/example IP ranges.
    These are reserved ranges intended for examples and documentation.
    """
    ranges = [
        "192.0.2",
        "198.51.100",
        "203.0.113",
    ]

    network = random.choice(ranges)
    host = (index % 254) + 1

    return f"{network}.{host}"


def generate_domain(index):
    """
    Uses fictional .invalid domains.
    """
    names = [
        "login-check",
        "security-alert",
        "account-verify",
        "mail-protection",
        "identity-check",
        "service-notice",
        "secure-login",
        "credential-review",
        "system-alert",
        "account-support",
    ]

    name = random.choice(names)

    return f"{name}-{index}.invalid"


def generate_url(index):
    domain = generate_domain(index)

    paths = [
        "/verify",
        "/account/check",
        "/security/notice",
        "/login",
        "/identity/verify",
        "/review",
    ]

    return f"https://{domain}{random.choice(paths)}"


def generate_hash(index):
    """
    Generates a deterministic SHA-256-looking synthetic value.
    It is NOT associated with a real file.
    """
    value = f"synthetic-demo-file-{index}-{random.random()}"

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def generate_email_domain(index):
    return f"sender-{index}.invalid"


def generate_cve(index):
    year = random.choice([2022, 2023, 2024, 2025, 2026])

    number = 1000 + index

    return f"CVE-{year}-{number}"


def generate_indicator(indicator_type, index):
    if indicator_type == "IP ADDRESS":
        return generate_ip(index)

    if indicator_type == "DOMAIN":
        return generate_domain(index)

    if indicator_type == "URL":
        return generate_url(index)

    if indicator_type == "FILE HASH":
        return generate_hash(index)

    if indicator_type == "EMAIL/SENDER DOMAIN":
        return generate_email_domain(index)

    if indicator_type == "CVE ID":
        return generate_cve(index)

    return "unknown.invalid"


def choose_severity():
    """
    Weighted severity generation.
    Most records are low/medium, while fewer are critical.
    """
    return random.choices(
        SEVERITIES,
        weights=[8, 25, 35, 24, 8],
        k=1
    )[0]


def severity_base_score(severity):
    scores = {
        "INFORMATIONAL": 10,
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 95,
    }

    return scores[severity]


def calculate_risk(severity, confidence):
    """
    Demonstration risk calculation.

    Severity contributes 60%.
    Confidence contributes 40%.

    This is a simplified educational model.
    """
    severity_score = severity_base_score(severity)

    risk = (
        severity_score * 0.60
        + confidence * 0.40
    )

    return round(min(max(risk, 0), 100), 2)


def choose_status(risk):
    if risk >= 80:
        return random.choice([
            "NEW",
            "UNDER_REVIEW",
            "MONITORING",
        ])

    return random.choice(STATUSES)


def choose_source():
    return random.choice(SOURCES)


def choose_mitre(category):
    """
    MITRE mapping is synthetic and educational.
    It is included only where a broad behavioral relationship
    can reasonably be demonstrated.
    """

    mapping = {
        "PHISHING": ("Initial Access", "Phishing"),
        "CREDENTIAL THREATS": ("Credential Access", "Valid Accounts"),
        "ACCOUNT SECURITY": ("Credential Access", "Valid Accounts"),
        "MALWARE": ("Execution", "User Execution"),
        "RANSOMWARE": ("Impact", "Data Encrypted for Impact"),
        "SOCIAL ENGINEERING": ("Initial Access", "Phishing"),
        "DATA EXPOSURE": ("Collection", "Data from Information Repositories"),
        "WEB THREATS": ("Initial Access", "Phishing"),
        "NETWORK THREATS": ("Command and Control", "Application Layer Protocol"),
        "VULNERABILITY EXPOSURE": ("Initial Access", "User Execution"),
    }

    return mapping.get(category, (None, None))

def generate_record(index):
    category = random.choice(THREAT_CATEGORIES)

    indicator_type = random.choice(INDICATOR_TYPES)

    indicator_value = generate_indicator(
        indicator_type,
        index
    )

    severity = choose_severity()

    confidence = random.randint(25, 98)

    risk = calculate_risk(
        severity,
        confidence
    )

    source_name, reliability = choose_source()

    now = datetime.now()

    first_seen = now - timedelta(
        days=random.randint(1, 180)
    )

    last_seen = first_seen + timedelta(
        days=random.randint(0, 20),
        hours=random.randint(0, 23),
    )

    if last_seen > now:
        last_seen = now

    threat_id = f"THR-2026-{index:04d}"

    threat_name = random.choice(
        THREAT_NAMES[category]
    )

    mitre_tactic, mitre_technique = choose_mitre(
        category
    )

    cve_id = ""

    if indicator_type == "CVE ID":
        cve_id = indicator_value

    country_or_region = random.choice([
        "Demo Region A",
        "Demo Region B",
        "Demo Region C",
        "Synthetic Region",
        "Not Available",
    ])

    status = choose_status(risk)

    return {
        "threat_id": threat_id,
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "threat_name": threat_name,
        "threat_category": category,
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "source_name": source_name,
        "source_reliability": reliability,
        "confidence_score": confidence,
        "severity": severity,
        "risk_score": risk,
        "status": status,
        "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "country_or_region_optional": country_or_region,
        "description": DESCRIPTIONS[category],
        "mitre_tactic_optional": mitre_tactic or "",
        "mitre_technique_optional": mitre_technique or "",
        "cve_id_optional": cve_id,
    }




def main():
    print("=" * 70)
    print("Synthetic Threat Intelligence Dataset Generator")
    print("=" * 70)

    print()
    print("Generating safe synthetic cybersecurity records...")
    print(f"Target records: {TOTAL_RECORDS}")
    print()

    records = []

    for index in range(1, TOTAL_RECORDS + 1):
        records.append(
            generate_record(index)
        )

    fieldnames = [
        "threat_id",
        "timestamp",
        "threat_name",
        "threat_category",
        "indicator_type",
        "indicator_value",
        "source_name",
        "source_reliability",
        "confidence_score",
        "severity",
        "risk_score",
        "status",
        "first_seen",
        "last_seen",
        "country_or_region_optional",
        "description",
        "mitre_tactic_optional",
        "mitre_technique_optional",
        "cve_id_optional",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(records)

    print("Dataset generated successfully!")
    print()
    print(f"File: {OUTPUT_FILE}")
    print(f"Records: {len(records)}")
    print()
    print("IMPORTANT:")
    print("- All indicators are synthetic.")
    print("- No suspicious infrastructure was contacted.")
    print("- No malware was executed.")
    print("- IOC presence does NOT mean confirmed compromise.")
    print("=" * 70)


if __name__ == "__main__":
    main()