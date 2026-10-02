from pathlib import Path
from typing import Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# SERVICE IMPORTS
# ============================================================

from backend.services.enrichment_engine import (
    load_threat_data,
    enrich_indicator,
)

from backend.services.correlation_engine import (
    correlate_indicator,
)

from backend.services.alert_engine import (
    generate_alert_from_indicator,
    generate_alerts_from_dataset,
)

from backend.services.attack_mapper import (
    map_indicator_to_attack,
    get_attack_summary,
    find_by_tactic,
)

from backend.services.vulnerability_engine import (
    analyze_cve,
    get_vulnerability_summary,
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Cybersecurity Threat Intelligence Dashboard",
    description=(
        "Defensive cybersecurity dashboard for synthetic threat "
        "intelligence, IOC analysis, risk awareness, alerts, "
        "MITRE ATT&CK context, and vulnerability awareness."
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# JSON SAFETY HELPER
# ============================================================

def make_json_safe(value):
    """
    Convert Pandas/NumPy values into standard Python values
    that FastAPI can serialize as JSON.
    """

    if value is None:
        return None

    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, TypeError):
            pass

    if isinstance(value, dict):
        return {
            str(key): make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            make_json_safe(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            make_json_safe(item)
            for item in value
        ]

    if isinstance(value, set):
        return [
            make_json_safe(item)
            for item in value
        ]

    return value


# ============================================================
# DATASET HELPER
# ============================================================

def get_dataset():
    """
    Load the synthetic threat intelligence dataset.
    """

    data_path = Path("data/threat_intelligence_dataset.csv")

    if not data_path.exists():
        raise HTTPException(
            status_code=500,
            detail="Threat intelligence dataset was not found.",
        )

    try:
        return load_threat_data()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load threat dataset: {exc}",
        )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "service": "Cybersecurity Threat Intelligence Dashboard",
        "status": "running",
        "version": "1.0.0",
        "mode": "defensive synthetic-data demonstration",
        "docs": "/docs",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "cybersecurity-threat-intelligence-dashboard",
    }


# ============================================================
# API INFORMATION
# ============================================================

@app.get("/api")
def api_information():
    return {
        "service": "Cybersecurity Threat Intelligence API",
        "version": "1.0.0",
        "endpoints": [
            "/api/health",
            "/api/threats",
            "/api/threats/{threat_id}",
            "/api/indicators/search",
            "/api/dashboard/stats",
            "/api/dashboard/trends",
            "/api/alerts",
            "/api/attack/summary",
            "/api/attack/indicator",
            "/api/vulnerabilities",
            "/api/vulnerabilities/{cve_id}",
        ],
    }


# ============================================================
# THREATS
# ============================================================

@app.get("/api/threats")
def get_threats(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    indicator_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    df = get_dataset()

    if category:
        df = df[
            df["threat_category"].astype(str).str.upper()
            == category.upper()
        ]

    if severity:
        df = df[
            df["severity"].astype(str).str.upper()
            == severity.upper()
        ]

    if status:
        df = df[
            df["status"].astype(str).str.upper()
            == status.upper()
        ]

    if indicator_type:
        df = df[
            df["indicator_type"].astype(str).str.upper()
            == indicator_type.upper()
        ]

    df = df.head(limit)

    records = df.to_dict(orient="records")

    return make_json_safe({
        "count": len(records),
        "threats": records,
    })


# ============================================================
# SINGLE THREAT
# ============================================================

@app.get("/api/threats/{threat_id}")
def get_threat(threat_id: str):
    df = get_dataset()

    matches = df[
        df["threat_id"].astype(str).str.upper()
        == threat_id.upper()
    ]

    if matches.empty:
        raise HTTPException(
            status_code=404,
            detail="Threat was not found.",
        )

    record = matches.iloc[0].to_dict()

    return make_json_safe({
        "found": True,
        "threat": record,
    })


# ============================================================
# IOC SEARCH
# ============================================================

@app.get("/api/indicators/search")
def search_indicator(indicator: str):
    indicator = indicator.strip()

    if not indicator:
        raise HTTPException(
            status_code=400,
            detail="Indicator cannot be empty.",
        )

    enrichment = enrich_indicator(indicator)
    correlation = correlate_indicator(indicator)
    attack_mapping = map_indicator_to_attack(indicator)
    alert = generate_alert_from_indicator(indicator)

    if not enrichment.get("found"):
        return make_json_safe({
            "found": False,
            "indicator": indicator,
            "message": (
                "Indicator was not found in the synthetic dataset."
            ),
            "safety_note": (
                "Dataset absence does not prove that an indicator "
                "is safe or malicious."
            ),
        })

    response = {
        "found": True,
        "indicator": indicator,
        "enrichment": enrichment,
        "correlation": correlation,
        "attack_mapping": attack_mapping,
        "alert": alert,
    }

    return make_json_safe(response)


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.get("/api/dashboard/stats")
def dashboard_stats():
    df = get_dataset()

    severity_distribution = (
        df["severity"]
        .value_counts()
        .to_dict()
    )

    category_distribution = (
        df["threat_category"]
        .value_counts()
        .to_dict()
    )

    indicator_distribution = (
        df["indicator_type"]
        .value_counts()
        .to_dict()
    )

    status_distribution = (
        df["status"]
        .value_counts()
        .to_dict()
    )

    return make_json_safe({
        "total_threats": len(df),
        "unique_indicators": int(
            df["indicator_value"].nunique()
        ),
        "unique_threat_categories": int(
            df["threat_category"].nunique()
        ),
        "unique_sources": int(
            df["source_name"].nunique()
        ),
        "severity_distribution": severity_distribution,
        "category_distribution": category_distribution,
        "indicator_distribution": indicator_distribution,
        "status_distribution": status_distribution,
        "average_risk_score": float(
            df["risk_score"].mean()
        ),
        "average_confidence_score": float(
            df["confidence_score"].mean()
        ),
    })


# ============================================================
# DASHBOARD TRENDS
# ============================================================

@app.get("/api/dashboard/trends")
def dashboard_trends():
    df = get_dataset()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    df = df.dropna(subset=["timestamp"])

    df["date"] = df["timestamp"].dt.date.astype(str)

    trends = (
        df.groupby("date")
        .size()
        .reset_index(name="count")
    )

    return make_json_safe({
        "trends": trends.to_dict(orient="records"),
    })


# ============================================================
# SECURITY ALERTS
# ============================================================
@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        alerts = generate_alerts_from_dataset()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to generate alerts: {exc}",
        )

    if severity:
        alerts = [
            alert
            for alert in alerts
            if str(alert.get("severity", "")).upper()
            == severity.upper()
        ]

    if status:
        alerts = [
            alert
            for alert in alerts
            if str(alert.get("status", "")).upper()
            == status.upper()
        ]

    # Limit before JSON serialization
    alerts = alerts[:limit]

    return make_json_safe({
        "count": len(alerts),
        "alerts": alerts,
    })

# ============================================================
# MITRE ATT&CK SUMMARY
# ============================================================

@app.get("/api/attack/summary")
def attack_summary():
    summary = get_attack_summary()

    return make_json_safe(summary)


# ============================================================
# MITRE ATT&CK INDICATOR MAPPING
# ============================================================

@app.get("/api/attack/indicator")
def attack_indicator(indicator: str):
    indicator = indicator.strip()

    if not indicator:
        raise HTTPException(
            status_code=400,
            detail="Indicator cannot be empty.",
        )

    result = map_indicator_to_attack(indicator)

    return make_json_safe(result)


# ============================================================
# MITRE ATT&CK TACTIC SEARCH
# ============================================================

@app.get("/api/attack/tactic")
def attack_tactic(tactic: str):
    tactic = tactic.strip()

    if not tactic:
        raise HTTPException(
            status_code=400,
            detail="Tactic cannot be empty.",
        )

    result = find_by_tactic(tactic)

    return make_json_safe(result)


# ============================================================
# VULNERABILITY SUMMARY
# ============================================================

@app.get("/api/vulnerabilities")
def vulnerabilities():
    summary = get_vulnerability_summary()

    return make_json_safe(summary)


# ============================================================
# SINGLE CVE ANALYSIS
# ============================================================

@app.get("/api/vulnerabilities/{cve_id}")
def vulnerability(cve_id: str):
    cve_id = cve_id.strip().upper()

    if not cve_id.startswith("CVE-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid CVE format.",
        )

    result = analyze_cve(cve_id)

    return make_json_safe(result)


# ============================================================
# STARTUP MESSAGE
# ============================================================

@app.on_event("startup")
def startup_message():
    print(
        "Cybersecurity Threat Intelligence API started "
        "using synthetic defensive data."
    )