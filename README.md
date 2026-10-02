# Cybersecurity Awareness & Threat Intelligence Dashboard

Live demo: https://cybersecurity-threatguard.onrender.com/
A defensive cybersecurity education and threat-intelligence analytics platform built with **Python, FastAPI, Pandas, React, Vite, Recharts, and pytest**.

The project combines synthetic threat-intelligence analysis with cybersecurity awareness learning, IOC investigation, risk scoring, security alerts, vulnerability awareness, MITRE ATT&CK context, and a defensive security quiz.

> **Ethical & Safety Notice:** This project is designed exclusively for defensive cybersecurity education and analysis. It uses synthetic demonstration data and does not execute malicious payloads, contact suspicious infrastructure, exploit systems, or perform unauthorized security testing.

---

## 1. Project Overview

Security teams need to understand large amounts of security information and distinguish between observations, indicators, alerts, threats, risk, confidence, and incidents.

This project demonstrates a structured defensive workflow using:

- Synthetic threat-intelligence data
- IOC validation
- Threat enrichment
- Risk scoring
- Confidence scoring
- Threat correlation
- Security alert generation
- MITRE ATT&CK context
- Vulnerability awareness
- REST APIs
- Interactive React dashboards
- Cybersecurity awareness modules
- A 30-question defensive security quiz
- Automated tests

---

## 2. Problem Statement

Cybersecurity information can be difficult to interpret because different concepts are often mixed together.

For example:

- An IOC observation does not automatically mean a system is compromised.
- A high risk score does not prove malicious activity.
- Correlation does not prove attacker attribution.
- A vulnerability record does not prove exploitation.
- An alert requires investigation and supporting evidence.

This project demonstrates how security observations can be organized into a defensive analysis workflow while separating **evidence, risk, confidence, and investigation status**.

---

## 3. Objectives

- Build a defensive threat-intelligence dashboard.
- Generate a large synthetic security dataset.
- Validate common IOC formats.
- Enrich indicators using local threat observations.
- Calculate explainable risk scores.
- Calculate evidence-confidence scores.
- Correlate related threat observations.
- Generate security alerts using defined thresholds.
- Provide MITRE ATT&CK behavioral context.
- Prioritize synthetic CVE observations.
- Provide cybersecurity awareness education.
- Evaluate learning using a security awareness quiz.
- Expose analysis capabilities through a REST API.
- Maintain automated tests for security modules.

---

## 4. Key Features

### Threat Intelligence

- 2,500 synthetic threat records
- Threat categories
- Indicator types
- Severity levels
- Confidence scores
- Risk scores
- Observation timestamps
- Source information
- Status tracking
- Optional MITRE ATT&CK context
- Synthetic CVE identifiers

### IOC Analysis

Supported indicator types:

- IP address
- Domain
- URL
- File hash
- Email/sender domain
- CVE ID

The IOC validator performs syntax and format validation locally without contacting external infrastructure.

### Threat Enrichment

The enrichment engine searches the local synthetic dataset and provides:

- Observation count
- Threat categories
- Highest severity
- Average/max risk
- Average/max confidence
- Statuses
- Sources
- First/last seen
- Related indicators
- ATT&CK context
- Analyst interpretation

### Risk Scoring

Risk is calculated from multiple factors:

| Factor | Weight |
|---|---:|
| Severity | 30% |
| Confidence | 25% |
| Recency | 15% |
| Frequency | 10% |
| Source reliability | 10% |
| Context/correlation | 10% |

Risk bands:

| Score | Level |
|---:|---|
| 0–20 | Informational |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

The risk score represents a level of concern based on defined factors. It does **not** confirm compromise or malicious activity.

### Confidence Scoring

Confidence represents the strength and quality of supporting evidence.

Factors include:

- Source reliability
- Observation frequency
- Analyst confirmation

Confidence and risk are intentionally treated as separate concepts.

### Threat Correlation

The correlation engine identifies relationships based on:

- Same indicator
- Common threat category
- Common source
- MITRE tactic context

It generates a correlation score and cluster identifier.

Correlation does not prove:

- Attacker attribution
- Compromise
- Malicious intent

### Security Alerts

The alert engine generates alerts when defined security thresholds are reached.

Alert states include:

- NEW
- INVESTIGATING
- MONITORING
- RESOLVED
- FALSE_POSITIVE

Alert information includes:

- Alert ID
- Threat ID
- Alert type
- Severity
- Risk score
- Confidence score
- Indicator
- Observation count
- Correlation count
- Status
- Analyst guidance

### MITRE ATT&CK Context

The project provides behavioral context using tactic and technique information present in the synthetic dataset.

The system deliberately does not invent ATT&CK technique IDs when the synthetic data does not contain them.

Mappings are marked as:

`DEMONSTRATION_CONTEXT`

They describe behavior context only and do not prove attribution or compromise.

### Vulnerability Awareness

The vulnerability engine analyzes synthetic CVE-style observations.

It provides:

- CVE observation count
- Severity
- Average risk
- Average confidence
- Priority score
- Priority level
- Categories
- Status
- Defensive recommendation

Priority scoring uses:

- Severity: 50%
- Observation frequency: 25%
- Confidence: 25%

The CVE records in the demonstration dataset are synthetic and should not be interpreted as real vulnerability intelligence.

---

## 5. Cybersecurity Awareness Center

The dashboard contains 12 awareness modules:

1. Phishing Awareness
2. Password & MFA Security
3. Safe Browsing
4. Ransomware Awareness
5. Social Engineering
6. Secure Wi-Fi
7. Mobile Security
8. Cloud Account Security
9. AI-Enabled Scam Awareness
10. Updates & Vulnerabilities
11. USB & Removable Media
12. Incident Reporting

The content focuses on defensive behavior and safe security practices.

---

## 6. Security Awareness Quiz

The platform includes a **30-question defensive cybersecurity quiz** covering phishing, passwords, MFA, safe browsing, ransomware, social engineering, account security, cloud security, incident reporting, and vulnerability awareness.

| Score | Interpretation |
|---:|---|
| 81–100 | Strong |
| 61–80 | Good |
| 41–60 | Basic |
| 0–40 | Needs Improvement |

The result also provides learning recommendations.

---

## 7. Dashboard

The React dashboard provides:

- Threat record statistics
- Unique indicator count
- Critical/high severity counts
- Average risk
- Severity distribution
- Indicator distribution
- Threat-category analysis
- Threat timeline
- Risk overview
- ATT&CK context
- Vulnerability awareness
- Recent security alerts
- IOC investigation
- Awareness Center
- Security Quiz

---

## 8. Architecture

```text
                    ┌─────────────────────────────┐
                    │      React + Vite UI        │
                    │       ThreatGuard           │
                    └──────────────┬──────────────┘
                                   │
                                   │ REST API
                                   ▼
                    ┌─────────────────────────────┐
                    │        FastAPI Backend      │
                    ├─────────────────────────────┤
                    │ Threat APIs                  │
                    │ IOC Search                   │
                    │ Dashboard Statistics         │
                    │ Alerts                       │
                    │ ATT&CK Context               │
                    │ Vulnerability Analysis       │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │      Security Engines       │
                    ├─────────────────────────────┤
                    │ IOC Validator               │
                    │ Enrichment Engine            │
                    │ Risk Engine                  │
                    │ Correlation Engine           │
                    │ Alert Engine                 │
                    │ ATT&CK Mapper                │
                    │ Vulnerability Engine         │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │ Synthetic Threat Dataset    │
                    │ CSV - 2,500 records         │
                    └─────────────────────────────┘
```

---

## 9. Technology Stack

### Backend

- Python
- FastAPI
- Pandas
- Uvicorn

### Frontend

- React
- Vite
- Recharts
- Lucide React
- JavaScript

### Testing

- pytest

### Data

- CSV
- Synthetic security observations

### Development

- Git
- GitHub
- Windows
- Python virtual environment

---

## 10. Project Structure

```text
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
│
├── backend/
│   ├── app.py
│   └── services/
│       ├── ioc_validator.py
│       ├── enrichment_engine.py
│       ├── risk_engine.py
│       ├── correlation_engine.py
│       ├── alert_engine.py
│       ├── attack_mapper.py
│       └── vulnerability_engine.py
│
├── data/
│   ├── threat_intelligence_dataset.csv
│   └── generate_threat_data.py
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── tests/
│   └── test_security_modules.py
│
├── .gitignore
└── README.md
```

---

## 11. Dataset

The project uses a locally generated synthetic dataset containing **2,500 threat observations**.

Example fields:

```text
threat_id
timestamp
threat_name
threat_category
indicator_type
indicator_value
source_name
confidence_score
severity
risk_score
status
first_seen
last_seen
country_or_region_optional
description
mitre_tactic_optional
mitre_technique_optional
cve_id_optional
```

The dataset uses reserved documentation IP ranges, example/invalid domains, synthetic hashes, and synthetic CVE-style identifiers.

No real suspicious infrastructure is contacted by the application.

---

## 12. Installation

### Clone the repository

```cmd
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

### Create and activate the Python environment

```cmd
python -m venv venv
venv\Scriptsctivate
```

### Install backend dependencies

```cmd
pip install fastapi uvicorn pandas pytest
```

### Install frontend dependencies

```cmd
cd frontend
npm install
```

---

## 13. Generate Synthetic Threat Data

From the project root:

```cmd
python data\generate_threat_data.py
```

This generates the local synthetic threat-intelligence CSV.

---

## 14. Run the Backend

From the project root with the virtual environment active:

```cmd
python -m uvicorn backend.app:app --reload
```

The API runs at:

```text
http://127.0.0.1:8000
```

Health endpoint:

```text
http://127.0.0.1:8000/api/health
```

---

## 15. Run the Frontend

Open another Command Prompt:

```cmd
cd frontend
npm run dev
```

Vite will display the local development URL.

The frontend communicates with:

```text
http://127.0.0.1:8000
```

---

## 16. Production Frontend Build

The production build has been tested successfully with:

```cmd
npm run build
```

Build output is generated in:

```text
frontend/dist/
```

---

## 17. REST API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | API health |
| `GET /api/threats` | Threat records |
| `GET /api/threats/{threat_id}` | Threat detail |
| `GET /api/indicators/search?indicator=...` | IOC investigation |
| `GET /api/dashboard/stats` | Dashboard statistics |
| `GET /api/dashboard/trends` | Threat trends |
| `GET /api/alerts` | Security alerts |
| `GET /api/attack/summary` | ATT&CK summary |
| `GET /api/attack/indicator` | ATT&CK indicator context |
| `GET /api/attack/tactic` | Tactic search |
| `GET /api/vulnerabilities` | Vulnerability summary |
| `GET /api/vulnerabilities/{cve_id}` | CVE detail |

Example IOC search:

```text
GET /api/indicators/search?indicator=203.0.113.250
```

---

## 18. Testing

Run the automated test suite:

```cmd
python -m pytest -q
```

Tests cover areas including:

- IOC validation
- Threat enrichment
- Risk scoring
- Confidence scoring
- Threat correlation
- Security alert generation
- ATT&CK context mapping
- Vulnerability analysis
- API behavior

---

## 19. Security Design Principles

This project follows defensive-by-design principles.

### Local Analysis

Threat observations are analyzed locally using the synthetic dataset.

### No Suspicious Infrastructure Contact

The system does not automatically visit domains, connect to IP addresses, download suspicious files, or interact with potentially malicious infrastructure.

### No Exploitation

The project does not contain exploitation functionality.

### No Malware Execution

The application does not execute malware or malicious payloads.

### No Unauthorized Testing

The platform is not designed for unauthorized scanning, penetration testing, credential attacks, or system intrusion.

### Evidence-Based Interpretation

```text
Observation ≠ Alert
Alert ≠ Incident
IOC Match ≠ Compromise
Risk ≠ Proof of Malicious Activity
Correlation ≠ Attribution
```

---

## 20. Risk vs Confidence

A central design principle is separating risk from confidence.

### Risk

Risk answers:

> How much concern does this observation create based on the scoring model?

### Confidence

Confidence answers:

> How strong is the supporting evidence?

Therefore:

```text
High Risk + Low Confidence
```

can exist and should trigger investigation rather than automatic conclusions.

Similarly:

```text
Low Risk + High Confidence
```

can represent a well-supported observation with limited expected impact.

---

## 21. SOC Investigation Workflow

```text
Observation
     │
     ▼
IOC Validation
     │
     ▼
Threat Enrichment
     │
     ▼
Risk + Confidence
     │
     ▼
Correlation
     │
     ▼
Alert Generation
     │
     ▼
Analyst Review
     │
     ▼
Monitoring / Resolution / False Positive
```

The system is intended to support analyst reasoning rather than automatically declaring incidents.

---

## 22. Limitations

The current version intentionally uses synthetic data.

It does not currently provide:

- Live threat-feed integration
- Real-time external IOC enrichment
- Production SIEM integration
- Production SOAR automation
- Real endpoint telemetry
- Real email telemetry
- Real vulnerability scanning
- Real CVE exploitation verification
- STIX/TAXII ingestion
- Enterprise authentication/RBAC

The ATT&CK mappings are demonstration context derived from the local dataset.

---

## 23. Future Improvements

Potential future enhancements include:

- Authorized live threat-intelligence feeds
- STIX/TAXII support
- CISA KEV integration
- EPSS-based vulnerability context
- IOC expiration and lifecycle management
- Alert deduplication
- Alert fatigue reduction
- SIEM integration
- SOAR workflows
- Endpoint telemetry
- Email-security telemetry
- Cloud-security telemetry
- Threat-hunting workflows
- ATT&CK Navigator integration
- Role-based access control
- Docker deployment
- CI/CD pipelines
- Centralized logging
- Advanced clustering
- Executive reporting
- Analyst case management

Any future live integration should use authorized and reputable defensive sources.

---

## 24. Learning Outcomes

This project demonstrates practical understanding of:

- Cyber Threat Intelligence
- IOC analysis
- Security analytics
- Risk assessment
- Confidence scoring
- Threat correlation
- Alert management
- Vulnerability prioritization
- MITRE ATT&CK concepts
- SOC investigation concepts
- Security awareness
- REST API development
- React dashboard development
- Automated testing
- Git/GitHub workflow
- Defensive cybersecurity engineering

---

## 25. GitHub Proof of Work

The repository contains development history showing incremental implementation of:

- Dataset generation
- IOC validation
- Threat enrichment
- Risk and confidence scoring
- Correlation
- Alerting
- ATT&CK context
- Vulnerability awareness
- REST API
- Automated tests
- React frontend

The project was developed as a modular cybersecurity engineering exercise rather than as a single monolithic script.

---

## 26. Suggested Screenshots

Useful screenshots for GitHub, LinkedIn, and the project report:

1. Project structure
2. Synthetic dataset
3. Threat dashboard
4. Severity distribution
5. Threat category chart
6. IOC distribution
7. Threat timeline
8. Risk overview
9. IOC investigation
10. Threat detail
11. Risk/confidence analysis
12. ATT&CK context
13. Vulnerability dashboard
14. Security alerts
15. Awareness Center
16. Security Quiz
17. Quiz result
18. Automated test results
19. REST API response
20. GitHub repository and commit history

---

## 27. Project Status

### Completed

- [x] Synthetic threat dataset
- [x] IOC validator
- [x] Threat enrichment engine
- [x] Risk scoring engine
- [x] Confidence scoring
- [x] Threat correlation engine
- [x] Security alert engine
- [x] MITRE ATT&CK context mapper
- [x] Vulnerability awareness engine
- [x] FastAPI REST API
- [x] React dashboard
- [x] IOC investigation interface
- [x] Awareness Center
- [x] Security Quiz
- [x] Automated tests
- [x] Production frontend build
- [x] Git version control

---

## 28. Conclusion

The Cybersecurity Awareness & Threat Intelligence Dashboard demonstrates how security observations can be transformed into structured defensive intelligence.

The project combines IOC validation, enrichment, risk scoring, confidence analysis, correlation, alerting, vulnerability awareness, ATT&CK context, and security education.

A key principle of the platform is:

> Security analytics should support investigation and informed decision-making rather than automatically treating an indicator as proof of compromise.

---

## 29. Ethical Disclaimer

This project is intended for:

- Education
- Defensive cybersecurity analysis
- Security awareness
- Threat-intelligence learning
- SOC workflow demonstration

It must not be used to:

- Access unauthorized systems
- Exploit vulnerabilities
- Deploy malware
- Steal credentials
- Conduct unauthorized scanning
- Attack networks
- Interact with malicious infrastructure

All demonstration threat data is synthetic or sanitized for educational use.

---

## Author

**Vyshnavi Porandla**

Cybersecurity / Computer Science Student

**Project:** Cybersecurity Awareness & Threat Intelligence Dashboard
