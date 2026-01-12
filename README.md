# SafeOps

SafeOps is a modular DevSecOps platform that automates CI/CD security analysis. It ingests pipeline logs, parses events, detects vulnerabilities with rules, flags behavioral anomalies with ML, suggests fixes, and generates audit-ready reports—all surfaced through a web dashboard.

## Highlights

- Log ingestion from CI/CD runs and GitHub Actions workflows
- Rule-based vulnerability detection aligned with OWASP, SLSA, CIS
- ML-based anomaly detection (Isolation Forest)
- Template-driven remediation suggestions
- PDF/JSON report generation
- Real-time dashboard with metrics and trends

## Architecture Overview

SafeOps is composed of multiple services behind an NGINX gateway:

- **Log Collector** (Node/Express + MongoDB): upload logs, fetch workflows
- **Log Parser** (Flask + MongoDB): parse logs into structured events
- **Vulnerability Detector** (Flask + Postgres): rule-based scanning
- **Fix Suggester** (Flask + Postgres): remediation templates
- **Anomaly Detector** (Flask + TimescaleDB): ML anomaly detection
- **Report Generator** (Node + Postgres): PDF/JSON reports
- **Dashboard** (React/Vite): UI for monitoring and analysis

## Tech Stack

- **Backend:** Python (Flask), Node.js
- **Frontend:** React, Vite, Tailwind
- **Databases:** MongoDB, PostgreSQL, TimescaleDB
- **Messaging:** RabbitMQ
- **Gateway:** NGINX
- **CI/CD:** Jenkins, SonarQube
- **ML:** scikit-learn (Isolation Forest)

## Repository Layout

```
./
├── docs/
│   ├── report/              # LaTeX report + figures + PDF
│   ├── media/               # Demo video
│   └── wiki/                # Project wiki content
├── gateway/                 # NGINX config
├── jenkins/                 # Jenkins image build
├── services/                # Microservices
├── docker-compose.yml       # Full stack orchestration
└── Jenkinsfile              # CI pipeline
```

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Git

### Run the stack

```bash
docker-compose up -d
```

Dashboard: `http://localhost:3007`
Gateway: `http://localhost:80`

### Key service ports

| Service | Port |
| --- | --- |
| Dashboard | 3007 |
| Log Collector | 3001 |
| Log Parser | 3002 |
| Vuln Detector | 3003 |
| Fix Suggester | 3004 |
| Anomaly Detector | 3005 |
| Report Generator | 3006 |
| Jenkins | 8080 |
| SonarQube | 9000 |
| RabbitMQ Mgmt | 15672 |

## Using the Platform

- Upload CI/CD logs or fetch GitHub Actions workflows from the dashboard.
- The parser and detectors run automatically (or trigger manually from the UI).
- Generate reports from the Pipelines view.

## Reports

- LaTeX source: `docs/report/Report.tex`
- PDF report: `docs/report/Report.pdf`

To rebuild the report:

```bash
pdflatex docs/report/Report.tex
```


## Team

- Hind Soulaimani
- Maryam Chentouf
- Houssam Joudar
- Oussama Ben Zian

## License

MIT License. See `LICENSE`.
