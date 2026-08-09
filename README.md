# Cyber Threat Intelligence Framework

A Java-based cyber threat detection and analysis system that analyzes login logs, scores IP risk using machine learning, detects threats in real time, auto-blocks critical IPs, and presents everything through an interactive offline HTML dashboard — all powered by Weka ML and SQLite.

![Java](https://img.shields.io/badge/Java-17-orange) ![SQLite](https://img.shields.io/badge/SQLite-3.45-blue) ![Weka](https://img.shields.io/badge/Weka-3.8.6-green) ![Maven](https://img.shields.io/badge/Maven-3.9-red) ![License](https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey)

---

## About

**Author:** Nilesh Kumar Mohanty | **Version:** 1.1 | **Year:** 2026

An end-to-end Cyber Threat Intelligence (CTI) system built in Java 17. It runs as a single console application — initializes an SQLite database, loads sample login/network data, trains ML models (Random Forest + J48 Decision Tree) to score IP risk, detects and classifies threats, auto-blocks critical IPs, exports CSV reports, and generates a fully offline, interactive HTML dashboard for visualizing everything.

---

## Features

| Module | Technique | Output |
|---|---|---|
| Login Analysis | Rule-based pattern matching | Failed login detection |
| Risk Scoring | ML (Random Forest / J48 Decision Tree via Weka) | Risk score + risk level per IP |
| Threat Detection | Signature + behavior-based detection | Categorized threat alerts (Critical/High/Medium/Low) |
| Duplicate Prevention | State-check before insert | No repeated threats/sample data across multiple runs |
| Auto-Blocking | Rule engine on critical threats | Automatic IP blacklisting |
| Alerting | Event-driven alert service | Real-time + daily summary alerts |
| Reporting | CSV export | Threats, failed logins, risk scores |
| **Dashboard** | **Offline HTML + Canvas 2D + vanilla JS** | **Interactive charts, live search/filter/sort, CSV download, print-to-PDF** |
| Audit Logging | Persistent system log | Full traceable audit trail |

---

## Dashboard Highlights

Generated at `reports/dashboard.html` — open in any browser, no internet required.

- 5 animated summary cards (Total Threats, Critical, High, Failed Logins, High-Risk IPs)
- Click-able donut chart — click a severity slice to instantly filter the threats table
- Live search bar + severity filter chips (All / Critical / High / Medium / Low)
- Sortable table columns (click any header to sort ascending/descending)
- Animated "Top Risky IPs" bar chart
- One-click CSV downloads: Threats, Risk Scores, Failed Logins, or a combined Full Report
- Print / Save-as-PDF button (uses the browser's native print dialog — works fully offline)

---

## Project Structure

```
CyberThreatIntelligence/
├── src/main/java/com/security/
│   ├── Main.java                     ← Entry point, orchestrates the pipeline
│   ├── config/
│   │   ├── AppConfig.java            ← App-wide configuration
│   │   └── DBConnection.java         ← SQLite connection handler
│   ├── dao/
│   │   ├── LoginDAO.java             ← Login log persistence
│   │   ├── ThreatDAO.java            ← Threat alert persistence
│   │   ├── RiskScoreDAO.java         ← Risk score persistence
│   │   ├── AuditLogDAO.java          ← Audit trail persistence
│   │   └── UserDAO.java              ← User data access
│   ├── model/
│   │   ├── User.java, LoginLog.java, RiskScore.java
│   │   ├── ThreatAlert.java, AuditLog.java
│   ├── service/
│   │   ├── LoginAnalyzer.java        ← Analyzes login patterns
│   │   ├── ThreatDetector.java       ← Detects, classifies & de-duplicates threats
│   │   ├── RiskScorer.java           ← ML-based IP risk scoring
│   │   ├── detection/
│   │   │   └── IPBlacklistService.java   ← Auto-blocks critical IPs
│   │   ├── ml/
│   │   │   ├── ModelTrainer.java     ← Trains Random Forest + J48
│   │   │   ├── ModelEvaluator.java   ← Evaluates trained models
│   │   │   ├── ModelPersistence.java ← Saves/loads .model files
│   │   │   └── RealTimePredictor.java← Loads model for live scoring
│   │   └── output/
│   │       ├── AlertService.java     ← Sends alerts + summaries
│   │       ├── CSVExporter.java      ← Exports CSV reports
│   │       ├── ReportGenerator.java  ← Generates full text report
│   │       └── DashboardGenerator.java ← Generates interactive HTML dashboard
│   └── utils/
│       ├── DateHelper.java
│       ├── ValidationUtil.java
│       └── Logger.java
├── src/main/resources/
│   ├── schema.sql                    ← Database schema
│   └── sample_data.sql               ← Seed data
├── reports/                          ← Auto-generated CSV reports + dashboard.html
├── logs/                             ← Auto-generated system logs
├── models/                           ← Auto-generated trained ML models
├── pom.xml
└── README.md
```

---

## Quick Start

### Prerequisites

Java 17+ · Apache Maven 3.8+ · IntelliJ IDEA (recommended)

### 1 — Clone

```bash
git clone https://github.com/Nilesh7832/CyberThreatIntelligence.git
cd CyberThreatIntelligence
```

### 2 — Build

```bash
mvn clean compile
```

### 3 — Run

Right-click `Main.java` in IntelliJ → Run, or:

```bash
mvn compile exec:java "-Dexec.mainClass=com.security.Main"
```

### 4 — View the Dashboard

Open `reports/dashboard.html` in any browser (just double-click the file).

### 5 — Outputs (auto-created in project root)

| Folder/File | Contents |
|---|---|
| `reports/dashboard.html` | Interactive visual dashboard (open in browser) |
| `reports/threats_<date>.csv` | All detected threat alerts |
| `reports/failed_logins_<date>.csv` | Failed login attempts |
| `reports/risk_scores_<date>.csv` | ML-based IP risk scores |
| `logs/cti_framework.log` | Full system execution log |
| `models/threat_model.model` | Trained Random Forest model |
| `models/decision_tree.model` | Trained J48 Decision Tree model |

---

## How It Works

1. **Database Init** — SQLite schema is created.
2. **Sample Data Load** — Loaded only once; skipped automatically on repeat runs to avoid duplicate records.
3. **ML Training** — Random Forest & J48 Decision Tree models are trained on login/threat data.
4. **Model Evaluation** — Both models are evaluated for accuracy.
5. **Login Analysis** — Failed login attempts are analyzed for patterns.
6. **Threat Detection** — Threats are detected and classified by severity; duplicate OPEN threats for the same IP + type are automatically skipped.
7. **Risk Scoring** — Each IP is scored using the trained ML model.
8. **Auto-Blocking** — IPs with CRITICAL threats are automatically blacklisted.
9. **Reporting** — A full text report and CSV exports are generated.
10. **Dashboard Generation** — An interactive offline HTML dashboard is built from the live database.
11. **Alerts** — Real-time and daily summary alerts are dispatched.

---

## Tech Stack

- **Language:** Java 17
- **Database:** SQLite (via `sqlite-jdbc`)
- **Machine Learning:** Weka 3.8.6 (Random Forest, J48 Decision Tree)
- **Build Tool:** Maven
- **Logging:** SLF4J + custom Logger utility
- **Data Format:** JSON (org.json) for structured data handling and dashboard data embedding
- **Dashboard:** Pure HTML5 + CSS3 + vanilla JavaScript (Canvas 2D) — zero external dependencies

---

## Roadmap — v2.0 (Coming Soon)

- [ ] REST API layer (Spring Boot)
- [ ] Real-time live dashboard (auto-refresh via WebSocket)
- [ ] Live network traffic ingestion
- [ ] Email/SMS alert integration
- [ ] Dockerized deployment
- [ ] JUnit 5 test suite
- [ ] Scheduled automated scans

---

## License

Copyright (c) 2026 Nilesh Kumar Mohanty. All rights reserved.

![License](https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey)

Licensed under Creative Commons Attribution-NonCommercial-NoDerivatives 4.0. You may view and share this work with attribution. You may not use it commercially, modify it, or claim it as your own.

📧 Contact: [Nilesh7832 on GitHub](https://github.com/Nilesh7832)
