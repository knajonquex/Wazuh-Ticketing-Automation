# 🛡️ Wazuh AI SOC Automation

An intelligent Security Operations Center (SOC) automation framework that monitors Wazuh alerts in real time, enriches Indicators of Compromise (IOCs) using threat intelligence services, performs AI-assisted incident analysis with Ollama, generates professional incident reports, and optionally emails them to security analysts for review.

> **Designed for SOC Analysts, Blue Teams, Incident Responders, and Cybersecurity Enthusiasts.**

---

## ✨ Features

- 📡 Real-time monitoring of Wazuh `alerts.json`
- 🔍 Automatic parsing of Wazuh/Sysmon alerts
- 🧠 AI-powered incident analysis using Ollama (Local LLM)
- 🌍 Threat intelligence enrichment
  - VirusTotal
  - AbuseIPDB
- 🧬 SHA-256 fingerprinting for duplicate detection
- 💾 AI response caching to avoid repeated LLM analysis
- 📑 Structured JSON incident reports
- 🌐 Professional HTML incident reports
- 📧 Email-ready HTML reports
- ⚙️ Policy Engine for controlling automation workflow
- 🛡️ MITRE ATT&CK mapping support
- 🔄 Modular architecture for future integrations

---

# Project Workflow

```
                   Wazuh Manager
                        │
                        ▼
                alerts.json Updated
                        │
                        ▼
                 File Monitoring
                  (watchdog)
                        │
                        ▼
                  Alert Reader
                        │
                        ▼
                 Alert Parser
                        │
                        ▼
                Policy Evaluation
                        │
          ┌─────────────┴─────────────┐
          │                           │
          ▼                           ▼
 Threat Intelligence          AI Analysis (Ollama)
(VirusTotal / AbuseIPDB)              │
          │                           │
          └─────────────┬─────────────┘
                        ▼
             Incident Report Generator
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
      HTML Report             Email Report
```

---

# Project Structure

```
Wazuh-AI-SOC-Automation/
│
├── monitor.py                 # Main monitoring engine
├── reader.py                  # Reads new Wazuh alerts
├── parser.py                  # Parses raw Wazuh JSON
├── filters.py                 # Alert filtering
├── policy_engine.py           # Decides processing workflow
│
├── threatintel.py             # Threat Intelligence orchestrator
├── virustotal.py              # VirusTotal integration
├── abuseipdb.py               # AbuseIPDB integration
│
├── ollama_ai.py               # AI analysis using Ollama
├── incident_fingerprint.py    # SHA256 incident fingerprint
├── cache.py                   # AI response caching
│
├── report.py                  # Structured report generator
├── html_report.py             # Standalone HTML report
├── email_report.py            # Email-safe HTML template
├── mailer.py                  # SMTP email sender
│
├── config.py                  # Project configuration
│
├── reports/                   # Generated reports
├── cache/                     # Cached AI analysis
└── logs/                      # Application logs
```

---

# Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3 |
| SIEM | Wazuh |
| Endpoint Logs | Sysmon |
| AI Engine | Ollama |
| LLM | Qwen 3 (Configurable) |
| Threat Intelligence | VirusTotal |
| Threat Intelligence | AbuseIPDB |
| Monitoring | watchdog |
| Email | SMTP |
| Reports | HTML |
| Hashing | SHA-256 |

---

# Requirements

- Python 3.10+
- Wazuh Manager
- Ollama
- VirusTotal API Key
- AbuseIPDB API Key
- SMTP Email Account

---

# Installation

Clone the repository

```bash
git clone git@github.com:knajonquex/Wazuh-Ticketing-Automation.git
```

Enter the directory

```bash
cd Wazuh-Ticketing-Automation
```

Install dependencies

```bash
pip install -r requirements.txt
```

Configure the project

Edit:

```
config.py
```

Configure:

- Wazuh alerts path
- Ollama server
- API Keys
- SMTP credentials

---

# Configure Ollama

Example:

```env
OLLAMA_URL="http://localhost:11434/api/generate"

OLLAMA_MODEL="qwen3:8b"
```

Start Ollama

```bash
ollama serve
```

Pull your preferred model

```bash
ollama pull qwen3:8b
```

---

# Running

```bash
python3 monitor.py
```

The application will continuously monitor

```
alerts.json
```

and automatically process new security alerts.

---

# Processing Pipeline

Each incoming alert goes through:

1. Read new alert
2. Parse JSON
3. Evaluate policy
4. IOC enrichment
5. AI analysis
6. Cache lookup/storage
7. Generate structured report
8. Generate HTML report
9. Generate email-ready report
10. Send notification (optional)

---

# Threat Intelligence

Current integrations:

- VirusTotal Hash Lookup
- AbuseIPDB IP Lookup

Future integrations can include:

- AlienVault OTX
- URLHaus
- Hybrid Analysis
- GreyNoise
- MISP
- Shodan

---

# AI Analysis

Each incident is analyzed to generate:

- Executive Summary
- Threat Assessment
- Business Impact
- False Positive Assessment
- Confidence Rating
- Containment Recommendations
- Eradication Recommendations
- Recovery Recommendations
- Investigation Findings
- IOC Summary
- Analyst Conclusion

---

# Report Output

The framework generates:

### Structured JSON Report

Contains:

- Alert metadata
- Agent information
- MITRE ATT&CK
- Threat Intelligence
- AI analysis

---

### Professional HTML Report

Includes:

- Executive Summary
- Event Details
- Network Information
- File Information
- IOC Table
- MITRE Mapping
- Threat Intelligence Results
- Risk Assessment
- Analyst Findings
- Response Actions
- Recommendations

---

### Email Report

Optimized HTML format compatible with common email clients using inline CSS.

---

# Configuration

Most project behavior is controlled through:

```
config.py
```

Including:

- Enable/disable AI analysis
- Enable/disable Threat Intelligence
- Report generation
- Email notifications
- IOC lookups
- Logging
- Worker settings
- Duplicate alert window

---

# Future Roadmap

- Jira integration
- TheHive integration
- ServiceNow integration
- Slack/Discord notifications
- Multi-tenant support
- IOC correlation engine
- Detection rule tuning
- Malware sandbox integration
- Threat hunting dashboard
- PDF report generation
- Docker deployment
- REST API

---

# Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes. Always validate AI-generated findings before taking containment or remediation actions in production environments.

---

# Author

**Knajonquex**

- SOC Analyst
- Digital Forensics Student
- Cybersecurity Enthusiast

---

## ⭐ Support

If you found this project useful, consider giving it a **Star** on GitHub!
