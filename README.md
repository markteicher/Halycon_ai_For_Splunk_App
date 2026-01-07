# Halcyon.ai for Splunk App

## Overview

Halcyon is a full cycle agent that protects against ransomware, identifying and proactively disrupting attackers at every stage of the ransomware attack chain. With behavioral engines trained on indicators of ransomware, we detect suspicious activity early in the attack chain. If an attacker gains a foothold, Halycon.ai will attempt to prevent execution and detect data exfiltration attempts
Full Splunk App for Halcyon.ai ransomware protection and resilience. 

This Splunk app provides the ability to monitor, investigate, and operationalize Halcyon alerts, artifacts, detections, response actions, and platform health using the Halcyon API.  

Real-time visibility into ransomware activity, behavioral detections, and automated response outcomes collected from Halcyon.ai without having to learn the Halycon.ai User Interface as well Halycon Filtering User Interface Dynamics.


## Halycon.ai supports the following Operating Systems:

Supported Microsoft(tm) Operating System Environments

- Microsoft Windows 10

- Microsoft Windows 11

- Microsoft Server 2012 R2 (x64)

- Microsoft Server 2016

- Microsoft Server 2019

- Microsoft Server 2022+



Supported Linux Operating System Environments:

- RHEL 8

- RHEL 9

- RHEL binary compatible distributions
  
- Oracle Linux

- AlmaLinux

- Rocky Linux

- Ubuntu 22.04

- Ubuntu 24.04 LTS.

- Debian 11

- Debian 12

- AWS Linux 2

- AWS Linux 2023

## Features

### 🛡️ Core Capabilities
| Feature | Description |
|---------|-------------|
| 🚨 Alert Monitoring | Ingest and track Halcyon ransomware alerts |
| 🧬 Alert Artifacts | Collect forensic artifacts associated with alerts |
| 🧠 Detection Intelligence | Behavioral detection context and metadata |
| 🛑 Response Actions | Visibility into automated prevention and response |
| 🖥️ Endpoint Coverage | Host, device, and platform-level telemetry |
| 👥 User & Tenant Context | Multi-tenant and user attribution support |

### 📈 Advanced Analytics
| Feature | Description |
|---------|-------------|
| 📊 Alert Trending | Alert volume trends over time |
| 🔍 Artifact Analysis | Artifact type, frequency, and severity analysis |
| ⏱️ Time-to-Response | Detection-to-response timing metrics |
| 🧭 Attack Chain Visibility | Kill-chain stage analysis |
| 🧩 Alert Correlation | Correlate alerts by host, user, or campaign |
| 🏷️ Threat Categorization | Group alerts by ransomware family or behavior |

### ⚙️ Operational Excellence
| Feature | Description |
|---------|-------------|
| 📊 Ingestion Metrics | API calls, records processed, and rates |
| 💓 Collection Health | API connectivity and data freshness |
| ✅ Configuration Validation | Automated setup validation |
| 🕐 Scheduled Health Checks | Periodic API and token checks |
| 📋 API Log Viewer | Full visibility into API activity and errors |

### 🚀 Deployment
| Feature | Description |
|---------|-------------|
| 📊 Pre-built Dashboards | Immediate insights out of the box |
| 🖥️ Web UI Setup | Configure via Splunk Web |
| ☁️ Splunk Cloud Ready | AppInspect-friendly design |
| 📡 Modular Input | Secure API-based data ingestion |

## Installation

### Step 1: Deploy the App
1. Download the `Halcyon_For_Splunk_App-1.0.0.tar.gz`
2. In Splunk Web, navigate to **Apps → Manage Apps**
3. Click **Install app from file**
4. Upload the `.tar.gz` file
5. Restart Splunk if prompted

### Step 2: Configure the App
1. Navigate to **Apps → Halcyon → Setup**
2. Configure the following settings

#### API Configuration
- **Halcyon API Token**
- **API Base URL**: https://api.halcyon.ai
- **Verify SSL**
- **Request Timeout**

#### Proxy Configuration (Optional)
- **Use Proxy**
- **Proxy URL**
- **Proxy Username**
- **Proxy Password**

#### Data Inputs
- Alerts
- Alert Artifacts
- Detection Metadata
- Response Actions
- Hosts / Endpoints
- Platform Health

### Step 3: Validate Configuration
- Test API connection
- Automatic validation on first launch

### Step 4: Verify Data Collection
```spl
index=security_halcyon sourcetype=halcyon:*
| stats count by sourcetype
```

## Directory Structure
```
Halcyon_For_Splunk_App/
├── app.manifest
├── LICENSE
├── README.md
├── default/
│   ├── app.conf
│   ├── inputs.conf
│   ├── indexes.conf
│   ├── props.conf
│   ├── transforms.conf
│   ├── macros.conf
│   ├── restmap.conf
│   ├── savedsearches.conf
│   ├── web.conf
│   └── data/ui/
│       ├── nav/default.xml
│       └── views/
│           ├── setup.xml
│           ├── halcyon_overview.xml
│           ├── halcyon_alerts.xml
│           ├── halcyon_artifacts.xml
│           ├── halcyon_detections.xml
│           ├── halcyon_response.xml
│           ├── halcyon_hosts.xml
│           ├── halcyon_trending.xml
│           ├── halcyon_operations.xml
│           └── halcyon_health.xml
├── bin/
│   ├── halcyon_input.py
│   ├── halcyon_setup_handler.py
│   └── halcyon_validation.py
├── metadata/
│   ├── default.meta
│   └── local.meta
└── static/
    ├── appIcon.png
    ├── appIcon_2x.png
```
## 📊 Dashboards
| Dashboard | Description |
|----------|-------------|
| 🧭 Overview | Executive ransomware posture |
| 🚨 Alerts | Alert investigation |
| 🧬 Artifacts | Artifact analysis |
| 🕵️ Detections | Detection logic |
| ⚡ Response | Automated response |
| 🖥️ Hosts | Endpoint visibility |
| 📈 Trending | Trends |
| ⚙️ Operations | Metrics |
| ❤️ Health | API health |

## 🧾 Sourcetypes
| Sourcetype | Description |
|-----------|-------------|
| `halcyon:alerts` | Alerts |
| `halcyon:artifacts` | Artifacts |
| `halcyon:detections` | Detections |
| `halcyon:responses` | Responses |
| `halcyon:hosts` | Hosts |
| `halcyon:health` | Health |

## 📦 Requirements
- Splunk Enterprise / Splunk Cloud
- Python 3.x (Splunk bundled)
- Halcyon API Token

## ✅ AppInspect Compliance
- Proper directory structure
- Secure credential handling
- Inputs disabled by default
- `app.manifest` included
- Apache 2.0 License

## 🛠️ Troubleshooting
- Verify API token
- Test API connectivity
- Review Splunk internal logs

## 📚 Support
- Halcyon API Docs: https://api.halcyon.ai/docs
- Splunk Docs: https://docs.splunk.com

## 📜 License
Apache License 2.0
