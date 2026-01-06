# Halcyon.ai for Splunk

## Overview
Full Splunk App for Halcyon.ai ransomware protection and resilience. Monitor, investigate, and operationalize Halcyon alerts, artifacts, detections, response actions, and platform health using the Halcyon API.



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
- **Halcyon API Token**: API token from Halcyon console
- **API Base URL**: `https://api.halcyon.ai`
- **Verify SSL**: Enable certificate verification
- **Request Timeout**: Default 60 seconds

#### Proxy Configuration (Optional)
- **Use Proxy**
- **Proxy URL**
- **Proxy Username**
- **Proxy Password**

#### Data Inputs
Select which data to collect:
- Alerts
- Alert Artifacts
- Detection Metadata
- Response Actions
- Hosts / Endpoints
- Platform Health

3. Click **Save**

### Step 3: Validate Configuration
- Click **Test API Connection**
- Confirm successful authentication
- Validation runs automatically on first launch

### Step 4: Verify Data Collection
Run the following search:
```spl
index=security_halcyon sourcetype=halcyon:*
| stats count by sourcetype
