# AD Security Monitoring Platform

## Overview

Automated Active Directory and Entra ID security monitoring with CrowdStrike integration, Teams alerting, and Power BI reporting.

**What it does:**
- **Daily** - Fast critical security checks (5-10 minutes)
- **Weekly** - Full AD/Entra assessment + CrowdStrike correlation (30-60 minutes)
- **Alerts** - Teams notifications for critical findings
- **Reports** - CSV exports and Power BI dashboards

---

## Quick Start

### 1. One-Time Setup

```powershell
# Run as Administrator
cd C:\Users\ivolovnik\adreview\AD_review\Monitoring
.\Setup-MonitoringEnvironment.ps1 -SetupScheduledTasks -TeamsWebhookUrl "https://outlook.office.com/webhook/..."
```

This will:
- Create directory structure
- Install PowerShell module dependencies
- Configure Teams webhook
- Create scheduled tasks (Daily 7AM, Weekly Sunday 2AM)
- Generate setup report

### 2. Test Run

```powershell
# Run daily checks manually
.\Invoke-MonitoringWorkflow.ps1 -WorkflowType Daily

# Run weekly assessment
.\Invoke-MonitoringWorkflow.ps1 -WorkflowType Weekly -SendTeamsAlerts
```

### 3. View Results

- **Daily Checks:** `./Monitoring/DailyChecks/`
- **CrowdStrike Data:** `./Monitoring/CrowdStrike/`
- **CSV Exports:** `./ExportedData/CSV/`
- **Power BI Data:** `./ExportedData/PowerBI/`
- **Logs:** `./Logs/`

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Scheduled Tasks                    │
│  Daily 7AM     Weekly Sun 2AM    Daily 4AM          │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Daily    │  │ Full         │  │ Data         │   │
│  │ Checks   │  │ Assessment   │  │ Export       │   │
│  └──────────┘  └──────────────┘  └──────────────┘   │
└──────────────────────────────────────────────────────┘
         │                  │                 │
         └──────────────────┼─────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────┐
│              Monitoring Orchestrator                 │
│  Invoke-MonitoringWorkflow.ps1                       │
│  - Coordinates all scripts                           │
│  - Handles errors and logging                        │
│  - Manages configuration                             │
└──────────────────────────────────────────────────────┘
         │                  │                 │
         ▼                  ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Daily Checks │  │ CrowdStrike  │  │ Data Export  │
│ (5-10 min)   │  │ Collection   │  │ CSV/DB/PBI   │
└──────────────┘  └──────────────┘  └──────────────┘
                                          │
                            ┌─────────────┴─────────────┐
                            ▼                           ▼
                     ┌──────────────┐          ┌──────────────┐
                     │ CSV Files    │          │ Power BI     │
                     │ (Historical) │          │ Dashboard    │
                     └──────────────┘          └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Teams Alerts │
                     │ (Real-time)  │
                     └──────────────┘
```

---

## Scripts

### Core Scripts

| Script | Purpose | Runtime |
|--------|---------|---------|
| `Invoke-MonitoringWorkflow.ps1` | Master orchestrator - runs complete workflow | 5-60 min |
| `Invoke-DailySecurityChecks.ps1` | Fast critical-only checks | 5-10 min |
| `Invoke-CrowdStrikeCollection.ps1` | CrowdStrike Falcon API integration | 10-15 min |
| `Send-TeamsAlert.ps1` | Teams webhook alerting | <1 min |
| `Invoke-DataExport.ps1` | CSV/Database/Power BI export | 5-10 min |
| `Setup-MonitoringEnvironment.ps1` | One-time environment setup | 5-10 min |

### Usage Examples

#### Daily Checks Only
```powershell
.\Invoke-DailySecurityChecks.ps1 -IncludeEntra -AlertThreshold High
```

#### CrowdStrike Collection
```powershell
# Using environment variables for credentials
$env:FALCON_CLIENT_ID = "your-client-id"
$env:FALCON_CLIENT_SECRET = "your-secret"

.\Invoke-CrowdStrikeCollection.ps1 -CollectionType Daily -ADComputerCSV "ad-computers.csv"
```

#### Send Teams Alert
```powershell
$findings = Import-Csv "daily-checks-latest.csv" | Where-Object { $_.Severity -eq "Critical" }

.\Send-TeamsAlert.ps1 `
    -WebhookUrl "https://outlook.office.com/webhook/..." `
    -Severity Critical `
    -Findings $findings `
    -IncludeDetails
```

#### Full Weekly Workflow
```powershell
.\Invoke-MonitoringWorkflow.ps1 `
    -WorkflowType Weekly `
    -SendTeamsAlerts `
    -LogPath "weekly-run.log"
```

---

## Configuration

Edit `config/monitoring-config.json`:

```json
{
  "Monitoring": {
    "DailySchedule": {
      "Enabled": true,
      "Time": "07:00",
      "IncludeEntra": true,
      "AlertThreshold": "High"
    },
    "WeeklySchedule": {
      "Enabled": true,
      "DayOfWeek": "Sunday",
      "Time": "02:00",
      "IncludeEntra": true,
      "GenerateDiagrams": true
    }
  },
  "CrowdStrike": {
    "Enabled": true,
    "CloudRegion": "us-1",
    "CollectionType": "Daily"
  },
  "Teams": {
    "Enabled": true,
    "WebhookUrl": "https://outlook.office.com/webhook/...",
    "DailyDigest": {
      "Enabled": true,
      "Time": "07:30",
      "IncludeFindings": true,
      "MaxFindings": 10
    },
    "CriticalAlerts": {
      "Enabled": true,
      "ImmediateNotification": true,
      "SeverityThreshold": "Critical"
    }
  },
  "Database": {
    "Enabled": false,
    "Type": "SQLServer",
    "Server": "your-sql-server",
    "Database": "ADSecurityMonitoring",
    "UseWindowsAuth": true,
    "RetentionDays": 365
  },
  "Export": {
    "CSV": {
      "Enabled": true,
      "OutputFolder": "./ExportedData/CSV",
      "RetentionDays": 90
    },
    "PowerBI": {
      "Enabled": true,
      "OutputFolder": "./ExportedData/PowerBI",
      "RefreshSchedule": "Daily"
    }
  }
}
```

---

## Prerequisites

### PowerShell Modules

```powershell
# Required (AD assessment)
Install-WindowsFeature RSAT-AD-PowerShell  # or install RSAT via Settings

# Optional (Entra ID assessment)
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser

# Optional (Database export)
Install-Module SqlServer -Scope CurrentUser
```

### CrowdStrike Falcon API

1. Generate API credentials in Falcon console:
   - Navigate to **Support > API Clients and Keys**
   - Click **Add new API client**
   - Select required scopes:
     - **Detects:** Read
     - **Hosts:** Read
     - **Vulnerabilities:** Read
     - **Identity Protection:** Read
   - Copy Client ID and Client Secret

2. Configure credentials:
   ```powershell
   # Option 1: Environment variables (recommended for automation)
   [Environment]::SetEnvironmentVariable("FALCON_CLIENT_ID", "your-id", "User")
   [Environment]::SetEnvironmentVariable("FALCON_CLIENT_SECRET", "your-secret", "User")

   # Option 2: Pass as parameters
   .\Invoke-CrowdStrikeCollection.ps1 -ClientId "your-id" -ClientSecret "your-secret"
   ```

### Microsoft Teams Webhook

1. In Teams, navigate to the channel where you want alerts
2. Click **•••** (More options) > **Connectors**
3. Search for **Incoming Webhook** and click **Add**
4. Give it a name (e.g., "AD Security Alerts") and upload an image (optional)
5. Click **Create** and copy the webhook URL
6. Test it:
   ```powershell
   .\Send-TeamsAlert.ps1 `
       -WebhookUrl "YOUR_WEBHOOK_URL" `
       -Severity Info `
       -AlertTitle "Test Alert" `
       -Summary "This is a test"
   ```

### Database (Optional)

```powershell
# SQL Server
.\Setup-MonitoringEnvironment.ps1 `
    -SetupDatabase `
    -DatabaseServer "sql-server-name" `
    -UseWindowsAuth

# PostgreSQL (schema needs adaptation - see Database/Schema.sql)
```

---

## Scheduled Tasks

The setup script creates three scheduled tasks:

| Task | Schedule | What it does |
|------|----------|--------------|
| **AD Security - Daily Checks** | Daily 7:00 AM | Runs critical security checks |
| **AD Security - Weekly Assessment** | Sunday 2:00 AM | Runs full AD/Entra assessment |
| **AD Security - Data Export** | Daily 4:00 AM | Exports data to CSV/database |

**Important Notes:**
- Tasks run as **SYSTEM** by default
- For Entra ID access, change task to run as a user with Graph permissions:
  1. Open **Task Scheduler**
  2. Find **AD Security - *** tasks
  3. Right-click > **Properties** > **General** tab
  4. Click **Change User or Group...**
  5. Select a user with Microsoft Graph access
  6. Check **Run whether user is logged on or not**

To modify schedules:
```powershell
# Disable a task
Disable-ScheduledTask -TaskName "AD Security - Daily Checks"

# Change schedule (example: run at 8 AM instead of 7 AM)
Set-ScheduledTask -TaskName "AD Security - Daily Checks" `
    -Trigger (New-ScheduledTaskTrigger -Daily -At "8:00AM")
```

---

## Power BI Integration

### Setup

1. **Run data export:**
   ```powershell
   .\Invoke-DataExport.ps1 -ExportType PowerBI
   ```

2. **Open Power BI Desktop**

3. **Get Data:**
   - Click **Get Data** > **Folder**
   - Select: `C:\Users\ivolovnik\adreview\AD_review\ExportedData\PowerBI\`
   - Click **Transform Data**

4. **Load CSV files:**
   - `consolidated-data.csv` - Main data table
   - `severity-summary.csv` - Aggregated summary

5. **Create visualizations:**
   - Risk score trend over time
   - Findings by severity (pie chart)
   - MITRE ATT&CK technique heatmap
   - CrowdStrike detections by device
   - MFA coverage trend

### Sample DAX Measures

```dax
-- Critical Findings Count
Critical Findings = 
CALCULATE(
    COUNTROWS('consolidated-data'),
    'consolidated-data'[Severity] = "Critical"
)

-- Risk Score (weighted)
Risk Score = 
DIVIDE(
    [Critical Findings] * 10 +
    CALCULATE(COUNTROWS('consolidated-data'), 'consolidated-data'[Severity] = "High") * 5 +
    CALCULATE(COUNTROWS('consolidated-data'), 'consolidated-data'[Severity] = "Medium") * 2,
    COUNTROWS('consolidated-data')
)

-- Week-over-Week Change
WoW Change = 
VAR CurrentWeek = [Total Findings]
VAR PreviousWeek = CALCULATE([Total Findings], DATEADD('consolidated-data'[Timestamp], -7, DAY))
RETURN CurrentWeek - PreviousWeek
```

---

## Alert Thresholds

### When Alerts are Sent

| Severity | Condition | Teams Notification |
|----------|-----------|-------------------|
| **Critical** | Any critical finding | Immediate |
| **High** | 3+ high findings | Immediate |
| **Medium** | 10+ medium findings | Daily digest only |
| **Low** | Any low findings | Weekly summary only |

### Default Critical Checks

| Check | Critical Threshold | High Threshold |
|-------|-------------------|----------------|
| krbtgt password age | >180 days | >90 days |
| New privileged group members | Any | 5+ |
| Unconstrained delegation | Any computer | - |
| New domain trusts | Any | - |
| CrowdStrike detections | 1+ Critical | 3+ High |
| Users without MFA | - | 10+ |

---

## Troubleshooting

### Daily Checks Fail

**Symptom:** Script errors on Entra ID checks

**Fix:**
```powershell
# Verify Graph modules
Get-Module -ListAvailable Microsoft.Graph.*

# Reinstall if needed
Install-Module Microsoft.Graph.Authentication -Force -Scope CurrentUser

# Test connection
Connect-MgGraph -Scopes "Directory.Read.All"
```

### CrowdStrike Collection Fails

**Symptom:** "Failed to authenticate to CrowdStrike API"

**Fix:**
```powershell
# Verify credentials are set
$env:FALCON_CLIENT_ID
$env:FALCON_CLIENT_SECRET

# Test API access manually
$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}
$body = @{
    client_id = $env:FALCON_CLIENT_ID
    client_secret = $env:FALCON_CLIENT_SECRET
}
Invoke-RestMethod -Uri "https://api.crowdstrike.com/oauth2/token" -Method Post -Headers $headers -Body $body
```

### Teams Alerts Not Sent

**Symptom:** "Failed to send alert to Teams"

**Fix:**
1. Verify webhook URL is correct and not expired
2. Test with simple message:
   ```powershell
   Invoke-RestMethod -Uri "WEBHOOK_URL" -Method Post `
       -ContentType "application/json" `
       -Body '{"text":"Test"}'
   ```
3. Check if connector is still enabled in Teams channel

### Database Import Fails

**Symptom:** "Failed to import CSV to database"

**Fix:**
```powershell
# Verify SQL connectivity
Invoke-Sqlcmd -ServerInstance "sql-server" -Database "ADSecurityMonitoring" `
    -Query "SELECT COUNT(*) FROM Daily Findings"

# Check table schema
Invoke-Sqlcmd -ServerInstance "sql-server" -Database "ADSecurityMonitoring" `
    -Query "EXEC sp_help 'DailyFindings'"

# Re-apply schema if needed
Invoke-Sqlcmd -ServerInstance "sql-server" -Database "ADSecurityMonitoring" `
    -InputFile ".\Database\Schema.sql"
```

---

## Data Retention

| Data Type | Default Retention | Configurable |
|-----------|------------------|--------------|
| CSV files | 90 days | Yes |
| Database records | 365 days | Yes |
| Log files | Manual cleanup | No |
| Power BI data | Current + 90 days | Yes |

To change retention:
```json
// In monitoring-config.json
{
  "Database": {
    "RetentionDays": 730  // 2 years
  },
  "Export": {
    "CSV": {
      "RetentionDays": 180  // 6 months
    }
  }
}
```

---

## Security Considerations

### Credential Storage

- **Environment Variables:** Good for testing, visible to all processes
- **Windows Credential Manager:** Better security, requires CredentialManager module
- **Azure Key Vault:** Best for production, requires Azure subscription

### File Permissions

Secure the monitoring folder:
```powershell
# Grant access only to specific group
$acl = Get-Acl "C:\Path\To\Monitoring"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "AD-Security-Team",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "C:\Path\To\Monitoring" $acl
```

### Audit Trail

All configuration changes and alert deliveries are logged:
- **Database:** `ConfigurationAudit` and `AlertNotifications` tables
- **Files:** `./Logs/` folder with timestamped log files

---

## Support

- **Documentation:** See project root README.md
- **Issues:** Check logs in `./Logs/`
- **Community:** Submit issues on GitHub
- **Updates:** Run setup script again after updating scripts

---

## Version History

### v1.0 - Current Release
- Initial monitoring platform release
- Daily and weekly assessment workflows
- CrowdStrike Falcon API integration
- Teams alert notifications
- CSV and database export
- Power BI data model

---

**Maintained by:** AD Security Team  
**Last Updated:** $(Get-Date -Format "yyyy-MM-dd")
