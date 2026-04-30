# AD Security Monitoring - Quick Start Guide

## 5-Minute Setup

### Step 1: Run Setup (as Administrator)

```powershell
cd C:\Users\ivolovnik\adreview\AD_review\Monitoring

.\Setup-MonitoringEnvironment.ps1 `
    -SetupScheduledTasks `
    -TeamsWebhookUrl "https://outlook.office.com/webhook/YOUR_WEBHOOK_URL"
```

### Step 2: Test It

```powershell
# Run daily checks
.\Invoke-MonitoringWorkflow.ps1 -WorkflowType Daily

# Check results
Get-ChildItem .\DailyChecks\ | Sort-Object LastWriteTime -Descending | Select-Object -First 3
```

### Step 3: Schedule It

Setup already created these scheduled tasks:
- **Daily 7:00 AM** - Critical security checks
- **Sunday 2:00 AM** - Full assessment
- **Daily 4:00 AM** - Data export

Verify in Task Scheduler:
```powershell
Get-ScheduledTask -TaskName "AD Security*" | Format-Table TaskName, State
```

---

## With CrowdStrike Integration

### Step 1: Get API Credentials

1. Login to Falcon console
2. Go to **Support > API Clients and Keys**
3. Create new API client with scopes:
   - Detects: Read
   - Hosts: Read
   - Vulnerabilities: Read
   - Identity Protection: Read

### Step 2: Configure

```powershell
# Set credentials
[Environment]::SetEnvironmentVariable("FALCON_CLIENT_ID", "your-client-id", "User")
[Environment]::SetEnvironmentVariable("FALCON_CLIENT_SECRET", "your-secret", "User")

# Update config
$config = Get-Content .\config\monitoring-config.json | ConvertFrom-Json
$config.CrowdStrike.Enabled = $true
$config | ConvertTo-Json -Depth 10 | Out-File .\config\monitoring-config.json -Encoding UTF8
```

### Step 3: Test

```powershell
.\Invoke-CrowdStrikeCollection.ps1 -CollectionType Daily

# Check results
Get-ChildItem .\CrowdStrike\ | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

---

## With Database (SQL Server)

### Step 1: Setup Database

```powershell
.\Setup-MonitoringEnvironment.ps1 `
    -SetupDatabase `
    -DatabaseServer "your-sql-server" `
    -UseWindowsAuth
```

### Step 2: Configure Export

```powershell
$config = Get-Content .\config\monitoring-config.json | ConvertFrom-Json
$config.Database.Enabled = $true
$config.Database.Server = "your-sql-server"
$config.Database.Database = "ADSecurityMonitoring"
$config | ConvertTo-Json -Depth 10 | Out-File .\config\monitoring-config.json -Encoding UTF8
```

### Step 3: Export Data

```powershell
.\Invoke-DataExport.ps1 -ExportType Database
```

### Step 4: Query It

```powershell
# Open SQL Server Management Studio
# Connect to: your-sql-server
# Database: ADSecurityMonitoring

-- View open findings
SELECT * FROM vw_OpenFindings;

-- View critical detections with AD correlation
SELECT * FROM vw_CriticalDetectionsWithAD;

-- Weekly trend
SELECT * FROM vw_WeeklyTrendSummary;
```

---

## Teams Alerts Configuration

### Get Webhook URL

1. Open Teams channel
2. Click **···** > **Connectors**
3. Add **Incoming Webhook**
4. Name it "AD Security Alerts"
5. Copy the URL

### Configure

```powershell
$config = Get-Content .\config\monitoring-config.json | ConvertFrom-Json
$config.Teams.Enabled = $true
$config.Teams.WebhookUrl = "https://outlook.office.com/webhook/YOUR_URL"
$config.Teams.CriticalAlerts.Enabled = $true
$config.Teams.DailyDigest.Enabled = $true
$config | ConvertTo-Json -Depth 10 | Out-File .\config\monitoring-config.json -Encoding UTF8
```

### Test

```powershell
.\Send-TeamsAlert.ps1 `
    -WebhookUrl $config.Teams.WebhookUrl `
    -Severity Info `
    -AlertTitle "Test Alert" `
    -Summary "Teams integration is working!"
```

---

## Power BI Setup

### Step 1: Export Data

```powershell
.\Invoke-DataExport.ps1 -ExportType PowerBI
```

### Step 2: Connect Power BI

1. Open **Power BI Desktop**
2. Click **Get Data** > **Folder**
3. Select: `C:\Users\ivolovnik\adreview\AD_review\ExportedData\PowerBI\`
4. Click **Transform Data**
5. Load `consolidated-data.csv`

### Step 3: Create Dashboard

**Suggested Visualizations:**

1. **Card:** Total Findings
   ```dax
   Total Findings = COUNTROWS('consolidated-data')
   ```

2. **Pie Chart:** Findings by Severity
   - Legend: Severity
   - Values: Count of FindingId

3. **Line Chart:** Risk Trend
   - X-axis: Timestamp (by day)
   - Y-axis: Count of findings

4. **Table:** Top MITRE Techniques
   - Columns: MITRETechnique, Count, Category

5. **Map:** CrowdStrike Detections by IP
   - Location: ExternalIpAddress
   - Size: Count of DetectionId

---

## Common Commands

### Check Status

```powershell
# Last daily check
Get-ChildItem .\DailyChecks\daily-checks-*.json |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 |
    ForEach-Object {
        $data = Get-Content $_.FullName | ConvertFrom-Json
        Write-Host "Last check: $($_.LastWriteTime)"
        Write-Host "Findings: $($data.Count)"
        Write-Host "Critical: $(($data | Where-Object { $_.Severity -eq 'Critical' }).Count)"
    }
```

### View Recent Alerts

```powershell
# Check what was sent to Teams
Get-ChildItem .\DailyChecks\alerts-*.json |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 5 |
    ForEach-Object {
        Write-Host "`n$($_.Name):"
        Get-Content $_.FullName | ConvertFrom-Json | Format-Table Title, Severity
    }
```

### Troubleshoot

```powershell
# Check logs
Get-ChildItem ..\Logs\*.log |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 |
    ForEach-Object { Get-Content $_.FullName -Tail 50 }

# Test individual script
.\Invoke-DailySecurityChecks.ps1 -IncludeEntra 2>&1 | Out-File test-output.log
```

---

## What Happens When

### Daily Workflow (7:00 AM)

```
7:00 AM - Scheduled task triggers
7:00-7:10 AM - Daily security checks run
7:10 AM - Results exported to JSON/CSV
7:10 AM - If critical findings: Teams alert sent
7:15 AM - Daily digest sent to Teams (if configured)
```

### Weekly Workflow (Sunday 2:00 AM)

```
2:00 AM - Scheduled task triggers
2:00-2:45 AM - Full AD/Entra assessment runs
2:45-3:00 AM - CrowdStrike data collected
3:00-3:15 AM - Data correlated with AD inventory
3:15 AM - Results exported
3:15 AM - Teams weekly summary sent (if configured)
```

### Data Export (4:00 AM Daily)

```
4:00 AM - Scheduled task triggers
4:00-4:05 AM - CSV files consolidated
4:05-4:10 AM - Data imported to database (if configured)
4:10 AM - Power BI data refreshed
```

---

## Next Steps

1. **Customize alert thresholds** in `config/monitoring-config.json`
2. **Add more CrowdStrike scopes** if needed (MalQuery, Threat Intel, etc.)
3. **Create custom Power BI visualizations** for your specific needs
4. **Integrate with SIEM** by pointing it to the CSV export folder
5. **Set up email notifications** as backup to Teams alerts
6. **Create runbooks** for common findings remediation

---

## Support

- **Logs:** `..\Logs\` folder
- **Config:** `config\monitoring-config.json`
- **Docs:** `README.md` in Monitoring folder
- **Database Schema:** `Database\Schema.sql`

**Questions?** Check the full README.md or review log files.
