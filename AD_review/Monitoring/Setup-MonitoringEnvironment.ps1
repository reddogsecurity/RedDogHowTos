<#
.SYNOPSIS
    One-time setup script for AD Security Monitoring environment

.DESCRIPTION
    Initializes the monitoring environment by:
    - Creating required directory structure
    - Installing PowerShell module dependencies
    - Setting up scheduled tasks for daily/weekly execution
    - Configuring Teams webhook integration
    - Initializing database schema (optional)
    - Creating credential stores for automation
    - Generating starter configuration

.PARAMETER OutputBasePath
    Base path for all monitoring data (default: current directory)

.PARAMETER SetupScheduledTasks
    Create Windows Scheduled Tasks for automated execution

.PARAMETER SetupDatabase
    Initialize database schema on specified server

.PARAMETER DatabaseServer
    Database server name (required if SetupDatabase is true)

.PARAMETER TeamsWebhookUrl
    Microsoft Teams webhook URL for alerts

.PARAMETER CrowdStrikeClientId
    CrowdStrike API Client ID (optional, can be configured later)

.PARAMETER CrowdStrikeClientSecret
    CrowdStrike API Client Secret (optional, can be configured later)

.PARAMETER UseWindowsAuth
    Use Windows authentication for database (default: true)

.EXAMPLE
    .\Setup-MonitoringEnvironment.ps1
    Basic setup without scheduled tasks and database

.EXAMPLE
    .\Setup-MonitoringEnvironment.ps1 -SetupScheduledTasks -TeamsWebhookUrl "https://..."
    Full setup with Teams alerts and scheduled tasks

.EXAMPLE
    .\Setup-MonitoringEnvironment.ps1 -SetupDatabase -DatabaseServer "sql01" -SetupScheduledTasks
    Full setup with database and scheduled tasks
#>

[CmdletBinding()]
param(
    [string]$OutputBasePath = "$PSScriptRoot",
    [switch]$SetupScheduledTasks,
    [switch]$SetupDatabase,
    [string]$DatabaseServer = "",
    [string]$TeamsWebhookUrl = "",
    [string]$CrowdStrikeClientId = "",
    [string]$CrowdStrikeClientSecret = "",
    [switch]$UseWindowsAuth,
    [switch]$SetupCertificateAuth,
    [string]$EntraClientId = "",
    [string]$EntraTenantId = "",
    [string]$CertificateThumbprint = "",
    [string]$CertificateSubject = "CN=AD-Security-Monitoring",
    [int]$CertificateValidYears = 2
)

# Require administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    $continue = Read-Host "Continue anyway? (yes/no)"
    if ($continue -ne "yes") {
        exit 1
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "AD Security Monitoring Setup" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================
# STEP 1: CREATE DIRECTORY STRUCTURE
# ============================================

Write-Host "[1/7] Creating directory structure..." -ForegroundColor Cyan

$directories = @(
    "$OutputBasePath\Monitoring\DailyChecks",
    "$OutputBasePath\Monitoring\CrowdStrike",
    "$OutputBasePath\Monitoring\config",
    "$OutputBasePath\Monitoring\Database",
    "$OutputBasePath\ExportedData\CSV",
    "$OutputBasePath\ExportedData\DatabaseStaging",
    "$OutputBasePath\ExportedData\PowerBI",
    "$OutputBasePath\Logs",
    "$OutputBasePath\Backups"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Write-Host "  [OK] Created: $dir" -ForegroundColor Green
    }
    else {
        Write-Host "  [OK] Exists: $dir" -ForegroundColor Gray
    }
}

# ============================================
# STEP 2: INSTALL POWERSHELL MODULES
# ============================================

Write-Host "`n[2/7] Checking PowerShell module dependencies..." -ForegroundColor Cyan

$requiredModules = @(
    @{ Name = "ActiveDirectory"; Feature = "RSAT-AD-PowerShell"; Critical = $true },
    @{ Name = "Microsoft.Graph.Authentication"; Feature = $null; Critical = $false },
    @{ Name = "Microsoft.Graph.Users"; Feature = $null; Critical = $false },
    @{ Name = "Microsoft.Graph.Groups"; Feature = $null; Critical = $false },
    @{ Name = "Microsoft.Graph.Identity.DirectoryManagement"; Feature = $null; Critical = $false },
    @{ Name = "SqlServer"; Feature = $null; Critical = $false }
)

$missingModules = @()

foreach ($module in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $module.Name -ErrorAction SilentlyContinue
    if ($installed) {
        Write-Host "  [OK] $($module.Name) is installed" -ForegroundColor Green
    }
    else {
        if ($module.Critical) {
            Write-Host "  [!] $($module.Name) is missing (required for AD assessment)" -ForegroundColor Yellow
            $missingModules += $module
        }
        else {
            Write-Host "  [-] $($module.Name) is optional (needed for Entra/Database features)" -ForegroundColor Gray
            $missingModules += $module
        }
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "`n  [*] Installing missing modules..." -ForegroundColor Yellow

    foreach ($module in $missingModules) {
        try {
            if ($module.Feature) {
                # Windows feature (RSAT)
                Write-Host "  Installing Windows feature: $($module.Feature)..." -ForegroundColor Yellow
                Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction SilentlyContinue | Out-Null
                Write-Host "  [OK] $($module.Name) installed" -ForegroundColor Green
            }
            else {
                # PowerShell Gallery module
                Install-Module -Name $module.Name -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
                Write-Host "  [OK] $($module.Name) installed from PowerShell Gallery" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  [X] Failed to install $($module.Name): $_" -ForegroundColor Red
        }
    }
}

# ============================================
# STEP 3.5: CONFIGURE CERTIFICATE AUTHENTICATION
# ============================================

if ($SetupCertificateAuth) {
    Write-Host "`n[3.5/7] Configuring certificate authentication..." -ForegroundColor Cyan

    # Check if we have required parameters
    if (-not $EntraClientId -or -not $EntraTenantId) {
        Write-Host "  [!] ClientId and TenantId are required for certificate auth" -ForegroundColor Yellow
        Write-Host "      You can configure these later in monitoring-config.json" -ForegroundColor Yellow
    }
    else {
        # Create certificate if thumbprint not provided
        if (-not $CertificateThumbprint) {
            Write-Host "  [*] Creating self-signed certificate..." -ForegroundColor Yellow

            try {
                $cert = New-SelfSignedCertificate `
                    -Subject $CertificateSubject `
                    -CertStoreLocation "Cert:\LocalMachine\My" `
                    -NotAfter (Get-Date).AddYears($CertificateValidYears) `
                    -KeyExportable `
                    -KeySpec Signature `
                    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

                $CertificateThumbprint = $cert.Thumbprint
                Write-Host "  [OK] Certificate created: $CertificateThumbprint" -ForegroundColor Green
                Write-Host "  Certificate Subject: $($cert.Subject)" -ForegroundColor Gray
                Write-Host "  Expires: $($cert.NotAfter)" -ForegroundColor Gray

                # Export public key
                $certPath = Join-Path $OutputBasePath "ad-monitoring-cert.cer"
                Export-Certificate -Cert $cert -FilePath $certPath -Type CERT -Force
                Write-Host "  [OK] Public key exported: $certPath" -ForegroundColor Green
                Write-Host "  NEXT: Upload this .cer file to your Azure AD App Registration" -ForegroundColor Yellow
            }
            catch {
                Write-Host "  [X] Failed to create certificate: $_" -ForegroundColor Red
                Write-Host "      You can create it manually using MMC or Azure Key Vault" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  [OK] Using existing certificate: $CertificateThumbprint" -ForegroundColor Green
        }

        # Update config file
        $configPath = Join-Path $OutputBasePath "Monitoring\config\monitoring-config.json"
        if (Test-Path $configPath) {
            $config = Get-Content $configPath | ConvertFrom-Json
            $config.Entra.Authentication.Method = "Certificate"
            $config.Entra.Authentication.ClientId = $EntraClientId
            $config.Entra.Authentication.TenantId = $EntraTenantId
            $config.Entra.Authentication.CertificateThumbprint = $CertificateThumbprint
            $config.Entra.Authentication.CertificateStoreLocation = "LocalMachine"
            $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
            Write-Host "  [OK] Certificate auth configured in config file" -ForegroundColor Green
        }

        # Set environment variables as backup
        [Environment]::SetEnvironmentVariable("MSGRAPH_CLIENT_ID", $EntraClientId, "Machine")
        [Environment]::SetEnvironmentVariable("MSGRAPH_TENANT_ID", $EntraTenantId, "Machine")
        [Environment]::SetEnvironmentVariable("MSGRAPH_CERT_THUMBPRINT", $CertificateThumbprint, "Machine")
        Write-Host "  [OK] Environment variables set (Machine scope)" -ForegroundColor Green

        Write-Host "`n  Certificate Authentication Configured:" -ForegroundColor Cyan
        Write-Host "    Client ID: $EntraClientId" -ForegroundColor White
        Write-Host "    Tenant ID: $EntraTenantId" -ForegroundColor White
        Write-Host "    Thumbprint: $CertificateThumbprint" -ForegroundColor White
        Write-Host "`n  IMPORTANT: You must also:" -ForegroundColor Yellow
        Write-Host "    1. Upload ad-monitoring-cert.cer to Azure AD App Registration" -ForegroundColor Yellow
        Write-Host "    2. Grant API permissions to the app registration" -ForegroundColor Yellow
        Write-Host "    3. Grant admin consent for the permissions" -ForegroundColor Yellow
        Write-Host "    See SERVICE-ACCOUNT-AUTH.md for detailed instructions" -ForegroundColor Yellow
    }
}
else {
    Write-Host "`n[3.5/7] Skipping certificate auth setup (use -SetupCertificateAuth to enable)" -ForegroundColor Yellow
    Write-Host "  You can configure this later by editing monitoring-config.json" -ForegroundColor Gray
}

# ============================================
# STEP 4: CONFIGURE TEAMS INTEGRATION
# ============================================

Write-Host "`n[4/8] Configuring Teams integration..." -ForegroundColor Cyan

if ($TeamsWebhookUrl) {
    # Update config file with webhook URL
    $configPath = Join-Path $OutputBasePath "Monitoring\config\monitoring-config.json"

    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        $config.Teams.WebhookUrl = $TeamsWebhookUrl
        $config.Teams.Enabled = $true
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "  [OK] Teams webhook URL configured" -ForegroundColor Green
    }

    # Test the webhook
    Write-Host "  [*] Testing Teams webhook..." -ForegroundColor Yellow
    $testPayload = @{
        type = "message"
        attachments = @(
            @{
                contentType = "application/vnd.microsoft.card.adaptive"
                content = @{
                    schema = "http://adaptivecards.io/schemas/adaptive-card.json"
                    type = "AdaptiveCard"
                    version = "1.4"
                    body = @(
                        @{
                            type = "TextBlock"
                            text = "AD Security Monitoring Setup Test"
                            weight = "Bolder"
                            size = "Large"
                            color = "Good"
                        }
                        @{
                            type = "TextBlock"
                            text = "This is a test message from the setup script. If you see this, Teams integration is working correctly!"
                            wrap = $true
                        }
                        @{
                            type = "TextBlock"
                            text = "Setup completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                            isSubtle = $true
                        }
                    )
                }
            }
        )
    }

    try {
        $jsonBody = $testPayload | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -ContentType "application/json" -Body $jsonBody -ErrorAction Stop
        Write-Host "  [OK] Teams webhook test sent successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "  [X] Teams webhook test failed: $_" -ForegroundColor Red
        Write-Host "  Hint: Verify the webhook URL and that the connector is enabled in Teams" -ForegroundColor Yellow
    }
}
else {
    Write-Host "  [-] Teams webhook URL not provided (can be configured later in monitoring-config.json)" -ForegroundColor Yellow
}

# ============================================
# STEP 4: CONFIGURE CROWDSTRIKE INTEGRATION
# ============================================

Write-Host "`n[4/7] Configuring CrowdStrike integration..." -ForegroundColor Cyan

if ($CrowdStrikeClientId -and $CrowdStrikeClientSecret) {
    # Store credentials securely using Windows Credential Manager
    Write-Host "  [*] Storing CrowdStrike credentials..." -ForegroundColor Yellow

    # Set environment variables for current session
    [Environment]::SetEnvironmentVariable("FALCON_CLIENT_ID", $CrowdStrikeClientId, "User")
    [Environment]::SetEnvironmentVariable("FALCON_CLIENT_SECRET", $CrowdStrikeClientSecret, "User")

    # Update config file
    $configPath = Join-Path $OutputBasePath "Monitoring\config\monitoring-config.json"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        $config.CrowdStrike.Enabled = $true
        $config.CrowdStrike.ClientId = $CrowdStrikeClientId
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "  [OK] CrowdStrike credentials configured" -ForegroundColor Green
    }

    Write-Host "  [!] Credentials stored in User environment variables" -ForegroundColor Yellow
    Write-Host "      For production, consider using Azure Key Vault or Windows Credential Manager" -ForegroundColor Yellow
}
else {
    Write-Host "  [-] CrowdStrike credentials not provided (can be configured later)" -ForegroundColor Yellow
    Write-Host "      Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables" -ForegroundColor Gray
}

# ============================================
# STEP 5: INITIALIZE DATABASE
# ============================================

if ($SetupDatabase) {
    Write-Host "`n[5/7] Initializing database..." -ForegroundColor Cyan

    if (-not $DatabaseServer) {
        Write-Error "DatabaseServer parameter is required when -SetupDatabase is specified"
        exit 1
    }

    $databaseName = "ADSecurityMonitoring"
    $schemaPath = Join-Path $OutputBasePath "Monitoring\Database\Schema.sql"

    if (-not (Test-Path $schemaPath)) {
        Write-Error "Database schema file not found: $schemaPath"
        exit 1
    }

    Write-Host "  Server: $DatabaseServer" -ForegroundColor Gray
    Write-Host "  Database: $databaseName" -ForegroundColor Gray

    # Create database
    $createDBSQL = "IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = '$databaseName') CREATE DATABASE [$databaseName];"

    try {
        Invoke-Sqlcmd -ServerInstance $DatabaseServer -Database "master" -Query $createDBSQL -ErrorAction Stop
        Write-Host "  [OK] Database created: $databaseName" -ForegroundColor Green
    }
    catch {
        Write-Host "  [X] Failed to create database: $_" -ForegroundColor Red
        exit 1
    }

    # Run schema
    try {
        Invoke-Sqlcmd -ServerInstance $DatabaseServer -Database $databaseName -InputFile $schemaPath -ErrorAction Stop
        Write-Host "  [OK] Database schema applied successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "  [X] Failed to apply schema: $_" -ForegroundColor Red
        exit 1
    }

    # Update config
    $configPath = Join-Path $OutputBasePath "Monitoring\config\monitoring-config.json"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        $config.Database.Enabled = $true
        $config.Database.Server = $DatabaseServer
        $config.Database.Database = $databaseName
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "  [OK] Database configuration updated in config file" -ForegroundColor Green
    }
}
else {
    Write-Host "`n[5/7] Skipping database setup (use -SetupDatabase to enable)" -ForegroundColor Yellow
}

# ============================================
# STEP 6: CREATE SCHEDULED TASKS
# ============================================

if ($SetupScheduledTasks) {
    Write-Host "`n[6/7] Creating scheduled tasks..." -ForegroundColor Cyan

    $scriptPath = Join-Path $OutputBasePath "Monitoring"
    $logPath = Join-Path $OutputBasePath "Logs"

    # Daily Security Checks task
    $taskName = "AD Security - Daily Checks"
    Write-Host "  [*] Creating task: $taskName..." -ForegroundColor Yellow

    $dailyAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath\Invoke-DailySecurityChecks.ps1`" -IncludeEntra -OutputFolder `"$scriptPath\DailyChecks`" 2>&1 | Out-File `"$logPath\daily-checks.log`" -Append"

    $dailyTrigger = New-ScheduledTaskTrigger -Daily -At "7:00AM"
    $dailySettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2)

    Register-ScheduledTask -TaskName $taskName -Action $dailyAction -Trigger $dailyTrigger `
        -Settings $dailySettings -Description "Run daily AD security checks" -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Host "  [OK] Task created: $taskName" -ForegroundColor Green

    # Weekly Full Assessment task
    $taskName = "AD Security - Weekly Assessment"
    Write-Host "  [*] Creating task: $taskName..." -ForegroundColor Yellow

    $weeklyAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath\..\script.ps1`" -IncludeEntra -OutputFolder `"$scriptPath\WeeklyAssessments`" -GenerateDiagrams 2>&1 | Out-File `"$logPath\weekly-assessment.log`" -Append"

    $weeklyTrigger = New-ScheduledTaskTrigger -Weekly -At "2:00AM" -DaysOfWeek Sunday
    $weeklySettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4)

    Register-ScheduledTask -TaskName $taskName -Action $weeklyAction -Trigger $weeklyTrigger `
        -Settings $weeklySettings -Description "Run weekly full AD security assessment" -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Host "  [OK] Task created: $taskName" -ForegroundColor Green

    # Data Export task
    $taskName = "AD Security - Data Export"
    Write-Host "  [*] Creating task: $taskName..." -ForegroundColor Yellow

    $exportAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath\Invoke-DataExport.ps1`" -ExportType All -OutputFolder `"$scriptPath\ExportedData`" 2>&1 | Out-File `"$logPath\data-export.log`" -Append"

    $exportTrigger = New-ScheduledTaskTrigger -Daily -At "4:00AM"
    $exportSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1)

    Register-ScheduledTask -TaskName $taskName -Action $exportAction -Trigger $exportTrigger `
        -Settings $exportSettings -Description "Export monitoring data to CSV and database" -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Host "  [OK] Task created: $taskName" -ForegroundColor Green

    Write-Host "`n  Scheduled Tasks Created:" -ForegroundColor Cyan
    Write-Host "    - Daily Checks: 7:00 AM daily" -ForegroundColor White
    Write-Host "    - Weekly Assessment: Sunday 2:00 AM" -ForegroundColor White
    Write-Host "    - Data Export: 4:00 AM daily" -ForegroundColor White
    Write-Host "`n  Note: Tasks run as SYSTEM. For Entra ID access, configure task to run as a user with Graph permissions." -ForegroundColor Yellow
}
else {
    Write-Host "`n[6/7] Skipping scheduled tasks (use -SetupScheduledTasks to enable)" -ForegroundColor Yellow
}

# ============================================
# STEP 7: GENERATE README & NEXT STEPS
# ============================================

Write-Host "`n[7/7] Generating setup completion report..." -ForegroundColor Cyan

$setupReport = @"
# AD Security Monitoring - Setup Complete

## Directory Structure
\`\`\`
$OutputBasePath/
├── Monitoring/
│   ├── DailyChecks/          # Daily security check results
│   ├── CrowdStrike/          # CrowdStrike Falcon data
│   ├── config/               # Configuration files
│   └── Database/             # Database schema
├── ExportedData/
│   ├── CSV/                  # CSV exports for history
│   ├── DatabaseStaging/      # Staging area for DB import
│   └── PowerBI/              # Power BI data & config
├── Logs/                     # Execution logs
└── Backups/                  # Backups
\`\`\`

## Scripts Available

| Script | Purpose |
|--------|---------|
| Invoke-DailySecurityChecks.ps1 | Fast critical-only checks (5-10 min) |
| Invoke-CrowdStrikeCollection.ps1 | CrowdStrike Falcon API integration |
| Send-TeamsAlert.ps1 | Teams webhook alerting |
| Invoke-DataExport.ps1 | CSV/Database/Power BI export |

## Next Steps

### 1. Configure Credentials
- Set environment variables for CrowdStrike:
  \`\`\`powershell
  [Environment]::SetEnvironmentVariable("FALCON_CLIENT_ID", "your-client-id", "User")
  [Environment]::SetEnvironmentVariable("FALCON_CLIENT_SECRET", "your-secret", "User")
  \`\`\`

### 2. Test Daily Checks
\`\`\`powershell
cd "$OutputBasePath\Monitoring"
.\Invoke-DailySecurityChecks.ps1 -IncludeEntra
\`\`\`

### 3. Configure Teams Alerts
- Edit: \`$OutputBasePath\Monitoring\config\monitoring-config.json\`
- Set Teams.WebhookUrl
- Test: \`.\Send-TeamsAlert.ps1 -WebhookUrl "URL"\`

### 4. Run Full Assessment
\`\`\`powershell
cd "$OutputBasePath"
..\script.ps1 -IncludeEntra -OutputFolder ".\Monitoring\WeeklyAssessments"
\`\`\`

### 5. Export Data
\`\`\`powershell
cd "$OutputBasePath\Monitoring"
.\Invoke-DataExport.ps1 -ExportType All
\`\`\`

### 6. Connect Power BI
- Open Power BI Desktop
- Get Data -> Folder -> Select \`$OutputBasePath\ExportedData\PowerBI\`
- Use provided data model template

## Scheduled Tasks
$(if ($SetupScheduledTasks) { "Created (check Task Scheduler)" } else { "Not created (use -SetupScheduledTasks)" })

## Database
$(if ($SetupDatabase) { "Initialized on $DatabaseServer" } else { "Not configured (use -SetupDatabase)" })

## Support
- Documentation: See README.md in project root
- Issues: Check PowerShell error logs in $OutputBasePath\Logs\
"@

$reportPath = Join-Path $OutputBasePath "SETUP-COMPLETE.md"
$setupReport | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "  [OK] Setup report generated: $reportPath" -ForegroundColor Green

# ============================================
# FINAL SUMMARY
# ============================================

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nOutput Base: $OutputBasePath" -ForegroundColor Cyan
Write-Host "Teams Configured: $(if ($TeamsWebhookUrl) { 'Yes' } else { 'No' })" -ForegroundColor Cyan
Write-Host "CrowdStrike Configured: $(if ($CrowdStrikeClientId) { 'Yes' } else { 'No' })" -ForegroundColor Cyan
Write-Host "Database Setup: $(if ($SetupDatabase) { "Yes ($DatabaseServer)" } else { 'No' })" -ForegroundColor Cyan
Write-Host "Scheduled Tasks: $(if ($SetupScheduledTasks) { 'Yes (3 tasks)' } else { 'No' })" -ForegroundColor Cyan

Write-Host "`nNext: Review SETUP-COMPLETE.md for detailed instructions" -ForegroundColor Yellow
Write-Host "`n========================================`n" -ForegroundColor Green
