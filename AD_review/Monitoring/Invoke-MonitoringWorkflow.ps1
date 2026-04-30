<#
.SYNOPSIS
    Master orchestrator for AD Security Monitoring - runs daily/weekly workflow

.DESCRIPTION
    Orchestrates the complete monitoring workflow:
    1. Runs daily security checks (or weekly full assessment)
    2. Collects CrowdStrike Falcon data
    3. Sends Teams alerts for critical findings
    4. Exports data to CSV/database/Power BI
    5. Logs all activity and errors

    Designed for automated scheduled execution or manual trigger.

.PARAMETER WorkflowType
    Daily: Fast critical checks (5-10 min)
    Weekly: Full assessment + CrowdStrike + export (30-60 min)

.PARAMETER ConfigPath
    Path to monitoring-config.json (default: ./config/monitoring-config.json)

.PARAMETER SendTeamsAlerts
    Override config and send Teams alerts

.PARAMETER SkipCrowdStrike
    Skip CrowdStrike data collection

.PARAMETER SkipExport
    Skip data export step

.PARAMETER ForceFullCollection
    Force full data collection even if recent collection exists

.PARAMETER LogPath
    Path to log file (default: ./Logs/orchestrator-YYYYMMDD.log)

.EXAMPLE
    .\Invoke-MonitoringWorkflow.ps1 -WorkflowType Daily
    Run daily workflow

.EXAMPLE
    .\Invoke-MonitoringWorkflow.ps1 -WorkflowType Weekly -SendTeamsAlerts
    Run weekly workflow with Teams alerts

.EXAMPLE
    .\Invoke-MonitoringWorkflow.ps1 -WorkflowType Daily -SkipCrowdStrike
    Run daily workflow without CrowdStrike
#>

[CmdletBinding()]
param(
    [ValidateSet("Daily", "Weekly")]
    [string]$WorkflowType = "Daily",
    [string]$ConfigPath = "$PSScriptRoot\config\monitoring-config.json",
    [switch]$SendTeamsAlerts,
    [switch]$SkipCrowdStrike,
    [switch]$SkipExport,
    [switch]$ForceFullCollection,
    [string]$LogPath = "",
    [ValidateSet("Interactive", "Certificate", "ManagedIdentity", "ClientSecret")]
    [string]$AuthMethod = "Interactive",
    [string]$ClientId = "",
    [string]$TenantId = "",
    [string]$CertificateThumbprint = "",
    [string]$CertificateStoreLocation = "CurrentUser",
    [System.Management.Automation.PSCredential]$ClientSecretCredential
)

# Setup logging
if (-not $LogPath) {
    $logDir = Join-Path $PSScriptRoot "..\Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    $LogPath = Join-Path $logDir "orchestrator-$(Get-Date -Format 'yyyyMMdd').log"
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Write to console
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host $logMessage -ForegroundColor $color

    # Write to log file
    $logMessage | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

# ============================================
# LOAD CONFIGURATION
# ============================================

Write-Log "Starting $WorkflowType monitoring workflow" "INFO"
Write-Log "Log file: $LogPath" "INFO"

$config = $null
if (Test-Path $ConfigPath) {
    try {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        Write-Log "Configuration loaded from $ConfigPath" "SUCCESS"
    }
    catch {
        Write-Log "Failed to load config: $_" "ERROR"
        Write-Log "Continuing with defaults..." "WARN"
    }
}
else {
    Write-Log "Config file not found: $ConfigPath" "WARN"
    Write-Log "Using default settings..." "INFO"
}

# Extract settings from config
$teamsEnabled = if ($SendTeamsAlerts) { $true } elseif ($config -and $config.Teams.Enabled) { $true } else { $false }
$teamsWebhookUrl = if ($config -and $config.Teams.WebhookUrl) { $config.Teams.WebhookUrl } else { "" }
$csEnabled = if ($SkipCrowdStrike) { $false } elseif ($config -and $config.CrowdStrike.Enabled) { $true } else { $false }
$exportEnabled = if ($SkipExport) { $false } elseif ($config -and ($config.Export.CSV.Enabled -or $config.Export.PowerBI.Enabled)) { $true } else { $false }

Write-Log "Configuration:" "INFO"
Write-Log "  Teams Alerts: $teamsEnabled" "INFO"
Write-Log "  CrowdStrike: $csEnabled" "INFO"
Write-Log "  Data Export: $exportEnabled" "INFO"

# ============================================
# WORKFLOW EXECUTION
# ============================================

$workflowStart = Get-Date
$allFindings = @()
$alertFindings = @()
$errors = @()

try {
    # ============================================
    # STEP 1: SECURITY CHECKS
    # ============================================

    Write-Log "`n========== STEP 1: Security Checks ==========" "INFO"

    $dailyChecksScript = Join-Path $PSScriptRoot "Invoke-DailySecurityChecks.ps1"

    if (-not (Test-Path $dailyChecksScript)) {
        Write-Log "Daily checks script not found: $dailyChecksScript" "ERROR"
        $errors += "Daily checks script not found"
    }
    else {
        $dailyParams = @{
            OutputFolder = (Join-Path $PSScriptRoot "DailyChecks")
            AuthMethod = $AuthMethod
        }

        if ($ClientId) { $dailyParams.ClientId = $ClientId }
        if ($TenantId) { $dailyParams.TenantId = $TenantId }
        if ($CertificateThumbprint) { $dailyParams.CertificateThumbprint = $CertificateThumbprint }
        if ($CertificateStoreLocation -ne "CurrentUser") { $dailyParams.CertificateStoreLocation = $CertificateStoreLocation }
        if ($ClientSecretCredential) { $dailyParams.ClientSecretCredential = $ClientSecretCredential }

        if ($WorkflowType -eq "Daily" -and $config -and $config.Monitoring.DailySchedule.IncludeEntra) {
            $dailyParams.IncludeEntra = $true
        }
        elseif ($WorkflowType -eq "Weekly") {
            $dailyParams.IncludeEntra = $true
        }

        if ($teamsEnabled -and $teamsWebhookUrl) {
            $dailyParams.TeamsWebhookUrl = $teamsWebhookUrl
        }

        if ($config -and $config.Monitoring.DailySchedule.AlertThreshold) {
            $dailyParams.AlertThreshold = $config.Monitoring.DailySchedule.AlertThreshold
        }

        # Check for baseline file
        $baselineFiles = Get-ChildItem -Path $dailyParams.OutputFolder -Filter "daily-checks-*.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($baselineFiles) {
            $dailyParams.BaselinePath = $baselineFiles.FullName
        }

        Write-Log "Running daily security checks..." "INFO"

        try {
            $dailyResults = & $dailyChecksScript @dailyParams
            $allFindings += $dailyResults

            if ($dailyResults) {
                $criticalCount = ($dailyResults | Where-Object { $_.Severity -eq "Critical" }).Count
                $highCount = ($dailyResults | Where-Object { $_.Severity -eq "High" }).Count
                Write-Log "Daily checks complete: $($dailyResults.Count) findings ($criticalCount critical, $highCount high)" "SUCCESS"

                # Collect alert-worthy findings
                $alertFindings += $dailyResults | Where-Object {
                    $_.Severity -in @("Critical", "High")
                }
            }
        }
        catch {
            Write-Log "Daily checks failed: $_" "ERROR"
            $errors += "Daily checks: $_"
        }
    }

    # ============================================
    # STEP 2: CROWDSTRIKE COLLECTION
    # ============================================

    if ($csEnabled) {
        Write-Log "`n========== STEP 2: CrowdStrike Collection ==========" "INFO"

        $csScript = Join-Path $PSScriptRoot "Invoke-CrowdStrikeCollection.ps1"

        if (-not (Test-Path $csScript)) {
            Write-Log "CrowdStrike script not found: $csScript" "ERROR"
            $errors += "CrowdStrike script not found"
        }
        else {
            # Check credentials
            $csClientId = if ($config -and $config.CrowdStrike.ClientId) {
                $config.CrowdStrike.ClientId
            }
            else {
                $env:FALCON_CLIENT_ID
            }

            $csClientSecret = if ($config -and $config.CrowdStrike.ClientSecret) {
                $config.CrowdStrike.ClientSecret
            }
            else {
                $env:FALCON_CLIENT_SECRET
            }

            if (-not $csClientId -or -not $csClientSecret) {
                Write-Log "CrowdStrike credentials not configured" "WARN"
                Write-Log "Set FALCON_CLIENT_ID/FALCON_CLIENT_SECRET or update config" "WARN"
            }
            else {
                $csParams = @{
                    OutputFolder = (Join-Path $PSScriptRoot "CrowdStrike")
                    ClientId = $csClientId
                    ClientSecret = $csClientSecret
                    CollectionType = if ($WorkflowType -eq "Weekly") { "Weekly" } else { "Daily" }
                    AuthMethod = $AuthMethod
                }

                if ($ClientId) { $csParams.ClientId = $ClientId }
                if ($TenantId) { $csParams.TenantId = $TenantId }
                if ($CertificateThumbprint) { $csParams.CertificateThumbprint = $CertificateThumbprint }

                if ($config -and $config.CrowdStrike.CloudRegion) {
                    $csParams.CloudRegion = $config.CrowdStrike.CloudRegion
                }

                # Find AD inventory files for correlation
                $weeklyFolder = Join-Path $PSScriptRoot "..\WeeklyAssessments"
                if (Test-Path $weeklyFolder) {
                    $computerFiles = Get-ChildItem -Path $weeklyFolder -Filter "ad-computers-*.csv" -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($computerFiles) {
                        $csParams.ADComputerCSV = $computerFiles.FullName
                    }

                    $userFiles = Get-ChildItem -Path $weeklyFolder -Filter "ad-users-*.csv" -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($userFiles) {
                        $csParams.ADUsersCSV = $userFiles.FullName
                    }
                }

                Write-Log "Running CrowdStrike collection..." "INFO"

                try {
                    $csResults = & $csScript @csParams
                    Write-Log "CrowdStrike collection complete" "SUCCESS"

                    # Add CrowdStrike findings to alert list
                    if ($csResults -and $csResults.Detections) {
                        $criticalDetections = $csResults.Detections | Where-Object {
                            $_.MaxSeverity -eq "Critical"
                        }
                        $highDetections = $csResults.Detections | Where-Object {
                            $_.MaxSeverity -eq "High"
                        }

                        if ($criticalDetections.Count -gt 0) {
                            $alertFindings += $criticalDetections | ForEach-Object {
                                [PSCustomObject]@{
                                    FindingId = "CS-$($_.DetectionId)"
                                    Title = "CrowdStrike Detection: $($_.Technique)"
                                    Severity = "Critical"
                                    Category = "CrowdStrike"
                                    Description = "Device: $($_.DeviceName), User: $($_.Username)"
                                    MITRETechnique = $_.Technique
                                    Evidence = $_
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Log "CrowdStrike collection failed: $_" "ERROR"
                    $errors += "CrowdStrike: $_"
                }
            }
        }
    }

    # ============================================
    # STEP 3: TEAMS ALERTS
    # ============================================

    if ($teamsEnabled -and $teamsWebhookUrl -and $alertFindings.Count -gt 0) {
        Write-Log "`n========== STEP 3: Teams Alerts ==========" "INFO"

        $teamsScript = Join-Path $PSScriptRoot "Send-TeamsAlert.ps1"

        if (-not (Test-Path $teamsScript)) {
            Write-Log "Teams alert script not found: $teamsScript" "ERROR"
            $errors += "Teams alert script not found"
        }
        else {
            $criticalCount = ($alertFindings | Where-Object { $_.Severity -eq "Critical" }).Count
            $highCount = ($alertFindings | Where-Object { $_.Severity -eq "High" }).Count

            $severity = if ($criticalCount -gt 0) { "Critical" } else { "High" }
            $source = if ($WorkflowType -eq "Weekly") { "Weekly Assessment" } else { "Daily Checks" }

            $teamsParams = @{
                WebhookUrl = $teamsWebhookUrl
                Severity = $severity
                Findings = $alertFindings
                Source = $source
                IncludeDetails = $true
                MaxFindings = 10
                Summary = "$($alertFindings.Count) finding(s) detected ($criticalCount critical, $highCount high)"
            }

            Write-Log "Sending Teams alert: $criticalCount critical, $highCount high findings" "INFO"

            try {
                & $teamsScript @teamsParams
                Write-Log "Teams alert sent successfully" "SUCCESS"
            }
            catch {
                Write-Log "Teams alert failed: $_" "ERROR"
                $errors += "Teams alert: $_"
            }
        }
    }
    elseif ($teamsEnabled -and $teamsWebhookUrl) {
        Write-Log "`nNo alert-worthy findings - skipping Teams notification" "INFO"
    }

    # ============================================
    # STEP 4: DATA EXPORT
    # ============================================

    if ($exportEnabled) {
        Write-Log "`n========== STEP 4: Data Export ==========" "INFO"

        $exportScript = Join-Path $PSScriptRoot "Invoke-DataExport.ps1"

        if (-not (Test-Path $exportScript)) {
            Write-Log "Data export script not found: $exportScript" "ERROR"
            $errors += "Data export script not found"
        }
        else {
            $exportParams = @{
                SourceFolder = $PSScriptRoot
                OutputFolder = (Join-Path $PSScriptRoot "..\ExportedData")
                ExportType = "All"
            }

            if ($csEnabled) {
                $exportParams.IncludeCrowdStrike = $true
            }

            if ($config -and $config.Database.Enabled -and $config.Database.Server) {
                $exportParams.DatabaseServer = $config.Database.Server
                $exportParams.DatabaseName = $config.Database.Database
            }

            Write-Log "Running data export..." "INFO"

            try {
                & $exportScript @exportParams
                Write-Log "Data export complete" "SUCCESS"
            }
            catch {
                Write-Log "Data export failed: $_" "ERROR"
                $errors += "Data export: $_"
            }
        }
    }

    # ============================================
    # WORKFLOW COMPLETE
    # ============================================

    $workflowEnd = Get-Date
    $duration = New-TimeSpan -Start $workflowStart -End $workflowEnd

    Write-Log "`n========================================" "INFO"
    Write-Log "Workflow Complete!" "SUCCESS"
    Write-Log "========================================" "INFO"
    Write-Log "Duration: $($duration.TotalMinutes.ToString('0.00')) minutes" "INFO"
    Write-Log "Total Findings: $($allFindings.Count)" "INFO"
    Write-Log "Alert Findings: $($alertFindings.Count)" "INFO"
    Write-Log "Errors: $($errors.Count)" "INFO"

    if ($errors.Count -gt 0) {
        Write-Log "`nErrors encountered:" "ERROR"
        foreach ($error in $errors) {
            Write-Log "  - $error" "ERROR"
        }
    }

    # Return summary
    return [PSCustomObject]@{
        WorkflowType = $WorkflowType
        Duration = $duration
        TotalFindings = $allFindings.Count
        AlertFindings = $alertFindings.Count
        Errors = $errors.Count
        ErrorDetails = $errors
        CompletedAt = Get-Date
    }
}
catch {
    Write-Log "Workflow failed with unhandled error: $_" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"

    throw $_
}
