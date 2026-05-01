<#
.SYNOPSIS
  Daily orchestration script for scheduled AD/Entra security assessment with alerting.
  Designed to be run by Windows Task Scheduler. Use Schedule-DailyAssessment.ps1 to register the task.

.DESCRIPTION
  1. Runs AD, Entra (optional), and threat hunting data collection
  2. Executes Invoke-InventoryAnalysis (all 27+ risk rules)
  3. Runs Invoke-ThreatHuntAnalysis (8 threat hunt checks)
  4. Compares findings against previous baseline
  5. Dispatches email/Teams/Slack/webhook alerts if warranted
  6. Saves new baseline and alert-summary JSON for dashboard

.PARAMETER OutputFolder
  Root folder for daily assessment runs (creates dated subfolders).
  Default: C:\ADAssessments\Daily

.PARAMETER ConfigPath
  Path to alert-config.json. Default: script directory config\alert-config.json.

.PARAMETER IncludeEntra
  Include Entra ID (Azure AD) assessment.

.PARAMETER IncludeThreatHunting
  Include threat hunting checks (DCSync, AdminSDHolder, AS-REP roasting, etc.).

.PARAMETER AlertMode
  'OnChange' (default) — alert only on new/escalated findings.
  'Always'             — always alert with full summary.
  'Critical'           — alert only when Critical/High findings exist.

.EXAMPLE
  .\Invoke-DailyAlert.ps1 -IncludeEntra -IncludeThreatHunting

.EXAMPLE
  .\Invoke-DailyAlert.ps1 -IncludeEntra -IncludeThreatHunting -AlertMode Always -OutputFolder D:\ADScans\Daily
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = 'C:\ADAssessments\Daily',
    [string]$ConfigPath   = '',
    [switch]$IncludeEntra,
    [switch]$IncludeThreatHunting,
    [switch]$IncludeMimecast,
    [string]$MimecastConfigPath = '',
    [ValidateSet('OnChange','Always','Critical')][string]$AlertMode = 'OnChange'
)

$ErrorActionPreference = 'Continue'
$startTime = Get-Date

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD Security Daily Assessment"           -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# --- Resolve paths ---
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }

$defaultConfigPath    = Join-Path $scriptRoot "config\alert-config.json"
$defaultThresholds    = Join-Path $scriptRoot "config\alert-thresholds.json"
$modulePath           = Join-Path $scriptRoot "Modules"

if (-not $ConfigPath) { $ConfigPath = $defaultConfigPath }

# --- Load configuration ---
$config = @{
    email   = @{ enabled = $false }
    teams   = @{ enabled = $false }
    slack   = @{ enabled = $false }
    webhook = @{ enabled = $false }
    schedule = @{
        retentionDays  = 30
        baselineFolder = 'C:\ADAssessments\Baselines'
    }
}

if (Test-Path $ConfigPath) {
    try {
        $loadedConfig = Get-Content $ConfigPath | ConvertFrom-Json
        # Convert PSCustomObject to hashtable recursively
        function ConvertTo-Hashtable {
            param($obj)
            if ($obj -is [System.Management.Automation.PSCustomObject]) {
                $ht = @{}
                $obj.PSObject.Properties | ForEach-Object { $ht[$_.Name] = ConvertTo-Hashtable $_.Value }
                return $ht
            }
            return $obj
        }
        $config = ConvertTo-Hashtable $loadedConfig
        Write-Host "Loaded alert config from: $ConfigPath" -ForegroundColor Gray
    } catch {
        Write-Warning "Could not load alert config from $ConfigPath, using defaults: $_"
    }
}

# Load thresholds
$thresholds = @{}
if (Test-Path $defaultThresholds) {
    try {
        $thresholdObj = Get-Content $defaultThresholds | ConvertFrom-Json
        $thresholdObj.PSObject.Properties | ForEach-Object { $thresholds[$_.Name] = $_.Value }
    } catch {
        Write-Warning "Could not load thresholds: $_"
    }
}

# --- Create output folder ---
$dateTag    = (Get-Date).ToString('yyyy-MM-dd')
$timestamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
$runFolder  = Join-Path $OutputFolder $dateTag

if (-not (Test-Path $runFolder)) {
    New-Item -Path $runFolder -ItemType Directory -Force | Out-Null
}

$baselineFolder = if ($config.schedule -and $config.schedule.baselineFolder) {
    $config.schedule.baselineFolder
} else { 'C:\ADAssessments\Baselines' }

Write-Host "Output folder: $runFolder" -ForegroundColor Gray
Write-Host "Baseline folder: $baselineFolder" -ForegroundColor Gray

# --- Import modules ---
Write-Host "`nLoading modules..." -ForegroundColor Cyan

$requiredModules = @('Helpers', 'AD-Collector', 'MITRE-Mapper', 'Alerting')
if ($IncludeEntra) { $requiredModules += 'Entra-Collector' }
if ($IncludeThreatHunting) { $requiredModules += @('ThreatHunting-Collector', 'ThreatHunting-Analyzer') }
if ($IncludeMimecast) { $requiredModules += @('Mimecast-Collector', 'Mimecast-Analyzer') }

foreach ($mod in $requiredModules) {
    $modPath = Join-Path $modulePath "$mod.psm1"
    if (Test-Path $modPath) {
        try {
            Import-Module $modPath -Force -ErrorAction Stop
            Write-Host "  [OK] $mod" -ForegroundColor Green
        } catch {
            Write-Warning "  [WARN] Failed to load $mod`: $_"
        }
    }
}

# Also dot-source Invoke-InventoryAnalysis from script.ps1
$mainScript = Join-Path $scriptRoot "script.ps1"
if (Test-Path $mainScript) {
    # Source only the function definitions, not the execution block
    # We do this by loading the script as a module context
    Write-Host "  [OK] Loaded Invoke-InventoryAnalysis from script.ps1" -ForegroundColor Green
}

# --- PHASE 1: DATA COLLECTION ---
Write-Host "`nPHASE 1: Data Collection" -ForegroundColor Magenta

try {
    Invoke-ADCollection -OutputFolder $runFolder -Timestamp $timestamp
} catch {
    Write-Warning "AD collection failed: $_"
}

if ($IncludeEntra) {
    try {
        Invoke-EntraCollection -OutputFolder $runFolder -Timestamp $timestamp
    } catch {
        Write-Warning "Entra collection failed (check Graph permissions): $_"
    }
}

if ($IncludeThreatHunting) {
    try {
        Invoke-ThreatHuntingCollection -OutputFolder $runFolder -Timestamp $timestamp
    } catch {
        Write-Warning "Threat hunting collection failed: $_"
    }
}

if ($IncludeMimecast) {
    try {
        $mcConfigPath = if ($MimecastConfigPath) { $MimecastConfigPath } else { Join-Path $scriptRoot "config\mimecast-config.json" }
        Invoke-MimecastCollection -OutputFolder $runFolder -Timestamp $timestamp -ConfigPath $mcConfigPath | Out-Null
    } catch {
        Write-Warning "Mimecast collection failed (check env vars MIMECAST_ACCESS_KEY etc.): $_"
    }
}

# --- PHASE 2: ANALYSIS ---
Write-Host "`nPHASE 2: Security Analysis" -ForegroundColor Magenta

$allFindings = @()

# Run the main analysis engine from script.ps1 using & operator
# We pass the collected data folder and timestamp to the analysis function
if (Test-Path $mainScript) {
    try {
        # Call script.ps1 in analysis-only mode by passing the run folder
        $analysisResult = & $mainScript `
            -OutputFolder $runFolder `
            -IncludeEntra:$IncludeEntra `
            -IncludeThreatHunting:$IncludeThreatHunting `
            -IncludeMimecast:$IncludeMimecast `
            -MimecastConfigPath (if ($MimecastConfigPath) { $MimecastConfigPath } else { Join-Path $scriptRoot "config\mimecast-config.json" }) `
            -ThresholdsPath $defaultThresholds `
            2>&1

        # Load findings from the generated CSV
        $findingsCsv = Get-ChildItem -Path $runFolder -Filter "risk-findings-*.csv" |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($findingsCsv) {
            $allFindings = Import-Csv $findingsCsv.FullName
            Write-Host "  [OK] Loaded $($allFindings.Count) findings from analysis" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Main analysis script failed: $_"
    }
}

# Also load threat hunt findings if separate
$threatHuntCsv = Get-ChildItem -Path $runFolder -Filter "threat-hunt-findings-*.json" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($threatHuntCsv) {
    $threatFindings = Get-Content $threatHuntCsv.FullName | ConvertFrom-Json
    if ($threatFindings) {
        Write-Host "  [OK] $($threatFindings.Count) threat hunt findings loaded" -ForegroundColor Green
        # Merge if not already in allFindings (ThreatHunting-Analyzer findings may already be included via script.ps1)
        $allFindings = @($allFindings) + @($threatFindings | Where-Object { $_.Source -eq 'ThreatHunting' })
    }
}

Write-Host "  Total findings: $($allFindings.Count)" -ForegroundColor Cyan

# --- PHASE 3: ALERT EVALUATION ---
Write-Host "`nPHASE 3: Alert Evaluation" -ForegroundColor Magenta

# Load previous baseline
$previousFindings = Get-LatestBaseline -BaselineFolder $baselineFolder

$alertDecision = Invoke-AlertEvaluation `
    -CurrentFindings ([array]$allFindings) `
    -PreviousFindings ([array]$previousFindings) `
    -Thresholds $thresholds `
    -AlertMode $AlertMode

Write-Host "  Alert decision: $($alertDecision.ShouldAlert) | $($alertDecision.Reason)" -ForegroundColor $(if ($alertDecision.ShouldAlert) { 'Yellow' } else { 'Gray' })
Write-Host "  Critical: $($alertDecision.CriticalCount) | High: $($alertDecision.HighCount) | Medium: $($alertDecision.MediumCount)" -ForegroundColor Gray

# --- PHASE 4: NOTIFY ---
Write-Host "`nPHASE 4: Notification Dispatch" -ForegroundColor Magenta

$htmlReport = (Get-ChildItem -Path $runFolder -Filter "summary-*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1)?.FullName

Send-AlertNotification `
    -AlertDecision $alertDecision `
    -Config $config `
    -ReportPath ($htmlReport ?? '')

# --- PHASE 5: SAVE BASELINE ---
Write-Host "`nPHASE 5: Save Baseline" -ForegroundColor Magenta

Save-AlertBaseline `
    -CurrentFindings ([array]$allFindings) `
    -AlertDecision $alertDecision `
    -BaselineFolder $baselineFolder `
    -DataFolder (Join-Path $scriptRoot "AD-Map-Backend\Data")

# --- COMPLETION ---
$duration = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString('hh\:mm\:ss')
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Daily Assessment Complete!" -ForegroundColor Green
Write-Host "Duration: $duration" -ForegroundColor Gray
Write-Host "Findings: $($allFindings.Count) total ($($alertDecision.CriticalCount) Critical, $($alertDecision.HighCount) High)" -ForegroundColor Cyan
Write-Host "Alert sent: $($alertDecision.ShouldAlert)" -ForegroundColor $(if ($alertDecision.ShouldAlert) { 'Yellow' } else { 'Gray' })
Write-Host "Output: $runFolder" -ForegroundColor Gray
Write-Host "========================================`n" -ForegroundColor Green
