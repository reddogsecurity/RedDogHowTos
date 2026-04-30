<#
.SYNOPSIS
  Master orchestration script for AD + Entra security assessment (Modular Version)

.DESCRIPTION
  This is the main entry point for the modular AD/Entra security assessment.
  It orchestrates the collection, analysis, and reporting modules.
  
  MODULAR ARCHITECTURE:
  - Modules/Helpers.psm1         → Common utility functions
  - Modules/AD-Collector.psm1    → Active Directory data collection
  - Modules/Entra-Collector.psm1 → Entra ID (Azure AD) data collection
  - Modules/Analyzer.psm1        → Security analysis engine (to be created)
  - Modules/Reporter.psm1        → HTML report generation (to be created)

.PARAMETER OutputFolder
  Path where assessment results will be stored (default: $env:TEMP\ADScan)

.PARAMETER IncludeEntra
  Include Entra ID (Azure AD) assessment in addition to on-prem AD

.PARAMETER MaxParallel
  Maximum parallel threads for data collection (not yet implemented)

.EXAMPLE
  .\Run-Assessment.ps1
  Run AD-only assessment

.EXAMPLE
  .\Run-Assessment.ps1 -IncludeEntra
  Run comprehensive AD + Entra ID assessment

.EXAMPLE
  .\Run-Assessment.ps1 -IncludeEntra -OutputFolder "C:\Assessments\Client1"
  Run full assessment with custom output location
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "$env:TEMP\ADScan",
    [switch]$IncludeEntra,
    [int]$MaxParallel = 8
)

# Initialize
if (-not (Test-Path $OutputFolder)) { 
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null 
}

$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$collectionErrors = @()

# Save metadata
$metadata = [PSCustomObject]@{
    CollectedAt = (Get-Date).ToString("u")
    Host = $env:COMPUTERNAME
    User = (whoami)
    IncludeEntra = $IncludeEntra.IsPresent
    ModularVersion = $true
    Version = "2.0-Modular"
}
$metadata | ConvertTo-Json | Out-File (Join-Path $OutputFolder "metadata-$timestamp.json")

# Import modules
$modulePath = Join-Path $PSScriptRoot "Modules"
Import-Module (Join-Path $modulePath "Helpers.psm1") -Force
Import-Module (Join-Path $modulePath "AD-Collector.psm1") -Force
if ($IncludeEntra) {
    Import-Module (Join-Path $modulePath "Entra-Collector.psm1") -Force
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Starting Modular Security Assessment" -ForegroundColor Cyan
Write-Host "Version: 2.0-Modular" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# === PHASE 1: DATA COLLECTION ===
Write-Host "PHASE 1: Data Collection" -ForegroundColor Magenta

# Collect AD data
try {
    Invoke-ADCollection -OutputFolder $OutputFolder -Timestamp $timestamp
} catch {
    Write-Warning "AD collection failed: $_"
    $collectionErrors += "AD collection: $_"
}

# Collect Entra data (if requested)
if ($IncludeEntra) {
    try {
        Invoke-EntraCollection -OutputFolder $OutputFolder -Timestamp $timestamp
    } catch {
        Write-Warning "Entra collection failed: $_"
        $collectionErrors += "Entra collection: $_"
    }
} else {
    Write-Host "`nSkipping Entra collection (use -IncludeEntra to enable)" -ForegroundColor Yellow
}

# === PHASE 2: ANALYSIS ===
Write-Host "`nPHASE 2: Security Analysis" -ForegroundColor Magenta
Write-Host "Note: Analysis and reporting modules are still in the monolithic script." -ForegroundColor Yellow
Write-Host "      Run the original script.ps1 to generate analysis reports." -ForegroundColor Yellow
Write-Host "      Or wait for Analyzer.psm1 and Reporter.psm1 modules to be created." -ForegroundColor Yellow

# === COMPLETION ===
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Data Collection Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Output Location: $OutputFolder" -ForegroundColor Cyan
Write-Host "Timestamp: $timestamp" -ForegroundColor Cyan

if ($collectionErrors.Count -gt 0) {
    Write-Host "`nErrors encountered:" -ForegroundColor Yellow
    $collectionErrors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Review collected data files in the output folder" -ForegroundColor Gray
Write-Host "  2. Run the full script.ps1 for comprehensive analysis (until Analyzer module is ready)" -ForegroundColor Gray
Write-Host "  3. Consider completing the modularization by creating Analyzer.psm1 and Reporter.psm1" -ForegroundColor Gray

