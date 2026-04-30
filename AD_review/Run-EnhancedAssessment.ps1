<#
.SYNOPSIS
    Master script to run all enhanced AD security assessment scripts.

.DESCRIPTION
    This orchestrator script runs all the new security assessment scripts in sequence,
    organizing output into a single timestamped folder for easy review and compliance reporting.

.PARAMETER OutputFolder
    Base path where assessment reports will be saved. A timestamped subfolder will be created.

.PARAMETER SkipEntraMFA
    Skip MFA status checking (useful if Graph permissions not available).

.PARAMETER SkipEntraComparison
    Skip AD to Entra comparison (useful for on-premises only environments).

.PARAMETER SkipSchemaAudit
    Skip schema permissions audit (requires elevated permissions).

.PARAMETER QuickScan
    Run minimal checks only (no Entra integration, no schema audit).

.EXAMPLE
    .\Run-EnhancedAssessment.ps1
    Run complete assessment with all features

.EXAMPLE
    .\Run-EnhancedAssessment.ps1 -QuickScan
    Run quick assessment without Entra integration

.EXAMPLE
    .\Run-EnhancedAssessment.ps1 -OutputFolder "C:\SecurityAudits"
    Run assessment with custom output location

.NOTES
    Requires: Active Directory PowerShell module
    Optional: Microsoft Graph modules for Entra features
    Run time: 10-30 minutes depending on environment size
#>

param(
    [string]$OutputFolder = "C:\AD_SecurityAssessments",
    [switch]$SkipEntraMFA,
    [switch]$SkipEntraComparison,
    [switch]$SkipSchemaAudit,
    [switch]$QuickScan
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Create timestamped output folder
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$assessmentFolder = Join-Path $OutputFolder "Assessment-$timestamp"

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  ENHANCED AD SECURITY ASSESSMENT - MASTER ORCHESTRATOR" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "`nAssessment Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "Output Folder: $assessmentFolder" -ForegroundColor White

# Create output directory
try {
    New-Item -ItemType Directory -Path $assessmentFolder -Force | Out-Null
    Write-Host "[OK] Created output directory" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create output directory: $_"
    exit 1
}

# Apply QuickScan settings
if ($QuickScan) {
    Write-Host "`n[INFO] Quick Scan mode enabled - Skipping Entra integration and schema audit" -ForegroundColor Yellow
    $SkipEntraMFA = $true
    $SkipEntraComparison = $true
    $SkipSchemaAudit = $true
}

# Get script directory
$scriptDir = $PSScriptRoot
$startTime = Get-Date

# Track results
$results = @{
    TotalScripts = 0
    Completed = 0
    Failed = 0
    Skipped = 0
    Scripts = @()
}

# Function to run script with error handling
function Invoke-AssessmentScript {
    param(
        [string]$ScriptName,
        [string]$Description,
        [array]$Parameters = @(),
        [bool]$Skip = $false
    )
    
    $results.TotalScripts++
    
    if ($Skip) {
        Write-Host "`n[$($results.TotalScripts)/$($results.TotalScripts)] SKIPPING: $ScriptName" -ForegroundColor Yellow
        Write-Host "    Reason: User requested skip or dependencies not available" -ForegroundColor Gray
        $results.Skipped++
        $results.Scripts += [PSCustomObject]@{
            Script = $ScriptName
            Status = "Skipped"
            Duration = "N/A"
            Message = "Skipped by user request"
        }
        return
    }
    
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "[$($results.TotalScripts)] Running: $ScriptName" -ForegroundColor Cyan
    Write-Host "    $Description" -ForegroundColor Gray
    Write-Host "================================================================" -ForegroundColor Cyan
    
    $scriptPath = Join-Path $scriptDir $ScriptName
    
    if (-not (Test-Path $scriptPath)) {
        Write-Warning "Script not found: $scriptPath"
        $results.Failed++
        $results.Scripts += [PSCustomObject]@{
            Script = $ScriptName
            Status = "Failed"
            Duration = "N/A"
            Message = "Script file not found"
        }
        return
    }
    
    $scriptStart = Get-Date
    
    try {
        $params = @{
            OutputFolder = $assessmentFolder
            ErrorAction = 'Continue'
        }
        
        # Add custom parameters
        foreach ($param in $Parameters) {
            $params[$param] = $true
        }
        
        & $scriptPath @params
        
        $scriptEnd = Get-Date
        $duration = ($scriptEnd - $scriptStart).TotalSeconds
        
        Write-Host "`n[OK] Completed in $([math]::Round($duration, 1)) seconds" -ForegroundColor Green
        $results.Completed++
        $results.Scripts += [PSCustomObject]@{
            Script = $ScriptName
            Status = "Success"
            Duration = "$([math]::Round($duration, 1))s"
            Message = "Completed successfully"
        }
    }
    catch {
        $scriptEnd = Get-Date
        $duration = ($scriptEnd - $scriptStart).TotalSeconds
        
        Write-Host "`n[FAIL] Error in $ScriptName : $_" -ForegroundColor Red
        $results.Failed++
        $results.Scripts += [PSCustomObject]@{
            Script = $ScriptName
            Status = "Failed"
            Duration = "$([math]::Round($duration, 1))s"
            Message = $_.Exception.Message
        }
    }
}

# ===== RUN ASSESSMENTS =====

Write-Host "`n[*] Starting assessment sequence..." -ForegroundColor Yellow

# 1. Expired Password Accounts Analysis
Invoke-AssessmentScript `
    -ScriptName "Get-ExpiredPasswordAccounts.ps1" `
    -Description "Analyzing accounts with expired passwords and last logon times"

# 2. Password Never Expire Analysis
Invoke-AssessmentScript `
    -ScriptName "Get-PasswordNeverExpireAccounts.ps1" `
    -Description "Identifying accounts with password never expires and privilege levels" `
    -Parameters @("CheckServiceAccounts")

# 3. Privileged Group Members Analysis
$skipMFA = $SkipEntraMFA
Invoke-AssessmentScript `
    -ScriptName "Get-PrivilegedGroupMembers.ps1" `
    -Description "Enumerating Domain Admins, Enterprise Admins, and other privileged groups" `
    -Parameters $(if (-not $skipMFA) { @("IncludeNested", "CheckEntraMFA") } else { @("IncludeNested") }) `
    -Skip $false

# 4. AD to Entra User Comparison
Invoke-AssessmentScript `
    -ScriptName "Compare-ADtoEntraUsers.ps1" `
    -Description "Comparing AD users to Entra ID to identify cloud-only and orphaned accounts" `
    -Parameters @("CompareAttributes", "IncludeLicensing") `
    -Skip $SkipEntraComparison

# 5. AD Schema Permissions Audit
Invoke-AssessmentScript `
    -ScriptName "Get-ADSchemaPermissions.ps1" `
    -Description "Auditing Active Directory schema object permissions" `
    -Skip $SkipSchemaAudit

# 6. Elevated Group Usage Analysis
Invoke-AssessmentScript `
    -ScriptName "Get-ElevatedGroupUsage.ps1" `
    -Description "Analyzing elevated permission groups and their usage patterns" `
    -Parameters $(if ($IncludeNestedMembers) { @("IncludeNestedMembers") } else { @() }) `
    -Skip $false

# ===== GENERATE SUMMARY =====

$endTime = Get-Date
$totalDuration = ($endTime - $startTime).TotalMinutes

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  ASSESSMENT COMPLETE - SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

Write-Host "`nExecution Summary:" -ForegroundColor Yellow
Write-Host "  Total Scripts: $($results.TotalScripts)" -ForegroundColor White
Write-Host "  Completed: $($results.Completed)" -ForegroundColor Green
Write-Host "  Failed: $($results.Failed)" -ForegroundColor $(if ($results.Failed -gt 0) { "Red" } else { "Green" })
Write-Host "  Skipped: $($results.Skipped)" -ForegroundColor Yellow
Write-Host "`nTotal Duration: $([math]::Round($totalDuration, 2)) minutes" -ForegroundColor White
Write-Host "Output Location: $assessmentFolder" -ForegroundColor Cyan

# Display detailed results
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  DETAILED RESULTS" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$results.Scripts | Format-Table -AutoSize

# Generate master summary report
$summaryPath = Join-Path $assessmentFolder "ASSESSMENT-SUMMARY.txt"
$summaryContent = @"
================================================================
ENHANCED AD SECURITY ASSESSMENT - EXECUTION SUMMARY
================================================================

Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Output Folder: $assessmentFolder
Total Duration: $([math]::Round($totalDuration, 2)) minutes

================================================================
EXECUTION STATISTICS
================================================================

Total Scripts Run: $($results.TotalScripts)
Successfully Completed: $($results.Completed)
Failed: $($results.Failed)
Skipped: $($results.Skipped)

================================================================
SCRIPT RESULTS
================================================================

$($results.Scripts | ForEach-Object {
    "[$($_.Status)] $($_.Script) - Duration: $($_.Duration)"
    "    Message: $($_.Message)"
    ""
})

================================================================
OUTPUT FILES GENERATED
================================================================

The following types of reports have been generated:

1. Expired Password Accounts
   - ExpiredPasswordAccounts-*.csv
   - PasswordsExpiringSoon-*.csv
   - AllAccountsPasswordAnalysis-*.csv
   - ExpiredPasswordReport-*.html

2. Password Never Expire Accounts
   - PasswordNeverExpire-All-*.csv
   - PasswordNeverExpire-Privileged-*.csv
   - PasswordNeverExpire-HighRisk-*.csv
   - PasswordNeverExpire-*.html

3. Privileged Group Members
   - PrivilegedGroupMembers-Detailed-*.csv
   - PrivilegedGroupMembers-Summary-*.csv
   - PrivilegedGroupMembers-Findings-*.csv
   - PrivilegedGroupMembers-*.html

$(if (-not $SkipEntraComparison) {
    "4. AD to Entra Comparison
   - EntraOnly-Users-*.csv
   - CloudOnly-Users-*.csv
   - Orphaned-Users-*.csv
   - ADOnly-Users-*.csv
   - Synced-Users-*.csv
   - AttributeMismatches-*.csv
   - ADEntraComparison-*.html"
})

$(if (-not $SkipSchemaAudit) {
    "5. AD Schema Permissions
   - ADSchemaPermissions-*.csv
   - ADSchemaPermissions-Detailed-*.csv
   - ADSchemaPermissions-*.html"
})

6. Elevated Group Usage Analysis
   - ElevatedGroupUsage-AllGroups-*.csv
   - ElevatedGroupUsage-Top10LeastUsed-*.csv
   - ElevatedGroupUsage-Top10MostUsed-*.csv
   - ElevatedGroupUsage-EmptyGroups-*.csv
   - ElevatedGroupUsage-CriticalRisk-*.csv
   - ElevatedGroupUsage-Report-*.html

================================================================
NEXT STEPS
================================================================

1. Review HTML reports for visual overview of findings
2. Prioritize Critical and High severity findings
3. Export CSV files for detailed analysis
4. Share reports with appropriate stakeholders
5. Plan remediation activities based on findings

================================================================
CRITICAL FINDINGS TO REVIEW IMMEDIATELY
================================================================

• Privileged accounts with expired passwords
• Privileged accounts with password never expires
• Privileged accounts without MFA (if checked)
• Disabled accounts in privileged groups
• Orphaned Entra ID accounts (if checked)
• Unauthorized schema permissions (if checked)
• Elevated groups with 90+ days of inactivity
• Empty elevated groups requiring cleanup

================================================================
RECOMMENDATIONS
================================================================

• Review all Critical and High risk findings within 24 hours
• Implement MFA for all privileged accounts
• Remove 'Password Never Expires' from privileged accounts
• Disable stale accounts (90+ days no logon)
• Review and clean up unused elevated groups (90+ days inactive)
• Remove empty groups to reduce attack surface
• Schedule regular assessments (monthly recommended)

================================================================
"@

$summaryContent | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "`n[OK] Master summary report saved: $summaryPath" -ForegroundColor Green

# Open output folder
Write-Host "`n[*] Opening output folder..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
explorer $assessmentFolder

Write-Host "`n================================================================" -ForegroundColor Green
Write-Host "  ASSESSMENT COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "`nReview the reports in: $assessmentFolder" -ForegroundColor Cyan
Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")




