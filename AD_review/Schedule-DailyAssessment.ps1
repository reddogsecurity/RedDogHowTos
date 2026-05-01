<#
.SYNOPSIS
  One-time setup script to register the AD Security Daily Assessment scheduled task.
  Run as Administrator. Requires PowerShell 5.1+.

.PARAMETER OutputFolder
  Root output folder for daily runs. Default: C:\ADAssessments\Daily

.PARAMETER RunTime
  Daily run time. Default: 06:00.

.PARAMETER RunAsAccount
  Account to run the task under. Use 'SYSTEM' or a dedicated service account (domain\svcADScan).
  Default: SYSTEM

.PARAMETER IncludeEntra
  Add -IncludeEntra flag to the scheduled task command.

.PARAMETER IncludeThreatHunting
  Add -IncludeThreatHunting flag to the scheduled task command.

.EXAMPLE
  .\Schedule-DailyAssessment.ps1 -IncludeEntra -IncludeThreatHunting

.EXAMPLE
  .\Schedule-DailyAssessment.ps1 -RunAsAccount "CORP\svc-adscan" -RunTime "07:00"
#>

[CmdletBinding()]
param(
    [string]$OutputFolder       = 'C:\ADAssessments\Daily',
    [string]$RunTime            = '06:00',
    [string]$RunAsAccount       = 'SYSTEM',
    [switch]$IncludeEntra,
    [switch]$IncludeThreatHunting
)

$taskName    = 'AD Security Daily Assessment'
$taskDesc    = 'Runs daily AD/Entra security assessment with threat hunting and alerting. Managed by RedDog Security.'
$scriptPath  = Join-Path $PSScriptRoot "Invoke-DailyAlert.ps1"

# --- Validation ---
if (-not (Test-Path $scriptPath)) {
    Write-Error "Invoke-DailyAlert.ps1 not found at: $scriptPath"
    exit 1
}

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# --- Build command arguments ---
$extraArgs = "-OutputFolder `"$OutputFolder`""
if ($IncludeEntra)         { $extraArgs += " -IncludeEntra" }
if ($IncludeThreatHunting) { $extraArgs += " -IncludeThreatHunting" }

$psExe   = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$psArgs  = "-NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`" $extraArgs"

Write-Host "`nScheduled Task Configuration:" -ForegroundColor Cyan
Write-Host "  Name:      $taskName"       -ForegroundColor Gray
Write-Host "  Script:    $scriptPath"     -ForegroundColor Gray
Write-Host "  Arguments: $psArgs"         -ForegroundColor Gray
Write-Host "  Run as:    $RunAsAccount"   -ForegroundColor Gray
Write-Host "  Run time:  Daily at $RunTime" -ForegroundColor Gray

# --- Create scheduled task components ---
$action  = New-ScheduledTaskAction -Execute $psExe -Argument $psArgs
$trigger = New-ScheduledTaskTrigger -Daily -At $RunTime

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable:$false `
    -Priority 6

$principal = if ($RunAsAccount -eq 'SYSTEM') {
    New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest -LogonType ServiceAccount
} else {
    New-ScheduledTaskPrincipal -UserId $RunAsAccount -RunLevel Highest -LogonType Password
}

# --- Register (or update) the task ---
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "`nTask '$taskName' already exists. Updating..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $taskDesc

Register-ScheduledTask -TaskName $taskName -InputObject $task -ErrorAction Stop | Out-Null

Write-Host "`n[OK] Scheduled task registered successfully!" -ForegroundColor Green

# --- Verification ---
$registered = Get-ScheduledTask -TaskName $taskName
Write-Host "`nTask Status: $($registered.State)" -ForegroundColor Cyan
Write-Host "Next Run:    $((Get-ScheduledTaskInfo -TaskName $taskName).NextRunTime)" -ForegroundColor Cyan

Write-Host @"

Next Steps:
  1. Edit config\alert-config.json to enable email/Teams/Slack notifications
  2. Edit config\alert-thresholds.json to tune detection thresholds
  3. For Entra integration: ensure Graph permissions are granted
     (Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All)
  4. Test manually: .\Invoke-DailyAlert.ps1 -IncludeEntra -IncludeThreatHunting
  5. Check Windows Event Viewer > Task Scheduler for run history

To remove this task:
  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false
"@ -ForegroundColor White
