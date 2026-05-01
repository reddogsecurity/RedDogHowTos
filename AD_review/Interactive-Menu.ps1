# Interactive-Menu.ps1
# Provides Invoke-InteractiveMode and Invoke-EmergencyResponseMenu.
#
# Usage (standalone):
#   .\Interactive-Menu.ps1
#
# Usage (dot-sourced by script.ps1):
#   . "$PSScriptRoot\Interactive-Menu.ps1"
#   if ($PSBoundParameters.Count -eq 0) { Invoke-InteractiveMode }

[CmdletBinding()]
param(
    [string]$OutputFolder = "$env:TEMP\ADScan"
)

# ============================================================
# MODULE BOOTSTRAP
# ============================================================

$_menuModulePath = Join-Path $PSScriptRoot "Modules\Menu-System.psm1"

if (-not (Test-Path $_menuModulePath)) {
    Write-Error "Required module not found: $_menuModulePath"
    exit 1
}

Import-Module $_menuModulePath -Force -ErrorAction Stop

# ============================================================
# INTERNAL HELPERS
# ============================================================

function _Invoke-Assessment {
    <#
    Runs script.ps1 with the supplied parameters. Centralises the call so all
    menu branches go through one place.
    #>
    param(
        [string]$OutputFolder,
        [switch]$IncludeEntra,
        [switch]$IncludeThreatHunting,
        [switch]$IncludeMimecast,
        [switch]$GenerateDiagrams,
        [string]$CompareWith = ""
    )

    $scriptPath = Join-Path $PSScriptRoot "script.ps1"

    if (-not (Test-Path $scriptPath)) {
        Write-Host ""
        Show-ProgressMessage -Message "script.ps1 not found at: $scriptPath" -Type Error
        Write-Host ""
        Read-Host "Press Enter to continue"
        return
    }

    $params = @{
        OutputFolder = $OutputFolder
    }
    if ($IncludeEntra)         { $params['IncludeEntra']         = $true }
    if ($IncludeThreatHunting) { $params['IncludeThreatHunting'] = $true }
    if ($IncludeMimecast)      { $params['IncludeMimecast']      = $true }
    if ($GenerateDiagrams)     { $params['GenerateDiagrams']     = $true }
    if ($CompareWith)          { $params['CompareWith']          = $CompareWith }

    try {
        & $scriptPath @params
    } catch {
        Write-Host ""
        Show-ProgressMessage -Message "Assessment failed: $_" -Type Error
    }

    Write-Host ""
    Read-Host "Press Enter to return to menu"
}

function _Show-NotImplemented {
    param([string]$Feature)
    Write-Host ""
    Show-ProgressMessage -Message "$Feature is not yet implemented (Phase 2)." -Type Warning
    Write-Host ""
    Read-Host "Press Enter to continue"
}

# ============================================================
# EMERGENCY RESPONSE SUB-MENU
# ============================================================

function Invoke-EmergencyResponseMenu {
    <#
    .SYNOPSIS
        Drives the emergency response sub-menu loop.

    .DESCRIPTION
        Displays Show-EmergencyMenu and handles each option until the user
        returns to the main menu. Actual response actions require
        Emergency-Response.psm1 (Phase 1.4).

    .EXAMPLE
        Invoke-EmergencyResponseMenu
    #>
    [CmdletBinding()]
    param()

    $emergencyRunning = $true

    while ($emergencyRunning) {
        Show-EmergencyMenu
        $choice = (Read-Host).ToUpper().Trim()

        switch ($choice) {

            "1" {
                # Disable User & Revoke All Sessions
                $userName = Read-Host "`n  Target username (SAM or UPN)"
                if ([string]::IsNullOrWhiteSpace($userName)) {
                    Show-ProgressMessage -Message "No username provided. Action cancelled." -Type Warning
                    Start-Sleep -Seconds 2
                    break
                }

                $confirmed = Confirm-Action `
                    -Title "DISABLE USER & REVOKE SESSIONS" `
                    -Message "  User   : $userName`n  Action : Disable account + revoke all AD/Entra sessions + move to CyberIncident OU" `
                    -ConfirmationWord "DISABLE"

                if ($confirmed) {
                    Show-ProgressMessage -Message "Loading Emergency-Response module..." -Type Info

                    $erModule = Join-Path $PSScriptRoot "Modules\Emergency-Response.psm1"
                    if (Test-Path $erModule) {
                        Import-Module $erModule -Force -ErrorAction Stop
                        Invoke-UserEmergencyDisable -UserSAMAccountName $userName -RevokeAllSessions
                    } else {
                        Show-ProgressMessage -Message "Emergency-Response.psm1 not found. Action not executed." -Type Error
                        Write-Host "  Expected: $erModule" -ForegroundColor DarkGray
                    }

                    Write-Host ""
                    Read-Host "Press Enter to continue"
                }
            }

            "2" {
                # Revoke Sessions Only
                $userName = Read-Host "`n  Target username (SAM or UPN)"
                if ([string]::IsNullOrWhiteSpace($userName)) {
                    Show-ProgressMessage -Message "No username provided. Action cancelled." -Type Warning
                    Start-Sleep -Seconds 2
                    break
                }

                $confirmed = Confirm-Action `
                    -Title "REVOKE SESSIONS" `
                    -Message "  User   : $userName`n  Action : Revoke all active AD + Entra sessions (account stays enabled)" `
                    -ConfirmationWord "REVOKE"

                if ($confirmed) {
                    $erModule = Join-Path $PSScriptRoot "Modules\Emergency-Response.psm1"
                    if (Test-Path $erModule) {
                        Import-Module $erModule -Force -ErrorAction Stop
                        Invoke-SessionRevocation -UserSAMAccountName $userName -Type Both
                    } else {
                        Show-ProgressMessage -Message "Emergency-Response.psm1 not found. Action not executed." -Type Error
                    }

                    Write-Host ""
                    Read-Host "Press Enter to continue"
                }
            }

            "3" { _Show-NotImplemented -Feature "Email removal (Mimecast/Exchange)" }

            "4" { _Show-NotImplemented -Feature "Mailbox suspension" }

            "5" { _Show-NotImplemented -Feature "CrowdStrike agent status check" }

            "6" { _Show-NotImplemented -Feature "Incident report generation" }

            "B" { $emergencyRunning = $false }

            default {
                Show-ProgressMessage -Message "Invalid selection '$choice'. Choose 1-6 or B." -Type Warning
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ============================================================
# MAIN INTERACTIVE LOOP
# ============================================================

function Invoke-InteractiveMode {
    <#
    .SYNOPSIS
        Launches the interactive menu and drives all user interactions.

    .DESCRIPTION
        Presents the main menu (via Menu-System.psm1) and dispatches each
        choice to the appropriate assessment run or sub-menu. Runs in a
        loop until the user selects Q (Quit).

        Assessment options build parameters and delegate to script.ps1 so
        all collection and reporting logic stays in one place.

    .PARAMETER OutputFolder
        Where to write reports. Defaults to $env:TEMP\ADScan.

    .EXAMPLE
        Invoke-InteractiveMode

    .EXAMPLE
        Invoke-InteractiveMode -OutputFolder "C:\Assessments\Client1"
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = "$env:TEMP\ADScan"
    )

    $mainRunning = $true

    while ($mainRunning) {

        Show-MainMenu
        $choice = (Read-Host).ToUpper().Trim()

        switch ($choice) {

            # ── Option 1: Full Security Assessment ──────────────────────
            "1" {
                Write-Host ""
                Show-ProgressMessage -Message "Preparing Full Security Assessment (AD + Entra ID + Diagrams)..." -Type Info
                Write-Host ""

                _Invoke-Assessment `
                    -OutputFolder  $OutputFolder `
                    -IncludeEntra `
                    -GenerateDiagrams
            }

            # ── Option 2: Quick Risk Check ───────────────────────────────
            "2" {
                Write-Host ""
                Show-ProgressMessage -Message "Preparing Quick Risk Check (AD only, no diagrams)..." -Type Info
                Write-Host ""

                _Invoke-Assessment -OutputFolder $OutputFolder
            }

            # ── Option 3: Select Specific Reports ───────────────────────
            "3" {
                $selectedReports = Show-ReportSelector

                if ($null -eq $selectedReports) {
                    # User pressed Q — return to main menu silently
                    break
                }

                Write-Host ""
                Show-ProgressMessage -Message "Building parameters for selected reports..." -Type Info

                # Map report keys → script.ps1 switches
                $keys           = $selectedReports | Select-Object -ExpandProperty Key
                $needEntra      = $keys | Where-Object { $_ -in @('zerotrust','devices','conditionalaccess') }
                $needDiagrams   = $keys | Where-Object { $_ -in @('network','accessmap') }
                $needTrends     = $keys | Where-Object { $_ -eq 'trends' }

                $compareFolder  = ""
                if ($needTrends) {
                    Write-Host ""
                    Write-Host "  Trend Analysis requires a previous assessment to compare against." -ForegroundColor Yellow
                    $compareFolder = Read-Host "  Enter path to previous assessment folder (or press Enter to skip)"
                }

                _Invoke-Assessment `
                    -OutputFolder  $OutputFolder `
                    -IncludeEntra:($needEntra.Count  -gt 0) `
                    -GenerateDiagrams:($needDiagrams.Count -gt 0) `
                    -CompareWith   $compareFolder
            }

            # ── Option 4: Emergency Response ─────────────────────────────
            "4" {
                Invoke-EmergencyResponseMenu
            }

            # ── Option 5: View Previous Reports ──────────────────────────
            "5" {
                Show-PreviousReports
            }

            # ── Option 6: Settings & Configuration ───────────────────────
            "6" {
                Show-SettingsMenu
            }

            # ── Q: Quit ───────────────────────────────────────────────────
            "Q" {
                Write-Host ""
                Write-Host "Exiting AD Security Assessment Tool." -ForegroundColor Gray
                Write-Host ""
                $mainRunning = $false
            }

            default {
                Write-Host ""
                Show-ProgressMessage -Message "Invalid selection '$choice'. Choose 1-6 or Q." -Type Warning
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ============================================================
# STANDALONE ENTRY POINT
# ============================================================
# When run directly (not dot-sourced into script.ps1), launch the menu.

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-InteractiveMode -OutputFolder $OutputFolder
}
