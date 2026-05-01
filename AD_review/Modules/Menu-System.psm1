# Menu-System.psm1
# Interactive menu system for AD Security Assessment Tool
# Version: 1.0
# Date: May 1, 2026

Set-StrictMode -Version 2.0

# ================================
# MAIN MENU FUNCTIONS
# ================================

function Show-MainMenu {
    <#
    .SYNOPSIS
        Displays the main menu with assessment options
    
    .DESCRIPTION
        Interactive menu allowing users to select what assessment to run
    
    .EXAMPLE
        Show-MainMenu
    #>
    
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "║         AD & Entra ID Security Assessment Tool            ║" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Full Security Assessment" -ForegroundColor Cyan
    Write-Host "      Run complete AD + Entra ID assessment with all reports" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] Quick Risk Check" -ForegroundColor Cyan
    Write-Host "      Fast risk scoring only (5 minutes)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [3] Select Specific Reports" -ForegroundColor Cyan
    Write-Host "      Choose which reports to generate" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [4] Emergency Response" -ForegroundColor Red
    Write-Host "      Incident response: disable users, revoke sessions, manage email" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [5] View Previous Reports" -ForegroundColor Cyan
    Write-Host "      List recently generated reports" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [6] Settings & Configuration" -ForegroundColor Cyan
    Write-Host "      Manage tool settings and credentials" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Enter your selection: " -NoNewline -ForegroundColor Yellow
}

function Show-EmergencyMenu {
    <#
    .SYNOPSIS
        Displays the emergency response menu
    
    .DESCRIPTION
        Quick access to incident response functions
    
    .EXAMPLE
        Show-EmergencyMenu
    #>
    
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                   EMERGENCY RESPONSE                       ║" -ForegroundColor Red
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "Incident Response Options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Disable User & Revoke All Sessions" -ForegroundColor Red
    Write-Host "      Immediately disable account, move to quarantine OU" -ForegroundColor Gray
    Write-Host "      and revoke all active sessions" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] Revoke Sessions Only (Keep Account Enabled)" -ForegroundColor Yellow
    Write-Host "      Revoke all active sessions without disabling account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [3] Remove Emails from Mailbox" -ForegroundColor Yellow
    Write-Host "      Remove emails from user's mailbox (soft or hard delete)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [4] Suspend Mailbox" -ForegroundColor Yellow
    Write-Host "      Immediately suspend mailbox access" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [5] Check Agent Status in CrowdStrike" -ForegroundColor Cyan
    Write-Host "      Query CrowdStrike Falcon for agent status & detections" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [6] Generate Incident Report" -ForegroundColor Cyan
    Write-Host "      Create detailed incident response report" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [B] Back to Main Menu" -ForegroundColor Gray
    Write-Host ""
    Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Enter your selection: " -NoNewline -ForegroundColor Yellow
}

# ================================
# REPORT SELECTION
# ================================

function Show-ReportSelector {
    <#
    .SYNOPSIS
        Interactive report selection menu
    
    .DESCRIPTION
        Allows users to select which reports to generate
    
    .OUTPUTS
        PSCustomObject[] - Array of selected reports
    
    .EXAMPLE
        $selected = Show-ReportSelector
    #>
    
    $reports = @(
        @{ 
            Name = "Identity Hygiene Report"
            Description = "Stale accounts, password issues, disabled accounts"
            Selected = $true
            Key = "identity"
        },
        @{ 
            Name = "Privileged Access Report"
            Description = "Admin membership, delegations, tier-0 accounts"
            Selected = $false
            Key = "privileged"
        },
        @{ 
            Name = "Zero Trust Readiness Report"
            Description = "Conditional Access, MFA, legacy auth, device compliance"
            Selected = $true
            Key = "zerotrust"
        },
        @{ 
            Name = "MITRE ATT&CK Mapping"
            Description = "Security findings mapped to MITRE techniques & tactics"
            Selected = $false
            Key = "mitre"
        },
        @{ 
            Name = "Executive Brief"
            Description = "Summary report for leadership (print-friendly HTML)"
            Selected = $true
            Key = "executive"
        },
        @{ 
            Name = "Network Graph Visualization"
            Description = "Visual representation of user, group, and computer relationships"
            Selected = $false
            Key = "network"
        },
        @{ 
            Name = "Privileged Access Map"
            Description = "Visual diagram of admin access paths and trust relationships"
            Selected = $false
            Key = "accessmap"
        },
        @{ 
            Name = "Trend Analysis"
            Description = "Historical comparison with previous assessments"
            Selected = $false
            Key = "trends"
        },
        @{ 
            Name = "Device Posture Report"
            Description = "Computer compliance, Intune status, OS versions"
            Selected = $false
            Key = "devices"
        },
        @{ 
            Name = "Conditional Access Analysis"
            Description = "Detailed CA policy review and coverage analysis"
            Selected = $false
            Key = "conditionalaccess"
        }
    )
    
    $currentIndex = 0
    
    do {
        Clear-Host
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║                   SELECT REPORTS TO RUN                    ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        
        # Display report options
        for ($i = 0; $i -lt $reports.Count; $i++) {
            $report = $reports[$i]
            $checkbox = if ($report.Selected) { "[X]" } else { "[ ]" }
            $highlight = if ($i -eq $currentIndex) { " --> " } else { "     " }
            $color = if ($i -eq $currentIndex) { "Yellow" } else { "Cyan" }
            
            Write-Host "$highlight$($i+1). $checkbox $($report.Name)" -ForegroundColor $color
            Write-Host "        $($report.Description)" -ForegroundColor Gray
            Write-Host ""
        }
        
        # Display instructions
        Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        
        $selectedCount = ($reports | Where-Object { $_.Selected }).Count
        Write-Host "Selected: $selectedCount report(s)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Commands:" -ForegroundColor Yellow
        Write-Host "  [Up/Down]     - Navigate options" -ForegroundColor Gray
        Write-Host "  [Space]       - Toggle selection" -ForegroundColor Gray
        Write-Host "  [All]         - Select all reports" -ForegroundColor Gray
        Write-Host "  [None]        - Deselect all reports" -ForegroundColor Gray
        Write-Host "  [Enter]       - Proceed with selected reports" -ForegroundColor Gray
        Write-Host "  [Q]           - Cancel and return to main menu" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Selection: " -NoNewline -ForegroundColor Yellow
        
        $key = [System.Console]::ReadKey($true)
        
        switch ($key.Key) {
            "UpArrow" {
                $currentIndex = if ($currentIndex -gt 0) { $currentIndex - 1 } else { $reports.Count - 1 }
            }
            "DownArrow" {
                $currentIndex = if ($currentIndex -lt $reports.Count - 1) { $currentIndex + 1 } else { 0 }
            }
            "Spacebar" {
                $reports[$currentIndex].Selected = -not $reports[$currentIndex].Selected
            }
            "A" {
                $reports | ForEach-Object { $_.Selected = $true }
            }
            "N" {
                $reports | ForEach-Object { $_.Selected = $false }
            }
            "Enter" {
                $selected = $reports | Where-Object { $_.Selected }
                if ($selected.Count -eq 0) {
                    Write-Host ""
                    Write-Host "ERROR: Please select at least one report" -ForegroundColor Red
                    Write-Host ""
                    Start-Sleep -Seconds 2
                } else {
                    return $selected
                }
            }
            "Q" {
                Write-Host ""
                Write-Host "Cancelled" -ForegroundColor Gray
                return $null
            }
        }
    } while ($true)
}

# ================================
# SETTINGS MENU
# ================================

function Show-SettingsMenu {
    <#
    .SYNOPSIS
        Displays settings and configuration menu
    
    .DESCRIPTION
        Allows users to configure tool settings
    
    .EXAMPLE
        Show-SettingsMenu
    #>
    
    do {
        Clear-Host
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║              SETTINGS & CONFIGURATION                     ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Configuration Options:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] View Current Configuration" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [2] Configure Output Directory" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [3] Test Certificate Authentication" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [4] View API Connection Status" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [5] Configure CrowdStrike Credentials" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [6] Configure Mimecast Credentials" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [B] Back to Main Menu" -ForegroundColor Gray
        Write-Host ""
        Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "Enter your selection: " -NoNewline -ForegroundColor Yellow
        
        $choice = Read-Host
        
        switch ($choice) {
            "1" {
                Write-Host ""
                Write-Host "Current Configuration:" -ForegroundColor Yellow
                Write-Host "  Output Directory: $PSScriptRoot\Reports" -ForegroundColor Gray
                Write-Host "  Logs Directory: $PSScriptRoot\Logs" -ForegroundColor Gray
                Write-Host "  Include Entra ID: Yes" -ForegroundColor Gray
                Write-Host "  Generate Diagrams: No" -ForegroundColor Gray
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "2" {
                Write-Host ""
                Write-Host "Output directory configuration not yet implemented" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "3" {
                Write-Host ""
                Write-Host "Testing certificate authentication..." -ForegroundColor Yellow
                Write-Host "Feature not yet implemented" -ForegroundColor Gray
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "4" {
                Write-Host ""
                Write-Host "API Connection Status:" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "B" {
                return
            }
            default {
                Write-Host ""
                Write-Host "Invalid selection" -ForegroundColor Red
                Write-Host ""
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

# ================================
# HELPER FUNCTIONS
# ================================

function Show-PreviousReports {
    <#
    .SYNOPSIS
        Display list of previously generated reports
    
    .DESCRIPTION
        Lists all reports in the Reports directory with timestamps
    
    .EXAMPLE
        Show-PreviousReports
    #>
    
    $reportsPath = "$PSScriptRoot\Reports"
    
    if (-not (Test-Path $reportsPath)) {
        Write-Host ""
        Write-Host "No reports found. Run an assessment to generate reports." -ForegroundColor Yellow
        Write-Host ""
        Start-Sleep -Seconds 2
        return
    }
    
    Clear-Host
    Write-Host ""
    Write-Host "═════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Previous Reports" -ForegroundColor Cyan
    Write-Host "═════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $reports = Get-ChildItem -Path $reportsPath -Filter "*.html", "*.xlsx" | 
                Sort-Object -Property LastWriteTime -Descending | 
                Select-Object -First 20
    
    if ($reports.Count -eq 0) {
        Write-Host "No reports found" -ForegroundColor Yellow
    } else {
        $reports | Format-Table -Property @(
            @{ Name = "Name"; Expression = { $_.Name }; Width = 40 }
            @{ Name = "Type"; Expression = { $_.Extension }; Width = 10 }
            @{ Name = "Size"; Expression = { "{0:N0} KB" -f ($_.Length / 1KB) }; Width = 12 }
            @{ Name = "Created"; Expression = { $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm") }; Width = 20 }
        ) -AutoSize
    }
    
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Get-MenuChoice {
    <#
    .SYNOPSIS
        Get and validate user menu choice
    
    .PARAMETER ValidChoices
        Array of valid choices
    
    .OUTPUTS
        String - The user's choice
    
    .EXAMPLE
        $choice = Get-MenuChoice -ValidChoices @("1", "2", "3", "Q")
    #>
    
    param(
        [string[]]$ValidChoices = @("1", "2", "3", "4", "5", "6", "Q")
    )
    
    $choice = Read-Host
    
    if ($choice -notin $ValidChoices) {
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        return $null
    }
    
    return $choice.ToUpper()
}

# ================================
# CONFIRMATION DIALOGS
# ================================

function Confirm-Action {
    <#
    .SYNOPSIS
        Display confirmation dialog for dangerous operations
    
    .PARAMETER Title
        Title of the confirmation dialog
    
    .PARAMETER Message
        Message to display
    
    .PARAMETER ConfirmationWord
        Word user must type to confirm (default: "YES")
    
    .OUTPUTS
        Boolean - True if confirmed, False otherwise
    
    .EXAMPLE
        if (Confirm-Action -Title "Disable User" -Message "Disable john.smith@company.com?") {
            # Perform action
        }
    #>
    
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$ConfirmationWord = "YES"
    )
    
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                     $Title" -ForegroundColor Red
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    Write-Host ""
    Write-Host "WARNING: This action cannot be easily undone!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Type '$ConfirmationWord' to proceed or press Enter to cancel:" -NoNewline -ForegroundColor Yellow
    $input = Read-Host
    
    if ($input -eq $ConfirmationWord) {
        return $true
    } else {
        Write-Host ""
        Write-Host "Action cancelled." -ForegroundColor Gray
        Start-Sleep -Seconds 1
        return $false
    }
}

# ================================
# DISPLAY FUNCTIONS
# ================================

function Show-ProgressMessage {
    <#
    .SYNOPSIS
        Display a progress message
    
    .PARAMETER Message
        The message to display
    
    .PARAMETER Type
        Type of message: Info, Success, Warning, Error
    
    .EXAMPLE
        Show-ProgressMessage -Message "Starting assessment..." -Type Info
    #>
    
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")][string]$Type = "Info"
    )
    
    $colors = @{
        "Info" = "Cyan"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error" = "Red"
    }
    
    $prefix = @{
        "Info" = "[*]"
        "Success" = "[+]"
        "Warning" = "[!]"
        "Error" = "[X]"
    }
    
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
}

# ================================
# EXPORT PUBLIC FUNCTIONS
# ================================

Export-ModuleMember -Function @(
    'Show-MainMenu',
    'Show-EmergencyMenu',
    'Show-ReportSelector',
    'Show-SettingsMenu',
    'Show-PreviousReports',
    'Get-MenuChoice',
    'Confirm-Action',
    'Show-ProgressMessage'
)
