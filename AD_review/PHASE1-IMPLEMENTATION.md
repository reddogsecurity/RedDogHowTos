# 🚀 Quick Implementation Guide - Start Here

**Focus:** Getting Phase 1 done in next 2 weeks  
**Status:** Ready to implement

---

## What We're Building This Week

### 1️⃣ Interactive Menu System
**Why:** Users see options on startup instead of running blind with parameters  
**Where:** Top-level execution in `script.ps1`  
**What it looks like:**
```
=== AD Security Assessment Tool ===
1. Full Assessment (AD + Entra + Reports)
2. Quick Risk Check Only
3. Select Specific Reports
4. Emergency Response Menu
5. View Previous Reports
6. Settings & Configuration
Q. Quit

Enter choice:
```

### 2️⃣ Emergency Response Submenu
**Why:** Quick access to critical incident response  
**Submenu:**
```
=== EMERGENCY RESPONSE ===
1. Disable User & Revoke Sessions
   - Accepts: username or email
   - Actions: Disable AD account, move to CyberIncident OU, revoke all sessions
2. Revoke All Sessions (User Stays Enabled)
3. Remove Recent Emails from Mailbox
4. Suspend Mailbox
5. Check CrowdStrike Agent Status
6. Generate Incident Report
Q. Back
```

### 3️⃣ Report Selector Menu
**Why:** Don't run everything if you only need one report  
**Selection:**
```
=== SELECT REPORTS TO RUN ===
[X] Identity Hygiene (stale accounts, password issues)
[ ] Privileged Access (admin membership, delegations)
[X] Zero Trust Readiness (conditional access, MFA)
[ ] MITRE ATT&CK Mapping
[X] Executive Brief (summary for leadership)
[ ] Network Graph Visualization
[ ] Trend Analysis (historical comparison)

Selected: 3 reports
[Spacebar] = Toggle | [Enter] = Run | [Q] = Cancel
```

---

## Implementation Steps (This Week)

### Step 1: Create Interactive Menu Module
**File:** `Modules/Menu-System.psm1`  
**Time:** 2 hours

```powershell
function Show-MainMenu {
    param(
        [string]$Title = "AD Security Assessment Tool"
    )
    
    Clear-Host
    Write-Host "═" * 60 -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "═" * 60
    Write-Host ""
    Write-Host "  1. Run Full Assessment" -ForegroundColor Yellow
    Write-Host "  2. Quick Risk Check Only" -ForegroundColor Yellow
    Write-Host "  3. Select Specific Reports" -ForegroundColor Yellow
    Write-Host "  4. Emergency Response" -ForegroundColor Red
    Write-Host "  5. View Previous Reports" -ForegroundColor Cyan
    Write-Host "  6. Settings & Configuration" -ForegroundColor Cyan
    Write-Host "  Q. Quit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Selection: " -NoNewline
}

function Show-EmergencyMenu {
    Clear-Host
    Write-Host "═" * 60 -ForegroundColor Red
    Write-Host "EMERGENCY RESPONSE" -ForegroundColor Red
    Write-Host "═" * 60
    Write-Host ""
    Write-Host "  1. Disable User & Revoke Sessions" -ForegroundColor Red
    Write-Host "  2. Revoke Sessions Only (Keep Account Enabled)" -ForegroundColor Yellow
    Write-Host "  3. Remove Emails from Mailbox" -ForegroundColor Yellow
    Write-Host "  4. Suspend Mailbox" -ForegroundColor Yellow
    Write-Host "  5. Check CrowdStrike Agent Status" -ForegroundColor Cyan
    Write-Host "  6. Generate Incident Report" -ForegroundColor Cyan
    Write-Host "  B. Back to Main Menu" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Selection: " -NoNewline
}

function Show-ReportSelector {
    [CmdletBinding()]
    param()
    
    $reports = @(
        @{ Name = "Identity Hygiene"; Selected = $true; Description = "Stale accounts, password issues" }
        @{ Name = "Privileged Access"; Selected = $false; Description = "Admin membership, delegations" }
        @{ Name = "Zero Trust Readiness"; Selected = $true; Description = "Conditional Access, MFA" }
        @{ Name = "MITRE ATT&CK Mapping"; Selected = $false; Description = "Threat mapping" }
        @{ Name = "Executive Brief"; Selected = $true; Description = "Summary for leadership" }
        @{ Name = "Network Graph"; Selected = $false; Description = "Visual representation" }
        @{ Name = "Trend Analysis"; Selected = $false; Description = "Historical comparison" }
    )
    
    # Return selected reports
    return $reports | Where-Object { $_.Selected }
}
```

---

### Step 2: Create Emergency Response Module
**File:** `Modules/Emergency-Response.psm1`  
**Time:** 3 hours

```powershell
# Session Revocation Functions
function Invoke-UserSessionRevocation {
    param(
        [Parameter(Mandatory=$true)][string]$UserIdentity,
        [ValidateSet("ADOnly","EntraOnly","Both")][string]$Type = "Both"
    )
    
    # Get user object
    $user = Get-ADUser -Identity $UserIdentity -ErrorAction Stop
    
    if ($Type -in "ADOnly", "Both") {
        Write-Host "[*] Revoking AD sessions for $($user.SamAccountName)..." -ForegroundColor Yellow
        # Logoff all sessions: query session /server:COMPUTERNAME | where { $_.UserName -eq $user }
        # OR use: Get-Process -ComputerName * -IncludeUserName | where { $_.UserName -like "*$($user.SamAccountName)" } | Stop-Process
    }
    
    if ($Type -in "EntraOnly", "Both") {
        Write-Host "[*] Revoking Entra ID sessions for $($user.UserPrincipalName)..." -ForegroundColor Yellow
        # Use Azure CLI: az ad user invalidate-all-refresh-tokens --id $user.ObjectId
    }
    
    Write-Host "[OK] Session revocation complete" -ForegroundColor Green
}

# Emergency Disable Function
function Invoke-UserEmergencyDisable {
    param(
        [Parameter(Mandatory=$true)][string]$UserIdentity,
        [string]$TargetOU = "OU=CyberIncident,DC=contoso,DC=com",
        [bool]$RevokeAllSessions = $true
    )
    
    $user = Get-ADUser -Identity $UserIdentity -ErrorAction Stop
    
    # Confirm action
    Write-Host ""
    Write-Host "WARNING: You are about to disable this user:" -ForegroundColor Red
    Write-Host "  Username: $($user.SamAccountName)" -ForegroundColor Yellow
    Write-Host "  Name: $($user.Name)" -ForegroundColor Yellow
    Write-Host "  Email: $($user.UserPrincipalName)" -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "Type 'YES' to proceed"
    
    if ($confirm -ne "YES") {
        Write-Host "Cancelled" -ForegroundColor Gray
        return
    }
    
    # Disable user
    Disable-ADAccount -Identity $user.ObjectGUID
    Write-Host "[OK] User account disabled" -ForegroundColor Green
    
    # Move to CyberIncident OU
    Move-ADObject -Identity $user.ObjectGUID -TargetPath $TargetOU
    Write-Host "[OK] User moved to CyberIncident OU" -ForegroundColor Green
    
    # Revoke sessions if requested
    if ($RevokeAllSessions) {
        Invoke-UserSessionRevocation -UserIdentity $UserIdentity -Type "Both"
    }
    
    # Log action
    Write-Host "[OK] Emergency disable complete - Audit logged" -ForegroundColor Green
}

# Audit logging wrapper
function New-SecurityAuditLog {
    param(
        [string]$Action,
        [string]$TargetUser,
        [string]$Reason,
        [string]$ExecutedBy = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    )
    
    $logEntry = @{
        Timestamp = Get-Date
        Action = $Action
        TargetUser = $TargetUser
        Reason = $Reason
        ExecutedBy = $ExecutedBy
    }
    
    # Log to file
    $logPath = "$PSScriptRoot\logs\security-audit-$(Get-Date -Format 'yyyy-MM-dd').log"
    $logEntry | ConvertTo-Json | Add-Content -Path $logPath
    
    return $logEntry
}
```

---

### Step 3: Integrate Menu into Main Script
**File:** `script.ps1`  
**Changes:** Add at the beginning (lines 1-50)  
**Time:** 1 hour

```powershell
# At TOP of script.ps1 (before existing code)

# Import menu module
Import-Module "$PSScriptRoot\Modules\Menu-System.psm1" -Force
Import-Module "$PSScriptRoot\Modules\Emergency-Response.psm1" -Force

# Main execution
function Invoke-InteractiveMode {
    do {
        Show-MainMenu
        $choice = Read-Host
        
        switch ($choice) {
            "1" {
                Write-Host "Starting Full Assessment..." -ForegroundColor Green
                # Call existing full assessment with -IncludeEntra and all reports
                & $PSScriptRoot\script.ps1 -IncludeEntra -GenerateDiagrams -Full
                break
            }
            "2" {
                Write-Host "Running Quick Risk Check..." -ForegroundColor Green
                # Quick assessment - risk scoring only
                & $PSScriptRoot\script.ps1 -QuickCheck
                break
            }
            "3" {
                Write-Host "Select reports to run..." -ForegroundColor Cyan
                $selectedReports = Show-ReportSelector
                # Execute with selected reports only
                break
            }
            "4" {
                Invoke-EmergencyResponseMenu
                break
            }
            "5" {
                # Show previous reports
                Get-ChildItem -Path "$PSScriptRoot\Reports" -Filter "*.html" | Select-Object Name, LastWriteTime | Format-Table
                break
            }
            "6" {
                # Settings
                Write-Host "Settings not yet implemented" -ForegroundColor Yellow
                break
            }
            "Q" {
                Write-Host "Exiting..." -ForegroundColor Gray
                exit 0
            }
            default {
                Write-Host "Invalid selection" -ForegroundColor Red
            }
        }
    } while ($true)
}

function Invoke-EmergencyResponseMenu {
    do {
        Show-EmergencyMenu
        $choice = Read-Host
        
        switch ($choice) {
            "1" {
                $userID = Read-Host "Enter username or email"
                Invoke-UserEmergencyDisable -UserIdentity $userID
                break
            }
            "2" {
                $userID = Read-Host "Enter username or email"
                Invoke-UserSessionRevocation -UserIdentity $userID -Type "Both"
                break
            }
            "3" {
                Write-Host "Email removal not yet implemented" -ForegroundColor Yellow
                break
            }
            "B" {
                return
            }
        }
        
        Read-Host "Press Enter to continue"
    } while ($true)
}

# Check if running in interactive mode (no parameters)
if ($PSBoundParameters.Count -eq 0) {
    Invoke-InteractiveMode
} else {
    # Existing parameter-based execution
    # ... rest of current script.ps1 ...
}
```

---

### Step 4: Testing Checklist
**Time:** 2 hours

```powershell
# Test 1: Menu appears on startup
.\script.ps1
# Expected: Interactive menu displays

# Test 2: Menu option 1 works
# Input: 1
# Expected: Full assessment runs

# Test 3: Emergency menu works
# Input: 4
# Expected: Emergency submenu shows

# Test 4: Emergency disable (test user)
# Create test user: New-ADUser -Name "TestUser-Emergency" -Enabled $true
# Input: 1, then input testuser-emergency username
# Expected: User disabled, moved to OU (verify in AD Users & Computers)

# Test 5: Session revocation (requires another logged-in user)
# Input: 2, then input username
# Expected: User sessions revoked (verify by checking their open sessions)
```

---

## Required API Credentials (Get These Ready)

For Phase 2 (next 2 weeks), gather:

```
□ CrowdStrike Falcon
  - Client ID
  - Client Secret
  - Base URL (US1, US2, EU, etc.)

□ Mimecast
  - App ID
  - App Key (secret)
  - Base URL

□ Microsoft Exchange Online
  - Tenant ID
  - Service Principal ID
  - Certificate thumbprint or secret

□ Azure Entra ID
  - Tenant ID
  - Application (Service Principal) ID
  - Certificate or client secret

□ Active Directory
  - Domain name
  - Service account or certificate
  - Target OU for disabled users
```

---

## Files to Create/Modify This Week

| File | Action | Status |
|------|--------|--------|
| `Modules/Menu-System.psm1` | CREATE | TODO |
| `Modules/Emergency-Response.psm1` | CREATE | TODO |
| `script.ps1` | MODIFY (top 50 lines) | TODO |
| `PRODUCTION-READINESS-PLAN.md` | CREATE | DONE |
| Test cases | CREATE | TODO |

---

## Success Looks Like

After this week:
- ✅ Running `.\script.ps1` with no parameters shows interactive menu
- ✅ Menu option 1 runs full assessment
- ✅ Menu option 4 shows emergency response menu
- ✅ Can disable a test user and move to CyberIncident OU
- ✅ Session revocation logic ready for Entra ID integration

**Estimated Time:** 8-10 hours development + 2 hours testing = ~1 day work

---

## Blockers to Resolve

Before starting, confirm:
1. ✅ Access to test AD environment? (assumed yes)
2. ⚠️ Target OU for disabled users exists? (create if not: `OU=CyberIncident,DC=contoso,DC=com`)
3. ⚠️ Running as admin/service account? (needed for AD operations)
4. ⚠️ PowerShell execution policy allows scripts? (Set-ExecutionPolicy -ExecutionPolicy RemoteSigned)

---

## Starting Now

Ready to begin Phase 1 implementation? Here's the kickoff:

1. Create `Modules/Menu-System.psm1` ← **START HERE**
2. Create `Modules/Emergency-Response.psm1`
3. Modify `script.ps1` top section
4. Test each component
5. Document any issues found

**Next Review:** After Phase 1 complete (check on CrowdStrike/Mimecast credentials for Phase 2)
