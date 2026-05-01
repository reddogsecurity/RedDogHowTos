# 🎯 Menu System - Quick Start (5 Minutes)

**Files Created:**
✅ `Modules/Menu-System.psm1` - Complete menu module  
✅ `INTEGRATION-STEPS.md` - Detailed integration guide  
✅ `Test-MenuSystem.ps1` - Test script  
✅ This file

---

## ⚡ 5-Minute Quick Start

### Step 1: Run the Test (2 minutes)
```powershell
cd C:\Path\To\AD_review

# Test the menu system works
.\Test-MenuSystem.ps1

# Expected: All 4 tests pass
# Output shows: [OK] All tests passed!
```

**Did it work?** ✅ Yes → Go to Step 2  
**Did it fail?** ❌ No → Check error message

---

### Step 2: Understand What You Have (1 minute)

**Menu-System.psm1 provides:**
```
Show-MainMenu              Display main menu (6 options)
Show-EmergencyMenu         Display emergency menu (6 options)
Show-ReportSelector        Interactive checkbox report picker
Show-SettingsMenu          Configuration menu
Show-PreviousReports       List previous generated reports
Confirm-Action             Safety dialog (require YES)
Show-ProgressMessage       Color-coded messages
Get-MenuChoice             Validate user input
```

---

### Step 3: Integrate Into script.ps1 (2 minutes)

**Open** `script.ps1` in VS Code

**At the VERY TOP** (line 1, before everything), add:
```powershell
# Interactive menu system
Import-Module "$PSScriptRoot\Modules\Menu-System.psm1" -Force -ErrorAction Stop
```

**Then find the MAIN EXECUTION PART** of your script (usually at the very end)

**Find this pattern:**
```powershell
# Your current entry point - might look like this:
if ($param1) { ... }
elseif ($param2) { ... }
```

**Replace with this:**
```powershell
# Check if running with parameters or interactive
if ($PSBoundParameters.Count -eq 0) {
    # No parameters = Interactive menu mode
    Invoke-InteractiveMode
} else {
    # Parameters provided = Legacy mode (existing code continues)
    # YOUR EXISTING SCRIPT CODE HERE
}
```

**Then add this function** (copy from INTEGRATION-STEPS.md):
```powershell
function Invoke-InteractiveMode {
    do {
        Show-MainMenu
        $choice = Get-MenuChoice -ValidChoices @("1", "2", "3", "4", "5", "6", "Q")
        
        if ($null -eq $choice) { continue }
        
        switch ($choice) {
            "1" {
                Write-Host ""
                Show-ProgressMessage -Message "Starting Full Assessment..." -Type Info
                # YOUR FULL ASSESSMENT CODE HERE
                Write-Host ""
                Read-Host "Press Enter"
            }
            "4" { Invoke-EmergencyResponseMenu }
            "Q" { exit 0 }
        }
    } while ($true)
}
```

---

## 🧪 Test After Integration

```powershell
# Test 1: Run with no parameters (should show menu)
.\script.ps1

# Expected output:
# ╔════════════════════════════════════════════════════════════╗
# ║         AD & Entra ID Security Assessment Tool            ║
# ╚════════════════════════════════════════════════════════════╝

# Test 2: Run with parameters (should run legacy mode)
.\script.ps1 -IncludeEntra -GenerateDiagrams

# Expected: Your existing script runs (no menu)
```

---

## 📋 What Each Menu Option Does

| Option | Feature | Status | Requires |
|--------|---------|--------|----------|
| **1** | Full Assessment | Ready | Your assessment code |
| **2** | Quick Check | Placeholder | Your quick check code |
| **3** | Select Reports | Ready | Your report generation code |
| **4** | Emergency Response | Ready | Emergency-Response.psm1 (coming) |
| **5** | Previous Reports | Ready | Reports folder |
| **6** | Settings | Placeholder | Your settings code |

---

## 🚨 Emergency Menu (Option 4)

**When you press 4, you get:**

```
1. Disable User & Revoke Sessions
   → Immediately disable + move OU + revoke all sessions

2. Revoke Sessions Only
   → Keep account enabled, just revoke sessions

3. Remove Emails
   → Delete emails (soft or hard delete) - Phase 2

4. Suspend Mailbox
   → Disable mailbox access - Phase 2

5. Check CrowdStrike Status
   → Query agent status - Phase 2

6. Generate Incident Report
   → Create detailed report
```

**Status:** Option 1-2 placeholders (need Emergency-Response.psm1)

---

## 🎨 Report Selector Demo

When you press 3 (Select Reports), you get:

```
[X] Identity Hygiene Report
    Stale accounts, password issues, disabled accounts
    
[ ] Privileged Access Report
    Admin membership, delegations, tier-0 accounts
    
[X] Zero Trust Readiness Report
    Conditional Access, MFA, legacy auth, device compliance

...more options...

Selected: 3 report(s)

Commands:
  [Up/Down]  - Navigate
  [Space]    - Toggle selection
  [All]      - Select all
  [None]     - Deselect all
  [Enter]    - Proceed
  [Q]        - Cancel
```

**How to use:**
- Arrow keys = Move cursor
- Spacebar = Check/uncheck
- Enter = Start generation
- Q = Cancel

---

## ✅ Verification Checklist

After integration, verify all of these work:

```
[ ] Menu appears when you run .\script.ps1
[ ] All 6 options appear in main menu
[ ] Option 1 shows "Starting Full Assessment..."
[ ] Option 4 shows emergency submenu
[ ] Option 3 shows interactive report picker
    [ ] Can press arrows
    [ ] Can press space to toggle
    [ ] Can press Enter to confirm
    [ ] Can press Q to cancel
[ ] Option Q exits script
[ ] Running with -IncludeEntra still works (legacy mode)
[ ] No errors in console
```

---

## 📁 File Structure After Integration

```
AD_review/
├── script.ps1                           [MODIFIED - Added menu code]
├── Modules/
│   └── Menu-System.psm1                 [NEW - Complete ✅]
├── Test-MenuSystem.ps1                  [NEW - Test script ✅]
├── INTEGRATION-STEPS.md                 [NEW - Detailed guide ✅]
├── INTEGRATION-GUIDE.md                 [NEW - Code samples ✅]
├── [existing files...]
```

---

## 🚀 What's Next

**After menu works:**

1. **Create Emergency-Response.psm1** (coming next)
   - Disable user function
   - Revoke sessions function
   - Audit logging

2. **Create Auth-Manager.psm1**
   - Certificate authentication
   - Credential handling

3. **Create Setup-Certificates.ps1**
   - AD CA enrollment
   - Certificate testing

4. **Phase 2: API Integrations**
   - CrowdStrike
   - Mimecast
   - Exchange Online

---

## 💡 Pro Tips

### Tip 1: Test Report Selector First
```powershell
# Just test the report selector in isolation
Import-Module .\Modules\Menu-System.psm1 -Force
$reports = Show-ReportSelector
$reports | Format-Table
```

### Tip 2: Color Codes
- 🔴 Red = Emergency/Dangerous
- 🟡 Yellow = User input needed
- 🟢 Green = Success
- 🔵 Cyan = Information
- Gray = Secondary info

### Tip 3: Confirmation Dialogs
Must type "YES" to confirm dangerous actions:
```powershell
Confirm-Action -Title "Disable User" `
               -Message "Disable john.smith?" `
               -ConfirmationWord "YES"
```

---

## 🆘 Troubleshooting

### Menu doesn't appear
```
❌ Problem: .\script.ps1 -IncludeEntra shows menu
✅ Solution: Run .\script.ps1 WITHOUT parameters

The menu only appears when you have ZERO parameters.
```

### Module import fails
```
❌ Problem: Cannot find path '.../Menu-System.psm1'
✅ Solution: Verify file exists and location is correct
            Run: Get-ChildItem .\Modules\Menu-System.psm1
```

### Report selector doesn't respond
```
❌ Problem: Arrow keys don't work
✅ Solution: Make sure focus is on console window
            Try clicking in the window first
            
If still broken: Run Test-MenuSystem.ps1 to diagnose
```

### Options don't do anything
```
❌ Problem: Press 1, nothing happens
✅ Solution: Replace placeholder functions with your actual code
            See INTEGRATION-STEPS.md Step 6
```

---

## 📞 Quick Reference

**Files to Know:**
- `Modules/Menu-System.psm1` - The menu module
- `INTEGRATION-STEPS.md` - Detailed step-by-step guide
- `Test-MenuSystem.ps1` - Run this to test everything
- `INTEGRATION-GUIDE.md` - Code samples

**Key Functions:**
- `Show-MainMenu` - Display main menu
- `Show-EmergencyMenu` - Display emergency menu  
- `Show-ReportSelector` - Pick reports interactively
- `Confirm-Action` - Safety confirmation dialog

**Common Tasks:**
- Test menu: `.\Test-MenuSystem.ps1`
- Test report picker: `Show-ReportSelector`
- Test emergency: `Show-EmergencyMenu`

---

## 🎉 You're Ready!

1. ✅ Menu system created
2. ✅ Integration guide provided
3. ✅ Test script ready
4. ✅ Everything documented

**Next action:** Run `.\Test-MenuSystem.ps1` and verify it passes all tests!

---

**Questions?** Check INTEGRATION-STEPS.md for detailed guidance.
