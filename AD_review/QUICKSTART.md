# Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Install Required Modules

```powershell
# For AD Collection (if not already installed)
# Install RSAT from Windows Features or:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# For Entra Collection (one-time install)
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Reports -Scope CurrentUser -Force
```

### Step 2: Run the Assessment

```powershell
# Navigate to the script directory
cd C:\Projects\AD_review

# AD-Only Assessment
.\script.ps1

# Full AD + Entra Assessment (recommended)
.\script.ps1 -IncludeEntra

# With Visual Diagrams (NEW!)
.\script.ps1 -IncludeEntra -GenerateDiagrams
```

**💡 New Feature**: `-GenerateDiagrams` creates visual maps showing:
- Privileged users, groups, and roles
- GPO → OU relationships
- Domain trust relationships
- OAuth permission grants

See [DIAGRAM-GENERATION-GUIDE.md](DIAGRAM-GENERATION-GUIDE.md) for details.

### Step 3: Review Results

1. **Open the HTML Summary**
   - Location: `$env:TEMP\ADScan\summary-{timestamp}.html`
   - Double-click to open in browser

2. **Review High-Priority Findings**
   - Look for red "High Severity" items
   - Address immediately: krbtgt age, delegation, no MFA

3. **Analyze RBAC Candidates**
   - Open: `rbac-candidates-{timestamp}.csv`
   - Use as starting point for Entra role design

4. **Plan GPO Migration**
   - Open: `gpo-modernization-{timestamp}.csv`
   - Identify GPOs to retire or migrate to Intune

---

## 📊 Understanding the Outputs

### Risk Findings
- **High Severity** 🔴 - Immediate action required
  - krbtgt password >180 days old
  - Unconstrained delegation
  - No Conditional Access policies
  - Admins without MFA

- **Medium Severity** 🟡 - Plan remediation
  - Stale accounts (>90 days)
  - Password never expires
  - Excessive OAuth permissions

- **Low Severity** 🟢 - Hygiene items
  - Unlinked GPOs
  - Cleanup candidates

### RBAC Candidates
Shows user groups with identical AD group memberships:
```csv
RoleName,UserCount,SourceGroups
RBAC_Role_1,15,"CN=Sales,OU=Groups,DC=contoso,DC=com|CN=CRM Users,OU=Groups,DC=contoso,DC=com"
```
**Action**: Create Entra role "Sales CRM Users" for these 15 users

### GPO Modernization
Lists GPOs and their link status:
```csv
GPO,Id,LinkCount
"Legacy Desktop Policy",{guid},0
"Security Baseline",{guid},5
```
**Action**: Retire GPOs with LinkCount=0, migrate security GPOs to Intune

---

## 🎯 Common Scenarios

### Scenario 1: New Client Assessment
```powershell
# Full assessment with custom location
.\script.ps1 -IncludeEntra -OutputFolder "C:\Assessments\ClientName-$(Get-Date -Format 'yyyy-MM-dd')"

# Deliverables:
# 1. HTML summary for client presentation
# 2. Risk findings CSV for remediation tracking
# 3. RBAC candidates for identity modernization
```

### Scenario 2: Security Audit
```powershell
# Focus on security findings
.\script.ps1 -IncludeEntra

# Review:
# - krbtgt password age
# - Delegation configurations
# - Conditional Access coverage
# - MFA enrollment
```

### Scenario 3: Zero Trust Readiness
```powershell
# Full Entra assessment
.\script.ps1 -IncludeEntra

# Check KPIs:
# - ConditionalAccessPolicies > 0
# - MFARegistered vs MFANotRegistered
# - Legacy auth sign-ins
```

### Scenario 4: RBAC Planning
```powershell
# Collect data and analyze
.\script.ps1 -IncludeEntra

# Use outputs:
# 1. rbac-candidates-*.csv → Seed roles
# 2. ad-groups-*.csv → Group sprawl analysis
# 3. entra-role-assignments-*.json → Current state
```

---

## 🔧 Troubleshooting

### "ActiveDirectory module not found"
```powershell
# Install RSAT
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### "Graph API permissions denied"
- Run with admin privileges for first-time consent
- Or: Pre-consent permissions in Azure Portal

### "Script execution disabled"
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "Parsing error on line X"
- Ensure script is saved with UTF-8 encoding
- Avoid special characters in file paths

---

## 📈 Best Practices

### 1. **Schedule Regular Assessments**
```powershell
# Monthly audit
$task = @{
    Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-File "C:\Scripts\AD_review\script.ps1" -IncludeEntra'
    Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
    Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
}
Register-ScheduledTask -TaskName "AD Security Assessment" @task
```

### 2. **Track Progress Over Time**
- Keep historical outputs in dated folders
- Compare KPIs month-over-month
- Track remediation progress

### 3. **Customize for Your Environment**
Edit risk thresholds in `Analyze-Inventory`:
```powershell
# Line ~363: Change stale account threshold
$stale = $adUsers | Where-Object {
    $_.Enabled -eq 'True' -and $_.DaysSinceLogon -and [int]$_.DaysSinceLogon -gt 60  # Changed from 90
}
```

### 4. **Export for Ticketing Systems**
```powershell
# Convert findings to tickets
$findings = Import-Csv "risk-findings-*.csv"
$findings | Where-Object { $_.Severity -eq 'High' } | 
    Select @{n='Title';e={"[Security] $($_.Finding)"}},
           @{n='Priority';e={'P1'}},
           @{n='Category';e={$_.Area}} |
    Export-Csv "tickets.csv" -NoTypeInformation
```

---

## 🎓 Next Steps After Assessment

### Immediate (Week 1)
1. ✅ Address High severity findings
2. ✅ Reset krbtgt password (if >180 days)
3. ✅ Review and remove unconstrained delegation
4. ✅ Enable MFA for Global Admins

### Short-term (Month 1)
1. 🎯 Implement basic Conditional Access policies
2. 🎯 Clean up stale accounts
3. 🎯 Review and revoke excessive OAuth permissions
4. 🎯 Plan RBAC model using seed roles

### Long-term (Quarter 1)
1. 🚀 Complete GPO → Intune migration
2. 🚀 Implement full Zero Trust architecture
3. 🚀 Deploy PIM for privileged access
4. 🚀 Establish regular assessment cadence

---

## 📞 Support Contacts

**For Script Issues**: Check README.md Known Issues section  
**For Security Findings**: Escalate High severity items immediately  
**For RBAC Planning**: Review rbac-candidates CSV with identity team  

---

**Pro Tip**: Run the script before major changes (e.g., domain migration) to establish a baseline, then run again after to validate improvements! 📊

