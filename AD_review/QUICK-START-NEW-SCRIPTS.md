# Quick Start Guide - New AD Security Scripts

## 🚀 Fastest Way to Start

### Option 1: Run Everything at Once (Recommended)
```powershell
# Navigate to the AD_review folder
cd C:\Users\reddog\Projects\Projects\AD_review

# Run the master orchestrator script
.\Run-EnhancedAssessment.ps1
```

This will:
- Run all 5 new security assessment scripts
- Create a timestamped output folder
- Generate HTML reports and CSV exports
- Open the results folder automatically
- Takes 10-30 minutes depending on environment size

---

### Option 2: Quick Scan (No Entra Integration)
```powershell
# For on-premises only or if you don't have Graph permissions
.\Run-EnhancedAssessment.ps1 -QuickScan
```

This runs:
- Expired password analysis ✓
- Password never expire checks ✓
- Privileged group enumeration ✓
- Skips Entra comparison ⊘
- Skips schema audit (requires elevated permissions) ⊘

---

### Option 3: Run Individual Scripts

#### 1. Check Expired Passwords & Last Logon
```powershell
.\Get-ExpiredPasswordAccounts.ps1
```
**What you get**: List of accounts with expired passwords, last logon times, and privileged account flags

#### 2. Check Domain Admins & Enterprise Admins
```powershell
.\Get-PrivilegedGroupMembers.ps1 -IncludeNested
```
**What you get**: Complete list of who's in privileged groups including nested memberships

#### 3. Check Password Never Expires Accounts
```powershell
.\Get-PasswordNeverExpireAccounts.ps1 -CheckServiceAccounts
```
**What you get**: Accounts with password never expires, their privilege levels, and risk assessment

#### 4. Compare AD to Entra ID
```powershell
.\Compare-ADtoEntraUsers.ps1 -CompareAttributes
```
**What you get**: Cloud-only accounts, orphaned accounts, and sync issues

#### 5. Check AD Schema Permissions (Requires Admin)
```powershell
.\Get-ADSchemaPermissions.ps1
```
**What you get**: Who has permissions to modify your AD schema

---

## 📋 Prerequisites Check

### Minimum Requirements
```powershell
# Check if you have AD module
Get-Module -ListAvailable -Name ActiveDirectory

# If not installed, run this (requires admin):
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### Optional (For Entra Features)
```powershell
# Check for Graph modules
Get-Module -ListAvailable -Name Microsoft.Graph.Authentication

# Install if needed:
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

---

## 🎯 Top 5 Most Common Use Cases

### 1. "I need to see who's in Domain Admins and Enterprise Admins"
```powershell
.\Get-PrivilegedGroupMembers.ps1 -IncludeNested
```
Open the HTML report: `PrivilegedGroupMembers-*.html`

### 2. "Which accounts have expired passwords?"
```powershell
.\Get-ExpiredPasswordAccounts.ps1
```
Open the HTML report: `ExpiredPasswordReport-*.html`

### 3. "Show me privileged accounts with security issues"
```powershell
.\Get-PasswordNeverExpireAccounts.ps1
```
Look for **Critical** risk accounts in: `PasswordNeverExpire-*.html`

### 4. "Are there cloud-only accounts in Entra that aren't in AD?"
```powershell
.\Compare-ADtoEntraUsers.ps1
```
Check the `EntraOnly-Users-*.csv` file

### 5. "Run a complete security audit"
```powershell
.\Run-EnhancedAssessment.ps1
```
Review all HTML reports in the timestamped output folder

---

## 📊 Understanding the Output

### All Scripts Generate:
1. **CSV Files** - Raw data for analysis/import
2. **HTML Reports** - Pretty, color-coded reports (open in browser)
3. **Console Summary** - Immediate statistics

### Where Files Are Saved:
- **Individual scripts**: Current directory by default
- **Master orchestrator**: `C:\AD_SecurityAssessments\Assessment-<timestamp>\`

### Color Coding in Reports:
- 🔴 **Red/Critical**: Requires immediate action
- 🟠 **Orange/High**: Review within 24-48 hours
- 🟡 **Yellow/Medium**: Address in next maintenance window
- 🟢 **Green/Low**: Monitor or informational

---

## ⚡ Quick Troubleshooting

### "ActiveDirectory module not found"
```powershell
# Install RSAT (requires admin)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### "Cannot connect to Microsoft Graph"
```powershell
# Connect manually first
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All"

# Then run the script
.\Get-PrivilegedGroupMembers.ps1 -CheckEntraMFA
```

### "Access Denied" for Schema Script
```powershell
# Schema permissions require Domain Admin or Schema Admin
# Either:
# 1. Run as admin: Right-click PowerShell -> Run as Administrator
# 2. Or skip the schema script: .\Run-EnhancedAssessment.ps1 -SkipSchemaAudit
```

### Script runs slow with large environment
```
This is normal. For environments with 10,000+ users:
- Each script takes 5-15 minutes
- Total assessment: 30-60 minutes
- Grab a coffee ☕ and let it run
```

---

## 🎨 Example Walkthrough

Let's say you want to check privileged account security:

```powershell
# Step 1: Navigate to scripts folder
cd C:\Users\reddog\Projects\Projects\AD_review

# Step 2: Check who's in privileged groups
.\Get-PrivilegedGroupMembers.ps1 -IncludeNested -CheckEntraMFA

# Step 3: Check for password issues in those accounts
.\Get-PasswordNeverExpireAccounts.ps1 -CheckServiceAccounts

# Step 4: Check for expired passwords
.\Get-ExpiredPasswordAccounts.ps1

# Step 5: Open the HTML reports
# They're saved in the current directory with timestamp in filename
# Look for files ending in .html
explorer .
```

**What you'll discover:**
- All members of Domain Admins, Enterprise Admins, Schema Admins, etc.
- Which privileged accounts don't have MFA
- Which privileged accounts have password never expires
- Which privileged accounts have expired passwords
- Stale accounts (no logon in 90+ days)

**Total time**: 5-10 minutes

---

## 📅 Recommended Schedule

### One-Time Initial Assessment
```powershell
.\Run-EnhancedAssessment.ps1
```

### Weekly (Monitor Changes)
```powershell
.\Get-PrivilegedGroupMembers.ps1 -IncludeNested
```

### Monthly (Password & Account Hygiene)
```powershell
.\Get-ExpiredPasswordAccounts.ps1
.\Get-PasswordNeverExpireAccounts.ps1
.\Compare-ADtoEntraUsers.ps1
```

### Quarterly (Full Audit)
```powershell
.\Run-EnhancedAssessment.ps1
```

---

## 🔥 Critical Findings to Act On Immediately

After running the assessments, prioritize these findings:

### 1. Privileged Accounts with Password Never Expires
**Found in**: `PasswordNeverExpire-Privileged-*.csv`  
**Action**: Remove the "Password Never Expires" flag immediately
```powershell
# For each account found:
Set-ADUser -Identity "USERNAME" -PasswordNeverExpires $false
```

### 2. Privileged Accounts Without MFA
**Found in**: `PrivilegedGroupMembers-Findings-*.csv`  
**Action**: Enable MFA in Entra ID immediately

### 3. Disabled Accounts in Privileged Groups
**Found in**: `PrivilegedGroupMembers-Findings-*.csv`  
**Action**: Remove from privileged groups
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "DisabledUser" -Confirm:$false
```

### 4. Orphaned Entra Accounts
**Found in**: `Orphaned-Users-*.csv`  
**Action**: Review and disable/delete in Entra ID

### 5. Expired Passwords on Privileged Accounts
**Found in**: `ExpiredPasswordAccounts-*.csv` (filter by IsPrivilegedAccount=True)  
**Action**: Force password reset immediately

---

## 💡 Pro Tips

1. **Save Assessment History**: Keep monthly snapshots to track improvements
   ```powershell
   $month = Get-Date -Format "yyyy-MM"
   .\Run-EnhancedAssessment.ps1 -OutputFolder "C:\Audits\$month"
   ```

2. **Filter CSV in Excel**: Open CSV files in Excel and use AutoFilter to focus on Critical/High items

3. **Share HTML Reports**: HTML files can be opened in any browser - easy to share with non-technical stakeholders

4. **Combine with Main Tool**: Run these scripts AFTER the main `script.ps1` for complete coverage

5. **Automate with Task Scheduler**: Schedule monthly runs
   ```powershell
   # Create a scheduled task to run the assessment
   $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\AD_review\Run-EnhancedAssessment.ps1 -QuickScan"
   $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
   Register-ScheduledTask -TaskName "Monthly AD Security Assessment" -Action $action -Trigger $trigger
   ```

---

## 📚 More Information

For detailed documentation on each script:
- **Complete Guide**: `NEW-FEATURES-GUIDE.md`
- **Main Project README**: `README.md`
- **Troubleshooting**: `HOW-TO-FIX-YOUR-DIRECTORY.md`

---

## 🆘 Need Help?

### Quick Help
```powershell
# Get help for any script:
Get-Help .\Get-ExpiredPasswordAccounts.ps1 -Full
Get-Help .\Get-PrivilegedGroupMembers.ps1 -Examples
```

### Common Questions

**Q: Can I run these in a test environment first?**  
A: Yes! All scripts are read-only and make no changes to AD or Entra.

**Q: How much disk space do I need?**  
A: Typically 10-50 MB per assessment, depending on environment size.

**Q: Can I run these without admin rights?**  
A: Yes, except for the schema permissions script which requires elevated permissions.

**Q: Will this impact production?**  
A: No. All queries are read-only. Performance impact is minimal (similar to running AD Users and Computers).

---

## ✅ Checklist for First Run

- [ ] AD module installed
- [ ] Navigated to AD_review folder
- [ ] Run `.\Run-EnhancedAssessment.ps1` (or `-QuickScan` if no Entra)
- [ ] Wait 10-30 minutes
- [ ] Review HTML reports in output folder
- [ ] Prioritize Critical and High findings
- [ ] Create remediation plan

---

**You're ready to go! Start with `.\Run-EnhancedAssessment.ps1` for the complete experience.**




