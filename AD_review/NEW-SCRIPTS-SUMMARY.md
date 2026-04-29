# Enhanced AD Security Assessment - New Scripts Summary

## 🎉 What Was Created

Five powerful new PowerShell scripts have been added to your AD security assessment toolkit, plus supporting documentation and a master orchestrator script.

---

## 📁 New Files Created

### Security Assessment Scripts

1. **Get-ExpiredPasswordAccounts.ps1**
   - Identifies accounts with expired passwords
   - Tracks last logon times
   - Flags privileged accounts with expired passwords
   - Identifies accounts expiring within 14 days

2. **Get-ADSchemaPermissions.ps1**
   - Audits AD schema object permissions
   - Identifies who can modify the schema
   - Detects unauthorized schema access
   - Generates searchable permission reports

3. **Get-PrivilegedGroupMembers.ps1**
   - Lists all members of Domain Admins, Enterprise Admins, Schema Admins
   - Enumerates 12+ privileged groups
   - Optional MFA status checking
   - Identifies disabled accounts in privileged groups

4. **Compare-ADtoEntraUsers.ps1**
   - Compares AD users with Entra ID (Azure AD)
   - Identifies cloud-only accounts
   - Detects orphaned accounts
   - Finds sync discrepancies

5. **Get-PasswordNeverExpireAccounts.ps1**
   - Identifies all accounts with "Password Never Expires"
   - Cross-references with privileged groups
   - Calculates risk levels (Critical/High/Medium/Low)
   - Identifies service accounts

### Orchestrator & Documentation

6. **Run-EnhancedAssessment.ps1**
   - Master script that runs all 5 assessments
   - Creates organized output folders
   - Generates summary reports
   - Tracks execution status

7. **NEW-FEATURES-GUIDE.md**
   - Comprehensive documentation for all scripts
   - Usage examples and parameters
   - Output file descriptions
   - Security best practices

8. **QUICK-START-NEW-SCRIPTS.md**
   - Quick start guide
   - Common use cases
   - Troubleshooting tips
   - Example walkthroughs

9. **NEW-SCRIPTS-SUMMARY.md** (this file)
   - Overview of what was created
   - Quick reference for all features

---

## 🚀 How to Use - Super Quick Start

### Option 1: Run Everything (Easiest)
```powershell
cd C:\Users\reddog\Projects\Projects\AD_review
.\Run-EnhancedAssessment.ps1
```
⏱️ Takes 10-30 minutes | 📊 Generates complete security assessment

### Option 2: Quick Scan (No Entra)
```powershell
.\Run-EnhancedAssessment.ps1 -QuickScan
```
⏱️ Takes 5-15 minutes | 📊 AD-only assessment

### Option 3: Individual Scripts
```powershell
# Check expired passwords
.\Get-ExpiredPasswordAccounts.ps1

# Check Domain Admins & Enterprise Admins
.\Get-PrivilegedGroupMembers.ps1 -IncludeNested

# Check password never expires
.\Get-PasswordNeverExpireAccounts.ps1

# Compare AD to Entra
.\Compare-ADtoEntraUsers.ps1

# Check schema permissions (requires admin)
.\Get-ADSchemaPermissions.ps1
```

---

## 📊 What Each Script Does

### 1️⃣ Expired Password Accounts
**Command**: `.\Get-ExpiredPasswordAccounts.ps1`

**Answers**:
- ✅ Which accounts have expired passwords?
- ✅ When did they last logon?
- ✅ Which privileged accounts have expired passwords? (CRITICAL)
- ✅ Which accounts are expiring soon?

**Output**:
- `ExpiredPasswordAccounts-*.csv` - All expired password accounts
- `PasswordsExpiringSoon-*.csv` - Expiring within 14 days
- `ExpiredPasswordReport-*.html` - Interactive report

**Critical Finding**: Privileged accounts with expired passwords

---

### 2️⃣ AD Schema Permissions
**Command**: `.\Get-ADSchemaPermissions.ps1`

**Answers**:
- ✅ Who has permissions to modify the AD schema?
- ✅ What schema objects have been modified?
- ✅ Are there unauthorized schema permissions?

**Output**:
- `ADSchemaPermissions-*.csv` - All schema permissions
- `ADSchemaPermissions-Detailed-*.csv` - Summary by object
- `ADSchemaPermissions-*.html` - Searchable report

**Critical Finding**: Unauthorized users with schema modification rights

**Note**: Requires elevated permissions (Domain Admin or Schema Admin)

---

### 3️⃣ Privileged Group Members
**Command**: `.\Get-PrivilegedGroupMembers.ps1 -IncludeNested -CheckEntraMFA`

**Answers**:
- ✅ Who is in Domain Admins?
- ✅ Who is in Enterprise Admins?
- ✅ Who is in Schema Admins, Administrators, Account Operators, etc.?
- ✅ Which privileged accounts don't have MFA? (CRITICAL)
- ✅ Which privileged accounts are stale (no logon 90+ days)?

**Output**:
- `PrivilegedGroupMembers-Detailed-*.csv` - All members
- `PrivilegedGroupMembers-Summary-*.csv` - Group statistics
- `PrivilegedGroupMembers-Findings-*.csv` - Security issues
- `PrivilegedGroupMembers-*.html` - Color-coded report

**Critical Findings**:
- Privileged accounts without MFA
- Disabled accounts in privileged groups
- Stale privileged accounts

---

### 4️⃣ AD to Entra User Comparison
**Command**: `.\Compare-ADtoEntraUsers.ps1 -CompareAttributes`

**Answers**:
- ✅ Which users are in Entra but NOT in AD? (cloud-only)
- ✅ Which users are in AD but NOT in Entra? (not syncing)
- ✅ Are there orphaned accounts? (CRITICAL)
- ✅ Are there sync issues/attribute mismatches?

**Output**:
- `EntraOnly-Users-*.csv` - Users only in Entra
- `CloudOnly-Users-*.csv` - True cloud-only accounts
- `Orphaned-Users-*.csv` - Previously synced, AD account deleted
- `ADOnly-Users-*.csv` - AD accounts not syncing
- `Synced-Users-*.csv` - Users in both systems
- `AttributeMismatches-*.csv` - Sync discrepancies
- `ADEntraComparison-*.html` - Visual comparison

**Critical Finding**: Orphaned accounts (security/licensing risk)

---

### 5️⃣ Password Never Expire Accounts
**Command**: `.\Get-PasswordNeverExpireAccounts.ps1 -CheckServiceAccounts`

**Answers**:
- ✅ Which accounts have "Password Never Expires" enabled?
- ✅ Which privileged accounts have this flag? (CRITICAL)
- ✅ What's the risk level of each account?
- ✅ Which are service accounts?

**Output**:
- `PasswordNeverExpire-All-*.csv` - All accounts
- `PasswordNeverExpire-Privileged-*.csv` - Privileged accounts
- `PasswordNeverExpire-HighRisk-*.csv` - Critical/High risk
- `PasswordNeverExpire-ServiceAccounts-*.csv` - Service accounts
- `PasswordNeverExpire-*.html` - Risk assessment report

**Critical Finding**: Privileged accounts with password never expires

**Risk Levels**:
- 🔴 **Critical**: Privileged account with password never expires
- 🟠 **High**: Never expires + stale (180+ days) or password never set
- 🟡 **Medium**: Never expires + moderately stale (90+ days)
- 🟢 **Low**: Standard account with never expires

---

## 🎯 Top 5 Critical Findings to Look For

After running the assessments, immediately check for:

### 1. Privileged Accounts with Password Never Expires 🔴
**Script**: Get-PasswordNeverExpireAccounts.ps1  
**File**: `PasswordNeverExpire-Privileged-*.csv`  
**Risk**: Critical  
**Action**: Remove "Password Never Expires" flag immediately

### 2. Privileged Accounts Without MFA 🔴
**Script**: Get-PrivilegedGroupMembers.ps1 -CheckEntraMFA  
**File**: `PrivilegedGroupMembers-Findings-*.csv`  
**Risk**: Critical  
**Action**: Enable MFA immediately

### 3. Privileged Accounts with Expired Passwords 🔴
**Script**: Get-ExpiredPasswordAccounts.ps1  
**File**: `ExpiredPasswordAccounts-*.csv` (filter IsPrivilegedAccount=True)  
**Risk**: Critical  
**Action**: Force password reset

### 4. Orphaned Entra Accounts 🟠
**Script**: Compare-ADtoEntraUsers.ps1  
**File**: `Orphaned-Users-*.csv`  
**Risk**: High  
**Action**: Review and disable/delete

### 5. Disabled Accounts in Privileged Groups 🟠
**Script**: Get-PrivilegedGroupMembers.ps1  
**File**: `PrivilegedGroupMembers-Findings-*.csv`  
**Risk**: High  
**Action**: Remove from privileged groups

---

## 📋 Prerequisites

### Required
- ✅ Windows 10/11 or Windows Server
- ✅ PowerShell 5.1 or higher
- ✅ Active Directory PowerShell module (RSAT)
- ✅ Domain user account with read access

### Optional (for Entra features)
- ⭕ Microsoft.Graph.Authentication
- ⭕ Microsoft.Graph.Users
- ⭕ Microsoft.Graph.Identity.SignIns
- ⭕ Permissions: User.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All

### Installation Commands
```powershell
# Install AD module (requires admin)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Install Graph modules (optional, for Entra features)
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

---

## 🎨 Output Examples

### All Scripts Generate
1. **CSV Files** - For data analysis, Excel import, filtering
2. **HTML Reports** - Interactive, color-coded, browser-based
3. **Console Output** - Real-time progress and summary statistics

### Output Organization
When using `Run-EnhancedAssessment.ps1`:
```
C:\AD_SecurityAssessments\
└── Assessment-2025-11-05_143022\
    ├── ASSESSMENT-SUMMARY.txt
    ├── ExpiredPasswordAccounts-20251105-143025.csv
    ├── ExpiredPasswordReport-20251105-143025.html
    ├── PasswordNeverExpire-All-20251105-143130.csv
    ├── PasswordNeverExpire-Privileged-20251105-143130.csv
    ├── PasswordNeverExpire-20251105-143130.html
    ├── PrivilegedGroupMembers-Detailed-20251105-143235.csv
    ├── PrivilegedGroupMembers-Summary-20251105-143235.csv
    ├── PrivilegedGroupMembers-Findings-20251105-143235.csv
    ├── PrivilegedGroupMembers-20251105-143235.html
    ├── EntraOnly-Users-20251105-143340.csv
    ├── CloudOnly-Users-20251105-143340.csv
    ├── Orphaned-Users-20251105-143340.csv
    ├── ADEntraComparison-20251105-143340.html
    ├── ADSchemaPermissions-20251105-143445.csv
    └── ADSchemaPermissions-20251105-143445.html
```

---

## 🔥 Real-World Examples

### Example 1: Security Audit Before Compliance Review
```powershell
# Run complete assessment
.\Run-EnhancedAssessment.ps1 -OutputFolder "C:\Audit-Q4-2025"

# Review HTML reports
# Focus on Critical and High findings
# Export findings to share with auditors
```

### Example 2: Incident Response - Compromised Account
```powershell
# Quick check of all privileged accounts
.\Get-PrivilegedGroupMembers.ps1 -IncludeNested -CheckEntraMFA

# Check for expired/weak passwords
.\Get-ExpiredPasswordAccounts.ps1
.\Get-PasswordNeverExpireAccounts.ps1

# Identify accounts that need password changes
```

### Example 3: Monthly Security Hygiene
```powershell
# Create monthly report
$month = Get-Date -Format "yyyy-MM"
.\Run-EnhancedAssessment.ps1 -OutputFolder "C:\MonthlyReports\$month"

# Compare to previous month to track improvements
```

### Example 4: Pre-Migration Check (Moving to Cloud)
```powershell
# Identify sync issues before migration
.\Compare-ADtoEntraUsers.ps1 -CompareAttributes -IncludeLicensing

# Identify accounts that need remediation
.\Get-PasswordNeverExpireAccounts.ps1 -CheckServiceAccounts
```

---

## ⏱️ Expected Run Times

| Environment Size | Quick Scan | Full Assessment |
|-----------------|------------|-----------------|
| Small (< 1,000 users) | 2-5 min | 5-10 min |
| Medium (1,000-5,000) | 5-10 min | 10-20 min |
| Large (5,000-20,000) | 10-20 min | 20-40 min |
| Enterprise (20,000+) | 20-40 min | 40-90 min |

*Times vary based on network speed, domain controller performance, and features enabled*

---

## 📚 Documentation

### Quick References
- **Quick Start**: `QUICK-START-NEW-SCRIPTS.md` ⭐ Start here!
- **Complete Guide**: `NEW-FEATURES-GUIDE.md` (detailed documentation)
- **This Summary**: `NEW-SCRIPTS-SUMMARY.md`

### Main Project Documentation
- **Main README**: `README.md`
- **Change Log**: `CHANGELOG.md`
- **Troubleshooting**: `HOW-TO-FIX-YOUR-DIRECTORY.md`

### Getting Help with Scripts
```powershell
# Get detailed help for any script
Get-Help .\Get-ExpiredPasswordAccounts.ps1 -Full
Get-Help .\Get-PrivilegedGroupMembers.ps1 -Examples
Get-Help .\Compare-ADtoEntraUsers.ps1 -Detailed
```

---

## ✅ Your Action Plan

### Step 1: Initial Setup (5 minutes)
```powershell
# Ensure AD module is installed
Get-Module -ListAvailable -Name ActiveDirectory

# If not installed (requires admin):
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### Step 2: First Run (10-30 minutes)
```powershell
# Navigate to scripts folder
cd C:\Users\reddog\Projects\Projects\AD_review

# Run complete assessment
.\Run-EnhancedAssessment.ps1

# Or quick scan if no Entra access
.\Run-EnhancedAssessment.ps1 -QuickScan
```

### Step 3: Review Results (30-60 minutes)
1. Open the timestamped output folder
2. Start with HTML reports (easier to read)
3. Focus on Critical and High severity findings
4. Export findings to CSV for detailed analysis

### Step 4: Remediate Critical Findings (Varies)
1. Privileged accounts with password issues
2. Accounts without MFA
3. Disabled accounts in privileged groups
4. Orphaned cloud accounts

### Step 5: Schedule Regular Assessments
- Weekly: Privileged group changes
- Monthly: Password and account hygiene
- Quarterly: Full assessment

---

## 🎊 Summary

You now have **5 powerful new security assessment scripts** that address all your requirements:

1. ✅ **Expired passwords + last logon** - Get-ExpiredPasswordAccounts.ps1
2. ✅ **AD schema permissions** - Get-ADSchemaPermissions.ps1
3. ✅ **Domain Admins & Enterprise Admins** - Get-PrivilegedGroupMembers.ps1
4. ✅ **AD to Entra comparison** - Compare-ADtoEntraUsers.ps1
5. ✅ **Password never expire + privileges** - Get-PasswordNeverExpireAccounts.ps1

Plus:
- **Master orchestrator** to run everything at once
- **Comprehensive documentation** with examples
- **HTML reports** for easy viewing
- **CSV exports** for detailed analysis

---

## 🚀 Ready to Start?

```powershell
cd C:\Users\reddog\Projects\Projects\AD_review
.\Run-EnhancedAssessment.ps1
```

**That's it!** The scripts will do the rest and generate a complete security assessment.

---

**Questions? Check `QUICK-START-NEW-SCRIPTS.md` or `NEW-FEATURES-GUIDE.md` for detailed help.**




