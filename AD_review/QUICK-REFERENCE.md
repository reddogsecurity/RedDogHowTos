# AD Security Assessment Tool - Quick Reference Card

## 🚀 **Quick Commands**

### **Basic Assessment**
```powershell
.\script.ps1 -IncludeEntra
```

### **With Visual Diagrams**
```powershell
.\script.ps1 -IncludeEntra -GenerateDiagrams
```

### **With Trend Tracking**
```powershell
.\script.ps1 -IncludeEntra -OutputFolder "C:\Assessments\2025-10" -CompareWith "C:\Assessments\2025-09"
```

### **Complete (All Features)**
```powershell
.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\Assessments\$(Get-Date -Format 'yyyy-MM')" -CompareWith "C:\Assessments\PreviousMonth"
```

---

## 📊 **Output Files**

### **Analysis Reports**
- `summary-{timestamp}.html` - **Main report** (open this first!)
- `risk-findings-{timestamp}.csv` - Security findings with MITRE mapping
- `rbac-candidates-{timestamp}.csv` - Suggested roles
- `gpo-modernization-{timestamp}.csv` - GPO migration plan
- `kpis-{timestamp}.json` - Key metrics

### **Advanced Analysis**
- `ca-gap-analysis-{timestamp}.csv` - Missing CA policies
- `findings-by-security-category-{timestamp}.csv` - Grouped by category
- `findings-by-mitre-tactic-{timestamp}.csv` - Grouped by MITRE
- `trend-analysis-{timestamp}.csv` - KPI trends (if `-CompareWith`)

### **Visual Diagrams** (if `-GenerateDiagrams`)
- `privileged-access-map-{timestamp}.png/.mmd/.dot`
- `gpo-topology-{timestamp}.png/.mmd/.dot`
- `trust-map-{timestamp}.png/.mmd/.dot`
- `app-grant-views-{timestamp}.png/.mmd/.dot`

---

## 🎯 **Key Features**

| Feature | Parameter | Output |
|---------|-----------|--------|
| **Basic Assessment** | (none) | HTML + CSV reports |
| **Visual Diagrams** | `-GenerateDiagrams` | 4 diagram types |
| **Trend Tracking** | `-CompareWith "folder"` | Trend analysis |
| **CA Gap Analysis** | `-IncludeEntra` | Auto-included |
| **MITRE Mapping** | (automatic) | Auto-included |

---

## 🔍 **What to Look For**

### **In HTML Report**
1. **Executive Summary** (top) - Key metrics at a glance
2. **High Severity Findings** (red) - Action immediately
3. **Remediation Playbook** - Assign owners and due dates
4. **RBAC Seed Roles** - Use for Entra role design
5. **Dark Mode Toggle** (top-right) - Better viewing

### **In CSV Files**
- `risk-findings-*.csv`:
  - **MITRETechniques** column - Threat intelligence
  - **SecurityCategory** column - Group by attack type
  - **RiskScore** column - Numeric priority (1-10)
  - **RemediationSteps** column - How to fix

### **In Diagrams**
- 🔴 **Red nodes** - High risk (no MFA, excessive permissions)
- 🟡 **Yellow nodes** - Medium risk
- 🟢 **Green nodes** - Low risk
- ⚠️ **Warning icon** - User without MFA
- 🔐 **Lock icon** - MFA enabled

---

## 📋 **Common Scenarios**

### **Monthly Security Review**
```powershell
$month = Get-Date -Format "yyyy-MM"
$prev = (Get-Date).AddMonths(-1).ToString("yyyy-MM")

.\script.ps1 `
    -IncludeEntra `
    -GenerateDiagrams `
    -OutputFolder "C:\Assessments\$month" `
    -CompareWith "C:\Assessments\$prev"

# Open HTML report
Invoke-Item "C:\Assessments\$month\summary-*.html"
```

### **Client Engagement**
```powershell
$client = "AcmeCorp"
$date = Get-Date -Format "yyyy-MM-dd"

.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\Clients\$client\$date"

# Deliverables:
# - HTML summary for presentation
# - Visual diagrams for security review
# - Risk findings CSV for remediation tracking
```

### **Compliance Audit**
```powershell
.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\Audits\Q4-2025"

# Review:
# - CA gap analysis for Zero Trust compliance
# - MITRE mappings for threat assessment
# - Risk findings for security controls
```

---

## 🛠️ **Prerequisites**

### **Required**
- ✅ PowerShell 5.1+
- ✅ ActiveDirectory module (RSAT)
- ✅ Microsoft.Graph modules (if `-IncludeEntra`)

### **Optional**
- 🎨 Graphviz (for PNG diagrams) - https://graphviz.org/download/
- 📦 Chocolatey: `choco install graphviz`

---

## 📖 **Documentation Quick Links**

| Document | Purpose | When to Read |
|----------|---------|--------------|
| `README.md` | Complete overview | First time users |
| `QUICKSTART.md` | 5-minute setup | Getting started |
| `DIAGRAM-GENERATION-GUIDE.md` | Diagram usage | Using `-GenerateDiagrams` |
| `MODULAR-ARCHITECTURE-GUIDE.md` | Module system | Developers |
| `FINAL-IMPLEMENTATION-SUMMARY.md` | All enhancements | See what's new in v3.0 |

---

## ⚡ **Power Tips**

### **View Dark Mode**
Open HTML report → Click "🌙 Dark Mode" button (top-right)

### **Print Report**
Browser → Print → Automatically optimized layout

### **View Diagrams**
```powershell
# PNG (easiest)
Invoke-Item "C:\Temp\ADScan\privileged-access-map-*.png"

# Mermaid (GitHub/GitLab)
Get-Content "C:\Temp\ADScan\*.mmd" | Set-Clipboard
# Paste at https://mermaid.live

# DOT (custom rendering)
dot -Tsvg diagram.dot -o diagram.svg
```

### **Track Monthly Improvements**
```powershell
# Save each month's assessment
.\script.ps1 -IncludeEntra -OutputFolder "C:\Assessments\$(Get-Date -Format 'yyyy-MM')"

# Next month, compare
.\script.ps1 -IncludeEntra -OutputFolder "C:\Assessments\2025-11" -CompareWith "C:\Assessments\2025-10"

# View trends
Import-Csv "C:\Assessments\2025-11\trend-analysis-*.csv" | 
    Where-Object { $_.Trend -eq 'Improved' } | 
    Format-Table KPI, PreviousValue, CurrentValue, PercentChange
```

---

## 🎯 **Severity Priorities**

| Severity | Action | Timeline |
|----------|--------|----------|
| 🔴 **High** | Immediate action required | Within 24-48 hours |
| 🟡 **Medium** | Plan remediation | Within 1-2 weeks |
| 🟢 **Low** | Hygiene improvements | Within 30 days |

### **High Priority Items**
- krbtgt password >180 days
- Unconstrained delegation
- Admins without MFA
- No Conditional Access policies
- External domain trusts without selective auth

---

## 🔥 **Quick Wins**

### **Enable Azure AD Security Defaults** (5 minutes)
If no CA policies exist - immediate interim protection

### **Reset krbtgt Password** (1 hour + 24hr wait)
If >180 days old - critical security control

### **Enforce MFA for Global Admins** (15 minutes)
Create CA policy: Require MFA for Global Administrator role

### **Block Legacy Authentication** (30 minutes)
Create CA policy: Block Exchange ActiveSync, Other Clients

---

## 📞 **Support**

### **Issues**
- Check `README.md` Known Issues section
- Review error messages in console
- Verify module installation
- Check Graph API permissions

### **Questions**
- Usage: See `QUICKSTART.md`
- Modules: See `MODULAR-ARCHITECTURE-GUIDE.md`
- Diagrams: See `DIAGRAM-GENERATION-GUIDE.md`

---

## 📊 **At a Glance**

**Version**: 3.0  
**Modules**: 8  
**Diagram Types**: 4  
**Output Files**: 73+  
**Security Rules**: 21+  
**MITRE Techniques**: 15+  
**Documentation**: 3,400+ lines  

**Status**: ✅ Production Ready

---

**Last Updated**: October 7, 2025  
**Print this card** for quick reference during assessments!

