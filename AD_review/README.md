# Active Directory & Entra ID Security Assessment Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![GitHub issues](https://img.shields.io/github/issues/YOUR_USERNAME/AD-Security-Assessment-Tool)](https://github.com/YOUR_USERNAME/AD-Security-Assessment-Tool/issues)
[![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/AD-Security-Assessment-Tool?style=social)](https://github.com/YOUR_USERNAME/AD-Security-Assessment-Tool/stargazers)

## 📋 Project Overview

A comprehensive PowerShell-based security assessment tool for Active Directory and Entra ID (Azure AD) environments. Performs read-only data collection and automated security analysis to identify risks, suggest RBAC roles, and plan modernization efforts.

> **🎯 Perfect for:** Security audits, Zero Trust assessments, RBAC planning, GPO modernization, and compliance reporting.

---

## ✅ Completed Features

### Data Collection
- [x] **Active Directory**
  - Users (with logon history, delegation flags, password settings)
  - Groups (with member counts, nesting analysis)
  - Computers (with logon history, OS versions)
  - Domain Controllers and Forest information
  - GPOs and their link status
  - OU ACLs and delegation permissions
  - Service Principal Names (SPN accounts)
  - Privileged group membership
  - Password policies (default + fine-grained)
  - krbtgt password age tracking
  - Trust relationships

- [x] **Entra ID (Azure AD)**
  - Users (with sign-in activity)
  - Groups (security and Microsoft 365)
  - Directory roles and assignments
  - Service Principals and Enterprise Apps
  - Application registrations
  - Conditional Access policies
  - OAuth2 permission grants
  - App role assignments
  - Sign-in logs (last 100)
  - **Authentication methods (MFA coverage)**

### Automated Security Analysis
- [x] **Identity Hygiene**
  - Stale enabled accounts (>90 days inactive)
  - Password never expires flags
  - Kerberos delegation risks (user & computer)
  - Unconstrained delegation detection

- [x] **Privileged Access**
  - Entra role membership analysis
  - Global Administrator count warnings
  - AD privileged group tracking

- [x] **Zero Trust Readiness**
  - Conditional Access policy presence check
  - MFA coverage analysis (users without MFA)
  - Legacy authentication detection
  - OAuth admin consent review

- [x] **RBAC Planning**
  - Automatic user clustering by AD group membership
  - Seed role generation for Entra RBAC model
  - Export to `rbac-candidates-*.csv`

- [x] **GPO Modernization**
  - Unlinked GPO identification
  - Retirement/migration candidates
  - Export to `gpo-modernization-*.csv`

- [x] **Security Posture**
  - krbtgt password age alerts (>180 days = HIGH)
  - SPN/Kerberoasting surface assessment
  - Service principal risk analysis
  - OU delegation anomaly detection

### Reporting & Outputs
- [x] **HTML Summary Report**
  - Modern, styled UI with gradients and box shadows
  - KPI dashboard
  - Risk findings (prioritized High/Medium/Low)
  - RBAC seed roles with explanations
  - GPO modernization plan
  - Actionable "Next Steps" roadmap

- [x] **Analysis Artifacts** (CSV/JSON)
  - `risk-findings-*.csv` - Prioritized security findings
  - `rbac-candidates-*.csv` - Suggested RBAC roles
  - `gpo-modernization-*.csv` - GPO migration plan
  - `kpis-*.json` - Key performance indicators
  - Individual entity exports (users, groups, etc.)

---

## 🚀 Recent Improvements (Completed)

### v2.0 - Combined Script with Advanced Analysis
- ✅ Merged `script2.ps1` analysis engine into `script.ps1`
- ✅ Added MFA/authentication methods collection
- ✅ Enhanced Zero Trust readiness checks
- ✅ Implemented RBAC seed role clustering
- ✅ Added GPO modernization planning
- ✅ Created comprehensive HTML report with styling
- ✅ Improved risk prioritization (13 security rules)
- ✅ Added OAuth permission grant analysis
- ✅ Integrated KPI dashboard
- ✅ Single-execution workflow (collect → analyze → report)

---

## 📦 Requirements

### PowerShell Modules
- **ActiveDirectory** (RSAT) - For AD queries
- **Microsoft.Graph** sub-modules (for Entra, if using `-IncludeEntra`):
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Identity.DirectoryManagement`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Groups`
  - `Microsoft.Graph.Applications`
  - `Microsoft.Graph.Identity.SignIns`
  - `Microsoft.Graph.Reports`

### Permissions
- **Active Directory**: Domain User with read access (default)
- **Entra ID (Graph API)**:
  - `Directory.Read.All`
  - `Application.Read.All`
  - `Policy.Read.All`
  - `AuditLog.Read.All`
  - `UserAuthenticationMethod.Read.All`

### System Requirements
- PowerShell 5.1 or later
- Windows with RSAT installed (for AD collection)
- Internet connectivity (for Entra collection)

---

## 💻 Usage

### Basic AD-Only Assessment
```powershell
.\script.ps1
```

### Full AD + Entra Assessment
```powershell
.\script.ps1 -IncludeEntra
```

### Custom Output Location
```powershell
.\script.ps1 -IncludeEntra -OutputFolder "C:\Assessments\Client1"
```

### Review Results
1. Open the generated HTML summary: `summary-{timestamp}.html`
2. Review CSV artifacts for detailed analysis
3. Address High severity findings immediately
4. Plan remediation using the risk findings CSV

---

## 📊 Output Files

### Analysis Reports
- `summary-{timestamp}.html` - Comprehensive HTML report
- `risk-findings-{timestamp}.csv` - Prioritized security findings
- `rbac-candidates-{timestamp}.csv` - Suggested RBAC roles
- `gpo-modernization-{timestamp}.csv` - GPO migration plan
- `kpis-{timestamp}.json` - Key performance indicators

### Raw Data Exports
- `ad-users-{timestamp}.csv/json` - AD user inventory
- `ad-groups-{timestamp}.csv/json` - AD group inventory
- `ad-computers-{timestamp}.csv/json` - Computer inventory
- `ad-gpos-{timestamp}.csv` - GPO inventory
- `ad-spn-accounts-{timestamp}.csv` - SPN accounts
- `entra-users-{timestamp}.csv/json` - Entra user inventory
- `entra-role-assignments-{timestamp}.json` - Entra roles
- `entra-conditionalaccess-{timestamp}.json` - CA policies
- `entra-authmethods-{timestamp}.csv` - MFA coverage
- And many more...

---

## 🔮 Future Enhancements (Planned)

### High Priority
- [ ] **Privileged User MFA Cross-Check**
  - Join Entra role members with auth methods
  - Flag Global Admins without MFA specifically
  - Export privileged-users-without-mfa.csv

- [ ] **Password Policy Deep Analysis**
  - Compare AD default policy vs. NIST recommendations
  - Highlight weak FGPP configurations
  - Suggest policy improvements

- [ ] **App Secret/Certificate Expiration**
  - Parse app registration secrets and certificates
  - Alert on expired or soon-to-expire credentials (30/60/90 days)
  - Export app-credential-status.csv

### Medium Priority
- [ ] **Conditional Access Gap Analysis**
  - Check if CA policies cover all users/apps
  - Identify gaps in Zero Trust implementation
  - Suggest missing policies (e.g., MFA for all users, block legacy auth)

- [ ] **Historical Trending**
  - Re-run analysis on old exports
  - Track KPI changes over time
  - Generate trend charts

- [ ] **Privileged Identity Management (PIM) Analysis**
  - Identify eligible vs. permanent role assignments
  - Check for just-in-time access usage
  - Recommend PIM candidates

- [ ] **License Optimization**
  - Compare assigned licenses to usage
  - Identify unused licenses
  - Suggest license optimization

### Low Priority / Future Ideas
- [ ] **Azure Resource RBAC**
  - Extend to Azure subscription-level RBAC
  - Identify over-permissioned accounts

- [ ] **Compliance Mapping**
  - Map findings to compliance frameworks (CIS, NIST, ISO 27001)
  - Generate compliance gap reports

- [ ] **Automated Remediation Scripts**
  - Generate remediation scripts for common issues
  - Interactive remediation mode

- [ ] **Email Report Generation**
  - Send HTML report via email
  - Schedule automated assessments

- [ ] **PowerBI Dashboard**
  - Export to PowerBI-compatible format
  - Interactive visualization

---

## 🐛 Known Issues

- ⚠️ **Encoding Issues**: Avoid emojis and special characters in Write-Host strings (causes parsing errors)
- ⚠️ **Graph Module Limit**: Do not import full `Microsoft.Graph` module (exceeds PowerShell function limit)
- ⚠️ **Large Environments**: MFA collection limited to first 500 users (performance)
- ⚠️ **Permissions**: Some Entra features require admin consent on first run

---

## 📝 Changelog

### Version 2.0 (Current)
- Combined script.ps1 and script2.ps1 into single comprehensive tool
- Added MFA/authentication methods collection
- Implemented RBAC seed role clustering
- Added GPO modernization planning
- Enhanced HTML report with modern styling
- Added 13 automated security risk rules
- Improved error handling and logging

### Version 1.0
- Initial AD and Entra data collection
- Basic HTML summary report
- Individual entity exports (CSV/JSON)
- Simple risk analysis

---

## 👥 Contributing

### Adding New Risk Rules
Edit the `Analyze-Inventory` function (lines ~360-481):
```powershell
# Add your custom rule
if ($yourCondition) {
    $findings.Add([pscustomobject]@{
        Area='Your Area'; 
        Finding='Your finding description'; 
        Severity='High|Medium|Low'; 
        Evidence='source-file-reference'
    })
}
```

### Adding New Data Collection
1. Add collection code in `Collect-ADInventory` or `Collect-EntraInventory`
2. Export using `Write-OutputFiles -Name "entity-name" -Object $data`
3. Update `Analyze-Inventory` to load and analyze the new data

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Disclaimer**: This tool is provided "as is" without warranty of any kind. Use at your own risk in compliance with your organization's security and privacy policies.

---

## 🆘 Support

For issues or questions:
1. Check the [Known Issues](#-known-issues) section
2. Review PowerShell error messages
3. Ensure all required modules are installed
4. Verify Graph API permissions are consented

---

## 📚 References

- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/)
- [Active Directory PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)
- [Azure AD/Entra ID Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)
- [Zero Trust Security Model](https://learn.microsoft.com/en-us/security/zero-trust/)

---

**Last Updated**: October 6, 2025  
**Status**: ✅ Production Ready  
**License**: MIT

