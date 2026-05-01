# 🎉 New Feature: Elevated Group Usage Analysis

## Summary

I've added comprehensive group usage analysis capabilities to your AD Security Assessment toolkit. This new feature helps you identify unused elevated groups and prioritize which groups to monitor or remove.

---

## 📦 What Was Added

### 1. Main Analysis Script
**File:** `Get-ElevatedGroupUsage.ps1` (682 lines)

A comprehensive PowerShell script that:
- ✅ Collects all groups with elevated permissions
- ✅ Analyzes usage patterns based on member activity
- ✅ Identifies **top 10 groups NOT used in 90+ days** (cleanup candidates)
- ✅ Identifies **top 10 MOST used groups** (monitoring priorities)
- ✅ Generates detailed CSV and HTML reports
- ✅ Provides risk assessment and recommendations

### 2. Demo Script
**File:** `Demo-GroupUsageAnalysis.ps1`

Interactive demonstration showing:
- Basic privileged group analysis
- Custom threshold configuration (60 days, 180 days)
- All groups analysis with nested members
- Quick scan for immediate issues

### 3. Documentation
**Files:**
- `GROUP-USAGE-ANALYSIS-README.md` - Complete documentation (600+ lines)
- `QUICK-START-GROUP-USAGE.md` - Quick start guide

### 4. Integration
**Modified:** `Run-EnhancedAssessment.ps1`
- Added group usage analysis as step 6
- Updated output file listing
- Enhanced critical findings section
- Added recommendations

**Modified:** `README.md`
- Added new "Enhanced Assessment Scripts" section
- Updated version to 2.4
- Documented new feature

---

## 🎯 Key Capabilities

### Usage Metrics
- **Last Activity Date**: When any group member last logged on
- **Days Since Last Activity**: Age of most recent activity
- **Active Member Count**: Members active within threshold (default 90 days)
- **Inactive Member Count**: Members beyond threshold
- **Disabled Member Count**: Disabled accounts still in group
- **Usage Score (0-100%)**: Calculated activity metric

### Risk Assessment
- **Critical**: 180+ days of inactivity
- **High**: 90+ days of inactivity
- **Medium**: 30+ days of inactivity
- **Low**: Active within 30 days

### Reports Generated
1. **All Groups CSV** - Complete analysis with all metrics
2. **Top 10 Least Used CSV** - Cleanup candidates (90+ days inactive)
3. **Top 10 Most Used CSV** - Monitoring priorities (highest activity)
4. **Empty Groups CSV** - Groups with no members
5. **Critical Risk CSV** - Groups with 180+ days inactivity
6. **HTML Dashboard** - Interactive visual report with color coding

---

## 🚀 How to Use

### Quickest Start (30 seconds)
```powershell
cd AD_review
.\Get-ElevatedGroupUsage.ps1
```

Then open the generated HTML file: `ElevatedGroupUsage-Report-*.html`

### Common Scenarios

#### Monthly Security Review
```powershell
.\Get-ElevatedGroupUsage.ps1
```
Review the HTML report → Identify critical groups → Take action

#### Aggressive Cleanup (60-day threshold)
```powershell
.\Get-ElevatedGroupUsage.ps1 -DaysInactive 60 -Top 20
```
Get top 20 groups unused for 60+ days

#### Comprehensive Analysis (All Groups)
```powershell
.\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups -IncludeNestedMembers
```
Analyze all security groups with nested membership (takes longer)

#### Part of Full Assessment
```powershell
.\Run-EnhancedAssessment.ps1
```
Now automatically includes group usage analysis

---

## 📊 Sample Output

### Console Summary
```
========================================
ANALYSIS SUMMARY
========================================

Groups Analyzed: 47
  - Elevated Groups: 18
  - Groups with Members: 42
  - Empty Groups: 5

Activity Status:
  - Active Groups (Score > 50%): 15
  - Inactive Groups (90+ days): 12

Risk Assessment:
  - Critical Risk (180+ days): 3
  - High Risk (90+ days): 9

[!] Top 3 Least Used Groups:
    • Legacy_Admin_2019: 312 days inactive (Usage: 0%)
    • Old_Project_Team: 245 days inactive (Usage: 0%)
    • Temp_Helpdesk_2023: 156 days inactive (Usage: 5%)

[✓] Top 3 Most Used Groups:
    • Domain Admins: Usage Score 98% (4/4 active users)
    • Enterprise Admins: Usage Score 95% (2/2 active users)
    • Backup Operators: Usage Score 87% (3/4 active users)
```

### HTML Report Features
- Summary statistics dashboard with gradient cards
- Color-coded risk levels (red/yellow/green)
- Usage score badges (high/medium/low)
- Elevated group badges
- Sortable tables
- Actionable recommendations
- Responsive design

---

## 💡 Use Cases

### 1. Security Audits
**Problem**: Need to identify security risks from unused elevated groups
**Solution**: Run analysis to find groups with 90+ days of inactivity
**Benefit**: Reduce attack surface by removing unused elevated access

### 2. Compliance Reporting
**Problem**: Need to demonstrate regular access reviews (PCI-DSS, SOC 2, ISO 27001)
**Solution**: Monthly automated runs with historical tracking
**Benefit**: Documentation for auditors showing due diligence

### 3. AD Cleanup Projects
**Problem**: Too many AD groups, unclear which are needed
**Solution**: Analyze all groups to prioritize cleanup efforts
**Benefit**: Focus on empty groups and 180+ day inactive groups first

### 4. Privileged Access Reviews
**Problem**: Quarterly review of elevated access required
**Solution**: Run analysis on elevated groups specifically
**Benefit**: Clear prioritized list with usage metrics

### 5. Risk Assessment
**Problem**: Need to quantify security posture
**Solution**: Track usage scores and risk levels over time
**Benefit**: Measurable improvement metrics

---

## 🎓 Key Concepts

### Usage Score Calculation
```
Base Score = (Active Members / Total Members) × 100

Bonus Points:
  +20 if any member active within 30 days
  +10 if any member active within 60 days

Final Score = Min(100, Base Score + Bonus)
```

**Interpretation:**
- **80-100%**: Highly active - monitor closely
- **50-79%**: Moderately active - regular reviews
- **25-49%**: Low activity - validate business need
- **0-24%**: Minimal/no activity - consider removal

### Elevated Group Detection
Groups are considered "elevated" if they meet any of these criteria:
1. In the predefined privileged groups list (Domain Admins, Enterprise Admins, etc.)
2. Have `AdminCount` attribute set to 1
3. Name contains admin/privileged keywords

### Activity Metrics
- Based on `lastLogonTimestamp` AD attribute
- Has ~14 day replication delay (acceptable for this analysis)
- Considers all user members, not just direct members (if `-IncludeNestedMembers` used)
- Ignores disabled accounts in usage calculation

---

## 📋 Files Created

```
AD_review/
├── Get-ElevatedGroupUsage.ps1              # Main analysis script (682 lines)
├── Demo-GroupUsageAnalysis.ps1             # Interactive demo script
├── GROUP-USAGE-ANALYSIS-README.md          # Full documentation
├── QUICK-START-GROUP-USAGE.md              # Quick start guide
├── NEW-GROUP-USAGE-FEATURE.md              # This file
├── Run-EnhancedAssessment.ps1              # Updated with new feature
└── README.md                                # Updated main README
```

---

## 🔄 Integration Points

### With Existing Scripts
- **Run-EnhancedAssessment.ps1**: Now includes group usage as step 6
- **Get-PrivilegedGroupMembers.ps1**: Complements with member-focused analysis
- **Compare-ADtoEntraUsers.ps1**: Can correlate with cloud sync status

### With Reporting
- CSV exports compatible with existing report formats
- HTML follows same design patterns as other reports
- Can be imported into Excel for further analysis

### With Automation
- Ready for scheduled task execution
- Consistent parameter structure
- Error handling for unattended runs

---

## ⚙️ Parameters Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `OutputFolder` | String | Current dir | Where to save reports |
| `IncludeNestedMembers` | Switch | False | Recursively enumerate nested groups |
| `Top` | Integer | 10 | Number of top/bottom groups to report |
| `DaysInactive` | Integer | 90 | Days to consider inactive |
| `IncludeAllGroups` | Switch | False | Analyze all security groups |

---

## 🎯 Next Steps

### Immediate Actions
1. **Try the demo**:
   ```powershell
   .\Demo-GroupUsageAnalysis.ps1
   ```

2. **Run basic analysis**:
   ```powershell
   .\Get-ElevatedGroupUsage.ps1
   ```

3. **Review the HTML report** - Open in browser for best experience

### Short-term (This Week)
1. Identify and remove empty groups (quick wins)
2. Review critical risk groups (180+ days inactive)
3. Validate business need for high-risk groups (90+ days)
4. Document findings and remediation plan

### Long-term (This Month)
1. Set up scheduled monthly runs
2. Establish baseline metrics
3. Implement access review process
4. Track improvement over time

---

## 📚 Documentation Index

- **Quick Start**: `QUICK-START-GROUP-USAGE.md`
- **Full Documentation**: `GROUP-USAGE-ANALYSIS-README.md`
- **Main README**: `README.md` (updated with new feature)
- **Demo Script**: `Demo-GroupUsageAnalysis.ps1`
- **This Summary**: `NEW-GROUP-USAGE-FEATURE.md`

---

## ✅ Quality Assurance

### Code Quality
- ✅ 682 lines of well-documented PowerShell
- ✅ Comprehensive error handling
- ✅ Progress indicators for long operations
- ✅ Follows existing toolkit patterns
- ✅ Compatible with PowerShell 5.1+

### Testing Considerations
- Test in non-production first
- Verify permissions (requires AD read access)
- Allow 5-30 minutes for large environments
- Check HTML report renders correctly in browser

### Security
- ✅ Read-only operations (no AD modifications)
- ✅ Requires minimal permissions
- ✅ Reports contain sensitive data - store securely
- ✅ No credentials stored or transmitted

---

## 🤝 Support

### Troubleshooting
- **Script runs slowly**: Remove `-IncludeAllGroups` or `-IncludeNestedMembers`
- **No groups found**: Check permissions and use `-IncludeAllGroups`
- **Inaccurate data**: Remember 14-day replication delay for lastLogonTimestamp

### Documentation
- Read `GROUP-USAGE-ANALYSIS-README.md` for detailed information
- Check `QUICK-START-GROUP-USAGE.md` for quick reference
- See examples in `Demo-GroupUsageAnalysis.ps1`

---

## 📈 Benefits

### Security
- ✅ Reduce attack surface by removing unused elevated groups
- ✅ Identify and remediate stale privileged access
- ✅ Prioritize monitoring on active elevated groups

### Compliance
- ✅ Document regular access reviews
- ✅ Demonstrate due diligence
- ✅ Provide audit trail of group usage

### Efficiency
- ✅ Automated analysis vs. manual review
- ✅ Prioritized action list
- ✅ Clear recommendations
- ✅ Time savings: Hours → Minutes

### Risk Management
- ✅ Quantifiable metrics (usage scores)
- ✅ Risk-based prioritization
- ✅ Track improvement over time
- ✅ Executive-ready reporting

---

## 🎉 Summary

You now have a powerful new tool to:
- **Identify** unused elevated groups
- **Prioritize** cleanup efforts
- **Monitor** active elevated groups
- **Report** on group usage patterns
- **Reduce** security risk

**Ready to start?**
```powershell
cd AD_review
.\Get-ElevatedGroupUsage.ps1
```

Then open the HTML report and enjoy! 🚀

---

**Feature Added**: December 3, 2025  
**Version**: 2.4  
**Author**: AD Security Assessment Tool Enhancement



















