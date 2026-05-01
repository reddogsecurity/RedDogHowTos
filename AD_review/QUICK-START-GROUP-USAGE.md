# Quick Start: Group Usage Analysis

## What's New?

**New Script**: `Get-ElevatedGroupUsage.ps1`

Analyzes Active Directory groups with elevated permissions to identify:
- ✅ **Top 10 groups** not used in 90+ days (cleanup candidates)
- ✅ **Top 10 most active groups** (monitoring priorities)
- ✅ Usage patterns and activity metrics
- ✅ Risk assessment and recommendations

## 🚀 Quick Start (30 seconds)

### Run Basic Analysis
```powershell
.\Get-ElevatedGroupUsage.ps1
```

**What it does:**
- Analyzes all privileged/elevated groups
- Shows top 10 least used (inactive 90+ days)
- Shows top 10 most used (highest activity)
- Generates CSV and HTML reports

**Output files** (in current directory):
- `ElevatedGroupUsage-AllGroups-*.csv` - Complete analysis
- `ElevatedGroupUsage-Top10LeastUsed-*.csv` - Cleanup candidates
- `ElevatedGroupUsage-Top10MostUsed-*.csv` - Monitor these
- `ElevatedGroupUsage-Report-*.html` - Visual dashboard

## 📊 Understanding Results

### Top 10 Least Used Groups
**These are your cleanup candidates:**
```
GroupName: Legacy_Helpdesk_Admins
Days Inactive: 247
Usage Score: 0%
Risk: Critical
→ No one has used this in 8+ months - likely can be removed
```

### Top 10 Most Used Groups
**These need regular monitoring:**
```
GroupName: Domain Admins
Usage Score: 95%
Active Members: 4/4
Days Inactive: 1
→ Highly active - ensure membership is correct
```

## ⚡ Common Scenarios

### Scenario 1: Monthly Security Review
```powershell
.\Get-ElevatedGroupUsage.ps1
```
Open the HTML report → Review critical risk groups → Take action

### Scenario 2: Aggressive Cleanup (60-day threshold)
```powershell
.\Get-ElevatedGroupUsage.ps1 -DaysInactive 60 -Top 20
```
Get top 20 groups unused for 60+ days

### Scenario 3: Analyze All Security Groups
```powershell
.\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups
```
Not just privileged - analyze everything

### Scenario 4: Deep Dive with Nested Members
```powershell
.\Get-ElevatedGroupUsage.ps1 -IncludeNestedMembers
```
Include nested group memberships for accurate counts

## 🎯 Key Metrics Explained

### Usage Score (0-100%)
- **80-100%**: Highly active - monitor closely
- **50-79%**: Moderately active
- **25-49%**: Low activity - validate need
- **0-24%**: Minimal/no activity - consider removal

### Risk Levels
- **Critical**: 180+ days inactive - immediate review
- **High**: 90+ days inactive - validate business need
- **Medium**: 30+ days inactive - watch for trend
- **Low**: Active within 30 days - normal

## 📋 Quick Action Checklist

1. **Run the script**:
   ```powershell
   .\Get-ElevatedGroupUsage.ps1
   ```

2. **Open HTML report** (ElevatedGroupUsage-Report-*.html)

3. **Identify quick wins**:
   - Empty groups → Remove immediately
   - 180+ days inactive → High priority review
   - 90+ days inactive → Validate with owners

4. **Take action**:
   - Document business justification OR
   - Schedule group for removal

5. **Schedule monthly runs** for ongoing monitoring

## 🔄 Integration with Assessment Suite

**Automatic execution** with full assessment:
```powershell
.\Run-EnhancedAssessment.ps1
```

This now includes:
1. Expired password accounts
2. Password never expire analysis
3. Privileged group members
4. AD to Entra comparison
5. Schema permissions audit
6. **→ Group usage analysis** ← NEW!

## 🎬 Try the Demo

**Interactive demonstration:**
```powershell
.\Demo-GroupUsageAnalysis.ps1
```

Shows:
- Basic analysis
- Custom thresholds
- All groups analysis
- Quick critical scan

## 💡 Pro Tips

### Tip 1: Start Conservative
Begin with default 90-day threshold, then adjust based on environment

### Tip 2: Focus on Empty Groups First
Easy wins - no business justification needed

### Tip 3: Document Everything
Keep track of why groups exist before removing

### Tip 4: Test in Non-Prod First
Validate the script in test environment before production

### Tip 5: Schedule Regular Runs
Monthly automated analysis tracks trends over time

## ⚠️ What to Watch For

**Critical Findings:**
- Elevated groups with 180+ days inactivity
- Empty privileged groups
- Groups with all disabled members

**High Priority:**
- Elevated groups with 90+ days inactivity
- Groups with low usage scores (<25%)

**Medium Priority:**
- Groups with declining usage trends
- Groups with outdated descriptions/ownership

## 📈 Sample Use Case

**Problem**: Too many AD groups, unsure which are used

**Solution**:
```powershell
# 1. Run comprehensive analysis
.\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups -Top 20

# 2. Open HTML report
start ElevatedGroupUsage-Report-*.html

# 3. Export critical groups for review
$critical = Import-Csv "ElevatedGroupUsage-CriticalRisk-*.csv"
$critical | Out-GridView

# 4. Remove empty groups
$empty = Import-Csv "ElevatedGroupUsage-EmptyGroups-*.csv"
# (Validate with business, then remove)
```

**Result**: Clear prioritized list of cleanup candidates

## 🔍 Detailed Example Output

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

## 📚 More Information

- **Full documentation**: `GROUP-USAGE-ANALYSIS-README.md`
- **Demo script**: `Demo-GroupUsageAnalysis.ps1`
- **Main script**: `Get-ElevatedGroupUsage.ps1`

## 🎯 Next Steps

1. Run the script now
2. Review the HTML report
3. Identify 3-5 groups to remove
4. Document and execute cleanup
5. Schedule monthly automated runs

---

**Ready?** Let's start:
```powershell
cd AD_review
.\Get-ElevatedGroupUsage.ps1
```

Then open the HTML report that gets generated! 🚀



















