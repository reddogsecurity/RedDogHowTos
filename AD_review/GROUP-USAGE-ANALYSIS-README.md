# Elevated Group Usage Analysis

## Overview

The **Get-ElevatedGroupUsage.ps1** script provides comprehensive analysis of Active Directory groups with elevated permissions, focusing on usage patterns to identify security risks and cleanup opportunities.

## Purpose

This tool helps you:
- **Identify unused elevated groups** that may pose security risks
- **Find the most active groups** that require regular monitoring
- **Discover empty groups** that should be removed
- **Assess usage patterns** based on member activity
- **Prioritize cleanup efforts** with risk-based scoring

## Key Features

### 1. Intelligent Group Discovery
- Automatically identifies elevated/privileged groups
- Checks `AdminCount` attribute for privileged groups
- Uses configurable privileged group list
- Keyword-based detection for admin-related groups
- Optional analysis of all security groups

### 2. Usage Metrics
- **Last Activity Date**: When any member last logged on
- **Days Since Last Activity**: Age of most recent activity
- **Active Member Count**: Members active within threshold
- **Inactive Member Count**: Members beyond threshold
- **Disabled Member Count**: Disabled accounts still in group
- **Usage Score (0-100%)**: Calculated activity metric

### 3. Risk Assessment
- **Critical**: 180+ days of inactivity
- **High**: 90+ days of inactivity
- **Medium**: 30+ days of inactivity
- **Low**: Active within 30 days

### 4. Comprehensive Reporting
- CSV exports for data analysis
- Interactive HTML dashboard
- Top N least used groups (cleanup candidates)
- Top N most used groups (monitoring priorities)
- Empty group inventory
- Critical risk group highlighting

## Usage Examples

### Basic Analysis (Recommended Start)
```powershell
.\Get-ElevatedGroupUsage.ps1
```
This analyzes all privileged/elevated groups with default settings:
- 90-day inactivity threshold
- Top 10 groups in each category
- CSV and HTML reports in current directory

### Custom Threshold
```powershell
.\Get-ElevatedGroupUsage.ps1 -DaysInactive 60 -Top 15
```
More aggressive analysis:
- 60-day inactivity threshold
- Top 15 groups in each category

### Comprehensive Analysis
```powershell
.\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups -IncludeNestedMembers
```
Most thorough analysis:
- Analyzes ALL security groups (not just privileged)
- Includes nested group memberships
- **Note**: May take 10-30 minutes in large environments

### Quick Critical Scan
```powershell
.\Get-ElevatedGroupUsage.ps1 -DaysInactive 180 -Top 5
```
Fast scan for severe issues:
- Only groups with 180+ days inactivity
- Top 5 most critical groups

### Custom Output Location
```powershell
.\Get-ElevatedGroupUsage.ps1 -OutputFolder "C:\SecurityAudits\GroupUsage"
```
Organize reports in specific location

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `OutputFolder` | String | Current directory | Where to save reports |
| `IncludeNestedMembers` | Switch | False | Recursively enumerate nested group members |
| `Top` | Integer | 10 | Number of top/bottom groups to report |
| `DaysInactive` | Integer | 90 | Days to consider a group inactive |
| `IncludeAllGroups` | Switch | False | Analyze all security groups, not just elevated |

## Understanding the Reports

### 1. ElevatedGroupUsage-AllGroups-*.csv
Complete inventory of all analyzed groups with metrics:
- Group name and description
- Elevation status
- Member counts (users, groups, computers)
- Activity metrics
- Usage score
- Risk level
- Recommendations

### 2. ElevatedGroupUsage-Top10LeastUsed-*.csv
Groups with the least activity (cleanup candidates):
- Sorted by days since last activity (descending)
- Focus on groups with no recent activity
- Candidates for removal or archival

### 3. ElevatedGroupUsage-Top10MostUsed-*.csv
Groups with the most activity (monitoring priorities):
- Sorted by usage score (descending)
- Active groups that need regular audits
- Ensure proper membership and permissions

### 4. ElevatedGroupUsage-EmptyGroups-*.csv
Groups with no members:
- Low-hanging fruit for cleanup
- Reduces attack surface
- Simplifies AD structure

### 5. ElevatedGroupUsage-CriticalRisk-*.csv
Groups with 180+ days inactivity:
- Highest priority for review
- Potential security risks
- Immediate action recommended

### 6. ElevatedGroupUsage-Report-*.html
Visual dashboard with:
- Summary statistics
- Color-coded risk levels
- Interactive tables
- Usage score visualization
- Actionable recommendations

## Usage Score Calculation

The Usage Score (0-100%) is calculated as follows:

```
Base Score = (Active Members / Total Members) × 100

Bonus Points:
  +20 if any member active within 30 days
  +10 if any member active within 60 days

Final Score = Min(100, Base Score + Bonus)
```

**Interpretation:**
- **80-100%**: Highly active group - monitor closely
- **50-79%**: Moderately active - regular reviews
- **25-49%**: Low activity - validate business need
- **0-24%**: Minimal/no activity - consider removal

## Integration with Enhanced Assessment

This script is automatically included when you run:

```powershell
.\Run-EnhancedAssessment.ps1
```

The group usage analysis runs as part of the complete security assessment suite, alongside:
- Expired password accounts
- Password never expire analysis
- Privileged group member enumeration
- AD to Entra comparison
- Schema permissions audit

## Use Cases

### 1. Security Audits
**Scenario**: Annual security review
**Approach**: 
```powershell
.\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups
```
**Action**: Review critical risk groups, validate elevated group necessity

### 2. Compliance Reporting
**Scenario**: PCI-DSS, SOC 2, or ISO 27001 audit
**Approach**: 
```powershell
.\Get-ElevatedGroupUsage.ps1 -DaysInactive 90
```
**Action**: Document group usage, demonstrate access review process

### 3. AD Cleanup Project
**Scenario**: Reducing AD clutter and attack surface
**Approach**: 
```powershell
.\Get-ElevatedGroupUsage.ps1 -DaysInactive 60 -Top 20
```
**Action**: Remove empty groups, archive inactive groups

### 4. Privileged Access Review
**Scenario**: Quarterly privileged access review
**Approach**: 
```powershell
.\Get-ElevatedGroupUsage.ps1
```
**Action**: Validate elevated group membership, remove unused elevated groups

### 5. Incident Response
**Scenario**: Investigating potential privilege escalation
**Approach**: 
```powershell
.\Get-ElevatedGroupUsage.ps1 -IncludeNestedMembers
```
**Action**: Identify all paths to elevated access, audit recent changes

## Best Practices

### Regular Execution
- **Monthly**: Run basic analysis to track trends
- **Quarterly**: Run comprehensive analysis with nested members
- **Annually**: Full security review with all groups

### Thresholds
- **90 days**: Standard inactivity threshold
- **60 days**: More aggressive for high-security environments
- **180 days**: Critical risk threshold for immediate action

### Remediation Workflow
1. **Week 1**: Run analysis, review reports
2. **Week 2**: Validate findings with group owners
3. **Week 3**: Remove empty groups, disable inactive groups
4. **Week 4**: Archive or delete confirmed unused groups
5. **Month 2**: Monitor for issues, document changes

### Group Removal Process
1. **Identify** unused group from report
2. **Validate** with business owners
3. **Document** business justification or removal approval
4. **Disable** group (change to distribution group or move to quarantine OU)
5. **Wait** 30 days for any issues to surface
6. **Remove** if no issues reported

## Troubleshooting

### Script Runs Slowly
**Problem**: Analysis takes too long
**Solutions**:
- Remove `-IncludeAllGroups` flag (analyze only elevated groups)
- Remove `-IncludeNestedMembers` flag
- Use `-Top 5` to reduce processing
- Run during off-hours

### No Groups Found
**Problem**: Report shows 0 groups
**Solutions**:
- Ensure you have read permissions to AD
- Check if `AdminCount` attribute is set correctly
- Use `-IncludeAllGroups` to see all security groups
- Verify AD PowerShell module is installed

### Inaccurate Last Logon Data
**Problem**: Last logon times seem incorrect
**Solutions**:
- Last logon data is based on `lastLogonTimestamp` (replicated, ~14 day delay)
- For real-time data, query `lastLogon` (requires DC enumeration)
- Consider data as "best effort" approximation

### Missing Groups
**Problem**: Expected groups not in report
**Solutions**:
- Check if group is a Distribution Group (script only analyzes Security Groups)
- Verify group exists: `Get-ADGroup -Identity "GroupName"`
- Use `-IncludeAllGroups` to see all groups

## Security Considerations

### Permissions Required
- **Minimum**: Domain Users (read access to AD)
- **Recommended**: Domain Admins (to see all groups)
- **Note**: Cannot enumerate groups you don't have read permissions for

### Data Sensitivity
Reports contain:
- Group names and descriptions
- Member counts
- Activity patterns
- Elevated group identification

**Protection**:
- Store reports in secure location
- Restrict access to security/IT teams only
- Consider data classification requirements
- Delete old reports per retention policy

### Operational Impact
- **Network**: Minimal (read-only LDAP queries)
- **DC Load**: Low to moderate depending on scope
- **Duration**: 5-30 minutes depending on parameters
- **Recommended**: Run during maintenance windows for large environments

## Integration with Other Tools

### PowerShell Scripts
```powershell
# Import results into another script
$results = Import-Csv "ElevatedGroupUsage-AllGroups-*.csv"
$criticalGroups = $results | Where-Object { $_.RiskLevel -eq "Critical" }
```

### Excel Analysis
- Open CSV files in Excel
- Create pivot tables for trend analysis
- Graph usage scores over time
- Compare monthly reports

### SIEM Integration
- Export CSV to SIEM for correlation
- Alert on new elevated groups
- Track group membership changes
- Monitor usage score trends

### Automation
```powershell
# Scheduled task example
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Get-ElevatedGroupUsage.ps1 -OutputFolder C:\Reports"
Register-ScheduledTask -TaskName "Weekly Group Usage Analysis" `
    -Trigger $trigger -Action $action
```

## Sample Output Interpretation

### Example: Critical Finding
```
Group: Legacy_Admin_Group
Days Inactive: 245
Usage Score: 0%
Risk Level: Critical
Recommendation: CRITICAL: No activity in 180+ days - Review for removal
```
**Action**: Immediate review required, likely candidate for removal

### Example: Active Group
```
Group: Domain Admins
Days Inactive: 2
Usage Score: 95%
Active Members: 3/3
Risk Level: Low
Recommendation: Active group - Monitor regularly
```
**Action**: Ensure membership is correct, continue regular audits

### Example: Empty Group
```
Group: Old_Project_Admins
Members: 0
Usage Score: 0%
Recommendation: Empty group - consider removal
```
**Action**: Remove if no longer needed

## Frequently Asked Questions

**Q: How often should I run this analysis?**
A: Monthly for monitoring, quarterly for comprehensive reviews

**Q: What's a good usage score threshold?**
A: Below 25% warrants investigation, 0% for 90+ days should be removed

**Q: Can I analyze non-security groups?**
A: No, script only analyzes Security Groups (Distribution Groups excluded)

**Q: Does this modify any groups?**
A: No, this is read-only analysis. No changes are made to AD.

**Q: How accurate is the activity data?**
A: Based on `lastLogonTimestamp` which has ~14 day replication delay

**Q: Can I customize the privileged groups list?**
A: Yes, edit the `$privilegedGroups` array in the script

**Q: What if a group has no user members?**
A: Groups with only group/computer members show 0% usage score

**Q: How do I handle service account groups?**
A: Service accounts may show low usage but are still necessary - validate business need

## Next Steps

1. **Run the demo script**:
   ```powershell
   .\Demo-GroupUsageAnalysis.ps1
   ```

2. **Review the HTML report** in your browser

3. **Start with quick wins**: Remove empty groups

4. **Plan remediation**: Work with business owners on inactive groups

5. **Schedule regular scans**: Set up monthly automated runs

6. **Integrate with assessment suite**: Use Run-EnhancedAssessment.ps1

## Support and Feedback

This script is part of the AD Security Assessment toolkit. For issues or enhancements:
- Review the script comments for detailed function documentation
- Check the CHANGELOG.md for recent updates
- Refer to NEW-FEATURES-GUIDE.md for related features

## Version History

- **v1.0** (2025-12-03): Initial release
  - Elevated group discovery
  - Usage metrics and scoring
  - Risk assessment
  - Top N reporting
  - HTML dashboard
  - Integration with enhanced assessment

---

**Author**: AD Security Assessment Tool
**Last Updated**: December 3, 2025
**Script**: Get-ElevatedGroupUsage.ps1



















