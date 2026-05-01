# Complete Walkthrough: AD Security Assessment Tool v3.0

## 🎯 **End-to-End Usage Guide**

This walkthrough demonstrates **all 8 major features** added in v3.0.

---

## 🚀 **Step-by-Step: Using All Features**

### **Step 1: Navigate to Project Folder**
```powershell
cd C:\Users\reddog\Projects\Projects\AD_review
```

### **Step 2: Run Complete Assessment**
```powershell
# First month (baseline)
.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\Assessments\2025-10"
```

**What Happens:**
```
========================================
Starting Black-Box Security Assessment
========================================

Collecting Active Directory inventory...
  Found 1,250 users - collecting details...
  ✓ Collected 1,250 users
Enumerating groups...
  ✓ Collected 456 groups
Enumerating computers...
  ✓ Collected 892 computers
...
Active Directory collection complete.

Collecting Entra (Azure AD) inventory...
Enumerating Entra users...
  ✓ Collected 1,180 users
Collecting authentication methods (MFA coverage)...
  Processing 500 users for MFA status...
    Progress: 10% (50/500 users)
    Progress: 20% (100/500 users)
    ...
  ✓ Collected MFA status for 500 users
Collecting service principal credentials...
  Processing 120 service principals...
    Progress: 10% (12/120 SPs)
    ...
  ✓ Collected credentials for 120 service principals
...
Entra collection complete.

Analyzing collected inventory...

Enriching findings with MITRE ATT&CK mappings...
  ✓ Enriched 24 findings with MITRE mappings

Generating MITRE category reports...
  ✓ Security Categories: 6
  ✓ MITRE Tactics: 8
  ✓ Findings with MITRE mapping: 24/24

Analyzing Conditional Access policy coverage...
  Found 12 CA policies (8 enabled, 4 report-only)

Conditional Access Gap Analysis Results:
  Total Policies: 12
  Enabled: 8
  User Coverage: 92.5%
  
  Baseline Policies:
    MFA for all users: ✓
    Block legacy auth: ✗
    Device compliance: ✓
    Admin MFA: ✓
  
  Gap Analysis:
    Missing baselines: 1
    Total gaps found: 3

========================================
Visual Diagram Generation
========================================

[1/4] Generating Privileged Access Map...
Privileged Access Map completed:
  - Users: 12
  - Users without MFA: 3
  - AD Groups: 4
  - Entra Roles: 6
  - Total Relationships: 22

[2/4] Generating GPO Topology Diagram...
GPO Topology diagram completed:
  - GPOs: 25
  - OUs: 15
  - Links: 38

[3/4] Generating Trust Map Diagram...
ℹ️  No domain trusts found. Skipping Trust Map.

[4/4] Generating App & Grant Views Diagram...
App & Grant Views diagram completed:
  - Service Principals: 45
  - OAuth Scopes: 12
  - Grants: 67

========================================
Assessment Complete!
========================================
```

### **Step 3: Review HTML Report**
```powershell
# Open the generated report
Invoke-Item "C:\Assessments\2025-10\summary-*.html"
```

**In Your Browser:**
1. **Top Section**: Executive Summary dashboard
   - Total Findings: 24
   - High Severity: 8 (red)
   - Medium Severity: 12 (yellow)
   - Low Severity: 4 (green)
   - AD Users: 1,250
   - Entra Users: 1,180

2. **Top-Right Corner**: Dark mode toggle 🌙
   - Click to switch themes
   - Preference saved automatically

3. **Risk Findings Table**: Now includes MITRE columns
   - MITRETechniques
   - SecurityCategory
   - RiskScore
   - BusinessImpact

4. **Remediation Playbook**: Editable cells
   - Click "Owner" to assign
   - Click "Due Date" to set deadline
   - Track status (Open → In Progress → Completed)

### **Step 4: Explore Visual Diagrams**
```powershell
# View all PNG diagrams
Get-ChildItem "C:\Assessments\2025-10" -Filter "*.png" | ForEach-Object {
    Invoke-Item $_.FullName
}
```

**Privileged Access Map**:
- Look for 🔴⚠️ nodes (users without MFA)
- Trace paths: User → Group → Role
- Identify excessive privileged access

**GPO Topology**:
- Red folders = unlinked GPOs (retire)
- Orange = many links (review)
- Dashed arrows = delegations (risky)

**App & Grant Views**:
- Red triangles = high-risk service principals
- Red diamonds = dangerous OAuth scopes
- Thick arrows = application permissions

### **Step 5: Review Gap Analysis**
```powershell
# View CA gaps
Import-Csv "C:\Assessments\2025-10\ca-gap-analysis-*.csv" | Format-Table -AutoSize
```

**Output:**
```
Area                    Gap                                          Severity  Recommendation
----                    ---                                          --------  --------------
Zero Trust Baseline     No policy blocking legacy authentication     High      Create CA policy: Block legacy auth
Identity Protection     No sign-in risk-based policies              Medium    Create CA policy: Require MFA for medium/high risk
Business Continuity     No break-glass accounts detected            Medium    Create 2-3 break-glass accounts
```

### **Step 6: Analyze MITRE Mapping**
```powershell
# View findings by tactic
Import-Csv "C:\Assessments\2025-10\findings-by-mitre-tactic-*.csv" | Format-Table -AutoSize
```

**Output:**
```
Tactic                  FindingCount  HighSeverity  Techniques
------                  ------------  ------------  ----------
Initial Access          8             5             T1078, T1110, T1566
Credential Access       6             4             T1558, T1110, T1078
Lateral Movement        4             3             T1558.003, T1550.003
Persistence             3             2             T1098, T1558.001
Privilege Escalation    2             1             T1484, T1098
```

### **Step 7: Review Security Categories**
```powershell
# View findings by security category
Import-Csv "C:\Assessments\2025-10\findings-by-security-category-*.csv" | Format-Table -AutoSize
```

**Output:**
```
Category                           Count  TotalRiskScore  HighSeverity
--------                           -----  --------------  ------------
Lateral Movement Prevention        5      42              4
Credential Protection             4      30              3
Attack Surface Reduction          6      28              2
Privileged Access Management      5      25              3
Data Protection                   2      12              0
Modernization                     2      8               0
```

---

## 📈 **Step 8: Next Month - Track Trends**

### **One Month Later**
```powershell
.\script.ps1 `
    -IncludeEntra `
    -GenerateDiagrams `
    -OutputFolder "C:\Assessments\2025-11" `
    -CompareWith "C:\Assessments\2025-10"
```

**New Output:**
```
Analyzing historical trends...
  Current: C:\Assessments\2025-11\kpis-20251107-120000.json
  Previous: C:\Assessments\2025-10\kpis-20251007-120000.json

Historical Trend Analysis:
  Comparing: 2025-10 → 2025-11
  Total KPIs tracked: 32
  Improvements: 18
  Regressions: 3
  Unchanged: 11
  Improvement Rate: 56.3%
  
  Top Improvements:
    • MFARegistered: 950 → 1,100 (+15.8%)
    • SPCredentialsExpired: 12 → 2 (-83.3%)
    • CABaselinesLegacyAuthBlocked: False → True (NEW POLICY!)
    
  ⚠️  Areas Needing Attention:
    • UsersWithoutMFA: 50 → 62 (+24.0%)
    • HighSeverityFindings: 8 → 10 (+25.0%)
```

### **View Trend Details**
```powershell
Import-Csv "C:\Assessments\2025-11\trend-analysis-*.csv" | 
    Select-Object KPI, PreviousValue, CurrentValue, Delta, Trend, Interpretation |
    Format-Table -AutoSize -Wrap
```

---

## 🎯 **Feature-by-Feature Demo**

### **Feature 1: MITRE ATT&CK Mapping**

**Before:**
```csv
Finding,Severity
"5 users without MFA",High
```

**After (v3.0):**
```csv
Finding,Severity,MITRETechniques,MITRETactics,SecurityCategory,RiskScore,BusinessImpact
"5 users without MFA",High,"T1078, T1110, T1566","Initial Access, Credential Access","Credential Protection",8,High
```

**Value**: Instant threat intelligence mapping

---

### **Feature 2: CA Gap Analysis**

**Command:**
```powershell
# Automatically runs when -IncludeEntra is used
```

**Reports:**
- Missing baseline policies
- User coverage %
- Policy inventory
- Break-glass account check

**Example Gap:**
```
No policy blocking legacy authentication
→ Recommendation: Create CA policy: Block Exchange ActiveSync, Other Clients for All Users
```

---

### **Feature 3: Visual Diagrams**

**Before**: Staring at CSV files trying to understand relationships  
**After**: Professional diagram showing privileged access paths

**Example Use:**
```
Security Team: "How many admins don't have MFA?"
You: "Here's a diagram - see the 3 red nodes with ⚠️ symbols? Those are Global Admins without MFA."
```

**Impact**: Instant visual understanding

---

### **Feature 4: Dark Mode**

**How to Use:**
1. Open HTML report
2. Click 🌙 button (top-right)
3. Theme switches instantly
4. Preference saved automatically

**Why It Matters:**
- Easier on eyes during late-night security reviews
- Professional look
- Accessibility improvement

---

### **Feature 5: Trend Tracking**

**First Month**: Establish baseline
```powershell
.\script.ps1 -IncludeEntra -OutputFolder "C:\Baseline"
```

**Second Month**: Track improvements
```powershell
.\script.ps1 -IncludeEntra -OutputFolder "C:\Month2" -CompareWith "C:\Baseline"
```

**Result**: See exactly what improved and what got worse

**Example:**
- MFA adoption: 70% → 85% ✅ (+15% improvement!)
- High severity findings: 12 → 8 ✅ (-33% reduction!)

---

### **Feature 6: Executive Summary**

**Before**: Long tables of data  
**After**: Dashboard with 6 key metrics

**Metrics Shown:**
- Total Findings (with severity breakdown)
- AD Users count
- Entra Users count
- All prominently displayed in grid

**Perfect for**: Executive presentations, board meetings

---

### **Feature 7: Progress Indicators**

**Before**: Script appears frozen for minutes  
**After**: Clear progress updates

**Example:**
```
Collecting authentication methods (MFA coverage)...
  Processing 500 users for MFA status...
    Progress: 10% (50/500 users)
    Progress: 20% (100/500 users)
    Progress: 30% (150/500 users)
    ...
  ✓ Collected MFA status for 500 users
```

**Impact**: Users know script is working, estimate completion time

---

### **Feature 8: Print-Friendly Output**

**How to Use:**
1. Open HTML report
2. Browser → Print (Ctrl+P)
3. Save as PDF

**What's Optimized:**
- White background (no ink waste)
- Proper page breaks
- Black text on white
- No decorative elements
- Links visible and underlined

**Result**: Professional PDF for physical distribution

---

## 🎓 **Advanced Usage**

### **Combine All Features**
```powershell
# Ultimate assessment command
.\script.ps1 `
    -IncludeEntra `
    -GenerateDiagrams `
    -OutputFolder "C:\Assessments\$(Get-Date -Format 'yyyy-MM')" `
    -CompareWith "C:\Assessments\$((Get-Date).AddMonths(-1).ToString('yyyy-MM'))"
```

**Generates:**
- ✅ 73+ output files
- ✅ HTML report with dark mode
- ✅ 12 diagram files (4 types × 3 formats)
- ✅ MITRE-mapped findings
- ✅ CA gap analysis (3 files)
- ✅ Trend analysis (2 files)
- ✅ Security category reports (2 files)

---

## 📊 **Real-World Scenario**

### **Quarterly Security Review**

**Q4 2024 (Baseline)**:
```powershell
.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\Audits\2024-Q4"
```

**Findings:**
- 24 total findings (12 High, 8 Medium, 4 Low)
- 125 users without MFA
- No CA policy blocking legacy auth
- krbtgt password 250 days old

**Q1 2025 (After Remediation)**:
```powershell
.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\Audits\2025-Q1" -CompareWith "C:\Audits\2024-Q4"
```

**Improvements:**
- 18 total findings (6 High, 8 Medium, 4 Low) ✅ **-25% findings**
- 42 users without MFA ✅ **-66% improvement**
- CA policy added to block legacy auth ✅ **Gap closed**
- krbtgt password reset ✅ **Critical issue resolved**

**Trend Report Shows:**
- 56% improvement rate
- 15 KPIs improved
- Only 2 regressions (acceptable - new users added)

**Executive Summary:**
"Security posture improved 56% quarter-over-quarter. High-severity findings reduced by 50%. MFA adoption increased from 70% to 96%."

---

## 🎨 **Visual Communication Example**

### **Before (v2.0)**
**Security Team to Executives:**
"We have some privileged accounts that don't have MFA enabled."

**Executives:**
"How many? Which accounts? How critical is this?"

**You:**
"Let me pull up the CSV... *scrolling through thousands of rows*"

### **After (v3.0)**
**Security Team to Executives:**
"Here's our Privileged Access Map." *Shows diagram*

**Diagram Shows:**
- 12 privileged users total
- 3 with ⚠️ red warning (no MFA)
- 2 in Global Administrator role
- 1 in Security Administrator role

**Executives:**
"I can see exactly who needs MFA. Let's fix those 3 immediately."

**Impact**: 10-minute discussion vs. 1-hour CSV analysis

---

## 📋 **Print Workflow for Board Meeting**

### **Preparation**
```powershell
# Run comprehensive assessment
.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\BoardMeeting\2025-Q4"

# Open HTML report
Invoke-Item "C:\BoardMeeting\2025-Q4\summary-*.html"
```

### **Print to PDF**
1. Browser → Print
2. Destination: Save as PDF
3. Result: Professional PDF with:
   - Executive summary on page 1
   - Risk findings on page 2-3
   - Remediation playbook on page 4-5
   - RBAC recommendations on page 6
   - Clean page breaks between sections

### **Add Diagrams**
```powershell
# Copy PNG diagrams to PowerPoint
$diagrams = Get-ChildItem "C:\BoardMeeting\2025-Q4" -Filter "*.png"
$diagrams | Copy-Item -Destination "C:\BoardMeeting\Presentation\"
```

**PowerPoint Slide 1**: Executive Summary (from PDF)  
**Slide 2**: Privileged Access Map (PNG)  
**Slide 3**: Key Findings (from PDF)  
**Slide 4**: Remediation Timeline (from playbook)  

---

## 🔍 **Detailed Output Exploration**

### **All Output Files**
```powershell
Get-ChildItem "C:\Assessments\2025-10" | Group-Object Extension | Select-Object Name, Count
```

**Result:**
```
Name    Count
----    -----
.csv    37
.json   23
.html   1
.dot    4
.mmd    4
.png    4 (if Graphviz installed)

Total: 73 files
```

### **Key Files to Review**

**Priority 1 (Immediate):**
- `summary-*.html` - Start here!
- `risk-findings-*.csv` - Filter by Severity='High'
- `privileged-access-map-*.png` - Identify admins without MFA

**Priority 2 (Planning):**
- `ca-gap-analysis-*.csv` - Missing Zero Trust policies
- `findings-by-security-category-*.csv` - Group remediation efforts
- `rbac-candidates-*.csv` - Design Entra roles

**Priority 3 (Trending):**
- `trend-analysis-*.csv` - Track improvements
- `findings-by-mitre-tactic-*.csv` - Understand attack vectors
- `kpis-*.json` - Baseline metrics

---

## 🎯 **Remediation Workflow**

### **Week 1: High Severity**
```powershell
# Filter high-severity findings
Import-Csv "C:\Assessments\2025-10\risk-findings-*.csv" | 
    Where-Object { $_.Severity -eq 'High' } |
    Select-Object Finding, MITRETechniques, RemediationSteps, EstimatedEffort |
    Format-Table -Wrap
```

**Action Plan:**
1. Reset krbtgt password (2-3 hours + 24hr wait)
2. Disable unconstrained delegation (8-12 hours)
3. Enforce MFA for Global Admins (15 minutes)
4. Create CA policy to block legacy auth (30 minutes)

### **Week 2-3: Medium Severity**
Review and plan medium-severity findings

### **Week 4: Low Severity + Planning**
Address hygiene items, plan next quarter

---

## 📱 **Mobile Access**

### **View on Phone/Tablet**
1. Email HTML report to yourself
2. Open on mobile device
3. Responsive layout adapts
4. Executive summary clearly visible
5. Scroll through findings
6. Dark mode works on mobile too!

**Perfect for:** Reviewing findings during commute, quick status checks

---

## 🎊 **Success Story**

### **Before v3.0**
- Manual CSV analysis: 2-3 hours
- Creating diagrams: 4-6 hours  
- MITRE mapping: 2-3 hours
- CA gap research: 2 hours
- Total: **10-14 hours per assessment**

### **After v3.0**
- Run script: 10-15 minutes
- Review HTML: 30 minutes
- Share diagrams: 5 minutes
- Total: **~1 hour per assessment**

**Time Saved**: 9-13 hours per assessment  
**ROI**: Break-even after 2 assessments  
**Annual Value**: 108-156 hours saved (monthly assessments)

---

## 🚀 **Next Steps**

### **Immediate**
1. ✅ Run test: `.\Test-DiagramGeneration.ps1`
2. ✅ Run real assessment: `.\script.ps1 -IncludeEntra -GenerateDiagrams`
3. ✅ Explore HTML report with dark mode
4. ✅ View generated diagrams
5. ✅ Review MITRE mappings

### **This Month**
6. Share HTML report with security team
7. Use diagrams in presentations
8. Start remediation using playbook
9. Install Graphviz for PNG rendering

### **Next Month**
10. Run with `-CompareWith` to track trends
11. Demonstrate improvements to management
12. Build quarterly trend report
13. Update remediation playbook

---

## 📞 **Quick Help**

### **Question**: "Where do I start?"
**Answer**: `QUICKSTART.md` - 5-minute setup guide

### **Question**: "How do I view diagrams?"
**Answer**: `DIAGRAM-GENERATION-GUIDE.md` + install Graphviz

### **Question**: "What's MITRE mapping?"
**Answer**: See `FEATURE-SHOWCASE.md` section 2

### **Question**: "How do I enable dark mode?"
**Answer**: Open HTML report, click 🌙 button (top-right)

### **Question**: "Can I print the report?"
**Answer**: Yes! Browser → Print → Save as PDF (auto-optimized)

---

**Walkthrough Version**: 3.0  
**Last Updated**: October 7, 2025  
**Status**: ✅ Complete  
**All Features Demonstrated**: ✅ Yes

**🎉 Congratulations on upgrading to v3.0! 🎉**

