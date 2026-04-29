# Assessment Report Export Tools

## Overview

This package includes two powerful export tools for generating stakeholder-friendly reports from your AD & Entra security assessments:

1. **Excel Workbook Export** - Multi-tab workbook with all assessment data
2. **Executive Brief (HTML)** - High-level summary that prints to PDF

## 📊 Excel Workbook Export

### Features
- **Multiple tabs** with organized data (KPIs, Findings, RBAC, GPOs, etc.)
- **Conditional formatting** for severity levels (Red/Orange/Yellow)
- **Auto-sized columns** with frozen headers
- **Professional table styling** for easy reading
- **No Excel required** - uses ImportExcel PowerShell module

### Usage

```powershell
# Basic usage (finds latest assessment automatically)
.\Export-ExcelReport.ps1 -OutputFolder "C:\Temp\ADScan" -Timestamp "20251007-120000"

# From your script
$xlsxPath = & .\Export-ExcelReport.ps1 -OutputFolder $outputFolder -Timestamp $nowTag
Invoke-Item $xlsxPath
```

### Output

Creates: `AD-Assessment-Report-{timestamp}.xlsx`

**Tabs included:**
- Executive Summary (KPIs as Metric/Value pairs)
- Risk Findings (with severity highlighting)
- Enhanced Findings (MITRE-mapped findings)
- MITRE Techniques
- Category Summary
- RBAC Candidates
- GPO Modernization
- AD Users, Groups, Computers
- Entra Roles, Service Principals, Conditional Access
- Auth Methods, SPNs, Delegation
- Trend Analysis (if available)

### Requirements

The script will automatically install the `ImportExcel` module if needed:

```powershell
Install-Module ImportExcel -Scope CurrentUser -Force
```

---

## 📄 Executive Brief (HTML)

### Features
- **Executive-friendly summary** with key metrics
- **Risk scoring** and overall posture assessment
- **Top 10 prioritized findings** by severity
- **Phased remediation plan** (Immediate/Short-term/Long-term)
- **Print-to-PDF button** for easy distribution
- **Professional styling** with charts and visualizations
- **Works everywhere** - just open in any browser

### Usage

```powershell
# Basic usage
.\Export-ExecutiveBrief.ps1 -OutputFolder "C:\Temp\ADScan" -Timestamp "20251007-120000"

# From your script
$htmlPath = & .\Export-ExecutiveBrief.ps1 -OutputFolder $outputFolder -Timestamp $nowTag
Start-Process $htmlPath  # Opens in default browser
```

### Output

Creates: `Executive-Brief-{timestamp}.html`

**Includes:**
- Overall risk level with color-coded banner
- Security posture summary (High/Medium/Low findings)
- Environment metrics (users, groups, GPOs, CA policies)
- Findings by area (bar chart visualization)
- Top 10 critical findings table
- 3-phase remediation plan
- Success metrics to track progress

### Creating PDF

1. Open the HTML file in your browser
2. Click the **"🖨️ Print to PDF"** button (or press `Ctrl+P`)
3. Select "Save as PDF" as the printer
4. Save and distribute to stakeholders

---

## 🚀 Quick Start Demo

Use the demo script to generate both reports at once:

```powershell
# Run with latest assessment
.\Demo-ReportExports.ps1

# Run with specific assessment
.\Demo-ReportExports.ps1 -OutputFolder "C:\Assessments\2025-10" -Timestamp "20251007-120000"

# Returns paths for scripting
$result = .\Demo-ReportExports.ps1
Write-Host "Excel: $($result.ExcelPath)"
Write-Host "HTML: $($result.HtmlPath)"
```

The demo script will:
1. ✅ Find your latest assessment (or use specified timestamp)
2. ✅ Generate Excel workbook with all data tabs
3. ✅ Generate HTML executive brief
4. ✅ Optionally open both files for review

---

## 📋 Integration with Main Assessment

Add these exports to your main `script.ps1` workflow:

```powershell
# At the end of your assessment script
Write-Host "`nGenerating stakeholder reports..." -ForegroundColor Cyan

# Generate Excel workbook
$xlsxPath = & "$PSScriptRoot\Export-ExcelReport.ps1" -OutputFolder $OutputFolder -Timestamp $nowTag
if ($xlsxPath) {
    Write-Host "✓ Excel report: $xlsxPath" -ForegroundColor Green
}

# Generate executive brief
$htmlPath = & "$PSScriptRoot\Export-ExecutiveBrief.ps1" -OutputFolder $OutputFolder -Timestamp $nowTag
if ($htmlPath) {
    Write-Host "✓ Executive brief: $htmlPath" -ForegroundColor Green
}
```

---

## 🎯 Use Cases

### Excel Workbook - For Technical Teams
- **Security Analysts**: Deep dive into findings with sorting/filtering
- **IT Operations**: Track remediation progress tab-by-tab
- **Auditors**: Comprehensive evidence for compliance reviews
- **Project Managers**: Export data for tracking tools

### Executive Brief - For Leadership
- **C-Level Executives**: High-level risk overview in 2 pages
- **Security Leadership**: Prioritized action plan with timeline
- **Board Presentations**: Print to PDF for meeting materials
- **External Auditors**: Quick posture summary

---

## 📝 File Structure

```
AD_review/
├── Export-ExcelReport.ps1          # Excel export script
├── Export-ExecutiveBrief.ps1       # HTML brief export script
├── Demo-ReportExports.ps1          # Demo/integration script
└── EXPORT-REPORTS-README.md        # This file
```

---

## 🔧 Troubleshooting

### ImportExcel Module Issues

If the Excel export fails to install the module:

```powershell
# Manual installation
Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber

# Verify installation
Get-Module ImportExcel -ListAvailable
```

### Missing Data Files

Both exports require these minimum files:
- `kpis-{timestamp}.json` - Environment metrics
- `risk-findings-{timestamp}.csv` - Security findings

Run your main assessment first:

```powershell
.\script.ps1 -IncludeEntra
```

### HTML Print Issues

If the Print to PDF button doesn't work:
1. Use `Ctrl+P` or browser menu → Print
2. Select "Save as PDF" destination
3. Adjust margins if needed (typically "Default" works)

---

## 💡 Tips & Best Practices

### Excel Workbook
1. **Filter by severity** - Use Excel filters on Severity column
2. **Sort by area** - Group findings by affected systems
3. **Track progress** - Add a "Status" column for remediation tracking
4. **Share selectively** - Export specific tabs for specific teams

### Executive Brief
1. **Print landscape** - Better fit for charts and tables
2. **Remove page breaks** - Edit CSS if printing on single page
3. **Customize branding** - Add company logo to HTML template
4. **Schedule regular** - Generate monthly for trend tracking

### Automation
1. **Schedule assessments** - Use Task Scheduler to run weekly
2. **Auto-generate reports** - Add exports to automated pipeline
3. **Email results** - Script distribution to stakeholder list
4. **Version control** - Keep historical reports for trending

---

## 🔐 Security Considerations

- **Excel files contain sensitive data** - Encrypt before sharing
- **HTML contains findings** - Don't host on public web servers
- **PDF distribution** - Use secure email or file sharing
- **Access control** - Limit report access to authorized personnel

---

## 📚 Additional Resources

- [ImportExcel Module Documentation](https://github.com/dfinke/ImportExcel)
- [PowerShell HTML Reporting Best Practices](https://learn.microsoft.com/en-us/powershell/)
- [Microsoft Security Best Practices](https://learn.microsoft.com/en-us/security/)

---

## 🆘 Support

For issues or questions:
1. Check the main assessment logs
2. Verify all required files exist
3. Review PowerShell execution errors
4. Check module installations

---

**Version:** 2.0  
**Last Updated:** October 2025  
**Compatibility:** PowerShell 5.1+ / PowerShell 7+

