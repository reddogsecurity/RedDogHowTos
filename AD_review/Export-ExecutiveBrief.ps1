<#
.SYNOPSIS
    Generates an executive-friendly HTML brief that can be printed to PDF

.DESCRIPTION
    Creates a professional HTML report with:
    - Executive summary with KPI metrics
    - Security posture overview with severity counts
    - Top 10 security findings prioritized by severity
    - Recommended actions timeline
    - Print-friendly styling for PDF export
    - Interactive charts and visualizations

.PARAMETER OutputFolder
    Path to assessment output folder containing CSV/JSON files

.PARAMETER Timestamp
    Timestamp string used in file naming (e.g., "20251007-120000")

.EXAMPLE
    .\Export-ExecutiveBrief.ps1 -OutputFolder "C:\Temp\ADScan" -Timestamp "20251007-120000"

.EXAMPLE
    $htmlPath = .\Export-ExecutiveBrief.ps1 -OutputFolder $outputFolder -Timestamp $nowTag
    Invoke-Item $htmlPath
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory)]
    [string]$Timestamp
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Executive Brief Export" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$htmlPath = Join-Path $OutputFolder "Executive-Brief-$Timestamp.html"

# Load required data files
$findingsPath = Join-Path $OutputFolder "risk-findings-$Timestamp.csv"
$kpisPath = Join-Path $OutputFolder "kpis-$Timestamp.json"

if (-not (Test-Path $findingsPath)) {
    Write-Warning "Risk findings file not found: $findingsPath"
    Write-Host "Run the main assessment first: .\script.ps1" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $kpisPath)) {
    Write-Warning "KPIs file not found: $kpisPath"
    Write-Host "Run the main assessment first: .\script.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host "Loading assessment data..." -ForegroundColor Gray

try {
    $findings = Import-Csv $findingsPath
    $kpis = Get-Content $kpisPath -Raw | ConvertFrom-Json
} catch {
    Write-Error "Failed to load assessment data: $_"
    exit 1
}

# Calculate key metrics
$highSeverity = ($findings | Where-Object { $_.Severity -eq 'High' }).Count
$mediumSeverity = ($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowSeverity = ($findings | Where-Object { $_.Severity -eq 'Low' }).Count
$totalFindings = $findings.Count

# Calculate risk score
$riskScore = ($highSeverity * 3) + ($mediumSeverity * 2) + ($lowSeverity * 1)
$maxRiskScore = $totalFindings * 3
$riskPercentage = if ($maxRiskScore -gt 0) { [math]::Round(($riskScore / $maxRiskScore) * 100, 1) } else { 0 }

# Determine overall risk level
$overallRiskLevel = if ($riskPercentage -ge 70) { 'Critical' }
                    elseif ($riskPercentage -ge 50) { 'High' }
                    elseif ($riskPercentage -ge 30) { 'Medium' }
                    else { 'Low' }

$overallRiskColor = switch ($overallRiskLevel) {
    'Critical' { '#c0392b' }
    'High' { '#e74c3c' }
    'Medium' { '#f39c12' }
    'Low' { '#27ae60' }
}

# Top findings sorted by severity
$topFindings = $findings | 
    Sort-Object @{Expression={
        switch ($_.Severity) {
            'High' { 1 }
            'Medium' { 2 }
            'Low' { 3 }
            default { 4 }
        }
    }} | Select-Object -First 10

# Group findings by area
$findingsByArea = $findings | Group-Object Area | Sort-Object Count -Descending | Select-Object -First 5

# Extract domain name safely
$domainName = if ($kpis.PSObject.Properties.Name -contains 'Domain') { 
    $kpis.Domain 
} else { 
    'Not Available' 
}

# Safe KPI extraction helper
function Get-SafeKPI($name, $default = 0) {
    if ($kpis.PSObject.Properties.Name -contains $name) {
        return $kpis.$name
    }
    return $default
}

Write-Host "Generating HTML brief..." -ForegroundColor Gray

# Generate HTML
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD &amp; Entra Security Assessment - Executive Brief</title>
    <style>
        @media print {
            body { margin: 0.5in; }
            .page { page-break-after: always; box-shadow: none; margin: 0; }
            .no-print { display: none; }
        }
        
        * { box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', 'Calibri', 'Helvetica Neue', Arial, sans-serif;
            max-width: 1200px;
            margin: 40px auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .page {
            background: white;
            padding: 40px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 4px;
        }
        
        h1 {
            color: #0078d4;
            border-bottom: 4px solid #0078d4;
            padding-bottom: 10px;
            margin-top: 0;
            font-size: 2.2em;
        }
        
        h2 {
            color: #333;
            margin-top: 30px;
            font-size: 1.5em;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 8px;
        }
        
        h3 {
            color: #555;
            font-size: 1.2em;
            margin-top: 20px;
        }
        
        .metadata {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            border-left: 4px solid #0078d4;
        }
        
        .metadata p {
            margin: 5px 0;
        }
        
        .risk-banner {
            background: ${overallRiskColor};
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            margin: 30px 0;
            font-size: 1.3em;
            font-weight: bold;
        }
        
        .severity-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .severity-box {
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .sev-high { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .sev-medium { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .sev-low { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); }
        
        .kpi-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
        }
        
        .kpi-label {
            font-size: 0.9em;
            opacity: 0.95;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }
        
        .kpi-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .kpi-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        
        .kpi-card .kpi-value {
            font-size: 2.5em;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        th {
            background: #0078d4;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .high { background: #e74c3c; color: white; }
        .medium { background: #f39c12; color: white; }
        .low { background: #3498db; color: white; }
        
        .recommendations {
            background: #e8f4f8;
            border-left: 4px solid #0078d4;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        
        .recommendations ol {
            margin: 10px 0;
            padding-left: 25px;
        }
        
        .recommendations li {
            margin: 10px 0;
            line-height: 1.8;
        }
        
        .area-chart {
            margin: 20px 0;
        }
        
        .area-bar {
            display: flex;
            align-items: center;
            margin: 8px 0;
        }
        
        .area-label {
            width: 200px;
            font-weight: 500;
        }
        
        .area-progress {
            flex: 1;
            background: #e0e0e0;
            height: 25px;
            border-radius: 12px;
            overflow: hidden;
            margin: 0 15px;
        }
        
        .area-fill {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 8px;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .footer {
            text-align: center;
            padding: 30px 20px;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
            margin-top: 40px;
        }
        
        .print-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #0078d4;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1em;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0,120,212,0.3);
            transition: all 0.3s;
        }
        
        .print-button:hover {
            background: #005a9e;
            box-shadow: 0 6px 16px rgba(0,120,212,0.4);
            transform: translateY(-2px);
        }
    </style>
</head>
<body>

<!-- Page 1: Executive Summary -->
<div class="page">
    <h1>Active Directory &amp; Entra ID Security Assessment</h1>
    
    <div class="metadata">
        <p><strong>Assessment Date:</strong> $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</p>
        <p><strong>Environment:</strong> $domainName</p>
        <p><strong>Assessment ID:</strong> $Timestamp</p>
    </div>
    
    <div class="risk-banner">
        Overall Risk Level: $overallRiskLevel ($riskPercentage% Risk Score)
    </div>
    
    <h2>Security Posture Overview</h2>
    <div class="severity-summary">
        <div class="severity-box sev-high">
            <div class="kpi-value">$highSeverity</div>
            <div class="kpi-label">High Risk Findings</div>
        </div>
        <div class="severity-box sev-medium">
            <div class="kpi-value">$mediumSeverity</div>
            <div class="kpi-label">Medium Risk Findings</div>
        </div>
        <div class="severity-box sev-low">
            <div class="kpi-value">$lowSeverity</div>
            <div class="kpi-label">Low Risk Findings</div>
        </div>
    </div>
    
    <h2>Environment Metrics</h2>
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">AD Users</div>
            <div class="kpi-value">$(Get-SafeKPI 'UsersAD')</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Entra Users</div>
            <div class="kpi-value">$(Get-SafeKPI 'UsersEntra')</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">AD Groups</div>
            <div class="kpi-value">$(Get-SafeKPI 'GroupsAD')</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">GPOs</div>
            <div class="kpi-value">$(Get-SafeKPI 'GPOs')</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">CA Policies</div>
            <div class="kpi-value">$(Get-SafeKPI 'ConditionalAccessPolicies')</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Computers</div>
            <div class="kpi-value">$(Get-SafeKPI 'ComputersAD')</div>
        </div>
    </div>
    
    <h2>Findings by Area</h2>
    <div class="area-chart">
$(
    $maxCount = ($findingsByArea | Measure-Object -Property Count -Maximum).Maximum
    foreach ($area in $findingsByArea) {
        $widthPercent = if ($maxCount -gt 0) { [math]::Round(($area.Count / $maxCount) * 100, 1) } else { 0 }
        @"
        <div class="area-bar">
            <div class="area-label">$($area.Name)</div>
            <div class="area-progress">
                <div class="area-fill" style="width: ${widthPercent}%">$($area.Count)</div>
            </div>
        </div>
"@
    }
)
    </div>
</div>

<!-- Page 2: Top Findings &amp; Recommendations -->
<div class="page">
    <h1>Critical Security Findings</h1>
    
    <p>The following findings require immediate attention and should be prioritized in your remediation plan:</p>
    
    <table>
        <thead>
            <tr>
                <th style="width: 50px;">Priority</th>
                <th>Area</th>
                <th>Finding</th>
                <th style="width: 100px;">Severity</th>
            </tr>
        </thead>
        <tbody>
$(
    $priority = 1
    foreach ($finding in $topFindings) {
        $sevClass = $finding.Severity.ToLower()
        @"
            <tr>
                <td style="text-align: center; font-weight: bold;">#$priority</td>
                <td>$($finding.Area)</td>
                <td>$($finding.Finding)</td>
                <td><span class="badge $sevClass">$($finding.Severity)</span></td>
            </tr>
"@
        $priority++
    }
)
        </tbody>
    </table>
    
    <h2>Recommended Action Plan</h2>
    <div class="recommendations">
        <h3>Phase 1: Immediate Actions (0-7 days)</h3>
        <ol>
            <li><strong>Address all HIGH severity findings</strong> - These represent critical security gaps that could lead to immediate compromise</li>
            <li><strong>Review privileged access</strong> - Verify all members of Domain Admins, Enterprise Admins, and Global Administrator roles</li>
            <li><strong>Enable MFA for all privileged accounts</strong> - Start with Global Admins and work down the privilege ladder</li>
$(if ($highSeverity -gt 0) {
    "            <li><strong>Create incident response plan</strong> - Document remediation steps for the $highSeverity high-risk findings</li>"
})
        </ol>
        
        <h3>Phase 2: Short-term Improvements (1-4 weeks)</h3>
        <ol>
            <li><strong>Implement Conditional Access policies</strong> - Begin with basic location and device policies</li>
            <li><strong>Address MEDIUM severity findings</strong> - Systematically work through configuration gaps</li>
            <li><strong>Deploy security baselines</strong> - Implement Microsoft security configuration baselines for AD and Entra</li>
            <li><strong>Establish monitoring</strong> - Set up alerts for privileged account activities</li>
        </ol>
        
        <h3>Phase 3: Long-term Strategy (1-3 months)</h3>
        <ol>
            <li><strong>Complete LOW severity remediations</strong> - Address remaining configuration issues</li>
            <li><strong>Implement Privileged Identity Management (PIM)</strong> - Move to just-in-time privileged access</li>
            <li><strong>Modernize Group Policy</strong> - Migrate security-critical GPOs to Intune/Endpoint Manager</li>
            <li><strong>Establish continuous assessment</strong> - Schedule quarterly security reviews</li>
        </ol>
    </div>
    
    <h2>Success Metrics</h2>
    <p>Track these key performance indicators to measure improvement:</p>
    <ul>
        <li>Reduce HIGH severity findings to zero within 30 days</li>
        <li>Achieve 100% MFA adoption for privileged accounts within 14 days</li>
        <li>Implement at least 3 Conditional Access policies within 30 days</li>
        <li>Reduce total findings count by 50% within 90 days</li>
        <li>Establish automated monitoring and alerting within 60 days</li>
    </ul>
</div>

<div class="footer">
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | <strong>Assessment ID:</strong> $Timestamp</p>
    <p>This is an automated security assessment report. For detailed remediation guidance, refer to the full Excel workbook.</p>
    <p><em>Active Directory &amp; Entra ID Security Assessment Tool v2.0</em></p>
</div>

<button class="print-button no-print" onclick="window.print()">Print to PDF</button>

</body>
</html>
"@

# Write HTML to file
try {
    $html | Out-File $htmlPath -Encoding UTF8 -Force
    Write-Host "[OK] HTML brief generated successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to write HTML file: $_"
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Executive Brief Export Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`nSummary:" -ForegroundColor White
Write-Host "  Overall Risk Level: $overallRiskLevel" -ForegroundColor $(
    switch ($overallRiskLevel) {
        'Critical' { 'Red' }
        'High' { 'Red' }
        'Medium' { 'Yellow' }
        'Low' { 'Green' }
    }
)
Write-Host "  Total Findings: $totalFindings" -ForegroundColor White
Write-Host "  - High: $highSeverity" -ForegroundColor Red
Write-Host "  - Medium: $mediumSeverity" -ForegroundColor Yellow
Write-Host "  - Low: $lowSeverity" -ForegroundColor Green

Write-Host "`nOutput:" -ForegroundColor White
Write-Host "  File path: $htmlPath" -ForegroundColor Cyan

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Open the HTML file in your browser" -ForegroundColor Gray
Write-Host "  2. Click 'Print to PDF' button (or Ctrl+P)" -ForegroundColor Gray
Write-Host "  3. Share the PDF with executive stakeholders" -ForegroundColor Gray
Write-Host "  4. Use alongside the Excel workbook for detailed remediation" -ForegroundColor Gray

Write-Host "`nOpen the brief:" -ForegroundColor Cyan
Write-Host "  Invoke-Item '$htmlPath'" -ForegroundColor Gray

# Return the path for scripting
return $htmlPath

