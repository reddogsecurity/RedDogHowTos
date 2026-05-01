<#
.SYNOPSIS
    Exports assessment data to a multi-tab Excel workbook with formatting

.DESCRIPTION
    Creates a stakeholder-friendly Excel workbook with:
    - Multiple data tabs (KPIs, Findings, RBAC, GPOs, etc.)
    - Auto-sizing and frozen headers
    - Conditional formatting for severity levels
    - Professional table styling
    - Executive summary tab

.PARAMETER OutputFolder
    Path to assessment output folder containing CSV/JSON files

.PARAMETER Timestamp
    Timestamp string used in file naming (e.g., "20251007-120000")

.EXAMPLE
    .\Export-ExcelReport.ps1 -OutputFolder "C:\Temp\ADScan" -Timestamp "20251007-120000"

.EXAMPLE
    $result = .\Export-ExcelReport.ps1 -OutputFolder $outputFolder -Timestamp $nowTag
    Write-Host "Excel file: $result"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputFolder,

    [Parameter(Mandatory)]
    [string]$Timestamp
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Excel Report Export" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check/Install ImportExcel module
if (-not (Get-Module -ListAvailable -Name ImportExcel)) { # This 'if' block starts here
    Write-Host "ImportExcel module not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "[OK] ImportExcel module installed successfully" -ForegroundColor Green
    } catch {
        Write-Error "Failed to install ImportExcel module: $_"
        Write-Host "Manual installation: Install-Module ImportExcel -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
} # This '}' closes the 'if' block - This was likely missing or incorrectly parsed due to later errors

try {
    Import-Module ImportExcel -ErrorAction Stop
} catch {
    Write-Error "Failed to import ImportExcel module: $_"
    exit 1
}

$xlsxPath = Join-Path $OutputFolder "AD-Assessment-Report-$Timestamp.xlsx"
Remove-Item $xlsxPath -ErrorAction SilentlyContinue

Write-Host "Generating Excel workbook..." -ForegroundColor Cyan
Write-Host "  Output: $xlsxPath" -ForegroundColor Gray

# Define tabs with priority ordering (most important first)
$tabs = @(
    @{Name='Executive Summary'; Path=(Join-Path $OutputFolder "kpis-$Timestamp.json"); Type='json'; Priority=1},
    @{Name='Risk Findings'; Path=(Join-Path $OutputFolder "risk-findings-$Timestamp.csv"); Type='csv'; Priority=2},
    @{Name='Enhanced Findings'; Path=(Join-Path $OutputFolder "enhanced-findings-$Timestamp.csv"); Type='csv'; Priority=3},
    @{Name='MITRE Techniques'; Path=(Join-Path $OutputFolder "mitre-summary-$Timestamp.csv"); Type='csv'; Priority=4},
    @{Name='Category Summary'; Path=(Join-Path $OutputFolder "category-summary-$Timestamp.csv"); Type='csv'; Priority=5},
    @{Name='RBAC Candidates'; Path=(Join-Path $OutputFolder "rbac-candidates-$Timestamp.csv"); Type='csv'; Priority=6},
    @{Name='GPO Modernization'; Path=(Join-Path $OutputFolder "gpo-modernization-$Timestamp.csv"); Type='csv'; Priority=7},
    @{Name='AD Users'; Path=(Join-Path $OutputFolder "ad-users-$Timestamp.csv"); Type='csv'; Priority=8},
    @{Name='AD Groups'; Path=(Join-Path $OutputFolder "ad-groups-$Timestamp.csv"); Type='csv'; Priority=9},
    @{Name='AD Computers'; Path=(Join-Path $OutputFolder "ad-computers-$Timestamp.csv"); Type='csv'; Priority=10},
    @{Name='Entra Roles'; Path=(Join-Path $OutputFolder "entra-role-assignments-$Timestamp.json"); Type='json'; Priority=11},
    @{Name='Service Principals'; Path=(Join-Path $OutputFolder "entra-serviceprincipals-$Timestamp.csv"); Type='csv'; Priority=12},
    @{Name='Conditional Access'; Path=(Join-Path $OutputFolder "entra-cap-$Timestamp.csv"); Type='csv'; Priority=13},
    @{Name='Auth Methods'; Path=(Join-Path $OutputFolder "entra-authmethods-$Timestamp.csv"); Type='csv'; Priority=14},
    @{Name='AD SPNs'; Path=(Join-Path $OutputFolder "ad-spns-$Timestamp.csv"); Type='csv'; Priority=15},
    @{Name='AD Delegation'; Path=(Join-Path $OutputFolder "ad-delegation-$Timestamp.csv"); Type='csv'; Priority=16},
    @{Name='Trend Analysis'; Path=(Join-Path $OutputFolder "trend-analysis-$Timestamp.csv"); Type='csv'; Priority=17}
)

$tabsCreated = 0
$tabsSkipped = 0

foreach ($tab in $tabs | Sort-Object Priority) {
    if (-not (Test-Path $tab.Path)) {
        Write-Host "  [SKIP] Skipping: $($tab.Name) - file not found" -ForegroundColor DarkGray
        $tabsSkipped++
        continue
    }

    Write-Host "  [+] Adding: $($tab.Name)" -ForegroundColor White

    try {
        switch ($tab.Type) {
            'csv' {
                $data = Import-Csv $tab.Path

                if ($data.Count -eq 0) {
                    Write-Host "    (empty file, skipped)" -ForegroundColor DarkGray
                    $tabsSkipped++
                    continue
                }

                $data | Export-Excel `
                    -Path $xlsxPath `
                    -WorksheetName $tab.Name `
                    -AutoSize `
                    -FreezeTopRow `
                    -BoldTopRow `
                    -TableStyle Medium2 `
                    -TableName ($tab.Name -replace '\s','_') `
                    -Append
            }
            'json' {
                $content = Get-Content $tab.Path -Raw
                if ([string]::IsNullOrWhiteSpace($content)) {
                    Write-Host "    (empty file, skipped)" -ForegroundColor DarkGray
                    $tabsSkipped++
                    continue
                }

                $obj = $content | ConvertFrom-Json

                # Handle single objects (like KPIs) - convert to key-value pairs
                if ($obj -isnot [System.Collections.IEnumerable] -or $obj -is [string]) {
                    $rows = @()
                    foreach ($prop in $obj.PSObject.Properties) {
                        $rows += [PSCustomObject]@{
                            Metric = $prop.Name
                            Value = $prop.Value
                        }
                    }
                    $obj = $rows
                }

                if ($obj.Count -eq 0) {
                    Write-Host "    (no data, skipped)" -ForegroundColor DarkGray
                    $tabsSkipped++
                    continue
                }

                $obj | Export-Excel `
                    -Path $xlsxPath `
                    -WorksheetName $tab.Name `
                    -AutoSize `
                    -FreezeTopRow `
                    -BoldTopRow `
                    -TableStyle Medium2 `
                    -TableName ($tab.Name -replace '\s','_') `
                    -Append
            }
        }
        $tabsCreated++
    } catch {
        Write-Warning "Failed to create tab '$($tab.Name)': $_"
        $tabsSkipped++
    }
}

# Apply conditional formatting to Risk Findings tab
$riskFindingsPath = Join-Path $OutputFolder "risk-findings-$Timestamp.csv"
if (Test-Path $riskFindingsPath) {
    Write-Host "`n  Applying conditional formatting..." -ForegroundColor Cyan
    try {
        # Import to get column letters
        $sampleData = Import-Csv $riskFindingsPath -First 1
        $severityColumn = 'C'  # Default assumption

        # Try to find Severity column
        if ($sampleData.PSObject.Properties.Name -contains 'Severity') {
            $colIndex = [array]::IndexOf([array]($sampleData.PSObject.Properties.Name), 'Severity')
            $severityColumn = [char](65 + $colIndex)  # Convert to A, B, C, etc.
        }

        # High severity - Red background
        Add-ConditionalFormatting `
            -Path $xlsxPath `
            -WorksheetName 'Risk Findings' `
            -Range "${severityColumn}:${severityColumn}" `
            -RuleType ContainsText `
            -ConditionValue 'High' `
            -BackgroundColor Red `
            -ForegroundColor White `
            -Bold

        # Medium severity - Orange background
        Add-ConditionalFormatting `
            -Path $xlsxPath `
            -WorksheetName 'Risk Findings' `
            -Range "${severityColumn}:${severityColumn}" `
            -RuleType ContainsText `
            -ConditionValue 'Medium' `
            -BackgroundColor Orange `
            -ForegroundColor White

        # Low severity - Yellow background
        Add-ConditionalFormatting `
            -Path $xlsxPath `
            -WorksheetName 'Risk Findings' `
            -Range "${severityColumn}:${severityColumn}" `
            -RuleType ContainsText `
            -ConditionValue 'Low' `
            -BackgroundColor Yellow `
            -ForegroundColor Black

        Write-Host "  [OK] Conditional formatting applied to Risk Findings" -ForegroundColor Green
    } catch {
        Write-Warning "Could not apply conditional formatting: $_"
    }
}

# Apply conditional formatting to Enhanced Findings if it exists
$enhancedFindingsPath = Join-Path $OutputFolder "enhanced-findings-$Timestamp.csv"
if (Test-Path $enhancedFindingsPath) {
    try {
        Add-ConditionalFormatting `
            -Path $xlsxPath `
            -WorksheetName 'Enhanced Findings' `
            -Range "C:C" `
            -RuleType ContainsText `
            -ConditionValue 'High' `
            -BackgroundColor Red `
            -ForegroundColor White `
            -Bold

        Write-Host "  [OK] Conditional formatting applied to Enhanced Findings" -ForegroundColor Green
    } catch {
        # Silently continue if tab doesn't exist
    }
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Excel Export Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`nSummary:" -ForegroundColor White
Write-Host "  Tabs created: $tabsCreated" -ForegroundColor Green
Write-Host "  Tabs skipped: $tabsSkipped" -ForegroundColor Gray
Write-Host "  File path: $xlsxPath" -ForegroundColor Cyan

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Open the Excel file to review all findings" -ForegroundColor Gray
Write-Host "  2. Share with stakeholders for review" -ForegroundColor Gray
Write-Host "  3. Use as input for remediation tracking" -ForegroundColor Gray

Write-Host "`nOpen the Excel file:" -ForegroundColor Cyan
Write-Host "  Invoke-Item `"$xlsxPath`"" -ForegroundColor Gray

# Return the path for scripting
return $xlsxPath