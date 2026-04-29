# Historical-TrendAnalyzer.psm1
# Compares assessment runs over time and tracks KPI improvements

Import-Module (Join-Path $PSScriptRoot "Helpers.psm1") -Force

function Invoke-TrendAnalysis {
    <#
    .SYNOPSIS
    Compares current assessment with previous runs to track improvements
    
    .DESCRIPTION
    Analyzes historical assessment data to:
    - Track KPI changes over time
    - Identify security improvements or regressions
    - Calculate trend percentages
    - Generate trend reports
    - Recommend focus areas
    
    .PARAMETER CurrentFolder
    Path to current assessment output folder
    
    .PARAMETER PreviousFolder
    Path to previous assessment output folder for comparison
    
    .PARAMETER Timestamp
    Timestamp string for current run
    
    .EXAMPLE
    Invoke-TrendAnalysis -CurrentFolder "C:\Assessments\2025-10" -PreviousFolder "C:\Assessments\2025-09" -Timestamp "20251007-120000"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CurrentFolder,
        
        [Parameter(Mandatory)]
        [string]$PreviousFolder,
        
        [Parameter(Mandatory)]
        [string]$Timestamp
    )
    
    Write-Host "Analyzing historical trends..." -ForegroundColor Cyan
    
    # Validate folders exist
    if (-not (Test-Path $CurrentFolder)) {
        Write-Error "Current folder not found: $CurrentFolder"
        return $null
    }
    
    if (-not (Test-Path $PreviousFolder)) {
        Write-Warning "Previous folder not found: $PreviousFolder - cannot perform trend analysis"
        return $null
    }
    
    # Load current KPIs
    $currentKpiFile = Get-LatestFile -Pattern "kpis-*.json" -Folder $CurrentFolder
    if (-not $currentKpiFile) {
        Write-Warning "No KPI file found in current folder"
        return $null
    }
    $currentKpis = Get-Content $currentKpiFile | ConvertFrom-Json
    
    # Load previous KPIs
    $previousKpiFile = Get-LatestFile -Pattern "kpis-*.json" -Folder $PreviousFolder
    if (-not $previousKpiFile) {
        Write-Warning "No KPI file found in previous folder"
        return $null
    }
    $previousKpis = Get-Content $previousKpiFile | ConvertFrom-Json
    
    Write-Host "  Current: $currentKpiFile" -ForegroundColor Gray
    Write-Host "  Previous: $previousKpiFile" -ForegroundColor Gray
    
    # Calculate deltas
    $trends = @()
    $improvements = 0
    $regressions = 0
    $unchanged = 0
    
    # Get all KPI names from both files
    $allKpiNames = @()
    if ($currentKpis.PSObject.Properties) {
        $allKpiNames += $currentKpis.PSObject.Properties.Name
    }
    if ($previousKpis.PSObject.Properties) {
        $allKpiNames += $previousKpis.PSObject.Properties.Name
    }
    $allKpiNames = $allKpiNames | Select-Object -Unique
    
    foreach ($kpiName in $allKpiNames) {
        $currentValue = $currentKpis.$kpiName
        $previousValue = $previousKpis.$kpiName
        
        # Skip if both are null
        if ($null -eq $currentValue -and $null -eq $previousValue) {
            continue
        }
        
        # Handle new or removed KPIs
        if ($null -eq $previousValue) {
            $trends += [PSCustomObject]@{
                KPI = $kpiName
                CurrentValue = $currentValue
                PreviousValue = 'N/A'
                Delta = 'NEW'
                PercentChange = 'N/A'
                Trend = 'New'
                Interpretation = 'New metric tracked in current assessment'
            }
            continue
        }
        
        if ($null -eq $currentValue) {
            $trends += [PSCustomObject]@{
                KPI = $kpiName
                CurrentValue = 'N/A'
                PreviousValue = $previousValue
                Delta = 'REMOVED'
                PercentChange = 'N/A'
                Trend = 'Removed'
                Interpretation = 'Metric no longer tracked'
            }
            continue
        }
        
        # Determine if numeric
        $isNumeric = ($currentValue -is [int] -or $currentValue -is [double]) -and 
                     ($previousValue -is [int] -or $previousValue -is [double])
        
        if ($isNumeric) {
            $delta = [int]$currentValue - [int]$previousValue
            $percentChange = if ([int]$previousValue -ne 0) {
                [math]::Round(($delta / [int]$previousValue) * 100, 1)
            } else {
                if ($delta -ne 0) { 100.0 } else { 0.0 }
            }
            
            # Determine if improvement or regression (context-dependent)
            $trend = if ($delta -eq 0) {
                $unchanged++
                'Unchanged'
            } elseif ($kpiName -match 'MFARegistered|Compliant|HasMFA|Enabled|PolicyCount') {
                # Higher is better
                if ($delta -gt 0) {
                    $improvements++
                    'Improved'
                } else {
                    $regressions++
                    'Regressed'
                }
            } elseif ($kpiName -match 'NotRegistered|NonCompliant|Expired|Without|Stale|Risk|Issue|Gap|Missing') {
                # Lower is better
                if ($delta -lt 0) {
                    $improvements++
                    'Improved'
                } else {
                    $regressions++
                    'Regressed'
                }
            } else {
                # Neutral change
                $unchanged++
                'Changed'
            }
            
            # Interpretation
            $interpretation = Get-TrendInterpretation -KpiName $kpiName -Delta $delta -Trend $trend
            
            $trends += [PSCustomObject]@{
                KPI = $kpiName
                CurrentValue = $currentValue
                PreviousValue = $previousValue
                Delta = $delta
                PercentChange = "${percentChange}%"
                Trend = $trend
                Interpretation = $interpretation
            }
        } else {
            # Non-numeric comparison (boolean, string)
            $trend = if ($currentValue -eq $previousValue) {
                $unchanged++
                'Unchanged'
            } else {
                'Changed'
            }
            
            $trends += [PSCustomObject]@{
                KPI = $kpiName
                CurrentValue = $currentValue
                PreviousValue = $previousValue
                Delta = 'N/A'
                PercentChange = 'N/A'
                Trend = $trend
                Interpretation = "Changed from '$previousValue' to '$currentValue'"
            }
        }
    }
    
    # Export trend analysis
    $trendCsv = Join-Path $CurrentFolder "trend-analysis-$Timestamp.csv"
    $trends | Export-Csv $trendCsv -NoTypeInformation -Force
    
    # Generate trend summary
    $trendSummary = @{
        CurrentAssessment = Split-Path $CurrentFolder -Leaf
        PreviousAssessment = Split-Path $PreviousFolder -Leaf
        ComparisonDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        TotalKPIs = $trends.Count
        Improvements = $improvements
        Regressions = $regressions
        Unchanged = $unchanged
        ImprovementRate = if ($trends.Count -gt 0) { 
            [math]::Round(($improvements / $trends.Count) * 100, 1) 
        } else { 0 }
        TopImprovements = ($trends | Where-Object { $_.Trend -eq 'Improved' } | 
                          Sort-Object { [math]::Abs([int]$_.Delta) } -Descending | 
                          Select-Object -First 5).KPI
        TopRegressions = ($trends | Where-Object { $_.Trend -eq 'Regressed' } | 
                         Sort-Object { [math]::Abs([int]$_.Delta) } -Descending | 
                         Select-Object -First 5).KPI
    }
    
    $summaryJson = Join-Path $CurrentFolder "trend-summary-$Timestamp.json"
    $trendSummary | ConvertTo-Json -Depth 3 | Out-File $summaryJson -Force
    
    # Console output
    Write-Host "`nHistorical Trend Analysis:" -ForegroundColor Cyan
    Write-Host "  Comparing: $(Split-Path $PreviousFolder -Leaf) -> $(Split-Path $CurrentFolder -Leaf)" -ForegroundColor White
    Write-Host "  Total KPIs tracked: $($trends.Count)" -ForegroundColor White
    Write-Host "  Improvements: $improvements" -ForegroundColor Green
    Write-Host "  Regressions: $regressions" -ForegroundColor $(if ($regressions -gt 0) { 'Red' } else { 'Gray' })
    Write-Host "  Unchanged: $unchanged" -ForegroundColor Gray
    Write-Host "  Improvement Rate: $($trendSummary.ImprovementRate)%" -ForegroundColor $(if ($trendSummary.ImprovementRate -ge 50) { 'Green' } elseif ($trendSummary.ImprovementRate -ge 25) { 'Yellow' } else { 'Red' })
    
    if ($improvements -gt 0) {
        Write-Host "`n  Top Improvements:" -ForegroundColor Green
        $topImproved = $trends | Where-Object { $_.Trend -eq 'Improved' } | 
                       Sort-Object { [math]::Abs([double]($_.Delta -replace '[^\d\-\.]', '')) } -Descending | 
                       Select-Object -First 3
        foreach ($item in $topImproved) {
            Write-Host "    - $($item.KPI): $($item.PreviousValue) -> $($item.CurrentValue) ($($item.PercentChange))" -ForegroundColor Gray
        }
    }
    
    if ($regressions -gt 0) {
        Write-Host "`n  [!]️  Areas Needing Attention:" -ForegroundColor Yellow
        $topRegressed = $trends | Where-Object { $_.Trend -eq 'Regressed' } | 
                        Sort-Object { [math]::Abs([double]($_.Delta -replace '[^\d\-\.]', '')) } -Descending | 
                        Select-Object -First 3
        foreach ($item in $topRegressed) {
            Write-Host "    - $($item.KPI): $($item.PreviousValue) -> $($item.CurrentValue) ($($item.PercentChange))" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nTrend files exported:" -ForegroundColor Gray
    Write-Host "  - $trendCsv" -ForegroundColor Gray
    Write-Host "  - $summaryJson" -ForegroundColor Gray
    
    return [PSCustomObject]@{
        Trends = $trends
        Summary = $trendSummary
        TrendCsvPath = $trendCsv
        SummaryJsonPath = $summaryJson
        ImprovementCount = $improvements
        RegressionCount = $regressions
        UnchangedCount = $unchanged
    }
}

function Get-TrendInterpretation {
    <#
    .SYNOPSIS
    Generates human-readable interpretation of KPI trends
    #>
    param(
        [string]$KpiName,
        [int]$Delta,
        [string]$Trend
    )
    
    if ($Trend -eq 'Unchanged') {
        return "No change from previous assessment"
    }
    
    # Positive trends (higher is better)
    if ($KpiName -match 'MFARegistered|CABaseline|Compliant|Managed') {
        if ($Delta -gt 0) {
            return "[+] Security improved: $Delta more users/items secured"
        } else {
            return "[!] Security regression: $([math]::Abs($Delta)) fewer users/items secured"
        }
    }
    
    # Negative trends (lower is better)
    if ($KpiName -match 'NotRegistered|NonCompliant|Expired|Expiring|Without|Stale|High|Risk') {
        if ($Delta -lt 0) {
            return "[+] Risk reduced: $([math]::Abs($Delta)) fewer issues"
        } else {
            return "[!] Risk increased: $Delta more issues detected"
        }
    }
    
    # Neutral trends (informational)
    if ($Delta -gt 0) {
        return "Increased by $Delta"
    } elseif ($Delta -lt 0) {
        return "Decreased by $([math]::Abs($Delta))"
    } else {
        return "No change"
    }
}

function Get-AssessmentFolders {
    <#
    .SYNOPSIS
    Scans parent directory for assessment folders and returns them sorted by date
    
    .PARAMETER BaseFolder
    Parent folder containing assessment subfolders
    
    .EXAMPLE
    Get-AssessmentFolders -BaseFolder "C:\Assessments"
    Returns: @("C:\Assessments\2025-10", "C:\Assessments\2025-09", ...)
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseFolder
    )
    
    if (-not (Test-Path $BaseFolder)) {
        Write-Warning "Base folder not found: $BaseFolder"
        return @()
    }
    
    # Find folders with KPI files
    $assessmentFolders = @()
    Get-ChildItem -Path $BaseFolder -Directory | ForEach-Object {
        $kpiFile = Get-ChildItem -Path $_.FullName -Filter "kpis-*.json" -File | Select-Object -First 1
        if ($kpiFile) {
            $assessmentFolders += [PSCustomObject]@{
                Path = $_.FullName
                Name = $_.Name
                Date = $kpiFile.LastWriteTime
            }
        }
    }
    
    # Sort by date descending (newest first)
    return $assessmentFolders | Sort-Object Date -Descending
}

function New-TrendChart {
    <#
    .SYNOPSIS
    Generates a simple text-based trend chart for console display
    
    .PARAMETER Trends
    Array of trend objects
    
    .PARAMETER KpiName
    Name of KPI to chart
    #>
    param(
        [Parameter(Mandatory)]
        $Trends,
        
        [Parameter(Mandatory)]
        [string]$KpiName
    )
    
    $kpiTrend = $Trends | Where-Object { $_.KPI -eq $KpiName }
    if (-not $kpiTrend) {
        return "No data for $KpiName"
    }
    
    $prev = $kpiTrend.PreviousValue
    $curr = $kpiTrend.CurrentValue
    $delta = $kpiTrend.Delta
    
    # Simple arrow indicator
    $arrow = if ($delta -eq 0 -or $delta -eq 'N/A') { '-->' }
             elseif ($delta -gt 0) { '(+)' }
             else { '(-)' }
    
    return "${prev} ${arrow} ${curr} (${delta}, $($kpiTrend.PercentChange))"
}

Export-ModuleMember -Function Invoke-TrendAnalysis, Get-AssessmentFolders, New-TrendChart

