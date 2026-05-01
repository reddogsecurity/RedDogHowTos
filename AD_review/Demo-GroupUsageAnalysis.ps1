<#
.SYNOPSIS
    Demo script for the Group Usage Analysis feature

.DESCRIPTION
    Demonstrates how to use Get-ElevatedGroupUsage.ps1 with different options

.NOTES
    This demo shows various usage patterns of the group usage analysis tool
#>

Write-Host @"

╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║          ELEVATED GROUP USAGE ANALYSIS - DEMO                 ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "This demo will show you how to analyze group usage patterns in AD`n" -ForegroundColor White

# Demo 1: Basic privileged group analysis
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "DEMO 1: Basic Analysis - Privileged Groups Only" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "Command:" -ForegroundColor White
Write-Host "  .\Get-ElevatedGroupUsage.ps1`n" -ForegroundColor Gray

Write-Host "This will:" -ForegroundColor White
Write-Host "  • Analyze all privileged/elevated groups" -ForegroundColor Gray
Write-Host "  • Show top 10 least used groups (90+ days inactive)" -ForegroundColor Gray
Write-Host "  • Show top 10 most used groups" -ForegroundColor Gray
Write-Host "  • Generate CSV and HTML reports`n" -ForegroundColor Gray

$response = Read-Host "Run Demo 1? (y/n)"
if ($response -eq 'y') {
    .\Get-ElevatedGroupUsage.ps1
    Write-Host "`n[Demo 1 Complete]`n" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Demo 2: Custom threshold and top count
Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "DEMO 2: Custom Threshold - 60 Days, Top 15 Groups" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "Command:" -ForegroundColor White
Write-Host "  .\Get-ElevatedGroupUsage.ps1 -DaysInactive 60 -Top 15`n" -ForegroundColor Gray

Write-Host "This will:" -ForegroundColor White
Write-Host "  • Use 60-day inactivity threshold (instead of default 90)" -ForegroundColor Gray
Write-Host "  • Show top 15 groups in each category (instead of 10)" -ForegroundColor Gray
Write-Host "  • More aggressive detection of unused groups`n" -ForegroundColor Gray

$response = Read-Host "Run Demo 2? (y/n)"
if ($response -eq 'y') {
    $outputFolder = ".\Demo2-60Days"
    if (-not (Test-Path $outputFolder)) {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    }
    .\Get-ElevatedGroupUsage.ps1 -DaysInactive 60 -Top 15 -OutputFolder $outputFolder
    Write-Host "`n[Demo 2 Complete]`n" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Demo 3: All groups with nested members
Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "DEMO 3: Comprehensive Analysis - All Groups, Nested Members" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "Command:" -ForegroundColor White
Write-Host "  .\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups -IncludeNestedMembers`n" -ForegroundColor Gray

Write-Host "This will:" -ForegroundColor White
Write-Host "  • Analyze ALL security groups (not just privileged)" -ForegroundColor Gray
Write-Host "  • Include nested group memberships for accurate counts" -ForegroundColor Gray
Write-Host "  • Most comprehensive analysis (takes longer)" -ForegroundColor Gray
Write-Host "  • WARNING: May take 10-30 minutes in large environments`n" -ForegroundColor Yellow

$response = Read-Host "Run Demo 3? (y/n) [WARNING: This may take a while]"
if ($response -eq 'y') {
    $outputFolder = ".\Demo3-AllGroups"
    if (-not (Test-Path $outputFolder)) {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    }
    .\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups -IncludeNestedMembers -OutputFolder $outputFolder
    Write-Host "`n[Demo 3 Complete]`n" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Demo 4: Quick scan for immediate issues
Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "DEMO 4: Quick Scan - Identify Immediate Issues" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "Command:" -ForegroundColor White
Write-Host "  .\Get-ElevatedGroupUsage.ps1 -DaysInactive 180 -Top 5`n" -ForegroundColor Gray

Write-Host "This will:" -ForegroundColor White
Write-Host "  • Focus on severely inactive groups (180+ days)" -ForegroundColor Gray
Write-Host "  • Show only top 5 in each category" -ForegroundColor Gray
Write-Host "  • Quick scan for immediate cleanup opportunities`n" -ForegroundColor Gray

$response = Read-Host "Run Demo 4? (y/n)"
if ($response -eq 'y') {
    $outputFolder = ".\Demo4-QuickScan"
    if (-not (Test-Path $outputFolder)) {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    }
    .\Get-ElevatedGroupUsage.ps1 -DaysInactive 180 -Top 5 -OutputFolder $outputFolder
    Write-Host "`n[Demo 4 Complete]`n" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Summary
Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    DEMO COMPLETE!                             ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Green

Write-Host "Key Features Demonstrated:" -ForegroundColor Yellow
Write-Host "  ✓ Basic privileged group analysis" -ForegroundColor Green
Write-Host "  ✓ Custom inactivity thresholds" -ForegroundColor Green
Write-Host "  ✓ Adjustable result counts" -ForegroundColor Green
Write-Host "  ✓ All groups vs privileged only" -ForegroundColor Green
Write-Host "  ✓ Nested membership analysis" -ForegroundColor Green
Write-Host "  ✓ Quick scans for critical issues" -ForegroundColor Green

Write-Host "`nReports Generated:" -ForegroundColor Yellow
Write-Host "  • CSV files with detailed analysis" -ForegroundColor Gray
Write-Host "  • HTML report with visual dashboard" -ForegroundColor Gray
Write-Host "  • Summary statistics" -ForegroundColor Gray
Write-Host "  • Top unused groups (candidates for removal)" -ForegroundColor Gray
Write-Host "  • Top used groups (active groups to monitor)" -ForegroundColor Gray
Write-Host "  • Empty groups list" -ForegroundColor Gray
Write-Host "  • Critical risk groups (180+ days inactive)" -ForegroundColor Gray

Write-Host "`nUse Cases:" -ForegroundColor Yellow
Write-Host "  1. Security Audits - Identify unused elevated groups" -ForegroundColor Cyan
Write-Host "  2. Compliance - Document group usage patterns" -ForegroundColor Cyan
Write-Host "  3. Cleanup Projects - Find groups to remove" -ForegroundColor Cyan
Write-Host "  4. Risk Assessment - Identify stale privileged groups" -ForegroundColor Cyan
Write-Host "  5. Access Reviews - Validate group necessity" -ForegroundColor Cyan

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Review the HTML reports in your browser" -ForegroundColor White
Write-Host "  2. Analyze the top unused groups for removal candidates" -ForegroundColor White
Write-Host "  3. Validate business need for inactive elevated groups" -ForegroundColor White
Write-Host "  4. Schedule regular usage analysis (monthly recommended)" -ForegroundColor White
Write-Host "  5. Integrate into Run-EnhancedAssessment.ps1 for automated reports" -ForegroundColor White

Write-Host "`nIntegration with Assessment Suite:" -ForegroundColor Yellow
Write-Host "  This script is now part of the enhanced AD assessment suite." -ForegroundColor White
Write-Host "  Run .\Run-EnhancedAssessment.ps1 to include this analysis" -ForegroundColor White
Write-Host "  automatically with all other security checks.`n" -ForegroundColor White

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")




