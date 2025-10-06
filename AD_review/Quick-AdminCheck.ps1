<#
.SYNOPSIS
    Quick one-liner to check admin groups from existing assessment

.DESCRIPTION
    Simple script to quickly display admin group information from your AD assessment.
    Just point it to your assessment folder and it shows the critical admin groups.

.PARAMETER AssessmentFolder
    Path to your AD assessment folder (default: searches common locations)

.EXAMPLE
    .\Quick-AdminCheck.ps1
    Quick check using default search

.EXAMPLE
    .\Quick-AdminCheck.ps1 -AssessmentFolder "C:\Assessments\Client1"
    Check specific assessment folder
#>

[CmdletBinding()]
param(
    [string]$AssessmentFolder = $null
)

# Auto-find assessment folder if not specified
if (-not $AssessmentFolder) {
    $possiblePaths = @(
        "$env:TEMP\ADScan",
        "C:\Temp\ADScan",
        "C:\Assessments\*",
        "C:\ADAssessment\*"
    )
    
    foreach ($path in $possiblePaths) {
        $found = Get-ChildItem -Path $path -Filter "ad-privileged-groups-*.json" -ErrorAction SilentlyContinue | 
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($found) {
            $AssessmentFolder = $found.Directory.FullName
            break
        }
    }
}

if (-not $AssessmentFolder -or -not (Test-Path $AssessmentFolder)) {
    Write-Host "❌ No assessment folder found. Run your AD assessment first:" -ForegroundColor Red
    Write-Host "   .\script.ps1 -IncludeEntra" -ForegroundColor Yellow
    exit 1
}

Write-Host "🔍 Checking admin groups in: $AssessmentFolder" -ForegroundColor Cyan

# Find and load the privileged groups data
$privilegedGroupsFile = Get-ChildItem -Path $AssessmentFolder -Filter "ad-privileged-groups-*.json" | 
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $privilegedGroupsFile) {
    Write-Host "❌ No ad-privileged-groups-*.json found in assessment" -ForegroundColor Red
    exit 1
}

try {
    $data = Get-Content $privilegedGroupsFile.FullName | ConvertFrom-Json
} catch {
    Write-Host "❌ Failed to load assessment data: $_" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Loaded assessment data from: $($privilegedGroupsFile.Name)" -ForegroundColor Green

# Filter for critical admin groups
$criticalGroups = @('Schema Admins', 'Enterprise Admins', 'Domain Admins', 'Administrators')
$adminGroups = $data | Where-Object { $_.Group -in $criticalGroups }

Write-Host "`n🏛️ CRITICAL ADMIN GROUPS:" -ForegroundColor Yellow
Write-Host "=========================" -ForegroundColor Yellow

foreach ($group in $adminGroups) {
    $riskLevel = switch ($group.Group) {
        'Schema Admins' { '🔴 CRITICAL' }
        'Enterprise Admins' { '🔴 CRITICAL' }
        'Domain Admins' { '🟡 HIGH' }
        'Administrators' { '🟡 HIGH' }
    }
    
    Write-Host "`n📋 $($group.Group)" -ForegroundColor White
    Write-Host "   Risk Level: $riskLevel" -ForegroundColor $(if ($riskLevel -like '*CRITICAL*') { 'Red' } else { 'Yellow' })
    Write-Host "   Members: $($group.Count)" -ForegroundColor Gray
    
    if ($group.Count -gt 0) {
        Write-Host "   Member List:" -ForegroundColor Gray
        foreach ($member in $group.Members) {
            Write-Host "     • $($member.Name) ($($member.SamAccountName))" -ForegroundColor DarkGray
        }
        
        # Risk assessment
        $risk = switch ($group.Group) {
            'Schema Admins' { if ($group.Count -gt 2) { '⚠️ TOO MANY MEMBERS (>2)' } else { '✅ OK' } }
            'Enterprise Admins' { if ($group.Count -gt 3) { '⚠️ TOO MANY MEMBERS (>3)' } else { '✅ OK' } }
            'Domain Admins' { if ($group.Count -gt 5) { '⚠️ TOO MANY MEMBERS (>5)' } else { '✅ OK' } }
            'Administrators' { if ($group.Count -gt 10) { '⚠️ TOO MANY MEMBERS (>10)' } else { '✅ OK' } }
        }
        Write-Host "   Assessment: $risk" -ForegroundColor $(if ($risk -like '*⚠️*') { 'Red' } else { 'Green' })
    } else {
        Write-Host "   ✅ No members (Good!)" -ForegroundColor Green
    }
}

# Summary
$totalAdmins = ($adminGroups | Measure-Object -Property Count -Sum).Sum
Write-Host "`n📊 SUMMARY:" -ForegroundColor Cyan
Write-Host "===========" -ForegroundColor Cyan
Write-Host "Total Critical Admin Members: $totalAdmins" -ForegroundColor White

$criticalIssues = @()
if (($adminGroups | Where-Object { $_.Group -eq 'Schema Admins' -and $_.Count -gt 2 }).Count -gt 0) { 
    $criticalIssues += "Schema Admins >2 members" 
}
if (($adminGroups | Where-Object { $_.Group -eq 'Enterprise Admins' -and $_.Count -gt 3 }).Count -gt 0) { 
    $criticalIssues += "Enterprise Admins >3 members" 
}
if (($adminGroups | Where-Object { $_.Group -eq 'Domain Admins' -and $_.Count -gt 5 }).Count -gt 0) { 
    $criticalIssues += "Domain Admins >5 members" 
}

if ($criticalIssues.Count -gt 0) {
    Write-Host "`n🚨 CRITICAL ISSUES FOUND:" -ForegroundColor Red
    foreach ($issue in $criticalIssues) {
        Write-Host "   • $issue" -ForegroundColor Red
    }
} else {
    Write-Host "`n✅ No critical admin group issues detected" -ForegroundColor Green
}

Write-Host "`n💡 RECOMMENDATIONS:" -ForegroundColor Yellow
Write-Host "==================" -ForegroundColor Yellow
Write-Host "1. Minimize admin group membership" -ForegroundColor Gray
Write-Host "2. Use Privileged Access Management (PIM)" -ForegroundColor Gray
Write-Host "3. Implement just-in-time access" -ForegroundColor Gray
Write-Host "4. Monitor admin group changes" -ForegroundColor Gray
Write-Host "5. Regular access reviews" -ForegroundColor Gray

Write-Host "`n🔧 For detailed analysis, run:" -ForegroundColor Cyan
Write-Host "   .\Get-AdminGroups.ps1 -IncludeDetails" -ForegroundColor Gray
