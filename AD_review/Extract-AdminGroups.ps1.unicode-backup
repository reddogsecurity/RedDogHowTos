<#
.SYNOPSIS
    Extract admin group information from existing AD assessment data

.DESCRIPTION
    This script reads the privileged groups data from your existing AD assessment
    and extracts detailed information about Schema, Enterprise, and Domain Admins.

.PARAMETER AssessmentFolder
    Path to the folder containing your AD assessment results

.PARAMETER OutputFolder
    Path where extracted admin group data will be saved

.EXAMPLE
    .\Extract-AdminGroups.ps1 -AssessmentFolder "C:\Temp\ADScan"
    Extract admin groups from existing assessment

.EXAMPLE
    .\Extract-AdminGroups.ps1 -AssessmentFolder "C:\Assessments\Client1" -OutputFolder "C:\AdminAnalysis"
    Extract with custom output location
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AssessmentFolder,
    
    [string]$OutputFolder = "$env:TEMP\AdminGroups"
)

# Create output folder
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Extracting Admin Groups from Assessment" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Find the privileged groups JSON file
$privilegedGroupsFile = Get-ChildItem -Path $AssessmentFolder -Filter "ad-privileged-groups-*.json" | 
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $privilegedGroupsFile) {
    Write-Error "No ad-privileged-groups-*.json file found in $AssessmentFolder"
    Write-Host "Available files:" -ForegroundColor Yellow
    Get-ChildItem -Path $AssessmentFolder -Filter "*.json" | Select-Object Name, LastWriteTime
    exit 1
}

Write-Host "Found assessment file: $($privilegedGroupsFile.Name)" -ForegroundColor Green

# Load the privileged groups data
try {
    $privilegedGroupsData = Get-Content $privilegedGroupsFile.FullName | ConvertFrom-Json
    Write-Host "Loaded privileged groups data successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to load privileged groups data: $_"
    exit 1
}

# Extract admin group information
Write-Host "`nAnalyzing admin groups..." -ForegroundColor Yellow

$adminGroups = @('Schema Admins', 'Enterprise Admins', 'Domain Admins', 'Administrators')
$adminAnalysis = @()

foreach ($groupData in $privilegedGroupsData) {
    if ($groupData.Group -in $adminGroups) {
        Write-Host "Processing: $($groupData.Group)" -ForegroundColor Gray
        
        $analysis = [PSCustomObject]@{
            GroupName = $groupData.Group
            MemberCount = $groupData.Count
            Members = $groupData.Members
            RiskLevel = switch ($groupData.Group) {
                'Schema Admins' { 'CRITICAL - Can modify AD schema' }
                'Enterprise Admins' { 'CRITICAL - Forest-wide admin rights' }
                'Domain Admins' { 'HIGH - Domain-wide admin rights' }
                'Administrators' { 'HIGH - Local admin on all domain controllers' }
                default { 'UNKNOWN' }
            }
            SecurityRecommendations = switch ($groupData.Group) {
                'Schema Admins' { 
                    '1. Remove all members except break-glass accounts|' +
                    '2. Use Privileged Access Workstations|' +
                    '3. Monitor schema changes|' +
                    '4. Implement just-in-time access'
                }
                'Enterprise Admins' { 
                    '1. Minimize membership (0-2 members)|' +
                    '2. Use PIM/PAM solutions|' +
                    '3. Require MFA|' +
                    '4. Monitor all activities|' +
                    '5. Regular access reviews'
                }
                'Domain Admins' { 
                    '1. Minimize membership|' +
                    '2. Use separate admin accounts|' +
                    '3. Implement PIM|' +
                    '4. Monitor delegation|' +
                    '5. Regular access reviews'
                }
                'Administrators' { 
                    '1. Review membership|' +
                    '2. Remove unnecessary members|' +
                    '3. Use least privilege|' +
                    '4. Monitor local admin rights'
                }
                default { 'Review membership and implement least privilege' }
            }
            AnalysisDate = (Get-Date).ToString("u")
            SourceAssessment = $privilegedGroupsFile.Name
        }
        
        $adminAnalysis += $analysis
        
        Write-Host "  Found $($groupData.Count) members" -ForegroundColor Green
        
        # Display member names
        if ($groupData.Count -gt 0) {
            Write-Host "  Members:" -ForegroundColor DarkGray
            foreach ($member in $groupData.Members) {
                Write-Host "    • $($member.Name) ($($member.SamAccountName))" -ForegroundColor DarkGray
            }
        }
    }
}

# Generate summary
$summary = [PSCustomObject]@{
    AnalysisDate = (Get-Date).ToString("u")
    SourceAssessment = $privilegedGroupsFile.Name
    AssessmentFolder = $AssessmentFolder
    TotalAdminGroupsAnalyzed = $adminAnalysis.Count
    TotalMembersAcrossAllGroups = ($adminAnalysis | Measure-Object -Property MemberCount -Sum).Sum
    CriticalFindings = @(
        if (($adminAnalysis | Where-Object { $_.GroupName -eq 'Schema Admins' -and $_.MemberCount -gt 2 }).Count -gt 0) { 'Schema Admins has >2 members (HIGH RISK)' }
        if (($adminAnalysis | Where-Object { $_.GroupName -eq 'Enterprise Admins' -and $_.MemberCount -gt 3 }).Count -gt 0) { 'Enterprise Admins has >3 members (HIGH RISK)' }
        if (($adminAnalysis | Where-Object { $_.GroupName -eq 'Domain Admins' -and $_.MemberCount -gt 5 }).Count -gt 0) { 'Domain Admins has >5 members (MEDIUM RISK)' }
        if (($adminAnalysis | Where-Object { $_.GroupName -eq 'Administrators' -and $_.MemberCount -gt 10 }).Count -gt 0) { 'Administrators group has >10 members (MEDIUM RISK)' }
    )
}

# Export results
$adminAnalysisFile = Join-Path $OutputFolder "extracted-admin-groups-$timestamp.json"
$adminAnalysis | ConvertTo-Json -Depth 6 | Out-File $adminAnalysisFile -Force

$adminAnalysisCSV = Join-Path $OutputFolder "extracted-admin-groups-$timestamp.csv"
$adminAnalysis | Select-Object GroupName, MemberCount, RiskLevel, AnalysisDate | 
    Export-Csv $adminAnalysisCSV -NoTypeInformation -Force

# Create detailed member list
$allMembers = @()
foreach ($group in $adminAnalysis) {
    foreach ($member in $group.Members) {
        $allMembers += [PSCustomObject]@{
            GroupName = $group.GroupName
            MemberName = $member.Name
            SamAccountName = $member.SamAccountName
            ObjectClass = $member.objectClass
            RiskLevel = $group.RiskLevel
        }
    }
}

if ($allMembers.Count -gt 0) {
    $membersFile = Join-Path $OutputFolder "extracted-admin-members-$timestamp.csv"
    $allMembers | Export-Csv $membersFile -NoTypeInformation -Force
}

$summaryFile = Join-Path $OutputFolder "extracted-admin-summary-$timestamp.json"
$summary | ConvertTo-Json -Depth 6 | Out-File $summaryFile -Force

# Display results
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Admin Groups Extraction Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`n📊 Summary:" -ForegroundColor White
Write-Host "  Source Assessment: $($summary.SourceAssessment)" -ForegroundColor Gray
Write-Host "  Groups Analyzed: $($summary.TotalAdminGroupsAnalyzed)" -ForegroundColor Gray
Write-Host "  Total Admin Members: $($summary.TotalMembersAcrossAllGroups)" -ForegroundColor Gray

Write-Host "`n⚠️ Critical Findings:" -ForegroundColor Yellow
if ($summary.CriticalFindings.Count -gt 0) {
    foreach ($finding in $summary.CriticalFindings) {
        Write-Host "  • $finding" -ForegroundColor Red
    }
} else {
    Write-Host "  • No critical findings detected" -ForegroundColor Green
}

Write-Host "`n📁 Output Files:" -ForegroundColor White
Write-Host "  • Analysis: $adminAnalysisFile" -ForegroundColor Gray
Write-Host "  • Summary CSV: $adminAnalysisCSV" -ForegroundColor Gray
if ($allMembers.Count -gt 0) {
    Write-Host "  • Members: $membersFile" -ForegroundColor Gray
}
Write-Host "  • Summary JSON: $summaryFile" -ForegroundColor Gray

Write-Host "`n🔍 Group Details:" -ForegroundColor White
foreach ($group in $adminAnalysis) {
    $riskColor = switch ($group.RiskLevel) {
        { $_ -like 'CRITICAL*' } { 'Red' }
        { $_ -like 'HIGH*' } { 'Yellow' }
        default { 'White' }
    }
    
    Write-Host "  $($group.GroupName): $($group.MemberCount) members [$($group.RiskLevel)]" -ForegroundColor $riskColor
}

Write-Host "`n💡 Next Steps:" -ForegroundColor White
Write-Host "  1. Review the extracted admin group information" -ForegroundColor Gray
Write-Host "  2. Identify unnecessary admin group members" -ForegroundColor Gray
Write-Host "  3. Implement Privileged Access Management (PIM)" -ForegroundColor Gray
Write-Host "  4. Set up monitoring for admin group changes" -ForegroundColor Gray
Write-Host "  5. Conduct regular access reviews" -ForegroundColor Gray

Write-Host "`n🔧 To get detailed member information, run:" -ForegroundColor Cyan
Write-Host "  .\Get-AdminGroups.ps1 -IncludeDetails" -ForegroundColor Gray
