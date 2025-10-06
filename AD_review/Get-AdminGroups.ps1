<#
.SYNOPSIS
    Extract and analyze Schema, Enterprise, and Domain Admin groups

.DESCRIPTION
    This script extracts detailed information about the most privileged groups in Active Directory:
    - Schema Admins
    - Enterprise Admins  
    - Domain Admins
    - Administrators (Built-in)
    
    It provides both current members and historical analysis of these critical security groups.

.PARAMETER OutputFolder
    Path where output files will be saved

.PARAMETER IncludeDetails
    Include detailed member information and account status

.EXAMPLE
    .\Get-AdminGroups.ps1
    Extract admin groups using default temp folder

.EXAMPLE
    .\Get-AdminGroups.ps1 -OutputFolder "C:\SecurityAudit" -IncludeDetails
    Extract with detailed member information to custom folder
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "$env:TEMP\AdminGroups",
    [switch]$IncludeDetails
)

# Create output folder
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Extracting Critical Admin Groups" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Ensure AD module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a machine with RSAT installed."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# Define the critical admin groups
$criticalAdminGroups = @(
    'Schema Admins',
    'Enterprise Admins', 
    'Domain Admins',
    'Administrators'
)

Write-Host "Analyzing critical admin groups..." -ForegroundColor Yellow

$adminAnalysis = @()
$allMembers = @()

foreach ($groupName in $criticalAdminGroups) {
    Write-Host "Processing: $groupName" -ForegroundColor Gray
    
    try {
        # Get the group
        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
        
        if ($group) {
            # Get group properties
            $groupProps = Get-ADGroup -Identity $groupName -Properties Description,GroupCategory,GroupScope,whenCreated,whenChanged,managedBy
            
            # Get members (recursive)
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue
            
            # Get detailed member information if requested
            $detailedMembers = @()
            if ($IncludeDetails -and $members.Count -gt 0) {
                Write-Host "  Getting detailed member information..." -ForegroundColor DarkGray
                
                foreach ($member in $members) {
                    try {
                        if ($member.objectClass -eq 'user') {
                            $userDetails = Get-ADUser -Identity $member.SamAccountName -Properties `
                                Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,AdminCount,`
                                TrustedForDelegation,TrustedToAuthForDelegation,whenCreated,whenChanged,`
                                MemberOf,Description -ErrorAction SilentlyContinue
                            
                            if ($userDetails) {
                                $detailedMembers += [PSCustomObject]@{
                                    SamAccountName = $userDetails.SamAccountName
                                    DisplayName = $userDetails.Name
                                    Enabled = $userDetails.Enabled
                                    LastLogonDate = $userDetails.LastLogonDate
                                    PasswordLastSet = $userDetails.PasswordLastSet
                                    PasswordNeverExpires = $userDetails.PasswordNeverExpires
                                    AdminCount = $userDetails.AdminCount
                                    TrustedForDelegation = $userDetails.TrustedForDelegation
                                    TrustedToAuthForDelegation = $userDetails.TrustedToAuthForDelegation
                                    WhenCreated = $userDetails.whenCreated
                                    WhenChanged = $userDetails.whenChanged
                                    Description = $userDetails.Description
                                    DaysSinceLastLogon = if ($userDetails.LastLogonDate) { 
                                        (Get-Date) - $userDetails.LastLogonDate | Select-Object -ExpandProperty Days 
                                    } else { $null }
                                    DaysSincePasswordSet = if ($userDetails.PasswordLastSet) { 
                                        (Get-Date) - $userDetails.PasswordLastSet | Select-Object -ExpandProperty Days 
                                    } else { $null }
                                }
                            }
                        } elseif ($member.objectClass -eq 'group') {
                            $groupDetails = Get-ADGroup -Identity $member.SamAccountName -Properties Description,GroupCategory,GroupScope -ErrorAction SilentlyContinue
                            
                            if ($groupDetails) {
                                $detailedMembers += [PSCustomObject]@{
                                    SamAccountName = $groupDetails.SamAccountName
                                    DisplayName = $groupDetails.Name
                                    Enabled = $null
                                    LastLogonDate = $null
                                    PasswordLastSet = $null
                                    PasswordNeverExpires = $null
                                    AdminCount = $null
                                    TrustedForDelegation = $null
                                    TrustedToAuthForDelegation = $null
                                    WhenCreated = $groupDetails.whenCreated
                                    WhenChanged = $groupDetails.whenChanged
                                    Description = $groupDetails.Description
                                    DaysSinceLastLogon = $null
                                    DaysSincePasswordSet = $null
                                    IsGroup = $true
                                    GroupCategory = $groupDetails.GroupCategory
                                    GroupScope = $groupDetails.GroupScope
                                }
                            }
                        }
                    } catch {
                        Write-Warning "  Failed to get details for member: $($member.SamAccountName) - $_"
                    }
                }
            }
            
            # Create analysis object
            $analysis = [PSCustomObject]@{
                GroupName = $groupName
                DistinguishedName = $group.DistinguishedName
                Description = $groupProps.Description
                GroupCategory = $groupProps.GroupCategory
                GroupScope = $groupProps.GroupScope
                WhenCreated = $groupProps.whenCreated
                WhenChanged = $groupProps.whenChanged
                ManagedBy = $groupProps.managedBy
                MemberCount = $members.Count
                Members = $members | Select-Object Name, SamAccountName, objectClass
                DetailedMembers = if ($IncludeDetails) { $detailedMembers } else { @() }
                RiskLevel = switch ($groupName) {
                    'Schema Admins' { 'CRITICAL - Can modify AD schema' }
                    'Enterprise Admins' { 'CRITICAL - Forest-wide admin rights' }
                    'Domain Admins' { 'HIGH - Domain-wide admin rights' }
                    'Administrators' { 'HIGH - Local admin on all domain controllers' }
                    default { 'UNKNOWN' }
                }
                SecurityRecommendations = switch ($groupName) {
                    'Schema Admins' { '1. Remove all members except break-glass accounts|2. Use Privileged Access Workstations|3. Monitor schema changes|4. Implement just-in-time access' }
                    'Enterprise Admins' { '1. Minimize membership (0-2 members)|2. Use PIM/PAM solutions|3. Require MFA|4. Monitor all activities|5. Regular access reviews' }
                    'Domain Admins' { '1. Minimize membership|2. Use separate admin accounts|3. Implement PIM|4. Monitor delegation|5. Regular access reviews' }
                    'Administrators' { '1. Review membership|2. Remove unnecessary members|3. Use least privilege|4. Monitor local admin rights' }
                    default { 'Review membership and implement least privilege' }
                }
            }
            
            $adminAnalysis += $analysis
            $allMembers += $detailedMembers | Where-Object { $_.objectClass -eq 'user' -or $_.IsGroup }
            
            Write-Host "  Found $($members.Count) members" -ForegroundColor Green
            
        } else {
            Write-Warning "Group '$groupName' not found in domain"
            
            # Add entry for missing group
            $adminAnalysis += [PSCustomObject]@{
                GroupName = $groupName
                DistinguishedName = $null
                Description = "Group not found"
                GroupCategory = $null
                GroupScope = $null
                WhenCreated = $null
                WhenChanged = $null
                ManagedBy = $null
                MemberCount = 0
                Members = @()
                DetailedMembers = @()
                RiskLevel = 'UNKNOWN - Group not found'
                SecurityRecommendations = 'Investigate why this group is missing'
            }
        }
        
    } catch {
        Write-Error "Failed to process group '$groupName': $_"
    }
}

# Generate summary statistics
$summary = [PSCustomObject]@{
    AnalysisDate = (Get-Date).ToString("u")
    Domain = (Get-ADDomain).DNSRoot
    TotalGroupsAnalyzed = $criticalAdminGroups.Count
    GroupsFound = ($adminAnalysis | Where-Object { $_.MemberCount -ge 0 }).Count
    TotalMembersAcrossAllGroups = ($adminAnalysis | Measure-Object -Property MemberCount -Sum).Sum
    CriticalFindings = @(
        if (($adminAnalysis | Where-Object { $_.GroupName -eq 'Schema Admins' -and $_.MemberCount -gt 2 }).Count -gt 0) { 'Schema Admins has >2 members (HIGH RISK)' }
        if (($adminAnalysis | Where-Object { $_.GroupName -eq 'Enterprise Admins' -and $_.MemberCount -gt 3 }).Count -gt 0) { 'Enterprise Admins has >3 members (HIGH RISK)' }
        if (($adminAnalysis | Where-Object { $_.GroupName -eq 'Domain Admins' -and $_.MemberCount -gt 5 }).Count -gt 0) { 'Domain Admins has >5 members (MEDIUM RISK)' }
        if ($allMembers | Where-Object { $_.Enabled -eq $false -and $_.SamAccountName -ne $null }).Count -gt 0) { 'Disabled accounts found in admin groups' }
        if ($allMembers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.SamAccountName -ne $null }).Count -gt 0) { 'Admin accounts with non-expiring passwords' }
        if ($allMembers | Where-Object { $_.DaysSinceLastLogon -gt 90 -and $_.Enabled -eq $true -and $_.SamAccountName -ne $null }).Count -gt 0) { 'Active admin accounts not logged in >90 days' }
    )
}

# Export results
$adminAnalysisFile = Join-Path $OutputFolder "admin-groups-analysis-$timestamp.json"
$adminAnalysis | ConvertTo-Json -Depth 6 | Out-File $adminAnalysisFile -Force

$adminAnalysisCSV = Join-Path $OutputFolder "admin-groups-summary-$timestamp.csv"
$adminAnalysis | Select-Object GroupName, MemberCount, RiskLevel, WhenCreated, ManagedBy | 
    Export-Csv $adminAnalysisCSV -NoTypeInformation -Force

if ($allMembers.Count -gt 0) {
    $membersFile = Join-Path $OutputFolder "admin-group-members-$timestamp.csv"
    $allMembers | Export-Csv $membersFile -NoTypeInformation -Force
}

$summaryFile = Join-Path $OutputFolder "admin-groups-summary-$timestamp.json"
$summary | ConvertTo-Json -Depth 6 | Out-File $summaryFile -Force

# Display results
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Admin Groups Analysis Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`n📊 Summary:" -ForegroundColor White
Write-Host "  Domain: $($summary.Domain)" -ForegroundColor Gray
Write-Host "  Groups Analyzed: $($summary.TotalGroupsAnalyzed)" -ForegroundColor Gray
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
Write-Host "  1. Review the JSON analysis file for detailed information" -ForegroundColor Gray
Write-Host "  2. Check for disabled or stale admin accounts" -ForegroundColor Gray
Write-Host "  3. Implement Privileged Access Management (PIM)" -ForegroundColor Gray
Write-Host "  4. Set up monitoring for admin group changes" -ForegroundColor Gray
Write-Host "  5. Conduct regular access reviews" -ForegroundColor Gray

if ($IncludeDetails) {
    Write-Host "`n📋 Detailed Member Information Available:" -ForegroundColor Cyan
    Write-Host "  • Account status (enabled/disabled)" -ForegroundColor Gray
    Write-Host "  • Last logon dates" -ForegroundColor Gray
    Write-Host "  • Password information" -ForegroundColor Gray
    Write-Host "  • Delegation settings" -ForegroundColor Gray
    Write-Host "  • Account creation/modification dates" -ForegroundColor Gray
}
