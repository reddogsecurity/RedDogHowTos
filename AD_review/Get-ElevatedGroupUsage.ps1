<#
.SYNOPSIS
    Analyzes elevated permission groups and their usage patterns in Active Directory.

.DESCRIPTION
    This script identifies groups with elevated permissions and analyzes their usage based on
    member activity. It provides insights into:
    - Groups with the least activity (unused in 90+ days)
    - Groups with the most activity (most frequently used)
    - Overall group usage statistics and risk assessment
    
    Usage is determined by analyzing the last logon time of all group members.

.PARAMETER OutputFolder
    Path where the reports will be saved. Defaults to current directory.

.PARAMETER IncludeNestedMembers
    Recursively enumerate nested group memberships for more accurate usage analysis.

.PARAMETER Top
    Number of top/bottom groups to report. Defaults to 10.

.PARAMETER DaysInactive
    Number of days to consider a group inactive. Defaults to 90.

.PARAMETER IncludeAllGroups
    Analyze all security groups, not just privileged ones.

.EXAMPLE
    .\Get-ElevatedGroupUsage.ps1
    Analyze privileged groups with default settings

.EXAMPLE
    .\Get-ElevatedGroupUsage.ps1 -Top 20 -DaysInactive 60
    Get top 20 groups with 60-day inactivity threshold

.EXAMPLE
    .\Get-ElevatedGroupUsage.ps1 -IncludeAllGroups -IncludeNestedMembers
    Analyze all security groups with nested membership

.NOTES
    Requires: Active Directory PowerShell module
    Permissions: Domain user with read access to AD
    Author: AD Security Assessment Tool
    Version: 1.0
#>

param(
    [string]$OutputFolder = ".",
    [switch]$IncludeNestedMembers,
    [int]$Top = 10,
    [int]$DaysInactive = 90,
    [switch]$IncludeAllGroups
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ELEVATED GROUP USAGE ANALYSIS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get domain info
$domain = Get-ADDomain
Write-Host "[*] Domain: $($domain.DNSRoot)" -ForegroundColor Yellow
Write-Host "[*] Inactivity Threshold: $DaysInactive days" -ForegroundColor Yellow
Write-Host "[*] Analysis Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "[*] Include Nested Members: $IncludeNestedMembers`n" -ForegroundColor Yellow

# Define privileged/elevated groups
$privilegedGroups = @(
    'Enterprise Admins',
    'Schema Admins',
    'Domain Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
    'Cryptographic Operators',
    'Network Configuration Operators',
    'Remote Desktop Users',
    'Distributed COM Users',
    'IIS_IUSRS',
    'Event Log Readers'
)

# Function to get all members' last logon times
function Get-GroupUsageMetrics {
    param(
        [Parameter(Mandatory=$true)]
        $Group,
        [bool]$Recursive = $false
    )
    
    try {
        # Get group members - force array to handle single-member groups properly
        $members = @(if ($Recursive) {
            Get-ADGroupMember -Identity $Group -Recursive -ErrorAction Stop
        } else {
            Get-ADGroupMember -Identity $Group -ErrorAction Stop
        })
        
        # Properly check for empty groups (handles null and zero-count scenarios)
        if (-not $members -or $members.Count -eq 0) {
            return [PSCustomObject]@{
                HasMembers = $false
                UserCount = 0
                GroupCount = 0
                ComputerCount = 0
                LastActivityDate = $null
                DaysSinceLastActivity = $null
                AverageLastLogonDays = $null
                ActiveMemberCount = 0
                InactiveMemberCount = 0
                DisabledMemberCount = 0
                MostRecentUser = $null
                UsageScore = 0
            }
        }
        
        $userMembers = @()
        $groupMembers = 0
        $computerMembers = 0
        $lastActivityDate = $null
        $logonDays = @()
        $activeMemberCount = 0
        $inactiveMemberCount = 0
        $disabledMemberCount = 0
        $mostRecentUser = $null
        
        foreach ($member in $members) {
            switch ($member.objectClass) {
                'user' {
                    try {
                        $userDetails = Get-ADUser -Identity $member.SamAccountName -Properties `
                            lastLogonTimestamp, Enabled, LastLogonDate, WhenChanged -ErrorAction Stop
                        
                        $lastLogon = $null
                        if ($userDetails.lastLogonTimestamp) {
                            $lastLogon = [DateTime]::FromFileTime($userDetails.lastLogonTimestamp)
                        } elseif ($userDetails.LastLogonDate) {
                            $lastLogon = $userDetails.LastLogonDate
                        }
                        
                        $userMembers += [PSCustomObject]@{
                            SamAccountName = $userDetails.SamAccountName
                            Enabled = $userDetails.Enabled
                            LastLogon = $lastLogon
                            WhenChanged = $userDetails.WhenChanged
                        }
                        
                        # Track activity metrics
                        if (-not $userDetails.Enabled) {
                            $disabledMemberCount++
                        } elseif ($lastLogon) {
                            $daysSinceLogon = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
                            $logonDays += $daysSinceLogon
                            
                            if ($lastLogon -gt $inactiveThreshold) {
                                $activeMemberCount++
                            } else {
                                $inactiveMemberCount++
                            }
                            
                            # Track most recent activity
                            if (-not $lastActivityDate -or $lastLogon -gt $lastActivityDate) {
                                $lastActivityDate = $lastLogon
                                $mostRecentUser = $userDetails.SamAccountName
                            }
                        } else {
                            $inactiveMemberCount++
                        }
                    }
                    catch {
                        Write-Verbose "Could not retrieve details for user: $($member.SamAccountName)"
                    }
                }
                'group' { $groupMembers++ }
                'computer' { $computerMembers++ }
            }
        }
        
        # Calculate usage score (0-100)
        # Higher score = more active group
        $usageScore = 0
        if ($userMembers.Count -gt 0) {
            $activeRatio = ($activeMemberCount / $userMembers.Count) * 100
            
            $recentActivityBonus = if ($lastActivityDate -and $lastActivityDate -gt (Get-Date).AddDays(-30)) { 
                20 
            } elseif ($lastActivityDate -and $lastActivityDate -gt (Get-Date).AddDays(-60)) { 
                10 
            } else { 0 }
            
            $usageScore = [math]::Min(100, $activeRatio + $recentActivityBonus)
        }
        
        $avgLastLogonDays = if ($logonDays.Count -gt 0) {
            ($logonDays | Measure-Object -Average).Average
        } else { $null }
        
        $daysSinceLastActivity = if ($lastActivityDate) {
            (New-TimeSpan -Start $lastActivityDate -End (Get-Date)).Days
        } else { $null }
        
        return [PSCustomObject]@{
            HasMembers = $true
            UserCount = $userMembers.Count
            GroupCount = $groupMembers
            ComputerCount = $computerMembers
            LastActivityDate = $lastActivityDate
            DaysSinceLastActivity = $daysSinceLastActivity
            AverageLastLogonDays = $avgLastLogonDays
            ActiveMemberCount = $activeMemberCount
            InactiveMemberCount = $inactiveMemberCount
            DisabledMemberCount = $disabledMemberCount
            MostRecentUser = $mostRecentUser
            UsageScore = [math]::Round($usageScore, 2)
        }
    }
    catch {
        Write-Warning "Error analyzing group $($Group.Name): $_"
        return $null
    }
}

# Function to determine if group has elevated permissions
function Test-ElevatedGroup {
    param($Group)
    
    # Check if in privileged groups list
    if ($Group.Name -in $privilegedGroups) {
        return $true
    }
    
    # Check AdminCount attribute
    if ($Group.AdminCount -eq 1) {
        return $true
    }
    
    # Check if name contains admin/privileged keywords
    $elevatedKeywords = @('admin', 'privileged', 'elevated', 'power', 'security', 'audit', 'compliance')
    foreach ($keyword in $elevatedKeywords) {
        if ($Group.Name -like "*$keyword*") {
            return $true
        }
    }
    
    return $false
}

# Collect groups to analyze
Write-Host "[*] Discovering groups to analyze..." -ForegroundColor Yellow

$groupsToAnalyze = @()

if ($IncludeAllGroups) {
    Write-Host "    Collecting all security groups..." -ForegroundColor Gray
    $allGroups = Get-ADGroup -Filter "GroupCategory -eq 'Security'" -Properties AdminCount, Description, whenCreated, whenChanged, ManagedBy
    $groupsToAnalyze = $allGroups
    Write-Host "    [OK] Found $($groupsToAnalyze.Count) security groups" -ForegroundColor Green
} else {
    Write-Host "    Collecting privileged/elevated groups..." -ForegroundColor Gray
    
    # Get explicitly defined privileged groups
    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties AdminCount, Description, whenCreated, whenChanged, ManagedBy -ErrorAction SilentlyContinue
            if ($group) {
                $groupsToAnalyze += $group
            }
        }
        catch {
            Write-Verbose "Group not found: $groupName"
        }
    }
    
    # Get groups with AdminCount = 1
    $adminCountGroups = Get-ADGroup -Filter "AdminCount -eq 1" -Properties AdminCount, Description, whenCreated, whenChanged, ManagedBy -ErrorAction SilentlyContinue
    foreach ($group in $adminCountGroups) {
        if ($group.Name -notin $groupsToAnalyze.Name) {
            $groupsToAnalyze += $group
        }
    }
    
    Write-Host "    [OK] Found $($groupsToAnalyze.Count) elevated groups" -ForegroundColor Green
}

# Analyze each group
Write-Host "`n[*] Analyzing group usage patterns..." -ForegroundColor Yellow
$analysisResults = @()
$progressCounter = 0

foreach ($group in $groupsToAnalyze) {
    $progressCounter++
    $percentComplete = [math]::Round(($progressCounter / $groupsToAnalyze.Count) * 100, 1)
    Write-Progress -Activity "Analyzing Groups" -Status "Processing $($group.Name) ($progressCounter of $($groupsToAnalyze.Count))" -PercentComplete $percentComplete
    
    Write-Host "    [$progressCounter/$($groupsToAnalyze.Count)] $($group.Name)" -ForegroundColor Gray
    
    $usage = Get-GroupUsageMetrics -Group $group -Recursive $IncludeNestedMembers.IsPresent
    
    if ($usage) {
        $isElevated = Test-ElevatedGroup -Group $group
        
        $riskLevel = "Low"
        # Add null checks to prevent false "Low" risk for groups with no activity data
        if ($null -ne $usage.DaysSinceLastActivity) {
            if ($usage.DaysSinceLastActivity -ge 180) { $riskLevel = "Critical" }
            elseif ($usage.DaysSinceLastActivity -ge 90) { $riskLevel = "High" }
            elseif ($usage.DaysSinceLastActivity -ge 30) { $riskLevel = "Medium" }
        }
        
        $analysisResults += [PSCustomObject]@{
            GroupName = $group.Name
            IsElevated = $isElevated
            DistinguishedName = $group.DistinguishedName
            Description = $group.Description
            AdminCount = $group.AdminCount
            WhenCreated = $group.whenCreated
            WhenChanged = $group.whenChanged
            ManagedBy = $group.ManagedBy
            HasMembers = $usage.HasMembers
            TotalMembers = $usage.UserCount + $usage.GroupCount + $usage.ComputerCount
            UserMembers = $usage.UserCount
            GroupMembers = $usage.GroupCount
            ComputerMembers = $usage.ComputerCount
            LastActivityDate = $usage.LastActivityDate
            DaysSinceLastActivity = $usage.DaysSinceLastActivity
            AverageLastLogonDays = $usage.AverageLastLogonDays
            ActiveMembers = $usage.ActiveMemberCount
            InactiveMembers = $usage.InactiveMemberCount
            DisabledMembers = $usage.DisabledMemberCount
            MostRecentUser = $usage.MostRecentUser
            UsageScore = $usage.UsageScore
            RiskLevel = $riskLevel
            Recommendation = if (-not $usage.HasMembers) {
                "Empty group - consider removal"
            } elseif ($null -ne $usage.DaysSinceLastActivity -and $usage.DaysSinceLastActivity -ge 180) {
                "CRITICAL: No activity in 180+ days - Review for removal"
            } elseif ($null -ne $usage.DaysSinceLastActivity -and $usage.DaysSinceLastActivity -ge 90) {
                "HIGH: No activity in 90+ days - Validate business need"
            } elseif ($usage.DisabledMemberCount -eq $usage.UserCount -and $usage.UserCount -gt 0) {
                "All members disabled - Clean up or remove group"
            } elseif ($usage.UsageScore -lt 25) {
                "Low usage detected - Review membership"
            } else {
                "Active group - Monitor regularly"
            }
        }
    }
}

Write-Progress -Activity "Analyzing Groups" -Completed

# Generate reports
Write-Host "`n[*] Generating reports..." -ForegroundColor Yellow

# Top 10 least used groups (inactive)
$leastUsedGroups = $analysisResults | 
    Where-Object { $_.HasMembers -eq $true -and $_.DaysSinceLastActivity -ne $null } |
    Sort-Object DaysSinceLastActivity -Descending |
    Select-Object -First $Top

# Top 10 most used groups (active)
$mostUsedGroups = $analysisResults | 
    Where-Object { $_.HasMembers -eq $true -and $_.UsageScore -gt 0 } |
    Sort-Object UsageScore -Descending |
    Select-Object -First $Top

# Groups with no members
$emptyGroups = $analysisResults | Where-Object { -not $_.HasMembers }

# Critical risk groups
$criticalGroups = $analysisResults | Where-Object { $_.RiskLevel -eq "Critical" }

# Summary statistics
$summary = [PSCustomObject]@{
    AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Domain = $domain.DNSRoot
    TotalGroupsAnalyzed = $analysisResults.Count
    ElevatedGroups = ($analysisResults | Where-Object { $_.IsElevated -eq $true }).Count
    GroupsWithMembers = ($analysisResults | Where-Object { $_.HasMembers -eq $true }).Count
    EmptyGroups = $emptyGroups.Count
    InactiveGroups = ($analysisResults | Where-Object { $null -ne $_.DaysSinceLastActivity -and $_.DaysSinceLastActivity -ge $DaysInactive }).Count
    ActiveGroups = ($analysisResults | Where-Object { $_.UsageScore -gt 50 }).Count
    CriticalRiskGroups = $criticalGroups.Count
    HighRiskGroups = ($analysisResults | Where-Object { $_.RiskLevel -eq "High" }).Count
    DaysInactiveThreshold = $DaysInactive
}

# Export results
Write-Host "    Exporting CSV files..." -ForegroundColor Gray

$allResultsPath = Join-Path $OutputFolder "ElevatedGroupUsage-AllGroups-$timestamp.csv"
$analysisResults | Export-Csv -Path $allResultsPath -NoTypeInformation
Write-Host "    [OK] All groups: $allResultsPath" -ForegroundColor Green

$leastUsedPath = Join-Path $OutputFolder "ElevatedGroupUsage-Top${Top}LeastUsed-$timestamp.csv"
$leastUsedGroups | Export-Csv -Path $leastUsedPath -NoTypeInformation
Write-Host "    [OK] Least used (Top $Top): $leastUsedPath" -ForegroundColor Green

$mostUsedPath = Join-Path $OutputFolder "ElevatedGroupUsage-Top${Top}MostUsed-$timestamp.csv"
$mostUsedGroups | Export-Csv -Path $mostUsedPath -NoTypeInformation
Write-Host "    [OK] Most used (Top $Top): $mostUsedPath" -ForegroundColor Green

$summaryPath = Join-Path $OutputFolder "ElevatedGroupUsage-Summary-$timestamp.csv"
$summary | Export-Csv -Path $summaryPath -NoTypeInformation
Write-Host "    [OK] Summary: $summaryPath" -ForegroundColor Green

if ($emptyGroups.Count -gt 0) {
    $emptyPath = Join-Path $OutputFolder "ElevatedGroupUsage-EmptyGroups-$timestamp.csv"
    $emptyGroups | Export-Csv -Path $emptyPath -NoTypeInformation
    Write-Host "    [OK] Empty groups: $emptyPath" -ForegroundColor Green
}

if ($criticalGroups.Count -gt 0) {
    $criticalPath = Join-Path $OutputFolder "ElevatedGroupUsage-CriticalRisk-$timestamp.csv"
    $criticalGroups | Export-Csv -Path $criticalPath -NoTypeInformation
    Write-Host "    [OK] Critical risk: $criticalPath" -ForegroundColor Green
}

# Generate HTML report
Write-Host "    Generating HTML report..." -ForegroundColor Gray
$htmlPath = Join-Path $OutputFolder "ElevatedGroupUsage-Report-$timestamp.html"

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Elevated Group Usage Analysis Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        h1 { 
            color: #1976d2; 
            border-bottom: 3px solid #1976d2; 
            padding-bottom: 10px; 
        }
        h2 { 
            color: #424242; 
            border-bottom: 2px solid #e0e0e0; 
            padding-bottom: 5px; 
            margin-top: 30px; 
        }
        .summary { 
            background-color: #fff; 
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-label { 
            font-size: 12px; 
            opacity: 0.9; 
            text-transform: uppercase; 
        }
        .stat-value { 
            font-size: 32px; 
            font-weight: bold; 
            margin-top: 5px; 
        }
        .critical { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .warning { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
        .success { background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); color: #333; }
        .info { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        
        table { 
            border-collapse: collapse; 
            width: 100%; 
            background-color: #fff; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            margin: 20px 0; 
        }
        th { 
            background-color: #1976d2; 
            color: white; 
            padding: 12px; 
            text-align: left; 
            font-weight: 600; 
        }
        td { 
            padding: 10px 12px; 
            border-bottom: 1px solid #e0e0e0; 
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        .risk-critical { background-color: #ffebee; color: #c62828; font-weight: bold; }
        .risk-high { background-color: #fff3e0; color: #ef6c00; font-weight: bold; }
        .risk-medium { background-color: #fff9c4; color: #f57f17; }
        .risk-low { background-color: #e8f5e9; color: #2e7d32; }
        
        .elevated-badge {
            background-color: #ff5722;
            color: white;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
        }
        .usage-score {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        .score-high { background-color: #4caf50; color: white; }
        .score-medium { background-color: #ff9800; color: white; }
        .score-low { background-color: #f44336; color: white; }
        
        .alert {
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            border-left: 4px solid;
        }
        .alert-critical {
            background-color: #ffebee;
            border-color: #c62828;
            color: #b71c1c;
        }
        .alert-warning {
            background-color: #fff3e0;
            border-color: #ef6c00;
            color: #e65100;
        }
        .alert-info {
            background-color: #e3f2fd;
            border-color: #1976d2;
            color: #0d47a1;
        }
    </style>
</head>
<body>
    <h1>Elevated Group Usage Analysis Report</h1>
    
    <div class="summary">
        <p><strong>Analysis Date:</strong> $($summary.AnalysisDate)</p>
        <p><strong>Domain:</strong> $($summary.Domain)</p>
        <p><strong>Inactivity Threshold:</strong> $DaysInactive days</p>
        <p><strong>Analysis Scope:</strong> $(if ($IncludeAllGroups) { "All Security Groups" } else { "Elevated/Privileged Groups Only" })</p>
    </div>
    
    <div class="stat-grid">
        <div class="stat-box info">
            <div class="stat-label">Total Groups</div>
            <div class="stat-value">$($summary.TotalGroupsAnalyzed)</div>
        </div>
        <div class="stat-box warning">
            <div class="stat-label">Elevated Groups</div>
            <div class="stat-value">$($summary.ElevatedGroups)</div>
        </div>
        <div class="stat-box critical">
            <div class="stat-label">Inactive Groups</div>
            <div class="stat-value">$($summary.InactiveGroups)</div>
        </div>
        <div class="stat-box success">
            <div class="stat-label">Active Groups</div>
            <div class="stat-value">$($summary.ActiveGroups)</div>
        </div>
    </div>
    
    $(if ($criticalGroups.Count -gt 0) {
        "<div class='alert alert-critical'>
            <strong>âš ï¸ CRITICAL:</strong> $($criticalGroups.Count) groups have no activity in 180+ days and require immediate review!
        </div>"
    })
    
    $(if ($emptyGroups.Count -gt 0) {
        "<div class='alert alert-warning'>
            <strong>âš ï¸ WARNING:</strong> $($emptyGroups.Count) empty groups detected - consider cleanup.
        </div>"
    })
    
    <h2>Top $Top Least Used Groups (Inactive in $DaysInactive+ Days)</h2>
    $(if ($leastUsedGroups.Count -eq 0) {
        "<div class='alert alert-info'>No groups found inactive for $DaysInactive+ days. Excellent!</div>"
    } else {
        "<table>
            <tr>
                <th>Group Name</th>
                <th>Elevated</th>
                <th>Members</th>
                <th>Days Inactive</th>
                <th>Last Activity</th>
                <th>Usage Score</th>
                <th>Risk</th>
                <th>Recommendation</th>
            </tr>
            $($leastUsedGroups | ForEach-Object {
                $scoreClass = if ($_.UsageScore -ge 60) { "score-high" } elseif ($_.UsageScore -ge 30) { "score-medium" } else { "score-low" }
                "<tr>
                    <td><strong>$($_.GroupName)</strong></td>
                    <td>$(if ($_.IsElevated) { '<span class="elevated-badge">ELEVATED</span>' } else { 'No' })</td>
                    <td>$($_.TotalMembers) ($($_.ActiveMembers) active)</td>
                    <td class='risk-$($_.RiskLevel.ToLower())'>$($_.DaysSinceLastActivity)</td>
                    <td>$($_.LastActivityDate)</td>
                    <td><span class='usage-score $scoreClass'>$($_.UsageScore)%</span></td>
                    <td class='risk-$($_.RiskLevel.ToLower())'>$($_.RiskLevel)</td>
                    <td style='font-size: 12px;'>$($_.Recommendation)</td>
                </tr>"
            })
        </table>"
    })
    
    <h2>Top $Top Most Used Groups (Highest Activity)</h2>
    <table>
        <tr>
            <th>Group Name</th>
            <th>Elevated</th>
            <th>Members</th>
            <th>Active Members</th>
            <th>Last Activity</th>
            <th>Usage Score</th>
            <th>Risk</th>
        </tr>
        $($mostUsedGroups | ForEach-Object {
            $scoreClass = if ($_.UsageScore -ge 60) { "score-high" } elseif ($_.UsageScore -ge 30) { "score-medium" } else { "score-low" }
            "<tr>
                <td><strong>$($_.GroupName)</strong></td>
                <td>$(if ($_.IsElevated) { '<span class="elevated-badge">ELEVATED</span>' } else { 'No' })</td>
                <td>$($_.TotalMembers)</td>
                <td>$($_.ActiveMembers) / $($_.UserMembers) users</td>
                <td>$($_.LastActivityDate)</td>
                <td><span class='usage-score $scoreClass'>$($_.UsageScore)%</span></td>
                <td class='risk-$($_.RiskLevel.ToLower())'>$($_.RiskLevel)</td>
            </tr>"
        })
    </table>
    
    $(if ($criticalGroups.Count -gt 0) {
        "<h2>âš ï¸ Critical Risk Groups (180+ Days Inactive)</h2>
        <table>
            <tr>
                <th>Group Name</th>
                <th>Elevated</th>
                <th>Days Inactive</th>
                <th>Members</th>
                <th>Recommendation</th>
            </tr>
            $($criticalGroups | ForEach-Object {
                "<tr class='risk-critical'>
                    <td><strong>$($_.GroupName)</strong></td>
                    <td>$(if ($_.IsElevated) { '<span class="elevated-badge">ELEVATED</span>' } else { 'No' })</td>
                    <td>$($_.DaysSinceLastActivity)</td>
                    <td>$($_.TotalMembers)</td>
                    <td>$($_.Recommendation)</td>
                </tr>"
            })
        </table>"
    })
    
    $(if ($emptyGroups.Count -gt 0) {
        "<h2>Empty Groups (No Members)</h2>
        <table>
            <tr>
                <th>Group Name</th>
                <th>Elevated</th>
                <th>Created</th>
                <th>Last Changed</th>
                <th>Managed By</th>
            </tr>
            $($emptyGroups | ForEach-Object {
                "<tr>
                    <td><strong>$($_.GroupName)</strong></td>
                    <td>$(if ($_.IsElevated) { '<span class="elevated-badge">ELEVATED</span>' } else { 'No' })</td>
                    <td>$($_.WhenCreated)</td>
                    <td>$($_.WhenChanged)</td>
                    <td style='font-size: 11px;'>$($_.ManagedBy)</td>
                </tr>"
            })
        </table>"
    })
    
    <h2>Recommendations</h2>
    <div class="summary">
        <ol>
            <li><strong>Review Critical Risk Groups:</strong> Immediately investigate groups with 180+ days of inactivity</li>
            <li><strong>Clean Up Empty Groups:</strong> Remove groups with no members to reduce clutter</li>
            <li><strong>Validate Inactive Groups:</strong> For groups inactive 90+ days, confirm business need</li>
            <li><strong>Monitor Elevated Groups:</strong> Implement regular access reviews for elevated permission groups</li>
            <li><strong>Implement JIT Access:</strong> Consider Just-In-Time access for rarely used elevated groups</li>
            <li><strong>Document Active Groups:</strong> Ensure highly active groups have proper documentation and approval</li>
            <li><strong>Set Up Alerts:</strong> Configure monitoring for membership changes in elevated groups</li>
            <li><strong>Regular Reviews:</strong> Schedule quarterly reviews of group usage patterns</li>
        </ol>
    </div>
    
    <div class="alert alert-info">
        <strong>â„¹ï¸ Usage Score Calculation:</strong><br>
        Usage Score (0-100%) is calculated based on:<br>
        â€¢ Percentage of active members (logged in within $DaysInactive days)<br>
        â€¢ Recent activity bonus (20 points for activity within 30 days, 10 points for 60 days)<br>
        â€¢ Higher scores indicate more frequently used groups
    </div>
    
    <p style="margin-top: 40px; text-align: center; color: #999; font-size: 12px;">
        Generated by AD Security Assessment Tool | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    </p>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "    [OK] HTML Report: $htmlPath" -ForegroundColor Green

# Display console summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nGroups Analyzed: $($summary.TotalGroupsAnalyzed)" -ForegroundColor White
Write-Host "  - Elevated Groups: $($summary.ElevatedGroups)" -ForegroundColor Yellow
Write-Host "  - Groups with Members: $($summary.GroupsWithMembers)" -ForegroundColor White
Write-Host "  - Empty Groups: $($summary.EmptyGroups)" -ForegroundColor $(if ($summary.EmptyGroups -gt 0) { "Yellow" } else { "Green" })

Write-Host "`nActivity Status:" -ForegroundColor White
Write-Host "  - Active Groups (Score > 50%): $($summary.ActiveGroups)" -ForegroundColor Green
Write-Host "  - Inactive Groups ($DaysInactive+ days): $($summary.InactiveGroups)" -ForegroundColor Yellow

Write-Host "`nRisk Assessment:" -ForegroundColor White
Write-Host "  - Critical Risk (180+ days): $($summary.CriticalRiskGroups)" -ForegroundColor $(if ($summary.CriticalRiskGroups -gt 0) { "Red" } else { "Green" })
Write-Host "  - High Risk (90+ days): $($summary.HighRiskGroups)" -ForegroundColor $(if ($summary.HighRiskGroups -gt 0) { "Yellow" } else { "Green" })

if ($leastUsedGroups.Count -gt 0) {
    Write-Host "`n[!] Top 3 Least Used Groups:" -ForegroundColor Red
    $leastUsedGroups | Select-Object -First 3 | ForEach-Object {
        Write-Host "    - $($_.GroupName): $($_.DaysSinceLastActivity) days inactive (Usage: $($_.UsageScore)%)" -ForegroundColor Yellow
    }
}

if ($mostUsedGroups.Count -gt 0) {
    Write-Host "`n[OK] Top 3 Most Used Groups:" -ForegroundColor Green
    $mostUsedGroups | Select-Object -First 3 | ForEach-Object {
        Write-Host "    - $($_.GroupName): Usage Score $($_.UsageScore)% ($($_.ActiveMembers)/$($_.UserMembers) active users)" -ForegroundColor Cyan
    }
}

Write-Host "`n[*] Analysis complete! Reports saved to:" -ForegroundColor Green
Write-Host "    $OutputFolder" -ForegroundColor Cyan

Write-Host "`n========================================`n" -ForegroundColor Cyan





