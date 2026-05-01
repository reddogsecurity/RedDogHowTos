<#
.SYNOPSIS
    Lists all members of privileged Active Directory groups including Domain Admins and Enterprise Admins.

.DESCRIPTION
    This script enumerates membership of critical privileged groups in Active Directory,
    including Domain Admins, Enterprise Admins, Schema Admins, and other built-in
    administrative groups. It provides detailed information about each member including
    their last logon time, account status, and whether MFA is enabled (if Entra integration is available).

.PARAMETER OutputFolder
    Path where the report will be saved. Defaults to current directory.

.PARAMETER IncludeNested
    Recursively enumerate nested group memberships.

.PARAMETER CheckEntraMFA
    Check if members have MFA enabled in Entra ID (requires Microsoft Graph connection).

.EXAMPLE
    .\Get-PrivilegedGroupMembers.ps1
    
.EXAMPLE
    .\Get-PrivilegedGroupMembers.ps1 -OutputFolder "C:\Reports" -IncludeNested

.EXAMPLE
    .\Get-PrivilegedGroupMembers.ps1 -CheckEntraMFA
    Check privileged accounts and their MFA status in Entra ID

.NOTES
    Requires: Active Directory PowerShell module
    Optional: Microsoft.Graph modules for MFA status check
    Permissions: Domain user with read access to AD
#>

param(
    [string]$OutputFolder = ".",
    [switch]$IncludeNested,
    [switch]$CheckEntraMFA
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Privileged Group Membership Analysis" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get domain info
$domain = Get-ADDomain
$forest = Get-ADForest
Write-Host "[*] Domain: $($domain.DNSRoot)" -ForegroundColor Yellow
Write-Host "[*] Forest: $($forest.Name)" -ForegroundColor Yellow
Write-Host "[*] Recursive membership: $IncludeNested`n" -ForegroundColor Yellow

# Define privileged groups to check
$privilegedGroups = @(
    @{Name='Enterprise Admins'; Scope='Forest'; Description='Full control over the entire forest'},
    @{Name='Schema Admins'; Scope='Forest'; Description='Can modify the Active Directory schema'},
    @{Name='Domain Admins'; Scope='Domain'; Description='Full control over the domain'},
    @{Name='Administrators'; Scope='BuiltIn'; Description='Built-in administrators group'},
    @{Name='Account Operators'; Scope='BuiltIn'; Description='Can create and manage user accounts'},
    @{Name='Server Operators'; Scope='BuiltIn'; Description='Can manage domain servers'},
    @{Name='Backup Operators'; Scope='BuiltIn'; Description='Can backup and restore files'},
    @{Name='Print Operators'; Scope='BuiltIn'; Description='Can manage printers'},
    @{Name='DnsAdmins'; Scope='Domain'; Description='Can administer DNS service'},
    @{Name='Group Policy Creator Owners'; Scope='Domain'; Description='Can create and modify GPOs'},
    @{Name='Enterprise Read-only Domain Controllers'; Scope='Forest'; Description='Read-only domain controller accounts'},
    @{Name='Read-only Domain Controllers'; Scope='Domain'; Description='Read-only domain controller accounts'}
)

# Check MFA status if requested
$mfaStatusMap = @{}
if ($CheckEntraMFA) {
    Write-Host "[*] Checking Entra ID MFA status..." -ForegroundColor Yellow
    
    try {
        # Check if Graph modules are available
        $graphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Users')
        $modulesAvailable = $true
        
        foreach ($module in $graphModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Warning "Module $module not found. Install with: Install-Module $module"
                $modulesAvailable = $false
            }
        }
        
        if ($modulesAvailable) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
            Import-Module Microsoft.Graph.Users -ErrorAction Stop
            
            # Connect to Graph
            Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "User.Read.All" -NoWelcome -ErrorAction Stop
            
            # Get all users and their MFA methods
            Write-Host "    Querying Entra ID for MFA registration status..." -ForegroundColor Gray
            $entraUsers = Get-MgUser -All -Property UserPrincipalName, Id
            
            foreach ($user in $entraUsers) {
                try {
                    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                    $hasMFA = ($authMethods | Where-Object { $_.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }).Count -gt 0
                    $mfaStatusMap[$user.UserPrincipalName] = $hasMFA
                } catch {
                    $mfaStatusMap[$user.UserPrincipalName] = "Error"
                }
            }
            
            Write-Host "    [OK] Retrieved MFA status for $($mfaStatusMap.Count) users" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to check Entra MFA status: $_"
        $CheckEntraMFA = $false
    }
}

# Function to get detailed member information
function Get-DetailedMemberInfo {
    param(
        [Parameter(Mandatory=$true)]
        $Member,
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string]$GroupScope
    )
    
    $memberType = $Member.objectClass
    $details = [PSCustomObject]@{
        GroupName = $GroupName
        GroupScope = $GroupScope
        MemberName = $Member.Name
        MemberSamAccountName = $Member.SamAccountName
        MemberType = $memberType
        MemberUPN = $null
        Enabled = $null
        LastLogon = $null
        DaysSinceLogon = $null
        PasswordLastSet = $null
        PasswordNeverExpires = $null
        AdminCount = $null
        MFAEnabled = $null
        DistinguishedName = $Member.DistinguishedName
    }
    
    # Get additional details for user accounts
    if ($memberType -eq 'user') {
        try {
            $userDetails = Get-ADUser -Identity $Member.SamAccountName -Properties `
                UserPrincipalName, Enabled, lastLogonTimestamp, PasswordLastSet, `
                PasswordNeverExpires, AdminCount -ErrorAction Stop
            
            $details.MemberUPN = $userDetails.UserPrincipalName
            $details.Enabled = $userDetails.Enabled
            $details.PasswordLastSet = $userDetails.PasswordLastSet
            $details.PasswordNeverExpires = $userDetails.PasswordNeverExpires
            $details.AdminCount = $userDetails.AdminCount
            
            if ($userDetails.lastLogonTimestamp) {
                $details.LastLogon = [DateTime]::FromFileTime($userDetails.lastLogonTimestamp)
                $details.DaysSinceLogon = (New-TimeSpan -Start $details.LastLogon -End (Get-Date)).Days
            }
            
            # Check MFA status if available
            if ($CheckEntraMFA -and $mfaStatusMap.ContainsKey($userDetails.UserPrincipalName)) {
                $details.MFAEnabled = $mfaStatusMap[$userDetails.UserPrincipalName]
            }
        }
        catch {
            Write-Warning "Could not retrieve details for user $($Member.SamAccountName): $_"
        }
    }
    
    return $details
}

# Enumerate each privileged group
$allResults = @()
$groupSummary = @()

foreach ($groupInfo in $privilegedGroups) {
    $groupName = $groupInfo.Name
    Write-Host "`n[*] Checking group: $groupName ($($groupInfo.Scope))" -ForegroundColor Cyan
    Write-Host "    Description: $($groupInfo.Description)" -ForegroundColor Gray
    
    try {
        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
        
        if ($group) {
            # Get members (recursive or direct) - force array to handle single-member groups properly
            if ($IncludeNested) {
                $members = @(Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop)
                Write-Host "    [OK] Found $($members.Count) members (including nested)" -ForegroundColor Green
            }
            else {
                $members = @(Get-ADGroupMember -Identity $group -ErrorAction Stop)
                Write-Host "    [OK] Found $($members.Count) direct members" -ForegroundColor Green
            }
            
            # Get detailed information for each member
            $memberCount = 0
            $userCount = 0
            $groupCount = 0
            $computerCount = 0
            
            foreach ($member in $members) {
                $memberDetails = Get-DetailedMemberInfo -Member $member -GroupName $groupName -GroupScope $groupInfo.Scope
                $allResults += $memberDetails
                
                $memberCount++
                switch ($member.objectClass) {
                    'user' { $userCount++ }
                    'group' { $groupCount++ }
                    'computer' { $computerCount++ }
                }
            }
            
            # Add to summary
            $groupSummary += [PSCustomObject]@{
                GroupName = $groupName
                Scope = $groupInfo.Scope
                Description = $groupInfo.Description
                TotalMembers = $memberCount
                Users = $userCount
                Groups = $groupCount
                Computers = $computerCount
                DistinguishedName = $group.DistinguishedName
            }
            
            Write-Host "    Users: $userCount | Groups: $groupCount | Computers: $computerCount" -ForegroundColor Gray
        }
        else {
            Write-Host "    [SKIP] Group not found in this domain" -ForegroundColor Yellow
            $groupSummary += [PSCustomObject]@{
                GroupName = $groupName
                Scope = $groupInfo.Scope
                Description = $groupInfo.Description
                TotalMembers = 0
                Users = 0
                Groups = 0
                Computers = 0
                DistinguishedName = "Not found"
            }
        }
    }
    catch {
        Write-Warning "Error processing group ${groupName}: $_"
        $groupSummary += [PSCustomObject]@{
            GroupName = $groupName
            Scope = $groupInfo.Scope
            Description = $groupInfo.Description
            TotalMembers = "Error"
            Users = "Error"
            Groups = "Error"
            Computers = "Error"
            DistinguishedName = "Error"
        }
    }
}

# Display summary statistics
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalPrivilegedUsers = ($allResults | Where-Object { $_.MemberType -eq 'user' } | Select-Object -Unique MemberSamAccountName).Count
$totalPrivilegedGroups = ($allResults | Where-Object { $_.MemberType -eq 'group' } | Select-Object -Unique MemberSamAccountName).Count

Write-Host "Total Unique Privileged Users: $totalPrivilegedUsers" -ForegroundColor White
Write-Host "Total Unique Privileged Groups: $totalPrivilegedGroups" -ForegroundColor White

# Critical findings
$disabledPrivileged = $allResults | Where-Object { $_.MemberType -eq 'user' -and $_.Enabled -eq $false }
$stalePrivileged = $allResults | Where-Object { $_.MemberType -eq 'user' -and $null -ne $_.DaysSinceLogon -and $_.DaysSinceLogon -gt 90 }
$neverExpiresPrivileged = $allResults | Where-Object { $_.MemberType -eq 'user' -and $_.PasswordNeverExpires -eq $true }

if ($disabledPrivileged.Count -gt 0) {
    Write-Host "`n[!] WARNING: $($disabledPrivileged.Count) DISABLED accounts in privileged groups!" -ForegroundColor Red
}

if ($stalePrivileged.Count -gt 0) {
    Write-Host "[!] WARNING: $($stalePrivileged.Count) privileged accounts with no logon in 90+ days!" -ForegroundColor Yellow
}

if ($neverExpiresPrivileged.Count -gt 0) {
    Write-Host "[!] WARNING: $($neverExpiresPrivileged.Count) privileged accounts with 'Password Never Expires'!" -ForegroundColor Yellow
}

if ($CheckEntraMFA) {
    $noMFAPrivileged = $allResults | Where-Object { $_.MemberType -eq 'user' -and $_.MFAEnabled -eq $false }
    if ($noMFAPrivileged.Count -gt 0) {
        Write-Host "[!] CRITICAL: $($noMFAPrivileged.Count) privileged accounts WITHOUT MFA enabled!" -ForegroundColor Red
    }
}

# Display group summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "GROUP SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
$groupSummary | Format-Table -AutoSize

# Export results
Write-Host "[*] Exporting results..." -ForegroundColor Yellow

# Export detailed member list
$detailedPath = Join-Path $OutputFolder "PrivilegedGroupMembers-Detailed-$timestamp.csv"
$allResults | Export-Csv -Path $detailedPath -NoTypeInformation
Write-Host "    [OK] Detailed member list: $detailedPath" -ForegroundColor Green

# Export group summary
$summaryPath = Join-Path $OutputFolder "PrivilegedGroupMembers-Summary-$timestamp.csv"
$groupSummary | Export-Csv -Path $summaryPath -NoTypeInformation
Write-Host "    [OK] Group summary: $summaryPath" -ForegroundColor Green

# Export critical findings
if ($disabledPrivileged.Count -gt 0 -or $stalePrivileged.Count -gt 0 -or $neverExpiresPrivileged.Count -gt 0) {
    $findingsPath = Join-Path $OutputFolder "PrivilegedGroupMembers-Findings-$timestamp.csv"
    $findings = @()
    
    foreach ($account in $disabledPrivileged) {
        $findings += [PSCustomObject]@{
            Finding = "Disabled privileged account"
            Severity = "High"
            Account = $account.MemberSamAccountName
            Group = $account.GroupName
            Details = "Account is disabled but still member of privileged group"
        }
    }
    
    foreach ($account in $stalePrivileged) {
        $findings += [PSCustomObject]@{
            Finding = "Stale privileged account"
            Severity = "Medium"
            Account = $account.MemberSamAccountName
            Group = $account.GroupName
            Details = "No logon activity in $($account.DaysSinceLogon) days"
        }
    }
    
    foreach ($account in $neverExpiresPrivileged) {
        $findings += [PSCustomObject]@{
            Finding = "Password never expires"
            Severity = "Medium"
            Account = $account.MemberSamAccountName
            Group = $account.GroupName
            Details = "Privileged account has password set to never expire"
        }
    }
    
    if ($CheckEntraMFA) {
        foreach ($account in $noMFAPrivileged) {
            $findings += [PSCustomObject]@{
                Finding = "No MFA enabled"
                Severity = "Critical"
                Account = $account.MemberSamAccountName
                Group = $account.GroupName
                Details = "Privileged account does not have MFA enabled in Entra ID"
            }
        }
    }
    
    $findings | Export-Csv -Path $findingsPath -NoTypeInformation
    Write-Host "    [OK] Critical findings: $findingsPath" -ForegroundColor Green
}

# Generate HTML report
$htmlPath = Join-Path $OutputFolder "PrivilegedGroupMembers-$timestamp.html"
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Privileged Group Membership Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #d32f2f; }
        h2 { color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }
        .summary { background-color: #fff; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-label { font-weight: bold; color: #666; }
        .stat-value { font-size: 24px; font-weight: bold; color: #d32f2f; }
        .critical { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        table { border-collapse: collapse; width: 100%; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        th { background-color: #1976d2; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .disabled { background-color: #ffebee; }
        .stale { background-color: #fff9c4; }
        .no-mfa { background-color: #ffcdd2; font-weight: bold; }
        .enterprise-admin { background-color: #e8f5e9; }
        .domain-admin { background-color: #e3f2fd; }
    </style>
</head>
<body>
    <h1>Privileged Group Membership Report</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p><strong>Domain:</strong> $($domain.DNSRoot)</p>
    <p><strong>Forest:</strong> $($forest.Name)</p>
    <p><strong>Recursive Membership:</strong> $IncludeNested</p>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stat">
            <div class="stat-label">Unique Privileged Users</div>
            <div class="stat-value">$totalPrivilegedUsers</div>
        </div>
        <div class="stat">
            <div class="stat-label">Privileged Groups</div>
            <div class="stat-value" style="color: #1976d2;">$totalPrivilegedGroups</div>
        </div>
    </div>
    
    $(if ($noMFAPrivileged.Count -gt 0) {
        "<div class='critical'><strong>CRITICAL:</strong> $($noMFAPrivileged.Count) privileged accounts do not have MFA enabled!</div>"
    })
    
    $(if ($disabledPrivileged.Count -gt 0) {
        "<div class='critical'><strong>HIGH RISK:</strong> $($disabledPrivileged.Count) disabled accounts still in privileged groups!</div>"
    })
    
    $(if ($stalePrivileged.Count -gt 0) {
        "<div class='warning'><strong>WARNING:</strong> $($stalePrivileged.Count) privileged accounts with no logon activity in 90+ days.</div>"
    })
    
    $(if ($neverExpiresPrivileged.Count -gt 0) {
        "<div class='warning'><strong>WARNING:</strong> $($neverExpiresPrivileged.Count) privileged accounts have 'Password Never Expires' enabled.</div>"
    })
    
    <h2>Group Summary</h2>
    <table>
        <tr>
            <th>Group Name</th>
            <th>Scope</th>
            <th>Description</th>
            <th>Total Members</th>
            <th>Users</th>
            <th>Groups</th>
            <th>Computers</th>
        </tr>
        $(foreach ($group in $groupSummary) {
            "<tr>
                <td><strong>$($group.GroupName)</strong></td>
                <td>$($group.Scope)</td>
                <td style='font-size: 11px;'>$($group.Description)</td>
                <td>$($group.TotalMembers)</td>
                <td>$($group.Users)</td>
                <td>$($group.Groups)</td>
                <td>$($group.Computers)</td>
            </tr>"
        })
    </table>
    
    <h2>Enterprise Admins Members</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Account</th>
            <th>Type</th>
            <th>Enabled</th>
            <th>Last Logon</th>
            <th>Days Since Logon</th>
            $(if ($CheckEntraMFA) { "<th>MFA</th>" } else { "" })
        </tr>
        $(foreach ($member in ($allResults | Where-Object { $_.GroupName -eq 'Enterprise Admins' } | Sort-Object MemberName)) {
            $rowClass = ""
            if ($member.Enabled -eq $false) { $rowClass = "disabled" }
            elseif ($null -ne $member.DaysSinceLogon -and $member.DaysSinceLogon -gt 90) { $rowClass = "stale" }
            elseif ($member.MFAEnabled -eq $false) { $rowClass = "no-mfa" }
            
            "<tr class='$rowClass'>
                <td>$($member.MemberName)</td>
                <td>$($member.MemberSamAccountName)</td>
                <td>$($member.MemberType)</td>
                <td>$($member.Enabled)</td>
                <td>$($member.LastLogon)</td>
                <td>$($member.DaysSinceLogon)</td>
                $(if ($CheckEntraMFA) { '<td>' + $($member.MFAEnabled) + '</td>' } else { '' })
            </tr>"
        })
    </table>
    
    <h2>Domain Admins Members</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Account</th>
            <th>Type</th>
            <th>Enabled</th>
            <th>Last Logon</th>
            <th>Days Since Logon</th>
            $(if ($CheckEntraMFA) { "<th>MFA</th>" } else { "" })
        </tr>
        $(foreach ($member in ($allResults | Where-Object { $_.GroupName -eq 'Domain Admins' } | Sort-Object MemberName)) {
            $rowClass = ""
            if ($member.Enabled -eq $false) { $rowClass = "disabled" }
            elseif ($null -ne $member.DaysSinceLogon -and $member.DaysSinceLogon -gt 90) { $rowClass = "stale" }
            elseif ($member.MFAEnabled -eq $false) { $rowClass = "no-mfa" }
            
            "<tr class='$rowClass'>
                <td>$($member.MemberName)</td>
                <td>$($member.MemberSamAccountName)</td>
                <td>$($member.MemberType)</td>
                <td>$($member.Enabled)</td>
                <td>$($member.LastLogon)</td>
                <td>$($member.DaysSinceLogon)</td>
                $(if ($CheckEntraMFA) { '<td>' + $($member.MFAEnabled) + '</td>' } else { '' })
            </tr>"
        })
    </table>
    
    <h2>All Privileged Group Members</h2>
    <table>
        <tr>
            <th>Group</th>
            <th>Name</th>
            <th>Account</th>
            <th>Type</th>
            <th>Enabled</th>
            <th>Last Logon</th>
            $(if ($CheckEntraMFA) { "<th>MFA</th>" } else { "" })
        </tr>
        $(foreach ($member in ($allResults | Sort-Object GroupName, MemberName)) {
            $rowClass = ""
            if ($member.Enabled -eq $false) { $rowClass = "disabled" }
            elseif ($null -ne $member.DaysSinceLogon -and $member.DaysSinceLogon -gt 90) { $rowClass = "stale" }
            elseif ($member.MFAEnabled -eq $false) { $rowClass = "no-mfa" }
            
            "<tr class='$rowClass'>
                <td>$($member.GroupName)</td>
                <td>$($member.MemberName)</td>
                <td>$($member.MemberSamAccountName)</td>
                <td>$($member.MemberType)</td>
                <td>$($member.Enabled)</td>
                <td>$($member.LastLogon)</td>
                $(if ($CheckEntraMFA) { '<td>' + $($member.MFAEnabled) + '</td>' } else { '' })
            </tr>"
        })
    </table>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "    [OK] HTML Report: $htmlPath" -ForegroundColor Green

Write-Host "`n[*] Analysis complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan



