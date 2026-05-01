<#
.SYNOPSIS
    Identifies all accounts with "Password Never Expires" and checks if they have privileged permissions.

.DESCRIPTION
    This script enumerates all Active Directory user accounts that have the "Password Never Expires"
    flag enabled. It cross-references these accounts against privileged groups and identifies
    security risks associated with accounts that have both non-expiring passwords and elevated
    privileges.

.PARAMETER OutputFolder
    Path where the report will be saved. Defaults to current directory.

.PARAMETER IncludeDisabled
    Include disabled accounts in the report.

.PARAMETER CheckServiceAccounts
    Specifically identify service accounts (accounts with SPNs).

.EXAMPLE
    .\Get-PasswordNeverExpireAccounts.ps1
    
.EXAMPLE
    .\Get-PasswordNeverExpireAccounts.ps1 -OutputFolder "C:\Reports" -IncludeDisabled

.EXAMPLE
    .\Get-PasswordNeverExpireAccounts.ps1 -CheckServiceAccounts
    Include service account identification

.NOTES
    Requires: Active Directory PowerShell module
    Permissions: Domain user with read access to AD
    
    Security Note: Accounts with "Password Never Expires" violate security best practices,
    especially when combined with privileged access.
#>

param(
    [string]$OutputFolder = ".",
    [switch]$IncludeDisabled,
    [switch]$CheckServiceAccounts
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Password Never Expires Account Analysis" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get domain info
$domain = Get-ADDomain
Write-Host "[*] Domain: $($domain.DNSRoot)" -ForegroundColor Yellow

# Define privileged groups
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
    'Group Policy Creator Owners'
)

# Get members of all privileged groups
Write-Host "[*] Enumerating privileged group members..." -ForegroundColor Yellow
$privilegedMembers = @{}
$privilegedGroupDetails = @()

foreach ($groupName in $privilegedGroups) {
    try {
        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
        if ($group) {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
            Write-Host "    $groupName : $($members.Count) members" -ForegroundColor Gray
            
            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    if (-not $privilegedMembers.ContainsKey($member.SamAccountName)) {
                        $privilegedMembers[$member.SamAccountName] = @()
                    }
                    $privilegedMembers[$member.SamAccountName] += $groupName
                }
            }
            
            $privilegedGroupDetails += [PSCustomObject]@{
                GroupName = $groupName
                MemberCount = $members.Count
            }
        }
    }
    catch {
        Write-Warning "Could not enumerate group ${groupName}: $_"
    }
}

Write-Host "    [OK] Found $($privilegedMembers.Count) unique privileged user accounts" -ForegroundColor Green

# Get all accounts with Password Never Expires
Write-Host "`n[*] Querying accounts with 'Password Never Expires'..." -ForegroundColor Yellow

$properties = @(
    'SamAccountName', 'UserPrincipalName', 'DisplayName', 'Enabled',
    'PasswordLastSet', 'PasswordNeverExpires', 'lastLogonTimestamp',
    'whenCreated', 'whenChanged', 'AdminCount', 'ServicePrincipalName',
    'MemberOf', 'DistinguishedName', 'Description', 'Department', 'Title'
)

$neverExpireAccounts = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties $properties

Write-Host "    [OK] Found $($neverExpireAccounts.Count) accounts with 'Password Never Expires'" -ForegroundColor Green

# Process accounts
Write-Host "`n[*] Analyzing account privileges and risk..." -ForegroundColor Yellow
$results = foreach ($account in $neverExpireAccounts) {
    # Skip if filtering disabled accounts
    if (-not $IncludeDisabled -and -not $account.Enabled) {
        continue
    }
    
    # Calculate password age
    $passwordAge = $null
    if ($account.PasswordLastSet) {
        $passwordAge = (New-TimeSpan -Start $account.PasswordLastSet -End (Get-Date)).Days
    }
    
    # Calculate last logon
    $lastLogon = $null
    $daysSinceLogon = $null
    if ($account.lastLogonTimestamp) {
        $lastLogon = [DateTime]::FromFileTime($account.lastLogonTimestamp)
        $daysSinceLogon = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
    }
    
    # Check if privileged
    $isPrivileged = $false
    $privilegedGroupMembership = @()
    $privilegeLevel = "Standard User"
    
    if ($account.AdminCount -eq 1) {
        $isPrivileged = $true
        $privilegeLevel = "Privileged (AdminCount=1)"
    }
    
    if ($privilegedMembers.ContainsKey($account.SamAccountName)) {
        $isPrivileged = $true
        $privilegedGroupMembership = $privilegedMembers[$account.SamAccountName]
        $privilegeLevel = "Privileged: " + ($privilegedGroupMembership -join ", ")
    }
    
    # Check if service account
    $isServiceAccount = $false
    $spnCount = 0
    if ($CheckServiceAccounts -and $account.ServicePrincipalName) {
        $isServiceAccount = $true
        $spnCount = $account.ServicePrincipalName.Count
    }
    
    # Determine risk level
    $riskLevel = "Low"
    $riskFactors = @()
    
    if ($isPrivileged) {
        $riskLevel = "Critical"
        $riskFactors += "Privileged account"
    }
    
    if ($account.Enabled -eq $false) {
        $riskFactors += "Disabled account"
    }
    
    if ($daysSinceLogon -gt 180) {
        $riskLevel = if ($riskLevel -eq "Critical") { "Critical" } else { "High" }
        $riskFactors += "No logon in 180+ days"
    }
    elseif ($daysSinceLogon -gt 90) {
        $riskLevel = if ($riskLevel -eq "Critical") { "Critical" } elseif ($riskLevel -eq "High") { "High" } else { "Medium" }
        $riskFactors += "No logon in 90+ days"
    }
    
    if ($passwordAge -gt 365) {
        $riskLevel = if ($riskLevel -eq "Critical") { "Critical" } elseif ($riskLevel -eq "High") { "High" } else { "Medium" }
        $riskFactors += "Password over 1 year old"
    }
    
    if (-not $account.PasswordLastSet) {
        $riskLevel = "High"
        $riskFactors += "Password never set"
    }
    
    # Create result object
    [PSCustomObject]@{
        SamAccountName = $account.SamAccountName
        UserPrincipalName = $account.UserPrincipalName
        DisplayName = $account.DisplayName
        Enabled = $account.Enabled
        Department = $account.Department
        Title = $account.Title
        Description = $account.Description
        IsPrivileged = $isPrivileged
        PrivilegeLevel = $privilegeLevel
        PrivilegedGroups = ($privilegedGroupMembership -join "; ")
        AdminCount = $account.AdminCount
        IsServiceAccount = $isServiceAccount
        SPNCount = $spnCount
        PasswordLastSet = $account.PasswordLastSet
        PasswordAge_Days = $passwordAge
        LastLogon = $lastLogon
        DaysSinceLogon = $daysSinceLogon
        WhenCreated = $account.whenCreated
        RiskLevel = $riskLevel
        RiskFactors = ($riskFactors -join "; ")
        DistinguishedName = $account.DistinguishedName
    }
}

# Display summary statistics
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Accounts with 'Password Never Expires': $($results.Count)" -ForegroundColor White

$privilegedNeverExpire = $results | Where-Object { $_.IsPrivileged -eq $true }
$enabledNeverExpire = $results | Where-Object { $_.Enabled -eq $true }
$staleNeverExpire = $results | Where-Object { $_.DaysSinceLogon -gt 90 }
$criticalRisk = $results | Where-Object { $_.RiskLevel -eq "Critical" }
$highRisk = $results | Where-Object { $_.RiskLevel -eq "High" }
$mediumRisk = $results | Where-Object { $_.RiskLevel -eq "Medium" }

Write-Host "`nAccount Status:" -ForegroundColor Cyan
Write-Host "  Enabled: $($enabledNeverExpire.Count)" -ForegroundColor Green
Write-Host "  Disabled: $(($results | Where-Object { $_.Enabled -eq $false }).Count)" -ForegroundColor Gray

Write-Host "`nPrivilege Analysis:" -ForegroundColor Cyan
Write-Host "  Privileged Accounts: $($privilegedNeverExpire.Count)" -ForegroundColor Red
Write-Host "  Standard Accounts: $(($results | Where-Object { $_.IsPrivileged -eq $false }).Count)" -ForegroundColor White

if ($CheckServiceAccounts) {
    $serviceAccounts = $results | Where-Object { $_.IsServiceAccount -eq $true }
    Write-Host "  Service Accounts (with SPNs): $($serviceAccounts.Count)" -ForegroundColor Magenta
}

Write-Host "`nRisk Distribution:" -ForegroundColor Cyan
Write-Host "  Critical Risk: $($criticalRisk.Count)" -ForegroundColor Red
Write-Host "  High Risk: $($highRisk.Count)" -ForegroundColor DarkYellow
Write-Host "  Medium Risk: $($mediumRisk.Count)" -ForegroundColor Yellow
Write-Host "  Low Risk: $(($results | Where-Object { $_.RiskLevel -eq "Low" }).Count)" -ForegroundColor Green

Write-Host "`nActivity Analysis:" -ForegroundColor Cyan
Write-Host "  Accounts inactive 90+ days: $($staleNeverExpire.Count)" -ForegroundColor Yellow

# Critical findings
if ($privilegedNeverExpire.Count -gt 0) {
    Write-Host "`n[!] CRITICAL: $($privilegedNeverExpire.Count) PRIVILEGED accounts have 'Password Never Expires' enabled!" -ForegroundColor Red
    Write-Host "    This is a significant security risk and violates best practices." -ForegroundColor Red
    
    # Show the privileged accounts
    Write-Host "`n    Privileged accounts with password never expires:" -ForegroundColor Yellow
    $privilegedNeverExpire | 
        Select-Object SamAccountName, PrivilegedGroups, Enabled, DaysSinceLogon |
        Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
}

# Export results
Write-Host "`n[*] Exporting results..." -ForegroundColor Yellow

# Export all accounts
$allAccountsPath = Join-Path $OutputFolder "PasswordNeverExpire-All-$timestamp.csv"
$results | Sort-Object RiskLevel, IsPrivileged -Descending | Export-Csv -Path $allAccountsPath -NoTypeInformation
Write-Host "    [OK] All accounts: $allAccountsPath" -ForegroundColor Green

# Export privileged accounts only
if ($privilegedNeverExpire.Count -gt 0) {
    $privilegedPath = Join-Path $OutputFolder "PasswordNeverExpire-Privileged-$timestamp.csv"
    $privilegedNeverExpire | Sort-Object PrivilegeLevel | Export-Csv -Path $privilegedPath -NoTypeInformation
    Write-Host "    [OK] Privileged accounts: $privilegedPath" -ForegroundColor Green
}

# Export high/critical risk accounts
$highRiskAccounts = $results | Where-Object { $_.RiskLevel -in @("Critical", "High") }
if ($highRiskAccounts.Count -gt 0) {
    $highRiskPath = Join-Path $OutputFolder "PasswordNeverExpire-HighRisk-$timestamp.csv"
    $highRiskAccounts | Sort-Object RiskLevel, DaysSinceLogon -Descending | Export-Csv -Path $highRiskPath -NoTypeInformation
    Write-Host "    [OK] High/Critical risk accounts: $highRiskPath" -ForegroundColor Green
}

# Export service accounts if checked
if ($CheckServiceAccounts) {
    $serviceAccounts = $results | Where-Object { $_.IsServiceAccount -eq $true }
    if ($serviceAccounts.Count -gt 0) {
        $serviceAccountsPath = Join-Path $OutputFolder "PasswordNeverExpire-ServiceAccounts-$timestamp.csv"
        $serviceAccounts | Sort-Object IsPrivileged, SPNCount -Descending | Export-Csv -Path $serviceAccountsPath -NoTypeInformation
        Write-Host "    [OK] Service accounts: $serviceAccountsPath" -ForegroundColor Green
    }
}

# Generate HTML report
$htmlPath = Join-Path $OutputFolder "PasswordNeverExpire-$timestamp.html"
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Password Never Expires Account Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #d32f2f; }
        h2 { color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 5px; margin-top: 30px; }
        .summary { background-color: #fff; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-top: 15px; }
        .stat-box { padding: 15px; border-radius: 5px; text-align: center; }
        .stat-label { font-weight: bold; color: #666; font-size: 11px; text-transform: uppercase; }
        .stat-value { font-size: 28px; font-weight: bold; margin-top: 5px; }
        .box-red { background-color: #ffebee; color: #c62828; }
        .box-orange { background-color: #fff3e0; color: #e65100; }
        .box-yellow { background-color: #fff9c4; color: #f57f17; }
        .box-green { background-color: #e8f5e9; color: #2e7d32; }
        .box-blue { background-color: #e3f2fd; color: #1565c0; }
        .critical-alert { background-color: #f8d7da; border: 2px solid #dc3545; padding: 15px; margin: 15px 0; border-radius: 5px; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        table { border-collapse: collapse; width: 100%; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; font-size: 13px; }
        th { background-color: #1976d2; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .risk-critical { background-color: #ffcdd2; font-weight: bold; }
        .risk-high { background-color: #ffe0b2; }
        .risk-medium { background-color: #fff9c4; }
        .risk-low { background-color: #f5f5f5; }
        .privileged { border-left: 4px solid #d32f2f; }
        .disabled { color: #999; font-style: italic; }
        .recommendations { background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-top: 20px; }
        .recommendations h3 { color: #2e7d32; margin-top: 0; }
        .recommendations ul { line-height: 1.8; }
    </style>
</head>
<body>
    <h1>Password Never Expires Account Report</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p><strong>Domain:</strong> $($domain.DNSRoot)</p>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stat-grid">
            <div class="stat-box box-blue">
                <div class="stat-label">Total Accounts</div>
                <div class="stat-value">$($results.Count)</div>
            </div>
            <div class="stat-box box-red">
                <div class="stat-label">Privileged</div>
                <div class="stat-value">$($privilegedNeverExpire.Count)</div>
            </div>
            <div class="stat-box box-red">
                <div class="stat-label">Critical Risk</div>
                <div class="stat-value">$($criticalRisk.Count)</div>
            </div>
            <div class="stat-box box-orange">
                <div class="stat-label">High Risk</div>
                <div class="stat-value">$($highRisk.Count)</div>
            </div>
            <div class="stat-box box-yellow">
                <div class="stat-label">Medium Risk</div>
                <div class="stat-value">$($mediumRisk.Count)</div>
            </div>
            <div class="stat-box box-green">
                <div class="stat-label">Low Risk</div>
                <div class="stat-value">$(($results | Where-Object { $_.RiskLevel -eq "Low" }).Count)</div>
            </div>
        </div>
    </div>
    
    $(if ($privilegedNeverExpire.Count -gt 0) {
        "<div class='critical-alert'>
            <h3 style='color: #d32f2f; margin-top: 0;'>CRITICAL SECURITY RISK</h3>
            <p><strong>$($privilegedNeverExpire.Count) privileged accounts have 'Password Never Expires' enabled!</strong></p>
            <p>This is a severe security vulnerability. Privileged accounts should always have password expiration policies enforced.</p>
        </div>"
    })
    
    $(if ($staleNeverExpire.Count -gt 0) {
        "<div class='warning'><strong>WARNING:</strong> $($staleNeverExpire.Count) accounts have not logged on in 90+ days. Consider disabling these accounts.</div>"
    })
    
    <h2>Privileged Accounts with Password Never Expires</h2>
    $(if ($privilegedNeverExpire.Count -gt 0) {
        "<p style='color: #d32f2f;'><strong>Action Required:</strong> These accounts require immediate attention.</p>
        <table>
            <tr>
                <th>Account</th>
                <th>Display Name</th>
                <th>Privileged Groups</th>
                <th>Enabled</th>
                <th>Password Age (Days)</th>
                <th>Last Logon</th>
                <th>Days Since Logon</th>
                <th>Risk Factors</th>
            </tr>
            $(foreach ($account in ($privilegedNeverExpire | Sort-Object RiskLevel, DaysSinceLogon -Descending)) {
                $rowClass = "risk-" + $account.RiskLevel.ToLower() + " privileged"
                if (-not $account.Enabled) { $rowClass += " disabled" }
                "<tr class='$rowClass'>
                    <td><strong>$($account.SamAccountName)</strong></td>
                    <td>$($account.DisplayName)</td>
                    <td style='font-size: 11px;'>$($account.PrivilegedGroups)</td>
                    <td>$($account.Enabled)</td>
                    <td>$($account.PasswordAge_Days)</td>
                    <td>$($account.LastLogon)</td>
                    <td>$($account.DaysSinceLogon)</td>
                    <td style='font-size: 11px;'>$($account.RiskFactors)</td>
                </tr>"
            })
        </table>"
    } else {
        "<p style='color: #2e7d32;'><strong>Good News:</strong> No privileged accounts have 'Password Never Expires' enabled.</p>"
    })
    
    <h2>High/Critical Risk Accounts</h2>
    $(if ($highRiskAccounts.Count -gt 0) {
        "<table>
            <tr>
                <th>Account</th>
                <th>Display Name</th>
                <th>Risk Level</th>
                <th>Is Privileged</th>
                <th>Enabled</th>
                <th>Password Age</th>
                <th>Days Since Logon</th>
                <th>Risk Factors</th>
            </tr>
            $(foreach ($account in ($highRiskAccounts | Sort-Object RiskLevel, IsPrivileged -Descending)) {
                $rowClass = "risk-" + $account.RiskLevel.ToLower()
                if (-not $account.Enabled) { $rowClass += " disabled" }
                "<tr class='$rowClass'>
                    <td>$($account.SamAccountName)</td>
                    <td>$($account.DisplayName)</td>
                    <td><strong>$($account.RiskLevel)</strong></td>
                    <td>$($account.IsPrivileged)</td>
                    <td>$($account.Enabled)</td>
                    <td>$($account.PasswordAge_Days)</td>
                    <td>$($account.DaysSinceLogon)</td>
                    <td style='font-size: 11px;'>$($account.RiskFactors)</td>
                </tr>"
            })
        </table>"
    } else {
        "<p style='color: #2e7d32;'>No high or critical risk accounts identified.</p>"
    })
    
    <h2>All Accounts with Password Never Expires</h2>
    <table>
        <tr>
            <th>Account</th>
            <th>Display Name</th>
            <th>Department</th>
            <th>Risk Level</th>
            <th>Is Privileged</th>
            <th>Enabled</th>
            <th>Password Age</th>
            <th>Days Since Logon</th>
        </tr>
        $(foreach ($account in ($results | Sort-Object RiskLevel, IsPrivileged -Descending)) {
            $rowClass = "risk-" + $account.RiskLevel.ToLower()
            if (-not $account.Enabled) { $rowClass += " disabled" }
            if ($account.IsPrivileged) { $rowClass += " privileged" }
            "<tr class='$rowClass'>
                <td>$($account.SamAccountName)</td>
                <td>$($account.DisplayName)</td>
                <td>$($account.Department)</td>
                <td>$($account.RiskLevel)</td>
                <td>$($account.IsPrivileged)</td>
                <td>$($account.Enabled)</td>
                <td>$($account.PasswordAge_Days)</td>
                <td>$($account.DaysSinceLogon)</td>
            </tr>"
        })
    </table>
    
    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li><strong>Privileged Accounts:</strong> Immediately remove 'Password Never Expires' flag from all privileged accounts. Enforce regular password changes (every 90 days recommended).</li>
            <li><strong>Service Accounts:</strong> Consider using Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA) which handle password management automatically.</li>
            <li><strong>Stale Accounts:</strong> Disable accounts that haven't logged on in 90+ days after verification with account owners.</li>
            <li><strong>Password Policy:</strong> Review and enforce a strong password policy with maximum password age of 90 days for privileged accounts.</li>
            <li><strong>Monitoring:</strong> Implement ongoing monitoring to prevent new accounts from being created with 'Password Never Expires' enabled.</li>
            <li><strong>Audit:</strong> Conduct quarterly reviews of accounts with 'Password Never Expires' to ensure business justification.</li>
        </ul>
    </div>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "    [OK] HTML Report: $htmlPath" -ForegroundColor Green

# Display risk distribution chart (text-based)
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "RISK DISTRIBUTION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$criticalBar = "█" * [Math]::Min(($criticalRisk.Count), 50)
$highBar = "█" * [Math]::Min(($highRisk.Count), 50)
$mediumBar = "█" * [Math]::Min(($mediumRisk.Count), 50)
$lowBar = "█" * [Math]::Min((($results | Where-Object { $_.RiskLevel -eq "Low" }).Count), 50)

Write-Host "Critical: " -NoNewline; Write-Host $criticalBar -ForegroundColor Red -NoNewline; Write-Host " ($($criticalRisk.Count))"
Write-Host "High    : " -NoNewline; Write-Host $highBar -ForegroundColor DarkYellow -NoNewline; Write-Host " ($($highRisk.Count))"
Write-Host "Medium  : " -NoNewline; Write-Host $mediumBar -ForegroundColor Yellow -NoNewline; Write-Host " ($($mediumRisk.Count))"
Write-Host "Low     : " -NoNewline; Write-Host $lowBar -ForegroundColor Green -NoNewline; Write-Host " ($(($results | Where-Object { $_.RiskLevel -eq "Low" }).Count))"

Write-Host "`n[*] Analysis complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan




