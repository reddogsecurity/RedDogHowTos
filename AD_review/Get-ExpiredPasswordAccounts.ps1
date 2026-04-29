<#
.SYNOPSIS
    Identifies user accounts with expired passwords and their last logon times.

.DESCRIPTION
    This script queries Active Directory for user accounts that have expired passwords,
    including detailed information about password expiration dates and last logon times.
    It retrieves the maximum password age from the domain policy and calculates which
    accounts have expired passwords.

.PARAMETER OutputFolder
    Path where the report will be saved. Defaults to current directory.

.PARAMETER IncludeDisabled
    Include disabled accounts in the report.

.EXAMPLE
    .\Get-ExpiredPasswordAccounts.ps1
    
.EXAMPLE
    .\Get-ExpiredPasswordAccounts.ps1 -OutputFolder "C:\Reports" -IncludeDisabled

.NOTES
    Requires: Active Directory PowerShell module
    Permissions: Domain user with read access to AD
#>

param(
    [string]$OutputFolder = ".",
    [switch]$IncludeDisabled
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Expired Password Account Analysis" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get domain password policy
Write-Host "[*] Retrieving domain password policy..." -ForegroundColor Yellow
$domainPolicy = Get-ADDefaultDomainPasswordPolicy
$maxPasswordAge = $domainPolicy.MaxPasswordAge.Days

if ($maxPasswordAge -eq 0) {
    Write-Warning "Domain password policy has MaxPasswordAge set to 0 (passwords never expire by policy)."
    $maxPasswordAge = 90  # Default to 90 days for calculation
    Write-Host "    Using 90 days as default for calculation." -ForegroundColor Gray
} else {
    Write-Host "    Max Password Age: $maxPasswordAge days" -ForegroundColor Green
}

# Build filter based on parameters
$filter = "*"
if (-not $IncludeDisabled) {
    Write-Host "[*] Filtering for enabled accounts only..." -ForegroundColor Yellow
}

# Get all users with password and logon information
Write-Host "[*] Querying Active Directory for user accounts..." -ForegroundColor Yellow
$users = Get-ADUser -Filter $filter -Properties `
    SamAccountName, UserPrincipalName, Enabled, DisplayName, `
    PasswordLastSet, PasswordNeverExpires, PasswordExpired, `
    lastLogonTimestamp, lastLogon, whenCreated, whenChanged, `
    AdminCount, MemberOf, DistinguishedName, Department, Title, `
    MailNickname, mail

Write-Host "    Found $($users.Count) total user accounts" -ForegroundColor Green

# Process users to identify expired passwords
Write-Host "`n[*] Analyzing password expiration status..." -ForegroundColor Yellow
$results = foreach ($user in $users) {
    # Skip if filtering disabled accounts
    if (-not $IncludeDisabled -and -not $user.Enabled) {
        continue
    }
    
    # Calculate password age
    $passwordAge = $null
    $passwordExpirationDate = $null
    $isExpired = $false
    $daysUntilExpiration = $null
    
    if ($user.PasswordLastSet -and -not $user.PasswordNeverExpires) {
        $passwordAge = (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
        $passwordExpirationDate = $user.PasswordLastSet.AddDays($maxPasswordAge)
        $daysUntilExpiration = (New-TimeSpan -Start (Get-Date) -End $passwordExpirationDate).Days
        
        if ($daysUntilExpiration -lt 0) {
            $isExpired = $true
        }
    } elseif (-not $user.PasswordLastSet) {
        $isExpired = $true  # Never set password
    }
    
    # Get last logon (use most recent between lastLogon and lastLogonTimestamp)
    $lastLogonDate = $null
    $daysSinceLastLogon = $null
    
    if ($user.lastLogonTimestamp) {
        $lastLogonDate = [DateTime]::FromFileTime($user.lastLogonTimestamp)
        $daysSinceLastLogon = (New-TimeSpan -Start $lastLogonDate -End (Get-Date)).Days
    }
    
    # Check if user is privileged
    $isPrivileged = $false
    if ($user.AdminCount -eq 1) {
        $isPrivileged = $true
    }
    
    # Create result object (include all users or only expired based on reporting needs)
    [PSCustomObject]@{
        SamAccountName = $user.SamAccountName
        UserPrincipalName = $user.UserPrincipalName
        DisplayName = $user.DisplayName
        Enabled = $user.Enabled
        Department = $user.Department
        Title = $user.Title
        Email = $user.mail
        PasswordLastSet = $user.PasswordLastSet
        PasswordAge_Days = $passwordAge
        PasswordExpirationDate = $passwordExpirationDate
        DaysUntilExpiration = $daysUntilExpiration
        PasswordExpired = $isExpired
        PasswordNeverExpires = $user.PasswordNeverExpires
        LastLogonDate = $lastLogonDate
        DaysSinceLastLogon = $daysSinceLastLogon
        IsPrivilegedAccount = $isPrivileged
        WhenCreated = $user.whenCreated
        WhenChanged = $user.whenChanged
        DistinguishedName = $user.DistinguishedName
    }
}

# Filter for expired passwords only
$expiredPasswordAccounts = $results | Where-Object { $_.PasswordExpired -eq $true }
$expiringSoon = $results | Where-Object { 
    $_.PasswordExpired -eq $false -and 
    $_.DaysUntilExpiration -ne $null -and 
    $_.DaysUntilExpiration -le 14 -and 
    $_.DaysUntilExpiration -gt 0 
}

# Display summary statistics
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Accounts Analyzed: $($results.Count)" -ForegroundColor White
Write-Host "Accounts with EXPIRED Passwords: $($expiredPasswordAccounts.Count)" -ForegroundColor Red
Write-Host "Accounts with Passwords Expiring Soon (14 days): $($expiringSoon.Count)" -ForegroundColor Yellow
Write-Host "Password Never Expires Accounts: $(($results | Where-Object { $_.PasswordNeverExpires -eq $true }).Count)" -ForegroundColor Magenta

$privilegedExpired = $expiredPasswordAccounts | Where-Object { $_.IsPrivilegedAccount -eq $true }
if ($privilegedExpired.Count -gt 0) {
    Write-Host "`n[!] WARNING: $($privilegedExpired.Count) PRIVILEGED accounts have expired passwords!" -ForegroundColor Red
}

$staleExpired = $expiredPasswordAccounts | Where-Object { $_.DaysSinceLastLogon -gt 90 }
Write-Host "`nAccounts with expired passwords AND no logon in 90+ days: $($staleExpired.Count)" -ForegroundColor Yellow

# Export results
Write-Host "`n[*] Exporting results..." -ForegroundColor Yellow

# Export expired password accounts
if ($expiredPasswordAccounts.Count -gt 0) {
    $expiredPath = Join-Path $OutputFolder "ExpiredPasswordAccounts-$timestamp.csv"
    $expiredPasswordAccounts | Export-Csv -Path $expiredPath -NoTypeInformation
    Write-Host "    [OK] Expired password accounts: $expiredPath" -ForegroundColor Green
    
    # Top 10 expired by last logon
    Write-Host "`n[*] Top 10 expired password accounts by last logon:" -ForegroundColor Cyan
    $expiredPasswordAccounts | 
        Sort-Object DaysSinceLastLogon -Descending | 
        Select-Object -First 10 SamAccountName, DisplayName, LastLogonDate, DaysSinceLastLogon, PasswordLastSet, IsPrivilegedAccount |
        Format-Table -AutoSize
}

# Export expiring soon
if ($expiringSoon.Count -gt 0) {
    $expiringSoonPath = Join-Path $OutputFolder "PasswordsExpiringSoon-$timestamp.csv"
    $expiringSoon | Export-Csv -Path $expiringSoonPath -NoTypeInformation
    Write-Host "    [OK] Passwords expiring soon (14 days): $expiringSoonPath" -ForegroundColor Green
}

# Export full analysis (all accounts)
$allAccountsPath = Join-Path $OutputFolder "AllAccountsPasswordAnalysis-$timestamp.csv"
$results | Export-Csv -Path $allAccountsPath -NoTypeInformation
Write-Host "    [OK] Complete password analysis: $allAccountsPath" -ForegroundColor Green

# Generate HTML report for easy viewing
$htmlPath = Join-Path $OutputFolder "ExpiredPasswordReport-$timestamp.html"
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Expired Password Account Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #d32f2f; }
        h2 { color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }
        .summary { background-color: #fff; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-label { font-weight: bold; color: #666; }
        .stat-value { font-size: 24px; font-weight: bold; color: #d32f2f; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        .critical { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }
        table { border-collapse: collapse; width: 100%; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #1976d2; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .expired { color: #d32f2f; font-weight: bold; }
        .privileged { background-color: #fff9c4; }
        .stale { color: #ff6f00; }
    </style>
</head>
<body>
    <h1>Expired Password Account Report</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p><strong>Domain:</strong> $((Get-ADDomain).DNSRoot)</p>
    <p><strong>Max Password Age Policy:</strong> $maxPasswordAge days</p>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stat">
            <div class="stat-label">Total Accounts</div>
            <div class="stat-value" style="color: #1976d2;">$($results.Count)</div>
        </div>
        <div class="stat">
            <div class="stat-label">Expired Passwords</div>
            <div class="stat-value">$($expiredPasswordAccounts.Count)</div>
        </div>
        <div class="stat">
            <div class="stat-label">Expiring Soon (14d)</div>
            <div class="stat-value" style="color: #ff9800;">$($expiringSoon.Count)</div>
        </div>
        <div class="stat">
            <div class="stat-label">Never Expires</div>
            <div class="stat-value" style="color: #9c27b0;">$(($results | Where-Object { $_.PasswordNeverExpires }).Count)</div>
        </div>
    </div>
    
    $(if ($privilegedExpired.Count -gt 0) {
        "<div class='critical'><strong>CRITICAL:</strong> $($privilegedExpired.Count) privileged accounts have expired passwords!</div>"
    })
    
    $(if ($staleExpired.Count -gt 0) {
        "<div class='warning'><strong>WARNING:</strong> $($staleExpired.Count) accounts have both expired passwords and no logon activity in 90+ days.</div>"
    })
    
    <h2>Accounts with Expired Passwords</h2>
    <table>
        <tr>
            <th>Username</th>
            <th>Display Name</th>
            <th>Enabled</th>
            <th>Last Logon</th>
            <th>Days Since Logon</th>
            <th>Password Last Set</th>
            <th>Password Age (Days)</th>
            <th>Privileged</th>
        </tr>
        $(foreach ($account in ($expiredPasswordAccounts | Sort-Object DaysSinceLastLogon -Descending)) {
            $rowClass = if ($account.IsPrivilegedAccount) { " class='privileged'" } else { "" }
            $staleClass = if ($account.DaysSinceLastLogon -gt 90) { " class='stale'" } else { "" }
            "<tr$rowClass>
                <td>$($account.SamAccountName)</td>
                <td>$($account.DisplayName)</td>
                <td>$($account.Enabled)</td>
                <td$staleClass>$($account.LastLogonDate)</td>
                <td$staleClass>$($account.DaysSinceLastLogon)</td>
                <td>$($account.PasswordLastSet)</td>
                <td class='expired'>$($account.PasswordAge_Days)</td>
                <td>$($account.IsPrivilegedAccount)</td>
            </tr>"
        })
    </table>
    
    <h2>Passwords Expiring Soon (Next 14 Days)</h2>
    <table>
        <tr>
            <th>Username</th>
            <th>Display Name</th>
            <th>Days Until Expiration</th>
            <th>Expiration Date</th>
            <th>Last Logon</th>
        </tr>
        $(foreach ($account in ($expiringSoon | Sort-Object DaysUntilExpiration)) {
            "<tr>
                <td>$($account.SamAccountName)</td>
                <td>$($account.DisplayName)</td>
                <td style='font-weight: bold; color: #ff9800;'>$($account.DaysUntilExpiration)</td>
                <td>$($account.PasswordExpirationDate)</td>
                <td>$($account.LastLogonDate)</td>
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




