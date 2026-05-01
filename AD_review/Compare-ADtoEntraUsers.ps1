<#
.SYNOPSIS
    Compares Active Directory users with Entra ID (Azure AD) users to identify synchronization gaps.

.DESCRIPTION
    This script compares user accounts between on-premises Active Directory and Entra ID
    (Azure AD) to identify:
    - Users in Entra ID but not in AD (cloud-only accounts)
    - Users in AD but not in Entra ID (not synchronized)
    - Users in both with different attributes (sync issues)
    - Orphaned accounts and licensing status

.PARAMETER OutputFolder
    Path where the report will be saved. Defaults to current directory.

.PARAMETER CompareAttributes
    Compare additional attributes like DisplayName, Email, etc. for discrepancies.

.PARAMETER IncludeLicensing
    Include license assignment information for Entra users.

.EXAMPLE
    .\Compare-ADtoEntraUsers.ps1
    
.EXAMPLE
    .\Compare-ADtoEntraUsers.ps1 -OutputFolder "C:\Reports" -CompareAttributes

.EXAMPLE
    .\Compare-ADtoEntraUsers.ps1 -IncludeLicensing
    Include Microsoft 365 license information

.NOTES
    Requires: Active Directory PowerShell module
    Requires: Microsoft.Graph modules (Authentication, Users)
    Permissions: 
      - AD: Domain user with read access
      - Entra: User.Read.All, Directory.Read.All
#>

param(
    [string]$OutputFolder = ".",
    [switch]$CompareAttributes,
    [switch]$IncludeLicensing
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

# Check Graph modules
$graphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
foreach ($module in $graphModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Module $module not found. Install with: Install-Module $module -Scope CurrentUser"
        exit 1
    }
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "AD to Entra ID User Comparison" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get AD Domain info
$domain = Get-ADDomain
$domainDNS = $domain.DNSRoot
Write-Host "[*] AD Domain: $domainDNS" -ForegroundColor Yellow

# Connect to Microsoft Graph
Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Yellow
try {
    if ($IncludeLicensing) {
        Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Organization.Read.All" -NoWelcome -ErrorAction Stop
    } else {
        Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All" -NoWelcome -ErrorAction Stop
    }
    Write-Host "    [OK] Connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Get tenant info
$tenant = Get-MgOrganization
$tenantName = $tenant.DisplayName
Write-Host "[*] Entra Tenant: $tenantName" -ForegroundColor Yellow

# Collect AD Users
Write-Host "`n[*] Collecting Active Directory users..." -ForegroundColor Yellow
$adUsers = Get-ADUser -Filter * -Properties `
    SamAccountName, UserPrincipalName, DisplayName, Enabled, `
    EmailAddress, mail, whenCreated, lastLogonTimestamp, `
    PasswordLastSet, DistinguishedName

Write-Host "    [OK] Found $($adUsers.Count) AD users" -ForegroundColor Green

# Collect Entra ID Users
Write-Host "`n[*] Collecting Entra ID users..." -ForegroundColor Yellow
$properties = @(
    "Id", "UserPrincipalName", "DisplayName", "Mail", 
    "AccountEnabled", "CreatedDateTime", "UserType", 
    "OnPremisesSyncEnabled", "OnPremisesDistinguishedName",
    "OnPremisesSamAccountName", "SignInActivity"
)

if ($IncludeLicensing) {
    $properties += "AssignedLicenses"
}

$entraUsers = Get-MgUser -All -Property ($properties -join ",") | Select-Object $properties

Write-Host "    [OK] Found $($entraUsers.Count) Entra ID users" -ForegroundColor Green

# Create lookup dictionaries
Write-Host "`n[*] Analyzing user accounts..." -ForegroundColor Yellow

$adUsersByUPN = @{}
$adUsersBySamAccount = @{}
foreach ($user in $adUsers) {
    if ($user.UserPrincipalName) {
        $adUsersByUPN[$user.UserPrincipalName.ToLower()] = $user
    }
    if ($user.SamAccountName) {
        $adUsersBySamAccount[$user.SamAccountName.ToLower()] = $user
    }
}

$entraUsersByUPN = @{}
foreach ($user in $entraUsers) {
    if ($user.UserPrincipalName) {
        $entraUsersByUPN[$user.UserPrincipalName.ToLower()] = $user
    }
}

# Comparison results
$entraOnlyUsers = @()      # Users in Entra but not in AD (cloud-only)
$adOnlyUsers = @()          # Users in AD but not in Entra (not synced)
$syncedUsers = @()          # Users in both
$attributeMismatches = @()  # Users with attribute differences

# Find Entra-only users (cloud-only accounts)
Write-Host "[*] Identifying Entra-only (cloud-only) accounts..." -ForegroundColor Yellow
foreach ($entraUser in $entraUsers) {
    $upn = $entraUser.UserPrincipalName.ToLower()
    
    if (-not $adUsersByUPN.ContainsKey($upn)) {
        # Check if this is a synced account
        $isSynced = $entraUser.OnPremisesSyncEnabled -eq $true
        $lastSignIn = $null
        if ($entraUser.SignInActivity.LastSignInDateTime) {
            $lastSignIn = $entraUser.SignInActivity.LastSignInDateTime
        }
        
        $licenseInfo = "N/A"
        if ($IncludeLicensing -and $entraUser.AssignedLicenses) {
            $licenseInfo = $entraUser.AssignedLicenses.Count
        }
        
        $entraOnlyUsers += [PSCustomObject]@{
            UserPrincipalName = $entraUser.UserPrincipalName
            DisplayName = $entraUser.DisplayName
            Mail = $entraUser.Mail
            AccountEnabled = $entraUser.AccountEnabled
            UserType = $entraUser.UserType
            IsSyncedFromOnPrem = $isSynced
            OnPremSamAccountName = $entraUser.OnPremisesSamAccountName
            OnPremDN = $entraUser.OnPremisesDistinguishedName
            CreatedDateTime = $entraUser.CreatedDateTime
            LastSignIn = $lastSignIn
            AssignedLicenses = $licenseInfo
            Status = if ($isSynced) { "Orphaned (was synced)" } else { "Cloud-only" }
        }
    }
    else {
        # User exists in both
        $adUser = $adUsersByUPN[$upn]
        
        $lastLogon = $null
        if ($adUser.lastLogonTimestamp) {
            $lastLogon = [DateTime]::FromFileTime($adUser.lastLogonTimestamp)
        }
        
        $licenseInfo = "N/A"
        if ($IncludeLicensing -and $entraUser.AssignedLicenses) {
            $licenseInfo = $entraUser.AssignedLicenses.Count
        }
        
        $syncInfo = [PSCustomObject]@{
            UserPrincipalName = $entraUser.UserPrincipalName
            DisplayName_AD = $adUser.DisplayName
            DisplayName_Entra = $entraUser.DisplayName
            Mail_AD = if ($adUser.mail) { $adUser.mail } else { $adUser.EmailAddress }
            Mail_Entra = $entraUser.Mail
            Enabled_AD = $adUser.Enabled
            Enabled_Entra = $entraUser.AccountEnabled
            LastLogon_AD = $lastLogon
            LastSignIn_Entra = $entraUser.SignInActivity.LastSignInDateTime
            PasswordLastSet_AD = $adUser.PasswordLastSet
            IsSyncedFromOnPrem = $entraUser.OnPremisesSyncEnabled
            AssignedLicenses = $licenseInfo
        }
        
        $syncedUsers += $syncInfo
        
        # Check for attribute mismatches if requested
        if ($CompareAttributes) {
            $mismatches = @()
            
            if ($adUser.DisplayName -ne $entraUser.DisplayName) {
                $mismatches += "DisplayName"
            }
            
            $adMail = if ($adUser.mail) { $adUser.mail } else { $adUser.EmailAddress }
            if ($adMail -and $entraUser.Mail -and ($adMail -ne $entraUser.Mail)) {
                $mismatches += "Mail"
            }
            
            if ($adUser.Enabled -ne $entraUser.AccountEnabled) {
                $mismatches += "AccountEnabled"
            }
            
            if ($mismatches.Count -gt 0) {
                $attributeMismatches += [PSCustomObject]@{
                    UserPrincipalName = $entraUser.UserPrincipalName
                    MismatchedAttributes = ($mismatches -join ", ")
                    DisplayName_AD = $adUser.DisplayName
                    DisplayName_Entra = $entraUser.DisplayName
                    Mail_AD = $adMail
                    Mail_Entra = $entraUser.Mail
                    Enabled_AD = $adUser.Enabled
                    Enabled_Entra = $entraUser.AccountEnabled
                }
            }
        }
    }
}

# Find AD-only users (not synced to Entra)
Write-Host "[*] Identifying AD-only (not synced) accounts..." -ForegroundColor Yellow
foreach ($adUser in $adUsers) {
    $upn = $adUser.UserPrincipalName.ToLower()
    
    if (-not $entraUsersByUPN.ContainsKey($upn)) {
        $lastLogon = $null
        $daysSinceLogon = $null
        if ($adUser.lastLogonTimestamp) {
            $lastLogon = [DateTime]::FromFileTime($adUser.lastLogonTimestamp)
            $daysSinceLogon = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
        }
        
        $adOnlyUsers += [PSCustomObject]@{
            SamAccountName = $adUser.SamAccountName
            UserPrincipalName = $adUser.UserPrincipalName
            DisplayName = $adUser.DisplayName
            Enabled = $adUser.Enabled
            Mail = if ($adUser.mail) { $adUser.mail } else { $adUser.EmailAddress }
            WhenCreated = $adUser.whenCreated
            LastLogon = $lastLogon
            DaysSinceLogon = $daysSinceLogon
            PasswordLastSet = $adUser.PasswordLastSet
            DistinguishedName = $adUser.DistinguishedName
        }
    }
}

# Display summary statistics
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total AD Users: $($adUsers.Count)" -ForegroundColor White
Write-Host "Total Entra Users: $($entraUsers.Count)" -ForegroundColor White
Write-Host "`nComparison Results:" -ForegroundColor Cyan
Write-Host "  Users in BOTH systems: $($syncedUsers.Count)" -ForegroundColor Green
Write-Host "  Users ONLY in Entra (cloud-only): $($entraOnlyUsers.Count)" -ForegroundColor Yellow
Write-Host "  Users ONLY in AD (not synced): $($adOnlyUsers.Count)" -ForegroundColor Magenta

if ($CompareAttributes -and $attributeMismatches.Count -gt 0) {
    Write-Host "  Users with attribute mismatches: $($attributeMismatches.Count)" -ForegroundColor Red
}

# Critical findings
$cloudOnlyAccounts = $entraOnlyUsers | Where-Object { $_.Status -eq "Cloud-only" }
$orphanedAccounts = $entraOnlyUsers | Where-Object { $_.Status -eq "Orphaned (was synced)" }

Write-Host "`nEntra-Only Account Details:" -ForegroundColor Cyan
Write-Host "  True cloud-only accounts: $($cloudOnlyAccounts.Count)" -ForegroundColor White
Write-Host "  Orphaned (previously synced): $($orphanedAccounts.Count)" -ForegroundColor Red

if ($orphanedAccounts.Count -gt 0) {
    Write-Host "`n[!] WARNING: $($orphanedAccounts.Count) orphaned accounts detected!" -ForegroundColor Red
    Write-Host "    These accounts were previously synced from AD but no longer exist there." -ForegroundColor Yellow
}

# Export results
Write-Host "`n[*] Exporting results..." -ForegroundColor Yellow

# Entra-only users
if ($entraOnlyUsers.Count -gt 0) {
    $entraOnlyPath = Join-Path $OutputFolder "EntraOnly-Users-$timestamp.csv"
    $entraOnlyUsers | Sort-Object UserPrincipalName | Export-Csv -Path $entraOnlyPath -NoTypeInformation
    Write-Host "    [OK] Entra-only users: $entraOnlyPath" -ForegroundColor Green
    
    # Cloud-only accounts
    if ($cloudOnlyAccounts.Count -gt 0) {
        $cloudOnlyPath = Join-Path $OutputFolder "CloudOnly-Users-$timestamp.csv"
        $cloudOnlyAccounts | Sort-Object UserPrincipalName | Export-Csv -Path $cloudOnlyPath -NoTypeInformation
        Write-Host "    [OK] Cloud-only users: $cloudOnlyPath" -ForegroundColor Green
    }
    
    # Orphaned accounts
    if ($orphanedAccounts.Count -gt 0) {
        $orphanedPath = Join-Path $OutputFolder "Orphaned-Users-$timestamp.csv"
        $orphanedAccounts | Sort-Object UserPrincipalName | Export-Csv -Path $orphanedPath -NoTypeInformation
        Write-Host "    [OK] Orphaned users: $orphanedPath" -ForegroundColor Green
    }
}

# AD-only users
if ($adOnlyUsers.Count -gt 0) {
    $adOnlyPath = Join-Path $OutputFolder "ADOnly-Users-$timestamp.csv"
    $adOnlyUsers | Sort-Object UserPrincipalName | Export-Csv -Path $adOnlyPath -NoTypeInformation
    Write-Host "    [OK] AD-only users: $adOnlyPath" -ForegroundColor Green
}

# Synced users
if ($syncedUsers.Count -gt 0) {
    $syncedPath = Join-Path $OutputFolder "Synced-Users-$timestamp.csv"
    $syncedUsers | Sort-Object UserPrincipalName | Export-Csv -Path $syncedPath -NoTypeInformation
    Write-Host "    [OK] Synced users: $syncedPath" -ForegroundColor Green
}

# Attribute mismatches
if ($CompareAttributes -and $attributeMismatches.Count -gt 0) {
    $mismatchPath = Join-Path $OutputFolder "AttributeMismatches-$timestamp.csv"
    $attributeMismatches | Sort-Object UserPrincipalName | Export-Csv -Path $mismatchPath -NoTypeInformation
    Write-Host "    [OK] Attribute mismatches: $mismatchPath" -ForegroundColor Green
}

# Generate HTML report
$htmlPath = Join-Path $OutputFolder "ADEntraComparison-$timestamp.html"
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD to Entra ID User Comparison Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #0078d4; }
        h2 { color: #424242; border-bottom: 2px solid #0078d4; padding-bottom: 5px; margin-top: 30px; }
        .summary { background-color: #fff; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-box { padding: 15px; border-radius: 5px; text-align: center; }
        .stat-label { font-weight: bold; color: #666; font-size: 12px; text-transform: uppercase; }
        .stat-value { font-size: 32px; font-weight: bold; margin-top: 5px; }
        .box-blue { background-color: #e3f2fd; }
        .box-green { background-color: #e8f5e9; }
        .box-yellow { background-color: #fff9c4; }
        .box-red { background-color: #ffebee; }
        .box-purple { background-color: #f3e5f5; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        .critical { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }
        table { border-collapse: collapse; width: 100%; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        th { background-color: #0078d4; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { padding: 10px; border-bottom: 1px solid #ddd; font-size: 13px; }
        tr:hover { background-color: #f5f5f5; }
        .cloud-only { background-color: #fff9c4; }
        .orphaned { background-color: #ffcdd2; font-weight: bold; }
        .disabled { color: #999; }
        .mismatch { background-color: #ffebee; }
    </style>
</head>
<body>
    <h1>AD to Entra ID User Comparison Report</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p><strong>AD Domain:</strong> $domainDNS</p>
    <p><strong>Entra Tenant:</strong> $tenantName</p>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stat-grid">
            <div class="stat-box box-blue">
                <div class="stat-label">Total AD Users</div>
                <div class="stat-value" style="color: #0078d4;">$($adUsers.Count)</div>
            </div>
            <div class="stat-box box-blue">
                <div class="stat-label">Total Entra Users</div>
                <div class="stat-value" style="color: #0078d4;">$($entraUsers.Count)</div>
            </div>
            <div class="stat-box box-green">
                <div class="stat-label">Synced Users</div>
                <div class="stat-value" style="color: #4caf50;">$($syncedUsers.Count)</div>
            </div>
            <div class="stat-box box-yellow">
                <div class="stat-label">Entra-Only (Cloud)</div>
                <div class="stat-value" style="color: #ff9800;">$($cloudOnlyAccounts.Count)</div>
            </div>
            <div class="stat-box box-red">
                <div class="stat-label">Orphaned Accounts</div>
                <div class="stat-value" style="color: #f44336;">$($orphanedAccounts.Count)</div>
            </div>
            <div class="stat-box box-purple">
                <div class="stat-label">AD-Only (Not Synced)</div>
                <div class="stat-value" style="color: #9c27b0;">$($adOnlyUsers.Count)</div>
            </div>
        </div>
    </div>
    
    $(if ($orphanedAccounts.Count -gt 0) {
        "<div class='critical'><strong>CRITICAL:</strong> $($orphanedAccounts.Count) orphaned accounts detected! These were previously synced from AD but the AD account no longer exists.</div>"
    })
    
    $(if ($cloudOnlyAccounts.Count -gt 10) {
        "<div class='warning'><strong>NOTICE:</strong> $($cloudOnlyAccounts.Count) cloud-only accounts found. Review to ensure this is expected.</div>"
    })
    
    $(if ($adOnlyUsers.Count -gt 0) {
        "<div class='warning'><strong>INFO:</strong> $($adOnlyUsers.Count) AD accounts are not synchronized to Entra ID.</div>"
    })
    
    <h2>Entra-Only Users (In Entra but NOT in AD)</h2>
    <p>These accounts exist in Entra ID but not in Active Directory. Review to identify cloud-only accounts vs. orphaned accounts.</p>
    <table>
        <tr>
            <th>User Principal Name</th>
            <th>Display Name</th>
            <th>Status</th>
            <th>Enabled</th>
            <th>User Type</th>
            <th>Last Sign-In</th>
            $(if ($IncludeLicensing) { "<th>Licenses</th>" } else { "" })
        </tr>
        $(foreach ($user in ($entraOnlyUsers | Sort-Object Status, UserPrincipalName)) {
            $rowClass = if ($user.Status -eq "Orphaned (was synced)") { "orphaned" } else { "cloud-only" }
            "<tr class='$rowClass'>
                <td>$($user.UserPrincipalName)</td>
                <td>$($user.DisplayName)</td>
                <td>$($user.Status)</td>
                <td>$($user.AccountEnabled)</td>
                <td>$($user.UserType)</td>
                <td>$($user.LastSignIn)</td>
                $(if ($IncludeLicensing) { '<td>' + $($user.AssignedLicenses) + '</td>' } else { '' })
            </tr>"
        })
    </table>
    
    <h2>AD-Only Users (In AD but NOT in Entra)</h2>
    <p>These accounts exist in Active Directory but are not synchronized to Entra ID.</p>
    <table>
        <tr>
            <th>User Principal Name</th>
            <th>SAM Account</th>
            <th>Display Name</th>
            <th>Enabled</th>
            <th>Last Logon</th>
            <th>Days Since Logon</th>
        </tr>
        $(foreach ($user in ($adOnlyUsers | Sort-Object UserPrincipalName)) {
            $rowClass = if (-not $user.Enabled) { "disabled" } else { "" }
            "<tr class='$rowClass'>
                <td>$($user.UserPrincipalName)</td>
                <td>$($user.SamAccountName)</td>
                <td>$($user.DisplayName)</td>
                <td>$($user.Enabled)</td>
                <td>$($user.LastLogon)</td>
                <td>$($user.DaysSinceLogon)</td>
            </tr>"
        })
    </table>
    
    $(if ($CompareAttributes -and $attributeMismatches.Count -gt 0) {
        "<h2>Attribute Mismatches (Sync Issues)</h2>
        <p>These accounts exist in both systems but have different attribute values.</p>
        <table>
            <tr>
                <th>User Principal Name</th>
                <th>Mismatched Attributes</th>
                <th>DisplayName (AD)</th>
                <th>DisplayName (Entra)</th>
                <th>Enabled (AD)</th>
                <th>Enabled (Entra)</th>
            </tr>
            $(foreach ($user in ($attributeMismatches | Sort-Object UserPrincipalName)) {
                "<tr class='mismatch'>
                    <td>$($user.UserPrincipalName)</td>
                    <td><strong>$($user.MismatchedAttributes)</strong></td>
                    <td>$($user.DisplayName_AD)</td>
                    <td>$($user.DisplayName_Entra)</td>
                    <td>$($user.Enabled_AD)</td>
                    <td>$($user.Enabled_Entra)</td>
                </tr>"
            })
        </table>"
    })
    
    <h2>Recommendations</h2>
    <ul>
        <li><strong>Orphaned Accounts:</strong> Review and disable/delete orphaned Entra accounts that no longer have corresponding AD accounts.</li>
        <li><strong>Cloud-Only Accounts:</strong> Ensure cloud-only accounts are intentional and properly managed.</li>
        <li><strong>AD-Only Accounts:</strong> Review why these accounts are not syncing. Check OU filtering and sync scope.</li>
        $(if ($CompareAttributes) {
            "<li><strong>Attribute Mismatches:</strong> Investigate sync issues causing attribute discrepancies.</li>"
        })
    </ul>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "    [OK] HTML Report: $htmlPath" -ForegroundColor Green

# Display sample of Entra-only users
if ($entraOnlyUsers.Count -gt 0) {
    Write-Host "`n[*] Sample Entra-only users (first 10):" -ForegroundColor Cyan
    $entraOnlyUsers | 
        Select-Object -First 10 UserPrincipalName, DisplayName, Status, AccountEnabled, UserType |
        Format-Table -AutoSize
}

Write-Host "`n[*] Analysis complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Disconnect from Graph
Disconnect-MgGraph | Out-Null



