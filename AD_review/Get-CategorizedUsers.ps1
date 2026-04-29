<#
.SYNOPSIS
    Categorizes users in both Active Directory and Entra ID by last login, elevated status, and other criteria.

.DESCRIPTION
    This script collects users from both Active Directory and Entra ID, then categorizes them into
    multiple categories based on:
    - Last login activity (Active, Inactive, Stale, Never logged in)
    - Elevated/Privileged status (Domain Admins, Enterprise Admins, AdminCount, etc.)
    - Account status (Enabled, Disabled)
    - MFA status (for Entra ID users)
    - Password status (Never expires, Expired, etc.)
    - Service accounts vs regular users
    - Account type (Cloud-only, Synced, AD-only)
    
    Results are exported to CSV files organized by category for easy review and action.

.PARAMETER OutputFolder
    Path where the categorized reports will be saved. Defaults to current directory.

.PARAMETER IncludeEntraUsers
    Include Entra ID users in the categorization (requires Microsoft Graph connection).

.PARAMETER IncludeMFAStatus
    Check MFA status for Entra ID users (requires additional Graph permissions).

.PARAMETER DaysActive
    Number of days to consider a user "Active". Defaults to 30 days.

.PARAMETER DaysInactive
    Number of days to consider a user "Inactive". Defaults to 90 days.

.PARAMETER DaysStale
    Number of days to consider a user "Stale". Defaults to 180 days.

.EXAMPLE
    .\Get-CategorizedUsers.ps1
    Categorize AD users only with default thresholds
    
.EXAMPLE
    .\Get-CategorizedUsers.ps1 -IncludeEntraUsers -IncludeMFAStatus
    Categorize users from both AD and Entra ID, including MFA status
    
.EXAMPLE
    .\Get-CategorizedUsers.ps1 -DaysActive 14 -DaysInactive 60 -DaysStale 120
    Use custom thresholds for activity categorization

.EXAMPLE
    .\Get-CategorizedUsers.ps1 -IncludeEntraUsers -CyberMode
    Run analysis and show the remediation menu.

.EXAMPLE
    .\Get-CategorizedUsers.ps1 -Action DisableADUser -ActionTarget john.doe -DisableMinutes 15
    Run analysis and disable an AD user for 15 minutes automatically.

.EXAMPLE
    .\Get-CategorizedUsers.ps1 -Action RemoveEntraEmails
    Run analysis and remove email data from all Entra users.

.NOTES
    Requires: Active Directory PowerShell module
    Optional: Microsoft.Graph modules (Authentication, Users, Identity.SignIns)
    Permissions: 
      - AD: Domain user with read access
      - Entra: User.Read.All, Directory.Read.All (MFA: UserAuthenticationMethod.Read.All)
      - Entra remediation: User.ReadWrite.All, Directory.ReadWrite.All
#>

param(
    [string]$OutputFolder = ".",
    [switch]$IncludeEntraUsers,
    [switch]$IncludeMFAStatus,
    [int]$DaysActive = 30,
    [int]$DaysInactive = 90,
    [int]$DaysStale = 180,
    [switch]$NoReports,
    [switch]$CyberMode,
    [ValidateSet('None','DisableADUser','RevokeEntraSessions','BlockPasswordChange','RemoveEntraEmails')]
    [string]$Action = 'None',
    [string]$ActionTarget = '',
    [int]$DisableMinutes = 15,
    [ValidateSet('AD','Entra')]
    [string]$PasswordChangeSource = 'AD'
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# Check Graph modules if Entra users requested
if ($IncludeEntraUsers) {
    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
    if ($IncludeMFAStatus) {
        $requiredModules += 'Microsoft.Graph.Identity.SignIns'
    }
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Error "Module $module not found. Install with: Install-Module $module -Scope CurrentUser"
            exit 1
        }
    }
    
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    if ($IncludeMFAStatus) {
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "USER CATEGORIZATION ANALYSIS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get AD Domain info
$domain = Get-ADDomain
$domainDNS = $domain.DNSRoot
Write-Host "[*] AD Domain: $domainDNS" -ForegroundColor Yellow
Write-Host "[*] Activity Thresholds:" -ForegroundColor Yellow
Write-Host "    - Active: Last $DaysActive days" -ForegroundColor Gray
Write-Host "    - Inactive: $DaysInactive-$DaysStale days" -ForegroundColor Gray
Write-Host "    - Stale: $DaysStale+ days" -ForegroundColor Gray

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
    'Group Policy Creator Owners',
    'Cryptographic Operators',
    'Network Configuration Operators'
)

# Function to determine if user is elevated
function Test-ElevatedUser {
    param($User, $MemberOf)
    
    # Check AdminCount
    if ($User.AdminCount -eq 1) {
        return $true
    }
    
    # Check privileged group membership
    if ($MemberOf) {
        foreach ($group in $MemberOf) {
            $groupName = (Get-ADGroup -Identity $group -ErrorAction SilentlyContinue).Name
            if ($groupName -in $privilegedGroups) {
                return $true
            }
        }
    }
    
    # Check if name contains admin keywords
    $adminKeywords = @('admin', 'adm', 'svc', 'service', 'sa', 'sql', 'exchange')
    $samAccount = $User.SamAccountName.ToLower()
    foreach ($keyword in $adminKeywords) {
        if ($samAccount -like "*$keyword*") {
            return $true
        }
    }
    
    return $false
}

# Function to categorize by last login
function Get-LoginCategory {
    param(
        $LastLogon,          # Intentionally untyped so $null is allowed
        [int]$DaysActive,
        [int]$DaysInactive,
        [int]$DaysStale
    )
    
    if (-not $LastLogon) {
        return "Never Logged In"
    }
    
    $daysSince = (New-TimeSpan -Start $LastLogon -End (Get-Date)).Days
    
    if ($daysSince -le $DaysActive) {
        return "Active"
    }
    elseif ($daysSince -le $DaysInactive) {
        return "Inactive"
    }
    elseif ($daysSince -le $DaysStale) {
        return "Stale"
    }
    else {
        return "Very Stale"
    }
}

# Function to determine account type
function Get-AccountType {
    param($User)
    
    $samAccount = $User.SamAccountName.ToLower()
    
    # Service account patterns
    if ($samAccount -like "svc*" -or 
        $samAccount -like "*service*" -or 
        $samAccount -like "*sa" -or
        $samAccount -like "sql*" -or
        $samAccount -like "exchange*" -or
        $User.Description -like "*service*" -or
        $User.Description -like "*application*") {
        return "Service Account"
    }
    
    # Test/Generic accounts
    if ($samAccount -like "test*" -or 
        $samAccount -like "demo*" -or
        $samAccount -like "guest*" -or
        $samAccount -eq "guest") {
        return "Test/Generic Account"
    }
    
    # Admin accounts
    if ($samAccount -like "*admin*" -or 
        $samAccount -like "*adm*") {
        return "Administrative Account"
    }
    
    return "Regular User"
}

# Action helper state
$GraphConnected = $false

function Connect-ToGraph {
    param(
        [switch]$RequireWrite
    )

    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users'
    )

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Error "Module $module not found. Install with: Install-Module $module -Scope CurrentUser"
            return $false
        }
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop

    $scopes = @(
        "User.Read.All",
        "Directory.Read.All"
    )

    if ($RequireWrite) {
        $scopes += "User.ReadWrite.All"
        $scopes += "Directory.ReadWrite.All"
    }

    try {
        Connect-MgGraph -Scopes ($scopes | Sort-Object -Unique) -NoWelcome -ErrorAction Stop
        $global:GraphConnected = $true
        return $true
    }
    catch {
        Write-Warning "Failed to connect to Microsoft Graph for remediation actions: $_"
        return $false
    }
}

function Disable-ADUserTemporarily {
    param(
        [Parameter(Mandatory)] [string]$SamAccountName,
        [int]$Minutes = 15
    )

    Write-Host "`n[*] Disabling AD user $SamAccountName for $Minutes minutes..." -ForegroundColor Yellow
    try {
        Disable-ADAccount -Identity $SamAccountName -ErrorAction Stop
        Write-Host "    [OK] Disabled $SamAccountName" -ForegroundColor Green
    }
    catch {
        Write-Warning "Unable to disable AD user '$SamAccountName': $_"
        return
    }

    $triggerTime = (Get-Date).AddMinutes($Minutes)
    try {
        $jobName = "Reenable-$($SamAccountName)-$($triggerTime.ToString('yyyyMMddHHmmss'))"
        $trigger = New-JobTrigger -Once -At $triggerTime
        Register-ScheduledJob -Name $jobName -Trigger $trigger -ScriptBlock {
            Import-Module ActiveDirectory -ErrorAction Stop
            Enable-ADAccount -Identity $using:SamAccountName -ErrorAction Stop
        } -ErrorAction Stop

        Write-Host "    [OK] Scheduled automatic re-enable job: $jobName at $triggerTime" -ForegroundColor Green
    }
    catch {
        Write-Warning "Disabled account, but failed to create scheduled re-enable job: $_"
        Write-Host "    You must manually run: Enable-ADAccount -Identity $SamAccountName" -ForegroundColor Yellow
    }
}

function Revoke-EntraUserSessions {
    param(
        [Parameter(Mandatory)] [string]$UserPrincipalName
    )

    if (-not (Connect-ToGraph -RequireWrite)) {
        return
    }

    Write-Host "`n[*] Revoking sign-in sessions for $UserPrincipalName..." -ForegroundColor Yellow
    try {
        $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to find Entra user '$UserPrincipalName': $_"
        return
    }

    try {
        Invoke-MgGraphRequest -Method POST -Uri "/users/$($user.Id)/revokeSignInSessions" -ErrorAction Stop | Out-Null
        Write-Host "    [OK] Revoked active sessions for $UserPrincipalName" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to revoke sessions for '$UserPrincipalName': $_"
    }
}

function Set-UserCannotChangePassword {
    param(
        [Parameter(Mandatory)] [ValidateSet('AD','Entra')] [string]$Source,
        [Parameter(Mandatory)] [string]$Identifier
    )

    if ($Source -eq 'AD') {
        Write-Host "`n[*] Blocking password changes for AD user $Identifier..." -ForegroundColor Yellow
        try {
            Set-ADUser -Identity $Identifier -CannotChangePassword $true -ErrorAction Stop
            Write-Host "    [OK] $Identifier can no longer change password" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to set CannotChangePassword for AD user '$Identifier': $_"
        }
        return
    }

    if (-not (Connect-ToGraph -RequireWrite)) {
        return
    }

    Write-Host "`n[*] Blocking password changes for Entra user $Identifier..." -ForegroundColor Yellow
    try {
        $user = Get-MgUser -UserId $Identifier -ErrorAction Stop
        $body = @{ userCannotChangePassword = $true }
        Invoke-MgGraphRequest -Method PATCH -Uri "/users/$($user.Id)" -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json" -ErrorAction Stop | Out-Null
        Write-Host "    [OK] $Identifier can no longer change password" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to set CannotChangePassword for Entra user '$Identifier': $_"
    }
}

function Remove-AllEntraEmails {
    if (-not (Connect-ToGraph -RequireWrite)) {
        return
    }

    $confirm = Read-Host "This action will remove mail attributes for all Entra users. Type 'YES' to confirm"
    if ($confirm -ne 'YES') {
        Write-Host "Aborted email removal." -ForegroundColor Yellow
        return
    }

    Write-Host "`n[*] Removing email data from all Entra users..." -ForegroundColor Yellow
    $users = Get-MgUser -All -Property Mail,OtherMails,Id,UserPrincipalName
    $successCount = 0
    $failureCount = 0

    foreach ($user in $users) {
        try {
            $body = @{ otherMails = @() }
            if ($user.Mail) {
                $body.mail = $null
            }
            Invoke-MgGraphRequest -Method PATCH -Uri "/users/$($user.Id)" -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json" -ErrorAction Stop | Out-Null
            $successCount++
        }
        catch {
            Write-Warning "Failed to clear email data for $($user.UserPrincipalName): $_"
            $failureCount++
        }
    }

    Write-Host "    [OK] Completed email cleanup for $successCount users. Failures: $failureCount" -ForegroundColor Green
}

function Show-CyberActionMenu {
    while ($true) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "POST-ANALYSIS CYBER RESPONSE MENU" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "1) Disable an AD user for 15 minutes" -ForegroundColor White
        Write-Host "2) Revoke Entra sign-in sessions for a user" -ForegroundColor White
        Write-Host "3) Block a user from changing password" -ForegroundColor White
        Write-Host "4) Remove email data from all Entra users" -ForegroundColor White
        Write-Host "5) Exit" -ForegroundColor White

        $choice = Read-Host "Choose an action (1-5)"

        switch ($choice) {
            '1' {
                $sam = Read-Host 'Enter AD SamAccountName to disable'
                if ($sam) { Disable-ADUserTemporarily -SamAccountName $sam -Minutes 15 }
                continue
            }
            '2' {
                $upn = Read-Host 'Enter Entra user principal name (UPN)'
                if ($upn) { Revoke-EntraUserSessions -UserPrincipalName $upn }
                continue
            }
            '3' {
                $source = Read-Host 'Source (AD/Entra)'
                if ($source -in @('AD','Entra')) {
                    $id = Read-Host 'Enter SamAccountName or UPN'
                    if ($id) { Set-UserCannotChangePassword -Source $source -Identifier $id }
                }
                else {
                    Write-Warning 'Invalid source. Please enter AD or Entra.'
                }
                continue
            }
            '4' {
                Remove-AllEntraEmails
                continue
            }
            '5' {
                Write-Host 'Exiting remediation menu.' -ForegroundColor Cyan
                break
            }
            default {
                Write-Warning 'Please select a valid option between 1 and 5.'
                continue
            }
        }
    }
}

# Collect AD Users
Write-Host "`n[*] Collecting Active Directory users..." -ForegroundColor Yellow
$adUsers = Get-ADUser -Filter * -Properties `
    SamAccountName, UserPrincipalName, DisplayName, Enabled, `
    lastLogonTimestamp, LastLogonDate, PasswordLastSet, `
    PasswordNeverExpires, PasswordExpired, AdminCount, `
    MemberOf, whenCreated, Description, EmailAddress, mail

Write-Host "    [OK] Found $($adUsers.Count) AD users" -ForegroundColor Green

# Categorize AD Users
Write-Host "`n[*] Categorizing AD users..." -ForegroundColor Yellow
$adCategorizedUsers = @()

foreach ($user in $adUsers) {
    # Get last logon
    $lastLogon = $null
    if ($user.lastLogonTimestamp) {
        $lastLogon = [DateTime]::FromFileTime($user.lastLogonTimestamp)
    } elseif ($user.LastLogonDate) {
        $lastLogon = $user.LastLogonDate
    }
    
    $daysSinceLogon = if ($lastLogon) {
        (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
    } else { $null }
    
    # Determine categories
    $loginCategory = Get-LoginCategory -LastLogon $lastLogon -DaysActive $DaysActive -DaysInactive $DaysInactive -DaysStale $DaysStale
    $isElevated = Test-ElevatedUser -User $user -MemberOf $user.MemberOf
    $accountType = Get-AccountType -User $user
    
    # Password status
    $passwordStatus = "Normal"
    if ($user.PasswordNeverExpires) {
        $passwordStatus = "Never Expires"
    } elseif ($user.PasswordExpired) {
        $passwordStatus = "Expired"
    } elseif ($user.PasswordLastSet) {
        $passwordAge = (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
        if ($passwordAge -gt 365) {
            $passwordStatus = "Old (>1 year)"
        }
    }
    
    # Risk level calculation
    $riskScore = 0
    $riskLevel = "Low"
    
    if (-not $user.Enabled) { $riskScore += 2 }
    if ($isElevated) { $riskScore += 5 }
    if ($loginCategory -eq "Very Stale") { $riskScore += 4 }
    elseif ($loginCategory -eq "Stale") { $riskScore += 2 }
    elseif ($loginCategory -eq "Never Logged In") { $riskScore += 3 }
    if ($passwordStatus -eq "Never Expires") { $riskScore += 3 }
    if ($passwordStatus -eq "Expired") { $riskScore += 2 }
    if ($accountType -eq "Service Account" -and $isElevated) { $riskScore += 3 }
    
    if ($riskScore -ge 10) { $riskLevel = "Critical" }
    elseif ($riskScore -ge 7) { $riskLevel = "High" }
    elseif ($riskScore -ge 4) { $riskLevel = "Medium" }
    
    $adCategorizedUsers += [PSCustomObject]@{
        Source = "Active Directory"
        SamAccountName = $user.SamAccountName
        UserPrincipalName = $user.UserPrincipalName
        DisplayName = $user.DisplayName
        Enabled = $user.Enabled
        AccountType = $accountType
        IsElevated = $isElevated
        AdminCount = $user.AdminCount
        LoginCategory = $loginCategory
        LastLogon = $lastLogon
        DaysSinceLogon = $daysSinceLogon
        PasswordStatus = $passwordStatus
        PasswordLastSet = $user.PasswordLastSet
        PasswordNeverExpires = $user.PasswordNeverExpires
        WhenCreated = $user.whenCreated
        Description = $user.Description
        Email = if ($user.mail) { $user.mail } else { $user.EmailAddress }
        RiskScore = $riskScore
        RiskLevel = $riskLevel
        MemberOfCount = if ($user.MemberOf) { $user.MemberOf.Count } else { 0 }
    }
}

Write-Host "    [OK] Categorized $($adCategorizedUsers.Count) AD users" -ForegroundColor Green

# Collect Entra ID Users if requested
$entraCategorizedUsers = @()
$mfaStatusMap = @{}

if ($IncludeEntraUsers) {
    Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        $scopes = @("User.Read.All", "Directory.Read.All")
        if ($IncludeMFAStatus) {
            $scopes += "UserAuthenticationMethod.Read.All"
        }
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        $global:GraphConnected = $true
        Write-Host "    [OK] Connected to Microsoft Graph" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        $IncludeEntraUsers = $false
    }
    
    if ($IncludeEntraUsers) {
        # Get tenant info
        $tenant = Get-MgOrganization
        $tenantName = $tenant.DisplayName
        Write-Host "[*] Entra Tenant: $tenantName" -ForegroundColor Yellow
        
        # Collect MFA status if requested
        if ($IncludeMFAStatus) {
            Write-Host "[*] Collecting MFA status..." -ForegroundColor Yellow
            try {
                $entraUsersForMFA = Get-MgUser -All -Property UserPrincipalName, Id
                foreach ($user in $entraUsersForMFA) {
                    try {
                        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                        $hasMFA = ($authMethods | Where-Object { 
                            $_.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' 
                        }).Count -gt 0
                        $mfaStatusMap[$user.UserPrincipalName] = $hasMFA
                    }
                    catch {
                        $mfaStatusMap[$user.UserPrincipalName] = "Error"
                    }
                }
                Write-Host "    [OK] Retrieved MFA status for $($mfaStatusMap.Count) users" -ForegroundColor Green
            }
            catch {
                Write-Warning "Error collecting MFA status: $_"
            }
        }
        
        # Collect Entra Users
        Write-Host "`n[*] Collecting Entra ID users..." -ForegroundColor Yellow
        $properties = @(
            "Id", "UserPrincipalName", "DisplayName", "Mail", 
            "AccountEnabled", "CreatedDateTime", "UserType", 
            "OnPremisesSyncEnabled", "OnPremisesDistinguishedName",
            "OnPremisesSamAccountName", "SignInActivity"
        )
        
        $entraUsers = Get-MgUser -All -Property ($properties -join ",")
        Write-Host "    [OK] Found $($entraUsers.Count) Entra ID users" -ForegroundColor Green
        
        # Categorize Entra Users
        Write-Host "`n[*] Categorizing Entra ID users..." -ForegroundColor Yellow
        
        foreach ($user in $entraUsers) {
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = if ($lastSignIn) {
                (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days
            } else { $null }
            
            # Determine categories
            $loginCategory = Get-LoginCategory -LastLogon $lastSignIn -DaysActive $DaysActive -DaysInactive $DaysInactive -DaysStale $DaysStale
            
            # Account type
            $accountType = "Regular User"
            if ($user.UserType -eq "Guest") {
                $accountType = "Guest Account"
            } elseif (-not $user.OnPremisesSyncEnabled) {
                $accountType = "Cloud-Only Account"
            } elseif ($user.OnPremisesSyncEnabled) {
                $accountType = "Synced Account"
            }
            
            # Check if elevated (simplified - would need role assignments for full check)
            $isElevated = $false
            if ($user.UserPrincipalName -like "*admin*" -or 
                $user.DisplayName -like "*Admin*" -or
                $user.UserPrincipalName -like "*svc*" -or
                $user.UserPrincipalName -like "*service*") {
                $isElevated = $true
            }
            
            # MFA status
            $mfaEnabled = $null
            if ($IncludeMFAStatus -and $mfaStatusMap.ContainsKey($user.UserPrincipalName)) {
                $mfaEnabled = $mfaStatusMap[$user.UserPrincipalName]
            }
            
            # Risk level calculation
            $riskScore = 0
            $riskLevel = "Low"
            
            if (-not $user.AccountEnabled) { $riskScore += 2 }
            if ($isElevated) { $riskScore += 5 }
            if ($loginCategory -eq "Very Stale") { $riskScore += 4 }
            elseif ($loginCategory -eq "Stale") { $riskScore += 2 }
            elseif ($loginCategory -eq "Never Logged In") { $riskScore += 3 }
            if ($accountType -eq "Cloud-Only Account" -and $isElevated) { $riskScore += 2 }
            if ($IncludeMFAStatus -and $mfaEnabled -eq $false -and $isElevated) { $riskScore += 4 }
            
            if ($riskScore -ge 10) { $riskLevel = "Critical" }
            elseif ($riskScore -ge 7) { $riskLevel = "High" }
            elseif ($riskScore -ge 4) { $riskLevel = "Medium" }
            
            $entraCategorizedUsers += [PSCustomObject]@{
                Source = "Entra ID"
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AccountEnabled = $user.AccountEnabled
                AccountType = $accountType
                IsElevated = $isElevated
                IsSyncedFromOnPrem = $user.OnPremisesSyncEnabled
                OnPremSamAccountName = $user.OnPremisesSamAccountName
                LoginCategory = $loginCategory
                LastSignIn = $lastSignIn
                DaysSinceSignIn = $daysSinceSignIn
                MFAEnabled = $mfaEnabled
                UserType = $user.UserType
                WhenCreated = $user.CreatedDateTime
                Email = $user.Mail
                RiskScore = $riskScore
                RiskLevel = $riskLevel
            }
        }
        
        Write-Host "    [OK] Categorized $($entraCategorizedUsers.Count) Entra ID users" -ForegroundColor Green
    }
}

if (-not $NoReports) {
    # Create category-based exports
    Write-Host "`n[*] Generating categorized reports..." -ForegroundColor Yellow

    # AD User Categories
    $adCategories = @{
    "ByLoginActivity" = @{
        "Active" = $adCategorizedUsers | Where-Object { $_.LoginCategory -eq "Active" }
        "Inactive" = $adCategorizedUsers | Where-Object { $_.LoginCategory -eq "Inactive" }
        "Stale" = $adCategorizedUsers | Where-Object { $_.LoginCategory -eq "Stale" }
        "Very Stale" = $adCategorizedUsers | Where-Object { $_.LoginCategory -eq "Very Stale" }
        "Never Logged In" = $adCategorizedUsers | Where-Object { $_.LoginCategory -eq "Never Logged In" }
    }
    "ByElevatedStatus" = @{
        "Elevated" = $adCategorizedUsers | Where-Object { $_.IsElevated -eq $true }
        "Non-Elevated" = $adCategorizedUsers | Where-Object { $_.IsElevated -eq $false }
    }
    "ByAccountStatus" = @{
        "Enabled" = $adCategorizedUsers | Where-Object { $_.Enabled -eq $true }
        "Disabled" = $adCategorizedUsers | Where-Object { $_.Enabled -eq $false }
    }
    "ByAccountType" = $adCategorizedUsers | Group-Object AccountType | ForEach-Object { @{$_.Name = $_.Group} }
    "ByPasswordStatus" = $adCategorizedUsers | Group-Object PasswordStatus | ForEach-Object { @{$_.Name = $_.Group} }
    "ByRiskLevel" = $adCategorizedUsers | Group-Object RiskLevel | ForEach-Object { @{$_.Name = $_.Group} }
}

# Export AD categories
foreach ($categoryType in $adCategories.Keys) {
    $categoryData = $adCategories[$categoryType]
    
    if ($categoryData -is [hashtable]) {
        foreach ($subCategory in $categoryData.Keys) {
            $users = $categoryData[$subCategory]
            if ($users.Count -gt 0) {
                $fileName = "AD-Users-$categoryType-$subCategory-$timestamp.csv"
                $filePath = Join-Path $OutputFolder $fileName
                $users | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DisplayName'; Descending=$false} | Export-Csv -Path $filePath -NoTypeInformation
                Write-Host "    [OK] $categoryType\$subCategory : $($users.Count) users -> $fileName" -ForegroundColor Green
            }
        }
    }
}

# Export all AD users
$allADPath = Join-Path $OutputFolder "AD-Users-All-$timestamp.csv"
$adCategorizedUsers | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DisplayName'; Descending=$false} | Export-Csv -Path $allADPath -NoTypeInformation
Write-Host "    [OK] All AD Users: $allADPath" -ForegroundColor Green

# Entra User Categories (if included)
if ($entraCategorizedUsers.Count -gt 0) {
    $entraCategories = @{
        "ByLoginActivity" = @{
            "Active" = $entraCategorizedUsers | Where-Object { $_.LoginCategory -eq "Active" }
            "Inactive" = $entraCategorizedUsers | Where-Object { $_.LoginCategory -eq "Inactive" }
            "Stale" = $entraCategorizedUsers | Where-Object { $_.LoginCategory -eq "Stale" }
            "Very Stale" = $entraCategorizedUsers | Where-Object { $_.LoginCategory -eq "Very Stale" }
            "Never Logged In" = $entraCategorizedUsers | Where-Object { $_.LoginCategory -eq "Never Logged In" }
        }
        "ByElevatedStatus" = @{
            "Elevated" = $entraCategorizedUsers | Where-Object { $_.IsElevated -eq $true }
            "Non-Elevated" = $entraCategorizedUsers | Where-Object { $_.IsElevated -eq $false }
        }
        "ByAccountStatus" = @{
            "Enabled" = $entraCategorizedUsers | Where-Object { $_.AccountEnabled -eq $true }
            "Disabled" = $entraCategorizedUsers | Where-Object { $_.AccountEnabled -eq $false }
        }
        "ByAccountType" = $entraCategorizedUsers | Group-Object AccountType | ForEach-Object { @{$_.Name = $_.Group} }
        "ByMFAStatus" = @{
            "MFA Enabled" = $entraCategorizedUsers | Where-Object { $_.MFAEnabled -eq $true }
            "MFA Disabled" = $entraCategorizedUsers | Where-Object { $_.MFAEnabled -eq $false }
            "MFA Unknown" = $entraCategorizedUsers | Where-Object { $null -eq $_.MFAEnabled }
        }
        "ByRiskLevel" = $entraCategorizedUsers | Group-Object RiskLevel | ForEach-Object { @{$_.Name = $_.Group} }
    }
    
    # Export Entra categories
    foreach ($categoryType in $entraCategories.Keys) {
        $categoryData = $entraCategories[$categoryType]
        
        if ($categoryData -is [hashtable]) {
            foreach ($subCategory in $categoryData.Keys) {
                $users = $categoryData[$subCategory]
                if ($users.Count -gt 0) {
                    $fileName = "Entra-Users-$categoryType-$subCategory-$timestamp.csv"
                    $filePath = Join-Path $OutputFolder $fileName
                    $users | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DisplayName'; Descending=$false} | Export-Csv -Path $filePath -NoTypeInformation
                    Write-Host "    [OK] $categoryType\$subCategory : $($users.Count) users -> $fileName" -ForegroundColor Green
                }
            }
        }
    }
    
    # Export all Entra users
    $allEntraPath = Join-Path $OutputFolder "Entra-Users-All-$timestamp.csv"
    $entraCategorizedUsers | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DisplayName'; Descending=$false} | Export-Csv -Path $allEntraPath -NoTypeInformation
    Write-Host "    [OK] All Entra Users: $allEntraPath" -ForegroundColor Green
}
else {
    Write-Host "`n[*] Skipping report export because -NoReports was specified." -ForegroundColor Yellow
}

# Generate summary statistics
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nActive Directory Users:" -ForegroundColor White
Write-Host "  Total: $($adCategorizedUsers.Count)" -ForegroundColor Cyan
Write-Host "  By Login Activity:" -ForegroundColor Yellow
$adCategorizedUsers | Group-Object LoginCategory | ForEach-Object {
    Write-Host "    - $($_.Name): $($_.Count)" -ForegroundColor Gray
}
Write-Host "  By Elevated Status:" -ForegroundColor Yellow
Write-Host "    - Elevated: $(($adCategorizedUsers | Where-Object { $_.IsElevated -eq $true }).Count)" -ForegroundColor Gray
Write-Host "    - Non-Elevated: $(($adCategorizedUsers | Where-Object { $_.IsElevated -eq $false }).Count)" -ForegroundColor Gray
Write-Host "  By Risk Level:" -ForegroundColor Yellow
$adCategorizedUsers | Group-Object RiskLevel | Sort-Object Name -Descending | ForEach-Object {
    Write-Host "    - $($_.Name): $($_.Count)" -ForegroundColor $(if ($_.Name -eq "Critical") { "Red" } elseif ($_.Name -eq "High") { "Yellow" } else { "Gray" })
}

if ($entraCategorizedUsers.Count -gt 0) {
    Write-Host "`nEntra ID Users:" -ForegroundColor White
    Write-Host "  Total: $($entraCategorizedUsers.Count)" -ForegroundColor Cyan
    Write-Host "  By Login Activity:" -ForegroundColor Yellow
    $entraCategorizedUsers | Group-Object LoginCategory | ForEach-Object {
        Write-Host "    - $($_.Name): $($_.Count)" -ForegroundColor Gray
    }
    Write-Host "  By Elevated Status:" -ForegroundColor Yellow
    Write-Host "    - Elevated: $(($entraCategorizedUsers | Where-Object { $_.IsElevated -eq $true }).Count)" -ForegroundColor Gray
    Write-Host "    - Non-Elevated: $(($entraCategorizedUsers | Where-Object { $_.IsElevated -eq $false }).Count)" -ForegroundColor Gray
    if ($IncludeMFAStatus) {
        Write-Host "  By MFA Status:" -ForegroundColor Yellow
        $entraCategorizedUsers | Group-Object MFAEnabled | ForEach-Object {
            $status = if ($null -eq $_.Name) { "Unknown" } elseif ($_.Name -eq $true) { "Enabled" } else { "Disabled" }
            Write-Host "    - MFA $status : $($_.Count)" -ForegroundColor Gray
        }
    }
    Write-Host "  By Risk Level:" -ForegroundColor Yellow
    $entraCategorizedUsers | Group-Object RiskLevel | Sort-Object Name -Descending | ForEach-Object {
        Write-Host "    - $($_.Name): $($_.Count)" -ForegroundColor $(if ($_.Name -eq "Critical") { "Red" } elseif ($_.Name -eq "High") { "Yellow" } else { "Gray" })
    }
}

# Critical findings
$criticalAD = ($adCategorizedUsers | Where-Object { $_.RiskLevel -eq "Critical" }).Count
$criticalEntra = ($entraCategorizedUsers | Where-Object { $_.RiskLevel -eq "Critical" }).Count

if ($criticalAD -gt 0 -or $criticalEntra -gt 0) {
    Write-Host "`n[!] CRITICAL RISK USERS:" -ForegroundColor Red
    if ($criticalAD -gt 0) {
        Write-Host "  AD: $criticalAD users require immediate attention" -ForegroundColor Red
    }
    if ($criticalEntra -gt 0) {
        Write-Host "  Entra: $criticalEntra users require immediate attention" -ForegroundColor Red
    }
}

Write-Host "`n[*] Analysis complete! Reports saved to:" -ForegroundColor Green
Write-Host "    $OutputFolder" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

function Perform-CyberAction {
    switch ($Action) {
        'DisableADUser' {
            if (-not $ActionTarget) {
                Write-Warning 'ActionTarget is required for DisableADUser.'
                return
            }
            Disable-ADUserTemporarily -SamAccountName $ActionTarget -Minutes $DisableMinutes
            return
        }
        'RevokeEntraSessions' {
            if (-not $ActionTarget) {
                Write-Warning 'ActionTarget is required for RevokeEntraSessions.'
                return
            }
            Revoke-EntraUserSessions -UserPrincipalName $ActionTarget
            return
        }
        'BlockPasswordChange' {
            if (-not $ActionTarget) {
                Write-Warning 'ActionTarget is required for BlockPasswordChange.'
                return
            }
            Set-UserCannotChangePassword -Source $PasswordChangeSource -Identifier $ActionTarget
            return
        }
        'RemoveEntraEmails' {
            Remove-AllEntraEmails
            return
        }
        default {
            Write-Warning "Unknown action: $Action"
            return
        }
    }
}

if ($Action -ne 'None') {
    Perform-CyberAction
}
elseif ($CyberMode) {
    Show-CyberActionMenu
}
    Disconnect-MgGraph | Out-Null
}

