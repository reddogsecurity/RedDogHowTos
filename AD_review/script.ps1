<#
.SYNOPSIS
  Black-box AD + Entra (Azure AD) discovery and security analysis - comprehensive read-only assessment.

.DESCRIPTION
  This script performs a complete security assessment of Active Directory and Entra ID environments:
  
  DATA COLLECTION:
  - Active Directory: Users, Groups, Computers, GPOs, Trusts, SPNs, Password Policies, OU ACLs
  - Entra ID: Users, Groups, Roles, Apps, Service Principals, Conditional Access, OAuth Grants, MFA Methods
  
  AUTOMATED ANALYSIS:
  - Identity Hygiene: Flags stale accounts, password issues, delegation risks
  - Privileged Access: Analyzes role membership, excessive permissions, privileged users without MFA
  - Zero Trust Readiness: CA policy baseline validation, MFA coverage, legacy auth detection
  - RBAC Seed Roles: Automatic user clustering by AD group membership with Jaccard similarity merging
  - GPO Modernization: Identifies GPOs to retire or migrate to Intune
  - Security Posture: krbtgt age, Kerberoast surface, OAuth consent analysis
  - Service Principal Hardening: Credential expiration, lifetime analysis, high-privilege permission detection
  - Device Posture: Compliance status, unmanaged device access detection (requires Intune)
  
  OUTPUTS:
  - Comprehensive HTML summary with KPIs, risk findings, and actionable recommendations
  - risk-findings-*.csv: Prioritized security findings (High/Medium/Low)
  - rbac-candidates-*.csv: Suggested RBAC roles based on group membership patterns
  - gpo-modernization-*.csv: GPO migration/retirement candidates
  - kpis-*.json: Key performance indicators
  - Individual CSV/JSON exports for all collected entities

.NOTES
  - Requires: ActiveDirectory module (RSAT) for AD queries
  - Requires: Microsoft.Graph sub-modules for Entra queries (only if -IncludeEntra):
    * Microsoft.Graph.Authentication
    * Microsoft.Graph.Identity.DirectoryManagement
    * Microsoft.Graph.Users
    * Microsoft.Graph.Groups
    * Microsoft.Graph.Applications
    * Microsoft.Graph.Identity.SignIns
    * Microsoft.Graph.Reports
    * Microsoft.Graph.DeviceManagement (optional - for Intune device inventory)
  - Permissions: Directory.Read.All, Application.Read.All, Policy.Read.All, 
                 AuditLog.Read.All, UserAuthenticationMethod.Read.All,
                 DeviceManagementManagedDevices.Read.All (optional - for Intune devices)
  - Note: DO NOT import the full 'Microsoft.Graph' meta-module; it will exceed PowerShell's function limit
  - Troubleshooting: If cmdlets are not recognized, manually install modules:
    Install-Module Microsoft.Graph.Identity.SignIns -Force -Scope CurrentUser
  - All operations are READ-ONLY; no modifications are made to AD or Entra

.EXAMPLE
  .\script.ps1
  Run AD-only assessment (local environment)

.EXAMPLE
  .\script.ps1 -IncludeEntra
  Run comprehensive AD + Entra ID assessment

.EXAMPLE
  .\script.ps1 -IncludeEntra -OutputFolder "C:\Assessments\Client1"
  Run full assessment with custom output location
#>

param(
    [string]$OutputFolder = "$env:TEMP\ADScan",
    [switch]$IncludeEntra,
    [int]$MaxParallel = 8
)

# --- Preparations
if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$now = (Get-Date).ToString("yyyyMMdd-HHmmss")
$meta = [PSCustomObject]@{
    CollectedAt = (Get-Date).ToString("u")
    Host = $env:COMPUTERNAME
    User = (whoami)
    IncludeEntra = $IncludeEntra.IsPresent
}
$meta | ConvertTo-Json | Out-File (Join-Path $OutputFolder "metadata-$now.json")

# --- Helper: write output helper
function Write-OutputFiles {
    param($Name, $Object)
    $csv = Join-Path $OutputFolder "$Name-$now.csv"
    $json = Join-Path $OutputFolder "$Name-$now.json"
    $Object | Export-Csv -Path $csv -NoTypeInformation -Force
    $Object | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Force
}

function Get-LatestFile {
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Folder
    )
    $f = Get-ChildItem -Path $Folder -Filter $Pattern -File -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
    return $f?.FullName
}

# --- AD DISCOVERY ---
function Collect-ADInventory {
    Write-Host "Collecting Active Directory inventory..." -ForegroundColor Cyan

    # ensure AD module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found. Install RSAT or run on a machine with RSAT installed."
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    # Basic domain/forest info
    try {
        $forest = Get-ADForest
        $domain = Get-ADDomain
        $dcs = Get-ADDomainController -Filter * | Select Name,HostName,IPv4Address,OperatingSystem,IsGlobalCatalog
        
        # Detailed trust enumeration
        $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue | Select Name,Direction,TrustType,Source,Target,@{n='TrustAttributes';e={$_.TrustAttributes}},WhenCreated,SelectiveAuthentication
    } catch {
        Write-Warning "Error querying forest/domain: $_"
    }

    $forest | ConvertTo-Json | Out-File (Join-Path $OutputFolder "forest-$now.json")
    $domain | ConvertTo-Json | Out-File (Join-Path $OutputFolder "domain-$now.json")
    $dcs | ConvertTo-Json | Out-File (Join-Path $OutputFolder "dcs-$now.json")
    $trusts | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-trusts-$now.json")

    # Password policies
    Write-Host "Collecting password policies..." -ForegroundColor Gray
    $defaultPwdPolicy = Get-ADDefaultDomainPasswordPolicy
    $defaultPwdPolicy | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-default-pwd-policy-$now.json")
    
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue | Select Name,Precedence,MinPasswordLength,PasswordHistoryCount,LockoutThreshold,ComplexityEnabled,AppliesTo
    if ($fgpp) {
        $fgpp | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-fgpp-$now.json")
    }

    # Users, groups, computers (paged)
    Write-Host "Enumerating users..." -ForegroundColor Gray
    $users = Get-ADUser -Filter * -Properties SamAccountName,UserPrincipalName,Enabled,whenCreated,whenChanged,lastLogonTimestamp,PasswordLastSet,AdminCount,PasswordNeverExpires,TrustedForDelegation,TrustedToAuthForDelegation,MemberOf | Select SamAccountName,UserPrincipalName,Enabled,whenCreated, @{n='LastLogon';e={if($_.lastLogonTimestamp){[DateTime]::FromFileTime($_.lastLogonTimestamp)}}},PasswordLastSet,AdminCount,PasswordNeverExpires,TrustedForDelegation,TrustedToAuthForDelegation,@{n='DaysSinceLogon';e={if($_.lastLogonTimestamp){(New-TimeSpan -Start ([DateTime]::FromFileTime($_.lastLogonTimestamp)) -End (Get-Date)).Days}}},MemberOf
    Write-OutputFiles -Name "ad-users" -Object $users

    Write-Host "Enumerating groups..." -ForegroundColor Gray
    $groups = Get-ADGroup -Filter * -Properties SamAccountName,GroupCategory,GroupScope,whenCreated,member | Select SamAccountName,GroupCategory,GroupScope,whenCreated,@{n='MemberCount';e={$_.member.count}}
    Write-OutputFiles -Name "ad-groups" -Object $groups

    Write-Host "Enumerating computers..." -ForegroundColor Gray
    $computers = Get-ADComputer -Filter * -Properties Name,OperatingSystem,OperatingSystemVersion,IPv4Address,whenCreated,lastLogonTimestamp,TrustedForDelegation,TrustedToAuthForDelegation,MemberOf | Select Name,OperatingSystem,OperatingSystemVersion, @{n='LastLogon';e={if($_.lastLogonTimestamp){[DateTime]::FromFileTime($_.lastLogonTimestamp)}}},@{n='DaysSinceLogon';e={if($_.lastLogonTimestamp){(New-TimeSpan -Start ([DateTime]::FromFileTime($_.lastLogonTimestamp)) -End (Get-Date)).Days}}},whenCreated,TrustedForDelegation,TrustedToAuthForDelegation
    Write-OutputFiles -Name "ad-computers" -Object $computers
    
    # Check krbtgt password age (critical security metric)
    Write-Host "Checking krbtgt account..." -ForegroundColor Gray
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet,whenCreated
    $krbtgtAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
    $krbtgtInfo = [PSCustomObject]@{
        Account = 'krbtgt'
        PasswordLastSet = $krbtgt.PasswordLastSet
        PasswordAgeDays = $krbtgtAge
        WhenCreated = $krbtgt.whenCreated
        RiskLevel = if($krbtgtAge -gt 180){'HIGH - Password >180 days old'}elseif($krbtgtAge -gt 90){'MEDIUM'}else{'OK'}
    }
    $krbtgtInfo | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-krbtgt-$now.json")

    # Identify privileged groups membership
    $privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Enterprise Read-only Domain Controllers') 
    $privResults = foreach ($g in $privGroups) {
        $grp = Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue
        if ($grp) {
            $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue | Select-Object Name,SamAccountName,objectClass
            [PSCustomObject]@{ Group = $g; Count = $members.count; Members = $members }
        } else {
            [PSCustomObject]@{ Group = $g; Count = 0; Members = @() }
        }
    }
    $privResults | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "ad-privileged-groups-$now.json")

    # GPOs and links
    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
        Write-Host "Enumerating GPOs..." -ForegroundColor Gray
        $gpos = Get-GPO -All | Select DisplayName,Id,CreationTime,ModificationTime
        $gpoLinks = foreach ($g in $gpos) {
            $links = (Get-GPOReport -Guid $g.Id -ReportType XML) -as [xml]
            [PSCustomObject]@{ GPO = $g.DisplayName; Id = $g.Id; XML = $links.OuterXml }
        }
        $gpos | Export-Csv (Join-Path $OutputFolder "ad-gpos-$now.csv") -NoTypeInformation -Force
        $gpoLinks | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputFolder "ad-gpo-links-$now.json")
    } else {
        Write-Warning "GPMC / GroupPolicy module not available. Install GroupPolicy RSAT if you need GPO details."
    }

    # OU ACLs - detect non-standard permissions (simplified)
    Write-Host "Enumerating OUs and ACLs (read-only)..." -ForegroundColor Gray
    $ous = Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion,distinguishedName | Select Name,DistinguishedName,ProtectedFromAccidentalDeletion
    $ouAclFindings = foreach ($ou in $ous) {
        try {
            $acl = Get-Acl "AD:$($ou.DistinguishedName)"
            $aces = $acl.Access | Select IdentityReference,ActiveDirectoryRights,AccessControlType,InheritanceType
            [PSCustomObject]@{ OU = $ou.Name; DN = $ou.DistinguishedName; ACEs = $aces }
        } catch {
            [PSCustomObject]@{ OU = $ou.Name; DN = $ou.DistinguishedName; ACEs = "error: $_" }
        }
    }
    $ouAclFindings | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "ad-ou-acls-$now.json")

    # SPNs (Kerberoast surface)
    Write-Host "Collecting accounts with SPNs (service accounts)..." -ForegroundColor Gray
    $spnAccounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName | Select SamAccountName,ServicePrincipalName
    $spnAccounts | Export-Csv (Join-Path $OutputFolder "ad-spn-accounts-$now.csv") -NoTypeInformation -Force

    Write-Host "Active Directory collection complete." -ForegroundColor Green
}

# --- ENTRA / AZURE AD DISCOVERY ---
function Collect-EntraInventory {
    param()
    Write-Host "Collecting Entra (Azure AD) inventory via Microsoft Graph..." -ForegroundColor Cyan

    # CRITICAL: Prevent PowerShell from auto-loading the entire Microsoft.Graph meta-module (16k+ functions)
    $PSModuleAutoLoadingPreference = 'None'
    
    # Ensure Microsoft.Graph sub-modules (importing specific modules to avoid function limit)
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement', 
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Applications',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Reports'
    )
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing $module..." -ForegroundColor Gray
            try {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Host "  [OK] Installed $module" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to install ${module}: $($_.Exception.Message)"
                continue
            }
        }
        
        try {
            Import-Module $module -ErrorAction Stop
            Write-Host "  [OK] Loaded $module" -ForegroundColor DarkGray
        } catch {
            Write-Warning "Failed to import ${module}: $($_.Exception.Message)"
        }
    }

    # Scopes you will need: Directory.Read.All, Application.Read.All, Policy.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, DeviceManagementManagedDevices.Read.All
    Write-Host "Interactive sign-in to Graph (consent for required permissions may be required)..." -ForegroundColor Gray
    Connect-MgGraph -Scopes "Directory.Read.All","Application.Read.All","Policy.Read.All","AuditLog.Read.All","UserAuthenticationMethod.Read.All","DeviceManagementManagedDevices.Read.All" -ErrorAction Stop

    # Basic tenant info
    $tenant = Get-MgOrganization | Select Id,DisplayName
    $tenant | ConvertTo-Json | Out-File (Join-Path $OutputFolder "entra-tenant-$now.json")

    # Users
    Write-Host "Enumerating Entra users..." -ForegroundColor Gray
    $users = Get-MgUser -All -Property "displayName,mail,userPrincipalName,accountEnabled,createdDateTime,signInActivity" | Select Id,DisplayName,Mail,UserPrincipalName,AccountEnabled,CreatedDateTime,@{n='LastSignIn';e={$_.SignInActivity.LastSignInDateTime}}
    Write-OutputFiles -Name "entra-users" -Object $users

    # Groups
    Write-Host "Enumerating Entra groups..." -ForegroundColor Gray
    $groups = Get-MgGroup -All | Select Id,DisplayName,MailEnabled,SecurityEnabled,GroupTypes,CreatedDateTime
    Write-OutputFiles -Name "entra-groups" -Object $groups

    # Admin role assignments (Privileged roles)
    Write-Host "Enumerating role assignments (directory roles)..." -ForegroundColor Gray
    $roles = Get-MgDirectoryRole -All | Select Id,DisplayName,RoleTemplateId
    $roleAssignments = foreach ($r in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All | Select Id,DisplayName,UserPrincipalName,@{n='Type';e={$_.AdditionalProperties.'@odata.type'}}
        [PSCustomObject]@{ Role = $r.DisplayName; Template = $r.RoleTemplateId; MemberCount = $members.count; Members = $members }
    }
    $roleAssignments | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "entra-role-assignments-$now.json")

    # Service principals & applications
    Write-Host "Enumerating service principals & enterprise apps..." -ForegroundColor Gray
    $sps = Get-MgServicePrincipal -All | Select Id,DisplayName,AppId,Tags,AppOwnerTenantId
    Write-OutputFiles -Name "entra-serviceprincipals" -Object $sps

    $apps = Get-MgApplication -All | Select Id,DisplayName,AppId,SignInAudience,CreatedDateTime
    Write-OutputFiles -Name "entra-apps" -Object $apps
    
    # Service Principal Credentials (secrets & certificates)
    Write-Host "Collecting service principal credentials (secrets/certs)..." -ForegroundColor Gray
    $spCredentials = @()
    foreach ($sp in ($sps | Select-Object -First 500)) {
        try {
            # Password credentials (secrets)
            $secrets = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
            foreach ($secret in $secrets) {
                $daysToExpiry = if ($secret.EndDateTime) { (New-TimeSpan -Start (Get-Date) -End $secret.EndDateTime).Days } else { $null }
                $lifetimeDays = if ($secret.StartDateTime -and $secret.EndDateTime) { 
                    (New-TimeSpan -Start $secret.StartDateTime -End $secret.EndDateTime).Days 
                } else { $null }
                
                $spCredentials += [PSCustomObject]@{
                    ServicePrincipal = $sp.DisplayName
                    SPId = $sp.Id
                    CredentialType = 'Secret'
                    KeyId = $secret.KeyId
                    StartDate = $secret.StartDateTime
                    EndDate = $secret.EndDateTime
                    DaysToExpiry = $daysToExpiry
                    LifetimeDays = $lifetimeDays
                }
            }
            
            # Certificate credentials
            $certs = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
            foreach ($cert in $certs) {
                $daysToExpiry = if ($cert.EndDateTime) { (New-TimeSpan -Start (Get-Date) -End $cert.EndDateTime).Days } else { $null }
                $lifetimeDays = if ($cert.StartDateTime -and $cert.EndDateTime) { 
                    (New-TimeSpan -Start $cert.StartDateTime -End $cert.EndDateTime).Days 
                } else { $null }
                
                $spCredentials += [PSCustomObject]@{
                    ServicePrincipal = $sp.DisplayName
                    SPId = $sp.Id
                    CredentialType = 'Certificate'
                    KeyId = $cert.KeyId
                    StartDate = $cert.StartDateTime
                    EndDate = $cert.EndDateTime
                    DaysToExpiry = $daysToExpiry
                    LifetimeDays = $lifetimeDays
                }
            }
        } catch {
            Write-Warning "Failed to get credentials for $($sp.DisplayName): $($_.Exception.Message)"
        }
    }
    if ($spCredentials.Count -gt 0) {
        Write-OutputFiles -Name "entra-sp-credentials" -Object $spCredentials
    }
    
    # OAuth consented permissions (delegated & application permissions)
    Write-Host "Enumerating OAuth2 permission grants..." -ForegroundColor Gray
    try {
        $oauth2Grants = Get-MgOauth2PermissionGrant -All | Select Id,ClientId,ConsentType,PrincipalId,ResourceId,Scope
        $oauth2Grants | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "entra-oauth2-grants-$now.json")
        
        # App role assignments (application permissions) - Enhanced with permission names
        $appRoleAssignments = foreach($sp in $sps | Select-Object -First 500) {
            try {
                $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                foreach($r in $roles) {
                    # Try to resolve permission name from resource SP
                    $permissionName = "Unknown"
                    try {
                        $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $r.ResourceId -ErrorAction SilentlyContinue
                        $appRole = $resourceSP.AppRoles | Where-Object { $_.Id -eq $r.AppRoleId }
                        if ($appRole) {
                            $permissionName = $appRole.Value
                        }
                    } catch { }
                    
                    [PSCustomObject]@{
                        ServicePrincipal = $sp.DisplayName
                        SPId = $sp.Id
                        ResourceId = $r.ResourceId
                        ResourceDisplayName = $r.ResourceDisplayName
                        AppRoleId = $r.AppRoleId
                        PermissionName = $permissionName
                        PrincipalType = $r.PrincipalType
                    }
                }
            } catch { }
        }
        $appRoleAssignments | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "entra-approle-assignments-$now.json")
    } catch {
        Write-Warning "OAuth permission enumeration failed: $_"
    }

    # Conditional Access Policies (Policy.Read.All)
    Write-Host "Enumerating Conditional Access policies..." -ForegroundColor Gray
    try {
        if (Get-Command Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue) {
            # Newer cmdlet name
            $ca = Get-MgIdentityConditionalAccessPolicy -All
            $ca | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputFolder "entra-conditionalaccess-$now.json")
        } elseif (Get-Command Get-MgConditionalAccessPolicy -ErrorAction SilentlyContinue) {
            # Legacy cmdlet name
            $ca = Get-MgConditionalAccessPolicy -All
            $ca | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputFolder "entra-conditionalaccess-$now.json")
        } else {
            Write-Warning "Conditional Access cmdlet not found. Ensure Microsoft.Graph.Identity.SignIns module v2.0+ is installed."
            Write-Host "  Try: Install-Module Microsoft.Graph.Identity.SignIns -Force -Scope CurrentUser" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Conditional Access policies require 'Policy.Read.All' permission: $_"
    }

    # (Optional) Sign-in logs / Audit logs - may require AuditLog.Read.All
    try {
        Write-Host "Attempting to collect recent sign-ins (if permissions allowed)..." -ForegroundColor Gray
        $signins = Get-MgAuditLogSignIn -All -Top 500 | Select-Object Id,UserDisplayName,UserPrincipalName,AppDisplayName,ClientAppUsed,IpAddress,CreatedDateTime,Status
        $signins | Export-Csv (Join-Path $OutputFolder "entra-signins-$now.csv") -NoTypeInformation -Force
    } catch {
        Write-Warning "Sign-in retrieval likely blocked by permissions: $_"
    }

    # MFA / Authentication Methods (UserAuthenticationMethod.Read.All)
    Write-Host "Collecting authentication methods (MFA coverage)..." -ForegroundColor Gray
    try {
        $authMethods = foreach ($user in ($users | Select-Object -First 500)) {
            try {
                $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                $methodTypes = $methods | ForEach-Object { $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' }
                [PSCustomObject]@{
                    UserId = $user.Id
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    MethodCount = $methods.Count
                    Methods = ($methodTypes -join ', ')
                    HasMFA = ($methodTypes | Where-Object { $_ -notmatch 'password' }).Count -gt 0
                }
            } catch { }
        }
        $authMethods | Export-Csv (Join-Path $OutputFolder "entra-authmethods-$now.csv") -NoTypeInformation -Force
    } catch {
        Write-Warning "Authentication methods collection requires 'UserAuthenticationMethod.Read.All': $_"
    }

    # Device Inventory (Intune + Azure AD Devices) - Phase 2
    Write-Host "Collecting device inventory (Intune + Azure AD devices)..." -ForegroundColor Gray
    try {
        # Try to get Intune managed devices
        if (Get-Command Get-MgDeviceManagementManagedDevice -ErrorAction SilentlyContinue) {
            $intuneDevices = Get-MgDeviceManagementManagedDevice -All | Select-Object DeviceName,Id,ManagedDeviceId,OperatingSystem,OsVersion,ComplianceState,ManagementAgent,EnrolledDateTime,LastSyncDateTime,AzureAdDeviceId,UserPrincipalName
            if ($intuneDevices) {
                Write-OutputFiles -Name "entra-intune-devices" -Object $intuneDevices
                Write-Host "  Collected $($intuneDevices.Count) Intune managed devices" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  Intune device collection skipped (Microsoft.Graph.DeviceManagement module not available)" -ForegroundColor DarkGray
        }

        # Azure AD registered/joined devices
        if (Get-Command Get-MgDevice -ErrorAction SilentlyContinue) {
            $aadDevices = Get-MgDevice -All | Select-Object DisplayName,Id,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,ApproximateLastSignInDateTime,RegisteredOwners
            if ($aadDevices) {
                Write-OutputFiles -Name "entra-aad-devices" -Object $aadDevices
                Write-Host "  Collected $($aadDevices.Count) Azure AD devices" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  Azure AD device collection skipped (permissions or module issue)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Device inventory collection failed: $($_.Exception.Message)"
    }

    Disconnect-MgGraph
    
    # Clean up Graph modules to prevent session bloat
    Get-Module Microsoft.Graph* | Remove-Module -Force
    
    Write-Host "Entra collection complete." -ForegroundColor Green
}

# --- COMPREHENSIVE ANALYSIS ENGINE ---
function Analyze-Inventory {
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$NowTag
    )

    Write-Host "Analyzing collected inventory..." -ForegroundColor Cyan

    $findings = New-Object System.Collections.Generic.List[object]
    $kpis     = [ordered]@{}
        # --- Remediation Guidance Mapping ---
        $remediationGuide = @{
            'StaleUsers' = @{
                Impact = 'Inactive accounts are attack targets - credentials may be compromised without detection'
                Steps = '1. Review list of inactive users in ad-users CSV|2. Disable accounts inactive >90 days|3. Move to quarantine OU for 30 days|4. Delete if no business need documented|5. Implement automated account lifecycle policy'
                Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
                Effort = '2-4 hours'
                Category = 'Identity Hygiene'
            }
            'PasswordNeverExpires' = @{
                Impact = 'Accounts with non-expiring passwords pose long-term credential theft risk'
                Steps = '1. Review users with PasswordNeverExpires flag|2. For service accounts: transition to gMSA or Entra managed identity|3. For users: remove flag and enforce password rotation|4. Implement password policy compliance monitoring'
                Reference = 'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview'
                Effort = '4-6 hours'
                Category = 'Identity Hygiene'
            }
            'KerberosDelegation' = @{
                Impact = 'Delegation allows accounts to impersonate users - creates high lateral movement risk'
                Steps = '1. Review delegation assignments in evidence file|2. Remove unconstrained delegation immediately|3. Replace with constrained or resource-based delegation|4. Enable "Account is sensitive and cannot be delegated" for privileged users|5. Monitor Event 4662 for delegation abuse'
                Reference = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
                Effort = '6-8 hours'
                Category = 'Privileged Access'
            }
            'UnconstrainedDelegation' = @{
                Impact = 'CRITICAL: Enables credential theft and Golden Ticket attacks via TGT harvesting'
                Steps = '1. URGENT: Identify all computers with unconstrained delegation|2. Replace with constrained delegation for specific services only|3. Enable SMB signing and LDAP signing|4. Monitor Event 4768/4769 for TGT requests|5. Consider Protected Users group for sensitive accounts'
                Reference = 'https://adsecurity.org/?p=1667'
                Effort = '8-12 hours'
                Category = 'Privileged Access'
            }
            'KrbtgtPassword' = @{
                Impact = 'CRITICAL: Old krbtgt password enables indefinite Golden Ticket attacks'
                Steps = '1. Schedule maintenance window - requires 2 sessions 24 hours apart|2. Run New-KrbtgtKeys.ps1 to reset password|3. Wait 24 hours for AD replication|4. Run New-KrbtgtKeys.ps1 again (second reset)|5. Monitor Event Logs for Kerberos errors|6. Set recurring reminder for 180 days'
                Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password'
                Effort = '2-3 hours + 24hr wait'
                Category = 'Critical Security'
            }
            'SPNAccounts' = @{
                Impact = 'SPNs expose service accounts to Kerberoasting - offline password cracking attacks'
                Steps = '1. Audit all SPN accounts in evidence CSV|2. Set long complex passwords (25+ characters) or use gMSA|3. Transition to group Managed Service Accounts where possible|4. Enable "Account is sensitive" for high-value SPNs|5. Monitor Event 4769 for RC4 encryption (Kerberoast indicator)|6. Implement SPN ACL restrictions'
                Reference = 'https://adsecurity.org/?p=2293'
                Effort = '6-10 hours'
                Category = 'Identity Hygiene'
            }
            'OversizedGroups' = @{
                Impact = 'Large groups complicate access review and often contain excessive permissions'
                Steps = '1. Review groups with 500+ members|2. Identify group purpose and business owner|3. Split into functional sub-groups by department/role|4. Implement RBAC model using Entra ID roles|5. Remove circular/nested group sprawl|6. Establish group management policy with regular reviews'
                Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices'
                Effort = '10-15 hours'
                Category = 'Access Management'
            }
            'PrivilegedRoles' = @{
                Impact = 'Excessive privileged access increases insider threat and breach impact radius'
                Steps = '1. Review all members of privileged roles in evidence JSON|2. Remove unnecessary permanent assignments|3. Implement Privileged Identity Management (PIM) for just-in-time access|4. Require MFA for all privileged accounts|5. Create emergency break-glass accounts (2-3)|6. Enable privileged activity auditing and alerts'
                Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure'
                Effort = '8-12 hours'
                Category = 'Privileged Access'
            }
            'NoConditionalAccess' = @{
                Impact = 'CRITICAL: No Zero Trust controls - authentication security relies solely on passwords'
                Steps = '1. Enable Azure AD Security Defaults immediately as interim measure|2. Plan Conditional Access policy rollout|3. Start with: require MFA for all users|4. Add: block legacy authentication protocols|5. Implement: require compliant or hybrid joined devices|6. Add: risk-based sign-in policies|7. Test all policies in report-only mode before enforcement'
                Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/plan-conditional-access'
                Effort = '12-20 hours'
                Category = 'Zero Trust'
            }
            'NoMFA' = @{
                Impact = 'Users without MFA are vulnerable to password spray, phishing, and credential stuffing attacks'
                Steps = '1. Launch MFA registration campaign with user communications|2. Start with Global Admins (mandatory)|3. Roll out to all users in phases by department|4. Provide multiple MFA methods: Microsoft Authenticator app, FIDO2 keys, Windows Hello for Business|5. Configure Conditional Access to block legacy auth that bypasses MFA|6. Monitor MFA registration compliance dashboard'
                Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks'
                Effort = '15-25 hours + user training'
                Category = 'Zero Trust'
            }
            'LegacyAuth' = @{
                Impact = 'Legacy authentication protocols bypass MFA and modern security controls entirely'
                Steps = '1. Identify applications using legacy auth in sign-in logs|2. Update or replace legacy applications|3. Configure Conditional Access policy to block legacy auth|4. Create temporary exception for service accounts with monitoring|5. Monitor blocked sign-in attempts|6. Plan decommissioning of IMAP/POP/SMTP protocols'
                Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication'
                Effort = '8-15 hours'
                Category = 'Zero Trust'
            }
            'RiskyServicePrincipals' = @{
                Impact = 'Orphaned or misconfigured service principals may have excessive API permissions'
                Steps = '1. Audit all service principals in evidence CSV|2. Identify and document business owner for each|3. Review assigned API permissions and consent grants|4. Remove unused or orphaned service principals|5. Implement least-privilege permissions for remaining SPs|6. Enable credential expiration (max 12 months)|7. Monitor for suspicious SP activity'
                Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-remove-app'
                Effort = '6-10 hours'
                Category = 'Application Security'
            }
            'OAuthPermissions' = @{
                Impact = 'Admin-consented grants may provide excessive access to organizational data and resources'
                Steps = '1. Review all admin-consented OAuth grants in evidence JSON|2. Validate business need and risk for each application|3. Revoke excessive or unused permissions|4. Implement app consent policies to restrict future consents|5. Enable admin consent request workflow for user submissions|6. Conduct security awareness training on OAuth consent risks'
                Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-admin-consent-workflow'
                Effort = '4-8 hours'
                Category = 'Application Security'
            }
            'UnlinkedGPOs' = @{
                Impact = 'Unlinked GPOs create configuration drift and potential security gaps if accidentally re-linked'
                Steps = '1. Review unlinked GPOs in evidence CSV|2. Document purpose and historical context|3. Backup GPO settings using Backup-GPO cmdlet|4. Delete or archive unlinked GPOs after stakeholder approval|5. Plan migration of remaining security GPOs to Intune configuration profiles|6. Develop GPO decommissioning roadmap'
                Reference = 'https://learn.microsoft.com/en-us/mem/intune/configuration/device-profiles'
                Effort = '3-6 hours'
                Category = 'Modernization'
            }
            'OUDelegation' = @{
                Impact = 'Non-standard OU permissions may allow unauthorized AD object modifications'
                Steps = '1. Review OU ACLs for non-standard permissions in evidence JSON|2. Identify and document delegation purpose with AD team|3. Remove unnecessary or overly-broad delegations|4. Implement least-privilege OU administration model|5. Document all approved delegations in runbook|6. Schedule quarterly permission audits'
                Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory'
                Effort = '4-8 hours'
                Category = 'Access Management'
            }
        }
    
        # Helper function to get remediation guidance
        function Get-RemediationGuidance {
            param([string]$RiskType)
            if ($remediationGuide.ContainsKey($RiskType)) {
                return $remediationGuide[$RiskType]
            }
            # Default fallback
            return @{
                Impact = 'Review finding details and consult security best practices for remediation approach'
                Steps = '1. Assess risk and business impact|2. Plan remediation strategy|3. Implement security controls|4. Verify effectiveness|5. Document changes'
                Reference = 'https://learn.microsoft.com/en-us/security/'
                Effort = 'TBD'
                Category = 'General'
            }
        }

    # --- Locate latest files ---
    $adUsersCsv   = if ($NowTag) { Join-Path $OutputFolder "ad-users-$NowTag.csv" } else { Get-LatestFile -Pattern 'ad-users-*.csv' -Folder $OutputFolder }
    $adGroupsCsv  = if ($NowTag) { Join-Path $OutputFolder "ad-groups-$NowTag.csv" } else { Get-LatestFile -Pattern 'ad-groups-*.csv' -Folder $OutputFolder }
    $adComputers  = if ($NowTag) { Join-Path $OutputFolder "ad-computers-$NowTag.csv" } else { Get-LatestFile -Pattern 'ad-computers-*.csv' -Folder $OutputFolder }
    $adSpnCsv     = if ($NowTag) { Join-Path $OutputFolder "ad-spn-accounts-$NowTag.csv" } else { Get-LatestFile -Pattern 'ad-spn-accounts-*.csv' -Folder $OutputFolder }
    $gposCsv      = if ($NowTag) { Join-Path $OutputFolder "ad-gpos-$NowTag.csv" } else { Get-LatestFile -Pattern 'ad-gpos-*.csv' -Folder $OutputFolder }
    $gpoLinksJson = if ($NowTag) { Join-Path $OutputFolder "ad-gpo-links-$NowTag.json" } else { Get-LatestFile -Pattern 'ad-gpo-links-*.json' -Folder $OutputFolder }
    $ouAclsJson   = if ($NowTag) { Join-Path $OutputFolder "ad-ou-acls-$NowTag.json" } else { Get-LatestFile -Pattern 'ad-ou-acls-*.json' -Folder $OutputFolder }
    $krbtgtJson   = if ($NowTag) { Join-Path $OutputFolder "ad-krbtgt-$NowTag.json" } else { Get-LatestFile -Pattern 'ad-krbtgt-*.json' -Folder $OutputFolder }
    $adPwdPolicyJson = if ($NowTag) { Join-Path $OutputFolder "ad-default-pwd-policy-$NowTag.json" } else { Get-LatestFile -Pattern 'ad-default-pwd-policy-*.json' -Folder $OutputFolder }
    $adFgppJson   = if ($NowTag) { Join-Path $OutputFolder "ad-fgpp-$NowTag.json" } else { Get-LatestFile -Pattern 'ad-fgpp-*.json' -Folder $OutputFolder }
    $adTrustsJson = if ($NowTag) { Join-Path $OutputFolder "ad-trusts-$NowTag.json" } else { Get-LatestFile -Pattern 'ad-trusts-*.json' -Folder $OutputFolder }

    $entraUsersCsv   = if ($NowTag) { Join-Path $OutputFolder "entra-users-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-users-*.csv' -Folder $OutputFolder }
    $entraGroupsCsv  = if ($NowTag) { Join-Path $OutputFolder "entra-groups-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-groups-*.csv' -Folder $OutputFolder }
    $rolesJson       = if ($NowTag) { Join-Path $OutputFolder "entra-role-assignments-$NowTag.json" } else { Get-LatestFile -Pattern 'entra-role-assignments-*.json' -Folder $OutputFolder }
    $caJson          = if ($NowTag) { Join-Path $OutputFolder "entra-conditionalaccess-$NowTag.json" } else { Get-LatestFile -Pattern 'entra-conditionalaccess-*.json' -Folder $OutputFolder }
    $spsCsv          = if ($NowTag) { Join-Path $OutputFolder "entra-serviceprincipals-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-serviceprincipals-*.csv' -Folder $OutputFolder }
    $appsCsv         = if ($NowTag) { Join-Path $OutputFolder "entra-apps-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-apps-*.csv' -Folder $OutputFolder }
    $signInsCsv      = if ($NowTag) { Join-Path $OutputFolder "entra-signins-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-signins-*.csv' -Folder $OutputFolder }
    $authMethodsCsv  = if ($NowTag) { Join-Path $OutputFolder "entra-authmethods-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-authmethods-*.csv' -Folder $OutputFolder }
    $oauth2Json      = if ($NowTag) { Join-Path $OutputFolder "entra-oauth2-grants-$NowTag.json" } else { Get-LatestFile -Pattern 'entra-oauth2-grants-*.json' -Folder $OutputFolder }
    $spCredsCsv      = if ($NowTag) { Join-Path $OutputFolder "entra-sp-credentials-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-sp-credentials-*.csv' -Folder $OutputFolder }
    $appRoleJson     = if ($NowTag) { Join-Path $OutputFolder "entra-approle-assignments-$NowTag.json" } else { Get-LatestFile -Pattern 'entra-approle-assignments-*.json' -Folder $OutputFolder }
    $intuneDevCsv    = if ($NowTag) { Join-Path $OutputFolder "entra-intune-devices-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-intune-devices-*.csv' -Folder $OutputFolder }
    $aadDevicesCsv   = if ($NowTag) { Join-Path $OutputFolder "entra-aad-devices-$NowTag.csv" } else { Get-LatestFile -Pattern 'entra-aad-devices-*.csv' -Folder $OutputFolder }

    # --- Load what exists ---
    $adUsers  = if (Test-Path $adUsersCsv)  { Import-Csv $adUsersCsv }  else { @() }
    $adGroups = if (Test-Path $adGroupsCsv) { Import-Csv $adGroupsCsv } else { @() }
    $adComps  = if (Test-Path $adComputers) { Import-Csv $adComputers } else { @() }
    $adSpn    = if (Test-Path $adSpnCsv)    { Import-Csv $adSpnCsv }    else { @() }
    $gpos     = if (Test-Path $gposCsv)     { Import-Csv $gposCsv }     else { @() }
    $gpoLinks = if (Test-Path $gpoLinksJson){ Get-Content $gpoLinksJson | ConvertFrom-Json } else { @() }
    $ouAcls   = if (Test-Path $ouAclsJson)  { Get-Content $ouAclsJson | ConvertFrom-Json }  else { @() }
    $krbtgt   = if (Test-Path $krbtgtJson)  { Get-Content $krbtgtJson | ConvertFrom-Json }  else { $null }
    $adPwdPolicy = if (Test-Path $adPwdPolicyJson) { Get-Content $adPwdPolicyJson | ConvertFrom-Json } else { $null }
    $adFgpp   = if (Test-Path $adFgppJson)  { Get-Content $adFgppJson | ConvertFrom-Json }  else { @() }
    $adTrusts = if (Test-Path $adTrustsJson){ Get-Content $adTrustsJson | ConvertFrom-Json } else { @() }

    $eUsers      = if (Test-Path $entraUsersCsv)  { Import-Csv $entraUsersCsv }  else { @() }
    $eGroups     = if (Test-Path $entraGroupsCsv) { Import-Csv $entraGroupsCsv } else { @() }
    $roles       = if (Test-Path $rolesJson)      { Get-Content $rolesJson | ConvertFrom-Json } else { @() }
    $ca          = if (Test-Path $caJson)         { Get-Content $caJson | ConvertFrom-Json }    else { @() }
    $sps         = if (Test-Path $spsCsv)         { Import-Csv $spsCsv }                         else { @() }
    $apps        = if (Test-Path $appsCsv)        { Import-Csv $appsCsv }                        else { @() }
    $signins     = if (Test-Path $signInsCsv)     { Import-Csv $signInsCsv }                     else { @() }
    $authMethods = if (Test-Path $authMethodsCsv) { Import-Csv $authMethodsCsv }                 else { @() }
    $oauth2      = if (Test-Path $oauth2Json)     { Get-Content $oauth2Json | ConvertFrom-Json } else { @() }
    $spCreds     = if (Test-Path $spCredsCsv)     { Import-Csv $spCredsCsv }                     else { @() }
    $appRoles    = if (Test-Path $appRoleJson)    { Get-Content $appRoleJson | ConvertFrom-Json } else { @() }
    $intuneDevs  = if (Test-Path $intuneDevCsv)   { Import-Csv $intuneDevCsv }                   else { @() }
    $aadDevices  = if (Test-Path $aadDevicesCsv)  { Import-Csv $aadDevicesCsv }                  else { @() }

    # --- KPIs ---
    $kpis.UsersAD         = $adUsers.Count
    $kpis.GroupsAD        = $adGroups.Count
    $kpis.ComputersAD     = $adComps.Count
    $kpis.SPNAccounts     = $adSpn.Count
    $kpis.UsersEntra      = $eUsers.Count
    $kpis.GroupsEntra     = $eGroups.Count
    $kpis.ConditionalAccessPolicies = ($ca | Measure-Object).Count
    $kpis.ServicePrincipals = $sps.Count

    # ========== RISK RULES ==========

    # 1) AD: stale but enabled users (>90d no logon)
    $stale = $adUsers | Where-Object {
        $_.Enabled -eq 'True' -and $_.DaysSinceLogon -and [int]$_.DaysSinceLogon -gt 90
    }
    if ($stale.Count -gt 0) {
        $remedy = Get-RemediationGuidance 'StaleUsers'
        $findings.Add([pscustomobject]@{
            Area='AD Users'
            Finding="$($stale.Count) enabled users inactive >90 days"
            Severity='Medium'
            Evidence='ad-users'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }

    # 2) AD: Password never expires
    if ($pwdNeverExpires.Count -gt 0) {
        $remedy = Get-RemediationGuidance 'PasswordNeverExpires'
        $findings.Add([pscustomobject]@{
            Area='AD Users'
            Finding="$($pwdNeverExpires.Count) enabled users with PasswordNeverExpires"
            Severity='Medium'
            Evidence='ad-users'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }
    # 3) AD: Delegation risks
    if ($delegUsers.Count -gt 0) {
        $remedy = Get-RemediationGuidance 'KerberosDelegation'
        $findings.Add([pscustomobject]@{
            Area='AD Delegation'
            Finding="$($delegUsers.Count) user accounts configured for Kerberos delegation"
            Severity='High'
            Evidence='ad-users'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }

    # 4) AD: Unconstrained delegation on computers
    if ($unconstrainedComps.Count -gt 0) {
        $remedy = Get-RemediationGuidance 'UnconstrainedDelegation'
        $findings.Add([pscustomobject]@{
            Area='AD Computers'
            Finding="$($unconstrainedComps.Count) computers with Unconstrained Delegation"
            Severity='High'
            Evidence='ad-computers'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }

    # 5) AD: krbtgt password age
    if ($krbtgt -and $krbtgt.RiskLevel -like 'HIGH*') {
        $remedy = Get-RemediationGuidance 'KrbtgtPassword'
        $findings.Add([pscustomobject]@{
            Area='AD Security'
            Finding="krbtgt password is $($krbtgt.PasswordAgeDays) days old (>180 days)"
            Severity='High'
            Evidence='ad-krbtgt'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }

    # 6) AD: SPN surface (Kerberoast risk)
    if ($adSpn.Count -gt 0) {
        $sev = if ($adSpn.Count -gt 100) {'High'} elseif ($adSpn.Count -gt 30) {'Medium'} else {'Low'}
        $remedy = Get-RemediationGuidance 'SPNAccounts'
        $findings.Add([pscustomobject]@{
            Area='AD SPNs'
            Finding="$($adSpn.Count) accounts with SPNs (kerberoastable surface)"
            Severity=$sev
            Evidence='ad-spn-accounts'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }

    # 7) AD: oversized group sprawl
    if ($bigGroups.Count -gt 0) {
        $remedy = Get-RemediationGuidance 'OversizedGroups'
        $findings.Add([pscustomobject]@{
            Area='AD Groups'
            Finding="$($bigGroups.Count) groups have >=500 members"
            Severity='Medium'
            Evidence='ad-groups'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }

    # 8) Entra: privileged roles & members
    foreach ($r in $roles) {
        if ($r.Role -match 'Global Administrator|Privileged Role Administrator|Application Administrator|Cloud Application Administrator|User Administrator') {
            if ($r.MemberCount -gt 0) {
                $sev = if($r.Role -match 'Global Administrator|Privileged Role Administrator'){'High'}else{'Medium'}
                $remedy = Get-RemediationGuidance 'PrivilegedRoles'
                $findings.Add([pscustomobject]@{
                    Area='Entra Roles'
                    Finding="$($r.Role) has $($r.MemberCount) members"
                    Severity=$sev
                    Evidence='entra-role-assignments'
                    Impact=$remedy.Impact
                    RemediationSteps=$remedy.Steps
                    Reference=$remedy.Reference
                    EstimatedEffort=$remedy.Effort
                    Category=$remedy.Category
                    Owner=''
                    DueDate=''
                    Status='Open'
                })
            }
        }
    }

    # 9) Entra: Conditional Access present?
    if (-not $ca -or $ca.Count -eq 0) {
        $remedy = Get-RemediationGuidance 'NoConditionalAccess'
        $findings.Add([pscustomobject]@{
            Area='Zero Trust'
            Finding='No Conditional Access policies found'
            Severity='High'
            Evidence='entra-conditionalaccess'
            Impact=$remedy.Impact
            RemediationSteps=$remedy.Steps
            Reference=$remedy.Reference
            EstimatedEffort=$remedy.Effort
            Category=$remedy.Category
            Owner=''
            DueDate=''
            Status='Open'
        })
    }

    # 10) Entra: MFA coverage for privileged users
    if ($authMethods.Count -gt 0) {
        $noMFA = $authMethods | Where-Object { $_.HasMFA -eq 'False' }
        if ($noMFA.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Zero Trust'; Finding="$($noMFA.Count) users without MFA registered"; Severity='High'; Evidence='entra-authmethods'
            })
        }
        $kpis.MFARegistered = ($authMethods | Where-Object { $_.HasMFA -eq 'True' }).Count
        $kpis.MFANotRegistered = $noMFA.Count
    }

    # 11) Entra: sign-ins indicating legacy auth (ENHANCED: ClientAppUsed detection)
    $legacy = @()
    if ($signins.Count -gt 0) {
        # ClientAppUsed is the definitive field for protocol detection
        $legacy = $signins | Where-Object {
            $_.ClientAppUsed -match 'IMAP|POP|SMTP|Legacy|Exchange ActiveSync|Other clients|MAPI' -or
            $_.AppDisplayName -match 'IMAP|POP|SMTP|Legacy'
        }
        if ($legacy.Count -gt 0) {
            # Count unique users affected
            $legacyUsers = $legacy | Select-Object -ExpandProperty UserPrincipalName -Unique
            $findings.Add([pscustomobject]@{
                Area='Legacy Auth'; 
                Finding="$($legacy.Count) sign-ins via legacy protocols (IMAP/POP/SMTP/Basic Auth) from $($legacyUsers.Count) users"; 
                Severity='High'; 
                Evidence='entra-signins'
            })
        }
    }

    # 12) Service principals with potential issues
    $riskySps = $sps | Where-Object {
        -not $_.Tags -or $_.Tags -match 'WindowsAzureActiveDirectoryIntegratedApp'
    }
    if ($riskySps.Count -gt 0) {
        $findings.Add([pscustomobject]@{
            Area='Service Principals'; Finding="$($riskySps.Count) enterprise apps need review (owners/permissions)"; Severity='Medium'; Evidence='entra-serviceprincipals'
        })
    }

    # 13) OAuth grants - admin consent
    if ($oauth2 -and $oauth2.Count -gt 0) {
        $adminConsent = $oauth2 | Where-Object { $_.ConsentType -eq 'AllPrincipals' }
        if ($adminConsent.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='OAuth Permissions'; Finding="$($adminConsent.Count) admin-consented OAuth grants (review for excessive permissions)"; Severity='Medium'; Evidence='entra-oauth2-grants'
            })
        }
    }

    # === PHASE 1 ENHANCEMENTS ===

    # 14) PRIVILEGE RULESET: Privileged role members without MFA
    if ($roles -and $authMethods.Count -gt 0) {
        $privilegedRoles = @('Global Administrator','Privileged Role Administrator','Security Administrator',
                             'Application Administrator','Cloud Application Administrator','User Administrator',
                             'Exchange Administrator','SharePoint Administrator','Teams Administrator')
        
        foreach ($r in $roles) {
            if ($r.Role -in $privilegedRoles -and $r.Members) {
                foreach ($member in $r.Members) {
                    if ($member.Type -match 'user') {
                        $userAuth = $authMethods | Where-Object { $_.UserPrincipalName -eq $member.UserPrincipalName }
                        if ($userAuth -and $userAuth.HasMFA -eq 'False') {
                            $findings.Add([pscustomobject]@{
                                Area='Privileged Access'; 
                                Finding="$($member.DisplayName) in $($r.Role) lacks MFA"; 
                                Severity='High'; 
                                Evidence='entra-role-assignments,entra-authmethods'
                            })
                        } elseif (-not $userAuth) {
                            # User exists in role but no auth method data (likely permission issue)
                            $findings.Add([pscustomobject]@{
                                Area='Privileged Access'; 
                                Finding="$($member.DisplayName) in $($r.Role) - MFA status unknown"; 
                                Severity='High'; 
                                Evidence='entra-role-assignments'
                            })
                        }
                    }
                }
            }
        }
    }

    # 15) CA BASELINES: Validate Zero Trust baseline policies
    if ($ca -and $ca.Count -gt 0) {
        $caBaselines = @{
            'RequireMFA' = $ca | Where-Object { 
                $_.GrantControls.BuiltInControls -contains 'mfa' -and 
                ($_.Conditions.Users.IncludeUsers -contains 'All' -or $_.State -eq 'enabled')
            }
            'BlockLegacyAuth' = $ca | Where-Object { 
                ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or 
                 $_.Conditions.ClientAppTypes -contains 'other') -and 
                $_.GrantControls.BuiltInControls -contains 'block' -and
                $_.State -eq 'enabled'
            }
            'RequireCompliantDevice' = $ca | Where-Object { 
                ($_.GrantControls.BuiltInControls -contains 'compliantDevice' -or 
                 $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice') -and
                $_.State -eq 'enabled'
            }
        }

        foreach ($baseline in $caBaselines.GetEnumerator()) {
            if (-not $baseline.Value -or $baseline.Value.Count -eq 0) {
                $baselineName = switch ($baseline.Key) {
                    'RequireMFA' { 'Require MFA for all users' }
                    'BlockLegacyAuth' { 'Block legacy authentication' }
                    'RequireCompliantDevice' { 'Require compliant/managed devices' }
                    default { $baseline.Key }
                }
                $findings.Add([pscustomobject]@{
                    Area='Zero Trust Baseline'; 
                    Finding="Missing CA policy: $baselineName"; 
                    Severity='High'; 
                    Evidence='entra-conditionalaccess'
                })
            }
        }
        
        # Track CA baseline compliance
        $kpis.CABaselinesMFAEnabled = ($caBaselines['RequireMFA'] | Measure-Object).Count -gt 0
        $kpis.CABaselinesLegacyAuthBlocked = ($caBaselines['BlockLegacyAuth'] | Measure-Object).Count -gt 0
        $kpis.CABaselinesDeviceComplianceRequired = ($caBaselines['RequireCompliantDevice'] | Measure-Object).Count -gt 0
    }

    # 16) SERVICE PRINCIPAL HARDENING: Credential expiration & lifetime issues
    if ($spCreds.Count -gt 0) {
        # Secrets expiring soon (<30 days)
        $expiringSoon = $spCreds | Where-Object { 
            $null -ne $_.DaysToExpiry -and $_.DaysToExpiry -ne '' -and [int]$_.DaysToExpiry -lt 30 -and [int]$_.DaysToExpiry -ge 0
        }
        if ($expiringSoon.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Service Principal Security'; 
                Finding="$($expiringSoon.Count) service principal credentials expiring in <30 days"; 
                Severity='High'; 
                Evidence='entra-sp-credentials'
            })
        }

        # Long-lived secrets (>1 year lifetime)
        $longLived = $spCreds | Where-Object { 
            $null -ne $_.LifetimeDays -and $_.LifetimeDays -ne '' -and [int]$_.LifetimeDays -gt 365
        }
        if ($longLived.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Service Principal Security'; 
                Finding="$($longLived.Count) service principals with credentials >1 year lifetime"; 
                Severity='Medium'; 
                Evidence='entra-sp-credentials'
            })
        }

        # Already expired credentials
        $expired = $spCreds | Where-Object { 
            $null -ne $_.DaysToExpiry -and $_.DaysToExpiry -ne '' -and [int]$_.DaysToExpiry -lt 0
        }
        if ($expired.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Service Principal Security'; 
                Finding="$($expired.Count) service principals have EXPIRED credentials (cleanup needed)"; 
                Severity='Medium'; 
                Evidence='entra-sp-credentials'
            })
        }

        # KPIs
        $kpis.SPCredentialsTotal = $spCreds.Count
        $kpis.SPCredentialsExpiringSoon = $expiringSoon.Count
        $kpis.SPCredentialsLongLived = $longLived.Count
        $kpis.SPCredentialsExpired = $expired.Count
    }

    # === PHASE 2 ENHANCEMENTS ===

    # 17) SERVICE PRINCIPAL HIGH-PRIVILEGE PERMISSIONS: Detect risky Graph/API scopes
    if ($appRoles -and $appRoles.Count -gt 0) {
        $dangerousPerms = @(
            'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'RoleManagement.ReadWrite.Directory',
            'User.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All',
            'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Group.ReadWrite.All'
        )
        
        $riskyPerms = $appRoles | Where-Object { 
            $dangerousPerms -contains $_.PermissionName 
        }
        
        if ($riskyPerms.Count -gt 0) {
            # Group by SP to get unique count
            $riskySpNames = $riskyPerms | Select-Object -ExpandProperty ServicePrincipal -Unique
            $findings.Add([pscustomobject]@{
                Area='Service Principal Permissions'; 
                Finding="$($riskySpNames.Count) service principals have HIGH-RISK Graph permissions (Directory.ReadWrite.All, etc)"; 
                Severity='High'; 
                Evidence='entra-approle-assignments'
            })
            
            # Detailed findings for critical permissions
            $criticalPerms = $riskyPerms | Where-Object { 
                $_.PermissionName -in @('Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory','Application.ReadWrite.All')
            }
            foreach ($perm in $criticalPerms) {
                $findings.Add([pscustomobject]@{
                    Area='Service Principal Permissions'; 
                    Finding="$($perm.ServicePrincipal) has CRITICAL permission: $($perm.PermissionName)"; 
                    Severity='High'; 
                    Evidence='entra-approle-assignments'
                })
            }
        }
        
        $kpis.SPHighRiskPermissions = $riskyPerms.Count
    }

    # 18) DEVICE POSTURE: Unmanaged devices & compliance issues
    if ($aadDevices.Count -gt 0 -or $intuneDevs.Count -gt 0) {
        # Non-compliant devices
        $nonCompliantAAD = $aadDevices | Where-Object { $_.IsCompliant -eq 'False' }
        if ($nonCompliantAAD.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Device Compliance'; 
                Finding="$($nonCompliantAAD.Count) Azure AD devices are NON-COMPLIANT"; 
                Severity='Medium'; 
                Evidence='entra-aad-devices'
            })
        }

        $nonCompliantIntune = $intuneDevs | Where-Object { $_.ComplianceState -ne 'compliant' -and $_.ComplianceState -ne '' }
        if ($nonCompliantIntune.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Device Compliance'; 
                Finding="$($nonCompliantIntune.Count) Intune devices are NON-COMPLIANT"; 
                Severity='Medium'; 
                Evidence='entra-intune-devices'
            })
        }

        # Unmanaged devices accessing corporate resources (if sign-in data available)
        if ($signins.Count -gt 0) {
            # Parse sign-in device info - this is a simplified check
            $unmanagedSignIns = $signins | Where-Object { 
                $_.Status -notmatch 'Failure' -and 
                ($_.AppDisplayName -match 'Office|SharePoint|Exchange|Teams|Azure')
            } | Select-Object -First 100  # Limit for performance
            
            # Note: Actual unmanaged check requires cross-ref with device inventory
            # This is a placeholder - real impl needs DeviceId correlation
            if ($unmanagedSignIns.Count -gt 0) {
                $findings.Add([pscustomobject]@{
                    Area='Device Posture'; 
                    Finding="Sign-ins to critical apps detected - review device compliance status"; 
                    Severity='Low'; 
                    Evidence='entra-signins,entra-aad-devices'
                })
            }
        }

        # KPIs
        $kpis.DevicesAAD = $aadDevices.Count
        $kpis.DevicesIntune = $intuneDevs.Count
        $kpis.DevicesNonCompliantAAD = $nonCompliantAAD.Count
        $kpis.DevicesNonCompliantIntune = $nonCompliantIntune.Count
    }

    # === PHASE 3 / TIER 1 ENHANCEMENTS (ZERO TRUST HARDENING) ===

    # 19) AD PASSWORD POLICY VALIDATION: Default domain policy security baseline
    if ($adPwdPolicy) {
        # Minimum password length check
        if ([int]$adPwdPolicy.MinPasswordLength -lt 12) {
            $findings.Add([pscustomobject]@{
                Area='Password Policy'; 
                Finding="Weak default password policy: MinLength=$($adPwdPolicy.MinPasswordLength) (recommend ≥12 chars)"; 
                Severity='Medium'; 
                Evidence='ad-default-pwd-policy'
            })
        }

        # Complexity requirement check
        if ($adPwdPolicy.ComplexityEnabled -ne 'True') {
            $findings.Add([pscustomobject]@{
                Area='Password Policy'; 
                Finding="Password complexity NOT enforced in default domain policy"; 
                Severity='High'; 
                Evidence='ad-default-pwd-policy'
            })
        }

        # Lockout threshold check (brute-force protection)
        if ([int]$adPwdPolicy.LockoutThreshold -eq 0) {
            $findings.Add([pscustomobject]@{
                Area='Password Policy'; 
                Finding="Account lockout DISABLED (infinite password attempts allowed)"; 
                Severity='High'; 
                Evidence='ad-default-pwd-policy'
            })
        } elseif ([int]$adPwdPolicy.LockoutThreshold -gt 10) {
            $findings.Add([pscustomobject]@{
                Area='Password Policy'; 
                Finding="Account lockout threshold high ($($adPwdPolicy.LockoutThreshold) attempts) - recommend ≤10"; 
                Severity='Low'; 
                Evidence='ad-default-pwd-policy'
            })
        }

        # Password age check
        if ([int]$adPwdPolicy.MaxPasswordAge.Days -gt 90) {
            $findings.Add([pscustomobject]@{
                Area='Password Policy'; 
                Finding="Password max age is $($adPwdPolicy.MaxPasswordAge.Days) days (recommend ≤90 for privileged accounts)"; 
                Severity='Low'; 
                Evidence='ad-default-pwd-policy'
            })
        }

        # KPIs
        $kpis.PasswordMinLength = $adPwdPolicy.MinPasswordLength
        $kpis.PasswordComplexityEnabled = $adPwdPolicy.ComplexityEnabled
        $kpis.PasswordLockoutThreshold = $adPwdPolicy.LockoutThreshold
    }

    # 20) FINE-GRAINED PASSWORD POLICIES: Role-based password enforcement
    if ($adFgpp.Count -eq 0 -and $adUsers.Count -gt 100) {
        $findings.Add([pscustomobject]@{
            Area='Password Policy'; 
            Finding='No Fine-Grained Password Policies (FGPP) defined - consider role-based policies for admins'; 
            Severity='Low'; 
            Evidence='ad-fgpp'
        })
    } elseif ($adFgpp.Count -gt 0) {
        $kpis.FGPPCount = $adFgpp.Count
    }

    # 21) TRUST ANALYSIS: External trust attack surface
    if ($adTrusts.Count -gt 0) {
        # Flag non-hierarchical trusts (external/forest trusts = lateral movement risk)
        $externalTrusts = $adTrusts | Where-Object { 
            $_.TrustType -ne 'ParentChild' -and $_.TrustType -ne 'TreeRoot' 
        }
        
        if ($externalTrusts.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Domain Trusts'; 
                Finding="$($externalTrusts.Count) external/forest trusts present - review for least privilege & SID filtering"; 
                Severity='Medium'; 
                Evidence='ad-trusts'
            })
        }

        # Flag bidirectional trusts (higher risk)
        $bidirectionalTrusts = $adTrusts | Where-Object { $_.Direction -eq 'Bidirectional' }
        if ($bidirectionalTrusts.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Area='Domain Trusts'; 
                Finding="$($bidirectionalTrusts.Count) bidirectional trusts (higher attack surface than one-way)"; 
                Severity='Low'; 
                Evidence='ad-trusts'
            })
        }

        # KPIs
        $kpis.DomainTrustsTotal = $adTrusts.Count
        $kpis.DomainTrustsExternal = $externalTrusts.Count
        $kpis.DomainTrustsBidirectional = $bidirectionalTrusts.Count
    }

    # --- RBAC Candidate Roles (cluster users by group membership) - ENHANCED WITH JACCARD SIMILARITY ---
    
    # Helper function: Calculate Jaccard similarity between two sets
    function Get-JaccardSimilarity {
        param([string[]]$set1, [string[]]$set2)
        if ($set1.Count -eq 0 -and $set2.Count -eq 0) { return 1.0 }
        if ($set1.Count -eq 0 -or $set2.Count -eq 0) { return 0.0 }
        
        $intersection = ($set1 | Where-Object { $set2 -contains $_ }).Count
        $union = ($set1 + $set2 | Select-Object -Unique).Count
        
        if ($union -eq 0) { return 0.0 }
        return [math]::Round($intersection / $union, 2)
    }
    
    $userMembership = @()
    foreach ($u in $adUsers) {
        $groups = @()
        if ($u.MemberOf) {
            $groups = ($u.MemberOf -split '[;`n`r]') | Where-Object { $_ -and $_ -notmatch '^\s*$' }
        }
        $userMembership += [pscustomobject]@{ User=$u.SamAccountName; Groups=[string[]]$groups }
    }

    # Initial clustering by exact group membership match
    $clusters = @{}
    foreach ($m in $userMembership) {
        $sig = ($m.Groups | Sort-Object) -join '|'
        if (-not $clusters.ContainsKey($sig)) { $clusters[$sig] = New-Object System.Collections.Generic.List[object] }
        $clusters[$sig].Add($m.User)
    }

    # Phase 2: Merge similar clusters using Jaccard similarity (threshold: 0.8)
    $similarityThreshold = 0.8
    $refinedClusters = @{}
    
    foreach ($cluster in $clusters.GetEnumerator() | Where-Object { $_.Value.Count -ge 2 }) {
        $sig1 = ($cluster.Key -split '\|')
        $merged = $false
        
        foreach ($existing in $refinedClusters.GetEnumerator()) {
            $sig2 = ($existing.Key -split '\|')
            $similarity = Get-JaccardSimilarity $sig1 $sig2
            
            if ($similarity -ge $similarityThreshold) {
                # Merge into existing cluster
                foreach ($user in $cluster.Value) {
                    $refinedClusters[$existing.Key].Add($user)
                }
                $merged = $true
                break
            }
        }
        
        if (-not $merged) {
            # Create new refined cluster
            $refinedClusters[$cluster.Key] = $cluster.Value
        }
    }

    # Generate RBAC role candidates from refined clusters
    $rbacCandidates = @()
    $idx = 1
    foreach ($kv in $refinedClusters.GetEnumerator() | Where-Object { $_.Value.Count -ge 3 }) {
        $roleName = "RBAC_Role_$idx"
        $rbacCandidates += [pscustomobject]@{
            RoleName = $roleName
            UserCount = $kv.Value.Count
            SuggestedMembers = ($kv.Value -join ', ')
            SourceGroups = ($kv.Key)
            ClusteringMethod = "Jaccard (threshold: $similarityThreshold)"
        }
        $idx++
    }

    # --- GPO Modernization hints ---
    $gpoXmls = @()
    foreach ($item in $gpoLinks) {
        try {
            $doc = [xml]$item.XML
            $links = @($doc.GPO.LinksTo.LinkTo) | Where-Object { $_ }
            $gpoXmls += [pscustomobject]@{
                GPO = $item.GPO
                Id  = $item.Id
                LinkCount = ($links | Measure-Object).Count
            }
        } catch {}
    }
    $unlink = $gpoXmls | Where-Object { $_.LinkCount -eq 0 }
    $kpis.GPOs = $gpos.Count
    $kpis.GPOsUnlinked = $unlink.Count
    if ($unlink.Count -gt 0) {
        $findings.Add([pscustomobject]@{
            Area='GPOs'; Finding="$($unlink.Count) GPOs have no links (candidates to retire or migrate to Intune)"; Severity='Low'; Evidence='ad-gpo-links'
        })
    }

    # --- OU Delegation anomalies ---
    $aceIssues = 0
    foreach ($ou in $ouAcls) {
        foreach ($ace in $ou.ACEs) {
            $id = [string]$ace.IdentityReference
            $rights = [string]$ace.ActiveDirectoryRights
            if ($id -and $id -notmatch '^(NT AUTHORITY|BUILTIN|Domain Admins|Enterprise Admins|SYSTEM|Administrators)' -and
                $rights -match 'Write|Create|Delete|GenericAll|GenericWrite|All') {
                $aceIssues++
            }
        }
    }
    if ($aceIssues -gt 0) {
        $findings.Add([pscustomobject]@{
            Area='OU Delegation'; Finding="$aceIssues potentially risky OU ACEs for non-admin principals"; Severity='Medium'; Evidence='ad-ou-acls'
        })
    }

    # --- Persist analysis outputs ---
    $stamp = if ($NowTag) { $NowTag } else { (Get-Date).ToString('yyyyMMdd-HHmmss') }

    $riskCsv  = Join-Path $OutputFolder "risk-findings-$stamp.csv"
    $rbacCsv  = Join-Path $OutputFolder "rbac-candidates-$stamp.csv"
    $gpoCsv   = Join-Path $OutputFolder "gpo-modernization-$stamp.csv"
    $kpiJson  = Join-Path $OutputFolder "kpis-$stamp.json"

    $findings | Export-Csv $riskCsv -NoTypeInformation -Force
    $rbacCandidates | Export-Csv $rbacCsv -NoTypeInformation -Force
    $gpoXmls | Export-Csv $gpoCsv -NoTypeInformation -Force
    ($kpis | ConvertTo-Json) | Out-File $kpiJson -Force

    # --- Build HTML fragments ---
    $kpiTable = ($kpis.GetEnumerator() | Sort-Object Name | ForEach-Object{
        [pscustomobject]@{ KPI = $_.Name; Value = $_.Value }
    }) | ConvertTo-Html -Fragment

    $riskHtml = if ($findings.Count -gt 0) {
        $findings | Sort-Object @{e={switch($_.Severity){'High'{1}'Medium'{2}'Low'{3}default{4}}}} | ConvertTo-Html -Fragment
    } else { '<p>No heuristic risks found.</p>' }

    $rbacHtml = if ($rbacCandidates.Count -gt 0) {
        $rbacCandidates | Select-Object RoleName,UserCount,SourceGroups | ConvertTo-Html -Fragment
    } else { '<p>No RBAC candidates (min cluster size not met).</p>' }

    $gpoHtml = if ($gpoXmls.Count -gt 0) {
        $gpoXmls | Select-Object GPO,Id,LinkCount | ConvertTo-Html -Fragment
    } else { '<p>No GPO data.</p>' }

    # Generate Playbook HTML - slim table with Remediation → Owner → Due Date
    $playbookHtml = if ($findings.Count -gt 0) {
        $playbookData = $findings | Sort-Object @{e={switch($_.Severity){'High'{1}'Medium'{2}'Low'{3}default{4}}}} | Select-Object @{n='#';e={$findings.IndexOf($_)+1}},Area,Finding,Severity,@{n='Remediation';e={$_.RemediationSteps}},@{n='Owner';e={'[Assign]'}},@{n='Due Date';e={'[Set Date]'}},@{n='Status';e={$_.Status}}
        
        # Create custom HTML table for better control
        $tableRows = ""
        $rowNum = 1
        foreach ($item in ($findings | Sort-Object @{e={switch($_.Severity){'High'{1}'Medium'{2}'Low'{3}default{4}}}})) {
            $sevClass = switch($item.Severity) {
                'High' { 'class="high"' }
                'Medium' { 'class="medium"' }
                'Low' { 'class="low"' }
                default { '' }
            }
            # Truncate remediation steps for slim view
            $shortRemediation = if ($item.RemediationSteps.Length -gt 100) { 
                $item.RemediationSteps.Substring(0,100) + "..." 
            } else { 
                $item.RemediationSteps 
            }
            
            $tableRows += @"
        <tr>
            <td>$rowNum</td>
            <td>$($item.Area)</td>
            <td>$($item.Finding)</td>
            <td $sevClass>$($item.Severity)</td>
            <td style='font-size:0.9em;'>$shortRemediation</td>
            <td contenteditable='true' style='background:#ffffcc;cursor:text;'>-</td>
            <td contenteditable='true' style='background:#ffffcc;cursor:text;'>-</td>
            <td><span class='status-badge' style='background:#ffa500;color:white;padding:3px 8px;border-radius:3px;font-size:0.85em;'>$($item.Status)</span></td>
        </tr>
"@
            $rowNum++
        }
        
        @"
<table class='playbook-table'>
    <thead>
        <tr>
            <th>#</th>
            <th>Area</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>Remediation Steps</th>
            <th>Owner</th>
            <th>Due Date</th>
            <th>Status</th>
        </tr>
    </thead>
    <tbody>
$tableRows
    </tbody>
</table>
<p style='font-size:0.9em;color:#666;margin-top:10px;'><em>💡 Tip: Owner and Due Date cells are editable. Click to fill in assignments. See full remediation details in the Risk Findings CSV.</em></p>
"@
    } else { 
        '<p>No remediation items required - environment looks good!</p>' 
    }

    return [pscustomobject]@{
        RiskCsv = $riskCsv
        RbacCsv = $rbacCsv
        GpoCsv  = $gpoCsv
        KpiJson = $kpiJson
        KpiHtml = $kpiTable
        RiskHtml = $riskHtml
        RbacHtml = $rbacHtml
        GpoHtml = $gpoHtml
        PlaybookHtml = $playbookHtml
        Findings = $findings
        KPIs = $kpis
    }
}

# Run collections
$collectionErrors = @()

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Starting Black-Box Security Assessment" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    Collect-ADInventory
} catch {
    Write-Warning "AD collection failed: $_"
    $collectionErrors += "AD collection: $_"
}

if ($IncludeEntra) {
    try {
        Collect-EntraInventory
    } catch {
        Write-Warning "Entra collection failed: $_"
        $collectionErrors += "Entra collection: $_"
    }
} else {
    Write-Host "`nSkipping Entra collection (use -IncludeEntra to enable)" -ForegroundColor Yellow
}

# === CALL THE COMPREHENSIVE ANALYSIS ===
$analysis = Analyze-Inventory -OutputFolder $OutputFolder -NowTag $now

# --- Build enhanced HTML summary with risk analysis ---
Write-Host "Building comprehensive HTML summary..." -ForegroundColor Cyan

# Collect file summary
$filesSummary = @()
Get-ChildItem -Path $OutputFolder -Filter "*$now.csv" | ForEach-Object {
    $count = (Import-Csv $_.FullName | Measure-Object).Count
    $filesSummary += [PSCustomObject]@{ File = $_.Name; Count = $count }
}
$filesHtml = $filesSummary | ConvertTo-Html -Fragment

# Build HTML with enhanced styling
$htmlHead = @"
<style>
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
    h2 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 5px; margin-top: 30px; }
    h3 { color: #0078d4; margin-top: 20px; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    th { background: #0078d4; color: white; padding: 12px; text-align: left; font-weight: 600; }
    td { padding: 10px; border-bottom: 1px solid #ddd; }
    tr:hover { background: #f9f9f9; }
    tr:nth-child(even) { background: #fafafa; }
    .high { color: #d13438; font-weight: bold; }
    .medium { color: #ff8c00; font-weight: bold; }
    .low { color: #107c10; }
    .meta { background: linear-gradient(135deg, #e8f4fc 0%, #d4e9f7 100%); padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 5px solid #0078d4; }
    .kpi-box { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 10px 0; }
    .info-box { background: #fff4e6; padding: 15px; border-left: 4px solid #ff8c00; margin: 15px 0; border-radius: 4px; }
    .playbook-table { font-size: 0.95em; }
    .playbook-table th { font-size: 0.9em; }
    .playbook-table td[contenteditable="true"] { border: 1px dashed #ccc; min-width: 120px; }
    .playbook-table td[contenteditable="true"]:focus { outline: 2px solid #0078d4; background: #fffde7; }
    .status-badge { display: inline-block; }
</style>
"@

$htmlBody = @"
<h1>🔍 Black-Box AD & Entra ID Security Assessment</h1>
<div class="meta">
    <strong>Collection Time:</strong> $($meta.CollectedAt)<br>
    <strong>Host:</strong> $($meta.Host)<br>
    <strong>User:</strong> $($meta.User)<br>
    <strong>Entra Included:</strong> $($meta.IncludeEntra)
</div>

<h2>📊 Key Performance Indicators</h2>
<div class="kpi-box">
$($analysis.KpiHtml)
</div>

<h2>📁 Data Files Collected</h2>
$filesHtml

<h2>⚠️ Risk Findings & Remediation Playbook</h2>
<p><strong>Automated analysis identified the following security concerns, prioritized by severity:</strong></p>
$($analysis.RiskHtml)

<h2>📋 Remediation Playbook</h2>
<div class="info-box">
<strong>Action Plan:</strong> Use this playbook to track remediation progress. Assign owners and due dates for each finding below.
</div>
$($analysis.PlaybookHtml)

<h2>🎯 RBAC Seed Roles</h2>
<div class="info-box">
<strong>Purpose:</strong> These clusters group users by identical AD group membership patterns. Use them as seed roles for your RBAC model in Entra ID, then refine based on business requirements.
</div>
$($analysis.RbacHtml)

<h2>🔄 GPO Modernization Plan</h2>
<div class="info-box">
<strong>Migration Strategy:</strong> GPOs with zero links are safe to retire or can be translated to Intune/MDM policies if functionality is still needed. Focus security GPOs for Intune Security Baseline migration.
</div>
$($analysis.GpoHtml)

<h2>📈 Next Steps</h2>
<ol>
    <li><strong>Review High-Severity Findings:</strong> Address krbtgt password age, delegation issues, and privileged access immediately</li>
    <li><strong>Zero Trust Roadmap:</strong> Implement Conditional Access policies, enforce MFA for all users (especially admins)</li>
    <li><strong>RBAC Implementation:</strong> Use the seed roles in <code>$($analysis.RbacCsv)</code> to design your Entra RBAC model</li>
    <li><strong>GPO Migration:</strong> Review <code>$($analysis.GpoCsv)</code> and plan Intune baseline migration</li>
    <li><strong>Identity Hygiene:</strong> Cleanup stale accounts, review service principals, and audit OAuth permissions</li>
</ol>

<h2>📂 Analysis Artifacts</h2>
<ul>
    <li><strong>Risk Findings:</strong> $($analysis.RiskCsv)</li>
    <li><strong>RBAC Candidates:</strong> $($analysis.RbacCsv)</li>
    <li><strong>GPO Modernization:</strong> $($analysis.GpoCsv)</li>
    <li><strong>KPIs (JSON):</strong> $($analysis.KpiJson)</li>
</ul>

<p style="margin-top: 40px; color: #666; font-size: 0.9em; border-top: 1px solid #ddd; padding-top: 20px;">
<em>Generated by Black-Box Security Assessment Script | All data collected in read-only mode</em>
</p>
"@

$html = ConvertTo-Html -Head $htmlHead -Body $htmlBody -Title "BlackBox Security Assessment $now"
$htmlPath = Join-Path $OutputFolder "summary-$now.html"
$html | Out-File $htmlPath -Force

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Assessment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Output Location: $OutputFolder" -ForegroundColor Cyan
Write-Host "HTML Summary: $htmlPath" -ForegroundColor Cyan

if ($collectionErrors.Count -gt 0) {
    Write-Host "`nErrors encountered during collection:" -ForegroundColor Yellow
    $collectionErrors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}

Write-Host "`nAnalysis Artifacts Generated:" -ForegroundColor White
Write-Host "  - Risk Findings:      $($analysis.RiskCsv)" -ForegroundColor Gray
Write-Host "  - RBAC Candidates:    $($analysis.RbacCsv)" -ForegroundColor Gray
Write-Host "  - GPO Modernization:  $($analysis.GpoCsv)" -ForegroundColor Gray
Write-Host "  - KPIs (JSON):        $($analysis.KpiJson)" -ForegroundColor Gray

$highFindings = ($analysis.Findings | Where-Object { $_.Severity -eq 'High' }).Count
$medFindings = ($analysis.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowFindings = ($analysis.Findings | Where-Object { $_.Severity -eq 'Low' }).Count

Write-Host "`nRisk Summary:" -ForegroundColor White
Write-Host "  - High Severity:    $highFindings findings" -ForegroundColor Red
Write-Host "  - Medium Severity:  $medFindings findings" -ForegroundColor Yellow
Write-Host "  - Low Severity:     $lowFindings findings" -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Open the HTML summary to review all findings and recommendations" -ForegroundColor Gray
Write-Host "  2. Address HIGH severity findings immediately (delegation, krbtgt, etc)" -ForegroundColor Gray
Write-Host "  3. Review RBAC candidates CSV to design your Entra role model" -ForegroundColor Gray
Write-Host "  4. Plan GPO to Intune migration using the modernization CSV" -ForegroundColor Gray
Write-Host "  5. Implement Zero Trust controls (CA policies, MFA enforcement)" -ForegroundColor Gray
