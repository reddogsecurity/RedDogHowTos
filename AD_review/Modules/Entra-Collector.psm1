# Entra-Collector.psm1
# Entra ID (Azure AD) data collection module

Import-Module (Join-Path $PSScriptRoot "Helpers.psm1") -Force

function Invoke-EntraCollection {
    <#
    .SYNOPSIS
    Collects Entra ID (Azure AD) inventory data via Microsoft Graph
    
    .PARAMETER OutputFolder
    Path where collected data will be stored
    
    .PARAMETER Timestamp
    Timestamp string to append to output files
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory)]
        [string]$Timestamp
    )
    
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

    # Connect to Graph
    Write-Host "Interactive sign-in to Graph (consent for required permissions may be required)..." -ForegroundColor Gray
    Connect-MgGraph -Scopes "Directory.Read.All","Application.Read.All","Policy.Read.All","AuditLog.Read.All","UserAuthenticationMethod.Read.All","DeviceManagementManagedDevices.Read.All" -ErrorAction Stop

    # Basic tenant info
    $tenant = Get-MgOrganization | Select-Object Id,DisplayName
    $tenant | ConvertTo-Json | Out-File (Join-Path $OutputFolder "entra-tenant-$Timestamp.json")

    # Users
    Write-Host "Enumerating Entra users..." -ForegroundColor Gray
    $users = Get-MgUser -All -Property "displayName,mail,userPrincipalName,accountEnabled,createdDateTime,signInActivity" | 
        Select-Object Id,DisplayName,Mail,UserPrincipalName,AccountEnabled,CreatedDateTime,@{n='LastSignIn';e={$_.SignInActivity.LastSignInDateTime}}
    Write-OutputFiles -Name "entra-users" -Object $users -OutputFolder $OutputFolder -Timestamp $Timestamp

    # Groups
    Write-Host "Enumerating Entra groups..." -ForegroundColor Gray
    $groups = Get-MgGroup -All | Select-Object Id,DisplayName,MailEnabled,SecurityEnabled,GroupTypes,CreatedDateTime
    Write-OutputFiles -Name "entra-groups" -Object $groups -OutputFolder $OutputFolder -Timestamp $Timestamp

    # Admin role assignments (Privileged roles)
    Write-Host "Enumerating role assignments (directory roles)..." -ForegroundColor Gray
    $roles = Get-MgDirectoryRole -All | Select-Object Id,DisplayName,RoleTemplateId
    $roleAssignments = foreach ($r in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All | 
            Select-Object Id,@{n='DisplayName';e={$_.AdditionalProperties.displayName}},@{n='UserPrincipalName';e={$_.AdditionalProperties.userPrincipalName}},@{n='Type';e={$_.AdditionalProperties.'@odata.type'}}
        [PSCustomObject]@{ Role = $r.DisplayName; Template = $r.RoleTemplateId; MemberCount = $members.count; Members = $members }
    }
    $roleAssignments | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "entra-role-assignments-$Timestamp.json")

    # Service principals & applications
    Write-Host "Enumerating service principals & enterprise apps..." -ForegroundColor Gray
    $sps = Get-MgServicePrincipal -All | Select-Object Id,DisplayName,AppId,Tags,AppOwnerTenantId
    Write-OutputFiles -Name "entra-serviceprincipals" -Object $sps -OutputFolder $OutputFolder -Timestamp $Timestamp

    $apps = Get-MgApplication -All | Select-Object Id,DisplayName,AppId,SignInAudience,CreatedDateTime
    Write-OutputFiles -Name "entra-apps" -Object $apps -OutputFolder $OutputFolder -Timestamp $Timestamp
    
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
        Write-OutputFiles -Name "entra-sp-credentials" -Object $spCredentials -OutputFolder $OutputFolder -Timestamp $Timestamp
    }
    
    # OAuth consented permissions
    Write-Host "Enumerating OAuth2 permission grants..." -ForegroundColor Gray
    try {
        $oauth2Grants = Get-MgOauth2PermissionGrant -All | Select-Object Id,ClientId,ConsentType,PrincipalId,ResourceId,Scope
        $oauth2Grants | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "entra-oauth2-grants-$Timestamp.json")
        
        # App role assignments (application permissions)
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
        $appRoleAssignments | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "entra-approle-assignments-$Timestamp.json")
    } catch {
        Write-Warning "OAuth permission enumeration failed: $_"
    }

    # Conditional Access Policies
    Write-Host "Enumerating Conditional Access policies..." -ForegroundColor Gray
    try {
        if (Get-Command Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue) {
            $ca = Get-MgIdentityConditionalAccessPolicy -All
            $ca | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputFolder "entra-conditionalaccess-$Timestamp.json")
        } else {
            Write-Warning "Conditional Access cmdlet not found. Ensure Microsoft.Graph.Identity.SignIns module v2.0+ is installed."
        }
    } catch {
        Write-Warning "Conditional Access policies require 'Policy.Read.All' permission: $_"
    }

    # Sign-in logs
    try {
        Write-Host "Attempting to collect recent sign-ins (if permissions allowed)..." -ForegroundColor Gray
        $signins = Get-MgAuditLogSignIn -All -Top 500 | Select-Object Id,UserDisplayName,UserPrincipalName,AppDisplayName,ClientAppUsed,IpAddress,CreatedDateTime,Status
        $signins | Export-Csv (Join-Path $OutputFolder "entra-signins-$Timestamp.csv") -NoTypeInformation -Force
    } catch {
        Write-Warning "Sign-in retrieval likely blocked by permissions: $_"
    }

    # MFA / Authentication Methods
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
        $authMethods | Export-Csv (Join-Path $OutputFolder "entra-authmethods-$Timestamp.csv") -NoTypeInformation -Force
    } catch {
        Write-Warning "Authentication methods collection requires 'UserAuthenticationMethod.Read.All': $_"
    }

    # Device Inventory
    Write-Host "Collecting device inventory (Intune + Azure AD devices)..." -ForegroundColor Gray
    try {
        # Try to get Intune managed devices
        if (Get-Command Get-MgDeviceManagementManagedDevice -ErrorAction SilentlyContinue) {
            $intuneDevices = Get-MgDeviceManagementManagedDevice -All | 
                Select-Object DeviceName,Id,ManagedDeviceId,OperatingSystem,OsVersion,ComplianceState,ManagementAgent,EnrolledDateTime,LastSyncDateTime,AzureAdDeviceId,UserPrincipalName
            if ($intuneDevices) {
                Write-OutputFiles -Name "entra-intune-devices" -Object $intuneDevices -OutputFolder $OutputFolder -Timestamp $Timestamp
                Write-Host "  Collected $($intuneDevices.Count) Intune managed devices" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  Intune device collection skipped (Microsoft.Graph.DeviceManagement module not available)" -ForegroundColor DarkGray
        }

        # Azure AD registered/joined devices
        if (Get-Command Get-MgDevice -ErrorAction SilentlyContinue) {
            $aadDevices = Get-MgDevice -All | 
                Select-Object DisplayName,Id,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,ApproximateLastSignInDateTime
            if ($aadDevices) {
                Write-OutputFiles -Name "entra-aad-devices" -Object $aadDevices -OutputFolder $OutputFolder -Timestamp $Timestamp
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

Export-ModuleMember -Function Invoke-EntraCollection

