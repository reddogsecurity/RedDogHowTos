<#
.SYNOPSIS
    Lists and compares computers/servers from Active Directory and Entra ID (Azure AD).

.DESCRIPTION
    This script collects and compares computer/server accounts between on-premises Active Directory 
    and Entra ID (Azure AD) to identify:
    - Computers in AD but not in Entra (not hybrid joined)
    - Devices in Entra but not in AD (cloud-only devices)
    - Computers in both systems (hybrid joined)
    - Server vs workstation classification
    - Last activity and compliance status

.PARAMETER OutputFolder
    Path where the report will be saved. Defaults to current directory.

.PARAMETER IncludeIntuneDevices
    Include Intune managed devices in the Entra ID collection.

.PARAMETER FilterServersOnly
    Filter to show only servers (based on OperatingSystem or name patterns).

.PARAMETER CompareDevices
    Attempt to match and compare devices between AD and Entra ID.

.PARAMETER DaysActive
    Number of days to consider a computer "Active". Defaults to 30 days.

.PARAMETER DaysInactive
    Number of days to consider a computer "Inactive". Defaults to 90 days.

.PARAMETER DaysStale
    Number of days to consider a computer "Stale". Defaults to 180 days.

.EXAMPLE
    .\Get-ADandEntraComputers.ps1
    List all computers from both AD and Entra ID
    
.EXAMPLE
    .\Get-ADandEntraComputers.ps1 -FilterServersOnly -IncludeIntuneDevices
    List only servers from both systems, including Intune devices
    
.EXAMPLE
    .\Get-ADandEntraComputers.ps1 -CompareDevices -OutputFolder "C:\Reports"
    Compare and match devices between AD and Entra ID

.NOTES
    Requires: Active Directory PowerShell module
    Requires: Microsoft.Graph modules (Authentication, Devices, DeviceManagement)
    Permissions: 
      - AD: Domain user with read access
      - Entra: Device.Read.All, DeviceManagementManagedDevices.Read.All
#>

param(
    [string]$OutputFolder = ".",
    [switch]$IncludeIntuneDevices,
    [switch]$FilterServersOnly,
    [switch]$CompareDevices,
    [int]$DaysActive = 30,
    [int]$DaysInactive = 90,
    [int]$DaysStale = 180
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

# Check Graph modules
# We only hard-require the Authentication module; device cmdlets (Get-MgDevice, Get-MgDeviceManagementManagedDevice)
# will auto-load from the main Microsoft.Graph SDK if present.
$requiredModules = @('Microsoft.Graph.Authentication')
if ($IncludeIntuneDevices) {
    $requiredModules += 'Microsoft.Graph.DeviceManagement'
}

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Module $module not found. Install with: Install-Module $module -Scope CurrentUser"
        exit 1
    }
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

if ($IncludeIntuneDevices) {
    Import-Module Microsoft.Graph.DeviceManagement -ErrorAction Stop
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "AD and Entra ID Computer/Device Inventory" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get AD Domain info
$domain = Get-ADDomain
$domainDNS = $domain.DNSRoot
Write-Host "[*] AD Domain: $domainDNS" -ForegroundColor Yellow
Write-Host "[*] Activity Thresholds:" -ForegroundColor Yellow
Write-Host "    - Active: Last $DaysActive days" -ForegroundColor Gray
Write-Host "    - Inactive: $DaysActive-$DaysInactive days" -ForegroundColor Gray
Write-Host "    - Stale: $DaysInactive-$DaysStale days" -ForegroundColor Gray
Write-Host "    - Very Stale: $DaysStale+ days" -ForegroundColor Gray

# Connect to Microsoft Graph
Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Yellow
try {
    $scopes = @("Device.Read.All")
    if ($IncludeIntuneDevices) {
        $scopes += "DeviceManagementManagedDevices.Read.All"
    }
    Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
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

# Collect AD Computers
Write-Host "`n[*] Collecting Active Directory computers..." -ForegroundColor Yellow
$adComputers = Get-ADComputer -Filter * -Properties `
    Name, DNSHostName, OperatingSystem, OperatingSystemVersion, `
    IPv4Address, whenCreated, lastLogonTimestamp, Enabled, `
    TrustedForDelegation, TrustedToAuthForDelegation, MemberOf, `
    DistinguishedName, Description

Write-Host "    [OK] Found $($adComputers.Count) AD computers" -ForegroundColor Green

# Function to categorize by last usage
function Get-UsageCategory {
    param(
        $LastUsage,          # Intentionally untyped so $null is allowed
        [int]$DaysActive,
        [int]$DaysInactive,
        [int]$DaysStale
    )
    
    if (-not $LastUsage) {
        return "Never Used"
    }
    
    $daysSince = (New-TimeSpan -Start $LastUsage -End (Get-Date)).Days
    
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

# Classify AD computers as servers or workstations
$adComputerDetails = foreach ($computer in $adComputers) {
    $lastLogon = $null
    $daysSinceLogon = $null
    if ($computer.lastLogonTimestamp) {
        $lastLogon = [DateTime]::FromFileTime($computer.lastLogonTimestamp)
        $daysSinceLogon = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
    }
    
    # Determine usage category
    $usageCategory = Get-UsageCategory -LastUsage $lastLogon -DaysActive $DaysActive -DaysInactive $DaysInactive -DaysStale $DaysStale
    
    # Determine if server (Windows Server OS or name contains "SRV", "DC", etc.)
    $isServer = $false
    $computerType = "Workstation"
    if ($computer.OperatingSystem) {
        if ($computer.OperatingSystem -like "*Server*" -or 
            $computer.OperatingSystem -like "*Windows Server*") {
            $isServer = $true
            $computerType = "Server"
        }
    }
    if (-not $isServer) {
        $nameUpper = $computer.Name.ToUpper()
        if ($nameUpper -match "SRV|SERVER|DC|DOMAINCONTROLLER|SQL|EXCHANGE|SHAREPOINT") {
            $isServer = $true
            $computerType = "Server"
        }
    }
    
    # Calculate risk score based on usage and security settings
    $riskScore = 0
    $riskLevel = "Low"
    
    if (-not $computer.Enabled) { $riskScore += 2 }
    if ($usageCategory -eq "Very Stale") { $riskScore += 4 }
    elseif ($usageCategory -eq "Stale") { $riskScore += 2 }
    elseif ($usageCategory -eq "Never Used") { $riskScore += 3 }
    if ($computer.TrustedForDelegation -eq $true -and $computer.TrustedToAuthForDelegation -eq $true) { $riskScore += 5 }
    if ($isServer -and $usageCategory -eq "Very Stale") { $riskScore += 2 }
    
    if ($riskScore -ge 8) { $riskLevel = "Critical" }
    elseif ($riskScore -ge 5) { $riskLevel = "High" }
    elseif ($riskScore -ge 3) { $riskLevel = "Medium" }
    
    [PSCustomObject]@{
        Name = $computer.Name
        DNSHostName = $computer.DNSHostName
        OperatingSystem = $computer.OperatingSystem
        OperatingSystemVersion = $computer.OperatingSystemVersion
        IPv4Address = $computer.IPv4Address
        Enabled = $computer.Enabled
        WhenCreated = $computer.whenCreated
        LastLogon = $lastLogon
        LastUsed = $lastLogon  # Alias for clarity
        DaysSinceLogon = $daysSinceLogon
        DaysSinceLastUse = $daysSinceLogon  # Alias for clarity
        UsageCategory = $usageCategory
        ComputerType = $computerType
        IsServer = $isServer
        TrustedForDelegation = $computer.TrustedForDelegation
        TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
        HasUnconstrainedDelegation = ($computer.TrustedForDelegation -eq $true -and $computer.TrustedToAuthForDelegation -eq $true)
        MemberOfCount = if ($computer.MemberOf) { $computer.MemberOf.Count } else { 0 }
        DistinguishedName = $computer.DistinguishedName
        Description = $computer.Description
        RiskScore = $riskScore
        RiskLevel = $riskLevel
        Source = "Active Directory"
    }
}

# Filter servers if requested
if ($FilterServersOnly) {
    $adComputerDetails = $adComputerDetails | Where-Object { $_.IsServer -eq $true }
    Write-Host "    [FILTERED] Showing $($adComputerDetails.Count) servers only" -ForegroundColor Gray
}

# Collect Entra ID Devices (Azure AD registered/joined)
Write-Host "`n[*] Collecting Entra ID devices (Azure AD registered/joined)..." -ForegroundColor Yellow
try {
    $entraDevices = Get-MgDevice -All -Property `
        Id, DisplayName, DeviceId, OperatingSystem, OperatingSystemVersion, `
        TrustType, IsCompliant, IsManaged, ApproximateLastSignInDateTime, `
        RegistrationDateTime, AccountEnabled
    
    Write-Host "    [OK] Found $($entraDevices.Count) Entra ID devices" -ForegroundColor Green
}
catch {
    Write-Warning "Error collecting Entra ID devices: $_"
    $entraDevices = @()
}

# Process Entra devices
$entraDeviceDetails = foreach ($device in $entraDevices) {
    $isServer = $false
    $computerType = "Workstation"
    
    # Determine if server based on OS or name
    if ($device.OperatingSystem) {
        if ($device.OperatingSystem -like "*Server*" -or 
            $device.OperatingSystem -like "*Windows Server*") {
            $isServer = $true
            $computerType = "Server"
        }
    }
    if (-not $isServer -and $device.DisplayName) {
        $nameUpper = $device.DisplayName.ToUpper()
        if ($nameUpper -match "SRV|SERVER|DC|DOMAINCONTROLLER|SQL|EXCHANGE|SHAREPOINT") {
            $isServer = $true
            $computerType = "Server"
        }
    }
    
    $lastSignIn = $device.ApproximateLastSignInDateTime
    $daysSinceSignIn = $null
    if ($lastSignIn) {
        $daysSinceSignIn = (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days
    }
    
    # Determine usage category
    $usageCategory = Get-UsageCategory -LastUsage $lastSignIn -DaysActive $DaysActive -DaysInactive $DaysInactive -DaysStale $DaysStale
    
    # Calculate risk score
    $riskScore = 0
    $riskLevel = "Low"
    
    if (-not $device.AccountEnabled) { $riskScore += 2 }
    if ($usageCategory -eq "Very Stale") { $riskScore += 4 }
    elseif ($usageCategory -eq "Stale") { $riskScore += 2 }
    elseif ($usageCategory -eq "Never Used") { $riskScore += 3 }
    if ($isServer -and $usageCategory -eq "Very Stale") { $riskScore += 2 }
    if ($device.IsCompliant -eq $false) { $riskScore += 2 }
    
    if ($riskScore -ge 8) { $riskLevel = "Critical" }
    elseif ($riskScore -ge 5) { $riskLevel = "High" }
    elseif ($riskScore -ge 3) { $riskLevel = "Medium" }
    
    [PSCustomObject]@{
        Name = $device.DisplayName
        DeviceId = $device.DeviceId
        Id = $device.Id
        OperatingSystem = $device.OperatingSystem
        OperatingSystemVersion = $device.OperatingSystemVersion
        TrustType = $device.TrustType  # AzureADJoined, AzureADRegistered, HybridAzureADJoined
        IsCompliant = $device.IsCompliant
        IsManaged = $device.IsManaged
        AccountEnabled = $device.AccountEnabled
        RegistrationDateTime = $device.RegistrationDateTime
        LastSignIn = $lastSignIn
        LastUsed = $lastSignIn  # Alias for clarity
        DaysSinceSignIn = $daysSinceSignIn
        DaysSinceLastUse = $daysSinceSignIn  # Alias for clarity
        UsageCategory = $usageCategory
        ComputerType = $computerType
        IsServer = $isServer
        RiskScore = $riskScore
        RiskLevel = $riskLevel
        Source = "Entra ID"
    }
}

# Filter servers if requested
if ($FilterServersOnly) {
    $entraDeviceDetails = $entraDeviceDetails | Where-Object { $_.IsServer -eq $true }
    Write-Host "    [FILTERED] Showing $($entraDeviceDetails.Count) servers only" -ForegroundColor Gray
}

# Collect Intune managed devices if requested
$intuneDevices = @()
if ($IncludeIntuneDevices) {
    Write-Host "`n[*] Collecting Intune managed devices..." -ForegroundColor Yellow
    try {
        $intuneDevices = Get-MgDeviceManagementManagedDevice -All | 
            Select-Object DeviceName, Id, ManagedDeviceId, OperatingSystem, OsVersion, `
                ComplianceState, ManagementAgent, EnrolledDateTime, LastSyncDateTime, `
                AzureAdDeviceId, UserPrincipalName
        
        Write-Host "    [OK] Found $($intuneDevices.Count) Intune managed devices" -ForegroundColor Green
        
        # Process Intune devices
        $intuneDeviceDetails = foreach ($device in $intuneDevices) {
            $isServer = $false
            $computerType = "Workstation"
            
            if ($device.OperatingSystem) {
                if ($device.OperatingSystem -like "*Server*" -or 
                    $device.OperatingSystem -like "*Windows Server*") {
                    $isServer = $true
                    $computerType = "Server"
                }
            }
            if (-not $isServer -and $device.DeviceName) {
                $nameUpper = $device.DeviceName.ToUpper()
                if ($nameUpper -match "SRV|SERVER|DC|DOMAINCONTROLLER|SQL|EXCHANGE|SHAREPOINT") {
                    $isServer = $true
                    $computerType = "Server"
                }
            }
            
            $lastSync = $device.LastSyncDateTime
            $daysSinceSync = if ($lastSync) { 
                (New-TimeSpan -Start $lastSync -End (Get-Date)).Days 
            } else { $null }
            
            # Determine usage category
            $usageCategory = Get-UsageCategory -LastUsage $lastSync -DaysActive $DaysActive -DaysInactive $DaysInactive -DaysStale $DaysStale
            
            # Calculate risk score
            $riskScore = 0
            $riskLevel = "Low"
            
            if ($usageCategory -eq "Very Stale") { $riskScore += 4 }
            elseif ($usageCategory -eq "Stale") { $riskScore += 2 }
            elseif ($usageCategory -eq "Never Used") { $riskScore += 3 }
            if ($isServer -and $usageCategory -eq "Very Stale") { $riskScore += 2 }
            if ($device.ComplianceState -ne "Compliant") { $riskScore += 2 }
            
            if ($riskScore -ge 8) { $riskLevel = "Critical" }
            elseif ($riskScore -ge 5) { $riskLevel = "High" }
            elseif ($riskScore -ge 3) { $riskLevel = "Medium" }
            
            [PSCustomObject]@{
                Name = $device.DeviceName
                DeviceId = $device.AzureAdDeviceId
                Id = $device.Id
                OperatingSystem = $device.OperatingSystem
                OperatingSystemVersion = $device.OsVersion
                TrustType = "IntuneManaged"
                IsCompliant = $device.ComplianceState
                IsManaged = $true
                AccountEnabled = $true
                RegistrationDateTime = $device.EnrolledDateTime
                LastSignIn = $lastSync
                LastUsed = $lastSync  # Alias for clarity
                DaysSinceSignIn = $daysSinceSync
                DaysSinceLastUse = $daysSinceSync  # Alias for clarity
                UsageCategory = $usageCategory
                ComputerType = $computerType
                IsServer = $isServer
                ManagementAgent = $device.ManagementAgent
                UserPrincipalName = $device.UserPrincipalName
                RiskScore = $riskScore
                RiskLevel = $riskLevel
                Source = "Intune"
            }
        }
        
        # Filter servers if requested
        if ($FilterServersOnly) {
            $intuneDeviceDetails = $intuneDeviceDetails | Where-Object { $_.IsServer -eq $true }
            Write-Host "    [FILTERED] Showing $($intuneDeviceDetails.Count) servers only" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Error collecting Intune devices: $_"
        $intuneDeviceDetails = @()
    }
}

# Compare devices if requested
$matchedDevices = @()
$adOnlyDevices = @()
$entraOnlyDevices = @()

if ($CompareDevices) {
    Write-Host "`n[*] Comparing devices between AD and Entra ID..." -ForegroundColor Yellow
    
    # Create lookup dictionaries
    $adDevicesByName = @{}
    foreach ($device in $adComputerDetails) {
        $nameKey = $device.Name.ToLower()
        if (-not $adDevicesByName.ContainsKey($nameKey)) {
            $adDevicesByName[$nameKey] = @()
        }
        $adDevicesByName[$nameKey] += $device
    }
    
    $entraDevicesByName = @{}
    foreach ($device in $entraDeviceDetails) {
        if ($device.Name) {
            $nameKey = $device.Name.ToLower()
            if (-not $entraDevicesByName.ContainsKey($nameKey)) {
                $entraDevicesByName[$nameKey] = @()
            }
            $entraDevicesByName[$nameKey] += $device
        }
    }
    
    # Find matches
    foreach ($adDevice in $adComputerDetails) {
        $nameKey = $adDevice.Name.ToLower()
        if ($entraDevicesByName.ContainsKey($nameKey)) {
            $matchedEntra = $entraDevicesByName[$nameKey][0]
            $matchedDevices += [PSCustomObject]@{
                Name = $adDevice.Name
                AD_DNSHostName = $adDevice.DNSHostName
                AD_OperatingSystem = $adDevice.OperatingSystem
                AD_LastLogon = $adDevice.LastLogon
                AD_DaysSinceLogon = $adDevice.DaysSinceLogon
                AD_Enabled = $adDevice.Enabled
                Entra_TrustType = $matchedEntra.TrustType
                Entra_IsCompliant = $matchedEntra.IsCompliant
                Entra_IsManaged = $matchedEntra.IsManaged
                Entra_LastSignIn = $matchedEntra.LastSignIn
                Entra_DaysSinceSignIn = $matchedEntra.DaysSinceSignIn
                MatchType = "Name"
            }
        }
        else {
            $adOnlyDevices += $adDevice
        }
    }
    
    # Find Entra-only devices
    foreach ($entraDevice in $entraDeviceDetails) {
        if ($entraDevice.Name) {
            $nameKey = $entraDevice.Name.ToLower()
            if (-not $adDevicesByName.ContainsKey($nameKey)) {
                $entraOnlyDevices += $entraDevice
            }
        }
    }
    
    Write-Host "    [OK] Found $($matchedDevices.Count) matched devices" -ForegroundColor Green
    Write-Host "    [OK] Found $($adOnlyDevices.Count) AD-only devices" -ForegroundColor Yellow
    Write-Host "    [OK] Found $($entraOnlyDevices.Count) Entra-only devices" -ForegroundColor Yellow
}

# Display summary statistics
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$adServers = ($adComputerDetails | Where-Object { $_.IsServer -eq $true }).Count
$adWorkstations = ($adComputerDetails | Where-Object { $_.IsServer -eq $false }).Count
$entraServers = ($entraDeviceDetails | Where-Object { $_.IsServer -eq $true }).Count
$entraWorkstations = ($entraDeviceDetails | Where-Object { $_.IsServer -eq $false }).Count

Write-Host "Active Directory:" -ForegroundColor White
Write-Host "  Total Computers: $($adComputerDetails.Count)" -ForegroundColor Cyan
Write-Host "    - Servers: $adServers" -ForegroundColor Yellow
Write-Host "    - Workstations: $adWorkstations" -ForegroundColor Yellow
Write-Host "  By Usage Activity:" -ForegroundColor Yellow
$adComputerDetails | Group-Object UsageCategory | Sort-Object Name | ForEach-Object {
    Write-Host "    - $($_.Name): $($_.Count)" -ForegroundColor Gray
}

Write-Host "`nEntra ID (Azure AD):" -ForegroundColor White
Write-Host "  Total Devices: $($entraDeviceDetails.Count)" -ForegroundColor Cyan
Write-Host "    - Servers: $entraServers" -ForegroundColor Yellow
Write-Host "    - Workstations: $entraWorkstations" -ForegroundColor Yellow
Write-Host "  By Usage Activity:" -ForegroundColor Yellow
$entraDeviceDetails | Group-Object UsageCategory | Sort-Object Name | ForEach-Object {
    Write-Host "    - $($_.Name): $($_.Count)" -ForegroundColor Gray
}

if ($IncludeIntuneDevices -and $intuneDeviceDetails) {
    $intuneServers = ($intuneDeviceDetails | Where-Object { $_.IsServer -eq $true }).Count
    $intuneWorkstations = ($intuneDeviceDetails | Where-Object { $_.IsServer -eq $false }).Count
    Write-Host "`nIntune Managed:" -ForegroundColor White
    Write-Host "  Total Devices: $($intuneDeviceDetails.Count)" -ForegroundColor Cyan
    Write-Host "    - Servers: $intuneServers" -ForegroundColor Yellow
    Write-Host "    - Workstations: $intuneWorkstations" -ForegroundColor Yellow
    Write-Host "  By Usage Activity:" -ForegroundColor Yellow
    $intuneDeviceDetails | Group-Object UsageCategory | Sort-Object Name | ForEach-Object {
        Write-Host "    - $($_.Name): $($_.Count)" -ForegroundColor Gray
    }
}

if ($CompareDevices) {
    Write-Host "`nComparison Results:" -ForegroundColor Cyan
    Write-Host "  Matched (in both): $($matchedDevices.Count)" -ForegroundColor Green
    Write-Host "  AD-only: $($adOnlyDevices.Count)" -ForegroundColor Yellow
    Write-Host "  Entra-only: $($entraOnlyDevices.Count)" -ForegroundColor Yellow
}

# Security findings
$unconstrainedDelegation = ($adComputerDetails | Where-Object { $_.HasUnconstrainedDelegation -eq $true }).Count
$staleADComputers = ($adComputerDetails | Where-Object { $null -ne $_.DaysSinceLogon -and $_.DaysSinceLogon -gt 90 }).Count
$staleEntraDevices = ($entraDeviceDetails | Where-Object { $null -ne $_.DaysSinceSignIn -and $_.DaysSinceSignIn -gt 90 }).Count

if ($unconstrainedDelegation -gt 0) {
    Write-Host "`n[!] SECURITY WARNING: $unconstrainedDelegation AD computers with Unconstrained Delegation!" -ForegroundColor Red
}

if ($staleADComputers -gt 0) {
    Write-Host "[!] INFO: $staleADComputers AD computers with no logon in 90+ days" -ForegroundColor Yellow
}

if ($staleEntraDevices -gt 0) {
    Write-Host "[!] INFO: $staleEntraDevices Entra devices with no sign-in in 90+ days" -ForegroundColor Yellow
}

# Export results
Write-Host "`n[*] Exporting results..." -ForegroundColor Yellow

# AD Computers - All
$adPath = Join-Path $OutputFolder "AD-Computers-All-$timestamp.csv"
$adComputerDetails | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DaysSinceLastUse'; Descending=$true}, Name | Export-Csv -Path $adPath -NoTypeInformation
Write-Host "    [OK] AD Computers (All): $adPath" -ForegroundColor Green

# AD Computers - By Usage Category
$adUsageCategories = $adComputerDetails | Group-Object UsageCategory
foreach ($category in $adUsageCategories) {
    if ($category.Group.Count -gt 0) {
        $categoryPath = Join-Path $OutputFolder "AD-Computers-Usage-$($category.Name)-$timestamp.csv"
        $category.Group | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DaysSinceLastUse'; Descending=$true}, Name | Export-Csv -Path $categoryPath -NoTypeInformation
        Write-Host "    [OK] AD Computers ($($category.Name)): $categoryPath" -ForegroundColor Green
    }
}

# Entra Devices - All
$entraPath = Join-Path $OutputFolder "Entra-Devices-All-$timestamp.csv"
$entraDeviceDetails | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DaysSinceLastUse'; Descending=$true}, Name | Export-Csv -Path $entraPath -NoTypeInformation
Write-Host "    [OK] Entra Devices (All): $entraPath" -ForegroundColor Green

# Entra Devices - By Usage Category
$entraUsageCategories = $entraDeviceDetails | Group-Object UsageCategory
foreach ($category in $entraUsageCategories) {
    if ($category.Group.Count -gt 0) {
        $categoryPath = Join-Path $OutputFolder "Entra-Devices-Usage-$($category.Name)-$timestamp.csv"
        $category.Group | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DaysSinceLastUse'; Descending=$true}, Name | Export-Csv -Path $categoryPath -NoTypeInformation
        Write-Host "    [OK] Entra Devices ($($category.Name)): $categoryPath" -ForegroundColor Green
    }
}

# Intune Devices
if ($IncludeIntuneDevices -and $intuneDeviceDetails) {
    $intunePath = Join-Path $OutputFolder "Intune-Devices-All-$timestamp.csv"
    $intuneDeviceDetails | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DaysSinceLastUse'; Descending=$true}, Name | Export-Csv -Path $intunePath -NoTypeInformation
    Write-Host "    [OK] Intune Devices (All): $intunePath" -ForegroundColor Green
    
    # Intune Devices - By Usage Category
    $intuneUsageCategories = $intuneDeviceDetails | Group-Object UsageCategory
    foreach ($category in $intuneUsageCategories) {
        if ($category.Group.Count -gt 0) {
            $categoryPath = Join-Path $OutputFolder "Intune-Devices-Usage-$($category.Name)-$timestamp.csv"
            $category.Group | Sort-Object -Property @{Expression='RiskScore'; Descending=$true}, @{Expression='DaysSinceLastUse'; Descending=$true}, Name | Export-Csv -Path $categoryPath -NoTypeInformation
            Write-Host "    [OK] Intune Devices ($($category.Name)): $categoryPath" -ForegroundColor Green
        }
    }
}

# Comparison results
if ($CompareDevices) {
    if ($matchedDevices.Count -gt 0) {
        $matchedPath = Join-Path $OutputFolder "Matched-Devices-$timestamp.csv"
        $matchedDevices | Sort-Object Name | Export-Csv -Path $matchedPath -NoTypeInformation
        Write-Host "    [OK] Matched Devices: $matchedPath" -ForegroundColor Green
    }
    
    if ($adOnlyDevices.Count -gt 0) {
        $adOnlyPath = Join-Path $OutputFolder "ADOnly-Devices-$timestamp.csv"
        $adOnlyDevices | Sort-Object Name | Export-Csv -Path $adOnlyPath -NoTypeInformation
        Write-Host "    [OK] AD-Only Devices: $adOnlyPath" -ForegroundColor Green
    }
    
    if ($entraOnlyDevices.Count -gt 0) {
        $entraOnlyPath = Join-Path $OutputFolder "EntraOnly-Devices-$timestamp.csv"
        $entraOnlyDevices | Sort-Object Name | Export-Csv -Path $entraOnlyPath -NoTypeInformation
        Write-Host "    [OK] Entra-Only Devices: $entraOnlyPath" -ForegroundColor Green
    }
}

# Security findings
$securityFindings = @()
if ($unconstrainedDelegation -gt 0) {
    $unconstrainedComps = $adComputerDetails | Where-Object { $_.HasUnconstrainedDelegation -eq $true }
    foreach ($comp in $unconstrainedComps) {
        $securityFindings += [PSCustomObject]@{
            Finding = "Unconstrained Delegation"
            Severity = "Critical"
            ComputerName = $comp.Name
            DNSHostName = $comp.DNSHostName
            OperatingSystem = $comp.OperatingSystem
            Recommendation = "Replace with Constrained Delegation"
        }
    }
}

if ($securityFindings.Count -gt 0) {
    $securityPath = Join-Path $OutputFolder "Security-Findings-$timestamp.csv"
    $securityFindings | Export-Csv -Path $securityPath -NoTypeInformation
    Write-Host "    [OK] Security Findings: $securityPath" -ForegroundColor Green
}

Write-Host "`n[*] Analysis complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Disconnect from Graph
Disconnect-MgGraph | Out-Null

