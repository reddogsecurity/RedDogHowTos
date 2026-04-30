<#
.SYNOPSIS
    CrowdStrike Falcon API integration for AD security monitoring

.DESCRIPTION
    Collects security data from CrowdStrike Falcon platform and correlates it with AD/Entra ID:
    - Detections/incidents mapped to AD accounts
    - Device health and sensor status
    - Threat intelligence IOCs
    - Vulnerability assessments
    - Identity protection alerts
    - Correlation with AD user/computer inventory

    Outputs structured data for dashboard, alerting, and Power BI consumption.

.PARAMETER OutputFolder
    Path where results will be stored (default: ./CrowdStrike)

.PARAMETER ClientId
    CrowdStrike API Client ID (or set FALCON_CLIENT_ID environment variable)

.PARAMETER ClientSecret
    CrowdStrike API Client Secret (or set FALCON_CLIENT_SECRET environment variable)

.PARAMETER CloudRegion
    CrowdStrike cloud region: us-1, us-2, eu-1, us-gov-1 (default: us-1)

.PARAMETER CollectionType
    What to collect: Daily (last 24h), Weekly (last 7d), Full (all available)

.PARAMETER ADComputerCSV
    Path to AD computers CSV from assessment (for correlation)

.PARAMETER ADUsersCSV
    Path to AD users CSV from assessment (for correlation)

.EXAMPLE
    .\Invoke-CrowdStrikeCollection.ps1 -ClientId "abc123" -ClientSecret "secret"
    Daily collection with explicit credentials

.EXAMPLE
    .\Invoke-CrowdStrikeCollection.ps1 -CollectionType Weekly
    Weekly collection using environment variables for auth

.EXAMPLE
    .\Invoke-CrowdStrikeCollection.ps1 -CollectionType Daily -ADComputerCSV "ad-computers.csv"
    Daily collection with AD correlation

.NOTES
    Requires: CrowdStrike Falcon API credentials
    API Docs: https://falcon.crowdstrike.com/documentation
    Requires: PowerShell 5.1+ with TLS 1.2 support
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "$PSScriptRoot\CrowdStrike",
    [string]$ClientId = "",
    [string]$ClientSecret = "",
    [ValidateSet("us-1", "us-2", "eu-1", "us-gov-1")]
    [string]$CloudRegion = "us-1",
    [ValidateSet("Daily", "Weekly", "Full")]
    [string]$CollectionType = "Daily",
    [string]$ADComputerCSV = "",
    [string]$ADUsersCSV = "",
    [ValidateSet("Interactive", "Certificate", "ManagedIdentity", "ClientSecret")]
    [string]$AuthMethod = "Interactive",
    [string]$ClientId = "",
    [string]$TenantId = "",
    [string]$CertificateThumbprint = "",
    [string]$CertificateStoreLocation = "CurrentUser",
    [System.Management.Automation.PSCredential]$ClientSecretCredential
)

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dateStamp = Get-Date -Format "yyyy-MM-dd"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CrowdStrike Falcon Data Collection" -ForegroundColor Cyan
Write-Host "Collection Type: $CollectionType" -ForegroundColor Cyan
Write-Host "Cloud Region: $CloudRegion" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================
# AUTHENTICATION
# ============================================

# Get credentials from parameters or environment
if (-not $ClientId) {
    $ClientId = $env:FALCON_CLIENT_ID
}
if (-not $ClientSecret) {
    $ClientSecret = $env:FALCON_CLIENT_SECRET
}

if (-not $ClientId -or -not $ClientSecret) {
    Write-Error "CrowdStrike credentials not provided. Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables or pass as parameters."
    exit 1
}

# Determine base URL based on region
$baseUrl = switch ($CloudRegion) {
    "us-1" { "https://api.crowdstrike.com" }
    "us-2" { "https://api.us-2.crowdstrike.com" }
    "eu-1" { "https://api.eu-1.crowdstrike.com" }
    "us-gov-1" { "https://api.laggar.gcw.crowdstrike.com" }
}

Write-Host "[1/6] Authenticating to CrowdStrike Falcon API..." -ForegroundColor Cyan

# Get OAuth2 token
$authBody = @{
    client_id = $ClientId
    client_secret = $ClientSecret
}

try {
    $authResponse = Invoke-RestMethod -Uri "$baseUrl/oauth2/token" -Method Post `
        -ContentType "application/x-www-form-urlencoded" -Body $authBody -ErrorAction Stop

    $accessToken = $authResponse.access_token
    $authHeaders = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    Write-Host "  [OK] Authentication successful" -ForegroundColor Green
    Write-Host "  Token expires in: $($authResponse.expires_in) seconds" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to authenticate to CrowdStrike API: $_"
    exit 1
}

# Helper function for API calls
function Invoke-FalconAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        $Body = $null,
        [hashtable]$QueryParams = @{}
    )

    $url = "$baseUrl$Endpoint"

    # Add query parameters
    if ($QueryParams.Count -gt 0) {
        $queryString = ($QueryParams.GetEnumerator() | ForEach-Object {
            "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))"
        }) -join "&"
        $url = "$url?$queryString"
    }

    $params = @{
        Uri = $url
        Method = $Method
        Headers = $authHeaders
    }

    if ($Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 10
    }

    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        return $response
    }
    catch {
        Write-Warning "API call failed: $Endpoint - $_"
        return $null
    }
}

# ============================================
# LOAD AD INVENTORY FOR CORRELATION
# ============================================

Write-Host "`n[2/6] Loading AD inventory for correlation..." -ForegroundColor Cyan

$adComputers = @{}
$adUsers = @{}

if ($ADComputerCSV -and (Test-Path $ADComputerCSV)) {
    $computers = Import-Csv $ADComputerCSV
    foreach ($computer in $computers) {
        $key = ($computer.Name -replace '\$', '').ToLower()
        $adComputers[$key] = $computer
    }
    Write-Host "  [OK] Loaded $($adComputers.Count) AD computers" -ForegroundColor Green
}

if ($ADUsersCSV -and (Test-Path $ADUsersCSV)) {
    $users = Import-Csv $ADUsersCSV
    foreach ($user in $users) {
        $adUsers[$user.SamAccountName.ToLower()] = $user
    }
    Write-Host "  [OK] Loaded $($adUsers.Count) AD users" -ForegroundColor Green
}

# ============================================
# COLLECT DETECTIONS/INCIDENTS
# ============================================

Write-Host "`n[3/6] Collecting detections/incidents..." -ForegroundColor Cyan

# Determine date range
$dateRange = switch ($CollectionType) {
    "Daily" { (Get-Date).AddDays(-1) }
    "Weekly" { (Get-Date).AddDays(-7) }
    "Full" { (Get-Date).AddDays(-90) }
}

$dateFilter = $dateRange.ToString("yyyy-MM-ddTHH:mm:ssZ")

$detections = @()
$offset = 0
$limit = 5000

do {
    $response = Invoke-FalconAPI -Endpoint "/incidents/queries/detects/v1" `
        -QueryParams @{
            filter = "max_severity_display_name:'Critical','High'"
            offset = $offset
            limit = $limit
        }

    if ($response -and $response.resources) {
        foreach ($detectionId in $response.resources) {
            $detail = Invoke-FalconAPI -Endpoint "/incidents/entities/detects/GET/v1" `
                -QueryParams @{ ids = $detectionId }

            if ($detail -and $detail.resources) {
                foreach ($detection in $detail.resources) {
                    # Try to map to AD computer
                    $deviceName = $detection.device_name -replace '\$', ''
                    $adComputer = $adComputers[$deviceName.ToLower()]

                    # Try to map to AD user
                    $adUser = $null
                    if ($detection.username) {
                        $adUser = $adUsers[$detection.username.ToLower()]
                    }

                    $detections += [PSCustomObject]@{
                        DetectionId = $detection.id
                        DeviceId = $detection.device_id
                        DeviceName = $deviceName
                        ADComputerFound = [bool]$adComputer
                        Severity = $detection.severity
                        MaxSeverity = $detection.max_severity_display_name
                        Status = $detection.status
                        CreatedTime = $detection.created_timestamp
                        LastBehavior = $detection.last_behavior
                        Tactic = $detection.tactic
                        Technique = $detection.technique
                        Username = $detection.username
                        ADUserFound = [bool]$adUser
                        CommandLine = $detection.cmdline
                        FilePath = $detection.filepath
                        FileName = $detection.filename
                        MD5Hash = $detection.md5hash
                        SHA256Hash = $detection.sha256hash
                        ExternalIpAddress = $detection.external_ip
                        LocalIpAddress = $detection.local_ip
                        CorrelatedWithAD = [bool]($adComputer -or $adUser)
                    }
                }
            }
        }

        $offset += $limit
    }
    else {
        break
    }
} while ($response.resources.Count -eq $limit)

Write-Host "  [OK] Collected $($detections.Count) detections" -ForegroundColor Green

# Save detections
if ($detections.Count -gt 0) {
    $detectionsPath = Join-Path $OutputFolder "detections-$timestamp.csv"
    $detections | Export-Csv -Path $detectionsPath -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] Detections exported: $detectionsPath" -ForegroundColor Green

    # Save AD-correlated detections separately
    $adCorrelated = $detections | Where-Object { $_.CorrelatedWithAD }
    if ($adCorrelated.Count -gt 0) {
        $adCorrelatedPath = Join-Path $OutputFolder "detections-ad-correlated-$timestamp.csv"
        $adCorrelated | Export-Csv -Path $adCorrelatedPath -NoTypeInformation -Encoding UTF8
        Write-Host "  [OK] AD-correlated detections: $adCorrelatedPath ($($adCorrelated.Count) items)" -ForegroundColor Yellow
    }
}

# ============================================
# COLLECT DEVICE HEALTH & SENSOR STATUS
# ============================================

Write-Host "`n[4/6] Collecting device health and sensor status..." -ForegroundColor Cyan

$devices = @()
$offset = 0

do {
    $response = Invoke-FalconAPI -Endpoint "/devices/queries/devices-scroll/v1" `
        -QueryParams @{ limit = $limit; offset = $offset }

    if ($response -and $response.resources) {
        # Get device details in batches
        $batchSize = 100
        for ($i = 0; $i -lt $response.resources.Count; $i += $batchSize) {
            $batch = $response.resources[$i..([Math]::Min($i + $batchSize - 1, $response.resources.Count - 1))]
            $deviceDetails = Invoke-FalconAPI -Endpoint "/devices/entities/devices/v2" `
                -QueryParams @{ ids = ($batch -join ",") }

            if ($deviceDetails -and $deviceDetails.resources) {
                foreach ($device in $deviceDetails.resources) {
                    $deviceName = ($device.hostname -replace '\$', '').ToLower()
                    $adComputer = $adComputers[$deviceName]

                    $devices += [PSCustomObject]@{
                        DeviceId = $device.device_id
                        Hostname = $device.hostname
                        ADComputerFound = [bool]$adComputer
                        OS = $device.os_version
                        PlatformName = $device.platform_name
                        SensorVersion = $device.agent_version
                        SensorStatus = $device.status
                        LastSeen = $device.last_seen
                        ExternalIP = $device.external_ip
                        LocalIP = $device.local_ip
                        MacAddress = $device.mac_address
                        ModifiedDate = $device.modified_timestamp
                        ReducedFunctionalityMode = $device.reduced_functionality_mode
                        BiosManufacturer = $device.bios_manufacturer
                        SystemManufacturer = $device.system_manufacturer
                        SystemProductName = $device.system_product_name
                        CorrelatedWithAD = [bool]$adComputer
                    }
                }
            }
        }

        $offset += $response.resources.Count
    }
    else {
        break
    }
} while ($response.resources.Count -gt 0)

Write-Host "  [OK] Collected $($devices.Count) devices" -ForegroundColor Green

# Save devices
if ($devices.Count -gt 0) {
    $devicesPath = Join-Path $OutputFolder "devices-$timestamp.csv"
    $devices | Export-Csv -Path $devicesPath -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] Devices exported: $devicesPath" -ForegroundColor Green

    # Devices without AD correlation
    $noADCorrelation = $devices | Where-Object { -not $_.CorrelatedWithAD }
    if ($noADCorrelation.Count -gt 0) {
        Write-Host "  [!] $($noADCorrelation.Count) devices not found in AD inventory" -ForegroundColor Yellow
    }
}

# ============================================
# COLLECT VULNERABILITIES
# ============================================

Write-Host "`n[5/6] Collecting vulnerability assessments..." -ForegroundColor Cyan

$vulnerabilities = @()
$cves = @()

try {
    # Get vulnerability summary
    $vulnResponse = Invoke-FalconAPI -Endpoint "/spotlight/combined/vulnerabilities/v2" `
        -QueryParams @{
            filter = "status:'open'"
            limit = 100
        }

    if ($vulnResponse -and $vulnResponse.resources) {
        foreach ($vuln in $vulnResponse.resources) {
            $vulnerabilities += [PSCustomObject]@{
                CVEId = $vuln.cve.id
                CID = $vuln.cid
                Hostname = $vuln.hostname
                Aid = $vuln.aid
                CISACategories = ($vuln.cisa_categories -join ", ")
                ClosedDate = $vuln.closed_date
                CreatedDate = $vuln.created_date
                CVEDescription = $vuln.cve.description
                ExploitStatus = $vuln.exploit_status
                RemediationLevel = $vuln.remediation_level
                Severity = $vuln.severity
                Status = $vuln.status
            }

            # Track unique CVEs
            if ($cves.CVEId -notcontains $vuln.cve.id) {
                $cves += [PSCustomObject]@{
                    CVEId = $vuln.cve.id
                    Severity = $vuln.severity
                    ExploitStatus = $vuln.exploit_status
                    CISA = [bool]$vuln.cisa_categories
                    AffectedHosts = 1
                }
            }
        }
    }

    Write-Host "  [OK] Collected $($vulnerabilities.Count) vulnerability instances, $($cves.Count) unique CVEs" -ForegroundColor Green
}
catch {
    Write-Warning "Vulnerability collection failed: $_"
}

# Save vulnerabilities
if ($vulnerabilities.Count -gt 0) {
    $vulnPath = Join-Path $OutputFolder "vulnerabilities-$timestamp.csv"
    $vulnerabilities | Export-Csv -Path $vulnPath -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] Vulnerabilities exported: $vulnPath" -ForegroundColor Green
}

# Save CVE summary
if ($cves.Count -gt 0) {
    $cvesPath = Join-Path $OutputFolder "cves-summary-$timestamp.csv"
    $cves | Export-Csv -Path $cvesPath -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] CVE summary exported: $cvesPath" -ForegroundColor Green
}

# ============================================
# COLLECT IDENTITY PROTECTION ALERTS
# ============================================

Write-Host "`n[6/6] Collecting identity protection alerts..." -ForegroundColor Cyan

$identityAlerts = @()

try {
    # Query identity-related detections
    $identityResponse = Invoke-FalconAPI -Endpoint "/incidents/queries/detects/v1" `
        -QueryParams @{
            filter = "tactic:'Credential Access','Lateral Movement','Privilege Escalation'"
            limit = 1000
        }

    if ($identityResponse -and $identityResponse.resources) {
        foreach ($alertId in $identityResponse.resources) {
            $detail = Invoke-FalconAPI -Endpoint "/incidents/entities/detects/GET/v1" `
                -QueryParams @{ ids = $alertId }

            if ($detail -and $detail.resources) {
                foreach ($alert in $detail.resources) {
                    $adUser = $null
                    if ($alert.username) {
                        $adUser = $adUsers[$alert.username.ToLower()]
                    }

                    $identityAlerts += [PSCustomObject]@{
                        AlertId = $alert.id
                        DeviceId = $alert.device_id
                        DeviceName = $alert.device_name
                        Username = $alert.username
                        ADUserFound = [bool]$adUser
                        Severity = $alert.severity
                        Tactic = $alert.tactic
                        Technique = $alert.technique
                        CreatedTime = $alert.created_timestamp
                        Description = $alert.description
                        CommandLine = $alert.cmdline
                        CorrelatedWithAD = [bool]$adUser
                    }
                }
            }
        }
    }

    Write-Host "  [OK] Collected $($identityAlerts.Count) identity-related alerts" -ForegroundColor Green
}
catch {
    Write-Warning "Identity alert collection failed: $_"
}

# Save identity alerts
if ($identityAlerts.Count -gt 0) {
    $identityPath = Join-Path $OutputFolder "identity-alerts-$timestamp.csv"
    $identityAlerts | Export-Csv -Path $identityPath -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] Identity alerts exported: $identityPath" -ForegroundColor Green
}

# ============================================
# SUMMARY & METRICS
# ============================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CROWDSTRIKE COLLECTION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Detections/Incidents: $($detections.Count)" -ForegroundColor White
Write-Host "  AD-Correlated: $($detections | Where-Object { $_.CorrelatedWithAD }).Count)" -ForegroundColor Yellow
Write-Host "Devices: $($devices.Count)" -ForegroundColor White
Write-Host "  AD-Correlated: $($devices | Where-Object { $_.CorrelatedWithAD }).Count)" -ForegroundColor Yellow
Write-Host "Vulnerabilities: $($vulnerabilities.Count)" -ForegroundColor White
Write-Host "  Unique CVEs: $($cves.Count)" -ForegroundColor White
Write-Host "  CISA Known Exploited: $($cves | Where-Object { $_.CISA }).Count)" -ForegroundColor Red
Write-Host "Identity Alerts: $($identityAlerts.Count)" -ForegroundColor White
Write-Host "  AD-Correlated: $($identityAlerts | Where-Object { $_.CorrelatedWithAD }).Count)" -ForegroundColor Yellow

# Generate summary JSON for dashboard
$summary = [PSCustomObject]@{
    CollectionTimestamp = (Get-Date).ToString("u")
    CollectionType = $CollectionType
    CloudRegion = $CloudRegion
    TotalDetections = $detections.Count
    ADDetectionCorrelation = ($detections | Where-Object { $_.CorrelatedWithAD }).Count
    TotalDevices = $devices.Count
    ADDeviceCorrelation = ($devices | Where-Object { $_.CorrelatedWithAD }).Count
    TotalVulnerabilities = $vulnerabilities.Count
    UniqueCVEs = $cves.Count
    CISAExploitedCVEs = ($cves | Where-Object { $_.CISA }).Count
    IdentityAlerts = $identityAlerts.Count
    ADIdentityAlertCorrelation = ($identityAlerts | Where-Object { $_.CorrelatedWithAD }).Count
    CriticalDetections = ($detections | Where-Object { $_.MaxSeverity -eq "Critical" }).Count
    HighDetections = ($detections | Where-Object { $_.MaxSeverity -eq "High" }).Count
}

$summaryPath = Join-Path $OutputFolder "collection-summary-$timestamp.json"
$summary | ConvertTo-Json -Depth 4 | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "`n  [OK] Summary exported: $summaryPath" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "CrowdStrike Collection Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# Cleanup: Revoke token
try {
    Invoke-RestMethod -Uri "$baseUrl/oauth2/revoke" -Method Post `
        -Headers @{ "Authorization" = "Bearer $accessToken" } `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{ token = $accessToken } -ErrorAction SilentlyContinue | Out-Null
}
catch {
    # Ignore token revocation errors
}

return @{
    Detections = $detections
    Devices = $devices
    Vulnerabilities = $vulnerabilities
    IdentityAlerts = $identityAlerts
    Summary = $summary
}
