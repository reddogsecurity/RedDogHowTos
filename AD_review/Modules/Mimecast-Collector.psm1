<#
.SYNOPSIS
    Mimecast API 2.0 data collector for AD Security Assessment integration.
    Collects TTP URL logs, DLP logs, SIEM events, and impersonation logs.

.DESCRIPTION
    Authenticates to Mimecast API 2.0 using HMAC-SHA1 signing.
    All functions are read-only (GET/POST log retrieval only).
    Credentials are loaded from environment variables — never stored in config.

    Required environment variables:
        MIMECAST_ACCESS_KEY   — Access Key from API 2.0 application
        MIMECAST_SECRET_KEY   — Secret Key (Base64-encoded) from API 2.0 application
        MIMECAST_APP_ID       — Application ID
        MIMECAST_APP_KEY      — Application Key
        MIMECAST_BASE_URL     — (optional) Regional base URL; default: https://us-api.mimecast.com

.NOTES
    Mimecast API 2.0 reference: https://developer.services.mimecast.com/api-overview
    PSMimecast module reference: https://www.powershellgallery.com/packages/PSMimecast/1.1.2
#>

using namespace System.Security.Cryptography
using namespace System.Text

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Auth helpers ────────────────────────────────────────────────────────

function Get-MimecastCredentials {
    <#
    .SYNOPSIS Returns credential hashtable from environment variables, with validation.
    #>
    $creds = @{
        AccessKey  = $env:MIMECAST_ACCESS_KEY
        SecretKey  = $env:MIMECAST_SECRET_KEY
        AppId      = $env:MIMECAST_APP_ID
        AppKey     = $env:MIMECAST_APP_KEY
        BaseUrl    = if ($env:MIMECAST_BASE_URL) { $env:MIMECAST_BASE_URL.TrimEnd('/') } else { 'https://us-api.mimecast.com' }
    }

    $missing = $creds.Keys | Where-Object { $_ -ne 'BaseUrl' -and [string]::IsNullOrWhiteSpace($creds[$_]) }
    if ($missing) {
        throw "Missing Mimecast credential environment variables: $($missing -join ', '). " +
              "Set MIMECAST_ACCESS_KEY, MIMECAST_SECRET_KEY, MIMECAST_APP_ID, MIMECAST_APP_KEY."
    }

    return $creds
}

function New-MimecastAuthHeader {
    <#
    .SYNOPSIS
        Generates the Authorization and supporting headers required for each Mimecast API 2.0 request.

    .DESCRIPTION
        Mimecast API 2.0 uses HMAC-SHA1 signing:
          sig = Base64( HMACSHA1( SecretKey, "{date}:{requestId}:{uri}:{appKey}" ) )
          Authorization: MC {accessKey}:{sig}

    .PARAMETER Uri
        The URI path, e.g. /api/ttp/url/get-logs

    .PARAMETER Creds
        Hashtable from Get-MimecastCredentials
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Uri,
        [Parameter(Mandatory)][hashtable] $Creds
    )

    # RFC 1123 date string (UTC)
    $dateHeader = [DateTimeOffset]::UtcNow.ToString('ddd, dd MMM yyyy HH:mm:ss') + ' UTC'

    # Unique request ID
    $requestId  = [Guid]::NewGuid().ToString()

    # HMAC-SHA1 signature
    $dataToSign = "{0}:{1}:{2}:{3}" -f $dateHeader, $requestId, $Uri, $Creds.AppKey
    $secretBytes = [Convert]::FromBase64String($Creds.SecretKey)
    $hmac        = [HMACSHA1]::new($secretBytes)
    $sigBytes    = $hmac.ComputeHash([Encoding]::UTF8.GetBytes($dataToSign))
    $signature   = [Convert]::ToBase64String($sigBytes)
    $hmac.Dispose()

    return @{
        'Authorization' = "MC $($Creds.AccessKey):$signature"
        'x-mc-date'     = $dateHeader
        'x-mc-req-id'   = $requestId
        'x-mc-app-id'   = $Creds.AppId
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
    }
}

function Invoke-MimecastAPIRequest {
    <#
    .SYNOPSIS
        Core signed API request function. Returns the parsed response body.

    .PARAMETER Uri
        API path, e.g. /api/ttp/url/get-logs

    .PARAMETER Body
        PowerShell object to serialize as JSON request body.

    .PARAMETER Creds
        Credential hashtable from Get-MimecastCredentials.

    .PARAMETER Method
        HTTP method (default POST — all Mimecast log endpoints use POST).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]    $Uri,
        [Parameter(Mandatory)][hashtable] $Creds,
        [object]   $Body   = $null,
        [string]   $Method = 'POST'
    )

    $headers = New-MimecastAuthHeader -Uri $Uri -Creds $Creds
    $url     = "$($Creds.BaseUrl)$Uri"

    $params = @{
        Uri     = $url
        Method  = $Method
        Headers = $headers
    }

    if ($null -ne $Body) {
        $params['Body']        = ($Body | ConvertTo-Json -Depth 10 -Compress)
        $params['ContentType'] = 'application/json'
    }

    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        return $response
    }
    catch [System.Net.WebException] {
        $statusCode = [int]$_.Exception.Response.StatusCode
        Write-Warning "Mimecast API $Uri returned HTTP $statusCode : $($_.Exception.Message)"
        return $null
    }
    catch {
        Write-Warning "Mimecast API request to $Uri failed: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region ── TTP URL Logs ────────────────────────────────────────────────────────

function Get-MimecastTTPUrlLogs {
    <#
    .SYNOPSIS
        Retrieves URL Protect (TTP) click logs from Mimecast.
        Endpoint: POST /api/ttp/url/get-logs
        MITRE: T1566.002 (Spearphishing Link)

    .PARAMETER OutputFolder
        Folder where the JSON output will be written.

    .PARAMETER Timestamp
        Timestamp string used in the output filename.

    .PARAMETER Creds
        Mimecast credential hashtable.

    .PARAMETER FromDate
        Start of the log window (default: 24 hours ago).

    .PARAMETER ToDate
        End of the log window (default: now).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]    $OutputFolder,
        [Parameter(Mandatory)][string]    $Timestamp,
        [Parameter(Mandatory)][hashtable] $Creds,
        [DateTime] $FromDate = ([DateTime]::UtcNow.AddDays(-1)),
        [DateTime] $ToDate   = ([DateTime]::UtcNow)
    )

    Write-Host "  [Mimecast] Collecting TTP URL logs..." -ForegroundColor Cyan

    $allLogs  = [System.Collections.Generic.List[object]]::new()
    $pageToken = $null
    $pageNum   = 0

    do {
        $pageNum++
        $requestBody = @{
            meta = @{ pagination = @{ pageSize = 500 } }
            data = @(
                @{
                    from      = $FromDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    to        = $ToDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    scanResult = 'all'     # malicious, suspicious, clean, all
                }
            )
        }

        if ($pageToken) {
            $requestBody.meta.pagination['pageToken'] = $pageToken
        }

        $response = Invoke-MimecastAPIRequest -Uri '/api/ttp/url/get-logs' -Creds $Creds -Body $requestBody

        if ($null -eq $response) { break }

        # Response structure: { data: [ { clickLogs: [...] } ], meta: { pagination: { next: "token" } } }
        $logs = $response.data | ForEach-Object { $_.clickLogs } | Where-Object { $_ }
        if ($logs) { $allLogs.AddRange(@($logs)) }

        $pageToken = $response.meta?.pagination?.next
        Write-Verbose "  TTP URL page $pageNum — fetched $($logs.Count) records (total: $($allLogs.Count))"

    } while (-not [string]::IsNullOrEmpty($pageToken))

    $outputPath = Join-Path $OutputFolder "mimecast-ttp-url-$Timestamp.json"
    $allLogs | ConvertTo-Json -Depth 10 | Set-Content -Path $outputPath -Encoding UTF8

    Write-Host "  [Mimecast] TTP URL logs: $($allLogs.Count) records → $outputPath" -ForegroundColor Green
    return $outputPath
}

#endregion

#region ── DLP Logs ────────────────────────────────────────────────────────────

function Get-MimecastDLPLogs {
    <#
    .SYNOPSIS
        Retrieves Data Leak Prevention logs from Mimecast.
        Endpoint: POST /api/dlp/get-logs
        MITRE: T1048 (Exfiltration Over Alternative Protocol)

    .PARAMETER OutputFolder
        Folder where the JSON output will be written.

    .PARAMETER Timestamp
        Timestamp string used in the output filename.

    .PARAMETER Creds
        Mimecast credential hashtable.

    .PARAMETER FromDate
        Start of the log window (default: 24 hours ago).

    .PARAMETER ToDate
        End of the log window (default: now).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]    $OutputFolder,
        [Parameter(Mandatory)][string]    $Timestamp,
        [Parameter(Mandatory)][hashtable] $Creds,
        [DateTime] $FromDate = ([DateTime]::UtcNow.AddDays(-1)),
        [DateTime] $ToDate   = ([DateTime]::UtcNow)
    )

    Write-Host "  [Mimecast] Collecting DLP logs..." -ForegroundColor Cyan

    $allLogs   = [System.Collections.Generic.List[object]]::new()
    $pageToken = $null
    $pageNum   = 0

    do {
        $pageNum++
        $requestBody = @{
            meta = @{ pagination = @{ pageSize = 500 } }
            data = @(
                @{
                    from = $FromDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    to   = $ToDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                }
            )
        }

        if ($pageToken) {
            $requestBody.meta.pagination['pageToken'] = $pageToken
        }

        $response = Invoke-MimecastAPIRequest -Uri '/api/dlp/get-logs' -Creds $Creds -Body $requestBody

        if ($null -eq $response) { break }

        # Response structure: { data: [ { dlpLogs: [...] } ], meta: { pagination: { next: "token" } } }
        $logs = $response.data | ForEach-Object { $_.dlpLogs } | Where-Object { $_ }
        if ($logs) { $allLogs.AddRange(@($logs)) }

        $pageToken = $response.meta?.pagination?.next
        Write-Verbose "  DLP page $pageNum — fetched $($logs.Count) records (total: $($allLogs.Count))"

    } while (-not [string]::IsNullOrEmpty($pageToken))

    $outputPath = Join-Path $OutputFolder "mimecast-dlp-$Timestamp.json"
    $allLogs | ConvertTo-Json -Depth 10 | Set-Content -Path $outputPath -Encoding UTF8

    Write-Host "  [Mimecast] DLP logs: $($allLogs.Count) records → $outputPath" -ForegroundColor Green
    return $outputPath
}

#endregion

#region ── SIEM Logs ───────────────────────────────────────────────────────────

function Get-MimecastSIEMLogs {
    <#
    .SYNOPSIS
        Retrieves SIEM event logs from Mimecast (requires Enhanced Logging enabled in account).
        Endpoint: POST /api/siem/v1/batch/events/siem
        Returns a newline-delimited JSON stream; persists the mc-siem-token for incremental pulls.

    .PARAMETER OutputFolder
        Folder where the JSON output will be written.

    .PARAMETER Timestamp
        Timestamp string used in the output filename.

    .PARAMETER Creds
        Mimecast credential hashtable.

    .PARAMETER TokenPath
        Path to a file storing the last mc-siem-token for incremental collection.
        If null/absent, performs a full pull for the past 24 hours.

    .PARAMETER Type
        SIEM event type filter: receipt, process, jrnl, delivery, av, spam, impersonation (default: all).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]    $OutputFolder,
        [Parameter(Mandatory)][string]    $Timestamp,
        [Parameter(Mandatory)][hashtable] $Creds,
        [string]   $TokenPath = $null,
        [string]   $Type      = 'all'
    )

    Write-Host "  [Mimecast] Collecting SIEM logs..." -ForegroundColor Cyan

    # Load persisted token for incremental pull
    $siemToken = $null
    if ($TokenPath -and (Test-Path $TokenPath)) {
        $siemToken = (Get-Content $TokenPath -Raw).Trim()
        Write-Verbose "  SIEM: resuming from token $siemToken"
    }

    $allEvents = [System.Collections.Generic.List[object]]::new()
    $pageNum   = 0

    do {
        $pageNum++
        $requestBody = @{
            data = @(
                @{
                    type         = $Type
                    compress     = $false
                    fileFormat   = 'json'
                }
            )
        }

        if ($siemToken) {
            $requestBody.data[0]['token'] = $siemToken
        }

        # SIEM endpoint returns a raw newline-delimited JSON body (not a JSON envelope)
        $uri     = '/api/siem/v1/batch/events/siem'
        $headers = New-MimecastAuthHeader -Uri $uri -Creds $Creds
        $url     = "$($Creds.BaseUrl)$uri"

        try {
            $webRequest = [System.Net.HttpWebRequest]::Create($url)
            $webRequest.Method      = 'POST'
            $webRequest.ContentType = 'application/json'
            foreach ($h in $headers.Keys) { $webRequest.Headers[$h] = $headers[$h] }

            $bodyBytes = [Encoding]::UTF8.GetBytes(($requestBody | ConvertTo-Json -Depth 10 -Compress))
            $webRequest.ContentLength = $bodyBytes.Length
            $reqStream = $webRequest.GetRequestStream()
            $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
            $reqStream.Close()

            $webResponse   = $webRequest.GetResponse()
            $newSiemToken  = $webResponse.Headers['mc-siem-token']
            $reader        = [System.IO.StreamReader]::new($webResponse.GetResponseStream())
            $rawBody       = $reader.ReadToEnd()
            $reader.Close()
            $webResponse.Close()

            # Parse newline-delimited JSON
            $lines = $rawBody -split "`n" | Where-Object { $_.Trim() -ne '' }
            foreach ($line in $lines) {
                try {
                    $event = $line | ConvertFrom-Json
                    $allEvents.Add($event)
                }
                catch { Write-Verbose "  SIEM: skipping non-JSON line" }
            }

            Write-Verbose "  SIEM page $pageNum — fetched $($lines.Count) events (total: $($allEvents.Count))"

            # Update token — empty token means no more data
            $siemToken = $newSiemToken
            if ($TokenPath) {
                $siemToken | Set-Content -Path $TokenPath -Encoding UTF8 -NoNewline
            }
        }
        catch {
            Write-Warning "  SIEM batch request failed (page $pageNum): $($_.Exception.Message)"
            break
        }

    } while (-not [string]::IsNullOrEmpty($siemToken))

    $outputPath = Join-Path $OutputFolder "mimecast-siem-$Timestamp.json"
    $allEvents | ConvertTo-Json -Depth 10 | Set-Content -Path $outputPath -Encoding UTF8

    Write-Host "  [Mimecast] SIEM logs: $($allEvents.Count) events → $outputPath" -ForegroundColor Green
    return $outputPath
}

#endregion

#region ── Impersonation Logs ──────────────────────────────────────────────────

function Get-MimecastImpersonationLogs {
    <#
    .SYNOPSIS
        Retrieves Impersonation Protect logs from Mimecast.
        Endpoint: POST /api/ttp/impersonation/get-logs
        MITRE: T1566.001 (Spearphishing Attachment), T1656 (Impersonation)

    .PARAMETER OutputFolder
        Folder where the JSON output will be written.

    .PARAMETER Timestamp
        Timestamp string used in the output filename.

    .PARAMETER Creds
        Mimecast credential hashtable.

    .PARAMETER FromDate
        Start of the log window (default: 24 hours ago).

    .PARAMETER ToDate
        End of the log window (default: now).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]    $OutputFolder,
        [Parameter(Mandatory)][string]    $Timestamp,
        [Parameter(Mandatory)][hashtable] $Creds,
        [DateTime] $FromDate = ([DateTime]::UtcNow.AddDays(-1)),
        [DateTime] $ToDate   = ([DateTime]::UtcNow)
    )

    Write-Host "  [Mimecast] Collecting impersonation logs..." -ForegroundColor Cyan

    $allLogs   = [System.Collections.Generic.List[object]]::new()
    $pageToken = $null
    $pageNum   = 0

    do {
        $pageNum++
        $requestBody = @{
            meta = @{ pagination = @{ pageSize = 500 } }
            data = @(
                @{
                    from          = $FromDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    to            = $ToDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    taggedMalicious = $false   # false = return all; analyzer filters for malicious
                }
            )
        }

        if ($pageToken) {
            $requestBody.meta.pagination['pageToken'] = $pageToken
        }

        $response = Invoke-MimecastAPIRequest -Uri '/api/ttp/impersonation/get-logs' -Creds $Creds -Body $requestBody

        if ($null -eq $response) { break }

        # Response structure: { data: [ { impersonationLogs: [...] } ], meta: { pagination: { next: "token" } } }
        $logs = $response.data | ForEach-Object { $_.impersonationLogs } | Where-Object { $_ }
        if ($logs) { $allLogs.AddRange(@($logs)) }

        $pageToken = $response.meta?.pagination?.next
        Write-Verbose "  Impersonation page $pageNum — fetched $($logs.Count) records (total: $($allLogs.Count))"

    } while (-not [string]::IsNullOrEmpty($pageToken))

    $outputPath = Join-Path $OutputFolder "mimecast-impersonation-$Timestamp.json"
    $allLogs | ConvertTo-Json -Depth 10 | Set-Content -Path $outputPath -Encoding UTF8

    Write-Host "  [Mimecast] Impersonation logs: $($allLogs.Count) records → $outputPath" -ForegroundColor Green
    return $outputPath
}

#endregion

#region ── Master collection entry point ──────────────────────────────────────

function Invoke-MimecastCollection {
    <#
    .SYNOPSIS
        Master entry point — collects all Mimecast log types.
        Called by Run-Assessment.ps1 and Invoke-DailyAlert.ps1 when -IncludeMimecast is set.

    .PARAMETER OutputFolder
        Folder where JSON output files will be written.

    .PARAMETER Timestamp
        Timestamp string used in output filenames (format: yyyyMMdd-HHmmss).

    .PARAMETER ConfigPath
        Path to mimecast-config.json (optional; falls back to module defaults).

    .PARAMETER CollectTTPUrl
        Collect TTP URL (URL Protect) click logs. Default: true.

    .PARAMETER CollectDLP
        Collect DLP logs. Default: true.

    .PARAMETER CollectSIEM
        Collect SIEM event logs. Default: true. Requires Enhanced Logging enabled.

    .PARAMETER CollectImpersonation
        Collect Impersonation Protect logs. Default: true.

    .PARAMETER DaysBack
        Number of days of history to collect (default: 1 for daily runs; increase for initial pull).

    .PARAMETER SIEMTokenPath
        Path to file storing the SIEM continuation token for incremental pulls.

    .OUTPUTS
        Hashtable of collected file paths, keyed by log type.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $OutputFolder,
        [Parameter(Mandatory)][string] $Timestamp,
        [string]  $ConfigPath          = $null,
        [bool]    $CollectTTPUrl       = $true,
        [bool]    $CollectDLP          = $true,
        [bool]    $CollectSIEM         = $true,
        [bool]    $CollectImpersonation = $true,
        [int]     $DaysBack            = 1,
        [string]  $SIEMTokenPath       = $null
    )

    Write-Host "`n[Phase] Mimecast Collection (past $DaysBack day(s))" -ForegroundColor Magenta
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta

    # Merge optional config file overrides
    $config = @{}
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        try {
            $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
            Write-Verbose "Loaded Mimecast config from $ConfigPath"
        }
        catch {
            Write-Warning "Failed to load mimecast-config.json: $($_.Exception.Message). Using defaults."
        }
    }

    # Apply config overrides
    if ($config.daysBack)             { $DaysBack     = $config.daysBack }
    if ($config.collectTTPUrl -ne $null) { $CollectTTPUrl = $config.collectTTPUrl }
    if ($config.collectDLP -ne $null)    { $CollectDLP    = $config.collectDLP }
    if ($config.collectSIEM -ne $null)   { $CollectSIEM   = $config.collectSIEM }
    if ($config.collectImpersonation -ne $null) { $CollectImpersonation = $config.collectImpersonation }

    # Override base URL from config (avoids requiring env var for regional endpoint)
    if ($config.baseUrl -and -not $env:MIMECAST_BASE_URL) {
        $env:MIMECAST_BASE_URL = $config.baseUrl
    }

    # Validate credentials early — fail fast before spending time on other collectors
    try {
        $creds = Get-MimecastCredentials
    }
    catch {
        Write-Warning "[Mimecast] Skipping collection — credentials not configured: $($_.Exception.Message)"
        return @{}
    }

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    $fromDate = [DateTime]::UtcNow.AddDays(-$DaysBack)
    $toDate   = [DateTime]::UtcNow
    $results  = @{}

    # TTP URL logs
    if ($CollectTTPUrl) {
        try {
            $results['TTPUrl'] = Get-MimecastTTPUrlLogs `
                -OutputFolder $OutputFolder `
                -Timestamp    $Timestamp `
                -Creds        $creds `
                -FromDate     $fromDate `
                -ToDate       $toDate
        }
        catch {
            Write-Warning "[Mimecast] TTP URL collection failed: $($_.Exception.Message)"
        }
    }

    # DLP logs
    if ($CollectDLP) {
        try {
            $results['DLP'] = Get-MimecastDLPLogs `
                -OutputFolder $OutputFolder `
                -Timestamp    $Timestamp `
                -Creds        $creds `
                -FromDate     $fromDate `
                -ToDate       $toDate
        }
        catch {
            Write-Warning "[Mimecast] DLP collection failed: $($_.Exception.Message)"
        }
    }

    # SIEM logs
    if ($CollectSIEM) {
        try {
            $tokenPath = $SIEMTokenPath ?? (Join-Path $OutputFolder '.mimecast-siem-token')
            $results['SIEM'] = Get-MimecastSIEMLogs `
                -OutputFolder $OutputFolder `
                -Timestamp    $Timestamp `
                -Creds        $creds `
                -TokenPath    $tokenPath
        }
        catch {
            Write-Warning "[Mimecast] SIEM collection failed: $($_.Exception.Message)"
        }
    }

    # Impersonation logs
    if ($CollectImpersonation) {
        try {
            $results['Impersonation'] = Get-MimecastImpersonationLogs `
                -OutputFolder $OutputFolder `
                -Timestamp    $Timestamp `
                -Creds        $creds `
                -FromDate     $fromDate `
                -ToDate       $toDate
        }
        catch {
            Write-Warning "[Mimecast] Impersonation collection failed: $($_.Exception.Message)"
        }
    }

    $successCount = ($results.Values | Where-Object { $_ }).Count
    Write-Host "`n[Mimecast] Collection complete — $successCount/$($results.Count) log types collected." -ForegroundColor Magenta
    return $results
}

#endregion

Export-ModuleMember -Function @(
    'Invoke-MimecastCollection',
    'Get-MimecastTTPUrlLogs',
    'Get-MimecastDLPLogs',
    'Get-MimecastSIEMLogs',
    'Get-MimecastImpersonationLogs',
    'Invoke-MimecastAPIRequest'
)
