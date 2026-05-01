# Alerting.psm1
# Threshold-based alert evaluation and multi-channel notification dispatch.
# Works purely with finding objects — no AD/Entra dependencies.
# Used by Invoke-DailyAlert.ps1 for scheduled daily runs.

function Invoke-AlertEvaluation {
    <#
    .SYNOPSIS
    Compares current findings against the previous baseline to determine if alerts are warranted.

    .PARAMETER CurrentFindings
    Array of current run findings (canonical shape: Area, Finding, Severity, ...).

    .PARAMETER PreviousFindings
    Array of findings from the previous baseline run. Pass @() for first run.

    .PARAMETER Thresholds
    Hashtable of thresholds (loaded from config/alert-thresholds.json).

    .PARAMETER AlertMode
    'OnChange' (default), 'Always', or 'Critical'.

    .OUTPUTS
    Hashtable with: ShouldAlert, Reason, NewFindings, ResolvedFindings, EscalatedFindings, AllCritical
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$CurrentFindings,
        [array]$PreviousFindings = @(),
        [hashtable]$Thresholds = @{},
        [ValidateSet('OnChange','Always','Critical')][string]$AlertMode = 'OnChange'
    )

    $ageOutDays = if ($Thresholds.ageOutDays) { $Thresholds.ageOutDays } else { 30 }

    # Identify new findings (in current but not in previous, matched by Finding text)
    $prevFindingTexts = @($PreviousFindings | Select-Object -ExpandProperty Finding)
    $newFindings     = @($CurrentFindings | Where-Object { $prevFindingTexts -notcontains $_.Finding })
    $resolvedFindings = @($PreviousFindings | Where-Object {
        $currTexts = @($CurrentFindings | Select-Object -ExpandProperty Finding)
        $currTexts -notcontains $_.Finding
    })

    # Escalated findings: same finding text, severity went up
    $escalatedFindings = @()
    foreach ($curr in $CurrentFindings) {
        $prev = $PreviousFindings | Where-Object { $_.Finding -eq $curr.Finding } | Select-Object -First 1
        if ($prev -and $curr.Severity -eq 'Critical' -and $prev.Severity -ne 'Critical') {
            $escalatedFindings += $curr
        }
    }

    $allCritical = @($CurrentFindings | Where-Object { $_.Severity -in @('Critical', 'High') })

    # Hard override: DCSync or AdminSDHolder new findings always alert
    $hardAlertFindings = @($newFindings | Where-Object { $_.Finding -match 'DCSync|AdminSDHolder|WMI subscription' })

    # Determine if we should alert
    $shouldAlert = $false
    $reason = ''

    if ($hardAlertFindings.Count -gt 0) {
        $shouldAlert = $true
        $reason = "CRITICAL: $($hardAlertFindings.Count) high-priority threat finding(s) detected ($(($hardAlertFindings | Select-Object -First 2 -ExpandProperty Finding) -join '; '))"
    } elseif ($AlertMode -eq 'Always') {
        $shouldAlert = $true
        $reason = "Daily assessment complete: $($CurrentFindings.Count) total findings"
    } elseif ($AlertMode -eq 'Critical') {
        if ($allCritical.Count -gt 0) {
            $shouldAlert = $true
            $reason = "$($allCritical.Count) Critical/High findings require attention"
        }
    } elseif ($AlertMode -eq 'OnChange') {
        if ($newFindings.Count -gt 0) {
            $shouldAlert = $true
            $reason = "$($newFindings.Count) new findings since last run"
        } elseif ($escalatedFindings.Count -gt 0) {
            $shouldAlert = $true
            $reason = "$($escalatedFindings.Count) findings escalated to Critical severity"
        }
    }

    # Age-out: re-alert if unresolved findings are older than ageOutDays (prevents baseline drift)
    if (-not $shouldAlert -and $PreviousFindings.Count -gt 0 -and $allCritical.Count -gt 0) {
        # Check if any critical findings have been in baseline for > ageOutDays without resolution
        $agedOutCritical = @($allCritical | Where-Object {
            $prev = $PreviousFindings | Where-Object { $_.Finding -eq $_.Finding } | Select-Object -First 1
            if ($prev -and $prev.PSObject.Properties['BaselineDate']) {
                $baselineAge = (New-TimeSpan -Start ([datetime]$prev.BaselineDate) -End (Get-Date)).Days
                return $baselineAge -ge $ageOutDays
            }
            return $false
        })
        if ($agedOutCritical.Count -gt 0) {
            $shouldAlert = $true
            $reason = "REMINDER: $($agedOutCritical.Count) Critical/High finding(s) unresolved for $ageOutDays+ days"
        }
    }

    return @{
        ShouldAlert        = $shouldAlert
        Reason             = $reason
        NewFindings        = $newFindings
        ResolvedFindings   = $resolvedFindings
        EscalatedFindings  = $escalatedFindings
        AllCritical        = $allCritical
        TotalFindings      = $CurrentFindings.Count
        CriticalCount      = @($CurrentFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        HighCount          = @($CurrentFindings | Where-Object { $_.Severity -eq 'High' }).Count
        MediumCount        = @($CurrentFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        Timestamp          = (Get-Date).ToString('u')
    }
}

function Send-AlertNotification {
    <#
    .SYNOPSIS
    Dispatches alert to all configured notification channels.

    .PARAMETER AlertDecision
    Result from Invoke-AlertEvaluation.

    .PARAMETER Config
    Hashtable loaded from config/alert-config.json.

    .PARAMETER ReportPath
    Optional path to the HTML assessment report for linking in notifications.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AlertDecision,
        [Parameter(Mandatory)][hashtable]$Config,
        [string]$ReportPath = ''
    )

    if (-not $AlertDecision.ShouldAlert) {
        Write-Host "No alert conditions met. Skipping notifications." -ForegroundColor Gray
        return
    }

    Write-Host "`nSending alert notifications..." -ForegroundColor Cyan
    Write-Host "  Reason: $($AlertDecision.Reason)" -ForegroundColor Yellow

    if ($Config.email -and $Config.email.enabled) {
        Send-EmailAlert -AlertDecision $AlertDecision -EmailConfig $Config.email -ReportPath $ReportPath
    }
    if ($Config.teams -and $Config.teams.enabled) {
        Send-TeamsAlert -AlertDecision $AlertDecision -TeamsConfig $Config.teams -ReportPath $ReportPath
    }
    if ($Config.slack -and $Config.slack.enabled) {
        Send-SlackAlert -AlertDecision $AlertDecision -SlackConfig $Config.slack -ReportPath $ReportPath
    }
    if ($Config.webhook -and $Config.webhook.enabled) {
        Send-WebhookAlert -AlertDecision $AlertDecision -WebhookConfig $Config.webhook
    }
}

function Send-EmailAlert {
    <#
    .SYNOPSIS
    Sends alert email via SMTP or Microsoft Graph API.
    For Graph: requires GRAPH_CLIENT_SECRET env var and tenant config.
    For SMTP: uses built-in Send-MailMessage.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$AlertDecision,
        [hashtable]$EmailConfig,
        [string]$ReportPath = ''
    )

    $subject = "$($EmailConfig.subjectPrefix) $($AlertDecision.Reason)"
    $htmlBody = Get-AlertHtmlBody -AlertDecision $AlertDecision -ReportPath $ReportPath

    try {
        if ($EmailConfig.useGraph) {
            # Microsoft Graph sendMail approach
            # Requires: Connect-MgGraph -Scopes 'Mail.Send' OR service principal with Mail.Send
            $token = Get-GraphToken -ErrorAction Stop
            $mailBody = @{
                message = @{
                    subject      = $subject
                    body         = @{ contentType = 'HTML'; content = $htmlBody }
                    toRecipients = @($EmailConfig.toAddresses | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                }
                saveToSentItems = $false
            } | ConvertTo-Json -Depth 10

            $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
            Invoke-RestMethod -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/users/$($EmailConfig.fromAddress)/sendMail" `
                -Headers $headers -Body $mailBody -ErrorAction Stop

            Write-Host "  [OK] Email alert sent via Graph to $($EmailConfig.toAddresses -join ', ')" -ForegroundColor Green
        } else {
            # SMTP fallback — credentials from env var SMTP_PASSWORD
            $smtpPwd = $env:SMTP_PASSWORD
            $credential = if ($smtpPwd) {
                New-Object System.Management.Automation.PSCredential($EmailConfig.fromAddress, (ConvertTo-SecureString $smtpPwd -AsPlainText -Force))
            } else { $null }

            $smtpParams = @{
                SmtpServer  = $EmailConfig.smtpServer
                Port        = $EmailConfig.smtpPort
                From        = $EmailConfig.fromAddress
                To          = $EmailConfig.toAddresses
                Subject     = $subject
                Body        = $htmlBody
                BodyAsHtml  = $true
                UseSsl      = $true
            }
            if ($credential) { $smtpParams.Credential = $credential }
            Send-MailMessage @smtpParams -ErrorAction Stop
            Write-Host "  [OK] Email alert sent via SMTP to $($EmailConfig.toAddresses -join ', ')" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Email alert failed: $_"
    }
}

function Send-TeamsAlert {
    <#
    .SYNOPSIS
    Posts Adaptive Card to a Teams channel via Incoming Webhook.
    WebhookUrl must be configured in alert-config.json (Teams → Incoming Webhooks connector).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$AlertDecision,
        [hashtable]$TeamsConfig,
        [string]$ReportPath = ''
    )

    if (-not $TeamsConfig.webhookUrl) {
        Write-Warning "Teams webhook URL not configured in alert-config.json"
        return
    }

    # Build Adaptive Card payload
    $severityColor = if ($AlertDecision.CriticalCount -gt 0) { 'Attention' } elseif ($AlertDecision.HighCount -gt 0) { 'Warning' } else { 'Good' }

    $topFindings = @($AlertDecision.NewFindings | Select-Object -First 5)
    $findingRows = $topFindings | ForEach-Object {
        @{
            type   = 'TableRow'
            cells  = @(
                @{ items = @(@{ type = 'TextBlock'; text = $_.Severity; weight = 'Bolder'; color = $(if ($_.Severity -eq 'Critical') { 'Attention' } elseif ($_.Severity -eq 'High') { 'Warning' } else { 'Default' }) }) }
                @{ items = @(@{ type = 'TextBlock'; text = ($_.Finding -replace "'", "''"); wrap = $true }) }
            )
        }
    }

    $cardBody = @(
        @{
            type   = 'TextBlock'
            text   = "AD Security Alert"
            weight = 'Bolder'
            size   = 'Large'
            color  = $severityColor
        }
        @{
            type = 'FactSet'
            facts = @(
                @{ title = 'Timestamp'; value = $AlertDecision.Timestamp }
                @{ title = 'Reason';    value = $AlertDecision.Reason }
                @{ title = 'Critical';  value = "$($AlertDecision.CriticalCount)" }
                @{ title = 'High';      value = "$($AlertDecision.HighCount)" }
                @{ title = 'Total';     value = "$($AlertDecision.TotalFindings)" }
            )
        }
    )

    if ($topFindings.Count -gt 0) {
        $cardBody += @{
            type = 'TextBlock'
            text = 'New Findings'
            weight = 'Bolder'
            separator = $true
        }
        foreach ($f in $topFindings) {
            $cardBody += @{
                type  = 'TextBlock'
                text  = "[$($f.Severity)] $($f.Finding)"
                wrap  = $true
                color = if ($f.Severity -eq 'Critical') { 'Attention' } elseif ($f.Severity -eq 'High') { 'Warning' } else { 'Default' }
            }
        }
    }

    $actions = @()
    if ($ReportPath) {
        $actions += @{
            type  = 'Action.OpenUrl'
            title = 'View Full Report'
            url   = "file:///$($ReportPath -replace '\\', '/')"
        }
    }

    $payload = @{
        type        = 'message'
        attachments = @(@{
            contentType = 'application/vnd.microsoft.card.adaptive'
            content     = @{
                '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                type      = 'AdaptiveCard'
                version   = '1.4'
                body      = $cardBody
                actions   = $actions
            }
        })
    } | ConvertTo-Json -Depth 15

    try {
        Invoke-RestMethod -Method POST -Uri $TeamsConfig.webhookUrl -Body $payload `
            -ContentType 'application/json' -ErrorAction Stop
        Write-Host "  [OK] Teams alert sent to $($TeamsConfig.channelName)" -ForegroundColor Green
    } catch {
        Write-Warning "Teams alert failed: $_"
    }
}

function Send-SlackAlert {
    <#
    .SYNOPSIS
    Posts Block Kit message to a Slack channel via Incoming Webhook.
    WebhookUrl must be configured in alert-config.json.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$AlertDecision,
        [hashtable]$SlackConfig,
        [string]$ReportPath = ''
    )

    if (-not $SlackConfig.webhookUrl) {
        Write-Warning "Slack webhook URL not configured in alert-config.json"
        return
    }

    $blocks = @(
        @{
            type = 'header'
            text = @{ type = 'plain_text'; text = 'AD Security Alert'; emoji = $true }
        }
        @{
            type = 'section'
            fields = @(
                @{ type = 'mrkdwn'; text = "*Reason:*`n$($AlertDecision.Reason)" }
                @{ type = 'mrkdwn'; text = "*Time:*`n$($AlertDecision.Timestamp)" }
                @{ type = 'mrkdwn'; text = "*Critical:* $($AlertDecision.CriticalCount)" }
                @{ type = 'mrkdwn'; text = "*High:* $($AlertDecision.HighCount)" }
            )
        }
    )

    $newFindingsList = ($AlertDecision.NewFindings | Select-Object -First 5 | ForEach-Object { "• [$($_.Severity)] $($_.Finding)" }) -join "`n"
    if ($newFindingsList) {
        $blocks += @{
            type = 'section'
            text = @{ type = 'mrkdwn'; text = "*New Findings:*`n$newFindingsList" }
        }
    }

    $payload = @{ blocks = $blocks } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod -Method POST -Uri $SlackConfig.webhookUrl -Body $payload `
            -ContentType 'application/json' -ErrorAction Stop
        Write-Host "  [OK] Slack alert sent" -ForegroundColor Green
    } catch {
        Write-Warning "Slack alert failed: $_"
    }
}

function Send-WebhookAlert {
    <#
    .SYNOPSIS
    Posts the full alert decision as JSON to a generic webhook (SIEM/SOAR integration).
    Supports optional auth header (e.g., "Bearer <token>" or "ApiKey <key>").
    Set env var WEBHOOK_AUTH_HEADER to override config value.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$AlertDecision,
        [hashtable]$WebhookConfig
    )

    if (-not $WebhookConfig.url) {
        Write-Warning "Webhook URL not configured in alert-config.json"
        return
    }

    $authHeader = $env:WEBHOOK_AUTH_HEADER
    if (-not $authHeader -and $WebhookConfig.authHeader) { $authHeader = $WebhookConfig.authHeader }

    $headers = @{ 'Content-Type' = 'application/json' }
    if ($authHeader) { $headers['Authorization'] = $authHeader }

    $payload = @{
        source        = 'AD-Security-Assessment'
        timestamp     = $AlertDecision.Timestamp
        shouldAlert   = $AlertDecision.ShouldAlert
        reason        = $AlertDecision.Reason
        criticalCount = $AlertDecision.CriticalCount
        highCount     = $AlertDecision.HighCount
        mediumCount   = $AlertDecision.MediumCount
        totalFindings = $AlertDecision.TotalFindings
        newFindings   = @($AlertDecision.NewFindings | Select-Object Area, Finding, Severity, Category, MITRETechniques)
    } | ConvertTo-Json -Depth 8

    try {
        Invoke-RestMethod -Method POST -Uri $WebhookConfig.url -Body $payload -Headers $headers -ErrorAction Stop
        Write-Host "  [OK] Webhook alert sent to $($WebhookConfig.url)" -ForegroundColor Green
    } catch {
        Write-Warning "Webhook alert failed: $_"
    }
}

function Save-AlertBaseline {
    <#
    .SYNOPSIS
    Saves the current findings as the new baseline for next-run comparison.
    Also writes a summary JSON file for the C# backend to detect.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$CurrentFindings,
        [Parameter(Mandatory)][hashtable]$AlertDecision,
        [Parameter(Mandatory)][string]$BaselineFolder,
        [Parameter(Mandatory)][string]$DataFolder
    )

    if (-not (Test-Path $BaselineFolder)) {
        New-Item -Path $BaselineFolder -ItemType Directory -Force | Out-Null
    }

    $dateStamp = (Get-Date).ToString('yyyy-MM-dd')
    $baselinePath = Join-Path $BaselineFolder "alert-baseline-$dateStamp.json"

    # Add BaselineDate to each finding for age-out tracking
    $baselineFindings = $CurrentFindings | ForEach-Object {
        $f = $_
        if (-not $f.PSObject.Properties['BaselineDate']) {
            $f | Add-Member -NotePropertyName 'BaselineDate' -NotePropertyValue (Get-Date).ToString('u') -Force
        }
        $f
    }

    $baselineFindings | ConvertTo-Json -Depth 8 | Out-File $baselinePath -Force
    Write-Host "  [OK] Baseline saved: $baselinePath" -ForegroundColor Gray

    # Prune old baselines (keep last 30)
    $oldBaselines = Get-ChildItem -Path $BaselineFolder -Filter 'alert-baseline-*.json' |
        Sort-Object LastWriteTime -Descending | Select-Object -Skip 30
    $oldBaselines | Remove-Item -Force -ErrorAction SilentlyContinue

    # Write alert-summary JSON to Data folder for C# backend SignalR detection
    $summaryPath = Join-Path $DataFolder "alert-summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    @{
        Timestamp      = $AlertDecision.Timestamp
        ShouldAlert    = $AlertDecision.ShouldAlert
        Reason         = $AlertDecision.Reason
        CriticalCount  = $AlertDecision.CriticalCount
        HighCount      = $AlertDecision.HighCount
        MediumCount    = $AlertDecision.MediumCount
        TotalFindings  = $AlertDecision.TotalFindings
        NewFindingsCount = $AlertDecision.NewFindings.Count
    } | ConvertTo-Json | Out-File $summaryPath -Force
    Write-Host "  [OK] Alert summary written for dashboard: $summaryPath" -ForegroundColor Gray
}

function Get-LatestBaseline {
    <#
    .SYNOPSIS
    Loads the most recent baseline findings for comparison.
    Returns empty array if no baseline exists.
    #>
    param([string]$BaselineFolder)

    if (-not (Test-Path $BaselineFolder)) { return @() }

    $latest = Get-ChildItem -Path $BaselineFolder -Filter 'alert-baseline-*.json' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $latest) { return @() }

    try {
        return Get-Content $latest.FullName | ConvertFrom-Json
    } catch {
        Write-Warning "Could not load baseline from $($latest.FullName): $_"
        return @()
    }
}

function Get-AlertHtmlBody {
    <#
    .SYNOPSIS
    Generates an HTML email body for the alert notification.
    #>
    param([hashtable]$AlertDecision, [string]$ReportPath = '')

    $topFindings = $AlertDecision.NewFindings | Select-Object -First 10
    $findingRows = ($topFindings | ForEach-Object {
        $color = switch ($_.Severity) {
            'Critical' { '#d13438' }
            'High'     { '#ff8c00' }
            'Medium'   { '#ffd700' }
            default    { '#107c10' }
        }
        "<tr><td style='color:$color;font-weight:bold;'>$($_.Severity)</td><td>$($_.Area)</td><td>$($_.Finding)</td></tr>"
    }) -join "`n"

    $reportLink = if ($ReportPath) { "<p><a href='file:///$($ReportPath -replace '\\', '/')'>View Full Report</a></p>" } else { '' }

    return @"
<!DOCTYPE html>
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;max-width:800px;margin:20px auto;">
  <h2 style="color:#d13438;">AD Security Alert</h2>
  <p><strong>$($AlertDecision.Reason)</strong></p>
  <p>Time: $($AlertDecision.Timestamp)</p>
  <table style="border-collapse:collapse;width:100%;">
    <tr style="background:#f3f2f1;">
      <th style="border:1px solid #ccc;padding:8px;">Critical</th>
      <th style="border:1px solid #ccc;padding:8px;">High</th>
      <th style="border:1px solid #ccc;padding:8px;">Medium</th>
      <th style="border:1px solid #ccc;padding:8px;">Total</th>
    </tr>
    <tr style="text-align:center;">
      <td style="border:1px solid #ccc;padding:8px;color:#d13438;font-weight:bold;">$($AlertDecision.CriticalCount)</td>
      <td style="border:1px solid #ccc;padding:8px;color:#ff8c00;font-weight:bold;">$($AlertDecision.HighCount)</td>
      <td style="border:1px solid #ccc;padding:8px;color:#856404;font-weight:bold;">$($AlertDecision.MediumCount)</td>
      <td style="border:1px solid #ccc;padding:8px;font-weight:bold;">$($AlertDecision.TotalFindings)</td>
    </tr>
  </table>
  $(if ($topFindings.Count -gt 0) { "<h3>New Findings</h3><table style='border-collapse:collapse;width:100%;'><thead><tr style='background:#f3f2f1;'><th style='border:1px solid #ccc;padding:8px;'>Severity</th><th style='border:1px solid #ccc;padding:8px;'>Area</th><th style='border:1px solid #ccc;padding:8px;'>Finding</th></tr></thead><tbody>$findingRows</tbody></table>" })
  $reportLink
  <p style="color:#666;font-size:0.9em;">Generated by AD Security Assessment | RedDog Security Platform</p>
</body>
</html>
"@
}

# Internal helper: get Graph access token from environment or managed identity
function Get-GraphToken {
    # Try service principal credentials from environment
    $clientId     = $env:GRAPH_CLIENT_ID
    $clientSecret = $env:GRAPH_CLIENT_SECRET
    $tenantId     = $env:AZURE_TENANT_ID

    if ($clientId -and $clientSecret -and $tenantId) {
        $body = @{
            client_id     = $clientId
            client_secret = $clientSecret
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }
        $response = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
            -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        return $response.access_token
    }

    # Fallback: try managed identity (IMDS endpoint)
    try {
        $imdsResponse = Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/' `
            -Headers @{ Metadata = 'true' } -ErrorAction Stop
        return $imdsResponse.access_token
    } catch { }

    throw "No Graph credentials available. Set GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, AZURE_TENANT_ID environment variables."
}

Export-ModuleMember -Function @(
    'Invoke-AlertEvaluation',
    'Send-AlertNotification',
    'Send-EmailAlert',
    'Send-TeamsAlert',
    'Send-SlackAlert',
    'Send-WebhookAlert',
    'Save-AlertBaseline',
    'Get-LatestBaseline',
    'Get-AlertHtmlBody'
)
