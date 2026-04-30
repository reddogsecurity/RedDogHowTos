<#
.SYNOPSIS
    Microsoft Teams webhook integration for AD security alerts

.DESCRIPTION
    Sends formatted alert messages to Microsoft Teams channels using Incoming Webhook connector.
    Supports adaptive cards with rich formatting, severity-based color coding, and actionable messages.

    Can be used standalone or integrated with other monitoring scripts.

.PARAMETER WebhookUrl
    Microsoft Teams Incoming Webhook URL (required)

.PARAMETER AlertTitle
    Title of the alert message

.PARAMETER Severity
    Alert severity: Critical, High, Medium, Low, Info

.PARAMETER Findings
    Array of finding objects to include in the alert (from daily checks or other sources)

.PARAMETER Summary
    Summary text for the alert

.PARAMETER Source
    Source of the alert (e.g., "Daily Security Checks", "CrowdStrike", "Weekly Assessment")

.PARAMETER IncludeDetails
    Include detailed finding information in the message

.PARAMETER MaxFindings
    Maximum number of findings to include in the message (default: 10)

.PARAMETER ActionUrl
    Optional URL for "View Details" button (e.g., link to dashboard or file share)

.PARAMETER AdditionalFacts
    Hashtable of additional key-value facts to display in the alert

.EXAMPLE
    Send-CrowdStrikeAlert -WebhookUrl "https://..." -Severity Critical -Findings $findings
    Send critical alert with findings to Teams

.EXAMPLE
    Send-DailyDigest -WebhookUrl "https://..." -Findings $findings -Summary "Daily summary"
    Send daily digest summary

.NOTES
    Requires: Microsoft Teams Incoming Webhook configured in a channel
    Setup: Teams Channel -> Connectors -> Incoming Webhook -> Copy URL
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$WebhookUrl,

    [string]$AlertTitle = "",
    [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
    [string]$Severity = "High",
    $Findings = @(),
    [string]$Summary = "",
    [string]$Source = "AD Security Monitoring",
    [switch]$IncludeDetails,
    [int]$MaxFindings = 10,
    [string]$ActionUrl = "",
    [hashtable]$AdditionalFacts = @{}
)

# ============================================
# BUILD TEAMS MESSAGE
# ============================================

function Build-TeamsAdaptiveCard {
    param(
        [string]$Title,
        [string]$Severity,
        [string]$Summary,
        $Findings,
        [string]$Source,
        [switch]$IncludeDetails,
        [int]$MaxFindings,
        [string]$ActionUrl,
        [hashtable]$AdditionalFacts
    )

    # Determine color and emoji based on severity
    $severityConfig = switch ($Severity) {
        "Critical" {
            @{ Color = "Attention"; Emoji = "[!!]"; Priority = "Urgent" }
        }
        "High" {
            @{ Color = "Warning"; Emoji = "[!]"; Priority = "High" }
        }
        "Medium" {
            @{ Color = "Good"; Emoji = "[~]"; Priority = "Medium" }
        }
        "Low" {
            @{ Color = "Accent"; Emoji = "[-]"; Priority = "Low" }
        }
        "Info" {
            @{ Color = "Accent"; Emoji = "[i]"; Priority = "Informational" }
        }
    }

    # Count findings by severity
    $criticalCount = 0
    $highCount = 0
    $mediumCount = 0
    $lowCount = 0

    if ($Findings.Count -gt 0) {
        $criticalCount = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
        $highCount = ($Findings | Where-Object { $_.Severity -eq "High" }).Count
        $mediumCount = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
        $lowCount = ($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    }

    # Build adaptive card
    $card = @{
        type = "message"
        attachments = @(
            @{
                contentType = "application/vnd.microsoft.card.adaptive"
                content = @{
                    schema = "http://adaptivecards.io/schemas/adaptive-card.json"
                    type = "AdaptiveCard"
                    version = "1.4"
                    body = @()
                    actions = @()
                }
            }
        )
    }

    $body = $card.attachments[0].content.body

    # Title
    $body += @{
        type = "TextBlock"
        text = "$($severityConfig.Emoji) $Title"
        weight = "Bolder"
        size = "Large"
        color = $severityConfig.Color
        wrap = $true
    }

    # Metadata row
    $metadataRow = @{
        type = "TextBlock"
        text = "**Source:** $Source | **Severity:** $Severity | **Time:** $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        isSubtle = $true
        spacing = "Small"
        wrap = $true
    }
    $body += $metadataRow

    # Summary
    if ($Summary) {
        $body += @{
            type = "TextBlock"
            text = $Summary
            wrap = $true
            spacing = "Medium"
        }
    }

    # Facts section (findings count + additional facts)
    $facts = @()

    if ($Findings.Count -gt 0) {
        $facts += @{ title = "Total Findings"; value = $Findings.Count }
        if ($criticalCount -gt 0) { $facts += @{ title = "Critical"; value = $criticalCount } }
        if ($highCount -gt 0) { $facts += @{ title = "High"; value = $highCount } }
        if ($mediumCount -gt 0) { $facts += @{ title = "Medium"; value = $mediumCount } }
        if ($lowCount -gt 0) { $facts += @{ title = "Low"; value = $lowCount } }
    }

    # Add custom facts
    foreach ($key in $AdditionalFacts.Keys) {
        $facts += @{ title = $key; value = $AdditionalFacts[$key] }
    }

    if ($facts.Count -gt 0) {
        $body += @{
            type = "FactSet"
            facts = $facts
            spacing = "Medium"
        }
    }

    # Findings list
    if ($IncludeDetails -and $Findings.Count -gt 0) {
        $body += @{
            type = "TextBlock"
            text = "Top Findings:"
            weight = "Bolder"
            spacing = "Large"
        }

        $findingsToShow = $Findings | Select-Object -First $MaxFindings

        foreach ($finding in $findingsToShow) {
            $findingEmoji = switch ($finding.Severity) {
                "Critical" { "[!!]" }
                "High" { "[!]" }
                "Medium" { "[~]" }
                "Low" { "[-]" }
                default { "[-]" }
            }

            $findingText = "$findingEmoji **$($finding.Title)**"
            if ($finding.Description) {
                $findingText += "`n$($finding.Description)"
            }
            if ($finding.Remediation) {
                $findingText += "`n**Remediation:** $($finding.Remediation)"
            }

            $body += @{
                type = "TextBlock"
                text = $findingText
                wrap = $true
                spacing = "Small"
                separator = $true
            }
        }

        if ($Findings.Count -gt $MaxFindings) {
            $body += @{
                type = "TextBlock"
                text = "*... and $($Findings.Count - $MaxFindings) more findings*"
                isSubtle = $true
                italic = $true
                spacing = "Small"
            }
        }
    }

    # Actions (buttons)
    $actions = $card.attachments[0].content.actions

    if ($ActionUrl) {
        $actions += @{
            type = "Action.OpenUrl"
            title = "View Details"
            url = $ActionUrl
            iconUrl = "https://adaptivecards.io/content/go.png"
        }
    }

    return $card
}

# ============================================
# SEND MESSAGE
# ============================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Sending Teams Alert" -ForegroundColor Cyan
Write-Host "Severity: $Severity" -ForegroundColor Cyan
Write-Host "Source: $Source" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Build alert title if not provided
if (-not $AlertTitle) {
    $findingCount = if ($Findings.Count -gt 0) { $Findings.Count } else { "0" }
    $AlertTitle = "$Severity Security Alert - $findingCount Finding(s)"
}

# Build adaptive card
$teamsCard = Build-TeamsAdaptiveCard `
    -Title $AlertTitle `
    -Severity $Severity `
    -Summary $Summary `
    -Findings $Findings `
    -Source $Source `
    -IncludeDetails:$IncludeDetails `
    -MaxFindings $MaxFindings `
    -ActionUrl $ActionUrl `
    -AdditionalFacts $AdditionalFacts

# Convert to JSON
$jsonBody = $teamsCard | ConvertTo-Json -Depth 10 -Compress

# Send to Teams
try {
    Write-Host "[*] Sending message to Teams..." -ForegroundColor Yellow

    $response = Invoke-RestMethod `
        -Uri $WebhookUrl `
        -Method Post `
        -ContentType "application/json" `
        -Body $jsonBody `
        -ErrorAction Stop

    Write-Host "  [OK] Alert sent successfully to Teams" -ForegroundColor Green
    Write-Host "  Response: $response" -ForegroundColor Gray
}
catch {
    Write-Host "  [X] Failed to send alert to Teams" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    Write-Host "  Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Red

    # Check for common errors
    if ($_.Exception.Response.StatusCode -eq 400) {
        Write-Host "  Hint: Check webhook URL and message format" -ForegroundColor Yellow
    }
    elseif ($_.Exception.Response.StatusCode -eq 401 -or $_.Exception.Response.StatusCode -eq 403) {
        Write-Host "  Hint: Webhook may be disabled or deleted. Check Teams channel connector." -ForegroundColor Yellow
    }
    elseif ($_.Exception.Response.StatusCode -eq 404) {
        Write-Host "  Hint: Webhook URL is invalid. Re-create the Incoming Webhook connector." -ForegroundColor Yellow
    }

    throw "Failed to send Teams alert: $_"
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Teams Alert Sent Successfully!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green
