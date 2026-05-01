<#
.SYNOPSIS
    Mimecast security log analyzer for AD Security Assessment integration.
    Produces canonical findings from TTP URL, DLP, SIEM, and Impersonation logs.

.DESCRIPTION
    Consumes JSON files written by Mimecast-Collector.psm1 and optionally cross-references
    AD user data (ad-users-*.csv) to identify privileged users involved in email attacks.

    Finding shapes match the canonical format used by script.ps1 / ThreatHunting-Analyzer.psm1:
        Area / Finding / Severity / Evidence / Impact / RemediationSteps / Reference / Category

    MITRE techniques covered:
        T1566.001 — Spearphishing Attachment
        T1566.002 — Spearphishing Link (TTP URL clicks)
        T1048     — Exfiltration Over Alternative Protocol (DLP)
        T1114     — Email Collection (SIEM + DLP combined)
        T1656     — Impersonation
        T1110.003 — Password Spray (cross-correlated from SIEM auth events)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ─────────────────────────────────────────────────────────────

function Get-MimecastFile {
    <#
    .SYNOPSIS Returns the most recent matching Mimecast JSON file from the data folder.
    #>
    param(
        [string] $DataPath,
        [string] $Pattern
    )

    $files = Get-ChildItem -Path $DataPath -Filter $Pattern -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending
    return $files | Select-Object -First 1
}

function Read-MimecastJson {
    param([string] $FilePath)
    if (-not $FilePath -or -not (Test-Path $FilePath)) { return @() }
    try {
        $raw = Get-Content $FilePath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $parsed = $raw | ConvertFrom-Json
        # Handle both array and object responses
        if ($parsed -is [array]) { return $parsed }
        return @($parsed)
    }
    catch {
        Write-Warning "Failed to parse $FilePath: $($_.Exception.Message)"
        return @()
    }
}

function Load-MimecastThresholds {
    <#
    .SYNOPSIS Loads thresholds from alert-thresholds.json, falling back to safe defaults.
    #>
    param([string] $ThresholdsPath)

    $defaults = @{
        mimecastDLPViolationCount      = 5
        mimecastURLClickCount          = 3     # clicks on malicious URLs per user per day
        mimecastImpersonationThreshold = 2     # distinct impersonation attempts targeting same user
        mimecastSprayWindowMinutes     = 60
        mimecastSprayThreshold         = 15    # failed auth events from single source in window
        mimecastPrivilegedRisk         = $true # escalate severity when privileged AD user involved
    }

    if ($ThresholdsPath -and (Test-Path $ThresholdsPath)) {
        try {
            $file = Get-Content $ThresholdsPath -Raw | ConvertFrom-Json
            foreach ($key in $defaults.Keys) {
                if ($null -ne $file.$key) { $defaults[$key] = $file.$key }
            }
        }
        catch { Write-Verbose "Could not load thresholds: $($_.Exception.Message)" }
    }
    return $defaults
}

function Get-PrivilegedUserEmails {
    <#
    .SYNOPSIS
        Loads AD user emails that have AdminCount=1 or are in privileged groups.
        Used to escalate severity when a privileged user clicks a malicious URL / triggers DLP.
    #>
    param([string] $DataPath)

    $userFile = Get-MimecastFile -DataPath $DataPath -Pattern 'ad-users-*.csv'
    if (-not $userFile) { return @{} }

    try {
        $users = Import-Csv $userFile.FullName
        $privEmails = @{}
        foreach ($u in $users) {
            if ($u.AdminCount -eq '1' -or $u.Enabled -eq 'True') {
                $email = $u.EmailAddress ?? $u.UserPrincipalName
                if ($email) { $privEmails[$email.ToLower()] = $u.SamAccountName }
            }
        }
        return $privEmails
    }
    catch {
        Write-Verbose "Could not load AD users for cross-reference: $($_.Exception.Message)"
        return @{}
    }
}

function New-MimecastFinding {
    param(
        [string] $Area,
        [string] $Finding,
        [string] $Severity,
        [string] $Evidence,
        [string] $Impact,
        [string] $RemediationSteps,
        [string] $Reference = '',
        [string] $Category  = 'Email Security'
    )
    return [PSCustomObject]@{
        Area             = $Area
        Finding          = $Finding
        Severity         = $Severity
        Evidence         = $Evidence
        Impact           = $Impact
        RemediationSteps = $RemediationSteps
        Reference        = $Reference
        Category         = $Category
        Source           = 'Mimecast'
    }
}

#endregion

#region ── TTP URL Analysis ────────────────────────────────────────────────────

function Test-MaliciousURLClicks {
    <#
    .SYNOPSIS
        Identifies users who clicked malicious or suspicious URLs tracked by TTP URL Protect.
        Escalates to Critical when a privileged AD user (AdminCount=1) is involved.
        MITRE: T1566.002 — Spearphishing Link
    #>
    [CmdletBinding()]
    param(
        [string]    $DataPath,
        [hashtable] $Thresholds,
        [hashtable] $PrivilegedEmails
    )

    $findings = @()
    $ttpFile  = Get-MimecastFile -DataPath $DataPath -Pattern 'mimecast-ttp-url-*.json'
    if (-not $ttpFile) { return $findings }

    $logs = Read-MimecastJson -FilePath $ttpFile.FullName
    if (-not $logs) { return $findings }

    # Filter to actual clicks on malicious/suspicious URLs
    $dangerousClicks = $logs | Where-Object {
        $_.scanResult -in @('malicious', 'suspicious') -and $_.action -in @('block', 'log', 'allow')
    }

    if (-not $dangerousClicks) { return $findings }

    # Group by user
    $byUser = $dangerousClicks | Group-Object { $_.userEmailAddress }

    foreach ($userGroup in $byUser) {
        $email      = $userGroup.Name
        $clickCount = $userGroup.Count
        $isPriv     = $PrivilegedEmails.ContainsKey($email.ToLower())

        # Severity escalation
        $severity = if ($isPriv) {
            'Critical'
        }
        elseif ($clickCount -ge $Thresholds.mimecastURLClickCount) {
            'High'
        }
        else {
            'Medium'
        }

        $urls    = ($userGroup.Group | Select-Object -ExpandProperty url -Unique | Select-Object -First 5) -join '; '
        $privTag = if ($isPriv) { " [PRIVILEGED ACCOUNT: $($PrivilegedEmails[$email.ToLower()])]" } else { '' }

        $findings += New-MimecastFinding `
            -Area             'Email Security' `
            -Finding          "Malicious URL Click: $email$privTag" `
            -Severity         $severity `
            -Evidence         "$clickCount click(s) on malicious/suspicious URL(s). Sample URLs: $urls" `
            -Impact           "User may have been redirected to a phishing page or malware delivery site. Credential compromise or malware infection risk." `
            -RemediationSteps "1. Immediately investigate $email for credential compromise. 2. Force password reset if privileged. 3. Review device for malware. 4. Check for MFA bypass. 5. Review Mimecast URL Protect policy to block vs. allow on click." `
            -Reference        'T1566.002'
    }

    # Campaign detection: multiple users clicking same URL domain
    $domainGroups = $dangerousClicks | Group-Object {
        try { ([Uri]$_.url).Host } catch { 'unknown' }
    } | Where-Object { $_.Count -ge 3 }

    foreach ($dg in $domainGroups) {
        $affectedUsers = ($dg.Group | Select-Object -ExpandProperty userEmailAddress -Unique) -join ', '
        $findings += New-MimecastFinding `
            -Area             'Email Security' `
            -Finding          "Spearphishing Campaign Detected: $($dg.Name)" `
            -Severity         'High' `
            -Evidence         "$($dg.Count) clicks from $(@($dg.Group.userEmailAddress | Select-Object -Unique).Count) users targeting domain: $($dg.Name). Users: $affectedUsers" `
            -Impact           "Coordinated phishing campaign targeting multiple users. May indicate targeted attack or broad credential harvesting." `
            -RemediationSteps "1. Block domain $($dg.Name) at gateway. 2. Notify all affected users. 3. Review MFA status for all clicked users. 4. Submit domain to Mimecast threat intelligence." `
            -Reference        'T1566.002'
    }

    return $findings
}

#endregion

#region ── DLP Analysis ────────────────────────────────────────────────────────

function Test-DLPViolations {
    <#
    .SYNOPSIS
        Identifies significant DLP policy violations, especially outbound data exfiltration.
        Escalates when a privileged user is the sender.
        MITRE: T1048 — Exfiltration Over Alternative Protocol
    #>
    [CmdletBinding()]
    param(
        [string]    $DataPath,
        [hashtable] $Thresholds,
        [hashtable] $PrivilegedEmails
    )

    $findings = @()
    $dlpFile  = Get-MimecastFile -DataPath $DataPath -Pattern 'mimecast-dlp-*.json'
    if (-not $dlpFile) { return $findings }

    $logs = Read-MimecastJson -FilePath $dlpFile.FullName
    if (-not $logs) { return $findings }

    # Only outbound violations are exfiltration risk; inbound = phishing/malware delivery
    $outbound = $logs | Where-Object { $_.route -in @('outbound', 'internal') }

    if (-not $outbound) { return $findings }

    # Group by sender
    $bySender = $outbound | Group-Object { $_.senderAddress }

    foreach ($senderGroup in $bySender) {
        $sender    = $senderGroup.Name
        $count     = $senderGroup.Count
        $isPriv    = $PrivilegedEmails.ContainsKey($sender.ToLower())

        if ($count -lt $Thresholds.mimecastDLPViolationCount -and -not $isPriv) { continue }

        $severity = if ($isPriv) { 'Critical' } elseif ($count -ge $Thresholds.mimecastDLPViolationCount * 2) { 'High' } else { 'Medium' }
        $policies = ($senderGroup.Group | Select-Object -ExpandProperty policy -Unique) -join ', '
        $recipients = ($senderGroup.Group | Select-Object -ExpandProperty recipientAddress -Unique | Select-Object -First 5) -join '; '
        $privTag  = if ($isPriv) { " [PRIVILEGED ACCOUNT: $($PrivilegedEmails[$sender.ToLower()])]" } else { '' }

        $findings += New-MimecastFinding `
            -Area             'Data Exfiltration' `
            -Finding          "DLP Violation: $sender$privTag" `
            -Severity         $severity `
            -Evidence         "$count DLP violation(s) by $sender. Policies triggered: $policies. Recipients: $recipients" `
            -Impact           "Possible data exfiltration or policy violation. Sensitive data may have been sent externally." `
            -RemediationSteps "1. Review email content for $sender. 2. Verify recipient domains are legitimate business partners. 3. Check for compromised account sending data out. 4. Review DLP policy configuration. 5. Consider quarantine if violation appears malicious." `
            -Reference        'T1048'
    }

    # Summary finding if total violations is high
    if ($outbound.Count -ge $Thresholds.mimecastDLPViolationCount * 5) {
        $findings += New-MimecastFinding `
            -Area             'Data Exfiltration' `
            -Finding          "High Volume DLP Violations: $($outbound.Count) outbound events" `
            -Severity         'High' `
            -Evidence         "$($outbound.Count) total outbound DLP violations in the past 24 hours across $($bySender.Count) senders." `
            -Impact           "Elevated data exfiltration risk. May indicate insider threat, compromised accounts, or misconfigured DLP policy." `
            -RemediationSteps "1. Review DLP policy tuning to reduce false positives. 2. Investigate top senders. 3. Consider temporary block-on-detect for high-risk policies. 4. Alert data protection officer if regulated data involved." `
            -Reference        'T1048'
    }

    return $findings
}

#endregion

#region ── Impersonation Analysis ─────────────────────────────────────────────

function Test-ImpersonationAttacks {
    <#
    .SYNOPSIS
        Identifies impersonation attacks targeting internal users, especially executives.
        MITRE: T1566.001 (Spearphishing Attachment), T1656 (Impersonation)
    #>
    [CmdletBinding()]
    param(
        [string]    $DataPath,
        [hashtable] $Thresholds,
        [hashtable] $PrivilegedEmails
    )

    $findings = @()
    $impFile  = Get-MimecastFile -DataPath $DataPath -Pattern 'mimecast-impersonation-*.json'
    if (-not $impFile) { return $findings }

    $logs = Read-MimecastJson -FilePath $impFile.FullName
    if (-not $logs) { return $findings }

    # Focus on messages tagged malicious or with high-confidence identifiers
    $maliciousImp = $logs | Where-Object {
        $_.taggedMalicious -eq $true -or
        ($_.impersonationResults | Where-Object { $_.checkerResult -eq 'hit' })
    }

    if (-not $maliciousImp) { return $findings }

    # Group by targeted recipient (who is being impersonated or targeted)
    $byTarget = $maliciousImp | Group-Object { $_.recipientAddress }

    foreach ($targetGroup in $byTarget) {
        $target  = $targetGroup.Name
        $count   = $targetGroup.Count
        $isPriv  = $PrivilegedEmails.ContainsKey($target.ToLower())

        if ($count -lt $Thresholds.mimecastImpersonationThreshold -and -not $isPriv) { continue }

        $severity = if ($isPriv -and $count -ge 2) { 'Critical' }
                    elseif ($isPriv)                { 'High' }
                    elseif ($count -ge $Thresholds.mimecastImpersonationThreshold * 3) { 'High' }
                    else                            { 'Medium' }

        $senders  = ($targetGroup.Group | Select-Object -ExpandProperty senderAddress -Unique | Select-Object -First 5) -join '; '
        $identifiers = ($targetGroup.Group | ForEach-Object {
            $_.impersonationResults | Where-Object { $_.checkerResult -eq 'hit' } | Select-Object -ExpandProperty checkType
        } | Select-Object -Unique) -join ', '
        $privTag  = if ($isPriv) { " [PRIVILEGED TARGET: $($PrivilegedEmails[$target.ToLower()])]" } else { '' }

        $findings += New-MimecastFinding `
            -Area             'Email Security' `
            -Finding          "Impersonation Attack Targeting: $target$privTag" `
            -Severity         $severity `
            -Evidence         "$count impersonation attempt(s) targeting $target. Sender(s): $senders. Identifiers: $identifiers" `
            -Impact           "Business email compromise (BEC) or targeted spearphishing. Privileged users targeted may be manipulated into wire transfers, credential theft, or malware installation." `
            -RemediationSteps "1. Alert $target about BEC/impersonation campaign. 2. Enable DMARC/DKIM/SPF strict enforcement. 3. Configure Mimecast to block display name spoofing. 4. Train $target on verifying unusual requests via secondary channel. 5. Review mail flow rules for similar patterns." `
            -Reference        'T1566.001, T1656'
    }

    # BEC campaign detection: multiple executives targeted by same sender pattern
    $senderDomains = $maliciousImp | Group-Object {
        try { ($_.senderAddress -split '@')[1] } catch { 'unknown' }
    } | Where-Object { $_.Count -ge 3 }

    foreach ($sg in $senderDomains) {
        $targets = ($sg.Group | Select-Object -ExpandProperty recipientAddress -Unique) -join ', '
        $findings += New-MimecastFinding `
            -Area             'Email Security' `
            -Finding          "BEC Campaign from Domain: $($sg.Name)" `
            -Severity         'High' `
            -Evidence         "$($sg.Count) impersonation messages from domain $($sg.Name) targeting $(@($sg.Group.recipientAddress | Select-Object -Unique).Count) recipients: $targets" `
            -Impact           "Coordinated BEC campaign. Attackers may be testing which targets respond before launching financial fraud." `
            -RemediationSteps "1. Block sending domain $($sg.Name) at gateway. 2. Quarantine any messages from this domain pending review. 3. Alert all targeted recipients. 4. Submit to Mimecast and Microsoft/CISA threat sharing." `
            -Reference        'T1566.001, T1656'
    }

    return $findings
}

#endregion

#region ── SIEM Analysis ──────────────────────────────────────────────────────

function Test-EmailAuthAnomalies {
    <#
    .SYNOPSIS
        Analyzes SIEM events for authentication anomalies:
        - Password spray patterns from inbound auth events
        - Compromised account indicators (auth success after failures, geo anomaly)
        MITRE: T1110.003 (Password Spray), T1114 (Email Collection)
    #>
    [CmdletBinding()]
    param(
        [string]    $DataPath,
        [hashtable] $Thresholds,
        [hashtable] $PrivilegedEmails
    )

    $findings = @()
    $siemFile = Get-MimecastFile -DataPath $DataPath -Pattern 'mimecast-siem-*.json'
    if (-not $siemFile) { return $findings }

    $events = Read-MimecastJson -FilePath $siemFile.FullName
    if (-not $events) { return $findings }

    # Filter to authentication events (type: receipt contains auth failure codes)
    $authEvents = $events | Where-Object {
        $_.type -eq 'receipt' -or $_.type -eq 'process'
    }

    if (-not $authEvents) { return $findings }

    # Password spray: many auth failures from single IP to many accounts within window
    $windowStart = [DateTime]::UtcNow.AddMinutes(-$Thresholds.mimecastSprayWindowMinutes)
    $recentAuths = $authEvents | Where-Object {
        try { [DateTime]::Parse($_.datetime ?? $_.timestamp) -gt $windowStart }
        catch { $false }
    }

    $failuresByIP = $recentAuths |
        Where-Object { $_.act -eq 'Blocked' -or $_.result -eq 'rejected' } |
        Group-Object { $_.senderIP ?? $_.sourceIP ?? 'unknown' } |
        Where-Object { $_.Count -ge $Thresholds.mimecastSprayThreshold }

    foreach ($ipGroup in $failuresByIP) {
        $uniqueTargets = ($ipGroup.Group | Select-Object -ExpandProperty rcpt -Unique).Count
        if ($uniqueTargets -lt 5) { continue }   # Spray = multiple targets, not single account lockout

        $findings += New-MimecastFinding `
            -Area             'Email Security' `
            -Finding          "Email Password Spray from $($ipGroup.Name)" `
            -Severity         'High' `
            -Evidence         "$($ipGroup.Count) auth failures from IP $($ipGroup.Name) targeting $uniqueTargets unique recipients in $($Thresholds.mimecastSprayWindowMinutes) minutes." `
            -Impact           "Active password spray attack via SMTP/IMAP. May result in mailbox compromise and email collection by attacker." `
            -RemediationSteps "1. Block IP $($ipGroup.Name) at email gateway. 2. Enable MFA for all mailboxes. 3. Review accounts targeted for successful auths. 4. Check for inbox rules forwarding mail externally. 5. Submit IP to Mimecast and CISA threat intel." `
            -Reference        'T1110.003'
    }

    # Compromised mailbox indicators: new inbox rules forwarding externally
    $forwardEvents = $events | Where-Object {
        $_.type -eq 'process' -and ($_.act -eq 'forward' -or $_.subject -match 'inbox rule|forward')
    }

    if ($forwardEvents.Count -ge 1) {
        $forwardUsers = ($forwardEvents | Select-Object -ExpandProperty senderAddress -Unique) -join ', '
        $findings += New-MimecastFinding `
            -Area             'Email Security' `
            -Finding          "Suspicious Email Forwarding Rules Detected" `
            -Severity         'High' `
            -Evidence         "$($forwardEvents.Count) email forward event(s) detected. Users: $forwardUsers" `
            -Impact           "Inbox forwarding rules are a common persistence technique after mailbox compromise. Attacker may be collecting sensitive emails." `
            -RemediationSteps "1. Immediately review inbox rules for: $forwardUsers. 2. Remove unauthorized forwarding rules. 3. Force password reset and MFA re-enrollment. 4. Review Azure AD sign-in logs for impossible travel. 5. Check sent items for data exfiltration." `
            -Reference        'T1114'
    }

    return $findings
}

#endregion

#region ── Master analysis entry point ────────────────────────────────────────

function Invoke-MimecastAnalysis {
    <#
    .SYNOPSIS
        Master entry point — runs all Mimecast analysis checks.
        Returns an array of canonical finding objects.

    .PARAMETER DataPath
        Folder containing mimecast-*.json files from Invoke-MimecastCollection.

    .PARAMETER ThresholdsPath
        Path to alert-thresholds.json (optional; uses safe defaults if absent).

    .PARAMETER ADDataPath
        Folder containing ad-users-*.csv for privileged user cross-reference.
        If omitted, defaults to DataPath.

    .OUTPUTS
        [PSCustomObject[]] — array of findings in canonical shape.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $DataPath,
        [string] $ThresholdsPath = $null,
        [string] $ADDataPath     = $null
    )

    Write-Host "`n[Phase] Mimecast Analysis" -ForegroundColor Magenta
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta

    $adPath     = $ADDataPath ?? $DataPath
    $thresholds = Load-MimecastThresholds -ThresholdsPath $ThresholdsPath
    $privEmails = Get-PrivilegedUserEmails -DataPath $adPath

    Write-Verbose "Loaded $($privEmails.Count) privileged user email addresses for cross-reference."

    $allFindings = @()

    # TTP URL — malicious link clicks
    Write-Host "  Checking TTP URL click logs..." -ForegroundColor Cyan
    $allFindings += Test-MaliciousURLClicks `
        -DataPath        $DataPath `
        -Thresholds      $thresholds `
        -PrivilegedEmails $privEmails

    # DLP — outbound data exfiltration
    Write-Host "  Checking DLP violation logs..." -ForegroundColor Cyan
    $allFindings += Test-DLPViolations `
        -DataPath        $DataPath `
        -Thresholds      $thresholds `
        -PrivilegedEmails $privEmails

    # Impersonation — BEC / spearphishing targeting
    Write-Host "  Checking impersonation logs..." -ForegroundColor Cyan
    $allFindings += Test-ImpersonationAttacks `
        -DataPath        $DataPath `
        -Thresholds      $thresholds `
        -PrivilegedEmails $privEmails

    # SIEM — auth anomalies + email collection indicators
    Write-Host "  Checking SIEM event logs..." -ForegroundColor Cyan
    $allFindings += Test-EmailAuthAnomalies `
        -DataPath        $DataPath `
        -Thresholds      $thresholds `
        -PrivilegedEmails $privEmails

    $critCount = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($allFindings | Where-Object { $_.Severity -eq 'High'     }).Count
    Write-Host "`n[Mimecast] Analysis complete — $($allFindings.Count) findings (Critical: $critCount, High: $highCount)" -ForegroundColor Magenta

    return $allFindings
}

#endregion

Export-ModuleMember -Function @(
    'Invoke-MimecastAnalysis',
    'Test-MaliciousURLClicks',
    'Test-DLPViolations',
    'Test-ImpersonationAttacks',
    'Test-EmailAuthAnomalies'
)
