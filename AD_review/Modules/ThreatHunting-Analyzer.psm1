# ThreatHunting-Analyzer.psm1
# Analyzes threat hunting data collected by ThreatHunting-Collector.psm1.
# Also analyzes Entra sign-in logs for impossible travel and brute force patterns.
# Returns findings in the canonical shape used by Invoke-InventoryAnalysis in script.ps1.

Import-Module (Join-Path $PSScriptRoot "Helpers.psm1") -Force

function Invoke-ThreatHuntAnalysis {
    <#
    .SYNOPSIS
    Runs all threat hunting analysis checks and returns findings array.

    .PARAMETER OutputFolder
    Folder containing threat hunting JSON files and Entra sign-in CSV.

    .PARAMETER NowTag
    Timestamp tag used when collecting data (matches file naming convention).

    .PARAMETER ThresholdsPath
    Optional path to alert-thresholds.json for configurable thresholds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$NowTag = '',
        [string]$ThresholdsPath = ''
    )

    Write-Host "`nRunning threat hunting analysis..." -ForegroundColor Cyan

    # Load thresholds (use defaults if file not provided)
    $thresholds = Load-ThreatThresholds -ThresholdsPath $ThresholdsPath

    $allFindings = [System.Collections.Generic.List[object]]::new()

    $dcsyncFindings = Test-DCSyncRights -OutputFolder $OutputFolder -NowTag $NowTag
    $adminSDFindings = Test-AdminSDHolderAbuse -OutputFolder $OutputFolder -NowTag $NowTag
    $asrepFindings = Test-ASREPRoastSurface -OutputFolder $OutputFolder -NowTag $NowTag
    $groupChangeFindings = Test-PrivilegedGroupChanges -OutputFolder $OutputFolder -NowTag $NowTag
    $wmiFindings = Test-WMIPersistence -OutputFolder $OutputFolder -NowTag $NowTag
    $aclFindings = Test-ACLAbusePaths -OutputFolder $OutputFolder -NowTag $NowTag
    $travelFindings = Test-ImpossibleTravel -OutputFolder $OutputFolder -NowTag $NowTag -Thresholds $thresholds
    $bruteForceFindings = Test-BruteForcePatterns -OutputFolder $OutputFolder -NowTag $NowTag -Thresholds $thresholds

    foreach ($f in @($dcsyncFindings, $adminSDFindings, $asrepFindings, $groupChangeFindings,
                     $wmiFindings, $aclFindings, $travelFindings, $bruteForceFindings)) {
        if ($f) { foreach ($item in $f) { $allFindings.Add($item) } }
    }

    # Write threat hunt findings to a separate JSON for the backend and alerting
    $threatFindingsPath = Join-Path $OutputFolder "threat-hunt-findings-$(if ($NowTag) { $NowTag } else { (Get-Date).ToString('yyyyMMdd-HHmmss') }).json"
    $allFindings | ConvertTo-Json -Depth 6 | Out-File $threatFindingsPath -Force

    Write-Host "  [OK] Threat hunting analysis complete: $($allFindings.Count) findings" -ForegroundColor Green

    return $allFindings
}

# --- Helper: Load thresholds from JSON or return defaults ---
function Load-ThreatThresholds {
    param([string]$ThresholdsPath)

    $defaults = @{
        BruteForceThreshold       = 10
        PasswordSprayThreshold    = 20
        PasswordSprayWindowMinutes = 60
        ImpossibleTravelWindowHours = 2
        KnownIPRanges             = @()
    }

    if ($ThresholdsPath -and (Test-Path $ThresholdsPath)) {
        try {
            $loaded = Get-Content $ThresholdsPath | ConvertFrom-Json
            if ($loaded.bruteForceThreshold)         { $defaults.BruteForceThreshold = $loaded.bruteForceThreshold }
            if ($loaded.passwordSprayThreshold)       { $defaults.PasswordSprayThreshold = $loaded.passwordSprayThreshold }
            if ($loaded.passwordSprayWindowMinutes)   { $defaults.PasswordSprayWindowMinutes = $loaded.passwordSprayWindowMinutes }
            if ($loaded.impossibleTravelWindowHours)  { $defaults.ImpossibleTravelWindowHours = $loaded.impossibleTravelWindowHours }
            if ($loaded.knownIPRanges)                { $defaults.KnownIPRanges = $loaded.knownIPRanges }
        } catch {
            Write-Warning "Could not load thresholds from $ThresholdsPath, using defaults"
        }
    }
    return $defaults
}

# --- Helper: Load latest threat file ---
function Get-ThreatFile {
    param([string]$Pattern, [string]$OutputFolder, [string]$NowTag)
    if ($NowTag) {
        $path = Join-Path $OutputFolder ($Pattern -replace '\*', $NowTag)
        if (Test-Path $path) { return $path }
    }
    return Get-LatestFile -Pattern $Pattern -Folder $OutputFolder
}

# --- Helper: Build canonical finding object ---
function New-ThreatFinding {
    param(
        [string]$Area,
        [string]$Finding,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [string]$Evidence,
        [string]$Impact,
        [string]$RemediationSteps,
        [string]$Reference,
        [string]$Category,
        [string]$MITRETechniques = '',
        [string]$MITRETactics = ''
    )
    return [PSCustomObject]@{
        Area              = $Area
        Finding           = $Finding
        Severity          = $Severity
        Evidence          = $Evidence
        Impact            = $Impact
        RemediationSteps  = $RemediationSteps
        Reference         = $Reference
        EstimatedEffort   = 'TBD'
        Category          = $Category
        MITRETechniques   = $MITRETechniques
        MITRETactics      = $MITRETactics
        Owner             = ''
        DueDate           = ''
        Status            = 'Open'
        Source            = 'ThreatHunting'
    }
}

# ============================================================
# ANALYSIS FUNCTIONS
# ============================================================

function Test-DCSyncRights {
    <#
    .SYNOPSIS
    Flags non-legitimate principals with DCSync replication rights (MITRE T1003.006).
    #>
    [CmdletBinding()]
    param([string]$OutputFolder, [string]$NowTag)

    $path = Get-ThreatFile -Pattern 'threat-dcsync-rights-*.json' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $data = Get-Content $path | ConvertFrom-Json
    if (-not $data) { return @() }

    $findings = @()
    $illegal = @($data | Where-Object { -not $_.IsLegitimate })

    foreach ($entry in $illegal) {
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Credential Access' `
            -Finding     "Non-legitimate DCSync right: $($entry.Principal) has $($entry.Right)" `
            -Severity    'Critical' `
            -Evidence    'threat-dcsync-rights' `
            -Impact      'CRITICAL: This principal can dump all domain credentials using Mimikatz dcsync without touching any DC disk. Immediate investigation required.' `
            -RemediationSteps '1. URGENT: Identify who added this permission and when|2. Remove the replication right using ADSI Edit or PowerShell Set-Acl|3. Run Mimikatz dcsync audit to check if credentials were harvested|4. Reset krbtgt password twice (24hr apart) to invalidate any stolen credentials|5. Audit all user password resets since the right was added|6. Only Domain Controllers and specific backup service accounts should hold these rights' `
            -Reference   'https://attack.mitre.org/techniques/T1003/006/' `
            -Category    'Credential Access' `
            -MITRETechniques 'T1003.006' `
            -MITRETactics 'Credential Access'
    }

    if ($illegal.Count -gt 0) {
        Write-Host "  [!] CRITICAL: $($illegal.Count) non-legitimate DCSync rights found" -ForegroundColor Red
    }
    return $findings
}

function Test-AdminSDHolderAbuse {
    <#
    .SYNOPSIS
    Flags non-standard high-risk ACEs on AdminSDHolder (MITRE T1098).
    #>
    [CmdletBinding()]
    param([string]$OutputFolder, [string]$NowTag)

    $path = Get-ThreatFile -Pattern 'threat-adminsdholder-acl-*.json' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $data = Get-Content $path | ConvertFrom-Json
    if (-not $data) { return @() }

    $findings = @()
    $suspicious = @($data | Where-Object { -not $_.IsLegitimate -and $_.IsHighRisk })

    foreach ($entry in $suspicious) {
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Persistence' `
            -Finding     "AdminSDHolder ACE abuse: $($entry.Principal) has $($entry.Rights)" `
            -Severity    'Critical' `
            -Evidence    'threat-adminsdholder-acl' `
            -Impact      'CRITICAL: ACEs on AdminSDHolder are propagated by SDProp (runs every 60 min) to all protected accounts including Domain Admins. This creates persistent backdoor access that survives group removal.' `
            -RemediationSteps '1. URGENT: Remove the non-standard ACE from AdminSDHolder using ADSI Edit|2. Wait up to 60 min for SDProp to propagate the fix, or force immediately with LDAPMod|3. Audit who added this permission using Security Event Log (Event 4662 on CN=AdminSDHolder)|4. Investigate the principal for signs of compromise|5. Run forest-wide privileged access audit to find other persistence mechanisms' `
            -Reference   'https://attack.mitre.org/techniques/T1098/' `
            -Category    'Persistence' `
            -MITRETechniques 'T1098' `
            -MITRETactics 'Persistence, Privilege Escalation'
    }

    if ($suspicious.Count -gt 0) {
        Write-Host "  [!] CRITICAL: $($suspicious.Count) non-standard AdminSDHolder ACEs found" -ForegroundColor Red
    }
    return $findings
}

function Test-ASREPRoastSurface {
    <#
    .SYNOPSIS
    Flags enabled accounts without Kerberos pre-authentication (MITRE T1558.004).
    #>
    [CmdletBinding()]
    param([string]$OutputFolder, [string]$NowTag)

    $path = Get-ThreatFile -Pattern 'threat-asrep-accounts-*.json' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $data = Get-Content $path | ConvertFrom-Json
    if (-not $data) { return @() }

    $findings = @()
    $enabled = @($data | Where-Object { $_.Enabled -eq $true })

    foreach ($user in $enabled) {
        $isCritical = ($user.AdminCount -eq 1)
        $severity = if ($isCritical) { 'Critical' } else { 'High' }

        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Credential Access' `
            -Finding     "AS-REP roastable account: $($user.SamAccountName) $(if ($isCritical) { '(AdminCount=1 - CRITICAL)' })" `
            -Severity    $severity `
            -Evidence    'threat-asrep-accounts' `
            -Impact      "$(if ($isCritical) { 'CRITICAL: ' })This account can be AS-REP roasted - an attacker can request a Kerberos AS-REP without credentials and crack the password hash offline." `
            -RemediationSteps '1. Enable Kerberos pre-authentication: Set-ADUser -Identity <user> -KerberosEncryptionType Default (re-enables pre-auth)|2. Review why pre-auth was disabled - legacy applications may require it|3. If required for legacy app, isolate the service account, use strong password (25+ chars)|4. Monitor Event 4768 with Pre-Authentication Type = 0 in Security Log' `
            -Reference   'https://attack.mitre.org/techniques/T1558/004/' `
            -Category    'Credential Access' `
            -MITRETechniques 'T1558.004' `
            -MITRETactics 'Credential Access'
    }

    if ($enabled.Count -gt 0) {
        Write-Host "  [!] $($enabled.Count) AS-REP roastable accounts found" -ForegroundColor Yellow
    }
    return $findings
}

function Test-PrivilegedGroupChanges {
    <#
    .SYNOPSIS
    Flags same-day additions to tier-0 privileged groups (MITRE T1098).
    #>
    [CmdletBinding()]
    param([string]$OutputFolder, [string]$NowTag)

    $path = Get-ThreatFile -Pattern 'threat-group-changes-*.json' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $data = Get-Content $path | ConvertFrom-Json
    if (-not $data) { return @() }

    $findings = @()
    $today = (Get-Date).Date
    $todayTier0 = @($data | Where-Object {
        $_.IsTier0Group -eq $true -and
        ([datetime]$_.TimeCreated).Date -eq $today
    })

    foreach ($change in $todayTier0) {
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Privilege Escalation' `
            -Finding     "Tier-0 group change TODAY: $($change.MemberAdded) added to $($change.GroupName) by $($change.ChangedBy)" `
            -Severity    'Critical' `
            -Evidence    'threat-group-changes' `
            -Impact      'CRITICAL: Same-day addition to a tier-0 privileged group is highly unusual and may indicate privilege escalation or insider threat activity.' `
            -RemediationSteps '1. URGENT: Verify with AD team if this change was authorized and change-ticket exists|2. If unauthorized: remove the member immediately|3. Disable or isolate the account that made the change if unverified|4. Review the added member for suspicious activity in sign-in logs|5. Check if similar changes were made to other privileged groups today|6. Consider enabling PIM to require approval for tier-0 changes' `
            -Reference   'https://attack.mitre.org/techniques/T1098/' `
            -Category    'Privilege Escalation' `
            -MITRETechniques 'T1098' `
            -MITRETactics 'Persistence, Privilege Escalation'
    }

    if ($todayTier0.Count -gt 0) {
        Write-Host "  [!] CRITICAL: $($todayTier0.Count) tier-0 group changes TODAY" -ForegroundColor Red
    }

    # Also report all 7-day changes as informational
    $allTier0 = @($data | Where-Object { $_.IsTier0Group })
    if ($allTier0.Count -gt $todayTier0.Count) {
        $recentCount = $allTier0.Count - $todayTier0.Count
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Privilege Escalation' `
            -Finding     "$recentCount tier-0 group membership changes in the last 7 days (excluding today)" `
            -Severity    'High' `
            -Evidence    'threat-group-changes' `
            -Impact      'Recent changes to tier-0 privileged groups should be reviewed and correlated with change tickets.' `
            -RemediationSteps '1. Review all changes in threat-group-changes evidence file|2. Validate each change has an approved change ticket|3. Remove any unauthorized additions|4. Implement approval workflow for tier-0 group changes (PIM)' `
            -Reference   'https://attack.mitre.org/techniques/T1098/' `
            -Category    'Privilege Escalation' `
            -MITRETechniques 'T1098' `
            -MITRETactics 'Persistence, Privilege Escalation'
    }

    return $findings
}

function Test-WMIPersistence {
    <#
    .SYNOPSIS
    Flags non-built-in WMI event consumer bindings (MITRE T1546.003).
    #>
    [CmdletBinding()]
    param([string]$OutputFolder, [string]$NowTag)

    $path = Get-ThreatFile -Pattern 'threat-wmi-subscriptions-*.json' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $data = Get-Content $path | ConvertFrom-Json
    if (-not $data) { return @() }

    $findings = @()
    $suspicious = @($data | Where-Object { -not $_.IsBuiltIn })

    foreach ($sub in $suspicious) {
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Persistence' `
            -Finding     "Suspicious WMI subscription: Filter='$($sub.FilterName)' Consumer='$($sub.ConsumerName)'" `
            -Severity    'Critical' `
            -Evidence    'threat-wmi-subscriptions' `
            -Impact      'CRITICAL: WMI event subscriptions are a stealthy persistence mechanism that survives reboots. Non-Microsoft subscriptions are rare and highly suspicious.' `
            -RemediationSteps '1. URGENT: Investigate the consumer script or executable path in the evidence file|2. Remove using: Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WMIObject|3. Also remove the filter and consumer objects|4. Scan the system for associated malware (script content may reveal payload)|5. Check for other persistence mechanisms on this host|6. Review when the subscription was created (correlate with compromise timeline)' `
            -Reference   'https://attack.mitre.org/techniques/T1546/003/' `
            -Category    'Persistence' `
            -MITRETechniques 'T1546.003' `
            -MITRETactics 'Persistence, Privilege Escalation'
    }

    if ($suspicious.Count -gt 0) {
        Write-Host "  [!] CRITICAL: $($suspicious.Count) suspicious WMI subscriptions found" -ForegroundColor Red
    }
    return $findings
}

function Test-ACLAbusePaths {
    <#
    .SYNOPSIS
    Flags non-admin principals with dangerous rights on privileged OUs (MITRE T1222.001).
    #>
    [CmdletBinding()]
    param([string]$OutputFolder, [string]$NowTag)

    $path = Get-ThreatFile -Pattern 'threat-acl-abusepaths-*.json' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $data = Get-Content $path | ConvertFrom-Json
    if (-not $data) { return @() }

    $findings = @()
    $abusePaths = @($data | Where-Object { -not $_.IsLegitimate })

    if ($abusePaths.Count -gt 0) {
        $principalList = ($abusePaths | Select-Object -ExpandProperty Principal -Unique) -join ', '
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Privilege Escalation' `
            -Finding     "$($abusePaths.Count) ACL abuse paths found on privileged OUs (principals: $principalList)" `
            -Severity    'High' `
            -Evidence    'threat-acl-abusepaths' `
            -Impact      'Non-admin principals with GenericAll/WriteDacl/WriteOwner rights can modify protected object permissions, reset passwords, or add themselves to privileged groups.' `
            -RemediationSteps '1. Review each principal and OU in the evidence file|2. Remove dangerous rights using Active Directory Users and Computers or Set-Acl|3. Investigate why the rights were granted - may indicate previous compromise|4. Enable auditing on privileged OUs (Event 4662) to detect future modifications|5. Consider tiered AD admin model to isolate privileged OUs' `
            -Reference   'https://attack.mitre.org/techniques/T1222/001/' `
            -Category    'Privilege Escalation' `
            -MITRETechniques 'T1222.001' `
            -MITRETactics 'Defense Evasion'
    }

    return $findings
}

function Test-ImpossibleTravel {
    <#
    .SYNOPSIS
    Detects impossible travel patterns in Entra sign-in logs (MITRE T1078).
    Two sign-ins from different countries within the configured time window.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder,
        [string]$NowTag,
        [hashtable]$Thresholds
    )

    $path = Get-ThreatFile -Pattern 'entra-signins-*.csv' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $signIns = Import-Csv $path -ErrorAction SilentlyContinue
    if (-not $signIns) { return @() }

    $findings = @()
    $windowHours = if ($Thresholds -and $Thresholds.ImpossibleTravelWindowHours) { $Thresholds.ImpossibleTravelWindowHours } else { 2 }
    $knownRanges = if ($Thresholds -and $Thresholds.KnownIPRanges) { $Thresholds.KnownIPRanges } else { @() }

    # Group by user and sort by time
    $byUser = $signIns | Where-Object {
        $_.UserPrincipalName -and $_.CreatedDateTime -and $_.LocationCountry
    } | Group-Object UserPrincipalName

    $impossibleTravels = @()

    foreach ($userGroup in $byUser) {
        $userSignIns = $userGroup.Group |
            Sort-Object { [datetime]$_.CreatedDateTime }

        for ($i = 0; $i -lt ($userSignIns.Count - 1); $i++) {
            $current = $userSignIns[$i]
            $next    = $userSignIns[$i + 1]

            $currentCountry = $current.LocationCountry
            $nextCountry    = $next.LocationCountry

            if (-not $currentCountry -or -not $nextCountry) { continue }
            if ($currentCountry -eq $nextCountry) { continue }

            try {
                $timeDelta = ([datetime]$next.CreatedDateTime) - ([datetime]$current.CreatedDateTime)
                $hoursApart = [Math]::Abs($timeDelta.TotalHours)

                if ($hoursApart -le $windowHours) {
                    # Skip if either IP is in known ranges
                    $skipKnown = $false
                    foreach ($range in $knownRanges) {
                        if ($current.IPAddress -match $range -or $next.IPAddress -match $range) {
                            $skipKnown = $true
                            break
                        }
                    }
                    if ($skipKnown) { continue }

                    $impossibleTravels += [PSCustomObject]@{
                        User          = $userGroup.Name
                        Country1      = $currentCountry
                        Country2      = $nextCountry
                        Time1         = $current.CreatedDateTime
                        Time2         = $next.CreatedDateTime
                        HoursApart    = [Math]::Round($hoursApart, 1)
                        IP1           = $current.IPAddress
                        IP2           = $next.IPAddress
                    }
                }
            } catch {
                # Skip sign-in with unparseable timestamp
            }
        }
    }

    if ($impossibleTravels.Count -gt 0) {
        Write-Host "  [!] $($impossibleTravels.Count) impossible travel incidents detected" -ForegroundColor Yellow
        $affectedUsers = ($impossibleTravels | Select-Object -ExpandProperty User -Unique) -join ', '
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Identity Protection' `
            -Finding     "$($impossibleTravels.Count) impossible travel incidents across $($impossibleTravels | Select-Object -ExpandProperty User -Unique | Measure-Object).Count user(s)" `
            -Severity    'High' `
            -Evidence    'entra-signins (impossible travel analysis)' `
            -Impact      'Sign-ins from geographically impossible locations within a short time window indicate account compromise or credential sharing.' `
            -RemediationSteps '1. Review affected users: investigate each impossible travel event|2. Check if VPN or proxy explains the location discrepancy|3. For confirmed anomalies: revoke all sessions (Revoke-MgUserSignInSession)|4. Force password reset for affected accounts|5. Enable sign-in risk policy in Entra Conditional Access to auto-block risky sign-ins|6. Implement Continuous Access Evaluation (CAE) for real-time threat response' `
            -Reference   'https://attack.mitre.org/techniques/T1078/' `
            -Category    'Identity Protection' `
            -MITRETechniques 'T1078' `
            -MITRETactics 'Initial Access, Defense Evasion'
    }

    return $findings
}

function Test-BruteForcePatterns {
    <#
    .SYNOPSIS
    Detects brute force and password spray patterns in Entra sign-in logs (MITRE T1110.003).
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder,
        [string]$NowTag,
        [hashtable]$Thresholds
    )

    $path = Get-ThreatFile -Pattern 'entra-signins-*.csv' -OutputFolder $OutputFolder -NowTag $NowTag
    if (-not $path) { return @() }

    $signIns = Import-Csv $path -ErrorAction SilentlyContinue
    if (-not $signIns) { return @() }

    $findings = @()
    $bruteThreshold = if ($Thresholds -and $Thresholds.BruteForceThreshold) { $Thresholds.BruteForceThreshold } else { 10 }
    $sprayThreshold = if ($Thresholds -and $Thresholds.PasswordSprayThreshold) { $Thresholds.PasswordSprayThreshold } else { 20 }
    $windowMinutes  = if ($Thresholds -and $Thresholds.PasswordSprayWindowMinutes) { $Thresholds.PasswordSprayWindowMinutes } else { 60 }

    # ErrorCode 50126 = invalid username or password
    $failedSignIns = $signIns | Where-Object {
        $_.StatusErrorCode -eq '50126' -and $_.CreatedDateTime
    }

    if (-not $failedSignIns -or $failedSignIns.Count -eq 0) { return $findings }

    # --- Brute force: per-user ---
    $byUser = $failedSignIns | Group-Object UserPrincipalName
    $bruteForceTargets = @()

    foreach ($userGroup in $byUser) {
        $sortedFails = $userGroup.Group | Sort-Object { [datetime]$_.CreatedDateTime }
        # Sliding window: count failures within windowMinutes
        for ($i = 0; $i -lt $sortedFails.Count; $i++) {
            $windowEnd = ([datetime]$sortedFails[$i].CreatedDateTime).AddMinutes($windowMinutes)
            $inWindow = @($sortedFails | Where-Object { [datetime]$_.CreatedDateTime -ge [datetime]$sortedFails[$i].CreatedDateTime -and [datetime]$_.CreatedDateTime -le $windowEnd })
            if ($inWindow.Count -ge $bruteThreshold) {
                $bruteForceTargets += [PSCustomObject]@{
                    User          = $userGroup.Name
                    FailCount     = $inWindow.Count
                    WindowStart   = $sortedFails[$i].CreatedDateTime
                }
                break  # One finding per user
            }
        }
    }

    if ($bruteForceTargets.Count -gt 0) {
        $targetList = ($bruteForceTargets | Select-Object -ExpandProperty User) -join ', '
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Credential Access' `
            -Finding     "Brute force detected: $($bruteForceTargets.Count) account(s) with $bruteThreshold+ failures in ${windowMinutes}min window" `
            -Severity    'High' `
            -Evidence    'entra-signins (brute force analysis)' `
            -Impact      "Targeted password guessing against specific accounts. Affected users: $targetList" `
            -RemediationSteps '1. Lock out or require MFA challenge for the targeted accounts immediately|2. Review sign-in logs for any successful authentication from the same IP|3. Enable Smart Lockout in Entra ID (already on by default but verify threshold)|4. Block the source IP in Conditional Access or WAF if identified|5. Check if the account was compromised (look for successful logins after the failures)|6. Enable Identity Protection risk policies for automated response' `
            -Reference   'https://attack.mitre.org/techniques/T1110/' `
            -Category    'Credential Access' `
            -MITRETechniques 'T1110' `
            -MITRETactics 'Credential Access'
    }

    # --- Password spray: many users from same IP ---
    $byIP = $failedSignIns | Where-Object { $_.IPAddress } | Group-Object IPAddress
    $spraySourceIPs = @()

    foreach ($ipGroup in $byIP) {
        if ($ipGroup.Count -lt $sprayThreshold) { continue }
        # Check unique users in window
        $sortedFails = $ipGroup.Group | Sort-Object { [datetime]$_.CreatedDateTime }
        for ($i = 0; $i -lt $sortedFails.Count; $i++) {
            $windowEnd = ([datetime]$sortedFails[$i].CreatedDateTime).AddMinutes($windowMinutes)
            $inWindow = @($sortedFails | Where-Object {
                [datetime]$_.CreatedDateTime -ge [datetime]$sortedFails[$i].CreatedDateTime -and
                [datetime]$_.CreatedDateTime -le $windowEnd
            })
            $uniqueUsers = @($inWindow | Select-Object -ExpandProperty UserPrincipalName -Unique)
            if ($uniqueUsers.Count -ge $sprayThreshold) {
                $spraySourceIPs += [PSCustomObject]@{
                    SourceIP     = $ipGroup.Name
                    UniqueUsers  = $uniqueUsers.Count
                    WindowStart  = $sortedFails[$i].CreatedDateTime
                }
                break
            }
        }
    }

    if ($spraySourceIPs.Count -gt 0) {
        $ipList = ($spraySourceIPs | Select-Object -ExpandProperty SourceIP) -join ', '
        $findings += New-ThreatFinding `
            -Area        'Threat Hunt: Credential Access' `
            -Finding     "Password spray detected from $($spraySourceIPs.Count) source IP(s) targeting $sprayThreshold+ users in ${windowMinutes}min" `
            -Severity    'High' `
            -Evidence    'entra-signins (password spray analysis)' `
            -Impact      "Low-and-slow password spray attack spreading failures across many accounts to evade per-account lockout. Source IPs: $ipList" `
            -RemediationSteps '1. Block the source IP(s) in Conditional Access Named Locations|2. Force password reset for all targeted users|3. Review successful sign-ins from the same IPs|4. Enable Identity Protection sign-in risk policies|5. Implement Conditional Access requiring MFA for all users|6. Report the IP to your ISP/threat intel platform|7. Consider deploying Entra ID Password Protection to block weak/sprayed passwords' `
            -Reference   'https://attack.mitre.org/techniques/T1110/003/' `
            -Category    'Credential Access' `
            -MITRETechniques 'T1110.003' `
            -MITRETactics 'Credential Access'
    }

    return $findings
}

Export-ModuleMember -Function @(
    'Invoke-ThreatHuntAnalysis',
    'Test-DCSyncRights',
    'Test-AdminSDHolderAbuse',
    'Test-ASREPRoastSurface',
    'Test-PrivilegedGroupChanges',
    'Test-WMIPersistence',
    'Test-ACLAbusePaths',
    'Test-ImpossibleTravel',
    'Test-BruteForcePatterns'
)
