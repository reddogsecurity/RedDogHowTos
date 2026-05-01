# ThreatHunting-Collector.psm1
# Read-only threat hunting data collection for advanced attack technique detection.
# Collects raw AD/Entra data needed by ThreatHunting-Analyzer.psm1.
# All operations are READ-ONLY; no modifications are made to AD.

Import-Module (Join-Path $PSScriptRoot "Helpers.psm1") -Force

function Invoke-ThreatHuntingCollection {
    <#
    .SYNOPSIS
    Orchestrates all threat hunting data collection functions.

    .PARAMETER OutputFolder
    Path where collected data will be stored.

    .PARAMETER Timestamp
    Timestamp string to append to output files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [Parameter(Mandatory)]
        [string]$Timestamp
    )

    Write-Host "`nRunning threat hunting data collection..." -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found. Skipping threat hunting collection."
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    Get-DCSyncRights      -OutputFolder $OutputFolder -Timestamp $Timestamp
    Get-AdminSDHolderACL  -OutputFolder $OutputFolder -Timestamp $Timestamp
    Get-ASREPRoastableUsers -OutputFolder $OutputFolder -Timestamp $Timestamp
    Get-ConstrainedDelegationMisconfig -OutputFolder $OutputFolder -Timestamp $Timestamp
    Get-PrivilegedGroupChanges -OutputFolder $OutputFolder -Timestamp $Timestamp
    Get-WMISubscriptionPersistence -OutputFolder $OutputFolder -Timestamp $Timestamp
    Get-ACLAbusePaths      -OutputFolder $OutputFolder -Timestamp $Timestamp

    Write-Host "  [OK] Threat hunting data collection complete" -ForegroundColor Green
}

function Get-DCSyncRights {
    <#
    .SYNOPSIS
    Identifies non-legitimate principals with DCSync replication rights on the domain NC.
    Maps to MITRE T1003.006 (OS Credential Dumping: DCSync).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )

    Write-Host "  Checking DCSync replication rights..." -ForegroundColor Gray

    # GUIDs for replication extended rights
    $replicateAllGuid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
    $replicateGuid    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes

    # Well-known principals that legitimately hold DCSync rights
    $legitimateExclusions = @(
        'Domain Controllers',
        'ENTERPRISE DOMAIN CONTROLLERS',
        'Administrators',
        'NT AUTHORITY\SYSTEM',
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
    )

    $results = @()

    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $domainPath = "AD:$domainDN"

        $acl = Get-Acl -Path $domainPath -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $objectType = $ace.ObjectType.ToString()
            if ($objectType -eq $replicateAllGuid -or $objectType -eq $replicateGuid) {
                $identityRef = $ace.IdentityReference.ToString()

                # Check if this is a legitimate principal
                $isLegitimate = $false
                foreach ($excl in $legitimateExclusions) {
                    if ($identityRef -match [regex]::Escape($excl)) {
                        $isLegitimate = $true
                        break
                    }
                }

                $results += [PSCustomObject]@{
                    Principal      = $identityRef
                    Right          = if ($objectType -eq $replicateAllGuid) { 'DS-Replication-Get-Changes-All' } else { 'DS-Replication-Get-Changes' }
                    AccessType     = $ace.AccessControlType.ToString()
                    IsLegitimate   = $isLegitimate
                    DomainDN       = $domainDN
                    CollectedAt    = (Get-Date).ToString('u')
                }
            }
        }

        $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "threat-dcsync-rights-$Timestamp.json") -Force
        $illegitimate = $results | Where-Object { -not $_.IsLegitimate }
        Write-Host "    DCSync rights: $($results.Count) total, $($illegitimate.Count) non-legitimate" -ForegroundColor $(if ($illegitimate.Count -gt 0) { 'Red' } else { 'DarkGray' })
    } catch {
        Write-Warning "DCSync rights check failed: $_"
        @() | ConvertTo-Json | Out-File (Join-Path $OutputFolder "threat-dcsync-rights-$Timestamp.json") -Force
    }
}

function Get-AdminSDHolderACL {
    <#
    .SYNOPSIS
    Reads ACEs on CN=AdminSDHolder to detect persistence via SDProp propagation.
    Maps to MITRE T1098 (Account Manipulation).
    AdminSDHolder ACEs are propagated to all protected accounts every 60 minutes by SDProp.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )

    Write-Host "  Checking AdminSDHolder ACL for non-standard entries..." -ForegroundColor Gray

    $legitimatePrincipals = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'SYSTEM',
        'NT AUTHORITY\SYSTEM',
        'BUILTIN\Administrators',
        'Account Operators',
        'Backup Operators'
    )

    $results = @()

    try {
        $domain = Get-ADDomain
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
        $adminSDHolderPath = "AD:$adminSDHolderDN"

        $acl = Get-Acl -Path $adminSDHolderPath -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $identityRef = $ace.IdentityReference.ToString()
            $rights = $ace.ActiveDirectoryRights.ToString()

            $isLegitimate = $false
            foreach ($legit in $legitimatePrincipals) {
                if ($identityRef -match [regex]::Escape($legit)) {
                    $isLegitimate = $true
                    break
                }
            }

            # Flag non-standard ACEs with significant rights
            $isHighRisk = ($rights -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty|GenericWrite')

            $results += [PSCustomObject]@{
                Principal      = $identityRef
                Rights         = $rights
                AccessType     = $ace.AccessControlType.ToString()
                IsLegitimate   = $isLegitimate
                IsHighRisk     = $isHighRisk
                ObjectType     = $ace.ObjectType.ToString()
                AdminSDHolderDN = $adminSDHolderDN
                CollectedAt    = (Get-Date).ToString('u')
            }
        }

        $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "threat-adminsdholder-acl-$Timestamp.json") -Force
        $nonStandard = $results | Where-Object { -not $_.IsLegitimate -and $_.IsHighRisk }
        Write-Host "    AdminSDHolder ACEs: $($results.Count) total, $($nonStandard.Count) non-standard high-risk" -ForegroundColor $(if ($nonStandard.Count -gt 0) { 'Red' } else { 'DarkGray' })
    } catch {
        Write-Warning "AdminSDHolder ACL check failed: $_"
        @() | ConvertTo-Json | Out-File (Join-Path $OutputFolder "threat-adminsdholder-acl-$Timestamp.json") -Force
    }
}

function Get-ASREPRoastableUsers {
    <#
    .SYNOPSIS
    Finds enabled accounts with Kerberos pre-authentication disabled (AS-REP roastable).
    Maps to MITRE T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )

    Write-Host "  Checking for AS-REP roastable accounts..." -ForegroundColor Gray

    $results = @()

    try {
        $asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
            -Properties SamAccountName, UserPrincipalName, Enabled, AdminCount,
                        PasswordLastSet, LastLogonDate, MemberOf, DoesNotRequirePreAuth `
            -ErrorAction Stop

        foreach ($user in $asrepUsers) {
            $results += [PSCustomObject]@{
                SamAccountName        = $user.SamAccountName
                UserPrincipalName     = $user.UserPrincipalName
                Enabled               = $user.Enabled
                AdminCount            = $user.AdminCount
                PasswordLastSet       = $user.PasswordLastSet
                LastLogonDate         = $user.LastLogonDate
                MemberOf              = ($user.MemberOf -join '; ')
                DoesNotRequirePreAuth = $true
                CollectedAt           = (Get-Date).ToString('u')
            }
        }

        $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "threat-asrep-accounts-$Timestamp.json") -Force
        $enabled = $results | Where-Object { $_.Enabled -eq $true }
        Write-Host "    AS-REP roastable accounts: $($results.Count) total ($($enabled.Count) enabled)" -ForegroundColor $(if ($enabled.Count -gt 0) { 'Yellow' } else { 'DarkGray' })
    } catch {
        Write-Warning "AS-REP roastable account check failed: $_"
        @() | ConvertTo-Json | Out-File (Join-Path $OutputFolder "threat-asrep-accounts-$Timestamp.json") -Force
    }
}

function Get-ConstrainedDelegationMisconfig {
    <#
    .SYNOPSIS
    Separates delegation types for targeted analysis.
    Unconstrained delegation (TrustedForDelegation) is highest risk.
    Protocol transition (TrustedToAuthForDelegation) enables S4U2Self impersonation.
    Maps to MITRE T1550.003 (Pass the Ticket).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )

    Write-Host "  Checking delegation misconfigurations..." -ForegroundColor Gray

    $results = @()

    try {
        # Get DCs to exclude from unconstrained delegation findings (DCs legitimately have this)
        $dcNames = (Get-ADDomainController -Filter *).Name

        # Users and computers with any delegation
        $delegObjects = Get-ADObject -Filter { (TrustedForDelegation -eq $true) -or (TrustedToAuthForDelegation -eq $true) } `
            -Properties SamAccountName, ObjectClass, TrustedForDelegation, TrustedToAuthForDelegation,
                        'msDS-AllowedToDelegateTo', AdminCount, Enabled, OperatingSystem `
            -ErrorAction SilentlyContinue

        foreach ($obj in $delegObjects) {
            $delegType = 'None'
            $riskLevel = 'Low'

            if ($obj.TrustedForDelegation -eq $true) {
                $isDC = $dcNames -contains $obj.SamAccountName.TrimEnd('$')
                $delegType = if ($isDC) { 'Unconstrained (DC - Legitimate)' } else { 'Unconstrained' }
                $riskLevel  = if ($isDC) { 'Info' } else { 'Critical' }
            } elseif ($obj.TrustedToAuthForDelegation -eq $true) {
                $delegType = 'Protocol Transition (S4U2Self)'
                $riskLevel = 'High'
            }

            $delegTo = $obj.'msDS-AllowedToDelegateTo'
            $delegToList = if ($delegTo) { ($delegTo -join '; ') } else { '' }

            $results += [PSCustomObject]@{
                SamAccountName         = $obj.SamAccountName
                ObjectClass            = $obj.ObjectClass
                DelegationType         = $delegType
                RiskLevel              = $riskLevel
                DelegatesTo            = $delegToList
                AdminCount             = $obj.AdminCount
                Enabled                = $obj.Enabled
                OperatingSystem        = $obj.OperatingSystem
                CollectedAt            = (Get-Date).ToString('u')
            }
        }

        $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "threat-constrained-delegation-$Timestamp.json") -Force
        $unconstrained = $results | Where-Object { $_.DelegationType -eq 'Unconstrained' }
        Write-Host "    Delegation misconfigs: $($unconstrained.Count) unconstrained (non-DC)" -ForegroundColor $(if ($unconstrained.Count -gt 0) { 'Red' } else { 'DarkGray' })
    } catch {
        Write-Warning "Delegation misconfig check failed: $_"
        @() | ConvertTo-Json | Out-File (Join-Path $OutputFolder "threat-constrained-delegation-$Timestamp.json") -Force
    }
}

function Get-PrivilegedGroupChanges {
    <#
    .SYNOPSIS
    Reads Security Event Log for privileged group membership changes (last 7 days).
    Event IDs: 4728 (global), 4732 (local), 4756 (universal) - member added.
    Maps to MITRE T1098 (Account Manipulation).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )

    Write-Host "  Checking privileged group membership changes (last 7 days)..." -ForegroundColor Gray

    $tier0Groups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
    $lookbackDays = 7
    $startTime = (Get-Date).AddDays(-$lookbackDays)

    $results = @()

    try {
        # Event IDs for member added to security groups
        $eventIds = @(4728, 4732, 4756)
        $filterHash = @{
            LogName   = 'Security'
            Id        = $eventIds
            StartTime = $startTime
        }

        $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt $startTime }

        foreach ($evt in $events) {
            try {
                $xml = [xml]$evt.ToXml()
                $data = $xml.Event.EventData.Data

                $memberName = ($data | Where-Object { $_.Name -eq 'MemberName' }).'#text'
                $groupName  = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $subjectUser = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                $subjectDomain = ($data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'

                $isTier0 = $tier0Groups -contains $groupName

                $results += [PSCustomObject]@{
                    EventId       = $evt.Id
                    TimeCreated   = $evt.TimeCreated.ToString('u')
                    MemberAdded   = $memberName
                    GroupName     = $groupName
                    ChangedBy     = "$subjectDomain\$subjectUser"
                    IsTier0Group  = $isTier0
                    CollectedAt   = (Get-Date).ToString('u')
                }
            } catch {
                # Skip malformed events
            }
        }

        $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "threat-group-changes-$Timestamp.json") -Force
        $tier0Changes = $results | Where-Object { $_.IsTier0Group }
        Write-Host "    Privileged group changes: $($results.Count) total, $($tier0Changes.Count) tier-0" -ForegroundColor $(if ($tier0Changes.Count -gt 0) { 'Red' } else { 'DarkGray' })
    } catch {
        Write-Warning "Privileged group change check failed (may need to run on a DC): $_"
        @() | ConvertTo-Json | Out-File (Join-Path $OutputFolder "threat-group-changes-$Timestamp.json") -Force
    }
}

function Get-WMISubscriptionPersistence {
    <#
    .SYNOPSIS
    Enumerates WMI event subscriptions that could be used for persistence.
    Non-Microsoft WMI consumers are a strong indicator of persistence.
    Maps to MITRE T1546.003 (Event Triggered Execution: Windows Management Instrumentation).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )

    Write-Host "  Checking WMI event subscription persistence..." -ForegroundColor Gray

    $results = @()

    try {
        $filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' `
            -ErrorAction SilentlyContinue

        $consumers = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' `
            -ErrorAction SilentlyContinue

        $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' `
            -ErrorAction SilentlyContinue

        foreach ($binding in $bindings) {
            $filterRef  = $binding.Filter.ToString()
            $consumerRef = $binding.Consumer.ToString()

            # Match filter
            $matchedFilter = $filters | Where-Object { $_.Name -and $filterRef -match [regex]::Escape($_.Name) } | Select-Object -First 1
            # Match consumer
            $matchedConsumer = $consumers | Where-Object { $_.Name -and $consumerRef -match [regex]::Escape($_.Name) } | Select-Object -First 1

            # Microsoft/Windows built-in subscriptions are expected
            $filterName   = if ($matchedFilter) { $matchedFilter.Name } else { $filterRef }
            $consumerName = if ($matchedConsumer) { $matchedConsumer.Name } else { $consumerRef }
            $isBuiltIn = ($filterName -match '^(SCM|BVTFilter|TSlogonEvents|TSlogonFilter|RmAssistEventFilter|NAP|MSFT_|Windows|Microsoft)' -or
                          $consumerName -match '^(SCM|BVTConsumer|MSFT_|Microsoft|ScrubberConsumer)')

            $results += [PSCustomObject]@{
                FilterName      = $filterName
                ConsumerName    = $consumerName
                ConsumerQuery   = if ($matchedFilter) { $matchedFilter.Query } else { '' }
                ConsumerScript  = if ($matchedConsumer -and $matchedConsumer.PSObject.Properties['ScriptText']) { $matchedConsumer.ScriptText } else { '' }
                ConsumerExecutable = if ($matchedConsumer -and $matchedConsumer.PSObject.Properties['ExecutablePath']) { $matchedConsumer.ExecutablePath } else { '' }
                IsBuiltIn       = $isBuiltIn
                CollectedAt     = (Get-Date).ToString('u')
            }
        }

        $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "threat-wmi-subscriptions-$Timestamp.json") -Force
        $suspicious = $results | Where-Object { -not $_.IsBuiltIn }
        Write-Host "    WMI subscriptions: $($results.Count) total, $($suspicious.Count) non-built-in" -ForegroundColor $(if ($suspicious.Count -gt 0) { 'Red' } else { 'DarkGray' })
    } catch {
        Write-Warning "WMI subscription check failed: $_"
        @() | ConvertTo-Json | Out-File (Join-Path $OutputFolder "threat-wmi-subscriptions-$Timestamp.json") -Force
    }
}

function Get-ACLAbusePaths {
    <#
    .SYNOPSIS
    Identifies non-admin principals with dangerous rights (GenericAll/WriteDacl/WriteOwner)
    on privileged OUs and user objects — classic ACL abuse paths for privilege escalation.
    Maps to MITRE T1222.001 (File and Directory Permissions Modification: Windows).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )

    Write-Host "  Scanning for ACL abuse paths on privileged OUs..." -ForegroundColor Gray

    $legitimatePrincipals = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'SYSTEM', 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators',
        'Account Operators', 'CREATOR OWNER', 'Pre-Windows 2000 Compatible Access'
    )

    $dangerousRights = 'GenericAll|WriteDacl|WriteOwner|GenericWrite'

    $results = @()

    try {
        $domain = Get-ADDomain
        # Get all OUs
        $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName -ErrorAction SilentlyContinue

        foreach ($ou in $ous) {
            try {
                $ouPath = "AD:$($ou.DistinguishedName)"
                $acl = Get-Acl -Path $ouPath -ErrorAction SilentlyContinue
                if (-not $acl) { continue }

                foreach ($ace in $acl.Access) {
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    if ($rights -notmatch $dangerousRights) { continue }

                    $identityRef = $ace.IdentityReference.ToString()
                    $isLegitimate = $false
                    foreach ($legit in $legitimatePrincipals) {
                        if ($identityRef -match [regex]::Escape($legit)) {
                            $isLegitimate = $true
                            break
                        }
                    }

                    if (-not $isLegitimate) {
                        $results += [PSCustomObject]@{
                            ObjectDN       = $ou.DistinguishedName
                            ObjectType     = 'OU'
                            Principal      = $identityRef
                            Rights         = $rights
                            AccessType     = $ace.AccessControlType.ToString()
                            IsLegitimate   = $false
                            CollectedAt    = (Get-Date).ToString('u')
                        }
                    }
                }
            } catch {
                # Skip OUs that can't be read
            }
        }

        $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "threat-acl-abusepaths-$Timestamp.json") -Force
        Write-Host "    ACL abuse paths: $($results.Count) non-standard dangerous ACEs found" -ForegroundColor $(if ($results.Count -gt 0) { 'Yellow' } else { 'DarkGray' })
    } catch {
        Write-Warning "ACL abuse path scan failed: $_"
        @() | ConvertTo-Json | Out-File (Join-Path $OutputFolder "threat-acl-abusepaths-$Timestamp.json") -Force
    }
}

Export-ModuleMember -Function @(
    'Invoke-ThreatHuntingCollection',
    'Get-DCSyncRights',
    'Get-AdminSDHolderACL',
    'Get-ASREPRoastableUsers',
    'Get-ConstrainedDelegationMisconfig',
    'Get-PrivilegedGroupChanges',
    'Get-WMISubscriptionPersistence',
    'Get-ACLAbusePaths'
)
