# MITRE-Mapper.psm1
# Maps security findings to MITRE ATT&CK techniques and adds risk scoring

function Get-MITRETechniqueMapping {
    <#
    .SYNOPSIS
    Returns MITRE ATT&CK technique mappings for security findings
    #>
    
    return @{
        'StaleUsers' = @{
            Techniques = @('T1078.002')  # Valid Accounts: Domain Accounts
            TacticPhases = @('Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion')
            SecurityCategory = 'Attack Surface Reduction'
            HealthCategory = 'Lifecycle Management'
            RiskScore = 6
            BusinessImpact = 'Medium'
        }
        'PasswordNeverExpires' = @{
            Techniques = @('T1078', 'T1110')  # Valid Accounts, Brute Force
            TacticPhases = @('Initial Access', 'Credential Access')
            SecurityCategory = 'Credential Protection'
            HealthCategory = 'Lifecycle Management'
            RiskScore = 7
            BusinessImpact = 'High'
        }
        'KerberosDelegation' = @{
            Techniques = @('T1558.003')  # Kerberoasting
            TacticPhases = @('Credential Access', 'Lateral Movement')
            SecurityCategory = 'Lateral Movement Prevention'
            HealthCategory = 'Performance Optimization'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'UnconstrainedDelegation' = @{
            Techniques = @('T1558.003', 'T1550.003')  # Kerberoasting, Pass the Ticket
            TacticPhases = @('Credential Access', 'Lateral Movement')
            SecurityCategory = 'Lateral Movement Prevention'
            HealthCategory = 'Performance Optimization'
            RiskScore = 10
            BusinessImpact = 'Critical'
        }
        'KrbtgtPassword' = @{
            Techniques = @('T1558.001')  # Golden Ticket
            TacticPhases = @('Credential Access', 'Persistence')
            SecurityCategory = 'Lateral Movement Prevention'
            HealthCategory = 'Operational Excellence'
            RiskScore = 10
            BusinessImpact = 'Critical'
        }
        'SPNAccounts' = @{
            Techniques = @('T1558.003')  # Kerberoasting
            TacticPhases = @('Credential Access')
            SecurityCategory = 'Attack Surface Reduction'
            HealthCategory = 'Lifecycle Management'
            RiskScore = 7
            BusinessImpact = 'High'
        }
        'OversizedGroups' = @{
            Techniques = @('T1069.002')  # Domain Groups Discovery
            TacticPhases = @('Discovery')
            SecurityCategory = 'Privileged Access Management'
            HealthCategory = 'Performance Optimization'
            RiskScore = 4
            BusinessImpact = 'Medium'
        }
        'PrivilegedRoles' = @{
            Techniques = @('T1078.004')  # Valid Accounts: Cloud Accounts
            TacticPhases = @('Persistence', 'Privilege Escalation')
            SecurityCategory = 'Privileged Access Management'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'NoConditionalAccess' = @{
            Techniques = @('T1078', 'T1110')  # Valid Accounts, Brute Force
            TacticPhases = @('Initial Access', 'Defense Evasion')
            SecurityCategory = 'Attack Surface Reduction'
            HealthCategory = 'Modernization'
            RiskScore = 9
            BusinessImpact = 'Critical'
        }
        'NoMFA' = @{
            Techniques = @('T1078', 'T1110', 'T1566')  # Valid Accounts, Brute Force, Phishing
            TacticPhases = @('Initial Access', 'Credential Access')
            SecurityCategory = 'Credential Protection'
            HealthCategory = 'Modernization'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'LegacyAuth' = @{
            Techniques = @('T1078', 'T1589')  # Valid Accounts, Credential Harvesting
            TacticPhases = @('Initial Access', 'Defense Evasion')
            SecurityCategory = 'Attack Surface Reduction'
            HealthCategory = 'Modernization'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'RiskyServicePrincipals' = @{
            Techniques = @('T1078.004', 'T1550')  # Cloud Accounts, Use Alternate Authentication
            TacticPhases = @('Persistence', 'Privilege Escalation', 'Defense Evasion')
            SecurityCategory = 'Privileged Access Management'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 7
            BusinessImpact = 'High'
        }
        'OAuthPermissions' = @{
            Techniques = @('T1528', 'T1098')  # Steal Application Access Token, Account Manipulation
            TacticPhases = @('Credential Access', 'Persistence')
            SecurityCategory = 'Data Protection'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 6
            BusinessImpact = 'Medium'
        }
        'UnlinkedGPOs' = @{
            Techniques = @('T1484')  # Domain Policy Modification
            TacticPhases = @('Privilege Escalation', 'Defense Evasion')
            SecurityCategory = 'Attack Surface Reduction'
            HealthCategory = 'Modernization'
            RiskScore = 3
            BusinessImpact = 'Low'
        }
        'OUDelegation' = @{
            Techniques = @('T1098', 'T1484')  # Account Manipulation, Domain Policy Modification
            TacticPhases = @('Persistence', 'Privilege Escalation')
            SecurityCategory = 'Privileged Access Management'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 6
            BusinessImpact = 'Medium'
        }
        # --- Threat Hunting Techniques ---
        'DCSyncRights' = @{
            Techniques = @('T1003.006')  # OS Credential Dumping: DCSync
            TacticPhases = @('Credential Access')
            SecurityCategory = 'Lateral Movement Prevention'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 10
            BusinessImpact = 'Critical'
        }
        'AdminSDHolderAbuse' = @{
            Techniques = @('T1098')  # Account Manipulation
            TacticPhases = @('Persistence', 'Privilege Escalation')
            SecurityCategory = 'Privileged Access Management'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 10
            BusinessImpact = 'Critical'
        }
        'ImpossibleTravel' = @{
            Techniques = @('T1078')  # Valid Accounts
            TacticPhases = @('Initial Access', 'Defense Evasion')
            SecurityCategory = 'Identity Protection'
            HealthCategory = 'Operational Excellence'
            RiskScore = 9
            BusinessImpact = 'Critical'
        }
        'BruteForce' = @{
            Techniques = @('T1110.003')  # Password Spraying
            TacticPhases = @('Credential Access')
            SecurityCategory = 'Credential Protection'
            HealthCategory = 'Operational Excellence'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'ASREPRoast' = @{
            Techniques = @('T1558.004')  # AS-REP Roasting
            TacticPhases = @('Credential Access')
            SecurityCategory = 'Lateral Movement Prevention'
            HealthCategory = 'Lifecycle Management'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'WMIPersistence' = @{
            Techniques = @('T1546.003')  # Event Triggered Execution: WMI
            TacticPhases = @('Persistence', 'Privilege Escalation')
            SecurityCategory = 'Endpoint Hardening'
            HealthCategory = 'Operational Excellence'
            RiskScore = 9
            BusinessImpact = 'Critical'
        }
        'ACLAbusePath' = @{
            Techniques = @('T1222.001')  # File and Directory Permissions Modification: Windows
            TacticPhases = @('Defense Evasion')
            SecurityCategory = 'Privileged Access Management'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        # --- Mimecast / Email Security Techniques ---
        'SpearphishingLink' = @{
            Techniques = @('T1566.002')  # Phishing: Spearphishing Link
            TacticPhases = @('Initial Access')
            SecurityCategory = 'Email Security'
            HealthCategory = 'Operational Excellence'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'SpearphishingAttachment' = @{
            Techniques = @('T1566.001')  # Phishing: Spearphishing Attachment
            TacticPhases = @('Initial Access')
            SecurityCategory = 'Email Security'
            HealthCategory = 'Operational Excellence'
            RiskScore = 8
            BusinessImpact = 'High'
        }
        'EmailExfiltration' = @{
            Techniques = @('T1048')  # Exfiltration Over Alternative Protocol
            TacticPhases = @('Exfiltration')
            SecurityCategory = 'Data Exfiltration'
            HealthCategory = 'Compliance &amp; Governance'
            RiskScore = 9
            BusinessImpact = 'Critical'
        }
        'EmailCollection' = @{
            Techniques = @('T1114')  # Email Collection
            TacticPhases = @('Collection')
            SecurityCategory = 'Email Security'
            HealthCategory = 'Operational Excellence'
            RiskScore = 7
            BusinessImpact = 'High'
        }
        'Impersonation' = @{
            Techniques = @('T1656', 'T1566.001')  # Impersonation, Spearphishing Attachment
            TacticPhases = @('Defense Evasion', 'Initial Access')
            SecurityCategory = 'Email Security'
            HealthCategory = 'Operational Excellence'
            RiskScore = 8
            BusinessImpact = 'High'
        }
    }
}

function Get-MITRETechniqueInfo {
    <#
    .SYNOPSIS
    Returns detailed information about a MITRE ATT&CK technique
    
    .PARAMETER TechniqueID
    MITRE technique ID (e.g., 'T1078')
    #>
    param([string]$TechniqueID)
    
    $techniques = @{
        'T1078' = @{
            Name = 'Valid Accounts'
            Description = 'Adversaries may obtain and abuse credentials of existing accounts'
            URL = 'https://attack.mitre.org/techniques/T1078/'
        }
        'T1078.002' = @{
            Name = 'Valid Accounts: Domain Accounts'
            Description = 'Adversaries may obtain and abuse credentials of domain accounts'
            URL = 'https://attack.mitre.org/techniques/T1078/002/'
        }
        'T1078.004' = @{
            Name = 'Valid Accounts: Cloud Accounts'
            Description = 'Adversaries may obtain and abuse credentials of cloud accounts'
            URL = 'https://attack.mitre.org/techniques/T1078/004/'
        }
        'T1110' = @{
            Name = 'Brute Force'
            Description = 'Adversaries may use brute force techniques to gain access'
            URL = 'https://attack.mitre.org/techniques/T1110/'
        }
        'T1558' = @{
            Name = 'Steal or Forge Kerberos Tickets'
            Description = 'Adversaries may attempt to subvert Kerberos authentication'
            URL = 'https://attack.mitre.org/techniques/T1558/'
        }
        'T1558.001' = @{
            Name = 'Golden Ticket'
            Description = 'Adversaries may forge Kerberos TGTs to maintain persistence'
            URL = 'https://attack.mitre.org/techniques/T1558/001/'
        }
        'T1558.003' = @{
            Name = 'Kerberoasting'
            Description = 'Adversaries may abuse a valid Kerberos ticket-granting ticket to obtain service account credentials'
            URL = 'https://attack.mitre.org/techniques/T1558/003/'
        }
        'T1550' = @{
            Name = 'Use Alternate Authentication Material'
            Description = 'Adversaries may use alternate authentication material'
            URL = 'https://attack.mitre.org/techniques/T1550/'
        }
        'T1550.003' = @{
            Name = 'Pass the Ticket'
            Description = 'Adversaries may pass Kerberos tickets to move laterally'
            URL = 'https://attack.mitre.org/techniques/T1550/003/'
        }
        'T1484' = @{
            Name = 'Domain Policy Modification'
            Description = 'Adversaries may modify domain policy to evade defenses'
            URL = 'https://attack.mitre.org/techniques/T1484/'
        }
        'T1566' = @{
            Name = 'Phishing'
            Description = 'Adversaries may send phishing messages to gain access'
            URL = 'https://attack.mitre.org/techniques/T1566/'
        }
        'T1098' = @{
            Name = 'Account Manipulation'
            Description = 'Adversaries may manipulate accounts to maintain access'
            URL = 'https://attack.mitre.org/techniques/T1098/'
        }
        'T1069.002' = @{
            Name = 'Permission Groups Discovery: Domain Groups'
            Description = 'Adversaries may attempt to find domain-level groups'
            URL = 'https://attack.mitre.org/techniques/T1069/002/'
        }
        'T1528' = @{
            Name = 'Steal Application Access Token'
            Description = 'Adversaries may steal application access tokens'
            URL = 'https://attack.mitre.org/techniques/T1528/'
        }
        'T1589' = @{
            Name = 'Gather Victim Identity Information'
            Description = 'Adversaries may gather information about victim identities'
            URL = 'https://attack.mitre.org/techniques/T1589/'
        }
        'T1136' = @{
            Name = 'Create Account'
            Description = 'Adversaries may create accounts to maintain access'
            URL = 'https://attack.mitre.org/techniques/T1136/'
        }
        'T1003.006' = @{
            Name = 'OS Credential Dumping: DCSync'
            Description = 'Adversaries may use DCSync to dump credentials from Active Directory'
            URL = 'https://attack.mitre.org/techniques/T1003/006/'
        }
        'T1558.004' = @{
            Name = 'Steal or Forge Kerberos Tickets: AS-REP Roasting'
            Description = 'Adversaries may reveal credentials of accounts with pre-authentication disabled'
            URL = 'https://attack.mitre.org/techniques/T1558/004/'
        }
        'T1110.003' = @{
            Name = 'Brute Force: Password Spraying'
            Description = 'Adversaries may use a single password against many accounts to avoid lockouts'
            URL = 'https://attack.mitre.org/techniques/T1110/003/'
        }
        'T1546.003' = @{
            Name = 'Event Triggered Execution: Windows Management Instrumentation'
            Description = 'Adversaries may establish persistence using WMI event subscriptions'
            URL = 'https://attack.mitre.org/techniques/T1546/003/'
        }
        'T1222.001' = @{
            Name = 'File and Directory Permissions Modification: Windows'
            Description = 'Adversaries may modify file or directory permissions to evade access controls'
            URL = 'https://attack.mitre.org/techniques/T1222/001/'
        }
        'T1566.001' = @{
            Name = 'Phishing: Spearphishing Attachment'
            Description = 'Adversaries may send spearphishing emails with malicious attachments'
            URL = 'https://attack.mitre.org/techniques/T1566/001/'
        }
        'T1566.002' = @{
            Name = 'Phishing: Spearphishing Link'
            Description = 'Adversaries may send spearphishing emails with a malicious link'
            URL = 'https://attack.mitre.org/techniques/T1566/002/'
        }
        'T1048' = @{
            Name = 'Exfiltration Over Alternative Protocol'
            Description = 'Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel'
            URL = 'https://attack.mitre.org/techniques/T1048/'
        }
        'T1114' = @{
            Name = 'Email Collection'
            Description = 'Adversaries may target user email to collect sensitive information'
            URL = 'https://attack.mitre.org/techniques/T1114/'
        }
        'T1656' = @{
            Name = 'Impersonation'
            Description = 'Adversaries may impersonate a trusted person or organization to persuade and trick targets'
            URL = 'https://attack.mitre.org/techniques/T1656/'
        }
    }
    
    if ($techniques.ContainsKey($TechniqueID)) {
        return $techniques[$TechniqueID]
    }
    
    return @{
        Name = "Unknown Technique"
        Description = "No description available for $TechniqueID"
        URL = "https://attack.mitre.org/techniques/$TechniqueID/"
    }
}

function Add-MITREMapping {
    <#
    .SYNOPSIS
    Enriches findings with MITRE ATT&CK technique mappings and enhanced categorization
    
    .PARAMETER Findings
    Array of finding objects to enrich
    
    .EXAMPLE
    $enrichedFindings = Add-MITREMapping -Findings $findings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings
    )
    
    Write-Host "Enriching findings with MITRE ATT&CK mappings..." -ForegroundColor Cyan
    
    $mappings = Get-MITRETechniqueMapping
    $enrichedFindings = @()
    
    foreach ($finding in $Findings) {
        # Determine risk type from finding or category
        $riskType = $null
        
        # Try to match finding text to risk type
        if ($finding.Finding -match 'inactive.*90 days') { $riskType = 'StaleUsers' }
        elseif ($finding.Finding -match 'PasswordNeverExpires') { $riskType = 'PasswordNeverExpires' }
        elseif ($finding.Finding -match 'Kerberos delegation' -and $finding.Finding -match 'user') { $riskType = 'KerberosDelegation' }
        elseif ($finding.Finding -match 'Unconstrained Delegation') { $riskType = 'UnconstrainedDelegation' }
        elseif ($finding.Finding -match 'krbtgt') { $riskType = 'KrbtgtPassword' }
        elseif ($finding.Finding -match 'SPN') { $riskType = 'SPNAccounts' }
        elseif ($finding.Finding -match 'groups.*500') { $riskType = 'OversizedGroups' }
        elseif ($finding.Area -match 'Entra Roles' -or $finding.Finding -match 'Administrator') { $riskType = 'PrivilegedRoles' }
        elseif ($finding.Finding -match 'No Conditional Access') { $riskType = 'NoConditionalAccess' }
        elseif ($finding.Finding -match 'without MFA') { $riskType = 'NoMFA' }
        elseif ($finding.Finding -match 'legacy.*protocol') { $riskType = 'LegacyAuth' }
        elseif ($finding.Area -match 'Service Principal') { $riskType = 'RiskyServicePrincipals' }
        elseif ($finding.Area -match 'OAuth') { $riskType = 'OAuthPermissions' }
        elseif ($finding.Finding -match 'no links') { $riskType = 'UnlinkedGPOs' }
        elseif ($finding.Area -match 'OU Delegation') { $riskType = 'OUDelegation' }
        elseif ($finding.Finding -match 'DCSync') { $riskType = 'DCSyncRights' }
        elseif ($finding.Finding -match 'AdminSDHolder') { $riskType = 'AdminSDHolderAbuse' }
        elseif ($finding.Finding -match 'impossible travel') { $riskType = 'ImpossibleTravel' }
        elseif ($finding.Finding -match 'Brute force|Password spray') { $riskType = 'BruteForce' }
        elseif ($finding.Finding -match 'AS-REP roast') { $riskType = 'ASREPRoast' }
        elseif ($finding.Finding -match 'WMI subscription') { $riskType = 'WMIPersistence' }
        elseif ($finding.Finding -match 'ACL abuse paths') { $riskType = 'ACLAbusePath' }
        elseif ($finding.Finding -match 'Malicious URL Click|Spearphishing Campaign') { $riskType = 'SpearphishingLink' }
        elseif ($finding.Finding -match 'Impersonation Attack|BEC Campaign') { $riskType = 'Impersonation' }
        elseif ($finding.Finding -match 'DLP Violation|High Volume DLP') { $riskType = 'EmailExfiltration' }
        elseif ($finding.Finding -match 'Email.*Forward|Suspicious.*Forward') { $riskType = 'EmailCollection' }
        elseif ($finding.Finding -match 'Email Password Spray') { $riskType = 'BruteForce' }
        elseif ($finding.Category -eq 'Email Security') { $riskType = 'SpearphishingLink' }
        
        if ($riskType -and $mappings.ContainsKey($riskType)) {
            $mapping = $mappings[$riskType]
            
            # Add MITRE fields to finding
            $finding | Add-Member -NotePropertyName 'MITRETechniques' -NotePropertyValue ($mapping.Techniques -join ', ') -Force
            $finding | Add-Member -NotePropertyName 'MITRETactics' -NotePropertyValue ($mapping.TacticPhases -join ', ') -Force
            $finding | Add-Member -NotePropertyName 'SecurityCategory' -NotePropertyValue $mapping.SecurityCategory -Force
            $finding | Add-Member -NotePropertyName 'HealthCategory' -NotePropertyValue $mapping.HealthCategory -Force
            $finding | Add-Member -NotePropertyName 'RiskScore' -NotePropertyValue $mapping.RiskScore -Force
            $finding | Add-Member -NotePropertyName 'BusinessImpact' -NotePropertyValue $mapping.BusinessImpact -Force
        } else {
            # Default mapping for unmapped findings
            $finding | Add-Member -NotePropertyName 'MITRETechniques' -NotePropertyValue 'N/A' -Force
            $finding | Add-Member -NotePropertyName 'MITRETactics' -NotePropertyValue 'N/A' -Force
            $finding | Add-Member -NotePropertyName 'SecurityCategory' -NotePropertyValue 'General Security' -Force
            $finding | Add-Member -NotePropertyName 'HealthCategory' -NotePropertyValue 'General' -Force
            
            # Calculate risk score with context
            $areaValue = if ($finding.Area) { $finding.Area } else { '' }
            $findingValue = if ($finding.Finding) { $finding.Finding } else { '' }
            $score = Get-NumericRiskScore -Severity $finding.Severity -Area $areaValue -Finding $findingValue
            $finding | Add-Member -NotePropertyName 'RiskScore' -NotePropertyValue $score -Force
            
            # Calculate business impact with context
            $severityValue = if ($finding.Severity) { $finding.Severity } else { '' }
            $biz = Get-BusinessImpact -Finding @{ Area=$areaValue; Finding=$findingValue; Severity=$severityValue }
            $finding | Add-Member -NotePropertyName 'BusinessImpact' -NotePropertyValue $biz -Force
        }
        
        $enrichedFindings += $finding
    }
    
    $enrichedCount = $enrichedFindings.Count
    Write-Host "  [OK] Enriched $enrichedCount findings with MITRE mappings" -ForegroundColor Green
    
    return $enrichedFindings
}

function Get-NumericRiskScore {
    <#
    .SYNOPSIS
    Converts severity to numeric risk score with optional context-based weighting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        
        [string]$Area = '',
        [string]$Finding = ''
    )
    
    $base = switch ($Severity) {
        'Critical' { 95 }
        'High'     { 80 }
        'Medium'   { 55 }
        'Low'      { 30 }
        default    { 10 }
    }
    
    # Add context-based weight adjustments
    $w = 0
    if ($Area -match 'Privileged|Global Admin|Domain Admin') { $w += 10 }
    if ($Area -match 'OAuth|Service Principal')              { $w += 5  }
    if ($Finding -match 'No Conditional Access|legacy auth') { $w += 5  }
    
    # Clamp to 0-100 range
    [Math]::Min(100, [Math]::Max(0, $base + $w))
}

function Get-BusinessImpact {
    <#
    .SYNOPSIS
    Classifies business impact based on finding context
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )

    $area     = if ($Finding['Area']) { $Finding['Area'].ToString() } else { '' }
    $msg      = if ($Finding['Finding']) { $Finding['Finding'].ToString() } else { '' }
    $severity = if ($Finding['Severity']) { $Finding['Severity'].ToString() } else { '' }

    # Rule-based impact classification
    if ($area -match 'Privileged|Global Admin|Domain Admin' -or $msg -match 'MFA.*lack|PIM.*missing') { 
        return 'High: Privileged Access' 
    }
    if ($area -match 'OAuth|Service Principal|Application' -and $msg -match 'ReadWrite|expiring|long-lived') { 
        return 'High: App-to-tenant risk' 
    }
    if ($area -match 'Conditional Access' -and $msg -match 'No .* policies') { 
        return 'High: Zero Trust gap' 
    }
    if ($area -match 'Legacy Auth|IMAP|POP|SMTP') { 
        return 'Medium: Credential/Session Risk' 
    }
    if ($area -match 'Password Policy|FGPP') { 
        return 'Medium: Identity Hygiene' 
    }
    if ($area -match 'SPN|Kerberoast') { 
        return 'Medium: Lateral Movement Surface' 
    }
    if ($area -match 'GPO|OU Delegation|Trusts') { 
        return 'Medium: Configuration Risk' 
    }

    # Fallback to severity-based classification
    switch ($severity) {
        'High'   { 'High: General' }
        'Medium' { 'Medium: General' }
        'Low'    { 'Low: General' }
        default  { 'Informational' }
    }
}

function New-MITRECategoryReport {
    <#
    .SYNOPSIS
    Generates a categorized view of findings by MITRE tactics and security categories
    
    .PARAMETER EnrichedFindings
    Array of findings enriched with MITRE mappings
    
    .PARAMETER OutputFolder
    Path to output folder
    
    .PARAMETER Timestamp
    Timestamp for file naming
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$EnrichedFindings,
        
        [Parameter(Mandatory)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory)]
        [string]$Timestamp
    )
    
    Write-Host "Generating MITRE category reports..." -ForegroundColor Cyan
    
    # Group by security category
    $bySecurityCategory = $EnrichedFindings | Group-Object SecurityCategory | ForEach-Object {
        [PSCustomObject]@{
            Category = $_.Name
            Count = $_.Count
            TotalRiskScore = ($_.Group | Measure-Object -Property RiskScore -Sum).Sum
            HighSeverity = ($_.Group | Where-Object { $_.Severity -eq 'High' }).Count
            MediumSeverity = ($_.Group | Where-Object { $_.Severity -eq 'Medium' }).Count
            LowSeverity = ($_.Group | Where-Object { $_.Severity -eq 'Low' }).Count
        }
    } | Sort-Object TotalRiskScore -Descending
    
    # Group by MITRE tactic
    $byTactic = @()
    foreach ($finding in $EnrichedFindings) {
        if ($finding.MITRETactics -and $finding.MITRETactics -ne 'N/A') {
            $tactics = $finding.MITRETactics -split ',\s*'
            foreach ($tactic in $tactics) {
                $byTactic += [PSCustomObject]@{
                    Tactic = $tactic.Trim()
                    Finding = $finding.Finding
                    Severity = $finding.Severity
                    Technique = $finding.MITRETechniques
                }
            }
        }
    }
    
    $tacticSummary = $byTactic | Group-Object Tactic | ForEach-Object {
        $uniqueTechs = $_.Group | Select-Object -ExpandProperty Technique -Unique
        $techList = $uniqueTechs -join "; "
        [PSCustomObject]@{
            Tactic = $_.Name
            FindingCount = $_.Count
            HighSeverity = ($_.Group | Where-Object { $_.Severity -eq 'High' }).Count
            Techniques = $techList
        }
    } | Sort-Object FindingCount -Descending
    
    # Export category reports
    $secCatFilename = "findings-by-security-category-{0}.csv" -f $Timestamp
    $securityCatCsv = Join-Path $OutputFolder $secCatFilename
    $bySecurityCategory | Export-Csv $securityCatCsv -NoTypeInformation -Force
    
    $tacticFilename = "findings-by-mitre-tactic-{0}.csv" -f $Timestamp
    $tacticCsv = Join-Path $OutputFolder $tacticFilename
    $tacticSummary | Export-Csv $tacticCsv -NoTypeInformation -Force
    
    # Generate summary stats
    $categoryStats = @{
        TotalCategories = $bySecurityCategory.Count
        TotalTactics = $tacticSummary.Count
        TopSecurityCategory = ($bySecurityCategory | Select-Object -First 1).Category
        TopTactic = ($tacticSummary | Select-Object -First 1).Tactic
        FindingsWithMITRE = ($EnrichedFindings | Where-Object { $_.MITRETechniques -ne 'N/A' }).Count
        AverageRiskScore = [math]::Round(($EnrichedFindings | Measure-Object -Property RiskScore -Average).Average, 1)
    }
    
    Write-Host "  [OK] MITRE category report generation complete" -ForegroundColor Green
    
    return [PSCustomObject]@{
        SecurityCategories = $bySecurityCategory
        MITRETactics = $tacticSummary
        Stats = $categoryStats
        SecurityCategoryCsvPath = $securityCatCsv
        TacticCsvPath = $tacticCsv
    }
}

Export-ModuleMember -Function @(
    'Get-MITRETechniqueMapping',
    'Get-MITRETechniqueInfo',
    'Add-MITREMapping',
    'New-MITRECategoryReport',
    'Get-NumericRiskScore',
    'Get-BusinessImpact'
)
