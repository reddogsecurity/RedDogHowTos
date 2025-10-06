<#
.SYNOPSIS
    Enhanced findings categorization with MITRE ATT&CK mapping

.DESCRIPTION
    This script enhances the existing AD assessment findings with:
    1. Security-focused categorization (Attack Surface, Lateral Movement, etc.)
    2. AD Health categorization (Performance, Maintenance, etc.)
    3. MITRE ATT&CK technique mapping
    4. Risk scoring and prioritization
    5. Enhanced HTML reporting with category filters

.PARAMETER AssessmentFolder
    Path to existing AD assessment results

.PARAMETER OutputFolder
    Path for enhanced categorization output
#>

[CmdletBinding()]
param(
    [string]$AssessmentFolder = "$env:TEMP\ADScan",
    [string]$OutputFolder = "$env:TEMP\EnhancedFindings"
)

# Create output folder
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Enhanced Findings Categorization" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# === ENHANCED CATEGORIZATION MAPPING ===
$enhancedCategorization = @{
    # === SECURITY CATEGORIES ===
    'AttackSurface' = @{
        Name = 'Attack Surface Reduction'
        Description = 'Findings that reduce the overall attack surface'
        Icon = '🛡️'
        SubCategories = @('Stale Accounts', 'Unused Permissions', 'Legacy Protocols', 'Unused Applications')
        MITRETechniques = @('T1078', 'T1136', 'T1550', 'T1566')
        RiskWeight = 8
    }
    'LateralMovement' = @{
        Name = 'Lateral Movement Prevention'
        Description = 'Findings that prevent or detect lateral movement'
        Icon = '🕸️'
        SubCategories = @('Kerberos Delegation', 'Trust Relationships', 'Service Accounts', 'Privilege Escalation')
        MITRETechniques = @('T1550', 'T1484', 'T1078', 'T1055', 'T1021')
        RiskWeight = 9
    }
    'CredentialProtection' = @{
        Name = 'Credential Protection'
        Description = 'Findings related to credential security and protection'
        Icon = '🔐'
        SubCategories = @('Password Policies', 'MFA Implementation', 'Credential Storage', 'Account Lockout')
        MITRETechniques = @('T1110', 'T1555', 'T1078', 'T1056')
        RiskWeight = 9
    }
    'PrivilegeAccess' = @{
        Name = 'Privileged Access Management'
        Description = 'Findings related to privileged account security'
        Icon = '👑'
        SubCategories = @('Admin Groups', 'Service Principals', 'Role Assignments', 'PIM Implementation')
        MITRETechniques = @('T1078', 'T1484', 'T1098', 'T1550')
        RiskWeight = 10
    }
    'DetectionResponse' = @{
        Name = 'Detection & Response'
        Description = 'Findings that improve detection and response capabilities'
        Icon = '🔍'
        SubCategories = @('Auditing', 'Logging', 'Monitoring', 'Incident Response')
        MITRETechniques = @('T1562', 'T1070', 'T1055', 'T1036')
        RiskWeight = 7
    }
    'DataProtection' = @{
        Name = 'Data Protection'
        Description = 'Findings related to data security and access control'
        Icon = '📁'
        SubCategories = @('Data Classification', 'Access Controls', 'Encryption', 'Backup Security')
        MITRETechniques = @('T1486', 'T1552', 'T1078', 'T1059')
        RiskWeight = 8
    }
    
    # === AD HEALTH CATEGORIES ===
    'PerformanceOptimization' = @{
        Name = 'Performance Optimization'
        Description = 'Findings that improve AD performance and efficiency'
        Icon = '⚡'
        SubCategories = @('Group Size', 'Query Optimization', 'Replication', 'Index Maintenance')
        MITRETechniques = @()
        RiskWeight = 3
    }
    'LifecycleManagement' = @{
        Name = 'Lifecycle Management'
        Description = 'Findings related to account and resource lifecycle'
        Icon = '🔄'
        SubCategories = @('Account Provisioning', 'Deprovisioning', 'Resource Cleanup', 'License Management')
        MITRETechniques = @('T1078', 'T1136')
        RiskWeight = 5
    }
    'ComplianceGovernance' = @{
        Name = 'Compliance & Governance'
        Description = 'Findings related to compliance and governance requirements'
        Icon = '📋'
        SubCategories = @('Audit Requirements', 'Policy Compliance', 'Access Reviews', 'Documentation')
        MITRETechniques = @('T1562', 'T1078')
        RiskWeight = 6
    }
    'Modernization' = @{
        Name = 'Modernization'
        Description = 'Findings that enable AD modernization and cloud migration'
        Icon = '☁️'
        SubCategories = @('GPO Migration', 'Cloud Integration', 'Zero Trust', 'Modern Authentication')
        MITRETechniques = @('T1550', 'T1078', 'T1566')
        RiskWeight = 4
    }
    'OperationalExcellence' = @{
        Name = 'Operational Excellence'
        Description = 'Findings that improve operational efficiency and reliability'
        Icon = '🔧'
        SubCategories = @('Automation', 'Monitoring', 'Backup', 'Disaster Recovery')
        MITRETechniques = @()
        RiskWeight = 3
    }
}

# === MITRE ATT&CK TECHNIQUE MAPPING ===
$mitreTechniques = @{
    'T1078' = @{
        Name = 'Valid Accounts'
        Description = 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.'
        Link = 'https://attack.mitre.org/techniques/T1078/'
        Phase = 'Initial Access, Persistence, Privilege Escalation, Defense Evasion'
    }
    'T1136' = @{
        Name = 'Create Account'
        Description = 'Adversaries may create an account to maintain access to victim systems.'
        Link = 'https://attack.mitre.org/techniques/T1136/'
        Phase = 'Persistence'
    }
    'T1550' = @{
        Name = 'Use Alternate Authentication Material'
        Description = 'Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to authenticate to a system.'
        Link = 'https://attack.mitre.org/techniques/T1550/'
        Phase = 'Defense Evasion, Lateral Movement'
    }
    'T1566' = @{
        Name = 'Phishing'
        Description = 'Adversaries may send phishing messages to gain access to victim systems.'
        Link = 'https://attack.mitre.org/techniques/T1566/'
        Phase = 'Initial Access'
    }
    'T1484' = @{
        Name = 'Domain Policy Modification'
        Description = 'Adversaries may modify the configuration settings of a domain to evade security measures.'
        Link = 'https://attack.mitre.org/techniques/T1484/'
        Phase = 'Defense Evasion'
    }
    'T1055' = @{
        Name = 'Process Injection'
        Description = 'Adversaries may inject code into processes in order to evade process-based defenses.'
        Link = 'https://attack.mitre.org/techniques/T1055/'
        Phase = 'Defense Evasion, Privilege Escalation'
    }
    'T1021' = @{
        Name = 'Remote Services'
        Description = 'Adversaries may use remote services to initially access and/or persist within a network.'
        Link = 'https://attack.mitre.org/techniques/T1021/'
        Phase = 'Lateral Movement, Persistence'
    }
    'T1110' = @{
        Name = 'Brute Force'
        Description = 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.'
        Link = 'https://attack.mitre.org/techniques/T1110/'
        Phase = 'Credential Access'
    }
    'T1555' = @{
        Name = 'Credentials from Password Stores'
        Description = 'Adversaries may search for common password storage locations to obtain user credentials.'
        Link = 'https://attack.mitre.org/techniques/T1555/'
        Phase = 'Credential Access'
    }
    'T1056' = @{
        Name = 'Input Capture'
        Description = 'Adversaries may use methods of capturing user input for obtaining credentials for Valid Accounts.'
        Link = 'https://attack.mitre.org/techniques/T1056/'
        Phase = 'Credential Access'
    }
    'T1098' = @{
        Name = 'Account Manipulation'
        Description = 'Adversaries may manipulate accounts to maintain and/or escalate access within an environment.'
        Link = 'https://attack.mitre.org/techniques/T1098/'
        Phase = 'Persistence'
    }
    'T1562' = @{
        Name = 'Impair Defenses'
        Description = 'Adversaries may maliciously modify a system or network to impair or disable defensive mechanisms.'
        Link = 'https://attack.mitre.org/techniques/T1562/'
        Phase = 'Defense Evasion'
    }
    'T1070' = @{
        Name = 'Indicator Removal on Host'
        Description = 'Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses.'
        Link = 'https://attack.mitre.org/techniques/T1070/'
        Phase = 'Defense Evasion'
    }
    'T1036' = @{
        Name = 'Masquerading'
        Description = 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign.'
        Link = 'https://attack.mitre.org/techniques/T1036/'
        Phase = 'Defense Evasion'
    }
    'T1486' = @{
        Name = 'Data Encrypted for Impact'
        Description = 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.'
        Link = 'https://attack.mitre.org/techniques/T1486/'
        Phase = 'Impact'
    }
    'T1552' = @{
        Name = 'Unsecured Credentials'
        Description = 'Adversaries may search compromised systems to find and obtain insecurely stored credentials.'
        Link = 'https://attack.mitre.org/techniques/T1552/'
        Phase = 'Credential Access'
    }
    'T1059' = @{
        Name = 'Command and Scripting Interpreter'
        Description = 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.'
        Link = 'https://attack.mitre.org/techniques/T1059/'
        Phase = 'Execution'
    }
}

# === FINDING TO CATEGORY MAPPING ===
$findingMappings = @{
    'StaleUsers' = @{
        SecurityCategory = 'AttackSurface'
        HealthCategory = 'LifecycleManagement'
        MITRETechniques = @('T1078', 'T1136')
        RiskScore = 6
        BusinessImpact = 'Medium'
        TechnicalDifficulty = 'Low'
    }
    'PasswordNeverExpires' = @{
        SecurityCategory = 'CredentialProtection'
        HealthCategory = 'ComplianceGovernance'
        MITRETechniques = @('T1110', 'T1555')
        RiskScore = 7
        BusinessImpact = 'High'
        TechnicalDifficulty = 'Medium'
    }
    'KerberosDelegation' = @{
        SecurityCategory = 'LateralMovement'
        HealthCategory = 'PerformanceOptimization'
        MITRETechniques = @('T1550', 'T1021')
        RiskScore = 8
        BusinessImpact = 'High'
        TechnicalDifficulty = 'High'
    }
    'UnconstrainedDelegation' = @{
        SecurityCategory = 'LateralMovement'
        HealthCategory = 'PerformanceOptimization'
        MITRETechniques = @('T1550', 'T1484')
        RiskScore = 10
        BusinessImpact = 'Critical'
        TechnicalDifficulty = 'High'
    }
    'KrbtgtPassword' = @{
        SecurityCategory = 'LateralMovement'
        HealthCategory = 'OperationalExcellence'
        MITRETechniques = @('T1550', 'T1484')
        RiskScore = 9
        BusinessImpact = 'Critical'
        TechnicalDifficulty = 'High'
    }
    'SPNAccounts' = @{
        SecurityCategory = 'CredentialProtection'
        HealthCategory = 'LifecycleManagement'
        MITRETechniques = @('T1550', 'T1110')
        RiskScore = 7
        BusinessImpact = 'High'
        TechnicalDifficulty = 'Medium'
    }
    'OversizedGroups' = @{
        SecurityCategory = 'AttackSurface'
        HealthCategory = 'PerformanceOptimization'
        MITRETechniques = @('T1078')
        RiskScore = 4
        BusinessImpact = 'Medium'
        TechnicalDifficulty = 'Medium'
    }
    'PrivilegedRoles' = @{
        SecurityCategory = 'PrivilegeAccess'
        HealthCategory = 'ComplianceGovernance'
        MITRETechniques = @('T1078', 'T1484', 'T1098')
        RiskScore = 8
        BusinessImpact = 'High'
        TechnicalDifficulty = 'Medium'
    }
    'NoConditionalAccess' = @{
        SecurityCategory = 'AttackSurface'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1078', 'T1566')
        RiskScore = 9
        BusinessImpact = 'Critical'
        TechnicalDifficulty = 'High'
    }
    'NoMFA' = @{
        SecurityCategory = 'CredentialProtection'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1110', 'T1566')
        RiskScore = 8
        BusinessImpact = 'High'
        TechnicalDifficulty = 'Medium'
    }
    'LegacyAuth' = @{
        SecurityCategory = 'AttackSurface'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1078', 'T1110')
        RiskScore = 8
        BusinessImpact = 'High'
        TechnicalDifficulty = 'Medium'
    }
    'RiskyServicePrincipals' = @{
        SecurityCategory = 'PrivilegeAccess'
        HealthCategory = 'LifecycleManagement'
        MITRETechniques = @('T1078', 'T1098')
        RiskScore = 6
        BusinessImpact = 'Medium'
        TechnicalDifficulty = 'Medium'
    }
    'OAuthPermissions' = @{
        SecurityCategory = 'DataProtection'
        HealthCategory = 'ComplianceGovernance'
        MITRETechniques = @('T1078', 'T1484')
        RiskScore = 6
        BusinessImpact = 'Medium'
        TechnicalDifficulty = 'Low'
    }
    'UnlinkedGPOs' = @{
        SecurityCategory = 'DetectionResponse'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1562')
        RiskScore = 3
        BusinessImpact = 'Low'
        TechnicalDifficulty = 'Low'
    }
    'OUDelegation' = @{
        SecurityCategory = 'PrivilegeAccess'
        HealthCategory = 'ComplianceGovernance'
        MITRETechniques = @('T1078', 'T1484')
        RiskScore = 5
        BusinessImpact = 'Medium'
        TechnicalDifficulty = 'Medium'
    }
}

# === LOAD EXISTING FINDINGS ===
Write-Host "Loading existing assessment findings..." -ForegroundColor Gray

# Find the latest risk findings CSV
$findingsFile = Get-ChildItem -Path $AssessmentFolder -Filter "risk-findings-*.csv" | 
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $findingsFile) {
    Write-Error "No risk-findings-*.csv file found in $AssessmentFolder"
    Write-Host "Run your AD assessment first: .\script.ps1 -IncludeEntra" -ForegroundColor Yellow
    exit 1
}

try {
    $originalFindings = Import-Csv $findingsFile.FullName
    Write-Host "Loaded $($originalFindings.Count) findings from: $($findingsFile.Name)" -ForegroundColor Green
} catch {
    Write-Error "Failed to load findings: $_"
    exit 1
}

# === ENHANCE FINDINGS WITH CATEGORIZATION ===
Write-Host "`nEnhancing findings with categorization and MITRE mapping..." -ForegroundColor Yellow

$enhancedFindings = @()
$categorySummary = @{}
$mitreSummary = @{}

foreach ($finding in $originalFindings) {
    # Determine finding type from the finding text or area
    $findingType = $null
    $findingText = $finding.Finding.ToLower()
    $findingArea = $finding.Area.ToLower()
    
    # Map finding to type
    if ($findingText -match 'stale|inactive.*users') { $findingType = 'StaleUsers' }
    elseif ($findingText -match 'passwordneverexpires') { $findingType = 'PasswordNeverExpires' }
    elseif ($findingText -match 'kerberos delegation') { $findingType = 'KerberosDelegation' }
    elseif ($findingText -match 'unconstrained delegation') { $findingType = 'UnconstrainedDelegation' }
    elseif ($findingText -match 'krbtgt.*password') { $findingType = 'KrbtgtPassword' }
    elseif ($findingText -match 'spn.*accounts|kerberoastable') { $findingType = 'SPNAccounts' }
    elseif ($findingText -match 'groups.*>=.*500|oversized.*groups') { $findingType = 'OversizedGroups' }
    elseif ($findingText -match 'privileged.*roles|administrator.*members') { $findingType = 'PrivilegedRoles' }
    elseif ($findingText -match 'no.*conditional.*access') { $findingType = 'NoConditionalAccess' }
    elseif ($findingText -match 'no.*mfa|without.*mfa') { $findingType = 'NoMFA' }
    elseif ($findingText -match 'legacy.*auth') { $findingType = 'LegacyAuth' }
    elseif ($findingText -match 'service.*principal.*review') { $findingType = 'RiskyServicePrincipals' }
    elseif ($findingText -match 'oauth.*grants') { $findingType = 'OAuthPermissions' }
    elseif ($findingText -match 'gpo.*unlinked|no.*links') { $findingType = 'UnlinkedGPOs' }
    elseif ($findingText -match 'ou.*delegation') { $findingType = 'OUDelegation' }
    
    # Get enhancement data
    $enhancement = if ($findingMappings.ContainsKey($findingType)) { 
        $findingMappings[$findingType] 
    } else { 
        @{
            SecurityCategory = 'Unknown'
            HealthCategory = 'Unknown'
            MITRETechniques = @()
            RiskScore = 5
            BusinessImpact = 'Medium'
            TechnicalDifficulty = 'Medium'
        }
    }
    
    # Get category details
    $securityCategory = $enhancedCategorization[$enhancement.SecurityCategory]
    $healthCategory = $enhancedCategorization[$enhancement.HealthCategory]
    
    # Create enhanced finding
    $enhanced = [PSCustomObject]@{
        # Original fields
        Area = $finding.Area
        Finding = $finding.Finding
        Severity = $finding.Severity
        Evidence = $finding.Evidence
        Impact = $finding.Impact
        RemediationSteps = $finding.RemediationSteps
        Reference = $finding.Reference
        EstimatedEffort = $finding.EstimatedEffort
        Category = $finding.Category
        Owner = $finding.Owner
        DueDate = $finding.DueDate
        Status = $finding.Status
        
        # Enhanced fields
        FindingType = $findingType
        SecurityCategory = $securityCategory.Name
        SecurityCategoryIcon = $securityCategory.Icon
        SecurityCategoryDescription = $securityCategory.Description
        HealthCategory = $healthCategory.Name
        HealthCategoryIcon = $healthCategory.Icon
        HealthCategoryDescription = $healthCategory.Description
        
        # MITRE ATT&CK
        MITRETechniques = $enhancement.MITRETechniques -join ', '
        MITREDetails = ($enhancement.MITRETechniques | ForEach-Object { 
            $tech = $mitreTechniques[$_]
            if ($tech) { "$($_): $($tech.Name)" } 
        }) -join '; '
        
        # Risk scoring
        RiskScore = $enhancement.RiskScore
        BusinessImpact = $enhancement.BusinessImpact
        TechnicalDifficulty = $enhancement.TechnicalDifficulty
        PriorityScore = $enhancement.RiskScore * $securityCategory.RiskWeight
        
        # Additional metadata
        EnhancedDate = (Get-Date).ToString("u")
        SourceAssessment = $findingsFile.Name
    }
    
    $enhancedFindings += $enhanced
    
    # Update summaries
    if (-not $categorySummary.ContainsKey($securityCategory.Name)) {
        $categorySummary[$securityCategory.Name] = @{
            Count = 0
            RiskScore = 0
            Icon = $securityCategory.Icon
        }
    }
    $categorySummary[$securityCategory.Name].Count++
    $categorySummary[$securityCategory.Name].RiskScore += $enhancement.RiskScore
    
    foreach ($technique in $enhancement.MITRETechniques) {
        if (-not $mitreSummary.ContainsKey($technique)) {
            $mitreSummary[$technique] = 0
        }
        $mitreSummary[$technique]++
    }
}

# === EXPORT ENHANCED FINDINGS ===
$enhancedFindingsFile = Join-Path $OutputFolder "enhanced-findings-$timestamp.csv"
$enhancedFindings | Export-Csv $enhancedFindingsFile -NoTypeInformation -Force

$enhancedFindingsJson = Join-Path $OutputFolder "enhanced-findings-$timestamp.json"
$enhancedFindings | ConvertTo-Json -Depth 6 | Out-File $enhancedFindingsJson -Force

# === CREATE CATEGORY SUMMARY ===
$categorySummaryData = $categorySummary.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
        Category = $_.Key
        Icon = $_.Value.Icon
        FindingCount = $_.Value.Count
        AverageRiskScore = [math]::Round($_.Value.RiskScore / $_.Value.Count, 2)
        TotalRiskScore = $_.Value.RiskScore
        CategoryType = if ($enhancedCategorization.Values.Name -contains $_.Key) { 'Security' } else { 'Health' }
    }
} | Sort-Object TotalRiskScore -Descending

$categorySummaryFile = Join-Path $OutputFolder "category-summary-$timestamp.csv"
$categorySummaryData | Export-Csv $categorySummaryFile -NoTypeInformation -Force

# === CREATE MITRE SUMMARY ===
$mitreSummaryData = $mitreSummary.GetEnumerator() | ForEach-Object {
    $technique = $mitreTechniques[$_.Key]
    [PSCustomObject]@{
        TechniqueID = $_.Key
        TechniqueName = $technique.Name
        Description = $technique.Description
        Phase = $technique.Phase
        FindingCount = $_.Value
        Link = $technique.Link
    }
} | Sort-Object FindingCount -Descending

$mitreSummaryFile = Join-Path $OutputFolder "mitre-summary-$timestamp.csv"
$mitreSummaryData | Export-Csv $mitreSummaryFile -NoTypeInformation -Force

# === GENERATE ENHANCED HTML REPORT ===
Write-Host "`nGenerating enhanced HTML report..." -ForegroundColor Yellow

$htmlHead = @"
<style>
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
    h2 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 5px; margin-top: 30px; }
    h3 { color: #0078d4; margin-top: 20px; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    th { background: #0078d4; color: white; padding: 12px; text-align: left; font-weight: 600; }
    td { padding: 10px; border-bottom: 1px solid #ddd; }
    tr:hover { background: #f9f9f9; }
    .high { color: #d13438; font-weight: bold; }
    .medium { color: #ff8c00; font-weight: bold; }
    .low { color: #107c10; }
    .category-filter { margin: 20px 0; padding: 15px; background: #e8f4fc; border-radius: 8px; }
    .mitre-badge { background: #d13438; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin: 2px; display: inline-block; }
    .risk-score { font-weight: bold; }
    .security-category { background: #fff4e6; }
    .health-category { background: #e6f3ff; }
</style>
<script>
function filterByCategory(category) {
    const rows = document.querySelectorAll('#findingsTable tbody tr');
    rows.forEach(row => {
        if (category === 'All' || row.dataset.category === category) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}
</script>
"@

# Group findings by security category
$securityFindings = $enhancedFindings | Where-Object { $_.SecurityCategory -ne 'Unknown' } | 
    Group-Object SecurityCategory | Sort-Object Count -Descending

$healthFindings = $enhancedFindings | Where-Object { $_.HealthCategory -ne 'Unknown' } | 
    Group-Object HealthCategory | Sort-Object Count -Descending

$htmlBody = @"
<h1>🛡️ Enhanced AD Security Assessment</h1>
<p><strong>Analysis Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<p><strong>Total Findings:</strong> $($enhancedFindings.Count) | <strong>Security Categories:</strong> $($securityFindings.Count) | <strong>Health Categories:</strong> $($healthFindings.Count)</p>

<div class="category-filter">
    <strong>Filter by Category:</strong>
    <button onclick="filterByCategory('All')" style="margin: 5px; padding: 5px 10px;">All</button>
    $(($enhancedCategorization.Keys | ForEach-Object { 
        $cat = $enhancedCategorization[$_]
        "<button onclick=`"filterByCategory('$($cat.Name)')`" style=`"margin: 5px; padding: 5px 10px;`">$($cat.Icon) $($cat.Name)</button>"
    }) -join ' ')
</div>

<h2>📊 Security Categories Overview</h2>
<table>
    <thead>
        <tr><th>Category</th><th>Findings</th><th>Avg Risk Score</th><th>Description</th></tr>
    </thead>
    <tbody>
        $(($categorySummaryData | Where-Object { $_.CategoryType -eq 'Security' } | ForEach-Object {
            $cat = $enhancedCategorization.Values | Where-Object { $_.Name -eq $_.Category }
            "<tr class='security-category'><td>$($cat.Icon) $($_.Category)</td><td>$($_.FindingCount)</td><td class='risk-score'>$($_.AverageRiskScore)</td><td>$($cat.Description)</td></tr>"
        }) -join '')
    </tbody>
</table>

<h2>🔧 AD Health Categories Overview</h2>
<table>
    <thead>
        <tr><th>Category</th><th>Findings</th><th>Avg Risk Score</th><th>Description</th></tr>
    </thead>
    <tbody>
        $(($categorySummaryData | Where-Object { $_.CategoryType -eq 'Health' } | ForEach-Object {
            $cat = $enhancedCategorization.Values | Where-Object { $_.Name -eq $_.Category }
            "<tr class='health-category'><td>$($cat.Icon) $($_.Category)</td><td>$($_.FindingCount)</td><td class='risk-score'>$($_.AverageRiskScore)</td><td>$($cat.Description)</td></tr>"
        }) -join '')
    </tbody>
</table>

<h2>🎯 MITRE ATT&CK Techniques</h2>
<table>
    <thead>
        <tr><th>Technique</th><th>Findings</th><th>Phase</th><th>Description</th></tr>
    </thead>
    <tbody>
        $(($mitreSummaryData | ForEach-Object {
            "<tr><td><a href='$($_.Link)' target='_blank'><span class='mitre-badge'>$($_.TechniqueID)</span> $($_.TechniqueName)</a></td><td>$($_.FindingCount)</td><td>$($_.Phase)</td><td>$($_.Description)</td></tr>"
        }) -join '')
    </tbody>
</table>

<h2>🔍 Enhanced Findings by Category</h2>
<table id="findingsTable">
    <thead>
        <tr><th>Category</th><th>Finding</th><th>Severity</th><th>Risk Score</th><th>MITRE</th><th>Business Impact</th><th>Technical Difficulty</th></tr>
    </thead>
    <tbody>
        $(($enhancedFindings | Sort-Object PriorityScore -Descending | ForEach-Object {
            $mitreBadges = if ($_.MITRETechniques) {
                ($_.MITRETechniques -split ',' | ForEach-Object { 
                    "<span class='mitre-badge'>$($_.Trim())</span>" 
                }) -join ' '
            } else { '' }
            
            "<tr data-category='$($_.SecurityCategory)' class='security-category'>
                <td>$($_.SecurityCategoryIcon) $($_.SecurityCategory)</td>
                <td>$($_.Finding)</td>
                <td class='$($_.Severity.ToLower())'>$($_.Severity)</td>
                <td class='risk-score'>$($_.RiskScore)</td>
                <td>$mitreBadges</td>
                <td>$($_.BusinessImpact)</td>
                <td>$($_.TechnicalDifficulty)</td>
            </tr>"
        }) -join '')
    </tbody>
</table>

<h2>📈 Risk Prioritization Matrix</h2>
<p><strong>Priority Score = Risk Score × Category Weight</strong></p>
<table>
    <thead>
        <tr><th>Finding</th><th>Priority Score</th><th>Risk Score</th><th>Category Weight</th><th>Business Impact</th><th>Technical Difficulty</th></tr>
    </thead>
    <tbody>
        $(($enhancedFindings | Sort-Object PriorityScore -Descending | Select-Object -First 10 | ForEach-Object {
            $catWeight = ($enhancedCategorization.Values | Where-Object { $_.Name -eq $_.SecurityCategory }).RiskWeight
            "<tr><td>$($_.Finding)</td><td class='risk-score'>$($_.PriorityScore)</td><td>$($_.RiskScore)</td><td>$catWeight</td><td>$($_.BusinessImpact)</td><td>$($_.TechnicalDifficulty)</td></tr>"
        }) -join '')
    </tbody>
</table>

<p style="margin-top: 40px; color: #666; font-size: 0.9em; border-top: 1px solid #ddd; padding-top: 20px;">
<em>Enhanced Assessment with MITRE ATT&CK Mapping | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</em>
</p>
"@

$html = ConvertTo-Html -Head $htmlHead -Body $htmlBody -Title "Enhanced AD Security Assessment $timestamp"
$htmlPath = Join-Path $OutputFolder "enhanced-assessment-$timestamp.html"
$html | Out-File $htmlPath -Force

# === DISPLAY RESULTS ===
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Enhanced Categorization Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`n📊 Summary:" -ForegroundColor White
Write-Host "  Original Findings: $($originalFindings.Count)" -ForegroundColor Gray
Write-Host "  Enhanced Findings: $($enhancedFindings.Count)" -ForegroundColor Gray
Write-Host "  Security Categories: $($securityFindings.Count)" -ForegroundColor Gray
Write-Host "  Health Categories: $($healthFindings.Count)" -ForegroundColor Gray
Write-Host "  MITRE Techniques: $($mitreSummary.Count)" -ForegroundColor Gray

Write-Host "`n🎯 Top Security Categories:" -ForegroundColor Yellow
$categorySummaryData | Where-Object { $_.CategoryType -eq 'Security' } | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.Icon) $($_.Category): $($_.FindingCount) findings (Avg Risk: $($_.AverageRiskScore))" -ForegroundColor Gray
}

Write-Host "`n🔴 Top MITRE Techniques:" -ForegroundColor Yellow
$mitreSummaryData | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.TechniqueID) $($_.TechniqueName): $($_.FindingCount) findings" -ForegroundColor Gray
}

Write-Host "`n📁 Output Files:" -ForegroundColor White
Write-Host "  • Enhanced Findings: $enhancedFindingsFile" -ForegroundColor Gray
Write-Host "  • Category Summary: $categorySummaryFile" -ForegroundColor Gray
Write-Host "  • MITRE Summary: $mitreSummaryFile" -ForegroundColor Gray
Write-Host "  • Enhanced HTML Report: $htmlPath" -ForegroundColor Gray

Write-Host "`n💡 Next Steps:" -ForegroundColor White
Write-Host "  1. Review the enhanced HTML report with category filters" -ForegroundColor Gray
Write-Host "  2. Focus on high-priority security findings first" -ForegroundColor Gray
Write-Host "  3. Use MITRE mappings for threat modeling" -ForegroundColor Gray
Write-Host "  4. Implement security controls based on attack techniques" -ForegroundColor Gray
Write-Host "  5. Track remediation progress by category" -ForegroundColor Gray

Write-Host "`n🔧 Open the enhanced report:" -ForegroundColor Cyan
Write-Host "  Invoke-Item '$htmlPath'" -ForegroundColor Gray
