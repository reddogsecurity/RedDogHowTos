<#
.SYNOPSIS
    Demo script showing enhanced categorization with MITRE ATT&CK mapping

.DESCRIPTION
    This script demonstrates what your findings would look like with:
    1. Security vs Health categorization
    2. MITRE ATT&CK technique mapping
    3. Enhanced risk scoring
    4. Category-based prioritization
#>

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Enhanced Categorization Demo" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Demo findings with enhanced categorization
$demoFindings = @(
    @{
        Finding = "5 enabled users inactive >90 days"
        Severity = "Medium"
        Area = "AD Users"
        SecurityCategory = "Attack Surface Reduction"
        HealthCategory = "Lifecycle Management"
        MITRETechniques = @("T1078", "T1136")  # Valid Accounts, Create Account
        RiskScore = 6
        BusinessImpact = "Medium"
        TechnicalDifficulty = "Low"
        Icon = "️"
    },
    @{
        Finding = "krbtgt password is 250 days old (>180 days)"
        Severity = "High"
        Area = "AD Security"
        SecurityCategory = "Lateral Movement Prevention"
        HealthCategory = "Operational Excellence"
        MITRETechniques = @("T1550", "T1484")  # Use Alternate Authentication Material, Domain Policy Modification
        RiskScore = 9
        BusinessImpact = "Critical"
        TechnicalDifficulty = "High"
        Icon = "🕸️"
    },
    @{
        Finding = "3 computers with Unconstrained Delegation"
        Severity = "High"
        Area = "AD Computers"
        SecurityCategory = "Lateral Movement Prevention"
        HealthCategory = "Performance Optimization"
        MITRETechniques = @("T1550", "T1484")  # Use Alternate Authentication Material, Domain Policy Modification
        RiskScore = 10
        BusinessImpact = "Critical"
        TechnicalDifficulty = "High"
        Icon = "🕸️"
    },
    @{
        Finding = "15 users without MFA registered"
        Severity = "High"
        Area = "Zero Trust"
        SecurityCategory = "Credential Protection"
        HealthCategory = "Modernization"
        MITRETechniques = @("T1110", "T1566")  # Brute Force, Phishing
        RiskScore = 8
        BusinessImpact = "High"
        TechnicalDifficulty = "Medium"
        Icon = "[MFA]"
    },
    @{
        Finding = "Domain Admins has 8 members"
        Severity = "Medium"
        Area = "Entra Roles"
        SecurityCategory = "Privileged Access Management"
        HealthCategory = "Compliance &amp; Governance"
        MITRETechniques = @("T1078", "T1484", "T1098")  # Valid Accounts, Domain Policy Modification, Account Manipulation
        RiskScore = 8
        BusinessImpact = "High"
        TechnicalDifficulty = "Medium"
        Icon = "👑"
    },
    @{
        Finding = "No Conditional Access policies found"
        Severity = "High"
        Area = "Zero Trust"
        SecurityCategory = "Attack Surface Reduction"
        HealthCategory = "Modernization"
        MITRETechniques = @("T1078", "T1566")  # Valid Accounts, Phishing
        RiskScore = 9
        BusinessImpact = "Critical"
        TechnicalDifficulty = "High"
        Icon = "️"
    },
    @{
        Finding = "25 service principals with credentials >1 year lifetime"
        Severity = "Medium"
        Area = "Service Principal Security"
        SecurityCategory = "Credential Protection"
        HealthCategory = "Lifecycle Management"
        MITRETechniques = @("T1550", "T1110")  # Use Alternate Authentication Material, Brute Force
        RiskScore = 7
        BusinessImpact = "High"
        TechnicalDifficulty = "Medium"
        Icon = "[MFA]"
    },
    @{
        Finding = "3 GPOs have no links (candidates to retire)"
        Severity = "Low"
        Area = "GPOs"
        SecurityCategory = "Detection &amp; Response"
        HealthCategory = "Modernization"
        MITRETechniques = @("T1562")  # Impair Defenses
        RiskScore = 3
        BusinessImpact = "Low"
        TechnicalDifficulty = "Low"
        Icon = ""
    },
    @{
        Finding = "12 groups have >=500 members"
        Severity = "Medium"
        Area = "AD Groups"
        SecurityCategory = "Attack Surface Reduction"
        HealthCategory = "Performance Optimization"
        MITRETechniques = @("T1078")  # Valid Accounts
        RiskScore = 4
        BusinessImpact = "Medium"
        TechnicalDifficulty = "Medium"
        Icon = "️"
    },
    @{
        Finding = "8 admin-consented OAuth grants (review for excessive permissions)"
        Severity = "Medium"
        Area = "OAuth Permissions"
        SecurityCategory = "Data Protection"
        HealthCategory = "Compliance &amp; Governance"
        MITRETechniques = @("T1078", "T1484")  # Valid Accounts, Domain Policy Modification
        RiskScore = 6
        BusinessImpact = "Medium"
        TechnicalDifficulty = "Low"
        Icon = ""
    }
)

Write-Host " SECURITY CATEGORIES:" -ForegroundColor Yellow
Write-Host "=======================" -ForegroundColor Yellow

# Group by security category
$securityCategories = $demoFindings | Group-Object SecurityCategory | Sort-Object Count -Descending

foreach ($category in $securityCategories) {
    Write-Host "`n$($category.Name):" -ForegroundColor White
    $highRisk = ($category.Group | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumRisk = ($category.Group | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowRisk = ($category.Group | Where-Object { $_.Severity -eq 'Low' }).Count
    $avgRiskScore = [math]::Round((($category.Group | Measure-Object -Property RiskScore -Average).Average), 1)
    
    Write-Host "  Findings: $($category.Count) | High: $highRisk | Medium: $mediumRisk | Low: $lowRisk | Avg Risk: $avgRiskScore" -ForegroundColor Gray
    
    foreach ($finding in $category.Group | Sort-Object RiskScore -Descending) {
        $severityColor = switch ($finding.Severity) {
            'High' { 'Red' }
            'Medium' { 'Yellow' }
            'Low' { 'Green' }
        }
        Write-Host "    $($finding.Icon) $($finding.Finding) [$($finding.Severity)] (Risk: $($finding.RiskScore))" -ForegroundColor $severityColor
        Write-Host "      MITRE: $($finding.MITRETechniques -join ', ') | Impact: $($finding.BusinessImpact) | Difficulty: $($finding.TechnicalDifficulty)" -ForegroundColor DarkGray
    }
}

Write-Host "`n AD HEALTH CATEGORIES:" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

# Group by health category
$healthCategories = $demoFindings | Group-Object HealthCategory | Sort-Object Count -Descending

foreach ($category in $healthCategories) {
    Write-Host "`n$($category.Name):" -ForegroundColor White
    $avgRiskScore = [math]::Round((($category.Group | Measure-Object -Property RiskScore -Average).Average), 1)
    Write-Host "  Findings: $($category.Count) | Avg Risk: $avgRiskScore" -ForegroundColor Gray
    
    foreach ($finding in $category.Group | Sort-Object RiskScore -Descending) {
        Write-Host "    - $($finding.Finding)" -ForegroundColor DarkGray
    }
}

Write-Host "`n MITRE ATT&CK TECHNIQUES:" -ForegroundColor Magenta
Write-Host "=============================" -ForegroundColor Magenta

# Group by MITRE techniques
$mitreTechniques = @{}
foreach ($finding in $demoFindings) {
    foreach ($technique in $finding.MITRETechniques) {
        if (-not $mitreTechniques.ContainsKey($technique)) {
            $mitreTechniques[$technique] = @()
        }
        $mitreTechniques[$technique] += $finding
    }
}

$mitreTechniqueNames = @{
    'T1078' = 'Valid Accounts'
    'T1136' = 'Create Account'
    'T1550' = 'Use Alternate Authentication Material'
    'T1484' = 'Domain Policy Modification'
    'T1110' = 'Brute Force'
    'T1566' = 'Phishing'
    'T1098' = 'Account Manipulation'
    'T1021' = 'Remote Services'
    'T1562' = 'Impair Defenses'
    'T1555' = 'Credentials from Password Stores'
}

foreach ($technique in ($mitreTechniques.Keys | Sort-Object)) {
    $findings = $mitreTechniques[$technique]
    $techniqueName = $mitreTechniqueNames[$technique]
    Write-Host "`n$technique - ${techniqueName}:" -ForegroundColor White
    Write-Host "  Affects $($findings.Count) findings" -ForegroundColor Gray
    foreach ($finding in $findings) {
        Write-Host "    - $($finding.Finding) [$($finding.Severity)]" -ForegroundColor DarkGray
    }
}

Write-Host "`n RISK PRIORITIZATION:" -ForegroundColor Yellow
Write-Host "========================" -ForegroundColor Yellow

Write-Host "Top 5 findings by risk score:" -ForegroundColor White
$demoFindings | Sort-Object RiskScore -Descending | Select-Object -First 5 | ForEach-Object {
    $priority = if ($_.RiskScore -ge 9) { "[H] CRITICAL" } elseif ($_.RiskScore -ge 7) { "[M] HIGH" } else { "[L] MEDIUM" }
    Write-Host "  $($_.RiskScore) - $($_.Finding) [$priority]" -ForegroundColor $(if ($_.RiskScore -ge 9) { 'Red' } elseif ($_.RiskScore -ge 7) { 'Yellow' } else { 'Green' })
}

Write-Host "`n IMPLEMENTATION BENEFITS:" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host "✅ Clear separation of Security vs Operational concerns" -ForegroundColor Green
Write-Host "✅ MITRE ATT&CK mapping for threat modeling" -ForegroundColor Green
Write-Host "✅ Risk scoring for prioritization" -ForegroundColor Green
Write-Host "✅ Business impact assessment" -ForegroundColor Green
Write-Host "✅ Technical difficulty estimation" -ForegroundColor Green
Write-Host "✅ Category-based filtering and reporting" -ForegroundColor Green

Write-Host "`n DIFFICULTY ASSESSMENT:" -ForegroundColor Yellow
Write-Host "=========================" -ForegroundColor Yellow
Write-Host "[L] EASY (2-3 hours): Basic categorization and MITRE IDs" -ForegroundColor Green
Write-Host "[M] MODERATE (4-6 hours): Risk scoring and enhanced HTML" -ForegroundColor Yellow
Write-Host "[H] COMPLEX (8-12 hours): Full framework integration" -ForegroundColor Red

Write-Host "`n🚀 RECOMMENDED NEXT STEPS:" -ForegroundColor White
Write-Host "1. Start with basic categorization (EASY)" -ForegroundColor Gray
Write-Host "2. Add MITRE technique IDs to existing findings" -ForegroundColor Gray
Write-Host "3. Enhance HTML report with category sections" -ForegroundColor Gray
Write-Host "4. Implement risk scoring for prioritization" -ForegroundColor Gray
Write-Host "5. Create category-based dashboards" -ForegroundColor Gray

Write-Host "`n📝 To implement this in your script:" -ForegroundColor Cyan
Write-Host "Run: .\Add-CategorizationToScript.ps1" -ForegroundColor Gray
Write-Host "This shows you exactly what to modify in script.ps1" -ForegroundColor Gray
