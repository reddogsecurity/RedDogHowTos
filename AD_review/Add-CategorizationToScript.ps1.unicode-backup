<#
.SYNOPSIS
    Simple integration script to add categorization to existing script.ps1

.DESCRIPTION
    This script shows how to modify your existing script.ps1 to include:
    1. Security vs Health categorization
    2. MITRE ATT&CK technique mapping
    3. Enhanced risk scoring
    4. Category-based HTML sections

.EXAMPLE
    .\Add-CategorizationToScript.ps1
    Shows the modifications needed for script.ps1
#>

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Adding Categorization to Your Script" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "📋 DIFFICULTY ASSESSMENT:" -ForegroundColor Yellow
Write-Host "=========================" -ForegroundColor Yellow
Write-Host "🟢 EASY (2-3 hours):" -ForegroundColor Green
Write-Host "  • Add Security/Health categories to existing findings" -ForegroundColor Gray
Write-Host "  • Add MITRE technique IDs to remediation guidance" -ForegroundColor Gray
Write-Host "  • Enhance HTML with category sections" -ForegroundColor Gray

Write-Host "`n🟡 MODERATE (4-6 hours):" -ForegroundColor Yellow
Write-Host "  • Implement risk scoring algorithm" -ForegroundColor Gray
Write-Host "  • Add category-based filtering" -ForegroundColor Gray
Write-Host "  • Create MITRE technique lookup" -ForegroundColor Gray

Write-Host "`n🔴 COMPLEX (8-12 hours):" -ForegroundColor Red
Write-Host "  • Full MITRE ATT&CK framework integration" -ForegroundColor Gray
Write-Host "  • Advanced risk prioritization matrix" -ForegroundColor Gray
Write-Host "  • Interactive dashboard with drill-downs" -ForegroundColor Gray

Write-Host "`n💡 RECOMMENDED APPROACH:" -ForegroundColor Cyan
Write-Host "Start with EASY modifications, then enhance incrementally" -ForegroundColor White

Write-Host "`n🔧 STEP 1: Modify the remediation guidance mapping" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow

$step1Code = @'
# --- Enhanced Remediation Guidance Mapping ---
$remediationGuide = @{
    'StaleUsers' = @{
        Impact = 'Inactive accounts are attack targets - credentials may be compromised without detection'
        Steps = '1. Review list of inactive users in ad-users CSV|2. Disable accounts inactive >90 days|3. Move to quarantine OU for 30 days|4. Delete if no business need documented|5. Implement automated account lifecycle policy'
        Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
        Effort = '2-4 hours'
        Category = 'Identity Hygiene'
        # NEW FIELDS:
        SecurityCategory = 'Attack Surface Reduction'
        HealthCategory = 'Lifecycle Management'
        MITRETechniques = @('T1078', 'T1136')  # Valid Accounts, Create Account
        RiskScore = 6
        BusinessImpact = 'Medium'
    }
    'PasswordNeverExpires' = @{
        Impact = 'Accounts with non-expiring passwords pose long-term credential theft risk'
        Steps = '1. Review users with PasswordNeverExpires flag|2. For service accounts: transition to gMSA or Entra managed identity|3. For users: remove flag and enforce password rotation|4. Implement password policy compliance monitoring'
        Reference = 'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview'
        Effort = '4-6 hours'
        Category = 'Identity Hygiene'
        # NEW FIELDS:
        SecurityCategory = 'Credential Protection'
        HealthCategory = 'Compliance & Governance'
        MITRETechniques = @('T1110', 'T1555')  # Brute Force, Credentials from Password Stores
        RiskScore = 7
        BusinessImpact = 'High'
    }
    'KerberosDelegation' = @{
        Impact = 'Delegation allows accounts to impersonate users - creates high lateral movement risk'
        Steps = '1. Review delegation assignments in evidence file|2. Remove unconstrained delegation immediately|3. Replace with constrained or resource-based delegation|4. Enable "Account is sensitive and cannot be delegated" for privileged users|5. Monitor Event 4662 for delegation abuse'
        Reference = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
        Effort = '6-8 hours'
        Category = 'Privileged Access'
        # NEW FIELDS:
        SecurityCategory = 'Lateral Movement Prevention'
        HealthCategory = 'Performance Optimization'
        MITRETechniques = @('T1550', 'T1021')  # Use Alternate Authentication Material, Remote Services
        RiskScore = 8
        BusinessImpact = 'High'
    }
    'UnconstrainedDelegation' = @{
        Impact = 'CRITICAL: Enables credential theft and Golden Ticket attacks via TGT harvesting'
        Steps = '1. URGENT: Identify all computers with unconstrained delegation|2. Replace with constrained delegation for specific services only|3. Enable SMB signing and LDAP signing|4. Monitor Event 4768/4769 for TGT requests|5. Consider Protected Users group for sensitive accounts'
        Reference = 'https://adsecurity.org/?p=1667'
        Effort = '8-12 hours'
        Category = 'Privileged Access'
        # NEW FIELDS:
        SecurityCategory = 'Lateral Movement Prevention'
        HealthCategory = 'Performance Optimization'
        MITRETechniques = @('T1550', 'T1484')  # Use Alternate Authentication Material, Domain Policy Modification
        RiskScore = 10
        BusinessImpact = 'Critical'
    }
    'KrbtgtPassword' = @{
        Impact = 'CRITICAL: Old krbtgt password enables indefinite Golden Ticket attacks'
        Steps = '1. Schedule maintenance window - requires 2 sessions 24 hours apart|2. Run New-KrbtgtKeys.ps1 to reset password|3. Wait 24 hours for AD replication|4. Run New-KrbtgtKeys.ps1 again (second reset)|5. Monitor Event Logs for Kerberos errors|6. Set recurring reminder for 180 days'
        Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password'
        Effort = '2-3 hours + 24hr wait'
        Category = 'Critical Security'
        # NEW FIELDS:
        SecurityCategory = 'Lateral Movement Prevention'
        HealthCategory = 'Operational Excellence'
        MITRETechniques = @('T1550', 'T1484')  # Use Alternate Authentication Material, Domain Policy Modification
        RiskScore = 9
        BusinessImpact = 'Critical'
    }
    'SPNAccounts' = @{
        Impact = 'SPNs expose service accounts to Kerberoasting - offline password cracking attacks'
        Steps = '1. Audit all SPN accounts in evidence CSV|2. Set long complex passwords (25+ characters) or use gMSA|3. Transition to group Managed Service Accounts where possible|4. Enable "Account is sensitive" for high-value SPNs|5. Monitor Event 4769 for RC4 encryption (Kerberoast indicator)|6. Implement SPN ACL restrictions'
        Reference = 'https://adsecurity.org/?p=2293'
        Effort = '6-10 hours'
        Category = 'Identity Hygiene'
        # NEW FIELDS:
        SecurityCategory = 'Credential Protection'
        HealthCategory = 'Lifecycle Management'
        MITRETechniques = @('T1550', 'T1110')  # Use Alternate Authentication Material, Brute Force
        RiskScore = 7
        BusinessImpact = 'High'
    }
    'OversizedGroups' = @{
        Impact = 'Large groups complicate access review and often contain excessive permissions'
        Steps = '1. Review groups with 500+ members|2. Identify group purpose and business owner|3. Split into functional sub-groups by department/role|4. Implement RBAC model using Entra ID roles|5. Remove circular/nested group sprawl|6. Establish group management policy with regular reviews'
        Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices'
        Effort = '10-15 hours'
        Category = 'Access Management'
        # NEW FIELDS:
        SecurityCategory = 'Attack Surface Reduction'
        HealthCategory = 'Performance Optimization'
        MITRETechniques = @('T1078')  # Valid Accounts
        RiskScore = 4
        BusinessImpact = 'Medium'
    }
    'PrivilegedRoles' = @{
        Impact = 'Excessive privileged access increases insider threat and breach impact radius'
        Steps = '1. Review all members of privileged roles in evidence JSON|2. Remove unnecessary permanent assignments|3. Implement Privileged Identity Management (PIM) for just-in-time access|4. Require MFA for all privileged accounts|5. Create emergency break-glass accounts (2-3)|6. Enable privileged activity auditing and alerts'
        Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure'
        Effort = '8-12 hours'
        Category = 'Privileged Access'
        # NEW FIELDS:
        SecurityCategory = 'Privileged Access Management'
        HealthCategory = 'Compliance & Governance'
        MITRETechniques = @('T1078', 'T1484', 'T1098')  # Valid Accounts, Domain Policy Modification, Account Manipulation
        RiskScore = 8
        BusinessImpact = 'High'
    }
    'NoConditionalAccess' = @{
        Impact = 'CRITICAL: No Zero Trust controls - authentication security relies solely on passwords'
        Steps = '1. Enable Azure AD Security Defaults immediately as interim measure|2. Plan Conditional Access policy rollout|3. Start with: require MFA for all users|4. Add: block legacy authentication protocols|5. Implement: require compliant or hybrid joined devices|6. Add: risk-based sign-in policies|7. Test all policies in report-only mode before enforcement'
        Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/plan-conditional-access'
        Effort = '12-20 hours'
        Category = 'Zero Trust'
        # NEW FIELDS:
        SecurityCategory = 'Attack Surface Reduction'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1078', 'T1566')  # Valid Accounts, Phishing
        RiskScore = 9
        BusinessImpact = 'Critical'
    }
    'NoMFA' = @{
        Impact = 'Users without MFA are vulnerable to password spray, phishing, and credential stuffing attacks'
        Steps = '1. Launch MFA registration campaign with user communications|2. Start with Global Admins (mandatory)|3. Roll out to all users in phases by department|4. Provide multiple MFA methods: Microsoft Authenticator app, FIDO2 keys, Windows Hello for Business|5. Configure Conditional Access to block legacy auth that bypasses MFA|6. Monitor MFA registration compliance dashboard'
        Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks'
        Effort = '15-25 hours + user training'
        Category = 'Zero Trust'
        # NEW FIELDS:
        SecurityCategory = 'Credential Protection'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1110', 'T1566')  # Brute Force, Phishing
        RiskScore = 8
        BusinessImpact = 'High'
    }
    'LegacyAuth' = @{
        Impact = 'Legacy authentication protocols bypass MFA and modern security controls entirely'
        Steps = '1. Identify applications using legacy auth in sign-in logs|2. Update or replace legacy applications|3. Configure Conditional Access policy to block legacy auth|4. Create temporary exception for service accounts with monitoring|5. Monitor blocked sign-in attempts|6. Plan decommissioning of IMAP/POP/SMTP protocols'
        Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication'
        Effort = '8-15 hours'
        Category = 'Zero Trust'
        # NEW FIELDS:
        SecurityCategory = 'Attack Surface Reduction'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1078', 'T1110')  # Valid Accounts, Brute Force
        RiskScore = 8
        BusinessImpact = 'High'
    }
    'RiskyServicePrincipals' = @{
        Impact = 'Orphaned or misconfigured service principals may have excessive API permissions'
        Steps = '1. Audit all service principals in evidence CSV|2. Identify and document business owner for each|3. Review assigned API permissions and consent grants|4. Remove unused or orphaned service principals|5. Implement least-privilege permissions for remaining SPs|6. Enable credential expiration (max 12 months)|7. Monitor for suspicious SP activity'
        Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-remove-app'
        Effort = '6-10 hours'
        Category = 'Application Security'
        # NEW FIELDS:
        SecurityCategory = 'Privileged Access Management'
        HealthCategory = 'Lifecycle Management'
        MITRETechniques = @('T1078', 'T1098')  # Valid Accounts, Account Manipulation
        RiskScore = 6
        BusinessImpact = 'Medium'
    }
    'OAuthPermissions' = @{
        Impact = 'Admin-consented grants may provide excessive access to organizational data and resources'
        Steps = '1. Review all admin-consented OAuth grants in evidence JSON|2. Validate business need and risk for each application|3. Revoke excessive or unused permissions|4. Implement app consent policies to restrict future consents|5. Enable admin consent request workflow for user submissions|6. Conduct security awareness training on OAuth consent risks'
        Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-admin-consent-workflow'
        Effort = '4-8 hours'
        Category = 'Application Security'
        # NEW FIELDS:
        SecurityCategory = 'Data Protection'
        HealthCategory = 'Compliance & Governance'
        MITRETechniques = @('T1078', 'T1484')  # Valid Accounts, Domain Policy Modification
        RiskScore = 6
        BusinessImpact = 'Medium'
    }
    'UnlinkedGPOs' = @{
        Impact = 'Unlinked GPOs create configuration drift and potential security gaps if accidentally re-linked'
        Steps = '1. Review unlinked GPOs in evidence CSV|2. Document purpose and historical context|3. Backup GPO settings using Backup-GPO cmdlet|4. Delete or archive unlinked GPOs after stakeholder approval|5. Plan migration of remaining security GPOs to Intune configuration profiles|6. Develop GPO decommissioning roadmap'
        Reference = 'https://learn.microsoft.com/en-us/mem/intune/configuration/device-profiles'
        Effort = '3-6 hours'
        Category = 'Modernization'
        # NEW FIELDS:
        SecurityCategory = 'Detection & Response'
        HealthCategory = 'Modernization'
        MITRETechniques = @('T1562')  # Impair Defenses
        RiskScore = 3
        BusinessImpact = 'Low'
    }
    'OUDelegation' = @{
        Impact = 'Non-standard OU permissions may allow unauthorized AD object modifications'
        Steps = '1. Review OU ACLs for non-standard permissions in evidence JSON|2. Identify and document delegation purpose with AD team|3. Remove unnecessary or overly-broad delegations|4. Implement least-privilege OU administration model|5. Document all approved delegations in runbook|6. Schedule quarterly permission audits'
        Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory'
        Effort = '4-8 hours'
        Category = 'Access Management'
        # NEW FIELDS:
        SecurityCategory = 'Privileged Access Management'
        HealthCategory = 'Compliance & Governance'
        MITRETechniques = @('T1078', 'T1484')  # Valid Accounts, Domain Policy Modification
        RiskScore = 5
        BusinessImpact = 'Medium'
    }
}
'@

Write-Host $step1Code -ForegroundColor Gray

Write-Host "`n🔧 STEP 2: Enhance the findings creation" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow

$step2Code = @'
# When creating findings, add the new fields:
$findings.Add([pscustomobject]@{
    Area='AD Users'
    Finding="$($stale.Count) enabled users inactive >90 days"
    Severity='Medium'
    Evidence='ad-users'
    Impact=$remedy.Impact
    RemediationSteps=$remedy.Steps
    Reference=$remedy.Reference
    EstimatedEffort=$remedy.Effort
    Category=$remedy.Category
    # NEW FIELDS:
    SecurityCategory=$remedy.SecurityCategory
    HealthCategory=$remedy.HealthCategory
    MITRETechniques=($remedy.MITRETechniques -join ', ')
    RiskScore=$remedy.RiskScore
    BusinessImpact=$remedy.BusinessImpact
    Owner=''
    DueDate=''
    Status='Open'
})
'@

Write-Host $step2Code -ForegroundColor Gray

Write-Host "`n🔧 STEP 3: Add category sections to HTML" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Yellow

$step3Code = @'
# Add this to your HTML generation section (around line 1450):

# Group findings by security category
$securityFindings = $findings | Where-Object { $_.SecurityCategory } | Group-Object SecurityCategory
$healthFindings = $findings | Where-Object { $_.HealthCategory } | Group-Object HealthCategory

# Add to HTML body:
$htmlBody += @"

<h2>🛡️ Security Categories</h2>
$(($securityFindings | ForEach-Object {
    $categoryName = $_.Name
    $categoryFindings = $_.Group
    $highRiskCount = ($categoryFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumRiskCount = ($categoryFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowRiskCount = ($categoryFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    
    @"
<div class="info-box">
    <h3>$categoryName</h3>
    <p><strong>Findings:</strong> $($categoryFindings.Count) | <strong>High:</strong> $highRiskCount | <strong>Medium:</strong> $mediumRiskCount | <strong>Low:</strong> $lowRiskCount</p>
    <p><strong>MITRE Techniques:</strong> $(($categoryFindings | Select-Object -ExpandProperty MITRETechniques -Unique) -join ', ')</p>
</div>
"@
}) -join '')

<h2>🔧 AD Health Categories</h2>
$(($healthFindings | ForEach-Object {
    $categoryName = $_.Name
    $categoryFindings = $_.Group
    @"
<div class="info-box">
    <h3>$categoryName</h3>
    <p><strong>Findings:</strong> $($categoryFindings.Count) | <strong>Avg Risk Score:</strong> $([math]::Round((($categoryFindings | Measure-Object -Property RiskScore -Average).Average), 1))</p>
</div>
"@
}) -join '')
"@
'@

Write-Host $step3Code -ForegroundColor Gray

Write-Host "`n🔧 STEP 4: Add MITRE technique lookup function" -ForegroundColor Yellow
Write-Host "===========================================" -ForegroundColor Yellow

$step4Code = @'
# Add this function to your script:

function Get-MITREDescription {
    param([string]$TechniqueID)
    
    $mitreTechniques = @{
        'T1078' = @{
            Name = 'Valid Accounts'
            Description = 'Adversaries may obtain and abuse credentials of existing accounts'
            Phase = 'Initial Access, Persistence, Privilege Escalation, Defense Evasion'
            Link = 'https://attack.mitre.org/techniques/T1078/'
        }
        'T1136' = @{
            Name = 'Create Account'
            Description = 'Adversaries may create an account to maintain access to victim systems'
            Phase = 'Persistence'
            Link = 'https://attack.mitre.org/techniques/T1136/'
        }
        'T1550' = @{
            Name = 'Use Alternate Authentication Material'
            Description = 'Adversaries may use alternate authentication material like password hashes, Kerberos tickets'
            Phase = 'Defense Evasion, Lateral Movement'
            Link = 'https://attack.mitre.org/techniques/T1550/'
        }
        'T1110' = @{
            Name = 'Brute Force'
            Description = 'Adversaries may use brute force techniques to gain access to accounts'
            Phase = 'Credential Access'
            Link = 'https://attack.mitre.org/techniques/T1110/'
        }
        'T1555' = @{
            Name = 'Credentials from Password Stores'
            Description = 'Adversaries may search for common password storage locations'
            Phase = 'Credential Access'
            Link = 'https://attack.mitre.org/techniques/T1555/'
        }
        'T1484' = @{
            Name = 'Domain Policy Modification'
            Description = 'Adversaries may modify domain configuration to evade security measures'
            Phase = 'Defense Evasion'
            Link = 'https://attack.mitre.org/techniques/T1484/'
        }
        'T1021' = @{
            Name = 'Remote Services'
            Description = 'Adversaries may use remote services to access and persist within a network'
            Phase = 'Lateral Movement, Persistence'
            Link = 'https://attack.mitre.org/techniques/T1021/'
        }
        'T1098' = @{
            Name = 'Account Manipulation'
            Description = 'Adversaries may manipulate accounts to maintain or escalate access'
            Phase = 'Persistence'
            Link = 'https://attack.mitre.org/techniques/T1098/'
        }
        'T1566' = @{
            Name = 'Phishing'
            Description = 'Adversaries may send phishing messages to gain access to victim systems'
            Phase = 'Initial Access'
            Link = 'https://attack.mitre.org/techniques/T1566/'
        }
        'T1562' = @{
            Name = 'Impair Defenses'
            Description = 'Adversaries may modify systems to impair or disable defensive mechanisms'
            Phase = 'Defense Evasion'
            Link = 'https://attack.mitre.org/techniques/T1562/'
        }
    }
    
    return $mitreTechniques[$TechniqueID]
}
'@

Write-Host $step4Code -ForegroundColor Gray

Write-Host "`n📊 IMPLEMENTATION IMPACT:" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host "✅ Benefits:" -ForegroundColor Green
Write-Host "  • Clear security vs operational categorization" -ForegroundColor Gray
Write-Host "  • MITRE ATT&CK technique mapping for threat modeling" -ForegroundColor Gray
Write-Host "  • Risk scoring for prioritization" -ForegroundColor Gray
Write-Host "  • Enhanced HTML reporting with category sections" -ForegroundColor Gray
Write-Host "  • Better stakeholder communication (Security vs IT Operations)" -ForegroundColor Gray

Write-Host "`n⚠️ Considerations:" -ForegroundColor Yellow
Write-Host "  • Slightly larger CSV/JSON output files" -ForegroundColor Gray
Write-Host "  • More complex HTML generation" -ForegroundColor Gray
Write-Host "  • Need to maintain MITRE technique mappings" -ForegroundColor Gray

Write-Host "`n🚀 RECOMMENDED IMPLEMENTATION:" -ForegroundColor Cyan
Write-Host "1. Start with Step 1 (add fields to remediation guide)" -ForegroundColor White
Write-Host "2. Test with a few findings first" -ForegroundColor White
Write-Host "3. Add Step 2 (enhanced findings creation)" -ForegroundColor White
Write-Host "4. Implement Step 3 (HTML sections)" -ForegroundColor White
Write-Host "5. Add Step 4 (MITRE lookup) for advanced features" -ForegroundColor White

Write-Host "`n💡 ALTERNATIVE: Use the standalone enhancement script" -ForegroundColor Cyan
Write-Host "Run: .\Enhanced-Findings-Categorization.ps1" -ForegroundColor Gray
Write-Host "This processes your existing assessment without modifying script.ps1" -ForegroundColor Gray
