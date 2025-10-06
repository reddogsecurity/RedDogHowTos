# Helpers.psm1
# Common helper functions for AD assessment

function Write-OutputFiles {
    <#
    .SYNOPSIS
    Exports data to both CSV and JSON formats
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        $Object,
        
        [Parameter(Mandatory)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory)]
        [string]$Timestamp
    )
    
    $csv = Join-Path $OutputFolder "$Name-$Timestamp.csv"
    $json = Join-Path $OutputFolder "$Name-$Timestamp.json"
    $Object | Export-Csv -Path $csv -NoTypeInformation -Force
    $Object | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Force
}

function Get-LatestFile {
    <#
    .SYNOPSIS
    Gets the most recent file matching a pattern
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Pattern,
        
        [Parameter(Mandatory)]
        [string]$Folder
    )
    
    $f = Get-ChildItem -Path $Folder -Filter $Pattern -File -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
    return $f?.FullName
}

function Get-RemediationGuidance {
    <#
    .SYNOPSIS
    Returns remediation guidance for a specific risk type
    #>
    param([string]$RiskType)
    
    $remediationGuide = @{
        'StaleUsers' = @{
            Impact = 'Inactive accounts are attack targets - credentials may be compromised without detection'
            Steps = '1. Review list of inactive users in ad-users CSV|2. Disable accounts inactive >90 days|3. Move to quarantine OU for 30 days|4. Delete if no business need documented|5. Implement automated account lifecycle policy'
            Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
            Effort = '2-4 hours'
            Category = 'Identity Hygiene'
        }
        'PasswordNeverExpires' = @{
            Impact = 'Accounts with non-expiring passwords pose long-term credential theft risk'
            Steps = '1. Review users with PasswordNeverExpires flag|2. For service accounts: transition to gMSA or Entra managed identity|3. For users: remove flag and enforce password rotation|4. Implement password policy compliance monitoring'
            Reference = 'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview'
            Effort = '4-6 hours'
            Category = 'Identity Hygiene'
        }
        'KerberosDelegation' = @{
            Impact = 'Delegation allows accounts to impersonate users - creates high lateral movement risk'
            Steps = '1. Review delegation assignments in evidence file|2. Remove unconstrained delegation immediately|3. Replace with constrained or resource-based delegation|4. Enable "Account is sensitive and cannot be delegated" for privileged users|5. Monitor Event 4662 for delegation abuse'
            Reference = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
            Effort = '6-8 hours'
            Category = 'Privileged Access'
        }
        'UnconstrainedDelegation' = @{
            Impact = 'CRITICAL: Enables credential theft and Golden Ticket attacks via TGT harvesting'
            Steps = '1. URGENT: Identify all computers with unconstrained delegation|2. Replace with constrained delegation for specific services only|3. Enable SMB signing and LDAP signing|4. Monitor Event 4768/4769 for TGT requests|5. Consider Protected Users group for sensitive accounts'
            Reference = 'https://adsecurity.org/?p=1667'
            Effort = '8-12 hours'
            Category = 'Privileged Access'
        }
        'KrbtgtPassword' = @{
            Impact = 'CRITICAL: Old krbtgt password enables indefinite Golden Ticket attacks'
            Steps = '1. Schedule maintenance window - requires 2 sessions 24 hours apart|2. Run New-KrbtgtKeys.ps1 to reset password|3. Wait 24 hours for AD replication|4. Run New-KrbtgtKeys.ps1 again (second reset)|5. Monitor Event Logs for Kerberos errors|6. Set recurring reminder for 180 days'
            Reference = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password'
            Effort = '2-3 hours + 24hr wait'
            Category = 'Critical Security'
        }
        'SPNAccounts' = @{
            Impact = 'SPNs expose service accounts to Kerberoasting - offline password cracking attacks'
            Steps = '1. Audit all SPN accounts in evidence CSV|2. Set long complex passwords (25+ characters) or use gMSA|3. Transition to group Managed Service Accounts where possible|4. Enable "Account is sensitive" for high-value SPNs|5. Monitor Event 4769 for RC4 encryption (Kerberoast indicator)|6. Implement SPN ACL restrictions'
            Reference = 'https://adsecurity.org/?p=2293'
            Effort = '6-10 hours'
            Category = 'Identity Hygiene'
        }
        'OversizedGroups' = @{
            Impact = 'Large groups complicate access review and often contain excessive permissions'
            Steps = '1. Review groups with 500+ members|2. Identify group purpose and business owner|3. Split into functional sub-groups by department/role|4. Implement RBAC model using Entra ID roles|5. Remove circular/nested group sprawl|6. Establish group management policy with regular reviews'
            Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices'
            Effort = '10-15 hours'
            Category = 'Access Management'
        }
        'PrivilegedRoles' = @{
            Impact = 'Excessive privileged access increases insider threat and breach impact radius'
            Steps = '1. Review all members of privileged roles in evidence JSON|2. Remove unnecessary permanent assignments|3. Implement Privileged Identity Management (PIM) for just-in-time access|4. Require MFA for all privileged accounts|5. Create emergency break-glass accounts (2-3)|6. Enable privileged activity auditing and alerts'
            Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure'
            Effort = '8-12 hours'
            Category = 'Privileged Access'
        }
        'NoConditionalAccess' = @{
            Impact = 'CRITICAL: No Zero Trust controls - authentication security relies solely on passwords'
            Steps = '1. Enable Azure AD Security Defaults immediately as interim measure|2. Plan Conditional Access policy rollout|3. Start with: require MFA for all users|4. Add: block legacy authentication protocols|5. Implement: require compliant or hybrid joined devices|6. Add: risk-based sign-in policies|7. Test all policies in report-only mode before enforcement'
            Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/plan-conditional-access'
            Effort = '12-20 hours'
            Category = 'Zero Trust'
        }
        'NoMFA' = @{
            Impact = 'Users without MFA are vulnerable to password spray, phishing, and credential stuffing attacks'
            Steps = '1. Launch MFA registration campaign with user communications|2. Start with Global Admins (mandatory)|3. Roll out to all users in phases by department|4. Provide multiple MFA methods: Microsoft Authenticator app, FIDO2 keys, Windows Hello for Business|5. Configure Conditional Access to block legacy auth that bypasses MFA|6. Monitor MFA registration compliance dashboard'
            Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks'
            Effort = '15-25 hours + user training'
            Category = 'Zero Trust'
        }
        'LegacyAuth' = @{
            Impact = 'Legacy authentication protocols bypass MFA and modern security controls entirely'
            Steps = '1. Identify applications using legacy auth in sign-in logs|2. Update or replace legacy applications|3. Configure Conditional Access policy to block legacy auth|4. Create temporary exception for service accounts with monitoring|5. Monitor blocked sign-in attempts|6. Plan decommissioning of IMAP/POP/SMTP protocols'
            Reference = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication'
            Effort = '8-15 hours'
            Category = 'Zero Trust'
        }
    }
    
    if ($remediationGuide.ContainsKey($RiskType)) {
        return $remediationGuide[$RiskType]
    }
    
    # Default fallback
    return @{
        Impact = 'Review finding details and consult security best practices for remediation approach'
        Steps = '1. Assess risk and business impact|2. Plan remediation strategy|3. Implement security controls|4. Verify effectiveness|5. Document changes'
        Reference = 'https://learn.microsoft.com/en-us/security/'
        Effort = 'TBD'
        Category = 'General'
    }
}

Export-ModuleMember -Function Write-OutputFiles, Get-LatestFile, Get-RemediationGuidance

