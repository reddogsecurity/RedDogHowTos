# AD-Collector.psm1
# Active Directory data collection module

Import-Module (Join-Path $PSScriptRoot "Helpers.psm1") -Force

function Invoke-ADCollection {
    <#
    .SYNOPSIS
    Collects Active Directory inventory data
    
    .PARAMETER OutputFolder
    Path where collected data will be stored
    
    .PARAMETER Timestamp
    Timestamp string to append to output files
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory)]
        [string]$Timestamp
    )
    
    Write-Host "Collecting Active Directory inventory..." -ForegroundColor Cyan

    # Ensure AD module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found. Install RSAT or run on a machine with RSAT installed."
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    # Basic domain/forest info
    try {
        $forest = Get-ADForest
        $domain = Get-ADDomain
        $dcs = Get-ADDomainController -Filter * | Select-Object Name,HostName,IPv4Address,OperatingSystem,IsGlobalCatalog
        
        # Detailed trust enumeration
        $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue | Select-Object Name,Direction,TrustType,Source,Target,@{n='TrustAttributes';e={$_.TrustAttributes}},WhenCreated,SelectiveAuthentication
    } catch {
        Write-Warning "Error querying forest/domain: $_"
    }

    $forest | ConvertTo-Json | Out-File (Join-Path $OutputFolder "forest-$Timestamp.json")
    $domain | ConvertTo-Json | Out-File (Join-Path $OutputFolder "domain-$Timestamp.json")
    $dcs | ConvertTo-Json | Out-File (Join-Path $OutputFolder "dcs-$Timestamp.json")
    $trusts | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-trusts-$Timestamp.json")

    # Password policies
    Write-Host "Collecting password policies..." -ForegroundColor Gray
    $defaultPwdPolicy = Get-ADDefaultDomainPasswordPolicy
    $defaultPwdPolicy | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-default-pwd-policy-$Timestamp.json")
    
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue | Select-Object Name,Precedence,MinPasswordLength,PasswordHistoryCount,LockoutThreshold,ComplexityEnabled,AppliesTo
    if ($fgpp) {
        $fgpp | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-fgpp-$Timestamp.json")
    }

    # Users, groups, computers (paged)
    Write-Host "Enumerating users..." -ForegroundColor Gray
    $users = Get-ADUser -Filter * -Properties SamAccountName,UserPrincipalName,Enabled,whenCreated,whenChanged,lastLogonTimestamp,PasswordLastSet,AdminCount,PasswordNeverExpires,TrustedForDelegation,TrustedToAuthForDelegation,MemberOf | 
        Select-Object SamAccountName,UserPrincipalName,Enabled,whenCreated, 
            @{n='LastLogon';e={if($_.lastLogonTimestamp){[DateTime]::FromFileTime($_.lastLogonTimestamp)}}},
            PasswordLastSet,AdminCount,PasswordNeverExpires,TrustedForDelegation,TrustedToAuthForDelegation,
            @{n='DaysSinceLogon';e={if($_.lastLogonTimestamp){(New-TimeSpan -Start ([DateTime]::FromFileTime($_.lastLogonTimestamp)) -End (Get-Date)).Days}}},
            MemberOf
    Write-OutputFiles -Name "ad-users" -Object $users -OutputFolder $OutputFolder -Timestamp $Timestamp

    Write-Host "Enumerating groups..." -ForegroundColor Gray
    $groups = Get-ADGroup -Filter * -Properties SamAccountName,GroupCategory,GroupScope,whenCreated,member | 
        Select-Object SamAccountName,GroupCategory,GroupScope,whenCreated,@{n='MemberCount';e={$_.member.count}}
    Write-OutputFiles -Name "ad-groups" -Object $groups -OutputFolder $OutputFolder -Timestamp $Timestamp

    Write-Host "Enumerating computers..." -ForegroundColor Gray
    $computers = Get-ADComputer -Filter * -Properties Name,OperatingSystem,OperatingSystemVersion,IPv4Address,whenCreated,lastLogonTimestamp,TrustedForDelegation,TrustedToAuthForDelegation,MemberOf | 
        Select-Object Name,OperatingSystem,OperatingSystemVersion, 
            @{n='LastLogon';e={if($_.lastLogonTimestamp){[DateTime]::FromFileTime($_.lastLogonTimestamp)}}},
            @{n='DaysSinceLogon';e={if($_.lastLogonTimestamp){(New-TimeSpan -Start ([DateTime]::FromFileTime($_.lastLogonTimestamp)) -End (Get-Date)).Days}}},
            whenCreated,TrustedForDelegation,TrustedToAuthForDelegation
    Write-OutputFiles -Name "ad-computers" -Object $computers -OutputFolder $OutputFolder -Timestamp $Timestamp
    
    # Check krbtgt password age (critical security metric)
    Write-Host "Checking krbtgt account..." -ForegroundColor Gray
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet,whenCreated
    $krbtgtAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
    $krbtgtInfo = [PSCustomObject]@{
        Account = 'krbtgt'
        PasswordLastSet = $krbtgt.PasswordLastSet
        PasswordAgeDays = $krbtgtAge
        WhenCreated = $krbtgt.whenCreated
        RiskLevel = if($krbtgtAge -gt 180){'HIGH - Password >180 days old'}elseif($krbtgtAge -gt 90){'MEDIUM'}else{'OK'}
    }
    $krbtgtInfo | ConvertTo-Json | Out-File (Join-Path $OutputFolder "ad-krbtgt-$Timestamp.json")

    # Identify privileged groups membership
    $privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Enterprise Read-only Domain Controllers') 
    $privResults = foreach ($g in $privGroups) {
        $grp = Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue
        if ($grp) {
            $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue | Select-Object Name,SamAccountName,objectClass
            [PSCustomObject]@{ Group = $g; Count = $members.count; Members = $members }
        } else {
            [PSCustomObject]@{ Group = $g; Count = 0; Members = @() }
        }
    }
    $privResults | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "ad-privileged-groups-$Timestamp.json")

    # GPOs and links
    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
        Write-Host "Enumerating GPOs..." -ForegroundColor Gray
        $gpos = Get-GPO -All | Select-Object DisplayName,Id,CreationTime,ModificationTime
        $gpoLinks = foreach ($g in $gpos) {
            $links = (Get-GPOReport -Guid $g.Id -ReportType XML) -as [xml]
            [PSCustomObject]@{ GPO = $g.DisplayName; Id = $g.Id; XML = $links.OuterXml }
        }
        $gpos | Export-Csv (Join-Path $OutputFolder "ad-gpos-$Timestamp.csv") -NoTypeInformation -Force
        $gpoLinks | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputFolder "ad-gpo-links-$Timestamp.json")
    } else {
        Write-Warning "GPMC / GroupPolicy module not available. Install GroupPolicy RSAT if you need GPO details."
    }

    # OU ACLs - detect non-standard permissions (simplified)
    Write-Host "Enumerating OUs and ACLs (read-only)..." -ForegroundColor Gray
    $ous = Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion,distinguishedName | 
        Select-Object Name,DistinguishedName,ProtectedFromAccidentalDeletion
    $ouAclFindings = foreach ($ou in $ous) {
        try {
            $acl = Get-Acl "AD:$($ou.DistinguishedName)"
            $aces = $acl.Access | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,InheritanceType
            [PSCustomObject]@{ OU = $ou.Name; DN = $ou.DistinguishedName; ACEs = $aces }
        } catch {
            [PSCustomObject]@{ OU = $ou.Name; DN = $ou.DistinguishedName; ACEs = "error: $_" }
        }
    }
    $ouAclFindings | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputFolder "ad-ou-acls-$Timestamp.json")

    # SPNs (Kerberoast surface)
    Write-Host "Collecting accounts with SPNs (service accounts)..." -ForegroundColor Gray
    $spnAccounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName | 
        Select-Object SamAccountName,ServicePrincipalName
    $spnAccounts | Export-Csv (Join-Path $OutputFolder "ad-spn-accounts-$Timestamp.csv") -NoTypeInformation -Force

    Write-Host "Active Directory collection complete." -ForegroundColor Green
}

Export-ModuleMember -Function Invoke-ADCollection

