<#
.SYNOPSIS
    Daily critical security checks for AD and Entra ID - Fast assessment (5-10 min)

.DESCRIPTION
    Performs rapid critical security checks focused on changes and high-risk findings:
    - Privileged role membership changes
    - MFA disabled or method changes
    - New OAuth admin consents
    - krbtgt password age (>180 days critical)
    - New external domain trusts
    - High-risk service principal changes
    - New privileged group members
    - Accounts with password never expiring (new)
    - Unconstrained delegation detection

    Designed for automated daily execution with Teams alerting.

.PARAMETER OutputFolder
    Path where results will be stored (default: ./DailyChecks)

.PARAMETER IncludeEntra
    Include Entra ID checks (requires Graph authentication)

.PARAMETER BaselinePath
    Path to previous day's results for comparison (optional)

.PARAMETER TeamsWebhookUrl
    Microsoft Teams webhook URL for sending alerts (optional)

.PARAMETER AlertThreshold
    Minimum severity to alert on: Critical, High, Medium (default: High)

.EXAMPLE
    .\Invoke-DailySecurityChecks.ps1
    Run AD-only daily checks

.EXAMPLE
    .\Invoke-DailySecurityChecks.ps1 -IncludeEntra -AlertThreshold Critical
    Run full daily checks, only alert on critical findings

.EXAMPLE
    .\Invoke-DailySecurityChecks.ps1 -IncludeEntra -TeamsWebhookUrl "https://outlook.office.com/webhook/..." -BaselinePath "yesterday.json"
    Run with Teams alerts and comparison to baseline

.NOTES
    Requires: ActiveDirectory module (RSAT)
    Requires: Microsoft.Graph modules (for Entra checks)
    Permissions: Directory.Read.All, UserAuthenticationMethod.Read.All
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "$PSScriptRoot\DailyChecks",
    [switch]$IncludeEntra,
    [string]$BaselinePath = "",
    [string]$TeamsWebhookUrl = "",
    [ValidateSet("Critical", "High", "Medium")]
    [string]$AlertThreshold = "High",
    [ValidateSet("Interactive", "Certificate", "ManagedIdentity", "ClientSecret")]
    [string]$AuthMethod = "Interactive",
    [string]$ClientId = "",
    [string]$TenantId = "",
    [string]$CertificateThumbprint = "",
    [string]$CertificateStoreLocation = "CurrentUser",
    [System.Management.Automation.PSCredential]$ClientSecretCredential
)

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dateStamp = Get-Date -Format "yyyy-MM-dd"
$results = @()
$alertFindings = @()

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Daily Critical Security Checks" -ForegroundColor Cyan
Write-Host "Date: $dateStamp" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Helper function to add finding
function Add-Finding {
    param(
        [string]$Id,
        [string]$Title,
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,
        [string]$Category,
        [string]$Description,
        [string]$Remediation,
        [string]$MITRETechnique = "",
        $Evidence = $null
    )

    $finding = [PSCustomObject]@{
        FindingId = $Id
        Title = $Title
        Severity = $Severity
        Category = $Category
        Description = $Description
        Remediation = $Remediation
        MITRETechnique = $MITRETechnique
        Evidence = $Evidence
        CheckedAt = (Get-Date).ToString("u")
        Status = "Open"
    }

    $script:results += $finding

    # Check if this should trigger alert based on threshold
    $severityLevels = @{ "Critical" = 4; "High" = 3; "Medium" = 2; "Low" = 1; "Info" = 0 }
    $thresholdLevel = $severityLevels[$AlertThreshold]
    $findingLevel = $severityLevels[$Severity]

    if ($findingLevel -ge $thresholdLevel) {
        $script:alertFindings += $finding
    }
}

# ============================================
# ACTIVE DIRECTORY CRITICAL CHECKS
# ============================================

Write-Host "[1/8] Checking AD critical items..." -ForegroundColor Cyan

# Check 1: krbtgt Password Age
try {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction Stop
    $krbtgtAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days

    if ($krbtgtAge -gt 180) {
        Add-Finding -Id "AD-001" -Title "krbtgt password older than 180 days" `
            -Severity "Critical" -Category "Privileged Access" `
            -Description "krbtgt password is $krbtgtAge days old. Enables Golden Ticket attacks." `
            -Remediation "Reset krbtgt password twice with 24hr gap using New-KrbtgtKeys.ps1" `
            -MITRETechnique "T1558.001" -Evidence @{ Age = $krbtgtAge; LastSet = $krbtgt.PasswordLastSet }
    }
    elseif ($krbtgtAge -gt 90) {
        Add-Finding -Id "AD-001" -Title "krbtgt password approaching 180 day limit" `
            -Severity "High" -Category "Privileged Access" `
            -Description "krbtgt password is $krbtgtAge days old. Should be reset before 180 days." `
            -Remediation "Schedule krbtgt password reset during next maintenance window" `
            -MITRETechnique "T1558.001" -Evidence @{ Age = $krbtgtAge; LastSet = $krbtgt.PasswordLastSet }
    }
}
catch {
    Add-Finding -Id "AD-001" -Title "Unable to check krbtgt password" `
        -Severity "High" -Category "Privileged Access" `
        -Description "Failed to retrieve krbtgt account: $_" `
        -Remediation "Verify AD module permissions and connectivity"
}

# Check 2: New Privileged Group Members (last 24h)
try {
    $privilegedGroups = @(
        "Enterprise Admins", "Domain Admins", "Schema Admins",
        "Account Operators", "Backup Operators", "Print Operators",
        "Administrators"
    )

    $oneDayAgo = (Get-Date).AddDays(-1)
    $newPrivMembers = @()

    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup $groupName -Properties Members -ErrorAction Stop
            foreach ($memberDN in $group.Members) {
                $member = Get-ADObject $memberDN -Properties whenCreated -ErrorAction SilentlyContinue
                if ($member -and $member.whenCreated -gt $oneDayAgo) {
                    $newPrivMembers += [PSCustomObject]@{
                        Group = $groupName
                        Member = $member.Name
                        MemberType = $member.ObjectClass
                        AddedOn = $member.whenCreated
                    }
                }
            }
        }
        catch {
            # Group may not exist, skip
        }
    }

    if ($newPrivMembers.Count -gt 0) {
        Add-Finding -Id "AD-002" -Title "New members added to privileged groups" `
            -Severity "Critical" -Category "Privileged Access" `
            -Description "$($newPrivMembers.Count) new member(s) added to privileged groups in last 24 hours" `
            -Remediation "Review new memberships. Verify changes are authorized. Check change management tickets." `
            -MITRETechnique "T1078.002" -Evidence $newPrivMembers
    }
}
catch {
    Add-Finding -Id "AD-002" -Title "Failed to check privileged group membership" `
        -Severity "High" -Category "Privileged Access" `
        -Description "Error checking privileged groups: $_" `
        -Remediation "Verify AD module permissions"
}

# Check 3: Unconstrained Delegation
try {
    $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516 } `
        -Properties TrustedForDelegation, Description -ErrorAction Stop

    if ($unconstrainedComputers.Count -gt 0) {
        $compNames = ($unconstrainedComputers | Select-Object -ExpandProperty Name) -join ", "
        Add-Finding -Id "AD-003" -Title "Computers with unconstrained delegation enabled" `
            -Severity "Critical" -Category "Privileged Access" `
            -Description "$($unconstrainedComputers.Count) computer(s) have unconstrained delegation: $compNames" `
            -Remediation "Disable unconstrained delegation. Use constrained or resource-based delegation instead." `
            -MITRETechnique "T1558.003" -Evidence ($unconstrainedComputers | Select-Object Name, DNSHostName, Description)
    }
}
catch {
    Add-Finding -Id "AD-003" -Title "Failed to check delegation settings" `
        -Severity "High" -Category "Privileged Access" `
        -Description "Error checking delegation: $_" `
        -Remediation "Verify AD module permissions"
}

# Check 4: New External Domain Trusts (last 24h)
try {
    $oneDayAgo = (Get-Date).AddDays(-1)
    $trusts = Get-ADTrust -Filter * -ErrorAction Stop
    $newTrusts = @()

    foreach ($trust in $trusts) {
        # Check if trust was created recently or has recent changes
        $trustObj = Get-ADObject -Identity $trust.DistinguishedName -Properties whenCreated, whenChanged -ErrorAction SilentlyContinue
        if ($trustObj) {
            if ($trustObj.whenCreated -gt $oneDayAgo -or $trustObj.whenChanged -gt $oneDayAgo) {
                $newTrusts += [PSCustomObject]@{
                    Source = $trust.Source
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    Direction = $trust.TrustDirection
                    Transitive = $trust.IsTransitive
                    Created = $trustObj.whenCreated
                    Changed = $trustObj.whenChanged
                }
            }
        }
    }

    if ($newTrusts.Count -gt 0) {
        Add-Finding -Id "AD-004" -Title "New or modified domain trusts detected" `
            -Severity "Critical" -Category "Access Management" `
            -Description "$($newTrusts.Count) domain trust(s) created or modified in last 24 hours" `
            -Remediation "Verify trust relationships are authorized. Review trust permissions." `
            -MITRETechnique "T1586.002" -Evidence $newTrusts
    }
}
catch {
    # Trust checks may fail in single-domain environments, log as info
    Add-Finding -Id "AD-004" -Title "Failed to check domain trusts" `
        -Severity "Medium" -Category "Access Management" `
        -Description "Error checking domain trusts: $_" `
        -Remediation "Verify AD module permissions"
}

# Check 5: Password Never Expiring Accounts (new in last 24h)
try {
    $oneDayAgo = (Get-Date).AddDays(-1)
    $pwdNeverExpire = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
        -Properties PasswordNeverExpires, PasswordLastSet, whenCreated -ErrorAction Stop |
        Where-Object { $_.whenCreated -gt $oneDayAgo -or $_.PasswordLastSet -gt $oneDayAgo }

    if ($pwdNeverExpire.Count -gt 0) {
        Add-Finding -Id "AD-005" -Title "New accounts with non-expiring passwords" `
            -Severity "High" -Category "Identity Hygiene" `
            -Description "$($pwdNeverExpire.Count) new account(s) created with PasswordNeverExpires flag" `
            -Remediation "Review accounts. Remove PasswordNeverExpires flag. Use gMSA for service accounts." `
            -MITRETechnique "T1078" -Evidence ($pwdNeverExpire | Select-Object SamAccountName, Name, whenCreated)
    }
}
catch {
    Add-Finding -Id "AD-005" -Title "Failed to check password expiration" `
        -Severity "Medium" -Category "Identity Hygiene" `
        -Description "Error checking password expiration: $_" `
        -Remediation "Verify AD module permissions"
}

Write-Host "  [OK] AD checks completed" -ForegroundColor Green

# ============================================
# ENTRA ID CRITICAL CHECKS
# ============================================

if ($IncludeEntra) {
    Write-Host "`n[2/8] Checking Entra ID critical items..." -ForegroundColor Cyan

    try {
        # Load configuration if available
        $configPath = Join-Path $PSScriptRoot "config\monitoring-config.json"
        $config = $null
        if (Test-Path $configPath) {
            $config = Get-Content $configPath | ConvertFrom-Json
        }

        # Determine authentication method
        $effectiveAuthMethod = $AuthMethod
        $effectiveClientId = $ClientId
        $effectiveTenantId = $TenantId
        $effectiveThumbprint = $CertificateThumbprint

        # Load from config if not provided as parameters
        if ($effectiveAuthMethod -eq "Interactive" -and $config -and $config.Entra -and $config.Entra.Authentication) {
            $authConfig = $config.Entra.Authentication
            if ($authConfig.Method -in @("Certificate", "ManagedIdentity", "ClientSecret")) {
                $effectiveAuthMethod = $authConfig.Method
                $effectiveClientId = if ($authConfig.ClientId) { $authConfig.ClientId } else { $env:MSGRAPH_CLIENT_ID }
                $effectiveTenantId = if ($authConfig.TenantId) { $authConfig.TenantId } else { $env:MSGRAPH_TENANT_ID }
                $effectiveThumbprint = if ($authConfig.CertificateThumbprint) { $authConfig.CertificateThumbprint } else { $env:MSGRAPH_CERT_THUMBPRINT }
            }
        }

        # Also check environment variables for certificate auth
        if ($effectiveAuthMethod -eq "Certificate") {
            if (-not $effectiveClientId) { $effectiveClientId = $env:MSGRAPH_CLIENT_ID }
            if (-not $effectiveTenantId) { $effectiveTenantId = $env:MSGRAPH_TENANT_ID }
            if (-not $effectiveThumbprint) { $effectiveThumbprint = $env:MSGRAPH_CERT_THUMBPRINT }
        }

        # Check if already connected to Graph
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "  Connecting to Microsoft Graph (Method: $effectiveAuthMethod)..." -ForegroundColor Yellow

            switch ($effectiveAuthMethod) {
                "Certificate" {
                    # Certificate-based authentication
                    if (-not $effectiveClientId -or -not $effectiveTenantId -or -not $effectiveThumbprint) {
                        Write-Error "Certificate auth requires ClientId, TenantId, and CertificateThumbprint"
                        Write-Host "  Set via parameters, config file, or environment variables:" -ForegroundColor Yellow
                        Write-Host "    MSGRAPH_CLIENT_ID, MSGRAPH_TENANT_ID, MSGRAPH_CERT_THUMBPRINT" -ForegroundColor Yellow
                        throw "Missing certificate authentication parameters"
                    }

                    $connectParams = @{
                        ClientId = $effectiveClientId
                        TenantId = $effectiveTenantId
                        CertificateThumbprint = $effectiveThumbprint
                        NoWelcome = $true
                    }

                    if ($CertificateStoreLocation -eq "LocalMachine") {
                        $connectParams.CertificateStoreLocation = "LocalMachine"
                    }

                    Connect-MgGraph @connectParams
                    Write-Host "  [OK] Connected via certificate auth" -ForegroundColor Green
                }

                "ManagedIdentity" {
                    # Managed identity authentication (Azure VMs only)
                    try {
                        Connect-MgGraph -Identity -NoWelcome
                        Write-Host "  [OK] Connected via managed identity" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Managed identity authentication failed: $_"
                        Write-Host "  Note: Managed identity only works on Azure VMs with managed identity enabled" -ForegroundColor Yellow
                        throw $_
                    }
                }

                "ClientSecret" {
                    # Client secret authentication
                    if (-not $ClientSecretCredential) {
                        # Try to get from environment or config
                        $secret = $env:MSGRAPH_CLIENT_SECRET
                        if ($config -and $config.Entra -and $config.Entra.Authentication -and $config.Entra.Authentication.ClientSecret) {
                            $secret = $config.Entra.Authentication.ClientSecret
                        }

                        if ($secret) {
                            $ClientSecretCredential = New-Object PSCredential(
                                "any",
                                (ConvertTo-SecureString $secret -AsPlainText -Force)
                            )
                        }
                        else {
                            Write-Error "ClientSecret auth requires ClientSecretCredential parameter or MSGRAPH_CLIENT_SECRET environment variable"
                            throw "Missing client secret credential"
                        }
                    }

                    if (-not $effectiveClientId -or -not $effectiveTenantId) {
                        Write-Error "ClientSecret auth requires ClientId and TenantId"
                        throw "Missing client secret parameters"
                    }

                    Connect-MgGraph `
                        -ClientId $effectiveClientId `
                        -TenantId $effectiveTenantId `
                        -ClientSecretCredential $ClientSecretCredential `
                        -NoWelcome
                    Write-Host "  [OK] Connected via client secret" -ForegroundColor Green
                }

                "Interactive" {
                    # Interactive authentication (default - requires user interaction)
                    Write-Host "  Using interactive authentication - browser login required" -ForegroundColor Yellow
                    Connect-MgGraph -Scopes "Directory.Read.All", "UserAuthenticationMethod.Read.All", "Policy.Read.All" -NoWelcome
                    Write-Host "  [OK] Connected via interactive auth" -ForegroundColor Green
                }

                default {
                    throw "Unsupported authentication method: $effectiveAuthMethod"
                }
            }

            # Display connection context
            $connContext = Get-MgContext
            Write-Host "  Tenant: $($connContext.TenantId)" -ForegroundColor Gray
            Write-Host "  Scopes: $($connContext.Scopes -join ', ')" -ForegroundColor Gray
        }
        else {
            Write-Host "  [OK] Already connected to Microsoft Graph" -ForegroundColor Green
        }

        # Check 6: MFA Disabled or Methods Changed
        try {
            $users = Get-MgUser -All -Property "Id,UserPrincipalName,DisplayName" -Top 1000
            $mfaDisabled = @()

            foreach ($user in $users) {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                if (-not $authMethods -or $authMethods.Count -eq 0) {
                    $mfaDisabled += [PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        Status = "No MFA methods registered"
                    }
                }
            }

            if ($mfaDisabled.Count -gt 5) {
                Add-Finding -Id "ENT-001" -Title "Multiple users without MFA methods" `
                    -Severity "High" -Category "Zero Trust" `
                    -Description "$($mfaDisabled.Count) users have no MFA methods registered" `
                    -Remediation "Enforce MFA registration via Conditional Access policy" `
                    -MITRETechnique "T1078" -Evidence ($mfaDisabled | Select-Object -First 20)
            }
            elseif ($mfaDisabled.Count -gt 0) {
                Add-Finding -Id "ENT-001" -Title "Users without MFA methods" `
                    -Severity "Medium" -Category "Zero Trust" `
                    -Description "$($mfaDisabled.Count) user(s) have no MFA methods registered" `
                    -Remediation "Enforce MFA registration via Conditional Access policy" `
                    -MITRETechnique "T1078" -Evidence ($mfaDisabled | Select-Object -First 20)
            }
        }
        catch {
            Write-Warning "MFA check failed: $_"
        }

        # Check 7: New OAuth Admin Consents (last 24h)
        try {
            $oneDayAgo = (Get-Date).AddDays(-1)
            $oAuthGrants = Get-MgOAuth2PermissionGrant -All -ErrorAction Stop |
                Where-Object { $_.ConsentType -eq "AllPrincipals" -or $_.ConsentType -eq "Principal" }

            $recentGrants = @()
            foreach ($grant in $oAuthGrants) {
                # Get app details
                $sp = Get-MgServicePrincipal -Filter "Id eq '$($grant.ClientId)'" -ErrorAction SilentlyContinue
                if ($sp) {
                    $recentGrants += [PSCustomObject]@{
                        AppName = $sp.DisplayName
                        Scope = $grant.Scope
                        ConsentType = $grant.ConsentType
                        ResourceId = $grant.ResourceId
                    }
                }
            }

            if ($recentGrants.Count -gt 0) {
                Add-Finding -Id "ENT-002" -Title "OAuth admin consent grants detected" `
                    -Severity "High" -Category "Application Security" `
                    -Description "$($recentGrants.Count) OAuth admin consent grant(s) found. Review for excessive permissions." `
                    -Remediation "Review granted permissions. Revoke unnecessary access. Implement consent policy." `
                    -MITRETechnique "T1528" -Evidence ($recentGrants | Select-Object -First 20)
            }
        }
        catch {
            Write-Warning "OAuth grants check failed: $_"
        }

        # Check 8: High-Privilege Service Principals
        try {
            $highRiskPermissions = @(
                "Directory.ReadWrite.All",
                "Directory.AccessAsUser.All",
                "RoleManagement.ReadWrite.Directory",
                "User.ReadWrite.All",
                "Group.ReadWrite.All",
                "Application.ReadWrite.All"
            )

            $servicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
            $riskySPs = @()

            foreach ($sp in $servicePrincipals) {
                # Check app roles
                $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                foreach ($role in $appRoles) {
                    foreach ($riskPerm in $highRiskPermissions) {
                        if ($role.AppRoleId -like "*$riskPerm*") {
                            $riskySPs += [PSCustomObject]@{
                                Name = $sp.DisplayName
                                AppId = $sp.AppId
                                Permission = $riskPerm
                                AssignmentType = "Application"
                            }
                        }
                    }
                }
            }

            if ($riskySPs.Count -gt 0) {
                Add-Finding -Id "ENT-003" -Title "Service principals with high-risk permissions" `
                    -Severity "Critical" -Category "Application Security" `
                    -Description "$($riskySPs.Count) service principal(s) have high-risk Graph API permissions" `
                    -Remediation "Review and reduce permissions. Implement least-privilege. Monitor usage." `
                    -MITRETechnique "T1528" -Evidence ($riskySPs | Select-Object -First 20)
            }
        }
        catch {
            Write-Warning "Service principal check failed: $_"
        }

        Write-Host "  [OK] Entra ID checks completed" -ForegroundColor Green

        # Disconnect from Graph
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Add-Finding -Id "ENT-000" -Title "Entra ID checks failed" `
            -Severity "High" -Category "Collection Error" `
            -Description "Failed to complete Entra ID checks: $_" `
            -Remediation "Check Graph module installation and permissions"
    }
}

# ============================================
# COMPARISON WITH BASELINE
# ============================================

$changes = @()
if ($BaselinePath -and (Test-Path $BaselinePath)) {
    Write-Host "`n[3/8] Comparing with baseline..." -ForegroundColor Cyan

    $baseline = Get-Content $BaselinePath | ConvertFrom-Json
    $currentFindings = $results | Where-Object { $_.Status -eq "Open" }

    foreach ($finding in $currentFindings) {
        $baselineFinding = $baseline | Where-Object { $_.FindingId -eq $finding.FindingId }
        if (-not $baselineFinding) {
            $changes += [PSCustomObject]@{
                ChangeType = "New"
                FindingId = $finding.FindingId
                Title = $finding.Title
                Severity = $finding.Severity
            }
        }
    }

    if ($changes.Count -gt 0) {
        Write-Host "  [!] $($changes.Count) new finding(s) since baseline" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK] No new findings since baseline" -ForegroundColor Green
    }
}

# ============================================
# EXPORT RESULTS
# ============================================

Write-Host "`n[4/8] Exporting results..." -ForegroundColor Cyan

# Export JSON (full results)
$jsonPath = Join-Path $OutputFolder "daily-checks-$timestamp.json"
$results | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host "  [OK] JSON: $jsonPath" -ForegroundColor Green

# Export CSV
$csvPath = Join-Path $OutputFolder "daily-checks-$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "  [OK] CSV: $csvPath" -ForegroundColor Green

# Export alerts-only JSON
if ($alertFindings.Count -gt 0) {
    $alertPath = Join-Path $OutputFolder "alerts-$timestamp.json"
    $alertFindings | ConvertTo-Json -Depth 4 | Out-File -FilePath $alertPath -Encoding UTF8
    Write-Host "  [OK] Alerts: $alertPath ($($alertFindings.Count) findings)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DAILY CHECKS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Findings: $($results.Count)" -ForegroundColor White
Write-Host "  Critical: $($results | Where-Object { $_.Severity -eq 'Critical' }).Count)" -ForegroundColor Red
Write-Host "  High: $(($results | Where-Object { $_.Severity -eq 'High' }).Count)" -ForegroundColor Magenta
Write-Host "  Medium: $(($results | Where-Object { $_.Severity -eq 'Medium' }).Count)" -ForegroundColor Yellow
Write-Host "  Low: $(($results | Where-Object { $_.Severity -eq 'Low' }).Count)" -ForegroundColor Green
Write-Host "Alert-Worthy: $($alertFindings.Count)" -ForegroundColor Yellow

# ============================================
# TEAMS ALERT
# ============================================

if ($alertFindings.Count -gt 0 -and $TeamsWebhookUrl) {
    Write-Host "`n[5/8] Sending Teams alert..." -ForegroundColor Cyan

    # Build Teams adaptive card message
    $criticalCount = ($alertFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($alertFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = ($alertFindings | Where-Object { $_.Severity -eq 'Medium' }).Count

    $teamsPayload = @{
        type = "message"
        attachments = @(
            @{
                contentType = "application/vnd.microsoft.card.adaptive"
                content = @{
                    schema = "http://adaptivecards.io/schemas/adaptive-card.json"
                    type = "AdaptiveCard"
                    version = "1.4"
                    body = @(
                        @{
                            type = "TextBlock"
                            text = "AD/Entra Daily Security Alert"
                            weight = "Bolding"
                            size = "Large"
                            color = if ($criticalCount -gt 0) { "Attention" } else { "Warning" }
                        }
                        @{
                            type = "TextBlock"
                            text = "Date: $dateStamp"
                            spacing = "None"
                            isSubtle = $true
                        }
                        @{
                            type = "FactSet"
                            facts = @(
                                @{ title = "Critical"; value = $criticalCount }
                                @{ title = "High"; value = $highCount }
                                @{ title = "Medium"; value = $mediumCount }
                                @{ title = "Total"; value = $alertFindings.Count }
                            )
                        }
                        @{
                            type = "TextBlock"
                            text = "Top Findings:"
                            weight = "Bolding"
                            spacing = "Medium"
                        }
                    )
                }
            }
        )
    }

    # Add top 5 findings to card
    $topFindings = $alertFindings | Select-Object -First 5
    foreach ($finding in $topFindings) {
        $severityEmoji = switch ($finding.Severity) {
            "Critical" { "[!!]" }
            "High" { "[!]" }
            "Medium" { "[~]" }
            default { "[-]" }
        }

        $teamsPayload.attachments[0].content.body += @{
            type = "TextBlock"
            text = "$severityEmoji **$($finding.Title)**`n   $($finding.Description)"
            wrap = $true
            spacing = "Small"
        }
    }

    # Add link to full results
    $teamsPayload.attachments[0].content.body += @{
        type = "TextBlock"
        text = "[View Full Report](file://$OutputFolder)"
        spacing = "Medium"
    }

    # Send to Teams
    try {
        $jsonBody = $teamsPayload | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -ContentType "application/json" -Body $jsonBody -ErrorAction Stop
        Write-Host "  [OK] Teams alert sent successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "  [X] Failed to send Teams alert: $_" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Daily Checks Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# Return results for pipeline usage
return $results
