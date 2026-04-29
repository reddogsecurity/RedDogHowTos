# ConditionalAccess-Analyzer.psm1
# Analyzes Conditional Access policy coverage and identifies gaps

Import-Module (Join-Path $PSScriptRoot "Helpers.psm1") -Force

function Invoke-CAGapAnalysis {
    <#
    .SYNOPSIS
    Analyzes Conditional Access policy coverage and identifies gaps
    
    .DESCRIPTION
    Performs comprehensive analysis of Conditional Access policies to:
    - Identify users not covered by any CA policy
    - Find applications without protection
    - Check for missing baseline policies
    - Calculate coverage percentages
    - Suggest missing policies
    
    .PARAMETER OutputFolder
    Path to folder containing assessment data
    
    .PARAMETER Timestamp
    Timestamp string for file naming
    
    .PARAMETER CAPoliciesJson
    Path to entra-conditionalaccess JSON file
    
    .PARAMETER EntraUsersCsv
    Path to entra-users CSV file
    
    .EXAMPLE
    Invoke-CAGapAnalysis -OutputFolder "C:\Assessments" -Timestamp "20251007-120000"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory)]
        [string]$Timestamp,
        
        [Parameter()]
        [string]$CAPoliciesJson,
        
        [Parameter()]
        [string]$EntraUsersCsv
    )
    
    Write-Host "Analyzing Conditional Access policy coverage..." -ForegroundColor Cyan
    
    # Load CA policies
    $caPolicies = if ($CAPoliciesJson -and (Test-Path $CAPoliciesJson)) {
        Get-Content $CAPoliciesJson | ConvertFrom-Json
    } else {
        Write-Warning "No Conditional Access policies file found"
        return $null
    }
    
    # Load users
    $users = if ($EntraUsersCsv -and (Test-Path $EntraUsersCsv)) {
        Import-Csv $EntraUsersCsv
    } else {
        Write-Warning "No Entra users file found"
        return $null
    }
    
    if (-not $caPolicies -or $caPolicies.Count -eq 0) {
        Write-Warning "No Conditional Access policies found - cannot perform gap analysis"
        
        # Return basic gap report
        return [PSCustomObject]@{
            TotalPolicies = 0
            EnabledPolicies = 0
            UserCoverage = 0
            AppCoverage = 0
            GapFindings = @([PSCustomObject]@{
                Area = 'Zero Trust'
                Gap = 'No Conditional Access policies deployed'
                Severity = 'Critical'
                Impact = 'All users can authenticate without MFA or device compliance checks'
                Recommendation = 'Enable Azure AD Security Defaults immediately, then deploy CA policies'
            })
            MissingBaselines = @('Require MFA for all users', 'Block legacy authentication', 'Require compliant device')
            CoverageStats = @{}
        }
    }
    
    # Initialize analysis structures
    $gaps = @()
    $missingBaselines = @()
    $coverageStats = @{}
    
    # Filter enabled policies only
    $enabledPolicies = $caPolicies | Where-Object { $_.State -eq 'enabled' }
    $reportOnlyPolicies = $caPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
    
    Write-Host "  Found $($caPolicies.Count) CA policies ($($enabledPolicies.Count) enabled, $($reportOnlyPolicies.Count) report-only)" -ForegroundColor Gray
    
    # === BASELINE POLICY CHECKS ===
    
    # 1. Require MFA for all users
    $hasMFAPolicy = $enabledPolicies | Where-Object {
        ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.BuiltInControls -contains 'Mfa') -and
        ($_.Conditions.Users.IncludeUsers -contains 'All' -or 
         $_.Conditions.Users.IncludeRoles -contains 'All')
    }
    
    if (-not $hasMFAPolicy) {
        $missingBaselines += 'Require MFA for all users'
        $gaps += [PSCustomObject]@{
            Area = 'Zero Trust Baseline'
            Gap = 'No policy requiring MFA for all users'
            Severity = 'High'
            Impact = 'Users can authenticate with password only - vulnerable to credential theft'
            Recommendation = 'Create CA policy: Require MFA for all users, all cloud apps'
            PolicyName = '[Missing] Require MFA - All Users'
            Conditions = 'Users: All, Apps: All Cloud Apps'
            Controls = 'Grant: Require MFA'
        }
    }
    
    # 2. Block legacy authentication
    $hasBlockLegacyAuth = $enabledPolicies | Where-Object {
        ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or 
         $_.Conditions.ClientAppTypes -contains 'other' -or
         $_.Conditions.ClientAppTypes -contains 'ExchangeActiveSync') -and
        ($_.GrantControls.BuiltInControls -contains 'block' -or $_.GrantControls.BuiltInControls -contains 'Block')
    }
    
    if (-not $hasBlockLegacyAuth) {
        $missingBaselines += 'Block legacy authentication'
        $gaps += [PSCustomObject]@{
            Area = 'Zero Trust Baseline'
            Gap = 'No policy blocking legacy authentication protocols'
            Severity = 'High'
            Impact = 'Legacy protocols (IMAP, POP, SMTP) bypass MFA entirely'
            Recommendation = 'Create CA policy: Block legacy auth for all users, all apps'
            PolicyName = '[Missing] Block Legacy Authentication'
            Conditions = 'Users: All, Apps: All, Client Apps: Exchange ActiveSync, Other Clients'
            Controls = 'Block Access'
        }
    }
    
    # 3. Require compliant or hybrid joined devices
    $hasDeviceCompliancePolicy = $enabledPolicies | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'compliantDevice' -or 
        $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice' -or
        $_.GrantControls.BuiltInControls -contains 'CompliantDevice' -or
        $_.GrantControls.BuiltInControls -contains 'DomainJoinedDevice'
    }
    
    if (-not $hasDeviceCompliancePolicy) {
        $missingBaselines += 'Require compliant or hybrid joined device'
        $gaps += [PSCustomObject]@{
            Area = 'Zero Trust Baseline'
            Gap = 'No policy requiring device compliance or hybrid join'
            Severity = 'Medium'
            Impact = 'Unmanaged devices can access corporate resources'
            Recommendation = 'Create CA policy: Require compliant device for all users, all apps (with break-glass exclusions)'
            PolicyName = '[Missing] Require Compliant Device'
            Conditions = 'Users: All (exclude break-glass), Apps: All Cloud Apps'
            Controls = 'Grant: Require compliant device OR hybrid Azure AD joined device'
        }
    }
    
    # 4. Require MFA for admins (specific)
    $hasAdminMFAPolicy = $enabledPolicies | Where-Object {
        ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.BuiltInControls -contains 'Mfa') -and
        ($_.Conditions.Users.IncludeRoles -and $_.Conditions.Users.IncludeRoles.Count -gt 0)
    }
    
    if (-not $hasAdminMFAPolicy) {
        $missingBaselines += 'Require MFA for administrators (role-based)'
        $gaps += [PSCustomObject]@{
            Area = 'Privileged Access Protection'
            Gap = 'No specific MFA policy for admin roles'
            Severity = 'High'
            Impact = 'Privileged accounts may not be forced to use MFA'
            Recommendation = 'Create CA policy: Require MFA for all admin directory roles'
            PolicyName = '[Missing] Require MFA - Admins'
            Conditions = 'Roles: All admin roles, Apps: All'
            Controls = 'Grant: Require MFA'
        }
    }
    
    # 5. Block access from untrusted locations
    $hasLocationPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.Locations -and 
        ($_.Conditions.Locations.ExcludeLocations -contains 'AllTrusted' -or
         $_.Conditions.Locations.IncludeLocations -contains 'All')
    }
    
    if (-not $hasLocationPolicy) {
        $gaps += [PSCustomObject]@{
            Area = 'Zero Trust Baseline'
            Gap = 'No location-based access policies'
            Severity = 'Low'
            Impact = 'Cannot restrict access from untrusted/risky locations'
            Recommendation = 'Create CA policy: Block or require MFA from untrusted locations'
            PolicyName = '[Missing] Location-Based Access Control'
            Conditions = 'Users: All, Locations: All (exclude trusted locations)'
            Controls = 'Grant: Require MFA OR Block access'
        }
    }
    
    # 6. Sign-in risk-based policy
    $hasSignInRiskPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.SignInRiskLevels -and $_.Conditions.SignInRiskLevels.Count -gt 0
    }
    
    if (-not $hasSignInRiskPolicy) {
        $gaps += [PSCustomObject]@{
            Area = 'Identity Protection'
            Gap = 'No sign-in risk-based policies'
            Severity = 'Medium'
            Impact = 'Cannot automatically respond to risky sign-ins detected by Azure AD Identity Protection'
            Recommendation = 'Create CA policy: Require MFA for medium/high risk sign-ins, block for high risk'
            PolicyName = '[Missing] Sign-in Risk Policy'
            Conditions = 'Users: All, Sign-in Risk: Medium, High'
            Controls = 'Grant: Require MFA (medium), Block (high)'
        }
    }
    
    # 7. User risk-based policy
    $hasUserRiskPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.UserRiskLevels -and $_.Conditions.UserRiskLevels.Count -gt 0
    }
    
    if (-not $hasUserRiskPolicy) {
        $gaps += [PSCustomObject]@{
            Area = 'Identity Protection'
            Gap = 'No user risk-based policies'
            Severity = 'Medium'
            Impact = 'Cannot automatically respond to compromised user accounts'
            Recommendation = 'Create CA policy: Require password change for high-risk users'
            PolicyName = '[Missing] User Risk Policy'
            Conditions = 'Users: All, User Risk: High'
            Controls = 'Grant: Require password change + MFA'
        }
    }
    
    # === COVERAGE ANALYSIS ===
    
    # Analyze user coverage
    $allUsersIncluded = @()
    $allUsersExcluded = @()
    
    foreach ($policy in $enabledPolicies) {
        # Check inclusions
        if ($policy.Conditions.Users.IncludeUsers -contains 'All') {
            $allUsersIncluded += 'All'
        } elseif ($policy.Conditions.Users.IncludeUsers) {
            $allUsersIncluded += $policy.Conditions.Users.IncludeUsers
        }
        
        # Check exclusions
        if ($policy.Conditions.Users.ExcludeUsers) {
            $allUsersExcluded += $policy.Conditions.Users.ExcludeUsers
        }
    }
    
    # Calculate coverage
    $userCoveragePercentage = if ($users.Count -gt 0) {
        if ($allUsersIncluded -contains 'All') {
            $excludedCount = ($allUsersExcluded | Select-Object -Unique).Count
            [math]::Round((($users.Count - $excludedCount) / $users.Count) * 100, 1)
        } else {
            $includedCount = ($allUsersIncluded | Select-Object -Unique).Count
            [math]::Round(($includedCount / $users.Count) * 100, 1)
        }
    } else { 0 }
    
    # Check for break-glass accounts
    $hasBreakGlass = $allUsersExcluded.Count -ge 2
    if (-not $hasBreakGlass -and $enabledPolicies.Count -gt 0) {
        $gaps += [PSCustomObject]@{
            Area = 'Business Continuity'
            Gap = 'No break-glass accounts detected in CA exclusions'
            Severity = 'Medium'
            Impact = 'Risk of admin lockout if CA policies misconfigured'
            Recommendation = 'Create 2-3 break-glass accounts, exclude from all CA policies, monitor usage'
            PolicyName = '[Best Practice] Break-Glass Accounts'
            Conditions = 'N/A'
            Controls = 'Exclude emergency access accounts from ALL policies'
        }
    }
    
    # Policy state warnings
    if ($reportOnlyPolicies.Count -gt 0) {
        $gaps += [PSCustomObject]@{
            Area = 'Policy Enforcement'
            Gap = "$($reportOnlyPolicies.Count) policies in report-only mode (not enforced)"
            Severity = 'Low'
            Impact = 'Policies are not actively blocking risky sign-ins'
            Recommendation = 'Review report data, then enable policies for enforcement'
            PolicyName = 'Report-Only Policies'
            Conditions = "Policies: $($reportOnlyPolicies.DisplayName -join ', ')"
            Controls = 'Change State to Enabled'
        }
    }
    
    # === CALCULATE STATISTICS ===
    
    $coverageStats = @{
        TotalPolicies = $caPolicies.Count
        EnabledPolicies = $enabledPolicies.Count
        ReportOnlyPolicies = $reportOnlyPolicies.Count
        DisabledPolicies = ($caPolicies | Where-Object { $_.State -eq 'disabled' }).Count
        UserCoveragePercentage = $userCoveragePercentage
        HasMFABaseline = $null -ne $hasMFAPolicy
        HasBlockLegacyAuth = $null -ne $hasBlockLegacyAuth
        HasDeviceCompliance = $null -ne $hasDeviceCompliancePolicy
        HasAdminMFAPolicy = $null -ne $hasAdminMFAPolicy
        HasLocationPolicy = $null -ne $hasLocationPolicy
        HasSignInRiskPolicy = $null -ne $hasSignInRiskPolicy
        HasUserRiskPolicy = $null -ne $hasUserRiskPolicy
        HasBreakGlassAccounts = $hasBreakGlass
        MissingBaselineCount = $missingBaselines.Count
        TotalGaps = $gaps.Count
    }
    
    # Export gap analysis
    $gapCsv = Join-Path $OutputFolder "ca-gap-analysis-$Timestamp.csv"
    $gaps | Export-Csv $gapCsv -NoTypeInformation -Force
    
    # Export coverage stats
    $coverageJson = Join-Path $OutputFolder "ca-coverage-stats-$Timestamp.json"
    $coverageStats | ConvertTo-Json | Out-File $coverageJson -Force
    
    # Generate detailed policy inventory
    $policyInventory = @()
    foreach ($policy in $caPolicies) {
        $includeUsers = if ($policy.Conditions.Users.IncludeUsers -contains 'All') { 'All Users' }
                        elseif ($policy.Conditions.Users.IncludeUsers) { "$($policy.Conditions.Users.IncludeUsers.Count) users" }
                        else { '0 users' }
        
        $includeRoles = if ($policy.Conditions.Users.IncludeRoles) { "$($policy.Conditions.Users.IncludeRoles.Count) roles" } else { '0 roles' }
        $excludeUsers = if ($policy.Conditions.Users.ExcludeUsers) { "$($policy.Conditions.Users.ExcludeUsers.Count) users" } else { '0 users' }
        
        $controls = if ($policy.GrantControls.BuiltInControls) {
            $policy.GrantControls.BuiltInControls -join ', '
        } else { 'Block' }
        
        $policyInventory += [PSCustomObject]@{
            DisplayName = $policy.DisplayName
            State = $policy.State
            IncludeUsers = $includeUsers
            IncludeRoles = $includeRoles
            ExcludeUsers = $excludeUsers
            ClientAppTypes = ($policy.Conditions.ClientAppTypes -join ', ')
            GrantControls = $controls
            CreatedDateTime = $policy.CreatedDateTime
            ModifiedDateTime = $policy.ModifiedDateTime
        }
    }
    
    $inventoryCsv = Join-Path $OutputFolder "ca-policy-inventory-$Timestamp.csv"
    $policyInventory | Export-Csv $inventoryCsv -NoTypeInformation -Force
    
    # Console output
    Write-Host "`nConditional Access Gap Analysis Results:" -ForegroundColor Cyan
    Write-Host "  Total Policies: $($coverageStats.TotalPolicies)" -ForegroundColor White
    Write-Host "  Enabled: $($coverageStats.EnabledPolicies)" -ForegroundColor Green
    Write-Host "  Report-Only: $($coverageStats.ReportOnlyPolicies)" -ForegroundColor Yellow
    Write-Host "  User Coverage: $($coverageStats.UserCoveragePercentage)%" -ForegroundColor $(if ($userCoveragePercentage -ge 90) { 'Green' } elseif ($userCoveragePercentage -ge 70) { 'Yellow' } else { 'Red' })
    
    Write-Host "`n  Baseline Policies:" -ForegroundColor White
    Write-Host "    MFA for all users: $(if ($coverageStats.HasMFABaseline) { '[OK]' } else { '[X]' })" -ForegroundColor $(if ($coverageStats.HasMFABaseline) { 'Green' } else { 'Red' })
    Write-Host "    Block legacy auth: $(if ($coverageStats.HasBlockLegacyAuth) { '[OK]' } else { '[X]' })" -ForegroundColor $(if ($coverageStats.HasBlockLegacyAuth) { 'Green' } else { 'Red' })
    Write-Host "    Device compliance: $(if ($coverageStats.HasDeviceCompliance) { '[OK]' } else { '[X]' })" -ForegroundColor $(if ($coverageStats.HasDeviceCompliance) { 'Green' } else { 'Red' })
    Write-Host "    Admin MFA: $(if ($coverageStats.HasAdminMFAPolicy) { '[OK]' } else { '[X]' })" -ForegroundColor $(if ($coverageStats.HasAdminMFAPolicy) { 'Green' } else { 'Red' })
    
    Write-Host "`n  Gap Analysis:" -ForegroundColor White
    Write-Host "    Missing baselines: $($missingBaselines.Count)" -ForegroundColor $(if ($missingBaselines.Count -eq 0) { 'Green' } else { 'Red' })
    Write-Host "    Total gaps found: $($gaps.Count)" -ForegroundColor $(if ($gaps.Count -eq 0) { 'Green' } elseif ($gaps.Count -le 3) { 'Yellow' } else { 'Red' })
    
    Write-Host "`nExported Files:" -ForegroundColor Gray
    Write-Host "  - $gapCsv" -ForegroundColor Gray
    Write-Host "  - $coverageJson" -ForegroundColor Gray
    Write-Host "  - $inventoryCsv" -ForegroundColor Gray
    
    return [PSCustomObject]@{
        TotalPolicies = $coverageStats.TotalPolicies
        EnabledPolicies = $coverageStats.EnabledPolicies
        UserCoverage = $userCoveragePercentage
        GapFindings = $gaps
        MissingBaselines = $missingBaselines
        CoverageStats = $coverageStats
        GapCsvPath = $gapCsv
        CoverageJsonPath = $coverageJson
        InventoryCsvPath = $inventoryCsv
    }
}

Export-ModuleMember -Function Invoke-CAGapAnalysis

