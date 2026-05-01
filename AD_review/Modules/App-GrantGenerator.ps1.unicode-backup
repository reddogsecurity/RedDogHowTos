# App & Grant Views Diagram Generator
# Creates diagrams showing service principals with OAuth scopes and permissions

class ServicePrincipalNode {
    [string]$Name
    [string]$DisplayName
    [string]$ObjectId
    [string]$AppId
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    ServicePrincipalNode([string]$Name, [string]$DisplayName, [string]$ObjectId, [string]$AppId) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.ObjectId = $ObjectId
        $this.AppId = $AppId
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class OAuthScopeNode {
    [string]$Name
    [string]$DisplayName
    [string]$ScopeType
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    OAuthScopeNode([string]$Name, [string]$DisplayName, [string]$ScopeType) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.ScopeType = $ScopeType
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class GrantEdge {
    [string]$From
    [string]$To
    [string]$GrantType
    [string]$PermissionType
    [hashtable]$Properties
    
    GrantEdge([string]$From, [string]$To, [string]$GrantType, [string]$PermissionType) {
        $this.From = $From
        $this.To = $To
        $this.GrantType = $GrantType
        $this.PermissionType = $PermissionType
        $this.Properties = @{}
    }
}

function New-AppGrantDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building App & Grant Views diagram..." -ForegroundColor Cyan
    
    # Check if we have service principal data
    if (-not $GraphData.DataCache.ContainsKey("servicePrincipals") -or 
        -not $GraphData.DataCache.ContainsKey("oauthScopes")) {
        Write-Warning "Service principal or OAuth scope data not available. Using sample data..."
        $spData = Get-SampleServicePrincipalData
        $scopeData = Get-SampleOAuthScopeData
        $grantData = Get-SampleGrantData
    } else {
        $spData = $GraphData.DataCache["servicePrincipals"]
        $scopeData = $GraphData.DataCache["oauthScopes"]
        $grantData = $GraphData.DataCache["grantData"]
    }
    
    # Build service principal nodes
    $spNodes = @()
    foreach ($sp in $spData) {
        $node = [ServicePrincipalNode]::new($sp.Name, $sp.DisplayName, $sp.ObjectId, $sp.AppId)
        $node.Properties["appType"] = $sp.AppType
        $node.Properties["signInAudience"] = $sp.SignInAudience
        $node.Properties["homepageUrl"] = $sp.HomepageUrl
        $node.Properties["hasSecret"] = $sp.HasSecret -eq "True"
        $node.Properties["secretExpiry"] = $sp.SecretExpiry
        $node.Properties["certificateExpiry"] = $sp.CertificateExpiry
        $node.Properties["isPrivileged"] = $sp.IsPrivileged -eq "True"
        $node.Properties["lastUsed"] = $sp.LastUsed
        $node.Properties["grantCount"] = $sp.GrantCount
        
        # Calculate risk score
        $riskScore = 0
        if ($sp.IsPrivileged -eq "True") { $riskScore += 10 }
        if ($sp.HasSecret -eq "True") { $riskScore += 5 }
        if ($sp.GrantCount -gt 10) { $riskScore += 8 }
        if ($sp.AppType -eq "MultiTenant") { $riskScore += 6 }
        if ($sp.SignInAudience -eq "AzureADMultipleOrgs") { $riskScore += 4 }
        
        # Check for expired secrets/certificates
        if ($sp.SecretExpiry -and [DateTime]$sp.SecretExpiry -lt (Get-Date).AddDays(30)) { $riskScore += 7 }
        if ($sp.CertificateExpiry -and [DateTime]$sp.CertificateExpiry -lt (Get-Date).AddDays(30)) { $riskScore += 7 }
        
        # Check for unused applications
        if ($sp.LastUsed -and [DateTime]$sp.LastUsed -lt (Get-Date).AddDays(-90)) { $riskScore += 3 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 20) { "High" } elseif ($riskScore -ge 10) { "Medium" } else { "Low" }
        
        $spNodes += $node
    }
    
    # Build OAuth scope nodes
    $scopeNodes = @()
    foreach ($scope in $scopeData) {
        $node = [OAuthScopeNode]::new($scope.Name, $scope.DisplayName, $scope.ScopeType)
        $node.Properties["description"] = $scope.Description
        $node.Properties["isAdminConsentRequired"] = $scope.IsAdminConsentRequired -eq "True"
        $node.Properties["isHighPrivilege"] = $scope.IsHighPrivilege -eq "True"
        $node.Properties["grantCount"] = $scope.GrantCount
        
        # Calculate risk score
        $riskScore = 0
        if ($scope.IsHighPrivilege -eq "True") { $riskScore += 10 }
        if ($scope.IsAdminConsentRequired -eq "True") { $riskScore += 5 }
        if ($scope.GrantCount -gt 20) { $riskScore += 6 }
        if ($scope.ScopeType -eq "Application") { $riskScore += 4 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 15) { "High" } elseif ($riskScore -ge 8) { "Medium" } else { "Low" }
        
        $scopeNodes += $node
    }
    
    # Build grant edges
    $grantEdges = @()
    foreach ($grant in $grantData) {
        $edge = [GrantEdge]::new($grant.ServicePrincipal, $grant.Scope, $grant.GrantType, $grant.PermissionType)
        $edge.Properties["consentType"] = $grant.ConsentType
        $edge.Properties["grantedBy"] = $grant.GrantedBy
        $edge.Properties["grantedOn"] = $grant.GrantedOn
        $edge.Properties["isExpired"] = $grant.IsExpired -eq "True"
        
        $grantEdges += $edge
    }
    
    # Generate Graphviz DOT
    $dotPath = Join-Path $OutputFolder "app-grant-views-$Timestamp.dot"
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('digraph AppGrantViews {')
    [void]$sb.AppendLine('rankdir=LR; fontsize=10; fontname="Segoe UI";')
    [void]$sb.AppendLine('node [style=filled, fontname="Segoe UI", fontsize=9];')
    [void]$sb.AppendLine('edge [color="#7f8c8d"];')
    
    # Define colors for risk levels
    $riskColors = @{ High='#e74c3c'; Medium='#e67e22'; Low='#f1c40f' }
    
    # Add service principal nodes (triangles)
    foreach ($node in $spNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        
        $label = "$($node.DisplayName)"
        if ($node.Properties["isPrivileged"]) { $label += " (Privileged)" }
        if ($node.Properties["hasSecret"]) { $label += " (Secret)" }
        
        [void]$sb.AppendLine("$safeName [label=""$label"", fillcolor=""$color"", shape=triangle];")
    }
    
    # Add OAuth scope nodes (diamonds)
    foreach ($node in $scopeNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        
        $label = "$($node.DisplayName)"
        if ($node.Properties["isHighPrivilege"]) { $label += " (High Priv)" }
        if ($node.Properties["isAdminConsentRequired"]) { $label += " (Admin)" }
        
        [void]$sb.AppendLine("$safeName [label=""$label"", fillcolor=""$color"", shape=diamond];")
    }
    
    # Add grant edges with different styles
    foreach ($edge in $grantEdges) {
        $fromSafe = ($edge.From -replace '[^A-Za-z0-9_@\-\.]', '_')
        $toSafe = ($edge.To -replace '[^A-Za-z0-9_@\-\.]', '_')
        
        $edgeStyle = "solid"
        $edgeColor = "#7f8c8d"
        
        # Style based on permission type
        switch ($edge.PermissionType) {
            "Application" {
                $edgeColor = "#e74c3c"
                $edgeStyle = "bold"
            }
            "Delegated" {
                $edgeColor = "#e67e22"
                $edgeStyle = "solid"
            }
            "Directory" {
                $edgeColor = "#8e44ad"
                $edgeStyle = "dashed"
            }
        }
        
        # Add consent type indicator
        $edgeLabel = $edge.GrantType
        if ($edge.Properties["consentType"] -eq "Admin") {
            $edgeLabel += " (Admin)"
        } elseif ($edge.Properties["consentType"] -eq "User") {
            $edgeLabel += " (User)"
        }
        
        [void]$sb.AppendLine("$fromSafe -> $toSafe [label=""$edgeLabel"", style=""$edgeStyle"", color=""$edgeColor""];")
    }
    
    [void]$sb.AppendLine('}')
    $sb.ToString() | Out-File $dotPath -Encoding utf8
    
    # Generate Mermaid version
    $mmdPath = Join-Path $OutputFolder "app-grant-views-$Timestamp.mmd"
    $mmd = [System.Text.StringBuilder]::new()
    [void]$mmd.AppendLine('flowchart LR')
    
    # Add service principals
    foreach ($node in $spNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        $privIcon = if ($node.Properties["isPrivileged"]) { "👑" } else { "📱" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon$privIcon $($node.DisplayName)""]")
    }
    
    # Add OAuth scopes
    foreach ($node in $scopeNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        $scopeIcon = if ($node.Properties["isHighPrivilege"]) { "🔐" } else { "🔑" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon$scopeIcon $($node.DisplayName)""]")
    }
    
    # Add grant relationships
    foreach ($edge in $grantEdges) {
        $fromName = ($edge.From -replace '.*\.', '')
        $toName = ($edge.To -replace '.*\.', '')
        
        if ($edge.PermissionType -eq "Application") {
            [void]$mmd.AppendLine("  $fromName ==> $toName")
        } else {
            [void]$mmd.AppendLine("  $fromName --> $toName")
        }
    }
    
    $mmd.ToString() | Out-File $mmdPath -Encoding utf8
    
    # Try to render PNG if Graphviz is available
    $pngPath = $null
    $dotExe = (Get-Command dot -ErrorAction SilentlyContinue).Source
    if ($dotExe) {
        $pngPath = Join-Path $OutputFolder "app-grant-views-$Timestamp.png"
        & $dotExe -Tpng $dotPath -o $pngPath
        Write-Host "App & Grant Views PNG rendered: $pngPath" -ForegroundColor Green
    }
    
    Write-Host "App & Grant Views diagram completed:" -ForegroundColor Green
    Write-Host "  - Service Principals: $($spNodes.Count)" -ForegroundColor White
    Write-Host "  - OAuth Scopes: $($scopeNodes.Count)" -ForegroundColor White
    Write-Host "  - Grants: $($grantEdges.Count)" -ForegroundColor White
    Write-Host "  - High Risk SPs: $(($spNodes | Where-Object { $_.RiskLevel -eq "High" }).Count)" -ForegroundColor Red
    Write-Host "  - High Risk Scopes: $(($scopeNodes | Where-Object { $_.RiskLevel -eq "High" }).Count)" -ForegroundColor Red
    
    return [pscustomobject]@{
        Dot = $dotPath
        Mermaid = $mmdPath
        PNG = $pngPath
        Stats = @{
            ServicePrincipalCount = $spNodes.Count
            OAuthScopeCount = $scopeNodes.Count
            GrantCount = $grantEdges.Count
            HighRiskSPs = ($spNodes | Where-Object { $_.RiskLevel -eq "High" }).Count
            HighRiskScopes = ($scopeNodes | Where-Object { $_.RiskLevel -eq "High" }).Count
            PrivilegedSPs = ($spNodes | Where-Object { $_.Properties["isPrivileged"] -eq $true }).Count
            ExpiredSecrets = ($spNodes | Where-Object { 
                $_.Properties["secretExpiry"] -and [DateTime]$_.Properties["secretExpiry"] -lt (Get-Date).AddDays(30)
            }).Count
        }
    }
}

function Get-SampleServicePrincipalData {
    return @(
        [pscustomobject]@{
            Name = "SharePoint-Online"
            DisplayName = "Microsoft SharePoint"
            ObjectId = "12345678-1234-1234-1234-123456789012"
            AppId = "00000003-0000-0ff1-ce00-000000000000"
            AppType = "MultiTenant"
            SignInAudience = "AzureADMultipleOrgs"
            HomepageUrl = "https://sharepoint.com"
            HasSecret = "False"
            SecretExpiry = ""
            CertificateExpiry = "2025-12-31"
            IsPrivileged = "True"
            LastUsed = "2024-11-30"
            GrantCount = 15
        },
        [pscustomobject]@{
            Name = "Graph-Explorer"
            DisplayName = "Microsoft Graph Explorer"
            ObjectId = "87654321-4321-4321-4321-210987654321"
            AppId = "de8bc8b5-d9f9-48b1-a8ad-b748da725064"
            AppType = "MultiTenant"
            SignInAudience = "AzureADMultipleOrgs"
            HomepageUrl = "https://developer.microsoft.com/graph/graph-explorer"
            HasSecret = "True"
            SecretExpiry = "2025-01-15"
            CertificateExpiry = ""
            IsPrivileged = "True"
            LastUsed = "2024-11-28"
            GrantCount = 25
        },
        [pscustomobject]@{
            Name = "Contoso-CRM"
            DisplayName = "Contoso CRM Application"
            ObjectId = "11111111-2222-3333-4444-555555555555"
            AppId = "11111111-2222-3333-4444-555555555556"
            AppType = "SingleTenant"
            SignInAudience = "AzureADMyOrg"
            HomepageUrl = "https://crm.contoso.com"
            HasSecret = "True"
            SecretExpiry = "2024-12-10"
            CertificateExpiry = ""
            IsPrivileged = "False"
            LastUsed = "2024-11-29"
            GrantCount = 8
        },
        [pscustomobject]@{
            Name = "Legacy-App"
            DisplayName = "Legacy Application"
            ObjectId = "66666666-7777-8888-9999-000000000000"
            AppId = "66666666-7777-8888-9999-000000000001"
            AppType = "SingleTenant"
            SignInAudience = "AzureADMyOrg"
            HomepageUrl = "https://legacy.contoso.com"
            HasSecret = "True"
            SecretExpiry = "2024-01-15"
            CertificateExpiry = ""
            IsPrivileged = "False"
            LastUsed = "2024-08-15"
            GrantCount = 3
        },
        [pscustomobject]@{
            Name = "PowerBI-Service"
            DisplayName = "Power BI Service"
            ObjectId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            AppId = "00000009-0000-0000-c000-000000000000"
            AppType = "MultiTenant"
            SignInAudience = "AzureADMultipleOrgs"
            HomepageUrl = "https://app.powerbi.com"
            HasSecret = "False"
            SecretExpiry = ""
            CertificateExpiry = "2025-06-30"
            IsPrivileged = "True"
            LastUsed = "2024-11-30"
            GrantCount = 12
        }
    )
}

function Get-SampleOAuthScopeData {
    return @(
        [pscustomobject]@{
            Name = "User.Read"
            DisplayName = "Read user profiles"
            ScopeType = "Delegated"
            Description = "Allows the app to read the signed-in user's profile"
            IsAdminConsentRequired = "False"
            IsHighPrivilege = "False"
            GrantCount = 45
        },
        [pscustomobject]@{
            Name = "User.ReadWrite.All"
            DisplayName = "Read and write all users' full profiles"
            ScopeType = "Application"
            Description = "Allows the app to read and write the full profile of all users in your organization"
            IsAdminConsentRequired = "True"
            IsHighPrivilege = "True"
            GrantCount = 8
        },
        [pscustomobject]@{
            Name = "Directory.Read.All"
            DisplayName = "Read directory data"
            ScopeType = "Application"
            Description = "Allows the app to read data in your organization's directory"
            IsAdminConsentRequired = "True"
            IsHighPrivilege = "True"
            GrantCount = 12
        },
        [pscustomobject]@{
            Name = "Group.ReadWrite.All"
            DisplayName = "Read and write all groups"
            ScopeType = "Application"
            Description = "Allows the app to create, read, update and delete groups and group memberships"
            IsAdminConsentRequired = "True"
            IsHighPrivilege = "True"
            GrantCount = 5
        },
        [pscustomobject]@{
            Name = "Mail.Read"
            DisplayName = "Read user mail"
            ScopeType = "Delegated"
            Description = "Allows the app to read mail in user mailboxes"
            IsAdminConsentRequired = "False"
            IsHighPrivilege = "False"
            GrantCount = 23
        },
        [pscustomobject]@{
            Name = "Files.ReadWrite.All"
            DisplayName = "Read and write files in all site collections"
            ScopeType = "Application"
            Description = "Allows the app to read, create, update and delete files in all site collections"
            IsAdminConsentRequired = "True"
            IsHighPrivilege = "True"
            GrantCount = 3
        }
    )
}

function Get-SampleGrantData {
    return @(
        [pscustomobject]@{
            ServicePrincipal = "Graph-Explorer"
            Scope = "User.Read"
            GrantType = "OAuth2"
            PermissionType = "Delegated"
            ConsentType = "User"
            GrantedBy = "user@contoso.com"
            GrantedOn = "2024-11-01"
            IsExpired = "False"
        },
        [pscustomobject]@{
            ServicePrincipal = "Graph-Explorer"
            Scope = "User.ReadWrite.All"
            GrantType = "OAuth2"
            PermissionType = "Application"
            ConsentType = "Admin"
            GrantedBy = "admin@contoso.com"
            GrantedOn = "2024-10-15"
            IsExpired = "False"
        },
        [pscustomobject]@{
            ServicePrincipal = "Contoso-CRM"
            Scope = "Directory.Read.All"
            GrantType = "OAuth2"
            PermissionType = "Application"
            ConsentType = "Admin"
            GrantedBy = "admin@contoso.com"
            GrantedOn = "2024-09-20"
            IsExpired = "False"
        },
        [pscustomobject]@{
            ServicePrincipal = "PowerBI-Service"
            Scope = "Files.ReadWrite.All"
            GrantType = "OAuth2"
            PermissionType = "Application"
            ConsentType = "Admin"
            GrantedBy = "admin@contoso.com"
            GrantedOn = "2024-08-10"
            IsExpired = "False"
        },
        [pscustomobject]@{
            ServicePrincipal = "SharePoint-Online"
            Scope = "Group.ReadWrite.All"
            GrantType = "OAuth2"
            PermissionType = "Application"
            ConsentType = "Admin"
            GrantedBy = "admin@contoso.com"
            GrantedOn = "2024-07-05"
            IsExpired = "False"
        },
        [pscustomobject]@{
            ServicePrincipal = "Legacy-App"
            Scope = "Mail.Read"
            GrantType = "OAuth2"
            PermissionType = "Delegated"
            ConsentType = "User"
            GrantedBy = "user@contoso.com"
            GrantedOn = "2024-06-01"
            IsExpired = "False"
        }
    )
}

Export-ModuleMember -Function New-AppGrantDiagram
