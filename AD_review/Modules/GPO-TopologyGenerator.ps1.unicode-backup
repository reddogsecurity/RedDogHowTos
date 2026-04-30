# GPO Topology Diagram Generator
# Creates diagrams showing GPO ↔ OU links with risky delegations

class GPONode {
    [string]$Name
    [string]$DisplayName
    [string]$GUID
    [string]$Domain
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    GPONode([string]$Name, [string]$DisplayName, [string]$GUID, [string]$Domain) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.GUID = $GUID
        $this.Domain = $Domain
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class OUNode {
    [string]$Name
    [string]$DisplayName
    [string]$DistinguishedName
    [string]$Domain
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    OUNode([string]$Name, [string]$DisplayName, [string]$DistinguishedName, [string]$Domain) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.DistinguishedName = $DistinguishedName
        $this.Domain = $Domain
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class GPOEdge {
    [string]$From
    [string]$To
    [string]$EdgeType
    [string]$LinkType
    [hashtable]$Properties
    
    GPOEdge([string]$From, [string]$To, [string]$EdgeType, [string]$LinkType) {
        $this.From = $From
        $this.To = $To
        $this.EdgeType = $EdgeType
        $this.LinkType = $LinkType
        $this.Properties = @{}
    }
}

function New-GPOTopologyDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building GPO Topology diagram..." -ForegroundColor Cyan
    
    # Check if we have GPO data
    if (-not $GraphData.DataCache.ContainsKey("gpoData") -or 
        -not $GraphData.DataCache.ContainsKey("ouData")) {
        Write-Warning "GPO or OU data not available. Collecting sample data..."
        $gpoData = Get-SampleGPOData
        $ouData = Get-SampleOUData
        $delegationData = Get-SampleDelegationData
    } else {
        $gpoData = $GraphData.DataCache["gpoData"]
        $ouData = $GraphData.DataCache["ouData"]
        $delegationData = if ($GraphData.DataCache.ContainsKey("delegationData")) { 
            $GraphData.DataCache["delegationData"] 
        } else { @() }
    }
    
    # Build GPO nodes
    $gpoNodes = @()
    foreach ($gpo in $gpoData) {
        $node = [GPONode]::new($gpo.Name, $gpo.DisplayName, $gpo.GUID, $gpo.Domain)
        $node.Properties["description"] = $gpo.Description
        $node.Properties["enabled"] = $gpo.Enabled -eq "True"
        $node.Properties["linkCount"] = $gpo.LinkCount
        $node.Properties["hasUnlinkedOUs"] = $gpo.HasUnlinkedOUs -eq "True"
        
        # Calculate risk score
        $riskScore = 0
        if ($gpo.HasUnlinkedOUs -eq "True") { $riskScore += 5 }
        if ($gpo.LinkCount -gt 10) { $riskScore += 3 }
        if ($gpo.Name -match "Default|Built") { $riskScore += 2 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 8) { "High" } elseif ($riskScore -ge 4) { "Medium" } else { "Low" }
        
        $gpoNodes += $node
    }
    
    # Build OU nodes
    $ouNodes = @()
    foreach ($ou in $ouData) {
        $node = [OUNode]::new($ou.Name, $ou.DisplayName, $ou.DistinguishedName, $ou.Domain)
        $node.Properties["objectCount"] = $ou.ObjectCount
        $node.Properties["hasDelegations"] = $ou.HasDelegations -eq "True"
        $node.Properties["isPrivileged"] = $ou.IsPrivileged -eq "True"
        
        # Calculate risk score
        $riskScore = 0
        if ($ou.IsPrivileged -eq "True") { $riskScore += 8 }
        if ($ou.HasDelegations -eq "True") { $riskScore += 5 }
        if ($ou.ObjectCount -gt 100) { $riskScore += 2 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 10) { "High" } elseif ($riskScore -ge 5) { "Medium" } else { "Low" }
        
        $ouNodes += $node
    }
    
    # Build GPO-OU edges (links)
    $gpoEdges = @()
    foreach ($gpo in $gpoData) {
        if ($gpo.LinkedOUs) {
            $linkedOUs = $gpo.LinkedOUs -split ','
            foreach ($ouName in $linkedOUs) {
                if ($ouName.Trim()) {
                    $edge = [GPOEdge]::new("GPO::$($gpo.Name)", "OU::$($ouName.Trim())", "appliesTo", "link")
                    $edge.Properties["enforced"] = $gpo.Enforced -eq "True"
                    $edge.Properties["inheritance"] = $gpo.Inheritance
                    $gpoEdges += $edge
                }
            }
        }
    }
    
    # Add delegation edges
    foreach ($delegation in $delegationData) {
        $edge = [GPOEdge]::new("OU::$($delegation.OU)", "PRINCIPAL::$($delegation.Principal)", "delegatedTo", "delegation")
        $edge.Properties["permissions"] = $delegation.Permissions
        $edge.Properties["isInherited"] = $delegation.IsInherited -eq "True"
        $gpoEdges += $edge
    }
    
    # Generate Graphviz DOT
    $dotPath = Join-Path $OutputFolder "gpo-topology-$Timestamp.dot"
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('digraph GPOTopology {')
    [void]$sb.AppendLine('rankdir=TB; fontsize=10; fontname="Segoe UI";')
    [void]$sb.AppendLine('node [style=filled, fontname="Segoe UI", fontsize=9];')
    [void]$sb.AppendLine('edge [color="#7f8c8d"];')
    
    # Define colors for risk levels
    $riskColors = @{ High='#e74c3c'; Medium='#e67e22'; Low='#f1c40f' }
    
    # Add GPO nodes (folders)
    foreach ($node in $gpoNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        [void]$sb.AppendLine("$safeName [label=""$($node.DisplayName)"", fillcolor=""$color"", shape=folder];")
    }
    
    # Add OU nodes (rectangles)
    foreach ($node in $ouNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        [void]$sb.AppendLine("$safeName [label=""$($node.DisplayName)"", fillcolor=""$color"", shape=rectangle];")
    }
    
    # Add edges
    foreach ($edge in $gpoEdges) {
        $fromSafe = ($edge.From -replace '[^A-Za-z0-9_@\-\.]', '_')
        $toSafe = ($edge.To -replace '[^A-Za-z0-9_@\-\.]', '_')
        
        if ($edge.EdgeType -eq "appliesTo") {
            [void]$sb.AppendLine("$fromSafe -> $toSafe [label=""applies""];")
        } elseif ($edge.EdgeType -eq "delegatedTo") {
            [void]$sb.AppendLine("$fromSafe -> $toSafe [label=""delegated"", style=dashed, color=""#e74c3c""];")
        }
    }
    
    [void]$sb.AppendLine('}')
    $sb.ToString() | Out-File $dotPath -Encoding utf8
    
    # Generate Mermaid version
    $mmdPath = Join-Path $OutputFolder "gpo-topology-$Timestamp.mmd"
    $mmd = [System.Text.StringBuilder]::new()
    [void]$mmd.AppendLine('flowchart TD')
    
    # Add GPOs
    foreach ($node in $gpoNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon $($node.DisplayName)""]")
    }
    
    # Add OUs
    foreach ($node in $ouNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon $($node.DisplayName)""]")
    }
    
    # Add edges
    foreach ($edge in $gpoEdges) {
        $fromName = ($edge.From -replace '.*::', '')
        $toName = ($edge.To -replace '.*::', '')
        
        if ($edge.EdgeType -eq "appliesTo") {
            [void]$mmd.AppendLine("  $fromName --> $toName")
        } elseif ($edge.EdgeType -eq "delegatedTo") {
            [void]$mmd.AppendLine("  $fromName -.-> $toName")
        }
    }
    
    $mmd.ToString() | Out-File $mmdPath -Encoding utf8
    
    # Try to render PNG if Graphviz is available
    $pngPath = $null
    $dotExe = (Get-Command dot -ErrorAction SilentlyContinue).Source
    if ($dotExe) {
        $pngPath = Join-Path $OutputFolder "gpo-topology-$Timestamp.png"
        & $dotExe -Tpng $dotPath -o $pngPath
        Write-Host "GPO Topology PNG rendered: $pngPath" -ForegroundColor Green
    }
    
    Write-Host "GPO Topology diagram completed:" -ForegroundColor Green
    Write-Host "  - GPOs: $($gpoNodes.Count)" -ForegroundColor White
    Write-Host "  - OUs: $($ouNodes.Count)" -ForegroundColor White
    Write-Host "  - Links: $(($gpoEdges | Where-Object { $_.EdgeType -eq 'appliesTo' }).Count)" -ForegroundColor White
    Write-Host "  - Delegations: $(($gpoEdges | Where-Object { $_.EdgeType -eq 'delegatedTo' }).Count)" -ForegroundColor White
    
    return [pscustomobject]@{
        Dot = $dotPath
        Mermaid = $mmdPath
        PNG = $pngPath
        Stats = @{
            GPOCount = $gpoNodes.Count
            OUCount = $ouNodes.Count
            LinkCount = ($gpoEdges | Where-Object { $_.EdgeType -eq 'appliesTo' }).Count
            DelegationCount = ($gpoEdges | Where-Object { $_.EdgeType -eq 'delegatedTo' }).Count
            HighRiskGPOs = ($gpoNodes | Where-Object { $_.RiskLevel -eq "High" }).Count
            HighRiskOUs = ($ouNodes | Where-Object { $_.RiskLevel -eq "High" }).Count
        }
    }
}

function Get-SampleGPOData {
    return @(
        [pscustomobject]@{
            Name = "Default Domain Policy"
            DisplayName = "Default Domain Policy"
            GUID = "31B2F340-016D-11D2-945F-00C04FB984F9"
            Domain = "contoso.com"
            Description = "Default domain policy"
            Enabled = "True"
            LinkCount = 1
            HasUnlinkedOUs = "False"
            LinkedOUs = "Domain Controllers"
            Enforced = "False"
            Inheritance = "Inherited"
        },
        [pscustomobject]@{
            Name = "Default Domain Controllers Policy"
            DisplayName = "Default Domain Controllers Policy"
            GUID = "6AC1786C-016F-11D2-945F-00C04FB984F9"
            Domain = "contoso.com"
            Description = "Default domain controllers policy"
            Enabled = "True"
            LinkCount = 1
            HasUnlinkedOUs = "True"
            LinkedOUs = "Domain Controllers"
            Enforced = "False"
            Inheritance = "Inherited"
        },
        [pscustomobject]@{
            Name = "Security Baselines"
            DisplayName = "Security Baselines"
            GUID = "12345678-1234-1234-1234-123456789012"
            Domain = "contoso.com"
            Description = "Security baseline settings"
            Enabled = "True"
            LinkCount = 5
            HasUnlinkedOUs = "False"
            LinkedOUs = "Users,Computers,Finance,HR,IT"
            Enforced = "True"
            Inheritance = "Inherited"
        },
        [pscustomobject]@{
            Name = "Finance Security Policy"
            DisplayName = "Finance Security Policy"
            GUID = "87654321-4321-4321-4321-210987654321"
            Domain = "contoso.com"
            Description = "Finance-specific security settings"
            Enabled = "True"
            LinkCount = 2
            HasUnlinkedOUs = "False"
            LinkedOUs = "Finance,Finance-Servers"
            Enforced = "True"
            Inheritance = "Inherited"
        }
    )
}

function Get-SampleOUData {
    return @(
        [pscustomobject]@{
            Name = "Domain Controllers"
            DisplayName = "Domain Controllers"
            DistinguishedName = "OU=Domain Controllers,DC=contoso,DC=com"
            Domain = "contoso.com"
            ObjectCount = 5
            HasDelegations = "False"
            IsPrivileged = "True"
        },
        [pscustomobject]@{
            Name = "Users"
            DisplayName = "Users"
            DistinguishedName = "OU=Users,DC=contoso,DC=com"
            Domain = "contoso.com"
            ObjectCount = 250
            HasDelegations = "False"
            IsPrivileged = "False"
        },
        [pscustomobject]@{
            Name = "Computers"
            DisplayName = "Computers"
            DistinguishedName = "OU=Computers,DC=contoso,DC=com"
            Domain = "contoso.com"
            ObjectCount = 150
            HasDelegations = "False"
            IsPrivileged = "False"
        },
        [pscustomobject]@{
            Name = "Finance"
            DisplayName = "Finance"
            DistinguishedName = "OU=Finance,OU=Users,DC=contoso,DC=com"
            Domain = "contoso.com"
            ObjectCount = 45
            HasDelegations = "True"
            IsPrivileged = "False"
        },
        [pscustomobject]@{
            Name = "Finance-Servers"
            DisplayName = "Finance Servers"
            DistinguishedName = "OU=Finance-Servers,OU=Computers,DC=contoso,DC=com"
            Domain = "contoso.com"
            ObjectCount = 8
            HasDelegations = "True"
            IsPrivileged = "True"
        },
        [pscustomobject]@{
            Name = "HR"
            DisplayName = "Human Resources"
            DistinguishedName = "OU=HR,OU=Users,DC=contoso,DC=com"
            Domain = "contoso.com"
            ObjectCount = 25
            HasDelegations = "False"
            IsPrivileged = "False"
        },
        [pscustomobject]@{
            Name = "IT"
            DisplayName = "Information Technology"
            DistinguishedName = "OU=IT,OU=Users,DC=contoso,DC=com"
            Domain = "contoso.com"
            ObjectCount = 15
            HasDelegations = "True"
            IsPrivileged = "False"
        }
    )
}

function Get-SampleDelegationData {
    return @(
        [pscustomobject]@{
            OU = "Finance"
            Principal = "Finance-Admins"
            Permissions = "FullControl"
            IsInherited = "False"
        },
        [pscustomobject]@{
            OU = "Finance-Servers"
            Principal = "Finance-Admins"
            Permissions = "FullControl"
            IsInherited = "False"
        },
        [pscustomobject]@{
            OU = "Finance-Servers"
            Principal = "Server-Admins"
            Permissions = "ResetPassword"
            IsInherited = "True"
        },
        [pscustomobject]@{
            OU = "IT"
            Principal = "Helpdesk"
            Permissions = "CreateDeleteUsers"
            IsInherited = "False"
        }
    )
}

Export-ModuleMember -Function New-GPOTopologyDiagram
