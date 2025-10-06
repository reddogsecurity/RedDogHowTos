# Trust Map Diagram Generator
# Creates diagrams showing domain/forest trust relationships

class DomainNode {
    [string]$Name
    [string]$DisplayName
    [string]$DomainType
    [string]$FunctionalLevel
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    DomainNode([string]$Name, [string]$DisplayName, [string]$DomainType, [string]$FunctionalLevel) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.DomainType = $DomainType
        $this.FunctionalLevel = $FunctionalLevel
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class TrustEdge {
    [string]$From
    [string]$To
    [string]$TrustType
    [string]$TrustDirection
    [string]$Transitive
    [hashtable]$Properties
    
    TrustEdge([string]$From, [string]$To, [string]$TrustType, [string]$TrustDirection, [string]$Transitive) {
        $this.From = $From
        $this.To = $To
        $this.TrustType = $TrustType
        $this.TrustDirection = $TrustDirection
        $this.Transitive = $Transitive
        $this.Properties = @{}
    }
}

function New-TrustMapDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building Trust Map diagram..." -ForegroundColor Cyan
    
    # Check if we have trust data
    if (-not $GraphData.DataCache.ContainsKey("domainTrusts")) {
        Write-Warning "Domain trust data not available. Using sample data..."
        $trustData = Get-SampleTrustData
        $domainData = Get-SampleDomainData
    } else {
        $trustData = $GraphData.DataCache["domainTrusts"]
        $domainData = $GraphData.DataCache["domainData"]
    }
    
    # Build domain nodes
    $domainNodes = @()
    foreach ($domain in $domainData) {
        $node = [DomainNode]::new($domain.Name, $domain.DisplayName, $domain.DomainType, $domain.FunctionalLevel)
        $node.Properties["dcCount"] = $domain.DCCount
        $node.Properties["userCount"] = $domain.UserCount
        $node.Properties["computerCount"] = $domain.ComputerCount
        $node.Properties["isRootDomain"] = $domain.IsRootDomain -eq "True"
        $node.Properties["isExternal"] = $domain.IsExternal -eq "True"
        
        # Calculate risk score
        $riskScore = 0
        if ($domain.IsExternal -eq "True") { $riskScore += 10 }
        if ($domain.DomainType -eq "Forest") { $riskScore += 5 }
        if ($domain.FunctionalLevel -match "2008|2003") { $riskScore += 8 }
        if ($domain.DCCount -lt 2) { $riskScore += 5 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 15) { "High" } elseif ($riskScore -ge 8) { "Medium" } else { "Low" }
        
        $domainNodes += $node
    }
    
    # Build trust edges
    $trustEdges = @()
    foreach ($trust in $trustData) {
        $edge = [TrustEdge]::new($trust.SourceDomain, $trust.TargetDomain, $trust.TrustType, $trust.TrustDirection, $trust.Transitive)
        $edge.Properties["authentication"] = $trust.Authentication
        $edge.Properties["selectiveAuth"] = $trust.SelectiveAuth -eq "True"
        $edge.Properties["sidFiltering"] = $trust.SidFiltering -eq "True"
        $edge.Properties["trustStatus"] = $trust.TrustStatus
        
        $trustEdges += $edge
    }
    
    # Generate Graphviz DOT
    $dotPath = Join-Path $OutputFolder "trust-map-$Timestamp.dot"
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('digraph TrustMap {')
    [void]$sb.AppendLine('rankdir=LR; fontsize=10; fontname="Segoe UI";')
    [void]$sb.AppendLine('node [style=filled, fontname="Segoe UI", fontsize=9];')
    [void]$sb.AppendLine('edge [color="#7f8c8d"];')
    
    # Define colors and shapes for risk levels and domain types
    $riskColors = @{ High='#e74c3c'; Medium='#e67e22'; Low='#f1c40f' }
    $domainShapes = @{ Forest='cylinder'; Domain='ellipse'; External='diamond' }
    
    # Add domain nodes
    foreach ($node in $domainNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        $shape = $domainShapes[$node.DomainType]
        
        $label = "$($node.DisplayName)"
        if ($node.Properties["isRootDomain"]) { $label += " (Root)" }
        if ($node.Properties["isExternal"]) { $label += " (External)" }
        
        [void]$sb.AppendLine("$safeName [label=""$label"", fillcolor=""$color"", shape=$shape];")
    }
    
    # Add trust edges with different styles based on trust type
    foreach ($edge in $trustEdges) {
        $fromSafe = ($edge.From -replace '[^A-Za-z0-9_@\-\.]', '_')
        $toSafe = ($edge.To -replace '[^A-Za-z0-9_@\-\.]', '_')
        
        $edgeStyle = "solid"
        $edgeColor = "#7f8c8d"
        $edgeLabel = $edge.TrustType
        
        # Style based on trust type and direction
        switch ($edge.TrustType) {
            "External" {
                $edgeColor = "#e74c3c"
                $edgeStyle = "bold"
            }
            "Forest" {
                $edgeColor = "#e67e22"
                $edgeStyle = "solid"
            }
            "Parent-Child" {
                $edgeColor = "#27ae60"
                $edgeStyle = "solid"
            }
            "Shortcut" {
                $edgeColor = "#3498db"
                $edgeStyle = "dashed"
            }
        }
        
        # Add direction indicators
        if ($edge.TrustDirection -eq "Bidirectional") {
            $edgeLabel += " (↔)"
        } elseif ($edge.TrustDirection -eq "Inbound") {
            $edgeLabel += " (←)"
        } elseif ($edge.TrustDirection -eq "Outbound") {
            $edgeLabel += " (→)"
        }
        
        # Add transitive indicator
        if ($edge.Transitive -eq "False") {
            $edgeLabel += " (Non-transitive)"
        }
        
        [void]$sb.AppendLine("$fromSafe -> $toSafe [label=""$edgeLabel"", style=""$edgeStyle"", color=""$edgeColor""];")
    }
    
    [void]$sb.AppendLine('}')
    $sb.ToString() | Out-File $dotPath -Encoding utf8
    
    # Generate Mermaid version
    $mmdPath = Join-Path $OutputFolder "trust-map-$Timestamp.mmd"
    $mmd = [System.Text.StringBuilder]::new()
    [void]$mmd.AppendLine('flowchart LR')
    
    # Add domains with risk indicators
    foreach ($node in $domainNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        $typeIcon = if ($node.DomainType -eq "Forest") { "🌲" } elseif ($node.Properties["isExternal"]) { "🌐" } else { "🏢" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon$typeIcon $($node.DisplayName)""]")
    }
    
    # Add trust relationships
    foreach ($edge in $trustEdges) {
        $fromName = ($edge.From -replace '.*\.', '')
        $toName = ($edge.To -replace '.*\.', '')
        
        if ($edge.TrustDirection -eq "Bidirectional") {
            [void]$mmd.AppendLine("  $fromName <--> $toName")
        } else {
            [void]$mmd.AppendLine("  $fromName --> $toName")
        }
    }
    
    $mmd.ToString() | Out-File $mmdPath -Encoding utf8
    
    # Try to render PNG if Graphviz is available
    $pngPath = $null
    $dotExe = (Get-Command dot -ErrorAction SilentlyContinue).Source
    if ($dotExe) {
        $pngPath = Join-Path $OutputFolder "trust-map-$Timestamp.png"
        & $dotExe -Tpng $dotPath -o $pngPath
        Write-Host "Trust Map PNG rendered: $pngPath" -ForegroundColor Green
    }
    
    Write-Host "Trust Map diagram completed:" -ForegroundColor Green
    Write-Host "  - Domains: $($domainNodes.Count)" -ForegroundColor White
    Write-Host "  - Trusts: $($trustEdges.Count)" -ForegroundColor White
    Write-Host "  - External Trusts: $(($trustEdges | Where-Object { $_.TrustType -eq 'External' }).Count)" -ForegroundColor Red
    Write-Host "  - Forest Trusts: $(($trustEdges | Where-Object { $_.TrustType -eq 'Forest' }).Count)" -ForegroundColor Yellow
    
    return [pscustomobject]@{
        Dot = $dotPath
        Mermaid = $mmdPath
        PNG = $pngPath
        Stats = @{
            DomainCount = $domainNodes.Count
            TrustCount = $trustEdges.Count
            ExternalTrusts = ($trustEdges | Where-Object { $_.TrustType -eq 'External' }).Count
            ForestTrusts = ($trustEdges | Where-Object { $_.TrustType -eq 'Forest' }).Count
            ParentChildTrusts = ($trustEdges | Where-Object { $_.TrustType -eq 'Parent-Child' }).Count
            HighRiskDomains = ($domainNodes | Where-Object { $_.RiskLevel -eq "High" }).Count
        }
    }
}

function Get-SampleDomainData {
    return @(
        [pscustomobject]@{
            Name = "contoso.com"
            DisplayName = "Contoso Forest Root"
            DomainType = "Forest"
            FunctionalLevel = "2016"
            DCCount = 3
            UserCount = 1500
            ComputerCount = 800
            IsRootDomain = "True"
            IsExternal = "False"
        },
        [pscustomobject]@{
            Name = "europe.contoso.com"
            DisplayName = "Europe Domain"
            DomainType = "Domain"
            FunctionalLevel = "2016"
            DCCount = 2
            UserCount = 800
            ComputerCount = 400
            IsRootDomain = "False"
            IsExternal = "False"
        },
        [pscustomobject]@{
            Name = "asia.contoso.com"
            DisplayName = "Asia Domain"
            DomainType = "Domain"
            FunctionalLevel = "2012R2"
            DCCount = 1
            UserCount = 300
            ComputerCount = 150
            IsRootDomain = "False"
            IsExternal = "False"
        },
        [pscustomobject]@{
            Name = "partner.company.com"
            DisplayName = "Partner Company"
            DomainType = "External"
            FunctionalLevel = "2012R2"
            DCCount = 2
            UserCount = 200
            ComputerCount = 100
            IsRootDomain = "True"
            IsExternal = "True"
        },
        [pscustomobject]@{
            Name = "subsidiary.local"
            DisplayName = "Subsidiary Corp"
            DomainType = "External"
            FunctionalLevel = "2008R2"
            DCCount = 1
            UserCount = 50
            ComputerCount = 25
            IsRootDomain = "True"
            IsExternal = "True"
        }
    )
}

function Get-SampleTrustData {
    return @(
        [pscustomobject]@{
            SourceDomain = "contoso.com"
            TargetDomain = "europe.contoso.com"
            TrustType = "Parent-Child"
            TrustDirection = "Bidirectional"
            Transitive = "True"
            Authentication = "Kerberos"
            SelectiveAuth = "False"
            SidFiltering = "False"
            TrustStatus = "Active"
        },
        [pscustomobject]@{
            SourceDomain = "contoso.com"
            TargetDomain = "asia.contoso.com"
            TrustType = "Parent-Child"
            TrustDirection = "Bidirectional"
            Transitive = "True"
            Authentication = "Kerberos"
            SelectiveAuth = "False"
            SidFiltering = "False"
            TrustStatus = "Active"
        },
        [pscustomobject]@{
            SourceDomain = "contoso.com"
            TargetDomain = "partner.company.com"
            TrustType = "External"
            TrustDirection = "Bidirectional"
            Transitive = "False"
            Authentication = "NTLM"
            SelectiveAuth = "True"
            SidFiltering = "True"
            TrustStatus = "Active"
        },
        [pscustomobject]@{
            SourceDomain = "europe.contoso.com"
            TargetDomain = "asia.contoso.com"
            TrustType = "Shortcut"
            TrustDirection = "Bidirectional"
            Transitive = "True"
            Authentication = "Kerberos"
            SelectiveAuth = "False"
            SidFiltering = "False"
            TrustStatus = "Active"
        },
        [pscustomobject]@{
            SourceDomain = "contoso.com"
            TargetDomain = "subsidiary.local"
            TrustType = "External"
            TrustDirection = "Outbound"
            Transitive = "False"
            Authentication = "NTLM"
            SelectiveAuth = "True"
            SidFiltering = "True"
            TrustStatus = "Active"
        }
    )
}

Export-ModuleMember -Function New-TrustMapDiagram
