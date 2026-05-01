# Enhanced Graph Generator using configuration-driven approach
# Imports the enhanced data processor and generates multiple diagram types

# Import the enhanced data processor and diagram generators
. "$PSScriptRoot\modules\Enhanced-GraphDataProcessor.ps1"
. "$PSScriptRoot\modules\GPO-TopologyGenerator.ps1"
. "$PSScriptRoot\modules\Trust-MapGenerator.ps1"
. "$PSScriptRoot\modules\App-GrantGenerator.ps1"
. "$PSScriptRoot\modules\ZeroTrust-Generator.ps1"

function New-EnhancedGraphFromAudit {
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$NowTag,
        [string[]]$DiagramTypes = @("privileged-access", "gpo-topology", "trust-map", "app-grant-views", "zero-trust-controls", "risk-overview"),
        [string]$ConfigPath = $PSScriptRoot
    )
    
    $stamp = if ($NowTag) { $NowTag } else { (Get-Date).ToString('yyyyMMdd-HHmmss') }
    
    Write-Host "Starting Enhanced Graph Generation..." -ForegroundColor Cyan
    Write-Host "Output Folder: $OutputFolder" -ForegroundColor Yellow
    Write-Host "Timestamp: $stamp" -ForegroundColor Yellow
    Write-Host "Diagram Types: $($DiagramTypes -join ', ')" -ForegroundColor Yellow
    
    # Initialize the enhanced data processor
    $processor = [EnhancedGraphDataProcessor]::new($ConfigPath, $OutputFolder)
    
    try {
        # Load all data files
        $processor.LoadDataFiles($NowTag)
        
        # Build nodes and edges
        $processor.BuildNodes()
        $processor.BuildEdges()
        
        # Calculate risk scores
        $processor.CalculateRiskScores()
        
        # Get the processed graph data
        $graphData = $processor.GetGraphData()
        
        # Generate requested diagram types
        $results = @{}
        
        foreach ($diagramType in $DiagramTypes) {
            Write-Host "Generating $diagramType diagram..." -ForegroundColor Cyan
            
            switch ($diagramType.ToLower()) {
                "privileged-access" {
                    $results["privileged-access"] = New-PrivilegedAccessDiagram -GraphData $graphData -OutputFolder $OutputFolder -Timestamp $stamp
                }
                "gpo-topology" {
                    $results["gpo-topology"] = New-GPOTopologyDiagram -GraphData $graphData -OutputFolder $OutputFolder -Timestamp $stamp
                }
                "trust-map" {
                    $results["trust-map"] = New-TrustMapDiagram -GraphData $graphData -OutputFolder $OutputFolder -Timestamp $stamp
                }
                "app-grant-views" {
                    $results["app-grant-views"] = New-AppGrantDiagram -GraphData $graphData -OutputFolder $OutputFolder -Timestamp $stamp
                }
                "zero-trust-controls" {
                    $results["zero-trust-controls"] = New-ZeroTrustDiagram -GraphData $graphData -OutputFolder $OutputFolder -Timestamp $stamp
                }
                "service-accounts" {
                    $results["service-accounts"] = New-ServiceAccountDiagram -GraphData $graphData -OutputFolder $OutputFolder -Timestamp $stamp
                }
                "risk-overview" {
                    $results["risk-overview"] = New-RiskOverviewDiagram -GraphData $graphData -OutputFolder $OutputFolder -Timestamp $stamp
                }
                default {
                    Write-Warning "Unknown diagram type: $diagramType"
                }
            }
        }
        
        # Generate summary report
        $summaryPath = Join-Path $OutputFolder "graph-generation-summary-$stamp.txt"
        $summary = @"
Enhanced Graph Generation Summary
Generated: $(Get-Date)
Timestamp: $stamp

Diagram Types Generated:
$(foreach ($type in $DiagramTypes) { "- $type" })

Graph Statistics:
- Total Nodes: $($graphData.Nodes.Count)
- Total Edges: $($graphData.Edges.Count)
- High Risk Nodes: $(($graphData.Nodes | Where-Object { $_.RiskLevel -eq "High" }).Count)
- Medium Risk Nodes: $(($graphData.Nodes | Where-Object { $_.RiskLevel -eq "Medium" }).Count)
- Low Risk Nodes: $(($graphData.Nodes | Where-Object { $_.RiskLevel -eq "Low" }).Count)

Output Files:
$(foreach ($result in $results.Values) { 
    foreach ($key in $result.PSObject.Properties.Name) {
        "- $key`: $($result.$key)"
    }
})
"@
        
        $summary | Out-File $summaryPath -Encoding utf8
        Write-Host "Summary report saved: $summaryPath" -ForegroundColor Green
        
        return [pscustomobject]@{
            Success = $true
            Timestamp = $stamp
            Diagrams = $results
            Summary = $summaryPath
            GraphStats = @{
                NodeCount = $graphData.Nodes.Count
                EdgeCount = $graphData.Edges.Count
                HighRiskNodes = ($graphData.Nodes | Where-Object { $_.RiskLevel -eq "High" }).Count
                MediumRiskNodes = ($graphData.Nodes | Where-Object { $_.RiskLevel -eq "Medium" }).Count
                LowRiskNodes = ($graphData.Nodes | Where-Object { $_.RiskLevel -eq "Low" }).Count
            }
        }
        
    } catch {
        Write-Error "Graph generation failed: $($_.Exception.Message)"
        return [pscustomobject]@{
            Success = $false
            Error = $_.Exception.Message
            Timestamp = $stamp
        }
    }
}

function New-PrivilegedAccessDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building privileged access diagram..." -ForegroundColor Cyan
    
    # Filter to only privileged nodes and their relationships
    $privilegedNodes = $GraphData.Nodes | Where-Object { 
        $_.Properties.ContainsKey("isPrivileged") -and $_.Properties["isPrivileged"] -eq $true 
    }
    
    $privilegedEdges = $GraphData.Edges | Where-Object {
        $privilegedNodes | Where-Object { $_.Name -eq $_.From -or $_.Name -eq $_.To }
    }
    
    # Generate Graphviz DOT
    $dotPath = Join-Path $OutputFolder "privileged-access-$Timestamp.dot"
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('digraph PrivilegedAccess {')
    [void]$sb.AppendLine('rankdir=LR; fontsize=10; fontname="Segoe UI";')
    [void]$sb.AppendLine('node [shape=box, style=filled, fontname="Segoe UI", fontsize=9];')
    [void]$sb.AppendLine('edge [color="#7f8c8d"];')
    
    # Add nodes with risk-based styling
    foreach ($node in $privilegedNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $nodeConfig = $GraphData.Config.GetNodeTypeConfig($node.NodeType)
        $riskColor = $nodeConfig.riskColorMap[$node.RiskLevel]
        
        [void]$sb.AppendLine("$safeName [label=""$($node.DisplayName)"", fillcolor=""$riskColor""];")
    }
    
    # Add edges
    foreach ($edge in $privilegedEdges) {
        $fromSafe = ($edge.From -replace '[^A-Za-z0-9_@\-\.]', '_')
        $toSafe = ($edge.To -replace '[^A-Za-z0-9_@\-\.]', '_')
        [void]$sb.AppendLine("$fromSafe -> $toSafe;")
    }
    
    [void]$sb.AppendLine('}')
    $sb.ToString() | Out-File $dotPath -Encoding utf8
    
    # Generate Mermaid version
    $mmdPath = Join-Path $OutputFolder "privileged-access-$Timestamp.mmd"
    $mmd = [System.Text.StringBuilder]::new()
    [void]$mmd.AppendLine('flowchart LR')
    
    foreach ($edge in $privilegedEdges) {
        [void]$mmd.AppendLine("  ""$($edge.From)"" --> ""$($edge.To)""")
    }
    $mmd.ToString() | Out-File $mmdPath -Encoding utf8
    
    # Try to render PNG if Graphviz is available
    $pngPath = $null
    $dotExe = (Get-Command dot -ErrorAction SilentlyContinue).Source
    if ($dotExe) {
        $pngPath = Join-Path $OutputFolder "privileged-access-$Timestamp.png"
        & $dotExe -Tpng $dotPath -o $pngPath
        Write-Host "PNG rendered: $pngPath" -ForegroundColor Green
    }
    
    return [pscustomobject]@{
        Dot = $dotPath
        Mermaid = $mmdPath
        PNG = $pngPath
    }
}

function New-RiskOverviewDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building risk overview diagram..." -ForegroundColor Cyan
    
    # Group nodes by risk level
    $highRiskNodes = $GraphData.Nodes | Where-Object { $_.RiskLevel -eq "High" }
    $mediumRiskNodes = $GraphData.Nodes | Where-Object { $_.RiskLevel -eq "Medium" }
    $lowRiskNodes = $GraphData.Nodes | Where-Object { $_.RiskLevel -eq "Low" }
    
    # Generate Mermaid risk overview
    $mmdPath = Join-Path $OutputFolder "risk-overview-$Timestamp.mmd"
    $mmd = [System.Text.StringBuilder]::new()
    [void]$mmd.AppendLine('flowchart TD')
    [void]$mmd.AppendLine('  subgraph High["🔴 High Risk ($($highRiskNodes.Count) items)"]')
    
    foreach ($node in $highRiskNodes | Select-Object -First 10) {
        [void]$mmd.AppendLine("    $($node.Name)[""$($node.DisplayName)""]")
    }
    
    [void]$mmd.AppendLine('  end')
    [void]$mmd.AppendLine('  subgraph Medium["🟡 Medium Risk ($($mediumRiskNodes.Count) items)"]')
    
    foreach ($node in $mediumRiskNodes | Select-Object -First 10) {
        [void]$mmd.AppendLine("    $($node.Name)[""$($node.DisplayName)""]")
    }
    
    [void]$mmd.AppendLine('  end')
    [void]$mmd.AppendLine('  subgraph Low["🟢 Low Risk ($($lowRiskNodes.Count) items)"]')
    [void]$mmd.AppendLine("    LowSummary[""$($lowRiskNodes.Count) low risk items""]")
    [void]$mmd.AppendLine('  end')
    
    $mmd.ToString() | Out-File $mmdPath -Encoding utf8
    
    return [pscustomobject]@{
        Mermaid = $mmdPath
    }
}

function New-GPOTopologyDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building GPO topology diagram..." -ForegroundColor Cyan
    Write-Warning "GPO topology diagram not yet implemented - requires GPO data collection"
    
    return [pscustomobject]@{
        Status = "Not Implemented"
        Message = "Requires GPO data collection to be implemented"
    }
}

function New-TrustMapDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building trust map diagram..." -ForegroundColor Cyan
    Write-Warning "Trust map diagram not yet implemented - requires trust data collection"
    
    return [pscustomobject]@{
        Status = "Not Implemented"
        Message = "Requires trust data collection to be implemented"
    }
}

function New-ServiceAccountDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building service account diagram..." -ForegroundColor Cyan
    Write-Warning "Service account diagram not yet implemented - requires service account data collection"
    
    return [pscustomobject]@{
        Status = "Not Implemented"
        Message = "Requires service account data collection to be implemented"
    }
}

# Export functions for use
Export-ModuleMember -Function New-EnhancedGraphFromAudit, New-PrivilegedAccessDiagram, New-RiskOverviewDiagram
