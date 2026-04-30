# Comprehensive Demo for All Diagram Types
# Shows how to generate all available diagram types using the enhanced system

# Import the enhanced graph generator
. "$PSScriptRoot\Enhanced-GraphGenerator.ps1"

Write-Host "Enhanced Graph Generation - All Diagram Types Demo" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Example 1: Generate all diagram types
Write-Host "`nExample 1: Generate All Diagram Types" -ForegroundColor Yellow
$allDiagramTypes = @(
    "privileged-access",
    "gpo-topology", 
    "trust-map",
    "app-grant-views",
    "zero-trust-controls",
    "risk-overview"
)

$result1 = New-EnhancedGraphFromAudit -OutputFolder "C:\temp\audit-output" -DiagramTypes $allDiagramTypes

if ($result1.Success) {
    Write-Host "✓ All diagrams generated successfully!" -ForegroundColor Green
    Write-Host "  Total Nodes: $($result1.GraphStats.NodeCount)" -ForegroundColor White
    Write-Host "  Total Edges: $($result1.GraphStats.EdgeCount)" -ForegroundColor White
    Write-Host "  High Risk Nodes: $($result1.GraphStats.HighRiskNodes)" -ForegroundColor Red
    Write-Host "  Medium Risk Nodes: $($result1.GraphStats.MediumRiskNodes)" -ForegroundColor Yellow
    Write-Host "  Low Risk Nodes: $($result1.GraphStats.LowRiskNodes)" -ForegroundColor Green
    
    Write-Host "`n  Generated Diagrams:" -ForegroundColor Cyan
    foreach ($diagramType in $result1.Diagrams.Keys) {
        $diagram = $result1.Diagrams[$diagramType]
        Write-Host "    - $diagramType" -ForegroundColor White
        if ($diagram.Stats) {
            foreach ($stat in $diagram.Stats.PSObject.Properties) {
                Write-Host "      $($stat.Name): $($stat.Value)" -ForegroundColor Gray
            }
        }
    }
} else {
    Write-Host "✗ Failed: $($result1.Error)" -ForegroundColor Red
}

# Example 2: Generate specific diagram types for security assessment
Write-Host "`nExample 2: Security Assessment Focus" -ForegroundColor Yellow
$securityDiagramTypes = @("privileged-access", "app-grant-views", "zero-trust-controls")

$result2 = New-EnhancedGraphFromAudit -OutputFolder "C:\temp\audit-output" -DiagramTypes $securityDiagramTypes

if ($result2.Success) {
    Write-Host "✓ Security assessment diagrams generated!" -ForegroundColor Green
    
    # Show specific security metrics
    $privilegedStats = $result2.Diagrams["privileged-access"].Stats
    $appStats = $result2.Diagrams["app-grant-views"].Stats
    $ztStats = $result2.Diagrams["zero-trust-controls"].Stats
    
    Write-Host "`n  Security Assessment Summary:" -ForegroundColor Cyan
    Write-Host "    Privileged Access:" -ForegroundColor White
    Write-Host "      - High Risk Groups: $($privilegedStats.HighRiskGPOs)" -ForegroundColor Red
    Write-Host "      - High Risk OUs: $($privilegedStats.HighRiskOUs)" -ForegroundColor Red
    
    Write-Host "    Application Grants:" -ForegroundColor White
    Write-Host "      - High Risk Service Principals: $($appStats.HighRiskSPs)" -ForegroundColor Red
    Write-Host "      - High Risk OAuth Scopes: $($appStats.HighRiskScopes)" -ForegroundColor Red
    Write-Host "      - Expired Secrets: $($appStats.ExpiredSecrets)" -ForegroundColor Red
    
    Write-Host "    Zero-Trust Controls:" -ForegroundColor White
    Write-Host "      - High Risk Policies: $($ztStats.HighRiskPolicies)" -ForegroundColor Red
    Write-Host "      - Unprotected Targets: $($ztStats.UnprotectedTargets)" -ForegroundColor Red
    Write-Host "      - Disabled Policies: $($ztStats.DisabledPolicies)" -ForegroundColor Red
} else {
    Write-Host "✗ Failed: $($result2.Error)" -ForegroundColor Red
}

# Example 3: Generate infrastructure-focused diagrams
Write-Host "`nExample 3: Infrastructure Assessment" -ForegroundColor Yellow
$infraDiagramTypes = @("gpo-topology", "trust-map")

$result3 = New-EnhancedGraphFromAudit -OutputFolder "C:\temp\audit-output" -DiagramTypes $infraDiagramTypes

if ($result3.Success) {
    Write-Host "✓ Infrastructure diagrams generated!" -ForegroundColor Green
    
    $gpoStats = $result3.Diagrams["gpo-topology"].Stats
    $trustStats = $result3.Diagrams["trust-map"].Stats
    
    Write-Host "`n  Infrastructure Assessment Summary:" -ForegroundColor Cyan
    Write-Host "    GPO Topology:" -ForegroundColor White
    Write-Host "      - Total GPOs: $($gpoStats.GPOCount)" -ForegroundColor White
    Write-Host "      - Total OUs: $($gpoStats.OUCount)" -ForegroundColor White
    Write-Host "      - GPO Links: $($gpoStats.LinkCount)" -ForegroundColor White
    Write-Host "      - Delegations: $($gpoStats.DelegationCount)" -ForegroundColor Yellow
    
    Write-Host "    Trust Relationships:" -ForegroundColor White
    Write-Host "      - Total Domains: $($trustStats.DomainCount)" -ForegroundColor White
    Write-Host "      - Total Trusts: $($trustStats.TrustCount)" -ForegroundColor White
    Write-Host "      - External Trusts: $($trustStats.ExternalTrusts)" -ForegroundColor Red
    Write-Host "      - Forest Trusts: $($trustStats.ForestTrusts)" -ForegroundColor Yellow
} else {
    Write-Host "✗ Failed: $($result3.Error)" -ForegroundColor Red
}

# Example 4: Generate risk overview only
Write-Host "`nExample 4: Risk Overview Dashboard" -ForegroundColor Yellow
$riskResult = New-EnhancedGraphFromAudit -OutputFolder "C:\temp\audit-output" -DiagramTypes @("risk-overview")

if ($riskResult.Success) {
    Write-Host "✓ Risk overview dashboard generated!" -ForegroundColor Green
    Write-Host "  Use this for executive reporting and high-level risk assessment." -ForegroundColor White
} else {
    Write-Host "✗ Failed: $($riskResult.Error)" -ForegroundColor Red
}

Write-Host "`nDemo completed!" -ForegroundColor Cyan
Write-Host "Check the output folder for all generated diagrams:" -ForegroundColor White
Write-Host "  - Graphviz DOT files (.dot)" -ForegroundColor Gray
Write-Host "  - Mermaid diagrams (.mmd)" -ForegroundColor Gray
Write-Host "  - PNG images (.png) if Graphviz is installed" -ForegroundColor Gray
Write-Host "  - Summary reports (.txt)" -ForegroundColor Gray

Write-Host "`nAvailable Diagram Types:" -ForegroundColor Cyan
Write-Host "  1. privileged-access    - Shows privileged groups and role assignments" -ForegroundColor White
Write-Host "  2. gpo-topology        - Shows GPO links to OUs with delegations" -ForegroundColor White
Write-Host "  3. trust-map           - Shows domain/forest trust relationships" -ForegroundColor White
Write-Host "  4. app-grant-views     - Shows service principals with OAuth grants" -ForegroundColor White
Write-Host "  5. zero-trust-controls - Shows Conditional Access policy mappings" -ForegroundColor White
Write-Host "  6. risk-overview       - Shows high-level risk categorization" -ForegroundColor White
