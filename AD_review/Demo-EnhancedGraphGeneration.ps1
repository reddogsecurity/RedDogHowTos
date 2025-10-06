# Demo script for Enhanced Graph Generation
# Shows how to use the new configuration-driven approach

# Import the enhanced graph generator
. "$PSScriptRoot\Enhanced-GraphGenerator.ps1"

# Example usage
Write-Host "Enhanced Graph Generation Demo" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

# Example 1: Generate privileged access diagram only
Write-Host "`nExample 1: Privileged Access Diagram" -ForegroundColor Yellow
$result1 = New-EnhancedGraphFromAudit -OutputFolder "C:\temp\audit-output" -DiagramTypes @("privileged-access")

if ($result1.Success) {
    Write-Host "✓ Privileged access diagram generated successfully" -ForegroundColor Green
    Write-Host "  High Risk Nodes: $($result1.GraphStats.HighRiskNodes)" -ForegroundColor Red
    Write-Host "  Medium Risk Nodes: $($result1.GraphStats.MediumRiskNodes)" -ForegroundColor Yellow
    Write-Host "  Low Risk Nodes: $($result1.GraphStats.LowRiskNodes)" -ForegroundColor Green
} else {
    Write-Host "✗ Failed: $($result1.Error)" -ForegroundColor Red
}

# Example 2: Generate multiple diagram types
Write-Host "`nExample 2: Multiple Diagram Types" -ForegroundColor Yellow
$result2 = New-EnhancedGraphFromAudit -OutputFolder "C:\temp\audit-output" -DiagramTypes @("privileged-access", "risk-overview")

if ($result2.Success) {
    Write-Host "✓ Multiple diagrams generated successfully" -ForegroundColor Green
    foreach ($diagramType in $result2.Diagrams.Keys) {
        Write-Host "  - $diagramType diagram created" -ForegroundColor Cyan
    }
} else {
    Write-Host "✗ Failed: $($result2.Error)" -ForegroundColor Red
}

# Example 3: Generate with specific timestamp
Write-Host "`nExample 3: Specific Timestamp" -ForegroundColor Yellow
$timestamp = "20241201-120000"
$result3 = New-EnhancedGraphFromAudit -OutputFolder "C:\temp\audit-output" -NowTag $timestamp -DiagramTypes @("privileged-access")

if ($result3.Success) {
    Write-Host "✓ Diagram generated with timestamp: $($result3.Timestamp)" -ForegroundColor Green
} else {
    Write-Host "✗ Failed: $($result3.Error)" -ForegroundColor Red
}

Write-Host "`nDemo completed!" -ForegroundColor Cyan
Write-Host "Check the output folder for generated diagrams." -ForegroundColor White
