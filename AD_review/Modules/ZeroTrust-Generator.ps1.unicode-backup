# Zero-Trust Controls Diagram Generator
# Creates diagrams showing Conditional Access policy mappings and zero-trust controls

class CAPolicyNode {
    [string]$Name
    [string]$DisplayName
    [string]$ObjectId
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    CAPolicyNode([string]$Name, [string]$DisplayName, [string]$ObjectId) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.ObjectId = $ObjectId
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class CATargetNode {
    [string]$Name
    [string]$DisplayName
    [string]$TargetType
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    CATargetNode([string]$Name, [string]$DisplayName, [string]$TargetType) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.TargetType = $TargetType
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class CAControlNode {
    [string]$Name
    [string]$DisplayName
    [string]$ControlType
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    CAControlNode([string]$Name, [string]$DisplayName, [string]$ControlType) {
        $this.Name = $Name
        $this.DisplayName = $DisplayName
        $this.ControlType = $ControlType
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
}

class CAEdge {
    [string]$From
    [string]$To
    [string]$EdgeType
    [string]$RelationshipType
    [hashtable]$Properties
    
    CAEdge([string]$From, [string]$To, [string]$EdgeType, [string]$RelationshipType) {
        $this.From = $From
        $this.To = $To
        $this.EdgeType = $EdgeType
        $this.RelationshipType = $RelationshipType
        $this.Properties = @{}
    }
}

function New-ZeroTrustDiagram {
    param(
        [Parameter(Mandatory)]$GraphData,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Timestamp
    )
    
    Write-Host "Building Zero-Trust Controls diagram..." -ForegroundColor Cyan
    
    # Check if we have CA data
    if (-not $GraphData.DataCache.ContainsKey("caPolicies") -or 
        -not $GraphData.DataCache.ContainsKey("caTargets")) {
        Write-Warning "Conditional Access data not available. Using sample data..."
        $policyData = Get-SampleCAPolicyData
        $targetData = Get-SampleCATargetData
        $controlData = Get-SampleCAControlData
        $mappingData = Get-SampleCAMappingData
    } else {
        $policyData = $GraphData.DataCache["caPolicies"]
        $targetData = $GraphData.DataCache["caTargets"]
        $controlData = $GraphData.DataCache["caControls"]
        $mappingData = $GraphData.DataCache["caMappings"]
    }
    
    # Build CA policy nodes
    $policyNodes = @()
    foreach ($policy in $policyData) {
        $node = [CAPolicyNode]::new($policy.Name, $policy.DisplayName, $policy.ObjectId)
        $node.Properties["state"] = $policy.State
        $node.Properties["enabled"] = $policy.Enabled -eq "True"
        $node.Properties["priority"] = $policy.Priority
        $node.Properties["createdDateTime"] = $policy.CreatedDateTime
        $node.Properties["modifiedDateTime"] = $policy.ModifiedDateTime
        $node.Properties["targetCount"] = $policy.TargetCount
        $node.Properties["controlCount"] = $policy.ControlCount
        $node.Properties["isHighRisk"] = $policy.IsHighRisk -eq "True"
        
        # Calculate risk score
        $riskScore = 0
        if ($policy.IsHighRisk -eq "True") { $riskScore += 10 }
        if ($policy.Enabled -eq "False") { $riskScore += 8 }
        if ($policy.TargetCount -gt 50) { $riskScore += 5 }
        if ($policy.ControlCount -lt 2) { $riskScore += 6 }
        if ($policy.State -eq "Draft") { $riskScore += 3 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 15) { "High" } elseif ($riskScore -ge 8) { "Medium" } else { "Low" }
        
        $policyNodes += $node
    }
    
    # Build target nodes
    $targetNodes = @()
    foreach ($target in $targetData) {
        $node = [CATargetNode]::new($target.Name, $target.DisplayName, $target.TargetType)
        $node.Properties["objectType"] = $target.ObjectType
        $node.Properties["memberCount"] = $target.MemberCount
        $node.Properties["isPrivileged"] = $target.IsPrivileged -eq "True"
        $node.Properties["isExternal"] = $target.IsExternal -eq "True"
        $node.Properties["policyCount"] = $target.PolicyCount
        
        # Calculate risk score
        $riskScore = 0
        if ($target.IsPrivileged -eq "True") { $riskScore += 10 }
        if ($target.IsExternal -eq "True") { $riskScore += 8 }
        if ($target.PolicyCount -eq 0) { $riskScore += 7 }
        if ($target.MemberCount -gt 100) { $riskScore += 3 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 15) { "High" } elseif ($riskScore -ge 8) { "Medium" } else { "Low" }
        
        $targetNodes += $node
    }
    
    # Build control nodes
    $controlNodes = @()
    foreach ($control in $controlData) {
        $node = [CAControlNode]::new($control.Name, $control.DisplayName, $control.ControlType)
        $node.Properties["controlAction"] = $control.ControlAction
        $node.Properties["isRequired"] = $control.IsRequired -eq "True"
        $node.Properties["isHighImpact"] = $control.IsHighImpact -eq "True"
        $node.Properties["policyCount"] = $control.PolicyCount
        $node.Properties["effectiveness"] = $control.Effectiveness
        
        # Calculate risk score
        $riskScore = 0
        if ($control.IsHighImpact -eq "True") { $riskScore += 8 }
        if ($control.IsRequired -eq "False") { $riskScore += 5 }
        if ($control.PolicyCount -lt 5) { $riskScore += 4 }
        if ($control.Effectiveness -lt 0.7) { $riskScore += 6 }
        
        $node.RiskScore = $riskScore
        $node.RiskLevel = if ($riskScore -ge 12) { "High" } elseif ($riskScore -ge 6) { "Medium" } else { "Low" }
        
        $controlNodes += $node
    }
    
    # Build mapping edges
    $mappingEdges = @()
    foreach ($mapping in $mappingData) {
        $edge = [CAEdge]::new($mapping.Policy, $mapping.Target, "targets", $mapping.RelationshipType)
        $edge.Properties["appliesTo"] = $mapping.AppliesTo
        $edge.Properties["excludeFrom"] = $mapping.ExcludeFrom -eq "True"
        $edge.Properties["priority"] = $mapping.Priority
        
        $mappingEdges += $edge
    }
    
    # Add control edges
    foreach ($policy in $policyData) {
        if ($policy.Controls) {
            $controls = $policy.Controls -split ','
            foreach ($controlName in $controls) {
                if ($controlName.Trim()) {
                    $edge = [CAEdge]::new($policy.Name, $controlName.Trim(), "uses", "control")
                    $edge.Properties["controlAction"] = $policy.ControlAction
                    $mappingEdges += $edge
                }
            }
        }
    }
    
    # Generate Graphviz DOT
    $dotPath = Join-Path $OutputFolder "zero-trust-controls-$Timestamp.dot"
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('digraph ZeroTrustControls {')
    [void]$sb.AppendLine('rankdir=TB; fontsize=10; fontname="Segoe UI";')
    [void]$sb.AppendLine('node [style=filled, fontname="Segoe UI", fontsize=9];')
    [void]$sb.AppendLine('edge [color="#7f8c8d"];')
    
    # Define colors for risk levels
    $riskColors = @{ High='#e74c3c'; Medium='#e67e22'; Low='#f1c40f' }
    
    # Add policy nodes (rectangles)
    foreach ($node in $policyNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        
        $label = "$($node.DisplayName)"
        if ($node.Properties["enabled"] -eq $false) { $label += " (Disabled)" }
        if ($node.Properties["isHighRisk"]) { $label += " (High Risk)" }
        
        [void]$sb.AppendLine("$safeName [label=""$label"", fillcolor=""$color"", shape=rectangle];")
    }
    
    # Add target nodes (ellipses)
    foreach ($node in $targetNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        
        $label = "$($node.DisplayName)"
        if ($node.Properties["isPrivileged"]) { $label += " (Privileged)" }
        if ($node.Properties["isExternal"]) { $label += " (External)" }
        
        [void]$sb.AppendLine("$safeName [label=""$label"", fillcolor=""$color"", shape=ellipse];")
    }
    
    # Add control nodes (diamonds)
    foreach ($node in $controlNodes) {
        $safeName = ($node.Name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $color = $riskColors[$node.RiskLevel]
        
        $label = "$($node.DisplayName)"
        if ($node.Properties["isRequired"]) { $label += " (Required)" }
        if ($node.Properties["isHighImpact"]) { $label += " (High Impact)" }
        
        [void]$sb.AppendLine("$safeName [label=""$label"", fillcolor=""$color"", shape=diamond];")
    }
    
    # Add edges with different styles
    foreach ($edge in $mappingEdges) {
        $fromSafe = ($edge.From -replace '[^A-Za-z0-9_@\-\.]', '_')
        $toSafe = ($edge.To -replace '[^A-Za-z0-9_@\-\.]', '_')
        
        $edgeStyle = "solid"
        $edgeColor = "#7f8c8d"
        
        if ($edge.EdgeType -eq "targets") {
            $edgeColor = "#3498db"
            $edgeStyle = "solid"
        } elseif ($edge.EdgeType -eq "uses") {
            $edgeColor = "#e67e22"
            $edgeStyle = "dashed"
        }
        
        if ($edge.Properties["excludeFrom"] -eq $true) {
            $edgeColor = "#e74c3c"
            $edgeStyle = "dotted"
        }
        
        [void]$sb.AppendLine("$fromSafe -> $toSafe [style=""$edgeStyle"", color=""$edgeColor""];")
    }
    
    [void]$sb.AppendLine('}')
    $sb.ToString() | Out-File $dotPath -Encoding utf8
    
    # Generate Mermaid version
    $mmdPath = Join-Path $OutputFolder "zero-trust-controls-$Timestamp.mmd"
    $mmd = [System.Text.StringBuilder]::new()
    [void]$mmd.AppendLine('flowchart TD')
    
    # Add policies
    foreach ($node in $policyNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        $policyIcon = if ($node.Properties["enabled"]) { "✅" } else { "❌" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon$policyIcon $($node.DisplayName)""]")
    }
    
    # Add targets
    foreach ($node in $targetNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        $targetIcon = if ($node.Properties["isPrivileged"]) { "👑" } else { "👤" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon$targetIcon $($node.DisplayName)""]")
    }
    
    # Add controls
    foreach ($node in $controlNodes) {
        $riskIcon = if ($node.RiskLevel -eq "High") { "🔴" } elseif ($node.RiskLevel -eq "Medium") { "🟡" } else { "🟢" }
        $controlIcon = if ($node.Properties["isRequired"]) { "🔒" } else { "🔓" }
        [void]$mmd.AppendLine("  $($node.Name)[""$riskIcon$controlIcon $($node.DisplayName)""]")
    }
    
    # Add relationships
    foreach ($edge in $mappingEdges) {
        $fromName = ($edge.From -replace '.*\.', '')
        $toName = ($edge.To -replace '.*\.', '')
        
        if ($edge.EdgeType -eq "targets") {
            if ($edge.Properties["excludeFrom"] -eq $true) {
                [void]$mmd.AppendLine("  $fromName -.-> $toName")
            } else {
                [void]$mmd.AppendLine("  $fromName --> $toName")
            }
        } elseif ($edge.EdgeType -eq "uses") {
            [void]$mmd.AppendLine("  $fromName ==> $toName")
        }
    }
    
    $mmd.ToString() | Out-File $mmdPath -Encoding utf8
    
    # Try to render PNG if Graphviz is available
    $pngPath = $null
    $dotExe = (Get-Command dot -ErrorAction SilentlyContinue).Source
    if ($dotExe) {
        $pngPath = Join-Path $OutputFolder "zero-trust-controls-$Timestamp.png"
        & $dotExe -Tpng $dotPath -o $pngPath
        Write-Host "Zero-Trust Controls PNG rendered: $pngPath" -ForegroundColor Green
    }
    
    Write-Host "Zero-Trust Controls diagram completed:" -ForegroundColor Green
    Write-Host "  - Policies: $($policyNodes.Count)" -ForegroundColor White
    Write-Host "  - Targets: $($targetNodes.Count)" -ForegroundColor White
    Write-Host "  - Controls: $($controlNodes.Count)" -ForegroundColor White
    Write-Host "  - High Risk Policies: $(($policyNodes | Where-Object { $_.RiskLevel -eq "High" }).Count)" -ForegroundColor Red
    Write-Host "  - Unprotected Targets: $(($targetNodes | Where-Object { $_.Properties["policyCount"] -eq 0 }).Count)" -ForegroundColor Red
    
    return [pscustomobject]@{
        Dot = $dotPath
        Mermaid = $mmdPath
        PNG = $pngPath
        Stats = @{
            PolicyCount = $policyNodes.Count
            TargetCount = $targetNodes.Count
            ControlCount = $controlNodes.Count
            HighRiskPolicies = ($policyNodes | Where-Object { $_.RiskLevel -eq "High" }).Count
            UnprotectedTargets = ($targetNodes | Where-Object { $_.Properties["policyCount"] -eq 0 }).Count
            DisabledPolicies = ($policyNodes | Where-Object { $_.Properties["enabled"] -eq $false }).Count
            PrivilegedTargets = ($targetNodes | Where-Object { $_.Properties["isPrivileged"] -eq $true }).Count
        }
    }
}

function Get-SampleCAPolicyData {
    return @(
        [pscustomobject]@{
            Name = "Require MFA for Admins"
            DisplayName = "Require MFA for All Administrators"
            ObjectId = "11111111-1111-1111-1111-111111111111"
            State = "Enabled"
            Enabled = "True"
            Priority = 1
            CreatedDateTime = "2024-01-15"
            ModifiedDateTime = "2024-11-01"
            TargetCount = 5
            ControlCount = 2
            IsHighRisk = "True"
            Controls = "Require MFA,Require Compliant Device"
            ControlAction = "Grant"
        },
        [pscustomobject]@{
            Name = "Block Legacy Auth"
            DisplayName = "Block Legacy Authentication"
            ObjectId = "22222222-2222-2222-2222-222222222222"
            State = "Enabled"
            Enabled = "True"
            Priority = 2
            CreatedDateTime = "2024-02-01"
            ModifiedDateTime = "2024-10-15"
            TargetCount = 50
            ControlCount = 1
            IsHighRisk = "False"
            Controls = "Block Access"
            ControlAction = "Block"
        },
        [pscustomobject]@{
            Name = "High Risk Sign-ins"
            DisplayName = "High Risk Sign-in Protection"
            ObjectId = "33333333-3333-3333-3333-333333333333"
            State = "Enabled"
            Enabled = "True"
            Priority = 3
            CreatedDateTime = "2024-03-01"
            ModifiedDateTime = "2024-09-20"
            TargetCount = 200
            ControlCount = 3
            IsHighRisk = "True"
            Controls = "Require MFA,Require Password Change,Require Compliant Device"
            ControlAction = "Grant"
        },
        [pscustomobject]@{
            Name = "Finance Team Policy"
            DisplayName = "Finance Team Access Policy"
            ObjectId = "44444444-4444-4444-4444-444444444444"
            State = "Draft"
            Enabled = "False"
            Priority = 4
            CreatedDateTime = "2024-11-15"
            ModifiedDateTime = "2024-11-15"
            TargetCount = 25
            ControlCount = 2
            IsHighRisk = "False"
            Controls = "Require MFA,Require Compliant Device"
            ControlAction = "Grant"
        },
        [pscustomobject]@{
            Name = "External Users"
            DisplayName = "External User Restrictions"
            ObjectId = "55555555-5555-5555-5555-555555555555"
            State = "Enabled"
            Enabled = "True"
            Priority = 5
            CreatedDateTime = "2024-04-01"
            ModifiedDateTime = "2024-08-10"
            TargetCount = 15
            ControlCount = 1
            IsHighRisk = "False"
            Controls = "Require Compliant Device"
            ControlAction = "Grant"
        }
    )
}

function Get-SampleCATargetData {
    return @(
        [pscustomobject]@{
            Name = "Global Admins"
            DisplayName = "Global Administrators"
            TargetType = "Group"
            ObjectType = "Group"
            MemberCount = 5
            IsPrivileged = "True"
            IsExternal = "False"
            PolicyCount = 1
        },
        [pscustomobject]@{
            Name = "Security Admins"
            DisplayName = "Security Administrators"
            TargetType = "Group"
            ObjectType = "Group"
            MemberCount = 8
            IsPrivileged = "True"
            IsExternal = "False"
            PolicyCount = 1
        },
        [pscustomobject]@{
            Name = "Finance Team"
            DisplayName = "Finance Department"
            TargetType = "Group"
            ObjectType = "Group"
            MemberCount = 25
            IsPrivileged = "False"
            IsExternal = "False"
            PolicyCount = 0
        },
        [pscustomobject]@{
            Name = "Guest Users"
            DisplayName = "Guest Users"
            TargetType = "Group"
            ObjectType = "Group"
            MemberCount = 15
            IsPrivileged = "False"
            IsExternal = "True"
            PolicyCount = 1
        },
        [pscustomobject]@{
            Name = "All Users"
            DisplayName = "All Users"
            TargetType = "Group"
            ObjectType = "Group"
            MemberCount = 500
            IsPrivileged = "False"
            IsExternal = "False"
            PolicyCount = 2
        },
        [pscustomobject]@{
            Name = "Exchange Online"
            DisplayName = "Microsoft Exchange Online"
            TargetType = "Cloud App"
            ObjectType = "Application"
            MemberCount = 0
            IsPrivileged = "False"
            IsExternal = "False"
            PolicyCount = 1
        },
        [pscustomobject]@{
            Name = "SharePoint Online"
            DisplayName = "Microsoft SharePoint Online"
            TargetType = "Cloud App"
            ObjectType = "Application"
            MemberCount = 0
            IsPrivileged = "False"
            IsExternal = "False"
            PolicyCount = 1
        },
        [pscustomobject]@{
            Name = "High Risk Users"
            DisplayName = "High Risk User Accounts"
            TargetType = "Group"
            ObjectType = "Group"
            MemberCount = 12
            IsPrivileged = "False"
            IsExternal = "False"
            PolicyCount = 1
        }
    )
}

function Get-SampleCAControlData {
    return @(
        [pscustomobject]@{
            Name = "Require MFA"
            DisplayName = "Require Multi-Factor Authentication"
            ControlType = "Authentication"
            ControlAction = "Grant"
            IsRequired = "True"
            IsHighImpact = "True"
            PolicyCount = 3
            Effectiveness = 0.95
        },
        [pscustomobject]@{
            Name = "Require Compliant Device"
            DisplayName = "Require Compliant Device"
            ControlType = "Device"
            ControlAction = "Grant"
            IsRequired = "True"
            IsHighImpact = "True"
            PolicyCount = 4
            Effectiveness = 0.88
        },
        [pscustomobject]@{
            Name = "Block Access"
            DisplayName = "Block Access"
            ControlType = "Authentication"
            ControlAction = "Block"
            IsRequired = "False"
            IsHighImpact = "True"
            PolicyCount = 1
            Effectiveness = 1.0
        },
        [pscustomobject]@{
            Name = "Require Password Change"
            DisplayName = "Require Password Change"
            ControlType = "Authentication"
            ControlAction = "Grant"
            IsRequired = "False"
            IsHighImpact = "False"
            PolicyCount = 1
            Effectiveness = 0.75
        },
        [pscustomobject]@{
            Name = "Require Terms of Use"
            DisplayName = "Require Terms of Use Acceptance"
            ControlType = "Authentication"
            ControlAction = "Grant"
            IsRequired = "False"
            IsHighImpact = "False"
            PolicyCount = 2
            Effectiveness = 0.65
        }
    )
}

function Get-SampleCAMappingData {
    return @(
        [pscustomobject]@{
            Policy = "Require MFA for Admins"
            Target = "Global Admins"
            RelationshipType = "include"
            AppliesTo = "All Cloud Apps"
            ExcludeFrom = "False"
            Priority = 1
        },
        [pscustomobject]@{
            Policy = "Require MFA for Admins"
            Target = "Security Admins"
            RelationshipType = "include"
            AppliesTo = "All Cloud Apps"
            ExcludeFrom = "False"
            Priority = 1
        },
        [pscustomobject]@{
            Policy = "Block Legacy Auth"
            Target = "All Users"
            RelationshipType = "include"
            AppliesTo = "All Cloud Apps"
            ExcludeFrom = "False"
            Priority = 2
        },
        [pscustomobject]@{
            Policy = "High Risk Sign-ins"
            Target = "High Risk Users"
            RelationshipType = "include"
            AppliesTo = "All Cloud Apps"
            ExcludeFrom = "False"
            Priority = 3
        },
        [pscustomobject]@{
            Policy = "External Users"
            Target = "Guest Users"
            RelationshipType = "include"
            AppliesTo = "All Cloud Apps"
            ExcludeFrom = "False"
            Priority = 5
        },
        [pscustomobject]@{
            Policy = "Finance Team Policy"
            Target = "Finance Team"
            RelationshipType = "include"
            AppliesTo = "Exchange Online,SharePoint Online"
            ExcludeFrom = "False"
            Priority = 4
        }
    )
}

Export-ModuleMember -Function New-ZeroTrustDiagram
