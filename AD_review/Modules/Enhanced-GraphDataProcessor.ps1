# Enhanced Graph Data Processor
# Provides configuration-driven data processing with expanded relationship types

class GraphConfiguration {
    [hashtable]$PrivilegedConfig
    [hashtable]$RelationshipTypes
    [string]$ConfigPath
    
    GraphConfiguration([string]$ConfigPath) {
        $this.ConfigPath = $ConfigPath
        $this.LoadConfiguration()
    }
    
    [void]LoadConfiguration() {
        $configDir = Join-Path $this.ConfigPath "config"
        $privilegedConfigPath = Join-Path $configDir "privileged-config.json"
        $relationshipConfigPath = Join-Path $configDir "relationship-types.json"
        
        if (Test-Path $privilegedConfigPath) {
            $this.PrivilegedConfig = Get-Content $privilegedConfigPath | ConvertFrom-Json -AsHashtable
        } else {
            throw "Configuration file not found: $privilegedConfigPath"
        }
        
        if (Test-Path $relationshipConfigPath) {
            $this.RelationshipTypes = Get-Content $relationshipConfigPath | ConvertFrom-Json -AsHashtable
        } else {
            throw "Configuration file not found: $relationshipConfigPath"
        }
    }
    
    [array]GetPrivilegedGroups([string]$Tier = "all") {
        $groups = @()
        if ($Tier -eq "all") {
            foreach ($tier in $this.PrivilegedConfig.privilegedADGroups.PSObject.Properties.Name) {
                $groups += $this.PrivilegedConfig.privilegedADGroups.$tier
            }
        } else {
            $groups = $this.PrivilegedConfig.privilegedADGroups.$Tier
        }
        return $groups
    }
    
    [array]GetPrivilegedRoles([string]$Tier = "all") {
        $roles = @()
        if ($Tier -eq "all") {
            foreach ($tier in $this.PrivilegedConfig.privilegedEntraRoles.PSObject.Properties.Name) {
                $roles += $this.PrivilegedConfig.privilegedEntraRoles.$tier
            }
        } else {
            $roles = $this.PrivilegedConfig.privilegedEntraRoles.$Tier
        }
        return $roles
    }
    
    [hashtable]GetRelationshipConfig([string]$RelationshipType) {
        return $this.RelationshipTypes.relationshipTypes.$RelationshipType
    }
    
    [hashtable]GetNodeTypeConfig([string]$NodeType) {
        return $this.RelationshipTypes.nodeTypes.$NodeType
    }
}

class GraphEdge {
    [string]$From
    [string]$To
    [string]$EdgeType
    [string]$Direction
    [int]$RiskWeight
    [hashtable]$Properties
    
    GraphEdge([string]$From, [string]$To, [string]$EdgeType, [string]$Direction, [int]$RiskWeight) {
        $this.From = $From
        $this.To = $To
        $this.EdgeType = $EdgeType
        $this.Direction = $Direction
        $this.RiskWeight = $RiskWeight
        $this.Properties = @{}
    }
}

class GraphNode {
    [string]$Name
    [string]$NodeType
    [string]$DisplayName
    [hashtable]$Properties
    [string]$RiskLevel
    [int]$RiskScore
    
    GraphNode([string]$Name, [string]$NodeType, [string]$DisplayName) {
        $this.Name = $Name
        $this.NodeType = $NodeType
        $this.DisplayName = $DisplayName
        $this.Properties = @{}
        $this.RiskLevel = "Low"
        $this.RiskScore = 0
    }
    
    [void]CalculateRiskScore([hashtable]$RiskConfig, [array]$Edges) {
        $score = 0
        
        # Base risk from node type and properties
        if ($this.Properties.ContainsKey("isPrivileged") -and $this.Properties["isPrivileged"]) {
            $score += $RiskConfig.riskFactors.privilegedGroupMembership
        }
        
        if ($this.Properties.ContainsKey("isServiceAccount") -and $this.Properties["isServiceAccount"]) {
            $score += $RiskConfig.riskFactors.serviceAccountUsage
        }
        
        # Risk from relationships
        $relationshipCount = 0
        foreach ($edge in $Edges) {
            if ($edge.From -eq $this.Name -or $edge.To -eq $this.Name) {
                $score += $edge.RiskWeight
                $relationshipCount++
            }
        }
        
        # Multiple relationships increase risk
        if ($relationshipCount -gt 3) {
            $score += $RiskConfig.riskFactors.multipleRoleAssignment
        }
        
        $this.RiskScore = $score
        
        # Determine risk level
        if ($score -ge 15) {
            $this.RiskLevel = "High"
        } elseif ($score -ge 8) {
            $this.RiskLevel = "Medium"
        } else {
            $this.RiskLevel = "Low"
        }
    }
}

class EnhancedGraphDataProcessor {
    [GraphConfiguration]$Config
    [string]$OutputFolder
    [hashtable]$DataCache
    [array]$Nodes
    [array]$Edges
    
    EnhancedGraphDataProcessor([string]$ConfigPath, [string]$OutputFolder) {
        $this.Config = [GraphConfiguration]::new($ConfigPath)
        $this.OutputFolder = $OutputFolder
        $this.DataCache = @{}
        $this.Nodes = @()
        $this.Edges = @()
    }
    
    [void]LoadDataFiles([string]$Timestamp = "") {
        Write-Host "Loading data files..." -ForegroundColor Cyan
        
        # Load CSV files
        $csvFiles = @(
            @{Name="adUsers"; Pattern="ad-users-*.csv"},
            @{Name="adGroups"; Pattern="ad-groups-*.csv"},
            @{Name="gpoData"; Pattern="gpo-data-*.csv"},
            @{Name="ouData"; Pattern="ou-data-*.csv"},
            @{Name="serviceAccounts"; Pattern="service-accounts-*.csv"},
            @{Name="applications"; Pattern="applications-*.csv"},
            @{Name="domainTrusts"; Pattern="domain-trusts-*.csv"}
        )
        
        foreach ($file in $csvFiles) {
            $path = $this.FindDataFile($file.Pattern, $Timestamp)
            if ($path) {
                $this.DataCache[$file.Name] = Import-Csv $path
                Write-Host "Loaded $($file.Name): $path" -ForegroundColor Green
            }
        }
        
        # Load JSON files
        $jsonFiles = @(
            @{Name="entraRoles"; Pattern="entra-role-assignments-*.json"},
            @{Name="servicePrincipals"; Pattern="service-principals-*.json"},
            @{Name="oauthScopes"; Pattern="oauth-scopes-*.json"}
        )
        
        foreach ($file in $jsonFiles) {
            $path = $this.FindDataFile($file.Pattern, $Timestamp)
            if ($path) {
                $this.DataCache[$file.Name] = Get-Content $path | ConvertFrom-Json
                Write-Host "Loaded $($file.Name): $path" -ForegroundColor Green
            }
        }
        
        # Load risk findings
        $riskPath = $this.FindDataFile("risk-findings-*.csv", $Timestamp)
        if ($riskPath) {
            $this.DataCache["riskFindings"] = Import-Csv $riskPath
            Write-Host "Loaded risk findings: $riskPath" -ForegroundColor Green
        }
    }
    
    [string]FindDataFile([string]$Pattern, [string]$Timestamp) {
        if ($Timestamp) {
            $specificFile = Join-Path $this.OutputFolder ($Pattern -replace '\*', $Timestamp)
            if (Test-Path $specificFile) {
                return $specificFile
            }
        }
        
        $latestFile = Get-ChildItem -Path $this.OutputFolder -Filter $Pattern -File -ErrorAction SilentlyContinue |
                     Sort-Object LastWriteTime -Descending | Select-Object -First 1
        
        return if ($latestFile) { $latestFile.FullName } else { $null }
    }
    
    [void]BuildNodes() {
        Write-Host "Building nodes..." -ForegroundColor Cyan
        
        # Build user nodes
        if ($this.DataCache.ContainsKey("adUsers")) {
            foreach ($user in $this.DataCache["adUsers"]) {
                $node = [GraphNode]::new($user.SamAccountName, "user", $user.DisplayName)
                $node.Properties["email"] = $user.UserPrincipalName
                $node.Properties["enabled"] = $user.Enabled -eq "True"
                $node.Properties["lastLogon"] = $user.LastLogonDate
                
                # Check if service account
                $isServiceAccount = $false
                foreach ($pattern in $this.Config.PrivilegedConfig.serviceAccountPatterns) {
                    if ($user.SamAccountName -match $pattern) {
                        $isServiceAccount = $true
                        break
                    }
                }
                $node.Properties["isServiceAccount"] = $isServiceAccount
                
                $this.Nodes += $node
            }
        }
        
        # Build group nodes
        if ($this.DataCache.ContainsKey("adGroups")) {
            foreach ($group in $this.DataCache["adGroups"]) {
                $node = [GraphNode]::new($group.SamAccountName, "group", $group.Name)
                $node.Properties["description"] = $group.Description
                $node.Properties["groupType"] = $group.GroupType
                
                # Check if privileged
                $privilegedGroups = $this.Config.GetPrivilegedGroups()
                $node.Properties["isPrivileged"] = $privilegedGroups -contains $group.SamAccountName
                
                $this.Nodes += $node
            }
        }
        
        # Build role nodes (from Entra data)
        if ($this.DataCache.ContainsKey("entraRoles")) {
            foreach ($role in $this.DataCache["entraRoles"]) {
                $node = [GraphNode]::new($role.Role, "role", $role.Role)
                $node.Properties["memberCount"] = $role.MemberCount
                
                # Check if privileged
                $privilegedRoles = $this.Config.GetPrivilegedRoles()
                $node.Properties["isPrivileged"] = $privilegedRoles -contains $role.Role
                
                $this.Nodes += $node
            }
        }
        
        Write-Host "Built $($this.Nodes.Count) nodes" -ForegroundColor Green
    }
    
    [void]BuildEdges() {
        Write-Host "Building edges..." -ForegroundColor Cyan
        
        # Build AD membership edges
        $this.BuildADMembershipEdges()
        
        # Build Entra role assignment edges
        $this.BuildEntraRoleEdges()
        
        # Build GPO edges (if data available)
        $this.BuildGPOEdges()
        
        # Build service account edges (if data available)
        $this.BuildServiceAccountEdges()
        
        Write-Host "Built $($this.Edges.Count) edges" -ForegroundColor Green
    }
    
    [void]BuildADMembershipEdges() {
        if (-not $this.DataCache.ContainsKey("adGroups")) { return }
        
        $privilegedGroups = $this.Config.GetPrivilegedGroups()
        
        foreach ($group in $this.DataCache["adGroups"]) {
            if ($privilegedGroups -contains $group.SamAccountName) {
                try {
                    $members = Get-ADGroupMember -Identity $group.SamAccountName -Recursive -ErrorAction SilentlyContinue
                    foreach ($member in $members) {
                        $memberName = if ($member.SamAccountName) { $member.SamAccountName } else { $member.Name }
                        if ($memberName) {
                            $edge = [GraphEdge]::new($memberName, "GROUP::$($group.SamAccountName)", "memberOf", "user -> group", 5)
                            $edge.Properties["recursive"] = $true
                            $this.Edges += $edge
                        }
                    }
                } catch {
                    Write-Warning "Could not get members for group $($group.SamAccountName): $($_.Exception.Message)"
                }
            }
        }
    }
    
    [void]BuildEntraRoleEdges() {
        if (-not $this.DataCache.ContainsKey("entraRoles")) { return }
        
        $privilegedRoles = $this.Config.GetPrivilegedRoles()
        
        foreach ($role in $this.DataCache["entraRoles"]) {
            if ($privilegedRoles -contains $role.Role -and $role.MemberCount -gt 0) {
                foreach ($member in $role.Members) {
                    $memberName = if ($member.UserPrincipalName) { $member.UserPrincipalName } else { $member.DisplayName }
                    if ($memberName) {
                        $edge = [GraphEdge]::new("ROLE::$($role.Role)", $memberName, "assignedTo", "role -> principal", 8)
                        $edge.Properties["assignmentType"] = $member.AssignmentType
                        $this.Edges += $edge
                    }
                }
            }
        }
    }
    
    [void]BuildGPOEdges() {
        # Placeholder for GPO edges - would require GPO data
        if ($this.DataCache.ContainsKey("gpoData") -and $this.DataCache.ContainsKey("ouData")) {
            Write-Host "GPO edge building not yet implemented" -ForegroundColor Yellow
        }
    }
    
    [void]BuildServiceAccountEdges() {
        # Placeholder for service account edges - would require application data
        if ($this.DataCache.ContainsKey("serviceAccounts") -and $this.DataCache.ContainsKey("applications")) {
            Write-Host "Service account edge building not yet implemented" -ForegroundColor Yellow
        }
    }
    
    [void]CalculateRiskScores() {
        Write-Host "Calculating risk scores..." -ForegroundColor Cyan
        
        foreach ($node in $this.Nodes) {
            $node.CalculateRiskScore($this.Config.PrivilegedConfig.riskScoring, $this.Edges)
        }
        
        Write-Host "Risk scores calculated" -ForegroundColor Green
    }
    
    [hashtable]GetGraphData() {
        return @{
            Nodes = $this.Nodes
            Edges = $this.Edges
            Config = $this.Config
            DataCache = $this.DataCache
        }
    }
}
