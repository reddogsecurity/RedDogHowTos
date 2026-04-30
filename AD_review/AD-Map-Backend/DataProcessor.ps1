# AD Map Data Processor
# Converts PowerShell collection output to API-ready JSON format

param(
    [string]$InputPath = "C:\Users\reddog\Projects\Projects\AD_review\Data",
    [string]$OutputPath = "C:\Users\reddog\Projects\Projects\AD_review\AD-Map-Backend\Data",
    [string]$ApiUrl = "https://localhost:7001/api"
)

function Convert-ADDataToApiFormat {
    param(
        [string]$InputPath,
        [string]$OutputPath
    )
    
    Write-Host "Converting AD data to API format..." -ForegroundColor Green
    
    # Ensure output directory exists
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force
    }
    
    try {
        # Process AD Users
        $userFiles = Get-ChildItem -Path $InputPath -Filter "ad-users-*.csv" | Sort-Object LastWriteTime -Descending
        if ($userFiles) {
            $users = Import-Csv $userFiles[0].FullName
            $apiUsers = $users | ForEach-Object {
                @{
                    SamAccountName = $_.SamAccountName
                    DisplayName = $_.DisplayName
                    UserPrincipalName = $_.UserPrincipalName
                    IsPrivileged = [bool]$_.IsPrivileged
                    RiskScore = [int]$_.RiskScore
                    MfaEnabled = [bool]$_.MfaEnabled
                    LastLogon = if ($_.LastLogonDate) { [DateTime]$_.LastLogonDate } else { $null }
                    PasswordNeverExpires = [bool]$_.PasswordNeverExpires
                }
            }
            $apiUsers | ConvertTo-Json -Depth 3 | Out-File -FilePath "$OutputPath\ad-users.json" -Encoding UTF8
            Write-Host "Processed $($apiUsers.Count) users" -ForegroundColor Green
        }
        
        # Process AD Groups
        $groupFiles = Get-ChildItem -Path $InputPath -Filter "ad-groups-*.csv" | Sort-Object LastWriteTime -Descending
        if ($groupFiles) {
            $groups = Import-Csv $groupFiles[0].FullName
            $apiGroups = $groups | ForEach-Object {
                @{
                    SamAccountName = $_.SamAccountName
                    Name = $_.Name
                    Scope = $_.GroupScope
                    MemberCount = [int]$_.MemberCount
                    IsPrivileged = [bool]$_.IsPrivileged
                }
            }
            $apiGroups | ConvertTo-Json -Depth 3 | Out-File -FilePath "$OutputPath\ad-groups.json" -Encoding UTF8
            Write-Host "Processed $($apiGroups.Count) groups" -ForegroundColor Green
        }
        
        # Process AD Computers
        $computerFiles = Get-ChildItem -Path $InputPath -Filter "ad-computers-*.csv" | Sort-Object LastWriteTime -Descending
        if ($computerFiles) {
            $computers = Import-Csv $computerFiles[0].FullName
            $apiComputers = $computers | ForEach-Object {
                @{
                    Name = $_.Name
                    OperatingSystem = $_.OperatingSystem
                    DelegationType = $_.TrustedForDelegation
                    IsDomainController = [bool]$_.IsDomainController
                }
            }
            $apiComputers | ConvertTo-Json -Depth 3 | Out-File -FilePath "$OutputPath\ad-computers.json" -Encoding UTF8
            Write-Host "Processed $($apiComputers.Count) computers" -ForegroundColor Green
        }
        
        # Process Risk Analysis
        $riskFiles = Get-ChildItem -Path $InputPath -Filter "risk-findings-*.csv" | Sort-Object LastWriteTime -Descending
        if ($riskFiles) {
            $riskFindings = Import-Csv $riskFiles[0].FullName
            $apiRiskAnalysis = @{
                TotalUsers = ($users | Measure-Object).Count
                HighRiskUsers = ($users | Where-Object { [int]$_.RiskScore -gt 60 } | Measure-Object).Count
                PrivilegedUsers = ($users | Where-Object { [bool]$_.IsPrivileged } | Measure-Object).Count
                UsersWithoutMfa = ($users | Where-Object { -not [bool]$_.MfaEnabled } | Measure-Object).Count
                Findings = $riskFindings | ForEach-Object {
                    @{
                        Id = $_.Id
                        Title = $_.Title
                        Description = $_.Description
                        Severity = $_.Severity
                        RiskScore = [int]$_.RiskScore
                        MitreTechnique = $_.MitreTechnique
                    }
                }
            }
            $apiRiskAnalysis | ConvertTo-Json -Depth 3 | Out-File -FilePath "$OutputPath\risk-analysis.json" -Encoding UTF8
            Write-Host "Processed risk analysis data" -ForegroundColor Green
        }
        
        # Create network graph data
        Create-NetworkGraphData -Users $apiUsers -Groups $apiGroups -Computers $apiComputers -OutputPath $OutputPath
        
        Write-Host "Data conversion completed successfully!" -ForegroundColor Green
        
    } catch {
        Write-Error "Error converting data: $($_.Exception.Message)"
        throw
    }
}

function Create-NetworkGraphData {
    param(
        [array]$Users,
        [array]$Groups,
        [array]$Computers,
        [string]$OutputPath
    )
    
    Write-Host "Creating network graph data..." -ForegroundColor Green
    
    $nodes = @()
    $edges = @()
    
    # Add user nodes
    foreach ($user in $Users) {
        $nodes += @{
            id = "user-$($user.SamAccountName)"
            label = $user.DisplayName
            type = "user"
            data = $user
            privileged = $user.IsPrivileged
            riskScore = $user.RiskScore
            mfaEnabled = $user.MfaEnabled
        }
    }
    
    # Add group nodes
    foreach ($group in $Groups) {
        $nodes += @{
            id = "group-$($group.SamAccountName)"
            label = $group.Name
            type = "group"
            data = $group
            privileged = $group.IsPrivileged
            memberCount = $group.MemberCount
        }
    }
    
    # Add computer nodes
    foreach ($computer in $Computers) {
        $nodes += @{
            id = "computer-$($computer.Name)"
            label = $computer.Name
            type = "computer"
            data = $computer
            os = $computer.OperatingSystem
            delegation = $computer.DelegationType
        }
    }
    
    # Create edges (simplified - you'd need to process membership data)
    # This is a placeholder - you'd need to process the actual membership relationships
    
    $networkGraph = @{
        nodes = $nodes
        edges = $edges
    }
    
    $networkGraph | ConvertTo-Json -Depth 5 | Out-File -FilePath "$OutputPath\network-graph.json" -Encoding UTF8
    Write-Host "Network graph data created" -ForegroundColor Green
}

function Send-DataToApi {
    param(
        [string]$DataPath,
        [string]$ApiUrl
    )
    
    Write-Host "Sending data to API..." -ForegroundColor Green
    
    try {
        # Send users
        $usersJson = Get-Content "$DataPath\ad-users.json" -Raw
        Invoke-RestMethod -Uri "$ApiUrl/ad/users" -Method POST -Body $usersJson -ContentType "application/json"
        
        # Send groups
        $groupsJson = Get-Content "$DataPath\ad-groups.json" -Raw
        Invoke-RestMethod -Uri "$ApiUrl/ad/groups" -Method POST -Body $groupsJson -ContentType "application/json"
        
        # Send computers
        $computersJson = Get-Content "$DataPath\ad-computers.json" -Raw
        Invoke-RestMethod -Uri "$ApiUrl/ad/computers" -Method POST -Body $computersJson -ContentType "application/json"
        
        # Send risk analysis
        $riskJson = Get-Content "$DataPath\risk-analysis.json" -Raw
        Invoke-RestMethod -Uri "$ApiUrl/ad/risk-analysis" -Method POST -Body $riskJson -ContentType "application/json"
        
        Write-Host "Data sent to API successfully!" -ForegroundColor Green
        
    } catch {
        Write-Warning "API not available or error sending data: $($_.Exception.Message)"
        Write-Host "Data files are ready in: $DataPath" -ForegroundColor Yellow
    }
}

# Main execution
Write-Host "AD Map Data Processor" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan

# Convert data
Convert-ADDataToApiFormat -InputPath $InputPath -OutputPath $OutputPath

# Send to API (optional)
if ($ApiUrl) {
    Send-DataToApi -DataPath $OutputPath -ApiUrl $ApiUrl
}

Write-Host "Processing complete!" -ForegroundColor Green
