<#
.SYNOPSIS
    Data export pipeline for AD security monitoring - CSV and database export

.DESCRIPTION
    Transforms PowerShell assessment data into structured formats for:
    - Organized CSV export with standardized naming
    - Database import (SQL Server or PostgreSQL)
    - Power BI-ready data model
    - Historical data archival

    Supports both daily checks and weekly full assessments.

.PARAMETER SourceFolder
    Path to folder containing assessment results (default: ./Monitoring)

.PARAMETER OutputFolder
    Base path for exported data (default: ./ExportedData)

.PARAMETER ExportType
    What to export: CSV, Database, PowerBI, All (default: All)

.PARAMETER DatabaseServer
    Database server name or IP (for database export)

.PARAMETER DatabaseName
    Database name (default: ADSecurityMonitoring)

.PARAMETER DatabaseType
    Database engine: SQLServer, PostgreSQL (default: SQLServer)

.PARAMETER UseWindowsAuth
    Use Windows authentication instead of SQL auth (default: true)

.PARAMETER SQLCredential
    PSCredential object for SQL authentication (if not using Windows auth)

.PARAMETER RetentionDays
    Number of days to retain data in database (default: 365)

.PARAMETER IncludeCrowdStrike
    Include CrowdStrike data in export (default: true)

.EXAMPLE
    .\Invoke-DataExport.ps1 -ExportType CSV
    Export to CSV only

.EXAMPLE
    .\Invoke-DataExport.ps1 -ExportType Database -DatabaseServer "sql01" -DatabaseName "ADSecurity"
    Export to SQL Server database

.EXAMPLE
    .\Invoke-DataExport.ps1 -ExportType All -IncludeCrowdStrike
    Full export including CrowdStrike data
#>

[CmdletBinding()]
param(
    [string]$SourceFolder = "$PSScriptRoot",
    [string]$OutputFolder = "$PSScriptRoot\ExportedData",
    [ValidateSet("CSV", "Database", "PowerBI", "All")]
    [string]$ExportType = "All",
    [string]$DatabaseServer = "",
    [string]$DatabaseName = "ADSecurityMonitoring",
    [ValidateSet("SQLServer", "PostgreSQL")]
    [string]$DatabaseType = "SQLServer",
    [switch]$UseWindowsAuth = $true,
    [System.Management.Automation.PSCredential]$SQLCredential,
    [int]$RetentionDays = 365,
    [switch]$IncludeCrowdStrike
)

# Ensure output folders exist
$csvRoot = Join-Path $OutputFolder "CSV"
$dbStaging = Join-Path $OutputFolder "DatabaseStaging"
$powerBIFolder = Join-Path $OutputFolder "PowerBI"

if (-not (Test-Path $csvRoot)) { New-Item -Path $csvRoot -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $dbStaging)) { New-Item -Path $dbStaging -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $powerBIFolder)) { New-Item -Path $powerBIFolder -ItemType Directory -Force | Out-Null }

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dateStamp = Get-Date -Format "yyyy-MM-dd"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Data Export Pipeline" -ForegroundColor Cyan
Write-Host "Export Type: $ExportType" -ForegroundColor Cyan
Write-Host "Date: $dateStamp" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================
# HELPER FUNCTIONS
# ============================================

function Get-LatestFiles {
    param(
        [string]$Folder,
        [string]$Pattern,
        [int]$Count = 1
    )

    if (-not (Test-Path $Folder)) {
        return @()
    }

    Get-ChildItem -Path $Folder -Filter $Pattern -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $Count
}

function Import-LatestFile {
    param(
        [string]$Folder,
        [string]$Pattern
    )

    $file = Get-LatestFiles -Folder $Folder -Pattern $Pattern -Count 1
    if ($file) {
        if ($file.Extension -eq ".csv") {
            return Import-Csv $file.FullName
        }
        elseif ($file.Extension -eq ".json") {
            return Get-Content $file.FullName | ConvertFrom-Json
        }
    }
    return @()
}

function Invoke-SQLQuery {
    param(
        [string]$Server,
        [string]$Database,
        [string]$Query,
        [switch]$UseWindowsAuthentication,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionString = if ($UseWindowsAuthentication) {
        "Server=$Server;Database=$Database;Integrated Security=True;TrustServerCertificate=True;"
    }
    else {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        "Server=$Server;Database=$Database;User ID=$username;Password=$password;TrustServerCertificate=True;"
    }

    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        $command = $connection.CreateCommand()
        $command.CommandText = $Query
        $command.ExecuteNonQuery() | Out-Null

        $connection.Close()
        return $true
    }
    catch {
        Write-Warning "SQL query failed: $_"
        return $false
    }
}

function Import-CSVToDatabase {
    param(
        [string]$Server,
        [string]$Database,
        [string]$TableName,
        [string]$CSVPath,
        [switch]$UseWindowsAuthentication,
        [System.Management.Automation.PSCredential]$Credential
    )

    if (-not (Test-Path $CSVPath)) {
        Write-Warning "CSV file not found: $CSVPath"
        return $false
    }

    $data = Import-Csv $CSVPath
    if ($data.Count -eq 0) {
        Write-Host "  [SKIP] No data in $CSVPath" -ForegroundColor Yellow
        return $true
    }

    # Build INSERT statement
    $columns = $data[0].PSObject.Properties.Name
    $insertBase = "INSERT INTO $TableName ($($columns -join ', ')) VALUES "

    $connectionString = if ($UseWindowsAuthentication) {
        "Server=$Server;Database=$Database;Integrated Security=True;TrustServerCertificate=True;"
    }
    else {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        "Server=$Server;Database=$Database;User ID=$username;Password=$password;TrustServerCertificate=True;"
    }

    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()
        $transaction = $connection.BeginTransaction()

        $batchSize = 100
        $batchCount = 0

        for ($i = 0; $i -lt $data.Count; $i += $batchSize) {
            $batch = $data[$i..([Math]::Min($i + $batchSize - 1, $data.Count - 1))]
            $valuesList = @()

            foreach ($row in $batch) {
                $values = @()
                foreach ($col in $columns) {
                    $val = $row.$col
                    if ($null -eq $val) {
                        $values.Add("NULL")
                    }
                    else {
                        $escaped = $val.ToString().Replace("'", "''")
                        $values.Add("'${escaped}'")
                    }
                }
                $valuesList.Add("($($values -join ', '))")
            }

            $insertSQL = "$insertBase $($valuesList -join ', ')"

            $command = $connection.CreateCommand()
            $command.CommandText = $insertSQL
            $command.Transaction = $transaction
            $command.ExecuteNonQuery() | Out-Null

            $batchCount++
        }

        $transaction.Commit()
        $connection.Close()

        Write-Host "  [OK] Imported $($data.Count) rows to $TableName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Failed to import CSV to database: $_"
        return $false
    }
}

# ============================================
# CSV EXPORT
# ============================================

if ($ExportType -in @("CSV", "All")) {
    Write-Host "[1/4] Exporting to CSV..." -ForegroundColor Cyan

    # Find and organize daily checks
    $dailyCheckFiles = Get-LatestFiles -Folder $SourceFolder -Pattern "daily-checks-*.json" -Count 30
    $dailyCheckCSV = Join-Path $csvRoot "daily-checks-history.csv"

    $allDailyChecks = @()
    foreach ($file in $dailyCheckFiles) {
        $data = Get-Content $file.FullName | ConvertFrom-Json
        $allDailyChecks += $data
    }

    if ($allDailyChecks.Count -gt 0) {
        $allDailyChecks | Export-Csv -Path $dailyCheckCSV -NoTypeInformation -Encoding UTF8 -Append
        Write-Host "  [OK] Daily checks: $($allDailyChecks.Count) findings exported" -ForegroundColor Green
    }

    # Find and organize CrowdStrike data
    if ($IncludeCrowdStrike) {
        $csFiles = @(
            @{ Pattern = "detections-*.csv"; Target = "crowdstrike-detections.csv" },
            @{ Pattern = "devices-*.csv"; Target = "crowdstrike-devices.csv" },
            @{ Pattern = "vulnerabilities-*.csv"; Target = "crowdstrike-vulnerabilities.csv" },
            @{ Pattern = "identity-alerts-*.csv"; Target = "crowdstrike-identity-alerts.csv" },
            @{ Pattern = "cves-summary-*.csv"; Target = "crowdstrike-cves.csv" }
        )

        foreach ($csFile in $csFiles) {
            $sourceFiles = Get-LatestFiles -Folder (Join-Path $SourceFolder "CrowdStrike") -Pattern $csFile.Pattern -Count 30
            $targetPath = Join-Path $csvRoot $csFile.Target

            $allData = @()
            foreach ($file in $sourceFiles) {
                $allData += Import-Csv $file.FullName
            }

            if ($allData.Count -gt 0) {
                $allData | Export-Csv -Path $targetPath -NoTypeInformation -Encoding UTF8 -Append
                Write-Host "  [OK] CrowdStrike $($csFile.Target): $($allData.Count) items" -ForegroundColor Green
            }
        }
    }

    # Find and organize weekly assessments
    $weeklyFiles = Get-LatestFiles -Folder $SourceFolder -Pattern "ad-users-*.csv" -Count 20
    $weeklyCSV = Join-Path $csvRoot "weekly-assessments-history"

    if ($weeklyFiles.Count -gt 0) {
        foreach ($file in $weeklyFiles) {
            $targetPath = "${weeklyCSV}-$($file.BaseName -replace 'ad-users-', '').csv"
            Copy-Item $file.FullName -Destination $targetPath -Force
        }
        Write-Host "  [OK] Weekly assessments: $($weeklyFiles.Count) snapshots" -ForegroundColor Green
    }

    # Create master index
    $index = [PSCustomObject]@{
        ExportTimestamp = (Get-Date).ToString("u")
        CSVFolder = $csvRoot
        DailyCheckFiles = $dailyCheckFiles.Count
        WeeklyAssessmentFiles = $weeklyFiles.Count
        TotalDailyFindings = $allDailyChecks.Count
    }

    $indexPath = Join-Path $csvRoot "export-index-$timestamp.json"
    $index | ConvertTo-Json | Out-File -FilePath $indexPath -Encoding UTF8
    Write-Host "  [OK] Export index created: $indexPath" -ForegroundColor Green
}

# ============================================
# DATABASE EXPORT
# ============================================

if ($ExportType -in @("Database", "All") -and $DatabaseServer) {
    Write-Host "`n[2/4] Exporting to database..." -ForegroundColor Cyan

    Write-Host "  Server: $DatabaseServer" -ForegroundColor Gray
    Write-Host "  Database: $DatabaseName" -ForegroundColor Gray
    Write-Host "  Type: $DatabaseType" -ForegroundColor Gray

    # Create database if not exists
    $createDBSQL = "IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = '$DatabaseName') CREATE DATABASE [$DatabaseName];"
    $masterDB = if ($DatabaseType -eq "SQLServer") { "master" } else { "postgres" }

    Write-Host "  [*] Creating database if not exists..." -ForegroundColor Yellow
    Invoke-SQLQuery -Server $DatabaseServer -Database $masterDB -Query $createDBSQL `
        -UseWindowsAuthentication:$UseWindowsAuth -Credential $SQLCredential | Out-Null

    # Create tables
    Write-Host "  [*] Creating tables..." -ForegroundColor Yellow

    $createTablesSQL = @"
-- Daily Security Findings
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'DailyFindings')
CREATE TABLE DailyFindings (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    FindingId NVARCHAR(50),
    Title NVARCHAR(500),
    Severity NVARCHAR(20),
    Category NVARCHAR(100),
    Description NVARCHAR(MAX),
    Remediation NVARCHAR(MAX),
    MITRETechnique NVARCHAR(50),
    Evidence NVARCHAR(MAX),
    CheckedAt DATETIME2,
    Status NVARCHAR(20),
    ExportedAt DATETIME2 DEFAULT GETUTCDATE()
);

-- CrowdStrike Detections
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'CrowdStrikeDetections')
CREATE TABLE CrowdStrikeDetections (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    DetectionId NVARCHAR(100),
    DeviceId NVARCHAR(100),
    DeviceName NVARCHAR(200),
    ADComputerFound BIT,
    Severity INT,
    MaxSeverity NVARCHAR(50),
    Status NVARCHAR(50),
    CreatedTime DATETIME2,
    Tactic NVARCHAR(100),
    Technique NVARCHAR(100),
    Username NVARCHAR(200),
    ADUserFound BIT,
    CommandLine NVARCHAR(MAX),
    FilePath NVARCHAR(MAX),
    FileName NVARCHAR(200),
    MD5Hash NVARCHAR(100),
    SHA256Hash NVARCHAR(100),
    ExternalIpAddress NVARCHAR(50),
    LocalIpAddress NVARCHAR(50),
    CorrelatedWithAD BIT,
    ExportedAt DATETIME2 DEFAULT GETUTCDATE()
);

-- CrowdStrike Devices
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'CrowdStrikeDevices')
CREATE TABLE CrowdStrikeDevices (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    DeviceId NVARCHAR(100),
    Hostname NVARCHAR(200),
    ADComputerFound BIT,
    OS NVARCHAR(200),
    PlatformName NVARCHAR(100),
    SensorVersion NVARCHAR(50),
    SensorStatus NVARCHAR(50),
    LastSeen DATETIME2,
    ExternalIP NVARCHAR(50),
    LocalIP NVARCHAR(50),
    MacAddress NVARCHAR(50),
    ReducedFunctionalityMode BIT,
    CorrelatedWithAD BIT,
    ExportedAt DATETIME2 DEFAULT GETUTCDATE()
);

-- CrowdStrike Vulnerabilities
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'CrowdStrikeVulnerabilities')
CREATE TABLE CrowdStrikeVulnerabilities (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    CVEId NVARCHAR(50),
    Hostname NVARCHAR(200),
    AIS NVARCHAR(100),
    CISACategories NVARCHAR(MAX),
    ExploitStatus NVARCHAR(100),
    Severity NVARCHAR(50),
    Status NVARCHAR(50),
    CreatedDate DATETIME2,
    ExportedAt DATETIME2 DEFAULT GETUTCDATE()
);

-- Collection Summary
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'CollectionSummary')
CREATE TABLE CollectionSummary (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    CollectionTimestamp DATETIME2,
    CollectionType NVARCHAR(50),
    TotalDetections INT,
    ADDetectionCorrelation INT,
    TotalDevices INT,
    ADDeviceCorrelation INT,
    TotalVulnerabilities INT,
    UniqueCVEs INT,
    CISAExploitedCVEs INT,
    IdentityAlerts INT,
    ADIdentityAlertCorrelation INT,
    CriticalDetections INT,
    HighDetections INT,
    ExportedAt DATETIME2 DEFAULT GETUTCDATE()
);

-- Cleanup old data
DELETE FROM DailyFindings WHERE ExportedAt < DATEADD(day, -$RetentionDays, GETUTCDATE());
DELETE FROM CrowdStrikeDetections WHERE ExportedAt < DATEADD(day, -$RetentionDays, GETUTCDATE());
DELETE FROM CrowdStrikeDevices WHERE ExportedAt < DATEADD(day, -$RetentionDays, GETUTCDATE());
DELETE FROM CrowdStrikeVulnerabilities WHERE ExportedAt < DATEADD(day, -$RetentionDays, GETUTCDATE());
DELETE FROM CollectionSummary WHERE ExportedAt < DATEADD(day, -$RetentionDays, GETUTCDATE());
"@

    Invoke-SQLQuery -Server $DatabaseServer -Database $DatabaseName -Query $createTablesSQL `
        -UseWindowsAuthentication:$UseWindowsAuth -Credential $SQLCredential | Out-Null

    Write-Host "  [OK] Tables created/verified" -ForegroundColor Green

    # Import CSV data to database
    Write-Host "  [*] Importing data to tables..." -ForegroundColor Yellow

    # Import daily findings
    $dailyCSV = Join-Path $csvRoot "daily-checks-history.csv"
    if (Test-Path $dailyCSV) {
        Import-CSVToDatabase -Server $DatabaseServer -Database $DatabaseName `
            -TableName "DailyFindings" -CSVPath $dailyCSV `
            -UseWindowsAuthentication:$UseWindowsAuth -Credential $SQLCredential
    }

    # Import CrowdStrike detections
    $csDetections = Join-Path $csvRoot "crowdstrike-detections.csv"
    if (Test-Path $csDetections) {
        Import-CSVToDatabase -Server $DatabaseServer -Database $DatabaseName `
            -TableName "CrowdStrikeDetections" -CSVPath $csDetections `
            -UseWindowsAuthentication:$UseWindowsAuth -Credential $SQLCredential
    }

    # Import CrowdStrike devices
    $csDevices = Join-Path $csvRoot "crowdstrike-devices.csv"
    if (Test-Path $csDevices) {
        Import-CSVToDatabase -Server $DatabaseServer -Database $DatabaseName `
            -TableName "CrowdStrikeDevices" -CSVPath $csDevices `
            -UseWindowsAuthentication:$UseWindowsAuth -Credential $SQLCredential
    }

    # Import CrowdStrike vulnerabilities
    $csVulns = Join-Path $csvRoot "crowdstrike-vulnerabilities.csv"
    if (Test-Path $csVulns) {
        Import-CSVToDatabase -Server $DatabaseServer -Database $DatabaseName `
            -TableName "CrowdStrikeVulnerabilities" -CSVPath $csVulns `
            -UseWindowsAuthentication:$UseWindowsAuth -Credential $SQLCredential
    }

    Write-Host "  [OK] Database import complete" -ForegroundColor Green
}

# ============================================
# POWER BI EXPORT
# ============================================

if ($ExportType -in @("PowerBI", "All")) {
    Write-Host "`n[3/4] Preparing Power BI data..." -ForegroundColor Cyan

    # Create consolidated dataset for Power BI
    $powerBI_Data = @()

    # Add daily findings
    $dailyCSV = Join-Path $csvRoot "daily-checks-history.csv"
    if (Test-Path $dailyCSV) {
        $dailyData = Import-Csv $dailyCSV
        foreach ($finding in $dailyData) {
            $powerBI_Data += [PSCustomObject]@{
                DataSource = "AD-DailyCheck"
                Timestamp = $finding.CheckedAt
                Severity = $finding.Severity
                Category = $finding.Category
                Title = $finding.Title
                Description = $finding.Description
                MITRETechnique = $finding.MITRETechnique
                Remediation = $finding.Remediation
                SourceSystem = "AD Security Monitoring"
            }
        }
    }

    # Add CrowdStrike detections
    $csDetections = Join-Path $csvRoot "crowdstrike-detections.csv"
    if (Test-Path $csDetections) {
        $csData = Import-Csv $csDetections
        foreach ($detection in $csData) {
            $powerBI_Data += [PSCustomObject]@{
                DataSource = "CrowdStrike-Detection"
                Timestamp = $detection.CreatedTime
                Severity = $detection.MaxSeverity
                Category = "CrowdStrike"
                Title = "Detection: $($detection.Technique)"
                Description = "Device: $($detection.DeviceName), User: $($detection.Username)"
                MITRETechnique = $detection.Technique
                Remediation = "Investigate in CrowdStrike console"
                SourceSystem = "CrowdStrike Falcon"
            }
        }
    }

    # Create summary tables for Power BI
    $powerBI_Summary = @()

    if ($powerBI_Data.Count -gt 0) {
        $grouped = $powerBI_Data | Group-Object Severity
        foreach ($group in $grouped) {
            $powerBI_Summary += [PSCustomObject]@{
                Severity = $group.Name
                Count = $group.Count
                Percentage = [math]::Round(($group.Count / $powerBI_Data.Count) * 100, 2)
                CalculatedAt = (Get-Date).ToString("u")
            }
        }
    }

    # Export to Power BI folder
    $powerBI_CSV = Join-Path $powerBIFolder "consolidated-data.csv"
    $powerBI_Data | Export-Csv -Path $powerBI_CSV -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] Consolidated data: $($powerBI_Data.Count) rows" -ForegroundColor Green

    $powerBI_Summary_CSV = Join-Path $powerBIFolder "severity-summary.csv"
    $powerBI_Summary | Export-Csv -Path $powerBI_Summary_CSV -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] Severity summary: $($powerBI_Summary.Count) rows" -ForegroundColor Green

    # Create Power BI data source configuration
    $pbiConfig = @{
        DataSources = @(
            @{
                Name = "ConsolidatedData"
                Path = $powerBI_CSV
                Type = "CSV"
                Description = "All security findings and detections"
            },
            @{
                Name = "SeveritySummary"
                Path = $powerBI_Summary_CSV
                Type = "CSV"
                Description = "Aggregated severity counts"
            }
        )
        RefreshSchedule = "Daily at 8:00 AM"
        LastUpdated = (Get-Date).ToString("u")
    }

    $configPath = Join-Path $powerBIFolder "powerbi-config.json"
    $pbiConfig | ConvertTo-Json -Depth 4 | Out-File -FilePath $configPath -Encoding UTF8
    Write-Host "  [OK] Power BI config: $configPath" -ForegroundColor Green
}

# ============================================
# FINAL SUMMARY
# ============================================

Write-Host "`n[4/4] Generating export summary..." -ForegroundColor Cyan

$exportSummary = [PSCustomObject]@{
    ExportTimestamp = (Get-Date).ToString("u")
    ExportType = $ExportType
    OutputFolder = $OutputFolder
    CSVFiles = (Get-ChildItem $csvRoot -File -ErrorAction SilentlyContinue).Count
    DatabaseServer = if ($DatabaseServer) { $DatabaseServer } else { "N/A" }
    DatabaseName = if ($ExportType -in @("Database", "All")) { $DatabaseName } else { "N/A" }
    PowerBIFiles = (Get-ChildItem $powerBIFolder -File -ErrorAction SilentlyContinue).Count
}

$summaryPath = Join-Path $OutputFolder "export-summary-$timestamp.json"
$exportSummary | ConvertTo-Json | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "EXPORT SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Export Type: $ExportType" -ForegroundColor White
Write-Host "CSV Files: $($exportSummary.CSVFiles)" -ForegroundColor White
Write-Host "Database: $($exportSummary.DatabaseName)" -ForegroundColor White
Write-Host "Power BI Files: $($exportSummary.PowerBIFiles)" -ForegroundColor White
Write-Host "`nOutput Location: $OutputFolder" -ForegroundColor Yellow

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Data Export Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

return $exportSummary
