<#
.SYNOPSIS
    Compares two CSV files (Entra and AD users) and exports differences to separate CSV files.

.DESCRIPTION
    This script compares user data from Entra ID (Azure AD) and Active Directory CSV files
    to identify:
    - Users in Entra but not in AD (cloud-only accounts)
    - Users in AD but not in Entra (not synced)
    - Users in both with different attributes (sync discrepancies)
    - Summary statistics and counts

.PARAMETER EntraCSV
    Path to the Entra ID users CSV file (required)

.PARAMETER ADCSV
    Path to the Active Directory users CSV file (required)

.PARAMETER OutputFolder
    Path where the difference reports will be saved (defaults to current directory)

.PARAMETER MatchColumn
    Column name to use for matching users between the two files (defaults to 'UserPrincipalName')
    Common options: 'UserPrincipalName', 'SamAccountName', 'Mail', 'EmailAddress'

.PARAMETER CompareAttributes
    Switch to enable detailed attribute comparison for users that exist in both files

.PARAMETER IgnoreCase
    Switch to perform case-insensitive matching (default: true)

.EXAMPLE
    .\Compare-CSVUsers.ps1 -EntraCSV "entra-users-20240101.csv" -ADCSV "ad-users-20240101.csv"
    
.EXAMPLE
    .\Compare-CSVUsers.ps1 -EntraCSV "entra-users.csv" -ADCSV "ad-users.csv" -OutputFolder "C:\Reports" -CompareAttributes

.EXAMPLE
    .\Compare-CSVUsers.ps1 -EntraCSV "entra-users.csv" -ADCSV "ad-users.csv" -MatchColumn "Mail" -CompareAttributes

.NOTES
    Author: AI Risk Evaluator Team
    Version: 1.0
    Date: 2024-01-01
    
    The script will:
    1. Load both CSV files
    2. Match users based on the specified column
    3. Identify differences
    4. Export separate CSV files for:
       - Entra-only users
       - AD-only users
       - Attribute mismatches (if CompareAttributes is used)
    5. Generate a summary report
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Entra CSV file not found: $_"
        }
        $true
    })]
    [string]$EntraCSV,
    
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "AD CSV file not found: $_"
        }
        $true
    })]
    [string]$ADCSV,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFolder = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$MatchColumn = "UserPrincipalName",
    
    [Parameter(Mandatory=$false)]
    [switch]$CompareAttributes,
    
    [Parameter(Mandatory=$false)]
    [switch]$IgnoreCase = $true
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Generate timestamp for output files
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CSV User Comparison Tool" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    Write-Host "[*] Creating output folder: $OutputFolder" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

# Load CSV files
Write-Host "[*] Loading CSV files..." -ForegroundColor Yellow
try {
    Write-Host "    Loading Entra CSV: $EntraCSV" -ForegroundColor Gray
    $entraUsers = Import-Csv -Path $EntraCSV
    
    Write-Host "    Loading AD CSV: $ADCSV" -ForegroundColor Gray
    $adUsers = Import-Csv -Path $ADCSV
    
    Write-Host "    [OK] Loaded $($entraUsers.Count) Entra users and $($adUsers.Count) AD users" -ForegroundColor Green
} catch {
    Write-Error "Failed to load CSV files: $_"
    exit 1
}

# Validate that match column exists in both files
Write-Host "`n[*] Validating match column '$MatchColumn'..." -ForegroundColor Yellow
$entraColumns = $entraUsers[0].PSObject.Properties.Name
$adColumns = $adUsers[0].PSObject.Properties.Name

if ($MatchColumn -notin $entraColumns) {
    Write-Error "Match column '$MatchColumn' not found in Entra CSV. Available columns: $($entraColumns -join ', ')"
    exit 1
}

if ($MatchColumn -notin $adColumns) {
    Write-Error "Match column '$MatchColumn' not found in AD CSV. Available columns: $($adColumns -join ', ')"
    exit 1
}

Write-Host "    [OK] Match column validated" -ForegroundColor Green

# Create lookup dictionaries
Write-Host "`n[*] Building lookup dictionaries..." -ForegroundColor Yellow

$entraUsersByMatch = @{}
$adUsersByMatch = @{}

foreach ($user in $entraUsers) {
    if ($null -ne $user.$MatchColumn -and $user.$MatchColumn -ne "") {
        $key = if ($IgnoreCase) { 
            $user.$MatchColumn.ToString().ToLower() 
        } else { 
            $user.$MatchColumn.ToString() 
        }
        $entraUsersByMatch[$key] = $user
    }
}

foreach ($user in $adUsers) {
    if ($null -ne $user.$MatchColumn -and $user.$MatchColumn -ne "") {
        $key = if ($IgnoreCase) { 
            $user.$MatchColumn.ToString().ToLower() 
        } else { 
            $user.$MatchColumn.ToString() 
        }
        $adUsersByMatch[$key] = $user
    }
}

Write-Host "    [OK] Built lookup dictionaries ($($entraUsersByMatch.Count) Entra, $($adUsersByMatch.Count) AD)" -ForegroundColor Green

# Find differences
Write-Host "`n[*] Analyzing differences..." -ForegroundColor Yellow

$entraOnlyUsers = @()
$adOnlyUsers = @()
$syncedUsers = @()
$attributeMismatches = @()

# Find Entra-only users (in Entra but not in AD)
foreach ($key in $entraUsersByMatch.Keys) {
    if (-not $adUsersByMatch.ContainsKey($key)) {
        $user = $entraUsersByMatch[$key]
        $entraOnlyUsers += $user
    } else {
        $syncedUsers += @{
            Key = $key
            EntraUser = $entraUsersByMatch[$key]
            ADUser = $adUsersByMatch[$key]
        }
    }
}

# Find AD-only users (in AD but not in Entra)
foreach ($key in $adUsersByMatch.Keys) {
    if (-not $entraUsersByMatch.ContainsKey($key)) {
        $user = $adUsersByMatch[$key]
        $adOnlyUsers += $user
    }
}

# Compare attributes if requested
if ($CompareAttributes) {
    Write-Host "    [*] Comparing attributes for synced users..." -ForegroundColor Gray
    
    foreach ($sync in $syncedUsers) {
        $entraUser = $sync.EntraUser
        $adUser = $sync.ADUser
        $differences = @()
        
        # Get common columns to compare
        $commonColumns = $entraColumns | Where-Object { $_ -in $adColumns -and $_ -ne $MatchColumn }
        
        foreach ($column in $commonColumns) {
            $entraValue = if ($null -ne $entraUser.$column) { $entraUser.$column.ToString() } else { "" }
            $adValue = if ($null -ne $adUser.$column) { $adUser.$column.ToString() } else { "" }
            
            if ($IgnoreCase) {
                if ($entraValue.ToLower() -ne $adValue.ToLower()) {
                    $differences += @{
                        Column = $column
                        EntraValue = $entraValue
                        ADValue = $adValue
                    }
                }
            } else {
                if ($entraValue -ne $adValue) {
                    $differences += @{
                        Column = $column
                        EntraValue = $entraValue
                        ADValue = $adValue
                    }
                }
            }
        }
        
        if ($differences.Count -gt 0) {
            $mismatchObj = [PSCustomObject]@{
                $MatchColumn = $entraUser.$MatchColumn
                DifferenceCount = $differences.Count
                Differences = ($differences | ForEach-Object { "$($_.Column): '$($_.EntraValue)' vs '$($_.ADValue)'" }) -join "; "
            }
            
            # Add individual difference columns
            foreach ($diff in $differences) {
                $mismatchObj | Add-Member -NotePropertyName "$($diff.Column)_Entra" -NotePropertyValue $diff.EntraValue -Force
                $mismatchObj | Add-Member -NotePropertyName "$($diff.Column)_AD" -NotePropertyValue $diff.ADValue -Force
            }
            
            $attributeMismatches += $mismatchObj
        }
    }
}

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Comparison Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Entra Users Total:    $($entraUsers.Count)" -ForegroundColor White
Write-Host "AD Users Total:       $($adUsers.Count)" -ForegroundColor White
Write-Host "Synced Users:         $($syncedUsers.Count)" -ForegroundColor Green
Write-Host "Entra-Only Users:     $($entraOnlyUsers.Count)" -ForegroundColor Yellow
Write-Host "AD-Only Users:        $($adOnlyUsers.Count)" -ForegroundColor Yellow
if ($CompareAttributes) {
    Write-Host "Attribute Mismatches:  $($attributeMismatches.Count)" -ForegroundColor $(if ($attributeMismatches.Count -gt 0) { "Red" } else { "Green" })
}
Write-Host "========================================`n" -ForegroundColor Cyan

# Export results
Write-Host "[*] Exporting results..." -ForegroundColor Yellow

# Export Entra-only users
if ($entraOnlyUsers.Count -gt 0) {
    $entraOnlyPath = Join-Path $OutputFolder "EntraOnly-Users-$timestamp.csv"
    $entraOnlyUsers | Sort-Object $MatchColumn | Export-Csv -Path $entraOnlyPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Entra-only users: $entraOnlyPath" -ForegroundColor Green
} else {
    Write-Host "    [-] No Entra-only users found" -ForegroundColor Gray
}

# Export AD-only users
if ($adOnlyUsers.Count -gt 0) {
    $adOnlyPath = Join-Path $OutputFolder "ADOnly-Users-$timestamp.csv"
    $adOnlyUsers | Sort-Object $MatchColumn | Export-Csv -Path $adOnlyPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] AD-only users: $adOnlyPath" -ForegroundColor Green
} else {
    Write-Host "    [-] No AD-only users found" -ForegroundColor Gray
}

# Export synced users
if ($syncedUsers.Count -gt 0) {
    $syncedPath = Join-Path $OutputFolder "Synced-Users-$timestamp.csv"
    $syncedExport = $syncedUsers | ForEach-Object {
        $entraUser = $_.EntraUser
        $adUser = $_.ADUser
        
        # Create combined object with both Entra and AD data
        $combined = [PSCustomObject]@{}
        $combined | Add-Member -NotePropertyName $MatchColumn -NotePropertyValue $entraUser.$MatchColumn
        
        # Add all Entra columns with _Entra suffix
        foreach ($prop in $entraUser.PSObject.Properties) {
            if ($prop.Name -ne $MatchColumn) {
                $combined | Add-Member -NotePropertyName "$($prop.Name)_Entra" -NotePropertyValue $prop.Value
            }
        }
        
        # Add all AD columns with _AD suffix
        foreach ($prop in $adUser.PSObject.Properties) {
            if ($prop.Name -ne $MatchColumn) {
                $combined | Add-Member -NotePropertyName "$($prop.Name)_AD" -NotePropertyValue $prop.Value
            }
        }
        
        $combined
    }
    $syncedExport | Sort-Object $MatchColumn | Export-Csv -Path $syncedPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Synced users: $syncedPath" -ForegroundColor Green
}

# Export attribute mismatches
if ($CompareAttributes -and $attributeMismatches.Count -gt 0) {
    $mismatchPath = Join-Path $OutputFolder "AttributeMismatches-$timestamp.csv"
    $attributeMismatches | Sort-Object $MatchColumn | Export-Csv -Path $mismatchPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] Attribute mismatches: $mismatchPath" -ForegroundColor Green
} elseif ($CompareAttributes) {
    Write-Host "    [-] No attribute mismatches found" -ForegroundColor Gray
}

# Generate summary report
$summaryPath = Join-Path $OutputFolder "ComparisonSummary-$timestamp.txt"
$summaryContent = @"
CSV User Comparison Summary Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
========================================

Input Files:
- Entra CSV: $EntraCSV
- AD CSV: $ADCSV
- Match Column: $MatchColumn

Statistics:
- Entra Users Total:    $($entraUsers.Count)
- AD Users Total:       $($adUsers.Count)
- Synced Users:         $($syncedUsers.Count)
- Entra-Only Users:     $($entraOnlyUsers.Count)
- AD-Only Users:        $($adOnlyUsers.Count)
$(if ($CompareAttributes) { "- Attribute Mismatches:  $($attributeMismatches.Count)" })

Output Files:
$(if ($entraOnlyUsers.Count -gt 0) { "- Entra-Only Users: EntraOnly-Users-$timestamp.csv" })
$(if ($adOnlyUsers.Count -gt 0) { "- AD-Only Users: ADOnly-Users-$timestamp.csv" })
$(if ($syncedUsers.Count -gt 0) { "- Synced Users: Synced-Users-$timestamp.csv" })
$(if ($CompareAttributes -and $attributeMismatches.Count -gt 0) { "- Attribute Mismatches: AttributeMismatches-$timestamp.csv" })

Analysis:
"@

if ($entraOnlyUsers.Count -gt 0) {
    $summaryContent += "`n⚠️  $($entraOnlyUsers.Count) users exist in Entra but not in AD (cloud-only or orphaned accounts)"
}

if ($adOnlyUsers.Count -gt 0) {
    $summaryContent += "`n⚠️  $($adOnlyUsers.Count) users exist in AD but not in Entra (not synchronized)"
}

if ($CompareAttributes -and $attributeMismatches.Count -gt 0) {
    $summaryContent += "`n⚠️  $($attributeMismatches.Count) synced users have attribute discrepancies that may indicate sync issues"
}

if ($entraOnlyUsers.Count -eq 0 -and $adOnlyUsers.Count -eq 0 -and ($CompareAttributes -eq $false -or $attributeMismatches.Count -eq 0)) {
    $summaryContent += "`n✅ All users are synchronized with no discrepancies found!"
}

$summaryContent | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "    [OK] Summary report: $summaryPath" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Comparison completed successfully!" -ForegroundColor Green
Write-Host "Output folder: $OutputFolder" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

