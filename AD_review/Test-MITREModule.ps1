# Test-MITREModule.ps1
# Quick test to verify MITRE-Mapper.psm1 loads correctly

Write-Host "=== MITRE-Mapper Module Test ===" -ForegroundColor Cyan
Write-Host ""

# Get the script root and module path
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptRoot "Modules\MITRE-Mapper.psm1"

Write-Host "Script Root: $scriptRoot" -ForegroundColor Gray
Write-Host "Module Path: $modulePath" -ForegroundColor Gray
Write-Host ""

# Check if module file exists
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] Module file not found at: $modulePath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Current directory contents:" -ForegroundColor Yellow
    Get-ChildItem $scriptRoot
    exit 1
}

Write-Host "[OK] Module file exists" -ForegroundColor Green

# Try to import the module
try {
    Import-Module $modulePath -Force -ErrorAction Stop
    Write-Host "[OK] Module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to import module: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace
    exit 1
}

Write-Host ""

# Test each exported function
$expectedFunctions = @(
    'Get-MITRETechniqueMapping',
    'Get-MITRETechniqueInfo',
    'Add-MITREMapping',
    'New-MITRECategoryReport',
    'Get-NumericRiskScore',
    'Get-BusinessImpact'
)

Write-Host "Checking exported functions:" -ForegroundColor Cyan
$allFound = $true
foreach ($funcName in $expectedFunctions) {
    $cmd = Get-Command $funcName -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host "  [OK] $funcName" -ForegroundColor Green
    } else {
        Write-Host "  [X] $funcName [NOT FOUND]" -ForegroundColor Red
        $allFound = $false
    }
}

Write-Host ""

if (-not $allFound) {
    Write-Host "[ERROR] Some functions are missing!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Available commands from module:" -ForegroundColor Yellow
    Get-Command -Module MITRE-Mapper | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }
    exit 1
}

# Test basic functionality
Write-Host "Testing basic functionality:" -ForegroundColor Cyan

# Test 1: Get-NumericRiskScore
try {
    $score = Get-NumericRiskScore -Severity 'High' -Area 'Test' -Finding 'Test finding'
    Write-Host "  [OK] Get-NumericRiskScore returned: $score" -ForegroundColor Green
} catch {
    Write-Host "  [X] Get-NumericRiskScore failed: $($_.Exception.Message)" -ForegroundColor Red
    $allFound = $false
}

# Test 2: Get-BusinessImpact
try {
    $impact = Get-BusinessImpact -Finding @{ Area='Test'; Finding='Test'; Severity='High' }
    Write-Host "  [OK] Get-BusinessImpact returned: $impact" -ForegroundColor Green
} catch {
    Write-Host "  [X] Get-BusinessImpact failed: $($_.Exception.Message)" -ForegroundColor Red
    $allFound = $false
}

# Test 3: Add-MITREMapping with sample finding
try {
    $sampleFinding = [PSCustomObject]@{
        Area = 'AD Users'
        Finding = '10 enabled users inactive over 90 days'
        Severity = 'Medium'
        Evidence = 'ad-users'
    }
    
    $enriched = Add-MITREMapping -Findings @($sampleFinding)
    
    $enrichedArray = @($enriched)
    if ($enrichedArray.Count -eq 1) {
        Write-Host "  [OK] Add-MITREMapping processed 1 finding" -ForegroundColor Green
        Write-Host "    - MITRE Techniques: $($enrichedArray[0].MITRETechniques)" -ForegroundColor Gray
        Write-Host "    - Security Category: $($enrichedArray[0].SecurityCategory)" -ForegroundColor Gray
        Write-Host "    - Risk Score: $($enrichedArray[0].RiskScore)" -ForegroundColor Gray
    } else {
        Write-Host "  [X] Add-MITREMapping returned unexpected count: $($enrichedArray.Count)" -ForegroundColor Red
        $allFound = $false
    }
} catch {
    Write-Host "  [X] Add-MITREMapping failed: $($_.Exception.Message)" -ForegroundColor Red
    $allFound = $false
}

Write-Host ""

if ($allFound) {
    Write-Host "=== ALL TESTS PASSED ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "The MITRE-Mapper module is working correctly!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== SOME TESTS FAILED ===" -ForegroundColor Red
    exit 1
}

