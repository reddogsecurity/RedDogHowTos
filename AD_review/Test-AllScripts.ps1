# Test-AllScripts.ps1
# Comprehensive validation of all scripts in the AD_review project

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "AD Review Project - Complete Validation" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$allPassed = $true
$results = @()

function Test-ScriptSyntax {
    param([string]$Path, [string]$Name)
    
    Write-Host "Testing: $Name" -ForegroundColor White
    
    if (-not (Test-Path $Path)) {
        Write-Host "  [SKIP] File not found" -ForegroundColor Yellow
        return [PSCustomObject]@{ Name=$Name; Status='Skipped'; Errors=0 }
    }
    
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    
    if ($errors.Count -eq 0) {
        Write-Host "  [OK] Syntax valid" -ForegroundColor Green
        return [PSCustomObject]@{ Name=$Name; Status='Pass'; Errors=0 }
    } else {
        Write-Host "  [FAIL] $($errors.Count) syntax errors" -ForegroundColor Red
        foreach ($err in $errors | Select-Object -First 3) {
            Write-Host "    Line $($err.Extent.StartLineNumber): $($err.Message)" -ForegroundColor Yellow
        }
        return [PSCustomObject]@{ Name=$Name; Status='Fail'; Errors=$errors.Count }
    }
}

# Test main scripts
Write-Host "Main Scripts:" -ForegroundColor Cyan
Write-Host "-------------" -ForegroundColor Cyan
$results += Test-ScriptSyntax (Join-Path $PSScriptRoot "script.ps1") "script.ps1"
$results += Test-ScriptSyntax (Join-Path $PSScriptRoot "Export-ExcelReport.ps1") "Export-ExcelReport.ps1"
$results += Test-ScriptSyntax (Join-Path $PSScriptRoot "Export-ExecutiveBrief.ps1") "Export-ExecutiveBrief.ps1"

Write-Host ""

# Test modules
Write-Host "Modules:" -ForegroundColor Cyan
Write-Host "--------" -ForegroundColor Cyan
$modulePath = Join-Path $PSScriptRoot "Modules"
$results += Test-ScriptSyntax (Join-Path $modulePath "Helpers.psm1") "Helpers.psm1"
$results += Test-ScriptSyntax (Join-Path $modulePath "MITRE-Mapper.psm1") "MITRE-Mapper.psm1"
$results += Test-ScriptSyntax (Join-Path $modulePath "AD-Collector.psm1") "AD-Collector.psm1"
$results += Test-ScriptSyntax (Join-Path $modulePath "Entra-Collector.psm1") "Entra-Collector.psm1"
$results += Test-ScriptSyntax (Join-Path $modulePath "ConditionalAccess-Analyzer.psm1") "ConditionalAccess-Analyzer.psm1"
$results += Test-ScriptSyntax (Join-Path $modulePath "GraphGenerator.psm1") "GraphGenerator.psm1"
$results += Test-ScriptSyntax (Join-Path $modulePath "Historical-TrendAnalyzer.psm1") "Historical-TrendAnalyzer.psm1"

Write-Host ""

# Test MITRE module import
Write-Host "Module Import Tests:" -ForegroundColor Cyan
Write-Host "--------------------" -ForegroundColor Cyan
try {
    Import-Module (Join-Path $modulePath "MITRE-Mapper.psm1") -Force -ErrorAction Stop
    $commands = Get-Command -Module MITRE-Mapper
    if ($commands.Count -eq 6) {
        Write-Host "  [OK] MITRE-Mapper: 6 functions exported" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] MITRE-Mapper: Expected 6 functions, got $($commands.Count)" -ForegroundColor Red
        $allPassed = $false
    }
} catch {
    Write-Host "  [FAIL] MITRE-Mapper import failed: $($_.Exception.Message)" -ForegroundColor Red
    $allPassed = $false
}

Write-Host ""

# Summary
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$passed = ($results | Where-Object { $_.Status -eq 'Pass' }).Count
$failed = ($results | Where-Object { $_.Status -eq 'Fail' }).Count
$skipped = ($results | Where-Object { $_.Status -eq 'Skipped' }).Count

Write-Host "Results:" -ForegroundColor White
Write-Host "  Passed:  $passed" -ForegroundColor Green
Write-Host "  Failed:  $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Gray' })
Write-Host "  Skipped: $skipped" -ForegroundColor Yellow

Write-Host ""

if ($failed -eq 0) {
    Write-Host "ALL TESTS PASSED - Project is ready to use!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "SOME TESTS FAILED - Review errors above" -ForegroundColor Red
    Write-Host ""
    Write-Host "Failed files:" -ForegroundColor Yellow
    $results | Where-Object { $_.Status -eq 'Fail' } | ForEach-Object {
        Write-Host "  - $($_.Name) ($($_.Errors) errors)" -ForegroundColor Red
    }
    exit 1
}

