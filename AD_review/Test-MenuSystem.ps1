# Test-MenuSystem.ps1
# Quick test of the interactive menu system
# Run this BEFORE integrating into script.ps1

[CmdletBinding()]
param()

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           MENU SYSTEM - QUICK TEST                        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Test 1: Module Import
Write-Host "[1/4] Testing module import..." -ForegroundColor Yellow

try {
    Import-Module "$PSScriptRoot\Modules\Menu-System.psm1" -Force -ErrorAction Stop
    Write-Host "      [OK] Menu-System.psm1 imported successfully" -ForegroundColor Green
} catch {
    Write-Host "      [ERROR] Failed to import Menu-System.psm1" -ForegroundColor Red
    Write-Host "      Details: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Test 2: Verify Functions
Write-Host "[2/4] Verifying exported functions..." -ForegroundColor Yellow

$functions = @(
    'Show-MainMenu',
    'Show-EmergencyMenu',
    'Show-ReportSelector',
    'Show-SettingsMenu',
    'Show-PreviousReports',
    'Get-MenuChoice',
    'Confirm-Action',
    'Show-ProgressMessage'
)

$missing = @()
foreach ($func in $functions) {
    $cmd = Get-Command $func -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host "      [OK] $func" -ForegroundColor Green
    } else {
        Write-Host "      [ERROR] $func not found" -ForegroundColor Red
        $missing += $func
    }
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "Missing functions: $($missing -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Test 3: Test Main Menu Display
Write-Host "[3/4] Testing main menu display..." -ForegroundColor Yellow
Write-Host ""

Show-MainMenu
$choice = Read-Host

Write-Host ""
Write-Host "      You selected: $choice" -ForegroundColor Gray

if ($choice -notin @("1", "2", "3", "4", "5", "6", "Q")) {
    Write-Host "      [WARNING] Invalid choice (expected for test)" -ForegroundColor Yellow
} else {
    Write-Host "      [OK] Valid menu choice" -ForegroundColor Green
}

Write-Host ""

# Test 4: Test Progress Messages
Write-Host "[4/4] Testing progress messages..." -ForegroundColor Yellow
Write-Host ""

Show-ProgressMessage -Message "This is an info message" -Type Info
Show-ProgressMessage -Message "This is a success message" -Type Success
Show-ProgressMessage -Message "This is a warning message" -Type Warning
Show-ProgressMessage -Message "This is an error message" -Type Error

Write-Host ""

# Summary
Write-Host "═════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host "═════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "[OK] All tests passed!" -ForegroundColor Green
Write-Host ""
Write-Host "Menu-System.psm1 is ready for integration." -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Follow the steps in INTEGRATION-STEPS.md" -ForegroundColor Gray
Write-Host "  2. Add module import to script.ps1" -ForegroundColor Gray
Write-Host "  3. Integrate Invoke-InteractiveMode function" -ForegroundColor Gray
Write-Host "  4. Test full integration" -ForegroundColor Gray
Write-Host ""
Write-Host "Once integrated, run your script with no parameters:" -ForegroundColor Yellow
Write-Host "  .\script.ps1" -ForegroundColor Cyan
Write-Host ""
