# Test-ScriptSyntax.ps1
# Quick syntax validation for script.ps1

Write-Host "=== PowerShell Syntax Validation ===" -ForegroundColor Cyan
Write-Host ""

$scriptPath = Join-Path $PSScriptRoot "script.ps1"

if (-not (Test-Path $scriptPath)) {
    Write-Host "ERROR: script.ps1 not found at: $scriptPath" -ForegroundColor Red
    exit 1
}

Write-Host "Checking: $scriptPath" -ForegroundColor Gray
Write-Host ""

# Test syntax by tokenizing and parsing the script
$errors = $null
$tokens = $null

$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, 
    [ref]$tokens, 
    [ref]$errors
)

if ($errors.Count -eq 0) {
    Write-Host "SYNTAX VALID - No parse errors found!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Script Statistics:" -ForegroundColor Cyan
    $lineCount = (Get-Content $scriptPath).Count
    $funcCount = ($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)).Count
    Write-Host "  - Total Lines: $lineCount" -ForegroundColor Gray
    Write-Host "  - Tokens: $($tokens.Count)" -ForegroundColor Gray
    Write-Host "  - Functions: $funcCount" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The script is ready to run!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "SYNTAX ERRORS FOUND:" -ForegroundColor Red
    Write-Host ""
    foreach ($err in $errors) {
        Write-Host "  Line $($err.Extent.StartLineNumber): $($err.Message)" -ForegroundColor Yellow
        $extentText = $err.Extent.Text
        if ($extentText.Length -gt 60) {
            $extentText = $extentText.Substring(0, 60) + "..."
        }
        Write-Host "    at: $extentText" -ForegroundColor Gray
        Write-Host ""
    }
    exit 1
}
