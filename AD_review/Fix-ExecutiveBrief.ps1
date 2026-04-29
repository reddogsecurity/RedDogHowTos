# Fix-ExecutiveBrief.ps1
# Removes Unicode characters and fixes string escaping in Export-ExecutiveBrief.ps1

param(
    [string]$FilePath = (Join-Path $PSScriptRoot "Export-ExecutiveBrief.ps1")
)

Write-Host "=== Fixing Export-ExecutiveBrief.ps1 ===" -ForegroundColor Cyan
Write-Host "Target file: $FilePath" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $FilePath)) {
    Write-Host "[ERROR] File not found: $FilePath" -ForegroundColor Red
    exit 1
}

# Read the file
$content = Get-Content $FilePath -Raw -Encoding UTF8

# Apply fixes
$originalLength = $content.Length

# Fix 1: Remove Unicode checkmarks and x marks
$content = $content -replace '[OK]', '[OK]'
$content = $content -replace '[X]', '[X]'
$content = $content -replace '[SKIP]', '[SKIP]'

# Fix 2: Remove emoji characters  
$content = $content -replace '️', ''
$content = $content -replace '', ''
$content = $content -replace '', ''
$content = $content -replace '', ''
$content = $content -replace '', ''
$content = $content -replace '', ''
$content = $content -replace '', ''
$content = $content -replace '️', ''
$content = $content -replace '', ''
$content = $content -replace '', ''
$content = $content -replace '', ''

# Fix 3: Fix ampersands in HTML (if not already HTML entity)
$content = $content -replace '&amp; Entra ID', '&amp; Entra ID'
$content = $content -replace '&amp; Entra', '&amp; Entra'
$content = $content -replace 'AD &amp; Entra', 'AD &amp; Entra'

# Fix 4: Fix the specific backtick escaping issue on line 594
$content = $content -replace 'Invoke-Item `"', 'Invoke-Item '''
$content = $content -replace '`"\$htmlPath\`"', '''$htmlPath'''

# Fix 5: Remove any other problematic backticks
$content = $content -replace '`"', "'"

# Create backup
$backupPath = $FilePath + ".backup"
Copy-Item $FilePath $backupPath -Force
Write-Host "[OK] Backup created: $backupPath" -ForegroundColor Green

# Save fixed content
$content | Set-Content $FilePath -Encoding UTF8 -NoNewline -Force

Write-Host "[OK] File updated" -ForegroundColor Green
Write-Host "    Original size: $originalLength bytes" -ForegroundColor Gray
Write-Host "    New size: $($content.Length) bytes" -ForegroundColor Gray

# Validate syntax
Write-Host ""
Write-Host "Validating syntax..." -ForegroundColor Cyan

$errors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$tokens, [ref]$errors)

if ($errors.Count -eq 0) {
    Write-Host "[SUCCESS] File is now syntax valid!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run: .\Export-ExecutiveBrief.ps1 -OutputFolder <path> -Timestamp <timestamp>" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "[FAIL] Still has $($errors.Count) syntax errors:" -ForegroundColor Red
    foreach ($err in $errors | Select-Object -First 5) {
        Write-Host "  Line $($err.Extent.StartLineNumber): $($err.Message)" -ForegroundColor Yellow
    }
    exit 1
}

