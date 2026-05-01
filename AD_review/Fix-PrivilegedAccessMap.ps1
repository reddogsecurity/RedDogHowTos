$file = Join-Path $PSScriptRoot "Modules\PrivilegedAccess-MapGenerator.psm1"

Write-Host "Fixing PrivilegedAccess-MapGenerator.psm1..." -ForegroundColor Cyan

$content = Get-Content $file -Raw -Encoding UTF8

# Backup
$backupFile = $file + ".backup"
$content | Set-Content $backupFile -Encoding UTF8 -NoNewline
Write-Host "[OK] Backup created" -ForegroundColor Green

# Replace all known emojis/Unicode
$content = $content -creplace '\uD83D\uDD34', '[H]'  # Red circle
$content = $content -creplace '\uD83D\uDFE1', '[M]'  # Yellow circle
$content = $content -creplace '\uD83D\uDFE2', '[L]'  # Green circle  
$content = $content -creplace '\uD83D\uDD10', '[MFA]'  # Lock with key
$content = $content -creplace '\u26A0\uFE0F', '[!]'  # Warning sign with variant
$content = $content -creplace '\u26A0', '[!]'  # Warning sign

# Save
$content | Set-Content $file -Encoding UTF8 -NoNewline

Write-Host "[OK] File updated" -ForegroundColor Green

# Test
$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors) | Out-Null

if ($errors.Count -eq 0) {
    Write-Host "[SUCCESS] File is now syntax valid!" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Still has $($errors.Count) errors" -ForegroundColor Red
    $errors | Select-Object -First 3 | ForEach-Object {
        Write-Host "  Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Yellow
    }
}

