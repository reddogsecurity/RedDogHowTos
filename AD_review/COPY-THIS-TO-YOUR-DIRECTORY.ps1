<#
.SYNOPSIS
    Fix PowerShell Unicode Issues - Run this in YOUR adreview directory
    
.DESCRIPTION
    This script will fix ALL Unicode character issues in your PowerShell files.
    
.INSTRUCTIONS
    1. Copy this file to: C:\Users\ivolovnik\adreview\
    2. Open PowerShell in that directory
    3. Run: powershell -ExecutionPolicy Bypass -File .\COPY-THIS-TO-YOUR-DIRECTORY.ps1
    
.EXAMPLE
    cd C:\Users\ivolovnik\adreview
    powershell -ExecutionPolicy Bypass -File .\COPY-THIS-TO-YOUR-DIRECTORY.ps1
#>

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PowerShell Unicode Fix Tool" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$targetFolder = $PSScriptRoot
Write-Host "Working in: $targetFolder" -ForegroundColor White
Write-Host ""

# Define ALL emoji and Unicode replacements
$charMap = @(
    # Emoji colored circles
    @{ Char = [char]0xD83D + [char]0xDD34; Replace = '[H]' }  # Red circle
    @{ Char = [char]0xD83D + [char]0xDFE1; Replace = '[M]' }  # Yellow circle
    @{ Char = [char]0xD83D + [char]0xDFE2; Replace = '[L]' }  # Green circle
    @{ Char = [char]0xD83D + [char]0xDD10; Replace = '[MFA]' }  # Lock
    
    # Arrows
    @{ Char = [char]0x2192; Replace = '->' }   # →
    @{ Char = [char]0x2190; Replace = '<-' }   # ←
    @{ Char = [char]0x2191; Replace = '(+)' }  # ↑
    @{ Char = [char]0x2193; Replace = '(-)' }  # ↓
    @{ Char = [char]0x2194; Replace = '<->' }  # ↔
    
    # Checkmarks
    @{ Char = [char]0x2713; Replace = '[OK]' }  # ✓
    @{ Char = [char]0x2714; Replace = '[OK]' }  # ✔
    @{ Char = [char]0x2717; Replace = '[X]' }   # ✗
    @{ Char = [char]0x2718; Replace = '[X]' }   # ✘
    
    # Warnings
    @{ Char = [char]0x26A0; Replace = '[!]' }   # ⚠
    
    # Math symbols
    @{ Char = [char]0x2265; Replace = 'or more' }  # ≥
    @{ Char = [char]0x2264; Replace = 'or less' }  # ≤
    
    # Bullets
    @{ Char = [char]0x2022; Replace = '-' }  # •
    
    # Info
    @{ Char = [char]0x2139; Replace = '[INFO]' }  # ℹ
)

# Find all PS files
$files = Get-ChildItem -Path $targetFolder -Include *.ps1,*.psm1 -Recurse -File

Write-Host "Found $($files.Count) PowerShell files" -ForegroundColor White
Write-Host ""

$fixedCount = 0

foreach ($file in $files) {
    $relativePath = $file.Name
    $content = Get-Content $file.FullName -Raw -Encoding UTF8
    $originalContent = $content
    
    # Apply simple replacements first
    foreach ($map in $charMap) {
        $content = $content.Replace($map.Char, $map.Replace)
    }
    
    # Additional regex-based replacements for complex emojis
    # Pattern: any emoji character (U+1F300 to U+1F9FF range)
    $content = $content -replace '[\uD83C-\uD83E][\uDC00-\uDFFF]', ''
    
    # Fix specific known problematic patterns
    $content = $content -replace '\$\(0x26A0\)\$\(0xFE0F\)', '[!]'
    $content = $content -replace '\$\(0x2139\)\$\(0xFE0F\)', '[INFO]'
    
    if ($content -ne $originalContent) {
        # Backup
        Copy-Item $file.FullName ($file.FullName + ".bak") -Force
        
        # Save
        $content | Set-Content $file.FullName -Encoding UTF8 -NoNewline -Force
        
        Write-Host "  [FIXED] $relativePath" -ForegroundColor Green
        $fixedCount++
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Cleanup Complete!" -ForegroundColor Green  
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Files fixed: $fixedCount" -ForegroundColor Green
Write-Host ""
Write-Host "Now run your script:" -ForegroundColor Cyan
Write-Host "  .\script.ps1 -IncludeEntra" -ForegroundColor White
Write-Host ""

