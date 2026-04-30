# Fix-UnicodeInAllFiles.ps1
# Removes all Unicode emoji and special characters from PowerShell files

param(
    [string]$FolderPath = $PSScriptRoot
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Unicode Character Removal Tool" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Scanning folder: $FolderPath" -ForegroundColor Gray
Write-Host ""

# Find all PowerShell files
$psFiles = Get-ChildItem -Path $FolderPath -Include *.ps1,*.psm1 -Recurse -File

Write-Host "Found $($psFiles.Count) PowerShell files" -ForegroundColor White
Write-Host ""

$fixedCount = 0
$skippedCount = 0

foreach ($file in $psFiles) {
    Write-Host "Processing: $($file.Name)" -ForegroundColor Cyan
    
    # Read file content
    $content = Get-Content $file.FullName -Raw -Encoding UTF8
    $originalContent = $content
    
    # Define all replacements
    $replacements = @{
        # Arrows
        '->' = '->'
        '<-' = '<-'
        '(+)' = '(+)'
        '(-)' = '(-)'
        '<->' = '<->'
        
        # Checkmarks and X marks
        '[OK]' = '[OK]'
        '[OK]' = '[OK]'
        '[X]' = '[X]'
        '[X]' = '[X]'
        '[SKIP]' = '[SKIP]'
        
        # Colored circles (emojis)
        '[H]' = '[H]'
        '[M]' = '[M]'
        '[L]' = '[L]'
        '[I]' = '[I]'
        '⚫' = '[*]'
        '⚪' = '[O]'
        
        # Common emojis
        '[MFA]' = '[MFA]'
        '[!]️' = '[!]'
        '[!]' = '[!]'
        '❌' = '[X]'
        '✅' = '[OK]'
        '' = ''
        '' = ''
        '' = ''
        '' = ''
        '️' = ''
        '' = ''
        '' = ''
        '' = ''
        '' = ''
        '' = ''
        '️' = ''
        '' = ''
        '[INFO]️' = '[INFO]'
        '[INFO]' = '[INFO]'
        '' = ''
        '' = ''
        '' = ''
        '️' = ''
        '' = ''
        
        # Comparison operators (when in strings)
        'or more' = 'or more'
        'or less' = 'or less'
        'not equal' = 'not equal'
        'approx' = 'approximately'
        
        # Bullets
        '-' = '-'
        '-' = '-'
        '-' = '-'
        '-' = '-'
    }
    
    # Apply all replacements
    foreach ($old in $replacements.Keys) {
        $new = $replacements[$old]
        $content = $content -replace [regex]::Escape($old), $new
    }
    
    # Check if file was modified
    if ($content -ne $originalContent) {
        # Create backup
        $backupPath = $file.FullName + ".bak"
        $originalContent | Set-Content $backupPath -Encoding UTF8 -NoNewline
        
        # Save fixed content
        $content | Set-Content $file.FullName -Encoding UTF8 -NoNewline
        
        Write-Host "  [FIXED] Removed Unicode characters" -ForegroundColor Green
        $fixedCount++
    } else {
        Write-Host "  [OK] No Unicode characters found" -ForegroundColor Gray
        $skippedCount++
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Unicode Cleanup Complete" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Files fixed: $fixedCount" -ForegroundColor Green
Write-Host "Files unchanged: $skippedCount" -ForegroundColor Gray
Write-Host ""
Write-Host "Backups created with .bak extension" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next step: Run .\Test-AllScripts.ps1 to validate all files" -ForegroundColor Cyan

