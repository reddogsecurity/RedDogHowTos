# One-liner to show admin groups from your existing assessment
# Just run this in PowerShell after your AD assessment

# Find the latest assessment folder
$assessmentFolder = if (Test-Path "$env:TEMP\ADScan") { "$env:TEMP\ADScan" } else { "C:\Temp\ADScan" }
$adminFile = Get-ChildItem -Path $assessmentFolder -Filter "ad-privileged-groups-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($adminFile) {
    Write-Host "🔍 Admin Groups from: $($adminFile.Name)" -ForegroundColor Cyan
    
    $data = Get-Content $adminFile.FullName | ConvertFrom-Json
    $criticalGroups = $data | Where-Object { $_.Group -in @('Schema Admins', 'Enterprise Admins', 'Domain Admins', 'Administrators') }
    
    foreach ($group in $criticalGroups) {
        $risk = switch ($group.Group) {
            'Schema Admins' { '🔴 CRITICAL' }
            'Enterprise Admins' { '🔴 CRITICAL' }
            'Domain Admins' { '🟡 HIGH' }
            'Administrators' { '🟡 HIGH' }
        }
        
        Write-Host "`n$($group.Group): $($group.Count) members $risk" -ForegroundColor $(if ($risk -like '*CRITICAL*') { 'Red' } else { 'Yellow' })
        
        if ($group.Count -gt 0) {
            foreach ($member in $group.Members) {
                Write-Host "  • $($member.Name)" -ForegroundColor Gray
            }
        }
    }
} else {
    Write-Host "❌ No assessment data found. Run: .\script.ps1 -IncludeEntra" -ForegroundColor Red
}
