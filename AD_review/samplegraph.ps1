function New-GraphFromAudit {
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$NowTag
    )
    $stamp = if ($NowTag) { $NowTag } else { (Get-Date).ToString('yyyyMMdd-HHmmss') }

    # Load inputs (pick latest if NowTag not passed)
    function Get-LatestFile($pattern) {
        Get-ChildItem -Path $OutputFolder -Filter $pattern -File -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -desc | Select-Object -First 1
    }
    $adUsersCsv = if ($NowTag) { Join-Path $OutputFolder "ad-users-$NowTag.csv" } else { (Get-LatestFile 'ad-users-*.csv').FullName }
    $adGroupsCsv= if ($NowTag) { Join-Path $OutputFolder "ad-groups-$NowTag.csv"} else { (Get-LatestFile 'ad-groups-*.csv').FullName }
    $rolesJson  = if ($NowTag) { Join-Path $OutputFolder "entra-role-assignments-$NowTag.json"} else { (Get-LatestFile 'entra-role-assignments-*.json').FullName }
    $riskCsv    = if ($NowTag) { Join-Path $OutputFolder "risk-findings-$NowTag.csv"} else { (Get-LatestFile 'risk-findings-*.csv').FullName }

    $users  = if ($adUsersCsv)  { Import-Csv $adUsersCsv } else { @() }
    $groups = if ($adGroupsCsv) { Import-Csv $adGroupsCsv } else { @() }
    $roles  = if ($rolesJson)   { Get-Content $rolesJson | ConvertFrom-Json } else { @() }
    $risk   = if ($riskCsv)     { Import-Csv $riskCsv } else { @() }

    # Build severity map from findings
    $sevColor = @{ High='#e74c3c'; Medium='#e67e22'; Low='#f1c40f' }
    $nodeStyle = @{}  # key = name, value = color
    foreach ($f in $risk) {
        # crude mapping: color all mentioned areas broadly
        if ($f.Area -match 'Entra Roles') { $nodeStyle['ROLE*'] = $sevColor[$f.Severity] }
        if ($f.Area -match 'AD SPNs')     { $nodeStyle['SPN*']  = $sevColor[$f.Severity] }
    }

    # Select privileged groups (AD) and roles (Entra)
    $privAdGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')
    $privGroups = $groups | Where-Object { $privAdGroups -contains $_.SamAccountName }

    # Entra roles expanded
    $privRoles = @('Global Administrator','Privileged Role Administrator','Application Administrator','Cloud Application Administrator','User Administrator','Security Administrator','Exchange Administrator','SharePoint Administrator')
    $roleEdges = @()
    foreach ($r in $roles) {
        if ($privRoles -contains $r.Role -and $r.MemberCount -gt 0) {
            foreach ($m in $r.Members) {
                $label = if ($m.UserPrincipalName) { $m.UserPrincipalName } else { $m.DisplayName }
                if ($label) { $roleEdges += [pscustomobject]@{ From="ROLE::$($r.Role)"; To=$label } }
            }
        }
    }

    # AD group edges (users to the key admin groups only, to keep it readable)
    $adEdges = @()
    foreach ($g in $privGroups) {
        try {
            $members = Get-ADGroupMember -Identity $g.SamAccountName -Recursive -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                $name = if ($m.SamAccountName) { $m.SamAccountName } else { $m.Name }
                if ($name) { $adEdges += [pscustomobject]@{ From=$name; To="GROUP::$($g.SamAccountName)" } }
            }
        } catch {}
    }

    # ---------- Graphviz DOT ----------
    $dotPath = Join-Path $OutputFolder "privileged-map-$stamp.dot"
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('digraph G {')
    [void]$sb.AppendLine('rankdir=LR; fontsize=10; fontname="Segoe UI"; node [shape=box, style=filled, fillcolor="#ecf0f1", fontname="Segoe UI", fontsize=9]; edge [color="#7f8c8d"];')

    # Define helper for style
    function Add-Node($name, $type) {
        $safe = ($name -replace '[^A-Za-z0-9_@\-\.]', '_')
        $label = $name
        $fill = '#ecf0f1'
        if ($type -eq 'role' -and $nodeStyle.ContainsKey('ROLE*')) { $fill = $nodeStyle['ROLE*'] }
        if ($type -eq 'spn'  -and $nodeStyle.ContainsKey('SPN*'))  { $fill = $nodeStyle['SPN*']  }
        if ($type -eq 'group') { $fill = '#d6eaf8' }
        if ($type -eq 'user')  { $fill = '#fdfefe' }
        [void]$sb.AppendLine("$safe [label=""$label"", fillcolor=""$fill""];")
        return $safe
    }

    $nodes = New-Object System.Collections.Generic.HashSet[string]

    foreach ($e in $roleEdges) {
        if (-not $nodes.Contains($e.From)) { [void]$nodes.Add($e.From); [void](Add-Node $e.From 'role') }
        if (-not $nodes.Contains($e.To))   { [void]$nodes.Add($e.To);   [void](Add-Node $e.To   'user') }
        [void]$sb.AppendLine(("{0} -> {1};" -f (($e.From -replace '[^A-Za-z0-9_@\-\.]','_')), (($e.To -replace '[^A-Za-z0-9_@\-\.]','_'))))
    }
    foreach ($e in $adEdges) {
        $fromType='user'; $toType='group'
        if (-not $nodes.Contains($e.From)) { [void]$nodes.Add($e.From); [void](Add-Node $e.From $fromType) }
        if (-not $nodes.Contains($e.To))   { [void]$nodes.Add($e.To);   [void](Add-Node $e.To   $toType) }
        [void]$sb.AppendLine(("{0} -> {1};" -f (($e.From -replace '[^A-Za-z0-9_@\-\.]','_')), (($e.To -replace '[^A-Za-z0-9_@\-\.]','_'))))
    }

    [void]$sb.AppendLine('}')
    $sb.ToString() | Out-File $dotPath -Encoding utf8 -Force

    # If Graphviz is installed, render PNG automatically
    $dotExe = (Get-Command dot -ErrorAction SilentlyContinue).Source
    if ($dotExe) {
        $pngPath = Join-Path $OutputFolder "privileged-map-$stamp.png"
        & $dotExe -Tpng $dotPath -o $pngPath
        Write-Host "Graphviz PNG created: $pngPath" -ForegroundColor Green
    } else {
        Write-Host "DOT file created (install Graphviz to render): $dotPath" -ForegroundColor Yellow
    }

    # ---------- Mermaid (for README/Substack) ----------
    $mPath = Join-Path $OutputFolder "privileged-map-$stamp.mmd"
    $m = [System.Text.StringBuilder]::new()
    [void]$m.AppendLine('flowchart LR')
    foreach ($e in $roleEdges) {
        [void]$m.AppendLine(("  ""{0}"" --> ""{1}""" -f $e.From, $e.To))
    }
    foreach ($e in $adEdges) {
        [void]$m.AppendLine(("  ""{0}"" --> ""{1}""" -f $e.From, $e.To))
    }
    $m.ToString() | Out-File $mPath -Encoding utf8 -Force
    Write-Host "Mermaid saved: $mPath" -ForegroundColor Green

    return [pscustomobject]@{ Dot=$dotPath; Mermaid=$mPath }
}