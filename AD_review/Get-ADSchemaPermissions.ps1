<#
.SYNOPSIS
    Retrieves permissions (ACLs) for Active Directory schema objects.

.DESCRIPTION
    This script queries Active Directory schema objects and retrieves their security
    descriptors (Access Control Lists). It can target specific schema objects or
    enumerate all schema classes and attributes with their permissions.

.PARAMETER SchemaObjectName
    Specific schema object name to query (e.g., "User", "Computer", "ms-Mcs-AdmPwd").
    If not specified, queries all schema objects.

.PARAMETER ObjectType
    Type of schema object: ClassSchema, AttributeSchema, or All. Default is All.

.PARAMETER ShowInherited
    Include inherited permissions in the output.

.PARAMETER OutputFolder
    Path where the report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-ADSchemaPermissions.ps1 -SchemaObjectName "User"
    Get permissions for the User class schema object.

.EXAMPLE
    .\Get-ADSchemaPermissions.ps1 -ObjectType AttributeSchema -OutputFolder "C:\Reports"
    Get permissions for all attribute schema objects.

.EXAMPLE
    .\Get-ADSchemaPermissions.ps1 -ShowInherited
    Get all schema permissions including inherited permissions.

.NOTES
    Requires: Active Directory PowerShell module
    Permissions: Schema Admins or Domain Admins group membership (or delegated rights)
    Note: Reading schema requires elevated permissions in most environments
#>

param(
    [string]$SchemaObjectName = "",
    [ValidateSet("ClassSchema", "AttributeSchema", "All")]
    [string]$ObjectType = "All",
    [switch]$ShowInherited,
    [string]$OutputFolder = "."
)

# Ensure AD module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "AD Schema Object Permissions Analysis" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get the schema naming context
$rootDSE = Get-ADRootDSE
$schemaDN = $rootDSE.schemaNamingContext
Write-Host "[*] Schema Naming Context: $schemaDN" -ForegroundColor Yellow

# Function to parse and format permissions
function Get-FormattedACL {
    param(
        [Parameter(Mandatory=$true)]
        $ADObject,
        [bool]$IncludeInherited = $false
    )
    
    try {
        $acl = Get-Acl -Path "AD:$($ADObject.DistinguishedName)"
        
        $permissions = foreach ($ace in $acl.Access) {
            # Skip inherited if not requested
            if (-not $IncludeInherited -and $ace.IsInherited) {
                continue
            }
            
            [PSCustomObject]@{
                SchemaObject = $ADObject.Name
                ObjectClass = $ADObject.objectClass
                DistinguishedName = $ADObject.DistinguishedName
                IdentityReference = $ace.IdentityReference
                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                AccessControlType = $ace.AccessControlType
                ObjectType = $ace.ObjectType
                InheritedObjectType = $ace.InheritedObjectType
                InheritanceType = $ace.InheritanceType
                InheritanceFlags = $ace.InheritanceFlags
                PropagationFlags = $ace.PropagationFlags
                IsInherited = $ace.IsInherited
            }
        }
        
        return $permissions
    }
    catch {
        Write-Warning "Failed to get ACL for $($ADObject.Name): $_"
        return $null
    }
}

# Query schema objects based on parameters
$results = @()

if ($SchemaObjectName) {
    # Query specific schema object
    Write-Host "[*] Querying specific schema object: $SchemaObjectName..." -ForegroundColor Yellow
    
    try {
        $schemaObject = Get-ADObject -Filter "name -eq '$SchemaObjectName'" -SearchBase $schemaDN -Properties *
        
        if ($schemaObject) {
            Write-Host "    [OK] Found schema object: $($schemaObject.Name) (Type: $($schemaObject.objectClass))" -ForegroundColor Green
            $permissions = Get-FormattedACL -ADObject $schemaObject -IncludeInherited $ShowInherited
            $results += $permissions
        }
        else {
            Write-Warning "Schema object '$SchemaObjectName' not found."
        }
    }
    catch {
        Write-Error "Failed to query schema object: $_"
    }
}
else {
    # Query all schema objects based on type
    Write-Host "[*] Querying schema objects..." -ForegroundColor Yellow
    
    $filter = switch ($ObjectType) {
        "ClassSchema" { "(objectClass=classSchema)" }
        "AttributeSchema" { "(objectClass=attributeSchema)" }
        "All" { "(|(objectClass=classSchema)(objectClass=attributeSchema))" }
    }
    
    try {
        $schemaObjects = Get-ADObject -LDAPFilter $filter -SearchBase $schemaDN -Properties objectClass, cn
        Write-Host "    [OK] Found $($schemaObjects.Count) schema objects" -ForegroundColor Green
        
        $counter = 0
        foreach ($schemaObject in $schemaObjects) {
            $counter++
            if ($counter % 50 -eq 0) {
                Write-Host "    Processing object $counter of $($schemaObjects.Count)..." -ForegroundColor Gray
            }
            
            $permissions = Get-FormattedACL -ADObject $schemaObject -IncludeInherited $ShowInherited
            if ($permissions) {
                $results += $permissions
            }
        }
    }
    catch {
        Write-Error "Failed to query schema objects: $_"
    }
}

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Schema Objects Analyzed: $(($results | Select-Object -Unique SchemaObject).Count)" -ForegroundColor White
Write-Host "Total Permission Entries: $($results.Count)" -ForegroundColor White
Write-Host "Include Inherited Permissions: $ShowInherited" -ForegroundColor White

# Group by identity to show who has schema access
$identityGroups = $results | Group-Object IdentityReference | Sort-Object Count -Descending
Write-Host "`nTop 10 Identities with Schema Permissions:" -ForegroundColor Cyan
$identityGroups | Select-Object -First 10 | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count) permissions" -ForegroundColor Gray
}

# Export results
Write-Host "`n[*] Exporting results..." -ForegroundColor Yellow

if ($results.Count -gt 0) {
    # Export to CSV
    $csvPath = Join-Path $OutputFolder "ADSchemaPermissions-$timestamp.csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "    [OK] CSV Export: $csvPath" -ForegroundColor Green
    
    # Export detailed analysis by schema object
    $schemaObjectGroups = $results | Group-Object SchemaObject
    $detailedPath = Join-Path $OutputFolder "ADSchemaPermissions-Detailed-$timestamp.csv"
    
    $detailedResults = foreach ($group in $schemaObjectGroups) {
        $obj = $group.Group | Select-Object -First 1
        [PSCustomObject]@{
            SchemaObject = $group.Name
            ObjectClass = $obj.ObjectClass
            DistinguishedName = $obj.DistinguishedName
            TotalPermissions = $group.Count
            UniqueIdentities = ($group.Group | Select-Object -Unique IdentityReference).Count
            Identities = (($group.Group | Select-Object -Unique IdentityReference).IdentityReference -join "; ")
        }
    }
    
    $detailedResults | Export-Csv -Path $detailedPath -NoTypeInformation
    Write-Host "    [OK] Detailed Summary: $detailedPath" -ForegroundColor Green
    
    # Generate HTML report
    $htmlPath = Join-Path $OutputFolder "ADSchemaPermissions-$timestamp.html"
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Schema Permissions Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #1976d2; }
        h2 { color: #424242; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }
        .summary { background-color: #fff; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-label { font-weight: bold; color: #666; }
        .stat-value { font-size: 24px; font-weight: bold; color: #1976d2; }
        table { border-collapse: collapse; width: 100%; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        th { background-color: #1976d2; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { padding: 10px; border-bottom: 1px solid #ddd; font-size: 12px; }
        tr:hover { background-color: #f5f5f5; }
        .allow { color: #4caf50; font-weight: bold; }
        .deny { color: #f44336; font-weight: bold; }
        .inherited { color: #9e9e9e; font-style: italic; }
        .filter { margin: 10px 0; padding: 10px; background-color: #fff; }
        .filter input { padding: 5px; width: 300px; }
    </style>
    <script>
        function filterTable() {
            var input = document.getElementById("searchInput");
            var filter = input.value.toUpperCase();
            var table = document.getElementById("permissionsTable");
            var tr = table.getElementsByTagName("tr");
            
            for (var i = 1; i < tr.length; i++) {
                var td = tr[i].getElementsByTagName("td");
                var found = false;
                for (var j = 0; j < td.length; j++) {
                    if (td[j]) {
                        var txtValue = td[j].textContent || td[j].innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                tr[i].style.display = found ? "" : "none";
            }
        }
    </script>
</head>
<body>
    <h1>AD Schema Permissions Report</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p><strong>Schema DN:</strong> $schemaDN</p>
    <p><strong>Include Inherited:</strong> $ShowInherited</p>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stat">
            <div class="stat-label">Schema Objects</div>
            <div class="stat-value">$(($results | Select-Object -Unique SchemaObject).Count)</div>
        </div>
        <div class="stat">
            <div class="stat-label">Total Permissions</div>
            <div class="stat-value">$($results.Count)</div>
        </div>
        <div class="stat">
            <div class="stat-label">Unique Identities</div>
            <div class="stat-value">$(($results | Select-Object -Unique IdentityReference).Count)</div>
        </div>
    </div>
    
    <h2>Top 10 Identities with Schema Access</h2>
    <table>
        <tr>
            <th>Identity</th>
            <th>Permission Count</th>
        </tr>
        $(foreach ($identity in ($identityGroups | Select-Object -First 10)) {
            "<tr>
                <td>$($identity.Name)</td>
                <td>$($identity.Count)</td>
            </tr>"
        })
    </table>
    
    <h2>Schema Objects Summary</h2>
    <table>
        <tr>
            <th>Schema Object</th>
            <th>Object Class</th>
            <th>Total Permissions</th>
            <th>Unique Identities</th>
        </tr>
        $(foreach ($item in ($detailedResults | Sort-Object SchemaObject)) {
            "<tr>
                <td>$($item.SchemaObject)</td>
                <td>$($item.ObjectClass)</td>
                <td>$($item.TotalPermissions)</td>
                <td>$($item.UniqueIdentities)</td>
            </tr>"
        })
    </table>
    
    <h2>All Permissions (Detailed)</h2>
    <div class="filter">
        <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search permissions...">
    </div>
    <table id="permissionsTable">
        <tr>
            <th>Schema Object</th>
            <th>Identity</th>
            <th>Rights</th>
            <th>Access Type</th>
            <th>Inherited</th>
            <th>Inheritance Type</th>
        </tr>
        $(foreach ($perm in ($results | Sort-Object SchemaObject, IdentityReference)) {
            $accessClass = if ($perm.AccessControlType -eq "Allow") { "allow" } else { "deny" }
            $inheritedClass = if ($perm.IsInherited) { "inherited" } else { "" }
            "<tr>
                <td>$($perm.SchemaObject)</td>
                <td>$($perm.IdentityReference)</td>
                <td>$($perm.ActiveDirectoryRights)</td>
                <td class='$accessClass'>$($perm.AccessControlType)</td>
                <td class='$inheritedClass'>$($perm.IsInherited)</td>
                <td>$($perm.InheritanceType)</td>
            </tr>"
        })
    </table>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "    [OK] HTML Report: $htmlPath" -ForegroundColor Green
}
else {
    Write-Warning "No permissions found to export."
}

Write-Host "`n[*] Analysis complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan




