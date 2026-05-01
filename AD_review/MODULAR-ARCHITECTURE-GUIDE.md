# Modular Architecture Guide

## 🏗️ **Overview**

The AD Security Assessment Tool has been refactored into a **modular architecture** for better maintainability, reusability, and testability.

### **Before** (Monolithic)
- Single 1,600+ line script
- Inline functions mixed with execution logic
- Hard to maintain and test
- Duplicated code across projects

### **After** (Modular)
- Core script: ~1,200 lines
- Reusable modules in `Modules/` folder
- Separation of concerns
- Easy to test and extend

---

## 📁 **Module Structure**

```
AD_review/
├── script.ps1                    # Main orchestration script
├── Modules/
│   ├── Helpers.psm1             # Common utilities
│   ├── AD-Collector.psm1        # Active Directory data collection
│   ├── Entra-Collector.psm1    # Entra ID data collection
│   ├── App-GrantGenerator.ps1   # OAuth grant visualization
│   ├── GPO-TopologyGenerator.ps1 # GPO topology diagrams
│   ├── Trust-MapGenerator.ps1   # Trust relationship maps
│   └── ZeroTrust-Generator.ps1  # Zero Trust policy analysis
└── config/
    ├── privileged-config.json   # Privileged role definitions
    └── relationship-types.json  # Relationship type mappings
```

---

## 🔧 **Module Descriptions**

### **1. Helpers.psm1** 
**Common Utility Functions**

**Exported Functions:**
- `Write-OutputFiles` - Exports data to CSV and JSON
- `Get-LatestFile` - Retrieves most recent file by pattern
- `Get-RemediationGuidance` - Returns remediation steps for findings

**Usage:**
```powershell
Import-Module .\Modules\Helpers.psm1

# Export data
Write-OutputFiles -Name "users" -Object $users -OutputFolder "C:\Output" -Timestamp "20251007-120000"

# Get latest file
$latestUsers = Get-LatestFile -Pattern "ad-users-*.csv" -Folder "C:\Output"

# Get remediation guidance
$guidance = Get-RemediationGuidance -RiskType "StaleUsers"
```

**Key Features:**
- 15+ remediation guidance templates
- Consistent export formatting
- Depth-6 JSON serialization

---

### **2. AD-Collector.psm1**
**Active Directory Data Collection**

**Exported Functions:**
- `Invoke-ADCollection` - Collects all AD inventory data

**Parameters:**
- `OutputFolder` (Mandatory) - Where to save collected data
- `Timestamp` (Mandatory) - Timestamp string for file naming

**Usage:**
```powershell
Import-Module .\Modules\AD-Collector.psm1

Invoke-ADCollection -OutputFolder "C:\Assessments\AD" -Timestamp (Get-Date -Format "yyyyMMdd-HHmmss")
```

**Collected Data:**
- Forest & domain info
- Domain controllers
- Trusts
- Password policies (default & FGPP)
- Users (with delegation, logon history)
- Groups (with member counts)
- Computers (with OS, logon data)
- krbtgt password age
- Privileged group membership
- GPOs & links
- OU ACLs
- SPN accounts

**Outputs:** 15+ JSON/CSV files

---

### **3. Entra-Collector.psm1**
**Entra ID (Azure AD) Data Collection**

**Exported Functions:**
- `Invoke-EntraCollection` - Collects all Entra ID inventory data

**Parameters:**
- `OutputFolder` (Mandatory) - Where to save collected data
- `Timestamp` (Mandatory) - Timestamp string for file naming

**Usage:**
```powershell
Import-Module .\Modules\Entra-Collector.psm1

Invoke-EntraCollection -OutputFolder "C:\Assessments\Entra" -Timestamp (Get-Date -Format "yyyyMMdd-HHmmss")
```

**Collected Data:**
- Tenant info
- Users (with sign-in activity)
- Groups
- Directory roles & assignments
- Service principals
- Applications
- Service principal credentials (secrets/certs)
- OAuth2 permission grants
- App role assignments
- Conditional Access policies
- Sign-in logs (last 500)
- Authentication methods (MFA coverage)
- Intune managed devices
- Azure AD devices

**Outputs:** 12+ JSON/CSV files

**Graph API Scopes Required:**
- Directory.Read.All
- Application.Read.All
- Policy.Read.All
- AuditLog.Read.All
- UserAuthenticationMethod.Read.All
- DeviceManagementManagedDevices.Read.All

---

## 🚀 **How It Works**

### **Main Script Flow**

```powershell
# 1. Import modules
Import-Module .\Modules\Helpers.psm1 -Force
Import-Module .\Modules\AD-Collector.psm1 -Force
Import-Module .\Modules\Entra-Collector.psm1 -Force

# 2. Prepare output folder
$OutputFolder = "C:\Assessments"
$now = Get-Date -Format "yyyyMMdd-HHmmss"

# 3. Collect AD data
Invoke-ADCollection -OutputFolder $OutputFolder -Timestamp $now

# 4. Collect Entra data (if enabled)
if ($IncludeEntra) {
    Invoke-EntraCollection -OutputFolder $OutputFolder -Timestamp $now
}

# 5. Analyze collected data
$analysis = Analyze-Inventory -OutputFolder $OutputFolder -NowTag $now

# 6. Generate HTML report
# ... (report generation logic)
```

---

## 🎯 **Benefits of Modular Architecture**

### **1. Separation of Concerns** ✅
- **Data Collection** (AD-Collector, Entra-Collector)
- **Analysis** (Analyze-Inventory in main script)
- **Utilities** (Helpers)
- **Visualization** (Graph generators - future)

### **2. Reusability** ♻️
```powershell
# Use AD collector in another script
Import-Module .\Modules\AD-Collector.psm1
Invoke-ADCollection -OutputFolder "C:\MyProject" -Timestamp (Get-Date -Format "yyyyMMdd-HHmmss")
```

### **3. Testability** 🧪
```powershell
# Test individual modules
Import-Module .\Modules\Helpers.psm1
Pester-Test { Get-RemediationGuidance -RiskType "StaleUsers" }
```

### **4. Maintainability** 🔧
- Each module has a single responsibility
- Changes to AD collection don't affect Entra collection
- Easy to add new modules without touching existing code

### **5. Extensibility** 📈
Add new modules without modifying core:
```powershell
# Add new module
Import-Module .\Modules\My-NewModule.psm1
Invoke-MyNewFeature -Parameters $params
```

---

## 📝 **Creating New Modules**

### **Template: New Collector Module**

```powershell
# MyData-Collector.psm1

Import-Module (Join-Path $PSScriptRoot "Helpers.psm1") -Force

function Invoke-MyDataCollection {
    <#
    .SYNOPSIS
    Collects data from My System
    
    .PARAMETER OutputFolder
    Path where collected data will be stored
    
    .PARAMETER Timestamp
    Timestamp string to append to output files
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,
        
        [Parameter(Mandatory)]
        [string]$Timestamp
    )
    
    Write-Host "Collecting My Data..." -ForegroundColor Cyan
    
    # Collection logic here
    $data = Get-MyData
    
    # Use helper to export
    Write-OutputFiles -Name "my-data" -Object $data -OutputFolder $OutputFolder -Timestamp $Timestamp
    
    Write-Host "My Data collection complete." -ForegroundColor Green
}

Export-ModuleMember -Function Invoke-MyDataCollection
```

### **Integrate Into Main Script**

```powershell
# In script.ps1

# Import your module
Import-Module (Join-Path $ModulePath "MyData-Collector.psm1") -Force

# Call it
try {
    Invoke-MyDataCollection -OutputFolder $OutputFolder -Timestamp $now
} catch {
    Write-Warning "My Data collection failed: $_"
}
```

---

## 🛠️ **Module Development Best Practices**

### **1. Follow Naming Conventions**
- **Collectors**: `Invoke-[Source]Collection`
- **Generators**: `New-[Output]Generator`  
- **Helpers**: `Get-`, `Set-`, `Write-`, `Read-`

### **2. Use Approved Verbs**
```powershell
# Good
Invoke-ADCollection
Get-LatestFile
Write-OutputFiles

# Avoid
Collect-ADInventory  # 'Collect' is not an approved verb
```

### **3. Parameter Validation**
```powershell
param(
    [Parameter(Mandatory)]
    [ValidateScript({Test-Path $_})]
    [string]$OutputFolder,
    
    [Parameter(Mandatory)]
    [ValidatePattern('^\d{8}-\d{6}$')]
    [string]$Timestamp
)
```

### **4. Error Handling**
```powershell
try {
    $data = Get-SomeData -ErrorAction Stop
} catch {
    Write-Warning "Failed to get data: $($_.Exception.Message)"
    return
}
```

### **5. Export Only Public Functions**
```powershell
# Internal helper (not exported)
function Get-InternalHelper {
    # ...
}

# Public function (exported)
function Invoke-MyCollection {
    Get-InternalHelper
    # ...
}

Export-ModuleMember -Function Invoke-MyCollection
```

---

## 🔄 **Migration Path (Monolithic → Modular)**

### **Step 1: Identify Logical Boundaries**
```
Monolithic Script
├── Helper Functions        → Helpers.psm1
├── AD Collection          → AD-Collector.psm1
├── Entra Collection       → Entra-Collector.psm1
├── Analysis Logic         → (Keep in main script)
└── Report Generation      → (Keep in main script)
```

### **Step 2: Extract Functions to Modules**
1. Create new `.psm1` file in `Modules/`
2. Copy function code
3. Update to use parameters instead of global variables
4. Add `Export-ModuleMember`
5. Test module in isolation

### **Step 3: Update Main Script**
1. Import new modules at top
2. Replace function calls with module calls
3. Pass required parameters
4. Remove old inline functions
5. Test end-to-end

### **Step 4: Update Documentation**
1. Document module functions
2. Update README
3. Add usage examples
4. Create migration guide (this document!)

---

## 📊 **Module Dependencies**

```
script.ps1
├── Helpers.psm1 (no dependencies)
├── AD-Collector.psm1
│   └── Helpers.psm1
├── Entra-Collector.psm1
│   └── Helpers.psm1
└── [Future Modules]
    └── Helpers.psm1
```

**Key Insight**: All modules depend on `Helpers.psm1`, but not on each other. This keeps coupling low.

---

## 🧪 **Testing Modules**

### **Unit Testing with Pester**

```powershell
# Install Pester
Install-Module Pester -Force

# Create test file: Helpers.Tests.ps1
Describe "Get-RemediationGuidance" {
    It "Returns guidance for StaleUsers" {
        $result = Get-RemediationGuidance -RiskType "StaleUsers"
        $result.Impact | Should -Not -BeNullOrEmpty
        $result.Steps | Should -Not -BeNullOrEmpty
    }
    
    It "Returns default guidance for unknown risk" {
        $result = Get-RemediationGuidance -RiskType "UnknownRisk"
        $result.Impact | Should -Match "Review finding details"
    }
}

# Run tests
Invoke-Pester .\Helpers.Tests.ps1
```

### **Integration Testing**

```powershell
# Test full collection
$testFolder = "C:\Temp\Test"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

Invoke-ADCollection -OutputFolder $testFolder -Timestamp $timestamp

# Verify outputs
Test-Path "$testFolder\ad-users-$timestamp.csv" | Should -Be $true
Test-Path "$testFolder\ad-groups-$timestamp.json" | Should -Be $true
```

---

## 📦 **Deployment**

### **Package Structure**
```
AD-Security-Assessment.zip
├── script.ps1
├── Modules/
│   ├── Helpers.psm1
│   ├── AD-Collector.psm1
│   └── Entra-Collector.psm1
├── config/
│   └── *.json
└── README.md
```

### **Installation**
```powershell
# Extract to folder
Expand-Archive AD-Security-Assessment.zip -DestinationPath "C:\Tools\"

# Run from installation folder
cd C:\Tools\AD-Security-Assessment
.\script.ps1 -IncludeEntra
```

**Important**: Always run from the script's directory to ensure modules are found via `$PSScriptRoot`.

---

## 🔍 **Troubleshooting**

### **Module Not Found**
```powershell
# Error: The specified module 'Helpers.psm1' was not loaded

# Solution: Ensure you're running from script directory
cd C:\Path\To\AD_review
.\script.ps1

# Or use absolute paths
$ModulePath = "C:\Path\To\AD_review\Modules"
Import-Module (Join-Path $ModulePath "Helpers.psm1") -Force
```

### **Function Not Exported**
```powershell
# Error: The term 'Write-OutputFiles' is not recognized

# Solution: Check Export-ModuleMember in module
Export-ModuleMember -Function Write-OutputFiles, Get-LatestFile
```

### **Stale Module Cache**
```powershell
# Force reload modules
Get-Module Helpers, AD-Collector, Entra-Collector | Remove-Module -Force
Import-Module .\Modules\Helpers.psm1 -Force
```

---

## 📚 **Further Reading**

- [PowerShell Modules Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules)
- [Advanced Functions](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced)
- [Pester Testing Framework](https://pester.dev/)
- [PowerShell Best Practices](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/strongly-encouraged-development-guidelines)

---

**Last Updated**: October 7, 2025  
**Version**: 2.2 (Modular Architecture)  
**Status**: ✅ Complete

