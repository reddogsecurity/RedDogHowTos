# AD Security Assessment - Modular Architecture

## 🎯 Overview

This document outlines the modular refactoring of the AD/Entra security assessment tool.

## 📁 Project Structure

```
AD_review/
├── Run-Assessment.ps1          # Master orchestration script (NEW)
├── script.ps1                  # Original monolithic script (kept for reference)
├── Modules/
│   ├── Helpers.psm1           # Common utility functions ✅ CREATED
│   ├── AD-Collector.psm1      # Active Directory data collection ✅ CREATED
│   ├── Entra-Collector.psm1   # Entra ID data collection ✅ CREATED
│   ├── Analyzer.psm1          # Security analysis engine (TODO)
│   └── Reporter.psm1          # HTML report generation (TODO)
└── Output/
    └── [timestamped data files]
```

## ✅ What's Been Modularized

### 1. **Helpers.psm1** (COMPLETED)
**Functions:**
- `Write-OutputFiles` - Dual CSV/JSON export
- `Get-LatestFile` - Find most recent data file
- `Get-RemediationGuidance` - Lookup remediation steps by risk type

**Size:** ~150 lines (extracted from main script)

### 2. **AD-Collector.psm1** (COMPLETED)
**Primary Function:** `Invoke-ADCollection`

**Collects:**
- Forest/Domain/DC information
- User accounts (w/ delegation, password policies)
- Groups & membership
- Computer accounts
- krbtgt password age analysis
- Privileged group memberships
- GPOs and links
- OU ACLs
- SPN accounts (Kerberoast surface)

**Size:** ~170 lines

### 3. **Entra-Collector.psm1** (COMPLETED)
**Primary Function:** `Invoke-EntraCollection`

**Collects:**
- Tenant information
- Users & groups
- Directory role assignments (privileged roles)
- Service principals & applications
- SP credentials (secrets/certificates)
- OAuth2 permission grants
- App role assignments
- Conditional Access policies
- Sign-in logs
- MFA/authentication methods
- Device inventory (Intune + AAD)

**Size:** ~280 lines

### 4. **Run-Assessment.ps1** (COMPLETED)
**Master orchestration script**

**Responsibilities:**
- Parameter handling
- Module loading
- Metadata generation
- Phase coordination (Collection → Analysis → Reporting)
- Error handling and summary

**Size:** ~80 lines

## 🚧 Still TODO

### 5. **Analyzer.psm1** (NOT YET CREATED)
**Would contain:**
- Risk analysis engine
- RBAC role clustering (Jaccard similarity)
- Password policy validation
- Trust analysis
- CA baseline validation
- Service principal hardening checks
- Device posture analysis

**Functions to create:**
- `Invoke-SecurityAnalysis`
- `Get-JaccardSimilarity`
- `New-RBACCandidates`
- `Test-PasswordPolicy`
- `Test-CABaselines`

**Estimated size:** ~600 lines

### 6. **Reporter.psm1** (NOT YET CREATED)
**Would contain:**
- HTML report generation
- CSS styling
- KPI table formatting
- Playbook table generation
- Risk findings HTML
- RBAC candidates HTML
- GPO modernization HTML

**Functions to create:**
- `New-HTMLReport`
- `New-PlaybookHTML`
- `New-KPITable`
- `Get-ReportCSS`

**Estimated size:** ~200 lines

## 📊 Benefits of Modular Architecture

### ✅ Maintainability
- **Before:** 1524 lines in one file
- **After:** 5-6 modules, each 80-300 lines
- Easier to locate and fix bugs
- Clear separation of concerns

### ✅ Testability
- Can unit test each module independently
- Mock data collection for testing analysis logic
- Test report generation without running live queries

### ✅ Reusability
- Use `AD-Collector.psm1` in other projects
- Share `Entra-Collector.psm1` with other teams
- Helpers can be used across multiple tools

### ✅ Parallel Development
- Multiple developers can work on different modules
- AD specialist works on AD-Collector
- Graph API expert works on Entra-Collector
- Front-end dev works on Reporter

### ✅ Version Control
- Easier to see what changed in git diffs
- Module-level versioning possible
- Better commit messages (e.g., "Fix: AD-Collector - handle empty OU ACLs")

### ✅ Performance Optimization
- Can lazy-load modules (only import what you need)
- Easier to identify performance bottlenecks
- Can parallelize collection modules in future

## 🔄 Migration Path

### Phase 1: Collection Modules ✅ DONE
- [x] Extract helper functions
- [x] Create AD-Collector module
- [x] Create Entra-Collector module
- [x] Create master orchestration script

### Phase 2: Analysis Module (NEXT)
- [ ] Extract analysis functions from script.ps1 (lines 463-1371)
- [ ] Create Analyzer.psm1 with risk rules
- [ ] Update Run-Assessment.ps1 to call analyzer

### Phase 3: Reporting Module
- [ ] Extract HTML generation from script.ps1 (lines 1402-1524)
- [ ] Create Reporter.psm1
- [ ] Update Run-Assessment.ps1 to call reporter

### Phase 4: Deprecate Monolith
- [ ] Validate all functionality works in modular version
- [ ] Update documentation
- [ ] Archive script.ps1

## 🚀 Usage

### Current (Modular Data Collection)
```powershell
# Collect AD data only
.\Run-Assessment.ps1

# Collect AD + Entra data
.\Run-Assessment.ps1 -IncludeEntra

# Custom output location
.\Run-Assessment.ps1 -IncludeEntra -OutputFolder "C:\Assessments\Client1"
```

### After Full Modularization (TODO)
```powershell
# Full assessment with all modules
.\Run-Assessment.ps1 -IncludeEntra -GenerateReport

# Collection only (skip analysis)
.\Run-Assessment.ps1 -CollectionOnly

# Analysis only (on existing data)
.\Run-Assessment.ps1 -AnalyzeExisting -InputFolder "C:\Assessments\Client1"

# Custom modules (advanced)
.\Run-Assessment.ps1 -Modules @('AD-Collector','Analyzer') -Skip 'Entra-Collector'
```

## 🧪 Testing Strategy

### Unit Tests (Future)
```powershell
# Test individual modules
Invoke-Pester Tests/Helpers.Tests.ps1
Invoke-Pester Tests/AD-Collector.Tests.ps1
Invoke-Pester Tests/Analyzer.Tests.ps1
```

### Integration Tests
```powershell
# Test full workflow with mock data
Invoke-Pester Tests/Integration.Tests.ps1
```

## 📝 Development Guidelines

### Adding New Risk Rules
1. Add remediation guidance to `Helpers.psm1` → `Get-RemediationGuidance`
2. Add analysis logic to `Analyzer.psm1` (when created)
3. Risk findings automatically appear in HTML report

### Adding New Data Collection
1. Add collection logic to appropriate collector module
2. Use `Write-OutputFiles` for consistent export format
3. Update Analyzer to consume new data

### Modifying HTML Output
1. All HTML changes go in `Reporter.psm1` (when created)
2. CSS in `Get-ReportCSS` function
3. Playbook table generation in `New-PlaybookHTML`

## 🔧 Troubleshooting

### Module Not Found Error
```powershell
# Ensure you're running from the AD_review directory
cd C:\Projects\AD_review
.\Run-Assessment.ps1
```

### Graph Module Conflicts
```powershell
# Clean up Graph modules
Get-Module Microsoft.Graph* | Remove-Module -Force

# Re-run assessment
.\Run-Assessment.ps1 -IncludeEntra
```

## 📚 Resources

- [PowerShell Module Design](https://learn.microsoft.com/en-us/powershell/scripting/developer/module/writing-a-windows-powershell-module)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview)
- [Active Directory Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)

---

**Status:** 🟡 Partial Implementation  
**Last Updated:** 2025-10-06  
**Version:** 2.0-Modular (In Progress)

