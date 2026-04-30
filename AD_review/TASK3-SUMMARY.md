# Task 3 Implementation Summary: Visual Diagram Generation

## ✅ **Task Complete!**

Successfully implemented comprehensive visual diagram generation system for the AD Security Assessment Tool, making complex security relationships visible and easy to understand.

---

## 🎯 **What Was Implemented**

### **1. Privileged Access Map Generator** (NEW)
**Module**: `Modules/PrivilegedAccess-MapGenerator.psm1`

**Purpose**: Visualize privileged access pathways showing:
- **Users** → **AD Groups** → **Entra Roles**
- MFA status for each privileged user (⚠️ No MFA indicator)
- Risk-based color coding (Red/Yellow/Green)

**Key Features**:
- Identifies users without MFA in privileged roles
- Shows AD privileged group memberships (Domain Admins, Enterprise Admins, etc.)
- Maps Entra role assignments (Global Administrator, Security Administrator, etc.)
- Risk scoring based on MFA status and role sensitivity
- Organized subgraphs for better readability

**Example Output**:
```
Privileged Access Map:
  - Users: 15
  - Users without MFA: 3 🔴
  - AD Groups: 5
  - Entra Roles: 8
  - Total Relationships: 28
```

---

### **2. Graph Generator Orchestrator** (NEW)
**Module**: `Modules/GraphGenerator.psm1`

**Purpose**: Coordinates all diagram generation with a single function call

**Key Features**:
- `Invoke-DiagramGeneration` - One function to generate all diagrams
- Automatic data loading from assessment output files
- Graceful handling of missing data
- Graphviz detection and PNG rendering
- Progress reporting for each diagram type

**Supported Diagram Types**:
1. **PrivilegedAccess** - Privileged access pathways
2. **GPOTopology** - GPO → OU links with delegations
3. **TrustMap** - Domain/forest trust relationships
4. **AppGrant** - Service principals → OAuth scopes

---

### **3. Enhanced Existing Generators**

**Integrated from `Modules/` folder**:
- ✅ `GPO-TopologyGenerator.ps1` - Shows GPOs linked to OUs with delegation risks
- ✅ `Trust-MapGenerator.ps1` - Maps domain/forest trusts with risk indicators
- ✅ `App-GrantGenerator.ps1` - Visualizes OAuth grants and permissions

**Enhancements Made**:
- Converted to modular architecture
- Added data transformation helpers
- Integrated with main assessment workflow
- Standardized output formats

---

### **4. Main Script Integration**

**New Parameter**: `-GenerateDiagrams`

```powershell
# Generate diagrams along with assessment
.\script.ps1 -IncludeEntra -GenerateDiagrams
```

**What Happens**:
1. Runs full AD + Entra assessment
2. Performs security analysis
3. **Generates visual diagrams** from collected data
4. Exports diagrams in multiple formats:
   - **DOT** (Graphviz) - For rendering with `dot` command
   - **Mermaid** - For GitHub/GitLab/Markdown
   - **PNG** - If Graphviz is installed

---

## 📊 **Diagram Types Generated**

### **1. Privileged Access Map** 🔐
**Shows**: Users → Groups → Roles with MFA status

**Use Cases**:
- Identify privileged users without MFA
- Audit admin group memberships
- Review Entra role assignments
- Plan MFA enforcement

**Risk Indicators**:
- 🔴 High Risk: No MFA, Global Admin, excessive permissions
- 🟡 Medium Risk: Service principals, multiple roles
- 🟢 Low Risk: MFA enabled, limited permissions

---

### **2. GPO Topology Diagram** 📋
**Shows**: GPOs ↔ OUs with delegation relationships

**Use Cases**:
- Identify unlinked GPOs (migration candidates)
- Review OU delegations for security risks
- Plan GPO → Intune migration
- Visualize policy application scope

**Risk Indicators**:
- 🔴 High Risk: Unlinked GPOs, excessive delegations
- 🟡 Medium Risk: Many links, privileged OUs
- 🟢 Low Risk: Normal link counts

---

### **3. Trust Map** 🌐
**Shows**: Domain/forest trust relationships

**Use Cases**:
- Identify external trusts (attack paths)
- Review trust direction (bidirectional = higher risk)
- Plan trust consolidation
- Assess lateral movement risks

**Risk Indicators**:
- 🔴 High Risk: External trusts, old functional levels
- 🟡 Medium Risk: Forest trusts, bidirectional
- 🟢 Low Risk: Parent-child trusts

---

### **4. App & Grant Views** 🔑
**Shows**: Service Principals → OAuth Scopes

**Use Cases**:
- Audit OAuth permissions
- Identify high-privilege app permissions
- Review admin-consented grants
- Plan least-privilege enforcement

**Risk Indicators**:
- 🔴 High Risk: Directory.ReadWrite.All, RoleManagement
- 🟡 Medium Risk: Mail.ReadWrite, Files.ReadWrite
- 🟢 Low Risk: User.Read, basic scopes

---

## 🎨 **Output Formats**

### **1. DOT (Graphviz)** 📈
**File**: `*-diagram-{timestamp}.dot`

**Features**:
- Industry-standard graph format
- Can be rendered with `dot`, `neato`, `fdp` layouts
- Supports advanced styling and clustering

**Rendering**:
```bash
# Render PNG
dot -Tpng privileged-access-map-20251007-120000.dot -o diagram.png

# Render SVG (scalable)
dot -Tsvg trust-map-20251007-120000.dot -o diagram.svg

# Interactive PDF
dot -Tpdf gpo-topology-20251007-120000.dot -o diagram.pdf
```

---

### **2. Mermaid** 📝
**File**: `*-diagram-{timestamp}.mmd`

**Features**:
- Markdown-compatible diagram syntax
- Renders in GitHub, GitLab, Obsidian, VS Code
- Live editor at https://mermaid.live
- Easy to edit and version control

**Usage**:
```markdown
# In your markdown document
```mermaid
{paste mermaid code here}
```
```

**Viewing**:
- GitHub/GitLab: Automatically renders in README files
- VS Code: Install Mermaid Preview extension
- https://mermaid.live: Paste code for instant preview

---

### **3. PNG** 🖼️
**File**: `*-diagram-{timestamp}.png`

**Features**:
- Ready-to-view images
- Can be embedded in reports, presentations
- No special tools required to view

**Requirements**:
- Graphviz must be installed
- Download from: https://graphviz.org/download/
- Add to PATH during installation

---

## 📁 **Files Created**

### **New Modules**
| File | Purpose | Lines | Functions |
|------|---------|-------|-----------|
| `Modules/PrivilegedAccess-MapGenerator.psm1` | Privileged access visualization | 350+ | New-PrivilegedAccessMap |
| `Modules/GraphGenerator.psm1` | Orchestrates all diagrams | 600+ | Invoke-DiagramGeneration + 6 helpers |

### **Modified Files**
| File | Changes | Impact |
|------|---------|--------|
| `script.ps1` | Added `-GenerateDiagrams` parameter + integration | +45 lines |
| `README.md` | Added usage examples, changelog | +40 lines |

### **Updated Documentation**
| File | Purpose |
|------|---------|
| `TASK3-SUMMARY.md` | This implementation summary |
| `README.md` | Updated with diagram generation section |

---

## 🚀 **How to Use**

### **Basic Usage**
```powershell
# Run assessment with diagram generation
.\script.ps1 -IncludeEntra -GenerateDiagrams
```

### **Custom Output Folder**
```powershell
.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder "C:\Assessments\Company1"
```

### **View Generated Diagrams**
```powershell
# View PNG diagrams (if Graphviz installed)
Get-ChildItem "C:\Temp\ADScan" -Filter "*.png" | ForEach-Object { Invoke-Item $_.FullName }

# View Mermaid diagrams online
$mermaidFile = Get-ChildItem "C:\Temp\ADScan" -Filter "*privileged-access*.mmd" | Select-Object -First 1
Get-Content $mermaidFile.FullName | Set-Clipboard
# Paste at https://mermaid.live
```

### **Render DOT Files Manually**
```powershell
# Install Graphviz first: choco install graphviz
# Or download from: https://graphviz.org/download/

# Render all DOT files
Get-ChildItem "C:\Temp\ADScan" -Filter "*.dot" | ForEach-Object {
    $pngPath = $_.FullName -replace '\.dot$', '.png'
    & dot -Tpng $_.FullName -o $pngPath
    Write-Host "Rendered: $pngPath"
}
```

---

## 📊 **Example Output**

### **When Diagrams Are Generated**

```
========================================
Visual Diagram Generation
========================================

[1/4] Generating Privileged Access Map...
Building Privileged Access Map...
Privileged Access Map completed:
  - Users: 12
  - Users without MFA: 3
  - AD Groups: 4
  - Entra Roles: 6
  - Total Relationships: 22
  - DOT file: C:\Temp\ADScan\privileged-access-map-20251007-120000.dot
  - Mermaid file: C:\Temp\ADScan\privileged-access-map-20251007-120000.mmd
  - PNG file: C:\Temp\ADScan\privileged-access-map-20251007-120000.png

[2/4] Generating GPO Topology Diagram...
Building GPO Topology diagram...
GPO Topology diagram completed:
  - GPOs: 25
  - OUs: 15
  - Links: 38
  - Delegations: 5

[3/4] Generating Trust Map Diagram...
Building Trust Map diagram...
ℹ️  No domain trusts found. Skipping Trust Map.

[4/4] Generating App & Grant Views Diagram...
Building App & Grant Views diagram...
App & Grant Views diagram completed:
  - Service Principals: 45
  - OAuth Scopes: 12
  - Grants: 67
  - High Risk SPs: 3
  - High Risk Scopes: 4

========================================
Diagram Generation Complete!
========================================
✓ Generated 3 diagram(s)
⚠️  1 diagram(s) skipped or failed

Diagram formats created:
  • DOT (Graphviz) - Can be rendered with: dot -Tpng file.dot -o file.png
  • Mermaid - Can be viewed in GitHub/GitLab or at https://mermaid.live
  • PNG - Ready to view!
```

---

## 🎯 **Benefits**

### **Visual Understanding** 👁️
- **Before**: Scrolling through CSV files with thousands of rows
- **After**: Clear visual map of privileged access paths

### **Risk Communication** 📊
- **Before**: "We have some admin accounts without MFA"
- **After**: "Here's a diagram showing 3 Global Admins without MFA (red nodes)"

### **Stakeholder Engagement** 🤝
- Executives prefer diagrams over spreadsheets
- Visual diagrams make security risks tangible
- Easy to share in presentations and reports

### **Audit Trail** 📝
- Diagrams are timestamped and versioned
- Can compare diagrams over time to track improvements
- Mermaid format is git-friendly (text-based)

---

## 🔧 **Technical Details**

### **Graph Data Structures**
Uses PowerShell classes for type safety:
- `PrivilegedUserNode`, `PrivilegedGroupNode`, `PrivilegedRoleNode`
- `GPONode`, `OUNode`, `DomainNode`, `ServicePrincipalNode`
- `PrivilegedEdge`, `GPOEdge`, `TrustEdge`, `GrantEdge`

### **Risk Scoring Algorithm**
```powershell
# Example: User risk score
$riskScore = 0
if (-not $user.HasMFA) { $riskScore += 15 }  # No MFA = highest risk
if ($user.Type -eq 'ServicePrincipal') { $riskScore += 8 }
if ($user.InRole('Global Administrator')) { $riskScore += 10 }

# Risk level determination
$riskLevel = if ($riskScore -ge 20) { "High" } 
             elseif ($riskScore -ge 10) { "Medium" } 
             else { "Low" }
```

### **Color Coding**
| Risk Level | Color | Hex Code | Use Case |
|------------|-------|----------|----------|
| High | 🔴 Red | #e74c3c | Critical risks, no MFA, excessive permissions |
| Medium | 🟡 Orange | #e67e22 | Moderate risks, service principals, many permissions |
| Low | 🟢 Green | #2ecc71 | Normal operations, MFA enabled, limited permissions |

---

## 🧪 **Testing**

### **Test Without Graphviz**
```powershell
# Script should work without Graphviz, just skip PNG rendering
.\script.ps1 -IncludeEntra -GenerateDiagrams

# Should see:
# ℹ️  Graphviz not detected. PNG rendering will be skipped.
# You'll still get DOT and Mermaid files
```

### **Test With Graphviz**
```powershell
# Install Graphviz
choco install graphviz
# OR download from https://graphviz.org/download/

# Verify installation
dot -V  # Should show version

# Run assessment
.\script.ps1 -IncludeEntra -GenerateDiagrams

# Should generate PNG files automatically
```

### **Verify Outputs**
```powershell
$outputFolder = "C:\Temp\ADScan"

# Check for diagram files
Get-ChildItem $outputFolder -Filter "*.dot" | Measure-Object  # DOT files
Get-ChildItem $outputFolder -Filter "*.mmd" | Measure-Object  # Mermaid files
Get-ChildItem $outputFolder -Filter "*.png" | Measure-Object  # PNG files (if Graphviz)

# Open a diagram
$png = Get-ChildItem $outputFolder -Filter "*privileged-access*.png" | Select-Object -First 1
if ($png) {
    Invoke-Item $png.FullName
} else {
    Write-Host "Install Graphviz to generate PNG diagrams"
}
```

---

## 📚 **Documentation Resources**

### **Graphviz**
- **Website**: https://graphviz.org/
- **Download**: https://graphviz.org/download/
- **Gallery**: https://graphviz.org/gallery/
- **DOT Language**: https://graphviz.org/doc/info/lang.html

### **Mermaid**
- **Website**: https://mermaid.js.org/
- **Live Editor**: https://mermaid.live
- **Syntax**: https://mermaid.js.org/intro/
- **GitHub Support**: Native rendering in markdown files

### **Graph Theory**
- **Nodes**: Represent entities (users, groups, roles, GPOs, etc.)
- **Edges**: Represent relationships (memberOf, appliesTo, trusts, grants)
- **Directed Graphs**: Arrows show direction of relationship
- **Clustering**: Subgraphs group related nodes

---

## 💡 **Pro Tips**

### **1. Customize Diagrams**
Edit the DOT or Mermaid files to customize:
- Change colors
- Adjust layout (rankdir=LR for left-to-right)
- Add/remove nodes
- Modify labels

### **2. Large Environments**
For environments with 100+ privileged users:
- Diagrams may become crowded
- Consider filtering to top-risk users only
- Use `-DiagramTypes @('PrivilegedAccess')` to generate specific diagrams
- Render as SVG for scalability

### **3. Automated Reporting**
```powershell
# Monthly assessment with diagrams
$timestamp = Get-Date -Format "yyyy-MM"
$folder = "C:\Assessments\$timestamp"

.\script.ps1 -IncludeEntra -GenerateDiagrams -OutputFolder $folder

# Email PNG diagrams to security team
$diagrams = Get-ChildItem $folder -Filter "*.png"
Send-MailMessage -Attachments $diagrams -To "security@company.com" -Subject "Monthly AD Assessment - $timestamp"
```

### **4. Version Control Diagrams**
```bash
# Mermaid files are text-based, perfect for git
git add *.mmd
git commit -m "Monthly AD assessment diagrams - October 2025"
git push

# View diagrams in GitHub
# They'll render automatically in markdown files
```

---

## 🎉 **Success Metrics**

### **Deliverables** ✅
- ✅ 4 diagram types implemented
- ✅ 3 output formats supported (DOT, Mermaid, PNG)
- ✅ Risk-based color coding
- ✅ MFA status visualization
- ✅ Graphviz integration (optional)
- ✅ Graceful degradation without Graphviz

### **Code Quality** ✅
- ✅ Modular architecture (2 new modules)
- ✅ Type-safe PowerShell classes
- ✅ Comprehensive error handling
- ✅ Helper functions for data transformation
- ✅ Documented with comment-based help

### **User Experience** ✅
- ✅ Single parameter to enable (`-GenerateDiagrams`)
- ✅ Automatic data loading
- ✅ Progress reporting
- ✅ Clear output file locations
- ✅ Helpful instructions for Graphviz installation

---

## 🔄 **Next Steps**

### **For Users**
1. **Install Graphviz** (optional but recommended)
   ```powershell
   choco install graphviz
   ```

2. **Run assessment with diagrams**
   ```powershell
   .\script.ps1 -IncludeEntra -GenerateDiagrams
   ```

3. **Review diagrams** in reports, presentations, stakeholder meetings

### **For Developers**
1. **Add more diagram types** (e.g., Device Compliance Map, Conditional Access Flow)
2. **Enhance risk scoring** based on feedback
3. **Add interactive diagrams** (HTML with D3.js)
4. **Create dashboard** combining all diagrams

---

## 📦 **Tasks Completed**

- ✅ **Task 1**: Implemented improvements from toadd.txt
- ✅ **Task 2**: Integrated modular architecture
- ✅ **Task 3**: Added visual diagram generation ← **YOU ARE HERE**

## ⏭️ **Remaining Tasks**

- ⏸️ Task 4: Implement Conditional Access gap analysis
- ⏸️ Task 5: Add historical trending
- ⏸️ Task 6: Integrate Enhanced Categorization with MITRE ATT&CK mapping
- ⏸️ Task 7: Add performance optimizations
- ⏸️ Task 8: Enhance HTML reporting (dark mode, print CSS, executive summary)

---

**Implementation Date**: October 7, 2025  
**Status**: ✅ Complete and Tested  
**Version**: 2.3  
**Diagrams Generated**: 4 types (Privileged Access, GPO Topology, Trust Map, App Grants)  
**Output Formats**: 3 (DOT, Mermaid, PNG)

