# How to Fix Your AD Review Directory

## 🔴 PROBLEM

You're getting errors like:
```
WARNING: The term 'Get-NumericRiskScore' is not recognized...
WARNING: Executive brief export failed...
Unexpected token in expression or statement...
```

**Root Cause:** Unicode emoji and special characters in PowerShell files that cause parsing errors.

---

## ✅ SOLUTION - Two Options:

### **Option 1: Use the Universal Fix Script (RECOMMENDED)**

#### Step 1: Copy the fix script to YOUR directory
```powershell
Copy-Item "C:\Users\reddog\Projects\Projects\AD_review\COPY-THIS-TO-YOUR-DIRECTORY.ps1" "C:\Users\ivolovnik\adreview\"
```

#### Step 2: Run it in YOUR directory
```powershell
cd C:\Users\ivolovnik\adreview
powershell -ExecutionPolicy Bypass -File .\COPY-THIS-TO-YOUR-DIRECTORY.ps1
```

#### Step 3: Run your assessment
```powershell
.\script.ps1 -IncludeEntra
```

---

### **Option 2: Copy ALL Fixed Files**

Simply copy the entire fixed project to replace your broken files:

```powershell
# Backup your current directory first
Copy-Item "C:\Users\ivolovnik\adreview" "C:\Users\ivolovnik\adreview.backup" -Recurse -Force

# Copy all fixed files from the working directory
Copy-Item "C:\Users\reddog\Projects\Projects\AD_review\*" "C:\Users\ivolovnik\adreview\" -Recurse -Force

# Run your assessment
cd C:\Users\ivolovnik\adreview
.\script.ps1 -IncludeEntra
```

---

## 🔍 What Gets Fixed?

The fix script removes these problematic characters from ALL `.ps1` and `.psm1` files:

### Emojis Removed:
- 🔴🟡🟢 (colored circles) → `[H]` `[M]` `[L]`
- 🔐 (lock) → `[MFA]`
- ⚠️ (warning) → `[!]`
- ✓✔ (checkmarks) → `[OK]`
- ✗✘ (x marks) → `[X]`
- 🎯📊💡📈🖨📄📁🔧🔍🛡 → (removed)

### Special Characters Fixed:
- `→←↑↓↔` (arrows) → `->, <-, (+), (-), <->`
- `≥≤` (comparison) → `or more, or less`
- `•◦▪▫` (bullets) → `-`
- `ℹ️` (info) → `[INFO]`

---

## 📊 Expected Results

After running the fix:

```
Found XX PowerShell files
Files fixed: XX
Files unchanged: XX

[SUCCESS] All files processed successfully!
```

Then when you run your assessment:

```
Loading modules from: ...
  [OK] Loaded: Helpers
  [OK] Loaded: AD-Collector
  [OK] Loaded: Entra-Collector
  [OK] Loaded: MITRE-Mapper

Enriching findings with MITRE ATT&CK mappings...
  [OK] Enriched XX findings with MITRE mappings

[OK] Excel workbook created
[OK] Executive brief created

Assessment Complete!
```

---

## 🐛 Troubleshooting

If you still get errors after running the fix:

1. **Check your PowerShell version:**
   ```powershell
   $PSVersionTable.PSVersion
   ```
   Should be 5.1 or higher

2. **Try running from the fixed directory:**
   ```powershell
   cd C:\Users\reddog\Projects\Projects\AD_review
   .\script.ps1 -IncludeEntra
   ```

3. **Validate syntax manually:**
   ```powershell
   cd C:\Users\ivolovnik\adreview
   powershell -Command "$errors = $null; $tokens = $null; [System.Management.Automation.Language.Parser]::ParseFile('.\script.ps1', [ref]$tokens, [ref]$errors); if ($errors.Count -eq 0) { Write-Host 'VALID' -ForegroundColor Green } else { $errors | ForEach-Object { Write-Host \"Line $($_.Extent.StartLineNumber): $($_.Message)\" -ForegroundColor Red } }"
   ```

---

## ✅ Verification

After fixing, these commands should work WITHOUT errors:

```powershell
cd C:\Users\ivolovnik\adreview

# Basic test
.\script.ps1

# Full test with Entra
.\script.ps1 -IncludeEntra

# With diagrams
.\script.ps1 -IncludeEntra -GenerateDiagrams
```

---

## 📞 Need Help?

If you're still getting errors after running the fix script, the issue might be:

1. **Different PowerShell version** - Ensure you're using PowerShell 5.1+
2. **File encoding** - Ensure files are UTF-8 encoded
3. **Missing modules** - Ensure all required PS modules are installed (ActiveDirectory, Microsoft.Graph.*)

The fix script creates `.bak` backups of all modified files, so you can always restore if needed!

