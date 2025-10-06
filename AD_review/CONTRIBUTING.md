# Contributing to AD Security Assessment Tool

Thank you for your interest in contributing! This project aims to provide a comprehensive, open-source security assessment tool for Active Directory and Entra ID environments.

## 🤝 How to Contribute

### Reporting Bugs
If you find a bug, please open an issue with:
- **Description**: Clear description of the issue
- **Steps to Reproduce**: How to reproduce the behavior
- **Expected Behavior**: What you expected to happen
- **Environment**: PowerShell version, OS version, module versions
- **Error Messages**: Any error messages or logs

### Suggesting Features
Feature requests are welcome! Please open an issue with:
- **Use Case**: Describe the problem you're trying to solve
- **Proposed Solution**: Your idea for how to implement it
- **Alternatives**: Any alternative solutions you've considered
- **Priority**: Why this feature would be valuable

### Contributing Code

#### Before You Start
1. Check existing issues to see if someone is already working on it
2. For major changes, open an issue first to discuss your approach
3. Fork the repository and create a feature branch

#### Development Guidelines

**Code Style:**
- Use PowerShell best practices (follow PSScriptAnalyzer recommendations)
- Add comment-based help for new functions
- Use meaningful variable names
- Keep functions focused and under 100 lines when possible

**Testing:**
- Test your changes in a lab environment first
- Verify the script works with both `-IncludeEntra` and AD-only modes
- Ensure backwards compatibility with existing outputs

**Documentation:**
- Update README.md if you add new features
- Update QUICKSTART.md for user-facing changes
- Add inline comments for complex logic
- Update the TODO.md file if relevant

#### Pull Request Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write clean, documented code
   - Follow existing code patterns
   - Test thoroughly

3. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add feature: brief description"
   ```

4. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Include test results or screenshots if applicable

## 🎯 Areas We'd Love Help With

### High Priority
- [ ] Additional security risk rules
- [ ] Performance optimization for large environments (>10k users)
- [ ] Cross-platform testing (PowerShell Core on Linux/Mac)
- [ ] Unit tests using Pester

### Medium Priority
- [ ] Historical trending and comparison features
- [ ] Enhanced conditional access gap analysis
- [ ] PIM (Privileged Identity Management) analysis
- [ ] PowerBI dashboard templates

### Documentation
- [ ] Video tutorials
- [ ] Blog posts about using the tool
- [ ] Translations to other languages
- [ ] Example reports and use cases

## 📋 Adding New Security Rules

To add a new security analysis rule, follow this pattern:

```powershell
# In the Analyze-Inventory function (around line 360+)

# Load your data source
$myData = Import-Csv (Join-Path $OutputFolder "my-data-*.csv")

# Analyze and create findings
if ($myData | Where-Object { $_.SomeRiskyCondition }) {
    $findings.Add([pscustomobject]@{
        Area = 'Security Category'
        Finding = 'Clear description of the issue'
        Severity = 'High|Medium|Low'
        Evidence = 'reference-to-data-file.csv'
    })
}
```

## 🐛 Code Quality

### Before Submitting
Run PSScriptAnalyzer to check for issues:
```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path .\script.ps1 -Recurse
```

### Severity Levels
Use these guidelines for risk severity:
- **High**: Immediate security risk, requires urgent action
  - Example: krbtgt password >180 days, unconstrained delegation
- **Medium**: Security concern, should be addressed soon
  - Example: Stale accounts, password never expires
- **Low**: Hygiene item, address when convenient
  - Example: Unlinked GPOs, cleanup candidates

## 🔒 Security Considerations

### Handling Sensitive Data
- **Never commit actual assessment results** to the repository
- **Don't include real credentials, domains, or usernames** in code or examples
- **Use generic examples** (e.g., contoso.com, example.org)
- Test data should be sanitized or synthetic

### Safe Coding Practices
- All operations should be **read-only** by default
- Clearly document any operations that modify AD or Entra
- Use `-WhatIf` and `-Confirm` for any destructive actions
- Handle errors gracefully without exposing sensitive information

## 📖 Documentation Standards

### README Updates
- Keep feature lists up to date
- Update version numbers
- Document new parameters or options
- Include examples for new features

### Code Comments
```powershell
<#
.SYNOPSIS
  Brief description of what the function does

.DESCRIPTION
  Detailed description of functionality

.PARAMETER ParameterName
  Description of the parameter

.EXAMPLE
  .\script.ps1 -ExampleParameter "value"
  Description of what this example does

.NOTES
  Any additional notes, limitations, or requirements
#>
```

## 🌟 Recognition

Contributors will be:
- Listed in the README.md Contributors section
- Mentioned in release notes for significant contributions
- Acknowledged in related blog posts or presentations

## ❓ Questions?

- Open an issue for questions about contributing
- Check existing issues and pull requests for similar discussions
- Review the README.md and other documentation first

## 📜 Code of Conduct

### Our Pledge
We are committed to providing a welcoming and inclusive environment for all contributors.

### Our Standards
- **Be respectful** of differing viewpoints and experiences
- **Be collaborative** and constructive in discussions
- **Be professional** in all interactions
- **Be patient** with new contributors

### Unacceptable Behavior
- Harassment, discrimination, or offensive comments
- Personal attacks or trolling
- Publishing others' private information
- Other conduct inappropriate in a professional setting

## 📊 Project Roadmap

See [TODO.md](TODO.md) for our current roadmap and priorities.

---

**Thank you for contributing to making Active Directory and Entra ID environments more secure!** 🔒✨

