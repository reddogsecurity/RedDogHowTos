# TODO List

## 🔥 High Priority (Next Sprint)

- [ ] **Privileged User MFA Cross-Check**
  - [ ] Join Entra role data with auth methods
  - [ ] Filter for Global/Privileged Admins
  - [ ] Flag accounts without MFA
  - [ ] Export `privileged-users-mfa-status.csv`
  - [ ] Add to HTML report findings

- [ ] **Password Policy Analysis**
  - [ ] Load AD default password policy
  - [ ] Load FGPP policies
  - [ ] Compare against NIST 800-63B recommendations
  - [ ] Generate policy recommendations
  - [ ] Add findings with severity ratings

- [ ] **App Secret/Certificate Expiration**
  - [ ] Enumerate app registrations with credentials
  - [ ] Calculate days until expiration
  - [ ] Alert on: expired, <30 days, <60 days, <90 days
  - [ ] Export `app-credentials-expiration.csv`

## 📊 Medium Priority (Next Month)

- [ ] **Conditional Access Gap Analysis**
  - [ ] Parse all CA policies
  - [ ] Identify included/excluded users & apps
  - [ ] Calculate coverage percentage
  - [ ] Flag gaps (users without CA, apps without protection)
  - [ ] Suggest missing policies

- [ ] **Historical Trending**
  - [ ] Add optional `-CompareWith` parameter
  - [ ] Load previous exports
  - [ ] Calculate KPI deltas
  - [ ] Generate trend CSV
  - [ ] Add trend section to HTML

- [ ] **PIM Analysis**
  - [ ] Check for PIM-eligible assignments
  - [ ] Compare eligible vs. permanent roles
  - [ ] Recommend PIM candidates
  - [ ] Track activation history

## 💡 Enhancement Ideas (Backlog)

- [ ] **Performance Optimization**
  - [ ] Add progress bars for long operations
  - [ ] Implement batching for large datasets
  - [ ] Add `-Fast` mode (skip detailed analysis)
  - [ ] Parallelize independent collections

- [ ] **Extended Reporting**
  - [ ] Email report option (`-SendEmail`)
  - [ ] PowerBI export format
  - [ ] Executive summary (1-page)
  - [ ] Detailed remediation playbook

- [ ] **Automation**
  - [ ] Scheduled task template
  - [ ] Auto-remediation scripts (safe items only)
  - [ ] Ticketing system integration
  - [ ] Alert thresholds (email on High findings)

- [ ] **Azure Expansion**
  - [ ] Azure subscription RBAC
  - [ ] Azure resource inventory
  - [ ] Key Vault secret rotation checks
  - [ ] NSG rule analysis

## 🐛 Known Issues to Fix

- [ ] Fix encoding issues completely (remove all Unicode dependencies)
- [ ] Handle large environments better (>10k users)
  - [ ] Implement pagination for auth methods (currently 500 user limit)
  - [ ] Add batching for Graph API calls
- [ ] Add better error handling for missing permissions
- [ ] Improve progress visibility during collection

## ✅ Completed (Archive)

- [x] Merge script2.ps1 into script.ps1
- [x] Add MFA/auth methods collection
- [x] Implement RBAC seed role clustering
- [x] Add GPO modernization analysis
- [x] Create comprehensive HTML report
- [x] Export strategic CSV artifacts
- [x] Add Zero Trust readiness checks
- [x] Fix PowerShell parsing errors
- [x] Create README.md
- [x] Create QUICKSTART.md
- [x] Create PROGRESS.md
- [x] Document all features

---

## 📅 Sprint Planning

### **Current Sprint** (Oct 3-10, 2025)
Focus: Enhanced analysis & MFA coverage

**Goals**:
1. Privileged user MFA cross-check
2. Password policy analysis
3. App credential expiration tracking

**Success Criteria**:
- All High priority items completed
- HTML report includes new findings
- CSV exports available for all new analyses

### **Next Sprint** (Oct 10-17, 2025)
Focus: Gap analysis & trending

**Goals**:
1. Conditional Access gap analysis
2. Historical trending implementation
3. Performance optimization

---

## 🎯 Quick Wins (Can Do Anytime)

- [ ] Add more KPIs to dashboard
  - [ ] Avg password age
  - [ ] MFA adoption percentage
  - [ ] CA policy count
- [ ] Improve HTML styling
  - [ ] Add dark mode toggle
  - [ ] Responsive design for mobile
  - [ ] Print-friendly CSS
- [ ] Add filters to analysis
  - [ ] `-Severity High` (only show High findings)
  - [ ] `-Area "Zero Trust"` (filter by area)
- [ ] Create example outputs folder
  - [ ] Sample HTML report
  - [ ] Sample CSV artifacts
  - [ ] Screenshot for README

---

**Tip**: Check off items with `[x]` as you complete them!

