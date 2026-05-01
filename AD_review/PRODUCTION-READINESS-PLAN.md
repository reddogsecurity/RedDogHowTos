# 🚀 AD-Review: Production Readiness Plan

**Date:** May 1, 2026  
**Status:** Strategic Planning Phase  
**Target:** Enterprise-grade AD security tool with emergency response capabilities

---

## 📊 Current State vs. Target

### Current Capabilities ✅
- ✅ AD & Entra ID security assessment
- ✅ Risk scoring & MITRE ATT&CK mapping
- ✅ Report generation (Excel, HTML, diagrams)
- ✅ Mimecast integration (basic)
- ✅ .NET REST API backend with SignalR
- ✅ Daily alerting system

### Missing Capabilities ❌ (Your Requirements)
1. ❌ Non-service-account execution (certificate-based)
2. ❌ Interactive menu system (choose what to run)
3. ❌ Modular report selection
4. ❌ **CrowdStrike Falcon API integration**
5. ❌ **Session revocation** (AD & Entra)
6. ❌ **Email removal** (soft/hard delete from mailboxes)
7. ❌ **User emergency disable** + move to CyberIncident OU
8. ❌ **Scheduled execution** (Windows service/task)
9. ❌ **Certificate enrollment & deployment**
10. ❌ Published application (standalone executable)

---

## 🎯 Implementation Roadmap

### **PHASE 1: Foundation & Emergency Response (Weeks 1-2)**

#### 1.1 Interactive Menu System
**Goal:** Users see menu on startup to choose what to run  
**Current File:** `script.ps1`  
**Changes Needed:**
```powershell
# Add to script.ps1 top-level execution
function Show-MainMenu {
    Write-Host "`n=== AD Security Assessment Tool ===" -ForegroundColor Cyan
    Write-Host "1. Run Full Security Assessment"
    Write-Host "2. Select Specific Reports"
    Write-Host "3. Emergency Response"
    Write-Host "4. View Scheduled Runs"
    Write-Host "5. Settings & Configuration"
    Write-Host "Q. Quit"
}
```
**Output:** Create `Interactive-Menu.ps1` module

#### 1.2 Modular Report Selection
**Goal:** Users choose which checks/reports to run  
**New File:** `Report-Selector.ps1`  
**Reports Available:**
- [ ] Identity Hygiene Report
- [ ] Privileged Access Report
- [ ] Zero Trust Readiness Report
- [ ] Network Graph Visualization
- [ ] Executive Brief
- [ ] Trend Analysis
- [ ] MITRE ATT&CK Mapping
- [ ] Device Posture Report
- [ ] Conditional Access Analysis
- [ ] Password Policy Assessment

#### 1.3 Certificate-Based Authentication
**Goal:** Run without service account; use certificate instead  
**Implementation:**
- Create `Setup-Certificates.ps1` for certificate enrollment
- Use Azure Key Vault OR Local CA
- Modify all credential handling to use certificates
- **Files to Update:**
  - `Modules/AD-Collector.psm1` - Use cert auth for AD
  - `Modules/Entra-Collector.psm1` - Use Microsoft.Graph with cert
  - Create `Auth-Manager.psm1` - Centralized certificate handling

#### 1.4 Emergency Response System
**Goal:** Quick actions for incident response  
**New File:** `Emergency-Response.ps1`  
**Functions Needed:**
```powershell
# Session Revocation
Invoke-SessionRevocation -UserSAMAccountName "attacker@domain" -Type Both  # AD + Entra

# User Disable & Move
Invoke-UserEmergencyDisable -UserSAMAccountName "compromised-user" `
    -TargetOU "OU=CyberIncident,OU=Disabled,DC=domain,DC=com" `
    -RevokeAllSessions $true

# Email Management (via Mimecast)
Invoke-EmailRemoval -UserEmail "compromised@domain.com" -Type "SoftDelete" # or "HardDelete"
```

---

### **PHASE 2: API Integrations (Weeks 2-3)**

#### 2.1 CrowdStrike Falcon API
**Goal:** Query agent status, detect threats, retrieve incidents  
**New Module:** `Modules/CrowdStrike-Connector.psm1`  
**Functions:**
```powershell
Get-CrowdStrikeAgents -FilterOnline $true
Get-CrowdStrikeDetections -UserId $user.ObjectId
Get-CrowdStrikeIncidents -SortBy "created_timestamp" -SortDirection "DESC"
```
**Implementation Details:**
- OAuth 2.0 client credentials flow
- Store API keys in secure vault
- Cache agent list (30 min TTL)
- Real-time threat correlation

#### 2.2 Mimecast Advanced Operations
**Goal:** Email removal, archiving, mailbox operations  
**Update File:** `Modules/Mimecast-Analyzer.psm1`  
**New Functions:**
```powershell
# Email Operations
Remove-MimecastEmails -UserEmail "user@company.com" -Query "from:attacker@evil.com" -Type "SoftDelete"
Remove-MimecastEmails -UserEmail "user@company.com" -Query "subject:invoice" -Type "HardDelete"

# Mailbox Operations
Suspend-MimecastMailbox -UserEmail "compromised@company.com"
Resume-MimecastMailbox -UserEmail "recovered@company.com"

# Search & Compliance
Get-MimecastEmailsByDateRange -UserEmail "user@company.com" -StartDate "2026-04-01" -EndDate "2026-05-01"
```

#### 2.3 Exchange Online Integration
**Goal:** Mailbox operations via Microsoft Graph  
**New Module:** `Modules/Exchange-Operations.psm1`  
**Functions:**
```powershell
Remove-EmailsFromMailbox -UserPrincipalName "user@company.com" `
    -SenderEmail "attacker@evil.com" `
    -DeleteType "SoftDelete"  # "HardDelete" for immediate deletion

Suspend-Mailbox -UserPrincipalName "user@company.com" -Reason "Security Investigation"
Resume-Mailbox -UserPrincipalName "user@company.com"
```

#### 2.4 Entra ID Session Management
**Goal:** Revoke all sessions for a user  
**Update File:** `Modules/Entra-Collector.psm1`  
**New Functions:**
```powershell
Invoke-EntraIdSessionRevocation -UserId "user@domain.com"  # Azure CLI: az ad user invalidate-all-refresh-tokens
```

---

### **PHASE 3: Deployment & Scheduling (Week 3-4)**

#### 3.1 Windows Service Installation
**Goal:** Run tool as scheduled service without service account  
**New Files:**
- `Deploy-AsService.ps1` - Service installation script
- `.NET Windows Service` - Wrapper around PowerShell

**Service Details:**
```
Service Name: ADSecurityMap
Display Name: AD Security Assessment Service
Startup Type: Automatic (Delayed)
Run As: Local System (with certificate auth)
Schedule: Daily 2:00 AM UTC
Recovery: Auto-restart on failure
```

#### 3.2 Certificate Enrollment
**Goal:** Automatic certificate enrollment for authentication  
**New File:** `Setup-CertificateEnrollment.ps1`  
**Process:**
1. Request certificate from AD CA (automatically)
2. Store in Local System certificate store
3. Configure renewal 30 days before expiry
4. Use for all API authentication

#### 3.3 Scheduled Task Creation
**Goal:** Create recurring assessment runs  
**New File:** `Create-ScheduledTasks.ps1`  
**Tasks to Create:**
```
FullAssessment     - Daily 2:00 AM (Full AD + Entra scan)
QuickCheck         - Every 4 hours (Risk score only)
AlertGeneration    - Daily 8:00 AM (Send alerts)
DataCleanup        - Weekly Sunday 1:00 AM (Archive old reports)
```

#### 3.4 Application Publishing
**Goal:** Standalone executable (no PowerShell required to run)  
**Approach:**
- Create .NET wrapper (`ADSecurityMap.Console.exe`)
- Bundle PowerShell scripts as resources
- Dotnet publish as self-contained app
- Single executable deployment

---

### **PHASE 4: Architecture Updates (Week 4)**

#### 4.1 Update .NET Backend
**File:** `AD-Map-Backend/Program.cs`  
**New Controllers:**
```csharp
// Emergency operations
[Route("api/[controller]")]
public class EmergencyController : ControllerBase
{
    [HttpPost("disable-user/{userId}")]
    public async Task<IActionResult> DisableUserEmergency(string userId)
    
    [HttpPost("revoke-sessions/{userId}")]
    public async Task<IActionResult> RevokeUserSessions(string userId)
}

// Report operations
[Route("api/[controller]")]
public class ReportsController : ControllerBase
{
    [HttpGet("available")]
    public async Task<IActionResult> GetAvailableReports()
    
    [HttpPost("generate")]
    public async Task<IActionResult> GenerateSelectedReports([FromBody] ReportRequest request)
}

// Integration operations
[Route("api/[controller]")]
public class IntegrationsController : ControllerBase
{
    [HttpGet("crowdstrike/agents")]
    public async Task<IActionResult> GetCrowdStrikeAgents()
    
    [HttpGet("mimecast/status/{userEmail}")]
    public async Task<IActionResult> GetMimecastStatus(string userEmail)
}
```

#### 4.2 New .NET Services
**Create:**
- `CrowdStrikeService.cs` - API integration
- `EmergencyResponseService.cs` - Revocation & disable logic
- `EmailOperationsService.cs` - Mimecast & Exchange operations
- `CertificateAuthService.cs` - Certificate-based auth
- `ScheduledExecutionService.cs` - Task scheduling

#### 4.3 Configuration Management
**Update:** `appsettings.json`
```json
{
  "CrowdStrike": {
    "ClientId": "${CROWDSTRIKE_CLIENT_ID}",
    "ClientSecret": "${CROWDSTRIKE_CLIENT_SECRET}",
    "BaseUrl": "https://api.crowdstrike.com"
  },
  "Mimecast": {
    "AppId": "${MIMECAST_APP_ID}",
    "AppKey": "${MIMECAST_APP_KEY}",
    "BaseUrl": "https://us-api.mimecast.com"
  },
  "Exchange": {
    "TenantId": "${AZURE_TENANT_ID}",
    "ClientId": "${AZURE_CLIENT_ID}",
    "CertificateThumbprint": "${CERT_THUMBPRINT}"
  },
  "Scheduling": {
    "FullAssessment": "0 2 * * *",      // Daily 2 AM
    "QuickCheck": "0 */4 * * *",        // Every 4 hours
    "AlertGeneration": "0 8 * * *"      // Daily 8 AM
  }
}
```

---

## 🔧 Technical Implementation Details

### Authentication Flow (Certificate-Based)
```
1. Service starts (Local System)
2. Loads certificate from Local System store
3. Uses cert for:
   - AD: Kerberos delegation or certificate auth
   - Azure: Azure AD certificate authentication
   - APIs: mTLS or bearer token from cert
4. No plaintext passwords stored anywhere
```

### Emergency Response Workflow
```
User triggers emergency response
    ↓
Show confirmation dialog (prevent accidents)
    ↓
Disable user in AD (set accountDisabled = $true)
    ↓
Move to CyberIncident OU
    ↓
Revoke Entra ID sessions (invalidate refresh tokens)
    ↓
Revoke AD sessions (logoff all sessions)
    ↓
Suspend mailbox in Exchange
    ↓
Remove recent emails via Mimecast
    ↓
Query CrowdStrike for agent status
    ↓
Generate incident report
    ↓
Send alerts to SOC team
    ↓
Log all actions to audit trail
```

---

## 📁 New File Structure

```
AD_review/
│
├── 🎮 Interactive UI
│   ├── Interactive-Menu.ps1
│   ├── Report-Selector.ps1
│   └── Settings-Manager.ps1
│
├── 🚨 Emergency Response
│   ├── Emergency-Response.ps1
│   ├── Session-Revocation.ps1
│   └── User-Deprovisioning.ps1
│
├── 🔐 Authentication & Certificates
│   ├── Setup-Certificates.ps1
│   ├── Certificate-Manager.ps1
│   └── Modules/Auth-Manager.psm1
│
├── 🌐 API Integrations (New Modules)
│   ├── Modules/CrowdStrike-Connector.psm1
│   ├── Modules/Exchange-Operations.psm1
│   ├── Modules/Mimecast-Advanced.psm1
│   └── Modules/Entra-SessionMgmt.psm1
│
├── ⏱️ Scheduling & Deployment
│   ├── Deploy-AsService.ps1
│   ├── Create-ScheduledTasks.ps1
│   └── Setup-Deployment.ps1
│
├── 📦 Backend (AD-Map-Backend/)
│   ├── Controllers/
│   │   ├── EmergencyController.cs (NEW)
│   │   ├── ReportsController.cs (NEW)
│   │   └── IntegrationsController.cs (NEW)
│   ├── Services/
│   │   ├── CrowdStrikeService.cs (NEW)
│   │   ├── EmergencyResponseService.cs (NEW)
│   │   ├── EmailOperationsService.cs (NEW)
│   │   └── CertificateAuthService.cs (NEW)
│   └── appsettings.json (UPDATE)
│
└── 📚 Documentation (Update)
    ├── PRODUCTION-READINESS-PLAN.md (THIS FILE)
    ├── IMPLEMENTATION-GUIDE.md
    ├── DEPLOYMENT-GUIDE.md
    └── EMERGENCY-PROCEDURES.md
```

---

## 🎯 Success Criteria

### Phase 1 Complete When:
- ✅ Interactive menu appears on startup
- ✅ Users can select which reports to run
- ✅ Certificate enrollment works without service account
- ✅ Emergency disable/revoke functions operational

### Phase 2 Complete When:
- ✅ CrowdStrike agents visible in tool
- ✅ Email deletion works via Mimecast
- ✅ Exchange mailbox operations functional
- ✅ Session revocation (Entra ID + AD) works

### Phase 3 Complete When:
- ✅ Runs as Windows service automatically
- ✅ Scheduled tasks execute on schedule
- ✅ Published as standalone .NET executable
- ✅ No external dependencies (PowerShell optional)

### Phase 4 Complete When:
- ✅ All new API controllers tested & documented
- ✅ Configuration management centralized
- ✅ Error handling & logging comprehensive
- ✅ Unit tests for critical paths
- ✅ Enterprise deployment guide complete

---

## 📋 Risk Mitigation

### Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Credential leakage | Use certificates only, never plaintext passwords |
| Accidental user disable | Add confirmation prompts, audit logging |
| Emergency actions blocked | Create whitelist of authorized users |
| Service won't start | Self-health checks, automatic recovery |
| API rate limits | Implement backoff & queue system |
| Certificate expiry | Auto-renewal 30 days before expiry |
| Data exposure in reports | Redact PII, encrypt sensitive data |
| Audit trail loss | Separate immutable audit database |

---

## 📅 Timeline Estimate

| Phase | Duration | Start | End | Complexity |
|-------|----------|-------|-----|------------|
| Phase 1 | 2 weeks | Week 1 | Week 2 | Medium |
| Phase 2 | 2 weeks | Week 2 | Week 3 | High |
| Phase 3 | 1.5 weeks | Week 3 | Week 4 | Medium |
| Phase 4 | 1 week | Week 4 | Week 5 | Medium |
| **Total** | **~5 weeks** | - | - | - |

---

## 💡 Next Steps

1. **Review this plan** - Validate priorities & timeline
2. **Approve API integrations** - CrowdStrike, Mimecast, Exchange authentication details
3. **Setup dev environment** - Ensure all APIs accessible in test environment
4. **Start Phase 1** - Begin with interactive menu system
5. **Establish source control** - Ensure all code properly versioned
6. **Create deployment procedures** - Document setup for production

---

## 🤝 Questions & Clarifications Needed

Before starting implementation, please confirm:

1. **CrowdStrike:**
   - [ ] API credentials available?
   - [ ] License includes API access?
   - [ ] Preferred authentication method (OAuth vs API keys)?

2. **Mimecast:**
   - [ ] Current integration working? (I see modules exist)
   - [ ] Hard delete vs soft delete preferences?
   - [ ] API rate limits documented?

3. **Exchange Online:**
   - [ ] Tenant ID available?
   - [ ] Service principal with mail delete permissions?
   - [ ] On-premises Exchange or pure cloud?

4. **Certificate Authority:**
   - [ ] Using Active Directory PKI or Azure Key Vault?
   - [ ] Template available for service certificates?
   - [ ] Auto-enrollment configured?

5. **Deployment:**
   - [ ] Windows Server 2019+ for service? Or cloud deployment?
   - [ ] Prefer Windows Service or PowerShell scheduled tasks?
   - [ ] GUI menu or CLI menu preferred?

---

## 📞 Support & Questions

This document is the master plan. Will be updated as implementation progresses.
