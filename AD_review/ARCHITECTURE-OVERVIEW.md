# AD Security Tool - Architecture Overview

## System Architecture (Target State)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE LAYER                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌────────────────┐ │
│  │  Interactive Menu    │  │  Web Dashboard       │  │  Windows GUI   │ │
│  │  (CLI - Main)        │  │  (HTML5 - Future)    │  │  (Future)      │ │
│  └──────────┬───────────┘  └──────────┬───────────┘  └────────┬───────┘ │
│             │                        │                        │          │
└─────────────┼────────────────────────┼────────────────────────┼──────────┘
              │                        │                        │
┌─────────────┼────────────────────────┼────────────────────────┼──────────┐
│             │                        │                        │          │
│             ▼                        ▼                        ▼          │
│  ┌──────────────────────────────────────────────────────────────┐       │
│  │        PowerShell Orchestration Layer                       │       │
│  │  (script.ps1, Run-Assessment.ps1, Emergency-Response.ps1) │       │
│  └───────────┬──────────────────────────────────────┬──────────┘       │
│              │                                      │                   │
│    ┌─────────▼─────────┐               ┌──────────▼──────────┐        │
│    │ Menu System       │               │ Report Selection    │        │
│    │ - Main Menu       │               │ - Checkbox UI       │        │
│    │ - Emergency Menu  │               │ - Selected Reports  │        │
│    │ - Settings Menu   │               │ - Execution Flow    │        │
│    └───────────────────┘               └─────────────────────┘        │
│                                                                       │
│  APPLICATION LOGIC LAYER                                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    PowerShell Modules                        │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │                                                              │   │
│  │ Data Collection:                                            │   │
│  │  - AD-Collector.psm1        ┐                              │   │
│  │  - Entra-Collector.psm1     ├─► Analysis & Enrichment     │   │
│  │  - ThreatHunting-Collector  │                             │   │
│  │                             ▼                             │   │
│  │                ┌────────────────────────┐                 │   │
│  │                │ MITRE-Mapper.psm1      │                 │   │
│  │                │ (Risk Scoring)         │                 │   │
│  │                └────────────────────────┘                 │   │
│  │                                                             │   │
│  │ Integration Modules:                                        │   │
│  │  - Mimecast-Collector.psm1                                │   │
│  │  - CrowdStrike-Connector.psm1      (NEW)                  │   │
│  │  - Exchange-Operations.psm1        (NEW)                  │   │
│  │                                                             │   │
│  │ Operations:                                                 │   │
│  │  - Emergency-Response.psm1         (NEW)                  │   │
│  │  - Session-Revocation.psm1         (NEW)                  │   │
│  │  - User-Deprovisioning.psm1        (NEW)                  │   │
│  │                                                             │   │
│  │ Reporting:                                                  │   │
│  │  - Export-ExcelReport.psm1                                │   │
│  │  - Export-ExecutiveBrief.psm1                             │   │
│  │  - GraphGenerator.psm1                                    │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
              │                 │                 │
┌─────────────▼────────────────▼─────────────────▼──────────────────────┐
│                     API INTEGRATION LAYER                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────┐  ┌──────────────────────────┐            │
│  │  External APIs           │  │  Active Directory        │            │
│  ├──────────────────────────┤  ├──────────────────────────┤            │
│  │                          │  │ [Certificate Auth]       │            │
│  │ - CrowdStrike Falcon     │  │ - User operations        │            │
│  │ - Mimecast Email         │  │ - Group membership       │            │
│  │ - Microsoft Graph        │  │ - Session management     │            │
│  │ - Exchange Online        │  │ - OU operations          │            │
│  │ - Azure Key Vault        │  │                          │            │
│  │                          │  │                          │            │
│  └──────────────────────────┘  └──────────────────────────┘            │
│                                                                          │
│  ┌──────────────────────────────┐  ┌─────────────────────┐             │
│  │  .NET REST API Backend       │  │  Windows Services   │             │
│  │  (AD-Map-Backend/)           │  │  & Scheduling       │             │
│  ├──────────────────────────────┤  ├─────────────────────┤             │
│  │                              │  │                     │             │
│  │ Controllers:                 │  │ - Windows Service   │             │
│  │ - ADController              │  │ - Scheduled Tasks   │             │
│  │ - EmergencyController (NEW) │  │ - Certificate Auth  │             │
│  │ - ReportsController (NEW)   │  │                     │             │
│  │ - IntegrationsController    │  │                     │             │
│  │                              │  │                     │             │
│  │ Services:                    │  │                     │             │
│  │ - DataRefreshService        │  │                     │             │
│  │ - CrowdStrikeService (NEW) │  │                     │             │
│  │ - EmergencyResponseService  │  │                     │             │
│  │ - EmailOperationsService    │  │                     │             │
│  │ - CertificateAuthService    │  │                     │             │
│  │                              │  │                     │             │
│  │ Real-time: SignalR Hub      │  │                     │             │
│  │                              │  │                     │             │
│  └──────────────────────────────┘  └─────────────────────┘             │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
              │                        │                    │
┌─────────────▼────────────────────────▼────────────────────▼──────────┐
│                          DATA LAYER                                    │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐  │
│  │  Reporting       │  │  Assessment      │  │  Audit Trail       │  │
│  │  Database        │  │  History         │  │  (Immutable)       │  │
│  ├──────────────────┤  ├──────────────────┤  ├────────────────────┤  │
│  │                  │  │                  │  │                    │  │
│  │ Excel Reports    │  │ JSON Snapshots   │  │ Security Events    │  │
│  │ HTML Reports     │  │ Historical Data  │  │ Emergency Actions  │  │
│  │ Diagrams/Graphs  │  │ Trend Analysis   │  │ Admin Changes      │  │
│  │                  │  │                  │  │ Compliance Log     │  │
│  │                  │  │                  │  │                    │  │
│  └──────────────────┘  └──────────────────┘  └────────────────────┘  │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │  PostgreSQL Database (Optional - for long-term storage)      │   │
│  │  - Users & Groups history                                    │   │
│  │  - Risk assessments over time                               │   │
│  │  - Alert/incident correlations                              │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagrams

### 1️⃣ Normal Assessment Flow
```
User selects "Full Assessment"
        │
        ▼
Script.ps1 imports all modules
        │
        ├─► AD-Collector → Query AD (Users, Groups, Computers, GPOs, Trusts)
        │
        ├─► Entra-Collector → Query Entra ID (Users, Roles, Apps, Conditional Access)
        │
        ├─► ThreatHunting-Collector → Check for suspicious patterns
        │
        ├─► MITRE-Mapper → Enrich findings with MITRE techniques + Risk scores
        │
        ├─► Mimecast-Collector → Query email security (optional)
        │
        ├─► CrowdStrike-Connector → Get agent status & detections (NEW)
        │
        ├─► Export-ExcelReport → Generate multi-tab workbook
        │
        ├─► Export-ExecutiveBrief → Generate HTML summary
        │
        └─► GraphGenerator → Create network diagrams
                │
                ▼
        Reports saved to /Reports folder
        Notify .NET backend via SignalR
        Display results in browser or web dashboard
```

### 2️⃣ Emergency Response Flow
```
User selects "Emergency Response" → "Disable User"
        │
        ▼
Prompt for username/email
        │
        ▼
Get-ADUser (lookup)
        │
        ▼
CONFIRMATION DIALOG (prevent accidents)
        │
        ▼
[POINT OF NO RETURN]
        │
        ├─► Disable-ADAccount (AD account disabled)
        │
        ├─► Move-ADObject (→ CyberIncident OU)
        │
        ├─► Invoke-SessionRevocation (AD sessions logoff)
        │
        ├─► az ad user invalidate-all-refresh-tokens (Entra ID sessions)
        │
        ├─► CrowdStrike: Query agent status for that user
        │
        ├─► Mimecast: Suspend mailbox
        │
        ├─► New-SecurityAuditLog (log all actions)
        │
        └─► Generate-IncidentReport & send to SOC
                │
                ▼
        Action complete with full audit trail
```

### 3️⃣ API Integration Flow (Phase 2)
```
CrowdStrike Agent Query:
    PowerShell → OAuth 2.0 → CrowdStrike API → JSON Response → Cache (30 min)

Email Removal via Mimecast:
    PowerShell → API Key Auth → Mimecast API → Queue removal → Async completion
    
User Disable via Exchange:
    PowerShell → Entra ID Certificate Auth → Microsoft Graph → Suspend/Disable

Session Revocation:
    PowerShell → Azure CLI → Entra ID API → Invalidate all refresh tokens
```

---

## Authentication Strategy (Certificates)

```
┌─────────────────────────────────────────────────────────────┐
│                  CERTIFICATE-BASED AUTH                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│ Option 1: Active Directory PKI (On-Premises)               │
│  1. Admin requests cert from AD CA (template: "Service Cert")
│  2. Cert stored in Local System certificate store
│  3. Service runs as Local System
│  4. PowerShell uses cert for AD/Entra auth
│  5. Auto-renewal via Group Policy (30 days before expiry)
│                                                               │
│ Option 2: Azure Key Vault (Cloud/Hybrid)                    │
│  1. Managed Identity on Windows Server/Azure VM
│  2. Retrieve cert from Key Vault at startup
│  3. Use cert for all API authentication
│  4. Key Vault handles rotation automatically
│  5. No credentials stored locally
│                                                               │
│ Option 3: Combination (Recommended)                          │
│  1. AD PKI for local/on-prem resources
│  2. Azure Key Vault for cloud resources
│  3. Cross-trust with certificate chaining
│                                                               │
└─────────────────────────────────────────────────────────────┘

Benefits:
  ✅ No plaintext passwords anywhere
  ✅ Automatic rotation & renewal
  ✅ Auditability (certificate tracking)
  ✅ No service account needed
  ✅ Runs as Local System (highest privileges needed)
  ✅ API keys stored in secure vault, not code
```

---

## Deployment Architecture

```
┌──────────────────────────────────┐
│   PRODUCTION DEPLOYMENT          │
├──────────────────────────────────┤
│                                  │
│  Windows Server 2019/2022        │
│  ┌────────────────────────────┐  │
│  │ AD Security Map Service    │  │
│  ├────────────────────────────┤  │
│  │ Run As: Local System       │  │
│  │ Startup: Automatic         │  │
│  │ RecoveryMode: Auto-restart │  │
│  │                            │  │
│  │ ┌──────────────────────┐   │  │
│  │ │ PowerShell Runner    │   │  │
│  │ │ (Full Assessment)    │   │  │
│  │ │                      │   │  │
│  │ │ Schedule: Daily 2 AM │   │  │
│  │ │ Duration: ~30 min    │   │  │
│  │ └──────────────────────┘   │  │
│  │                            │  │
│  │ ┌──────────────────────┐   │  │
│  │ │ .NET REST API        │   │  │
│  │ │ Port 5001 (HTTPS)    │   │  │
│  │ │ Swagger Docs: /      │   │  │
│  │ │ Health Check: /health│   │  │
│  │ └──────────────────────┘   │  │
│  │                            │  │
│  │ ┌──────────────────────┐   │  │
│  │ │ SignalR Hub          │   │  │
│  │ │ Real-time Alerts     │   │  │
│  │ │ /adhub               │   │  │
│  │ └──────────────────────┘   │  │
│  │                            │  │
│  │ ┌──────────────────────┐   │  │
│  │ │ Reports Directory    │   │  │
│  │ │ /Reports/            │   │  │
│  │ │ .xlsx, .html, .json  │   │  │
│  │ └──────────────────────┘   │  │
│  │                            │  │
│  │ ┌──────────────────────┐   │  │
│  │ │ Logs Directory       │   │  │
│  │ │ /Logs/               │   │  │
│  │ │ Audit trail          │   │  │
│  │ │ Application logs     │   │  │
│  │ └──────────────────────┘   │  │
│  │                            │  │
│  │ Certificates:              │  │
│  │ ┌──────────────────────┐   │  │
│  │ │ Local System Store   │   │  │
│  │ │ Subject: ADSecMap-SVC│   │  │
│  │ │ Issued By: Corp CA   │   │  │
│  │ │ Valid: 3 years       │   │  │
│  │ │ Auto-renew: 30d      │   │  │
│  │ └──────────────────────┘   │  │
│  │                            │  │
│  └────────────────────────────┘  │
│                                  │
│  Reverse Proxy (Traefik/nginx)   │
│  ┌────────────────────────────┐  │
│  │ api.company.com            │  │
│  │ → https://localhost:5001   │  │
│  │                            │  │
│  │ TLS Termination            │  │
│  │ Rate Limiting              │  │
│  │ Authentication             │  │
│  └────────────────────────────┘  │
│                                  │
│  Database Connections:           │
│  ✓ Active Directory (LDAP)       │
│  ✓ Entra ID (Microsoft.Graph)    │
│  ✓ CrowdStrike (REST API)        │
│  ✓ Mimecast (REST API)           │
│  ✓ Exchange Online (REST API)    │
│  ✓ PostgreSQL (optional)         │
│                                  │
└──────────────────────────────────┘
```

---

## Scheduled Tasks Configuration

```
Task 1: Full Daily Assessment
┌─────────────────────────────────────┐
│ Name: AD-FullAssessment             │
│ Trigger: Daily at 2:00 AM UTC       │
│ Run As: Local System                │
│ Action: PowerShell -File script.ps1 │
│           -IncludeEntra             │
│           -GenerateDiagrams         │
│           -Full                     │
│ Repeat: Every 24 hours              │
│ Duration: ~30 minutes               │
│ Retry: 3 times on failure           │
│ Notification: Email on failure      │
└─────────────────────────────────────┘

Task 2: Quick Risk Check
┌─────────────────────────────────────┐
│ Name: AD-QuickCheck                 │
│ Trigger: Every 4 hours (6x daily)   │
│ Run As: Local System                │
│ Action: PowerShell -File script.ps1 │
│           -QuickCheck               │
│ Duration: ~5 minutes                │
└─────────────────────────────────────┘

Task 3: Alert Generation
┌─────────────────────────────────────┐
│ Name: AD-AlertGeneration            │
│ Trigger: Daily at 8:00 AM UTC       │
│ Run As: Local System                │
│ Action: PowerShell -File            │
│         Invoke-DailyAlert.ps1       │
│ Duration: ~10 minutes               │
│ Action: Email alerts to SOC team    │
└─────────────────────────────────────┘

Task 4: Report Cleanup
┌─────────────────────────────────────┐
│ Name: AD-ReportCleanup              │
│ Trigger: Weekly Sunday 1:00 AM      │
│ Run As: Local System                │
│ Action: Archive reports older than  │
│         30 days to archive folder   │
│ Duration: ~5 minutes                │
└─────────────────────────────────────┘
```

---

## Security & Audit Logging

```
┌────────────────────────────────────────┐
│      COMPREHENSIVE AUDIT LOGGING       │
├────────────────────────────────────────┤
│                                        │
│ Level 1: Application Logs              │
│ ├─ What ran (assessment type)          │
│ ├─ When it ran (timestamp)             │
│ ├─ How long it took                    │
│ ├─ Success/failure status              │
│ └─ File: /Logs/app-YYYY-MM-DD.log     │
│                                        │
│ Level 2: Security Audit Logs           │
│ ├─ Emergency disable actions           │
│ ├─ Session revocation events           │
│ ├─ User or group modifications         │
│ ├─ API authentication events           │
│ ├─ Failed access attempts              │
│ ├─ Who executed the action             │
│ └─ File: /Logs/security-audit-*.log   │
│                                        │
│ Level 3: API Integration Logs          │
│ ├─ CrowdStrike queries                 │
│ ├─ Mimecast operations                 │
│ ├─ Exchange Online changes             │
│ ├─ Rate limit hit events               │
│ ├─ Timeout/retry events                │
│ └─ File: /Logs/api-integration-*.log  │
│                                        │
│ Level 4: Error Logs                    │
│ ├─ Exceptions & stack traces           │
│ ├─ Failed operations                   │
│ ├─ Authentication failures             │
│ ├─ Data validation errors              │
│ └─ File: /Logs/errors-YYYY-MM-DD.log  │
│                                        │
│ Retention Policy:                      │
│ ├─ Application logs: 30 days           │
│ ├─ Security audit: 1 year (immutable)  │
│ ├─ API logs: 90 days                   │
│ ├─ Error logs: 90 days                 │
│ └─ Archive older logs to /Archive/     │
│                                        │
└────────────────────────────────────────┘

Log Format (Security Events):
{
  "Timestamp": "2026-05-01T02:45:30Z",
  "EventType": "UserEmergencyDisable",
  "TargetUser": "john.smith",
  "TargetEmail": "john.smith@company.com",
  "ExecutedBy": "SOC-User@company.com",
  "SourceIP": "192.168.1.100",
  "Actions": [
    "Account Disabled",
    "Moved to OU: CyberIncident",
    "AD Sessions Revoked",
    "Entra ID Sessions Invalidated",
    "Mailbox Suspended",
    "Recent Emails Removed"
  ],
  "Reason": "Suspected account compromise - credential theft",
  "Status": "Success",
  "Duration": "2.3 seconds"
}
```

---

## Compliance & Security Checklist

```
✅ Authentication
  □ No plaintext passwords stored
  □ Certificate-based auth only
  □ API keys in secure vault
  □ Automatic credential rotation
  □ MFA for sensitive operations

✅ Auditing
  □ All actions logged with timestamps
  □ Who, what, when, why tracked
  □ Immutable audit trail maintained
  □ Monthly audit reviews scheduled
  □ Compliance reports auto-generated

✅ Access Control
  □ Principle of least privilege
  □ Role-based access (if multi-user)
  □ Service account locked down
  □ Whitelist for emergency actions
  □ Emergency actions require approval

✅ Data Protection
  □ Reports encrypted at rest
  □ HTTPS for all API traffic
  □ TLS 1.2 minimum enforced
  □ Sensitive data redacted from reports
  □ PII handling compliant with policy

✅ Operational
  □ Service auto-restart on failure
  □ Health checks every 5 minutes
  □ Alerts on service failure
  □ Backup of configuration & certs
  □ Disaster recovery plan documented
```

---

This architecture provides:
- 🔒 **Security**: Certificate-based auth, no credentials, full audit trails
- 🚀 **Scalability**: Modular design, API-driven operations
- 📊 **Visibility**: Real-time dashboards, historical analysis, trend tracking
- 🎯 **Reliability**: Auto-recovery, health checks, comprehensive logging
- 🛡️ **Compliance**: Full audit capabilities, secure by default
