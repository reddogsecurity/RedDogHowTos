# Service Account Authentication Guide

## Problem

Microsoft Graph PowerShell modules default to **interactive authentication** (browser login prompt), which fails when:
- Running as a scheduled task
- Running as a service account
- Running in non-interactive sessions

## Solution: App Registration with Certificate Authentication

This guide shows you how to set up **non-interactive authentication** using an Azure AD App Registration with certificate-based auth. This is the **most secure and production-ready** method.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Authentication Flow                       │
│                                                              │
│  ┌──────────────┐      Certificate        ┌──────────────┐   │
│  │ Service      │    ┌─────────────┐      │ Azure AD     │   │
│  │ Account /    │───>│ App         │─────>│ (Entra ID)   │   │
│  │ Scheduled    │    │ Registration│      │              │   │
│  │ Task         │    │ + Cert      │      └──────────────┘   │
│  └──────────────┘    └─────────────┘            │            │
│                                                  │            │
│                                                  ▼            │
│                                        ┌──────────────┐       │
│                                        │ Microsoft    │       │
│                                        │ Graph API    │       │
│                                        └──────────────┘       │
└──────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Setup

### Step 1: Create Self-Signed Certificate

Run this on the server where scheduled tasks will run:

```powershell
# Create certificate
$cert = New-SelfSignedCertificate `
    -Subject "CN=AD-Security-Monitoring" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(2) `
    -KeyExportable `
    -KeySpec Signature

# Export public key (for Azure AD)
$certBytes = $cert.RawData
$certBase64 = [Convert]::ToBase64String($certBytes)

# Save to file
$certBase64 | Out-File -FilePath ".\ad-monitoring-cert.cer" -Encoding UTF8

# Display thumbprint (you'll need this)
Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
Write-Host "Certificate saved to: .\ad-monitoring-cert.cer"
```

**Important:** Keep the `.cer` file secure. You'll upload it to Azure AD.

---

### Step 2: Create Azure AD App Registration

#### Option A: Using Azure Portal

1. **Navigate to Azure Portal**
   - Go to: https://portal.azure.com
   - Search for **App registrations**

2. **Create New Registration**
   - Click **New registration**
   - Name: `AD-Security-Monitoring`
   - Supported account types: **Accounts in this organizational directory only**
   - Redirect URI: Leave blank
   - Click **Register**

3. **Note Important Values**
   - Copy **Application (client) ID** - you'll need this
   - Copy **Directory (tenant) ID** - you'll need this

4. **Upload Certificate**
   - Click **Certificates & secrets**
   - Click **Upload certificate**
   - Select: `ad-monitoring-cert.cer`
   - Description: `AD Security Monitoring Service Account`
   - Click **Add**

5. **Assign API Permissions**
   - Click **API permissions**
   - Click **Add a permission**
   - Select **Microsoft Graph**
   - Select **Application permissions** (NOT Delegated permissions)
   
   Add these permissions:
   - `User.Read.All`
   - `Group.Read.All`
   - `Device.Read.All`
   - `Directory.Read.All`
   - `Application.Read.All`
   - `Policy.Read.All`
   - `UserAuthenticationMethod.Read.All`
   - `IdentityRiskEvent.Read.All` (optional - for risk detection)

6. **Grant Admin Consent**
   - Click **Grant admin consent for [Your Tenant]**
   - Click **Yes**
   - Status should show **Granted** for all permissions

#### Option B: Using PowerShell

```powershell
# Connect to Azure AD (requires Global Admin or Privileged Role Admin)
Connect-AzureAD

# Create app registration
$appName = "AD-Security-Monitoring"
$app = New-AzureADApplication `
    -DisplayName $appName `
    -IdentifierUris "https://$((Get-AzureADTenantDetail).ObjectId)/ad-security-monitoring"

# Create service principal
$sp = New-AzureADServicePrincipal -AppId $app.AppId

# Upload certificate
$certPath = ".\ad-monitoring-cert.cer"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($certPath)
$certBytes = $cert.GetRawCertData()
$certBase64 = [Convert]::ToBase64String($certBytes)
$certKeyId = New-Guid

Add-AzureADApplicationKeyCredential `
    -ObjectId $app.ObjectId `
    -CustomKeyIdentifier $certKeyId `
    -Type AsymmetricX509Cert `
    -Usage Verify `
    -Value $certBase64

# Add API permissions
$requiredResourceAccess = @{
    ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    ResourceAccess = @(
        @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role" }, # User.Read.All
        @{ Id = "5b567255-7703-4780-807c-7be8301ae99b"; Type = "Role" }, # Group.Read.All
        @{ Id = "7438b122-aefc-4978-80ed-43db9fcc7715"; Type = "Role" }, # Device.Read.All
        @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }, # Directory.Read.All
        @{ Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"; Type = "Role" }, # Application.Read.All
        @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Type = "Role" }, # Policy.Read.All
        @{ Id = "38d9df27-64da-44fd-b7c5-a6fbac20248f"; Type = "Role" }  # UserAuthenticationMethod.Read.All
    )
}

Set-AzureADApplication -ObjectId $app.ObjectId -RequiredResourceAccess @($requiredResourceAccess)

Write-Host "Application (client) ID: $($app.AppId)"
Write-Host "Directory (tenant) ID: $((Get-AzureADTenantDetail).ObjectId)"
```

---

### Step 3: Grant Directory Roles

The service principal needs directory reader role:

```powershell
# Connect to Azure AD
Connect-AzureAD

# Get service principal
$sp = Get-AzureADServicePrincipal -Filter "AppId eq 'YOUR_APP_ID'"

# Assign Directory Readers role
$role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
if (-not $role) {
    # Enable role if not already enabled
    $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "Directory Readers" }
    Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
    $role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
}

Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $sp.ObjectId

Write-Host "Directory Readers role assigned to service principal"
```

---

### Step 4: Update Scripts to Use Certificate Auth

The monitoring scripts have been updated to support certificate authentication. Here's how to configure:

#### Option 1: Update Config File

Edit `config/monitoring-config.json`:

```json
{
  "Entra": {
    "Authentication": {
      "Method": "Certificate",
      "ClientId": "YOUR_APP_ID",
      "TenantId": "YOUR_TENANT_ID",
      "CertificateThumbprint": "YOUR_CERT_THUMBPRINT",
      "CertificateStoreLocation": "CurrentUser",
      "CertificateStoreName": "My"
    }
  }
}
```

#### Option 2: Use Environment Variables

```powershell
# Set environment variables (add to scheduled task)
[Environment]::SetEnvironmentVariable("MSGRAPH_CLIENT_ID", "YOUR_APP_ID", "Machine")
[Environment]::SetEnvironmentVariable("MSGRAPH_TENANT_ID", "YOUR_TENANT_ID", "Machine")
[Environment]::SetEnvironmentVariable("MSGRAPH_CERT_THUMBPRINT", "YOUR_CERT_THUMBPRINT", "Machine")
```

#### Option 3: Pass as Parameters

```powershell
.\Invoke-DailySecurityChecks.ps1 `
    -IncludeEntra `
    -AuthMethod Certificate `
    -ClientId "your-app-id" `
    -TenantId "your-tenant-id" `
    -CertificateThumbprint "your-cert-thumbprint"
```

---

### Step 5: Test Certificate Authentication

```powershell
# Test connection
Connect-MgGraph `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -CertificateThumbprint "YOUR_CERT_THUMBPRINT" `
    -NoWelcome

# Verify connection
Get-MgContext

# Test read access
Get-MgUser -Top 5

# Disconnect
Disconnect-MgGraph
```

**Expected output:**
```
ClientId  TenantId  Scopes
--------  --------  ------
YOUR_APP  YOUR_TEN  {Directory.Read.All, User.Read.All, ...}
```

---

### Step 6: Update Scheduled Tasks

The scheduled tasks need to run as the service account that has access to the certificate.

#### Create Scheduled Task with Certificate Auth

```powershell
# Script path
$scriptPath = "C:\Users\ivolovnik\adreview\AD_review\Monitoring\Invoke-MonitoringWorkflow.ps1"
$logPath = "C:\Users\ivolovnik\adreview\AD_review\Logs"

# Create task action with authentication parameters
$arguments = @"
-NoProfile -ExecutionPolicy Bypass -File "$scriptPath" `
    -WorkflowType Daily `
    -AuthMethod Certificate `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -CertificateThumbprint "YOUR_CERT_THUMBPRINT" `
    -LogPath "$logPath\daily.log"
"@

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $arguments

# Create trigger (Daily at 7:00 AM)
$trigger = New-ScheduledTaskTrigger -Daily -At "7:00AM"

# Settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RunOnlyIfNetworkAvailable

# Register task (runs as SYSTEM - certificate must be in Machine store, or use service account)
Register-ScheduledTask `
    -TaskName "AD Security - Daily Checks" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "Daily AD security checks with certificate auth" `
    -User "SYSTEM" `
    -RunLevel Highest `
    -Force

Write-Host "Scheduled task created successfully"
```

---

## Alternative: Managed Identity (Azure VMs Only)

If your monitoring server is an **Azure VM**, you can use **Managed Identity** instead of certificates:

### Step 1: Enable Managed Identity

```powershell
# Enable system-assigned managed identity
Update-AzVM -ResourceGroupName "YourRG" -VMName "YourVM" -IdentityType SystemAssigned

# Get the managed identity object ID
$vm = Get-AzVM -ResourceGroupName "YourRG" -VMName "YourVM"
$identityId = $vm.Identity.PrincipalId

Write-Host "Managed Identity Object ID: $identityId"
```

### Step 2: Assign Permissions

```powershell
# Connect to Azure AD
Connect-AzureAD

# Get service principal for managed identity
$sp = Get-AzureADServicePrincipal -Filter "ObjectId eq '$identityId'"

# Assign Directory Readers role
$role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $sp.ObjectId
```

### Step 3: Update Scripts

The scripts automatically detect managed identity when no credentials are provided:

```powershell
# Will use managed identity automatically
Connect-MgGraph -Identity

# Test
Get-MgUser -Top 5
```

---

## Alternative: Client Secret (Less Secure)

For testing only, you can use a client secret instead of a certificate:

```powershell
# Create app registration with secret
Connect-AzureAD

$app = New-AzureADApplication `
    -DisplayName "AD-Security-Monitoring-Secret" `
    -IdentifierUris "https://yourtenant/ad-monitoring-secret"

$secret = New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId

Write-Host "Client ID: $($app.AppId)"
Write-Host "Client Secret: $($secret.Value)"
Write-Host "IMPORTANT: Save the client secret now - it won't be shown again!"

# Use in scripts
Connect-MgGraph `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -ClientSecretCredential (New-Object PSCredential(
        "any",
        (ConvertTo-SecureString "YOUR_CLIENT_SECRET" -AsPlainText -Force)
    ))
```

**Warning:** Secrets expire (default 6-24 months) and must be rotated. Certificates are more secure and can be auto-renewed.

---

## Security Best Practices

### Certificate Security

```powershell
# 1. Store certificate in Machine store (not CurrentUser) for service account access
$cert = New-SelfSignedCertificate `
    -Subject "CN=AD-Security-Monitoring" `
    -CertStoreLocation "Cert:\LocalMachine\My" `  # Machine store
    -NotAfter (Get-Date).AddYears(2) `
    -KeyExportable `
    -KeySpec Signature `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

# 2. Restrict certificate permissions
# Only the service account should have access to the private key

# 3. Enable certificate auto-renewal before expiration
# Set reminder for 30 days before expiration
```

### Service Account Setup

```powershell
# 1. Create dedicated service account (not a user account)
# In Active Directory Users and Computers:
# - Create user: svc-ad-monitoring
# - Set password to never expires (or use GMSA)
# - Add to "Denied RODC Password Replication Group"

# 2. Grant certificate access to service account
$cert = Get-Item "Cert:\LocalMachine\My\YOUR_THUMBPRINT"
$serviceAccount = "DOMAIN\svc-ad-monitoring"

# Grant read access to private key
$keyPath = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$keyFile = Get-Item "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyPath"
$acl = Get-Acl $keyFile
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $serviceAccount,
    "Read",
    "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $keyFile.FullName $acl

# 3. Configure scheduled task to run as service account
$credential = Get-Credential -Message "Enter service account credentials"

Register-ScheduledTask `
    -TaskName "AD Security - Daily Checks" `
    -Action $action `
    -Trigger $trigger `
    -User $credential.UserName `
    -Password $credential.GetNetworkCredential().Password `
    -RunLevel Highest `
    -Force
```

### Least Privilege

Only grant the minimum required permissions:

| Permission | Why It's Needed |
|-----------|----------------|
| `User.Read.All` | Read user accounts and MFA status |
| `Group.Read.All` | Read group memberships |
| `Device.Read.All` | Read device information |
| `Directory.Read.All` | Read directory objects |
| `Application.Read.All` | Read app registrations and service principals |
| `Policy.Read.All` | Read Conditional Access policies |
| `UserAuthenticationMethod.Read.All` | Read MFA methods |

**DO NOT grant:**
- `*ReadWrite*` permissions (monitoring should be read-only)
- `RoleManagement.ReadWrite.Directory` (no role changes needed)
- `Directory.ReadWrite.All` (no writes needed)

---

## Troubleshooting

### Issue: "Insufficient privileges to complete the operation"

**Cause:** App registration missing API permissions or admin consent not granted.

**Fix:**
1. Check assigned permissions in Azure Portal
2. Verify admin consent was granted
3. Wait 5-10 minutes for permissions to propagate
4. Test with: `Get-MgContext` to see granted scopes

### Issue: "Certificate with thumbprint was not found"

**Cause:** Certificate not in correct store or thumbprint mismatch.

**Fix:**
```powershell
# List available certificates
Get-ChildItem Cert:\LocalMachine\My | Format-Table Thumbprint, Subject, NotAfter

# Verify thumbprint matches config
$cert = Get-Item "Cert:\LocalMachine\My\YOUR_THUMBPRINT"
if ($cert) {
    Write-Host "Certificate found: $($cert.Subject)"
} else {
    Write-Host "Certificate not found!"
}
```

### Issue: "Scheduled task runs but authentication fails"

**Cause:** Service account doesn't have access to certificate private key.

**Fix:**
1. Open MMC > Certificates > Local Computer > Personal
2. Right-click certificate > All Tasks > Manage Private Keys
3. Add service account with **Read** permission
4. Test by running scheduled task manually

### Issue: "Token acquisition failed"

**Cause:** Network issues, incorrect tenant ID, or expired certificate.

**Fix:**
```powershell
# Verify certificate is not expired
$cert = Get-Item "Cert:\LocalMachine\My\YOUR_THUMBPRINT"
Write-Host "Certificate expires: $($cert.NotAfter)"

# Verify tenant ID
Connect-MgGraph `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -CertificateThumbprint "YOUR_THUMBPRINT" `
    -Verbose

# Check network connectivity
Test-NetConnection login.microsoftonline.com -Port 443
```

---

## Migration from Interactive to Certificate Auth

If you currently have scripts running with interactive auth:

### Step 1: Set Up Certificate Auth (Follow Steps 1-3 Above)

### Step 2: Test Side-by-Side

```powershell
# Old method (interactive) - keep for fallback
Connect-MgGraph -Scopes "Directory.Read.All"

# New method (certificate) - test this
Connect-MgGraph `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -CertificateThumbprint "YOUR_THUMBPRINT"

# Verify both work
Get-MgUser -Top 1
```

### Step 3: Update Scheduled Tasks

```powershell
# Get existing task
$task = Get-ScheduledTask -TaskName "AD Security - Daily Checks"

# Update action arguments to include certificate auth
$task.Actions[0].Arguments = $task.Actions[0].Arguments.Replace(
    "-IncludeEntra",
    "-IncludeEntra -AuthMethod Certificate -ClientId YOUR_APP_ID -TenantId YOUR_TENANT_ID -CertificateThumbprint YOUR_THUMBPRINT"
)

# Set task to run as service account (not SYSTEM)
$principal = New-ScheduledTaskPrincipal `
    -UserId "DOMAIN\svc-ad-monitoring" `
    -RunLevel Highest `
    -LogonType Password

$task.Principal = $principal

# Save changes
Set-ScheduledTask -InputObject $task

Write-Host "Scheduled task updated"
```

### Step 4: Monitor and Verify

```powershell
# Check task execution history
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" |
    Where-Object { $_.Message -like "*AD Security*" } |
    Select-Object -First 10 TimeCreated, Message

# Verify logs show successful authentication
Get-Content "C:\Path\To\Logs\daily.log" -Tail 20
```

---

## Summary

| Method | Security | Complexity | Best For |
|--------|----------|------------|----------|
| **Certificate** | ★★★★★ | Medium | Production (recommended) |
| **Managed Identity** | ★★★★★ | Low | Azure VMs only |
| **Client Secret** | ★★★ | Low | Testing/Development |
| **Interactive** | ★★★★ | High | Manual runs only |

**Recommendation:** Use **certificate authentication** for all scheduled tasks. It's the most secure, doesn't require secret rotation (certificates last 1-2 years), and works reliably with service accounts.

---

**Next:** Run `Setup-MonitoringEnvironment.ps1` with the `-AuthMethod Certificate` parameter to automate this setup.
