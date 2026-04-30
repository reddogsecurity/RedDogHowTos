# Certificate Authentication - Quick Reference Card

## For Scheduled Tasks (No Interactive Login)

### Option 1: Use Setup Script (Easiest)

```powershell
# Run as Administrator - creates certificate and configures everything
.\Setup-MonitoringEnvironment.ps1 `
    -SetupScheduledTasks `
    -SetupCertificateAuth `
    -EntraClientId "YOUR_APP_ID" `
    -EntraTenantId "YOUR_TENANT_ID" `
    -TeamsWebhookUrl "https://outlook.office.com/webhook/..."
```

This will:
- Create a self-signed certificate
- Configure all scripts to use certificate auth
- Set environment variables
- Create scheduled tasks
- Generate setup report

---

### Option 2: Manual Setup (Step-by-Step)

#### Step 1: Create Certificate

```powershell
# Run on the server where scheduled tasks will run
$cert = New-SelfSignedCertificate `
    -Subject "CN=AD-Security-Monitoring" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(2)

$thumbprint = $cert.Thumbprint
Write-Host "Thumbprint: $thumbprint"

# Export public key
Export-Certificate -Cert $cert -FilePath ".\ad-monitoring-cert.cer" -Type CERT
```

**Save the thumbprint!** You'll need it in the next steps.

---

#### Step 2: Create Azure AD App Registration

1. Go to **Azure Portal** > **App registrations**
2. Click **New registration**
3. Name: `AD-Security-Monitoring`
4. Click **Register**
5. Copy these values:
   - **Application (client) ID**: `________________________`
   - **Directory (tenant) ID**: `________________________`

---

#### Step 3: Upload Certificate

1. Click **Certificates & secrets**
2. Click **Upload certificate**
3. Select: `ad-monitoring-cert.cer`
4. Click **Add**

---

#### Step 4: Add API Permissions

Click **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**:

| Permission | Status |
|-----------|--------|
| `User.Read.All` | ☐ |
| `Group.Read.All` | ☐ |
| `Device.Read.All` | ☐ |
| `Directory.Read.All` | ☐ |
| `Application.Read.All` | ☐ |
| `Policy.Read.All` | ☐ |
| `UserAuthenticationMethod.Read.All` | ☐ |

Click **Grant admin consent for [Your Tenant]** > **Yes**

---

#### Step 5: Assign Directory Role

```powershell
# Connect to Azure AD
Connect-AzureAD

# Get your app's service principal
$sp = Get-AzureADServicePrincipal -Filter "AppId eq 'YOUR_APP_ID'"

# Assign Directory Readers role
$role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
if (-not $role) {
    $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "Directory Readers" }
    Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
    $role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
}

Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $sp.ObjectId
```

---

#### Step 6: Configure Monitoring Scripts

Edit `config\monitoring-config.json`:

```json
{
  "Entra": {
    "Authentication": {
      "Method": "Certificate",
      "ClientId": "YOUR_APP_ID_HERE",
      "TenantId": "YOUR_TENANT_ID_HERE",
      "CertificateThumbprint": "YOUR_THUMBPRINT_HERE",
      "CertificateStoreLocation": "LocalMachine"
    }
  }
}
```

**Or** set environment variables:

```powershell
[Environment]::SetEnvironmentVariable("MSGRAPH_CLIENT_ID", "YOUR_APP_ID", "Machine")
[Environment]::SetEnvironmentVariable("MSGRAPH_TENANT_ID", "YOUR_TENANT_ID", "Machine")
[Environment]::SetEnvironmentVariable("MSGRAPH_CERT_THUMBPRINT", "YOUR_THUMBPRINT", "Machine")
```

---

#### Step 7: Test Certificate Auth

```powershell
# Test connection
Connect-MgGraph `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -CertificateThumbprint "YOUR_THUMBPRINT" `
    -NoWelcome

# Verify connection
Get-MgContext

# Test read access
Get-MgUser -Top 3

# Run daily checks
.\Invoke-DailySecurityChecks.ps1 `
    -IncludeEntra `
    -AuthMethod Certificate `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -CertificateThumbprint "YOUR_THUMBPRINT"
```

---

### Option 3: Managed Identity (Azure VMs Only)

If your server is an Azure VM:

```powershell
# Enable managed identity
Update-AzVM -ResourceGroupName "YourRG" -VMName "YourVM" -IdentityType SystemAssigned

# Get managed identity object ID
$vm = Get-AzVM -ResourceGroupName "YourRG" -VMName "YourVM"
$identityId = $vm.Identity.PrincipalId
Write-Host "Managed Identity ID: $identityId"

# Assign permissions (in Azure AD)
Connect-AzureAD
$sp = Get-AzureADServicePrincipal -Filter "ObjectId eq '$identityId'"
$role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $sp.ObjectId

# Scripts will use managed identity automatically
.\Invoke-DailySecurityChecks.ps1 -IncludeEntra -AuthMethod ManagedIdentity
```

---

## Troubleshooting

### Check Certificate

```powershell
# List certificates
Get-ChildItem Cert:\LocalMachine\My | Format-Table Thumbprint, Subject, NotAfter

# Check specific certificate
Get-Item "Cert:\LocalMachine\My\YOUR_THUMBPRINT" | Select-Object *
```

### Check App Registration

```powershell
# Verify app registration
Connect-AzureAD
$app = Get-AzureADApplication -Filter "AppId eq 'YOUR_APP_ID'"
Write-Host "App Name: $($app.DisplayName)"
Write-Host "Certificates: $($app.KeyCredentials.Count)"
```

### Check Permissions

```powershell
# Test connection with verbose output
Connect-MgGraph `
    -ClientId "YOUR_APP_ID" `
    -TenantId "YOUR_TENANT_ID" `
    -CertificateThumbprint "YOUR_THUMBPRINT" `
    -Verbose

# Check granted permissions
Get-MgContext | Select-Object -ExpandProperty Scopes
```

### Common Errors

| Error | Fix |
|-------|-----|
| "Certificate not found" | Verify thumbprint matches certificate in LocalMachine store |
| "Insufficient privileges" | Grant API permissions and admin consent in Azure AD |
| "Token acquisition failed" | Check network connectivity to login.microsoftonline.com |
| "Scheduled task fails" | Ensure service account has read access to certificate private key |

---

## Scheduled Task Configuration

### Run as SYSTEM (Certificate in LocalMachine Store)

```powershell
$taskName = "AD Security - Daily Checks"
$scriptPath = "C:\Users\ivolovnik\adreview\AD_review\Monitoring\Invoke-MonitoringWorkflow.ps1"

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -WorkflowType Daily -AuthMethod Certificate"

$trigger = New-ScheduledTaskTrigger -Daily -At "7:00AM"

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -User "SYSTEM" `
    -RunLevel Highest `
    -Force
```

### Run as Service Account

```powershell
# Create service account in AD first: svc-ad-monitoring

$credential = Get-Credential -Message "Enter service account credentials"

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -User $credential.UserName `
    -Password $credential.GetNetworkCredential().Password `
    -RunLevel Highest `
    -Force

# Grant service account access to certificate private key
$cert = Get-Item "Cert:\LocalMachine\My\YOUR_THUMBPRINT"
$keyPath = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$keyFile = Get-Item "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyPath"
$acl = Get-Acl $keyFile
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "DOMAIN\svc-ad-monitoring",
    "Read",
    "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $keyFile.FullName $acl
```

---

## Migration Checklist

- [ ] Created self-signed certificate
- [ ] Exported public key (.cer file)
- [ ] Created Azure AD App Registration
- [ ] Uploaded certificate to App Registration
- [ ] Added all 7 API permissions
- [ ] Granted admin consent
- [ ] Assigned Directory Readers role
- [ ] Updated monitoring-config.json
- [ ] Set environment variables (optional)
- [ ] Tested certificate authentication
- [ ] Tested daily security checks
- [ ] Configured scheduled tasks
- [ ] Verified scheduled task runs successfully
- [ ] Documented certificate expiration date

**Certificate Expires:** ________________ (Set reminder 30 days before)

---

## Support

- **Full Guide:** See SERVICE-ACCOUNT-AUTH.md
- **Config File:** config\monitoring-config.json
- **Logs:** ..\Logs\ folder
- **Test Script:** Run `.\Invoke-DailySecurityChecks.ps1 -IncludeEntra -AuthMethod Certificate`
