<# 
.SYNOPSIS
  Export and dismiss Azure AD (Entra) risky users older than 7 days.

.DESCRIPTION
  - Backs up candidates to a timestamped CSV.
  - Dismisses risk via riskyUsers/dismiss Graph action (batched).
  - Optional -WhatIf mode to preview without making changes.

.REQUIREMENTS
  Install-Module Microsoft.Graph -Scope AllUsers
  Install-Module Microsoft.Graph.Identity.SignIns -Scope AllUsers
  Connect-MgGraph -Scopes "IdentityRiskyUser.ReadWrite.All"
#>

param(
  [switch]$WhatIf,
  [string[]]$States = @('atRisk', 'confirmedCompromised'),  # adjust as needed
  [int]$OlderThanDays = 7
)

# --- Ensure the right module(s) are present & loaded
try {
  if (-not (Get-Module -ListAvailable Microsoft.Graph.Identity.SignIns)) {
    Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force -ErrorAction Stop
  }
  Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
} catch {
  Write-Host "Could not load Microsoft.Graph.Identity.SignIns. Will rely on REST calls." -ForegroundColor Yellow
}

# --- Connect with the right scope
if (-not (Get-MgContext)) {
  Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
  Connect-MgGraph -Scopes "IdentityRiskyUser.ReadWrite.All" -ErrorAction Stop
}

# Verify connection
$context = Get-MgContext
if (-not $context) {
  throw "Failed to establish Microsoft Graph connection"
}
Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
Write-Host "Scopes: $($context.Scopes -join ', ')" -ForegroundColor Gray

# --- Helper: check whether the dismiss cmdlet exists
$hasDismissCmd = $null -ne (Get-Command -ErrorAction SilentlyContinue Invoke-MgDismissIdentityProtectionRiskyUser)

# --- Helper: Invoke Graph request with retry logic
function Invoke-GraphWithRetry {
  param(
    [string]$Uri,
    [string]$Method = "GET",
    [hashtable]$Body = $null,
    [int]$MaxRetries = 5,
    [int]$InitialDelaySeconds = 2
  )
  
  $attempt = 0
  $delay = $InitialDelaySeconds
  
  while ($attempt -lt $MaxRetries) {
    try {
      $attempt++
      Write-Verbose "Attempt $attempt of $MaxRetries for $Uri"
      
      $params = @{
        Method = $Method
        Uri = $Uri
      }
      if ($Body) {
        $params.Body = ($Body | ConvertTo-Json)
      }
      
      return Invoke-MgGraphRequest @params
    }
    catch {
      $errorMessage = $_.Exception.Message
      
      # Check if it's a throttling error (429) or transient error
      if ($errorMessage -like "*429*" -or $errorMessage -like "*503*" -or $errorMessage -like "*Too many retries*") {
        if ($attempt -lt $MaxRetries) {
          Write-Host "Request throttled or failed (attempt $attempt/$MaxRetries). Waiting $delay seconds..." -ForegroundColor Yellow
          Start-Sleep -Seconds $delay
          $delay = $delay * 2  # Exponential backoff
        } else {
          throw "Max retries exceeded: $errorMessage"
        }
      } else {
        # Non-retryable error
        throw
      }
    }
  }
}

# --- Pull risky users (prefer the cmdlet; fall back to REST with retry)
$riskyUsers = @()
Write-Host "`nRetrieving risky users..." -ForegroundColor Cyan

try {
  if (Get-Command -ErrorAction SilentlyContinue Get-MgIdentityProtectionRiskyUser) {
    Write-Host "Using Get-MgIdentityProtectionRiskyUser cmdlet..." -ForegroundColor Gray
    # Try cmdlet first but with error handling
    try {
      $riskyUsers = @(Get-MgIdentityProtectionRiskyUser -All -ErrorAction Stop)
    } catch {
      Write-Host "Cmdlet failed, falling back to REST API: $($_.Exception.Message)" -ForegroundColor Yellow
      $riskyUsers = @()  # Reset and try REST
    }
  }
  
  # REST fallback with manual retry logic
  if ($riskyUsers.Count -eq 0) {
    Write-Host "Using REST API with retry logic..." -ForegroundColor Gray
    $url = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=100"
    $pageCount = 0
    
    do {
      $pageCount++
      Write-Host "  Fetching page $pageCount..." -ForegroundColor Gray
      
      $resp = Invoke-GraphWithRetry -Uri $url -Method GET
      
      if ($resp.value) {
        $riskyUsers += $resp.value
        Write-Host "  Retrieved $($resp.value.Count) users (total: $($riskyUsers.Count))" -ForegroundColor Gray
      }
      $url = $resp.'@odata.nextLink'
    } while ($url)
  }
  
  Write-Host "Successfully retrieved $($riskyUsers.Count) risky users" -ForegroundColor Green
  
} catch {
  Write-Host "`nError Details:" -ForegroundColor Red
  Write-Host "  Message: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "  Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
  
  # Provide helpful troubleshooting info
  Write-Host "`nTroubleshooting suggestions:" -ForegroundColor Yellow
  Write-Host "  1. Check your internet connection" -ForegroundColor Yellow
  Write-Host "  2. Verify you have the correct permissions (IdentityRiskyUser.ReadWrite.All)" -ForegroundColor Yellow
  Write-Host "  3. Try disconnecting and reconnecting: Disconnect-MgGraph; Connect-MgGraph -Scopes 'IdentityRiskyUser.ReadWrite.All'" -ForegroundColor Yellow
  Write-Host "  4. Check if your organization has conditional access policies blocking the connection" -ForegroundColor Yellow
  Write-Host "  5. Try running with -Verbose flag for more details" -ForegroundColor Yellow
  
  throw "Failed to retrieve risky users: $($_.Exception.Message)"
}

if (-not $riskyUsers) {
  Write-Host "No risky users found." -ForegroundColor Cyan
  return
}

# --- Filter: older than N days + eligible states
$threshold = (Get-Date).AddDays(-[int]$OlderThanDays)
$oldRiskyUsers = $riskyUsers | Where-Object {
  $_.riskLastUpdatedDateTime -and
  ([datetime]$_.riskLastUpdatedDateTime) -lt $threshold -and
  $States -contains $_.riskState
}

if (-not $oldRiskyUsers) {
  Write-Host "No risky users older than $OlderThanDays days in states: $($States -join ', ')." -ForegroundColor Yellow
  return
}

# --- Backup BEFORE any change
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupPath = "OldRiskyUsers_$stamp.csv"
$oldRiskyUsers |
  Select-Object id, userPrincipalName, userDisplayName, riskState, riskLevel, riskDetail, riskLastUpdatedDateTime |
  Export-Csv -Path $backupPath -NoTypeInformation -Encoding UTF8
Write-Host "Backup saved to: $backupPath" -ForegroundColor Green

# --- Show summary
Write-Host "`nCandidates to dismiss: $($oldRiskyUsers.Count)" -ForegroundColor Cyan
$oldRiskyUsers | Select-Object userDisplayName, userPrincipalName, riskState, riskLevel, riskLastUpdatedDateTime |
  Format-Table -AutoSize

if ($WhatIf) {
  Write-Host "`nWhatIf mode: no changes made." -ForegroundColor Yellow
  return
}

# --- Dismiss (cmdlet if present; else REST POST with retry)
$ids = @($oldRiskyUsers | ForEach-Object { $_.id })
$batchSize = 50

Write-Host "`nDismissing $($ids.Count) risky users in batches of $batchSize..." -ForegroundColor Cyan

for ($i = 0; $i -lt $ids.Count; $i += $batchSize) {
  $slice = $ids[$i..([Math]::Min($i + $batchSize - 1, $ids.Count - 1))]
  $batchNum = [Math]::Floor($i / $batchSize) + 1
  
  try {
    Write-Host "  Processing batch $batchNum (users $($i+1)-$($i+$slice.Count))..." -ForegroundColor Gray
    
    if ($hasDismissCmd) {
      # Use cmdlet - it has built-in retry logic
      Invoke-MgDismissIdentityProtectionRiskyUser -BodyParameter @{ userIds = $slice }
    } else {
      # Use REST with our custom retry logic
      Invoke-GraphWithRetry -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss" `
        -Method POST `
        -Body @{ userIds = $slice } | Out-Null
    }
    
    Write-Host "  [OK] Dismissed batch $batchNum ($($slice.Count) users)" -ForegroundColor Green
  } catch {
    Write-Host "  [ERROR] Batch $batchNum error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Failed user IDs: $($slice -join ', ')" -ForegroundColor Red
  }
  
  # Small delay between batches to avoid throttling
  if ($i + $batchSize -lt $ids.Count) {
    Start-Sleep -Milliseconds 500
  }
}

Write-Host "`nRisky user cleanup completed." -ForegroundColor Cyan