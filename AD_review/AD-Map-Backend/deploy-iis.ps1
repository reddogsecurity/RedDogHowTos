# AD Map Backend - IIS Deployment Script
# Simple deployment for Windows Server with IIS

param(
    [string]$SiteName = "AD-Map-API",
    [string]$AppPoolName = "AD-Map-Pool",
    [string]$PhysicalPath = "C:\inetpub\wwwroot\AD-Map-API",
    [string]$DataPath = "C:\AD_Map_Data",
    [string]$Port = "80"
)

Write-Host "AD Map Backend - IIS Deployment" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check if IIS is installed
Write-Host "Checking IIS installation..." -ForegroundColor Yellow
$iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
if ($iisFeature.State -ne "Enabled") {
    Write-Host "❌ IIS is not installed. Installing IIS..." -ForegroundColor Yellow
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer, IIS-CommonHttpFeatures, IIS-HttpErrors, IIS-HttpLogging, IIS-RequestFiltering, IIS-StaticContent, IIS-DefaultDocument, IIS-DirectoryBrowsing, IIS-ASPNET45
    Write-Host "✅ IIS installed successfully" -ForegroundColor Green
} else {
    Write-Host "✅ IIS is already installed" -ForegroundColor Green
}

# Install ASP.NET Core Hosting Bundle
Write-Host "Checking ASP.NET Core Hosting Bundle..." -ForegroundColor Yellow
$hostingBundle = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like "*ASP.NET Core*Hosting*" }
if (-not $hostingBundle) {
    Write-Host "⚠️  ASP.NET Core Hosting Bundle not found" -ForegroundColor Yellow
    Write-Host "Please download and install from: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Cyan
    Write-Host "Look for 'ASP.NET Core Runtime 8.0.x - Windows Hosting Bundle'" -ForegroundColor Cyan
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne "y") {
        exit 1
    }
} else {
    Write-Host "✅ ASP.NET Core Hosting Bundle found" -ForegroundColor Green
}

# Create directories
Write-Host "Creating directories..." -ForegroundColor Yellow
if (!(Test-Path $PhysicalPath)) {
    New-Item -ItemType Directory -Path $PhysicalPath -Force
    Write-Host "✅ Created application directory: $PhysicalPath" -ForegroundColor Green
}

if (!(Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force
    Write-Host "✅ Created data directory: $DataPath" -ForegroundColor Green
}

# Build and publish the application
Write-Host "Building application..." -ForegroundColor Yellow
dotnet build -c Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "Publishing application..." -ForegroundColor Yellow
dotnet publish -c Release -o $PhysicalPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Publish failed" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Application published successfully" -ForegroundColor Green

# Create production appsettings
Write-Host "Creating production configuration..." -ForegroundColor Yellow
$productionConfig = @"
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "DataPath": "$DataPath",
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=$DataPath\admap.db"
  }
}
"@

$productionConfig | Out-File -FilePath "$PhysicalPath\appsettings.Production.json" -Encoding UTF8
Write-Host "✅ Production configuration created" -ForegroundColor Green

# Create Application Pool
Write-Host "Creating Application Pool..." -ForegroundColor Yellow
Import-Module WebAdministration

# Remove existing app pool if it exists
if (Get-IISAppPool -Name $AppPoolName -ErrorAction SilentlyContinue) {
    Remove-WebAppPool -Name $AppPoolName
    Write-Host "✅ Removed existing application pool" -ForegroundColor Green
}

# Create new app pool
New-WebAppPool -Name $AppPoolName
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value ApplicationPoolIdentity
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion -Value ""
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name enable32BitAppOnWin64 -Value $false
Write-Host "✅ Application pool created: $AppPoolName" -ForegroundColor Green

# Create IIS Site
Write-Host "Creating IIS Site..." -ForegroundColor Yellow
# Remove existing site if it exists
if (Get-IISSite -Name $SiteName -ErrorAction SilentlyContinue) {
    Remove-IISSite -Name $SiteName
    Write-Host "✅ Removed existing site" -ForegroundColor Green
}

# Create new site
New-IISSite -Name $SiteName -PhysicalPath $PhysicalPath -Port $Port -ApplicationPool $AppPoolName
Write-Host "✅ IIS Site created: $SiteName" -ForegroundColor Green

# Set permissions
Write-Host "Setting permissions..." -ForegroundColor Yellow
$acl = Get-Acl $PhysicalPath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)
Set-Acl -Path $PhysicalPath -AclObject $acl

$acl = Get-Acl $DataPath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)
Set-Acl -Path $DataPath -AclObject $acl
Write-Host "✅ Permissions set" -ForegroundColor Green

# Create firewall rule
Write-Host "Creating firewall rule..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "AD Map API IIS" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue
    Write-Host "✅ Firewall rule created" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Firewall rule may need manual configuration" -ForegroundColor Yellow
}

# Test the site
Write-Host "Testing the site..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
try {
    $response = Invoke-RestMethod -Uri "http://localhost:$Port/health" -Method GET -TimeoutSec 10
    Write-Host "✅ Site is responding: $($response.Status)" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Site test failed, but it may still be starting" -ForegroundColor Yellow
    Write-Host "Check IIS Manager and Event Viewer for details" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 IIS Deployment Complete!" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green
Write-Host "Site Name: $SiteName" -ForegroundColor Cyan
Write-Host "Application Pool: $AppPoolName" -ForegroundColor Cyan
Write-Host "Physical Path: $PhysicalPath" -ForegroundColor Cyan
Write-Host "Data Path: $DataPath" -ForegroundColor Cyan
Write-Host "URL: http://localhost:$Port" -ForegroundColor Cyan
Write-Host "API URL: http://localhost:$Port/api/ad/status" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Open IIS Manager to verify the site" -ForegroundColor White
Write-Host "2. Copy your PowerShell data files to: $DataPath" -ForegroundColor White
Write-Host "3. Run: .\DataProcessor.ps1 -InputPath 'C:\Your_AD_Data' -OutputPath '$DataPath'" -ForegroundColor White
Write-Host "4. Test the API at: http://localhost:$Port/api/ad/status" -ForegroundColor White
Write-Host "5. Update the frontend API endpoint to: http://your-server:$Port" -ForegroundColor White
