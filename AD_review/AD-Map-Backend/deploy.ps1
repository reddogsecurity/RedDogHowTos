# AD Map Backend Deployment Script
# Run this script on your Windows Server to deploy the API

param(
    [string]$Environment = "Production",
    [string]$DataPath = "C:\AD_Map_Data",
    [string]$Port = "5000",
    [string]$HttpsPort = "7001"
)

Write-Host "AD Map Backend Deployment Script" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check if .NET 8 is installed
Write-Host "Checking .NET 8 installation..." -ForegroundColor Yellow
try {
    $dotnetVersion = dotnet --version
    Write-Host "✅ .NET Version: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ .NET 8 not found. Please install .NET 8 SDK first." -ForegroundColor Red
    exit 1
}

# Create data directory
Write-Host "Creating data directory..." -ForegroundColor Yellow
if (!(Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force
    Write-Host "✅ Data directory created: $DataPath" -ForegroundColor Green
} else {
    Write-Host "✅ Data directory exists: $DataPath" -ForegroundColor Green
}

# Build the application
Write-Host "Building application..." -ForegroundColor Yellow
dotnet build -c Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Build successful" -ForegroundColor Green

# Publish the application
Write-Host "Publishing application..." -ForegroundColor Yellow
$publishPath = ".\publish"
dotnet publish -c Release -o $publishPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Publish failed" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Publish successful" -ForegroundColor Green

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
  },
  "Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http://0.0.0.0:$Port"
      },
      "Https": {
        "Url": "https://0.0.0.0:$HttpsPort"
      }
    }
  }
}
"@

$productionConfig | Out-File -FilePath "$publishPath\appsettings.Production.json" -Encoding UTF8
Write-Host "✅ Production configuration created" -ForegroundColor Green

# Create Windows Service (optional)
Write-Host "Creating Windows Service..." -ForegroundColor Yellow
$serviceName = "ADMapBackend"
$serviceExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($serviceExists) {
    Write-Host "Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $serviceName -Force
    sc.exe delete $serviceName
}

# Install as Windows Service
$servicePath = (Get-Item $publishPath).FullName
$exePath = "$servicePath\AD-Map-Backend.exe"

sc.exe create $serviceName binPath= $exePath start= auto
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Windows Service created: $serviceName" -ForegroundColor Green
    Start-Service -Name $serviceName
    Write-Host "✅ Service started" -ForegroundColor Green
} else {
    Write-Host "⚠️  Service creation failed, but application can still run manually" -ForegroundColor Yellow
}

# Create firewall rules
Write-Host "Creating firewall rules..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "AD Map API HTTP" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "AD Map API HTTPS" -Direction Inbound -Protocol TCP -LocalPort $HttpsPort -Action Allow -ErrorAction SilentlyContinue
    Write-Host "✅ Firewall rules created" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Firewall rules may need manual configuration" -ForegroundColor Yellow
}

# Test the API
Write-Host "Testing API..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
try {
    $response = Invoke-RestMethod -Uri "http://localhost:$Port/health" -Method GET -TimeoutSec 10
    Write-Host "✅ API is responding: $($response.Status)" -ForegroundColor Green
} catch {
    Write-Host "⚠️  API test failed, but service may still be starting" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Deployment Complete!" -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green
Write-Host "API URL: http://localhost:$Port" -ForegroundColor Cyan
Write-Host "HTTPS URL: https://localhost:$HttpsPort" -ForegroundColor Cyan
Write-Host "Swagger UI: http://localhost:$Port" -ForegroundColor Cyan
Write-Host "Health Check: http://localhost:$Port/health" -ForegroundColor Cyan
Write-Host "Data Path: $DataPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Copy your PowerShell data files to: $DataPath" -ForegroundColor White
Write-Host "2. Run: .\DataProcessor.ps1 -InputPath 'C:\Your_AD_Data' -OutputPath '$DataPath'" -ForegroundColor White
Write-Host "3. Access the API at the URLs above" -ForegroundColor White
