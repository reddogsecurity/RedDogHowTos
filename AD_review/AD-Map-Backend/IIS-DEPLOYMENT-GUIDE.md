# AD Interactive Map - IIS Deployment Guide

## 🎯 **Simple IIS Deployment for Windows Server**

This guide provides a streamlined deployment using IIS instead of Docker/nginx.

## 📋 **Prerequisites**

### **Server Requirements:**
- Windows Server 2016+ or Windows 10/11
- IIS with ASP.NET Core Hosting Bundle
- .NET 8.0 Runtime
- PowerShell 5.1+

### **What You Need:**
1. **ASP.NET Core Hosting Bundle** - Download from: https://dotnet.microsoft.com/download/dotnet/8.0
2. **Your existing PowerShell data collection** (already working!)

## 🚀 **Quick Deployment (5 Steps)**

### **Step 1: Prepare Your Server**
```powershell
# Run as Administrator
# The deploy script will install IIS and configure everything
```

### **Step 2: Copy Files to Server**
```powershell
# Copy the entire AD-Map-Backend folder to your server
# Example: C:\AD-Map-Backend\
```

### **Step 3: Run Deployment Script**
```powershell
# Open PowerShell as Administrator
cd C:\AD-Map-Backend
.\deploy-iis.ps1
```

### **Step 4: Process Your Data**
```powershell
# Run your existing PowerShell collection
.\script.ps1 -IncludeEntra -OutputFolder "C:\AD_Data"

# Process data for the API
.\DataProcessor.ps1 -InputPath "C:\AD_Data" -OutputPath "C:\AD_Map_Data"
```

### **Step 5: Access Your Application**
- **API:** http://your-server/api/ad/status
- **Frontend:** http://your-server (opens automatically)
- **Health Check:** http://your-server/health

## 🔧 **What the Script Does**

The `deploy-iis.ps1` script automatically:

✅ **Installs IIS** (if not present)  
✅ **Installs ASP.NET Core Hosting Bundle** (with instructions)  
✅ **Creates Application Pool** (AD-Map-Pool)  
✅ **Creates IIS Site** (AD-Map-API)  
✅ **Publishes the application** to IIS  
✅ **Sets up permissions** for IIS_IUSRS  
✅ **Creates firewall rules**  
✅ **Configures production settings**  

## 📁 **File Structure After Deployment**

```
C:\inetpub\wwwroot\AD-Map-API\
├── AD-Map-Backend.dll          # Your API
├── web.config                   # IIS configuration
├── appsettings.Production.json # Production settings
├── wwwroot\
│   └── index.html              # Frontend (served automatically)
└── [other .NET files]

C:\AD_Map_Data\                 # Your data directory
├── ad-users.json
├── ad-groups.json
├── ad-computers.json
└── risk-analysis.json
```

## 🌐 **Accessing Your Application**

### **API Endpoints:**
- `GET /health` - Health check
- `GET /api/ad/users` - User data
- `GET /api/ad/groups` - Group data  
- `GET /api/ad/network-graph` - Complete graph data
- `POST /api/ad/refresh` - Manual data refresh
- `GET /api/ad/status` - System status

### **Frontend:**
- Open `http://your-server` in any browser
- Interactive AD security map with real-time updates
- Dashboard with risk metrics
- Export capabilities

## 🔄 **Data Integration Workflow**

### **Daily Operations:**
```powershell
# 1. Run your existing PowerShell collection (unchanged)
.\script.ps1 -IncludeEntra -OutputFolder "C:\AD_Data"

# 2. Process data for the API (new step)
.\DataProcessor.ps1 -InputPath "C:\AD_Data" -OutputPath "C:\AD_Map_Data"

# 3. API automatically serves updated data
# 4. Frontend automatically refreshes
```

### **Automated Workflow (Optional):**
```powershell
# Create a scheduled task to run daily:
# 1. Run PowerShell collection
# 2. Process data
# 3. API serves updated data automatically
```

## 🛠️ **Troubleshooting**

### **Common Issues:**

1. **"ASP.NET Core Hosting Bundle not found"**
   - Download from: https://dotnet.microsoft.com/download/dotnet/8.0
   - Look for "ASP.NET Core Runtime 8.0.x - Windows Hosting Bundle"
   - Install and re-run the deployment script

2. **"IIS is not installed"**
   - The script will install IIS automatically
   - Or install manually: `Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole`

3. **"API not responding"**
   ```powershell
   # Check IIS Manager
   # Look for "AD-Map-API" site
   # Check Application Pool "AD-Map-Pool"
   # Check Event Viewer for errors
   ```

4. **"Data not loading"**
   ```powershell
   # Verify data files exist
   Get-ChildItem "C:\AD_Map_Data"
   
   # Test API endpoint
   Invoke-RestMethod -Uri "http://localhost/api/ad/status"
   ```

### **Manual Verification:**

```powershell
# Check if site is running
Get-IISSite -Name "AD-Map-API"

# Check application pool
Get-IISAppPool -Name "AD-Map-Pool"

# Test API
Invoke-RestMethod -Uri "http://localhost/api/ad/status"

# Check data files
Get-ChildItem "C:\AD_Map_Data"
```

## 🔒 **Security Considerations**

### **Firewall:**
- Port 80 (HTTP) is opened automatically
- For HTTPS, configure SSL certificate in IIS Manager

### **Permissions:**
- IIS_IUSRS has access to application and data directories
- Application runs under Application Pool Identity

### **HTTPS (Optional):**
1. Obtain SSL certificate
2. Configure in IIS Manager
3. Bind to port 443
4. Update frontend to use HTTPS

## 📊 **Monitoring**

### **IIS Manager:**
- Monitor site status
- Check application pool health
- View request logs

### **Event Viewer:**
- Application logs
- System logs
- Security logs

### **Performance:**
- Built-in caching (5-minute duration)
- Memory optimization
- Response compression

## 🎯 **Success Indicators**

After deployment, you should have:

✅ **IIS Site** "AD-Map-API" running  
✅ **Application Pool** "AD-Map-Pool" healthy  
✅ **API responding** at http://your-server/api/ad/status  
✅ **Frontend accessible** at http://your-server  
✅ **Data files** in C:\AD_Map_Data  
✅ **Real-time updates** working  

## 🚀 **Advantages of IIS Deployment**

### **vs Docker/nginx:**
- ✅ **Simpler setup** - No containerization complexity
- ✅ **Native Windows** - Built for Windows Server
- ✅ **IIS Management** - Familiar interface
- ✅ **Integrated security** - Windows authentication
- ✅ **Easy maintenance** - Standard Windows tools
- ✅ **Performance** - Native .NET hosting

### **vs Manual .NET:**
- ✅ **Production hosting** - Professional web server
- ✅ **Process management** - Automatic restart on failure
- ✅ **Security** - Built-in security features
- ✅ **Monitoring** - IIS logging and metrics
- ✅ **Scalability** - Load balancing support

## 📞 **Support**

### **IIS Manager:**
- Site configuration
- Application pool settings
- SSL certificates
- URL rewriting

### **API Endpoints:**
- All endpoints work the same as before
- SignalR hub for real-time updates
- Health checks and monitoring

### **Frontend:**
- Auto-detects API endpoint (same origin)
- No configuration needed
- Works with any modern browser

---

**🎉 Your AD Interactive Map is now running on IIS!**

**Simple, reliable, and production-ready for Windows Server environments.**
