# AD Interactive Map - Production Deployment Guide

## 🎯 Overview

This guide will help you deploy the AD Interactive Map solution to your Windows Server environment with production-ready configuration.

## 📋 Prerequisites

### **Server Requirements:**
- Windows Server 2016+ or Windows 10/11
- .NET 8.0 Runtime (or SDK for development)
- PowerShell 5.1+
- 4GB+ RAM
- 10GB+ free disk space

### **Network Requirements:**
- Port 5000 (HTTP) - API
- Port 7001 (HTTPS) - API (optional)
- Port 80/443 (if using reverse proxy)

## 🚀 Deployment Options

### **Option 1: Windows Service (Recommended)**

1. **Copy the project to your server:**
   ```powershell
   # Copy the entire AD-Map-Backend folder to your server
   # Example: C:\AD-Map-Backend\
   ```

2. **Run the deployment script:**
   ```powershell
   cd C:\AD-Map-Backend
   .\deploy.ps1 -Environment Production -DataPath "C:\AD_Map_Data"
   ```

3. **Verify deployment:**
   ```powershell
   # Check if service is running
   Get-Service -Name "ADMapBackend"
   
   # Test API endpoint
   Invoke-RestMethod -Uri "http://localhost:5000/health"
   ```

### **Option 2: Docker Container**

1. **Install Docker Desktop on Windows Server**

2. **Build and run:**
   ```powershell
   cd C:\AD-Map-Backend
   docker-compose up -d
   ```

3. **Verify:**
   ```powershell
   docker ps
   docker logs ad-map-backend
   ```

### **Option 3: Manual Deployment**

1. **Publish the application:**
   ```powershell
   dotnet publish -c Release -o C:\AD-Map-Backend\publish
   ```

2. **Create data directory:**
   ```powershell
   mkdir C:\AD_Map_Data
   ```

3. **Run the application:**
   ```powershell
   cd C:\AD-Map-Backend\publish
   dotnet AD-Map-Backend.dll --urls "http://0.0.0.0:5000"
   ```

## 🔧 Configuration

### **1. Data Integration**

Your existing PowerShell collection can be integrated:

```powershell
# Run your existing collection
.\script.ps1 -IncludeEntra -OutputFolder "C:\AD_Data"

# Process data for the API
.\DataProcessor.ps1 -InputPath "C:\AD_Data" -OutputPath "C:\AD_Map_Data"
```

### **2. API Configuration**

Edit `appsettings.Production.json`:

```json
{
  "DataPath": "C:\\AD_Map_Data",
  "Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http://0.0.0.0:5000"
      }
    }
  }
}
```

### **3. Frontend Configuration**

Update the API endpoint in `index.html`:

```javascript
// Change this line in the HTML file:
let apiBase = 'http://your-server-ip:5000';
```

## 🌐 Network Configuration

### **Firewall Rules**

```powershell
# Allow HTTP traffic
New-NetFirewallRule -DisplayName "AD Map API HTTP" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow

# Allow HTTPS traffic (if using)
New-NetFirewallRule -DisplayName "AD Map API HTTPS" -Direction Inbound -Protocol TCP -LocalPort 7001 -Action Allow
```

### **IIS Reverse Proxy (Optional)**

1. **Install IIS and URL Rewrite module**

2. **Create web.config:**
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <configuration>
     <system.webServer>
       <rewrite>
         <rules>
           <rule name="AD Map API" stopProcessing="true">
             <match url="^api/(.*)" />
             <action type="Rewrite" url="http://localhost:5000/api/{R:1}" />
           </rule>
         </rules>
       </rewrite>
     </system.webServer>
   </configuration>
   ```

## 📊 Monitoring & Maintenance

### **Health Checks**

```powershell
# Check API status
Invoke-RestMethod -Uri "http://localhost:5000/health"

# Check service status
Get-Service -Name "ADMapBackend"

# View logs
Get-EventLog -LogName Application -Source "AD-Map-Backend"
```

### **Data Refresh**

```powershell
# Manual data refresh
Invoke-RestMethod -Uri "http://localhost:5000/api/ad/refresh" -Method POST

# Or trigger from PowerShell
.\DataProcessor.ps1 -InputPath "C:\AD_Data" -OutputPath "C:\AD_Map_Data"
```

### **Logging**

Logs are written to:
- Windows Event Log (Application)
- Console output (if running manually)
- Docker logs (if using containers)

## 🔒 Security Considerations

### **1. Authentication (Optional)**

Add JWT authentication:

```csharp
// In Program.cs
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options => {
            // JWT configuration
        });
```

### **2. HTTPS Configuration**

```json
{
  "Kestrel": {
    "Endpoints": {
      "Https": {
        "Url": "https://0.0.0.0:7001",
        "Certificate": {
          "Path": "cert.pfx",
          "Password": "your-password"
        }
      }
    }
  }
}
```

### **3. CORS Configuration**

```json
{
  "Cors": {
    "AllowedOrigins": [
      "https://yourdomain.com",
      "https://admap.yourdomain.com"
    ]
  }
}
```

## 🚀 Performance Optimization

### **1. Caching**

The API includes built-in caching:
- Memory cache for frequently accessed data
- Response caching for API endpoints
- 5-minute cache duration (configurable)

### **2. Database (Optional)**

For large environments, consider adding a database:

```csharp
services.AddDbContext<ADMapContext>(options =>
    options.UseSqlite(connectionString));
```

### **3. Load Balancing**

For high-traffic scenarios:
- Use multiple API instances
- Implement load balancer (nginx, IIS)
- Use Redis for distributed caching

## 📈 Scaling Considerations

### **Small Environment (< 1000 users)**
- Single server deployment
- File-based data storage
- Basic monitoring

### **Medium Environment (1000-10000 users)**
- Database integration
- Caching layer
- Monitoring and alerting

### **Large Environment (> 10000 users)**
- Microservices architecture
- Database clustering
- Advanced monitoring
- Automated scaling

## 🔧 Troubleshooting

### **Common Issues:**

1. **API not starting:**
   ```powershell
   # Check .NET installation
   dotnet --version
   
   # Check port availability
   netstat -an | findstr :5000
   ```

2. **Data not loading:**
   ```powershell
   # Verify data files exist
   Get-ChildItem "C:\AD_Map_Data"
   
   # Check API endpoint
   Invoke-RestMethod -Uri "http://localhost:5000/api/ad/status"
   ```

3. **Frontend connection issues:**
   - Check API endpoint URL
   - Verify CORS configuration
   - Check browser console for errors

### **Log Analysis:**

```powershell
# View application logs
Get-EventLog -LogName Application -Source "AD-Map-Backend" -Newest 50

# Check service status
Get-Service -Name "ADMapBackend" | Format-List *
```

## 📋 Maintenance Schedule

### **Daily:**
- Monitor API health
- Check data freshness
- Review error logs

### **Weekly:**
- Update data from PowerShell collection
- Review performance metrics
- Check security logs

### **Monthly:**
- Update dependencies
- Review and rotate certificates
- Performance optimization review

## 🎯 Success Metrics

After deployment, you should have:

✅ **API running** on http://your-server:5000  
✅ **Health check** responding at /health  
✅ **Swagger UI** available at root URL  
✅ **Data files** in configured directory  
✅ **Frontend** connecting to API  
✅ **Real-time updates** working via SignalR  

## 📞 Support

### **API Endpoints:**
- `GET /health` - Health check
- `GET /api/ad/users` - User data
- `GET /api/ad/groups` - Group data
- `GET /api/ad/network-graph` - Complete graph data
- `POST /api/ad/refresh` - Manual data refresh
- `GET /api/ad/status` - System status

### **SignalR Hub:**
- `/adhub` - Real-time updates

### **Frontend:**
- Open `index.html` in browser
- Configure API endpoint
- Test connection

---

**🎉 Your AD Interactive Map is now ready for production use!**
