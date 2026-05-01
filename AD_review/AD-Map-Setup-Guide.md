# AD Interactive Map - Next Level Setup Guide

## 🎯 Overview

This guide will help you transform your existing AD security assessment tool into a next-level interactive mapping solution using .NET Core backend and enhanced frontend visualization.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (Enhanced)                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │   HTML/JS       │  │   Cytoscape.js  │  │   SignalR    │  │
│  │   Dashboard     │  │   Network Viz  │  │   Real-time  │  │
│  └─────────────────┘  └─────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Backend (.NET Core)                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │   REST API      │  │   SignalR Hub   │  │   Data       │  │
│  │   Endpoints     │  │   Real-time     │  │   Processing │  │
│  └─────────────────┘  └─────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Data Layer                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │   JSON Files    │  │   PowerShell    │  │   Your       │  │
│  │   (Current)     │  │   Collection    │  │   Scripts    │  │
│  └─────────────────┘  └─────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### **Step 1: Set Up Backend API**

1. **Navigate to the backend directory:**
   ```powershell
   cd "C:\Users\reddog\Projects\Projects\AD_review\AD-Map-Backend"
   ```

2. **Install .NET 8 SDK** (if not already installed):
   ```powershell
   # Download from: https://dotnet.microsoft.com/download/dotnet/8.0
   # Or use winget:
   winget install Microsoft.DotNet.SDK.8
   ```

3. **Restore packages and run:**
   ```powershell
   dotnet restore
   dotnet run
   ```

4. **Verify API is running:**
   - Open browser to: `https://localhost:7001/swagger`
   - You should see the API documentation

### **Step 2: Process Your Existing Data**

1. **Run your existing PowerShell collection:**
   ```powershell
   cd "C:\Users\reddog\Projects\Projects\AD_review"
   .\script.ps1 -IncludeEntra -OutputFolder "C:\AD_Data"
   ```

2. **Convert data to API format:**
   ```powershell
   .\AD-Map-Backend\DataProcessor.ps1 -InputPath "C:\AD_Data" -OutputPath "C:\Users\reddog\Projects\Projects\AD_review\AD-Map-Backend\Data"
   ```

### **Step 3: Launch Enhanced Frontend**

1. **Open the enhanced HTML file:**
   ```powershell
   # Open in browser:
   start "C:\Users\reddog\Projects\Projects\AD_review\AD-Map-Enhanced\index.html"
   ```

2. **Or serve it locally:**
   ```powershell
   # Using Python (if installed):
   cd "C:\Users\reddog\Projects\Projects\AD_review\AD-Map-Enhanced"
   python -m http.server 8080
   # Then open: http://localhost:8080
   ```

## 🔧 Configuration

### **Backend Configuration**

Edit `appsettings.json`:
```json
{
  "DataPath": "C:\\Users\\reddog\\Projects\\Projects\\AD_review\\AD-Map-Backend\\Data",
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=admap.db"
  }
}
```

### **Frontend Configuration**

Edit the API_BASE URL in `index.html`:
```javascript
const API_BASE = 'https://localhost:7001/api';
```

## 🎨 Enhanced Features

### **1. Real-time Updates**
- **SignalR integration** for live data updates
- **Connection status** indicator
- **Automatic refresh** when data changes

### **2. Advanced Visualizations**
- **Multiple layout algorithms** (Force, Circle, Grid, Hierarchy)
- **Risk-based coloring** (High risk = red, Medium = yellow, Low = green)
- **Interactive filtering** by type, privilege, risk level
- **Zoom and pan** capabilities

### **3. Dashboard Features**
- **Risk overview** with key metrics
- **Security posture** indicators
- **MFA coverage** percentage
- **Privileged user** tracking

### **4. Data Integration**
- **Automatic data processing** from your PowerShell scripts
- **JSON format conversion** for API consumption
- **Historical data** support
- **Export capabilities** (PNG, SVG)

## 🔄 Workflow Integration

### **Daily Operations:**
1. **Run your existing PowerShell collection** (as usual)
2. **Process data** with the new DataProcessor.ps1
3. **View results** in the enhanced interactive map
4. **Monitor changes** in real-time

### **Automated Workflow:**
```powershell
# Create a scheduled task or script:
# 1. Run data collection
.\script.ps1 -IncludeEntra -OutputFolder "C:\AD_Data"

# 2. Process for API
.\AD-Map-Backend\DataProcessor.ps1 -InputPath "C:\AD_Data" -OutputPath "C:\AD_Map_Backend\Data"

# 3. API automatically serves updated data
# 4. Frontend automatically refreshes
```

## 🛠️ Advanced Customization

### **Adding New Data Sources**

1. **Extend the API controller:**
   ```csharp
   [HttpGet("custom-data")]
   public async Task<IActionResult> GetCustomData()
   {
       // Your custom data processing
   }
   ```

2. **Update the frontend:**
   ```javascript
   // Add new visualization types
   // Update filtering options
   // Add new dashboard metrics
   ```

### **Database Integration**

1. **Add Entity Framework:**
   ```powershell
   dotnet add package Microsoft.EntityFrameworkCore.Sqlite
   dotnet add package Microsoft.EntityFrameworkCore.Design
   ```

2. **Create models and migrations:**
   ```csharp
   public class ADUser
   {
       public int Id { get; set; }
       public string SamAccountName { get; set; }
       // ... other properties
   }
   ```

### **Authentication & Security**

1. **Add JWT authentication:**
   ```csharp
   services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
           .AddJwtBearer(options => {
               // JWT configuration
           });
   ```

2. **Implement role-based access:**
   ```csharp
   [Authorize(Roles = "SecurityAdmin")]
   public class ADController : ControllerBase
   {
       // Controller methods
   }
   ```

## 📊 Performance Optimization

### **Large Environment Handling**

1. **Implement pagination:**
   ```csharp
   [HttpGet("users")]
   public async Task<IActionResult> GetUsers(int page = 1, int pageSize = 100)
   {
       // Paginated results
   }
   ```

2. **Add caching:**
   ```csharp
   services.AddMemoryCache();
   services.AddResponseCaching();
   ```

3. **Optimize Cytoscape rendering:**
   ```javascript
   // Use clustering for large datasets
   cy.nodes().forEach(node => {
       if (node.degree() > 50) {
           node.addClass('cluster');
       }
   });
   ```

## 🔍 Troubleshooting

### **Common Issues:**

1. **API not starting:**
   ```powershell
   # Check .NET version:
   dotnet --version
   
   # Check if port is available:
   netstat -an | findstr :7001
   ```

2. **Data not loading:**
   ```powershell
   # Verify data files exist:
   Get-ChildItem "C:\Users\reddog\Projects\Projects\AD_review\AD-Map-Backend\Data"
   
   # Check API endpoints:
   Invoke-RestMethod "https://localhost:7001/api/ad/users"
   ```

3. **Frontend connection issues:**
   ```javascript
   // Check browser console for errors
   // Verify API_BASE URL is correct
   // Ensure CORS is enabled
   ```

## 🚀 Next Steps

### **Phase 2 Enhancements:**
- [ ] **Database persistence** for historical tracking
- [ ] **Advanced analytics** with machine learning
- [ ] **Mobile responsive** design
- [ ] **Multi-tenant** support
- [ ] **API rate limiting** and security
- [ ] **Automated reporting** and alerts

### **Phase 3 Features:**
- [ ] **AI-powered risk assessment**
- [ ] **Predictive analytics**
- [ ] **Integration with SIEM** systems
- [ ] **Compliance reporting**
- [ ] **Workflow automation**

## 📚 Resources

- **Cytoscape.js Documentation:** https://js.cytoscape.org/
- **SignalR Documentation:** https://docs.microsoft.com/en-us/aspnet/core/signalr/
- **.NET Core API Documentation:** https://docs.microsoft.com/en-us/aspnet/core/web-api/
- **Your existing PowerShell scripts** (already working!)

## 🎯 Success Metrics

After implementation, you should have:
- ✅ **Real-time AD visualization** with your actual data
- ✅ **Interactive filtering** and search capabilities
- ✅ **Risk-based color coding** and alerts
- ✅ **Professional dashboard** with KPIs
- ✅ **Export capabilities** for reports
- ✅ **Scalable architecture** for future enhancements

---

**Ready to transform your AD security assessment into a next-level interactive mapping solution!** 🚀
