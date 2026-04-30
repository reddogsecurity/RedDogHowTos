using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;
using System.IO;
using AD_Map_Backend.Hubs;

namespace AD_Map_Backend.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ADController : ControllerBase
{
    private readonly ILogger<ADController> _logger;
    private readonly string _dataPath;
    private readonly IMemoryCache _cache;
    private readonly IHubContext<ADHub> _hubContext;

    public ADController(
        ILogger<ADController> logger, 
        IConfiguration configuration,
        IMemoryCache cache,
        IHubContext<ADHub> hubContext)
    {
        _logger = logger;
        _dataPath = configuration["DataPath"] ?? Path.Combine(Directory.GetCurrentDirectory(), "Data");
        _cache = cache;
        _hubContext = hubContext;
    }

    [HttpGet("users")]
    [ResponseCache(Duration = 300)] // Cache for 5 minutes
    public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 100)
    {
        try
        {
            var cacheKey = $"users_page_{page}_size_{pageSize}";
            if (_cache.TryGetValue(cacheKey, out List<ADUser>? cachedUsers))
            {
                return Ok(cachedUsers);
            }

            var users = await LoadJsonData<List<ADUser>>("ad-users");
            
            // Apply pagination
            var paginatedUsers = users
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToList();

            // Cache the result
            _cache.Set(cacheKey, paginatedUsers, TimeSpan.FromMinutes(5));

            return Ok(new
            {
                Data = paginatedUsers,
                TotalCount = users.Count,
                Page = page,
                PageSize = pageSize,
                TotalPages = (int)Math.Ceiling((double)users.Count / pageSize)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading users");
            return StatusCode(500, new { Error = "Error loading user data", Details = ex.Message });
        }
    }

    [HttpGet("groups")]
    public async Task<IActionResult> GetGroups()
    {
        try
        {
            var groups = await LoadJsonData<List<ADGroup>>("ad-groups");
            return Ok(groups);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading groups");
            return StatusCode(500, "Error loading group data");
        }
    }

    [HttpGet("computers")]
    public async Task<IActionResult> GetComputers()
    {
        try
        {
            var computers = await LoadJsonData<List<ADComputer>>("ad-computers");
            return Ok(computers);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading computers");
            return StatusCode(500, "Error loading computer data");
        }
    }

    [HttpGet("relationships")]
    public async Task<IActionResult> GetRelationships()
    {
        try
        {
            var relationships = new
            {
                UserMemberships = await LoadJsonData<List<UserMembership>>("user-memberships"),
                GroupNesting = await LoadJsonData<List<GroupNesting>>("group-nesting"),
                RoleAssignments = await LoadJsonData<List<RoleAssignment>>("role-assignments")
            };
            return Ok(relationships);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading relationships");
            return StatusCode(500, "Error loading relationship data");
        }
    }

    [HttpGet("risk-analysis")]
    public async Task<IActionResult> GetRiskAnalysis()
    {
        try
        {
            var riskData = await LoadJsonData<RiskAnalysis>("risk-analysis");
            return Ok(riskData);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading risk analysis");
            return StatusCode(500, "Error loading risk data");
        }
    }

    [HttpGet("network-graph")]
    [ResponseCache(Duration = 300)]
    public async Task<IActionResult> GetNetworkGraph()
    {
        try
        {
            var cacheKey = "network_graph";
            if (_cache.TryGetValue(cacheKey, out object? cachedGraph))
            {
                return Ok(cachedGraph);
            }

            var users = await LoadJsonData<List<ADUser>>("ad-users");
            var groups = await LoadJsonData<List<ADGroup>>("ad-groups");
            var computers = await LoadJsonData<List<ADComputer>>("ad-computers");
            var relationships = await GetRelationships();

            var graph = new
            {
                Nodes = BuildNodes(users, groups, computers),
                Edges = BuildEdges(relationships),
                Metadata = new
                {
                    GeneratedAt = DateTime.UtcNow,
                    TotalNodes = users.Count + groups.Count + computers.Count,
                    UserCount = users.Count,
                    GroupCount = groups.Count,
                    ComputerCount = computers.Count
                }
            };

            // Cache the result
            _cache.Set(cacheKey, graph, TimeSpan.FromMinutes(5));

            return Ok(graph);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error building network graph");
            return StatusCode(500, new { Error = "Error building network graph", Details = ex.Message });
        }
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshData()
    {
        try
        {
            // Clear cache
            _cache.Remove("users_page_1_size_100");
            _cache.Remove("network_graph");
            _cache.Remove("risk_analysis");

            // Notify clients about refresh
            await _hubContext.Clients.All.SendAsync("DataRefreshRequested", new
            {
                Timestamp = DateTime.UtcNow,
                Message = "Data refresh initiated"
            });

            _logger.LogInformation("Data refresh requested by client");
            return Ok(new { Message = "Data refresh initiated", Timestamp = DateTime.UtcNow });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing data");
            return StatusCode(500, new { Error = "Error refreshing data", Details = ex.Message });
        }
    }

    [HttpGet("status")]
    public IActionResult GetStatus()
    {
        try
        {
            var dataFiles = Directory.GetFiles(_dataPath, "*.json", SearchOption.TopDirectoryOnly);
            var latestFile = dataFiles
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.LastWriteTime)
                .FirstOrDefault();

            return Ok(new
            {
                Status = "Healthy",
                DataPath = _dataPath,
                LastDataUpdate = latestFile?.LastWriteTime,
                DataFilesCount = dataFiles.Length,
                ServerTime = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting status");
            return StatusCode(500, new { Error = "Error getting status", Details = ex.Message });
        }
    }

    private async Task<T> LoadJsonData<T>(string fileName)
    {
        var filePath = Path.Combine(_dataPath, $"{fileName}-*.json");
        var files = Directory.GetFiles(_dataPath, $"{fileName}-*.json");
        
        if (files.Length == 0)
        {
            throw new FileNotFoundException($"No data files found for {fileName}");
        }

        var latestFile = files.OrderByDescending(f => System.IO.File.GetCreationTime(f)).First();
        var json = await System.IO.File.ReadAllTextAsync(latestFile);
        return JsonSerializer.Deserialize<T>(json) ?? throw new InvalidOperationException("Failed to deserialize data");
    }

    private object BuildNodes(List<ADUser> users, List<ADGroup> groups, List<ADComputer> computers)
    {
        var nodes = new List<object>();

        // Add user nodes
        foreach (var user in users)
        {
            nodes.Add(new
            {
                id = $"user-{user.SamAccountName}",
                label = user.DisplayName,
                type = "user",
                data = user,
                privileged = user.IsPrivileged,
                riskScore = user.RiskScore,
                mfaEnabled = user.MfaEnabled
            });
        }

        // Add group nodes
        foreach (var group in groups)
        {
            nodes.Add(new
            {
                id = $"group-{group.SamAccountName}",
                label = group.Name,
                type = "group",
                data = group,
                privileged = group.IsPrivileged,
                memberCount = group.MemberCount
            });
        }

        // Add computer nodes
        foreach (var computer in computers)
        {
            nodes.Add(new
            {
                id = $"computer-{computer.Name}",
                label = computer.Name,
                type = "computer",
                data = computer,
                os = computer.OperatingSystem,
                delegation = computer.DelegationType
            });
        }

        return nodes;
    }

    private object BuildEdges(IActionResult relationships)
    {
        // Implementation for building edges from relationship data
        return new List<object>();
    }
}

// Data Models
public class ADUser
{
    public string SamAccountName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public bool IsPrivileged { get; set; }
    public int RiskScore { get; set; }
    public bool MfaEnabled { get; set; }
    public DateTime? LastLogon { get; set; }
    public bool PasswordNeverExpires { get; set; }
}

public class ADGroup
{
    public string SamAccountName { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public int MemberCount { get; set; }
    public bool IsPrivileged { get; set; }
}

public class ADComputer
{
    public string Name { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string DelegationType { get; set; } = string.Empty;
    public bool IsDomainController { get; set; }
}

public class UserMembership
{
    public string UserId { get; set; } = string.Empty;
    public string GroupId { get; set; } = string.Empty;
}

public class GroupNesting
{
    public string ParentGroupId { get; set; } = string.Empty;
    public string ChildGroupId { get; set; } = string.Empty;
}

public class RoleAssignment
{
    public string UserId { get; set; } = string.Empty;
    public string RoleId { get; set; } = string.Empty;
    public string AssignmentType { get; set; } = string.Empty;
}

public class RiskAnalysis
{
    public int TotalUsers { get; set; }
    public int HighRiskUsers { get; set; }
    public int PrivilegedUsers { get; set; }
    public int UsersWithoutMfa { get; set; }
    public List<RiskFinding> Findings { get; set; } = new();
}

public class RiskFinding
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public int RiskScore { get; set; }
    public string MitreTechnique { get; set; } = string.Empty;
}
