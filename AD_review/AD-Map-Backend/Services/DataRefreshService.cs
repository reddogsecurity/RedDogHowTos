using Microsoft.AspNetCore.SignalR;
using AD_Map_Backend.Hubs;
using System.Text.Json;

namespace AD_Map_Backend.Services
{
    public class DataRefreshService : BackgroundService
    {
        private readonly IHubContext<ADHub> _hubContext;
        private readonly ILogger<DataRefreshService> _logger;
        private readonly IConfiguration _configuration;
        private readonly string _dataPath;
        private DateTime _lastRefresh = DateTime.MinValue;
        private DateTime _lastAlertSeen = DateTime.MinValue;

        public DataRefreshService(
            IHubContext<ADHub> hubContext, 
            ILogger<DataRefreshService> logger,
            IConfiguration configuration)
        {
            _hubContext = hubContext;
            _logger = logger;
            _configuration = configuration;
            _dataPath = _configuration["DataPath"] ?? Path.Combine(Directory.GetCurrentDirectory(), "Data");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CheckForDataUpdates();
                    await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); // Check every 5 minutes
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in data refresh service");
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                }
            }
        }

        private async Task CheckForDataUpdates()
        {
            try
            {
                var dataFiles = Directory.GetFiles(_dataPath, "*.json", SearchOption.TopDirectoryOnly);
                var latestFile = dataFiles
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.LastWriteTime)
                    .FirstOrDefault();

                if (latestFile != null && latestFile.LastWriteTime > _lastRefresh)
                {
                    _lastRefresh = latestFile.LastWriteTime;

                    // Notify clients about data update
                    await _hubContext.Clients.Group("DataUpdates").SendAsync("DataUpdated", new
                    {
                        Timestamp = DateTime.UtcNow,
                        Message = "AD data has been refreshed",
                        LastUpdate = _lastRefresh
                    });

                    _logger.LogInformation("Data refresh notification sent to clients");
                }

                // Also check for new alert summaries from Invoke-DailyAlert.ps1
                await CheckForAlertSummaries(dataFiles);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for data updates");
            }
        }

        private async Task CheckForAlertSummaries(string[] allDataFiles)
        {
            try
            {
                var alertFiles = allDataFiles
                    .Where(f => Path.GetFileName(f).StartsWith("alert-summary-"))
                    .Select(f => new FileInfo(f))
                    .Where(f => f.LastWriteTime > _lastAlertSeen)
                    .OrderBy(f => f.LastWriteTime)
                    .ToList();

                foreach (var alertFile in alertFiles)
                {
                    _lastAlertSeen = alertFile.LastWriteTime;

                    var json = await File.ReadAllTextAsync(alertFile.FullName);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var summary = JsonSerializer.Deserialize<AlertSummary>(json, options);

                    if (summary?.ShouldAlert == true)
                    {
                        await _hubContext.Clients.Group("AlertSubscribers").SendAsync("NewAlert", new
                        {
                            Timestamp        = summary.Timestamp,
                            Reason           = summary.Reason,
                            CriticalCount    = summary.CriticalCount,
                            HighCount        = summary.HighCount,
                            MediumCount      = summary.MediumCount,
                            TotalFindings    = summary.TotalFindings,
                            NewFindingsCount = summary.NewFindingsCount
                        });

                        _logger.LogWarning("Alert broadcast via DataRefreshService: {Reason}", summary.Reason);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for alert summaries");
            }
        }
    }
}
