using Microsoft.AspNetCore.SignalR;
using AD_Map_Backend.Hubs;
using System.Text.Json;
using System.Collections.Concurrent;

namespace AD_Map_Backend.Services
{
    /// <summary>
    /// Background service that monitors for alert-summary-*.json files written by Invoke-DailyAlert.ps1.
    /// When a new alert summary is detected with ShouldAlert=true, broadcasts a SignalR notification
    /// to all "AlertSubscribers" group members. Maintains a rolling list of last 100 alerts in memory.
    /// </summary>
    public class AlertService : BackgroundService
    {
        private readonly IHubContext<ADHub> _hubContext;
        private readonly ILogger<AlertService> _logger;
        private readonly IConfiguration _configuration;
        private readonly string _dataPath;
        private DateTime _lastAlertCheck = DateTime.MinValue;

        // Rolling in-memory alert history (last 100 alerts)
        private static readonly ConcurrentQueue<AlertSummary> _recentAlerts = new();
        private const int MaxAlertHistory = 100;

        public AlertService(
            IHubContext<ADHub> hubContext,
            ILogger<AlertService> logger,
            IConfiguration configuration)
        {
            _hubContext = hubContext;
            _logger = logger;
            _configuration = configuration;
            _dataPath = _configuration["DataPath"] ?? Path.Combine(Directory.GetCurrentDirectory(), "Data");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Offset slightly from DataRefreshService to avoid simultaneous file access
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CheckForNewAlerts();
                    await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in alert service");
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                }
            }
        }

        private async Task CheckForNewAlerts()
        {
            try
            {
                if (!Directory.Exists(_dataPath))
                    return;

                // Find alert-summary-*.json files newer than last check
                var alertFiles = Directory.GetFiles(_dataPath, "alert-summary-*.json", SearchOption.TopDirectoryOnly)
                    .Select(f => new FileInfo(f))
                    .Where(f => f.LastWriteTime > _lastAlertCheck)
                    .OrderBy(f => f.LastWriteTime)
                    .ToList();

                foreach (var alertFile in alertFiles)
                {
                    _lastAlertCheck = alertFile.LastWriteTime;
                    await ProcessAlertFile(alertFile.FullName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for new alerts");
            }
        }

        private async Task ProcessAlertFile(string filePath)
        {
            try
            {
                var json = await File.ReadAllTextAsync(filePath);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var summary = JsonSerializer.Deserialize<AlertSummary>(json, options);

                if (summary == null)
                    return;

                // Add to rolling history
                _recentAlerts.Enqueue(summary);
                while (_recentAlerts.Count > MaxAlertHistory)
                    _recentAlerts.TryDequeue(out _);

                _logger.LogInformation("Alert summary processed: ShouldAlert={ShouldAlert}, Reason={Reason}",
                    summary.ShouldAlert, summary.Reason);

                if (summary.ShouldAlert)
                {
                    // Broadcast to all alert subscribers
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

                    _logger.LogWarning("Alert notification broadcast: {Reason} | Critical={Critical}, High={High}",
                        summary.Reason, summary.CriticalCount, summary.HighCount);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing alert file: {FilePath}", filePath);
            }
        }

        /// <summary>
        /// Returns the rolling list of recent alert summaries (newest first).
        /// </summary>
        public static IEnumerable<AlertSummary> GetRecentAlerts() =>
            _recentAlerts.OrderByDescending(a => a.Timestamp);
    }

    /// <summary>
    /// Represents the contents of an alert-summary-*.json file written by Invoke-DailyAlert.ps1.
    /// </summary>
    public class AlertSummary
    {
        public string Timestamp      { get; set; } = string.Empty;
        public bool ShouldAlert      { get; set; }
        public string Reason         { get; set; } = string.Empty;
        public int CriticalCount     { get; set; }
        public int HighCount         { get; set; }
        public int MediumCount       { get; set; }
        public int TotalFindings     { get; set; }
        public int NewFindingsCount  { get; set; }
        public bool Acknowledged     { get; set; }
    }
}
