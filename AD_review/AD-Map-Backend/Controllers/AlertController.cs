using Microsoft.AspNetCore.Mvc;
using AD_Map_Backend.Services;
using System.Text.Json;

namespace AD_Map_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AlertController : ControllerBase
    {
        private readonly ILogger<AlertController> _logger;
        private readonly IConfiguration _configuration;
        private readonly string _dataPath;

        public AlertController(ILogger<AlertController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
            _dataPath = _configuration["DataPath"] ?? Path.Combine(Directory.GetCurrentDirectory(), "Data");
        }

        /// <summary>
        /// Returns the last N alert summaries (newest first).
        /// </summary>
        [HttpGet("recent")]
        [ResponseCache(Duration = 30)]
        public IActionResult GetRecentAlerts([FromQuery] int count = 20)
        {
            var alerts = AlertService.GetRecentAlerts()
                .Take(Math.Min(count, 100))
                .ToList();

            return Ok(new
            {
                Alerts = alerts,
                Total  = alerts.Count,
                HasUnacknowledged = alerts.Any(a => a.ShouldAlert && !a.Acknowledged)
            });
        }

        /// <summary>
        /// Returns finding counts from the most recent baseline file.
        /// </summary>
        [HttpGet("baseline")]
        [ResponseCache(Duration = 60)]
        public IActionResult GetBaseline()
        {
            try
            {
                // Most recent alert-summary file contains the current baseline stats
                var summaryFiles = Directory.GetFiles(_dataPath, "alert-summary-*.json", SearchOption.TopDirectoryOnly)
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.LastWriteTime)
                    .Take(1)
                    .ToList();

                if (!summaryFiles.Any())
                    return Ok(new { Message = "No baseline available yet. Run Invoke-DailyAlert.ps1 to generate the first baseline." });

                var json   = System.IO.File.ReadAllText(summaryFiles[0].FullName);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var summary = JsonSerializer.Deserialize<AlertSummary>(json, options);

                return Ok(new
                {
                    LastRun       = summaryFiles[0].LastWriteTime,
                    Summary       = summary,
                    BaselineFile  = summaryFiles[0].Name
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading baseline");
                return StatusCode(500, new { Error = "Failed to load baseline" });
            }
        }

        /// <summary>
        /// Marks a specific alert as acknowledged. Writes acknowledgement to the alert summary file.
        /// Body: { "timestamp": "2026-03-14T06:01:23Z", "acknowledgedBy": "analyst@domain.com" }
        /// </summary>
        [HttpPost("acknowledge")]
        public IActionResult AcknowledgeAlert([FromBody] AcknowledgeRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Timestamp))
                return BadRequest(new { Error = "Timestamp is required" });

            try
            {
                // Find the matching alert summary file
                var alertFiles = Directory.GetFiles(_dataPath, "alert-summary-*.json", SearchOption.TopDirectoryOnly);
                var options    = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

                foreach (var filePath in alertFiles)
                {
                    try
                    {
                        var json    = System.IO.File.ReadAllText(filePath);
                        var summary = JsonSerializer.Deserialize<AlertSummary>(json, options);

                        if (summary?.Timestamp == request.Timestamp)
                        {
                            summary.Acknowledged = true;
                            var updatedJson = JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true });
                            System.IO.File.WriteAllText(filePath, updatedJson);

                            _logger.LogInformation("Alert acknowledged by {User}: {Timestamp}", request.AcknowledgedBy, request.Timestamp);
                            return Ok(new { Message = "Alert acknowledged", Timestamp = request.Timestamp });
                        }
                    }
                    catch { /* Skip malformed files */ }
                }

                return NotFound(new { Error = "Alert not found for timestamp: " + request.Timestamp });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error acknowledging alert");
                return StatusCode(500, new { Error = "Failed to acknowledge alert" });
            }
        }

        /// <summary>
        /// Returns alert service health status.
        /// </summary>
        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            var alertCount = AlertService.GetRecentAlerts().Count();
            var lastAlert  = AlertService.GetRecentAlerts().FirstOrDefault();

            return Ok(new
            {
                Service       = "AlertService",
                Status        = "Running",
                RecentAlerts  = alertCount,
                LastAlertTime = lastAlert?.Timestamp ?? "Never",
                HasActive     = lastAlert?.ShouldAlert ?? false
            });
        }
    }

    public class AcknowledgeRequest
    {
        public string? Timestamp      { get; set; }
        public string? AcknowledgedBy { get; set; }
    }
}
