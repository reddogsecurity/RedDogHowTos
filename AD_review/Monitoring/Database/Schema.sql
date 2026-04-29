-- ============================================
-- AD Security Monitoring Database Schema
-- SQL Server 2016+ / Azure SQL Database
-- ============================================

-- Create database (uncomment if needed)
-- CREATE DATABASE ADSecurityMonitoring;
-- GO

USE ADSecurityMonitoring;
GO

-- ============================================
-- DAILY SECURITY FINDINGS
-- ============================================
CREATE TABLE DailyFindings (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    FindingId NVARCHAR(50) NOT NULL,
    Title NVARCHAR(500) NOT NULL,
    Severity NVARCHAR(20) NOT NULL,
    Category NVARCHAR(100),
    Description NVARCHAR(MAX),
    Remediation NVARCHAR(MAX),
    MITRETechnique NVARCHAR(50),
    Evidence NVARCHAR(MAX),
    CheckedAt DATETIME2 NOT NULL,
    Status NVARCHAR(20) DEFAULT 'Open',
    AcknowledgedBy NVARCHAR(100),
    AcknowledgedAt DATETIME2,
    ResolvedBy NVARCHAR(100),
    ResolvedAt DATETIME2,
    ResolutionNotes NVARCHAR(MAX),
    ExportedAt DATETIME2 DEFAULT GETUTCDATE(),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE()
);

CREATE INDEX IX_DailyFindings_Severity ON Daily Findings(Severity);
CREATE INDEX IX_DailyFindings_CheckedAt ON Daily Findings(CheckedAt);
CREATE INDEX IX_DailyFindings_Status ON Daily Findings(Status);
CREATE INDEX IX_DailyFindings_Category ON Daily Findings(Category);
GO

-- ============================================
-- CROWDSTRIKE DETECTIONS
-- ============================================
CREATE TABLE CrowdStrikeDetections (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    DetectionId NVARCHAR(100) NOT NULL,
    DeviceId NVARCHAR(100),
    DeviceName NVARCHAR(200),
    ADComputerFound BIT DEFAULT 0,
    Severity INT,
    MaxSeverity NVARCHAR(50),
    Status NVARCHAR(50),
    CreatedTime DATETIME2,
    LastBehavior NVARCHAR(MAX),
    Tactic NVARCHAR(100),
    Technique NVARCHAR(100),
    Username NVARCHAR(200),
    ADUserFound BIT DEFAULT 0,
    CommandLine NVARCHAR(MAX),
    FilePath NVARCHAR(MAX),
    FileName NVARCHAR(200),
    MD5Hash NVARCHAR(100),
    SHA256Hash NVARCHAR(100),
    ExternalIpAddress NVARCHAR(50),
    LocalIpAddress NVARCHAR(50),
    CorrelatedWithAD BIT DEFAULT 0,
    AcknowledgedBy NVARCHAR(100),
    AcknowledgedAt DATETIME2,
    ResolvedBy NVARCHAR(100),
    ResolvedAt DATETIME2,
    ResolutionNotes NVARCHAR(MAX),
    ExportedAt DATETIME2 DEFAULT GETUTCDATE(),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE()
);

CREATE INDEX IX_CrowdStrikeDetections_Severity ON CrowdStrikeDetections(Severity);
CREATE INDEX IX_CrowdStrikeDetections_CreatedTime ON CrowdStrikeDetections(CreatedTime);
CREATE INDEX IX_CrowdStrikeDetections_DeviceName ON CrowdStrikeDetections(DeviceName);
CREATE INDEX IX_CrowdStrikeDetections_CorrelatedWithAD ON CrowdStrikeDetections(CorrelatedWithAD);
GO

-- ============================================
-- CROWDSTRIKE DEVICES
-- ============================================
CREATE TABLE CrowdStrikeDevices (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    DeviceId NVARCHAR(100) NOT NULL,
    Hostname NVARCHAR(200),
    ADComputerFound BIT DEFAULT 0,
    OS NVARCHAR(200),
    PlatformName NVARCHAR(100),
    SensorVersion NVARCHAR(50),
    SensorStatus NVARCHAR(50),
    LastSeen DATETIME2,
    ExternalIP NVARCHAR(50),
    LocalIP NVARCHAR(50),
    MacAddress NVARCHAR(50),
    ModifiedDate DATETIME2,
    ReducedFunctionalityMode BIT DEFAULT 0,
    CorrelatedWithAD BIT DEFAULT 0,
    ExportedAt DATETIME2 DEFAULT GETUTCDATE(),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
    UNIQUE(DeviceId, ExportedAt)
);

CREATE INDEX IX_CrowdStrikeDevices_Hostname ON CrowdStrikeDevices(Hostname);
CREATE INDEX IX_CrowdStrikeDevices_SensorStatus ON CrowdStrikeDevices(SensorStatus);
CREATE INDEX IX_CrowdStrikeDevices_LastSeen ON CrowdStrikeDevices(LastSeen);
GO

-- ============================================
-- CROWDSTRIKE VULNERABILITIES
-- ============================================
CREATE TABLE CrowdStrikeVulnerabilities (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    CVEId NVARCHAR(50) NOT NULL,
    CID NVARCHAR(100),
    Hostname NVARCHAR(200),
    Aid NVARCHAR(100),
    CISACategories NVARCHAR(MAX),
    ClosedDate DATETIME2,
    CreatedDate DATETIME2,
    CVEDescription NVARCHAR(MAX),
    ExploitStatus NVARCHAR(100),
    RemediationLevel NVARCHAR(100),
    Severity NVARCHAR(50),
    Status NVARCHAR(50),
    ExportedAt DATETIME2 DEFAULT GETUTCDATE(),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE()
);

CREATE INDEX IX_CrowdStrikeVulnerabilities_CVEId ON CrowdStrikeVulnerabilities(CVEId);
CREATE INDEX IX_CrowdStrikeVulnerabilities_Severity ON CrowdStrikeVulnerabilities(Severity);
CREATE INDEX IX_CrowdStrikeVulnerabilities_ExploitStatus ON CrowdStrikeVulnerabilities(ExploitStatus);
GO

-- ============================================
-- CROWDSTRIKE IDENTITY ALERTS
-- ============================================
CREATE TABLE CrowdStrikeIdentityAlerts (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    AlertId NVARCHAR(100) NOT NULL,
    DeviceId NVARCHAR(100),
    DeviceName NVARCHAR(200),
    Username NVARCHAR(200),
    ADUserFound BIT DEFAULT 0,
    Severity NVARCHAR(50),
    Tactic NVARCHAR(100),
    Technique NVARCHAR(100),
    CreatedTime DATETIME2,
    Description NVARCHAR(MAX),
    CommandLine NVARCHAR(MAX),
    CorrelatedWithAD BIT DEFAULT 0,
    AcknowledgedBy NVARCHAR(100),
    AcknowledgedAt DATETIME2,
    ResolvedBy NVARCHAR(100),
    ResolvedAt DATETIME2,
    ResolutionNotes NVARCHAR(MAX),
    ExportedAt DATETIME2 DEFAULT GETUTCDATE(),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE()
);

CREATE INDEX IX_CrowdStrikeIdentityAlerts_Severity ON CrowdStrikeIdentityAlerts(Severity);
CREATE INDEX IX_CrowdStrikeIdentityAlerts_Username ON CrowdStrikeIdentityAlerts(Username);
CREATE INDEX IX_CrowdStrikeIdentityAlerts_CreatedTime ON CrowdStrikeIdentityAlerts(CreatedTime);
GO

-- ============================================
-- COLLECTION SUMMARY (Metrics)
-- ============================================
CREATE TABLE CollectionSummary (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    CollectionTimestamp DATETIME2 NOT NULL,
    CollectionType NVARCHAR(50),
    CloudRegion NVARCHAR(20),
    TotalDetections INT DEFAULT 0,
    ADDetectionCorrelation INT DEFAULT 0,
    TotalDevices INT DEFAULT 0,
    ADDeviceCorrelation INT DEFAULT 0,
    TotalVulnerabilities INT DEFAULT 0,
    UniqueCVEs INT DEFAULT 0,
    CISAExploitedCVEs INT DEFAULT 0,
    IdentityAlerts INT DEFAULT 0,
    ADIdentityAlertCorrelation INT DEFAULT 0,
    CriticalDetections INT DEFAULT 0,
    HighDetections INT DEFAULT 0,
    ExportedAt DATETIME2 DEFAULT GETUTCDATE(),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE()
);

CREATE INDEX IX_CollectionSummary_Timestamp ON CollectionSummary(CollectionTimestamp);
CREATE INDEX IX_CollectionSummary_Type ON CollectionSummary(CollectionType);
GO

-- ============================================
-- ALERT NOTIFICATIONS LOG
-- ============================================
CREATE TABLE AlertNotifications (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    AlertTimestamp DATETIME2 DEFAULT GETUTCDATE(),
    AlertType NVARCHAR(50) NOT NULL,
    Severity NVARCHAR(20) NOT NULL,
    Title NVARCHAR(500) NOT NULL,
    Summary NVARCHAR(MAX),
    FindingsCount INT DEFAULT 0,
    SentTo NVARCHAR(200),
    DeliveryStatus NVARCHAR(50) DEFAULT 'Sent',
    DeliveryError NVARCHAR(MAX),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE()
);

CREATE INDEX IX_AlertNotifications_Timestamp ON AlertNotifications(AlertTimestamp);
CREATE INDEX IX_AlertNotifications_Severity ON AlertNotifications(Severity);
CREATE INDEX IX_AlertNotifications_DeliveryStatus ON AlertNotifications(DeliveryStatus);
GO

-- ============================================
-- ASSESSMENT SNAPSHOTS (Weekly full assessments)
-- ============================================
CREATE TABLE AssessmentSnapshots (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    SnapshotTimestamp DATETIME2 NOT NULL,
    AssessmentType NVARCHAR(50),
    TotalUsers INT DEFAULT 0,
    TotalGroups INT DEFAULT 0,
    TotalComputers INT DEFAULT 0,
    UsersWithoutMFA INT DEFAULT 0,
    PrivilegedUsers INT DEFAULT 0,
    StaleAccounts INT DEFAULT 0,
    PasswordNeverExpire INT DEFAULT 0,
    KrbtgtAge INT DEFAULT 0,
    RiskScore INT DEFAULT 0,
    MITRETechniques INT DEFAULT 0,
    HighFindings INT DEFAULT 0,
    MediumFindings INT DEFAULT 0,
    LowFindings INT DEFAULT 0,
    DataPath NVARCHAR(500),
    CreatedAt DATETIME2 DEFAULT GETUTCDATE()
);

CREATE INDEX IX_AssessmentSnapshots_Timestamp ON AssessmentSnapshots(SnapshotTimestamp);
CREATE INDEX IX_AssessmentSnapshots_RiskScore ON AssessmentSnapshots(RiskScore);
GO

-- ============================================
-- CONFIGURATION & AUDIT LOG
-- ============================================
CREATE TABLE ConfigurationAudit (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    ConfigKey NVARCHAR(100) NOT NULL,
    OldValue NVARCHAR(MAX),
    NewValue NVARCHAR(MAX),
    ChangedBy NVARCHAR(100),
    ChangedAt DATETIME2 DEFAULT GETUTCDATE(),
    ChangeReason NVARCHAR(500)
);

CREATE INDEX IX_ConfigurationAudit_Key ON ConfigurationAudit(ConfigKey);
CREATE INDEX IX_ConfigurationAudit_ChangedAt ON ConfigurationAudit(ChangedAt);
GO

-- ============================================
-- DATA CLEANUP PROCEDURE
-- ============================================
CREATE PROCEDURE CleanupOldData
    @RetentionDays INT = 365
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @cutoffDate DATETIME2 = DATEADD(day, -@RetentionDays, GETUTCDATE());

    DELETE FROM DailyFindings WHERE CreatedAt < @cutoffDate;
    DELETE FROM CrowdStrikeDetections WHERE CreatedAt < @cutoffDate;
    DELETE FROM CrowdStrikeDevices WHERE CreatedAt < @cutoffDate;
    DELETE FROM CrowdStrikeVulnerabilities WHERE CreatedAt < @cutoffDate;
    DELETE FROM CrowdStrikeIdentityAlerts WHERE CreatedAt < @cutoffDate;
    DELETE FROM CollectionSummary WHERE CreatedAt < @cutoffDate;
    DELETE FROM AlertNotifications WHERE CreatedAt < @cutoffDate;
    DELETE FROM AssessmentSnapshots WHERE CreatedAt < @cutoffDate;
END
GO

-- ============================================
-- VIEWS FOR REPORTING
-- ============================================

-- Current open findings
CREATE VIEW vw_OpenFindings
AS
SELECT
    f.FindingId,
    f.Title,
    f.Severity,
    f.Category,
    f.Description,
    f.CheckedAt,
    f.MITRETechnique,
    DATEDIFF(day, f.CheckedAt, GETUTCDATE()) as DaysOpen
FROM Daily Findings f
WHERE f.Status = 'Open'
ORDER BY
    CASE f.Severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        ELSE 5
    END,
    f.CheckedAt DESC;
GO

-- Critical detections with AD correlation
CREATE VIEW vw_CriticalDetectionsWithAD
AS
SELECT
    d.DetectionId,
    d.DeviceName,
    d.Username,
    d.MaxSeverity,
    d.Tactic,
    d.Technique,
    d.CreatedTime,
    d.ADComputerFound,
    d.ADUserFound,
    d.CorrelatedWithAD
FROM CrowdStrikeDetections d
WHERE (d.MaxSeverity = 'Critical' OR d.MaxSeverity = 'High')
    AND d.CorrelatedWithAD = 1
ORDER BY d.CreatedTime DESC;
GO

-- Weekly trend summary
CREATE VIEW vw_WeeklyTrendSummary
AS
SELECT
    DATEPART(ISO_WEEK, s.SnapshotTimestamp) as WeekNumber,
    YEAR(s.SnapshotTimestamp) as Year,
    MIN(s.SnapshotTimestamp) as SnapshotDate,
    AVG(s.RiskScore) as AvgRiskScore,
    SUM(s.HighFindings) as TotalHighFindings,
    SUM(s.MediumFindings) as TotalMediumFindings,
    SUM(s.UsersWithoutMFA) as UsersWithoutMFA,
    SUM(s.PrivilegedUsers) as PrivilegedUsers
FROM AssessmentSnapshots s
WHERE s.SnapshotTimestamp >= DATEADD(day, -90, GETUTCDATE())
GROUP BY
    DATEPART(ISO_WEEK, s.SnapshotTimestamp),
    YEAR(s.SnapshotTimestamp)
ORDER BY
    Year DESC,
    WeekNumber DESC;
GO

-- ============================================
-- INITIAL SEED DATA
-- ============================================

-- Insert sample configuration
INSERT INTO ConfigurationAudit (ConfigKey, NewValue, ChangedBy, ChangeReason)
VALUES
    ('AlertThreshold', 'High', 'System', 'Initial setup'),
    ('RetentionDays', '365', 'System', 'Initial setup'),
    ('CrowdStrikeEnabled', 'false', 'System', 'Initial setup - pending configuration');
GO

PRINT 'Database schema created successfully!';
PRINT '';
PRINT 'Tables created:';
PRINT '  - DailyFindings';
PRINT '  - CrowdStrikeDetections';
PRINT '  - CrowdStrikeDevices';
PRINT '  - CrowdStrikeVulnerabilities';
PRINT '  - CrowdStrikeIdentityAlerts';
PRINT '  - CollectionSummary';
PRINT '  - AlertNotifications';
PRINT '  - AssessmentSnapshots';
PRINT '  - ConfigurationAudit';
PRINT '';
PRINT 'Views created:';
PRINT '  - vw_OpenFindings';
PRINT '  - vw_CriticalDetectionsWithAD';
PRINT '  - vw_WeeklyTrendSummary';
PRINT '';
PRINT 'Stored procedures:';
PRINT '  - CleanupOldData';
