/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * BackendAPI — unified in-process API surface for all GUI-facing operations.
 *
 * Every feature exposed in the REST API and future desktop GUI is backed by
 * a method here. The REST server routes call into BackendAPI; the future
 * native GUI desktop app calls the same methods directly.
 *
 * Design principles:
 *   - One method per logical user action (not one method per HTTP verb).
 *   - All methods are synchronous, thread-safe, and return structured results.
 *   - Tier gating is applied here — callers never need to check the license.
 *   - All response types are plain C++ structs; JSON serialization is in the
 *     REST layer, not here.
 *   - Methods that modify state return a Result<T> with an error code + message.
 *
 * Tier availability is indicated in each method's doc comment:
 *   [ALL]     — Available in all tiers (Home, EDR, XDR)
 *   [EDR+]    — EDR and XDR only
 *   [XDR]     — XDR only
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace ShadowStrike::Products::Shared::API {

// ---------------------------------------------------------------------------
// Common result type
// ---------------------------------------------------------------------------

enum class ApiError : uint16_t {
    None = 0,
    NotInitialized,
    FeatureNotAvailable,    ///< Tier gate denied
    InvalidArgument,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    InternalError,
    OperationInProgress,
    RateLimited,
};

template<typename T>
struct Result {
    T         value{};
    ApiError  error = ApiError::None;
    std::string message;

    [[nodiscard]] bool ok() const noexcept { return error == ApiError::None; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
};

template<>
struct Result<void> {
    ApiError  error = ApiError::None;
    std::string message;
    [[nodiscard]] bool ok() const noexcept { return error == ApiError::None; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
};

// ---------------------------------------------------------------------------
// Protection status — [ALL]
// ---------------------------------------------------------------------------

struct ProtectionStatus {
    bool rtpEnabled              = false;
    bool behaviorBlockerRunning  = false;
    bool kernelSensorConnected   = false;
    bool mlEngineOperational     = false;
    bool detectionEngineLoaded   = false;
    bool tamperProtectionActive  = false;
    uint32_t activeRuleCount     = 0;
    uint32_t loadedModelCount    = 0;
    std::chrono::system_clock::time_point since{};
};

// ---------------------------------------------------------------------------
// Scan control — [ALL]
// ---------------------------------------------------------------------------

enum class ScanType   { Quick, Full, Custom, Memory };
enum class ScanStatus { Idle, Running, Paused, Completed, Cancelled, Error };

struct ScanState {
    ScanStatus status        = ScanStatus::Idle;
    float      pctComplete   = 0.0f;
    uint64_t   filesScanned  = 0;
    uint64_t   threatsFound  = 0;
    uint64_t   filesSkipped  = 0;
    std::wstring currentFile;
    std::chrono::milliseconds elapsed{0};
    std::chrono::milliseconds eta{0};
};

// ---------------------------------------------------------------------------
// Quarantine — [ALL]
// ---------------------------------------------------------------------------

struct QuarantineItem {
    std::string  id;
    std::wstring originalPath;
    std::string  sha256;
    std::string  threatName;
    std::string  detectionSource;
    float        confidence     = 0.0f;
    std::chrono::system_clock::time_point quarantinedAt{};
    uint64_t     fileSize       = 0;
};

// ---------------------------------------------------------------------------
// Exclusions / Allowlists — [ALL]
// ---------------------------------------------------------------------------

enum class ExclusionType {
    FilePath,     ///< Exact file path or glob
    Directory,    ///< Directory (recursive)
    Extension,    ///< File extension e.g. ".pdf"
    ProcessName,  ///< Process image name
    SHA256Hash,   ///< Exact SHA-256 hash
    SignerSubject ///< Authenticode signer subject CN
};

struct ExclusionEntry {
    std::string  id;
    ExclusionType type  = ExclusionType::FilePath;
    std::wstring  value;         ///< The excluded value (path, hash, name, etc.)
    std::string   description;   ///< Human note
    bool          enabled  = true;
    bool          caseSensitive = false;
    std::chrono::system_clock::time_point createdAt{};
};

// ---------------------------------------------------------------------------
// Block / Allow / Ask policies — [ALL]
// ---------------------------------------------------------------------------

enum class AccessDecision : uint8_t {
    Allow    = 0,
    Block    = 1,
    Ask      = 2,   ///< Prompt user (GUI must handle callback)
    AlwaysAllow = 3, ///< Permanent trust
    AlwaysBlock = 4  ///< Permanent block
};

enum class PolicyScope : uint8_t {
    Global,        ///< Platform-wide
    PerProcess,    ///< For a specific process image
    PerPath,       ///< For a specific file/dir path
    PerNetwork,    ///< For a specific host/IP/port
    WebcamAccess,  ///< Camera access control
    MicrophoneAccess ///< Microphone access control
};

struct PolicyEntry {
    std::string     id;
    PolicyScope     scope  = PolicyScope::Global;
    AccessDecision  decision = AccessDecision::Allow;
    std::wstring    target;   ///< Process path, dir, host, etc. (scope-dependent)
    std::string     signerSubject; ///< Optional signer match
    bool            enabled = true;
    std::chrono::system_clock::time_point createdAt{};
    std::string     note;
};

// ---------------------------------------------------------------------------
// Feature toggles — [ALL]
// ---------------------------------------------------------------------------

struct FeatureToggle {
    std::string id;          ///< e.g. "RealTimeProtection", "BehaviorBlocker"
    std::string displayName;
    std::string description;
    bool        enabled      = true;
    bool        tierLocked   = false; ///< Cannot change — below tier minimum
    std::string tier;        ///< Minimum tier: "All", "EDR", "XDR"
};

// ---------------------------------------------------------------------------
// Trust management — [ALL]
// ---------------------------------------------------------------------------

struct TrustedEntry {
    std::string  id;
    std::string  type;        ///< "signer", "hash", "path", "process"
    std::wstring value;
    std::string  signerSubject;
    std::string  note;
    bool         permanent = false;
    std::chrono::system_clock::time_point addedAt{};
};

// ---------------------------------------------------------------------------
// Response actions — [ALL] / [EDR+]
// ---------------------------------------------------------------------------

enum class ResponseAction : uint8_t {
    KillProcess,           ///< [ALL] Terminate a process
    SuspendProcess,        ///< [ALL] Suspend process threads
    QuarantineFile,        ///< [ALL] Move file to quarantine vault
    DeleteFile,            ///< [ALL] Permanently delete file
    IsolateNetwork,        ///< [EDR+] Cut network access
    RestoreFromQuarantine, ///< [ALL] Restore quarantined file
    TriggerScan,           ///< [ALL] Start a scan on target
    CollectForensics,      ///< [EDR+] Collect forensic artifacts
    RunPlaybook,           ///< [XDR] Execute a SOAR playbook
};

struct ResponseActionRequest {
    ResponseAction action;
    uint32_t       pid    = 0;         ///< For process actions
    std::wstring   path;               ///< For file/dir actions
    std::string    quarantineItemId;   ///< For quarantine restore/delete
    std::string    playbookId;         ///< For RunPlaybook
    std::string    reason;             ///< Analyst note
};

struct ResponseActionResult {
    bool        success   = false;
    std::string message;
    std::string forensicsCollectionId;  ///< If action == CollectForensics
};

// ---------------------------------------------------------------------------
// Alerts / Detections — [ALL]
// ---------------------------------------------------------------------------

enum class AlertSeverity : uint8_t {
    Informational = 0, Low = 1, Medium = 2, High = 3, Critical = 4
};

struct AlertEntry {
    std::string  id;
    AlertSeverity severity     = AlertSeverity::Low;
    std::string  threatName;
    std::string  description;
    std::string  detectionSource;
    std::wstring imagePath;
    uint32_t     pid           = 0;
    float        confidence    = 0.0f;
    float        score         = 0.0f;
    std::vector<std::string> mitreTechniques;
    std::vector<std::string> matchedRules;
    std::chrono::system_clock::time_point detectedAt{};
    bool         acknowledged  = false;
    bool         actedUpon     = false;
};

// ---------------------------------------------------------------------------
// Telemetry views — [ALL] / [EDR+]
// ---------------------------------------------------------------------------

struct TelemetrySummary {
    uint64_t eventsLastHour  = 0;
    uint64_t eventsLastDay   = 0;
    uint64_t alertsLastHour  = 0;
    uint64_t alertsLastDay   = 0;
    uint64_t scansDone       = 0;
    uint64_t threatsBlocked  = 0;
    uint64_t filesQuarantined = 0;
    std::chrono::system_clock::time_point since{};
};

struct ProcessTreeEntry {
    uint32_t     pid;
    uint32_t     parentPid;
    std::wstring imagePath;
    std::string  imageNameLower;
    std::string  commandLine;
    float        riskScore = 0.0f;
    std::vector<std::string> matchedRules;
    std::vector<uint32_t>    childPids;
};

// ---------------------------------------------------------------------------
// Webcam protection — [ALL]
// ---------------------------------------------------------------------------

enum class DevicePolicy : uint8_t { Allow = 0, Ask = 1, Block = 2 };

struct WebcamStatus {
    DevicePolicy policy        = DevicePolicy::Ask;
    uint32_t     deviceCount   = 0;
    uint32_t     accessAttempts = 0;
    uint32_t     denied        = 0;
    uint32_t     allowed       = 0;
    uint32_t     pending       = 0;
};

struct WebcamTrustedProcess {
    std::string  id;
    std::wstring imagePath;
    std::string  signerSubject;
    bool         pathIsWildcard = false;
};

// ---------------------------------------------------------------------------
// Per-policy configuration — [ALL]
// ---------------------------------------------------------------------------

struct PolicyConfig {
    std::string category;     ///< e.g. "RealTimeProtection", "Ransomware"
    std::string key;          ///< config key within category
    std::string value;        ///< JSON-encoded value
    std::string type;         ///< "bool", "int", "string", "float"
    std::string description;
    bool        readOnly = false;
};

// ============================================================================
// BackendAPI — the unified in-process API
// ============================================================================

class BackendAPI {
public:
    [[nodiscard]] static BackendAPI& Instance() noexcept;

    // -----------------------------------------------------------------------
    // Protection status [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<ProtectionStatus> GetProtectionStatus();
    [[nodiscard]] Result<void>             EnableRealTimeProtection(bool enable);

    // -----------------------------------------------------------------------
    // Scan control [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<void>      StartScan(ScanType type,
                                               std::vector<std::wstring> customPaths = {});
    [[nodiscard]] Result<void>      StopScan();
    [[nodiscard]] Result<void>      PauseScan();
    [[nodiscard]] Result<void>      ResumeScan();
    [[nodiscard]] Result<ScanState> GetScanState();

    // -----------------------------------------------------------------------
    // Quarantine [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<std::vector<QuarantineItem>> ListQuarantine(
        uint32_t limit = 200, uint32_t offset = 0);
    [[nodiscard]] Result<void> RestoreFromQuarantine(std::string_view id);
    [[nodiscard]] Result<void> DeleteFromQuarantine(std::string_view id);
    [[nodiscard]] Result<void> DeleteAllQuarantine();
    [[nodiscard]] Result<QuarantineItem> GetQuarantineItem(std::string_view id);

    // -----------------------------------------------------------------------
    // Exclusions / Allowlists [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<std::vector<ExclusionEntry>> ListExclusions();
    [[nodiscard]] Result<ExclusionEntry>  AddExclusion(ExclusionType type,
                                                         std::wstring value,
                                                         std::string description = {});
    [[nodiscard]] Result<void>            RemoveExclusion(std::string_view id);
    [[nodiscard]] Result<void>            EnableExclusion(std::string_view id, bool enable);

    // -----------------------------------------------------------------------
    // Block / Allow / Ask policies [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<std::vector<PolicyEntry>> ListPolicies(
        std::optional<PolicyScope> scopeFilter = std::nullopt);
    [[nodiscard]] Result<PolicyEntry> AddPolicy(PolicyScope scope,
                                                  AccessDecision decision,
                                                  std::wstring target,
                                                  std::string note = {});
    [[nodiscard]] Result<void>        RemovePolicy(std::string_view id);
    [[nodiscard]] Result<void>        UpdatePolicyDecision(std::string_view id,
                                                             AccessDecision newDecision);

    // -----------------------------------------------------------------------
    // Feature toggles [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<std::vector<FeatureToggle>> ListFeatureToggles();
    [[nodiscard]] Result<void>                       SetFeatureEnabled(
                                                       std::string_view featureId, bool enable);

    // -----------------------------------------------------------------------
    // Trust management [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<std::vector<TrustedEntry>> ListTrustedEntries();
    [[nodiscard]] Result<TrustedEntry>  AddTrustedEntry(std::string type,
                                                          std::wstring value,
                                                          std::string note = {},
                                                          bool permanent = false);
    [[nodiscard]] Result<void>          RemoveTrustedEntry(std::string_view id);

    // -----------------------------------------------------------------------
    // Response actions [ALL/EDR+]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<ResponseActionResult> ExecuteAction(
        const ResponseActionRequest& req);

    // -----------------------------------------------------------------------
    // Alerts / Detections [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<std::vector<AlertEntry>> ListAlerts(
        uint32_t limit = 100, uint32_t offset = 0,
        std::optional<AlertSeverity> minSeverity = std::nullopt);
    [[nodiscard]] Result<AlertEntry> GetAlert(std::string_view id);
    [[nodiscard]] Result<void>       AcknowledgeAlert(std::string_view id);
    [[nodiscard]] Result<void>       DismissAlert(std::string_view id);

    // -----------------------------------------------------------------------
    // Telemetry views [ALL/EDR+]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<TelemetrySummary>           GetTelemetrySummary();
    [[nodiscard]] Result<std::vector<ProcessTreeEntry>> GetProcessTree();

    // -----------------------------------------------------------------------
    // Webcam protection [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<WebcamStatus>                   GetWebcamStatus();
    [[nodiscard]] Result<void>                           SetWebcamPolicy(DevicePolicy p);
    [[nodiscard]] Result<std::vector<WebcamTrustedProcess>> ListWebcamTrusted();
    [[nodiscard]] Result<WebcamTrustedProcess>           AddWebcamTrustedProcess(
                                                           std::wstring imagePath,
                                                           std::string signerSubject = {},
                                                           bool isWildcard = false);
    [[nodiscard]] Result<void>                           RemoveWebcamTrustedProcess(std::string_view id);
    [[nodiscard]] Result<void>                           ApproveWebcamAccess(uint64_t eventId);
    [[nodiscard]] Result<void>                           DenyWebcamAccess(uint64_t eventId);

    // -----------------------------------------------------------------------
    // Per-policy configuration [ALL]
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<std::vector<PolicyConfig>> ListPolicyConfigs(
        std::optional<std::string_view> category = std::nullopt);
    [[nodiscard]] Result<PolicyConfig> GetPolicyConfig(std::string_view category,
                                                         std::string_view key);
    [[nodiscard]] Result<void>         SetPolicyConfig(std::string_view category,
                                                         std::string_view key,
                                                         std::string_view value);

    // -----------------------------------------------------------------------
    // Tier / License info [ALL]
    // -----------------------------------------------------------------------
    struct LicenseInfo {
        std::string tier;           ///< "Home", "EDR", "XDR"
        std::string organization;
        std::string licenseId;
        bool        valid    = false;
        std::chrono::system_clock::time_point expiresAt{};
    };
    [[nodiscard]] Result<LicenseInfo> GetLicenseInfo();

    // -----------------------------------------------------------------------
    // Statistics [ALL]
    // -----------------------------------------------------------------------
    struct EngineStats {
        uint64_t totalScans     = 0;
        uint64_t infections     = 0;
        uint64_t cacheHits      = 0;
        uint64_t ruleMatches    = 0;
        double   avgScanTimeMs  = 0.0;
        uint64_t uptime_seconds = 0;
    };
    [[nodiscard]] Result<EngineStats> GetEngineStats();

    BackendAPI(const BackendAPI&)            = delete;
    BackendAPI& operator=(const BackendAPI&) = delete;

private:
    BackendAPI() = default;
    ~BackendAPI() = default;

    [[nodiscard]] bool IsTierAllowed(const char* featureHint) const noexcept;
    [[nodiscard]] std::string GenerateId() const;
};

} // namespace ShadowStrike::Products::Shared::API
