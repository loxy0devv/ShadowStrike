/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - SERVICE COMMUNICATION MODULE
 * ============================================================================
 *
 * @file ServiceCommunicator.hpp
 * @brief Enterprise-grade IPC engine for secure communication between the
 *        privileged ShadowStrike service and user-mode components (UI, CLI, Tray).
 *
 * Implements a secure, asynchronous Named Pipe server with strict access control
 * (ACLs) to prevent privilege escalation. Handles command dispatching, status
 * broadcasting, and client session management.
 *
 * SECURITY FEATURES:
 * ==================
 * - Secure Named Pipes (\\.\pipe\ShadowStrikeServicePipe)
 * - Strict SDDL (Security Descriptor Definition Language) enforcement
 *   (Allow: SYSTEM, Administrators; Deny: Everyone else)
 * - Message size limits to prevent DoS
 * - Input validation and sanitization
 * - Client impersonation checks
 *
 * ARCHITECTURE:
 * =============
 * - Uses I/O Completion Ports (IOCP) or Overlapped I/O for scalability
 * - Thread pool integration for request processing
 * - JSON-based messaging protocol for extensibility
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include <map>
#include <chrono>
#include <optional>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
namespace ShadowStrike::Service {
    class ServiceCommunicatorImpl;
}

namespace ShadowStrike {
namespace Service {

// ============================================================================
// CONSTANTS
// ============================================================================
namespace CommunicationConstants {
    constexpr const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\ShadowStrikeServicePipe";

    // Default buffer sizes
    constexpr uint32_t IN_BUFFER_SIZE = 64 * 1024;  // 64KB
    constexpr uint32_t OUT_BUFFER_SIZE = 64 * 1024; // 64KB

    // Timeouts
    constexpr uint32_t CONNECT_TIMEOUT_MS = 5000;
    constexpr uint32_t WRITE_TIMEOUT_MS = 2000;

    // Limits
    constexpr size_t MAX_CONCURRENT_CLIENTS = 10;
    constexpr size_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB limit

    // Magic header for binary protocol validation (if used)
    constexpr uint32_t PROTOCOL_MAGIC = 0x53534156; // "SSAV"
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Communication command types
 */
enum class CommandType : uint32_t {
    Unknown             = 0,
    Heartbeat           = 1,    ///< Keep-alive
    GetStatus           = 10,   ///< Request service status
    StartScan           = 20,   ///< Initiate scan
    StopScan            = 21,   ///< Cancel scan
    UpdateConfig        = 30,   ///< Update configuration
    GetConfig           = 31,   ///< Retrieve configuration
    UpdateSignatures    = 40,   ///< Trigger update
    QuarantineAction    = 50,   ///< Restore/Delete quarantined items
    ThreatAlert         = 100,  ///< Server->Client: Threat detected
    LogMessage          = 101,  ///< Server->Client: Log stream

    // ── Server -> Client push events (v2 protocol) ─────────────────────────
    ProtectionStateChanged  = 102,  ///< Real-time protection state flipped
    ScanProgressEvent       = 103,  ///< Async scan progress update
    HeadlineStateChanged    = 104,  ///< Headline protection indicator changed
    AuthFailed              = 105,  ///< Service rejected a client auth attempt
    PgtiFeedUpdated         = 106,  ///< PGTI feed health or status changed
    RecommendationsChanged  = 107,  ///< Active recommendation set changed

    // ── Extended UI command set (v2 protocol) ──────────────────────────────
    AuthHandshake           = 199,  ///< Client presents session auth token

    // Module management
    ListModules             = 200,  ///< Enumerate available protection modules
    SetModuleEnabled        = 201,  ///< Enable / disable a named module
    SetModuleMode           = 202,  ///< Change a module's operating mode
    GetModuleConfig         = 203,  ///< Retrieve module configuration blob
    SetModuleConfig         = 204,  ///< Update module configuration blob

    // Protection control
    PauseProtection         = 210,  ///< Temporarily suspend real-time protection
    ResumeProtection        = 211,  ///< Resume real-time protection

    // Scan control
    // NOTE: Enum member names StartScan and StopScan are already used at values 20
    // and 21 above (existing wire protocol).  In the v2 UI protocol, the dispatcher
    // routes these commands by CommandType value; numeric codes 220 and 221 are
    // reserved in the v2 spec as wire-level routing values but are NOT represented
    // as named C++ enum members to avoid duplicate-name ODR issues.  Dispatcher
    // implementations must use static_cast<CommandType>(220) and (221) or their
    // own routing tables when handling those v2 codes.
    // Similarly, QuarantineAction is at 50 (legacy); 231 is the v2 dispatch code.
    GetScanProgress         = 222,  ///< Poll in-progress scan completion %

    // Quarantine — see also QuarantineAction=50 (legacy restore/delete verb)
    ListQuarantine          = 230,  ///< List all quarantined items

    // Reporting
    GetReports              = 240,  ///< Retrieve historical detection reports
    GetDashboard            = 250,  ///< Dashboard summary (threats, scans, modules)

    // Event subscription
    SubscribeEvents         = 260,  ///< Register for real-time push events

    // PGTI feed management
    ListPGTIFeeds           = 270,  ///< Enumerate configured threat-intel feeds
    SetPGTIFeedEnabled      = 271,  ///< Enable / disable a specific feed
    RefreshPGTIFeeds        = 272,  ///< Force-refresh all enabled feeds

    // Zero-Trust
    GetZeroTrustState       = 280,  ///< Query current Zero-Trust posture
    SetZeroTrustConfig      = 281,  ///< Update Zero-Trust policy
    AnswerZeroTrustPrompt   = 282,  ///< User response to a Zero-Trust prompt

    // Recommendations
    GetRecommendations      = 290,  ///< List pending security recommendations
    DismissRecommendation   = 291,  ///< Dismiss a specific recommendation

    // ── Exclusions / Allowlists (300–319) ─────────────────────────────────
    ListExclusions          = 300,  ///< Enumerate all exclusion rules
    AddExclusion            = 301,  ///< Add a new exclusion rule (path/hash/process)
    RemoveExclusion         = 302,  ///< Remove exclusion rule by id
    UpdateExclusion         = 303,  ///< Modify an existing exclusion rule
    ClearExclusions         = 304,  ///< Remove all exclusion rules (destructive)
    ImportExclusions        = 305,  ///< Bulk-import exclusion list (JSON array)
    ExportExclusions        = 306,  ///< Export all exclusions to JSON

    // ── Policy: Block / Allow / Ask (320–339) ─────────────────────────────
    GetAccessPolicy         = 320,  ///< Get current block/allow/ask policy
    SetAccessPolicy         = 321,  ///< Set block/allow/ask for a feature or path
    ListPolicyRules         = 322,  ///< List all per-feature policy rules
    AddPolicyRule           = 323,  ///< Add a policy rule
    RemovePolicyRule        = 324,  ///< Remove a policy rule by id
    GetDefaultPolicy        = 325,  ///< Query global default policy (block/allow/ask)
    SetDefaultPolicy        = 326,  ///< Set global default policy

    // ── Trust Management (340–359) ─────────────────────────────────────────
    ListTrustedItems        = 340,  ///< List all trusted files/processes/signers
    AddTrustedItem          = 341,  ///< Add a trusted item (hash/path/signer)
    RemoveTrustedItem       = 342,  ///< Remove trusted item by id
    IsTrusted               = 343,  ///< Query trust status for a specific item
    ListTrustedSigners      = 344,  ///< List trusted Authenticode signer subjects
    AddTrustedSigner        = 345,  ///< Trust all files from a signer subject
    RemoveTrustedSigner     = 346,  ///< Revoke signer trust

    // ── Feature Toggles (360–379) ─────────────────────────────────────────
    ListFeatures            = 360,  ///< List all features with enabled/tier state
    SetFeatureEnabled       = 361,  ///< Enable or disable a named feature
    GetFeatureStatus        = 362,  ///< Query a single feature's enabled state
    ResetFeatureDefaults    = 363,  ///< Reset all features to tier defaults

    // ── Protection Toggles (380–399) ──────────────────────────────────────
    GetProtectionStatus     = 380,  ///< Summary: which protections are active
    SetProtectionEnabled    = 381,  ///< Enable/disable a named protection module
    GetRealTimeStatus       = 382,  ///< Real-time protection on/off + state
    SetRealTimeEnabled      = 383,  ///< Toggle real-time protection on/off

    // ── Response Actions (400–419) ────────────────────────────────────────
    KillProcess             = 400,  ///< Terminate a process by PID
    SuspendProcess          = 401,  ///< Suspend all threads in a process
    IsolateProcess          = 402,  ///< Kill + quarantine the process executable
    QuarantineFile          = 403,  ///< Move a file to quarantine by path
    RestoreFromQuarantine   = 404,  ///< Restore a quarantined item (alias: QuarantineAction restore)
    DeleteFromQuarantine    = 405,  ///< Permanently delete quarantined item
    RemediateFile           = 406,  ///< Run automated remediation on a file/PID
    NetworkIsolate          = 407,  ///< Cut a process's network access
    BlockHash               = 408,  ///< Permanently block a file by SHA-256

    // ── Telemetry Views (420–439) ─────────────────────────────────────────
    GetTelemetryStream      = 420,  ///< Subscribe to live telemetry event stream
    QueryTelemetry          = 421,  ///< Query telemetry with filter (time/pid/type)
    GetProcessTree          = 422,  ///< Live process tree with evidence scores
    GetProcessDetail        = 423,  ///< Full detail for a single PID
    GetNetworkFlows         = 424,  ///< Active + recent network connections
    GetFileEvents           = 425,  ///< Recent file create/write/rename events
    GetRegistryEvents       = 426,  ///< Recent registry modifications
    GetDnsQueries           = 427,  ///< Recent DNS query log

    // ── Alert / Detection Views (440–459) ─────────────────────────────────
    ListAlerts              = 440,  ///< List recent alerts (paginated)
    GetAlertDetail          = 441,  ///< Full alert detail by id
    DismissAlert            = 442,  ///< Mark alert as reviewed
    GetDetectionHistory     = 443,  ///< Detection history with filter
    GetDetectionDetail      = 444,  ///< Full detection detail (rules matched, evidence)
    GetAttackChain          = 445,  ///< Attack chain / story for a detection
    ExportAlert             = 446,  ///< Export alert detail as JSON/CSV

    // ── Webcam / Device Protection (460–479) ──────────────────────────────
    GetWebcamPolicy         = 460,  ///< Get current camera access policy
    SetWebcamPolicy         = 461,  ///< Set camera policy (Allow/Ask/Block)
    ListWebcamDevices       = 462,  ///< Enumerate camera devices
    GetWebcamAccessLog      = 463,  ///< Recent camera access events
    AllowWebcamAccess       = 464,  ///< Approve a pending Ask event
    DenyWebcamAccess        = 465,  ///< Deny a pending Ask event
    ListWebcamTrusted       = 466,  ///< List trusted camera processes
    AddWebcamTrusted        = 467,  ///< Add trusted process for camera
    RemoveWebcamTrusted     = 468,  ///< Remove trusted process

    // ── Per-Policy Configuration (480–499) ───────────────────────────────
    GetTierInfo             = 480,  ///< Current product tier + license info
    ListPolicies            = 481,  ///< All named policy groups
    GetPolicy               = 482,  ///< Single policy by name
    SetPolicy               = 483,  ///< Update a policy key/value
    ResetPolicy             = 484,  ///< Reset policy to defaults
    ExportPolicy            = 485,  ///< Export all policies as JSON
    ImportPolicy            = 486,  ///< Import policies from JSON

    // ── EDR-specific (500–519) ────────────────────────────────────────────
    ListForensicArtifacts   = 500,  ///< List collected forensic artifacts (EDR+)
    CollectArtifact         = 501,  ///< Trigger artifact collection for a PID
    GetIncidents            = 502,  ///< List incidents (EDR+)
    GetIncidentDetail       = 503,  ///< Full incident detail
    CreateIncident          = 504,  ///< Manually create incident
    RunPlaybook             = 505,  ///< Execute named response playbook (EDR+)
    GetPlaybooks            = 506,  ///< List available playbooks
    GetHuntResults          = 507,  ///< Threat hunting query results (EDR+)
    SubmitHuntQuery         = 508,  ///< Execute a hunt query (IOC/YARA)
    GetVulnScanResults      = 509,  ///< Vulnerability scan results (EDR+)
    StartVulnScan           = 510,  ///< Trigger vulnerability scan
    GetLiveResponseShell    = 511,  ///< Live response: execute command + return output (EDR+)

    // ── XDR-specific (520–539) ────────────────────────────────────────────
    GetXDRCorrelations      = 520,  ///< Cross-source correlation results (XDR+)
    GetXDRStoryline         = 521,  ///< XDR attack storyline
    GetNetworkDetections    = 522,  ///< Network-layer detections (XDR+)
    GetEmailThreats         = 523,  ///< Email threat detections (XDR+)
    GetIdentityAlerts       = 524,  ///< Identity / AD threat alerts (XDR+)
    RunSOARPlaybook         = 525,  ///< SOAR local playbook (XDR+)
    GetFleetStatus          = 526,  ///< Multi-endpoint fleet summary (XDR+)

    // ── Rule Management (540–559) ─────────────────────────────────────────
    ListRules               = 540,  ///< List detection rules with stats
    GetRuleDetail           = 541,  ///< Single rule detail by id
    EnableRule              = 542,  ///< Enable a rule by id
    DisableRule             = 543,  ///< Disable a rule by id
    ReloadRules             = 544,  ///< Hot-reload all rule corpora
    ImportCustomRule        = 545,  ///< Import a custom native rule (EDR+)
    DeleteCustomRule        = 546,  ///< Delete custom rule (EDR+)
};

/**
 * @brief Client connection status
 */
enum class ClientStatus : uint8_t {
    Disconnected = 0,
    Connecting   = 1,
    Connected    = 2,
    Authenticated= 3,
    Error        = 4
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief IPC Message Structure
 */
struct IpcMessage {
    uint32_t magic = CommunicationConstants::PROTOCOL_MAGIC;
    CommandType type = CommandType::Unknown;
    uint32_t payloadSize = 0;
    uint64_t timestamp = 0;
    // Payload follows immediately after header in wire format
    std::vector<uint8_t> payload;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics for the communication subsystem
 */
struct CommunicatorStats {
    std::atomic<uint64_t> messagesReceived{0};
    std::atomic<uint64_t> messagesSent{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::atomic<uint64_t> connectionAttempts{0};
    std::atomic<uint64_t> activeConnections{0};
    std::atomic<uint64_t> droppedPackets{0};
    std::atomic<uint64_t> authFailures{0};

    CommunicatorStats() noexcept = default;
    CommunicatorStats(const CommunicatorStats& other) noexcept;
    CommunicatorStats& operator=(const CommunicatorStats& other) noexcept;
    CommunicatorStats(CommunicatorStats&&) = delete;
    CommunicatorStats& operator=(CommunicatorStats&&) = delete;

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * @brief Callback for handling received commands
 * @param cmd The command type
 * @param payload The raw payload data
 * @param responsePayload [Out] Data to send back to client
 * @return true if handled successfully
 */
using CommandHandler = std::function<bool(CommandType cmd,
                                          const std::vector<uint8_t>& payload,
                                          std::vector<uint8_t>& responsePayload)>;

/**
 * @brief Callback for v2 Envelope command handlers (verbs >= 100).
 *
 * Invoked by the ServiceCommunicator when it parses a v2 (24-byte Envelope)
 * frame from a connected client.  The handler is responsible for calling
 * SendResponseEnvelope() to send its reply.
 *
 * @param clientId    Opaque client identifier assigned at connection time.
 * @param sessionId   Windows logon session ID of the connecting process
 *                    (obtained via GetNamedPipeClientSessionId at accept time).
 *                    Used to verify IpcAuthToken per-session tokens.
 * @param requestId   Caller-side correlation ID echoed in the response envelope.
 * @param jsonPayload Raw UTF-8 JSON string extracted from the Envelope frame.
 */
using V2CommandHandler = std::function<void(std::uint64_t clientId,
                                             std::uint32_t sessionId,
                                             std::uint64_t requestId,
                                             std::string_view jsonPayload)>;

/**
 * @brief Callback for connection events
 */
using ConnectionCallback = std::function<void(uint64_t clientId, bool connected)>;

// ============================================================================
// SERVICE COMMUNICATOR CLASS
// ============================================================================

/**
 * @class ServiceCommunicator
 * @brief Manages secure IPC between the service and clients.
 */
class ServiceCommunicator final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    [[nodiscard]] static ServiceCommunicator& Instance() noexcept;

    // Delete copy/move
    ServiceCommunicator(const ServiceCommunicator&) = delete;
    ServiceCommunicator& operator=(const ServiceCommunicator&) = delete;
    ServiceCommunicator(ServiceCommunicator&&) = delete;
    ServiceCommunicator& operator=(ServiceCommunicator&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the IPC server
     * @return true if initialized successfully (security descriptor created)
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Start accepting connections
     * @return true if server started
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Stop the server and close connections
     */
    void Stop();

    /**
     * @brief Check if server is running
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // COMMUNICATION
    // ========================================================================

    /**
     * @brief Register a handler for a specific command type
     * @param type Command type to handle
     * @param handler Function to execute
     */
    void RegisterHandler(CommandType type, CommandHandler handler);

    /**
     * @brief Register a v2 Envelope handler for a specific command type.
     *
     * When the ServiceCommunicator receives a 24-byte Envelope frame whose
     * type field equals @p type, it invokes @p handler with the parsed client
     * context.  Replaces any previously registered handler for @p type.
     * Thread-safe; may be called before or after Start().
     *
     * @param type    CommandType value identifying this verb.
     * @param handler Callback that processes the request and sends a reply via
     *                SendResponseEnvelope().
     */
    void RegisterV2Handler(CommandType type, V2CommandHandler handler);

    /**
     * @brief Return whether a client has been authenticated via AuthHandshake.
     *
     * Thread-safe.
     *
     * @param clientId  Client identifier from the V2CommandHandler argument.
     * @return true if MarkClientAuthenticated() has been called for this client
     *         and the client has not yet disconnected.
     */
    [[nodiscard]] bool IsClientAuthenticated(std::uint64_t clientId) const;

    /**
     * @brief Send a v2 Envelope response to a specific connected client.
     *
     * Builds the 24-byte wire header, appends @p jsonPayload, and writes the
     * frame to the client's pipe handle.  If the client has already
     * disconnected, the write fails silently (WriteFile error is logged).
     *
     * Thread-safe; may be called from any thread (including a V2CommandHandler
     * invoked on a thread-pool task).
     *
     * @param clientId    Client to send to (from V2CommandHandler argument).
     * @param type        CommandType echoed in the response Envelope header.
     * @param requestId   Correlation ID echoed from the request Envelope.
     * @param jsonPayload UTF-8 JSON body (must be <= MAX_MESSAGE_SIZE bytes).
     */
    void SendResponseEnvelope(std::uint64_t    clientId,
                              CommandType      type,
                              std::uint64_t    requestId,
                              std::string_view jsonPayload);

    /**
     * @brief Broadcast a message to all connected and authenticated clients
     * @param type Message type
     * @param payload Data payload
     * @return Number of clients reached
     */
    [[nodiscard]] size_t Broadcast(CommandType type, const std::string& payload);

    /**
     * @brief Broadcast binary data
     */
    [[nodiscard]] size_t Broadcast(CommandType type, const std::vector<uint8_t>& payload);

    /**
     * @brief Broadcast a pre-serialised 24-byte Envelope to all authenticated clients.
     *
     * The serialised envelope is written as-is (caller must use EventPush::Build*
     * or Envelope::Serialize to produce it). Each client is subject to an
     * independent per-event-type token-bucket rate limit (20 events/sec, burst 20).
     * Unauthenticated clients are silently skipped.
     *
     * @param eventType           Command type (used for rate-bucket keying only).
     * @param serializedEnvelope  Pre-built wire bytes including 24-byte header.
     * @return Number of clients that received the message.
     */
    [[nodiscard]] size_t BroadcastEvent(CommandType                       eventType,
                                        const std::vector<std::uint8_t>& serializedEnvelope);

    /**
     * @brief Mark a client as authenticated so it receives BroadcastEvent messages.
     *
     * Called by the AuthHandshake command handler after successful token
     * verification. Safe to call from any thread.
     *
     * @param clientId  The client identifier assigned during connection.
     */
    void MarkClientAuthenticated(std::uint64_t clientId);

    /**
     * @brief Revoke a client's authenticated status.
     *
     * Idempotent. Called automatically when the client disconnects.
     *
     * @param clientId  The client identifier to revoke.
     */
    void RevokeClientAuthentication(std::uint64_t clientId);

    /**
     * @brief Return the Windows mandatory integrity level of the connected process.
     *
     * Captured at accept time via OpenProcessToken + TokenIntegrityLevel.
     * Returns SECURITY_MANDATORY_MEDIUM_RID (0x2000) if the client is not
     * found or if identity capture failed (conservative default).
     *
     * Use this to enforce per-operation privilege requirements:
     *   - Informational reads: Medium (0x2000) or higher
     *   - Write / toggle ops: High (0x3000) or higher
     *   - Destructive ops:    High (0x3000) or higher
     *
     * @param clientId  Client identifier from the V2CommandHandler argument.
     * @return SECURITY_MANDATORY_*_RID constant (DWORD).
     */
    [[nodiscard]] DWORD GetClientIntegrityLevel(std::uint64_t clientId) const noexcept;

    /**
     * @brief Return the string SID of the connecting user (e.g. "S-1-5-21-...").
     * Returns empty string if not available.
     */
    [[nodiscard]] std::wstring GetClientSid(std::uint64_t clientId) const noexcept;

    /**
     * @brief Return the PID of the connected client process.
     * Returns 0 if not available.
     */
    [[nodiscard]] DWORD GetClientPid(std::uint64_t clientId) const noexcept;

    // ========================================================================
    // DIAGNOSTICS & MANAGEMENT
    // ========================================================================

    /**
     * @brief Get current statistics
     */
    [[nodiscard]] CommunicatorStats GetStats() const;

    /**
     * @brief Reset statistics
     */
    void ResetStats();

    /**
     * @brief Perform self-test of IPC mechanisms
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ServiceCommunicator();
    ~ServiceCommunicator();

    // PIMPL
    std::unique_ptr<ServiceCommunicatorImpl> m_impl;

    static std::atomic<bool> s_instanceCreated;
};

} // namespace Service
} // namespace ShadowStrike
