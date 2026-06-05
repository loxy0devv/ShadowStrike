/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * WebcamProtection — detects and optionally blocks camera access attempts.
 *
 * Mechanism:
 *   Windows exposes camera devices through two main paths:
 *     1. Media Foundation / DirectShow (IMFMediaSource, IBaseFilter)
 *        tracked via COM activation monitoring
 *     2. WinRT Windows.Media.Capture.MediaCapture
 *        tracked via named-object creation and CreateFile calls to
 *        \\?\ROOT#MEDIA#... device paths
 *     3. Low-level: CreateFile to \Device\Video* / \\?\USB#... paths
 *        tracked in kernel via file-system pre-create callbacks in
 *        PhantomSensor.sys (IRP_MJ_CREATE to camera device names).
 *
 *   User-mode side:
 *     - Enumerate devices on startup, build a set of camera device paths.
 *     - Receive notifications from PhantomSensor.sys (IPC) when a process
 *       opens a camera device.
 *     - Apply the configured policy:
 *         Allow  — silent permit
 *         Ask    — raise alert, block until user responds via GUI API
 *         Block  — silent block
 *
 *   GUI API surface:
 *     - GET  /api/v1/devices/webcam          — list camera devices + access state
 *     - GET  /api/v1/devices/webcam/policy   — get current policy
 *     - PUT  /api/v1/devices/webcam/policy   — set policy (Allow/Ask/Block)
 *     - GET  /api/v1/devices/webcam/access   — recent access events
 *     - POST /api/v1/devices/webcam/allow    — approve a pending Ask
 *     - POST /api/v1/devices/webcam/deny     — deny a pending Ask
 *     - GET  /api/v1/devices/webcam/trusted  — trusted process list
 *     - POST /api/v1/devices/webcam/trusted  — add trusted process
 *     - DELETE /api/v1/devices/webcam/trusted/{id} — remove trusted process
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace ShadowStrike {
namespace Devices {

enum class CameraPolicy : uint8_t {
    Allow,   ///< Permit all access silently
    Ask,     ///< Raise alert, block until GUI approves or denies
    Block    ///< Deny all access silently
};

enum class CameraAccessDecision : uint8_t {
    Pending,
    Allowed,
    Denied
};

struct CameraDevice {
    std::string  deviceId;          ///< hardware device id
    std::wstring friendlyName;
    std::string  symbolicLink;      ///< \\?\... path
    bool         isBusy = false;    ///< currently in use
};

struct CameraAccessEvent {
    uint64_t     eventId = 0;
    std::chrono::system_clock::time_point at{};

    uint32_t     pid = 0;
    std::wstring imagePath;
    std::string  imageNameLower;
    std::string  commandLine;
    std::string  deviceId;
    std::wstring deviceName;

    CameraAccessDecision decision = CameraAccessDecision::Pending;
    std::string  userNote;          ///< populated when user responds through GUI
};

struct TrustedCameraProcess {
    std::string  id;                ///< stable uuid
    std::wstring imagePath;         ///< full path, or wildcard
    std::string  imageNameLower;
    std::string  signerSubject;     ///< if non-empty, only trust if signer matches
    bool         pathIsWildcard = false;
};

using CameraAlertHandler  = std::function<void(const CameraAccessEvent&)>;
using CameraDecisionHandler = std::function<void(uint64_t eventId, CameraAccessDecision)>;

class WebcamProtection {
public:
    [[nodiscard]] static WebcamProtection& Instance() noexcept {
        static WebcamProtection s_instance;
        return s_instance;
    }
    [[nodiscard]] static bool HasInstance() noexcept {
        return Instance().m_initialized;
    }
    [[nodiscard]] bool IsInitialized() const noexcept { return m_initialized; }

    WebcamProtection();
    ~WebcamProtection();

    /// One-time initialization. Enumerates camera devices.
    bool Initialize();
    void Shutdown();

    // -- Policy ----------------------------------------------------------

    [[nodiscard]] CameraPolicy GetPolicy() const noexcept;
    void SetPolicy(CameraPolicy policy) noexcept;

    // -- Trusted process list -------------------------------------------

    void AddTrustedProcess(TrustedCameraProcess entry);
    bool RemoveTrustedProcess(std::string_view id);
    [[nodiscard]] std::vector<TrustedCameraProcess> GetTrustedProcesses() const;

    // -- Device list -----------------------------------------------------

    [[nodiscard]] std::vector<CameraDevice> GetDevices() const;

    /// Refresh device enumeration (call after device hotplug).
    void RefreshDevices();

    // -- Access events ---------------------------------------------------

    [[nodiscard]] std::vector<CameraAccessEvent> GetRecentEvents(size_t limit = 100) const;

    // -- Called by IPC layer when kernel sensor fires --------------------
    //    Returns the decision (Allow/Deny) synchronously where possible
    //    or kicks the Ask flow and returns Pending.
    CameraAccessDecision OnCameraOpenAttempt(
        uint32_t pid,
        std::wstring imagePath,
        std::string commandLine,
        std::string deviceId,
        std::wstring deviceName);

    // -- GUI integration -------------------------------------------------

    /// Register a handler called when policy == Ask and a new event needs
    /// a user decision. The handler must call Respond() to unblock the
    /// waiting kernel IPC acknowledgment.
    uint64_t RegisterAlertHandler(CameraAlertHandler handler);
    bool     UnregisterAlertHandler(uint64_t token);

    /// Respond to a pending Ask event.
    bool Respond(uint64_t eventId, CameraAccessDecision decision,
                 std::string userNote = {});

    // -- Statistics -------------------------------------------------------

    struct Stats {
        uint64_t openAttempts  = 0;
        uint64_t allowed       = 0;
        uint64_t denied        = 0;
        uint64_t pendingAsks   = 0;
    };
    [[nodiscard]] Stats GetStats() const noexcept;

private:
    [[nodiscard]] bool IsTrusted(uint32_t pid,
                                  const std::wstring& imagePath,
                                  const std::string& imageNameLower) const;
    void LogEvent(CameraAccessEvent ev);
    void EnumerateDevices();

    mutable std::mutex           m_mutex;
    CameraPolicy                 m_policy     = CameraPolicy::Ask;
    std::vector<CameraDevice>    m_devices;
    std::vector<TrustedCameraProcess> m_trusted;

    struct PendingAsk {
        CameraAccessEvent event;
        std::condition_variable cv;
        CameraAccessDecision    decision = CameraAccessDecision::Pending;
    };
    std::unordered_map<uint64_t, std::shared_ptr<PendingAsk>> m_pending;
    std::mutex m_pendingMutex;
    std::condition_variable m_pendingCv;

    std::vector<CameraAccessEvent> m_eventLog;
    static constexpr size_t kMaxEventLog = 4096;

    std::vector<std::pair<uint64_t, CameraAlertHandler>> m_alertHandlers;
    std::atomic<uint64_t> m_nextHandlerToken{1};
    std::atomic<uint64_t> m_nextEventId{1};

    std::atomic<uint64_t> m_statAttempts{0};
    std::atomic<uint64_t> m_statAllowed{0};
    std::atomic<uint64_t> m_statDenied{0};

    bool m_initialized = false;
};

} // namespace Devices
} // namespace ShadowStrike
