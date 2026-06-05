/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "WebcamProtection.hpp"

#include <Windows.h>
#include <SetupAPI.h>
#include <devpkey.h>
#include <mfapi.h>
#include <mfidl.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>

#pragma comment(lib, "setupapi.lib")

namespace ShadowStrike {
namespace Devices {

namespace {
std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::string lower(const std::wstring& w) {
    std::string s; s.reserve(w.size());
    for (auto c : w) s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c & 0xFF))));
    return s;
}
std::string generateUuid() {
    // Simple timestamp+counter uuid for trusted-process entries
    static std::atomic<uint64_t> seq{0};
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::ostringstream oss;
    oss << std::hex << now << "-" << seq.fetch_add(1, std::memory_order_relaxed);
    return oss.str();
}
} // anon

WebcamProtection::WebcamProtection() = default;
WebcamProtection::~WebcamProtection() { Shutdown(); }

bool WebcamProtection::Initialize() {
    std::lock_guard<std::mutex> g(m_mutex);
    if (m_initialized) return true;
    EnumerateDevices();
    m_initialized = true;
    return true;
}

void WebcamProtection::Shutdown() {
    std::lock_guard<std::mutex> g(m_mutex);
    m_initialized = false;
    m_pending.clear();
}

void WebcamProtection::EnumerateDevices() {
    m_devices.clear();

    // Camera devices appear under KSCATEGORY_VIDEO_CAMERA and/or
    // KSCATEGORY_CAPTURE on Windows 10+. We enumerate via SetupAPI.
    static const GUID CAMERA_CAT = {0xe5323777,0xf976,0x4f5b,
                                    {0x9b,0x55,0xb9,0x46,0x99,0xc4,0x6e,0x44}};
    HDEVINFO devs = SetupDiGetClassDevsW(&CAMERA_CAT, nullptr, nullptr,
                                         DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devs == INVALID_HANDLE_VALUE) return;

    SP_DEVICE_INTERFACE_DATA iface{};
    iface.cbSize = sizeof(iface);
    DWORD idx = 0;
    while (SetupDiEnumDeviceInterfaces(devs, nullptr, &CAMERA_CAT, idx++, &iface)) {
        DWORD needed = 0;
        SetupDiGetDeviceInterfaceDetailW(devs, &iface, nullptr, 0, &needed, nullptr);
        if (needed == 0) continue;
        auto detail = std::make_unique<uint8_t[]>(needed);
        auto* d = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detail.get());
        d->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        SP_DEVINFO_DATA devInfo{};
        devInfo.cbSize = sizeof(devInfo);
        if (!SetupDiGetDeviceInterfaceDetailW(devs, &iface, d, needed, nullptr, &devInfo))
            continue;

        CameraDevice cam;
        cam.symbolicLink = lower(std::wstring(d->DevicePath));
        std::ostringstream idss;
        idss << "cam-" << idx;
        cam.deviceId = idss.str();

        // Get friendly name
        WCHAR name[256] = {};
        if (SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_FRIENDLYNAME,
                                              nullptr,
                                              reinterpret_cast<PBYTE>(name),
                                              sizeof(name), nullptr)) {
            cam.friendlyName = name;
        } else {
            cam.friendlyName = L"Camera " + std::to_wstring(idx);
        }
        m_devices.push_back(std::move(cam));
    }
    SetupDiDestroyDeviceInfoList(devs);
}

CameraPolicy WebcamProtection::GetPolicy() const noexcept {
    std::lock_guard<std::mutex> g(m_mutex);
    return m_policy;
}

void WebcamProtection::SetPolicy(CameraPolicy policy) noexcept {
    std::lock_guard<std::mutex> g(m_mutex);
    m_policy = policy;
}

void WebcamProtection::AddTrustedProcess(TrustedCameraProcess entry) {
    if (entry.id.empty()) entry.id = generateUuid();
    std::lock_guard<std::mutex> g(m_mutex);
    m_trusted.push_back(std::move(entry));
}

bool WebcamProtection::RemoveTrustedProcess(std::string_view id) {
    std::lock_guard<std::mutex> g(m_mutex);
    auto it = std::remove_if(m_trusted.begin(), m_trusted.end(),
                             [&](const auto& t){ return t.id == id; });
    if (it == m_trusted.end()) return false;
    m_trusted.erase(it, m_trusted.end());
    return true;
}

std::vector<TrustedCameraProcess> WebcamProtection::GetTrustedProcesses() const {
    std::lock_guard<std::mutex> g(m_mutex);
    return m_trusted;
}

std::vector<CameraDevice> WebcamProtection::GetDevices() const {
    std::lock_guard<std::mutex> g(m_mutex);
    return m_devices;
}

void WebcamProtection::RefreshDevices() {
    std::lock_guard<std::mutex> g(m_mutex);
    EnumerateDevices();
}

std::vector<CameraAccessEvent> WebcamProtection::GetRecentEvents(size_t limit) const {
    std::lock_guard<std::mutex> g(m_mutex);
    if (m_eventLog.empty()) return {};
    size_t start = m_eventLog.size() > limit ? m_eventLog.size() - limit : 0;
    return {m_eventLog.begin() + static_cast<ptrdiff_t>(start), m_eventLog.end()};
}

bool WebcamProtection::IsTrusted(uint32_t /*pid*/,
                                  const std::wstring& imagePath,
                                  const std::string& imageNameLower) const {
    // m_mutex already held by callers that call this
    for (const auto& t : m_trusted) {
        if (t.pathIsWildcard) {
            if (lower(t.imageNameLower) == imageNameLower) return true;
        } else {
            if (!t.imagePath.empty() && imagePath == t.imagePath) return true;
            if (!t.imageNameLower.empty() && t.imageNameLower == imageNameLower) return true;
        }
    }
    return false;
}

CameraAccessDecision WebcamProtection::OnCameraOpenAttempt(
        uint32_t pid,
        std::wstring imagePath,
        std::string commandLine,
        std::string deviceId,
        std::wstring deviceName) {

    m_statAttempts.fetch_add(1, std::memory_order_relaxed);

    CameraAccessEvent ev;
    ev.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
    ev.at = std::chrono::system_clock::now();
    ev.pid = pid;
    ev.imagePath = imagePath;
    ev.imageNameLower = lower(imagePath);
    {
        auto sep = ev.imageNameLower.find_last_of("\\/");
        if (sep != std::string::npos) ev.imageNameLower = ev.imageNameLower.substr(sep + 1);
    }
    ev.commandLine = std::move(commandLine);
    ev.deviceId = std::move(deviceId);
    ev.deviceName = std::move(deviceName);

    CameraPolicy policy;
    bool trusted;
    {
        std::lock_guard<std::mutex> g(m_mutex);
        policy = m_policy;
        trusted = IsTrusted(pid, ev.imagePath, ev.imageNameLower);
    }

    CameraAccessDecision decision;
    if (trusted || policy == CameraPolicy::Allow) {
        decision = CameraAccessDecision::Allowed;
        ev.decision = decision;
        LogEvent(ev);
        m_statAllowed.fetch_add(1, std::memory_order_relaxed);
        return decision;
    }
    if (policy == CameraPolicy::Block) {
        decision = CameraAccessDecision::Denied;
        ev.decision = decision;
        LogEvent(ev);
        m_statDenied.fetch_add(1, std::memory_order_relaxed);
        return decision;
    }

    // Ask policy: fire alert handlers and wait (with a timeout).
    ev.decision = CameraAccessDecision::Pending;
    LogEvent(ev);

    auto pending = std::make_shared<PendingAsk>();
    pending->event = ev;
    {
        std::lock_guard<std::mutex> pg(m_pendingMutex);
        m_pending[ev.eventId] = pending;
    }

    // Notify alert handlers (under a copy to avoid holding lock during call)
    std::vector<CameraAlertHandler> handlers;
    {
        std::lock_guard<std::mutex> g(m_mutex);
        for (const auto& [t, h] : m_alertHandlers) handlers.push_back(h);
    }
    for (auto& h : handlers) {
        try { if (h) h(ev); } catch (...) {}
    }

    // Wait up to 30 seconds for a GUI response
    std::unique_lock<std::mutex> pl(m_pendingMutex);
    pending->cv.wait_for(pl, std::chrono::seconds(30),
                         [&]{ return pending->decision != CameraAccessDecision::Pending; });

    decision = pending->decision;
    if (decision == CameraAccessDecision::Pending) {
        // Timeout → deny by default for Ask policy
        decision = CameraAccessDecision::Denied;
    }
    m_pending.erase(ev.eventId);

    if (decision == CameraAccessDecision::Allowed)
        m_statAllowed.fetch_add(1, std::memory_order_relaxed);
    else
        m_statDenied.fetch_add(1, std::memory_order_relaxed);

    // Update log entry decision
    {
        std::lock_guard<std::mutex> g(m_mutex);
        for (auto& e : m_eventLog) {
            if (e.eventId == ev.eventId) { e.decision = decision; break; }
        }
    }
    return decision;
}

bool WebcamProtection::Respond(uint64_t eventId, CameraAccessDecision decision,
                               std::string userNote) {
    std::lock_guard<std::mutex> pl(m_pendingMutex);
    auto it = m_pending.find(eventId);
    if (it == m_pending.end()) return false;
    it->second->event.userNote = std::move(userNote);
    it->second->event.decision = decision;
    it->second->decision = decision;
    it->second->cv.notify_all();
    return true;
}

uint64_t WebcamProtection::RegisterAlertHandler(CameraAlertHandler handler) {
    std::lock_guard<std::mutex> g(m_mutex);
    uint64_t t = m_nextHandlerToken.fetch_add(1, std::memory_order_relaxed);
    m_alertHandlers.emplace_back(t, std::move(handler));
    return t;
}

bool WebcamProtection::UnregisterAlertHandler(uint64_t token) {
    std::lock_guard<std::mutex> g(m_mutex);
    auto it = std::remove_if(m_alertHandlers.begin(), m_alertHandlers.end(),
                             [&](const auto& p){ return p.first == token; });
    if (it == m_alertHandlers.end()) return false;
    m_alertHandlers.erase(it, m_alertHandlers.end());
    return true;
}

WebcamProtection::Stats WebcamProtection::GetStats() const noexcept {
    Stats s;
    s.openAttempts = m_statAttempts.load(std::memory_order_relaxed);
    s.allowed      = m_statAllowed.load(std::memory_order_relaxed);
    s.denied       = m_statDenied.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> g(const_cast<std::mutex&>(m_pendingMutex));
        s.pendingAsks = m_pending.size();
    }
    return s;
}

void WebcamProtection::LogEvent(CameraAccessEvent ev) {
    std::lock_guard<std::mutex> g(m_mutex);
    m_eventLog.push_back(std::move(ev));
    while (m_eventLog.size() > kMaxEventLog) m_eventLog.erase(m_eventLog.begin());
}

} // namespace Devices
} // namespace ShadowStrike
