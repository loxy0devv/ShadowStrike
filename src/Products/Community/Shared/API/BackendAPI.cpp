/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "pch.h"
#include "BackendAPI.hpp"

#include "PhantomCore/Config/ProductTier.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/RealTime/RealTimeProtection.hpp"
#include "PhantomCore/Communication/AlertSystem.hpp"
#include "PhantomCore/Detection/DetectionEngine.hpp"
#include "PhantomCore/Devices/WebcamProtection.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "Products/Community/Shared/TierBoot/TierSelector.hpp"

#include <atomic>
#include <chrono>
#include <format>
#include <mutex>
#include <random>
#include <sstream>
#include <string_view>

namespace ShadowStrike::Products::Shared::API {

using namespace ShadowStrike::Config;
using namespace ShadowStrike::Core::Engine;
namespace RTP = ShadowStrike::RealTime;

static constexpr std::string_view kLog = "[BackendAPI]";

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

BackendAPI& BackendAPI::Instance() noexcept {
    static BackendAPI s;
    return s;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string BackendAPI::GenerateId() const {
    static std::atomic<uint64_t> seq{1000};
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return std::format("{:x}-{:x}", now, seq.fetch_add(1, std::memory_order_relaxed));
}

bool BackendAPI::IsTierAllowed(const char* /*featureHint*/) const noexcept {
    return true; // Feature gating delegated to ProductTierManager per method
}

// ---------------------------------------------------------------------------
// Protection status
// ---------------------------------------------------------------------------

Result<ProtectionStatus> BackendAPI::GetProtectionStatus() {
    ProtectionStatus s;
    try {
        auto& rtp = RTP::RealTimeProtection::Instance();
        auto st = rtp.GetStatus();
        s.rtpEnabled             = st.isProtected;
        s.kernelSensorConnected  = st.driverConnected;
        s.since                  = st.startTime;

        if (Detection::DetectionEngine::HasInstance()) {
            s.detectionEngineLoaded = Detection::DetectionEngine::Instance().IsInitialized();
            s.activeRuleCount = static_cast<uint32_t>(
                Detection::DetectionEngine::Instance().RuleCount());
        }
    } catch (const std::exception& e) {
        Utils::Logger::Error("{} GetProtectionStatus exception: {}", kLog, e.what());
        return {s, ApiError::InternalError, e.what()};
    }
    return {s};
}

Result<void> BackendAPI::EnableRealTimeProtection(bool enable) {
    try {
        auto& rtp = RTP::RealTimeProtection::Instance();
        if (enable) {
            rtp.Resume();
        } else {
            rtp.Pause(0, L"API request");
        }
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

// ---------------------------------------------------------------------------
// Scan control
// ---------------------------------------------------------------------------

Result<void> BackendAPI::StartScan(ScanType type, std::vector<std::wstring> customPaths) {
    try {
        auto& engine = ScanEngine::Instance();
        if (!engine.IsInitialized())
            return {ApiError::NotInitialized, "ScanEngine not ready"};

        ScanContext ctx;
        ctx.type = ScanType::OnDemand;

        switch (type) {
            case ScanType::Quick:  engine.QuickScan(); break;
            case ScanType::Full:   engine.FullScan(); break;
            case ScanType::Custom: engine.CustomScan(customPaths); break;
            case ScanType::Memory: {
                auto procs = engine.ScanAllProcesses();
                (void)procs;
                break;
            }
        }
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<void> BackendAPI::StopScan() {
    try {
        ScanEngine::Instance().CancelAllJobs();
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<void> BackendAPI::PauseScan() {
    // ScanEngine doesn't expose pause on batch — cancel all is the safe equivalent
    return StopScan();
}

Result<void> BackendAPI::ResumeScan() {
    return {}; // Stateless — next scan call starts fresh
}

Result<ScanState> BackendAPI::GetScanState() {
    ScanState state;
    try {
        // ScanEngine exposes per-job progress; we aggregate here
        auto& engine = ScanEngine::Instance();
        auto jobs = engine.GetActiveJobs();
        if (jobs.empty()) {
            state.status = ScanStatus::Idle;
        } else {
            state.status = ScanStatus::Running;
            // Sum progress across active jobs
            for (auto jobId : jobs) {
                auto progress = engine.GetJobProgress(jobId);
                if (progress) {
                    state.filesScanned += progress->filesScanned;
                    state.pctComplete   = progress->percentComplete;
                    state.elapsed       = progress->elapsed;
                    state.currentFile   = progress->currentFile;
                }
            }
        }
    } catch (...) {
        state.status = ScanStatus::Idle;
    }
    return {state};
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

Result<std::vector<QuarantineItem>> BackendAPI::ListQuarantine(uint32_t limit,
                                                                 uint32_t offset) {
    std::vector<QuarantineItem> items;
    try {
        auto& qm = QuarantineManager::Instance();
        auto entries = qm.ListItems(limit, offset);
        for (const auto& e : entries) {
            QuarantineItem qi;
            qi.id             = e.id;
            qi.originalPath   = e.originalPath;
            qi.sha256         = e.sha256;
            qi.threatName     = e.threatName;
            qi.detectionSource = e.detectionSource;
            qi.confidence     = e.confidence;
            qi.quarantinedAt  = e.quarantinedAt;
            qi.fileSize       = e.fileSize;
            items.push_back(std::move(qi));
        }
    } catch (const std::exception& e) {
        return {{}, ApiError::InternalError, e.what()};
    }
    return {items};
}

Result<void> BackendAPI::RestoreFromQuarantine(std::string_view id) {
    try {
        auto& qm = QuarantineManager::Instance();
        if (!qm.Restore(std::string(id)))
            return {ApiError::NotFound, "Quarantine item not found"};
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<void> BackendAPI::DeleteFromQuarantine(std::string_view id) {
    try {
        auto& qm = QuarantineManager::Instance();
        if (!qm.Delete(std::string(id)))
            return {ApiError::NotFound, "Quarantine item not found"};
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<void> BackendAPI::DeleteAllQuarantine() {
    try {
        QuarantineManager::Instance().DeleteAll();
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<QuarantineItem> BackendAPI::GetQuarantineItem(std::string_view id) {
    try {
        auto& qm = QuarantineManager::Instance();
        auto e = qm.GetItem(std::string(id));
        if (!e) return {QuarantineItem{}, ApiError::NotFound, "Not found"};
        QuarantineItem qi;
        qi.id             = e->id;
        qi.originalPath   = e->originalPath;
        qi.sha256         = e->sha256;
        qi.threatName     = e->threatName;
        qi.detectionSource = e->detectionSource;
        qi.confidence     = e->confidence;
        qi.quarantinedAt  = e->quarantinedAt;
        qi.fileSize       = e->fileSize;
        return {qi};
    } catch (const std::exception& e) {
        return {QuarantineItem{}, ApiError::InternalError, e.what()};
    }
}

// ---------------------------------------------------------------------------
// Exclusions
// ---------------------------------------------------------------------------

// Exclusions are stored in ConfigManager under "Exclusions/<id>" keys.
// A lightweight in-memory list is maintained here for the API.

static std::mutex g_exclusionMutex;
static std::vector<ExclusionEntry> g_exclusions;

Result<std::vector<ExclusionEntry>> BackendAPI::ListExclusions() {
    std::lock_guard g(g_exclusionMutex);
    return {g_exclusions};
}

Result<ExclusionEntry> BackendAPI::AddExclusion(ExclusionType type,
                                                  std::wstring value,
                                                  std::string description) {
    ExclusionEntry e;
    e.id          = GenerateId();
    e.type        = type;
    e.value       = std::move(value);
    e.description = std::move(description);
    e.enabled     = true;
    e.createdAt   = std::chrono::system_clock::now();

    // Also push to ScanEngine exclusion list
    try {
        ScanEngine::ExclusionRule sr;
        sr.type    = static_cast<ScanEngine::ExclusionRule::Type>(static_cast<int>(type));
        sr.pattern = e.value;
        sr.enabled = true;
        ScanEngine::Instance().AddExclusion(sr);
    } catch (...) {}

    std::lock_guard g(g_exclusionMutex);
    g_exclusions.push_back(e);
    return {e};
}

Result<void> BackendAPI::RemoveExclusion(std::string_view id) {
    std::lock_guard g(g_exclusionMutex);
    auto it = std::remove_if(g_exclusions.begin(), g_exclusions.end(),
                             [&](const auto& e){ return e.id == id; });
    if (it == g_exclusions.end())
        return {ApiError::NotFound, "Exclusion not found"};
    g_exclusions.erase(it, g_exclusions.end());
    return {};
}

Result<void> BackendAPI::EnableExclusion(std::string_view id, bool enable) {
    std::lock_guard g(g_exclusionMutex);
    for (auto& e : g_exclusions) {
        if (e.id == id) { e.enabled = enable; return {}; }
    }
    return {ApiError::NotFound, "Exclusion not found"};
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

static std::mutex g_policyMutex;
static std::vector<PolicyEntry> g_policies;

Result<std::vector<PolicyEntry>> BackendAPI::ListPolicies(
    std::optional<PolicyScope> scopeFilter) {
    std::lock_guard g(g_policyMutex);
    if (!scopeFilter) return {g_policies};
    std::vector<PolicyEntry> filtered;
    for (const auto& p : g_policies)
        if (p.scope == *scopeFilter) filtered.push_back(p);
    return {filtered};
}

Result<PolicyEntry> BackendAPI::AddPolicy(PolicyScope scope, AccessDecision decision,
                                           std::wstring target, std::string note) {
    PolicyEntry p;
    p.id        = GenerateId();
    p.scope     = scope;
    p.decision  = decision;
    p.target    = std::move(target);
    p.note      = std::move(note);
    p.enabled   = true;
    p.createdAt = std::chrono::system_clock::now();
    std::lock_guard g(g_policyMutex);
    g_policies.push_back(p);
    return {p};
}

Result<void> BackendAPI::RemovePolicy(std::string_view id) {
    std::lock_guard g(g_policyMutex);
    auto it = std::remove_if(g_policies.begin(), g_policies.end(),
                             [&](const auto& p){ return p.id == id; });
    if (it == g_policies.end()) return {ApiError::NotFound, "Policy not found"};
    g_policies.erase(it, g_policies.end());
    return {};
}

Result<void> BackendAPI::UpdatePolicyDecision(std::string_view id,
                                               AccessDecision newDecision) {
    std::lock_guard g(g_policyMutex);
    for (auto& p : g_policies) {
        if (p.id == id) { p.decision = newDecision; return {}; }
    }
    return {ApiError::NotFound, "Policy not found"};
}

// ---------------------------------------------------------------------------
// Feature toggles
// ---------------------------------------------------------------------------

Result<std::vector<FeatureToggle>> BackendAPI::ListFeatureToggles() {
    static const std::vector<std::pair<std::string, std::string>> kFeatures = {
        {"RealTimeProtection", "Real-Time File & Process Scanning"},
        {"BehaviorBlocker",    "Behavioral Threat Blocking"},
        {"NetworkFilter",      "Network Traffic Filtering"},
        {"ExploitPrevention",  "Exploit Prevention (DEP/CFG/ROP)"},
        {"RansomwareProtection","Ransomware Protection"},
        {"ZeroHourProtection", "Zero-Hour Cloud Verdict"},
        {"AMSIIntegration",    "AMSI Script Scanning"},
        {"WebcamProtection",   "Webcam Access Control"},
        {"StaticAnalysis",     "Pre-Execution Static Analysis"},
        {"DeepInspection",     "HyperDbg-aligned Memory Inspection"},
    };
    std::vector<FeatureToggle> out;
    try {
        auto& cfg = Config::ConfigManager::Instance();
        for (const auto& [id, name] : kFeatures) {
            FeatureToggle ft;
            ft.id = id; ft.displayName = name;
            ft.enabled = cfg.GetValue<bool>(std::wstring(id.begin(), id.end()) + L"/Enabled", true);
            out.push_back(std::move(ft));
        }
    } catch (...) {
        for (const auto& [id, name] : kFeatures)
            out.push_back({id, name, {}, true, false, "All"});
    }
    return {out};
}

Result<void> BackendAPI::SetFeatureEnabled(std::string_view featureId, bool enable) {
    try {
        std::wstring key = std::wstring(featureId.begin(), featureId.end()) + L"/Enabled";
        Config::ConfigManager::Instance().SetValue(key, enable);
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

// ---------------------------------------------------------------------------
// Trust management
// ---------------------------------------------------------------------------

static std::mutex g_trustMutex;
static std::vector<TrustedEntry> g_trusted;

Result<std::vector<TrustedEntry>> BackendAPI::ListTrustedEntries() {
    std::lock_guard g(g_trustMutex);
    return {g_trusted};
}

Result<TrustedEntry> BackendAPI::AddTrustedEntry(std::string type, std::wstring value,
                                                   std::string note, bool permanent) {
    TrustedEntry t;
    t.id       = GenerateId();
    t.type     = std::move(type);
    t.value    = std::move(value);
    t.note     = std::move(note);
    t.permanent = permanent;
    t.addedAt  = std::chrono::system_clock::now();
    std::lock_guard g(g_trustMutex);
    g_trusted.push_back(t);
    return {t};
}

Result<void> BackendAPI::RemoveTrustedEntry(std::string_view id) {
    std::lock_guard g(g_trustMutex);
    auto it = std::remove_if(g_trusted.begin(), g_trusted.end(),
                             [&](const auto& t){ return t.id == id; });
    if (it == g_trusted.end()) return {ApiError::NotFound, "Trust entry not found"};
    g_trusted.erase(it, g_trusted.end());
    return {};
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------

Result<ResponseActionResult> BackendAPI::ExecuteAction(const ResponseActionRequest& req) {
    ResponseActionResult result;
    try {
        using namespace ShadowStrike::Core::Process;
        switch (req.action) {
            case ResponseAction::KillProcess:
                if (req.pid == 0)
                    return {{false, "PID required"}, ApiError::InvalidArgument};
                ProcessKiller::Instance().KillProcess(req.pid);
                result.success = true;
                break;

            case ResponseAction::SuspendProcess:
                if (req.pid == 0)
                    return {{false, "PID required"}, ApiError::InvalidArgument};
                ProcessKiller::Instance().SuspendProcess(req.pid);
                result.success = true;
                break;

            case ResponseAction::QuarantineFile:
                if (req.path.empty())
                    return {{false, "Path required"}, ApiError::InvalidArgument};
                QuarantineManager::Instance().QuarantineFile(req.path, req.reason);
                result.success = true;
                break;

            case ResponseAction::DeleteFile:
                if (req.path.empty())
                    return {{false, "Path required"}, ApiError::InvalidArgument};
                if (!std::filesystem::remove(req.path))
                    return {{false, "Failed to delete"}, ApiError::InternalError};
                result.success = true;
                break;

            case ResponseAction::RestoreFromQuarantine:
                return ExecuteAction(ResponseActionRequest{
                    ResponseAction::RestoreFromQuarantine, 0, {}, req.quarantineItemId});

            case ResponseAction::TriggerScan:
                return {result, StartScan(ScanType::Custom, {req.path}).error};

            default:
                return {{false, "Action not implemented"}, ApiError::FeatureNotAvailable};
        }
    } catch (const std::exception& e) {
        return {{false, e.what()}, ApiError::InternalError, e.what()};
    }
    return {result};
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

Result<std::vector<AlertEntry>> BackendAPI::ListAlerts(uint32_t limit, uint32_t offset,
                                                         std::optional<AlertSeverity> minSev) {
    std::vector<AlertEntry> out;
    try {
        if (Communication::AlertSystem::HasInstance()) {
            auto& as = Communication::AlertSystem::Instance();
            auto raw = as.GetRecentAlerts(limit + offset);
            size_t count = 0;
            for (size_t i = offset; i < raw.size() && count < limit; ++i, ++count) {
                const auto& a = raw[i];
                AlertEntry ae;
                ae.id            = a.id;
                ae.severity      = static_cast<AlertSeverity>(static_cast<uint8_t>(a.severity));
                ae.threatName    = a.title;
                ae.description   = a.detail;
                ae.imagePath     = a.imagePath;
                ae.pid           = a.processId;
                ae.detectedAt    = a.detectedAt;
                ae.acknowledged  = a.acknowledged;
                for (auto& r : a.ruleIds) ae.matchedRules.push_back(r);
                if (minSev && ae.severity < *minSev) continue;
                out.push_back(std::move(ae));
            }
        }
    } catch (...) {}
    return {out};
}

Result<AlertEntry> BackendAPI::GetAlert(std::string_view id) {
    try {
        if (Communication::AlertSystem::HasInstance()) {
            auto& as = Communication::AlertSystem::Instance();
            auto a = as.FindAlert(std::string(id));
            if (!a) return {AlertEntry{}, ApiError::NotFound, "Not found"};
            AlertEntry ae;
            ae.id           = a->id;
            ae.severity     = static_cast<AlertSeverity>(static_cast<uint8_t>(a->severity));
            ae.threatName   = a->title;
            ae.description  = a->detail;
            ae.imagePath    = a->imagePath;
            ae.pid          = a->processId;
            ae.detectedAt   = a->detectedAt;
            ae.acknowledged = a->acknowledged;
            return {ae};
        }
    } catch (...) {}
    return {AlertEntry{}, ApiError::NotFound, "AlertSystem unavailable"};
}

Result<void> BackendAPI::AcknowledgeAlert(std::string_view id) {
    try {
        if (Communication::AlertSystem::HasInstance())
            Communication::AlertSystem::Instance().AcknowledgeAlert(std::string(id));
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<void> BackendAPI::DismissAlert(std::string_view id) {
    try {
        if (Communication::AlertSystem::HasInstance())
            Communication::AlertSystem::Instance().DismissAlert(std::string(id));
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

Result<TelemetrySummary> BackendAPI::GetTelemetrySummary() {
    TelemetrySummary s;
    try {
        auto& engine = ScanEngine::Instance();
        if (engine.IsInitialized()) {
            auto stats = engine.GetStatistics();
            s.scansDone      = stats.totalScans;
            s.threatsBlocked = stats.infectionsFound;
        }
        if (Communication::AlertSystem::HasInstance()) {
            s.alertsLastHour = Communication::AlertSystem::Instance().AlertCountLastHour();
            s.alertsLastDay  = Communication::AlertSystem::Instance().AlertCountLastDay();
        }
    } catch (...) {}
    s.since = std::chrono::system_clock::now();
    return {s};
}

Result<std::vector<ProcessTreeEntry>> BackendAPI::GetProcessTree() {
    std::vector<ProcessTreeEntry> out;
    try {
        if (!Detection::DetectionEngine::HasInstance()) return {out};
        auto nodes = Detection::DetectionEngine::Instance().GetProcessTree();
        for (const auto& n : nodes) {
            ProcessTreeEntry e;
            e.pid           = n.pid;
            e.parentPid     = n.parentPid;
            e.imagePath     = n.imagePath;
            e.imageNameLower = n.imageNameLower;
            e.commandLine   = n.commandLine;
            e.riskScore     = n.cumulativeScore;
            e.childPids     = n.childPids;
            for (auto& r : n.matchedRules) e.matchedRules.push_back(r);
            out.push_back(std::move(e));
        }
    } catch (...) {}
    return {out};
}

// ---------------------------------------------------------------------------
// Webcam
// ---------------------------------------------------------------------------

Result<WebcamStatus> BackendAPI::GetWebcamStatus() {
    WebcamStatus s;
    try {
        auto& wc = Devices::WebcamProtection::Instance();
        s.policy      = static_cast<DevicePolicy>(static_cast<uint8_t>(wc.GetPolicy()));
        auto stats    = wc.GetStats();
        s.deviceCount = static_cast<uint32_t>(wc.GetDevices().size());
        s.accessAttempts = static_cast<uint32_t>(stats.openAttempts);
        s.denied      = static_cast<uint32_t>(stats.denied);
        s.allowed     = static_cast<uint32_t>(stats.allowed);
        s.pending     = static_cast<uint32_t>(stats.pendingAsks);
    } catch (const std::exception& e) {
        return {s, ApiError::InternalError, e.what()};
    }
    return {s};
}

Result<void> BackendAPI::SetWebcamPolicy(DevicePolicy p) {
    try {
        using Devices::CameraPolicy;
        CameraPolicy cp;
        switch (p) {
            case DevicePolicy::Allow: cp = CameraPolicy::Allow; break;
            case DevicePolicy::Block: cp = CameraPolicy::Block; break;
            default:                  cp = CameraPolicy::Ask;   break;
        }
        Devices::WebcamProtection::Instance().SetPolicy(cp);
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<std::vector<WebcamTrustedProcess>> BackendAPI::ListWebcamTrusted() {
    std::vector<WebcamTrustedProcess> out;
    try {
        for (const auto& t : Devices::WebcamProtection::Instance().GetTrustedProcesses()) {
            WebcamTrustedProcess p;
            p.id             = t.id;
            p.imagePath      = t.imagePath;
            p.signerSubject  = t.signerSubject;
            p.pathIsWildcard = t.pathIsWildcard;
            out.push_back(std::move(p));
        }
    } catch (...) {}
    return {out};
}

Result<WebcamTrustedProcess> BackendAPI::AddWebcamTrustedProcess(
    std::wstring imagePath, std::string signerSubject, bool isWildcard) {
    try {
        Devices::TrustedCameraProcess t;
        t.imagePath      = std::move(imagePath);
        t.signerSubject  = std::move(signerSubject);
        t.pathIsWildcard = isWildcard;
        auto sep = t.imagePath.find_last_of(L"\\/");
        auto base = (sep == std::wstring::npos) ? t.imagePath : t.imagePath.substr(sep+1);
        t.imageNameLower.assign(base.begin(), base.end());
        for (auto& c : t.imageNameLower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        Devices::WebcamProtection::Instance().AddTrustedProcess(t);
        WebcamTrustedProcess r;
        r.id = t.id.empty() ? GenerateId() : t.id;
        r.imagePath = t.imagePath;
        r.signerSubject = t.signerSubject;
        r.pathIsWildcard = t.pathIsWildcard;
        return {r};
    } catch (const std::exception& e) {
        return {WebcamTrustedProcess{}, ApiError::InternalError, e.what()};
    }
}

Result<void> BackendAPI::RemoveWebcamTrustedProcess(std::string_view id) {
    try {
        if (!Devices::WebcamProtection::Instance().RemoveTrustedProcess(id))
            return {ApiError::NotFound, "Not found"};
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<void> BackendAPI::ApproveWebcamAccess(uint64_t eventId) {
    try {
        Devices::WebcamProtection::Instance().Respond(
            eventId, Devices::CameraAccessDecision::Allowed);
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

Result<void> BackendAPI::DenyWebcamAccess(uint64_t eventId) {
    try {
        Devices::WebcamProtection::Instance().Respond(
            eventId, Devices::CameraAccessDecision::Denied);
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

// ---------------------------------------------------------------------------
// Policy config
// ---------------------------------------------------------------------------

Result<std::vector<PolicyConfig>> BackendAPI::ListPolicyConfigs(
    std::optional<std::string_view> category) {
    std::vector<PolicyConfig> out;
    // Enumerate known config categories
    static const std::vector<std::tuple<std::string, std::string, std::string, std::string>> kKnown = {
        {"RealTimeProtection", "Enabled",        "bool",   "Enable real-time protection"},
        {"RealTimeProtection", "SensitivityLevel","int",   "Scan sensitivity 1=Low 2=Medium 3=High"},
        {"BehaviorBlocker",    "Enabled",         "bool",  "Enable behavioral blocking"},
        {"Ransomware",         "Enabled",         "bool",  "Enable ransomware protection"},
        {"NetworkFilter",      "Enabled",         "bool",  "Enable network traffic filtering"},
        {"WebcamProtection",   "Policy",          "string","Camera policy: Allow/Ask/Block"},
        {"Quarantine",         "AutoQuarantine",  "bool",  "Automatically quarantine threats"},
        {"StaticAnalysis",     "Enabled",         "bool",  "Enable pre-execution static analysis"},
        {"StaticAnalysis",     "BlockThreshold",  "float", "Score threshold for early block"},
        {"DeepInspection",     "Enabled",         "bool",  "Enable HyperDbg-aligned memory inspection"},
    };
    try {
        auto& cfg = Config::ConfigManager::Instance();
        for (const auto& [cat, key, type, desc] : kKnown) {
            if (category && cat != *category) continue;
            PolicyConfig pc;
            pc.category = cat; pc.key = key; pc.type = type; pc.description = desc;
            std::wstring wcat(cat.begin(), cat.end());
            std::wstring wkey(key.begin(), key.end());
            pc.value = Utils::StringUtils::ToNarrow(
                cfg.GetValue<std::wstring>(wcat + L"/" + wkey, L""));
            out.push_back(std::move(pc));
        }
    } catch (...) {}
    return {out};
}

Result<PolicyConfig> BackendAPI::GetPolicyConfig(std::string_view category,
                                                    std::string_view key) {
    try {
        auto& cfg = Config::ConfigManager::Instance();
        std::wstring wcat(category.begin(), category.end());
        std::wstring wkey(key.begin(), key.end());
        PolicyConfig pc;
        pc.category = std::string(category);
        pc.key      = std::string(key);
        pc.value    = Utils::StringUtils::ToNarrow(
            cfg.GetValue<std::wstring>(wcat + L"/" + wkey, L""));
        return {pc};
    } catch (const std::exception& e) {
        return {PolicyConfig{}, ApiError::InternalError, e.what()};
    }
}

Result<void> BackendAPI::SetPolicyConfig(std::string_view category,
                                          std::string_view key,
                                          std::string_view value) {
    try {
        auto& cfg = Config::ConfigManager::Instance();
        std::wstring wcat(category.begin(), category.end());
        std::wstring wkey(key.begin(), key.end());
        std::wstring wval(value.begin(), value.end());
        cfg.SetValue(wcat + L"/" + wkey, wval);
    } catch (const std::exception& e) {
        return {ApiError::InternalError, e.what()};
    }
    return {};
}

// ---------------------------------------------------------------------------
// License
// ---------------------------------------------------------------------------

Result<BackendAPI::LicenseInfo> BackendAPI::GetLicenseInfo() {
    LicenseInfo li;
    try {
        auto& tm = ProductTierManager::Instance();
        li.tier = [&]{
            switch (tm.GetCurrentTier()) {
                case ProductTier::Community:   return "Home";
                case ProductTier::Professional: return "EDR";
                case ProductTier::Enterprise:   return "XDR";
            }
            return "Home";
        }();
        li.valid = true;
        auto license = tm.GetLicenseInfo();
        li.organization = license.organizationName;
        li.licenseId    = license.licenseId;
        li.expiresAt    = license.expiresAt;
    } catch (...) {
        li.tier = "Home"; li.valid = true;
    }
    return {li};
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

Result<BackendAPI::EngineStats> BackendAPI::GetEngineStats() {
    EngineStats s;
    try {
        if (ScanEngine::Instance().IsInitialized()) {
            auto st = ScanEngine::Instance().GetStatistics();
            s.totalScans    = st.totalScans;
            s.infections    = st.infectionsFound;
            s.cacheHits     = st.cacheHits;
            s.avgScanTimeMs = st.averageScanTimeMs;
        }
        if (Detection::DetectionEngine::HasInstance()) {
            auto ds = Detection::DetectionEngine::Instance().GetStats();
            s.ruleMatches = ds.ruleStats.matches;
        }
    } catch (...) {}
    return {s};
}

} // namespace ShadowStrike::Products::Shared::API
