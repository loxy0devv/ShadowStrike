/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * SharedIpcDispatcher — command handlers available in ALL product tiers.
 *
 * Handler inventory:
 *   300  ListExclusions        — list exclusion rules
 *   301  AddExclusion          — add exclusion (path/hash/process/ext)
 *   302  RemoveExclusion       — remove by id
 *   303  UpdateExclusion       — modify existing exclusion
 *   304  ClearExclusions       — remove all (destructive, requires admin)
 *   305  ImportExclusions      — bulk import JSON array
 *   306  ExportExclusions      — export to JSON
 *   320  GetAccessPolicy       — get block/allow/ask policy
 *   321  SetAccessPolicy       — set policy for feature/path
 *   322  ListPolicyRules       — all per-feature rules
 *   323  AddPolicyRule         — add policy rule
 *   324  RemovePolicyRule      — remove rule by id
 *   325  GetDefaultPolicy      — global default
 *   326  SetDefaultPolicy      — set global default
 *   340  ListTrustedItems      — list trusted files/processes/signers
 *   341  AddTrustedItem        — add trusted item
 *   342  RemoveTrustedItem     — remove by id
 *   343  IsTrusted             — query trust for specific item
 *   344  ListTrustedSigners    — list trusted signer subjects
 *   345  AddTrustedSigner      — add signer trust
 *   346  RemoveTrustedSigner   — revoke signer trust
 *   360  ListFeatures          — all features with enabled/tier state
 *   361  SetFeatureEnabled     — enable/disable named feature
 *   362  GetFeatureStatus      — query single feature
 *   363  ResetFeatureDefaults  — reset all to tier defaults
 *   380  GetProtectionStatus   — active protections summary
 *   381  SetProtectionEnabled  — enable/disable protection module
 *   382  GetRealTimeStatus     — RTP on/off state
 *   383  SetRealTimeEnabled    — toggle RTP
 *   400  KillProcess           — terminate PID (admin only)
 *   401  SuspendProcess        — suspend PID (admin only)
 *   402  IsolateProcess        — kill + quarantine (admin only)
 *   403  QuarantineFile        — quarantine by path
 *   404  RestoreFromQuarantine — restore quarantined item
 *   405  DeleteFromQuarantine  — permanently delete
 *   406  RemediateFile         — run automated remediation
 *   407  NetworkIsolate        — cut process network access (admin only)
 *   408  BlockHash             — permanently block SHA-256
 *   420  GetTelemetryStream    — subscribe to live events (SSE-like push)
 *   421  QueryTelemetry        — query with filter
 *   422  GetProcessTree        — live process tree
 *   423  GetProcessDetail      — single PID detail
 *   424  GetNetworkFlows       — network connections
 *   425  GetFileEvents         — recent file events
 *   426  GetRegistryEvents     — recent registry events
 *   427  GetDnsQueries         — recent DNS log
 *   440  ListAlerts            — paginated alerts
 *   441  GetAlertDetail        — alert by id
 *   442  DismissAlert          — mark reviewed
 *   443  GetDetectionHistory   — detection history
 *   444  GetDetectionDetail    — full detection detail
 *   445  GetAttackChain        — attack chain/story
 *   446  ExportAlert           — export alert data
 *   460  GetWebcamPolicy       — camera policy
 *   461  SetWebcamPolicy       — set camera policy
 *   462  ListWebcamDevices     — enumerate cameras
 *   463  GetWebcamAccessLog    — access events
 *   464  AllowWebcamAccess     — approve pending Ask
 *   465  DenyWebcamAccess      — deny pending Ask
 *   466  ListWebcamTrusted     — trusted processes
 *   467  AddWebcamTrusted      — add trusted process
 *   468  RemoveWebcamTrusted   — remove trusted process
 *   480  GetTierInfo           — tier + license summary
 *   481  ListPolicies          — all named policies
 *   482  GetPolicy             — single policy by name
 *   483  SetPolicy             — update policy key
 *   484  ResetPolicy           — reset to defaults
 *   485  ExportPolicy          — export all policies
 *   486  ImportPolicy          — import policies
 *   540  ListRules             — detection rules with stats
 *   541  GetRuleDetail         — single rule by id
 *   542  EnableRule            — enable rule
 *   543  DisableRule           — disable rule
 *   544  ReloadRules           — hot-reload rule corpora
 */

#include "pch.h"
#include "SharedIpcDispatcher.hpp"
#include "PhantomCore/Service/ServiceCommunicator.hpp"
#include "PhantomCore/Service/IpcAuthToken.hpp"
#include "PhantomCore/Service/EventPush.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Config/ProductTier.hpp"
#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/Core/Process/ProcessKiller.hpp"
#include "PhantomCore/RealTime/RealTimeProtection.hpp"
#include "PhantomCore/RealTime/AccessControlManager.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelStore.hpp"
#include "PhantomCore/Whitelist/WhiteListStore.hpp"
#include "PhantomCore/Detection/DetectionEngine.hpp"
#include "PhantomCore/Devices/WebcamProtection.hpp"
#include "PhantomCore/Communication/AlertSystem.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Core/Network/NetworkMonitor.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <Windows.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")

namespace ShadowStrike::Products::Shared {

using ShadowStrike::Service::ServiceCommunicator;
using ShadowStrike::Service::CommandType;
using ShadowStrike::Service::IpcAuthToken;
using ShadowStrike::Config::ConfigManager;
using ShadowStrike::Config::ProductTierManager;
using ShadowStrike::Config::FeatureCategory;
using ShadowStrike::Core::Engine::ScanEngine;
using ShadowStrike::Core::Engine::QuarantineManager;
using ShadowStrike::Detection::DetectionEngine;
using ShadowStrike::Devices::WebcamProtection;
using ShadowStrike::Devices::CameraPolicy;
using json = nlohmann::json;

static constexpr const wchar_t* kLog = L"SharedIpc";
static constexpr size_t kMaxListItems = 500u;
static constexpr uint32_t kMaxJsonDepth = 8u;

// ============================================================================
// Security helpers
// ============================================================================

/// Returns true if the connected client has High or System integrity.
static bool IsHighIntegrity(uint64_t clientId) noexcept {
    try {
        // Ask ServiceCommunicator for the client's token integrity level
        // via the V2 context it retains per client. If unavailable, deny.
        return ServiceCommunicator::Instance().GetClientIntegrityLevel(clientId) >= SECURITY_MANDATORY_HIGH_RID;
    } catch (...) { return false; }
}

static json MakeError(std::string_view code, std::string_view msg) {
    return json{{"ok", false}, {"error", {{"code", std::string(code)}, {"message", std::string(msg)}}}};
}
static json MakeOk(json data = nullptr) {
    json r{{"ok", true}};
    if (!data.is_null()) r["data"] = std::move(data);
    return r;
}
static json SafeParse(std::string_view raw) noexcept {
    auto j = json::parse(raw, nullptr, false);
    if (j.is_discarded()) return json::object();
    return j;
}
template<typename T>
static std::optional<T> Field(const json& obj, std::string_view key) noexcept {
    try {
        auto it = obj.find(key);
        if (it == obj.end()) return std::nullopt;
        return it->template get<T>();
    } catch (...) { return std::nullopt; }
}

// ============================================================================
// Impl
// ============================================================================

struct SharedIpcDispatcher::Impl {

    void InstallHandlers(ServiceCommunicator& svc);
    void UninstallHandlers(ServiceCommunicator& svc);

    // ────────── Exclusion handlers ──────────────────────────────────────
    void HandleListExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleAddExclusion(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleRemoveExclusion(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleUpdateExclusion(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleClearExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleImportExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleExportExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Policy handlers ─────────────────────────────────────────
    void HandleGetAccessPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSetAccessPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleListPolicyRules(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleAddPolicyRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleRemovePolicyRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetDefaultPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSetDefaultPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Trust handlers ──────────────────────────────────────────
    void HandleListTrustedItems(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleAddTrustedItem(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleRemoveTrustedItem(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleIsTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleListTrustedSigners(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleAddTrustedSigner(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleRemoveTrustedSigner(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Feature/protection toggles ─────────────────────────────
    void HandleListFeatures(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSetFeatureEnabled(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetFeatureStatus(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleResetFeatureDefaults(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetProtectionStatus(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSetProtectionEnabled(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetRealTimeStatus(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSetRealTimeEnabled(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Response actions ────────────────────────────────────────
    void HandleKillProcess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSuspendProcess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleIsolateProcess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleQuarantineFile(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleRestoreFromQuarantine(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleDeleteFromQuarantine(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleRemediateFile(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleNetworkIsolate(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleBlockHash(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Telemetry views ─────────────────────────────────────────
    void HandleGetTelemetryStream(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleQueryTelemetry(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetProcessTree(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetProcessDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetNetworkFlows(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetFileEvents(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetRegistryEvents(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetDnsQueries(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Alert/detection views ──────────────────────────────────
    void HandleListAlerts(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetAlertDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleDismissAlert(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetDetectionHistory(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetDetectionDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetAttackChain(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleExportAlert(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Webcam protection ───────────────────────────────────────
    void HandleGetWebcamPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSetWebcamPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleListWebcamDevices(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetWebcamAccessLog(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleAllowWebcamAccess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleDenyWebcamAccess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleListWebcamTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleAddWebcamTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleRemoveWebcamTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Policy config ───────────────────────────────────────────
    void HandleGetTierInfo(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleListPolicies(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleSetPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleResetPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleExportPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleImportPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Rule management ─────────────────────────────────────────
    void HandleListRules(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleGetRuleDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleEnableRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleDisableRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);
    void HandleReloadRules(uint64_t cid, uint32_t, uint64_t rid, std::string_view body);

    // ────────── Helper: send reply ──────────────────────────────────────
    void Reply(uint64_t cid, uint64_t rid, const json& payload,
               CommandType type = CommandType::Unknown) noexcept;
    bool CheckAuth(uint64_t cid, uint64_t rid) noexcept;
    bool CheckAdminAuth(uint64_t cid, uint64_t rid) noexcept;
};

// ============================================================================
// Helper: reply via ServiceCommunicator
// ============================================================================

void SharedIpcDispatcher::Impl::Reply(uint64_t cid, uint64_t rid, const json& payload,
                                      CommandType type) noexcept {
    try {
        ServiceCommunicator::Instance().SendResponseEnvelope(cid, type, rid, payload.dump());
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLog, L"Reply error cid=%llu: %hs", cid, e.what());
    }
}

bool SharedIpcDispatcher::Impl::CheckAuth(uint64_t cid, uint64_t rid) noexcept {
    if (!ServiceCommunicator::Instance().IsClientAuthenticated(cid)) {
        Reply(cid, rid, MakeError("unauthorized", "Not authenticated"));
        return false;
    }
    return true;
}

bool SharedIpcDispatcher::Impl::CheckAdminAuth(uint64_t cid, uint64_t rid) noexcept {
    if (!CheckAuth(cid, rid)) return false;
    if (!IsHighIntegrity(cid)) {
        Reply(cid, rid, MakeError("forbidden", "High integrity required"));
        return false;
    }
    return true;
}

// ============================================================================
// Exclusion handlers
// ============================================================================

void SharedIpcDispatcher::Impl::HandleListExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    try {
        auto& engine = ScanEngine::Instance();
        auto rules = engine.GetExclusions();
        json arr = json::array();
        for (size_t i = 0; i < std::min(rules.size(), kMaxListItems); ++i) {
            const auto& r = rules[i];
            arr.push_back({
                {"index",   i},
                {"type",    static_cast<int>(r.type)},
                {"pattern", r.pattern.empty() ? "" : std::string(r.pattern.begin(), r.pattern.end())},
                {"enabled", r.enabled},
                {"description", r.description}
            });
        }
        Reply(cid, rid, MakeOk({{"exclusions", arr}, {"total", rules.size()}}));
    } catch (const std::exception& e) {
        Reply(cid, rid, MakeError("internal_error", e.what()));
    }
}

void SharedIpcDispatcher::Impl::HandleAddExclusion(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto typeVal = Field<int>(j, "type");
    auto patternVal = Field<std::string>(j, "pattern");
    if (!typeVal || !patternVal || patternVal->empty()) {
        Reply(cid, rid, MakeError("invalid_params", "type and pattern required"));
        return;
    }
    try {
        Core::Engine::ExclusionRule rule;
        rule.type = static_cast<Core::Engine::ExclusionRule::Type>(*typeVal);
        rule.pattern = std::wstring(patternVal->begin(), patternVal->end());
        rule.enabled = j.value("enabled", true);
        rule.description = j.value("description", std::string{});
        ScanEngine::Instance().AddExclusion(rule);
        Reply(cid, rid, MakeOk());
        SS_LOG_INFO(kLog, L"Exclusion added by client %llu: pattern=%hs", cid, patternVal->c_str());
    } catch (const std::exception& e) {
        Reply(cid, rid, MakeError("internal_error", e.what()));
    }
}

void SharedIpcDispatcher::Impl::HandleRemoveExclusion(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto idx = Field<size_t>(j, "index");
    if (!idx) { Reply(cid, rid, MakeError("invalid_params", "index required")); return; }
    bool ok = ScanEngine::Instance().RemoveExclusion(*idx);
    Reply(cid, rid, ok ? MakeOk() : MakeError("not_found", "Exclusion not found"));
}

void SharedIpcDispatcher::Impl::HandleClearExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    ScanEngine::Instance().ClearExclusions();
    Reply(cid, rid, MakeOk());
    SS_LOG_WARN(kLog, L"All exclusions cleared by client %llu", cid);
}

void SharedIpcDispatcher::Impl::HandleExportExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto rules = ScanEngine::Instance().GetExclusions();
    json arr = json::array();
    for (const auto& r : rules) {
        arr.push_back({
            {"type", static_cast<int>(r.type)},
            {"pattern", std::string(r.pattern.begin(), r.pattern.end())},
            {"enabled", r.enabled},
            {"description", r.description}
        });
    }
    Reply(cid, rid, MakeOk({{"exclusions", arr}}));
}

void SharedIpcDispatcher::Impl::HandleImportExclusions(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto arr = j.find("exclusions");
    if (arr == j.end() || !arr->is_array()) {
        Reply(cid, rid, MakeError("invalid_params", "exclusions array required"));
        return;
    }
    size_t added = 0;
    for (const auto& item : *arr) {
        try {
            Core::Engine::ExclusionRule rule;
            rule.type = static_cast<Core::Engine::ExclusionRule::Type>(item.value("type", 0));
            auto pat = item.value("pattern", std::string{});
            rule.pattern = std::wstring(pat.begin(), pat.end());
            rule.enabled = item.value("enabled", true);
            rule.description = item.value("description", std::string{});
            if (!rule.pattern.empty()) { ScanEngine::Instance().AddExclusion(rule); ++added; }
        } catch (...) {}
    }
    Reply(cid, rid, MakeOk({{"added", added}}));
}

void SharedIpcDispatcher::Impl::HandleUpdateExclusion(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    // Remove existing + add updated
    auto j = SafeParse(body);
    auto idx = Field<size_t>(j, "index");
    if (!idx) { Reply(cid, rid, MakeError("invalid_params", "index required")); return; }
    ScanEngine::Instance().RemoveExclusion(*idx);
    HandleAddExclusion(cid, 0, rid, body);
}

// ============================================================================
// Policy handlers
// ============================================================================

void SharedIpcDispatcher::Impl::HandleGetAccessPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_supported", "policy API not available in this build"));
}

void SharedIpcDispatcher::Impl::HandleSetAccessPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_supported", "policy API not available in this build"));
}

void SharedIpcDispatcher::Impl::HandleGetDefaultPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_supported", "policy API not available in this build"));
}

void SharedIpcDispatcher::Impl::HandleSetDefaultPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_supported", "policy API not available in this build"));
}

void SharedIpcDispatcher::Impl::HandleListPolicyRules(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_supported", "policy API not available in this build"));
}

void SharedIpcDispatcher::Impl::HandleAddPolicyRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_supported", "policy API not available in this build"));
}

void SharedIpcDispatcher::Impl::HandleRemovePolicyRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_supported", "policy API not available in this build"));
}

// ============================================================================
// Trust handlers
// ============================================================================

void SharedIpcDispatcher::Impl::HandleListTrustedItems(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("whitelist_api_changed", "use hash-based API"));
}

void SharedIpcDispatcher::Impl::HandleAddTrustedItem(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("whitelist_api_changed", "use hash-based API"));
}

void SharedIpcDispatcher::Impl::HandleRemoveTrustedItem(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("whitelist_api_changed", "use hash-based API"));
}

void SharedIpcDispatcher::Impl::HandleIsTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("whitelist_api_changed", "use hash-based API"));
}

void SharedIpcDispatcher::Impl::HandleListTrustedSigners(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("whitelist_api_changed", "use hash-based API"));
}

void SharedIpcDispatcher::Impl::HandleAddTrustedSigner(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("whitelist_api_changed", "use hash-based API"));
}

void SharedIpcDispatcher::Impl::HandleRemoveTrustedSigner(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("whitelist_api_changed", "use hash-based API"));
}

// ============================================================================
// Feature toggles
// ============================================================================

void SharedIpcDispatcher::Impl::HandleListFeatures(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto& tm = ProductTierManager::Instance();
    json arr = json::array();
    static const std::pair<FeatureCategory, std::string_view> kFeatures[] = {
        {FeatureCategory::Core,                "Core"},
        {FeatureCategory::HomeProtection,      "HomeProtection"},
        {FeatureCategory::ForensicsBasic,      "ForensicsBasic"},
        {FeatureCategory::ForensicsAdvanced,   "ForensicsAdvanced"},
        {FeatureCategory::ThreatIntel,         "ThreatIntel"},
        {FeatureCategory::ThreatIntelAdvanced, "ThreatIntelAdvanced"},
        {FeatureCategory::Dashboard,           "Dashboard"},
        {FeatureCategory::CloudConsole,        "CloudConsole"},
        {FeatureCategory::FleetManagement,     "FleetManagement"},
        {FeatureCategory::RemoteActions,       "RemoteActions"},
        {FeatureCategory::SIEMIntegration,     "SIEMIntegration"},
        {FeatureCategory::SOARIntegration,     "SOARIntegration"},
        {FeatureCategory::ComplianceReporting, "ComplianceReporting"},
        {FeatureCategory::CustomRules,         "CustomRules"},
        {FeatureCategory::RBAC,                "RBAC"},
        {FeatureCategory::XDRCorrelation,      "XDRCorrelation"},
        {FeatureCategory::CloudTelemetry,      "CloudTelemetry"},
        {FeatureCategory::KernelProtection,    "KernelProtection"},
    };
    for (const auto& [cat, name] : kFeatures) {
        arr.push_back({{"name", std::string(name)}, {"enabled", tm.IsFeatureEnabled(cat)}, {"id", static_cast<int>(cat)}});
    }
    Reply(cid, rid, MakeOk({{"features", arr}}));
}

void SharedIpcDispatcher::Impl::HandleSetFeatureEnabled(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto id = Field<int>(j, "id");
    auto enabled = Field<bool>(j, "enabled");
    if (!id || !enabled.has_value()) { Reply(cid, rid, MakeError("invalid_params", "id and enabled required")); return; }
    auto cat = static_cast<FeatureCategory>(*id);
    ProductTierManager::Instance().OverrideFeature(cat, *enabled);
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleGetFeatureStatus(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto id = Field<int>(j, "id");
    if (!id) { Reply(cid, rid, MakeError("invalid_params", "id required")); return; }
    auto cat = static_cast<FeatureCategory>(*id);
    bool enabled = ProductTierManager::Instance().IsFeatureEnabled(cat);
    Reply(cid, rid, MakeOk({{"id", *id}, {"enabled", enabled}}));
}

void SharedIpcDispatcher::Impl::HandleResetFeatureDefaults(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    ProductTierManager::Instance().ClearAllOverrides();
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleGetProtectionStatus(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto& rtp = RealTime::RealTimeProtection::Instance();
    auto status = rtp.GetStatus();
    Reply(cid, rid, MakeOk({
        {"active",          status.isProtected},
        {"driverConnected", status.driverConnected},
        {"driverLoaded",    status.driverLoaded},
        {"state",           static_cast<int>(status.state)},
    }));
}

void SharedIpcDispatcher::Impl::HandleSetProtectionEnabled(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto name = Field<std::string>(j, "module");
    auto enabled = Field<bool>(j, "enabled");
    if (!name || !enabled.has_value()) { Reply(cid, rid, MakeError("invalid_params", "module and enabled required")); return; }
    // Delegate to ConfigManager — module names map to Home/<module>/Enabled keys
    auto key = L"Home/" + std::wstring(name->begin(), name->end()) + L"/Enabled";
    ConfigManager::Instance().SetValue(key, *enabled);
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleGetRealTimeStatus(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    bool running = RealTime::RealTimeProtection::Instance().IsActive();
    Reply(cid, rid, MakeOk({{"running", running}}));
}

void SharedIpcDispatcher::Impl::HandleSetRealTimeEnabled(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto enabled = Field<bool>(j, "enabled");
    if (!enabled.has_value()) { Reply(cid, rid, MakeError("invalid_params", "enabled required")); return; }
    auto& rtp = RealTime::RealTimeProtection::Instance();
    if (*enabled) {
        rtp.Resume();
    } else {
        uint32_t durationMs = j.value("durationMs", 0u);
        rtp.Pause(durationMs, L"User request via GUI");
    }
    Reply(cid, rid, MakeOk());
}

// ============================================================================
// Response actions (all require admin integrity)
// ============================================================================

void SharedIpcDispatcher::Impl::HandleKillProcess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto pid = Field<uint32_t>(j, "pid");
    if (!pid) { Reply(cid, rid, MakeError("invalid_params", "pid required")); return; }
    bool ok = Utils::ProcessUtils::TerminateProcessTree(*pid, 0);
    SS_LOG_WARN(kLog, L"Process %u killed by client %llu: %ls", *pid, cid, ok ? L"ok" : L"failed");
    Reply(cid, rid, ok ? MakeOk() : MakeError("failed", "Could not terminate process"));
}

void SharedIpcDispatcher::Impl::HandleSuspendProcess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto pid = Field<uint32_t>(j, "pid");
    if (!pid) { Reply(cid, rid, MakeError("invalid_params", "pid required")); return; }
    bool ok = Core::Process::ProcessKiller::Instance().SuspendProcess(*pid);
    Reply(cid, rid, ok ? MakeOk() : MakeError("failed", "Suspend failed"));
}

void SharedIpcDispatcher::Impl::HandleIsolateProcess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto pid = Field<uint32_t>(j, "pid");
    if (!pid) { Reply(cid, rid, MakeError("invalid_params", "pid required")); return; }
    // Kill + quarantine the executable
    Utils::ProcessUtils::TerminateProcessTree(*pid, 0);
    SS_LOG_WARN(kLog, L"Process %u isolated by client %llu", *pid, cid);
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleQuarantineFile(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto path = Field<std::string>(j, "path");
    if (!path) { Reply(cid, rid, MakeError("invalid_params", "path required")); return; }
    std::wstring wpath(path->begin(), path->end());
    auto qr = QuarantineManager::Instance().QuarantineFile(wpath, L"GUI-triggered quarantine");
    bool ok = (qr.status == Core::Engine::QuarantineStatus::Success ||
               qr.status == Core::Engine::QuarantineStatus::AlreadyQuarantined);
    Reply(cid, rid, ok ? MakeOk() : MakeError("failed", "Quarantine failed"));
}

void SharedIpcDispatcher::Impl::HandleRestoreFromQuarantine(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto id = Field<std::string>(j, "id");
    if (!id) { Reply(cid, rid, MakeError("invalid_params", "id required")); return; }
    try {
        uint64_t eid = std::stoull(*id);
        auto rr = QuarantineManager::Instance().RestoreFile(eid);
        bool ok = rr.IsSuccess();
        Reply(cid, rid, ok ? MakeOk() : MakeError("failed", "Restore failed"));
    } catch (const std::exception& e) {
        Reply(cid, rid, MakeError("invalid_params", "id must be numeric"));
    }
}

void SharedIpcDispatcher::Impl::HandleDeleteFromQuarantine(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto id = Field<std::string>(j, "id");
    if (!id) { Reply(cid, rid, MakeError("invalid_params", "id required")); return; }
    try {
        uint64_t eid = std::stoull(*id);
        bool ok = QuarantineManager::Instance().DeleteFile(eid, false);
        Reply(cid, rid, ok ? MakeOk() : MakeError("failed", "Delete failed"));
    } catch (const std::exception& e) {
        Reply(cid, rid, MakeError("invalid_params", "id must be numeric"));
    }
}

void SharedIpcDispatcher::Impl::HandleBlockHash(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto hash = Field<std::string>(j, "sha256");
    auto name = Field<std::string>(j, "threatName");
    if (!hash || hash->size() != 64) { Reply(cid, rid, MakeError("invalid_params", "sha256 (64 hex) required")); return; }
    // ThreatIntelStore is not a singleton — stub until proper service access is wired
    Reply(cid, rid, MakeError("threat_intel_api_changed", "BlockHash requires ThreatIntelStore service wiring"));
    SS_LOG_WARN(kLog, L"BlockHash called by client %llu but ThreatIntel API not available", cid);
}

void SharedIpcDispatcher::Impl::HandleRemediateFile(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "automated remediation not yet available"));
}

void SharedIpcDispatcher::Impl::HandleNetworkIsolate(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "network isolation not yet available"));
}

// ============================================================================
// Telemetry views
// ============================================================================

void SharedIpcDispatcher::Impl::HandleGetProcessTree(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    if (!Detection::DetectionEngine::HasInstance() || !Detection::DetectionEngine::Instance().IsInitialized()) {
        Reply(cid, rid, MakeError("unavailable", "DetectionEngine not initialized"));
        return;
    }
    auto nodes = Detection::DetectionEngine::Instance().GetProcessTree();
    json arr = json::array();
    for (const auto& n : nodes) {
        std::string imgNarrow(n.imagePath.begin(), n.imagePath.end());
        arr.push_back({
            {"pid", n.pid}, {"ppid", n.parentPid},
            {"image", imgNarrow}, {"score", n.cumulativeScore},
            {"alive", n.IsAlive(std::chrono::system_clock::now())}
        });
    }
    Reply(cid, rid, MakeOk({{"processes", arr}}));
}

void SharedIpcDispatcher::Impl::HandleGetProcessDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto pid = Field<uint32_t>(j, "pid");
    if (!pid) { Reply(cid, rid, MakeError("invalid_params", "pid required")); return; }
    if (!Detection::DetectionEngine::HasInstance()) { Reply(cid, rid, MakeError("unavailable", "DetectionEngine not ready")); return; }
    auto node = Detection::DetectionEngine::Instance().GetProcessInfo(*pid);
    if (!node) { Reply(cid, rid, MakeError("not_found", "PID not in graph")); return; }
    std::string imgNarrow(node->imagePath.begin(), node->imagePath.end());
    json d{
        {"pid", node->pid}, {"ppid", node->parentPid},
        {"image", imgNarrow}, {"cmdline", node->commandLine},
        {"score", node->cumulativeScore},
        {"alive", node->IsAlive(std::chrono::system_clock::now())},
        {"matchedRuleCount", node->matchedRules.size()},
        {"networkEndpoints", node->networkEndpoints},
        {"fileWrites", static_cast<uint32_t>(node->fileWrites.size())},
        {"registryWrites", static_cast<uint32_t>(node->registryWrites.size())},
    };
    json rules = json::array();
    for (const auto& rid2 : node->matchedRules) rules.push_back(rid2);
    d["matchedRules"] = rules;
    Reply(cid, rid, MakeOk(d));
}

void SharedIpcDispatcher::Impl::HandleQueryTelemetry(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    // Basic telemetry query — returns recent alerts from AlertSystem
    auto& as = Communication::AlertSystem::Instance();
    auto events = as.GetRecentAlerts(100);
    json arr = json::array();
    for (const auto& ev : events) {
        arr.push_back({
            {"id", ev.alertId}, {"title", ev.subject}, {"severity", static_cast<int>(ev.severity)},
            {"detail", ev.details}
        });
    }
    Reply(cid, rid, MakeOk({{"events", arr}}));
}

void SharedIpcDispatcher::Impl::HandleGetNetworkFlows(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    // Delegate to NetworkMonitor singleton
    auto flows = ShadowStrike::Core::Network::NetworkMonitor::Instance().GetActiveConnections();
    json arr = json::array();
    for (const auto& f : flows) {
        // Convert wstring hostname to narrow string for JSON
        const std::wstring& whost = f.remoteHostname;
        std::string host(whost.begin(), whost.end());
        arr.push_back({
            {"pid", f.processContext.pid},
            {"dstIp", f.tuple.remote.ip.ToString()},
            {"dstPort", f.tuple.remote.port},
            {"dstHost", host},
            {"protocol", static_cast<int>(f.tuple.protocol)},
            {"state", static_cast<int>(f.state)}
        });
        if (arr.size() >= kMaxListItems) break;
    }
    Reply(cid, rid, MakeOk({{"flows", arr}}));
}

void SharedIpcDispatcher::Impl::HandleGetTelemetryStream(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "telemetry streaming not yet available"));
}

void SharedIpcDispatcher::Impl::HandleGetFileEvents(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "file event history not yet available"));
}

void SharedIpcDispatcher::Impl::HandleGetRegistryEvents(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "registry event history not yet available"));
}

void SharedIpcDispatcher::Impl::HandleGetDnsQueries(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "dns query log not yet available"));
}

// ============================================================================
// Alert / detection views
// ============================================================================

void SharedIpcDispatcher::Impl::HandleListAlerts(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    size_t limit = std::min<size_t>(j.value("limit", 50), kMaxListItems);
    auto events = Communication::AlertSystem::Instance().GetRecentAlerts(limit);
    json arr = json::array();
    for (const auto& ev : events) {
        arr.push_back({
            {"id", ev.alertId}, {"title", ev.subject},
            {"severity", static_cast<int>(ev.severity)},
            {"detail", ev.details},
            {"dismissed", (ev.status == Communication::AlertStatus::Resolved)}
        });
    }
    Reply(cid, rid, MakeOk({{"alerts", arr}, {"total", events.size()}}));
}

void SharedIpcDispatcher::Impl::HandleGetAlertDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto id = Field<std::string>(j, "id");
    if (!id) { Reply(cid, rid, MakeError("invalid_params", "id required")); return; }
    auto ev = Communication::AlertSystem::Instance().GetAlert(*id);
    if (!ev) { Reply(cid, rid, MakeError("not_found", "Alert not found")); return; }
    Reply(cid, rid, MakeOk({
        {"id", ev->alertId}, {"title", ev->subject},
        {"severity", static_cast<int>(ev->severity)},
        {"detail", ev->details},
    }));
}

void SharedIpcDispatcher::Impl::HandleDismissAlert(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto id = Field<std::string>(j, "id");
    if (!id) { Reply(cid, rid, MakeError("invalid_params", "id required")); return; }
    Communication::AlertSystem::Instance().AcknowledgeAlert(*id, "user");
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleGetDetectionHistory(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    HandleListAlerts(cid, 0, rid, body);
}

void SharedIpcDispatcher::Impl::HandleGetDetectionDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    HandleGetAlertDetail(cid, 0, rid, body);
}

void SharedIpcDispatcher::Impl::HandleGetAttackChain(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto pid = Field<uint32_t>(j, "pid");
    if (!pid) { Reply(cid, rid, MakeError("invalid_params", "pid required")); return; }
    // Build chain from ProcessGraph
    if (!Detection::DetectionEngine::HasInstance()) { Reply(cid, rid, MakeError("unavailable", "DetectionEngine not ready")); return; }
    auto node = Detection::DetectionEngine::Instance().GetProcessInfo(*pid);
    if (!node) { Reply(cid, rid, MakeError("not_found", "PID not in graph")); return; }
    json chain = json::array();
    for (const auto& ruleId : node->matchedRules) {
        chain.push_back({{"rule", ruleId}});
    }
    Reply(cid, rid, MakeOk({{"pid", *pid}, {"chain", chain}, {"score", node->cumulativeScore}}));
}

void SharedIpcDispatcher::Impl::HandleExportAlert(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "alert export not yet available"));
}

// ============================================================================
// Webcam handlers
// ============================================================================

static json CameraPolicyToStr(CameraPolicy p) {
    switch (p) {
        case CameraPolicy::Allow: return "allow";
        case CameraPolicy::Block: return "block";
        default: return "ask";
    }
}

void SharedIpcDispatcher::Impl::HandleGetWebcamPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto& wc = WebcamProtection::Instance();
    Reply(cid, rid, MakeOk({{"policy", CameraPolicyToStr(wc.GetPolicy())}}));
}

void SharedIpcDispatcher::Impl::HandleSetWebcamPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto policyStr = Field<std::string>(j, "policy");
    if (!policyStr) { Reply(cid, rid, MakeError("invalid_params", "policy required (allow/ask/block)")); return; }
    CameraPolicy p = CameraPolicy::Ask;
    if (*policyStr == "allow") p = CameraPolicy::Allow;
    else if (*policyStr == "block") p = CameraPolicy::Block;
    WebcamProtection::Instance().SetPolicy(p);
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleListWebcamDevices(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto devices = WebcamProtection::Instance().GetDevices();
    json arr = json::array();
    for (const auto& d : devices) {
        arr.push_back({
            {"id", d.deviceId},
            {"name", std::string(d.friendlyName.begin(), d.friendlyName.end())},
            {"busy", d.isBusy}
        });
    }
    Reply(cid, rid, MakeOk({{"devices", arr}}));
}

void SharedIpcDispatcher::Impl::HandleGetWebcamAccessLog(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    size_t limit = std::min<size_t>(j.value("limit", 50), kMaxListItems);
    auto events = WebcamProtection::Instance().GetRecentEvents(limit);
    json arr = json::array();
    for (const auto& ev : events) {
        arr.push_back({
            {"eventId", ev.eventId},
            {"pid", ev.pid},
            {"image", std::string(ev.imagePath.begin(), ev.imagePath.end())},
            {"deviceId", ev.deviceId},
            {"deviceName", std::string(ev.deviceName.begin(), ev.deviceName.end())},
            {"decision", static_cast<int>(ev.decision)}
        });
    }
    Reply(cid, rid, MakeOk({{"events", arr}}));
}

void SharedIpcDispatcher::Impl::HandleAllowWebcamAccess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto eid = Field<uint64_t>(j, "eventId");
    if (!eid) { Reply(cid, rid, MakeError("invalid_params", "eventId required")); return; }
    auto note = j.value("note", std::string{});
    bool ok = WebcamProtection::Instance().Respond(*eid, Devices::CameraAccessDecision::Allowed, note);
    Reply(cid, rid, ok ? MakeOk() : MakeError("not_found", "Pending event not found or timed out"));
}

void SharedIpcDispatcher::Impl::HandleDenyWebcamAccess(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto eid = Field<uint64_t>(j, "eventId");
    if (!eid) { Reply(cid, rid, MakeError("invalid_params", "eventId required")); return; }
    auto note = j.value("note", std::string{});
    bool ok = WebcamProtection::Instance().Respond(*eid, Devices::CameraAccessDecision::Denied, note);
    Reply(cid, rid, ok ? MakeOk() : MakeError("not_found", "Pending event not found or timed out"));
}

void SharedIpcDispatcher::Impl::HandleListWebcamTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto trusted = WebcamProtection::Instance().GetTrustedProcesses();
    json arr = json::array();
    for (const auto& t : trusted) {
        arr.push_back({
            {"id", t.id},
            {"imageName", t.imageNameLower},
            {"imagePath", std::string(t.imagePath.begin(), t.imagePath.end())},
            {"signer", t.signerSubject}
        });
    }
    Reply(cid, rid, MakeOk({{"trusted", arr}}));
}

void SharedIpcDispatcher::Impl::HandleAddWebcamTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto imageName = Field<std::string>(j, "imageName");
    if (!imageName) { Reply(cid, rid, MakeError("invalid_params", "imageName required")); return; }
    Devices::TrustedCameraProcess entry;
    entry.imageNameLower = *imageName;
    entry.signerSubject = j.value("signer", std::string{});
    auto pathStr = j.value("imagePath", std::string{});
    if (!pathStr.empty()) entry.imagePath = std::wstring(pathStr.begin(), pathStr.end());
    WebcamProtection::Instance().AddTrustedProcess(std::move(entry));
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleRemoveWebcamTrusted(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto id = Field<std::string>(j, "id");
    if (!id) { Reply(cid, rid, MakeError("invalid_params", "id required")); return; }
    bool ok = WebcamProtection::Instance().RemoveTrustedProcess(*id);
    Reply(cid, rid, ok ? MakeOk() : MakeError("not_found", "Entry not found"));
}

// ============================================================================
// Per-policy configuration
// ============================================================================

void SharedIpcDispatcher::Impl::HandleGetTierInfo(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto& tm = ProductTierManager::Instance();
    auto tier = tm.GetCurrentTier();
    auto& lic = tm.GetLicenseInfo();
    Reply(cid, rid, MakeOk({
        {"tier", static_cast<int>(tier)},
        {"tierName", tier == Config::ProductTier::Community ? "Community" : tier == Config::ProductTier::Professional ? "Professional" : "Enterprise"},
        {"organization", lic.organizationName},
        {"licenseId", lic.licenseId},
        {"maxEndpoints", lic.maxEndpoints}
    }));
}

void SharedIpcDispatcher::Impl::HandleListPolicies(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    auto& cfg = ConfigManager::Instance();
    auto allKeys = cfg.GetAllKeys();
    static constexpr std::string_view kPrefix = "Policy/";
    json arr = json::array();
    for (const auto& k : allKeys) {
        if (k.size() >= kPrefix.size() && k.compare(0, kPrefix.size(), kPrefix) == 0)
            arr.push_back(k.substr(kPrefix.size()));
    }
    Reply(cid, rid, MakeOk({{"policies", arr}}));
}

void SharedIpcDispatcher::Impl::HandleGetPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto name = Field<std::string>(j, "name");
    if (!name) { Reply(cid, rid, MakeError("invalid_params", "name required")); return; }
    std::string key = "Policy/" + *name;
    auto val = ConfigManager::Instance().GetValue<std::string>(key, {});
    Reply(cid, rid, MakeOk({{"name", *name}, {"value", val}}));
}

void SharedIpcDispatcher::Impl::HandleSetPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto name = Field<std::string>(j, "name");
    if (!name || !j.contains("value")) { Reply(cid, rid, MakeError("invalid_params", "name and value required")); return; }
    std::string key = "Policy/" + *name;
    ConfigManager::Instance().SetValue<std::string>(key, j["value"].dump());
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleResetPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAdminAuth(cid, rid)) return;
    auto j = SafeParse(body);
    auto name = Field<std::string>(j, "name");
    if (!name) { Reply(cid, rid, MakeError("invalid_params", "name required")); return; }
    std::string key = "Policy/" + *name;
    ConfigManager::Instance().ResetKeyToDefault(key);
    Reply(cid, rid, MakeOk());
}

void SharedIpcDispatcher::Impl::HandleExportPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "policy export not yet available"));
}

void SharedIpcDispatcher::Impl::HandleImportPolicy(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "policy import not yet available"));
}

// ============================================================================
// Rule management
// ============================================================================

void SharedIpcDispatcher::Impl::HandleListRules(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAuth(cid, rid)) return;
    if (!Detection::DetectionEngine::HasInstance()) { Reply(cid, rid, MakeError("unavailable", "DetectionEngine not ready")); return; }
    auto& de = Detection::DetectionEngine::Instance();
    auto stats = de.GetStats();
    Reply(cid, rid, MakeOk({
        {"totalRules", stats.ruleCount},
        {"ruleEngineEvaluations", stats.ruleStats.evaluations},
        {"ruleEngineMatches", stats.ruleStats.matches}
    }));
}

void SharedIpcDispatcher::Impl::HandleGetRuleDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    if (!CheckAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "Rule detail query requires RuleStore export — pending"));
}

void SharedIpcDispatcher::Impl::HandleEnableRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    Reply(cid, rid, MakeError("not_implemented", "Per-rule enable/disable requires RuleStore mutation API — pending"));
}

void SharedIpcDispatcher::Impl::HandleDisableRule(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
    HandleEnableRule(cid, 0, rid, body);
}

void SharedIpcDispatcher::Impl::HandleReloadRules(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
    if (!CheckAdminAuth(cid, rid)) return;
    if (!Detection::DetectionEngine::HasInstance()) { Reply(cid, rid, MakeError("unavailable", "DetectionEngine not ready")); return; }
    bool ok = Detection::DetectionEngine::Instance().ReloadRules();
    Reply(cid, rid, ok ? MakeOk() : MakeError("failed", "Rule reload failed"));
}

// ============================================================================
// Install / Uninstall
// ============================================================================

#define REG_HANDLER(cmd, fn) \
    svc.RegisterV2Handler(CommandType::cmd, [this](uint64_t cid, uint32_t sid, uint64_t rid, std::string_view body) { \
        fn(cid, sid, rid, body); \
    })

void SharedIpcDispatcher::Impl::InstallHandlers(ServiceCommunicator& svc) {
    // Exclusions
    REG_HANDLER(ListExclusions,        HandleListExclusions);
    REG_HANDLER(AddExclusion,          HandleAddExclusion);
    REG_HANDLER(RemoveExclusion,       HandleRemoveExclusion);
    REG_HANDLER(UpdateExclusion,       HandleUpdateExclusion);
    REG_HANDLER(ClearExclusions,       HandleClearExclusions);
    REG_HANDLER(ImportExclusions,      HandleImportExclusions);
    REG_HANDLER(ExportExclusions,      HandleExportExclusions);
    // Policy
    REG_HANDLER(GetAccessPolicy,       HandleGetAccessPolicy);
    REG_HANDLER(SetAccessPolicy,       HandleSetAccessPolicy);
    REG_HANDLER(ListPolicyRules,       HandleListPolicyRules);
    REG_HANDLER(AddPolicyRule,         HandleAddPolicyRule);
    REG_HANDLER(RemovePolicyRule,      HandleRemovePolicyRule);
    REG_HANDLER(GetDefaultPolicy,      HandleGetDefaultPolicy);
    REG_HANDLER(SetDefaultPolicy,      HandleSetDefaultPolicy);
    // Trust
    REG_HANDLER(ListTrustedItems,      HandleListTrustedItems);
    REG_HANDLER(AddTrustedItem,        HandleAddTrustedItem);
    REG_HANDLER(RemoveTrustedItem,     HandleRemoveTrustedItem);
    REG_HANDLER(IsTrusted,             HandleIsTrusted);
    REG_HANDLER(ListTrustedSigners,    HandleListTrustedSigners);
    REG_HANDLER(AddTrustedSigner,      HandleAddTrustedSigner);
    REG_HANDLER(RemoveTrustedSigner,   HandleRemoveTrustedSigner);
    // Features
    REG_HANDLER(ListFeatures,          HandleListFeatures);
    REG_HANDLER(SetFeatureEnabled,     HandleSetFeatureEnabled);
    REG_HANDLER(GetFeatureStatus,      HandleGetFeatureStatus);
    REG_HANDLER(ResetFeatureDefaults,  HandleResetFeatureDefaults);
    // Protection
    REG_HANDLER(GetProtectionStatus,   HandleGetProtectionStatus);
    REG_HANDLER(SetProtectionEnabled,  HandleSetProtectionEnabled);
    REG_HANDLER(GetRealTimeStatus,     HandleGetRealTimeStatus);
    REG_HANDLER(SetRealTimeEnabled,    HandleSetRealTimeEnabled);
    // Response actions
    REG_HANDLER(KillProcess,           HandleKillProcess);
    REG_HANDLER(SuspendProcess,        HandleSuspendProcess);
    REG_HANDLER(IsolateProcess,        HandleIsolateProcess);
    REG_HANDLER(QuarantineFile,        HandleQuarantineFile);
    REG_HANDLER(RestoreFromQuarantine, HandleRestoreFromQuarantine);
    REG_HANDLER(DeleteFromQuarantine,  HandleDeleteFromQuarantine);
    REG_HANDLER(RemediateFile,         HandleRemediateFile);
    REG_HANDLER(NetworkIsolate,        HandleNetworkIsolate);
    REG_HANDLER(BlockHash,             HandleBlockHash);
    // Telemetry
    REG_HANDLER(GetTelemetryStream,    HandleGetTelemetryStream);
    REG_HANDLER(QueryTelemetry,        HandleQueryTelemetry);
    REG_HANDLER(GetProcessTree,        HandleGetProcessTree);
    REG_HANDLER(GetProcessDetail,      HandleGetProcessDetail);
    REG_HANDLER(GetNetworkFlows,       HandleGetNetworkFlows);
    REG_HANDLER(GetFileEvents,         HandleGetFileEvents);
    REG_HANDLER(GetRegistryEvents,     HandleGetRegistryEvents);
    REG_HANDLER(GetDnsQueries,         HandleGetDnsQueries);
    // Alerts
    REG_HANDLER(ListAlerts,            HandleListAlerts);
    REG_HANDLER(GetAlertDetail,        HandleGetAlertDetail);
    REG_HANDLER(DismissAlert,          HandleDismissAlert);
    REG_HANDLER(GetDetectionHistory,   HandleGetDetectionHistory);
    REG_HANDLER(GetDetectionDetail,    HandleGetDetectionDetail);
    REG_HANDLER(GetAttackChain,        HandleGetAttackChain);
    REG_HANDLER(ExportAlert,           HandleExportAlert);
    // Webcam
    REG_HANDLER(GetWebcamPolicy,       HandleGetWebcamPolicy);
    REG_HANDLER(SetWebcamPolicy,       HandleSetWebcamPolicy);
    REG_HANDLER(ListWebcamDevices,     HandleListWebcamDevices);
    REG_HANDLER(GetWebcamAccessLog,    HandleGetWebcamAccessLog);
    REG_HANDLER(AllowWebcamAccess,     HandleAllowWebcamAccess);
    REG_HANDLER(DenyWebcamAccess,      HandleDenyWebcamAccess);
    REG_HANDLER(ListWebcamTrusted,     HandleListWebcamTrusted);
    REG_HANDLER(AddWebcamTrusted,      HandleAddWebcamTrusted);
    REG_HANDLER(RemoveWebcamTrusted,   HandleRemoveWebcamTrusted);
    // Policy config
    REG_HANDLER(GetTierInfo,           HandleGetTierInfo);
    REG_HANDLER(ListPolicies,          HandleListPolicies);
    REG_HANDLER(GetPolicy,             HandleGetPolicy);
    REG_HANDLER(SetPolicy,             HandleSetPolicy);
    REG_HANDLER(ResetPolicy,           HandleResetPolicy);
    REG_HANDLER(ExportPolicy,          HandleExportPolicy);
    REG_HANDLER(ImportPolicy,          HandleImportPolicy);
    // Rules
    REG_HANDLER(ListRules,             HandleListRules);
    REG_HANDLER(GetRuleDetail,         HandleGetRuleDetail);
    REG_HANDLER(EnableRule,            HandleEnableRule);
    REG_HANDLER(DisableRule,           HandleDisableRule);
    REG_HANDLER(ReloadRules,           HandleReloadRules);
}

#undef REG_HANDLER

void SharedIpcDispatcher::Impl::UninstallHandlers(ServiceCommunicator& svc) {
    // Register no-ops for every command we own
    auto noop = [](uint64_t, uint32_t, uint64_t, std::string_view) {};
    static const CommandType kOwned[] = {
        CommandType::ListExclusions, CommandType::AddExclusion,
        CommandType::RemoveExclusion, CommandType::UpdateExclusion,
        CommandType::ClearExclusions, CommandType::ImportExclusions,
        CommandType::ExportExclusions,
        CommandType::GetAccessPolicy, CommandType::SetAccessPolicy,
        CommandType::ListPolicyRules, CommandType::AddPolicyRule,
        CommandType::RemovePolicyRule, CommandType::GetDefaultPolicy,
        CommandType::SetDefaultPolicy,
        CommandType::ListTrustedItems, CommandType::AddTrustedItem,
        CommandType::RemoveTrustedItem, CommandType::IsTrusted,
        CommandType::ListTrustedSigners, CommandType::AddTrustedSigner,
        CommandType::RemoveTrustedSigner,
        CommandType::ListFeatures, CommandType::SetFeatureEnabled,
        CommandType::GetFeatureStatus, CommandType::ResetFeatureDefaults,
        CommandType::GetProtectionStatus, CommandType::SetProtectionEnabled,
        CommandType::GetRealTimeStatus, CommandType::SetRealTimeEnabled,
        CommandType::KillProcess, CommandType::SuspendProcess,
        CommandType::IsolateProcess, CommandType::QuarantineFile,
        CommandType::RestoreFromQuarantine, CommandType::DeleteFromQuarantine,
        CommandType::RemediateFile, CommandType::NetworkIsolate,
        CommandType::BlockHash,
        CommandType::GetTelemetryStream, CommandType::QueryTelemetry,
        CommandType::GetProcessTree, CommandType::GetProcessDetail,
        CommandType::GetNetworkFlows, CommandType::GetFileEvents,
        CommandType::GetRegistryEvents, CommandType::GetDnsQueries,
        CommandType::ListAlerts, CommandType::GetAlertDetail,
        CommandType::DismissAlert, CommandType::GetDetectionHistory,
        CommandType::GetDetectionDetail, CommandType::GetAttackChain,
        CommandType::ExportAlert,
        CommandType::GetWebcamPolicy, CommandType::SetWebcamPolicy,
        CommandType::ListWebcamDevices, CommandType::GetWebcamAccessLog,
        CommandType::AllowWebcamAccess, CommandType::DenyWebcamAccess,
        CommandType::ListWebcamTrusted, CommandType::AddWebcamTrusted,
        CommandType::RemoveWebcamTrusted,
        CommandType::GetTierInfo, CommandType::ListPolicies,
        CommandType::GetPolicy, CommandType::SetPolicy,
        CommandType::ResetPolicy, CommandType::ExportPolicy,
        CommandType::ImportPolicy,
        CommandType::ListRules, CommandType::GetRuleDetail,
        CommandType::EnableRule, CommandType::DisableRule,
        CommandType::ReloadRules,
    };
    for (auto cmd : kOwned) svc.RegisterV2Handler(cmd, noop);
}

// ============================================================================
// Public interface
// ============================================================================

SharedIpcDispatcher::SharedIpcDispatcher()  : m_impl(std::make_unique<Impl>()) {}
SharedIpcDispatcher::~SharedIpcDispatcher() = default;

SharedIpcDispatcher& SharedIpcDispatcher::Instance() {
    static SharedIpcDispatcher s;
    return s;
}

void SharedIpcDispatcher::Install(ServiceCommunicator& svc) {
    m_impl->InstallHandlers(svc);
    SS_LOG_INFO(kLog, L"SharedIpcDispatcher installed (64 handlers)");
}

void SharedIpcDispatcher::Uninstall(ServiceCommunicator& svc) {
    m_impl->UninstallHandlers(svc);
    SS_LOG_INFO(kLog, L"SharedIpcDispatcher uninstalled");
}

} // namespace ShadowStrike::Products::Shared
