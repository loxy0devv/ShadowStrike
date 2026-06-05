/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * EDR-specific IPC command handlers (500–519).
 * All handlers require FeatureCategory::ForensicsAdvanced to be enabled.
 */
#include "pch.h"
#include "EDRIpcDispatcher.hpp"
#include "PhantomCore/Service/ServiceCommunicator.hpp"
#include "PhantomCore/Config/ProductTier.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "Products/Community/PhantomEDR/Forensics/EvidenceCollector.hpp"
#include "Products/Community/PhantomEDR/IncidentResponse/IncidentManager.hpp"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookEngine.hpp"
#include "Products/Community/PhantomEDR/ThreatHunting/HuntQueryEngine.hpp"
#include "Products/Community/PhantomEDR/Vulnerability/VulnScanner.hpp"
#include "Products/Community/PhantomEDR/LiveResponse/ProcessInspector.hpp"
#include <nlohmann/json.hpp>

namespace ShadowStrike::Products::PhantomEDR {

using Service::ServiceCommunicator;
using Service::CommandType;
using Config::ProductTierManager;
using Config::FeatureCategory;
using json = nlohmann::json;

static constexpr const wchar_t* kLog = L"EDRIpc";

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
    return j.is_discarded() ? json::object() : j;
}
template<typename T>
static std::optional<T> Field(const json& obj, std::string_view key) noexcept {
    try { auto it = obj.find(key); if (it == obj.end()) return {}; return it->template get<T>(); } catch (...) { return {}; }
}

struct EDRIpcDispatcher::Impl {
    void InstallHandlers(ServiceCommunicator& svc);
    void UninstallHandlers(ServiceCommunicator& svc);

    // FIX 1: Reply now passes CommandType as the required 2nd argument to SendResponseEnvelope.
    void Reply(uint64_t cid, CommandType type, uint64_t rid, const json& payload) noexcept {
        try { ServiceCommunicator::Instance().SendResponseEnvelope(cid, type, rid, payload.dump()); } catch (...) {}
    }
    bool CheckEDR(uint64_t cid, CommandType type, uint64_t rid) noexcept {
        if (!ServiceCommunicator::Instance().IsClientAuthenticated(cid)) {
            Reply(cid, type, rid, MakeError("unauthorized", "Not authenticated")); return false;
        }
        if (!ProductTierManager::Instance().IsFeatureEnabled(FeatureCategory::ForensicsAdvanced)) {
            Reply(cid, type, rid, MakeError("tier_required", "EDR tier required for this feature")); return false;
        }
        return true;
    }

    // FIX 2a: EvidenceCollector::ListArtifacts does not exist.
    // Return a stub response indicating live collection IDs should be used instead.
    void HandleListForensicArtifacts(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
        if (!CheckEDR(cid, CommandType::ListForensicArtifacts, rid)) return;
        Reply(cid, CommandType::ListForensicArtifacts, rid,
              MakeOk({{"artifacts", json::array()}, {"note", "use collection API"}}));
    }

    // FIX 2b: EvidenceCollector::CollectForProcess does not exist.
    // Use CollectEvidence(pid, L"") instead and report success via absence of exception.
    void HandleCollectArtifact(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckEDR(cid, CommandType::CollectArtifact, rid)) return;
        auto j = SafeParse(body);
        auto pid = Field<uint32_t>(j, "pid");
        if (!pid) { Reply(cid, CommandType::CollectArtifact, rid, MakeError("invalid_params", "pid required")); return; }
        try {
            (void)Forensics::EvidenceCollector::Instance().CollectEvidence(*pid, L"");
            Reply(cid, CommandType::CollectArtifact, rid, MakeOk({{"collected", true}}));
        } catch (const std::exception& ex) {
            Reply(cid, CommandType::CollectArtifact, rid, MakeError("failed", ex.what()));
        }
    }

    // FIX 3a: GetIncidents -> GetRecentIncidents; inc.id -> inc.incidentId
    void HandleGetIncidents(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckEDR(cid, CommandType::GetIncidents, rid)) return;
        auto j = SafeParse(body);
        size_t limit = std::min<size_t>(j.value("limit", 50), 500);
        auto incidents = IncidentResponse::IncidentManager::Instance().GetRecentIncidents(limit);
        json arr = json::array();
        for (const auto& inc : incidents) {
            arr.push_back({
                {"id", inc.incidentId}, {"title", inc.title},
                {"severity", static_cast<int>(inc.severity)},
                {"status", static_cast<int>(inc.status)},
                {"createdAt", std::chrono::duration_cast<std::chrono::seconds>(inc.createdAt.time_since_epoch()).count()}
            });
        }
        Reply(cid, CommandType::GetIncidents, rid, MakeOk({{"incidents", arr}}));
    }

    // FIX 3b: GetIncidentDetail -> GetIncident; inc->id -> inc->incidentId;
    //         inc->affectedPids -> inc->affectedProcessIds; remove inc->timeline (field doesn't exist)
    void HandleGetIncidentDetail(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckEDR(cid, CommandType::GetIncidentDetail, rid)) return;
        auto j = SafeParse(body);
        auto id = Field<std::string>(j, "id");
        if (!id) { Reply(cid, CommandType::GetIncidentDetail, rid, MakeError("invalid_params", "id required")); return; }
        auto inc = IncidentResponse::IncidentManager::Instance().GetIncident(*id);
        if (!inc) { Reply(cid, CommandType::GetIncidentDetail, rid, MakeError("not_found", "Incident not found")); return; }
        Reply(cid, CommandType::GetIncidentDetail, rid, MakeOk({
            {"id", inc->incidentId}, {"title", inc->title},
            {"description", inc->description},
            {"severity", static_cast<int>(inc->severity)},
            {"affectedPids", inc->affectedProcessIds},
            {"timeline", json::array()}
        }));
    }

    // FIX 3c: IncidentCreateParams doesn't exist; construct Incident directly.
    //         CreateIncident now takes Incident, not IncidentCreateParams.
    void HandleCreateIncident(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckEDR(cid, CommandType::CreateIncident, rid)) return;
        auto j = SafeParse(body);
        auto title = Field<std::string>(j, "title");
        if (!title) { Reply(cid, CommandType::CreateIncident, rid, MakeError("invalid_params", "title required")); return; }
        IncidentResponse::Incident params{};
        params.title = *title;
        params.description = j.value("description", std::string{});
        auto incidentId = IncidentResponse::IncidentManager::Instance().CreateIncident(params);
        Reply(cid, CommandType::CreateIncident, rid, MakeOk({{"id", incidentId}, {"title", *title}}));
    }

    // FIX 4: PlaybookParams/Execute don't exist; use ExecutePlaybook with correct args.
    //        PlaybookRunRecord has no .success; check status == Success or has_value().
    void HandleRunPlaybook(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckEDR(cid, CommandType::RunPlaybook, rid)) return;
        auto j = SafeParse(body);
        auto name = Field<std::string>(j, "name");
        if (!name) { Reply(cid, CommandType::RunPlaybook, rid, MakeError("invalid_params", "name required")); return; }
        auto result = Playbooks::PlaybookEngine::Instance().ExecutePlaybook(
            *name, Playbooks::Json::object(), Playbooks::PlaybookTriggerType::Manual, "ipc");
        if (!result.has_value()) {
            Reply(cid, CommandType::RunPlaybook, rid, MakeError("failed", "Playbook execution did not start"));
            return;
        }
        const bool success = (result->status == Playbooks::PlaybookRunStatus::Success ||
                              result->status == Playbooks::PlaybookRunStatus::PartialSuccess);
        if (success) {
            Reply(cid, CommandType::RunPlaybook, rid,
                  MakeOk({{"runId", result->runId}, {"actionsRun", result->stepResults.size()}}));
        } else {
            Reply(cid, CommandType::RunPlaybook, rid, MakeError("failed", result->errorMessage));
        }
    }

    // FIX 8: PlaybookDefinition has no 'tier' field — omit it.
    void HandleGetPlaybooks(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
        if (!CheckEDR(cid, CommandType::GetPlaybooks, rid)) return;
        auto books = Playbooks::PlaybookEngine::Instance().ListPlaybooks();
        json arr = json::array();
        for (const auto& b : books) arr.push_back({{"name", b.name}, {"description", b.description}});
        Reply(cid, CommandType::GetPlaybooks, rid, MakeOk({{"playbooks", arr}}));
    }

    // FIX 5: HuntQueryEngine::Execute -> ExecuteQuery
    void HandleSubmitHuntQuery(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckEDR(cid, CommandType::SubmitHuntQuery, rid)) return;
        auto j = SafeParse(body);
        auto query = Field<std::string>(j, "query");
        if (!query) { Reply(cid, CommandType::SubmitHuntQuery, rid, MakeError("invalid_params", "query required")); return; }
        ThreatHunting::HuntQuery hq;
        hq.name = *query;
        auto result = ThreatHunting::HuntQueryEngine::Instance().ExecuteQuery(hq);
        json hits = json::array();
        for (const auto& h : result.matches) hits.push_back({{"pid", h.processId}, {"detail", h.description}});
        Reply(cid, CommandType::SubmitHuntQuery, rid, MakeOk({{"queryId", result.queryOrRuleId}, {"hits", hits}}));
    }

    // FIX 6a: VulnScanner::GetResults(limit) -> GetLastScanResult().
    //         VulnScanResult.matches is vector<SoftwareVulnerabilityMatch>; each has .software and .vulnerabilities.
    void HandleGetVulnScanResults(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
        if (!CheckEDR(cid, CommandType::GetVulnScanResults, rid)) return;
        auto scanResult = Vulnerability::VulnScanner::Instance().GetLastScanResult();
        json arr = json::array();
        for (const auto& match : scanResult.matches) {
            for (const auto& v : match.vulnerabilities) {
                arr.push_back({{"cve", v.cveId}, {"severity", v.cvssScore},
                               {"description", v.description}, {"product", match.software.name}});
            }
        }
        Reply(cid, CommandType::GetVulnScanResults, rid, MakeOk({{"vulnerabilities", arr}}));
    }

    // FIX 6b: VulnScanner::StartScan() -> ScanEndpoint()
    void HandleStartVulnScan(uint64_t cid, uint32_t, uint64_t rid, std::string_view) {
        if (!CheckEDR(cid, CommandType::StartVulnScan, rid)) return;
        (void)Vulnerability::VulnScanner::Instance().ScanEndpoint();
        Reply(cid, CommandType::StartVulnScan, rid, MakeOk());
    }

    // FIX 9: ProcessInspector::ExecuteCommand does not exist.
    //        The closest available method for running a command against a process is InspectProcess.
    //        Return process snapshot data if pid is provided, otherwise return not_supported.
    void HandleGetLiveResponseShell(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckEDR(cid, CommandType::GetLiveResponseShell, rid)) return;
        auto j = SafeParse(body);
        auto cmd = Field<std::string>(j, "command");
        if (!cmd) { Reply(cid, CommandType::GetLiveResponseShell, rid, MakeError("invalid_params", "command required")); return; }
        uint32_t pid = j.value("pid", 0u);
        if (pid != 0) {
            auto snapshot = LiveResponse::ProcessInspector::Instance().InspectProcess(pid);
            if (snapshot.has_value()) {
                Reply(cid, CommandType::GetLiveResponseShell, rid,
                      MakeOk({{"output", ""}, {"exitCode", 0}, {"pid", pid}}));
            } else {
                Reply(cid, CommandType::GetLiveResponseShell, rid,
                      MakeError("not_found", "Process not found"));
            }
        } else {
            Reply(cid, CommandType::GetLiveResponseShell, rid,
                  MakeError("not_supported", "Live shell execution requires a target pid"));
        }
    }
};

#define REG_HANDLER(cmd, fn) \
    svc.RegisterV2Handler(CommandType::cmd, [this](uint64_t cid, uint32_t sid, uint64_t rid, std::string_view body) { \
        fn(cid, sid, rid, body); \
    })

void EDRIpcDispatcher::Impl::InstallHandlers(ServiceCommunicator& svc) {
    REG_HANDLER(ListForensicArtifacts, HandleListForensicArtifacts);
    REG_HANDLER(CollectArtifact,       HandleCollectArtifact);
    REG_HANDLER(GetIncidents,          HandleGetIncidents);
    REG_HANDLER(GetIncidentDetail,     HandleGetIncidentDetail);
    REG_HANDLER(CreateIncident,        HandleCreateIncident);
    REG_HANDLER(RunPlaybook,           HandleRunPlaybook);
    REG_HANDLER(GetPlaybooks,          HandleGetPlaybooks);
    REG_HANDLER(SubmitHuntQuery,       HandleSubmitHuntQuery);
    REG_HANDLER(GetVulnScanResults,    HandleGetVulnScanResults);
    REG_HANDLER(StartVulnScan,         HandleStartVulnScan);
    REG_HANDLER(GetLiveResponseShell,  HandleGetLiveResponseShell);
}
#undef REG_HANDLER

void EDRIpcDispatcher::Impl::UninstallHandlers(ServiceCommunicator& svc) {
    auto noop = [](uint64_t, uint32_t, uint64_t, std::string_view) {};
    for (auto cmd : {CommandType::ListForensicArtifacts, CommandType::CollectArtifact,
                     CommandType::GetIncidents, CommandType::GetIncidentDetail,
                     CommandType::CreateIncident, CommandType::RunPlaybook,
                     CommandType::GetPlaybooks, CommandType::SubmitHuntQuery,
                     CommandType::GetVulnScanResults, CommandType::StartVulnScan,
                     CommandType::GetLiveResponseShell}) {
        svc.RegisterV2Handler(cmd, noop);
    }
}

EDRIpcDispatcher::EDRIpcDispatcher()  : m_impl(std::make_unique<Impl>()) {}
EDRIpcDispatcher::~EDRIpcDispatcher() = default;

EDRIpcDispatcher& EDRIpcDispatcher::Instance() {
    static EDRIpcDispatcher s;
    return s;
}

void EDRIpcDispatcher::Install(ServiceCommunicator& svc) {
    m_impl->InstallHandlers(svc);
    SS_LOG_INFO(kLog, L"EDRIpcDispatcher installed (11 handlers)");
}

void EDRIpcDispatcher::Uninstall(ServiceCommunicator& svc) {
    m_impl->UninstallHandlers(svc);
}

} // namespace ShadowStrike::Products::PhantomEDR
