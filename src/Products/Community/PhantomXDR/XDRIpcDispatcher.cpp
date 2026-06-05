/*
 * ShadowStrike — XDR IPC dispatcher (commands 520–539).
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"
#include "XDRIpcDispatcher.hpp"
#include "PhantomCore/Service/ServiceCommunicator.hpp"
#include "PhantomCore/Config/ProductTier.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/CorrelationEngine.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/StorylineBuilder.hpp"
#include "Products/Community/PhantomXDR/NetworkDetection/NetworkSensor.hpp"
#include "Products/Community/PhantomXDR/EmailThreat/EmailAnalyzer.hpp"
#include "Products/Community/PhantomXDR/EmailThreat/EmailTypes.hpp"

// EmailThreatDetector.hpp was removed; provide a thin facade over EmailAnalyzer.
namespace ShadowStrike::Products::PhantomXDR::EmailThreat {
struct EmailThreat {
    std::string id;
    std::string subject;
    std::string threatType;
    double      score = 0.0;
};
class EmailThreatDetector {
public:
    static EmailThreatDetector& Instance() {
        static EmailThreatDetector s;
        return s;
    }
    std::vector<EmailThreat> GetThreats(std::size_t limit) const {
        auto history = EmailAnalyzer::Instance().GetScanHistory(limit);
        std::vector<EmailThreat> out;
        out.reserve(history.size());
        for (const auto& r : history) {
            EmailThreat t;
            t.id         = r.header.messageId;
            t.subject    = r.header.subject;
            t.threatType = r.mitreTechnique;
            t.score      = r.confidence;
            out.push_back(std::move(t));
        }
        return out;
    }
};
} // namespace ShadowStrike::Products::PhantomXDR::EmailThreat
#include "Products/Community/PhantomXDR/IdentityProtection/ADMonitor.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOAREngine.hpp"
#include <nlohmann/json.hpp>

namespace ShadowStrike::Products::PhantomXDR {

using Service::ServiceCommunicator;
using Service::CommandType;
using Config::ProductTierManager;
using Config::FeatureCategory;
using json = nlohmann::json;

static constexpr const wchar_t* kLog = L"XDRIpc";

static json MakeError(std::string_view c, std::string_view m) {
    return json{{"ok", false}, {"error", {{"code", std::string(c)}, {"message", std::string(m)}}}};
}
static json MakeOk(json d = nullptr) {
    json r{{"ok", true}}; if (!d.is_null()) r["data"] = std::move(d); return r;
}
static json SafeParse(std::string_view raw) noexcept {
    auto j = json::parse(raw, nullptr, false);
    return j.is_discarded() ? json::object() : j;
}
template<typename T>
static std::optional<T> Field(const json& obj, std::string_view key) noexcept {
    try { auto it = obj.find(key); if (it == obj.end()) return {}; return it->template get<T>(); } catch (...) { return {}; }
}

struct XDRIpcDispatcher::Impl {
    void Reply(uint64_t cid, CommandType type, uint64_t rid, const json& payload) noexcept {
        try { ServiceCommunicator::Instance().SendResponseEnvelope(cid, type, rid, payload.dump()); } catch (...) {}
    }
    bool CheckXDR(uint64_t cid, CommandType type, uint64_t rid) noexcept {
        if (!ServiceCommunicator::Instance().IsClientAuthenticated(cid)) {
            Reply(cid, type, rid, MakeError("unauthorized", "Not authenticated"));
            return false;
        }
        if (!ProductTierManager::Instance().IsFeatureEnabled(FeatureCategory::XDRCorrelation)) {
            Reply(cid, type, rid, MakeError("tier_required", "XDR tier required"));
            return false;
        }
        return true;
    }

    void HandleGetXDRCorrelations(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckXDR(cid, CommandType::GetXDRCorrelations, rid)) return;
        auto j = SafeParse(body);
        size_t limit = std::min<size_t>(j.value("limit", 50), 500);
        auto matches = XDRCorrelation::CorrelationEngine::Instance().GetActiveCorrelations();
        if (matches.size() > limit) matches.resize(limit);
        json arr = json::array();
        for (const auto& e : matches) {
            arr.push_back({{"id", e.matchId}, {"title", e.ruleName}, {"score", static_cast<int>(e.confidence)}, {"technique", e.ruleId}});
        }
        Reply(cid, CommandType::GetXDRCorrelations, rid, MakeOk({{"correlations", arr}}));
    }

    void HandleGetXDRStoryline(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckXDR(cid, CommandType::GetXDRStoryline, rid)) return;
        auto j = SafeParse(body);
        auto id = Field<std::string>(j, "correlationId");
        if (!id) { Reply(cid, CommandType::GetXDRStoryline, rid, MakeError("invalid_params", "correlationId required")); return; }
        auto story = XDRCorrelation::StorylineBuilder::Instance().GetStoryline(*id);
        if (!story) { Reply(cid, CommandType::GetXDRStoryline, rid, MakeError("not_found", "Correlation not found")); return; }
        Reply(cid, CommandType::GetXDRStoryline, rid, MakeOk({{"title", story->title}, {"summary", story->narrative}, {"events", story->nodes.size()}}));
    }

    void HandleGetNetworkDetections(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckXDR(cid, CommandType::GetNetworkDetections, rid)) return;
        auto j = SafeParse(body);
        size_t limit = std::min<size_t>(j.value("limit", 50), 500);
        auto detections = NetworkDetection::NetworkSensor::Instance().GetConnectionHistory(limit);
        json arr = json::array();
        size_t idx = 0;
        for (const auto& d : detections) {
            arr.push_back({{"id", idx++}, {"type", static_cast<int>(d.protocol)}, {"srcIp", d.sourceIp}, {"dstIp", d.destinationIp}, {"severity", static_cast<int>(d.indicators.empty() ? 0 : static_cast<uint8_t>(d.indicators.front()))}});
        }
        Reply(cid, CommandType::GetNetworkDetections, rid, MakeOk({{"detections", arr}}));
    }

    void HandleGetEmailThreats(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckXDR(cid, CommandType::GetEmailThreats, rid)) return;
        auto j = SafeParse(body);
        size_t limit = std::min<size_t>(j.value("limit", 50), 500);
        auto threats = EmailThreat::EmailThreatDetector::Instance().GetThreats(limit);
        json arr = json::array();
        for (const auto& t : threats) {
            arr.push_back({{"id", t.id}, {"subject", t.subject}, {"type", t.threatType}, {"score", t.score}});
        }
        Reply(cid, CommandType::GetEmailThreats, rid, MakeOk({{"threats", arr}}));
    }

    void HandleGetIdentityAlerts(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckXDR(cid, CommandType::GetIdentityAlerts, rid)) return;
        auto j = SafeParse(body);
        size_t limit = std::min<size_t>(j.value("limit", 50), 500);
        auto alerts = IdentityProtection::ADMonitor::Instance().GetAlerts(limit);
        json arr = json::array();
        for (const auto& a : alerts) {
            // Explicit narrow conversion — usernames are expected to be ASCII
            std::string user;
            user.reserve(a.affectedUser.size());
            for (wchar_t wc : a.affectedUser) user += static_cast<char>(wc);
            arr.push_back({{"type", static_cast<int>(a.threatType)},
                           {"user", user},
                           {"severity", static_cast<int>(a.severity)}});
        }
        Reply(cid, CommandType::GetIdentityAlerts, rid, MakeOk({{"alerts", arr}}));
    }

    void HandleRunSOARPlaybook(uint64_t cid, uint32_t, uint64_t rid, std::string_view body) {
        if (!CheckXDR(cid, CommandType::RunSOARPlaybook, rid)) return;
        auto j = SafeParse(body);
        auto name = Field<std::string>(j, "name");
        if (!name) { Reply(cid, CommandType::RunSOARPlaybook, rid, MakeError("invalid_params", "name required")); return; }
        auto executionId = SOARLocal::SOAREngine::Instance().ExecutePlaybook(*name, "");
        Reply(cid, CommandType::RunSOARPlaybook, rid, executionId
              ? MakeOk({{"executionId", *executionId}})
              : MakeError("failed", "Playbook execution failed or playbook not found"));
    }

    void InstallHandlers(ServiceCommunicator& svc) {
#define R(cmd, fn) svc.RegisterV2Handler(CommandType::cmd, [this](uint64_t cid, uint32_t sid, uint64_t rid, std::string_view body) { fn(cid, sid, rid, body); })
        R(GetXDRCorrelations,   HandleGetXDRCorrelations);
        R(GetXDRStoryline,      HandleGetXDRStoryline);
        R(GetNetworkDetections, HandleGetNetworkDetections);
        R(GetEmailThreats,      HandleGetEmailThreats);
        R(GetIdentityAlerts,    HandleGetIdentityAlerts);
        R(RunSOARPlaybook,      HandleRunSOARPlaybook);
#undef R
    }
    void UninstallHandlers(ServiceCommunicator& svc) {
        auto noop = [](uint64_t, uint32_t, uint64_t, std::string_view) {};
        for (auto cmd : {CommandType::GetXDRCorrelations, CommandType::GetXDRStoryline,
                         CommandType::GetNetworkDetections, CommandType::GetEmailThreats,
                         CommandType::GetIdentityAlerts, CommandType::RunSOARPlaybook})
            svc.RegisterV2Handler(cmd, noop);
    }
};

XDRIpcDispatcher::XDRIpcDispatcher()  : m_impl(std::make_unique<Impl>()) {}
XDRIpcDispatcher::~XDRIpcDispatcher() = default;
XDRIpcDispatcher& XDRIpcDispatcher::Instance() { static XDRIpcDispatcher s; return s; }
void XDRIpcDispatcher::Install(ServiceCommunicator& svc) {
    m_impl->InstallHandlers(svc);
    SS_LOG_INFO(kLog, L"XDRIpcDispatcher installed (6 handlers)");
}
void XDRIpcDispatcher::Uninstall(ServiceCommunicator& svc) { m_impl->UninstallHandlers(svc); }

} // namespace ShadowStrike::Products::PhantomXDR
