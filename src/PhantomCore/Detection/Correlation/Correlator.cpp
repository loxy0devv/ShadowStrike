/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "Correlator.hpp"

#include <algorithm>
#include <sstream>

namespace ShadowStrike {
namespace Detection {

Correlator::Correlator(std::shared_ptr<RuleEngine> engine,
                       std::shared_ptr<ProcessGraph> graph,
                       CorrelatorConfig cfg)
    : m_engine(std::move(engine)), m_graph(std::move(graph)), m_cfg(cfg) {}

Correlator::~Correlator() = default;

uint64_t Correlator::Subscribe(VerdictHandler handler) {
    std::lock_guard<std::mutex> g(m_subMutex);
    uint64_t t = m_nextToken.fetch_add(1, std::memory_order_relaxed);
    m_subscribers.emplace_back(t, std::move(handler));
    return t;
}

bool Correlator::Unsubscribe(uint64_t token) {
    std::lock_guard<std::mutex> g(m_subMutex);
    auto it = std::remove_if(m_subscribers.begin(), m_subscribers.end(),
                             [&](const auto& p){ return p.first == token; });
    if (it == m_subscribers.end()) return false;
    m_subscribers.erase(it, m_subscribers.end());
    return true;
}

void Correlator::UpdateConfig(CorrelatorConfig cfg) {
    std::lock_guard<std::mutex> g(m_cfgMutex);
    m_cfg = cfg;
}

CorrelatorConfig Correlator::GetConfig() const {
    std::lock_guard<std::mutex> g(m_cfgMutex);
    return m_cfg;
}

Correlator::Stats Correlator::GetStats() const noexcept {
    return Stats{
        m_ingested.load(std::memory_order_relaxed),
        m_matched.load(std::memory_order_relaxed),
        m_verdicts.load(std::memory_order_relaxed),
        m_suppressed.load(std::memory_order_relaxed),
        m_seqMatches.load(std::memory_order_relaxed),
    };
}

VerdictAction Correlator::RecommendedAction(float score) const noexcept {
    auto cfg = GetConfig();
    if (score >= cfg.killScoreThreshold)       return VerdictAction::Kill;
    if (score >= cfg.blockScoreThreshold)      return VerdictAction::Block;
    if (score >= cfg.quarantineScoreThreshold) return VerdictAction::Quarantine;
    if (score >= cfg.monitorScoreThreshold)    return VerdictAction::Monitor;
    return VerdictAction::Allow;
}

std::string Correlator::BuildCauseChain(uint32_t pid) const {
    auto ancestry = m_graph->AncestryChain(pid);
    std::ostringstream oss;
    bool first = true;
    for (auto it = ancestry.rbegin(); it != ancestry.rend(); ++it) {
        if (!first) oss << " -> ";
        if (it->imageNameLower.empty()) oss << "[" << it->pid << "]";
        else                            oss << it->imageNameLower << "[" << it->pid << "]";
        first = false;
    }
    return oss.str();
}

void Correlator::Ingest(DetectionEvent ev) {
    m_ingested.fetch_add(1, std::memory_order_relaxed);

    // Maintain the process graph for process-lifecycle events.
    auto now = ev.timestamp.time_since_epoch().count() ? ev.timestamp
                                                       : std::chrono::system_clock::now();
    if (ev.scope == RuleScope::Process) {
        auto pid     = static_cast<uint32_t>(ev.fieldNumber("process.pid"));
        auto ppid    = static_cast<uint32_t>(ev.fieldNumber("process.parent.pid"));
        if (ev.action == "create" && pid != 0) {
            // Convert process.executable string -> wstring
            auto exec = ev.fieldString("process.executable");
            std::wstring wexec(exec.begin(), exec.end());
            m_graph->OnProcessStart(pid, ppid, std::move(wexec),
                                    ev.fieldString("process.command_line"),
                                    ev.fieldString("user.sid"),
                                    ev.fieldString("process.integrity_level"),
                                    now);
        } else if (ev.action == "exit" && pid != 0) {
            m_graph->OnProcessExit(pid, now);
        }
    } else if (ev.scope == RuleScope::Image) {
        auto pid = static_cast<uint32_t>(ev.fieldNumber("process.pid"));
        auto img = ev.fieldString("image.path");
        std::wstring w(img.begin(), img.end());
        m_graph->OnImageLoad(pid, std::move(w), ev.fieldBool("image.signed"));
    } else if (ev.scope == RuleScope::Network) {
        auto pid = static_cast<uint32_t>(ev.fieldNumber("process.pid"));
        auto host = ev.fieldString("network.destination.host");
        auto ip   = ev.fieldString("network.destination.ip");
        auto endpoint = host.empty() ? ip : host;
        if (!endpoint.empty()) m_graph->OnNetworkEndpoint(pid, endpoint);
    } else if (ev.scope == RuleScope::File) {
        auto pid = static_cast<uint32_t>(ev.fieldNumber("process.pid"));
        auto fp  = ev.fieldString("file.path");
        std::wstring w(fp.begin(), fp.end());
        if (!w.empty()) m_graph->OnFileWrite(pid, std::move(w));
    } else if (ev.scope == RuleScope::Registry) {
        auto pid = static_cast<uint32_t>(ev.fieldNumber("process.pid"));
        auto k = ev.fieldString("registry.key");
        if (!k.empty()) m_graph->OnRegistryWrite(pid, std::move(k));
    }

    // Single-event rule evaluation
    EvaluateSingle(ev);

    // Window event for sequence rules
    auto pid = static_cast<uint32_t>(ev.fieldNumber("process.pid"));
    if (pid != 0) {
        std::lock_guard<std::mutex> g(m_seqMutex);
        auto& dq = m_perProcessRing[pid];
        dq.push_back(ev);
        auto cfg = GetConfig();
        // trim by count
        while (dq.size() > cfg.maxSequenceEventsPerProcess) dq.pop_front();
        // trim by time
        auto cutoff = ev.timestamp - cfg.sequenceWindow;
        while (!dq.empty() && dq.front().timestamp < cutoff) dq.pop_front();
    }

    if (pid != 0) EvaluateSequenceFor(pid);
}

void Correlator::IngestStaticReport(uint32_t pid,
                                    const std::vector<RuleMatch>& staticMatches) {
    if (pid == 0) return;
    for (const auto& m : staticMatches) {
        if (m.suppressed) continue;
        m_graph->ApplyMatch(pid, m);
        m_matched.fetch_add(1, std::memory_order_relaxed);
    }
    float score = m_graph->Score(pid);
    if (score >= m_cfg.monitorScoreThreshold) {
        Verdict v;
        v.pid = pid;
        v.score = score;
        v.at = std::chrono::system_clock::now();
        for (const auto& m : staticMatches) v.matches.push_back(m);
        for (const auto& m : staticMatches)
            for (const auto& a : m.attack) v.attack.push_back(a);
        auto best = std::max_element(staticMatches.begin(), staticMatches.end(),
            [](const RuleMatch& a, const RuleMatch& b){
                int sa = a.rule ? static_cast<int>(a.rule->severity) : 0;
                int sb = b.rule ? static_cast<int>(b.rule->severity) : 0;
                return sa < sb;
            });
        if (best != staticMatches.end() && best->rule) {
            v.detectionName = best->rule->detectionName;
            v.genericDescription = best->rule->genericDescription;
            v.severity = best->rule->severity;
        } else {
            v.detectionName = "Generic.Static.Suspicious";
            v.severity = RuleSeverity::Low;
        }
        v.recommended = RecommendedAction(score);
        v.ancestry = m_graph->AncestryChain(pid);
        v.causeChain = BuildCauseChain(pid);
        Raise(std::move(v));
    }
}

void Correlator::EvaluateSingle(const DetectionEvent& ev) {
    if (!m_engine) return;
    auto matches = m_engine->Evaluate(ev);
    if (matches.empty()) return;

    auto pid = static_cast<uint32_t>(ev.fieldNumber("process.pid"));
    bool anyUnsuppressed = false;
    for (const auto& m : matches) {
        if (m.suppressed) { m_suppressed.fetch_add(1, std::memory_order_relaxed); continue; }
        anyUnsuppressed = true;
        m_matched.fetch_add(1, std::memory_order_relaxed);
        if (pid != 0) m_graph->ApplyMatch(pid, m);
    }
    if (!anyUnsuppressed) return;

    // Cross-process inheritance: a fraction of parent score flows down
    if (pid != 0 && m_cfg.inheritScoreFromParent) {
        auto node = m_graph->Get(pid);
        if (node) {
            float pscore = m_graph->Score(node->parentPid);
            float child  = m_graph->Score(pid);
            child = std::min(100.0f, child + pscore * m_cfg.parentInheritFraction * 0.1f);
            (void)child;
        }
    }

    // Decide whether to raise a verdict
    float score = m_graph->Score(pid);
    auto cfg = GetConfig();
    if (score < cfg.monitorScoreThreshold && !cfg.emitInformational) return;
    auto node = m_graph->Get(pid);

    bool trusted = node && node->trustedSigner;
    if (trusted && cfg.trustedSignerStrictness) {
        if (score < cfg.quarantineScoreThreshold + 20.0f) return;
    }

    Verdict v;
    v.pid = pid;
    v.score = score;
    v.at = std::chrono::system_clock::now();
    v.matches = std::move(matches);

    auto best = std::max_element(v.matches.begin(), v.matches.end(),
        [](const RuleMatch& a, const RuleMatch& b){
            int sa = a.rule ? static_cast<int>(a.rule->severity) : 0;
            int sb = b.rule ? static_cast<int>(b.rule->severity) : 0;
            return sa < sb;
        });
    if (best != v.matches.end() && best->rule) {
        v.detectionName = best->rule->detectionName;
        v.genericDescription = best->rule->genericDescription;
        v.severity = best->rule->severity;
        v.attack = best->rule->attack;
    } else {
        v.detectionName = "Generic.Suspicious.Behavior";
        v.severity = RuleSeverity::Low;
    }
    v.recommended = RecommendedAction(score);
    v.ancestry = m_graph->AncestryChain(pid);
    v.causeChain = BuildCauseChain(pid);
    Raise(std::move(v));
}

void Correlator::EvaluateSequenceFor(uint32_t pid) {
    if (!m_engine) return;
    std::vector<DetectionEvent> events;
    {
        std::lock_guard<std::mutex> g(m_seqMutex);
        auto it = m_perProcessRing.find(pid);
        if (it == m_perProcessRing.end()) return;
        events.assign(it->second.begin(), it->second.end());
    }
    if (events.size() < 2) return;
    auto seqMatches = m_engine->EvaluateSequence(events);
    if (seqMatches.empty()) return;

    m_seqMatches.fetch_add(seqMatches.size(), std::memory_order_relaxed);
    for (auto& m : seqMatches) {
        if (m.suppressed) continue;
        m_graph->ApplyMatch(pid, m);
    }

    float score = m_graph->Score(pid);
    auto cfg = GetConfig();
    if (score < cfg.monitorScoreThreshold) return;

    Verdict v;
    v.pid = pid;
    v.score = score;
    v.at = std::chrono::system_clock::now();
    v.matches = std::move(seqMatches);
    auto best = std::max_element(v.matches.begin(), v.matches.end(),
        [](const RuleMatch& a, const RuleMatch& b){
            int sa = a.rule ? static_cast<int>(a.rule->severity) : 0;
            int sb = b.rule ? static_cast<int>(b.rule->severity) : 0;
            return sa < sb;
        });
    if (best != v.matches.end() && best->rule) {
        v.detectionName = best->rule->detectionName;
        v.genericDescription = best->rule->genericDescription;
        v.severity = best->rule->severity;
        v.attack = best->rule->attack;
    } else {
        v.detectionName = "Generic.AttackChain.Sequence";
        v.severity = RuleSeverity::Medium;
    }
    v.recommended = RecommendedAction(score);
    v.ancestry = m_graph->AncestryChain(pid);
    v.causeChain = BuildCauseChain(pid);
    Raise(std::move(v));
}

void Correlator::Raise(Verdict v) {
    m_verdicts.fetch_add(1, std::memory_order_relaxed);
    std::vector<VerdictHandler> handlers;
    {
        std::lock_guard<std::mutex> g(m_subMutex);
        for (const auto& [t, h] : m_subscribers) handlers.push_back(h);
    }
    for (auto& h : handlers) {
        try { if (h) h(v); } catch (...) { /* swallow */ }
    }
}

} // namespace Detection
} // namespace ShadowStrike
