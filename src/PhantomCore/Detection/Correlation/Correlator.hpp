/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Correlator — high-level orchestrator that:
 *   1. ingests DetectionEvents from the EventBus
 *   2. maintains the ProcessGraph
 *   3. feeds events to RuleEngine for single-event matches
 *   4. windows events for sequence rules
 *   5. accumulates evidence onto process nodes
 *   6. raises a Verdict only when the per-process or per-graph score crosses
 *      a configurable threshold AND suppression doesn't apply
 *
 * Design principles:
 *   - Evidence-based, not single-event-based. A single "powershell.exe spawned"
 *     never raises an alert; it raises evidence.
 *   - Cross-process evidence is supported through descendant lookup in
 *     ProcessGraph: a child can inherit a fraction of its parent's score.
 *   - Configurable thresholds: per-severity bands so a chain of 3 medium-
 *     severity matches can outrank a single low-severity match.
 *   - Suppression / allowlisting are first class.
 */

#pragma once

#include "EventBus.hpp"
#include "ProcessGraph.hpp"
#include "../Rules/PhantomRule.hpp"
#include "../Rules/RuleEngine.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>

namespace ShadowStrike {
namespace Detection {

enum class VerdictAction : uint8_t {
    Allow,        ///< No action — informational only
    Monitor,      ///< Log only, keep watching
    Quarantine,   ///< Suggest quarantine
    Block,        ///< Block process / connection
    Kill          ///< Terminate process
};

struct Verdict {
    uint32_t pid                  = 0;
    std::string detectionName;
    std::string genericDescription;
    float score                   = 0.0f;
    RuleSeverity severity         = RuleSeverity::Informational;
    VerdictAction recommended     = VerdictAction::Allow;
    std::vector<RuleMatch> matches;
    std::vector<AttackMapping> attack;
    std::vector<ProcessNode> ancestry;
    std::chrono::system_clock::time_point at{};
    std::string causeChain;  ///< short, generic — analyst-friendly
};

using VerdictHandler = std::function<void(const Verdict&)>;

struct CorrelatorConfig {
    float monitorScoreThreshold     = 25.0f;
    float quarantineScoreThreshold  = 55.0f;
    float blockScoreThreshold       = 75.0f;
    float killScoreThreshold        = 90.0f;

    bool  inheritScoreFromParent    = true;
    float parentInheritFraction     = 0.25f;

    std::chrono::seconds sequenceWindow{60};

    /// If false, signed+trusted programs require an additional +20 score before raising verdicts.
    bool  trustedSignerStrictness   = true;

    /// Max events held in the sequence window per process (per-PID ring buffer).
    size_t maxSequenceEventsPerProcess = 256;

    bool  emitInformational         = false;  ///< if true, raises Verdict at any score
};

class Correlator {
public:
    Correlator(std::shared_ptr<RuleEngine> engine,
               std::shared_ptr<ProcessGraph> graph,
               CorrelatorConfig cfg = {});
    ~Correlator();

    /// Push an event for correlation. Synchronous evaluation.
    /// (For async, wrap with EventBus.)
    void Ingest(DetectionEvent ev);

    /// Apply a pre-computed static-analysis report to a process (called on
    /// process start if the image has been statically analyzed already).
    void IngestStaticReport(uint32_t pid, const std::vector<RuleMatch>& staticMatches);

    /// Register a verdict handler. Multiple handlers may be registered.
    uint64_t Subscribe(VerdictHandler handler);
    bool     Unsubscribe(uint64_t token);

    void UpdateConfig(CorrelatorConfig cfg);
    [[nodiscard]] CorrelatorConfig GetConfig() const;

    /// Statistics
    struct Stats {
        uint64_t ingested        = 0;
        uint64_t matched         = 0;
        uint64_t verdictsRaised  = 0;
        uint64_t suppressed      = 0;
        uint64_t sequenceMatches = 0;
    };
    [[nodiscard]] Stats GetStats() const noexcept;

private:
    void EvaluateSingle(const DetectionEvent& ev);
    void EvaluateSequenceFor(uint32_t pid);
    void Raise(Verdict v);
    VerdictAction RecommendedAction(float score) const noexcept;
    std::string BuildCauseChain(uint32_t pid) const;

    std::shared_ptr<RuleEngine>   m_engine;
    std::shared_ptr<ProcessGraph> m_graph;

    mutable std::mutex            m_cfgMutex;
    CorrelatorConfig              m_cfg;

    mutable std::mutex            m_seqMutex;
    std::unordered_map<uint32_t, std::deque<DetectionEvent>> m_perProcessRing;

    mutable std::mutex            m_subMutex;
    std::vector<std::pair<uint64_t, VerdictHandler>> m_subscribers;
    std::atomic<uint64_t>         m_nextToken{1};

    std::atomic<uint64_t> m_ingested{0};
    std::atomic<uint64_t> m_matched{0};
    std::atomic<uint64_t> m_verdicts{0};
    std::atomic<uint64_t> m_suppressed{0};
    std::atomic<uint64_t> m_seqMatches{0};
};

} // namespace Detection
} // namespace ShadowStrike
