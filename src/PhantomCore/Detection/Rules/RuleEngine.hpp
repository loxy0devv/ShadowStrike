/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * RuleEngine — evaluates PhantomRule objects against:
 *   - DetectionEvent (runtime events)
 *   - StaticFeatureBag (pre-execution feature sets from PE static analysis)
 *
 * Architecture:
 *   The engine is intentionally stateless w.r.t. rules — it pulls rule sets
 *   from a RuleStore reference and walks each rule whose scope matches the
 *   input. For scopes that require multi-event context (Sequence/Graph),
 *   the correlation engine performs windowing and feeds bundles back into
 *   RuleEngine.
 *
 * Performance:
 *   - Per-thread evaluation; no global locks on hot path.
 *   - Field accesses go through DetectionEvent's hash map (O(1)).
 *   - String comparisons short-circuit on length mismatch.
 *   - Regex predicates compile once and cache; cache lives in RuleEngine.
 *   - Feature predicates against PE static features are O(n) over a small
 *     pre-aggregated feature bag, never full disassembly during evaluation.
 */

#pragma once

#include "PhantomRule.hpp"

#include <memory>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
namespace Detection {

class RuleStore;

/**
 * StaticFeatureBag aggregates the features extracted from a PE during the
 * static-analysis pre-scan. Rule predicates with FeatureKind::Api / Mnemonic
 * / String etc consult this bag rather than the PE binary directly.
 */
struct StaticFeatureBag {
    std::unordered_set<std::string> strings;     // case-insensitive normalized
    std::unordered_set<std::string> apis;        // dll!api or just api (lower)
    std::unordered_set<std::string> mnemonics;   // mov, call, ...
    std::unordered_set<std::string> sections;    // .text, .rsrc, ...
    std::unordered_set<std::string> classes;     // .NET classes / C++ symbols
    std::unordered_set<std::string> namespaces;
    std::unordered_set<int64_t>     numbers;
    std::unordered_set<std::string> characteristics; // "has-tls", "high-entropy", "no-nx", ...
    std::unordered_set<std::string> os;          // "windows"
    std::unordered_set<std::string> arch;        // "amd64", "i386"
    std::unordered_set<std::string> format;      // "pe"

    // Raw bytes patterns are matched directly against the file buffer
    // by the StaticEngine before reaching the rule engine.
    std::unordered_set<std::string> bytes;       // lowercase hex string of matched patterns

    // Aggregated metrics for FeatureKind::EntropyAbove / ImportCountAbove
    double  fileEntropy   = 0.0;
    uint32_t importCount  = 0;
    uint32_t uniqueApis   = 0;
    bool     signed_       = false;
    std::string signerName;
};

struct RuleEngineConfig {
    bool   regexCachingEnabled = true;
    size_t regexCacheMax       = 4096;
    bool   evaluateHuntingRules = true;
    // Confidence/score thresholds — rules that compute below these are dropped.
    float  minConfidence = 0.0f;
    float  minScore      = 0.0f;
};

class RuleEngine {
public:
    explicit RuleEngine(std::shared_ptr<RuleStore> store,
                        RuleEngineConfig cfg = {}) noexcept;
    ~RuleEngine();

    /// Evaluate a single runtime event against all rules whose scope matches.
    /// Suppressed matches still appear in the output but with `suppressed = true`.
    std::vector<RuleMatch> Evaluate(const DetectionEvent& event) const;

    /// Evaluate static feature bag against all Static-scope rules.
    std::vector<RuleMatch> EvaluateStatic(const StaticFeatureBag& bag,
                                          std::string_view targetPath = {}) const;

    /// Evaluate a chronological sequence of events against Sequence-scope rules.
    std::vector<RuleMatch> EvaluateSequence(const std::vector<DetectionEvent>& events) const;

    /// Hot-swap rule store; previous store is released when last evaluation completes.
    void ReplaceStore(std::shared_ptr<RuleStore> newStore) noexcept;

    /// Statistics access
    struct Stats {
        uint64_t evaluations = 0;
        uint64_t matches     = 0;
        uint64_t suppressed  = 0;
        uint64_t regexCacheHits = 0;
        uint64_t regexCacheMisses = 0;
    };
    [[nodiscard]] Stats GetStats() const noexcept;
    void ResetStats() noexcept;

private:
    bool  EvalNode(const FeatureNode& node,
                   const DetectionEvent* event,
                   const StaticFeatureBag* bag,
                   std::vector<std::string>& trace) const;

    bool  EvalLeafStatic(const FeatureLeaf& leaf,
                         const StaticFeatureBag& bag,
                         std::vector<std::string>& trace) const;

    bool  EvalLeafRuntime(const FeatureLeaf& leaf,
                          const DetectionEvent& event,
                          std::vector<std::string>& trace) const;

    bool  EvalSequence(const std::vector<FeatureNode>& children,
                       std::chrono::milliseconds maxGap,
                       const std::vector<DetectionEvent>& events,
                       std::vector<std::string>& trace) const;

    bool  ApplySuppression(const PhantomRule& rule,
                           const DetectionEvent* event) const;

    const std::regex& GetRegex(std::string_view pattern, bool caseInsensitive) const;

    std::atomic<std::shared_ptr<RuleStore>> m_store;
    RuleEngineConfig           m_cfg;

    mutable std::shared_mutex                                m_regexMutex;
    mutable std::unordered_map<std::string, std::regex>      m_regexCache;

    mutable std::atomic<uint64_t> m_evaluations{0};
    mutable std::atomic<uint64_t> m_matches{0};
    mutable std::atomic<uint64_t> m_suppressed{0};
    mutable std::atomic<uint64_t> m_regexHits{0};
    mutable std::atomic<uint64_t> m_regexMisses{0};
};

} // namespace Detection
} // namespace ShadowStrike
