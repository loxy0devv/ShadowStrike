/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * ProcessGraph — in-memory representation of all live and recently-terminated
 * processes on the endpoint, with parent/child relationships, image lineage,
 * cumulative evidence, and decay.
 *
 * Used by:
 *   - Correlator to expand a single suspicious event into a kill-chain view
 *   - Evidence ledger to compute per-process risk score
 *   - GUI API to draw a process tree
 *
 * Thread-safe: a single internal shared_mutex protects the graph. Hot-path
 * lookups use shared_lock; mutations use unique_lock. We avoid blocking the
 * sensor on graph operations by accepting events through a non-blocking
 * MPSC queue inside EventBus.
 */

#pragma once

#include "../Rules/PhantomRule.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
namespace Detection {

struct ProcessNode {
    uint32_t pid           = 0;
    uint32_t parentPid     = 0;
    uint64_t creationToken = 0;  // sortable creation order

    std::wstring imagePath;
    std::string  imageNameLower;
    std::string  commandLine;
    std::string  userSid;
    std::string  integrityLevel;
    std::string  signerSubject;
    bool         signed_       = false;
    bool         trustedSigner = false;

    std::chrono::system_clock::time_point created{};
    std::optional<std::chrono::system_clock::time_point> terminated{};

    // -- evidence accumulation
    float        cumulativeScore   = 0.0f;  // 0..100
    RuleSeverity worstSeverity     = RuleSeverity::Informational;
    uint32_t     matchedRuleCount  = 0;
    std::vector<std::string> matchedRules;
    std::vector<AttackMapping> attack;

    // -- module loads, thread injections, network endpoints, file writes (tail buffers)
    std::vector<std::wstring> loadedImages;
    std::vector<std::string>  observedApis;
    std::vector<std::string>  networkEndpoints;
    std::vector<std::string>  registryWrites;
    std::vector<std::wstring> fileWrites;

    // -- relations
    std::vector<uint32_t> childPids;

    [[nodiscard]] bool IsAlive(std::chrono::system_clock::time_point now) const noexcept {
        return !terminated.has_value() || (now - *terminated) < std::chrono::minutes(30);
    }
};

class ProcessGraph {
public:
    ProcessGraph();
    ~ProcessGraph();

    /// Insert / update process node.
    void OnProcessStart(uint32_t pid, uint32_t parentPid,
                        std::wstring image, std::string commandLine,
                        std::string userSid, std::string integrity,
                        std::chrono::system_clock::time_point at);
    void OnProcessExit(uint32_t pid, std::chrono::system_clock::time_point at);

    /// Record an event against a process node (no PID lookup if pid==0).
    void OnImageLoad(uint32_t pid, std::wstring image, bool signedImg);
    void OnNetworkEndpoint(uint32_t pid, std::string endpoint);
    void OnFileWrite(uint32_t pid, std::wstring path);
    void OnRegistryWrite(uint32_t pid, std::string key);
    void OnApiSeen(uint32_t pid, std::string api);
    void OnSignerInfo(uint32_t pid, std::string subject, bool trusted);

    /// Apply a rule match's evidence to the process node.
    void ApplyMatch(uint32_t pid, const RuleMatch& match);

    /// Lookup
    [[nodiscard]] std::optional<ProcessNode> Get(uint32_t pid) const;
    [[nodiscard]] std::vector<ProcessNode>   Children(uint32_t pid) const;
    [[nodiscard]] std::vector<ProcessNode>   AncestryChain(uint32_t pid) const;
    [[nodiscard]] std::vector<uint32_t>      Descendants(uint32_t pid) const;
    [[nodiscard]] size_t                     Size() const noexcept;
    [[nodiscard]] std::vector<ProcessNode>   Snapshot() const;

    /// Garbage collect dead nodes older than `age`. Returns count removed.
    size_t Reap(std::chrono::seconds age = std::chrono::minutes(30));

    /// Per-process verdict: compute aggregated score.
    [[nodiscard]] float Score(uint32_t pid) const;

private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<uint32_t, ProcessNode> m_nodes;
    std::atomic<uint64_t>     m_creationCounter{0};
};

} // namespace Detection
} // namespace ShadowStrike
