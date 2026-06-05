/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * RuleStore — in-memory rule database with scope-indexed access.
 *
 * Designed for atomic hot-reload: a new RuleStore is built off-thread,
 * then swapped into the RuleEngine. The old store is freed when its
 * last shared_ptr is released, which happens after in-flight evaluations
 * release their store reference.
 */

#pragma once

#include "PhantomRule.hpp"

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <filesystem>

namespace ShadowStrike {
namespace Detection {

class RuleStore {
public:
    RuleStore();
    ~RuleStore();

    /// Add or replace a rule by id. Returns true if added, false if replaced.
    bool AddOrReplace(PhantomRule rule);

    /// Remove a rule by id. Returns true if removed.
    bool Remove(std::string_view id);

    /// Get a single rule by id.
    [[nodiscard]] const PhantomRule* Get(std::string_view id) const noexcept;

    /// All rules whose scope matches.
    [[nodiscard]] std::vector<const PhantomRule*> RulesByScope(RuleScope scope) const;

    /// All rules. Avoid in the hot path; this clones the pointer list.
    [[nodiscard]] std::vector<const PhantomRule*> All() const;

    /// Total rule count.
    [[nodiscard]] size_t Size() const noexcept;

    /// Sets a global suppression rule for `field == value` across every rule.
    void GlobalSuppress(std::string field, std::string value);

    /// Per-source count.
    [[nodiscard]] std::unordered_map<RuleSource, size_t> CountsBySource() const;

    /// Build a *new* RuleStore identical to this one with the given delta applied.
    [[nodiscard]] std::shared_ptr<RuleStore> CloneWith(PhantomRule extra) const;

    /// Load all native (*.yaml/*.json) rules from a directory tree.
    /// Implementation accepts the ShadowStrike native YAML/JSON format.
    [[nodiscard]] size_t LoadFromDirectory(const std::filesystem::path& dir,
                                           RuleSource sourceHint = RuleSource::Native);

private:
    mutable std::shared_mutex                       m_mutex;
    std::unordered_map<std::string, PhantomRule>    m_rules;
    std::unordered_map<int, std::vector<std::string>> m_byScope;  // keyed by static_cast<int>(scope)
    std::vector<std::pair<std::string, std::string>> m_globalSuppress;
};

} // namespace Detection
} // namespace ShadowStrike
