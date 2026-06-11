/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "RuleStore.hpp"
#include "RuleParser.hpp"

#include <algorithm>
#include <fstream>

namespace ShadowStrike {
namespace Detection {

RuleStore::RuleStore() = default;
RuleStore::~RuleStore() = default;

bool RuleStore::AddOrReplace(PhantomRule rule) {
    if (rule.id.empty()) return false;

    std::unique_lock lock(m_mutex);
    bool inserted = m_rules.find(rule.id) == m_rules.end();

    auto& slot = m_rules[rule.id];
    int oldScope = static_cast<int>(slot.scope);

    // Trace cross-corpus duplicate IDs so analysts can review collisions.
    if (!inserted && slot.source != rule.source) {
        std::string msg = "[RuleStore] Duplicate ID '" + rule.id +
            "' from source " + std::to_string(static_cast<int>(rule.source)) +
            " replaces source " + std::to_string(static_cast<int>(slot.source)) + "\n";
        OutputDebugStringA(msg.c_str());
    }

    if (!inserted) {
        auto& vec = m_byScope[oldScope];
        vec.erase(std::remove(vec.begin(), vec.end(), rule.id), vec.end());
    }

    int newScope = static_cast<int>(rule.scope);
    m_byScope[newScope].push_back(rule.id);
    slot = std::move(rule);
    return inserted;
}

bool RuleStore::Remove(std::string_view id) {
    std::unique_lock lock(m_mutex);
    auto it = m_rules.find(std::string(id));
    if (it == m_rules.end()) return false;
    int scope = static_cast<int>(it->second.scope);
    auto& vec = m_byScope[scope];
    vec.erase(std::remove(vec.begin(), vec.end(), it->first), vec.end());
    m_rules.erase(it);
    return true;
}

const PhantomRule* RuleStore::Get(std::string_view id) const noexcept {
    std::shared_lock lock(m_mutex);
    auto it = m_rules.find(std::string(id));
    return (it == m_rules.end()) ? nullptr : &it->second;
}

std::vector<const PhantomRule*> RuleStore::RulesByScope(RuleScope scope) const {
    std::shared_lock lock(m_mutex);
    auto it = m_byScope.find(static_cast<int>(scope));
    std::vector<const PhantomRule*> out;
    if (it == m_byScope.end()) return out;
    out.reserve(it->second.size());
    for (const auto& id : it->second) {
        auto rit = m_rules.find(id);
        if (rit != m_rules.end()) out.push_back(&rit->second);
    }
    return out;
}

std::vector<const PhantomRule*> RuleStore::All() const {
    std::shared_lock lock(m_mutex);
    std::vector<const PhantomRule*> out;
    out.reserve(m_rules.size());
    for (const auto& kv : m_rules) out.push_back(&kv.second);
    return out;
}

size_t RuleStore::Size() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_rules.size();
}

void RuleStore::GlobalSuppress(std::string field, std::string value) {
    std::unique_lock lock(m_mutex);
    m_globalSuppress.emplace_back(std::move(field), std::move(value));
    // Apply to existing rules.
    for (auto& kv : m_rules) {
        SuppressionClause sc;
        sc.field = m_globalSuppress.back().first;
        sc.values.push_back(m_globalSuppress.back().second);
        sc.isRegex = false;
        kv.second.fpGuard.suppress.push_back(sc);
    }
}

std::unordered_map<RuleSource, size_t> RuleStore::CountsBySource() const {
    std::shared_lock lock(m_mutex);
    std::unordered_map<RuleSource, size_t> out;
    for (const auto& kv : m_rules) out[kv.second.source]++;
    return out;
}

std::shared_ptr<RuleStore> RuleStore::CloneWith(PhantomRule extra) const {
    auto next = std::make_shared<RuleStore>();
    {
        std::shared_lock lock(m_mutex);
        for (const auto& kv : m_rules) next->AddOrReplace(kv.second);
        for (const auto& g : m_globalSuppress) next->m_globalSuppress.push_back(g);
    }
    next->AddOrReplace(std::move(extra));
    return next;
}

size_t RuleStore::LoadFromDirectory(const std::filesystem::path& dir,
                                    RuleSource sourceHint) {
    if (!std::filesystem::exists(dir)) return 0;

    size_t loaded = 0;
    for (auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        const auto& p = entry.path();
        auto ext = p.extension().string();
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext != ".yaml" && ext != ".yml" && ext != ".json") continue;

        std::ifstream f(p, std::ios::binary);
        if (!f) continue;
        std::string buf((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

        PhantomRule rule;
        if (RuleParser::ParseNativeText(buf, rule)) {
            rule.sourceUri = p.string();
            if (rule.source == RuleSource::Native) rule.source = sourceHint;
            rule.importedAt = std::chrono::system_clock::now();
            AddOrReplace(std::move(rule));
            ++loaded;
        }
    }
    return loaded;
}

} // namespace Detection
} // namespace ShadowStrike
