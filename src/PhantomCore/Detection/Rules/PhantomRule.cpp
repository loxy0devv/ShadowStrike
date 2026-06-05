/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "PhantomRule.hpp"

#include <sstream>

namespace ShadowStrike {
namespace Detection {

PhantomRule::PhantomRule(const PhantomRule& other)
    : id(other.id), detectionName(other.detectionName),
      genericDescription(other.genericDescription), title(other.title),
      status(other.status), scope(other.scope), source(other.source),
      version(other.version),
      windowsOnly(other.windowsOnly), platforms(other.platforms),
      namespaces(other.namespaces),
      severity(other.severity), baseConfidence(other.baseConfidence),
      weight(other.weight),
      attack(other.attack), references(other.references), authors(other.authors),
      logic(other.logic), fpGuard(other.fpGuard),
      sourceUri(other.sourceUri), sourceId(other.sourceId),
      importedAt(other.importedAt),
      matchCount(other.matchCount.load(std::memory_order_relaxed)),
      suppressionCount(other.suppressionCount.load(std::memory_order_relaxed)),
      falsePositiveCount(other.falsePositiveCount.load(std::memory_order_relaxed)) {}

PhantomRule& PhantomRule::operator=(const PhantomRule& other) {
    if (this == &other) return *this;
    id = other.id;
    detectionName = other.detectionName;
    genericDescription = other.genericDescription;
    title = other.title;
    status = other.status;
    scope = other.scope;
    source = other.source;
    version = other.version;
    windowsOnly = other.windowsOnly;
    platforms = other.platforms;
    namespaces = other.namespaces;
    severity = other.severity;
    baseConfidence = other.baseConfidence;
    weight = other.weight;
    attack = other.attack;
    references = other.references;
    authors = other.authors;
    logic = other.logic;
    fpGuard = other.fpGuard;
    sourceUri = other.sourceUri;
    sourceId = other.sourceId;
    importedAt = other.importedAt;
    matchCount.store(other.matchCount.load(std::memory_order_relaxed));
    suppressionCount.store(other.suppressionCount.load(std::memory_order_relaxed));
    falsePositiveCount.store(other.falsePositiveCount.load(std::memory_order_relaxed));
    return *this;
}

PhantomRule::PhantomRule(PhantomRule&& other) noexcept
    : id(std::move(other.id)), detectionName(std::move(other.detectionName)),
      genericDescription(std::move(other.genericDescription)),
      title(std::move(other.title)),
      status(other.status), scope(other.scope), source(other.source),
      version(other.version),
      windowsOnly(other.windowsOnly), platforms(std::move(other.platforms)),
      namespaces(std::move(other.namespaces)),
      severity(other.severity), baseConfidence(other.baseConfidence),
      weight(other.weight),
      attack(std::move(other.attack)),
      references(std::move(other.references)),
      authors(std::move(other.authors)),
      logic(std::move(other.logic)),
      fpGuard(std::move(other.fpGuard)),
      sourceUri(std::move(other.sourceUri)),
      sourceId(std::move(other.sourceId)),
      importedAt(other.importedAt),
      matchCount(other.matchCount.load(std::memory_order_relaxed)),
      suppressionCount(other.suppressionCount.load(std::memory_order_relaxed)),
      falsePositiveCount(other.falsePositiveCount.load(std::memory_order_relaxed)) {}

PhantomRule& PhantomRule::operator=(PhantomRule&& other) noexcept {
    if (this == &other) return *this;
    id = std::move(other.id);
    detectionName = std::move(other.detectionName);
    genericDescription = std::move(other.genericDescription);
    title = std::move(other.title);
    status = other.status;
    scope = other.scope;
    source = other.source;
    version = other.version;
    windowsOnly = other.windowsOnly;
    platforms = std::move(other.platforms);
    namespaces = std::move(other.namespaces);
    severity = other.severity;
    baseConfidence = other.baseConfidence;
    weight = other.weight;
    attack = std::move(other.attack);
    references = std::move(other.references);
    authors = std::move(other.authors);
    logic = std::move(other.logic);
    fpGuard = std::move(other.fpGuard);
    sourceUri = std::move(other.sourceUri);
    sourceId = std::move(other.sourceId);
    importedAt = other.importedAt;
    matchCount.store(other.matchCount.load(std::memory_order_relaxed));
    suppressionCount.store(other.suppressionCount.load(std::memory_order_relaxed));
    falsePositiveCount.store(other.falsePositiveCount.load(std::memory_order_relaxed));
    return *this;
}

// ============================================================================
// DetectionEvent helpers
// ============================================================================

std::string DetectionEvent::fieldString(std::string_view key) const noexcept {
    auto it = fields.find(std::string(key));
    if (it == fields.end()) return {};
    if (auto* sv = std::get_if<std::string>(&it->second)) return *sv;
    if (auto* nv = std::get_if<int64_t>(&it->second)) return std::to_string(*nv);
    if (auto* dv = std::get_if<double>(&it->second)) return std::to_string(*dv);
    if (auto* bv = std::get_if<bool>(&it->second)) return *bv ? "true" : "false";
    if (auto* lv = std::get_if<std::vector<std::string>>(&it->second)) {
        if (lv->empty()) return {};
        std::string out;
        for (size_t i = 0; i < lv->size(); ++i) {
            if (i) out.push_back(',');
            out.append((*lv)[i]);
        }
        return out;
    }
    return {};
}

int64_t DetectionEvent::fieldNumber(std::string_view key) const noexcept {
    auto it = fields.find(std::string(key));
    if (it == fields.end()) return 0;
    if (auto* nv = std::get_if<int64_t>(&it->second)) return *nv;
    if (auto* dv = std::get_if<double>(&it->second)) return static_cast<int64_t>(*dv);
    if (auto* sv = std::get_if<std::string>(&it->second)) {
        try { return std::stoll(*sv); } catch (...) { return 0; }
    }
    if (auto* bv = std::get_if<bool>(&it->second)) return *bv ? 1 : 0;
    return 0;
}

bool DetectionEvent::fieldBool(std::string_view key) const noexcept {
    auto it = fields.find(std::string(key));
    if (it == fields.end()) return false;
    if (auto* bv = std::get_if<bool>(&it->second)) return *bv;
    if (auto* nv = std::get_if<int64_t>(&it->second)) return *nv != 0;
    if (auto* sv = std::get_if<std::string>(&it->second)) {
        return !sv->empty() && (*sv != "0") && (*sv != "false") && (*sv != "False");
    }
    return false;
}

bool DetectionEvent::hasField(std::string_view key) const noexcept {
    return fields.find(std::string(key)) != fields.end();
}

std::vector<std::string> DetectionEvent::fieldList(std::string_view key) const {
    auto it = fields.find(std::string(key));
    if (it == fields.end()) return {};
    if (auto* lv = std::get_if<std::vector<std::string>>(&it->second)) return *lv;
    if (auto* sv = std::get_if<std::string>(&it->second)) return {*sv};
    return {};
}

// ============================================================================
// Enum -> string
// ============================================================================

std::string ToString(RuleScope s) noexcept {
    switch (s) {
        case RuleScope::Static:   return "static";
        case RuleScope::Process:  return "process";
        case RuleScope::Image:    return "image";
        case RuleScope::Thread:   return "thread";
        case RuleScope::Memory:   return "memory";
        case RuleScope::Registry: return "registry";
        case RuleScope::File:     return "file";
        case RuleScope::Network:  return "network";
        case RuleScope::Script:   return "script";
        case RuleScope::Sequence: return "sequence";
        case RuleScope::Graph:    return "graph";
        case RuleScope::Hunting:  return "hunting";
    }
    return "unknown";
}

std::string ToString(RuleSeverity s) noexcept {
    switch (s) {
        case RuleSeverity::Informational: return "informational";
        case RuleSeverity::Low:           return "low";
        case RuleSeverity::Medium:        return "medium";
        case RuleSeverity::High:          return "high";
        case RuleSeverity::Critical:      return "critical";
    }
    return "unknown";
}

std::string ToString(RuleStatus s) noexcept {
    switch (s) {
        case RuleStatus::Experimental: return "experimental";
        case RuleStatus::Test:         return "test";
        case RuleStatus::Stable:       return "stable";
        case RuleStatus::Deprecated:   return "deprecated";
        case RuleStatus::HuntingOnly:  return "hunting-only";
    }
    return "unknown";
}

std::string ToString(RuleSource s) noexcept {
    switch (s) {
        case RuleSource::Native:  return "native";
        case RuleSource::Capa:    return "capa";
        case RuleSource::Sigma:   return "sigma";
        case RuleSource::Elastic: return "elastic";
        case RuleSource::Yara:    return "yara";
        case RuleSource::Custom:  return "custom";
    }
    return "unknown";
}

} // namespace Detection
} // namespace ShadowStrike
