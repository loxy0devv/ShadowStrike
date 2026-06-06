/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "RuleEngine.hpp"
#include "RuleStore.hpp"

#include <algorithm>
#include <cctype>

namespace ShadowStrike {
namespace Detection {

namespace {

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

bool icontains(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (hay.size() < needle.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                ok = false; break;
            }
        }
        if (ok) return true;
    }
    return false;
}

bool istartswith(std::string_view hay, std::string_view prefix) noexcept {
    if (hay.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(hay[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

bool iendswith(std::string_view hay, std::string_view suffix) noexcept {
    if (hay.size() < suffix.size()) return false;
    size_t off = hay.size() - suffix.size();
    for (size_t i = 0; i < suffix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(hay[off + i])) !=
            std::tolower(static_cast<unsigned char>(suffix[i])))
            return false;
    }
    return true;
}

} // anonymous namespace

// ----------------------------------------------------------------------------

RuleEngine::RuleEngine(std::shared_ptr<RuleStore> store,
                       RuleEngineConfig cfg) noexcept
    : m_store(std::move(store)), m_cfg(cfg) {}

RuleEngine::~RuleEngine() = default;

void RuleEngine::ReplaceStore(std::shared_ptr<RuleStore> newStore) noexcept {
    m_store.store(std::move(newStore));
}

RuleEngine::Stats RuleEngine::GetStats() const noexcept {
    return Stats{
        m_evaluations.load(std::memory_order_relaxed),
        m_matches.load(std::memory_order_relaxed),
        m_suppressed.load(std::memory_order_relaxed),
        m_regexHits.load(std::memory_order_relaxed),
        m_regexMisses.load(std::memory_order_relaxed),
    };
}

void RuleEngine::ResetStats() noexcept {
    m_evaluations = 0;
    m_matches = 0;
    m_suppressed = 0;
    m_regexHits = 0;
    m_regexMisses = 0;
}

const std::regex& RuleEngine::GetRegex(std::string_view pattern, bool caseInsensitive) const {
    // Strip (?i) inline flag — std::regex ECMAScript mode doesn't support it.
    // Apply icase instead, which is semantically identical.
    if (pattern.starts_with("(?i)")) {
        caseInsensitive = true;
        pattern = pattern.substr(4);
    }

    std::string key(pattern);
    key.push_back('\x1F');
    key.push_back(caseInsensitive ? 'i' : 's');

    {
        std::shared_lock<std::shared_mutex> rl(m_regexMutex);
        auto it = m_regexCache.find(key);
        if (it != m_regexCache.end()) {
            m_regexHits.fetch_add(1, std::memory_order_relaxed);
            return it->second;
        }
    }

    m_regexMisses.fetch_add(1, std::memory_order_relaxed);
    auto flags = std::regex::ECMAScript | std::regex::optimize;
    if (caseInsensitive) flags |= std::regex::icase;

    std::unique_lock<std::shared_mutex> wl(m_regexMutex);
    // Save the key string before moving it into emplace — we need it for
    // re-lookup if eviction invalidates the iterator returned by emplace.
    std::string savedKey = key;
    auto [it, inserted] = m_regexCache.emplace(
        std::move(key), std::regex(pattern.data(), pattern.size(), flags));
    if (inserted && m_regexCache.size() > m_cfg.regexCacheMax) {
        // Simple eviction: drop a few random entries — cache will refill.
        auto victim = m_regexCache.begin();
        std::advance(victim, m_regexCache.size() / 4);
        m_regexCache.erase(m_regexCache.begin(), victim);
        // 'it' may now be a dangling iterator (our entry could have been evicted).
        // Re-lookup by the saved key to get a valid reference.
        auto found = m_regexCache.find(savedKey);
        if (found != m_regexCache.end()) return found->second;
        // Entry was itself evicted (unlikely but possible) — re-insert.
        auto [it2, _] = m_regexCache.emplace(
            std::move(savedKey), std::regex(pattern.data(), pattern.size(), flags));
        return it2->second;
    }
    return it->second;  // no eviction occurred — iterator is still valid
}

// ----------------------------------------------------------------------------
// Leaf evaluation: STATIC features
// ----------------------------------------------------------------------------

bool RuleEngine::EvalLeafStatic(const FeatureLeaf& leaf,
                                const StaticFeatureBag& bag,
                                std::vector<std::string>& trace) const {
    auto check = [&](bool ok, std::string_view tag) {
        if (ok) trace.emplace_back(std::string(tag) + ":" + leaf.value);
        return ok;
    };

    switch (leaf.kind) {
        case FeatureKind::String:
            return check(bag.strings.contains(leaf.value), "string");
        case FeatureKind::Substring: {
            for (const auto& s : bag.strings)
                if (icontains(s, leaf.value)) return check(true, "substring");
            return false;
        }
        case FeatureKind::Regex: {
            const auto& re = GetRegex(leaf.value, leaf.caseInsensitive);
            for (const auto& s : bag.strings)
                if (std::regex_search(s, re)) return check(true, "regex");
            return false;
        }
        case FeatureKind::Api: {
            // capa-style API match: allow "kernel32.VirtualAlloc" or "VirtualAlloc"
            if (bag.apis.contains(leaf.value)) return check(true, "api");
            for (const auto& a : bag.apis) {
                auto dot = a.find('!');
                if (dot != std::string::npos) {
                    if (iequals(a.substr(dot + 1), leaf.value)) return check(true, "api");
                } else if (iequals(a, leaf.value)) return check(true, "api");
            }
            return false;
        }
        case FeatureKind::Mnemonic:
            return check(bag.mnemonics.contains(leaf.value), "mnemonic");
        case FeatureKind::Number:
            return check(bag.numbers.contains(leaf.number), "number");
        case FeatureKind::OperandNumber:
            return check(bag.numbers.contains(leaf.number), "operand-number");
        case FeatureKind::Bytes:
            return check(bag.bytes.contains(leaf.value), "bytes");
        case FeatureKind::Section:
            return check(bag.sections.contains(leaf.value), "section");
        case FeatureKind::Characteristic:
            return check(bag.characteristics.contains(leaf.value), "characteristic");
        case FeatureKind::Class:
            return check(bag.classes.contains(leaf.value), "class");
        case FeatureKind::Namespace:
            return check(bag.namespaces.contains(leaf.value), "namespace");
        case FeatureKind::Os:
            return check(bag.os.contains(leaf.value), "os");
        case FeatureKind::Arch:
            return check(bag.arch.contains(leaf.value), "arch");
        case FeatureKind::Format:
            return check(bag.format.contains(leaf.value), "format");

        case FeatureKind::EntropyAbove:
            return check(bag.fileEntropy > leaf.ratio, "entropy");
        case FeatureKind::ImportCountAbove:
            return check(bag.importCount > leaf.number, "import-count");
        case FeatureKind::UniqueApiCountAbove:
            return check(bag.uniqueApis > leaf.number, "unique-api-count");

        case FeatureKind::SignerEquals:
            return check(iequals(bag.signerName, leaf.value), "signer-equals");
        case FeatureKind::SignerUntrusted:
            return check(bag.signed_ == false || bag.signerName.empty(), "signer-untrusted");
        case FeatureKind::Unsigned:
            return check(!bag.signed_, "unsigned");

        case FeatureKind::Match: {
            // Look up the referenced capa rule by name and evaluate it recursively
            auto store = m_store.load();
            if (!store) return false;
            const std::string refId = "capa-" + leaf.value;
            const PhantomRule* refRule = store->Get(refId);
            if (!refRule) return false;

            // Cycle guard: if this rule is already on the call stack for this thread,
            // treat it as no-match to prevent infinite recursion / stack overflow.
            thread_local std::unordered_set<std::string> tl_matchStack;
            if (tl_matchStack.count(refId)) return false;  // cycle detected
            tl_matchStack.insert(refId);
            struct MatchGuard {
                std::string id;
                ~MatchGuard() { tl_matchStack.erase(id); }
            } guard{refId};

            std::vector<std::string> sub;
            bool result = EvalNode(refRule->logic, nullptr, &bag, sub);
            if (result) trace.insert(trace.end(), sub.begin(), sub.end());
            return result;
        }

        case FeatureKind::Offset: {
            // offset: N — check if the numeric value appears in our numbers set
            if (leaf.number != 0)
                return check(bag.numbers.contains(leaf.number), "offset");
            return false;
        }

        case FeatureKind::Property: {
            // property: — .NET property access pattern; check strings and classes
            if (!leaf.value.empty()) {
                if (bag.strings.contains(leaf.value)) return check(true, "property");
                if (bag.classes.contains(leaf.value)) return check(true, "property");
            }
            return false;
        }

        default:
            return false; // Field/runtime predicates are not evaluable here
    }
}

// ----------------------------------------------------------------------------
// Leaf evaluation: RUNTIME field predicates
// ----------------------------------------------------------------------------

bool RuleEngine::EvalLeafRuntime(const FeatureLeaf& leaf,
                                 const DetectionEvent& event,
                                 std::vector<std::string>& trace) const {
    auto fieldStr = event.fieldString(leaf.field);

    auto tagged = [&](bool ok, std::string_view tag) {
        if (ok) trace.emplace_back(std::string(tag) + ":" + leaf.field + "=" + leaf.value);
        return ok;
    };

    switch (leaf.kind) {
        case FeatureKind::FieldEquals:
            return tagged(leaf.caseInsensitive
                          ? iequals(fieldStr, leaf.value)
                          : fieldStr == leaf.value,
                          "equals");
        case FeatureKind::FieldContains:
            return tagged(leaf.caseInsensitive
                          ? icontains(fieldStr, leaf.value)
                          : fieldStr.find(leaf.value) != std::string::npos,
                          "contains");
        case FeatureKind::FieldStartsWith:
            return tagged(leaf.caseInsensitive
                          ? istartswith(fieldStr, leaf.value)
                          : fieldStr.rfind(leaf.value, 0) == 0,
                          "startswith");
        case FeatureKind::FieldEndsWith:
            return tagged(leaf.caseInsensitive
                          ? iendswith(fieldStr, leaf.value)
                          : (fieldStr.size() >= leaf.value.size() &&
                             fieldStr.compare(fieldStr.size() - leaf.value.size(),
                                              leaf.value.size(), leaf.value) == 0),
                          "endswith");
        case FeatureKind::FieldRegex: {
            const auto& re = GetRegex(leaf.value, leaf.caseInsensitive);
            return tagged(std::regex_search(fieldStr, re), "regex");
        }
        case FeatureKind::FieldIn: {
            for (const auto& v : leaf.setValues) {
                if (leaf.caseInsensitive ? iequals(fieldStr, v) : fieldStr == v)
                    return tagged(true, "in");
            }
            return false;
        }
        case FeatureKind::FieldNotIn: {
            for (const auto& v : leaf.setValues) {
                if (leaf.caseInsensitive ? iequals(fieldStr, v) : fieldStr == v)
                    return false;
            }
            return tagged(true, "not-in");
        }
        case FeatureKind::FieldGt:
            return tagged(event.fieldNumber(leaf.field) > leaf.number, "gt");
        case FeatureKind::FieldLt:
            return tagged(event.fieldNumber(leaf.field) < leaf.number, "lt");
        case FeatureKind::FieldGe:
            return tagged(event.fieldNumber(leaf.field) >= leaf.number, "ge");
        case FeatureKind::FieldLe:
            return tagged(event.fieldNumber(leaf.field) <= leaf.number, "le");
        case FeatureKind::FieldExists:
            return tagged(event.hasField(leaf.field), "exists");
        case FeatureKind::FieldMissing:
            return tagged(!event.hasField(leaf.field), "missing");
        case FeatureKind::SignerEquals:
            return tagged(iequals(event.fieldString("file.signer.subject"), leaf.value),
                          "signer-equals");
        case FeatureKind::SignerUntrusted:
            return tagged(!event.fieldBool("file.signer.trusted"), "signer-untrusted");
        case FeatureKind::Unsigned:
            return tagged(!event.fieldBool("file.signer.signed"), "unsigned");
        case FeatureKind::ChildOf:
            return tagged(iequals(event.fieldString("process.parent.name"), leaf.value),
                          "child-of");
        case FeatureKind::DescendantOf: {
            auto chain = event.fieldList("process.ancestry");
            for (const auto& a : chain)
                if (iequals(a, leaf.value)) return tagged(true, "descendant-of");
            return false;
        }
        case FeatureKind::HasMitigation:
            return tagged(event.fieldBool("process.mitigation." + leaf.value), "has-mitigation");
        case FeatureKind::LacksMitigation:
            return tagged(!event.fieldBool("process.mitigation." + leaf.value), "lacks-mitigation");

        // Static features inside a runtime evaluation: walk staticFeatures vec
        case FeatureKind::String:
        case FeatureKind::Substring:
        case FeatureKind::Api:
        case FeatureKind::Bytes:
        case FeatureKind::Characteristic:
        case FeatureKind::Section:
        case FeatureKind::Mnemonic:
        case FeatureKind::Number: {
            for (const auto& sf : event.staticFeatures) {
                if (sf.kind == leaf.kind) {
                    if (leaf.kind == FeatureKind::Number) {
                        if (sf.number == leaf.number) return tagged(true, "static-feature");
                    } else {
                        if (leaf.caseInsensitive ? iequals(sf.value, leaf.value)
                                                  : sf.value == leaf.value)
                            return tagged(true, "static-feature");
                    }
                }
            }
            return false;
        }

        case FeatureKind::Match: {
            // Look up the referenced capa rule by name and evaluate it against the event
            auto store = m_store.load();
            if (!store) return false;
            const std::string refId = "capa-" + leaf.value;
            const PhantomRule* refRule = store->Get(refId);
            if (!refRule) return false;

            // Cycle guard: if this rule is already on the call stack for this thread,
            // treat it as no-match to prevent infinite recursion / stack overflow.
            thread_local std::unordered_set<std::string> tl_matchStack;
            if (tl_matchStack.count(refId)) return false;  // cycle detected
            tl_matchStack.insert(refId);
            struct MatchGuard {
                std::string id;
                ~MatchGuard() { tl_matchStack.erase(id); }
            } guard{refId};

            std::vector<std::string> sub;
            bool result = EvalNode(refRule->logic, &event, nullptr, sub);
            if (result) trace.insert(trace.end(), sub.begin(), sub.end());
            return result;
        }

        default:
            return false;
    }
}

// ----------------------------------------------------------------------------
// Recursive node evaluation
// ----------------------------------------------------------------------------

bool RuleEngine::EvalNode(const FeatureNode& node,
                          const DetectionEvent* event,
                          const StaticFeatureBag* bag,
                          std::vector<std::string>& trace) const {
    using Op = FeatureNode::Op;

    switch (node.op) {
        case Op::Leaf: {
            if (bag != nullptr && (event == nullptr ||
                node.leaf.field.empty())) {
                // static path
                if (EvalLeafStatic(node.leaf, *bag, trace)) return true;
            }
            if (event != nullptr) {
                return EvalLeafRuntime(node.leaf, *event, trace);
            }
            return false;
        }
        case Op::And: {
            std::vector<std::string> local;
            for (const auto& c : node.children) {
                if (!EvalNode(c, event, bag, local)) return false;
            }
            trace.insert(trace.end(), local.begin(), local.end());
            return !node.children.empty();
        }
        case Op::Or: {
            for (const auto& c : node.children) {
                std::vector<std::string> local;
                if (EvalNode(c, event, bag, local)) {
                    trace.insert(trace.end(), local.begin(), local.end());
                    return true;
                }
            }
            return false;
        }
        case Op::Not: {
            if (node.children.empty()) return false;
            std::vector<std::string> discard;
            return !EvalNode(node.children.front(), event, bag, discard);
        }
        case Op::AtLeast: {
            uint32_t hit = 0;
            std::vector<std::string> local;
            for (const auto& c : node.children) {
                std::vector<std::string> sub;
                if (EvalNode(c, event, bag, sub)) {
                    ++hit;
                    local.insert(local.end(), sub.begin(), sub.end());
                }
            }
            if (hit >= node.threshold) {
                trace.insert(trace.end(), local.begin(), local.end());
                return true;
            }
            return false;
        }
        case Op::Optional: {
            if (node.children.empty()) return true;
            std::vector<std::string> sub;
            EvalNode(node.children.front(), event, bag, sub);
            trace.insert(trace.end(), sub.begin(), sub.end());
            return true;  // optional always succeeds
        }
        case Op::Sequence:
            return false; // sequence is evaluated at multi-event level
    }
    return false;
}

bool RuleEngine::EvalSequence(const std::vector<FeatureNode>& children,
                              std::chrono::milliseconds maxGap,
                              const std::vector<DetectionEvent>& events,
                              std::vector<std::string>& trace) const {
    if (children.empty() || events.empty()) return false;
    size_t i = 0;
    std::chrono::system_clock::time_point prev{};
    bool havePrev = false;
    for (const auto& step : children) {
        bool matched = false;
        while (i < events.size()) {
            const auto& e = events[i];
            if (havePrev && maxGap.count() > 0) {
                auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(
                    e.timestamp - prev);
                if (gap > maxGap) {
                    // window expired before this step matched
                    return false;
                }
            }
            std::vector<std::string> sub;
            if (EvalNode(step, &e, nullptr, sub)) {
                trace.insert(trace.end(), sub.begin(), sub.end());
                prev = e.timestamp;
                havePrev = true;
                matched = true;
                ++i;
                break;
            }
            ++i;
        }
        if (!matched) return false;
    }
    return true;
}

// ----------------------------------------------------------------------------
// Suppression
// ----------------------------------------------------------------------------

bool RuleEngine::ApplySuppression(const PhantomRule& rule,
                                  const DetectionEvent* event) const {
    if (event == nullptr) return false;
    for (const auto& s : rule.fpGuard.suppress) {
        if (s.isRegex && !s.regex.empty()) {
            const auto& re = GetRegex(s.regex, true);
            if (std::regex_search(event->fieldString(s.field), re)) return true;
        } else {
            auto val = event->fieldString(s.field);
            for (const auto& v : s.values) {
                if (iequals(val, v)) return true;
            }
        }
    }
    return false;
}

// ----------------------------------------------------------------------------
// Public evaluation entry points
// ----------------------------------------------------------------------------

std::vector<RuleMatch> RuleEngine::Evaluate(const DetectionEvent& event) const {
    m_evaluations.fetch_add(1, std::memory_order_relaxed);
    auto store = m_store.load();
    if (!store) return {};

    std::vector<RuleMatch> out;
    auto candidates = store->RulesByScope(event.scope);
    for (const auto* rule : candidates) {
        if (rule->status == RuleStatus::Deprecated) continue;
        if (rule->scope == RuleScope::Sequence || rule->scope == RuleScope::Graph) continue;

        std::vector<std::string> trace;
        if (!EvalNode(rule->logic, &event, nullptr, trace)) continue;

        RuleMatch m;
        m.rule = rule;
        m.matchedLeaves = std::move(trace);
        m.confidence = rule->baseConfidence;
        m.score = rule->weight * static_cast<float>(static_cast<int>(rule->severity) + 1);
        m.attack = rule->attack;
        m.suppressed = ApplySuppression(*rule, &event);
        if (m.suppressed) {
            rule->suppressionCount.fetch_add(1, std::memory_order_relaxed);
            m_suppressed.fetch_add(1, std::memory_order_relaxed);
        } else {
            rule->matchCount.fetch_add(1, std::memory_order_relaxed);
            m_matches.fetch_add(1, std::memory_order_relaxed);
        }
        // HuntingOnly: clamp severity contribution
        if (rule->status == RuleStatus::HuntingOnly) {
            m.score = std::min(m.score, 1.0f);
        }
        if (m.confidence < m_cfg.minConfidence) continue;
        if (m.score < m_cfg.minScore) continue;
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<RuleMatch> RuleEngine::EvaluateStatic(const StaticFeatureBag& bag,
                                                  std::string_view /*targetPath*/) const {
    m_evaluations.fetch_add(1, std::memory_order_relaxed);
    auto store = m_store.load();
    if (!store) return {};

    std::vector<RuleMatch> out;
    auto candidates = store->RulesByScope(RuleScope::Static);
    for (const auto* rule : candidates) {
        if (rule->status == RuleStatus::Deprecated) continue;

        std::vector<std::string> trace;
        if (!EvalNode(rule->logic, nullptr, &bag, trace)) continue;

        RuleMatch m;
        m.rule = rule;
        m.matchedLeaves = std::move(trace);
        m.confidence = rule->baseConfidence;
        m.score = rule->weight * static_cast<float>(static_cast<int>(rule->severity) + 1);
        m.attack = rule->attack;
        m.suppressed = false;
        rule->matchCount.fetch_add(1, std::memory_order_relaxed);
        m_matches.fetch_add(1, std::memory_order_relaxed);

        if (rule->status == RuleStatus::HuntingOnly) m.score = std::min(m.score, 1.0f);
        if (m.confidence < m_cfg.minConfidence) continue;
        if (m.score < m_cfg.minScore) continue;
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<RuleMatch> RuleEngine::EvaluateSequence(const std::vector<DetectionEvent>& events) const {
    m_evaluations.fetch_add(1, std::memory_order_relaxed);
    auto store = m_store.load();
    if (!store) return {};

    std::vector<RuleMatch> out;
    auto candidates = store->RulesByScope(RuleScope::Sequence);
    for (const auto* rule : candidates) {
        if (rule->status == RuleStatus::Deprecated) continue;
        if (rule->logic.op != FeatureNode::Op::Sequence) continue;

        std::vector<std::string> trace;
        if (!EvalSequence(rule->logic.children, rule->logic.maxGap, events, trace))
            continue;

        RuleMatch m;
        m.rule = rule;
        m.matchedLeaves = std::move(trace);
        m.confidence = rule->baseConfidence;
        m.score = rule->weight * static_cast<float>(static_cast<int>(rule->severity) + 1);
        m.attack = rule->attack;
        rule->matchCount.fetch_add(1, std::memory_order_relaxed);
        m_matches.fetch_add(1, std::memory_order_relaxed);
        out.push_back(std::move(m));
    }
    return out;
}

} // namespace Detection
} // namespace ShadowStrike
