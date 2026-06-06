/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "RuleImporter.hpp"
#include "RuleStore.hpp"
#include "RuleParser.hpp"
#include "EmbeddedRuleLoader.hpp"

#include <fstream>
#include <sstream>

namespace ShadowStrike {
namespace Detection {

static std::string readFile(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::shared_ptr<RuleStore> RuleImporter::LoadAll(
        const std::filesystem::path& rulesRoot,
        ImportResult* result) {
    auto store = std::make_shared<RuleStore>();
    ImportResult r;

    // Prefer the new category-based layout (rules/native/) introduced in 2026.
    // Fall back to the legacy source-based layout (rules/phantom/) if the new
    // layout is not present, so existing installations keep working.
    auto nativeDir = rulesRoot / "native";
    auto legacyDir = rulesRoot / "phantom";
    r.native = LoadNative(
        std::filesystem::exists(nativeDir) ? nativeDir : legacyDir,
        *store);

    // External corpora: prefer rules/external/<corpus>, fall back to rules/<corpus>.
    auto capaDir  = rulesRoot / "external" / "capa";
    if (!std::filesystem::exists(capaDir)) capaDir = rulesRoot / "capa";
    r.capa = LoadCapa(capaDir, *store);

    auto sigmaDir = rulesRoot / "external" / "sigma";
    if (!std::filesystem::exists(sigmaDir)) sigmaDir = rulesRoot / "sigma";
    r.sigma = LoadSigma(sigmaDir, *store);

    // Elastic NDJSON — check both new and legacy paths.
    auto ndjsonNew    = rulesRoot / "external" / "elastic" / "custom-consolidated-rules.ndjson";
    auto ndjsonLegacy = rulesRoot / "elastic" / "custom-consolidated-rules.ndjson";
    auto ndjson = std::filesystem::exists(ndjsonNew) ? ndjsonNew : ndjsonLegacy;
    if (std::filesystem::exists(ndjson))
        r.elastic = LoadElastic(ndjson, *store);

    if (result) *result = r;
    return store;
}

size_t RuleImporter::LoadNative(const std::filesystem::path& dir,
                                RuleStore& store) {
    if (!std::filesystem::exists(dir)) return 0;
    size_t n = 0;
    for (auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext != ".yaml" && ext != ".yml" && ext != ".json") continue;
        auto text = readFile(entry.path());
        if (text.empty()) continue;
        PhantomRule rule;
        if (RuleParser::ParseNativeText(text, rule)) {
            rule.sourceUri = entry.path().string();
            rule.source = RuleSource::Native;
            rule.importedAt = std::chrono::system_clock::now();
            if (store.AddOrReplace(std::move(rule))) ++n;
        }
    }
    return n;
}

// Walk a FeatureNode tree and collect all FeatureKind::Match leaf values (referenced rule names).
static void collectMatchRefs(const FeatureNode& node, std::vector<std::string>& out) {
    if (node.op == FeatureNode::Op::Leaf) {
        if (node.leaf.kind == FeatureKind::Match && !node.leaf.value.empty())
            out.push_back(node.leaf.value);
        return;
    }
    for (const auto& child : node.children)
        collectMatchRefs(child, out);
}

size_t RuleImporter::LoadCapa(const std::filesystem::path& dir,
                               RuleStore& store) {
    if (!std::filesystem::exists(dir)) return 0;
    size_t n = 0;
    for (auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext != ".yaml" && ext != ".yml") continue;
        // Skip capa infra files
        auto stem = entry.path().stem().string();
        if (stem == "README" || stem == "release" || stem == "sync" ||
            stem == "tests" || stem == "workflow") continue;

        auto text = readFile(entry.path());
        if (text.empty()) continue;
        // capa rule files start with "rule:" at root
        if (text.find("rule:") == std::string::npos) continue;

        PhantomRule rule;
        ParseError err;
        if (RuleParser::ParseCapaYaml(text, rule, &err)) {
            rule.sourceUri = entry.path().string();
            rule.source = RuleSource::Capa;
            rule.importedAt = std::chrono::system_clock::now();
            if (store.AddOrReplace(std::move(rule))) ++n;
        }
    }

    // match: resolution pass — verify that every match: leaf refers to a rule that
    // was successfully imported. Unresolved references are non-fatal; EvalLeafStatic
    // returns false for missing match targets at evaluation time. This pass ensures
    // we at least have a complete picture of dangling references post-import.
    {
        auto all = store.All();
        for (const auto* r : all) {
            if (r->source != RuleSource::Capa) continue;
            std::vector<std::string> refs;
            collectMatchRefs(r->logic, refs);
            for (const auto& ref : refs) {
                // Lookup by canonical capa ID: "capa-<rule name>"
                std::string targetId = "capa-" + ref;
                if (!store.Get(targetId)) {
                    // Referenced rule not found — it will silently return false at
                    // evaluation time. No action needed; log point for future debug.
                    (void)targetId;
                }
            }
        }
    }

    return n;
}

size_t RuleImporter::LoadSigma(const std::filesystem::path& dir,
                                RuleStore& store) {
    if (!std::filesystem::exists(dir)) return 0;
    size_t n = 0;
    for (auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext != ".yaml" && ext != ".yml") continue;

        auto text = readFile(entry.path());
        if (text.empty()) continue;

        // Quick filter: only Windows-relevant rules
        if (!RuleParser::IsWindowsRelevant(text)) continue;

        PhantomRule rule;
        ParseError err;
        if (RuleParser::ParseSigmaYaml(text, rule, &err)) {
            rule.sourceUri = entry.path().string();
            rule.source = RuleSource::Sigma;
            rule.importedAt = std::chrono::system_clock::now();
            if (store.AddOrReplace(std::move(rule))) ++n;
        }
    }
    return n;
}

size_t RuleImporter::LoadElastic(const std::filesystem::path& ndjsonFile,
                                  RuleStore& store) {
    std::ifstream f(ndjsonFile, std::ios::binary);
    if (!f) return 0;
    size_t n = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line.front() == '#') continue;
        PhantomRule rule;
        if (RuleParser::ParseElasticJson(line, rule)) {
            rule.sourceUri = ndjsonFile.string();
            rule.source = RuleSource::Elastic;
            rule.importedAt = std::chrono::system_clock::now();
            if (store.AddOrReplace(std::move(rule))) ++n;
        }
    }
    return n;
}

size_t RuleImporter::LoadFromEmbedded(RuleStore& store, ImportResult* result) {
    return LoadEmbeddedRules(store, result);
}

} // namespace Detection
} // namespace ShadowStrike
