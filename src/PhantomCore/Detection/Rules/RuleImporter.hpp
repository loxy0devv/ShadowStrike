/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * RuleImporter — high-level façade that loads all rule corpora into a
 * RuleStore.
 *
 * Directory layout expected under the ShadowStrike install/source root:
 *
 *   rules/phantom/   — ShadowStrike native rules (loaded as RuleSource::Native)
 *   rules/capa/      — capa-rules corpus (loaded as RuleSource::Capa)
 *   rules/sigma/     — Sigma rules (loaded as RuleSource::Sigma, Windows-only)
 *   rules/elastic/   — Elastic rules (.ndjson, loaded as RuleSource::Elastic)
 *
 * Usage:
 *   auto store = RuleImporter::LoadAll("C:\\ProgramData\\ShadowStrike\\rules");
 *   auto engine = std::make_shared<RuleEngine>(store);
 */

#pragma once

#include "RuleStore.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>

namespace ShadowStrike {
namespace Detection {

struct ImportResult {
    size_t native  = 0;
    size_t capa    = 0;
    size_t sigma   = 0;
    size_t elastic = 0;
    size_t errors  = 0;
    size_t total() const noexcept { return native + capa + sigma + elastic; }
};

class RuleImporter {
public:
    /// Load all corpora from `rulesRoot` and return a populated store.
    [[nodiscard]] static std::shared_ptr<RuleStore>
    LoadAll(const std::filesystem::path& rulesRoot,
            ImportResult* result = nullptr);

    /// Load only the native phantom/ rules.
    [[nodiscard]] static size_t
    LoadNative(const std::filesystem::path& phantomDir, RuleStore& store);

    /// Load capa-rules YAML corpus.
    [[nodiscard]] static size_t
    LoadCapa(const std::filesystem::path& capaDir, RuleStore& store);

    /// Load Sigma Windows rules.
    [[nodiscard]] static size_t
    LoadSigma(const std::filesystem::path& sigmaDir, RuleStore& store);

    /// Load Elastic NDJSON rules.
    [[nodiscard]] static size_t
    LoadElastic(const std::filesystem::path& ndjsonFile, RuleStore& store);

    /// Load rules from the embedded compiled blob (preferred over disk in production).
    /// Returns 0 if no blob is embedded, allowing the caller to fall back to LoadAll.
    [[nodiscard]] static size_t
    LoadFromEmbedded(RuleStore& store, ImportResult* result = nullptr);
};

} // namespace Detection
} // namespace ShadowStrike
