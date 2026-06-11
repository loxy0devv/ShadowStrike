/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * StaticEngine — capa-style native static analysis in C++.
 *
 * Why not just use capa?
 *   capa is excellent but Python-bound. On large binaries (>50 MB) it can take
 *   tens of seconds, which is unacceptable as a pre-execution gate. This engine
 *   reimplements capa's *matching model* directly against the StaticFeatureBag
 *   computed from the PhantomCore PE parser + PhantomDisassembler.
 *
 *   The capa-rule corpus is preserved as-is (under rules/capa/) and converted
 *   to PhantomRule by RuleParser::ParseCapaYaml.
 *
 * What it produces:
 *   - A StaticReport with:
 *       - matched rule list (capa-namespaced, with severity & ATT&CK)
 *       - aggregate file score 0..100
 *       - prevalence indicators (signed/unsigned, signer trust, entropy, etc.)
 *       - feature bag (for fusion with runtime rule matches)
 *   - Designed to be FAST: feature extraction is single-pass; rule evaluation
 *     uses interning + hashing in StaticFeatureBag.
 *
 * Integration:
 *   The PhantomCore ScanEngine.ScanFile path calls StaticEngine::AnalyzeFile
 *   BEFORE expensive YARA / behavioral pipelines. A high-confidence verdict
 *   here can short-circuit the rest of the scan; a partial verdict feeds
 *   into the EvidenceLedger for runtime fusion.
 */

#pragma once

#include "../Rules/PhantomRule.hpp"
#include "../Rules/RuleEngine.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike {
namespace Detection {

class RuleEngine;

struct StaticReport {
    bool   isPe                = false;
    bool   isDotNet            = false;
    bool   isManaged           = false;
    bool   isSigned            = false;
    bool   signerTrusted       = false;
    bool   isPacked            = false;
    bool   isCorrupted         = false;
    std::string signerSubject;
    std::string md5;
    std::string sha256;
    std::string ssdeep;        // populated by FuzzyHasher if available

    double fileEntropy         = 0.0;
    double sectionEntropyMax   = 0.0;
    uint32_t importCount       = 0;
    uint32_t uniqueApis        = 0;
    uint32_t resourceCount     = 0;
    uint64_t fileSize          = 0;
    std::string architecture;
    std::string subsystem;

    StaticFeatureBag features;

    std::vector<RuleMatch> matches;
    std::vector<std::string> tags;          ///< short tags (packer:upx, lang:dotnet, ...)
    std::vector<AttackMapping> attack;      ///< aggregated ATT&CK from matched rules

    float aggregateScore       = 0.0f;      ///< 0..100
    float maliciousProbability = 0.0f;      ///< 0..1 (heuristic, NOT ML)
    RuleSeverity worstSeverity = RuleSeverity::Informational;

    std::chrono::milliseconds elapsed{0};
    std::vector<std::string> diagnostics;

    /// True if static-only evidence justifies treating the file as malicious.
    /// Mirrors capa's "very high" / "high" namespaces + signer/packer/entropy.
    [[nodiscard]] bool LikelyMalicious() const noexcept {
        return aggregateScore >= 75.0f || worstSeverity >= RuleSeverity::High;
    }

    /// True if there is enough static signal to escalate runtime monitoring.
    [[nodiscard]] bool Suspicious() const noexcept {
        return aggregateScore >= 40.0f;
    }
};

struct StaticEngineConfig {
    bool enableEntropy        = true;
    bool enableDisassembly    = true;     ///< if false, mnemonic/operand features are skipped
    bool enableSignatureCheck = true;
    bool enableYaraCorridor   = false;    ///< if true, additionally consult YaraRuleStore
    bool enableSsdeep         = false;    ///< populated only if FuzzyHasher present
    bool enableManagedAnalysis = true;

    uint64_t maxFileSize     = 256 * 1024 * 1024;
    uint32_t disassemblyDepth = 8 * 1024 * 1024;  ///< up to N bytes of .text disassembled
    uint32_t maxStringsPerSection = 4096;
    uint32_t minStringLen   = 5;
    std::chrono::milliseconds timeBudget{15000};  ///< hard deadline per file (was 1500 ms)
};

class StaticEngine {
public:
    explicit StaticEngine(std::shared_ptr<RuleEngine> engine,
                          StaticEngineConfig cfg = {});

    /// Analyze a file from disk. Returns false on hard I/O error;
    /// the report carries diagnostics for soft errors.
    bool AnalyzeFile(const std::filesystem::path& path, StaticReport& out);

    /// Analyze an in-memory buffer (zero-copy if possible).
    bool AnalyzeBuffer(std::span<const uint8_t> bytes,
                       std::string_view virtualPath,
                       StaticReport& out);

    void UpdateConfig(StaticEngineConfig cfg) noexcept { m_cfg = cfg; }
    [[nodiscard]] const StaticEngineConfig& Config() const noexcept { return m_cfg; }

    struct Stats {
        uint64_t analyzed      = 0;
        uint64_t errors        = 0;
        uint64_t earlyExits    = 0;
        uint64_t timeBudgetHit = 0;
        double   avgDurationMs = 0.0;
    };
    [[nodiscard]] Stats GetStats() const noexcept;
    void ResetStats() noexcept;

private:
    void ExtractCommonFeatures(std::span<const uint8_t> bytes,
                               StaticReport& out);
    void ExtractPeFeatures(std::span<const uint8_t> bytes, StaticReport& out);
    void ExtractDotNetFeatures(std::span<const uint8_t> bytes, StaticReport& out);
    void ExtractDisasmFeatures(std::span<const uint8_t> text,
                               uint64_t imageBase, StaticReport& out);
    void ComputeEntropy(std::span<const uint8_t> bytes, StaticReport& out);
    void ComputeHashes(std::span<const uint8_t> bytes, StaticReport& out);
    void DetectPackers(StaticReport& out);
    void DetectEmbeddedPE(StaticReport& out);
    void DetectDriverCharacteristics(StaticReport& out);
    void ScoreReport(StaticReport& out);
    void ApplyDescriptiveTags(StaticReport& out);

    std::shared_ptr<RuleEngine> m_engine;
    StaticEngineConfig          m_cfg;

    std::atomic<uint64_t> m_analyzed{0};
    std::atomic<uint64_t> m_errors{0};
    std::atomic<uint64_t> m_earlyExits{0};
    std::atomic<uint64_t> m_budgetHits{0};
    std::atomic<uint64_t> m_totalMicros{0};
};

} // namespace Detection
} // namespace ShadowStrike
