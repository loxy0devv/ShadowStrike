/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * RuleParser — converts external rule formats into PhantomRule:
 *   - ShadowStrike native YAML/JSON
 *   - capa YAML rules
 *   - Sigma YAML rules (Windows logsources only)
 *   - Elastic NDJSON detection rules
 *
 * Implementation note: we don't pull in a full YAML library here.
 * The ShadowStrike repository already vendors nlohmann::json for JSON
 * parsing, and we ship a small purpose-built YAML reader sufficient
 * for capa/sigma's restricted YAML dialect (no anchors, no flow tags
 * we don't recognize, no custom !! tags). Anything we can't parse is
 * skipped with a structured error rather than crashing.
 */

#pragma once

#include "PhantomRule.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike {
namespace Detection {

struct ParseError {
    std::string message;
    int line = 0;
    int column = 0;
};

class RuleParser {
public:
    /// Parse a single ShadowStrike-native rule (YAML or JSON).
    static bool ParseNativeText(std::string_view text, PhantomRule& out,
                                ParseError* err = nullptr);

    /// Parse one capa-rules YAML document into a PhantomRule.
    static bool ParseCapaYaml(std::string_view text, PhantomRule& out,
                              ParseError* err = nullptr);

    /// Parse one Sigma YAML document into a PhantomRule.
    /// Returns false if the rule is not relevant for Windows or unsupported.
    static bool ParseSigmaYaml(std::string_view text, PhantomRule& out,
                               ParseError* err = nullptr);

    /// Parse one Elastic detection-rule JSON object into a PhantomRule.
    /// Handles a single NDJSON line.
    static bool ParseElasticJson(std::string_view text, PhantomRule& out,
                                 ParseError* err = nullptr);

    /// Returns true if the rule should be windows-only / windows-relevant
    /// based on its logsource / product / index. Used by SigmaImporter.
    static bool IsWindowsRelevant(std::string_view sigmaText);
};

} // namespace Detection
} // namespace ShadowStrike
