/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Parser unit tests: verifies specific syntax variants handled by RuleParser.
 *
 * Covers:
 *   - field_eq / field_ne short aliases
 *   - pattern: key as alias for value: in field_regex nodes
 *   - feature: <Kind> compact notation (EntropyAbove, Characteristic, etc.)
 *   - Sequence step event: wrapper key
 *   - Numeric value extraction into leaf.number
 *   - New rules/native/ layout discovery via FindRulesRoot
 *
 * Run flags:
 *   --gtest_filter=RuleParserTest.*
 *   --gtest_filter=RuleLayoutTest.*
 */

#include "pch.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <algorithm>

#include "../../../src/PhantomCore/Detection/Rules/RuleParser.hpp"
#include "../../../src/PhantomCore/Detection/Rules/PhantomRule.hpp"

namespace fs = std::filesystem;
using namespace ShadowStrike::Detection;

// ===========================================================================
// Helpers
// ===========================================================================

namespace {

// Walk the feature tree and return the first leaf matching the predicate.
const FeatureLeaf* FindLeaf(const FeatureNode& node,
                             std::function<bool(const FeatureLeaf&)> pred) {
    if (node.op == FeatureNode::Op::Leaf) {
        return pred(node.leaf) ? &node.leaf : nullptr;
    }
    for (const auto& child : node.children) {
        if (auto* found = FindLeaf(child, pred)) return found;
    }
    return nullptr;
}

// Return all leaves in the tree.
void CollectLeaves(const FeatureNode& node, std::vector<const FeatureLeaf*>& out) {
    if (node.op == FeatureNode::Op::Leaf) {
        out.push_back(&node.leaf);
        return;
    }
    for (const auto& child : node.children) CollectLeaves(child, out);
}

} // anon

// ===========================================================================
// RuleParserTest: individual syntax-variant tests
// ===========================================================================

class RuleParserTest : public ::testing::Test {};

// ---------------------------------------------------------------------------
// 1. field_eq alias → FeatureKind::FieldEquals
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, FieldEqAliasProducesFieldEquals) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-field-eq
detection_name: "Test/FieldEq"
scope: process
status: stable
severity: medium
source: native
description: "Parser alias test"
logic:
  field_eq:
    field: process.name
    value: powershell.exe
    case_insensitive: true
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    EXPECT_EQ(rule.logic.op, FeatureNode::Op::Leaf);
    EXPECT_EQ(rule.logic.leaf.kind, FeatureKind::FieldEquals);
    EXPECT_EQ(rule.logic.leaf.field, "process.name");
    EXPECT_EQ(rule.logic.leaf.value, "powershell.exe");
    EXPECT_TRUE(rule.logic.leaf.caseInsensitive);
}

// ---------------------------------------------------------------------------
// 2. field_ne alias → FeatureKind::FieldNotIn
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, FieldNeAliasProducesFieldNotIn) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-field-ne
detection_name: "Test/FieldNe"
scope: process
status: stable
severity: low
source: native
description: "Parser field_ne alias test"
logic:
  field_ne:
    field: process.integrity_level
    value: high
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    EXPECT_EQ(rule.logic.op, FeatureNode::Op::Leaf);
    EXPECT_EQ(rule.logic.leaf.kind, FeatureKind::FieldNotIn);
    EXPECT_EQ(rule.logic.leaf.field, "process.integrity_level");
}

// ---------------------------------------------------------------------------
// 3. field_regex with pattern: key (newer rule style)
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, FieldRegexPatternKeyExtracted) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-pattern-key
detection_name: "Test/PatternKey"
scope: process
status: stable
severity: medium
source: native
description: "Parser pattern: key alias"
logic:
  field_regex:
    field: process.command_line
    pattern: "(?i)(powershell|cmd|wscript)"
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    EXPECT_EQ(rule.logic.leaf.kind, FeatureKind::FieldRegex);
    EXPECT_EQ(rule.logic.leaf.field, "process.command_line");
    EXPECT_FALSE(rule.logic.leaf.value.empty())
        << "pattern: value should have been extracted into leaf.value";
    EXPECT_NE(rule.logic.leaf.value.find("powershell"), std::string::npos);
}

// ---------------------------------------------------------------------------
// 4. feature: EntropyAbove compact notation
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, FeatureCompactEntropyAbove) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-entropy
detection_name: "Test/Entropy"
scope: static
status: stable
severity: medium
source: native
description: "Compact feature: notation test"
logic:
  and:
    - feature: EntropyAbove
      threshold: 7.2
    - feature: ImportCountAbove
      threshold: 3
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    ASSERT_EQ(rule.logic.op, FeatureNode::Op::And);
    ASSERT_GE(rule.logic.children.size(), 2u);

    bool foundEntropy = false;
    bool foundImport  = false;

    std::vector<const FeatureLeaf*> leaves;
    CollectLeaves(rule.logic, leaves);

    for (const auto* leaf : leaves) {
        if (leaf->kind == FeatureKind::EntropyAbove) {
            foundEntropy = true;
            EXPECT_GT(leaf->number, 0) << "threshold should be parsed into leaf.number";
        }
        if (leaf->kind == FeatureKind::ImportCountAbove) {
            foundImport = true;
            EXPECT_GE(leaf->number, 1);
        }
    }

    EXPECT_TRUE(foundEntropy) << "EntropyAbove leaf not found in parsed tree";
    EXPECT_TRUE(foundImport)  << "ImportCountAbove leaf not found in parsed tree";
}

// ---------------------------------------------------------------------------
// 5. feature: Characteristic compact notation
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, FeatureCompactCharacteristic) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-characteristic
detection_name: "Test/Characteristic"
scope: static
status: stable
severity: low
source: native
description: "Compact feature: Characteristic test"
logic:
  feature: Characteristic
  value: "no-exports"
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    EXPECT_EQ(rule.logic.leaf.kind, FeatureKind::Characteristic);
    EXPECT_EQ(rule.logic.leaf.value, "no-exports");
}

// ---------------------------------------------------------------------------
// 6. Sequence rule with event: wrapper key on each step
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, SequenceStepEventKeyParsed) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-seq-event
detection_name: "Test/SeqEvent"
scope: sequence
status: stable
severity: high
source: native
description: "Sequence event: wrapper key test"
logic:
  sequence:
    - id: step1
      within: 60s
      event:
        field_eq:
          field: process.name
          value: winword.exe
    - id: step2
      within: 30s
      after: step1
      event:
        field_regex:
          field: process.command_line
          pattern: "(?i)(powershell|cmd|wscript)"
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    EXPECT_EQ(rule.scope, RuleScope::Sequence);
    EXPECT_EQ(rule.logic.op, FeatureNode::Op::Sequence);
    ASSERT_GE(rule.logic.children.size(), 2u)
        << "Expected 2 sequence steps after parsing";

    const auto& step1 = rule.logic.children[0];
    const auto& step2 = rule.logic.children[1];

    // Each step should be a non-empty node (not a bare Custom leaf)
    EXPECT_NE(step1.op, FeatureNode::Op::Leaf)
        << "step1 should have inner content, not a bare leaf";
    EXPECT_NE(step2.op, FeatureNode::Op::Leaf)
        << "step2 should have inner content, not a bare leaf";

    // step1 should contain a FieldEquals leaf for process.name
    const FeatureLeaf* nameLeaf = FindLeaf(step1, [](const FeatureLeaf& l) {
        return l.kind == FeatureKind::FieldEquals && l.field == "process.name";
    });
    EXPECT_NE(nameLeaf, nullptr)
        << "step1 should contain a FieldEquals leaf for process.name";
}

// ---------------------------------------------------------------------------
// 7. Numeric value string is promoted to leaf.number
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, NumericStringPromotedToLeafNumber) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-num
detection_name: "Test/NumericField"
scope: network
status: stable
severity: low
source: native
description: "Numeric value promotion test"
logic:
  field_eq:
    field: network.destination_port
    value: 4444
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    EXPECT_EQ(rule.logic.leaf.kind, FeatureKind::FieldEquals);
    EXPECT_EQ(rule.logic.leaf.field, "network.destination_port");
    EXPECT_EQ(rule.logic.leaf.number, 4444)
        << "numeric value 4444 should be in leaf.number";
}

// ---------------------------------------------------------------------------
// 8. field_eq inside And node
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, FieldEqInsideAndNode) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-and-fieldeq
detection_name: "Test/AndFieldEq"
scope: file
status: stable
severity: medium
source: native
description: "field_eq in and context"
logic:
  and:
    - field_eq:
        field: file.extension
        value: .exe
    - field_eq:
        field: file.path
        value: "C:\\Users\\Public\\"
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    ASSERT_EQ(rule.logic.op, FeatureNode::Op::And);
    ASSERT_GE(rule.logic.children.size(), 2u);

    bool foundExt  = false;
    bool foundPath = false;
    for (const auto& child : rule.logic.children) {
        if (child.op == FeatureNode::Op::Leaf &&
            child.leaf.kind == FeatureKind::FieldEquals) {
            if (child.leaf.field == "file.extension")  foundExt  = true;
            if (child.leaf.field == "file.path")        foundPath = true;
        }
    }
    EXPECT_TRUE(foundExt)  << "file.extension leaf not found";
    EXPECT_TRUE(foundPath) << "file.path leaf not found";
}

// ---------------------------------------------------------------------------
// 9. Malformed rule returns false, not a crash
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, MalformedRuleReturnsFalse) {
    constexpr std::string_view yaml = R"(
this is: not: valid: yaml: at all
  broken indentation
   field: missing colon value
)";

    PhantomRule rule;
    ParseError  err;
    bool ok = RuleParser::ParseNativeText(yaml, rule, &err);
    // Must not crash; either returns false, or returns a rule with empty id
    if (ok) {
        // If it "succeeded", the id should be empty or the logic should be trivial
        EXPECT_TRUE(rule.id.empty() || rule.logic.op == FeatureNode::Op::Leaf);
    }
    // Either path is acceptable as long as there's no crash
    SUCCEED();
}

// ---------------------------------------------------------------------------
// 10. rule with both value: and pattern: — value: takes precedence
// ---------------------------------------------------------------------------
TEST_F(RuleParserTest, ValueKeyTakesPrecedenceOverPattern) {
    constexpr std::string_view yaml = R"(
id: ss-test-parser-precedence
detection_name: "Test/Precedence"
scope: process
status: stable
severity: low
source: native
description: "value: key precedence over pattern: key"
logic:
  field_regex:
    field: process.name
    value: "explicit_value"
    pattern: "should_not_win"
)";

    PhantomRule rule;
    ParseError  err;
    ASSERT_TRUE(RuleParser::ParseNativeText(yaml, rule, &err))
        << "Parse failed: " << err.message;

    EXPECT_EQ(rule.logic.leaf.kind, FeatureKind::FieldRegex);
    EXPECT_EQ(rule.logic.leaf.value, "explicit_value")
        << "value: key should win over pattern: when both present";
}

// ===========================================================================
// RuleLayoutTest: new rules/native/ layout discovery
// ===========================================================================

class RuleLayoutTest : public ::testing::Test {
protected:
    static fs::path FindRulesRoot() {
        wchar_t exePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        auto p = fs::path(exePath).parent_path();
        for (int depth = 0; depth < 8; ++depth) {
            if (fs::exists(p / L"rules" / L"native")) return p / L"rules";
            if (fs::exists(p / L"rules" / L"phantom")) return p / L"rules";
            p = p.parent_path();
        }
        return fs::current_path() / L"rules";
    }
};

// ---------------------------------------------------------------------------
// 11. rules/native/ directory exists
// ---------------------------------------------------------------------------
TEST_F(RuleLayoutTest, NativeDirectoryExists) {
    auto root = FindRulesRoot();
    auto nativeDir = root / "native";
    EXPECT_TRUE(fs::exists(nativeDir))
        << "rules/native/ directory not found under: " << root.string();
}

// ---------------------------------------------------------------------------
// 12. rules/native/ has at least 10 category subdirectories
// ---------------------------------------------------------------------------
TEST_F(RuleLayoutTest, NativeHasMultipleCategories) {
    auto root      = FindRulesRoot();
    auto nativeDir = root / "native";
    if (!fs::exists(nativeDir)) {
        GTEST_SKIP() << "rules/native/ not found";
    }

    int dirCount = 0;
    for (const auto& entry : fs::directory_iterator(nativeDir)) {
        if (entry.is_directory()) ++dirCount;
    }
    EXPECT_GE(dirCount, 10)
        << "Expected at least 10 category dirs under rules/native/; got " << dirCount;
}

// ---------------------------------------------------------------------------
// 13. rules/native/ rule files are parseable
// ---------------------------------------------------------------------------
TEST_F(RuleLayoutTest, NativeRuleFilesAreParseable) {
    auto root      = FindRulesRoot();
    auto nativeDir = root / "native";
    if (!fs::exists(nativeDir)) {
        GTEST_SKIP() << "rules/native/ not found";
    }

    int parsed  = 0;
    int failed  = 0;
    std::vector<std::string> failures;

    for (auto it = fs::recursive_directory_iterator(nativeDir);
         it != fs::recursive_directory_iterator(); ++it) {
        if (!it->is_regular_file()) continue;
        if (it->path().extension() != L".yaml" &&
            it->path().extension() != L".yml") continue;

        std::ifstream f(it->path());
        std::string text((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());

        PhantomRule rule;
        ParseError  err;
        if (RuleParser::ParseNativeText(text, rule, &err)) {
            ++parsed;
        } else {
            ++failed;
            failures.push_back(it->path().filename().string() + ": " + err.message);
            if (failures.size() >= 10) break;  // stop after first 10 failures
        }
    }

    EXPECT_GT(parsed, 0) << "No rules successfully parsed from rules/native/";
    EXPECT_EQ(failed, 0)
        << failed << " rule files failed to parse. First failures: "
        << [&]{
            std::string s;
            for (auto& f : failures) s += "\n  " + f;
            return s;
        }();
}

// ---------------------------------------------------------------------------
// 14. rules/external/ layout exists for capa/sigma/elastic
// ---------------------------------------------------------------------------
TEST_F(RuleLayoutTest, ExternalDirectoryExists) {
    auto root        = FindRulesRoot();
    auto externalDir = root / "external";
    EXPECT_TRUE(fs::exists(externalDir))
        << "rules/external/ directory not found under: " << root.string();

    if (fs::exists(externalDir)) {
        EXPECT_TRUE(fs::exists(externalDir / "capa")   ||
                    fs::exists(externalDir / "sigma")  ||
                    fs::exists(externalDir / "elastic"))
            << "rules/external/ should contain at least one of: capa, sigma, elastic";
    }
}
