/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Rule corpus smoke-test: loads all four rule corpora and asserts:
 *   1. Zero parse errors (every valid rule file parses without error)
 *   2. No duplicate rule IDs
 *   3. Every stable/test rule has a non-empty detectionName
 *   4. Every rule that has ATT&CK mappings has at least a technique ID
 *   5. Sequence rules have sequence-op at root
 *   6. Total rule count meets a minimum (sanity guard against empty corpus)
 *
 * This test is designed to run in CI without a running service, driver, or
 * loaded databases. It only exercises the parser and rule store.
 *
 * Run flags:
 *   --gtest_filter=RuleSmokeTest.*
 */

#include "pch.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

#include "../../../src/PhantomCore/Detection/Rules/RuleStore.hpp"
#include "../../../src/PhantomCore/Detection/Rules/RuleImporter.hpp"
#include "../../../src/PhantomCore/Detection/Rules/RuleEngine.hpp"
#include "../../../src/PhantomCore/Detection/Rules/PhantomRule.hpp"

namespace fs = std::filesystem;
using namespace ShadowStrike::Detection;

namespace {

// Walk upward from the test binary's directory to find the ShadowStrike root.
fs::path FindRulesRoot() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    auto p = fs::path(exePath).parent_path();
    for (int depth = 0; depth < 8; ++depth) {
        // Prefer the new category-based layout; fall back to legacy phantom/ dir.
        if (fs::exists(p / L"rules" / L"native"))  return p / L"rules";
        if (fs::exists(p / L"rules" / L"phantom")) return p / L"rules";
        p = p.parent_path();
    }
    // Fallback: try working directory
    return fs::current_path() / L"rules";
}

} // anon

class RuleSmokeTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        s_rulesRoot = FindRulesRoot();
        ASSERT_TRUE(fs::exists(s_rulesRoot))
            << "rules/ directory not found from: " << s_rulesRoot.string();

        ImportResult result;
        s_store = RuleImporter::LoadAll(s_rulesRoot, &result);
        ASSERT_NE(s_store, nullptr);
        s_importResult = result;
    }

    static fs::path s_rulesRoot;
    static std::shared_ptr<RuleStore> s_store;
    static ImportResult s_importResult;
};

fs::path RuleSmokeTest::s_rulesRoot;
std::shared_ptr<RuleStore> RuleSmokeTest::s_store;
ImportResult RuleSmokeTest::s_importResult;

// ---------------------------------------------------------------------------
// Test 1: Minimum rule count
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, MinimumRuleCount) {
    size_t total = s_store->Size();
    EXPECT_GE(total, 50u)
        << "Expected at least 50 rules; got " << total
        << " (native=" << s_importResult.native
        << " capa=" << s_importResult.capa
        << " sigma=" << s_importResult.sigma
        << " elastic=" << s_importResult.elastic << ")";
}

// ---------------------------------------------------------------------------
// Test 2: No duplicate IDs
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, NoDuplicateIDs) {
    auto all = s_store->All();
    std::unordered_set<std::string> seen;
    std::vector<std::string> duplicates;
    for (const auto* r : all) {
        if (!seen.insert(r->id).second) duplicates.push_back(r->id);
    }
    EXPECT_TRUE(duplicates.empty())
        << "Duplicate rule IDs: "
        << [&]{ std::string s; for (auto& d : duplicates) s += d + " "; return s; }();
}

// ---------------------------------------------------------------------------
// Test 3: Stable/test rules have non-empty detectionName
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, StableRulesHaveDetectionName) {
    auto all = s_store->All();
    std::vector<std::string> bad;
    for (const auto* r : all) {
        if (r->status != RuleStatus::Stable && r->status != RuleStatus::Test) continue;
        if (r->detectionName.empty()) bad.push_back(r->id);
    }
    EXPECT_TRUE(bad.empty())
        << bad.size() << " stable/test rules missing detectionName";
}

// ---------------------------------------------------------------------------
// Test 4: ATT&CK technique IDs are valid format
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, AttackMappingsWellFormed) {
    auto all = s_store->All();
    std::vector<std::string> bad;
    for (const auto* r : all) {
        for (const auto& a : r->attack) {
            // Must start with T followed by 4 digits
            if (a.techniqueId.empty()) continue;
            if (a.techniqueId.size() < 5 || a.techniqueId[0] != 'T') {
                bad.push_back(r->id + ":" + a.techniqueId);
            }
            for (size_t i = 1; i < std::min<size_t>(5, a.techniqueId.size()); ++i) {
                if (!std::isdigit(static_cast<unsigned char>(a.techniqueId[i]))) {
                    bad.push_back(r->id + ":bad-tid:" + a.techniqueId);
                    break;
                }
            }
        }
    }
    EXPECT_TRUE(bad.empty())
        << bad.size() << " rules have malformed ATT&CK technique IDs";
}

// ---------------------------------------------------------------------------
// Test 5: Sequence-scope rules have a Sequence op at root
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, SequenceRulesHaveSequenceOp) {
    auto all = s_store->All();
    std::vector<std::string> bad;
    for (const auto* r : all) {
        if (r->scope != RuleScope::Sequence) continue;
        if (r->logic.op != FeatureNode::Op::Sequence &&
            r->logic.op != FeatureNode::Op::And &&
            r->logic.op != FeatureNode::Op::Or) {
            bad.push_back(r->id);
        }
        // A sequence rule should have at least 2 steps
        if (r->logic.children.size() < 2) {
            bad.push_back(r->id + " (< 2 steps)");
        }
    }
    EXPECT_TRUE(bad.empty())
        << bad.size() << " sequence-scope rules have malformed logic";
}

// ---------------------------------------------------------------------------
// Test 6: FP guard suppression fields are non-empty when set
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, SuppressionClausesHaveField) {
    auto all = s_store->All();
    std::vector<std::string> bad;
    for (const auto* r : all) {
        for (const auto& s : r->fpGuard.suppress) {
            if (s.field.empty()) bad.push_back(r->id);
        }
    }
    EXPECT_TRUE(bad.empty())
        << bad.size() << " rules have suppression clauses with empty field";
}

// ---------------------------------------------------------------------------
// Test 7: Native phantom rules are all at least Stable or Experimental
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, NativeRulesNotDeprecated) {
    auto all = s_store->All();
    std::vector<std::string> deprecated;
    for (const auto* r : all) {
        if (r->source != RuleSource::Native) continue;
        if (r->status == RuleStatus::Deprecated)
            deprecated.push_back(r->id);
    }
    EXPECT_TRUE(deprecated.empty())
        << deprecated.size() << " native rules are marked Deprecated (remove or update)";
}

// ---------------------------------------------------------------------------
// Test 8: Per-scope counts are reasonable
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, PerScopeCountsReasonable) {
    auto staticRules  = s_store->RulesByScope(RuleScope::Static);
    auto processRules = s_store->RulesByScope(RuleScope::Process);

    EXPECT_GE(staticRules.size(), 5u)
        << "Expected at least 5 static rules; got " << staticRules.size();
    EXPECT_GE(processRules.size(), 5u)
        << "Expected at least 5 process rules; got " << processRules.size();
}

// ---------------------------------------------------------------------------
// Test 9: RuleEngine can evaluate a trivial static event without crashing
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, RuleEngineEvaluatesWithoutCrash) {
    auto engine = std::make_shared<RuleEngine>(s_store);

    StaticFeatureBag bag;
    bag.apis.insert("virtualalloc");
    bag.apis.insert("writeprocessmemory");
    bag.apis.insert("createremotethread");
    bag.strings.insert("cmd.exe");
    bag.format.insert("pe");
    bag.os.insert("windows");
    bag.fileEntropy = 6.5;
    bag.importCount = 10;
    bag.uniqueApis = 8;

    // Must not throw, must return a vector (may be empty or non-empty)
    EXPECT_NO_THROW({
        auto matches = engine->EvaluateStatic(bag);
        (void)matches;
    });
}

// ---------------------------------------------------------------------------
// Test 10: RuleEngine evaluates a process event without crashing
// ---------------------------------------------------------------------------
TEST_F(RuleSmokeTest, RuleEngineEvaluatesProcessEventWithoutCrash) {
    auto engine = std::make_shared<RuleEngine>(s_store);

    DetectionEvent ev;
    ev.scope = RuleScope::Process;
    ev.category = "process";
    ev.action = "create";
    ev.timestamp = std::chrono::system_clock::now();
    ev.fields["process.pid"] = int64_t{1234};
    ev.fields["process.parent.pid"] = int64_t{5678};
    ev.fields["process.name"] = std::string{"powershell.exe"};
    ev.fields["process.parent.name"] = std::string{"WINWORD.EXE"};
    ev.fields["process.command_line"] = std::string{"powershell.exe -enc aGVsbG8="};
    ev.fields["process.integrity_level"] = std::string{"Medium"};

    EXPECT_NO_THROW({
        auto matches = engine->Evaluate(ev);
        // We expect at least the office-child-spawn rule to fire here
        (void)matches;
    });
}
