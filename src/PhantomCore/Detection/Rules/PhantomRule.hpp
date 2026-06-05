/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Native ShadowStrike rule format and runtime representation.
 *
 * A PhantomRule is the unified rule object used by all detection stages:
 *  - Static (pre-execution) rules ported from capa
 *  - Sigma-derived runtime detection rules (Windows-only)
 *  - Elastic-derived runtime detection rules
 *  - Hand-written ShadowStrike native rules
 *
 * Design goals:
 *  - One in-memory representation for every rule, regardless of origin.
 *  - Single matching engine (RuleEngine) can evaluate any rule.
 *  - Carries provenance, severity, confidence, FP notes, ATT&CK mapping,
 *    and lifecycle state (experimental / stable / deprecated / hunting).
 *  - Supports single-event, sequence, and correlation predicates.
 *  - Cheap to copy (PIMPL avoided; rule objects are POD-ish).
 *  - Designed for hot-reload — RuleStore can swap pointers atomically.
 */

#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

namespace ShadowStrike {
namespace Detection {

// ============================================================================
// IDENTIFICATION & METADATA
// ============================================================================

enum class RuleScope : uint8_t {
    Static,         ///< Evaluated against a file / PE before execution
    Process,        ///< Evaluated against process creation event
    Image,          ///< Evaluated against image (DLL/EXE) load event
    Thread,         ///< Evaluated against thread creation / hijack event
    Memory,         ///< Evaluated against VAD / memory protection changes
    Registry,       ///< Evaluated against registry write/rename
    File,           ///< Evaluated against file create/write/rename
    Network,        ///< Evaluated against flow / DNS event
    Script,         ///< Evaluated against AMSI / script content
    Sequence,       ///< Evaluated against a sequence of events
    Graph,          ///< Evaluated against a multi-process subgraph
    Hunting         ///< Hunting-only — never raises a verdict, just enrichment
};

enum class RuleSeverity : uint8_t {
    Informational = 0,
    Low           = 1,
    Medium        = 2,
    High          = 3,
    Critical      = 4
};

enum class RuleStatus : uint8_t {
    Experimental, ///< Under evaluation, only logs
    Test,         ///< Test mode — surfaces but doesn't block
    Stable,       ///< Stable production rule
    Deprecated,   ///< Kept for history; not evaluated
    HuntingOnly   ///< Evaluated but never raises an alert above Informational
};

enum class RuleSource : uint8_t {
    Native,   ///< Hand-written ShadowStrike rule
    Capa,     ///< Imported from capa-rules
    Sigma,    ///< Imported from Sigma corpus
    Elastic,  ///< Imported from Elastic detection-rules
    Yara,     ///< Wrapped YARA rule
    Custom    ///< User-supplied custom rule
};

struct AttackMapping {
    std::string tacticId;        // e.g. "TA0005"
    std::string techniqueId;     // e.g. "T1055"
    std::string subTechniqueId;  // e.g. "T1055.012" (optional)
    std::string name;            // human-readable name (optional)
};

struct RuleAuthor {
    std::string name;
    std::string handle;          // e.g. github handle / email
};

struct RuleReference {
    std::string title;
    std::string url;
};

// ============================================================================
// FEATURE EXPRESSIONS
// ============================================================================
//
// A feature is a single observable fact about an event or a file:
//   - String literal or regex match
//   - API/import reference
//   - Mnemonic / opcode reference (static)
//   - Number/constant
//   - Bytes pattern (hex)
//   - Section / segment characteristic
//   - Field equality on a structured event (registry path, process name, etc)
//
// Features compose into a boolean tree via FeatureNode.

enum class FeatureKind : uint16_t {
    // -- Static (capa-style) ------------------------------------------------
    String,            ///< Literal string
    Regex,             ///< Regex string match
    Substring,         ///< Substring match
    Api,               ///< Imported API / call target
    Mnemonic,          ///< x86/x64 mnemonic appears in scope
    Number,            ///< Numeric immediate appears in scope
    Bytes,             ///< Hex byte sequence
    Section,           ///< PE section name (".text", ".rsrc", etc)
    Characteristic,    ///< Generic PE characteristic (e.g. "has-tls", "nx", "high-entropy")
    Class,             ///< C++/.NET class reference
    Namespace,         ///< .NET namespace reference
    Offset,            ///< Offset / structure access (for type-aware scopes)
    OperandNumber,     ///< Number used as instruction operand
    Property,          ///< Generic key/value property
    Os,                ///< OS marker — capa "windows" etc.
    Arch,              ///< Architecture marker — "i386", "amd64"
    Format,            ///< File format — "pe", "elf"

    // -- Dynamic / runtime --------------------------------------------------
    FieldEquals,       ///< Field == value (e.g. process.name == "powershell.exe")
    FieldContains,     ///< Field contains substring
    FieldRegex,        ///< Field matches regex
    FieldStartsWith,
    FieldEndsWith,
    FieldIn,           ///< Field value is in set
    FieldNotIn,
    FieldGt,
    FieldLt,
    FieldGe,
    FieldLe,
    FieldExists,
    FieldMissing,

    // -- Higher-order -------------------------------------------------------
    SignerEquals,      ///< Authenticode signer == value
    SignerUntrusted,   ///< Authenticode signer not in trusted set
    Unsigned,          ///< Binary not signed
    EntropyAbove,      ///< file/section entropy above threshold
    ImportCountAbove,
    UniqueApiCountAbove,
    ChildOf,           ///< current event's parent == value
    DescendantOf,      ///< current event in descendant chain of value
    OccurredWithin,    ///< previous event within N ms in same process tree
    HasMitigation,     ///< process has DEP/CFG/CET/ACG enabled
    LacksMitigation,
    Match,             ///< References another rule by name (capa match: feature)
    Custom             ///< user-defined opcode handled by RuleEngine extension
};

struct FeatureLeaf {
    FeatureKind kind = FeatureKind::String;
    std::string field;        ///< event field for runtime features (empty for static)
    std::string value;        ///< primary string value
    int64_t     number = 0;   ///< primary numeric value
    double      ratio  = 0.0; ///< primary fractional value (entropy, etc.)
    std::vector<std::string> setValues; ///< for FieldIn / FieldNotIn
    bool caseInsensitive = false;
    std::string description;  ///< analyst-facing hint (kept generic)
};

struct FeatureNode {
    enum class Op : uint8_t {
        Leaf,
        And,
        Or,
        Not,
        AtLeast,          ///< N or more of children match
        Optional,         ///< wraps a node — matching is allowed to be absent
        Sequence          ///< ordered children for sequence rules
    } op = Op::Leaf;

    // For Op::Leaf — the leaf condition
    FeatureLeaf leaf{};

    // For non-leaf — children
    std::vector<FeatureNode> children;

    // For Op::AtLeast — minimum number of matching children
    uint32_t threshold = 0;

    // For Op::Sequence — max allowed gap between adjacent events (0 = ignore)
    std::chrono::milliseconds maxGap{0};
};

// ============================================================================
// SUPPRESSION & FP CONTROL
// ============================================================================

struct SuppressionClause {
    std::string field;                ///< event field
    std::vector<std::string> values;  ///< value list (exact, case-insensitive)
    std::string regex;                ///< or regex
    bool isRegex = false;
};

struct FalsePositiveGuard {
    std::vector<std::string> notes;          ///< analyst-readable FP scenarios
    std::vector<SuppressionClause> suppress; ///< structured suppression conditions
};

// ============================================================================
// THE RULE OBJECT
// ============================================================================

struct PhantomRule {
    // -- Identity -----------------------------------------------------------
    std::string id;                  ///< canonical id, e.g. "ss-proc-001"
    std::string detectionName;       ///< short AV-style name, e.g. "Win32/Injection.Behavior"
    std::string genericDescription;  ///< concise generic description (NOT a tutorial)
    std::string title;               ///< human title (kept for provenance)

    // -- Lifecycle ----------------------------------------------------------
    RuleStatus status   = RuleStatus::Experimental;
    RuleScope  scope    = RuleScope::Static;
    RuleSource source   = RuleSource::Native;
    uint32_t   version  = 1;

    // -- Targeting ----------------------------------------------------------
    bool windowsOnly = true;          ///< ShadowStrike is Windows-only
    std::unordered_set<std::string> platforms{"windows"};
    std::vector<std::string> namespaces; ///< capa-style namespace path

    // -- Severity & confidence ---------------------------------------------
    RuleSeverity severity      = RuleSeverity::Low;
    float        baseConfidence = 0.5f;   ///< 0.0 – 1.0 base confidence on match
    float        weight         = 1.0f;   ///< contribution weight to evidence ledger

    // -- ATT&CK & references -----------------------------------------------
    std::vector<AttackMapping>  attack;
    std::vector<RuleReference>  references;
    std::vector<RuleAuthor>     authors;

    // -- The actual logic --------------------------------------------------
    FeatureNode logic;

    // -- FP control --------------------------------------------------------
    FalsePositiveGuard fpGuard;

    // -- Provenance --------------------------------------------------------
    std::string  sourceUri;                  ///< original file (capa / sigma / elastic)
    std::string  sourceId;                   ///< original rule id if available
    std::chrono:: system_clock::time_point importedAt{};

    // -- Telemetry ---------------------------------------------------------
    mutable std::atomic<uint64_t> matchCount{0};
    mutable std::atomic<uint64_t> suppressionCount{0};
    mutable std::atomic<uint64_t> falsePositiveCount{0};

    PhantomRule() = default;
    PhantomRule(const PhantomRule& other);
    PhantomRule& operator=(const PhantomRule& other);
    PhantomRule(PhantomRule&&) noexcept;
    PhantomRule& operator=(PhantomRule&&) noexcept;
};

// ============================================================================
// EVENT MODEL (the input to the rule engine)
// ============================================================================
//
// A single in-memory event is a key/value bag. The keys are dotted ECS-style
// names so Sigma and Elastic rules can be ported without bespoke field maps.

using EventValue = std::variant<std::monostate,
                                int64_t,
                                double,
                                bool,
                                std::string,
                                std::vector<std::string>>;

struct DetectionEvent {
    std::chrono::system_clock::time_point timestamp{};
    RuleScope scope = RuleScope::Process;
    std::string category;                          ///< coarse category ("process", "file", ...)
    std::string action;                            ///< fine-grained action ("create", "write")
    std::unordered_map<std::string, EventValue> fields;

    // Optional static-analysis features attached for fusion
    std::vector<FeatureLeaf> staticFeatures;

    [[nodiscard]] std::string fieldString(std::string_view key) const noexcept;
    [[nodiscard]] int64_t     fieldNumber(std::string_view key) const noexcept;
    [[nodiscard]] bool        fieldBool(std::string_view key) const noexcept;
    [[nodiscard]] bool        hasField(std::string_view key) const noexcept;
    [[nodiscard]] std::vector<std::string> fieldList(std::string_view key) const;
};

// ============================================================================
// MATCH RESULT
// ============================================================================

struct RuleMatch {
    const PhantomRule* rule = nullptr;
    float    confidence = 0.0f;      ///< computed confidence after suppression/context
    float    score      = 0.0f;      ///< score contribution to evidence ledger
    bool     suppressed = false;     ///< suppressed by FP guard
    std::vector<std::string> matchedLeaves;  ///< leaf descriptions, for analyst trace
    std::vector<AttackMapping> attack;       ///< copy-out for downstream
};

[[nodiscard]] std::string ToString(RuleScope s) noexcept;
[[nodiscard]] std::string ToString(RuleSeverity s) noexcept;
[[nodiscard]] std::string ToString(RuleStatus s) noexcept;
[[nodiscard]] std::string ToString(RuleSource s) noexcept;

} // namespace Detection
} // namespace ShadowStrike
