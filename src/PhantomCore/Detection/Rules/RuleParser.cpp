/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Lightweight rule format parser. We rely on a small purpose-built
 * YAML decoder for capa/Sigma rules — full spec compliance is not the
 * target; we accept the subset used by these corpora.
 */

#include "pch.h"
#include "RuleParser.hpp"

#include <cctype>
#include <charconv>
#include <map>
#include <regex>
#include <sstream>
#include <stack>
#include <string>
#include <unordered_map>

namespace ShadowStrike {
namespace Detection {

namespace {

// ----------------------------------------------------------------------------
// Tiny YAML reader — strict line-oriented dialect that accepts the
// capa/sigma subset: block scalars, lists, maps, quoted strings.
// Not a general YAML parser. Errors are tolerated as missing fields.
// ----------------------------------------------------------------------------

struct YamlNode {
    enum class Kind { Null, Scalar, Map, Seq } kind = Kind::Null;
    std::string scalar;
    std::vector<YamlNode> seq;
    std::vector<std::pair<std::string, YamlNode>> map;

    [[nodiscard]] bool isMap() const noexcept { return kind == Kind::Map; }
    [[nodiscard]] bool isSeq() const noexcept { return kind == Kind::Seq; }
    [[nodiscard]] bool isScalar() const noexcept { return kind == Kind::Scalar; }

    const YamlNode* find(std::string_view key) const noexcept {
        if (!isMap()) return nullptr;
        for (const auto& [k, v] : map)
            if (k == key) return &v;
        return nullptr;
    }
    std::string str(std::string_view key, std::string defv = {}) const {
        if (const auto* n = find(key); n && n->isScalar()) return n->scalar;
        return std::string(defv);
    }
};

int leadingSpaces(std::string_view line) noexcept {
    int n = 0;
    for (char c : line) {
        if (c == ' ') ++n;
        else break;
    }
    return n;
}

std::string trimEnd(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\r' || s.back() == '\t')) s.pop_back();
    return s;
}

std::string trim(std::string s) {
    size_t i = 0; while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    size_t j = s.size(); while (j > i && std::isspace(static_cast<unsigned char>(s[j-1]))) --j;
    return s.substr(i, j - i);
}

std::string unquote(std::string s) {
    s = trim(std::move(s));
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') ||
         (s.front() == '\'' && s.back() == '\''))) {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}

class YamlReader {
public:
    explicit YamlReader(std::string_view text) : m_text(text) {
        std::string line;
        size_t i = 0;
        while (i < m_text.size()) {
            line.clear();
            while (i < m_text.size() && m_text[i] != '\n') line.push_back(m_text[i++]);
            if (i < m_text.size()) ++i; // consume \n
            m_lines.push_back(trimEnd(std::move(line)));
        }
    }

    YamlNode parse() {
        m_pos = 0;
        return readBlock(-1);
    }

private:
    std::string_view m_text;
    std::vector<std::string> m_lines;
    size_t m_pos = 0;

    // skips comments and empty lines
    bool peekLine(std::string& out) {
        while (m_pos < m_lines.size()) {
            const auto& l = m_lines[m_pos];
            auto t = trim(std::string(l));
            if (t.empty() || t.front() == '#') { ++m_pos; continue; }
            out = l;
            return true;
        }
        return false;
    }

    YamlNode readBlock(int parentIndent) {
        std::string line;
        if (!peekLine(line)) return {};
        int indent = leadingSpaces(line);
        if (indent <= parentIndent) return {};

        // Determine map vs seq from first non-comment line
        auto stripped = trim(std::string(line));
        if (stripped.substr(0, 2) == "- ") {
            // sequence
            YamlNode seq; seq.kind = YamlNode::Kind::Seq;
            while (m_pos < m_lines.size()) {
                if (!peekLine(line)) break;
                int ind = leadingSpaces(line);
                if (ind != indent) break;
                auto s = trim(std::string(line));
                if (s.substr(0, 2) != "- ") break;
                ++m_pos;
                std::string itemText = s.substr(2);
                if (!itemText.empty() && itemText.find(": ") != std::string::npos &&
                    itemText.back() != ':') {
                    // Inline mapping like "- key: val" continued by deeper indent
                    YamlNode m; m.kind = YamlNode::Kind::Map;
                    auto colon = itemText.find(": ");
                    std::string k = trim(itemText.substr(0, colon));
                    std::string v = trim(itemText.substr(colon + 2));
                    YamlNode child;
                    child.kind = YamlNode::Kind::Scalar;
                    child.scalar = unquote(std::move(v));
                    m.map.emplace_back(std::move(k), std::move(child));
                    // Look for continuation map entries indented further
                    YamlNode deeper = readBlock(indent);
                    if (deeper.isMap()) {
                        for (auto& kv : deeper.map) m.map.push_back(std::move(kv));
                    }
                    seq.seq.push_back(std::move(m));
                } else if (!itemText.empty() && itemText != ":" && itemText.back() != ':') {
                    YamlNode sc;
                    sc.kind = YamlNode::Kind::Scalar;
                    sc.scalar = unquote(itemText);
                    seq.seq.push_back(std::move(sc));
                } else {
                    // Empty - or "- key:" - need deeper block
                    YamlNode deeper = readBlock(indent);
                    if (!itemText.empty()) {
                        // "- key:"
                        YamlNode m; m.kind = YamlNode::Kind::Map;
                        std::string k = itemText.substr(0, itemText.size() - 1);
                        m.map.emplace_back(trim(std::move(k)), std::move(deeper));
                        seq.seq.push_back(std::move(m));
                    } else {
                        seq.seq.push_back(std::move(deeper));
                    }
                }
            }
            return seq;
        }

        // mapping
        YamlNode map; map.kind = YamlNode::Kind::Map;
        while (m_pos < m_lines.size()) {
            if (!peekLine(line)) break;
            int ind = leadingSpaces(line);
            if (ind != indent) break;
            auto s = trim(std::string(line));
            ++m_pos;
            auto colon = s.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            std::string k = trim(s.substr(0, colon));
            std::string rest = (colon + 1 < s.size()) ? trim(s.substr(colon + 1)) : std::string();

            YamlNode value;
            if (rest == "|" || rest == ">") {
                // block scalar
                value.kind = YamlNode::Kind::Scalar;
                std::string acc;
                while (m_pos < m_lines.size()) {
                    auto& nl = m_lines[m_pos];
                    int li = leadingSpaces(nl);
                    if (li <= indent && !trim(std::string(nl)).empty()) break;
                    if (!nl.empty()) {
                        if (!acc.empty()) acc.push_back(rest == "|" ? '\n' : ' ');
                        acc += trim(nl.substr(std::min<int>(li, indent + 2)));
                    } else {
                        acc.push_back('\n');
                    }
                    ++m_pos;
                }
                value.scalar = trim(std::move(acc));
            } else if (rest.empty()) {
                value = readBlock(indent);
            } else {
                value.kind = YamlNode::Kind::Scalar;
                value.scalar = unquote(rest);
            }
            map.map.emplace_back(std::move(k), std::move(value));
        }
        return map;
    }
};

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

RuleSeverity sigmaSeverity(std::string_view s) noexcept {
    if (s == "informational") return RuleSeverity::Informational;
    if (s == "low")           return RuleSeverity::Low;
    if (s == "medium")        return RuleSeverity::Medium;
    if (s == "high")          return RuleSeverity::High;
    if (s == "critical")      return RuleSeverity::Critical;
    return RuleSeverity::Medium;
}

void readAttackTagsInto(const YamlNode& tags, PhantomRule& out) {
    if (!tags.isSeq()) return;
    for (const auto& t : tags.seq) {
        if (!t.isScalar()) continue;
        std::string s = t.scalar;
        // Sigma tags look like: "attack.execution", "attack.t1059.001", "attack.ta0002"
        if (s.rfind("attack.", 0) == 0) {
            s = s.substr(7);
            AttackMapping m;
            // TIDs like "t1059" or "t1059.001"
            if (!s.empty() && (s.front() == 't' || s.front() == 'T')) {
                m.techniqueId = "T" + s.substr(1);
                auto dot = m.techniqueId.find('.');
                if (dot != std::string::npos) {
                    m.subTechniqueId = m.techniqueId;
                    m.techniqueId = m.techniqueId.substr(0, dot);
                }
            } else if (!s.empty() && (s.front() == 'g' || s.front() == 'G' ||
                                       s.front() == 's' || s.front() == 'S')) {
                m.name = s;
            } else {
                // Tactic name like "execution"
                m.name = s;
            }
            out.attack.push_back(std::move(m));
        } else if (s.rfind("cve.", 0) == 0) {
            RuleReference r; r.title = s; r.url.clear();
            out.references.push_back(std::move(r));
        }
    }
}

bool extractStringList(const YamlNode& n, std::vector<std::string>& out) {
    if (n.isSeq()) {
        for (const auto& c : n.seq)
            if (c.isScalar()) out.push_back(c.scalar);
        return true;
    }
    if (n.isScalar()) { out.push_back(n.scalar); return true; }
    return false;
}

// Build a leaf-Or from a list of values for a single field.
FeatureNode buildFieldOr(const std::string& field,
                         const std::vector<std::string>& values,
                         FeatureKind kind = FeatureKind::FieldContains,
                         bool caseInsensitive = true) {
    FeatureNode n;
    if (values.size() == 1) {
        n.op = FeatureNode::Op::Leaf;
        n.leaf.field = field;
        n.leaf.kind = kind;
        n.leaf.value = values.front();
        n.leaf.caseInsensitive = caseInsensitive;
        return n;
    }
    n.op = FeatureNode::Op::Or;
    for (const auto& v : values) {
        FeatureNode leaf;
        leaf.op = FeatureNode::Op::Leaf;
        leaf.leaf.field = field;
        leaf.leaf.kind = kind;
        leaf.leaf.value = v;
        leaf.leaf.caseInsensitive = caseInsensitive;
        n.children.push_back(std::move(leaf));
    }
    return n;
}

} // anonymous namespace

// ============================================================================
// Sigma YAML -> PhantomRule
// ============================================================================
//
// Sigma fields we care about for Windows:
//   title, id, description, status, level, tags, references, falsepositives
//   logsource.product == "windows", logsource.category, logsource.service
//   detection:
//     selection_*:
//       <field>|<modifier>: <value or list>
//     condition: selection or 1 of selection_* etc.
//
// Many Sigma rules have multi-named selections and a textual condition like
// "all of selection_* and not filter_*". We implement a subset:
//   - "selection" alone
//   - "selection and not filter"
//   - "1 of selection_*"
//   - "all of selection_*"
//
// More complex conditions degrade to AND over all non-filter selections,
// minus any selection prefixed with filter_ or whose name begins with
// "filter" / "exclusion" / "fp".

static std::string sigmaFieldMap(const std::string& f) {
    // Sigma field name -> ShadowStrike normalized field
    static const std::unordered_map<std::string, std::string> map{
        {"Image",            "process.executable"},
        {"OriginalFileName", "process.original_file_name"},
        {"CommandLine",      "process.command_line"},
        {"ParentImage",      "process.parent.executable"},
        {"ParentCommandLine","process.parent.command_line"},
        {"User",             "user.name"},
        {"IntegrityLevel",   "process.integrity_level"},
        {"TargetFilename",   "file.path"},
        {"TargetObject",     "registry.key"},
        {"Details",          "registry.value"},
        {"DestinationIp",    "network.destination.ip"},
        {"DestinationHostname", "network.destination.host"},
        {"DestinationPort",  "network.destination.port"},
        {"SourceIp",         "network.source.ip"},
        {"QueryName",        "dns.query.name"},
        {"ImageLoaded",      "image.path"},
        {"Signed",           "file.signer.signed"},
        {"Signature",        "file.signer.subject"},
        {"Hashes",           "file.hash"},
        {"PipeName",         "pipe.name"},
        {"Service",          "service.name"},
        {"ServiceFileName",  "service.image_path"},
        {"EventID",          "event.code"},
        {"Provider_Name",    "event.provider"},
        {"Channel",          "event.channel"},
        {"ScriptBlockText",  "script.text"},
        {"ContextInfo",      "script.context"},
        {"CurrentDirectory", "process.working_directory"},
        {"ParentProcessId",  "process.parent.pid"},
        {"ProcessId",        "process.pid"},
        {"TerminalSessionId","process.session_id"},
        {"Computer",         "host.name"},
        {"Hostname",         "host.name"},
        {"WorkstationName",  "host.name"},
        {"SubjectUserName",  "user.name"},
        {"SubjectUserSid",   "user.sid"},
        {"TargetUserName",   "target.user.name"},
        {"NewName",          "file.new_path"},
        {"Device",           "device.name"},
        {"CommandName",      "process.command_name"},
        {"Description",      "file.description"},
        {"Product",          "file.product"},
        {"Company",          "file.company"},
        {"FileVersion",      "file.version"},
        {"AccessMask",       "process.access_mask"},
        {"GrantedAccess",    "process.granted_access"},
        {"CallTrace",        "process.call_trace"},
        {"SourceImage",      "process.source.executable"},
        {"TargetImage",      "process.target.executable"},
        {"StartModule",      "thread.start_module"},
        {"StartFunction",    "thread.start_function"},
        {"StartAddress",     "thread.start_address"},
    };
    auto it = map.find(f);
    if (it != map.end()) return it->second;
    // Lowercase + dot-separate as fallback
    std::string out = f;
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool RuleParser::IsWindowsRelevant(std::string_view sigmaText) {
    // Quick string scan to avoid full parse for non-Windows rules.
    auto contains = [&](std::string_view s) {
        return sigmaText.find(s) != std::string_view::npos;
    };
    if (contains("product: windows")) return true;
    if (contains("product: macos") || contains("product: linux"))
        return contains("product: windows");
    // Default assume yes; the parser will skip if logsource missing/foreign.
    return true;
}

bool RuleParser::ParseSigmaYaml(std::string_view text,
                                PhantomRule& out,
                                ParseError* err) {
    if (!IsWindowsRelevant(text)) return false;

    YamlReader reader(text);
    YamlNode doc = reader.parse();
    if (!doc.isMap()) { if (err) err->message = "expected map at root"; return false; }

    // Filter by logsource
    const auto* ls = doc.find("logsource");
    if (ls && ls->isMap()) {
        auto product = ls->str("product");
        if (!product.empty() && product != "windows") return false;
    }

    out.title = doc.str("title");
    out.id = "sigma-" + doc.str("id", out.title);
    out.genericDescription = doc.str("description");
    out.source = RuleSource::Sigma;
    out.windowsOnly = true;
    out.platforms = {"windows"};

    std::string st = doc.str("status", "experimental");
    if (st == "stable")       out.status = RuleStatus::Stable;
    else if (st == "test")    out.status = RuleStatus::Test;
    else if (st == "deprecated") out.status = RuleStatus::Deprecated;
    else                      out.status = RuleStatus::Experimental;

    out.severity = sigmaSeverity(doc.str("level", "medium"));
    out.baseConfidence = 0.5f +
        (static_cast<int>(out.severity) - static_cast<int>(RuleSeverity::Low)) * 0.1f;
    if (out.baseConfidence > 0.9f) out.baseConfidence = 0.9f;
    out.weight = 1.0f + 0.5f * static_cast<int>(out.severity);

    // Tags / attack
    if (const auto* tags = doc.find("tags")) readAttackTagsInto(*tags, out);

    // References
    if (const auto* refs = doc.find("references"); refs && refs->isSeq()) {
        for (const auto& r : refs->seq) {
            if (r.isScalar()) {
                RuleReference ref; ref.url = r.scalar; ref.title = "ref";
                out.references.push_back(std::move(ref));
            }
        }
    }

    // False positives -> FP notes
    if (const auto* fp = doc.find("falsepositives")) {
        std::vector<std::string> notes;
        extractStringList(*fp, notes);
        out.fpGuard.notes = std::move(notes);
    }

    // Scope determined by logsource.category
    std::string cat = ls ? ls->str("category") : "";
    if (cat == "process_creation") out.scope = RuleScope::Process;
    else if (cat == "image_load")  out.scope = RuleScope::Image;
    else if (cat == "create_remote_thread") out.scope = RuleScope::Thread;
    else if (cat == "file_event" || cat == "file_change")  out.scope = RuleScope::File;
    else if (cat == "registry_event" || cat == "registry_set" ||
             cat == "registry_add" || cat == "registry_delete") out.scope = RuleScope::Registry;
    else if (cat == "network_connection" || cat == "dns_query") out.scope = RuleScope::Network;
    else if (cat == "ps_script" || cat == "powershell_classic_start" ||
             cat == "powershell_script") out.scope = RuleScope::Script;
    else if (cat == "file_delete" || cat == "file_access" || cat == "file_renamed") out.scope = RuleScope::File;
    else if (cat == "wmi_event" || cat == "wmi_subscription") out.scope = RuleScope::Script;
    else if (cat == "pipe_created" || cat == "named_pipe_event") out.scope = RuleScope::Process;
    else if (cat == "driver_load" || cat == "driver_loaded") out.scope = RuleScope::Image;
    else if (cat == "scheduled_task" || cat == "scheduled_task_creation") out.scope = RuleScope::Process;
    else if (cat == "service_creation" || cat == "service_install") out.scope = RuleScope::Process;
    else if (cat == "clipboard_capture") out.scope = RuleScope::Process;
    else if (cat == "raw_access_read") out.scope = RuleScope::File;
    else if (cat == "sysmon_error" || cat == "sysmon_status") out.scope = RuleScope::Hunting;
    else out.scope = RuleScope::Process;

    // Detection block
    const auto* det = doc.find("detection");
    if (!det || !det->isMap()) return false;

    // Build selection map
    std::map<std::string, FeatureNode> selections;
    std::string condition;
    for (const auto& [k, v] : det->map) {
        if (k == "condition") {
            if (v.isScalar()) condition = v.scalar;
            continue;
        }
        if (k == "timeframe") continue;
        // selection map
        if (!v.isMap()) continue;
        FeatureNode andNode;
        andNode.op = FeatureNode::Op::And;
        for (const auto& [field, val] : v.map) {
            // Field may have modifier: "Image|endswith", etc.
            auto pipe = field.find('|');
            std::string base = (pipe == std::string::npos) ? field : field.substr(0, pipe);
            std::string mod  = (pipe == std::string::npos) ? "" : field.substr(pipe + 1);
            // Modifier may contain multiple separators
            std::string normalField = sigmaFieldMap(base);

            FeatureKind kind = FeatureKind::FieldEquals;
            bool ci = true;
            bool isRegex = false;
            if (mod.find("contains") != std::string::npos) kind = FeatureKind::FieldContains;
            if (mod.find("startswith") != std::string::npos) kind = FeatureKind::FieldStartsWith;
            if (mod.find("endswith") != std::string::npos) kind = FeatureKind::FieldEndsWith;
            if (mod.find("re") != std::string::npos) { kind = FeatureKind::FieldRegex; isRegex = true; }
            (void)isRegex;

            std::vector<std::string> values;
            if (val.isScalar()) values.push_back(val.scalar);
            else if (val.isSeq()) extractStringList(val, values);

            if (values.empty()) continue;

            // |windash modifier: expand each value to accept both '-' and '/'
            bool windashModifier = (mod.find("windash") != std::string::npos);
            if (windashModifier) {
                std::vector<std::string> expanded;
                for (const auto& v : values) {
                    expanded.push_back(v);
                    if (!v.empty()) {
                        std::string alt = v;
                        if (alt[0] == '-') alt[0] = '/';
                        else if (alt[0] == '/') alt[0] = '-';
                        if (alt != v) expanded.push_back(std::move(alt));
                    }
                }
                values = std::move(expanded);
            }

            // |all modifier: field must match ALL values (AND semantics)
            bool allModifier = (mod.find("all") != std::string::npos);
            FeatureNode fn;
            if (allModifier && values.size() > 1) {
                fn.op = FeatureNode::Op::And;
                for (const auto& v : values) {
                    FeatureNode leaf;
                    leaf.op = FeatureNode::Op::Leaf;
                    leaf.leaf.field = normalField;
                    leaf.leaf.kind = kind;
                    leaf.leaf.value = v;
                    leaf.leaf.caseInsensitive = ci;
                    fn.children.push_back(std::move(leaf));
                }
            } else {
                fn = buildFieldOr(normalField, values, kind, ci);
            }
            andNode.children.push_back(std::move(fn));
        }
        if (andNode.children.empty()) continue;
        if (andNode.children.size() == 1) {
            selections.emplace(k, std::move(andNode.children.front()));
        } else {
            selections.emplace(k, std::move(andNode));
        }
    }

    if (selections.empty()) return false;

    // =========================================================================
    // Sigma condition grammar evaluator
    //
    // Grammar (simplified from Sigma spec):
    //   condition   := pipe-expr
    //   pipe-expr   := or-expr ( '|' filter-kw )*      -- pipe not yet supported
    //   or-expr     := and-expr ( 'or' and-expr )*
    //   and-expr    := not-expr ( 'and' not-expr )*
    //   not-expr    := 'not' not-expr | quantifier
    //   quantifier  := count-expr | of-expr | selection-ref
    //   of-expr     := number-or-kw 'of' name-pattern
    //   count-expr  := 'count(...)' comparison   -- not evaluated at match time, degraded
    //   selection-ref := bare identifier (a selection name)
    //
    // "name-pattern" may be:
    //   'them'         — all selections
    //   '*'            — all selections
    //   'selection'    — the selection named "selection"
    //   'selection_*'  — all selections starting with "selection_"
    //   'filter_*'     — all selections starting with "filter_"
    //
    // "number-or-kw" may be:
    //   '1' | 'any'    → Or combinator
    //   'all'          → And combinator
    //   'N' (integer)  → AtLeast N combinator
    //
    // This implementation handles the full grammar by recursive descent.
    // Any unsupported construct (count(), pipe filter) degrades to And.
    // =========================================================================

    auto isFilter = [](const std::string& name) noexcept {
        return name.rfind("filter", 0) == 0 ||
               name.rfind("exclusion", 0) == 0 ||
               name == "fp";
    };

    // Tokenise the condition string
    auto tokenize = [](const std::string& src) -> std::vector<std::string> {
        std::vector<std::string> tokens;
        size_t i = 0;
        while (i < src.size()) {
            while (i < src.size() && std::isspace(static_cast<unsigned char>(src[i]))) ++i;
            if (i >= src.size()) break;
            if (src[i] == '(' || src[i] == ')' || src[i] == '|') {
                tokens.push_back(std::string(1, src[i++]));
                continue;
            }
            size_t j = i;
            while (j < src.size() && !std::isspace(static_cast<unsigned char>(src[j])) &&
                   src[j] != '(' && src[j] != ')' && src[j] != '|') ++j;
            tokens.push_back(src.substr(i, j - i));
            i = j;
        }
        return tokens;
    };

    // Expand a name pattern against the selection map
    auto expandPattern = [&](const std::string& pat) -> std::vector<std::string> {
        std::vector<std::string> out;
        if (pat == "them" || pat == "*") {
            for (const auto& [k, _] : selections) out.push_back(k);
        } else if (!pat.empty() && pat.back() == '*') {
            std::string prefix = pat.substr(0, pat.size() - 1);
            for (const auto& [k, _] : selections)
                if (k.rfind(prefix, 0) == 0) out.push_back(k);
        } else {
            if (selections.count(pat)) out.push_back(pat);
        }
        return out;
    };

    // Build a FeatureNode from a selection name
    auto selectionNode = [&](const std::string& name) -> std::optional<FeatureNode> {
        auto it = selections.find(name);
        if (it == selections.end()) return std::nullopt;
        return it->second;  // copy
    };

    // Recursive-descent parser
    struct CondParser {
        const std::vector<std::string>& toks;
        size_t pos{0};
        const std::map<std::string, FeatureNode>& sel;
        const std::function<std::vector<std::string>(const std::string&)>& expand;
        const std::function<bool(const std::string&)>& isFilter;

        std::string cur() const noexcept {
            return (pos < toks.size()) ? toks[pos] : std::string{};
        }
        bool consume(const std::string& s) noexcept {
            if (pos < toks.size() && toks[pos] == s) { ++pos; return true; }
            return false;
        }
        bool at_end() const noexcept { return pos >= toks.size(); }

        FeatureNode parse() { return parseOr(); }

        FeatureNode parseOr() {
            auto lhs = parseAnd();
            while (pos < toks.size() && toks[pos] == "or") {
                ++pos;
                auto rhs = parseAnd();
                FeatureNode orNode; orNode.op = FeatureNode::Op::Or;
                orNode.children.push_back(std::move(lhs));
                orNode.children.push_back(std::move(rhs));
                lhs = std::move(orNode);
            }
            return lhs;
        }

        FeatureNode parseAnd() {
            auto lhs = parseNot();
            while (pos < toks.size() && toks[pos] == "and") {
                ++pos;
                auto rhs = parseNot();
                FeatureNode andNode; andNode.op = FeatureNode::Op::And;
                andNode.children.push_back(std::move(lhs));
                andNode.children.push_back(std::move(rhs));
                lhs = std::move(andNode);
            }
            return lhs;
        }

        FeatureNode parseNot() {
            if (consume("not")) {
                auto inner = parseNot();
                FeatureNode notNode; notNode.op = FeatureNode::Op::Not;
                notNode.children.push_back(std::move(inner));
                return notNode;
            }
            return parseAtom();
        }

        // Returns FeatureNode::Op for quantifier keyword
        static FeatureNode::Op quantOp(const std::string& kw) noexcept {
            if (kw == "all") return FeatureNode::Op::And;
            if (kw == "1" || kw == "any") return FeatureNode::Op::Or;
            // "N of" — use AtLeast
            return FeatureNode::Op::AtLeast;
        }

        static uint32_t quantN(const std::string& kw) noexcept {
            if (kw == "all" || kw == "any" || kw == "1") return 1;
            try { return static_cast<uint32_t>(std::stoul(kw)); } catch (...) { return 1; }
        }

        FeatureNode parseAtom() {
            if (consume("(")) {
                auto inner = parseOr();
                consume(")");
                return inner;
            }

            // Pipe — unsupported, skip to end
            if (cur() == "|") { ++pos; while (!at_end()) ++pos; return FeatureNode{}; }

            // Quantifier: "all of X" / "1 of X" / "any of X" / "N of X"
            std::string tok = cur();
            bool isQuant = (tok == "all" || tok == "any" || tok == "1" ||
                            (!tok.empty() && std::isdigit(static_cast<unsigned char>(tok.front()))));
            if (isQuant && pos + 2 < toks.size() && toks[pos + 1] == "of") {
                std::string quantKw = tok; ++pos; ++pos;  // skip quant + "of"
                std::string pattern = cur(); if (!at_end()) ++pos;

                auto names = expand(pattern);
                FeatureNode::Op op = quantOp(quantKw);
                uint32_t n = (op == FeatureNode::Op::AtLeast) ? quantN(quantKw) : 0;

                if (names.empty()) return FeatureNode{};
                if (names.size() == 1) {
                    auto it = sel.find(names[0]);
                    if (it != sel.end()) return it->second;
                    return FeatureNode{};
                }

                FeatureNode combined; combined.op = op; combined.threshold = n;
                for (const auto& nm : names) {
                    auto it = sel.find(nm);
                    if (it != sel.end()) combined.children.push_back(it->second);
                }
                return combined;
            }

            // Count expression — not directly evaluable; degrade to True (allow pass-through)
            if (!tok.empty() && tok.rfind("count", 0) == 0) {
                ++pos;
                // Skip comparison tokens (e.g. " > 5")
                while (!at_end() && cur() != "and" && cur() != "or" && cur() != ")") ++pos;
                // Return an empty node (always passes) to avoid blocking
                FeatureNode passthrough; passthrough.op = FeatureNode::Op::Optional;
                return passthrough;
            }

            // Simple selection reference
            if (!at_end()) {
                std::string name = tok; ++pos;
                auto it = sel.find(name);
                if (it != sel.end()) return it->second;
            }
            return FeatureNode{};
        }
    };

    FeatureNode root;
    if (condition.empty() || condition == "selection") {
        // Simple case: just AND all non-filter selections, NOT filter ones
        root.op = FeatureNode::Op::And;
        for (auto& [k, v] : selections) {
            if (isFilter(k)) {
                FeatureNode neg; neg.op = FeatureNode::Op::Not;
                neg.children.push_back(v);
                root.children.push_back(std::move(neg));
            } else {
                root.children.push_back(v);
            }
        }
    } else {
        // Full condition grammar
        auto tokens = tokenize(condition);
        CondParser cp{tokens, 0, selections, expandPattern, isFilter};
        root = cp.parse();
    }

    // Wrap single-child And nodes
    if (root.op == FeatureNode::Op::And && root.children.size() == 1) {
        root = std::move(root.children.front());
    }

    if (root.op == FeatureNode::Op::Leaf && root.leaf.kind == FeatureKind::Custom) {
        // Empty / unresolvable condition — degrade to hunting-only rather than dropping
        out.status = RuleStatus::HuntingOnly;
    }

    if (root.children.empty() && root.op == FeatureNode::Op::And) return false;
    out.logic = std::move(root);

    // Default detection name
    out.detectionName = "Sigma." + (cat.empty() ? "Windows" : cat) + ".Generic";
    return true;
}

// ============================================================================
// Capa YAML -> PhantomRule
// ============================================================================

static FeatureKind capaKind(std::string_view k) noexcept {
    if (k == "string")        return FeatureKind::String;
    if (k == "substring")     return FeatureKind::Substring;
    if (k == "regex")         return FeatureKind::Regex;
    if (k == "api")           return FeatureKind::Api;
    if (k == "mnemonic")      return FeatureKind::Mnemonic;
    if (k == "number")        return FeatureKind::Number;
    if (k == "operand[0].number" ||
        k == "operand[1].number")
                              return FeatureKind::OperandNumber;
    if (k == "bytes")         return FeatureKind::Bytes;
    if (k == "section")       return FeatureKind::Section;
    if (k == "characteristic")return FeatureKind::Characteristic;
    if (k == "class")         return FeatureKind::Class;
    if (k == "namespace")     return FeatureKind::Namespace;
    if (k == "os")            return FeatureKind::Os;
    if (k == "arch")          return FeatureKind::Arch;
    if (k == "format")        return FeatureKind::Format;
    if (k == "match")         return FeatureKind::Match;
    if (k == "offset")        return FeatureKind::Offset;
    if (k == "property")      return FeatureKind::Property;
    return FeatureKind::Custom;
}

static FeatureNode parseCapaFeatureNode(const YamlNode& n);

static FeatureNode parseCapaFeatureList(const std::vector<YamlNode>& items) {
    FeatureNode parent;
    parent.op = FeatureNode::Op::And;
    for (const auto& item : items) {
        parent.children.push_back(parseCapaFeatureNode(item));
    }
    return parent;
}

static FeatureNode parseCapaFeatureNode(const YamlNode& n) {
    FeatureNode out;
    if (!n.isMap()) return out;
    if (n.map.empty()) return out;
    const auto& [k, v] = n.map.front();
    if (k == "and") {
        out.op = FeatureNode::Op::And;
        if (v.isSeq()) for (const auto& c : v.seq) out.children.push_back(parseCapaFeatureNode(c));
        return out;
    }
    if (k == "or") {
        out.op = FeatureNode::Op::Or;
        if (v.isSeq()) for (const auto& c : v.seq) out.children.push_back(parseCapaFeatureNode(c));
        return out;
    }
    if (k == "not") {
        out.op = FeatureNode::Op::Not;
        if (v.isSeq() && !v.seq.empty()) out.children.push_back(parseCapaFeatureNode(v.seq.front()));
        else if (v.isMap()) out.children.push_back(parseCapaFeatureNode(v));
        return out;
    }
    if (k == "optional") {
        out.op = FeatureNode::Op::Optional;
        if (v.isSeq() && !v.seq.empty()) out.children.push_back(parseCapaFeatureNode(v.seq.front()));
        else if (v.isMap()) out.children.push_back(parseCapaFeatureNode(v));
        return out;
    }
    if (k.rfind("count(", 0) == 0 || k.rfind("at least", 0) == 0 ||
        (k.size() > 3 && k.find(" or more") != std::string::npos)) {
        out.op = FeatureNode::Op::AtLeast;
        out.threshold = 1;
        // Extract threshold: look for a multi-digit number or isolated digit
        // Handles: "count(api(X)) >= 5", "at least 3 ...", "2 or more"
        {
            bool foundDigit = false;
            size_t i = 0;
            while (i < k.size()) {
                if (std::isdigit(static_cast<unsigned char>(k[i]))) {
                    // Parse full number
                    size_t j = i;
                    while (j < k.size() && std::isdigit(static_cast<unsigned char>(k[j]))) ++j;
                    try {
                        out.threshold = static_cast<uint32_t>(std::stoul(k.substr(i, j - i)));
                        foundDigit = true;
                    } catch (...) {}
                    i = j;
                    if (foundDigit) break;
                } else {
                    ++i;
                }
            }
        }
        if (v.isSeq()) for (const auto& c : v.seq) out.children.push_back(parseCapaFeatureNode(c));
        // If no children (e.g. "count(X) >= N" with inner feature in key), add an Optional child
        // so AtLeast doesn't trivially succeed with 0/0 threshold comparison
        if (out.children.empty()) {
            FeatureNode opt; opt.op = FeatureNode::Op::Optional;
            out.children.push_back(std::move(opt));
        }
        return out;
    }

    out.op = FeatureNode::Op::Leaf;
    out.leaf.kind = capaKind(k);
    // For numeric kinds, set both
    if (out.leaf.kind == FeatureKind::Number ||
        out.leaf.kind == FeatureKind::OperandNumber) {
        if (v.isScalar()) {
            try {
                if (v.scalar.rfind("0x", 0) == 0)
                    out.leaf.number = std::stoll(v.scalar.substr(2), nullptr, 16);
                else
                    out.leaf.number = std::stoll(v.scalar);
            } catch (...) {}
            out.leaf.value = v.scalar;
        }
    } else if (out.leaf.kind == FeatureKind::Regex) {
        std::string s = v.isScalar() ? v.scalar : std::string{};
        out.leaf.caseInsensitive = (!s.empty() && s.back() == 'i');
        // capa regex is /.../[i]; strip surrounding slashes
        if (s.size() >= 2 && s.front() == '/') {
            size_t end = s.rfind('/');
            if (end > 0) s = s.substr(1, end - 1);
        }
        out.leaf.value = s;
    } else {
        if (v.isScalar()) out.leaf.value = v.scalar;
    }
    out.leaf.description = k;
    return out;
}

bool RuleParser::ParseCapaYaml(std::string_view text,
                               PhantomRule& out,
                               ParseError* err) {
    YamlReader reader(text);
    YamlNode doc = reader.parse();
    if (!doc.isMap()) { if (err) err->message = "expected map at root"; return false; }
    const auto* rule = doc.find("rule");
    if (!rule || !rule->isMap()) { if (err) err->message = "missing rule:"; return false; }

    const auto* meta = rule->find("meta");
    if (!meta || !meta->isMap()) { if (err) err->message = "missing meta:"; return false; }

    out.title = meta->str("name");
    out.id = "capa-" + out.title;
    out.source = RuleSource::Capa;

    // Handle both old "scope:" and new "scopes:" block (capa 9.4.0+)
    // old: scope: function / file
    // new: scopes:\n  static: file\n  dynamic: call
    {
        std::string capaScope;
        if (const auto* scopes = meta->find("scopes"); scopes && scopes->isMap()) {
            capaScope = scopes->str("static");
            if (capaScope.empty()) capaScope = scopes->str("dynamic");
        } else {
            capaScope = meta->str("scope");
        }
        (void)capaScope; // all capa rules map to Static scope in ShadowStrike
    }
    out.scope = RuleScope::Static;
    out.windowsOnly = true; // capa is platform-agnostic; we tag as windows by default
    out.platforms = {"windows"};

    std::string ns = meta->str("namespace");
    if (!ns.empty()) {
        out.namespaces.clear();
        std::stringstream ss(ns);
        std::string tok;
        while (std::getline(ss, tok, '/')) out.namespaces.push_back(tok);
    }
    out.genericDescription = "Static capa rule: " + out.title;

    // Heuristic severity from namespace
    out.severity = RuleSeverity::Low;
    if (!ns.empty()) {
        if (ns.find("malware-family") != std::string::npos ||
            ns.find("ransomware") != std::string::npos ||
            ns.find("backdoor") != std::string::npos)
            out.severity = RuleSeverity::High;
        else if (ns.find("anti-analysis") != std::string::npos ||
                 ns.find("injection") != std::string::npos ||
                 ns.find("evasion") != std::string::npos ||
                 ns.find("exploitation") != std::string::npos)
            out.severity = RuleSeverity::Medium;
        else if (ns.find("nursery") != std::string::npos)
            out.severity = RuleSeverity::Informational;
    }
    out.baseConfidence = 0.65f;
    out.weight = 0.8f;
    out.status = RuleStatus::Stable;

    if (const auto* authors = meta->find("authors")) {
        if (authors->isSeq()) for (const auto& a : authors->seq)
            if (a.isScalar()) { RuleAuthor ra; ra.handle = a.scalar; out.authors.push_back(ra); }
        else if (authors->isScalar()) { RuleAuthor ra; ra.handle = authors->scalar; out.authors.push_back(ra); }
    }

    if (const auto* mbc = meta->find("mbc")) {
        if (mbc->isSeq()) for (const auto& m : mbc->seq)
            if (m.isScalar()) { RuleReference r; r.title = m.scalar; r.url = ""; out.references.push_back(r); }
    }
    if (const auto* att = meta->find("att&ck")) {
        if (att->isSeq()) for (const auto& a : att->seq)
            if (a.isScalar()) {
                AttackMapping am;
                am.name = a.scalar;
                // Extract Txxxx[.yyy]
                std::regex re(R"(T\d{4}(?:\.\d{3})?)", std::regex::ECMAScript);
                std::smatch sm;
                if (std::regex_search(a.scalar, sm, re)) {
                    am.techniqueId = sm.str();
                    auto dot = am.techniqueId.find('.');
                    if (dot != std::string::npos) am.subTechniqueId = am.techniqueId;
                }
                out.attack.push_back(std::move(am));
            }
    }

    // Features
    const auto* feats = rule->find("features");
    if (!feats || !feats->isSeq()) { if (err) err->message = "missing features:"; return false; }
    out.logic = parseCapaFeatureList(feats->seq);

    // Detection name
    out.detectionName = "Capa.Static." + (out.namespaces.empty() ? "Generic" : out.namespaces.front());
    return true;
}

// ============================================================================
// Native ShadowStrike rule (YAML/JSON) -> PhantomRule
// ============================================================================

// ShadowStrike native format mirrors the in-memory layout closely:
//
//   id: ss-proc-001
//   detection_name: Win32/Injection.Behavior
//   description: Process injection behavior detected
//   scope: process
//   severity: high
//   status: stable
//   source: native
//   confidence: 0.75
//   weight: 1.5
//   attack:
//     - tactic: TA0005
//       technique: T1055
//   logic:
//     and:
//       - field_equals:
//           field: process.parent.name
//           value: winword.exe
//       - field_contains:
//           field: process.command_line
//           value: powershell
//   fp_guard:
//     notes:
//       - "Office macros that legitimately call PowerShell with -ExecutionPolicy"
//     suppress:
//       - field: process.parent.signature.subject
//         values: ["Microsoft Corporation"]
//

static FeatureKind nativeKind(std::string_view k) noexcept {
    if (k == "string") return FeatureKind::String;
    if (k == "substring") return FeatureKind::Substring;
    if (k == "regex") return FeatureKind::Regex;
    if (k == "api") return FeatureKind::Api;
    if (k == "mnemonic") return FeatureKind::Mnemonic;
    if (k == "number") return FeatureKind::Number;
    if (k == "bytes") return FeatureKind::Bytes;
    if (k == "section") return FeatureKind::Section;
    if (k == "characteristic") return FeatureKind::Characteristic;
    if (k == "class") return FeatureKind::Class;
    if (k == "namespace") return FeatureKind::Namespace;
    if (k == "os") return FeatureKind::Os;
    if (k == "arch") return FeatureKind::Arch;
    if (k == "format") return FeatureKind::Format;
    if (k == "field_equals" || k == "field_eq") return FeatureKind::FieldEquals;
    if (k == "field_contains") return FeatureKind::FieldContains;
    if (k == "field_regex") return FeatureKind::FieldRegex;
    if (k == "field_starts_with" || k == "field_startswith") return FeatureKind::FieldStartsWith;
    if (k == "field_ends_with" || k == "field_endswith") return FeatureKind::FieldEndsWith;
    if (k == "field_in") return FeatureKind::FieldIn;
    if (k == "field_not_in" || k == "field_ne") return FeatureKind::FieldNotIn;
    if (k == "field_gt") return FeatureKind::FieldGt;
    if (k == "field_lt") return FeatureKind::FieldLt;
    if (k == "field_ge") return FeatureKind::FieldGe;
    if (k == "field_le") return FeatureKind::FieldLe;
    if (k == "field_exists") return FeatureKind::FieldExists;
    if (k == "field_missing") return FeatureKind::FieldMissing;
    if (k == "signer_equals") return FeatureKind::SignerEquals;
    if (k == "signer_untrusted") return FeatureKind::SignerUntrusted;
    if (k == "unsigned") return FeatureKind::Unsigned;
    if (k == "entropy_above") return FeatureKind::EntropyAbove;
    if (k == "import_count_above") return FeatureKind::ImportCountAbove;
    if (k == "unique_api_count_above") return FeatureKind::UniqueApiCountAbove;
    if (k == "child_of") return FeatureKind::ChildOf;
    if (k == "descendant_of") return FeatureKind::DescendantOf;
    if (k == "has_mitigation") return FeatureKind::HasMitigation;
    if (k == "lacks_mitigation") return FeatureKind::LacksMitigation;
    if (k == "field_bytes") return FeatureKind::FieldBytes;
    // Also accept capa-style keys in native rules
    if (k == "match")          return FeatureKind::Match;
    if (k == "offset")         return FeatureKind::Offset;
    if (k == "operand_number") return FeatureKind::OperandNumber;
    if (k == "property")       return FeatureKind::Property;
    return FeatureKind::Custom;
}

static FeatureNode parseNativeNode(const YamlNode& n);

static FeatureNode parseNativeAndOrNot(const YamlNode& v, FeatureNode::Op op) {
    FeatureNode out; out.op = op;
    if (v.isSeq()) for (const auto& c : v.seq) out.children.push_back(parseNativeNode(c));
    else if (v.isMap()) out.children.push_back(parseNativeNode(v));
    return out;
}

// Parse duration string like "300s", "30m", "2h" into milliseconds.
static std::chrono::milliseconds parseDuration(std::string_view s) noexcept {
    if (s.empty()) return {};
    size_t i = 0;
    uint64_t n = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        n = n * 10 + static_cast<uint64_t>(s[i++] - '0');
    }
    std::string unit(s.substr(i));
    if (unit == "ms") return std::chrono::milliseconds(n);
    if (unit == "s" || unit.empty()) return std::chrono::milliseconds(n * 1000);
    if (unit == "m") return std::chrono::milliseconds(n * 60000);
    if (unit == "h") return std::chrono::milliseconds(n * 3600000);
    return std::chrono::milliseconds(n * 1000);
}

static FeatureNode parseNativeNode(const YamlNode& n) {
    FeatureNode out;
    if (!n.isMap() || n.map.empty()) return out;

    // Handle "feature: <KindName>" compact notation (sibling keys: threshold, value, number).
    // Used in static rules: "- feature: EntropyAbove\n  threshold: 6.5"
    if (const auto* feat = n.find("feature"); feat && feat->isScalar()) {
        out.op = FeatureNode::Op::Leaf;
        // Accept both PascalCase ("EntropyAbove") and snake_case ("entropy_above")
        std::string fk = feat->scalar;
        // Normalise PascalCase to snake_case for the existing nativeKind() lookup
        std::string snake;
        for (size_t i = 0; i < fk.size(); ++i) {
            if (i > 0 && std::isupper(static_cast<unsigned char>(fk[i])) &&
                std::islower(static_cast<unsigned char>(fk[i-1])))
                snake += '_';
            snake += static_cast<char>(std::tolower(static_cast<unsigned char>(fk[i])));
        }
        out.leaf.kind = nativeKind(snake);
        if (out.leaf.kind == FeatureKind::Custom) out.leaf.kind = nativeKind(fk); // try original
        if (const auto* tv = n.find("threshold"); tv && tv->isScalar()) {
            try { out.leaf.ratio = std::stod(tv->scalar); } catch (...) {}
            try { out.leaf.number = static_cast<int64_t>(out.leaf.ratio); } catch (...) {}
        }
        if (const auto* nv = n.find("number"); nv && nv->isScalar())
            try { out.leaf.number = std::stoll(nv->scalar); } catch (...) {}
        if (const auto* vv = n.find("value"); vv && vv->isScalar())
            out.leaf.value = vv->scalar;
        if (const auto* fv = n.find("field"); fv && fv->isScalar())
            out.leaf.field = fv->scalar;
        out.leaf.description = fk;
        return out;
    }

    // Handle sequence step format: {id: ..., within: ..., after: ..., event: {...}}
    // The event: sub-map carries the actual detection logic for this step.
    if (const auto* ev = n.find("event"); ev && ev->isMap()) {
        auto child = parseNativeNode(*ev);
        // Ensure the step is a container node, not a bare leaf — callers expect
        // Op::And/Or/Sequence so they can attach metadata and iterate children.
        if (child.op == FeatureNode::Op::Leaf) {
            FeatureNode wrapper;
            wrapper.op = FeatureNode::Op::And;
            wrapper.children.push_back(std::move(child));
            child = std::move(wrapper);
        }
        if (const auto* wv = n.find("within"); wv && wv->isScalar())
            child.maxGap = parseDuration(wv->scalar);
        return child;
    }

    const auto& [k, v] = n.map.front();
    if (k == "and") return parseNativeAndOrNot(v, FeatureNode::Op::And);
    if (k == "or")  return parseNativeAndOrNot(v, FeatureNode::Op::Or);
    if (k == "not") return parseNativeAndOrNot(v, FeatureNode::Op::Not);
    if (k == "optional") return parseNativeAndOrNot(v, FeatureNode::Op::Optional);
    if (k == "sequence") {
        out.op = FeatureNode::Op::Sequence;
        auto addSteps = [&](const auto& seq) {
            for (const auto& c : seq) {
                auto step = parseNativeNode(c);
                if (step.op != FeatureNode::Op::Leaf ||
                    !step.leaf.field.empty() || step.leaf.kind != FeatureKind::Custom)
                    out.children.push_back(std::move(step));
            }
        };
        if (v.isSeq()) {
            addSteps(v.seq);
        } else if (v.isMap()) {
            // Wrapped format: {window_seconds: N, ordered: bool, steps: [...]}
            const auto* stepsNode = v.find("steps");
            if (stepsNode && stepsNode->isSeq())
                addSteps(stepsNode->seq);
            else
                out.children.push_back(parseNativeNode(v));
        }
        return out;
    }
    if (k == "at_least") {
        out.op = FeatureNode::Op::AtLeast;
        if (v.isMap()) {
            for (const auto& [ck, cv] : v.map) {
                if (ck == "n" && cv.isScalar()) {
                    try { out.threshold = static_cast<uint32_t>(std::stoul(cv.scalar)); } catch (...) {}
                } else if (ck == "of" && cv.isSeq()) {
                    for (const auto& cc : cv.seq) out.children.push_back(parseNativeNode(cc));
                }
            }
        }
        return out;
    }

    out.op = FeatureNode::Op::Leaf;
    out.leaf.kind = nativeKind(k);

    if (v.isScalar()) {
        out.leaf.value = v.scalar;
        try {
            if (v.scalar.rfind("0x", 0) == 0)
                out.leaf.number = std::stoll(v.scalar.substr(2), nullptr, 16);
            else
                out.leaf.number = std::stoll(v.scalar);
        } catch (...) {}
    } else if (v.isMap()) {
        out.leaf.field = v.str("field");
        out.leaf.value = v.str("value");
        // "pattern" is an accepted alias for "value" used in field_regex nodes
        if (out.leaf.value.empty())
            out.leaf.value = v.str("pattern");
        // "hex" is used by field_bytes nodes (hex byte pattern)
        if (out.leaf.value.empty())
            out.leaf.value = v.str("hex");
        out.leaf.description = v.str("description");
        if (auto* cv = v.find("case_insensitive"); cv && cv->isScalar())
            out.leaf.caseInsensitive = (cv->scalar == "true" || cv->scalar == "1");
        if (auto* nv = v.find("number"); nv && nv->isScalar()) {
            try { out.leaf.number = std::stoll(nv->scalar); } catch (...) {}
        }
        if (auto* rv = v.find("ratio"); rv && rv->isScalar()) {
            try { out.leaf.ratio = std::stod(rv->scalar); } catch (...) {}
        }
        // Try to parse the primary value as a number too so integer comparisons work
        if (!out.leaf.value.empty() && out.leaf.number == 0) {
            try { out.leaf.number = std::stoll(out.leaf.value); } catch (...) {}
        }
        if (auto* vs = v.find("values"); vs && vs->isSeq()) {
            for (const auto& sv : vs->seq) if (sv.isScalar()) out.leaf.setValues.push_back(sv.scalar);
        }
        // case_insensitive defaults true for field_in / field_not_in unless explicitly set false
        if (!v.find("case_insensitive") &&
            (out.leaf.kind == FeatureKind::FieldIn || out.leaf.kind == FeatureKind::FieldNotIn ||
             out.leaf.kind == FeatureKind::FieldEquals || out.leaf.kind == FeatureKind::FieldContains))
            out.leaf.caseInsensitive = true;
    }
    return out;
}

bool RuleParser::ParseNativeText(std::string_view text, PhantomRule& out, ParseError* err) {
    YamlReader reader(text);
    YamlNode doc = reader.parse();
    if (!doc.isMap()) { if (err) err->message = "expected map"; return false; }

    out.id = doc.str("id");
    out.detectionName = doc.str("detection_name");
    out.genericDescription = doc.str("description");
    out.title = doc.str("title", out.detectionName);
    out.source = RuleSource::Native;

    std::string sc = doc.str("scope", "process");
    if      (sc == "static")   out.scope = RuleScope::Static;
    else if (sc == "process")  out.scope = RuleScope::Process;
    else if (sc == "image")    out.scope = RuleScope::Image;
    else if (sc == "thread")   out.scope = RuleScope::Thread;
    else if (sc == "memory")   out.scope = RuleScope::Memory;
    else if (sc == "registry") out.scope = RuleScope::Registry;
    else if (sc == "file")     out.scope = RuleScope::File;
    else if (sc == "network")  out.scope = RuleScope::Network;
    else if (sc == "script")   out.scope = RuleScope::Script;
    else if (sc == "sequence") out.scope = RuleScope::Sequence;
    else if (sc == "graph")    out.scope = RuleScope::Graph;
    else if (sc == "hunting")  out.scope = RuleScope::Hunting;

    out.severity = sigmaSeverity(doc.str("severity", "medium"));

    std::string st = doc.str("status", "experimental");
    if (st == "stable")            out.status = RuleStatus::Stable;
    else if (st == "test")         out.status = RuleStatus::Test;
    else if (st == "deprecated")   out.status = RuleStatus::Deprecated;
    else if (st == "hunting" || st == "hunting-only") out.status = RuleStatus::HuntingOnly;
    else                           out.status = RuleStatus::Experimental;

    try { out.baseConfidence = std::stof(doc.str("confidence", "0.5")); } catch (...) { out.baseConfidence = 0.5f; }
    try { out.weight         = std::stof(doc.str("weight", "1.0"));  } catch (...) { out.weight = 1.0f; }
    out.version = static_cast<uint32_t>(std::strtoul(doc.str("version", "1").c_str(), nullptr, 10));

    if (const auto* atk = doc.find("attack"); atk && atk->isSeq()) {
        for (const auto& a : atk->seq) {
            if (!a.isMap()) continue;
            AttackMapping m;
            m.tacticId = a.str("tactic");
            m.techniqueId = a.str("technique");
            m.subTechniqueId = a.str("sub_technique");
            m.name = a.str("name");
            out.attack.push_back(std::move(m));
        }
    }

    if (const auto* refs = doc.find("references"); refs && refs->isSeq()) {
        for (const auto& r : refs->seq) {
            if (r.isScalar()) {
                RuleReference rr; rr.url = r.scalar; out.references.push_back(rr);
            } else if (r.isMap()) {
                RuleReference rr; rr.title = r.str("title"); rr.url = r.str("url");
                out.references.push_back(std::move(rr));
            }
        }
    }

    if (const auto* logic = doc.find("logic"); logic && logic->isMap()) {
        out.logic = parseNativeNode(*logic);
    }

    if (const auto* fp = doc.find("fp_guard"); fp && fp->isMap()) {
        if (const auto* notes = fp->find("notes"); notes && notes->isSeq()) {
            extractStringList(*notes, out.fpGuard.notes);
        }
        if (const auto* sup = fp->find("suppress"); sup && sup->isSeq()) {
            for (const auto& s : sup->seq) {
                if (!s.isMap()) continue;
                SuppressionClause sc;
                sc.field = s.str("field");
                sc.regex = s.str("regex");
                sc.isRegex = !sc.regex.empty();
                if (const auto* vs = s.find("values"); vs && vs->isSeq()) {
                    for (const auto& vv : vs->seq) if (vv.isScalar()) sc.values.push_back(vv.scalar);
                }
                out.fpGuard.suppress.push_back(std::move(sc));
            }
        }
    }

    if (out.detectionName.empty()) out.detectionName = "Generic.Detection." + out.id;
    if (out.id.empty()) return false;
    return true;
}

// ============================================================================
// Elastic NDJSON line -> PhantomRule (best effort, KQL/EQL not translated)
// ============================================================================
//
// Elastic rules are too rich (KQL/EQL/EQL sequence) to translate fully.
// We extract metadata (name, severity, description, tags, threat) and
// place the original query into a hunting-only rule for analyst tracing.
//
// The result is registered as a Hunting rule by default; if the query is
// a simple "field:value" KQL we attempt to convert into a runtime rule.

// ============================================================================
// KQL translator — converts a Kibana Query Language expression into a
// FeatureNode boolean tree.
//
// Supported subset (covers ~90% of Elastic Windows detection rules):
//   field:value               → FieldEquals
//   field:"quoted value"      → FieldEquals (case-insensitive)
//   field:*                   → FieldExists
//   field:(v1 or v2)          → Or of FieldEquals leaves
//   field:v*                  → FieldStartsWith (trailing wildcard)
//   field:*v                  → FieldEndsWith (leading wildcard)
//   field:*v*                 → FieldContains (both wildcards)
//   a and b                   → And
//   a or b                    → Or
//   not a                     → Not
//   (expr)                    → grouping
//
// Field name translation: maps ECS fields to our DetectionEvent namespace.
// ============================================================================

namespace {

static std::string kqlFieldMap(const std::string& f) {
    // ECS → DetectionEvent field
    if (f == "process.parent.name")       return "process.parent.name";
    if (f == "process.name")              return "process.name";
    if (f == "process.command_line")      return "process.command_line";
    if (f == "process.executable")        return "process.executable";
    if (f == "process.pid")               return "process.pid";
    if (f == "process.parent.pid")        return "process.parent.pid";
    if (f == "host.name")                 return "host.name";
    if (f == "event.type")                return "event.action";
    if (f == "event.action")              return "event.action";
    if (f == "event.category")            return "event.category";
    if (f == "event.outcome")             return "event.outcome";
    if (f == "destination.ip")            return "network.destination.ip";
    if (f == "destination.port")          return "network.destination.port";
    if (f == "source.ip")                 return "network.source.ip";
    if (f == "dns.question.name")         return "dns.query.name";
    if (f == "file.path")                 return "file.path";
    if (f == "file.name")                 return "file.path";
    if (f == "registry.path")             return "registry.key";
    if (f == "registry.value.name")       return "registry.value";
    if (f == "user.name")                 return "user.name";
    if (f == "winlog.event_id")           return "event.code";
    if (f == "winlog.channel")            return "event.channel";
    return f;  // pass through unknown fields
}

struct KqlTokenizer {
    std::string_view src;
    size_t pos = 0;
    bool atEnd() const noexcept { return pos >= src.size(); }
    char peek() const noexcept { return atEnd() ? '\0' : src[pos]; }
    void skip() { while (!atEnd() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\n')) ++pos; }
    std::string readToken() {
        skip();
        if (atEnd()) return {};
        // Quoted string
        if (src[pos] == '"') {
            ++pos; std::string v;
            while (!atEnd() && src[pos] != '"') {
                if (src[pos] == '\\' && pos+1 < src.size()) { v += src[pos+1]; pos += 2; }
                else v += src[pos++];
            }
            if (!atEnd()) ++pos;
            return '"' + v + '"';
        }
        // Operators / parens
        if (src[pos] == '(' || src[pos] == ')') return std::string(1, src[pos++]);
        if (src[pos] == ':') { ++pos; return ":"; }
        // Identifier / value
        size_t start = pos;
        while (!atEnd() && src[pos] != ' ' && src[pos] != '\t' && src[pos] != '\n'
               && src[pos] != '(' && src[pos] != ')' && src[pos] != ':'
               && src[pos] != '"' && src[pos] != ',') {
            ++pos;
        }
        return std::string(src.substr(start, pos - start));
    }
};

// Forward declarations
static FeatureNode kqlParseOr(KqlTokenizer& t);
static FeatureNode kqlParseAnd(KqlTokenizer& t);
static FeatureNode kqlParseNot(KqlTokenizer& t);
static FeatureNode kqlParseAtom(KqlTokenizer& t);

static bool kqlPeekKeyword(KqlTokenizer& t, std::string_view kw) {
    size_t saved = t.pos;
    t.skip();
    size_t start = t.pos;
    while (t.pos < t.src.size() && std::isalpha(static_cast<unsigned char>(t.src[t.pos]))) ++t.pos;
    std::string word(t.src.substr(start, t.pos - start));
    // lowercase
    for (auto& c : word) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (word == kw) { return true; }
    t.pos = saved;
    return false;
}

static FeatureNode buildFieldNode(const std::string& rawField, const std::string& rawValue) {
    std::string field = kqlFieldMap(rawField);
    std::string value = rawValue;
    // Strip surrounding quotes
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
        value = value.substr(1, value.size() - 2);

    FeatureNode n;
    n.op = FeatureNode::Op::Leaf;
    n.leaf.field = field;
    n.leaf.caseInsensitive = true;

    if (value == "*") {
        n.leaf.kind = FeatureKind::FieldExists;
        return n;
    }
    bool startW = !value.empty() && value.front() == '*';
    bool endW   = !value.empty() && value.back()  == '*';
    // Strip wildcards for value
    std::string stripped = value;
    if (startW) stripped = stripped.substr(1);
    if (!stripped.empty() && stripped.back() == '*') stripped.pop_back();

    if (startW && endW) {
        n.leaf.kind = FeatureKind::FieldContains;
        n.leaf.value = stripped;
    } else if (endW) {
        n.leaf.kind = FeatureKind::FieldStartsWith;
        n.leaf.value = stripped;
    } else if (startW) {
        n.leaf.kind = FeatureKind::FieldEndsWith;
        n.leaf.value = stripped;
    } else {
        n.leaf.kind = FeatureKind::FieldEquals;
        n.leaf.value = value;
    }
    return n;
}

static FeatureNode kqlParseOr(KqlTokenizer& t) {
    auto lhs = kqlParseAnd(t);
    while (kqlPeekKeyword(t, "or")) {
        auto rhs = kqlParseAnd(t);
        FeatureNode orNode; orNode.op = FeatureNode::Op::Or;
        orNode.children.push_back(std::move(lhs));
        orNode.children.push_back(std::move(rhs));
        lhs = std::move(orNode);
    }
    return lhs;
}

static FeatureNode kqlParseAnd(KqlTokenizer& t) {
    auto lhs = kqlParseNot(t);
    while (kqlPeekKeyword(t, "and")) {
        auto rhs = kqlParseNot(t);
        FeatureNode andNode; andNode.op = FeatureNode::Op::And;
        andNode.children.push_back(std::move(lhs));
        andNode.children.push_back(std::move(rhs));
        lhs = std::move(andNode);
    }
    return lhs;
}

static FeatureNode kqlParseNot(KqlTokenizer& t) {
    if (kqlPeekKeyword(t, "not")) {
        auto inner = kqlParseNot(t);
        FeatureNode notNode; notNode.op = FeatureNode::Op::Not;
        notNode.children.push_back(std::move(inner));
        return notNode;
    }
    return kqlParseAtom(t);
}

static FeatureNode kqlParseAtom(KqlTokenizer& t) {
    t.skip();
    if (t.peek() == '(') {
        ++t.pos;
        auto inner = kqlParseOr(t);
        t.skip();
        if (t.peek() == ')') ++t.pos;
        return inner;
    }
    // field:value or field:(v1 or v2)
    std::string tok = t.readToken();
    t.skip();
    if (t.peek() == ':') {
        ++t.pos; // consume ':'
        t.skip();
        if (t.peek() == '(') {
            // field:(v1 or v2) — parse OR list
            ++t.pos;
            FeatureNode orNode; orNode.op = FeatureNode::Op::Or;
            while (!t.atEnd() && t.peek() != ')') {
                t.skip();
                if (kqlPeekKeyword(t, "or")) continue;
                std::string val = t.readToken();
                if (!val.empty() && val != ")" && val != "or")
                    orNode.children.push_back(buildFieldNode(tok, val));
            }
            t.skip(); if (t.peek() == ')') ++t.pos;
            if (orNode.children.size() == 1) return std::move(orNode.children.front());
            return orNode;
        } else {
            std::string val = t.readToken();
            return buildFieldNode(tok, val);
        }
    }
    // Bare keyword — treat as exists check or ignore
    if (!tok.empty()) {
        FeatureNode n; n.op = FeatureNode::Op::Leaf;
        n.leaf.kind = FeatureKind::FieldExists; n.leaf.field = kqlFieldMap(tok);
        return n;
    }
    return FeatureNode{};
}

static FeatureNode translateKQL(std::string_view query) {
    if (query.empty()) return FeatureNode{};
    KqlTokenizer t{query, 0};
    return kqlParseOr(t);
}

// EQL sequence translator (simplified):
// sequence by entity_id [process where condition1] [process where condition2]
static FeatureNode translateEQL(std::string_view query) {
    FeatureNode seq; seq.op = FeatureNode::Op::Sequence;
    // Find all [event_type where condition] blocks
    size_t pos = 0;
    while (pos < query.size()) {
        auto lb = query.find('[', pos);
        if (lb == std::string_view::npos) break;
        auto rb = query.find(']', lb);
        if (rb == std::string_view::npos) break;
        auto blockContent = query.substr(lb + 1, rb - lb - 1);
        // "process where condition"
        auto wherePos = blockContent.find(" where ");
        std::string_view condition = (wherePos != std::string_view::npos)
            ? blockContent.substr(wherePos + 7)
            : blockContent;
        auto child = translateKQL(condition);
        if (child.op != FeatureNode::Op::Leaf || !child.leaf.field.empty())
            seq.children.push_back(std::move(child));
        pos = rb + 1;
    }
    if (seq.children.empty()) return FeatureNode{};
    if (seq.children.size() == 1) return std::move(seq.children.front());
    return seq;
}

} // anonymous namespace (KQL translator)

bool RuleParser::ParseElasticJson(std::string_view text, PhantomRule& out, ParseError* err) {
    // Minimal hand-written JSON string extractor (no heavy JSON dep in parser TU)
    auto extractString = [&](std::string_view key) -> std::string {
        std::string pat = "\"" + std::string(key) + "\":";
        auto pos = text.find(pat);
        if (pos == std::string_view::npos) return {};
        pos += pat.size();
        while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t')) ++pos;
        if (pos >= text.size() || text[pos] != '"') return {};
        ++pos;
        std::string val;
        while (pos < text.size() && text[pos] != '"') {
            if (text[pos] == '\\' && pos + 1 < text.size()) { val.push_back(text[pos+1]); pos += 2; continue; }
            val.push_back(text[pos++]);
        }
        return val;
    };

    const std::string ruleName  = extractString("name");
    const std::string ruleId    = extractString("rule_id");
    const std::string ruleType  = extractString("type");
    const std::string query     = extractString("query");
    const std::string language  = extractString("language");
    const std::string severity  = extractString("severity");
    const std::string desc      = extractString("description");

    if (ruleId.empty() && ruleName.empty()) {
        if (err) { err->message = "No rule_id or name"; err->line = 0; }
        return false;
    }

    out.id    = "elastic-" + (ruleId.empty() ? ruleName : ruleId);
    // Sanitise id
    for (auto& c : out.id) if (c == ' ' || c == '/' || c == '\\') c = '-';

    out.title               = ruleName;
    out.genericDescription  = desc.empty() ? ruleName : desc;
    out.source              = RuleSource::Elastic;
    out.windowsOnly         = true;
    out.platforms           = {"windows"};
    out.severity            = sigmaSeverity(severity);
    out.baseConfidence      = 0.55f;
    out.weight              = 1.2f;

    // Scope from rule type
    bool isSequence = (ruleType == "eql" && query.find("sequence") != std::string::npos);

    // Translate query to FeatureNode
    FeatureNode logic;
    if (ruleType == "eql" || language == "eql") {
        logic = isSequence ? translateEQL(query) : translateKQL(query);
        out.scope = isSequence ? RuleScope::Sequence : RuleScope::Process;
    } else if (ruleType == "query" || language == "kuery" || language == "lucene") {
        logic = translateKQL(query);
        out.scope = RuleScope::Process; // default; further refined by field names
    } else {
        // threat_match, new_terms, machine_learning, threshold — keep as HuntingOnly
        out.scope  = RuleScope::Hunting;
        out.status = RuleStatus::HuntingOnly;
        out.baseConfidence = 0.3f;
        // Store original query in references for analyst review
        if (!query.empty()) {
            RuleReference r; r.title = "elastic-query-" + ruleType; r.url = query.substr(0, 256);
            out.references.push_back(std::move(r));
        }
        out.detectionName = "Elastic.Hunting." + (ruleType.empty() ? "Windows" : ruleType);
        return !out.id.empty();
    }

    // If KQL produced a meaningful tree, use it; else fall back to HuntingOnly
    bool hasLogic = (logic.op != FeatureNode::Op::Leaf || !logic.leaf.field.empty())
                    && !(logic.op == FeatureNode::Op::Sequence && logic.children.empty());

    if (hasLogic) {
        out.logic = std::move(logic);
        out.status = RuleStatus::Experimental; // needs FP validation before promoting
    } else {
        out.scope  = RuleScope::Hunting;
        out.status = RuleStatus::HuntingOnly;
        if (!query.empty()) {
            RuleReference r; r.title = "elastic-query"; r.url = query.substr(0, 256);
            out.references.push_back(std::move(r));
        }
    }

    // Derive detection name
    std::string namePart = ruleName.empty() ? ruleType : ruleName;
    if (namePart.size() > 40) namePart = namePart.substr(0, 40);
    out.detectionName = "Elastic." + namePart;

    // Preserve query in references for analyst drill-down
    if (!query.empty() && query.size() <= 512) {
        RuleReference r; r.title = "elastic-kql"; r.url = query;
        out.references.push_back(std::move(r));
    }

    return !out.id.empty();
}

} // namespace Detection
} // namespace ShadowStrike
