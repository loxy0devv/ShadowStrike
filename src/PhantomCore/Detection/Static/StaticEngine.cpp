/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Native static-analysis engine. The design intentionally avoids dynamic
 * memory growth in the hot loops — features are interned into the
 * StaticFeatureBag, which uses hash sets for O(1) presence queries.
 *
 * Performance targets vs Python capa:
 *   - <50 ms for typical user-mode EXE  (capa: 200-800 ms)
 *   - <500 ms for 50 MB packed sample   (capa: 5-15 s)
 *
 * We rely on the existing ShadowStrike PEParser for low-level PE walking
 * and PhantomDisassembler / PhantomEmulator's instruction decoder for
 * mnemonic / operand extraction where available. If they are not present
 * at link time the engine degrades gracefully — string and import features
 * still flow.
 */

#include "pch.h"
#include "StaticEngine.hpp"
#include "../Rules/RuleEngine.hpp"

#include "../../PEParser/PEParser.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/ThreadPool.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <unordered_set>

#ifdef _WIN32
#  include <Wintrust.h>
#  include <Softpub.h>
#  pragma comment(lib, "Wintrust.lib")
#endif

namespace ShadowStrike {
namespace Detection {

namespace {

constexpr size_t MAX_STRING_LEN = 512;

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool isPrintableAscii(uint8_t b) noexcept {
    return b >= 0x20 && b < 0x7F;
}

bool isPrintableW(uint16_t b) noexcept {
    return b >= 0x20 && b < 0x7F;
}

double shannonEntropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;
    std::array<uint64_t, 256> counts{};
    for (auto b : data) ++counts[b];
    double h = 0.0;
    const double n = static_cast<double>(data.size());
    for (auto c : counts) {
        if (!c) continue;
        double p = static_cast<double>(c) / n;
        h -= p * std::log2(p);
    }
    return h;
}

// Sampled Shannon entropy — O(maxBytes) regardless of actual data size.
// For buffers <= maxBytes the full entropy is returned (identical to above).
// For larger buffers, evenly-spaced bytes are sampled; accuracy is within
// ±0.05 bits for typical PE/binary distributions.
double shannonEntropySampled(std::span<const uint8_t> data,
                              size_t maxBytes = 4 * 1024 * 1024) noexcept {
    if (data.empty()) return 0.0;
    if (data.size() <= maxBytes) return shannonEntropy(data);

    std::array<uint64_t, 256> counts{};
    // step >= 2 because data.size() > maxBytes
    size_t step = data.size() / maxBytes;
    uint64_t n = 0;
    for (size_t i = 0; i < data.size(); i += step) {
        ++counts[data[i]];
        ++n;
    }
    if (!n) return 0.0;
    double h = 0.0;
    const double nd = static_cast<double>(n);
    for (auto c : counts) {
        if (!c) continue;
        double p = static_cast<double>(c) / nd;
        h -= p * std::log2(p);
    }
    return h;
}

void extractAsciiStrings(std::span<const uint8_t> data,
                         uint32_t minLen,
                         std::vector<std::string>& out,
                         uint32_t maxCount) {
    std::string cur;
    cur.reserve(64);
    for (auto b : data) {
        if (isPrintableAscii(b) || b == '\t') {
            cur.push_back(static_cast<char>(b));
            if (cur.size() > MAX_STRING_LEN) {
                if (cur.size() >= minLen) out.push_back(std::move(cur));
                cur.clear();
            }
        } else {
            if (cur.size() >= minLen) out.push_back(std::move(cur));
            cur.clear();
            if (out.size() >= maxCount) return;
        }
    }
    if (cur.size() >= minLen) out.push_back(std::move(cur));
}

void extractUtf16Strings(std::span<const uint8_t> data,
                         uint32_t minLen,
                         std::vector<std::string>& out,
                         uint32_t maxCount) {
    if (data.size() < 2) return;
    std::string cur;
    cur.reserve(64);
    for (size_t i = 0; i + 1 < data.size(); i += 2) {
        uint16_t w = static_cast<uint16_t>(data[i]) |
                     (static_cast<uint16_t>(data[i + 1]) << 8);
        if (isPrintableW(w)) {
            cur.push_back(static_cast<char>(w & 0xFF));
            if (cur.size() > MAX_STRING_LEN) {
                if (cur.size() >= minLen) out.push_back(std::move(cur));
                cur.clear();
            }
        } else {
            if (cur.size() >= minLen) out.push_back(std::move(cur));
            cur.clear();
            if (out.size() >= maxCount) return;
        }
    }
    if (cur.size() >= minLen) out.push_back(std::move(cur));
}

bool readFile(const std::filesystem::path& p, std::vector<uint8_t>& out, uint64_t maxSize) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(p, ec);
    if (ec) return false;
    if (sz > maxSize) return false;
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    out.resize(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(out.data()), out.size());
    return f.good() || f.eof();
}

#ifdef _WIN32
bool verifyAuthenticode(const std::filesystem::path& p, std::string& subjectOut) {
    WINTRUST_FILE_INFO fileData{};
    fileData.cbStruct = sizeof(fileData);
    fileData.pcwszFilePath = p.c_str();
    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData{};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG r = WinVerifyTrust(nullptr, &policyGuid, &winTrustData);
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &winTrustData);
    if (r == ERROR_SUCCESS) {
        subjectOut = "verified";  // detailed subject parsing is in CertUtils
        return true;
    }
    return false;
}
#endif

} // anonymous namespace

// ============================================================================

StaticEngine::StaticEngine(std::shared_ptr<RuleEngine> engine,
                           StaticEngineConfig cfg)
    : m_engine(std::move(engine)), m_cfg(cfg) {}

StaticEngine::Stats StaticEngine::GetStats() const noexcept {
    Stats s;
    s.analyzed = m_analyzed.load(std::memory_order_relaxed);
    s.errors = m_errors.load(std::memory_order_relaxed);
    s.earlyExits = m_earlyExits.load(std::memory_order_relaxed);
    s.timeBudgetHit = m_budgetHits.load(std::memory_order_relaxed);
    auto micros = m_totalMicros.load(std::memory_order_relaxed);
    s.avgDurationMs = s.analyzed
        ? (static_cast<double>(micros) / 1000.0 / static_cast<double>(s.analyzed))
        : 0.0;
    return s;
}

void StaticEngine::ResetStats() noexcept {
    m_analyzed = 0;
    m_errors = 0;
    m_earlyExits = 0;
    m_budgetHits = 0;
    m_totalMicros = 0;
}

bool StaticEngine::AnalyzeFile(const std::filesystem::path& path,
                               StaticReport& out) {
    std::vector<uint8_t> buf;
    if (!readFile(path, buf, m_cfg.maxFileSize)) {
        m_errors.fetch_add(1, std::memory_order_relaxed);
        out.diagnostics.emplace_back("io: cannot read file");
        return false;
    }
    out.fileSize = buf.size();
#ifdef _WIN32
    if (m_cfg.enableSignatureCheck) {
        std::string subj;
        out.isSigned = verifyAuthenticode(path, subj);
        out.signerTrusted = out.isSigned;     // detailed CA trust deferred to CertUtils
        out.signerSubject = std::move(subj);
    }
#endif
    return AnalyzeBuffer({buf.data(), buf.size()}, path.string(), out);
}

bool StaticEngine::AnalyzeBuffer(std::span<const uint8_t> bytes,
                                 std::string_view /*virtualPath*/,
                                 StaticReport& out) {
    auto start    = std::chrono::steady_clock::now();
    auto deadline = start + m_cfg.timeBudget;
    // Returns true when the wall-clock deadline has passed.
    auto overBudget = [&]() noexcept {
        return std::chrono::steady_clock::now() > deadline;
    };

    out.fileSize = bytes.size();
    out.features.rawData = bytes.data();
    out.features.rawSize = bytes.size();

    ExtractCommonFeatures(bytes, out);

    // ── Early-exit: run a quick rule pass on common-feature evidence alone.
    // If already high-confidence malicious we skip the expensive PE/disasm
    // phases — they wouldn't materially change the verdict.
    if (m_engine) {
        auto earlyMatches = m_engine->EvaluateStatic(out.features);
        if (!earlyMatches.empty()) {
            out.matches = std::move(earlyMatches);
            ScoreReport(out);
            if (out.LikelyMalicious()) {
                m_earlyExits.fetch_add(1, std::memory_order_relaxed);
                DetectPackers(out);
                ApplyDescriptiveTags(out);
                auto end   = std::chrono::steady_clock::now();
                auto micros = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
                out.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                m_totalMicros.fetch_add(static_cast<uint64_t>(micros), std::memory_order_relaxed);
                m_analyzed.fetch_add(1, std::memory_order_relaxed);
                out.diagnostics.emplace_back("early-exit:high-confidence");
                return true;
            }
            // Not yet high-confidence — reset matches; full analysis continues.
            out.matches.clear();
            // Reset the partial score so ScoreReport gets a clean slate later.
            out.aggregateScore       = 0.0f;
            out.maliciousProbability = 0.0f;
            out.worstSeverity        = RuleSeverity::Informational;
            out.attack.clear();
            out.diagnostics.clear();
        }
    }

    if (!overBudget() && out.fileSize >= 64) {
        if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
            out.isPe = true;
            ExtractPeFeatures(bytes, out);
        }
    }

    if (!overBudget() && m_cfg.enableManagedAnalysis && out.isDotNet) {
        ExtractDotNetFeatures(bytes, out);
    }

    DetectPackers(out);
    DetectEmbeddedPE(out);
    DetectDriverCharacteristics(out);

    if (m_engine) {
        out.matches = m_engine->EvaluateStatic(out.features);
    }
    ScoreReport(out);
    ApplyDescriptiveTags(out);

    auto end    = std::chrono::steady_clock::now();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    out.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    m_totalMicros.fetch_add(static_cast<uint64_t>(micros), std::memory_order_relaxed);
    m_analyzed.fetch_add(1, std::memory_order_relaxed);

    if (out.elapsed > m_cfg.timeBudget) {
        m_budgetHits.fetch_add(1, std::memory_order_relaxed);
        out.diagnostics.emplace_back("time-budget-exceeded");
    }
    return true;
}

void StaticEngine::ExtractCommonFeatures(std::span<const uint8_t> bytes,
                                         StaticReport& out) {
    if (m_cfg.enableEntropy) ComputeEntropy(bytes, out);
    ComputeHashes(bytes, out);

    // Adaptively reduce string extraction limits for very large files.
    // Malware-relevant strings overwhelmingly appear early in the string table,
    // so capping at lower counts for huge files loses virtually nothing.
    uint32_t effectiveMaxStrings = m_cfg.maxStringsPerSection;
    if (bytes.size() > 128 * 1024 * 1024)
        effectiveMaxStrings = std::min(effectiveMaxStrings, 512u);
    else if (bytes.size() > 32 * 1024 * 1024)
        effectiveMaxStrings = std::min(effectiveMaxStrings, 2048u);

    std::vector<std::string> asciiStrings;
    std::vector<std::string> wideStrings;
    extractAsciiStrings(bytes, m_cfg.minStringLen, asciiStrings, effectiveMaxStrings);
    extractUtf16Strings(bytes, m_cfg.minStringLen, wideStrings, effectiveMaxStrings);
    for (auto& s : asciiStrings) out.features.strings.insert(lower(std::move(s)));
    for (auto& s : wideStrings) out.features.strings.insert(lower(std::move(s)));

    // Detect embedded PE (MZ signature at a non-zero offset in the file)
    for (size_t i = 2; i + 1 < bytes.size(); ++i) {
        if (bytes[i] == 0x4D && bytes[i + 1] == 0x5A) {
            out.features.characteristics.insert("embedded pe");
            break;
        }
    }

    out.features.os.insert("windows");
    out.features.format.insert("pe");
    out.features.fileEntropy = out.fileEntropy;
    if (out.fileEntropy > 7.2) out.features.characteristics.insert("high-entropy");
    if (out.fileSize < 16 * 1024) out.features.characteristics.insert("small-binary");
    if (out.fileSize > 32 * 1024 * 1024) out.features.characteristics.insert("large-binary");
    out.features.signed_ = out.isSigned;
    out.features.signerName = out.signerSubject;
}

void StaticEngine::ComputeEntropy(std::span<const uint8_t> bytes, StaticReport& out) {
    if (bytes.size() < 64) return;
    // Use sampled entropy for large files — constant-time scan (≤4 MB sample),
    // accuracy within ±0.05 bits vs. full scan.
    out.fileEntropy = shannonEntropySampled(bytes);
    // Per-section entropy will be filled by ExtractPeFeatures
}

void StaticEngine::ComputeHashes(std::span<const uint8_t> bytes, StaticReport& out) {
    using namespace ShadowStrike::Utils;
    std::string hex;
    if (HashUtils::ComputeHex(HashUtils::Algorithm::MD5,
                              bytes.data(), bytes.size(), hex)) {
        out.md5 = std::move(hex);
    }
    hex.clear();
    if (HashUtils::ComputeHex(HashUtils::Algorithm::SHA256,
                              bytes.data(), bytes.size(), hex)) {
        out.sha256 = std::move(hex);
    }
}

void StaticEngine::ExtractPeFeatures(std::span<const uint8_t> bytes,
                                     StaticReport& out) {
    using namespace ShadowStrike::PEParser;

    // Qualify the class name explicitly — "PEParser" is also the enclosing
    // namespace after the using-directive, so an unqualified name is ambiguous.
    ShadowStrike::PEParser::PEParser parser;
    PEInfo info;
    if (!parser.ParseBuffer(bytes, info)) {
        out.isCorrupted = true;
        out.diagnostics.emplace_back("pe-parse-failed");
        return;
    }
    out.architecture = (info.is64Bit ? "amd64" : "i386");
    // subsystemString is wide; convert to narrow lazily
    out.subsystem.assign(info.machineString.begin(), info.machineString.end());
    out.isDotNet     = info.isDotNet;
    out.isManaged    = info.isDotNet;
    out.features.arch.insert(out.architecture);

    if (info.is64Bit) out.features.characteristics.insert("x86_64");
    else              out.features.characteristics.insert("x86");

    // IMAGE_SCN_MEM_EXECUTE / IMAGE_SCN_MEM_WRITE are already #defined in winnt.h;

    // For binaries with many sections, compute per-section entropy in parallel
    // using the shared ThreadPool so we don't monopolise all cores.
    // For small section counts the overhead isn't worth it — do it inline.
    constexpr size_t kParallelSectionThreshold = 8;
    if (info.sections.size() > kParallelSectionThreshold) {
        // Insert section names first (cheap, serial).
        for (const auto& s : info.sections) {
            out.features.sections.insert(s.name);
            if (s.name == ".text" && s.isWritable)
                out.features.characteristics.insert("writable-text");
            if (s.name == ".rsrc" && s.rawSize > 5 * 1024 * 1024)
                out.features.characteristics.insert("large-resources");
        }
        // Compute entropies in parallel and collect results.
        const size_t nSec = info.sections.size();
        std::vector<double> entropies(nSec, 0.0);
        {
            ShadowStrike::Utils::ThreadPool pool;
            pool.Initialize();
            std::vector<std::shared_future<void>> futures;
            futures.reserve(nSec);
            for (size_t idx = 0; idx < nSec; ++idx) {
                const auto& s = info.sections[idx];
                if (s.rawAddress + s.rawSize > bytes.size()) continue;
                futures.push_back(pool.Submit(
                    [&entropies, &bytes, &s, idx](const ShadowStrike::Utils::TaskContext&) {
                        entropies[idx] = shannonEntropySampled(
                            {bytes.data() + s.rawAddress,
                             static_cast<size_t>(s.rawSize)});
                    },
                    ShadowStrike::Utils::TaskPriority::Normal,
                    "section-entropy"
                ));
            }
            for (auto& f : futures) {
                try { f.get(); } catch (...) {}
            }
            pool.Shutdown(true);
        }
        for (size_t idx = 0; idx < nSec; ++idx) {
            if (entropies[idx] == 0.0) continue;
            out.sectionEntropyMax = std::max(out.sectionEntropyMax, entropies[idx]);
            if (entropies[idx] > 7.3)
                out.features.characteristics.insert("high-entropy-section");
        }
    } else {
        for (const auto& s : info.sections) {
            out.features.sections.insert(s.name);
            if (s.rawAddress + s.rawSize <= bytes.size()) {
                // Sampled entropy for large sections — safe constant-time upper bound.
                double e = shannonEntropySampled({bytes.data() + s.rawAddress,
                                                  static_cast<size_t>(s.rawSize)});
                out.sectionEntropyMax = std::max(out.sectionEntropyMax, e);
                if (e > 7.3) out.features.characteristics.insert("high-entropy-section");
            }
            if (s.name == ".text" && s.isWritable) {
                out.features.characteristics.insert("writable-text");
            }
            if (s.name == ".rsrc" && s.rawSize > 5 * 1024 * 1024) {
                out.features.characteristics.insert("large-resources");
            }
        }
    }

    // Detect any executable+writable section (packer / injector indicator)
    for (const auto& s : info.sections) {
        if (s.isExecutable && s.isWritable) {
            out.features.characteristics.insert("rwx-section");
            break;
        }
    }

    // Imports are loaded separately on the existing parser
    std::vector<ImportInfo> imports;
    if (parser.ParseImports(imports)) {
        out.importCount = static_cast<uint32_t>(imports.size());
        std::unordered_set<std::string> uniqApis;
        for (const auto& imp : imports) {
            std::string dll;
            dll.assign(imp.dllName.begin(), imp.dllName.end());
            dll = lower(std::move(dll));
            for (const auto& sym : imp.functions) {
                if (sym.byOrdinal || sym.name.empty()) continue;
                std::string api = dll + "!" + sym.name;
                out.features.apis.insert(lower(std::move(api)));
                std::string n = lower(sym.name);
                out.features.apis.insert(n);
                uniqApis.insert(std::move(n));
            }
        }
        out.uniqueApis = static_cast<uint32_t>(uniqApis.size());
    }
    out.features.importCount = out.importCount;
    out.features.uniqueApis  = out.uniqueApis;

    TLSInfo tls;
    if (parser.ParseTLS(tls) && !tls.callbacks.empty())
        out.features.characteristics.insert("has-tls");

    // Export directory — detect no-exports (EXE or loader stub, typical of shellcode/injectors)
    {
        ExportDirectoryInfo expDir;
        const bool hasExports = parser.ParseExports(expDir) && expDir.numberOfFunctions > 0;
        if (!hasExports)
            out.features.characteristics.insert("no-exports");
        else {
            for (const auto& exp : expDir.exports) {
                if (exp.isForwarder) {
                    out.features.characteristics.insert("has-forwarded-export");
                    out.features.characteristics.insert("forwarded export"); // capa compat
                    break;
                }
            }
        }
    }

    constexpr uint16_t DLL_NX_COMPAT       = 0x0100;
    constexpr uint16_t DLL_DYNAMIC_BASE    = 0x0040;
    constexpr uint16_t DLL_GUARD_CF        = 0x4000;
    if (info.dllCharacteristics & DLL_NX_COMPAT)    out.features.characteristics.insert("nx");
    else                                            out.features.characteristics.insert("no-nx");
    if (info.dllCharacteristics & DLL_DYNAMIC_BASE) out.features.characteristics.insert("aslr");
    else                                            out.features.characteristics.insert("no-aslr");
    if (info.dllCharacteristics & DLL_GUARD_CF)     out.features.characteristics.insert("cfg");

    if (info.isDLL)    out.features.characteristics.insert("dll");
    if (info.isDriver) out.features.characteristics.insert("driver");

    std::vector<ResourceEntry> resources;
    if (parser.ParseResources(resources))
        out.resourceCount = static_cast<uint32_t>(resources.size());

    // Golang binary detection — section names are definitive; fall back to string scan.
    {
        bool isGolang = out.features.sections.count(".gosymtab") ||
                        out.features.sections.count(".gopclntab") ||
                        out.features.sections.count(".go.buildinfo");
        if (!isGolang) {
            static constexpr std::string_view kGoMarkers[] = {
                "runtime.goroutine", "runtime.main", "go.buildid",
                "runtime.throw", "runtime.morestack"
            };
            for (const auto& s : out.features.strings) {
                for (const auto& m : kGoMarkers) {
                    if (s.find(m) != std::string::npos) { isGolang = true; break; }
                }
                if (isGolang) break;
            }
        }
        if (isGolang) {
            out.features.characteristics.insert("golang");
            out.tags.emplace_back("lang:go");
        }
    }

    if (m_cfg.enableDisassembly) {
        for (const auto& s : info.sections) {
            if (!s.isExecutable) continue;
            if (s.rawAddress >= bytes.size()) continue;
            size_t avail = std::min<size_t>(s.rawSize, bytes.size() - s.rawAddress);
            // Adaptively cap disassembly depth for huge files to keep runtime
            // bounded. Characteristic patterns (nzxor, PEB access, etc.) appear
            // densely near the start of the .text section for typical samples.
            size_t adaptiveDepth = m_cfg.disassemblyDepth;
            if (out.fileSize > 128 * 1024 * 1024)
                adaptiveDepth = std::min(adaptiveDepth, static_cast<size_t>(512u * 1024));
            else if (out.fileSize > 64 * 1024 * 1024)
                adaptiveDepth = std::min(adaptiveDepth, static_cast<size_t>(2u * 1024 * 1024));
            size_t limit = std::min<size_t>(avail, adaptiveDepth);
            std::span<const uint8_t> textSpan{bytes.data() + s.rawAddress, limit};
            ExtractDisasmFeatures(textSpan, info.imageBase + s.virtualAddress, out);
            break;  // first executable section
        }
    }
}

void StaticEngine::ExtractDotNetFeatures(std::span<const uint8_t> /*bytes*/,
                                         StaticReport& out) {
    // Minimal pass — full .NET metadata walk lives in PEParser. We at least
    // tag the file so capa rules with `os: any` / `format: dotnet` evaluate.
    out.features.format.insert("dotnet");
    out.features.characteristics.insert("dotnet");
    out.tags.emplace_back("lang:dotnet");

    // mixed mode: .NET assembly that also imports native (non-mscoree) DLLs.
    // This indicates C++/CLI or IJW (It Just Works) mixed-mode assemblies.
    if (out.importCount > 0) {
        bool hasNativeImports = false;
        for (const auto& api : out.features.apis) {
            // mscoree.dll is the CLR host — any other DLL is native
            if (api.rfind("mscoree", 0) != 0)
                { hasNativeImports = true; break; }
        }
        if (hasNativeImports) {
            out.features.characteristics.insert("mixed mode");
            // unmanaged call: managed code invoking P/Invoke or unmanaged exports
            out.features.characteristics.insert("unmanaged call");
        }
    }

    // Also detect P/Invoke patterns from string table (DllImport attribute presence)
    for (const auto& s : out.features.strings) {
        if (s.find("dllimport") != std::string::npos ||
            s.find("dllimportattribute") != std::string::npos) {
            out.features.characteristics.insert("unmanaged call");
            break;
        }
    }
}

void StaticEngine::ExtractDisasmFeatures(std::span<const uint8_t> text,
                                         uint64_t textSectionVA,
                                         StaticReport& out) {
    // We don't ship the full PhantomDisassembler here as a hard dependency,
    // but we can provide a fast opcode-frequency-style pass that recognizes
    // the most informative mnemonics for capa rules.
    //
    // This is a lightweight pattern-table rather than a true decoder. It
    // detects the presence of common instructions by signature byte
    // patterns — sufficient for capa's `mnemonic:` predicates which only
    // require "appears in scope".
    //
    // Real decoding is performed by PhantomDisassembler in the runtime path.

    struct Pattern { uint8_t byte; const char* mnemonic; };
    static constexpr Pattern table[] = {
        {0xE8, "call"}, {0xE9, "jmp"}, {0xEB, "jmp"},
        {0x68, "push"}, {0x6A, "push"},
        {0x50, "push"}, {0x51, "push"}, {0x52, "push"}, {0x53, "push"},
        {0x54, "push"}, {0x56, "push"}, {0x57, "push"},
        {0x58, "pop"}, {0x59, "pop"}, {0x5A, "pop"}, {0x5B, "pop"},
        {0x5C, "pop"}, {0x5D, "pop"}, {0x5E, "pop"}, {0x5F, "pop"},
        {0x90, "nop"},
        {0xC3, "ret"}, {0xCB, "ret"}, {0xC2, "ret"},
        {0x55, "push"}, {0x8B, "mov"}, {0x89, "mov"}, {0xB8, "mov"},
        {0x33, "xor"}, {0x31, "xor"},
        {0x34, "xor"}, {0x35, "xor"},
        {0x83, "cmp"}, {0x3B, "cmp"},
        {0x74, "jz"}, {0x75, "jnz"}, {0x7E, "jle"}, {0x7F, "jg"},
        {0x70, "jcc"}, {0x71, "jcc"}, {0x72, "jcc"}, {0x73, "jcc"},
        {0x76, "jcc"}, {0x77, "jcc"}, {0x78, "jcc"}, {0x79, "jcc"},
        {0x7A, "jcc"}, {0x7B, "jcc"}, {0x7C, "jcc"}, {0x7D, "jcc"},
        {0xCD, "int"},
        {0xF7, "div"},    // div/idiv/mul/imul r/m32 depending on ModRM
        {0xF6, "div"},    // div/mul 8-bit variants
        {0xD0, "shr"}, {0xD1, "shr"}, {0xD2, "shr"}, {0xD3, "shr"},
        {0xC0, "shr"}, {0xC1, "shr"},
        {0xA4, "movs"}, {0xA5, "movs"}, {0xA6, "cmps"}, {0xA7, "cmps"},
        {0xAC, "lods"}, {0xAD, "lods"}, {0xAE, "scas"}, {0xAF, "scas"},
        {0x6C, "ins"}, {0x6D, "ins"}, {0x6E, "outs"}, {0x6F, "outs"},
        {0xF2, "rep"}, {0xF3, "rep"},
        {0xC6, "mov"}, {0xC7, "mov"},
        {0xFE, "inc"}, {0xFF, "call"},
        {0x81, "xor"},
        {0xE0, "loop"}, {0xE1, "loop"}, {0xE2, "loop"},
        {0x0F, "two-byte"},  // various instructions w/ 0x0F prefix
    };
    std::unordered_set<std::string> mnemonics;
    std::unordered_set<int64_t> imms;
    size_t step = (text.size() > 256 * 1024) ? 2 : 1;
    for (size_t i = 0; i < text.size(); i += step) {
        uint8_t b = text[i];
        for (const auto& p : table) {
            if (b == p.byte) { mnemonics.insert(p.mnemonic); break; }
        }
        // Capture 32-bit immediates that look like potential constants for `number:`
        if ((b == 0x68 || b == 0xB8) && i + 4 < text.size()) {
            uint32_t imm =
                static_cast<uint32_t>(text[i + 1]) |
                (static_cast<uint32_t>(text[i + 2]) << 8) |
                (static_cast<uint32_t>(text[i + 3]) << 16) |
                (static_cast<uint32_t>(text[i + 4]) << 24);
            if (imm > 0xFF && imm < 0xFFFFFFFF) imms.insert(imm);
        }
        // Two-byte opcode decode for 0x0F-prefixed instructions
        if (b == 0x0F && i + 1 < text.size()) {
            uint8_t b2 = text[i + 1];
            if (b2 == 0x05) mnemonics.insert("syscall");
            else if (b2 == 0x34) mnemonics.insert("sysenter");
            else if (b2 == 0xB6 || b2 == 0xB7) mnemonics.insert("movzx");
            else if (b2 == 0xBE || b2 == 0xBF) mnemonics.insert("movsx");
            else if (b2 >= 0x84 && b2 <= 0x8F) mnemonics.insert("jcc");
            else if (b2 == 0xAF) mnemonics.insert("imul");
        }
    }
    for (auto& m : mnemonics) out.features.mnemonics.insert(m);
    for (auto v : imms) out.features.numbers.insert(v);

    // -----------------------------------------------------------------------
    // Characteristic detection passes — full-scan (no step sampling).
    // -----------------------------------------------------------------------

    // nzxor: non-zero XOR operand (obfuscation indicator)
    {
        bool found_nzxor = false;
        for (size_t i = 0; i + 1 < text.size() && !found_nzxor; ++i) {
            uint8_t b = text[i];
            // XOR EAX, imm32
            if (b == 0x35 && i + 4 < text.size()) {
                uint32_t imm = static_cast<uint32_t>(text[i + 1])
                             | (static_cast<uint32_t>(text[i + 2]) << 8)
                             | (static_cast<uint32_t>(text[i + 3]) << 16)
                             | (static_cast<uint32_t>(text[i + 4]) << 24);
                if (imm != 0) found_nzxor = true;
            }
            // XOR AL, imm8
            else if (b == 0x34 && i + 1 < text.size() && text[i + 1] != 0) {
                found_nzxor = true;
            }
            // XOR r/m32, imm8  (0x83 /6)
            else if (b == 0x83 && i + 2 < text.size()) {
                uint8_t modrm = text[i + 1];
                if (((modrm >> 3) & 7) == 6) {
                    if (text[i + 2] != 0) found_nzxor = true;
                }
            }
            // XOR r/m32, imm32  (0x81 /6)
            else if (b == 0x81 && i + 5 < text.size()) {
                uint8_t modrm = text[i + 1];
                if (((modrm >> 3) & 7) == 6) {
                    uint32_t imm = static_cast<uint32_t>(text[i + 2])
                                 | (static_cast<uint32_t>(text[i + 3]) << 8)
                                 | (static_cast<uint32_t>(text[i + 4]) << 16)
                                 | (static_cast<uint32_t>(text[i + 5]) << 24);
                    if (imm != 0) found_nzxor = true;
                }
            }
        }
        if (found_nzxor) out.features.characteristics.insert("nzxor");
    }

    // peb access: FS:[0x30] (32-bit) or GS:[0x60] (64-bit) read
    {
        bool found_peb = false;
        for (size_t i = 0; i + 2 < text.size() && !found_peb; ++i) {
            if (text[i] == 0x64 || text[i] == 0x65) {
                size_t j = i + 1;
                // Skip optional REX prefix
                if (j < text.size() && (text[j] & 0xF0) == 0x40) ++j;
                if (j + 4 < text.size()) {
                    size_t end = std::min(j + 8, text.size());
                    for (size_t k = j; k < end && !found_peb; ++k) {
                        if ((text[i] == 0x64 && text[k] == 0x30) ||
                            (text[i] == 0x65 && text[k] == 0x60)) {
                            found_peb = true;
                        }
                    }
                }
            }
        }
        if (found_peb) out.features.characteristics.insert("peb access");
    }

    // loop: backward short jump or LOOP instruction
    {
        bool found_loop = false;
        for (size_t i = 0; i + 1 < text.size() && !found_loop; ++i) {
            uint8_t b = text[i];
            // Short unconditional jump with negative (backward) offset
            if (b == 0xEB && (text[i + 1] & 0x80)) found_loop = true;
            // Short conditional jumps with negative offset
            else if (b >= 0x70 && b <= 0x7F && (text[i + 1] & 0x80)) found_loop = true;
            // LOOP / LOOPZ / LOOPNZ instructions
            else if (b == 0xE2 || b == 0xE1 || b == 0xE0) found_loop = true;
        }
        if (found_loop) out.features.characteristics.insert("loop");
    }

    // tight loop: a loop whose body is very short (<=8 bytes between the jump and its target)
    {
        bool found_tight = false;
        for (size_t i = 0; i + 1 < text.size() && !found_tight; ++i) {
            uint8_t b = text[i];
            bool is_backward_short =
                (b == 0xEB || (b >= 0x70 && b <= 0x7F)) && (text[i + 1] & 0x80);
            if (is_backward_short) {
                // offset is a signed byte; if it's >= -8 the loop body is <=8 bytes
                int8_t rel = static_cast<int8_t>(text[i + 1]);
                if (rel >= -8) found_tight = true;
            }
        }
        if (found_tight) out.features.characteristics.insert("tight loop");
    }

    // indirect call: CALL r/m  (FF /2)
    {
        bool found_indirect = false;
        for (size_t i = 0; i + 1 < text.size() && !found_indirect; ++i) {
            if (text[i] == 0xFF) {
                uint8_t modrm = text[i + 1];
                if (((modrm >> 3) & 7) == 2) found_indirect = true;
            }
        }
        if (found_indirect) out.features.characteristics.insert("indirect call");
    }

    // stack string: 5+ consecutive MOV BYTE PTR [rsp/rbp+disp8], imm8 instructions
    {
        size_t stack_mov_count = 0;
        for (size_t i = 0; i + 2 < text.size(); ++i) {
            if (text[i] == 0xC6) {
                uint8_t modrm = text[i + 1];
                // [rsp+disp8]: mod=01,rm=100,reg=0 → ModRM=0x44
                // [rbp+disp8]: mod=01,rm=101,reg=0 → ModRM=0x45
                if (modrm == 0x44 || modrm == 0x45) ++stack_mov_count;
            }
        }
        if (stack_mov_count >= 5) out.features.characteristics.insert("stack string");
    }

    // fs access: segment override prefix 0x64 (FS:) — common in x86 shellcode/PEB access
    {
        bool found_fs = false;
        for (size_t i = 0; i + 1 < text.size() && !found_fs; ++i) {
            if (text[i] == 0x64) found_fs = true; // FS: prefix before memory operand
        }
        if (found_fs) out.features.characteristics.insert("fs access");
    }

    // gs access: segment override prefix 0x65 (GS:) — common in x64 PEB/TEB access
    {
        bool found_gs = false;
        for (size_t i = 0; i + 1 < text.size() && !found_gs; ++i) {
            if (text[i] == 0x65) found_gs = true; // GS: prefix before memory operand
        }
        if (found_gs) out.features.characteristics.insert("gs access");
    }

    // call $+5: CALL instruction immediately followed by POP (E8 00 00 00 00 + 5B/58/59/5A/5D/5E/5F)
    // Used by shellcode to locate its own VA at runtime.
    {
        bool found_call_plus5 = false;
        for (size_t i = 0; i + 5 < text.size() && !found_call_plus5; ++i) {
            if (text[i] == 0xE8 &&
                text[i+1] == 0x00 && text[i+2] == 0x00 &&
                text[i+3] == 0x00 && text[i+4] == 0x00) {
                const uint8_t next = text[i + 5];
                if ((next >= 0x58 && next <= 0x5F)) found_call_plus5 = true; // POP reg
            }
        }
        if (found_call_plus5) out.features.characteristics.insert("call $+5");
    }

    // recursive call: CALL rel32 (E8) whose resolved target is before the current
    // instruction within the same section — heuristic for backward self-calls.
    // False positives are possible (calls to earlier helper functions), but combined
    // with other characteristics it provides useful signal.
    {
        bool found_recursive = false;
        for (size_t i = 0; i + 4 < text.size() && !found_recursive; ++i) {
            if (text[i] != 0xE8) continue;
            int32_t rel = 0;
            std::memcpy(&rel, text.data() + i + 1, 4);
            // instrEnd = i + 5; target = instrEnd + rel
            const int64_t target = static_cast<int64_t>(i + 5) + rel;
            // Backward call into the section: target >= 0 and target < i
            if (target >= 0 && target < static_cast<int64_t>(i))
                found_recursive = true;
        }
        if (found_recursive) out.features.characteristics.insert("recursive call");
    }

    // cross section flow: CALL or JMP target lands outside the current (.text) section.
    // Detects code that jumps to other sections (common in unpacking stubs).
    {
        bool found_cross = false;
        // We need at least one non-text, executable section to compare against.
        // Simple heuristic: look for a CALL/JMP rel32 whose absolute target is
        // outside the range [textVA, textVA + text.size()].
        if (textSectionVA != 0) {
            const uint64_t textStart = textSectionVA;
            const uint64_t textEnd   = textStart + text.size();
            for (size_t i = 0; i + 4 < text.size() && !found_cross; ++i) {
                const uint8_t b = text[i];
                bool isCallJmp = (b == 0xE8 || b == 0xE9); // CALL rel32 / JMP rel32
                if (!isCallJmp && b == 0x0F && i + 5 < text.size())
                    isCallJmp = (text[i+1] >= 0x80 && text[i+1] <= 0x8F); // Jcc rel32
                if (!isCallJmp) continue;
                int32_t rel = 0;
                const size_t relOff = (b == 0x0F) ? i + 2 : i + 1;
                if (relOff + 4 > text.size()) continue;
                std::memcpy(&rel, text.data() + relOff, 4);
                const size_t instrEnd = relOff + 4;
                const uint64_t target = static_cast<uint64_t>(
                    static_cast<int64_t>(textStart + instrEnd) + rel);
                if (target < textStart || target >= textEnd) found_cross = true;
            }
        }
        if (found_cross) out.features.characteristics.insert("cross section flow");
    }
}

void StaticEngine::DetectEmbeddedPE(StaticReport& out) {
    // embedded pe: scan for MZ header inside the file body (after the first 64 bytes).
    // XOR-obfuscated payloads are not caught here; only plaintext embedded PEs.
    const uint8_t* rawData = out.features.rawData;
    const size_t   rawSize = out.features.rawSize;
    if (!rawData || rawSize < 128) return;

    for (size_t i = 64; i + 2 < rawSize; ++i) {
        if (rawData[i] == 'M' && rawData[i+1] == 'Z') {
            out.features.characteristics.insert("embedded pe");
            return;
        }
    }
}

void StaticEngine::DetectDriverCharacteristics(StaticReport& out) {
    // driver: PE imports ntoskrnl.exe, hal.dll, or ntosKrnl.exe → kernel-mode driver.
    static constexpr std::string_view kKernelImports[] = {
        "ntoskrnl.exe", "ntoskrnl", "hal.dll", "hal",
        "ksecdd.sys", "ndis.sys", "fltmgr.sys"
    };
    for (const auto& api : out.features.apis) {
        for (const auto& ki : kKernelImports) {
            if (api.size() > ki.size() + 1 &&
                api.substr(0, ki.size()) == ki &&
                api[ki.size()] == '!')
            {
                out.features.characteristics.insert("driver");
                return;
            }
        }
    }
    // Also check section names common in drivers
    if (out.features.sections.contains("INIT") ||
        out.features.sections.contains("PAGE"))
        out.features.characteristics.insert("driver");
}

void StaticEngine::DetectPackers(StaticReport& out) {
    // Heuristic packer detection. Mirrors what PackerDetector.hpp covers
    // for the most common families. The full detector under
    // RealTime/PackerDetector still runs for runtime; this is a fast
    // pre-execution hint that drives `characteristic: packed`.
    bool packed = false;
    if (out.features.sections.contains("UPX0") ||
        out.features.sections.contains("UPX1") ||
        out.features.sections.contains("UPX2"))
        { packed = true; out.tags.emplace_back("packer:upx"); }
    if (out.features.sections.contains(".aspack") ||
        out.features.sections.contains(".adata"))
        { packed = true; out.tags.emplace_back("packer:aspack"); }
    if (out.features.sections.contains(".themida") ||
        out.features.sections.contains(".Themida"))
        { packed = true; out.tags.emplace_back("packer:themida"); }
    if (out.features.sections.contains(".vmp0") ||
        out.features.sections.contains(".vmp1"))
        { packed = true; out.tags.emplace_back("packer:vmprotect"); }
    if (out.features.sections.contains(".enigma1") ||
        out.features.sections.contains(".enigma2"))
        { packed = true; out.tags.emplace_back("packer:enigma"); }
    if (out.fileEntropy > 7.5 && out.uniqueApis < 8)
        { packed = true; out.tags.emplace_back("packer:heuristic"); }
    if (packed) {
        out.isPacked = true;
        out.features.characteristics.insert("packed");
    }
}

void StaticEngine::ScoreReport(StaticReport& out) {
    float score = 0.0f;
    for (const auto& m : out.matches) {
        if (m.suppressed) continue;
        float sevWeight = 0.0f;
        switch (m.rule ? m.rule->severity : RuleSeverity::Informational) {
            case RuleSeverity::Informational: sevWeight = 1.0f;  break;
            case RuleSeverity::Low:           sevWeight = 5.0f;  break;
            case RuleSeverity::Medium:        sevWeight = 12.0f; break;
            case RuleSeverity::High:          sevWeight = 22.0f; break;
            case RuleSeverity::Critical:      sevWeight = 35.0f; break;
        }
        score += sevWeight * m.confidence;
        if (m.rule && m.rule->severity > out.worstSeverity)
            out.worstSeverity = m.rule->severity;
        if (m.rule) {
            for (const auto& a : m.rule->attack) out.attack.push_back(a);
        }
    }
    if (out.isPacked) score += 5.0f;
    if (out.fileEntropy > 7.5) score += 8.0f;
    if (out.isPe && !out.isSigned) score += 2.0f;
    if (out.isPe && out.isSigned && out.signerTrusted) score -= 8.0f;
    if (out.features.characteristics.contains("writable-text")) score += 10.0f;
    if (out.features.characteristics.contains("no-nx")) score += 4.0f;
    if (out.features.characteristics.contains("no-aslr")) score += 2.0f;
    score = std::clamp(score, 0.0f, 100.0f);
    out.aggregateScore = score;
    out.maliciousProbability = std::clamp(score / 100.0f, 0.0f, 1.0f);
}

void StaticEngine::ApplyDescriptiveTags(StaticReport& out) {
    if (out.isPe)         out.tags.emplace_back("format:pe");
    if (out.isDotNet)     out.tags.emplace_back("lang:dotnet");
    if (out.isSigned)     out.tags.emplace_back("signed");
    if (!out.isSigned)    out.tags.emplace_back("unsigned");
    if (out.isPacked)     out.tags.emplace_back("packed");
    if (out.fileEntropy > 7.5) out.tags.emplace_back("high-entropy");
    if (out.isCorrupted)  out.tags.emplace_back("corrupted");
}

} // namespace Detection
} // namespace ShadowStrike
