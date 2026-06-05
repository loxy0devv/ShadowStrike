# ShadowStrike Detection Integration

## Overview

This document describes the new detection layer (`src/PhantomCore/Detection/`) added in
the May 2026 integration sprint. It covers:

1. Native rule format
2. Static analysis engine (capa-style, C++ native)
3. Runtime correlation engine
4. HyperDbg-aligned deep telemetry probes
5. Webcam device protection
6. Rule corpora integration (capa, Sigma, Elastic)
7. Naming conventions
8. GUI-ready API surfaces

---

## 1. Directory Layout

```
src/PhantomCore/Detection/
├── DetectionEngine.hpp/.cpp          # Top-level façade
├── Rules/
│   ├── PhantomRule.hpp/.cpp          # Native rule in-memory format + event model
│   ├── RuleEngine.hpp/.cpp           # Rule evaluator (static + runtime + sequence)
│   ├── RuleStore.hpp/.cpp            # Atomic hot-reload rule database
│   ├── RuleParser.hpp/.cpp           # Parser: native YAML/JSON, capa, Sigma, Elastic
│   └── RuleImporter.hpp/.cpp         # Loads all corpora into a RuleStore
├── Static/
│   └── StaticEngine.hpp/.cpp         # capa-style PE static analysis
├── Correlation/
│   ├── ProcessGraph.hpp/.cpp         # Live process tree with evidence accumulation
│   ├── EventBus.hpp/.cpp             # MPSC event queue (sensor → correlator)
│   └── Correlator.hpp/.cpp           # Multi-event correlation + verdict emission
└── Telemetry/
    └── DeepInspection.hpp/.cpp       # HyperDbg-aligned user-mode deep probes

src/PhantomCore/Devices/
├── WebcamProtection.hpp/.cpp         # Camera access control with GUI API surface

rules/
├── phantom/                          # ShadowStrike native rules
│   ├── process/                      # Process-scope rules
│   ├── memory/                       # Memory-scope rules
│   ├── registry/                     # Registry-scope rules
│   ├── network/                      # Network-scope rules
│   ├── sequence/                     # Multi-event sequence rules
│   └── static/                       # Pre-execution static-analysis rules
├── capa/capa-rules-9.4.0/           # capa rule corpus (1,045 rules, preserved as-is)
├── sigma/windows/                    # Sigma Windows rules (2,233 rules)
└── elastic/                          # Elastic detection rules (NDJSON)
```

---

## 2. Native Rule Format

Rules are YAML files under `rules/phantom/`. The format maps directly to `PhantomRule`.

### Minimal example

```yaml
id: ss-proc-001
detection_name: "Win32/OfficeShell.Execution"
description: "Office application spawned an unusual child process."
scope: process        # process | image | thread | memory | registry | file |
                      # network | script | sequence | graph | hunting | static
severity: high        # informational | low | medium | high | critical
status: stable        # experimental | test | stable | deprecated | hunting-only
source: native
confidence: 0.80      # 0.0–1.0 base confidence on match
weight: 2.0           # score contribution multiplier

attack:
  - tactic: TA0002
    technique: T1566
    sub_technique: T1566.001
    name: "Phishing: Spearphishing Attachment"

logic:
  and:
    - field_in:
        field: process.parent.name
        values: [WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE]
        case_insensitive: true
    - field_in:
        field: process.name
        values: [powershell.exe, cmd.exe, wscript.exe]
        case_insensitive: true

fp_guard:
  notes:
    - "Enterprise macros may legitimately launch PowerShell."
  suppress:
    - field: process.command_line
      regex: "(?i)\\-ExecutionPolicy\\s+Bypass\\s+\\-File"
```

### Logic predicates

| Predicate | Description |
|-----------|-------------|
| `and`, `or`, `not` | Boolean combinators |
| `at_least: {n: N, of: [...]}` | N-of-M combinator |
| `sequence:` | Ordered multi-event (sequence-scope rules only) |
| `optional:` | Child always succeeds; presence is bonus signal |
| **Runtime field predicates** | |
| `field_equals` / `field_contains` / `field_startswith` / `field_endswith` | String comparisons |
| `field_regex` | ECMAScript regex |
| `field_in` / `field_not_in` | Set membership |
| `field_gt` / `field_lt` / `field_ge` / `field_le` | Numeric comparison |
| `field_exists` / `field_missing` | Field presence |
| `child_of` / `descendant_of` | Process lineage |
| `has_mitigation` / `lacks_mitigation` | Process mitigation flags |
| **Signer predicates** | |
| `signer_equals` | Signer subject match |
| `signer_untrusted` | Signer not in trusted set |
| `unsigned` | No Authenticode signature |
| **Static predicates (scope: static)** | |
| `string` / `substring` / `regex` | String in extracted strings |
| `api` | API in import table |
| `mnemonic` | x86 mnemonic present |
| `number` / `bytes` | Numeric constant or byte sequence |
| `section` / `characteristic` | PE section name or characteristic flag |
| `entropy_above` / `import_count_above` / `unique_api_count_above` | Aggregate metrics |

### Field namespace (ECS-aligned)

| Field | Description |
|-------|-------------|
| `process.pid` / `process.parent.pid` | Process IDs |
| `process.name` / `process.parent.name` | Image base names (lowercase) |
| `process.executable` / `process.parent.executable` | Full paths |
| `process.command_line` | Command line |
| `process.integrity_level` | Low / Medium / High / System |
| `process.ancestry` | List of ancestor names |
| `process.mitigation.*` | Per-flag boolean (dep, aslr, cfg, cet_shadow_stack, ...) |
| `file.path` / `file.hash` | File fields |
| `file.signer.signed` / `file.signer.subject` / `file.signer.trusted` | Authenticode |
| `image.path` / `image.signed` | Loaded DLL/EXE image |
| `registry.key` / `registry.value` | Registry write target |
| `network.destination.ip` / `.host` / `.port` | Network destination |
| `dns.query.name` | DNS query |
| `memory.type` / `memory.protection` / `memory.backed_by_image` | Memory region |
| `event.code` / `event.provider` / `event.channel` | Windows Event Log |
| `script.text` / `script.context` | AMSI / script content |
| `deep.finding` / `deep.detail` / `deep.address` | DeepInspection findings |
| `user.name` / `user.sid` | User context |

---

## 3. Static Analysis Engine

`StaticEngine` implements a C++-native capa-style analysis pipeline.

### Input → Output

```
File on disk (or in-memory buffer)
        │
        ▼
  StaticEngine::AnalyzeFile()
        │
        ├─ ComputeHashes     → md5, sha256
        ├─ ExtractCommonFeatures → ASCII + UTF-16 strings
        ├─ ComputeEntropy    → fileEntropy, sectionEntropyMax
        ├─ ExtractPeFeatures → sections, imports, characteristics
        │   ├─ TLS callbacks, DLL characteristics (NX/ASLR/CFG)
        │   └─ Section entropy per section
        ├─ ExtractDisasmFeatures → mnemonic + immediate frequency pass
        ├─ DetectPackers     → UPX, ASPack, VMProtect, Themida, heuristic
        ├─ RuleEngine::EvaluateStatic(features) → [RuleMatch]
        ├─ ScoreReport       → aggregateScore 0..100
        └─ ApplyDescriptiveTags → ["format:pe", "packed", "unsigned", ...]
                │
                ▼
          StaticReport
```

### Performance targets

| Sample type | Target latency |
|-------------|----------------|
| Typical EXE (< 5 MB) | < 30 ms |
| Large EXE (50 MB) | < 300 ms |
| Packed sample | < 150 ms (disasm depth-limited) |

### Integration with ScanEngine

`ScanEngine::ScanFile` calls `StaticEngine::AnalyzeFile` **first**, before YARA,
behavioral analysis, and ML inference. The resulting `StaticReport`:

- If `aggregateScore >= 75` → immediate Infected verdict, skips deeper stages
- If `aggregateScore >= 40` → enriches subsequent stages; elevates ML model prior
- `StaticReport.features` (the `StaticFeatureBag`) is forwarded to the
  Correlator via `IngestStaticReport` so runtime matches can be fused with
  pre-execution evidence

---

## 4. Correlation Engine

### Architecture

```
PhantomSensor.sys ──IPC──▶ EventBus (MPSC queue)
                                │
         runtime probes ────────┤
         AMSI/script hooks ─────┤
         WFP network events ────┘
                                │
                                ▼
                          Correlator::Ingest()
                                │
                    ┌───────────┴────────────┐
                    │                        │
             ProcessGraph               RuleEngine
          (accumulates evidence)    (evaluates per-event
                    │                  and per-sequence)
                    │                        │
                    └──────────┬─────────────┘
                               │
                       Evidence Ledger
                     (per-process score)
                               │
                    ┌──────────▼──────────┐
                    │  Threshold check    │
                    │  score >= Monitor?  │
                    └──────────┬──────────┘
                               │ yes
                               ▼
                          Verdict raised
                     (action: Allow/Monitor/
                      Quarantine/Block/Kill)
```

### Scoring

Each `RuleMatch` contributes: `score = weight × severity_multiplier × confidence`

Severity multipliers:

| Severity | Multiplier |
|----------|-----------|
| Informational | 1.0 |
| Low | 5.0 |
| Medium | 12.0 |
| High | 22.0 |
| Critical | 35.0 |

Per-process score accumulates multiplicatively. Trusted-signer processes
have their score multiplied by 0.7. Unsigned processes get +2. Writable
.text section adds +10.

Default thresholds:

| Action | Score |
|--------|-------|
| Monitor | ≥ 25 |
| Quarantine | ≥ 55 |
| Block | ≥ 75 |
| Kill | ≥ 90 |

### Sequence rules

Sequence-scope rules define an ordered list of event predicates under
`logic: sequence:`. The correlator maintains a per-process sliding window
(default 60 s, 256 events). When any sequence rule matches, the result is
sent to the verdict pipeline.

### Cross-process inheritance

When a child process matches a rule, its parent's accumulated score is
multiplied by `parentInheritFraction` (default 0.25) and added to the
child, reflecting the parent's prior evidence into the child's risk
assessment.

---

## 5. HyperDbg-Aligned Deep Telemetry

`DeepInspector` implements four probes based on HyperDbg's EPT/VMX capabilities,
adapted for user-mode via Windows kernel APIs:

| Probe | HyperDbg concept | User-mode mechanism |
|-------|------------------|---------------------|
| Memory map | EPT page-type tracking | `VirtualQueryEx` + region type/protection |
| Syscall sites | VMX syscall intercept | Scan executable pages for `0F 05` / `0F 34` outside ntdll |
| Module stomping | EPT-based .text guard | Compare first 64 bytes of loaded module vs on-disk PE |
| Thread anomaly | VMCS instruction pointer | `GetThreadContext` + VAD validation of RIP/RSP |

Findings are emitted as `DetectionEvent` with `scope=memory` or `scope=thread`
and fed through the correlator for evidence accumulation.

---

## 6. Webcam Protection

`WebcamProtection` (under `src/PhantomCore/Devices/`) provides:

- Device enumeration via SetupAPI KSCATEGORY_VIDEO_CAMERA
- Policy modes: **Allow**, **Ask**, **Block**
- Trusted-process allowlist (by path, name, or signer)
- Blocking mechanism: kernel sensor fires via IPC before `CreateFile` completes;
  user-mode responds Allow/Deny within 30 seconds
- Event log of all access attempts (decision + process + device)

### GUI API surface

These endpoints are available from `RESTServer`:

```
GET  /api/v1/devices/webcam                 — list cameras + current access state
GET  /api/v1/devices/webcam/policy          — get current policy
PUT  /api/v1/devices/webcam/policy          — set policy (Allow/Ask/Block)
GET  /api/v1/devices/webcam/access          — recent access events
POST /api/v1/devices/webcam/allow           — approve pending Ask (body: {eventId})
POST /api/v1/devices/webcam/deny            — deny pending Ask
GET  /api/v1/devices/webcam/trusted         — list trusted processes
POST /api/v1/devices/webcam/trusted         — add trusted process entry
DELETE /api/v1/devices/webcam/trusted/{id}  — remove trusted process entry
```

---

## 7. Rule Loading Order and Priorities

1. Native phantom rules loaded first (highest authority)
2. capa rules (scope=static, hunting-only for low-severity namespaces)
3. Sigma Windows rules (status downgraded from "stable" → "test" on import;
   manual review promotes to "stable")
4. Elastic rules (all imported as HuntingOnly; query strings preserved in
   references for analyst use but not executed natively)

### Counts after initial import

| Source | Count |
|--------|-------|
| Native phantom | 7 (grows with new rules) |
| capa 9.4.0 | ~800 parsed (some skipped: missing `rule:` block, nursery) |
| Sigma Windows | ~1,800 parsed (non-Windows filtered, complex conditions degraded) |
| Elastic | 16 (hunting-only metadata) |

---

## 8. Detection Naming Convention

Format: `[OS]/[Category].[Family].[Qualifier]`

Examples:

| Name | Meaning |
|------|---------|
| `Win32/OfficeShell.Execution` | Office spawned a shell process |
| `Win32/Memory.RWXRegion` | Unbacked RWX memory region |
| `Win32/Persist.RunKey` | Run key written by non-system process |
| `Win32/C2.Beaconing` | Periodic outbound connections from anomalous process |
| `Win32/LOLBin.NetworkActivity` | LOLBIN established a network connection |
| `Win32/LateralMovement.ReconChain` | Recon followed by lateral movement |
| `Win32/Crypter.AntiAnalysis` | Anti-analysis + packing heuristics |
| `Trojan.Stealer.Generic` | Credential/browser theft imports |
| `Ransomware.Trojan.Generic` | Encryption + shadow copy deletion |
| `Sigma.process_creation.Generic` | Sigma-derived process rule |
| `Capa.Static.anti-analysis` | Capa-derived static rule |
| `Elastic.Hunting.Windows` | Elastic hunting metadata |

---

## 9. Integration with Existing ScanEngine

The `DetectionEngine` is designed to integrate with the existing `ScanEngine`
pipeline with minimal changes. The recommended integration point:

```cpp
// In ScanEngine::Impl::ScanFileInternal():
StaticReport report = detectionEngine.AnalyzeFile(filePath, context.processId);
if (report.LikelyMalicious()) {
    result.verdict = ScanVerdict::Infected;
    result.detectionName = report.matches.front().rule->detectionName;
    result.confidence = report.maliciousProbability * 100.0f;
    return;
}
// Enrich subsequent stages with static features
context.staticFeatures = std::move(report.features);
// ... continue with YARA, ML, behavioral stages
```

---

## 10. False-Positive Discipline

Each rule carries a `fp_guard` block with:

- `notes[]` — human-readable FP scenarios for rule review
- `suppress[]` — structured suppression conditions evaluated at match time

Engine-level global suppressions can be applied via:
```cpp
store->GlobalSuppress("file.signer.subject", "Microsoft Windows");
```

The correlator additionally applies:
- **Trusted signer discount**: `score *= 0.7` for TrustedSigner processes
- **Threshold inflation**: when a process has `trustedSigner=true`, the
  quarantine threshold is raised by +20 before escalation

---

## 11. Hot Reload

Rules can be reloaded without stopping the engine:

```cpp
engine.ReloadRules();  // re-imports from rules root, swaps RuleStore atomically
```

In-flight evaluations complete against the old store; new evaluations use
the new store immediately after the atomic swap.
