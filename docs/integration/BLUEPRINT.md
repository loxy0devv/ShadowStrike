# ShadowStrike Phantom — System Blueprint

**Date:** 2026-05-28 | **Status:** Alpha → Integration Sprint Complete

---

## 1. Platform Purpose

ShadowStrike Phantom is an open-source, fully auditable Windows-only endpoint
protection platform. It aims to exceed the detection quality of CrowdStrike
Falcon, Microsoft Defender for Endpoint, and SentinelOne Singularity while
being entirely inspectable. There is no black-box kernel component, no hidden
telemetry, and no trust required.

---

## 2. Major Subsystems

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  USER MODE                                                                   │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐  │
│  │ PhantomEDR  │  │ PhantomHome │  │ PhantomXDR  │  │ Dashboard (WIP)  │  │
│  │ (service)   │  │ (GUI)       │  │ (service)   │  │                  │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────────────┘  │
│         └───────────────────────────────────┘                               │
│                             │                                               │
│  ╔══════════════════════════╪══════════════════════════════════════════════╗ │
│  ║          PhantomCore — Shared Detection Infrastructure                  ║ │
│  ║                          │                                              ║ │
│  ║  ┌─────────────────────────────────────────────────────────────────┐   ║ │
│  ║  │            DetectionEngine (NEW — Integration Sprint)            │   ║ │
│  ║  │   StaticEngine · RuleEngine · RuleStore · Correlator            │   ║ │
│  ║  │   ProcessGraph · EventBus · DeepInspector                        │   ║ │
│  ║  │   RuleImporter: Native + capa (1045) + Sigma (2233) + Elastic   │   ║ │
│  ║  └─────────────────────────────────────────────────────────────────┘   ║ │
│  ║                          │                                              ║ │
│  ║  ┌──────────┐  ┌─────────┤─────────┐  ┌─────────────────────────────┐ ║ │
│  ║  │ RealTime │  │  Engine  Modules  │  │  Detection Data Stores      │ ║ │
│  ║  │ Protection│  │ ScanEngine       │  │  SignatureStore (B-tree)    │ ║ │
│  ║  │ ExploitPrev│ │ ThreatDetector   │  │  PatternStore (Aho-Corasick)│ ║ │
│  ║  │ Behavior  │  │ HeuristicAnalyzer│  │  HashStore (Bloom filter)   │ ║ │
│  ║  │ Blocker   │  │ MachineLearning  │  │  ThreatIntel (STIX/TAXII)  │ ║ │
│  ║  └──────────┘  │ ZeroDayDetector  │  │  YaraRuleStore             │ ║ │
│  ║                └──────────────────┘  └─────────────────────────────┘ ║ │
│  ║                                                                         ║ │
│  ║  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ ║ │
│  ║  │ PhantomEmulator  │  │  PhantomCortex   │  │  AntiEvasion Suite   │ ║ │
│  ║  │ x86/x64 CPU emu  │  │  5 ONNX models   │  │  9 detector modules  │ ║ │
│  ║  │ 10 DLL stubs     │  │  < 1ms inference │  │  + ASM probes        │ ║ │
│  ║  │ 12 analyzers     │  │                  │  │                      │ ║ │
│  ║  └──────────────────┘  └──────────────────┘  └──────────────────────┘ ║ │
│  ║                                                                         ║ │
│  ║  ┌──────────┐  ┌─────────┐  ┌────────────────┐  ┌──────────────────┐ ║ │
│  ║  │ Security │  │ Scripts │  │ Devices        │  │ REST API Server  │ ║ │
│  ║  │ Self-Def │  │ AMSI    │  │ WebcamProtect  │  │ localhost:9443   │ ║ │
│  ║  │ TamperPr │  │ PS/JS   │  │ (NEW)          │  │ Bearer auth      │ ║ │
│  ║  └──────────┘  └─────────┘  └────────────────┘  └──────────────────┘ ║ │
│  ╚══════════════════════════════════════════════════════════════════════════╝ │
│                             │                                               │
│  ┌──────────────────────────┴───────────────────────────────────────────┐   │
│  │                    Encrypted IPC Bridge                               │   │
│  │         FilterConnectPort · AES-GCM · Auth token exchange             │   │
│  └──────────────────────────┬───────────────────────────────────────────┘   │
├─────────────────────────────┼───────────────────────────────────────────────┤
│  KERNEL MODE                │                                               │
│                             ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    PhantomSensor.sys                                  │   │
│  │            WDM Minifilter · Altitude 385210 · 20 Subsystems           │   │
│  │                                                                       │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │Syscall   │ │Memory    │ │Behavioral│ │FileSystem│ │Registry  │  │   │
│  │  │Monitor   │ │Monitor   │ │Engine    │ │Callbacks │ │Callbacks │  │   │
│  │  │Hell's/   │ │VAD·ROP   │ │MITRE 550+│ │Ransomware│ │Persist.  │  │   │
│  │  │Heaven's  │ │Injection │ │scoring   │ │detection │ │detection │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │Process   │ │Thread    │ │Image Load│ │Network   │ │Object    │  │   │
│  │  │Callbacks │ │Callbacks │ │Callbacks │ │WFP Filter│ │Callbacks │  │   │
│  │  │LOLBin    │ │Remote thr│ │DLL inject│ │C2/DGA    │ │Handle    │  │   │
│  │  │PID spoof │ │APC inject│ │Unsigned  │ │detection │ │protect.  │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                             │   │
│  │  │ETW       │ │Self-Prot │ │Cache /   │                             │   │
│  │  │Provider  │ │Anti-tamp │ │Exclusions│                             │   │
│  │  └──────────┘ └──────────┘ └──────────┘                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Subsystem Responsibilities

### 3.1 PhantomSensor.sys (Kernel)

- WDM minifilter at altitude 385210
- Intercepts: process/thread/image callbacks, file pre/post I/O, registry,
  network (WFP), object handles, ALPC
- Emits structured events via FilterConnectPort to user-mode
- No user-mode decision needed for kernel-level blocks (policy enforced locally)
- Coverity-verified, Driver Verifier clean

### 3.2 DetectionEngine (New, User Mode)

The integration layer added in this sprint. Receives events from the sensor
and applies multi-layer detection:

**Stage 1 — Pre-execution (Static)**
- `StaticEngine` runs capa-style PE analysis before the file executes
- Evaluates 800+ capa rules + 7 native static rules against `StaticFeatureBag`
- Produces risk score and feature bag for downstream stages

**Stage 2 — Runtime (Single Event)**
- `RuleEngine.Evaluate()` runs against each event
- 1,800+ Sigma Windows rules evaluated at runtime
- Matches accumulate evidence onto `ProcessGraph` nodes

**Stage 3 — Sequence Correlation**
- Correlator windows up to 256 events per process over 60 seconds
- Sequence-scope rules detect multi-step attack chains
- Parent-child score inheritance propagates attacker evidence

**Stage 4 — Verdict**
- Per-process score compared to thresholds (25/55/75/90)
- Verdict emitted with recommended action (Monitor/Quarantine/Block/Kill)
- Subscribers (ScanEngine, ResponseEngine, GUI) receive async callbacks

### 3.3 RuleStore / RuleEngine

Holds all rules in memory, indexed by scope for O(1) candidate lookup.
Supports atomic hot-reload — new store built off-thread, swapped in without
interrupting evaluations. Regex cache prevents repeated compilation.

### 3.4 StaticEngine

C++ reimplementation of capa's matching model. Single-pass feature extraction,
interned into `StaticFeatureBag` for O(1) rule predicate evaluation. 10–100×
faster than Python capa for the same ruleset.

### 3.5 ProcessGraph

In-memory process tree, continuously updated from `OnProcessStart/Exit` events.
Each node accumulates: score, matched rules, ATT&CK techniques, loaded images,
network endpoints, file writes, registry writes. Used for lineage display in GUI.

### 3.6 EventBus

MPSC bounded ring buffer. Decouples sensor I/O from rule evaluation. On overflow
(> 65,536 queued events), new events are dropped with a counter — preventing
backpressure on the sensor.

### 3.7 DeepInspector (HyperDbg-aligned)

Four user-mode probes inspired by HyperDbg's EPT/VMX capabilities:
- **InspectMemoryMap** — flags unbacked executable regions, RWX pages
- **InspectSyscallSites** — flags direct syscalls outside ntdll
- **InspectModuleStomping** — compares loaded module header bytes vs disk
- **InspectThreads** — flags stack pivots and unbacked instruction pointers

### 3.8 WebcamProtection

Camera access control with policy (Allow/Ask/Block), trusted-process list,
and GUI callback mechanism. Ask policy blocks the open attempt for up to
30 seconds waiting for a user decision via the REST API.

### 3.9 PhantomEmulator

Full x86/x64 CPU emulation engine. Separate from DetectionEngine; feeds
into `ScanEngine` via `EmulationEngine` module. Results flow back as
behavioral events that can be ingested into `DetectionEngine.IngestEvent()`.

### 3.10 PhantomCortex (AI)

5 ONNX models (LightGBM, CNN, GRU, MLP, Autoencoder). Runs in `< 1 ms`
on-device. `MachineLearningDetector` in `ScanEngine` consults PhantomCortex
after static analysis; confidence feeds into the detection pipeline.

---

## 4. Data Flow

```
File arrives (kernel pre-create callback)
        │
        ▼
   PhantomSensor.sys: IRP_MJ_CREATE
        │  (via FilterConnectPort IPC)
        ▼
   ScanEngine::ScanFile (user mode)
        │
        ├── [1] DetectionEngine.AnalyzeFile → StaticReport
        │         └── capa rules + native static rules
        │
        ├── [2] HashStore lookup  (O(1))
        ├── [3] WhitelistStore    (O(1))
        ├── [4] ThreatIntel       (STIX lookup)
        ├── [5] YaraRuleStore     (YARA scan)
        ├── [6] HeuristicAnalyzer (entropy, PE anomalies)
        ├── [7] PhantomEmulator   (emulation if packed)
        └── [8] MachineLearningDetector (ONNX inference)
                │
                ▼
           ScanVerdict (Clean/Infected/Suspicious)
                │
                ▼
          QuarantineManager / ResponseEngine

Process runs
        │
        ▼
   PhantomSensor.sys fires callbacks
   (process/thread/image/registry/network/file/syscall)
        │  IPC
        ▼
   EventBus.Push()
        │
        ▼
   Correlator.Ingest()
        ├── ProcessGraph update
        ├── RuleEngine.Evaluate() → [RuleMatch]
        ├── ProcessGraph.ApplyMatch() → score++
        └── Score >= threshold?
                │ yes
                ▼
           Verdict emitted → subscribers
           (ScanEngine / RTPEngine / AlertSystem / GUI callbacks)
```

---

## 5. Rule Pipeline

```
rules/phantom/   ─────────────────────────────┐
rules/capa/      ──── RuleImporter.LoadAll() ──┤──▶ RuleStore
rules/sigma/     ─────────────────────────────┤
rules/elastic/   ─────────────────────────────┘
                                               │
                                    RuleEngine (shared_ptr)
                                               │
                          ┌────────────────────┼────────────────────┐
                          │                    │                    │
                   EvaluateStatic()      Evaluate()        EvaluateSequence()
                  (StaticFeatureBag)  (DetectionEvent)  ([]DetectionEvent)
                          │                    │                    │
                          └────────────────────┴────────────────────┘
                                               │
                                        [RuleMatch]
                                               │
                                        Correlator
                                               │
                                        ProcessGraph
                                               │
                                          Verdict
```

---

## 6. GUI API Surface Summary

All endpoints exposed by `RESTServer` (localhost:9443, Bearer auth):

### Core
- `GET/POST /api/v1/auth/login|logout|session`
- `GET /api/v1/status` — engine health, detection counts
- `GET /api/v1/stats` — detection stats, FP counts
- `GET /api/v1/modules` — per-module status

### Detection
- `POST /api/v1/scan/file` — on-demand file scan
- `POST /api/v1/scan/process` — on-demand process scan
- `GET /api/v1/detections` — recent detections with ATT&CK
- `GET /api/v1/detections/{id}` — detection detail
- `GET /api/v1/process-tree` — live process graph

### Response
- `POST /api/v1/quarantine` — quarantine file
- `POST /api/v1/allow` — add to allowlist
- `POST /api/v1/block` — add to blocklist

### Policy
- `GET/PUT /api/v1/policy` — RTP on/off, scan sensitivity
- `GET/PUT /api/v1/devices/webcam/policy` — camera policy
- `GET/POST/DELETE /api/v1/devices/webcam/trusted` — trusted processes

### Rules
- `GET /api/v1/rules` — list loaded rules with stats
- `POST /api/v1/rules/reload` — hot-reload rule corpora
- `GET /api/v1/rules/{id}` — rule detail with match stats

---

## 7. Malware Class Coverage

| Class | Primary detection layer |
|-------|------------------------|
| Stealers | Static (CryptUnprotectData + sqlite3), Runtime (browser data access) |
| Ransomware | Static (encryption + shadow copy), Runtime (write rate + entropy) |
| Cryptominers | Runtime (CPU spike + network C2), Static (mining pool strings) |
| Loaders / Droppers | Static (download APIs), Runtime (child process creation) |
| Process Injection | Deep (RWX regions, unbacked IP), Sequence (VirtualAlloc→WriteProcessMemory→CreateRemoteThread) |
| DLL Sideloading | Image load rules (unsigned DLL in non-system path) |
| Persistence | Registry (Run key writes), Sequence (write→register→execute) |
| C2 / Beaconing | Network rules, behavioral timing patterns |
| Anti-Analysis | Static (capa anti-analysis namespace), Runtime (VM/sandbox evasion detection) |
| LOLBIN Abuse | Process rules (lolbin + network, lolbin + unusual parent) |
| Lateral Movement | Sequence rules (recon → lateral) |
| Credential Theft | Static + Runtime (LSASS access, browser data read) |
| Macro Malware | Process (Office child), Script (AMSI + VBA analysis) |
| Rootkits | PhantomSensor.sys kernel monitoring |
| Fileless | Script rules, AMSI, memory scan for shellcode |
| Zero-days | Behavioral anomaly scoring, deep inspection of exploit-like memory patterns |

---

## 8. Complete vs Incomplete

### Complete (as of this sprint)
- ✅ PhantomSensor.sys (kernel driver, Coverity-verified)
- ✅ DetectionEngine façade
- ✅ PhantomRule native format + parser (native, capa, Sigma, Elastic)
- ✅ RuleEngine (static + runtime + sequence evaluation)
- ✅ RuleStore (atomic hot-reload)
- ✅ RuleImporter (all four corpora)
- ✅ StaticEngine (capa-style, C++ native)
- ✅ ProcessGraph (live process tree + evidence accumulation)
- ✅ EventBus (MPSC, bounded, non-blocking)
- ✅ Correlator (single-event + sequence, verdict emission)
- ✅ DeepInspector (memory map, syscall sites, module stomping, thread anomalies)
- ✅ WebcamProtection (policy + Ask flow + GUI API surface)
- ✅ Native detection rules (7 high-quality rules across 5 scopes)
- ✅ Rule corpora copied into ShadowStrike (3,291 files: capa + Sigma + Elastic)
- ✅ PhantomCore (ScanEngine, BehaviorAnalyzer, HeuristicAnalyzer, etc.)
- ✅ PhantomEmulator (CPU emulation, 12 analyzers)
- ✅ PhantomCortex (5 ONNX models, inference bridge)
- ✅ REST API server (localhost:9443, Bearer auth, CSRF)

### Incomplete / Next Steps
- 🔧 PhantomCortex — 5th model retraining with synthetic + EMBER 2024 data
- 🔧 Product tier orchestration (Home/EDR/XDR) — 58% complete
- 🔧 Management Dashboard (React SPA) — 38% complete
- ✅ ShadowStrike.vcxproj updated (12 new ClCompile + 12 new ClInclude entries)
- ✅ Sigma condition full grammar parser (recursive descent, handles or/and/not/N-of/all-of/any-of/count)
- ✅ 59 native phantom rules (process, file, memory, network, registry, sequence, static scopes)
- ✅ CI rule-smoke-test (RuleSmokeTest.cpp — 10 assertions covering corpus integrity)
- ✅ DetectionEngine wired into ScanEngine (Stage 0.5 before YARA)
- ✅ Correlator verdicts routed to BehaviorBlocker (verdict → ProcessBehavior → AnalyzeBehavior)
- ✅ Kernel IPC events fed to EventBus (OnKernelProcessNotify, OnKernelImageLoad, OnKernelRegistryOp)
- 🔧 Webcam protection kernel-side IPC hookup (kernel pre-create block must call
       WebcamProtection::OnCameraOpenAttempt via FilterConnectPort)
- 🔧 Elastic rules: KQL/EQL queries not natively executed; retained as hunting
       metadata only; a KQL→PhantomRule translator is a future work item
- 🔧 PhantomDisassembler full implementation (replacing Zydis dependency)
- 🔧 Rule quality review: promote Sigma rules from Experimental to Stable
       after empirical FP testing

---

## 9. Next Priority Items

1. **Wire DetectionEngine into ScanEngine.ScanFile** — insert static-analysis
   stage before YARA; attach static features to subsequent scan context.

2. **Wire Correlator verdicts into RTPEngine / BehaviorBlocker** — subscribe
   to `DetectionEngine::SubscribeVerdicts` and route to the existing
   `AccessControlManager` for block/quarantine actions.

3. **Wire kernel events into EventBus** — the existing `FilterConnection.cpp`
   deserializes IPC messages; add a dispatch path to
   `DetectionEngine::IngestEvent`.

4. **ShadowStrike.vcxproj update** — add all new Detection/*.cpp files.

5. **Sigma condition parser** — extend RuleParser to handle the full Sigma
   condition grammar (arithmetic, keyword selection, etc.).

6. **50 additional native rules** — cover credential theft sequences, ransom
   write-rate chains, WMI lateral movement, scheduled-task abuse, DLL
   sideloading, etc.

7. **Rule quality gate** — add a CI rule-smoke-test that loads all corpora
   and asserts zero parse errors and no duplicate IDs.
