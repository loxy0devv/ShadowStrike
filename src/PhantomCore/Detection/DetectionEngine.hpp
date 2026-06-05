/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * DetectionEngine — top-level façade that wires together:
 *
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        DetectionEngine                              │
 *   │                                                                     │
 *   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
 *   │   │ StaticEngine │  │  RuleEngine  │  │     Correlator       │    │
 *   │   │ (capa-style) │  │ (rule eval)  │  │ (evidence + verdicts)│    │
 *   │   └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘    │
 *   │          │                 │                       │               │
 *   │          └─────────────────┴───────────────────────┘               │
 *   │                            │                                       │
 *   │   ┌─────────────────────────────────────────────────────────────┐  │
 *   │   │                    RuleStore                                 │  │
 *   │   │   (Native + Capa + Sigma + Elastic — 3,000+ rules)          │  │
 *   │   └─────────────────────────────────────────────────────────────┘  │
 *   │                                                                     │
 *   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
 *   │   │ProcessGraph  │  │  EventBus    │  │  DeepInspector       │    │
 *   │   │(process tree)│  │(MPSC queue)  │  │(HyperDbg-style probes)│   │
 *   │   └──────────────┘  └──────────────┘  └──────────────────────┘    │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Initialization:
 *   DetectionEngine::Config cfg;
 *   cfg.rulesRoot = L"C:\\ProgramData\\ShadowStrike\\rules";
 *   DetectionEngine engine;
 *   engine.Initialize(cfg);
 *
 * On file access:
 *   auto report = engine.AnalyzeFile(path, pid);
 *   // report.LikelyMalicious() / report.aggregateScore / report.matches
 *
 * On runtime event:
 *   engine.IngestEvent(ev);
 *   // verdicts are delivered asynchronously through the subscriber callbacks
 *
 * Subscribe to verdicts:
 *   engine.SubscribeVerdicts([](const Verdict& v) { ... });
 */

#pragma once

#include "Rules/PhantomRule.hpp"
#include "Rules/RuleEngine.hpp"
#include "Rules/RuleStore.hpp"
#include "Rules/RuleImporter.hpp"
#include "Static/StaticEngine.hpp"
#include "Correlation/Correlator.hpp"
#include "Correlation/EventBus.hpp"
#include "Correlation/ProcessGraph.hpp"
#include "Telemetry/DeepInspection.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>

namespace ShadowStrike {
namespace Detection {

class DetectionEngine {
public:
    // -----------------------------------------------------------------------
    // Singleton access — follows the same Meyers' singleton pattern used
    // throughout PhantomCore. Initialise via Initialize() before first use.
    // -----------------------------------------------------------------------
    [[nodiscard]] static DetectionEngine& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    struct Config {
        std::filesystem::path rulesRoot;

        StaticEngineConfig  staticCfg{};
        RuleEngineConfig    ruleCfg{};
        CorrelatorConfig    correlatorCfg{};

        bool enableDeepInspection    = true;
        bool asyncEventProcessing    = true;
        size_t eventBusCapacity      = 65536;
    };

    DetectionEngine();
    ~DetectionEngine();

    bool Initialize(const Config& cfg);
    void Shutdown();

    [[nodiscard]] bool IsInitialized() const noexcept;

    // -- Static analysis (pre-execution) --------------------------------

    /// Analyze a file on disk. Blocks until analysis completes.
    /// Feed the resulting matches to a process node when the process starts.
    [[nodiscard]] StaticReport AnalyzeFile(const std::filesystem::path& path,
                                            uint32_t pid = 0);

    // -- Runtime event ingestion ----------------------------------------

    /// Push a single runtime event. Non-blocking when async=true.
    void IngestEvent(DetectionEvent ev);

    /// Convenience: build and ingest a process-start event.
    void OnProcessStart(uint32_t pid, uint32_t ppid,
                        std::wstring imagePath, std::string commandLine,
                        std::string userSid = {}, std::string integrity = {});

    void OnProcessExit(uint32_t pid);

    void OnImageLoad(uint32_t pid, std::wstring imagePath, bool signed_);

    void OnNetworkConnection(uint32_t pid, std::string dstIp, std::string dstHost,
                              uint16_t dstPort);

    void OnFileEvent(uint32_t pid, std::string action, std::wstring filePath);

    void OnRegistryEvent(uint32_t pid, std::string action, std::string key,
                          std::string value = {});

    void OnScriptContent(uint32_t pid, std::string scriptText, std::string context);

    /// DNS query event (from DNS client callbacks or ETW)
    void OnDnsQuery(uint32_t pid, std::string queryName, std::string queryType = "A");

    /// Thread creation event (process injection detection)
    void OnThreadCreate(uint32_t pid, uint32_t tid, uint32_t remotePid,
                        uintptr_t startAddress, std::string startModule = {});

    // -- Deep inspection -------------------------------------------------

    /// Inspect a process's memory map, syscall sites, threads.
    /// Findings are automatically ingested as events.
    void DeepInspect(uint32_t pid);

    // -- Verdict callbacks -----------------------------------------------

    using VerdictCb = std::function<void(const Verdict&)>;
    uint64_t SubscribeVerdicts(VerdictCb cb);
    void     UnsubscribeVerdicts(uint64_t token);

    // -- Process graph access -------------------------------------------

    [[nodiscard]] std::optional<ProcessNode> GetProcessInfo(uint32_t pid) const;
    [[nodiscard]] std::vector<ProcessNode>   GetProcessTree() const;

    // -- Rule management ------------------------------------------------

    [[nodiscard]] size_t  RuleCount() const noexcept;
    [[nodiscard]] ImportResult LastImportResult() const noexcept;

    bool ReloadRules();

    // -- Statistics -------------------------------------------------------

    struct Stats {
        StaticEngine::Stats staticStats;
        RuleEngine::Stats   ruleStats;
        Correlator::Stats   correlatorStats;
        EventBus::Stats     busStats;
        DeepInspector::Stats deepStats;
        size_t ruleCount = 0;
    };
    [[nodiscard]] Stats GetStats() const;

private:
    Config                          m_cfg;
    std::shared_ptr<RuleStore>      m_store;
    std::shared_ptr<RuleEngine>     m_engine;
    std::shared_ptr<ProcessGraph>   m_graph;
    std::unique_ptr<StaticEngine>   m_staticEngine;
    std::unique_ptr<Correlator>     m_correlator;
    std::unique_ptr<EventBus>       m_bus;
    std::unique_ptr<DeepInspector>  m_deepInspector;

    bool                     m_initialized = false;
    std::atomic<bool>        m_reaperRunning{false};
    std::thread              m_reaperThread;
    ImportResult             m_lastImport{};
};

} // namespace Detection
} // namespace ShadowStrike
