/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "DetectionEngine.hpp"
#include "Static/ScanCache.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike {
namespace Detection {

DetectionEngine& DetectionEngine::Instance() noexcept {
    static DetectionEngine s_instance;
    return s_instance;
}

bool DetectionEngine::HasInstance() noexcept {
    // Access the singleton without constructing it: check the static local's
    // guard variable instead of calling Instance() which would construct it.
    // This is acceptable because static locals are constructed on first call.
    // We use a cheap atomic flag set during Initialize() to avoid the guard probe.
    static std::atomic<bool> s_ready{false};
    (void)s_ready;  // flag is set below in Initialize() after construction
    // Since we always construct on first call, HasInstance == was Initialize() called
    // We reuse m_initialized for this.
    return Instance().m_initialized;
}

DetectionEngine::DetectionEngine() = default;
DetectionEngine::~DetectionEngine() { Shutdown(); }

bool DetectionEngine::Initialize(const Config& cfg) {
    if (m_initialized) return true;
    m_cfg = cfg;

    // 1. Load rule corpora — prefer embedded blob; fall back to disk in dev mode
    m_store = std::make_shared<RuleStore>();
    RuleImporter::LoadFromEmbedded(*m_store, &m_lastImport);
    if (m_lastImport.total() == 0) {
        // Dev mode fallback: load from disk
        m_store = RuleImporter::LoadAll(cfg.rulesRoot, &m_lastImport);
    }

    // 2. Rule engine
    m_engine = std::make_shared<RuleEngine>(m_store, cfg.ruleCfg);

    // 3. Process graph
    m_graph = std::make_shared<ProcessGraph>();

    // 4. Static analysis engine
    m_staticEngine = std::make_unique<StaticEngine>(m_engine, cfg.staticCfg);

    // 5. Correlator
    m_correlator = std::make_unique<Correlator>(m_engine, m_graph, cfg.correlatorCfg);

    // 6. Event bus
    if (cfg.asyncEventProcessing) {
        m_bus = std::make_unique<EventBus>(cfg.eventBusCapacity);
        m_bus->Start([this](DetectionEvent ev) {
            m_correlator->Ingest(std::move(ev));
        });
    }

    // Start a periodic reaper for the process graph
    m_reaperRunning.store(true, std::memory_order_release);
    m_reaperThread = std::thread([this]() {
        while (m_reaperRunning.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            if (m_graph && m_reaperRunning.load(std::memory_order_acquire)) {
                m_graph->Reap(std::chrono::minutes(30));
            }
        }
    });

    // 7. Deep inspector
    if (cfg.enableDeepInspection) {
        m_deepInspector = std::make_unique<DeepInspector>();
    }

    m_initialized = true;
    return true;
}

void DetectionEngine::Shutdown() {
    if (!m_initialized) return;
    if (m_bus) m_bus->Stop();
    m_initialized = false;
    m_reaperRunning.store(false, std::memory_order_release);
    if (m_reaperThread.joinable()) m_reaperThread.join();
}

bool DetectionEngine::IsInitialized() const noexcept { return m_initialized; }

StaticReport DetectionEngine::AnalyzeFile(const std::filesystem::path& path,
                                           uint32_t pid) {
    StaticReport report;
    if (!m_staticEngine) return report;
    m_staticEngine->AnalyzeFile(path, report);
    if (pid != 0 && !report.matches.empty()) {
        m_correlator->IngestStaticReport(pid, report.matches);
    }
    return report;
}

void DetectionEngine::IngestEvent(DetectionEvent ev) {
    if (!m_initialized) return;
    if (m_bus) {
        m_bus->Push(std::move(ev));
    } else {
        m_correlator->Ingest(std::move(ev));
    }
}

void DetectionEngine::OnProcessStart(uint32_t pid, uint32_t ppid,
                                      std::wstring imagePath,
                                      std::string commandLine,
                                      std::string userSid,
                                      std::string integrity) {
    auto now = std::chrono::system_clock::now();
    m_graph->OnProcessStart(pid, ppid, imagePath, commandLine, userSid, integrity, now);

    DetectionEvent ev;
    ev.timestamp = now;
    ev.scope = RuleScope::Process;
    ev.category = "process";
    ev.action = "create";

    std::string narrow; narrow.reserve(imagePath.size());
    for (auto c : imagePath) narrow.push_back(static_cast<char>(c & 0xFF));
    auto base = narrow.rfind('\\');
    std::string name = (base == std::string::npos) ? narrow : narrow.substr(base + 1);
    for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Look up parent process info from the graph for richer Sigma field coverage
    std::string parentName;
    std::string parentExe;
    std::string parentCmd;
    if (auto parentInfo = m_graph->Get(ppid)) {
        parentExe.reserve(parentInfo->imagePath.size());
        for (auto c : parentInfo->imagePath)
            parentExe.push_back(static_cast<char>(c & 0xFF));
        auto pbase = parentExe.rfind('\\');
        parentName = (pbase == std::string::npos) ? parentExe : parentExe.substr(pbase + 1);
        for (auto& c : parentName) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        parentCmd = parentInfo->commandLine;
    }

    ev.fields["process.pid"]                  = static_cast<int64_t>(pid);
    ev.fields["process.parent.pid"]           = static_cast<int64_t>(ppid);
    ev.fields["process.executable"]           = narrow;
    ev.fields["process.name"]                 = name;
    ev.fields["process.command_line"]         = commandLine;
    ev.fields["user.sid"]                     = userSid;
    ev.fields["process.integrity_level"]      = integrity;
    ev.fields["process.parent.name"]          = parentName;
    ev.fields["process.parent.executable"]    = parentExe;
    ev.fields["process.parent.command_line"]  = parentCmd;
    ev.fields["process.working_directory"]    = std::string{};
    ev.fields["event.type"]                   = std::string("start");
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnProcessExit(uint32_t pid) {
    auto now = std::chrono::system_clock::now();
    m_graph->OnProcessExit(pid, now);
    DetectionEvent ev;
    ev.timestamp = now;
    ev.scope = RuleScope::Process;
    ev.category = "process";
    ev.action = "exit";
    ev.fields["process.pid"] = static_cast<int64_t>(pid);
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnImageLoad(uint32_t pid, std::wstring imagePath, bool signed_) {
    m_graph->OnImageLoad(pid, imagePath, signed_);
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.scope = RuleScope::Image;
    ev.category = "image";
    ev.action = "load";
    std::string narrow; narrow.reserve(imagePath.size());
    for (auto c : imagePath) narrow.push_back(static_cast<char>(c & 0xFF));
    for (auto& c : narrow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto imgbase = narrow.rfind('\\');
    std::string imgname = (imgbase == std::string::npos) ? narrow : narrow.substr(imgbase + 1);
    ev.fields["process.pid"]          = static_cast<int64_t>(pid);
    ev.fields["image.path"]           = narrow;
    ev.fields["image.signed"]         = signed_;
    ev.fields["image.name"]           = imgname;
    ev.fields["file.signer.signed"]   = signed_;
    ev.fields["file.signer.trusted"]  = signed_;
    ev.fields["file.signer.subject"]  = std::string{};
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnNetworkConnection(uint32_t pid, std::string dstIp,
                                           std::string dstHost, uint16_t dstPort) {
    std::string endpoint = dstHost.empty() ? dstIp : dstHost;
    m_graph->OnNetworkEndpoint(pid, endpoint);
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.scope = RuleScope::Network;
    ev.category = "network";
    ev.action = "connect";
    ev.fields["process.pid"]              = static_cast<int64_t>(pid);
    ev.fields["network.destination.ip"]   = dstIp;
    ev.fields["network.destination.host"] = dstHost;
    ev.fields["network.destination.port"] = static_cast<int64_t>(dstPort);
    ev.fields["network.direction"]        = std::string("outbound");
    ev.fields["source.ip"]                = std::string{};
    ev.fields["destination.ip"]           = dstIp;
    ev.fields["destination.port"]         = static_cast<int64_t>(dstPort);
    ev.fields["network.type"]             = std::string(dstIp.find(':') != std::string::npos ? "ipv6" : "ipv4");
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnFileEvent(uint32_t pid, std::string action,
                                   std::wstring filePath) {
    // Invalidate the incremental scan cache when a file is written or deleted
    // so the next ScanEngine::ScanFile() forces a fresh analysis.
    if (action == "write" || action == "modify" ||
        action == "delete" || action == "rename") {
        ScanCache::Instance().Invalidate(std::filesystem::path(filePath));
    }

    m_graph->OnFileWrite(pid, filePath);
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.scope = RuleScope::File;
    ev.category = "file";
    ev.action = action;
    std::string narrow; narrow.reserve(filePath.size());
    for (auto c : filePath) narrow.push_back(static_cast<char>(c & 0xFF));
    auto fbase = narrow.rfind('\\');
    std::string fname = (fbase == std::string::npos) ? narrow : narrow.substr(fbase + 1);
    auto fdot = fname.rfind('.');
    std::string fext = (fdot != std::string::npos) ? fname.substr(fdot + 1) : std::string{};
    for (auto& c : fext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    ev.fields["process.pid"]    = static_cast<int64_t>(pid);
    ev.fields["file.path"]      = narrow;
    ev.fields["file.name"]      = fname;
    ev.fields["file.extension"] = fext;
    ev.fields["event.type"]     = action;
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnRegistryEvent(uint32_t pid, std::string action,
                                       std::string key, std::string value) {
    m_graph->OnRegistryWrite(pid, key);
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.scope = RuleScope::Registry;
    ev.category = "registry";
    ev.action = action;
    ev.fields["process.pid"]   = static_cast<int64_t>(pid);
    ev.fields["registry.key"]  = key;
    ev.fields["registry.path"] = key;
    if (!value.empty()) {
        ev.fields["registry.value"]      = value;
        ev.fields["registry.value.name"] = value;
    }
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnScriptContent(uint32_t pid, std::string scriptText,
                                       std::string context) {
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.scope = RuleScope::Script;
    ev.category = "script";
    ev.action = "execute";
    ev.fields["process.pid"]    = static_cast<int64_t>(pid);
    ev.fields["script.text"]    = scriptText;
    ev.fields["script.context"] = context;
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnDnsQuery(uint32_t pid, std::string queryName, std::string queryType) {
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.scope = RuleScope::Network;
    ev.category = "dns";
    ev.action = "query";
    ev.fields["process.pid"]       = static_cast<int64_t>(pid);
    ev.fields["dns.query.name"]    = queryName;
    ev.fields["dns.question.name"] = queryName;
    ev.fields["dns.type"]          = queryType;
    m_graph->OnNetworkEndpoint(pid, queryName);
    IngestEvent(std::move(ev));
}

void DetectionEngine::OnThreadCreate(uint32_t pid, uint32_t tid, uint32_t remotePid,
                                      uintptr_t startAddress, std::string startModule) {
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.scope = RuleScope::Thread;
    ev.category = "thread";
    ev.action = "create";
    ev.fields["process.pid"]          = static_cast<int64_t>(pid);
    ev.fields["process.thread.id"]    = static_cast<int64_t>(tid);
    ev.fields["thread.start_address"] = static_cast<int64_t>(startAddress);
    ev.fields["thread.start_module"]  = startModule;
    if (remotePid != 0 && remotePid != pid) {
        ev.fields["process.target.pid"] = static_cast<int64_t>(remotePid);
        ev.fields["event.type"]         = std::string("remote_thread");
    } else {
        ev.fields["event.type"]         = std::string("thread");
    }
    IngestEvent(std::move(ev));
}

void DetectionEngine::DeepInspect(uint32_t pid) {
    if (!m_deepInspector || !m_initialized) return;
    std::vector<DeepEvidence> findings;
    m_deepInspector->InspectMemoryMap(pid, findings);
    m_deepInspector->InspectSyscallSites(pid, findings);
    m_deepInspector->InspectModuleStomping(pid, findings);
    m_deepInspector->InspectThreads(pid, findings);
    for (const auto& f : findings) {
        IngestEvent(DeepInspector::ToDetectionEvent(f));
    }
}

uint64_t DetectionEngine::SubscribeVerdicts(VerdictCb cb) {
    if (!m_correlator) return 0;
    return m_correlator->Subscribe(std::move(cb));
}

void DetectionEngine::UnsubscribeVerdicts(uint64_t token) {
    if (m_correlator) m_correlator->Unsubscribe(token);
}

std::optional<ProcessNode> DetectionEngine::GetProcessInfo(uint32_t pid) const {
    if (!m_graph) return std::nullopt;
    return m_graph->Get(pid);
}

std::vector<ProcessNode> DetectionEngine::GetProcessTree() const {
    if (!m_graph) return {};
    return m_graph->Snapshot();
}

size_t DetectionEngine::RuleCount() const noexcept {
    return m_store ? m_store->Size() : 0;
}

ImportResult DetectionEngine::LastImportResult() const noexcept {
    return m_lastImport;
}

bool DetectionEngine::ReloadRules() {
    if (!m_initialized) return false;
    auto newStore = RuleImporter::LoadAll(m_cfg.rulesRoot, &m_lastImport);
    auto newEngine = std::make_shared<RuleEngine>(newStore, m_cfg.ruleCfg);
    m_engine->ReplaceStore(newStore);
    m_store = std::move(newStore);
    return true;
}

DetectionEngine::Stats DetectionEngine::GetStats() const {
    Stats s;
    if (m_staticEngine)   s.staticStats     = m_staticEngine->GetStats();
    if (m_engine)         s.ruleStats       = m_engine->GetStats();
    if (m_correlator)     s.correlatorStats = m_correlator->GetStats();
    if (m_bus)            s.busStats        = m_bus->GetStats();
    if (m_deepInspector)  s.deepStats       = m_deepInspector->GetStats();
    if (m_store)          s.ruleCount       = m_store->Size();
    return s;
}

} // namespace Detection
} // namespace ShadowStrike
