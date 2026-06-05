/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * DeepInspection — HyperDbg-aligned telemetry concepts implemented in
 * user mode, with hooks to the existing PhantomSensor.sys kernel sensor.
 *
 * We do not embed the HyperDbg hypervisor (it would conflict with VBS
 * and many existing kernel products). Instead we lift the most useful
 * detection concepts:
 *
 *   - EPT-style page execution audit (RW->RX, unbacked execution)
 *   - syscall stub provenance (Hell's / Heaven's Gate)
 *   - control-flow integrity (CFG bitmap, shadow stack, retaddr sanity)
 *   - module-stomping detection (.text bytes vs on-disk)
 *
 * Findings are emitted as DetectionEvents with category="deep" and
 * scope=Memory or scope=Thread depending on signal.
 */

#pragma once

#include "../Rules/PhantomRule.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ShadowStrike {
namespace Detection {

struct ExecutionRegion {
    uintptr_t base = 0;
    size_t    size = 0;
    uint32_t  protection = 0;
    std::string moduleName;
    bool backedByModule = false;
    bool initiallyCode  = false;
    bool writableNow    = false;
};

struct SyscallStub {
    uintptr_t address = 0;
    std::string moduleName;
    bool insideNtdll = false;
    bool insideWow64Cpu = false;
    std::string preview;
};

enum class DeepFinding : uint16_t {
    None,
    DynamicCodeExecution,
    UnbackedExecutionAttempt,
    DirectSyscallSite,
    HeavensGate,
    HellsGate,
    ControlFlowAnomaly,
    StackPivot,
    ModuleStomping,
    SuspiciousAllocation,
    ManualMapping,
    ApcInjection,
    ThreadHijack,
    HookedNtdll
};

struct DeepEvidence {
    DeepFinding finding = DeepFinding::None;
    uint32_t pid = 0;
    uint32_t tid = 0;
    std::string detail;             // short, generic
    uintptr_t address = 0;
    std::string moduleName;
    RuleSeverity severity = RuleSeverity::Medium;
    float confidence = 0.7f;
};

class DeepInspector {
public:
    DeepInspector() noexcept = default;
    ~DeepInspector() = default;

    /// Walk a process's virtual memory map and emit findings.
    /// Returns true if the process was inspectable.
    bool InspectMemoryMap(uint32_t pid, std::vector<DeepEvidence>& out);

    /// Inspect syscall stubs of a process: locate every "syscall"
    /// instruction in the address space and tag those not in ntdll.
    bool InspectSyscallSites(uint32_t pid, std::vector<DeepEvidence>& out);

    /// Audit each loaded module's .text vs the on-disk PE.
    bool InspectModuleStomping(uint32_t pid, std::vector<DeepEvidence>& out);

    /// Inspect threads for stack pivots and control-flow anomalies.
    bool InspectThreads(uint32_t pid, std::vector<DeepEvidence>& out);

    /// Convert DeepEvidence into a DetectionEvent for the Correlator.
    static DetectionEvent ToDetectionEvent(const DeepEvidence& e);

    /// Statistics
    struct Stats {
        uint64_t inspectionsRun = 0;
        uint64_t findingsRaised = 0;
        uint64_t failed         = 0;
    };
    [[nodiscard]] Stats GetStats() const noexcept {
        return Stats{m_inspections.load(),
                     m_findings.load(),
                     m_failed.load()};
    }

private:
    std::atomic<uint64_t> m_inspections{0};
    std::atomic<uint64_t> m_findings{0};
    std::atomic<uint64_t> m_failed{0};
};

} // namespace Detection
} // namespace ShadowStrike
