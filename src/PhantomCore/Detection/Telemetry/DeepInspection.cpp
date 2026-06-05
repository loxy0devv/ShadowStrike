/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * User-mode probes that implement the HyperDbg-aligned deep inspection
 * concepts. Kernel-mode counterparts in PhantomSensor.sys provide the
 * authoritative view; this layer exists for cases where the kernel
 * sensor cannot reach (e.g. PPL-protected processes the driver
 * intentionally skips, or when running standalone in tests).
 */

#include "pch.h"
#include "DeepInspection.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <algorithm>
#include <fstream>

namespace ShadowStrike {
namespace Detection {

namespace {

std::string narrow(const std::wstring& w) {
    std::string s; s.reserve(w.size());
    for (auto c : w) s.push_back(static_cast<char>(c & 0xFF));
    return s;
}

bool readModulePath(HANDLE proc, HMODULE mod, std::wstring& out) {
    WCHAR buf[MAX_PATH];
    DWORD n = GetModuleFileNameExW(proc, mod, buf, MAX_PATH);
    if (n == 0) return false;
    out.assign(buf, n);
    return true;
}

bool addressInsideModule(uintptr_t addr, uintptr_t modBase, size_t modSize) noexcept {
    return addr >= modBase && addr < modBase + modSize;
}

} // anon

bool DeepInspector::InspectMemoryMap(uint32_t pid, std::vector<DeepEvidence>& out) {
    m_inspections.fetch_add(1, std::memory_order_relaxed);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) { m_failed.fetch_add(1, std::memory_order_relaxed); return false; }

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t end  = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < end) {
        if (VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        bool exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        bool writ = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (exec && mbi.State == MEM_COMMIT) {
            bool backedByImage = (mbi.Type == MEM_IMAGE);
            if (!backedByImage) {
                DeepEvidence e;
                e.pid = pid;
                e.address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                e.finding = DeepFinding::UnbackedExecutionAttempt;
                e.detail = "executable non-image region";
                e.severity = RuleSeverity::High;
                e.confidence = 0.8f;
                out.push_back(std::move(e));
                m_findings.fetch_add(1, std::memory_order_relaxed);
            } else if (writ) {
                DeepEvidence e;
                e.pid = pid;
                e.address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                e.finding = DeepFinding::DynamicCodeExecution;
                e.detail = "RWX image region";
                e.severity = RuleSeverity::High;
                e.confidence = 0.85f;
                out.push_back(std::move(e));
                m_findings.fetch_add(1, std::memory_order_relaxed);
            }
        }
        addr += mbi.RegionSize ? mbi.RegionSize : si.dwPageSize;
        if (mbi.RegionSize == 0) break;
    }

    CloseHandle(h);
    return true;
}

bool DeepInspector::InspectSyscallSites(uint32_t pid, std::vector<DeepEvidence>& out) {
    m_inspections.fetch_add(1, std::memory_order_relaxed);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) { m_failed.fetch_add(1, std::memory_order_relaxed); return false; }

    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, modules, sizeof(modules), &needed,
                              LIST_MODULES_ALL)) {
        CloseHandle(h);
        m_failed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    size_t count = needed / sizeof(HMODULE);
    uintptr_t ntdllBase = 0, ntdllSize = 0;
    uintptr_t wow64Base = 0, wow64Size = 0;
    for (size_t i = 0; i < count; ++i) {
        std::wstring path;
        if (!readModulePath(h, modules[i], path)) continue;
        MODULEINFO mi{};
        if (!GetModuleInformation(h, modules[i], &mi, sizeof(mi))) continue;
        std::wstring lower = path;
        for (auto& c : lower) c = (WCHAR)std::tolower((wchar_t)c);
        if (lower.find(L"\\ntdll.dll") != std::wstring::npos) {
            ntdllBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            ntdllSize = mi.SizeOfImage;
        } else if (lower.find(L"\\wow64cpu.dll") != std::wstring::npos) {
            wow64Base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            wow64Size = mi.SizeOfImage;
        }
    }

    if (ntdllBase == 0) { CloseHandle(h); return true; }

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t end  = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t buf[4096];
    while (addr < end) {
        if (VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        bool exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (exec && mbi.State == MEM_COMMIT) {
            size_t off = 0;
            while (off < mbi.RegionSize) {
                SIZE_T read = 0;
                size_t want = std::min<size_t>(sizeof(buf),
                                               mbi.RegionSize - off);
                if (!ReadProcessMemory(h,
                        reinterpret_cast<LPCVOID>(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + off),
                        buf, want, &read) || read < 2) break;
                for (size_t i = 0; i + 2 <= read; ++i) {
                    // SYSCALL: 0F 05  /  SYSENTER: 0F 34
                    bool sys = (buf[i] == 0x0F && (buf[i+1] == 0x05 || buf[i+1] == 0x34));
                    if (!sys) continue;
                    uintptr_t at = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + off + i;
                    bool inNtdll = addressInsideModule(at, ntdllBase, ntdllSize);
                    bool inWow64 = wow64Base && addressInsideModule(at, wow64Base, wow64Size);
                    if (inNtdll || inWow64) continue;
                    DeepEvidence e;
                    e.pid = pid;
                    e.address = at;
                    e.finding = DeepFinding::DirectSyscallSite;
                    e.detail = "syscall instruction outside ntdll";
                    e.severity = RuleSeverity::High;
                    e.confidence = 0.9f;
                    out.push_back(std::move(e));
                    m_findings.fetch_add(1, std::memory_order_relaxed);
                }
                off += read;
            }
        }
        addr += mbi.RegionSize ? mbi.RegionSize : si.dwPageSize;
        if (mbi.RegionSize == 0) break;
    }
    CloseHandle(h);
    return true;
}

bool DeepInspector::InspectModuleStomping(uint32_t pid, std::vector<DeepEvidence>& out) {
    m_inspections.fetch_add(1, std::memory_order_relaxed);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) { m_failed.fetch_add(1, std::memory_order_relaxed); return false; }

    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, modules, sizeof(modules), &needed,
                              LIST_MODULES_ALL)) {
        CloseHandle(h);
        m_failed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    size_t count = needed / sizeof(HMODULE);
    for (size_t i = 0; i < count; ++i) {
        std::wstring path;
        MODULEINFO mi{};
        if (!readModulePath(h, modules[i], path)) continue;
        if (!GetModuleInformation(h, modules[i], &mi, sizeof(mi))) continue;

        // Read first 0x400 bytes of in-memory PE, compare DOS+NT header layout
        uint8_t mem[0x400];
        SIZE_T r = 0;
        if (!ReadProcessMemory(h, mi.lpBaseOfDll, mem, sizeof(mem), &r) || r < 0x40)
            continue;

        std::ifstream f(path, std::ios::binary);
        if (!f) continue;
        uint8_t disk[0x400];
        f.read(reinterpret_cast<char*>(disk), sizeof(disk));
        std::streamsize got = f.gcount();
        if (got < 0x40) continue;

        // Compare e_lfanew and NT signature region. Module-stomping replaces .text
        // contents in memory while keeping headers intact, so this catches gross
        // mismatches but not surgical patches — that requires section-level audit.
        if (std::memcmp(mem, disk, std::min<size_t>(0x40, static_cast<size_t>(got))) == 0)
            continue;

        DeepEvidence e;
        e.pid = pid;
        e.address = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        e.moduleName = narrow(path);
        e.finding = DeepFinding::ModuleStomping;
        e.detail = "header mismatch with on-disk image";
        e.severity = RuleSeverity::High;
        e.confidence = 0.85f;
        out.push_back(std::move(e));
        m_findings.fetch_add(1, std::memory_order_relaxed);
    }
    CloseHandle(h);
    return true;
}

bool DeepInspector::InspectThreads(uint32_t pid, std::vector<DeepEvidence>& out) {
    m_inspections.fetch_add(1, std::memory_order_relaxed);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        m_failed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                              FALSE, pid);
    if (!proc) {
        CloseHandle(snap);
        m_failed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, te.th32ThreadID);
            if (!ht) continue;
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(ht, &ctx)) {
#ifdef _WIN64
                uintptr_t sp = ctx.Rsp;
                uintptr_t ip = ctx.Rip;
#else
                uintptr_t sp = ctx.Esp;
                uintptr_t ip = ctx.Eip;
#endif
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(sp), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    bool onStack = (mbi.Type == MEM_PRIVATE &&
                                    (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)));
                    if (!onStack && sp != 0) {
                        DeepEvidence ev;
                        ev.pid = pid; ev.tid = te.th32ThreadID;
                        ev.address = sp;
                        ev.finding = DeepFinding::StackPivot;
                        ev.detail = "RSP outside expected thread stack region";
                        ev.severity = RuleSeverity::High; ev.confidence = 0.8f;
                        out.push_back(std::move(ev));
                        m_findings.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(ip), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (mbi.Type != MEM_IMAGE && ip != 0) {
                        DeepEvidence ev;
                        ev.pid = pid; ev.tid = te.th32ThreadID;
                        ev.address = ip;
                        ev.finding = DeepFinding::UnbackedExecutionAttempt;
                        ev.detail = "thread IP in unbacked memory region";
                        ev.severity = RuleSeverity::Critical; ev.confidence = 0.9f;
                        out.push_back(std::move(ev));
                        m_findings.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
            CloseHandle(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    CloseHandle(proc);
    return true;
}

DetectionEvent DeepInspector::ToDetectionEvent(const DeepEvidence& e) {
    DetectionEvent ev;
    ev.timestamp = std::chrono::system_clock::now();
    ev.category = "deep";
    switch (e.finding) {
        case DeepFinding::DirectSyscallSite:
        case DeepFinding::HeavensGate:
        case DeepFinding::HellsGate:
            ev.scope = RuleScope::Thread; ev.action = "syscall_anomaly"; break;
        case DeepFinding::StackPivot:
        case DeepFinding::ThreadHijack:
        case DeepFinding::ApcInjection:
            ev.scope = RuleScope::Thread; ev.action = "thread_anomaly"; break;
        default:
            ev.scope = RuleScope::Memory; ev.action = "memory_anomaly"; break;
    }
    ev.fields["process.pid"] = static_cast<int64_t>(e.pid);
    ev.fields["thread.id"]   = static_cast<int64_t>(e.tid);
    ev.fields["deep.finding"] = static_cast<int64_t>(static_cast<uint16_t>(e.finding));
    ev.fields["deep.detail"]  = e.detail;
    if (!e.moduleName.empty()) ev.fields["image.path"] = e.moduleName;
    FeatureLeaf fl;
    fl.kind = FeatureKind::Characteristic;
    fl.value = e.detail;
    ev.staticFeatures.push_back(std::move(fl));
    return ev;
}

} // namespace Detection
} // namespace ShadowStrike