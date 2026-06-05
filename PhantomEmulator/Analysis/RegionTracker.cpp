/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RegionTracker.cpp — CAPE-inspired tracked-region implementation.
 *
 * Key CAPE concepts integrated:
 *   1. Entropy baseline recorded at MEM_COMMIT
 *   2. Entropy delta > kEntropyDeltaThreshold → trigger dump candidate
 *   3. Sub-allocation: RESERVE then COMMIT sets SubAllocation flag
 *   4. VirtualProtect RW→RX transition marks region Executable
 *   5. HasPEHeader check before dump (mirrors capemon's TestPERequirements)
 *
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "RegionTracker.hpp"
#include "../Core/Memory/VirtualMemory.hpp"

#include <algorithm>
#include <array>
#include <cmath>

namespace Phantom {

// PAGE_* protection constants (mirror Windows values for emulator context)
static constexpr uint32_t kPAGE_EXECUTE           = 0x10;
static constexpr uint32_t kPAGE_EXECUTE_READ       = 0x20;
static constexpr uint32_t kPAGE_EXECUTE_READWRITE  = 0x40;
static constexpr uint32_t kPAGE_EXECUTE_WRITECOPY  = 0x80;
static constexpr uint32_t kPAGE_READWRITE          = 0x04;
static constexpr uint32_t kPAGE_WRITECOPY          = 0x08;

static constexpr uint32_t kMEM_COMMIT  = 0x1000;
static constexpr uint32_t kMEM_RESERVE = 0x2000;

// ---------------------------------------------------------------------------

bool RegionTracker::IsExecutable(uint32_t protect) noexcept {
    return (protect & (kPAGE_EXECUTE | kPAGE_EXECUTE_READ |
                       kPAGE_EXECUTE_READWRITE | kPAGE_EXECUTE_WRITECOPY)) != 0;
}

bool RegionTracker::IsWritable(uint32_t protect) noexcept {
    return (protect & (kPAGE_READWRITE | kPAGE_WRITECOPY |
                       kPAGE_EXECUTE_READWRITE | kPAGE_EXECUTE_WRITECOPY)) != 0;
}

double RegionTracker::ComputeEntropy(const VirtualMemory& memory,
                                      GuestAddress base, GuestSize size) noexcept {
    if (size == 0 || size > kMaxDumpableRegionSize) return 0.0;
    // Read up to 64 KB sample for entropy (mirrors capemon's approach — full PE
    // entropy is expensive; sample is sufficient for delta detection).
    constexpr GuestSize kMaxSample = 64 * 1024;
    const GuestSize sample = std::min(size, kMaxSample);

    std::array<uint32_t, 256> freq{};
    size_t readable = 0;
    // Read in 4 KB pages to tolerate partial accessibility
    for (GuestSize off = 0; off < sample; off += 4096) {
        const GuestSize chunk = std::min<GuestSize>(4096, sample - off);
        uint8_t buf[4096];
        if (!memory.ReadGuestMemory(base + off, buf, chunk)) continue;
        for (size_t i = 0; i < chunk; ++i) freq[buf[i]]++;
        readable += chunk;
    }
    if (readable == 0) return 0.0;

    double h = 0.0;
    const double n = static_cast<double>(readable);
    for (auto c : freq) {
        if (!c) continue;
        const double p = c / n;
        h -= p * std::log2(p);
    }
    return h;
}

bool RegionTracker::HasPEHeader(const VirtualMemory& memory,
                                 GuestAddress base) noexcept {
    uint8_t header[64];
    if (!memory.ReadGuestMemory(base, header, sizeof(header))) return false;
    // DOS signature
    if (header[0] != 'M' || header[1] != 'Z') return false;
    // e_lfanew
    int32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, header + 60, 4);
    if (e_lfanew < 0 || e_lfanew > 0x800) return false;
    // PE signature
    uint8_t peSig[4];
    if (!memory.ReadGuestMemory(base + static_cast<GuestAddress>(e_lfanew), peSig, 4)) return false;
    return peSig[0] == 'P' && peSig[1] == 'E' && peSig[2] == 0 && peSig[3] == 0;
}

TrackedRegion* RegionTracker::FindMutable(GuestAddress addr) noexcept {
    for (auto& r : m_regions) {
        if (addr >= r.allocationBase && addr < r.allocationBase + r.regionSize)
            return &r;
    }
    return nullptr;
}

const TrackedRegion* RegionTracker::Find(GuestAddress addr) const noexcept {
    return const_cast<RegionTracker*>(this)->FindMutable(addr);
}

// ---------------------------------------------------------------------------

void RegionTracker::OnAllocation(GuestAddress base, GuestSize size, uint32_t type,
                                  uint32_t protect, uint64_t instrCount,
                                  const VirtualMemory& memory) noexcept {
    if (base == 0 || size == 0 || size > kMaxDumpableRegionSize) return;
    if (m_regions.size() >= kMaxRegions) return;

    auto* existing = FindMutable(base);

    if (type & kMEM_COMMIT) {
        if (existing && existing->state == RegionState::Reserved) {
            // RESERVE followed by COMMIT — this is the sub-allocation pattern
            existing->state = RegionState::Committed;
            existing->currentProtect = protect;
            existing->instrAtCommit = instrCount;
            existing->subAllocation = true;
            // Record entropy baseline on first commit
            if (existing->entropyBaseline == 0.0 && size >= kMinDumpableRegionSize) {
                existing->entropyBaseline = ComputeEntropy(memory, base, size);
                existing->entropyLast = existing->entropyBaseline;
            }
        } else if (!existing) {
            // Fresh commit
            TrackedRegion r;
            r.allocationBase  = base;
            r.regionSize      = size;
            r.protect         = protect;
            r.currentProtect  = protect;
            r.state           = IsExecutable(protect) ? RegionState::Executable
                              : (IsWritable(protect)  ? RegionState::Writable
                                                      : RegionState::Committed);
            r.instrAtCommit   = instrCount;
            if (size >= kMinDumpableRegionSize) {
                r.entropyBaseline = ComputeEntropy(memory, base, size);
                r.entropyLast = r.entropyBaseline;
            }
            m_regions.push_back(r);
        }
    } else if (type & kMEM_RESERVE) {
        if (!existing) {
            TrackedRegion r;
            r.allocationBase = base;
            r.regionSize     = size;
            r.protect        = protect;
            r.currentProtect = protect;
            r.state          = RegionState::Reserved;
            r.instrAtCommit  = instrCount;
            m_regions.push_back(r);
        }
    }
}

void RegionTracker::OnProtectionChange(GuestAddress base, uint32_t newProtect,
                                        uint32_t /*oldProtect*/, uint64_t instrCount,
                                        const VirtualMemory& memory) noexcept {
    auto* r = FindMutable(base);
    if (!r) return;

    const bool wasExec = IsExecutable(r->currentProtect);
    const bool isNowExec = IsExecutable(newProtect);

    r->currentProtect = newProtect;

    if (!wasExec && isNowExec) {
        // W→X transition: this is a prime unpack trigger
        r->state = RegionState::Executable;
        r->instrAtExec = instrCount;
        r->triggered = false;  // Allow dump on next entropy check

        // Update entropy snapshot at transition
        if (r->regionSize >= kMinDumpableRegionSize) {
            r->entropyLast = ComputeEntropy(memory, base, r->regionSize);
        }
    } else if (IsWritable(newProtect) && !IsWritable(r->currentProtect)) {
        r->state = RegionState::Writable;
        r->triggered = false;
    }
}

void RegionTracker::OnFree(GuestAddress base) noexcept {
    auto it = std::remove_if(m_regions.begin(), m_regions.end(),
        [base](const TrackedRegion& r) {
            return r.allocationBase == base;
        });
    m_regions.erase(it, m_regions.end());
}

std::vector<RegionTracker::DumpCandidate> RegionTracker::CheckEntropyDelta(
    uint64_t /*instrCount*/, const VirtualMemory& memory) noexcept {
    std::vector<DumpCandidate> out;

    for (auto& r : m_regions) {
        if (r.state != RegionState::Executable) continue;
        if (r.regionSize < kMinDumpableRegionSize) continue;
        if (r.triggered && r.dumpCount > 0) continue;

        const double current = ComputeEntropy(memory, r.allocationBase, r.regionSize);
        if (current == 0.0) continue;

        const double baseline = (r.entropyBaseline > 0.0) ? r.entropyBaseline : r.entropyLast;
        const double delta = std::abs(current - baseline);

        // CAPE insight: entropy drop (data being decrypted) is as significant as entropy rise
        // Delta > threshold → payload has been written/modified since baseline
        if (delta > kEntropyDeltaThreshold || (r.dumpCount == 0 && current > 6.0)) {
            DumpCandidate dc;
            dc.base          = r.allocationBase;
            dc.size          = r.regionSize;
            dc.entropyBefore = baseline;
            dc.entropyNow    = current;
            dc.delta         = delta;
            dc.isPE          = HasPEHeader(memory, r.allocationBase);
            out.push_back(dc);

            // Update last entropy so we don't re-trigger until another change
            r.entropyLast = current;
            r.triggered   = true;
            r.dumpCount++;
        }
    }

    return out;
}

void RegionTracker::MarkDumped(GuestAddress base) noexcept {
    auto* r = FindMutable(base);
    if (!r) return;
    r->entropyLast = 0.0; // Force re-check on next significant change
    r->triggered   = false;
}

std::vector<const TrackedRegion*> RegionTracker::GetExecutableRegions() const {
    std::vector<const TrackedRegion*> out;
    for (const auto& r : m_regions)
        if (r.state == RegionState::Executable) out.push_back(&r);
    return out;
}

} // namespace Phantom
