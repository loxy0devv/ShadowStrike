/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RegionTracker — CAPE-inspired tracked-region mechanism for emulation.
 *
 * Integrated from: capemon/CAPE/Unpacker.h + CAPE.c concepts
 *
 * CAPE's capemon uses AllocationHandler / ProtectionHandler / FreeHandler to
 * maintain a linked list of "tracked regions" (TRACKEDREGION). When a guest
 * transitions from writable to executable, CAPE:
 *   1. Records the entropy of the region at allocation time (baseline)
 *   2. Periodically checks if entropy has changed by more than ENTROPY_DELTA
 *   3. If entropy changed significantly → dump the region as an unpacked payload
 *   4. Uses hardware breakpoints on the OEP to confirm execution
 *
 * ShadowStrike's emulator already has W→X tracking via UnpackingEngine, but
 * was missing:
 *   - Per-region entropy baseline + delta threshold triggering
 *   - Sub-allocation tracking (MEM_RESERVE then MEM_COMMIT pattern)
 *   - Explicit dump trigger when entropy stabilizes post-unpack
 *
 * This header defines the C++ version of that logic, integrated into the
 * emulator's event callbacks.
 *
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "../Common/Types.hpp"
#include <cstdint>
#include <optional>
#include <vector>

namespace Phantom {

class VirtualMemory;

// Entropy change that signals significant payload transformation.
// Matches capemon's ENTROPY_DELTA = 0.005.
// Lowered slightly (0.003) for our emulation context since we have more control.
inline constexpr double kEntropyDeltaThreshold = 0.003;

// Minimum region size to consider for dump (mirrors capemon's PE_MIN_SIZE).
inline constexpr size_t kMinDumpableRegionSize = 0x800;

// Maximum dump size (mirrors capemon's PE_MAX_SIZE: 0x20000000 = 512 MB,
// lowered to 64 MB for emulation safety).
inline constexpr size_t kMaxDumpableRegionSize = 64u * 1024u * 1024u;

enum class RegionState : uint8_t {
    Reserved,    ///< MEM_RESERVE — not yet committed
    Committed,   ///< MEM_COMMIT with no-exec protection
    Writable,    ///< RW or RWX
    Executable,  ///< RX or RWX — candidate for dump
    Freed,       ///< VirtualFree called
};

struct TrackedRegion {
    GuestAddress allocationBase  = 0;
    GuestSize    regionSize      = 0;
    uint32_t     protect         = 0;   ///< PAGE_* flags at allocation
    uint32_t     currentProtect  = 0;   ///< Current PAGE_* flags
    RegionState  state           = RegionState::Reserved;
    double       entropyBaseline = 0.0; ///< Entropy at first commit
    double       entropyLast     = 0.0; ///< Entropy at last check
    uint64_t     instrAtCommit   = 0;
    uint64_t     instrAtExec     = 0;
    uint32_t     dumpCount       = 0;   ///< How many times we've dumped this region
    bool         subAllocation   = false; ///< Was RESERVE'd before COMMIT
    bool         triggered       = false; ///< Already triggered a dump at current state
};

/// Manages tracked emulated memory regions for CAPE-style unpacking detection.
/// Designed to be called from emulator hook callbacks (VirtualAlloc, VirtualProtect).
class RegionTracker {
public:
    RegionTracker() = default;
    ~RegionTracker() = default;

    // -----------------------------------------------------------------------
    // Emulator hook callbacks — call these from WinAPI emulation stubs
    // -----------------------------------------------------------------------

    /// Called when VirtualAlloc/NtAllocateVirtualMemory allocates memory.
    void OnAllocation(GuestAddress base, GuestSize size, uint32_t type,
                      uint32_t protect, uint64_t instrCount,
                      const VirtualMemory& memory) noexcept;

    /// Called when VirtualProtect/NtProtectVirtualMemory changes protection.
    void OnProtectionChange(GuestAddress base, uint32_t newProtect,
                            uint32_t oldProtect, uint64_t instrCount,
                            const VirtualMemory& memory) noexcept;

    /// Called when VirtualFree releases memory.
    void OnFree(GuestAddress base) noexcept;

    // -----------------------------------------------------------------------
    // Entropy-delta triggered dump detection (CAPE insight)
    // -----------------------------------------------------------------------

    /// Check whether any tracked region's entropy has changed significantly
    /// since last check. Returns regions that should be dumped.
    /// Call this periodically (e.g. every 10,000 instructions).
    struct DumpCandidate {
        GuestAddress base;
        GuestSize    size;
        double       entropyBefore;
        double       entropyNow;
        double       delta;
        bool         isPE;          ///< Detected valid PE header
    };
    std::vector<DumpCandidate> CheckEntropyDelta(uint64_t instrCount,
                                                   const VirtualMemory& memory) noexcept;

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    [[nodiscard]] const TrackedRegion* Find(GuestAddress addr) const noexcept;
    [[nodiscard]] size_t Size() const noexcept { return m_regions.size(); }
    [[nodiscard]] std::vector<const TrackedRegion*> GetExecutableRegions() const;

    /// Mark a region as already-dumped so we don't re-trigger until entropy
    /// changes again by kEntropyDeltaThreshold.
    void MarkDumped(GuestAddress base) noexcept;

private:
    [[nodiscard]] static bool IsExecutable(uint32_t protect) noexcept;
    [[nodiscard]] static bool IsWritable(uint32_t protect) noexcept;
    [[nodiscard]] static double ComputeEntropy(const VirtualMemory& memory,
                                               GuestAddress base, GuestSize size) noexcept;
    [[nodiscard]] static bool HasPEHeader(const VirtualMemory& memory,
                                          GuestAddress base) noexcept;

    TrackedRegion* FindMutable(GuestAddress addr) noexcept;

    static constexpr size_t kMaxRegions = 4096;
    std::vector<TrackedRegion> m_regions;
};

} // namespace Phantom
