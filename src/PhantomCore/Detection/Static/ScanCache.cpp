/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * ScanCache implementation — see ScanCache.hpp for design notes.
 */

#include "pch.h"
#include "ScanCache.hpp"

#include <chrono>
#include <system_error>
#include <vector>

namespace ShadowStrike {
namespace Detection {

// =============================================================================
// Singleton
// =============================================================================

ScanCache& ScanCache::Instance() noexcept {
    static ScanCache s_instance;
    return s_instance;
}

// =============================================================================
// MakeKey — read file metadata from disk
// =============================================================================

std::optional<ScanCache::Key> ScanCache::MakeKey(const std::filesystem::path& p) noexcept {
    try {
        std::error_code ec;

        // Canonicalize: resolve symlinks and normalise separators so that
        // "C:\foo\bar.exe" and "c:/foo/bar.exe" hash to the same entry.
        std::filesystem::path canon = std::filesystem::canonical(p, ec);
        if (ec) {
            // canonical() fails if the file doesn't exist — use the path as-is
            // so Invalidate() can still match by raw path.
            canon = p;
        }

        const auto sz = std::filesystem::file_size(canon, ec);
        if (ec) return std::nullopt;

        const auto lwt = std::filesystem::last_write_time(canon, ec);
        if (ec) return std::nullopt;

        // Convert file_time_type to a stable integer (nanoseconds since epoch).
        // file_time_type is implementation-defined but duration_cast is portable.
        const int64_t mtime = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                lwt.time_since_epoch()
            ).count()
        );

        return Key{ std::move(canon), sz, mtime };

    } catch (...) {
        return std::nullopt;
    }
}

// =============================================================================
// Get — shared (read) path
// =============================================================================

bool ScanCache::Get(const std::filesystem::path& path,
                    StaticReport& out) const noexcept {
    auto keyOpt = MakeKey(path);
    if (!keyOpt) return false;   // file not accessible → cache miss

    std::shared_lock lock(m_mutex);

    auto it = m_map.find(*keyOpt);
    if (it == m_map.end()) return false;

    out = it->second.first;    // copy StaticReport
    // Note: we do NOT update the LRU position on a read because that would
    // require upgrading to a unique_lock on the hot path.  The cache provides
    // correctness guarantees regardless of LRU order — only eviction policy is
    // slightly imprecise (reads don't refresh recency).  This is an intentional
    // trade-off: avoiding unique_lock contention on every read is more valuable
    // than perfect LRU accuracy under mixed read/write concurrency.
    return true;
}

// =============================================================================
// Put — exclusive (write) path
// =============================================================================

void ScanCache::Put(const std::filesystem::path& path, StaticReport result) {
    auto keyOpt = MakeKey(path);
    if (!keyOpt) return;   // can't stat the file — skip caching

    std::unique_lock lock(m_mutex);

    // If the same key is already present, update in place.
    auto it = m_map.find(*keyOpt);
    if (it != m_map.end()) {
        it->second.first = std::move(result);
        TouchLocked(it);
        return;
    }

    // Evict if at capacity.
    if (m_map.size() >= kMaxEntries) {
        EvictOneLocked();
    }

    // Insert at front of LRU list (most recently used).
    m_lruList.push_front(*keyOpt);
    m_map.emplace(*keyOpt, MapValue{ std::move(result), m_lruList.begin() });
}

// =============================================================================
// Invalidate — remove all entries for this path (any size/mtime)
// =============================================================================

void ScanCache::Invalidate(const std::filesystem::path& path) noexcept {
    try {
        // Build a canonical path for comparison (ignore errors — compare raw too).
        std::error_code ec;
        std::filesystem::path canon = std::filesystem::canonical(path, ec);
        if (ec) canon = path;

        std::unique_lock lock(m_mutex);

        // Collect keys to erase (can't erase while iterating unordered_map with
        // a range-for if we're also removing LRU list nodes).
        std::vector<Map::iterator> toErase;
        toErase.reserve(4);

        for (auto it = m_map.begin(); it != m_map.end(); ++it) {
            if (it->first.path == canon || it->first.path == path) {
                toErase.push_back(it);
            }
        }

        for (auto& it : toErase) {
            m_lruList.erase(it->second.second);
            m_map.erase(it);
        }

    } catch (...) {
        // Invalidate must never throw — it's called from event handlers.
    }
}

// =============================================================================
// Size
// =============================================================================

size_t ScanCache::Size() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_map.size();
}

// =============================================================================
// Clear
// =============================================================================

void ScanCache::Clear() noexcept {
    std::unique_lock lock(m_mutex);
    m_map.clear();
    m_lruList.clear();
}

// =============================================================================
// Private helpers
// =============================================================================

void ScanCache::TouchLocked(Map::iterator it) noexcept {
    // Move this key's LRU iterator to the front.
    m_lruList.splice(m_lruList.begin(), m_lruList, it->second.second);
    it->second.second = m_lruList.begin();
}

void ScanCache::EvictOneLocked() noexcept {
    if (m_lruList.empty()) return;

    // The back of the list is the least recently used.
    // Copy the key out BEFORE touching the list — pop_back() destroys the node,
    // which would leave a dangling reference if we held a Key& instead.
    Key lruKey = m_lruList.back();   // copy, not reference
    m_lruList.pop_back();             // destroy list node (lruKey is now our own copy)
    m_map.erase(lruKey);              // erase using the copy
}

} // namespace Detection
} // namespace ShadowStrike
