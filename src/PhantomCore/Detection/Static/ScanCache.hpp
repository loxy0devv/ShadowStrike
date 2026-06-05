/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * ScanCache — incremental scan cache for StaticEngine results.
 *
 * Design goals:
 *   - Skip rescanning files whose mtime + size are unchanged.
 *   - Automatically invalidate when a file is modified or deleted.
 *   - Bounded LRU (8,192 entries) with O(1) get/put/invalidate.
 *   - Fully thread-safe: shared_mutex lets concurrent readers proceed
 *     without serialising against one another on the hot path.
 *   - In-memory only — no disk persistence, no I/O overhead.
 */

#pragma once

#include "StaticEngine.hpp"

#include <cstdint>
#include <filesystem>
#include <list>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

namespace ShadowStrike {
namespace Detection {

/**
 * @class ScanCache
 * @brief LRU cache that maps (canonical_path, file_size, last_write_time) →
 *        StaticReport.
 *
 * Thread safety:
 *   Get()        — shared_lock  (many concurrent readers allowed)
 *   Put()        — unique_lock  (exclusive write)
 *   Invalidate() — unique_lock  (exclusive write)
 *
 * Cache key includes both file_size and last_write_time so that:
 *   - A file written with the same size still invalidates (mtime changed).
 *   - A file restored from backup at the same mtime is rechecked (size changed).
 *   - Two different paths never collide (path is part of the key).
 */
class ScanCache {
public:
    // -------------------------------------------------------------------------
    // Singleton access
    // -------------------------------------------------------------------------
    [[nodiscard]] static ScanCache& Instance() noexcept;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * @brief Query the cache for a file.
     *
     * Reads file_size and last_write_time from disk to form the lookup key.
     * Returns true and fills @p out when a fresh cached result exists.
     * Returns false on cache miss OR when the filesystem call fails (e.g.
     * file deleted between the call that triggered scanning and this lookup).
     *
     * This is the hot path — protected by shared_lock so it never serialises
     * against concurrent readers.
     */
    [[nodiscard]] bool Get(const std::filesystem::path& path,
                           StaticReport& out) const noexcept;

    /**
     * @brief Store a scan result.
     *
     * Reads file_size and last_write_time to form the key.
     * Evicts the LRU entry if the cache is at capacity.
     * No-op if the filesystem call to obtain file metadata fails.
     */
    void Put(const std::filesystem::path& path, StaticReport result);

    /**
     * @brief Invalidate all cache entries whose path matches @p path
     *        (regardless of size/mtime).
     *
     * Called when a file-write or file-delete event is observed so that the
     * next scan always sees fresh results.
     */
    void Invalidate(const std::filesystem::path& path) noexcept;

    /// Current number of cached entries.
    [[nodiscard]] size_t Size() const noexcept;

    /// Flush all entries.
    void Clear() noexcept;

private:
    // -------------------------------------------------------------------------
    // Key + hash
    // -------------------------------------------------------------------------

    struct Key {
        std::filesystem::path path;   ///< canonical path
        uintmax_t             size;   ///< file_size at scan time
        int64_t               mtime;  ///< last_write_time as nanoseconds since epoch

        [[nodiscard]] bool operator==(const Key& o) const noexcept {
            return size == o.size && mtime == o.mtime && path == o.path;
        }
    };

    struct KeyHash {
        [[nodiscard]] size_t operator()(const Key& k) const noexcept {
            // FNV-1a inspired mix of the three components
            size_t h = 14695981039346656037ULL;
            // Mix size
            h ^= static_cast<size_t>(k.size);
            h *= 1099511628211ULL;
            // Mix mtime
            h ^= static_cast<size_t>(static_cast<uint64_t>(k.mtime));
            h *= 1099511628211ULL;
            // Mix path hash (std::filesystem::path::hash_value)
            h ^= std::filesystem::hash_value(k.path);
            h *= 1099511628211ULL;
            return h;
        }
    };

    // -------------------------------------------------------------------------
    // LRU bookkeeping
    // -------------------------------------------------------------------------

    // The LRU list holds Keys in MRU→LRU order (front = most recently used).
    using LruList  = std::list<Key>;
    using LruIt    = LruList::iterator;
    using MapValue = std::pair<StaticReport, LruIt>;
    using Map      = std::unordered_map<Key, MapValue, KeyHash>;

    mutable std::shared_mutex m_mutex;
    LruList                   m_lruList;
    Map                       m_map;

    static constexpr size_t kMaxEntries = 8192;

    // -------------------------------------------------------------------------
    // Internal helpers (called under appropriate locks)
    // -------------------------------------------------------------------------

    /**
     * @brief Build a Key by querying the filesystem.
     *
     * Returns std::nullopt when the path does not exist or stat fails.
     */
    [[nodiscard]] static std::optional<Key>
        MakeKey(const std::filesystem::path& p) noexcept;

    // Move the iterator for an existing map entry to the front of m_lruList.
    void TouchLocked(Map::iterator it) noexcept;

    // Evict the LRU (back of list) entry. Must hold unique_lock.
    void EvictOneLocked() noexcept;

    // Singleton
    ScanCache()  = default;
    ~ScanCache() = default;

    ScanCache(const ScanCache&)            = delete;
    ScanCache& operator=(const ScanCache&) = delete;
};

} // namespace Detection
} // namespace ShadowStrike
