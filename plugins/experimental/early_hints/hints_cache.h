/** @file
 * Thread-safe hints cache with capacity-based eviction and optional disk persistence
 * for the early_hints plugin.
 *
 * @section license License
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <ts/ts.h>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <atomic>
#include <ctime>

// RAII guard for TSMutex  -- ensures unlock on all exit paths including exceptions
class TSMutexGuard
{
public:
  explicit TSMutexGuard(TSMutex m) : m_(m) { TSMutexLock(m_); }
  ~TSMutexGuard() { TSMutexUnlock(m_); }
  TSMutexGuard(const TSMutexGuard &) = delete;
  TSMutexGuard &operator=(const TSMutexGuard &) = delete;

private:
  TSMutex m_;
};

#include <list>

using LinkList    = std::vector<std::string>;
using LinkListPtr = std::shared_ptr<const LinkList>;

struct HintEntry {
  LinkListPtr links;
  time_t last_updated       = 0;
  mutable int request_count = 0; // Traffic gate: incremented by get(), NOT by put(). Not persisted.
  mutable std::list<std::string>::iterator lru_iterator{};
};

// File format magic: "EH" (Early Hints)
// v1 (0x45480001): original format (key + learn_count + links)
// v2 (0x45480002): adds per-entry last_updated after learn_count
// v3 (0x45480003): removes learn_count (dead code); format is key + last_updated + links
static constexpr uint32_t HINTS_CACHE_MAGIC    = 0x45480003;
static constexpr uint32_t HINTS_CACHE_MAGIC_V2 = 0x45480002;
static constexpr uint32_t HINTS_CACHE_MAGIC_V1 = 0x45480001;

class HintsCache
{
public:
  static constexpr int DEFAULT_MAX_ENTRIES = 10000;

  explicit HintsCache(int max_entries = DEFAULT_MAX_ENTRIES);
  ~HintsCache();

  // Noncopyable
  HintsCache(const HintsCache &) = delete;
  HintsCache &operator=(const HintsCache &) = delete;

  /**
   * Thread-safe get: returns shared_ptr to immutable link list (no deep copy).
   * Returns non-null if entry exists and request_count >= min_hits.
   * Increments request_count on every call (request_count is the only traffic gate).
   * If stale_evict_after > 0 and age(entry) > stale_evict_after, the entry is
   * served once then removed from the cache (stale eviction). Default 0 = disabled.
   */
  LinkListPtr get(const std::string &key, int min_hits, int stale_evict_after = 0);

  /**
   * Thread-safe get (legacy): copies links into output vector.
   * Returns true if entry exists and request_count >= min_hits.
   */
  bool get(const std::string &key, std::vector<std::string> &links, int min_hits, int stale_evict_after = 0);

  /**
   * Thread-safe peek: returns links if entry exists, regardless of request_count or min_hits.
   * Does NOT increment request_count. Use for:
   *   - Scanner skip check (entry has been learned before → skip scanner)
   *   - SEND_RESPONSE_HDR fallback (get links without double-counting traffic)
   */
  LinkListPtr peek(const std::string &key) const;

  /**
   * Thread-safe put: updates or creates entry.
   * Respects max_entries limit (evicts oldest entries when full).
   * If a persist path is set, persists the cache to disk after every update.
   */
  void put(const std::string &key, const std::vector<std::string> &links);

  /**
   * Thread-safe age lookup: returns (now - last_updated) in seconds for the entry.
   * Returns -1 if the entry does not exist.
   * Does NOT increment request_count.
   */
  time_t get_age(const std::string &key) const;

  /**
   * Thread-safe touch: resets last_updated to now without changing links.
   * Marks the entry dirty so the next persist flush writes the fresh timestamp.
   * No-op if the key does not exist.
   * Used by READ_CACHE_HDR when hints are stale but the HTML body is frozen in
   * the ATS cache  -- re-scanning is not possible, so just refresh the TTL.
   */
  void touch(const std::string &key);

  /**
   * Thread-safe remove: erases the entry for key from the cache.
   * Marks dirty so the next persist flush reflects the deletion.
   * No-op if the key does not exist.
   * Used by the purge-header path in TSRemapDoRemap to invalidate stale hints
   * on deploy. The purging request itself will re-learn via the scanner.
   */
  void remove(const std::string &key);

  /** Get total entries (for stats). */
  size_t size() const;

  /** Get count of entries dropped due to cache being full. */
  int64_t drops() const;

  /**
   * Thread-safe request count lookup: returns request_count for the entry.
   * Returns 0 if the entry does not exist.
   * Does NOT increment request_count. Used by SEND_RESPONSE_HDR to guard the
   * peek() fallback path against serving 200 Link headers before min_hit_count
   * is reached (peek() ignores the threshold by design).
   */
  int get_count(const std::string &key) const;

  /**
   * Number of times persist_to_disk() was actually called inside put().
   * Used by unit tests to verify the equality-check debounce:
   * identical link content for an existing key must NOT increment this counter.
   */
  int64_t put_persist_count() const;

  /**
   * Normalize URL path to cache key.
   * Strips query string  -- intentional: <head> resources are typically
   * identical across query string variants for the same path.
   */
  static std::string make_key(const char *path, int path_len);

  /** Set file path for disk persistence. Empty = no persistence (default). */
  void set_persist_path(const std::string &path);

  /** Get file path for disk persistence. */
  const std::string &
  get_persist_path() const
  {
    return persist_path_;
  }

  /** Persist entire cache to disk (atomic: write tmp → rename). */
  bool persist_to_disk();

  /** Load cache from disk. Returns true on success, false on error (cache stays empty). */
  bool load_from_disk();

  /**
   * Set minimum number of seconds between two automatic persist_to_disk() calls.
   * 0 = persist on every put() that sets is_dirty_. Default = 10s.
   * Thread-safe only if called before concurrent put() begins.
   */
  void
  set_persist_throttle(int seconds)
  {
    persist_throttle_interval_ = seconds;
  }

  /** Current dirty generation counter value (for unit testing). */
  uint64_t
  dirty_generation() const
  {
    return dirty_generation_.load(std::memory_order_acquire);
  }

  /** Number of entries evicted due to capacity (for unit testing). */
  int64_t evict_count() const;

private:
  mutable TSMutex mutex_;
  mutable TSMutex persist_mutex_; // Serialize persist_to_disk()  -- prevents concurrent disk writes
  std::unordered_map<std::string, HintEntry> entries_;
  mutable std::list<std::string> lru_list_; // LRU list of keys (front = MRU, back = LRU)
  int64_t drop_counter_ = 0;
  std::atomic<int64_t> persist_count_{0};           // Counts actual persist_to_disk() calls inside put()
  std::atomic<int64_t> evict_count_{0};             // Counts entries evicted by evict_oldest()
  mutable std::atomic<uint32_t> access_counter_{0}; // For probabilistic LRU promotion (1/16)
  int max_entries_;
  std::string persist_path_;

  // --- Throttle state ---
  std::atomic<bool> is_dirty_{false};
  std::atomic<uint64_t> dirty_generation_{0};
  time_t last_persist_time_      = 0;
  int persist_throttle_interval_ = 10;

  static constexpr int MAX_KEY_LEN = 4096; // Reject keys longer than this in put()

  // Evict oldest entries when cache is full (called with mutex held)
  void evict_oldest();
};
