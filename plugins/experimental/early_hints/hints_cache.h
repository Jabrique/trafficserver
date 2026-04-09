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
#include <ctime>

// RAII guard for TSMutex — ensures unlock on all exit paths including exceptions
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

using LinkList    = std::vector<std::string>;
using LinkListPtr = std::shared_ptr<const LinkList>;

struct HintEntry {
  LinkListPtr links;
  time_t last_updated = 0;
  int learn_count     = 0;
};

// File format magic: "EH" (Early Hints) + version 1
static constexpr uint32_t HINTS_CACHE_MAGIC = 0x45480001;

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
   * Returns non-null if entry exists and learn_count >= min_hits.
   * Entries never expire — they live until evicted by capacity or process restart.
   */
  LinkListPtr get(const std::string &key, int min_hits);

  /**
   * Thread-safe get (legacy): copies links into output vector.
   * Returns true if entry exists and learn_count >= min_hits.
   */
  bool get(const std::string &key, std::vector<std::string> &links, int min_hits);

  /**
   * Thread-safe put: updates or creates entry.
   * Respects max_entries limit (evicts oldest entries when full).
   * If a persist path is set, persists the cache to disk after every update.
   */
  void put(const std::string &key, const std::vector<std::string> &links);

  /** Get total entries (for stats). */
  size_t size();

  /** Get count of entries dropped due to cache being full. */
  int64_t drops() const;

  /**
   * Normalize URL path to cache key.
   * Strips query string — intentional: <head> resources are typically
   * identical across query string variants for the same path.
   */
  static std::string make_key(const char *path, int path_len);

  /** Set file path for disk persistence. Empty = no persistence (default). */
  void set_persist_path(const std::string &path);

  /** Persist entire cache to disk (atomic: write tmp → rename). */
  bool persist_to_disk();

  /** Load cache from disk. Returns true on success, false on error (cache stays empty). */
  bool load_from_disk();

private:
  TSMutex mutex_;
  std::unordered_map<std::string, HintEntry> entries_;
  int64_t drop_counter_ = 0;
  int max_entries_;
  std::string persist_path_;

  // Evict oldest entries when cache is full (called with mutex held)
  void evict_oldest();
};
