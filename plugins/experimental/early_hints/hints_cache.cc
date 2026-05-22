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

#include "hints_cache.h"
#include "config.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

HintsCache::HintsCache(int max_entries) : mutex_(TSMutexCreate()), persist_mutex_(TSMutexCreate()), max_entries_(max_entries) {}

HintsCache::~HintsCache()
{
  // Flush any unsaved data to disk before destroying mutexes.
  // This handles the case where put() was throttled or persist failed mid-session.
  // Acquire persist_mutex_ to serialize with any concurrent put() that may
  // also be calling persist_to_disk(). Lock order: persist_mutex_ then mutex_
  // (inside persist_to_disk), consistent with put() to avoid deadlock.
  if (is_dirty_.load(std::memory_order_acquire) && !persist_path_.empty()) {
    TSMutexGuard persist_guard(persist_mutex_);
    persist_to_disk();
  }

  if (mutex_) {
    TSMutexDestroy(mutex_);
  }
  if (persist_mutex_) {
    TSMutexDestroy(persist_mutex_);
  }
}

LinkListPtr
HintsCache::get(const std::string &key, int min_hits) const
{
  TSMutexGuard guard(mutex_);

  auto it = entries_.find(key);
  if (it == entries_.end()) {
    return nullptr;
  }

  const HintEntry &entry = it->second;

  // Traffic gate: request_count controls when hints are served.
  // Increment first so the very first call counts as request #1.
  // learn_count (incremented by put()) is no longer the serving gate —
  // it only controls persistence. This decouples scanner runs from traffic threshold.
  if (++entry.request_count < min_hits) {
    return nullptr;
  }

  // Probabilistic LRU promotion: only splice 1 out of every 16 accesses.
  // This reduces mutex hold time under high traffic by avoiding the linked
  // list modification on most reads. The LRU order stays approximately correct.
  if ((access_counter_.fetch_add(1, std::memory_order_relaxed) & 0xF) == 0) {
    lru_list_.splice(lru_list_.begin(), lru_list_, entry.lru_iterator);
  }

  // Return shared_ptr (ref-count bump, no deep copy)
  return entry.links;
}

bool
HintsCache::get(const std::string &key, std::vector<std::string> &links, int min_hits) const
{
  LinkListPtr ptr = get(key, min_hits);
  if (!ptr) {
    return false;
  }
  links = *ptr;
  return true;
}

LinkListPtr
HintsCache::peek(const std::string &key) const
{
  TSMutexGuard guard(mutex_);

  auto it = entries_.find(key);
  if (it == entries_.end()) {
    return nullptr;
  }
  // Return links without touching request_count or LRU order.
  // Used for scanner skip check and SEND_RESPONSE_HDR fallback.
  return it->second.links;
}

void
HintsCache::put(const std::string &key, const std::vector<std::string> &links)
{
  // Key length cap — reject keys longer than MAX_KEY_LEN.
  // Oversized keys cannot be URL paths in practice and risk O(n) memory bloat
  // in the persist file. Silently drop and count as a drop.
  if (key.size() > static_cast<size_t>(MAX_KEY_LEN)) {
    TSMutexGuard guard(mutex_);
    drop_counter_++;
    TSDebug("early_hints", "put: key too long (%zu > %d), dropping", key.size(), MAX_KEY_LEN);
    return;
  }

  {
    TSMutexGuard guard(mutex_);

    auto it = entries_.find(key);
    if (it != entries_.end()) {
      HintEntry &entry = it->second;

      // Equality-check debounce: if the incoming links are identical to what is
      // already stored, skip the shared_ptr allocation entirely.  This avoids
      // a heap allocation on every request after the cache warms up.
      if (!entry.links || *entry.links != links) {
        // Allocate inside the lock so the pointer is always in a consistent state.
        entry.links = std::make_shared<const LinkList>(links);
      }
      entry.last_updated = time(nullptr);

      // learn_count cap — cap at max_learn_count() to prevent int overflow
      // under sustained traffic. The count is persisted and used for min_hit_count.
      if (entry.learn_count < max_learn_count()) {
        entry.learn_count++;
      }

      // Move key to front of LRU list since it was updated
      lru_list_.splice(lru_list_.begin(), lru_list_, entry.lru_iterator);
    } else {
      // Enforce max entries limit — evict oldest if at capacity
      if (static_cast<int>(entries_.size()) >= max_entries_) {
        evict_oldest();
        if (static_cast<int>(entries_.size()) >= max_entries_) {
          drop_counter_++;
          TSDebug("early_hints", "cache full (%d entries), dropping key", max_entries_);
          return;
        }
      }

      lru_list_.push_front(key);
      HintEntry entry;
      entry.links        = std::make_shared<const LinkList>(links);
      entry.last_updated = time(nullptr);
      entry.learn_count  = 1;
      entry.lru_iterator = lru_list_.begin();
      entries_[key]      = std::move(entry);
    }

    // Mark cache as dirty so the destructor will flush if put()'s persist fails.
    // Increment generation BEFORE setting dirty flag so persist_to_disk() can
    // detect if a put() occurred between its snapshot and completion.
    dirty_generation_.fetch_add(1, std::memory_order_release);
    is_dirty_.store(true, std::memory_order_release);
  } // mutex released

  // Persist is serialized by persist_mutex_ to prevent two concurrent
  // put() calls from both entering persist_to_disk() simultaneously.
  // persist_to_disk() itself takes a snapshot under mutex_, so double-entry is safe
  // but wastes I/O. persist_mutex_ ensures only one persist runs at a time.
  // The throttle check limits disk writes to at most once per persist_throttle_interval_
  // seconds, preventing I/O storms from rapid put() calls under production traffic.
  if (!persist_path_.empty()) {
    TSMutexGuard persist_guard(persist_mutex_);
    time_t now = time(nullptr);
    if (now - last_persist_time_ >= persist_throttle_interval_) {
      if (persist_to_disk()) {
        last_persist_time_ = now;
        // persist_count_ is std::atomic, no mutex needed, no nested lock.
        persist_count_.fetch_add(1, std::memory_order_relaxed);
      }
    }
  }
}

size_t
HintsCache::size() const
{
  TSMutexGuard guard(mutex_);
  return entries_.size();
}

int64_t
HintsCache::drops() const
{
  TSMutexGuard guard(mutex_);
  return drop_counter_;
}

int64_t
HintsCache::put_persist_count() const
{
  return persist_count_.load(std::memory_order_relaxed);
}

std::string
HintsCache::make_key(const char *path, int path_len)
{
  if (path == nullptr || path_len <= 0) {
    return "/";
  }

  // Strip query string
  const char *qmark = static_cast<const char *>(memchr(path, '?', path_len));
  int key_len       = qmark ? static_cast<int>(qmark - path) : path_len;

  if (key_len <= 0) {
    return "/";
  }

  return std::string(path, key_len);
}

void
HintsCache::evict_oldest()
{
  // Called with mutex_ held. Remove the entry at the back of lru_list_ (Least Recently Used).
  if (lru_list_.empty()) {
    return;
  }

  std::string oldest_key = lru_list_.back();
  entries_.erase(oldest_key);
  lru_list_.pop_back();
}

void
HintsCache::set_persist_path(const std::string &path)
{
  persist_path_ = path;
}

bool
HintsCache::persist_to_disk()
{
  if (persist_path_.empty()) {
    return false;
  }

  // Step 1: Copy data under lock (shared_ptr copies are cheap)
  struct SnapshotEntry {
    std::string key;
    LinkListPtr links;
    int learn_count;
    time_t last_updated;
  };
  std::vector<SnapshotEntry> snapshot;
  uint64_t gen_snapshot = 0;

  {
    TSMutexGuard guard(mutex_);
    // Do NOT clear is_dirty_ here — clear it only after the rename succeeds.
    // Clearing before I/O means a crash or disk-full during fwrite/rename
    // would leave is_dirty_=false, causing the destructor to skip the final
    // flush and permanently lose the unsaved data.
    gen_snapshot = dirty_generation_.load(std::memory_order_acquire);
    snapshot.reserve(entries_.size());
    for (const auto &pair : entries_) {
      snapshot.push_back({pair.first, pair.second.links, pair.second.learn_count, pair.second.last_updated});
    }
  } // mutex released — disk I/O happens without blocking readers

  // Step 2: Serialize to temp file.
  // O_EXCL ensures we never follow a symlink or overwrite an existing file —
  // a pre-existing .tmp is always either a crash remnant (cleaned by load_from_disk)
  // or a symlink planted by an attacker; either way we refuse to write.
  std::string tmp_path = persist_path_ + ".tmp";
  int fd               = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0640);
  if (fd < 0) {
    TSDebug("early_hints", "persist: failed to open %s (O_EXCL): %s", tmp_path.c_str(), strerror(errno));
    return false;
  }
  FILE *fp = fdopen(fd, "wb");
  if (!fp) {
    close(fd);
    std::remove(tmp_path.c_str());
    TSDebug("early_hints", "persist: fdopen failed for %s", tmp_path.c_str());
    return false;
  }

  // Write header: magic + entry count
  uint32_t magic       = HINTS_CACHE_MAGIC;
  uint32_t entry_count = static_cast<uint32_t>(snapshot.size());
  if (fwrite(&magic, sizeof(magic), 1, fp) != 1 || fwrite(&entry_count, sizeof(entry_count), 1, fp) != 1) {
    fclose(fp);
    std::remove(tmp_path.c_str());
    return false;
  }

  // Write each entry
  for (const auto &entry : snapshot) {
    // Key
    uint16_t key_len = static_cast<uint16_t>(entry.key.size());
    if (fwrite(&key_len, sizeof(key_len), 1, fp) != 1 || fwrite(entry.key.data(), key_len, 1, fp) != 1) {
      fclose(fp);
      std::remove(tmp_path.c_str());
      return false;
    }

    // learn_count
    uint32_t lc = static_cast<uint32_t>(entry.learn_count);
    if (fwrite(&lc, sizeof(lc), 1, fp) != 1) {
      fclose(fp);
      std::remove(tmp_path.c_str());
      return false;
    }

    // last_updated (v2 field)
    uint64_t ts = static_cast<uint64_t>(entry.last_updated);
    if (fwrite(&ts, sizeof(ts), 1, fp) != 1) {
      fclose(fp);
      std::remove(tmp_path.c_str());
      return false;
    }

    // Links — count excludes any oversized entries (> UINT16_MAX bytes)
    uint16_t link_count = 0;
    if (entry.links) {
      for (const auto &link : *entry.links) {
        if (link.size() <= UINT16_MAX) {
          link_count++;
        }
      }
    }
    if (fwrite(&link_count, sizeof(link_count), 1, fp) != 1) {
      fclose(fp);
      std::remove(tmp_path.c_str());
      return false;
    }
    if (entry.links) {
      for (const auto &link : *entry.links) {
        if (link.size() > UINT16_MAX) {
          continue; // skip oversized links that would truncate via uint16_t cast
        }
        uint16_t link_len = static_cast<uint16_t>(link.size());
        if (fwrite(&link_len, sizeof(link_len), 1, fp) != 1 || fwrite(link.data(), link_len, 1, fp) != 1) {
          fclose(fp);
          std::remove(tmp_path.c_str());
          return false;
        }
      }
    }
  }

  // Check for buffered write errors before flushing (catches disk-full failures
  // that fwrite() may have silently swallowed into the kernel buffer).
  // fdatasync ensures data reaches stable storage before the atomic rename,
  // preventing a post-rename crash from leaving a zero-length or partial file.
  int sync_fd = fileno(fp);
  if (sync_fd >= 0) {
    fdatasync(sync_fd);
  }
  if (ferror(fp)) {
    fclose(fp);
    std::remove(tmp_path.c_str());
    TSDebug("early_hints", "persist: write error detected (disk full?), aborting rename");
    return false;
  }
  if (fclose(fp) != 0) {
    std::remove(tmp_path.c_str());
    TSDebug("early_hints", "persist: fclose failed, aborting rename");
    return false;
  }

  // Step 3: Atomic rename — only reached when all bytes are confirmed flushed.
  if (rename(tmp_path.c_str(), persist_path_.c_str()) != 0) {
    TSDebug("early_hints", "persist: rename failed");
    std::remove(tmp_path.c_str());
    return false;
  }

  // Rename succeeded — data is safely on disk.
  // Only clear the dirty flag if no put() occurred between our snapshot and now.
  // If dirty_generation_ advanced, a concurrent put() wrote new data that our
  // snapshot does not include — the flag must remain true so the destructor
  // or the next throttled persist will flush the unsaved data.
  {
    TSMutexGuard guard(mutex_);
    if (dirty_generation_.load(std::memory_order_acquire) == gen_snapshot) {
      is_dirty_.store(false, std::memory_order_release);
    }
  }

  TSDebug("early_hints", "persisted %u entries to %s", entry_count, persist_path_.c_str());
  return true;
}

bool
HintsCache::load_from_disk()
{
  if (persist_path_.empty()) {
    return false;
  }

  // Remove any stale .tmp file left by a prior crash. This unblocks the
  // O_EXCL open in persist_to_disk() and prevents it from accumulating.
  std::string tmp_path = persist_path_ + ".tmp";
  if (access(tmp_path.c_str(), F_OK) == 0) {
    if (unlink(tmp_path.c_str()) != 0) {
      TSDebug("early_hints", "load: failed to remove stale .tmp file %s: %s", tmp_path.c_str(), strerror(errno));
    } else {
      TSDebug("early_hints", "load: removed stale .tmp file %s", tmp_path.c_str());
    }
  }

  FILE *fp = fopen(persist_path_.c_str(), "rb");
  if (!fp) {
    TSDebug("early_hints", "load: no persist file at %s", persist_path_.c_str());
    return false;
  }

  // Read header
  uint32_t magic       = 0;
  uint32_t entry_count = 0;
  if (fread(&magic, sizeof(magic), 1, fp) != 1 || fread(&entry_count, sizeof(entry_count), 1, fp) != 1) {
    TSDebug("early_hints", "load: failed to read header");
    fclose(fp);
    return false;
  }

  if (magic == HINTS_CACHE_MAGIC_V1) {
    TSDebug("early_hints", "load: v1 format (0x%08x) not supported, cold start", magic);
    fclose(fp);
    return false;
  }
  if (magic != HINTS_CACHE_MAGIC) {
    TSDebug("early_hints", "load: bad magic 0x%08x (expected 0x%08x)", magic, HINTS_CACHE_MAGIC);
    fclose(fp);
    return false;
  }

  // Sanity check entry count
  if (entry_count > static_cast<uint32_t>(max_entries_) * 2) {
    TSDebug("early_hints", "load: entry count %u exceeds limit", entry_count);
    fclose(fp);
    return false;
  }

  // Atomic swap — build new_entries OUTSIDE the lock, then swap in.
  // This guarantees: if parsing fails mid-way, the existing cache is unaffected.
  // The swap is atomic (hold mutex only for the pointer swap, not for I/O).
  std::unordered_map<std::string, HintEntry> new_entries;

  for (uint32_t i = 0; i < entry_count; i++) {
    // Read key
    uint16_t key_len = 0;
    if (fread(&key_len, sizeof(key_len), 1, fp) != 1 || key_len == 0 || key_len > 4096) {
      TSDebug("early_hints", "load: corrupt entry %u (key_len=%u)", i, key_len);
      fclose(fp);
      return false; // existing cache untouched (swap not done yet)
    }
    std::string key(key_len, '\0');
    if (fread(&key[0], key_len, 1, fp) != 1) {
      fclose(fp);
      return false;
    }

    // Read learn_count
    uint32_t lc = 0;
    if (fread(&lc, sizeof(lc), 1, fp) != 1) {
      fclose(fp);
      return false;
    }
    // Clamp learn_count from disk to max_learn_count().
    // Prevents overflow if file was written by a buggy version without the cap.
    if (static_cast<int>(lc) > max_learn_count()) {
      lc = static_cast<uint32_t>(max_learn_count());
    }

    // Read last_updated (v2 field)
    uint64_t ts_on_disk = 0;
    if (fread(&ts_on_disk, sizeof(ts_on_disk), 1, fp) != 1) {
      fclose(fp);
      return false;
    }

    // Read links
    uint16_t link_count = 0;
    if (fread(&link_count, sizeof(link_count), 1, fp) != 1 || link_count > 1000) {
      fclose(fp);
      return false;
    }

    std::vector<std::string> links;
    links.reserve(link_count);
    for (uint16_t j = 0; j < link_count; j++) {
      uint16_t link_len = 0;
      if (fread(&link_len, sizeof(link_len), 1, fp) != 1 || link_len == 0 || link_len > 8192) {
        fclose(fp);
        return false;
      }
      std::string link(link_len, '\0');
      if (fread(&link[0], link_len, 1, fp) != 1) {
        fclose(fp);
        return false;
      }
      // Re-validate each persisted link value. A file written by an older plugin
      // version may contain rel types or attributes that the current version
      // would reject (e.g. rel=prefetch, preload without as=). Serving stale
      // invalid hints wastes browser fetch budget and may trigger browser warnings.
      if (is_valid_link_value(link) && has_valid_as_for_preload(link)) {
        links.push_back(std::move(link));
      } else {
        TSDebug("early_hints", "load: rejecting invalid persisted link: %s", link.c_str());
      }
    }

    // Only insert entries that have at least one valid link.
    // Entries whose every link failed validation are skipped entirely.
    if (static_cast<int>(new_entries.size()) < max_entries_ && !links.empty()) {
      HintEntry entry;
      entry.links        = std::make_shared<const LinkList>(std::move(links));
      entry.last_updated = static_cast<time_t>(ts_on_disk);
      entry.learn_count  = static_cast<int>(lc);
      new_entries[key]   = std::move(entry);
    }
  }

  fclose(fp);

  // Atomic swap — hold mutex only for the map swap (not for file I/O).
  // All parsing done above. Now swap new_entries into entries_ atomically.
  // Sort by last_updated ascending before building LRU so oldest entries
  // are at the back of the list (evicted first under LRU policy).
  size_t loaded_count = 0;
  {
    // Build sorted key list: oldest first -> push_back = oldest at LRU tail
    std::vector<std::pair<time_t, std::string>> sorted_keys;
    sorted_keys.reserve(new_entries.size());
    for (const auto &pair : new_entries) {
      sorted_keys.push_back({pair.second.last_updated, pair.first});
    }
    std::sort(sorted_keys.begin(), sorted_keys.end());

    TSMutexGuard guard(mutex_);
    entries_ = std::move(new_entries);
    lru_list_.clear();
    // Insert oldest first at front -> they end up at the back after all inserts
    // Actually: push_front means last inserted = front (MRU).
    // We want oldest at back. So iterate oldest first and push_back.
    for (const auto &sk : sorted_keys) {
      lru_list_.push_back(sk.second);
      auto it = entries_.find(sk.second);
      if (it != entries_.end()) {
        it->second.lru_iterator = std::prev(lru_list_.end());
      }
    }
    loaded_count = entries_.size();
  }

  TSDebug("early_hints", "loaded %zu entries from %s", loaded_count, persist_path_.c_str());
  return true;
}
