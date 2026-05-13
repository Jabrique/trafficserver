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
#include <cstring>
#include <cstdio>
#include <algorithm>

HintsCache::HintsCache(int max_entries) : mutex_(TSMutexCreate()), persist_mutex_(TSMutexCreate()), max_entries_(max_entries) {}

HintsCache::~HintsCache()
{
  if (mutex_) {
    TSMutexDestroy(mutex_);
  }
  if (persist_mutex_) {
    TSMutexDestroy(persist_mutex_);
  }
}

LinkListPtr
HintsCache::get(const std::string &key, int min_hits)
{
  TSMutexGuard guard(mutex_);

  auto it = entries_.find(key);
  if (it == entries_.end()) {
    return nullptr;
  }

  HintEntry &entry = it->second;

  // Check minimum hit count before serving hints
  if (entry.learn_count < min_hits) {
    return nullptr;
  }

  // Return shared_ptr (ref-count bump, no deep copy)
  return entry.links;
}

bool
HintsCache::get(const std::string &key, std::vector<std::string> &links, int min_hits)
{
  LinkListPtr ptr = get(key, min_hits);
  if (!ptr) {
    return false;
  }
  links = *ptr;
  return true;
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

  auto new_links = std::make_shared<const LinkList>(links);

  {
    TSMutexGuard guard(mutex_);

    auto it = entries_.find(key);
    if (it != entries_.end()) {
      HintEntry &entry = it->second;

      // Equality-check debounce.
      // Compare new links against the currently stored links.
      // If identical, skip the shared_ptr swap.
      // This avoids unnecessary memory allocation on every request after warm-up.
      if (!entry.links || *entry.links != links) {
        entry.links = std::move(new_links);
      }
      entry.last_updated = time(nullptr);

      // learn_count cap — cap at max_learn_count() to prevent int overflow
      // under sustained traffic. The count is persisted and used for min_hit_count.
      if (entry.learn_count < max_learn_count()) {
        entry.learn_count++;
      }
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

      HintEntry entry;
      entry.links        = std::move(new_links);
      entry.last_updated = time(nullptr);
      entry.learn_count  = 1;
      entries_[key]      = std::move(entry);
    }
  } // mutex released

  // Persist is serialized by persist_mutex_ to prevent two concurrent
  // put() calls from both entering persist_to_disk() simultaneously.
  // persist_to_disk() itself takes a snapshot under mutex_ — double-entry is safe
  // but wastes I/O. persist_mutex_ ensures only one persist runs at a time.
  if (!persist_path_.empty()) {
    TSMutexGuard persist_guard(persist_mutex_);
    persist_to_disk();
    TSMutexGuard cnt_guard(mutex_);
    persist_count_++;
  }
}

size_t
HintsCache::size()
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
  TSMutexGuard guard(mutex_);
  return persist_count_;
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
  // Called with mutex_ held. Remove the entry with the oldest last_updated.
  if (entries_.empty()) {
    return;
  }

  auto oldest = entries_.begin();
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (it->second.last_updated < oldest->second.last_updated) {
      oldest = it;
    }
  }
  entries_.erase(oldest);
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
  };
  std::vector<SnapshotEntry> snapshot;

  {
    TSMutexGuard guard(mutex_);
    snapshot.reserve(entries_.size());
    for (const auto &pair : entries_) {
      snapshot.push_back({pair.first, pair.second.links, pair.second.learn_count});
    }
  } // mutex released — disk I/O happens without blocking readers

  // Step 2: Serialize to temp file
  std::string tmp_path = persist_path_ + ".tmp";
  FILE *fp             = fopen(tmp_path.c_str(), "wb");
  if (!fp) {
    TSDebug("early_hints", "persist: failed to open %s for writing", tmp_path.c_str());
    return false;
  }

  // Write header: magic + entry count
  uint32_t magic       = HINTS_CACHE_MAGIC;
  uint32_t entry_count = static_cast<uint32_t>(snapshot.size());
  if (fwrite(&magic, sizeof(magic), 1, fp) != 1 || fwrite(&entry_count, sizeof(entry_count), 1, fp) != 1) {
    fclose(fp);
    return false;
  }

  // Write each entry
  for (const auto &entry : snapshot) {
    // Key
    uint16_t key_len = static_cast<uint16_t>(entry.key.size());
    if (fwrite(&key_len, sizeof(key_len), 1, fp) != 1 || fwrite(entry.key.data(), key_len, 1, fp) != 1) {
      fclose(fp);
      return false;
    }

    // learn_count
    uint32_t lc = static_cast<uint32_t>(entry.learn_count);
    if (fwrite(&lc, sizeof(lc), 1, fp) != 1) {
      fclose(fp);
      return false;
    }

    // Links
    uint16_t link_count = entry.links ? static_cast<uint16_t>(entry.links->size()) : 0;
    if (fwrite(&link_count, sizeof(link_count), 1, fp) != 1) {
      fclose(fp);
      return false;
    }
    if (entry.links) {
      for (const auto &link : *entry.links) {
        uint16_t link_len = static_cast<uint16_t>(link.size());
        if (fwrite(&link_len, sizeof(link_len), 1, fp) != 1 || fwrite(link.data(), link_len, 1, fp) != 1) {
          fclose(fp);
          return false;
        }
      }
    }
  }

  fclose(fp);

  // Step 3: Atomic rename
  if (rename(tmp_path.c_str(), persist_path_.c_str()) != 0) {
    TSDebug("early_hints", "persist: rename failed");
    return false;
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
      links.push_back(std::move(link));
    }

    // Only insert if within capacity
    if (static_cast<int>(new_entries.size()) < max_entries_) {
      HintEntry entry;
      entry.links        = std::make_shared<const LinkList>(std::move(links));
      entry.last_updated = time(nullptr);
      entry.learn_count  = static_cast<int>(lc);
      new_entries[key]   = std::move(entry);
    }
  }

  fclose(fp);

  // Atomic swap — hold mutex only for the map swap (not for file I/O).
  // All parsing done above. Now swap new_entries into entries_ atomically.
  {
    TSMutexGuard guard(mutex_);
    entries_ = std::move(new_entries);
  }

  TSDebug("early_hints", "loaded %zu entries from %s", entries_.size(), persist_path_.c_str());
  return true;
}
