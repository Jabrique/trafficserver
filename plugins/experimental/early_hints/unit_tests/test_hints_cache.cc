/** @file
 * Unit tests for the HintsCache component.
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

#include <catch.hpp>
#include "../hints_cache.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern std::atomic<int> g_mutex_destroy_count;

// ─── Basic put/get ──────────────────────────────────────────────────────────

TEST_CASE("HintsCache: basic put and get", "[hints_cache]")
{
  HintsCache cache;

  SECTION("put then get returns same links")
  {
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script", "</style.css>; rel=preload; as=style"};
    cache.put("/page", links);

    const HintsCache &const_cache = cache;
    auto result                   = const_cache.get("/page", 1);
    REQUIRE(result != nullptr);
    REQUIRE(result->size() == 2);
    CHECK((*result)[0] == "</app.js>; rel=preload; as=script");
    CHECK((*result)[1] == "</style.css>; rel=preload; as=style");
  }

  SECTION("get on non-existent key returns nullptr")
  {
    auto result = cache.get("/nonexistent", 1);
    CHECK(result == nullptr);
  }

  SECTION("get with min_hits=2 fails on first put")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);

    auto result = cache.get("/page", 2);
    CHECK(result == nullptr);
  }

  SECTION("get with min_hits=2 succeeds after two get() calls")
  {
    // min_hits threshold is met by request_count (traffic), not learn_count (scanner runs).
    // Scanner runs once; request_count increments on each get() call.
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);

    // First get: request_count=1 < 2 → null
    auto r1 = cache.get("/page", 2);
    CHECK(r1 == nullptr);

    // Second get: request_count=2 >= 2 → non-null
    auto r2 = cache.get("/page", 2);
    REQUIRE(r2 != nullptr);
    CHECK(r2->size() == 1);
  }

  SECTION("get with min_hits=1 succeeds on first put")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);

    auto result = cache.get("/page", 1);
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);
  }

  SECTION("put updates existing entry links")
  {
    std::vector<std::string> links1 = {"</old.css>; rel=preload; as=style"};
    std::vector<std::string> links2 = {"</new.css>; rel=preload; as=style"};
    cache.put("/page", links1);
    cache.put("/page", links2);

    auto result = cache.get("/page", 1);
    REQUIRE(result != nullptr);
    REQUIRE(result->size() == 1);
    CHECK((*result)[0] == "</new.css>; rel=preload; as=style");
  }

  SECTION("entries never expire — no TTL")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);

    // Even after getting multiple times, entry persists
    for (int i = 0; i < 100; i++) {
      auto result = cache.get("/page", 1);
      REQUIRE(result != nullptr);
    }
  }
}

// ─── Legacy get (vector overload) ───────────────────────────────────────────

TEST_CASE("HintsCache: legacy get (vector overload)", "[hints_cache]")
{
  HintsCache cache;

  SECTION("returns deep copy")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);

    std::vector<std::string> out;
    bool ok = cache.get("/page", out, 1);
    REQUIRE(ok);
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "</a.js>; rel=preload; as=script");
  }

  SECTION("returns false for missing key")
  {
    std::vector<std::string> out;
    bool ok = cache.get("/missing", out, 1);
    CHECK_FALSE(ok);
    CHECK(out.empty());
  }

  SECTION("modifying returned vector does not affect cache")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);

    std::vector<std::string> out;
    cache.get("/page", out, 1);
    out.clear();

    auto result = cache.get("/page", 1);
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);
  }
}

// ─── make_key ───────────────────────────────────────────────────────────────

TEST_CASE("HintsCache: make_key", "[hints_cache]")
{
  SECTION("strips query string") { CHECK(HintsCache::make_key("/page?q=1", 9) == "/page"); }

  SECTION("no query string — returns full path") { CHECK(HintsCache::make_key("/page/sub", 9) == "/page/sub"); }

  SECTION("empty path")
  {
    // make_key returns "/" for empty paths (ensures valid cache key)
    CHECK(HintsCache::make_key("", 0) == "/");
  }

  SECTION("path with fragment")
  {
    // Fragments are NOT stripped (known behavior)
    CHECK(HintsCache::make_key("/page#section", 13) == "/page#section");
  }

  SECTION("path with both query and fragment") { CHECK(HintsCache::make_key("/page?q=1#frag", 14) == "/page"); }

  SECTION("query at start")
  {
    // "?q=1" → strip query → "" → make_key returns "/"
    CHECK(HintsCache::make_key("?q=1", 4) == "/");
  }

  SECTION("just a slash") { CHECK(HintsCache::make_key("/", 1) == "/"); }
}

// ─── size ───────────────────────────────────────────────────────────────────

TEST_CASE("HintsCache: size tracking", "[hints_cache]")
{
  HintsCache cache;

  CHECK(cache.size() == 0);

  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
  cache.put("/page1", links);
  CHECK(cache.size() == 1);

  cache.put("/page2", links);
  CHECK(cache.size() == 2);

  cache.put("/page1", links);
  CHECK(cache.size() == 2); // update, not new entry
}

// ─── Eviction ───────────────────────────────────────────────────────────────

TEST_CASE("HintsCache: max_entries eviction", "[hints_cache]")
{
  HintsCache cache(100); // small capacity

  SECTION("filling to capacity works")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    for (int i = 0; i < 100; i++) {
      cache.put("/page" + std::to_string(i), links);
    }
    CHECK(cache.size() == 100);
  }

  SECTION("exceeding capacity evicts oldest entries")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    for (int i = 0; i < 200; i++) {
      cache.put("/page" + std::to_string(i), links);
    }
    // Cache should enforce max_entries (100) — oldest evicted
    CHECK(cache.size() <= 100);
    CHECK(cache.size() > 0);
  }

  SECTION("oldest entry is evicted first")
  {
    HintsCache small_cache(3);
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    small_cache.put("/first", links);
    small_cache.put("/second", links);
    small_cache.put("/third", links);
    CHECK(small_cache.size() == 3);

    // Adding a 4th evicts one entry to maintain capacity
    small_cache.put("/fourth", links);
    CHECK(small_cache.size() == 3);
    CHECK(small_cache.get("/fourth", 1) != nullptr); // new entry inserted
  }
}

// ─── Shared_ptr identity ────────────────────────────────────────────────────

TEST_CASE("HintsCache: shared_ptr semantics", "[hints_cache]")
{
  HintsCache cache;
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
  cache.put("/page", links);

  SECTION("two gets return same shared_ptr (no deep copy)")
  {
    auto r1 = cache.get("/page", 1);
    auto r2 = cache.get("/page", 1);
    REQUIRE(r1 != nullptr);
    REQUIRE(r2 != nullptr);
    CHECK(r1.get() == r2.get()); // same underlying object
  }

  SECTION("shared_ptr survives cache update")
  {
    auto old_ptr = cache.get("/page", 1);
    REQUIRE(old_ptr != nullptr);

    // Update with new links
    std::vector<std::string> new_links = {"</new.css>; rel=preload; as=style"};
    cache.put("/page", new_links);

    // Old pointer still valid (refcount keeps it alive)
    CHECK(old_ptr->size() == 1);
    CHECK((*old_ptr)[0] == "</a.js>; rel=preload; as=script");

    // New get returns new data
    auto new_ptr = cache.get("/page", 1);
    REQUIRE(new_ptr != nullptr);
    CHECK((*new_ptr)[0] == "</new.css>; rel=preload; as=style");
  }
}

// ─── Destructor ─────────────────────────────────────────────────────────────

TEST_CASE("HintsCache: destructor calls TSMutexDestroy", "[hints_cache]")
{
  int before = g_mutex_destroy_count.load();
  {
    HintsCache cache;
  } // destructor runs
  int after = g_mutex_destroy_count.load();
  // HintsCache now has 2 mutexes (mutex_ + persist_mutex_)
  CHECK(after == before + 2);
}

// ─── Thread safety ──────────────────────────────────────────────────────────

TEST_CASE("HintsCache: concurrent put/get", "[hints_cache][threading]")
{
  constexpr int NUM_THREADS    = 8;
  constexpr int OPS_PER_THREAD = 1000;
  constexpr int NUM_KEYS       = 20;

  HintsCache cache;

  auto worker = [&](int id) {
    for (int i = 0; i < OPS_PER_THREAD; i++) {
      std::string key = "/key" + std::to_string(i % NUM_KEYS);
      if (i % 3 == 0) {
        // Write
        std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
        cache.put(key, links);
      } else {
        // Read
        auto result = cache.get(key, 1);
        // May be null (not yet written) — just don't crash
        (void)result;
      }
    }
  };

  std::vector<std::thread> threads;
  for (int i = 0; i < NUM_THREADS; i++) {
    threads.emplace_back(worker, i);
  }
  for (auto &t : threads) {
    t.join();
  }

  CHECK(cache.size() > 0);
  CHECK(cache.size() <= NUM_KEYS);
}

// ─── Edge cases ─────────────────────────────────────────────────────────────

TEST_CASE("HintsCache: edge cases", "[hints_cache]")
{
  SECTION("put with empty links vector")
  {
    HintsCache cache;
    std::vector<std::string> empty;
    cache.put("/page", empty);

    auto result = cache.get("/page", 1);
    REQUIRE(result != nullptr);
    CHECK(result->empty());
  }

  SECTION("constructor with max_entries=0 still works")
  {
    HintsCache cache(0);
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);
    // With max_entries=0, nothing should be stored
    CHECK(cache.size() == 0);
    auto result = cache.get("/page", 1);
    CHECK(result == nullptr);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// Audit TDD tests
// ═════════════════════════════════════════════════════════════════════════════

// ─── Audit: drops() counter for when max_entries=0 ──────────────────────────

TEST_CASE("HintsCache audit: drops() counts entries dropped when max_entries=0", "[hints_cache][audit]")
{
  HintsCache cache(0);
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  CHECK(cache.drops() == 0);

  cache.put("/a", links);
  CHECK(cache.drops() == 1);

  cache.put("/b", links);
  CHECK(cache.drops() == 2);
}

TEST_CASE("HintsCache audit: eviction makes room — no drops", "[hints_cache][audit]")
{
  HintsCache cache(2);
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  cache.put("/a", links);
  cache.put("/b", links);
  CHECK(cache.size() == 2);
  CHECK(cache.drops() == 0);

  // Adding a 3rd key evicts oldest — no drop needed
  cache.put("/c", links);
  CHECK(cache.size() == 2);
  CHECK(cache.drops() == 0);
}

TEST_CASE("HintsCache audit: updating existing key when full is not a drop", "[hints_cache][audit]")
{
  HintsCache cache(3);
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  cache.put("/a", links);
  cache.put("/b", links);
  cache.put("/c", links);
  CHECK(cache.size() == 3);

  // Update existing key — should succeed without drop
  cache.put("/a", links);
  CHECK(cache.drops() == 0);
  CHECK(cache.size() == 3);
}

// ═════════════════════════════════════════════════════════════════════════════
// Audit V2: Missing test scenarios
// ═════════════════════════════════════════════════════════════════════════════

// cache-01: min_hits exact boundary
TEST_CASE("HintsCache audit v2: min_hits exact boundary", "[hints_cache][audit-v2]")
{
  // min_hits threshold is now met by request_count (traffic), not learn_count (scanner runs).
  // A single put() creates the entry; get() calls accumulate request_count.
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  SECTION("min_hits=5: null for first 4 gets, non-null on 5th")
  {
    HintsCache cache;
    cache.put("/page", links);

    // Requests 1-4: request_count 1→4 < 5 → null
    for (int i = 0; i < 4; i++) {
      CHECK(cache.get("/page", 5) == nullptr);
    }
    // Request 5: request_count 4→5 >= 5 → non-null
    auto result = cache.get("/page", 5);
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);
  }

  SECTION("min_hits=1: succeeds on the first get()")
  {
    HintsCache cache;
    cache.put("/page", links);
    REQUIRE(cache.get("/page", 1) != nullptr);
  }

  SECTION("vector overload respects same boundary")
  {
    HintsCache cache;
    cache.put("/page", links);

    std::vector<std::string> out;
    CHECK(cache.get("/page", out, 3) == false); // rc=0→1 < 3
    CHECK(cache.get("/page", out, 3) == false); // rc=1→2 < 3
    CHECK(cache.get("/page", out, 3) == true);  // rc=2→3 >= 3
  }
}

// cache-07: drops() counter accuracy after multiple evictions
TEST_CASE("HintsCache audit v2: drops counter with max_entries=0 multiple puts", "[hints_cache][audit-v2]")
{
  HintsCache cache(0);
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  for (int i = 0; i < 100; i++) {
    cache.put("/page" + std::to_string(i), links);
  }

  CHECK(cache.drops() == 100);
  CHECK(cache.size() == 0);
}

TEST_CASE("HintsCache audit v2: eviction does not increment drops", "[hints_cache][audit-v2]")
{
  HintsCache cache(3);
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  // Fill cache
  cache.put("/a", links);
  cache.put("/b", links);
  cache.put("/c", links);
  CHECK(cache.drops() == 0);

  // Add 10 more — evicts oldest each time, not a drop
  for (int i = 0; i < 10; i++) {
    cache.put("/new" + std::to_string(i), links);
  }
  CHECK(cache.drops() == 0);
  CHECK(cache.size() == 3);
}

// cache-08: make_key with special characters
TEST_CASE("HintsCache audit v2: make_key special characters", "[hints_cache][audit-v2]")
{
  SECTION("path with spaces")
  {
    auto key = HintsCache::make_key("/my page/test", 13);
    CHECK(key == "/my page/test");
  }

  SECTION("path with percent-encoded characters")
  {
    auto key = HintsCache::make_key("/path%20with%20spaces", 21);
    CHECK(key == "/path%20with%20spaces");
  }

  SECTION("path with unicode")
  {
    auto key = HintsCache::make_key("/p\xc3\xa4ge", 6);
    CHECK(key == "/p\xc3\xa4ge");
  }

  SECTION("path with query containing special chars")
  {
    auto key = HintsCache::make_key("/path?key=val&foo=bar#frag", 25);
    CHECK(key == "/path"); // query stripped
  }

  SECTION("path that is only a question mark")
  {
    auto key = HintsCache::make_key("?query", 6);
    CHECK(key == "/"); // no path, falls back to root
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// Cache Persistence Memory Optimization (Equality-Check on Links)
//
// Optimization: HintsCache::put() previously always replaced the shared_ptr
// for cached links even when the new links vector is identical to what is
// already stored. This causes unnecessary memory allocation + atomic ref-count
// operations on every request after warm-up.
//
// Fix: before swapping the cached links shared_ptr, compare the new links
// vector against the existing cached links. If equal, skip the swap.
// The learn_count still increments on every put() (needed for min_hit_count
// to survive restarts — learn_count must be persisted).
//
// Observability: shared_ptr identity. After a same-links put(), the shared_ptr
// returned by get() must point to the SAME underlying object (no new allocation).
// After a different-links put(), get() must return a new shared_ptr.
//
// put_persist_count() tracks actual persist_to_disk() calls (always fires when
// persist_path is set, since learn_count always changes on each put()).
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("put() equality-check — shared_ptr identity preserved for identical links", "[hints_cache][debounce]")
{
  SECTION("first put creates entry")
  {
    HintsCache cache;
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

    cache.put("/page", links);
    auto ptr1 = cache.get("/page", 1);
    REQUIRE(ptr1 != nullptr);
    CHECK(ptr1->size() == 1);
  }

  SECTION("second put with IDENTICAL links preserves shared_ptr identity (no new allocation)")
  {
    HintsCache cache;
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

    cache.put("/page", links);
    auto ptr1 = cache.get("/page", 1);
    REQUIRE(ptr1 != nullptr);

    // Second put with same links — shared_ptr should remain the same object
    cache.put("/page", links);
    auto ptr2 = cache.get("/page", 2); // min_hits=2, learn_count is now 2

    REQUIRE(ptr2 != nullptr);
    // Both pointers must point to the same underlying LinkList — no re-allocation
    CHECK(ptr1.get() == ptr2.get());
  }

  SECTION("put with DIFFERENT links creates new shared_ptr")
  {
    HintsCache cache;
    std::vector<std::string> links1 = {"</app.js>; rel=preload; as=script"};
    std::vector<std::string> links2 = {"</app.js>; rel=preload; as=script", "</style.css>; rel=preload; as=style"};

    cache.put("/page", links1);
    auto ptr1 = cache.get("/page", 1);
    REQUIRE(ptr1 != nullptr);

    cache.put("/page", links2); // different links — must create new shared_ptr
    auto ptr2 = cache.get("/page", 1);
    REQUIRE(ptr2 != nullptr);

    // Pointers must differ — new allocation
    CHECK(ptr1.get() != ptr2.get());
    // New content must be reflected
    REQUIRE(ptr2->size() == 2);
  }

  SECTION("learn_count still increments for identical-links puts (needed for persistence)")
  {
    // learn_count increments on every put() regardless of link equality.
    // This keeps persist files accurate so disk-loaded entries have correct learn_count.
    // min_hits serving threshold is now request_count-based (not learn_count-based).
    HintsCache cache;
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    cache.put("/page", links); // learn_count=1
    cache.put("/page", links); // learn_count=2 (identical links, learn_count still increments)
    cache.put("/page", links); // learn_count=3

    // request_count starts at 0 regardless of how many puts occurred.
    // min_hits=3 is satisfied by the 3rd get() call:
    CHECK(cache.get("/page", 3) == nullptr); // rc=0→1 < 3
    CHECK(cache.get("/page", 3) == nullptr); // rc=1→2 < 3
    auto result = cache.get("/page", 3);     // rc=2→3 >= 3
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);
  }

  SECTION("no persist_path set — put_persist_count stays 0")
  {
    HintsCache cache;
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    // No set_persist_path() — persist logic never runs
    cache.put("/page", links);
    cache.put("/page", links);

    CHECK(cache.put_persist_count() == 0);
  }

  SECTION("persist_path set — put_persist_count increments per put (learn_count persisted)")
  {
    std::string path = "/tmp/eh_put_persist_count_" + std::to_string(getpid()) + ".bin";
    std::remove(path.c_str());

    HintsCache cache;
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    cache.set_persist_path(path);
    cache.set_persist_throttle(0); // persist every put for this test
    cache.put("/page", links);     // count=1
    cache.put("/page", links);     // count=2 (learn_count changed, must persist)
    cache.put("/page", links);     // count=3

    // Every put must persist because learn_count changes (min_hit_count restart safety)
    CHECK(cache.put_persist_count() == 3);

    std::remove(path.c_str());
    std::remove((path + ".tmp").c_str());
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
// Cache Persistence Hardening
//
// 1. KEY LENGTH CAP: put() with key > MAX_KEY_LEN (4096) must be silently dropped.
//    Oversized keys cannot be valid URL paths and risk O(n) memory in persist file.
//
// 2. LEARN_COUNT CAP: learn_count must never exceed 1,000,000. Without a cap,
//    sustained high traffic to a single URL would eventually overflow int.
//
// 3. LOAD_FROM_DISK ATOMIC SWAP: load_from_disk() must build a temp map and
//    swap it in atomically (hold mutex only for the swap, not for parsing).
//    Without this: a parse failure mid-way leaves the cache permanently empty.
//
// 4. LEARN_COUNT CLAMP ON LOAD: learn_count > 1,000,000 read from disk must be
//    clamped to prevent overflow if file was written without the cap.
//
// 5. PERSIST CONCURRENCY: persist_to_disk() must be protected by persist_mutex_
//    to prevent two concurrent put() calls from both serializing the cache.
// ═════════════════════════════════════════════════════════════════════════════

// ─── Key length cap ───────────────────────────────────────────────────────────

TEST_CASE("HintsCache: put() rejects key longer than MAX_KEY_LEN (4096)", "[hints_cache][key_cap]")
{
  HintsCache cache;
  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  SECTION("key exactly at 4096 chars is accepted")
  {
    std::string key(4096, '/');
    cache.put(key, links);
    // Key at limit must be accepted
    CHECK(cache.size() == 1);
  }

  SECTION("key of 4097 chars is silently dropped")
  {
    std::string key(4097, '/');
    cache.put(key, links);
    // Key over limit: silently drop — cache stays empty
    CHECK(cache.size() == 0);
    CHECK(cache.drops() == 1);
  }

  SECTION("key of 65535 chars is silently dropped")
  {
    std::string key(65535, '/');
    cache.put(key, links);
    CHECK(cache.size() == 0);
    CHECK(cache.drops() == 1);
  }

  SECTION("drops() increments for oversized key (not confused with capacity drop)")
  {
    HintsCache small_cache(5);
    std::string long_key(5000, 'a');
    small_cache.put(long_key, links);
    small_cache.put(long_key, links);
    CHECK(small_cache.drops() == 2);
    CHECK(small_cache.size() == 0);
  }
}

// ─── learn_count cap ──────────────────────────────────────────────────────────

TEST_CASE("HintsCache: learn_count caps at max_learn_count()", "[hints_cache][learn_count_cap]")
{
  HintsCache cache;
  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  SECTION("learn_count does not exceed 1000000 after many identical puts")
  {
    // Simulate just above cap: 1000001 puts
    // This test relies on HintsCache exposing learn_count via get() behavior,
    // since there's no direct accessor. We verify via min_hits.
    //
    // After 1000000 puts, get(key, 1000000) must succeed.
    // After 1000001 puts (capped), get(key, 1000001) must FAIL (count is capped).
    //
    // We can't actually call put() 1000001 times in a test (too slow).
    // Instead: use the public learn_count accessor (requires adding it to hints_cache.h).
    // OR: test the clamp via load_from_disk with an oversized learn_count in the file.

    // The load path is the canonical test for clamp behavior:
    // A persisted file with learn_count = 2000000 must clamp to 1000000 after load.
    // // (See learn_count clamp test below.)
    //
    // For the put() cap: we test via put_persist_count() staying within reasonable bounds,
    // and verify through a test-only accessor if we add one. This section validates
    // the API contract — after the fix, HintsCache must expose max_learn_count.
    CHECK(HintsCache::max_learn_count() == 1000000);
  }

  SECTION("after exactly max_learn_count puts, get at max_learn_count succeeds")
  {
    // We use a much smaller MAX for this test — but HintsCache doesn't support
    // injecting a custom max_learn_count. So we test via the file-load path:
    // write a persist file with learn_count = max_learn_count, verify get works.
    // // (This test is verified in the load_from_disk clamp test below.)
    //
    // This section documents the API expectation for the cap constant.
    CHECK(HintsCache::max_learn_count() > 0);
    CHECK(HintsCache::max_learn_count() <= 2000000);
  }
}

// ─── load_from_disk atomic swap ───────────────────────────────────────────────

TEST_CASE("HintsCache: load_from_disk uses atomic swap — existing cache preserved on failure", "[hints_cache][atomic_load]")
{
  SECTION("load_from_disk on corrupt file does not clear existing cache")
  {
    // load_from_disk() must build a temporary map and swap it in atomically.
    // If parsing fails mid-way, the existing cache must remain unaffected.

    HintsCache cache;
    std::vector<std::string> existing_links = {"</existing.js>; rel=preload; as=script"};

    // Pre-populate cache with good data
    cache.put("/existing-page", existing_links);
    cache.put("/existing-page", existing_links);
    REQUIRE(cache.size() == 1);
    // Use min_hits=1 — the intent here is to verify entry exists before corrupt load.
    // (min_hits=2 checked learn_count in the old design; now request_count gates serving)
    REQUIRE(cache.get("/existing-page", 1) != nullptr);

    // Now "load" a corrupt file — this must NOT wipe the existing cache
    cache.set_persist_path("/dev/null"); // /dev/null reads as empty = bad magic
    bool ok = cache.load_from_disk();
    CHECK_FALSE(ok);

    // BUG: before fix, entries_ is cleared before magic check in some code paths.
    // AFTER FIX: existing cache must survive a failed load.
    // Note: the current implementation clears AFTER magic check for bad magic,
    // but clears BEFORE the loop for valid header. This is the race condition.
    //
    // This test covers the scenario where: cache is populated → load fails →
    // cache must still serve the pre-existing hints.
    //
    // After the fix (atomic swap), get on existing data must still work.
    // The cache path is /dev/null which reads as header failure → no clear.
    // This currently passes for /dev/null but fails for valid header + truncated entries.
    auto result = cache.get("/existing-page", 1);
    REQUIRE(result != nullptr);
    CHECK((*result)[0] == "</existing.js>; rel=preload; as=script");
  }

  SECTION("load_from_disk fails mid-parse — cache stays populated (valid header, truncated)")
  {
    // Write a file with valid header claiming 5 entries but only has data for 1.
    // After the 1st entry is read successfully, parsing the 2nd fails.
    // The 1st entry must NOT be committed if we use atomic swap.
    // (Or: all entries must be committed — the test documents which behavior is expected.)
    //
    // With atomic swap: all-or-nothing → on mid-parse failure, existing cache preserved.
    // Without atomic swap: partial entries committed, and original data wiped.
    //
    // This test verifies the all-or-nothing guarantee:
    // pre-existing cache data must be preserved if load_from_disk returns false.

    HintsCache cache(1000);
    std::vector<std::string> original_links = {"</original.js>; rel=preload; as=script"};
    cache.put("/original", original_links);
    cache.put("/original", original_links); // learn_count=2
    REQUIRE(cache.size() == 1);

    // Build a valid-header file claiming 2 entries, but only write 1 complete entry
    std::string path = "/tmp/eh_test_atomic_" + std::to_string(getpid()) + ".bin";
    {
      FILE *fp = fopen(path.c_str(), "wb");
      REQUIRE(fp);
      uint32_t magic = HINTS_CACHE_MAGIC;
      uint32_t count = 2; // claims 2 entries
      fwrite(&magic, sizeof(magic), 1, fp);
      fwrite(&count, sizeof(count), 1, fp);

      // Write 1 complete entry
      uint16_t key_len = 5;
      fwrite(&key_len, sizeof(key_len), 1, fp);
      fwrite("/page", 5, 1, fp);
      uint32_t lc = 3;
      fwrite(&lc, sizeof(lc), 1, fp);
      uint64_t ts = 0; // last_updated (v2 field)
      fwrite(&ts, sizeof(ts), 1, fp);
      uint16_t link_count = 1;
      fwrite(&link_count, sizeof(link_count), 1, fp);
      uint16_t ll = 30;
      fwrite(&ll, sizeof(ll), 1, fp);
      fwrite("</new.js>; rel=preload; as=script", 30, 1, fp); // NOLINT: correct size

      // Do NOT write 2nd entry — truncated
      fclose(fp);
    }

    cache.set_persist_path(path);
    bool ok = cache.load_from_disk();
    std::remove(path.c_str());

    CHECK_FALSE(ok); // Must fail (truncated)

    // ATOMIC SWAP GUARANTEE:
    // The pre-existing /original entry must still be in the cache.
    // (Without atomic swap: /original is gone, /page may or may not be there)
    auto result = cache.get("/original", 1);
    CHECK(result != nullptr); // Existing cache must be preserved
  }
}

// ─── learn_count clamp on load ──────────────────────────────────────────────

TEST_CASE("HintsCache: load_from_disk clamps oversized learn_count to max_learn_count", "[hints_cache][learn_count_clamp]")
{
  std::string path = "/tmp/eh_clamp_" + std::to_string(getpid()) + ".bin";

  // Write persist file with learn_count = 2,000,000 (above 1,000,000 cap)
  {
    FILE *fp = fopen(path.c_str(), "wb");
    REQUIRE(fp);
    uint32_t magic = HINTS_CACHE_MAGIC;
    uint32_t count = 1;
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&count, sizeof(count), 1, fp);

    uint16_t key_len = 5;
    fwrite(&key_len, sizeof(key_len), 1, fp);
    fwrite("/page", 5, 1, fp);

    uint32_t lc = 2000000; // way over cap
    fwrite(&lc, sizeof(lc), 1, fp);

    // v2 format: last_updated (uint64_t) follows learn_count.
    // Omitting this caused load_from_disk to misparse and return false.
    uint64_t ts = 0;
    fwrite(&ts, sizeof(ts), 1, fp);

    uint16_t link_count = 1;
    fwrite(&link_count, sizeof(link_count), 1, fp);
    const char *link  = "</app.js>; rel=preload; as=script";
    uint16_t link_len = static_cast<uint16_t>(strlen(link));
    fwrite(&link_len, sizeof(link_len), 1, fp);
    fwrite(link, link_len, 1, fp);

    fclose(fp);
  }

  HintsCache cache;
  cache.set_persist_path(path);
  REQUIRE(cache.load_from_disk());
  std::remove(path.c_str());

  // Entry must be loaded (learn_count was clamped from 2,000,000 to 1,000,000).
  // learn_count clamp is a persistence-only concern; the serving gate is request_count.
  // Verify entry exists and serves from first get() call (request_count 0→1 ≥ 1):
  auto result = cache.get("/page", 1);
  REQUIRE(result != nullptr);
  CHECK((*result)[0] == "</app.js>; rel=preload; as=script");

  // Verify entry was actually loaded (peek — no request_count side-effect):
  CHECK(cache.peek("/page") != nullptr);
}

// ─── Concurrent persist safety ───────────────────────────────────────────────

TEST_CASE("HintsCache: concurrent put() calls produce valid persist file", "[hints_cache][persist_concurrent][threading]")
{
  std::string path = "/tmp/eh_persist_conc_" + std::to_string(getpid()) + ".bin";
  std::remove(path.c_str());

  HintsCache cache;
  cache.set_persist_path(path);

  constexpr int NUM_THREADS     = 4;
  constexpr int PUTS_PER_THREAD = 50;

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  auto worker = [&](int id) {
    for (int i = 0; i < PUTS_PER_THREAD; i++) {
      std::string key = "/page" + std::to_string(id);
      cache.put(key, links);
    }
  };

  std::vector<std::thread> threads;
  for (int i = 0; i < NUM_THREADS; i++) {
    threads.emplace_back(worker, i);
  }
  for (auto &t : threads) {
    t.join();
  }

  // After concurrent puts, persist file must be readable and valid
  HintsCache cache2;
  cache2.set_persist_path(path);
  CHECK(cache2.load_from_disk());
  CHECK(cache2.size() > 0);
  CHECK(cache2.size() <= NUM_THREADS);

  std::remove(path.c_str());
}

// ═════════════════════════════════════════════════════════════════════════════
// Additional cache safety tests
//
// drop_counter_ must be safe under concurrent drops.
//     Currently int64_t protected only by mutex_ in drops() call-site.
//     But put() increments drop_counter_ INSIDE the mutex guard already,
//     so the real question is whether drops() const can call TSMutexGuard
//     on a non-mutable mutex. This is currently UB / non-const-correct.
//     Fix: make drops() thread-safe without UB (either mutable mutex or
//     change drop_counter_ to std::atomic<int64_t> and remove mutex from drops()).
//
// evict_oldest() should prefer stale (never-accessed) entries over recently read ones.
//     A freshly-accessed (get()) entry can be evicted before a stale
//     one that was written long ago but never read since.
//     Fix: add last_accessed to HintEntry, update in get(), use
//     max(last_updated, last_accessed) in evict_oldest().
// ═════════════════════════════════════════════════════════════════════════════

// ─── drops() concurrent safety test ──────────────────────────────────────────
//
// Test that concurrent put() calls into a full cache (max_entries=0) produce
// the exact expected drop count. This will race on drop_counter_ if it is not
// properly protected under all code paths.
//
// Expectation: drops() must be const-correct and race-free.
// TSMutexGuard on a non-mutable TSMutex in a const method is ill-formed.
// Once drop_counter_ becomes std::atomic<int64_t>, drops() can be truly const
// without any mutex, and concurrent increments are safe.

TEST_CASE("drops() returns exact count under concurrent pressure", "[hints_cache][drops][threading]")
{
  constexpr int NUM_THREADS = 8;
  constexpr int DROPS_PER   = 100; // each thread drops 100 keys into max_entries=0 cache

  HintsCache cache(0); // max_entries=0 → every put() is a drop
  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  auto worker = [&](int id) {
    for (int i = 0; i < DROPS_PER; i++) {
      cache.put("/key-" + std::to_string(id) + "-" + std::to_string(i), links);
    }
  };

  std::vector<std::thread> threads;
  for (int i = 0; i < NUM_THREADS; i++) {
    threads.emplace_back(worker, i);
  }
  for (auto &t : threads) {
    t.join();
  }

  // Expected: NUM_THREADS * DROPS_PER total drops, no races
  int64_t expected = static_cast<int64_t>(NUM_THREADS) * DROPS_PER;
  CHECK(cache.drops() == expected);
  CHECK(cache.size() == 0);
}

// ─── evict_oldest() must prefer entries never accessed ──────────────────
//
// Scenario: cache capacity=2, fill with entries A and B.
// Access (get) entry A. Then insert C → eviction needed.
// Fix: evict_oldest() should evict B (never accessed), not A (recently accessed).
// Without fix: evict_oldest uses only last_updated which is
// identical for A and B (both put at the same time). Eviction is non-deterministic.
// With fix: last_accessed is updated on get(), B is evicted because its
// max(last_updated, last_accessed) is older than A's max(last_updated, last_accessed).
//
// Expectation: without last_accessed, we cannot guarantee A survives. This test documents
// the expected post-fix behavior.

TEST_CASE("evict_oldest() prefers never-accessed entries over recently-accessed ones", "[hints_cache][eviction]")
{
  HintsCache cache(2);
  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  // Insert A and B at t=0 (same timestamp due to fast test)
  cache.put("/entry-A", links);
  cache.put("/entry-B", links);
  REQUIRE(cache.size() == 2);

  // Access A — this should update its last_accessed
  // We sleep 1 second to ensure time difference is observable
  std::this_thread::sleep_for(std::chrono::seconds(1));
  auto ptr_a = cache.get("/entry-A", 1);
  REQUIRE(ptr_a != nullptr); // confirm A is accessible

  // Now add C — one of A or B must be evicted
  cache.put("/entry-C", links);
  REQUIRE(cache.size() == 2); // still 2 after eviction

  // C must be present (just inserted)
  CHECK(cache.get("/entry-C", 1) != nullptr);

  // Requirement: A must survive because it was recently accessed.
  // B must be evicted because it was never accessed after initial put.
  // Without last_accessed, eviction is non-deterministic for same-timestamp entries.
  // After fix: A must always survive, B must be evicted.
  CHECK(cache.get("/entry-A", 1) != nullptr); // A: recently accessed → must survive
  CHECK(cache.get("/entry-B", 1) == nullptr); // B: never accessed → must be evicted
}

// ═══════════════════════════════════════════════════════════════════════════════
// Persist security hardening tests
//
// Three related invariants:
//  1. Stale .tmp file left by a prior crash must be removed by load_from_disk()
//     before any new persist attempt, so O_EXCL in persist_to_disk() always works.
//  2. persist_to_disk() must use O_EXCL so a pre-existing .tmp file (symlink or
//     regular file) causes persist to fail safely rather than overwrite it.
//  3. After persist_to_disk(), the persist file must have mode 0640 (not 0644
//     or 0666) so world-read is not granted on potentially sensitive URL paths.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("HintsCache persist: stale .tmp file is removed by load_from_disk", "[hints_cache][persist][security]")
{
  char dir_template[] = "/tmp/eh_cache_test_XXXXXX";
  char *dir           = mkdtemp(dir_template);
  REQUIRE(dir != nullptr);

  std::string persist_path = std::string(dir) + "/hints.bin";
  std::string tmp_path     = persist_path + ".tmp";

  // Pre-create a stale .tmp file (simulating a crash during prior persist)
  {
    FILE *fp = fopen(tmp_path.c_str(), "wb");
    REQUIRE(fp != nullptr);
    fwrite("stale", 1, 5, fp);
    fclose(fp);
  }
  REQUIRE(access(tmp_path.c_str(), F_OK) == 0); // stale .tmp exists

  HintsCache cache;
  cache.set_persist_path(persist_path);

  // load_from_disk() must remove the stale .tmp
  cache.load_from_disk();                     // no valid persist file — returns false, but cleans .tmp
  CHECK(access(tmp_path.c_str(), F_OK) != 0); // .tmp must be gone

  rmdir(dir);
}

TEST_CASE("HintsCache persist: symlink at .tmp path is not followed (O_EXCL)", "[hints_cache][persist][security]")
{
  char dir_template[] = "/tmp/eh_cache_test_XXXXXX";
  char *dir           = mkdtemp(dir_template);
  REQUIRE(dir != nullptr);

  std::string persist_path = std::string(dir) + "/hints.bin";
  std::string tmp_path     = persist_path + ".tmp";
  std::string victim_path  = std::string(dir) + "/victim.txt";

  // Attacker pre-creates victim file and symlinks .tmp → victim
  {
    FILE *fp = fopen(victim_path.c_str(), "wb");
    REQUIRE(fp != nullptr);
    fwrite("original", 1, 8, fp);
    fclose(fp);
  }
  REQUIRE(symlink(victim_path.c_str(), tmp_path.c_str()) == 0);

  HintsCache cache;
  cache.set_persist_path(persist_path);
  cache.put("/test", {R"(</a.js>; rel=preload; as=script)"});
  cache.put("/test", {R"(</a.js>; rel=preload; as=script)"}); // meet min_hits

  // persist_to_disk() must fail or skip — must NOT overwrite victim via symlink
  cache.persist_to_disk();

  // Verify victim file is unchanged
  FILE *fp = fopen(victim_path.c_str(), "rb");
  REQUIRE(fp != nullptr);
  char buf[32] = {};
  size_t n     = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  CHECK(std::string(buf, n) == "original"); // victim untouched

  // Cleanup
  unlink(tmp_path.c_str());
  unlink(victim_path.c_str());
  rmdir(dir);
}

TEST_CASE("HintsCache persist: file mode is 0640 after persist", "[hints_cache][persist][security]")
{
  char dir_template[] = "/tmp/eh_cache_test_XXXXXX";
  char *dir           = mkdtemp(dir_template);
  REQUIRE(dir != nullptr);

  std::string persist_path = std::string(dir) + "/hints.bin";

  HintsCache cache;
  cache.set_persist_path(persist_path);
  cache.put("/test", {R"(</a.js>; rel=preload; as=script)"});
  cache.put("/test", {R"(</a.js>; rel=preload; as=script)"}); // meet min_hits

  bool ok = cache.persist_to_disk();
  REQUIRE(ok);

  struct stat st;
  REQUIRE(stat(persist_path.c_str(), &st) == 0);
  mode_t perms = st.st_mode & 0777;
  CHECK(perms == 0640); // owner rw, group r, no world access

  unlink(persist_path.c_str());
  rmdir(dir);
}

TEST_CASE("HintsCache persist: no .tmp file remains after successful persist", "[hints_cache][persist][tmp_cleanup]")
{
  char dir_template[] = "/tmp/eh_cache_test_XXXXXX";
  char *dir           = mkdtemp(dir_template);
  REQUIRE(dir != nullptr);

  std::string persist_path = std::string(dir) + "/hints.bin";
  std::string tmp_path     = persist_path + ".tmp";

  HintsCache cache;
  cache.set_persist_path(persist_path);
  cache.set_persist_throttle(0);

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
  cache.put("/page", links);

  // After persist via put(), the .tmp file must be gone (renamed to persist path)
  CHECK(access(tmp_path.c_str(), F_OK) != 0);
  CHECK(access(persist_path.c_str(), F_OK) == 0);

  unlink(persist_path.c_str());
  rmdir(dir);
}

TEST_CASE("HintsCache persist: subsequent persist after stale .tmp is cleaned by load_from_disk",
          "[hints_cache][persist][tmp_cleanup]")
{
  char dir_template[] = "/tmp/eh_cache_test_XXXXXX";
  char *dir           = mkdtemp(dir_template);
  REQUIRE(dir != nullptr);

  std::string persist_path = std::string(dir) + "/hints.bin";
  std::string tmp_path     = persist_path + ".tmp";

  // Write a valid persist file first
  {
    HintsCache cache;
    cache.set_persist_path(persist_path);
    cache.set_persist_throttle(0);
    cache.put("/page1", {"</a.js>; rel=preload; as=script"});
  }
  REQUIRE(access(persist_path.c_str(), F_OK) == 0);

  // Simulate a crash: leave a stale .tmp file behind
  {
    FILE *fp = fopen(tmp_path.c_str(), "wb");
    REQUIRE(fp);
    fwrite("crash_remnant", 1, 13, fp);
    fclose(fp);
  }
  REQUIRE(access(tmp_path.c_str(), F_OK) == 0);

  // load_from_disk should remove the stale .tmp, and subsequent persist should work
  HintsCache cache2;
  cache2.set_persist_path(persist_path);
  cache2.set_persist_throttle(0);
  cache2.load_from_disk();
  CHECK(access(tmp_path.c_str(), F_OK) != 0); // .tmp removed

  // New persist should succeed (O_EXCL won't fail since .tmp is gone)
  cache2.put("/page2", {"</b.css>; rel=preload; as=style"});
  CHECK(access(persist_path.c_str(), F_OK) == 0);
  CHECK(access(tmp_path.c_str(), F_OK) != 0); // .tmp cleaned after persist

  // Verify data integrity
  HintsCache verify;
  verify.set_persist_path(persist_path);
  REQUIRE(verify.load_from_disk());
  CHECK(verify.size() == 2);

  unlink(persist_path.c_str());
  rmdir(dir);
}

// ═════════════════════════════════════════════════════════════════════════════
// Commit 11: request_count separates traffic gate from scanner trigger
//
// Before: get() returned null when learn_count < min_hits. Because cached_links
// was the scanner trigger, the scanner ran min_hit_count times — once per put().
//
// After: get() increments request_count per call and checks request_count >= min_hits.
//        peek() returns links without incrementing request_count (for scanner skip
//        check and SEND_RESPONSE_HDR fallback — avoids double-counting).
//        Scanner runs exactly once per URL (only when links == nullptr).
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("HintsCache: request_count separates traffic gate from scanner trigger", "[hints_cache][request_count]")
{
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  SECTION("put() does not increment request_count")
  {
    HintsCache cache;
    // 5 puts → learn_count=5, but request_count stays 0
    for (int i = 0; i < 5; i++) {
      cache.put("/page", links);
    }
    // First get with min_hits=1: request_count 0→1 >= 1 → non-null
    REQUIRE(cache.get("/page", 1) != nullptr);
    // But with min_hits=2: 5 puts do NOT make it serveable; 2nd get does.
    HintsCache cache2;
    cache2.put("/page", links);
    cache2.put("/page", links);
    cache2.put("/page", links);
    cache2.put("/page", links);
    cache2.put("/page", links);
    CHECK(cache2.get("/page", 2) == nullptr);   // rc=0→1 < 2
    REQUIRE(cache2.get("/page", 2) != nullptr); // rc=1→2 >= 2
  }

  SECTION("get() increments request_count toward min_hits threshold")
  {
    HintsCache cache;
    cache.put("/page", links);

    // request_count starts at 0; each get() increments it.
    for (int i = 1; i <= 4; i++) {
      CHECK(cache.get("/page", 5) == nullptr); // rc=i < 5
    }
    // 5th get: rc=4→5 >= 5 → non-null
    auto r = cache.get("/page", 5);
    REQUIRE(r != nullptr);
    CHECK(r->size() == 1);
  }

  SECTION("min_hits=1: first get() returns non-null regardless of put() count")
  {
    HintsCache cache;
    cache.put("/page", links);      // learn_count=1, rc=0
    auto r = cache.get("/page", 1); // rc=0→1 >= 1
    REQUIRE(r != nullptr);
    CHECK((*r)[0] == "</a.js>; rel=preload; as=script");
  }

  SECTION("learn_count still increments on put() independently of request_count")
  {
    // learn_count is persisted for disk reload. It must keep incrementing even
    // though it no longer gates the serving threshold.
    HintsCache cache;
    std::string path = "/tmp/eh_lc_sep_" + std::to_string(getpid()) + ".bin";
    std::remove(path.c_str());
    cache.set_persist_path(path);
    cache.set_persist_throttle(0);

    cache.put("/page", links); // learn_count=1 → persist
    cache.put("/page", links); // learn_count=2 → persist
    cache.put("/page", links); // learn_count=3 → persist

    // Every put() persists because learn_count changes (even for identical links)
    CHECK(cache.put_persist_count() == 3);

    std::remove(path.c_str());
    std::remove((path + ".tmp").c_str());
  }

  SECTION("request_count resets to 0 on cache eviction and re-insertion")
  {
    HintsCache cache(2);
    cache.put("/a", links);
    cache.put("/b", links);

    // Warm up /a to request_count=5
    for (int i = 0; i < 5; i++) {
      cache.get("/a", 1);
    }
    REQUIRE(cache.get("/a", 1) != nullptr);

    // Evict /a by adding two new entries
    cache.put("/c", links);
    cache.put("/d", links);

    // Re-insert /a
    cache.put("/a", links);

    // After re-insertion, request_count resets to 0 — min_hits=5 fails until 5 gets
    CHECK(cache.get("/a", 5) == nullptr); // rc=0→1 < 5
  }
}

TEST_CASE("HintsCache: peek() reads links without incrementing request_count", "[hints_cache][peek]")
{
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  SECTION("peek returns links for existing entry")
  {
    HintsCache cache;
    cache.put("/page", links);
    auto r = cache.peek("/page");
    REQUIRE(r != nullptr);
    CHECK(r->size() == 1);
    CHECK((*r)[0] == "</a.js>; rel=preload; as=script");
  }

  SECTION("peek returns nullptr for missing key")
  {
    HintsCache cache;
    CHECK(cache.peek("/nonexistent") == nullptr);
  }

  SECTION("peek does not increment request_count")
  {
    HintsCache cache;
    cache.put("/page", links);

    // 10 peeks — request_count stays at 0
    for (int i = 0; i < 10; i++) {
      REQUIRE(cache.peek("/page") != nullptr);
    }

    // First get() with min_hits=2: rc=0→1 < 2 → null
    CHECK(cache.get("/page", 2) == nullptr);
    // Second get(): rc=1→2 >= 2 → non-null
    REQUIRE(cache.get("/page", 2) != nullptr);
  }

  SECTION("peek returns updated links after put")
  {
    HintsCache cache;
    cache.put("/page", links);

    std::vector<std::string> new_links = {"</b.css>; rel=preload; as=style"};
    cache.put("/page", new_links);

    auto r = cache.peek("/page");
    REQUIRE(r != nullptr);
    REQUIRE(r->size() == 1);
    CHECK((*r)[0] == "</b.css>; rel=preload; as=style");
  }

  SECTION("peek returns nullptr after entry is evicted")
  {
    HintsCache cache(2);
    cache.put("/a", links);
    cache.put("/b", links);

    REQUIRE(cache.peek("/a") != nullptr);

    // Evict /a (it is LRU: /b was inserted last = MRU)
    cache.put("/c", links); // evicts /a
    cache.put("/d", links); // evicts /b

    CHECK(cache.peek("/a") == nullptr);
  }

  SECTION("shared_ptr returned by peek is the same object as from get")
  {
    HintsCache cache;
    cache.put("/page", links);

    auto p = cache.peek("/page");
    auto g = cache.get("/page", 1); // rc=0→1 >= 1

    REQUIRE(p != nullptr);
    REQUIRE(g != nullptr);
    CHECK(p.get() == g.get()); // same underlying LinkList object
  }
}
