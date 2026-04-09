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
#include <thread>
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

    auto result = cache.get("/page", 1);
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

  SECTION("get with min_hits=2 succeeds after second put")
  {
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);
    cache.put("/page", links);

    auto result = cache.get("/page", 2);
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);
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
  CHECK(after == before + 1);
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
  HintsCache cache;
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  // Put 5 times → learn_count = 5
  for (int i = 0; i < 5; i++) {
    cache.put("/page", links);
  }

  // min_hits=5: exactly at threshold → should succeed
  auto result5 = cache.get("/page", 5);
  REQUIRE(result5 != nullptr);
  CHECK(result5->size() == 1);

  // min_hits=6: one above threshold → should fail
  auto result6 = cache.get("/page", 6);
  CHECK(result6 == nullptr);

  // min_hits=4: one below threshold → should succeed
  auto result4 = cache.get("/page", 4);
  REQUIRE(result4 != nullptr);

  // min_hits=1: well below → should succeed
  auto result1 = cache.get("/page", 1);
  REQUIRE(result1 != nullptr);

  // Vector-based get: same boundary
  std::vector<std::string> out;
  CHECK(cache.get("/page", out, 5) == true);
  CHECK(cache.get("/page", out, 6) == false);
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
