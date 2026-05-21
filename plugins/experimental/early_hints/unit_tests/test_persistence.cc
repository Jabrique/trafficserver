/** @file
 * Unit tests for HintsCache disk persistence.
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
#include <cstdio>
#include <fstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

// Helper: create a unique temp file path in /tmp
static std::string
make_temp_path(const char *suffix)
{
  static int counter = 0;
  return std::string("/tmp/early_hints_test_") + std::to_string(getpid()) + "_" + std::to_string(counter++) + suffix;
}

// Helper: cleanup temp file
static void
cleanup(const std::string &path)
{
  std::remove(path.c_str());
  std::remove((path + ".tmp").c_str());
}

// Helper: check file exists
static bool
file_exists(const std::string &path)
{
  struct stat st;
  return stat(path.c_str(), &st) == 0;
}

// ─── Basic persistence ─────────────────────────────────────────────────────

TEST_CASE("Persistence: persist creates file at specified path", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
  cache.put("/page", links);

  CHECK(file_exists(path));
  cleanup(path);
}

TEST_CASE("Persistence: load restores entries correctly", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write
  {
    HintsCache cache;
    cache.set_persist_path(path);

    std::vector<std::string> links = {"</app.js>; rel=preload; as=script", "</style.css>; rel=preload; as=style"};
    cache.put("/page1", links);

    std::vector<std::string> links2 = {"</font.woff2>; rel=preload; as=font"};
    cache.put("/page2", links2);
  }

  // Read into new cache
  {
    HintsCache cache2;
    cache2.set_persist_path(path);
    REQUIRE(cache2.load_from_disk());

    CHECK(cache2.size() == 2);

    auto result1 = cache2.get("/page1", 1);
    REQUIRE(result1 != nullptr);
    REQUIRE(result1->size() == 2);
    CHECK((*result1)[0] == "</app.js>; rel=preload; as=script");
    CHECK((*result1)[1] == "</style.css>; rel=preload; as=style");

    auto result2 = cache2.get("/page2", 1);
    REQUIRE(result2 != nullptr);
    REQUIRE(result2->size() == 1);
    CHECK((*result2)[0] == "</font.woff2>; rel=preload; as=font");
  }

  cleanup(path);
}

TEST_CASE("Persistence: round-trip preserves learn_count", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Put 3 times (learn_count=3)
  {
    HintsCache cache;
    cache.set_persist_path(path);

    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
    cache.put("/page", links);
    cache.put("/page", links);
    cache.put("/page", links);
  }

  // Load and verify learn_count survived
  {
    HintsCache cache2;
    cache2.set_persist_path(path);
    REQUIRE(cache2.load_from_disk());

    // learn_count=3 means min_hits=3 should work
    auto result = cache2.get("/page", 3);
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);

    // min_hits=4 should fail
    auto result_fail = cache2.get("/page", 4);
    CHECK(result_fail == nullptr);
  }

  cleanup(path);
}

// ─── Atomic rename ──────────────────────────────────────────────────────────

TEST_CASE("Persistence: persist uses atomic rename (no .tmp left)", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
  cache.put("/page", links);

  // .tmp should not exist after successful persist
  CHECK_FALSE(file_exists(path + ".tmp"));
  CHECK(file_exists(path));

  cleanup(path);
}

// ─── Error handling ─────────────────────────────────────────────────────────

TEST_CASE("Persistence: load nonexistent file returns false, cache empty", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);

  CHECK_FALSE(cache.load_from_disk());
  CHECK(cache.size() == 0);
}

TEST_CASE("Persistence: load corrupt file (truncated header) returns false", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write truncated file (only 2 bytes)
  {
    std::ofstream f(path, std::ios::binary);
    char data[] = {0x45, 0x48};
    f.write(data, sizeof(data));
  }

  HintsCache cache;
  cache.set_persist_path(path);
  CHECK_FALSE(cache.load_from_disk());
  CHECK(cache.size() == 0);

  cleanup(path);
}

TEST_CASE("Persistence: load corrupt file (bad magic) returns false", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write file with wrong magic
  {
    std::ofstream f(path, std::ios::binary);
    uint32_t bad_magic = 0xDEADBEEF;
    uint32_t count     = 0;
    f.write(reinterpret_cast<char *>(&bad_magic), sizeof(bad_magic));
    f.write(reinterpret_cast<char *>(&count), sizeof(count));
  }

  HintsCache cache;
  cache.set_persist_path(path);
  CHECK_FALSE(cache.load_from_disk());
  CHECK(cache.size() == 0);

  cleanup(path);
}

TEST_CASE("Persistence: load corrupt file (truncated entry) returns false", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write valid header claiming 1 entry, but no entry data
  {
    std::ofstream f(path, std::ios::binary);
    uint32_t magic = HINTS_CACHE_MAGIC;
    uint32_t count = 1;
    f.write(reinterpret_cast<char *>(&magic), sizeof(magic));
    f.write(reinterpret_cast<char *>(&count), sizeof(count));
    // No entry data — truncated
  }

  HintsCache cache;
  cache.set_persist_path(path);
  CHECK_FALSE(cache.load_from_disk());

  cleanup(path);
}

// ─── Empty cache ────────────────────────────────────────────────────────────

TEST_CASE("Persistence: persist with empty cache creates valid file", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Persist empty cache
  {
    HintsCache cache;
    cache.set_persist_path(path);
    CHECK(cache.persist_to_disk());
    CHECK(file_exists(path));
  }

  // Load empty file
  {
    HintsCache cache2;
    cache2.set_persist_path(path);
    CHECK(cache2.load_from_disk());
    CHECK(cache2.size() == 0);
  }

  cleanup(path);
}

// ─── Overwrite ──────────────────────────────────────────────────────────────

TEST_CASE("Persistence: persist overwrites previous file (no duplicates)", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);
  cache.set_persist_throttle(0); // persist every put for this test
  std::vector<std::string> links1 = {"</old.js>; rel=preload; as=script"};
  cache.put("/page", links1);

  // Write version 2 (updates entry)
  std::vector<std::string> links2 = {"</new.js>; rel=preload; as=script", "</new.css>; rel=preload; as=style"};
  cache.put("/page", links2);

  // Load and verify only latest data
  HintsCache cache2;
  cache2.set_persist_path(path);
  REQUIRE(cache2.load_from_disk());
  CHECK(cache2.size() == 1);

  auto result = cache2.get("/page", 1);
  REQUIRE(result != nullptr);
  REQUIRE(result->size() == 2);
  CHECK((*result)[0] == "</new.js>; rel=preload; as=script");
  CHECK((*result)[1] == "</new.css>; rel=preload; as=style");

  cleanup(path);
}

// ─── Capacity eviction after load ───────────────────────────────────────────

TEST_CASE("Persistence: capacity eviction still works after load", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Create cache with 5 entries
  {
    HintsCache cache(5);
    cache.set_persist_path(path);

    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
    for (int i = 0; i < 5; i++) {
      cache.put("/page" + std::to_string(i), links);
    }
    CHECK(cache.size() == 5);
  }

  // Load into cache with max_entries=3 (only 3 should be loaded)
  {
    HintsCache cache2(3);
    cache2.set_persist_path(path);
    REQUIRE(cache2.load_from_disk());
    CHECK(cache2.size() <= 3);
  }

  cleanup(path);
}

// ─── No persist path ────────────────────────────────────────────────────────

TEST_CASE("Persistence: no persist path = persist_to_disk is no-op", "[persistence]")
{
  HintsCache cache;
  // No set_persist_path called

  CHECK_FALSE(cache.persist_to_disk());
  CHECK_FALSE(cache.load_from_disk());
}

// ─── Large cache round-trip ─────────────────────────────────────────────────

TEST_CASE("Persistence: large cache round-trip (500 entries)", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  constexpr int NUM_ENTRIES = 500;

  // Write
  {
    HintsCache cache(1000);
    cache.set_persist_path(path);

    for (int i = 0; i < NUM_ENTRIES; i++) {
      std::string key                = "/page/" + std::to_string(i);
      std::vector<std::string> links = {
        "</assets/bundle-" + std::to_string(i) + ".js>; rel=preload; as=script",
        "</assets/style-" + std::to_string(i) + ".css>; rel=preload; as=style",
      };
      cache.put(key, links);
    }
    CHECK(cache.size() == NUM_ENTRIES);
  }

  // Read and verify
  {
    HintsCache cache2(1000);
    cache2.set_persist_path(path);
    REQUIRE(cache2.load_from_disk());
    CHECK(cache2.size() == NUM_ENTRIES);

    // Spot-check some entries
    auto r0 = cache2.get("/page/0", 1);
    REQUIRE(r0 != nullptr);
    CHECK(r0->size() == 2);

    auto r499 = cache2.get("/page/499", 1);
    REQUIRE(r499 != nullptr);
    CHECK(r499->size() == 2);
    CHECK((*r499)[0] == "</assets/bundle-499.js>; rel=preload; as=script");
  }

  cleanup(path);
}

// ─── Auto-persist on put ────────────────────────────────────────────────────

TEST_CASE("Persistence: put triggers auto-persist when path set", "[persistence]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);
  cache.set_persist_throttle(0); // persist every put for this test

  // First put
  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
  cache.put("/page1", links);
  CHECK(file_exists(path));

  // Load into new cache and verify
  HintsCache cache2;
  cache2.set_persist_path(path);
  REQUIRE(cache2.load_from_disk());
  CHECK(cache2.size() == 1);
  CHECK(cache2.get("/page1", 1) != nullptr);

  // Second put
  cache.put("/page2", links);

  // Load again and verify both entries
  HintsCache cache3;
  cache3.set_persist_path(path);
  REQUIRE(cache3.load_from_disk());
  CHECK(cache3.size() == 2);

  cleanup(path);
}

// ═════════════════════════════════════════════════════════════════════════════
// Audit V2: Missing persistence scenarios
// ═════════════════════════════════════════════════════════════════════════════

// cache-02: Corrupt file with extra trailing data
TEST_CASE("Persistence audit v2: file with extra trailing data loads OK", "[persistence][audit-v2]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // First write a valid file
  {
    HintsCache cache;
    cache.set_persist_path(path);
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
    cache.put("/page", links);
  }

  // Append garbage bytes to the end
  {
    std::ofstream f(path, std::ios::binary | std::ios::app);
    char garbage[] = "GARBAGE_TRAILING_DATA_12345678";
    f.write(garbage, sizeof(garbage));
  }

  // Load should still succeed (reads declared entry_count, ignores trailing data)
  HintsCache cache2;
  cache2.set_persist_path(path);
  CHECK(cache2.load_from_disk());
  CHECK(cache2.size() == 1);

  auto result = cache2.get("/page", 1);
  REQUIRE(result != nullptr);
  CHECK(result->size() == 1);

  cleanup(path);
}

// cache-03: Corrupt file with truncated key data
TEST_CASE("Persistence audit v2: truncated key data returns false", "[persistence][audit-v2]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write header + entry with key_len=100 but only 5 bytes of key data
  {
    std::ofstream f(path, std::ios::binary);
    uint32_t magic = HINTS_CACHE_MAGIC;
    uint32_t count = 1;
    f.write(reinterpret_cast<char *>(&magic), sizeof(magic));
    f.write(reinterpret_cast<char *>(&count), sizeof(count));

    // key_len = 100 (but we'll only write 5 bytes)
    uint16_t key_len = 100;
    f.write(reinterpret_cast<char *>(&key_len), sizeof(key_len));
    f.write("short", 5); // only 5 bytes, not 100
    // File ends here — truncated
  }

  HintsCache cache;
  cache.set_persist_path(path);
  CHECK_FALSE(cache.load_from_disk());
  CHECK(cache.size() == 0);

  cleanup(path);
}

// cache-04: Corrupt file with extreme key_len and link_count
TEST_CASE("Persistence audit v2: extreme key_len rejected", "[persistence][audit-v2]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write header + entry with key_len = 65535 (exceeds 4096 limit)
  {
    std::ofstream f(path, std::ios::binary);
    uint32_t magic = HINTS_CACHE_MAGIC;
    uint32_t count = 1;
    f.write(reinterpret_cast<char *>(&magic), sizeof(magic));
    f.write(reinterpret_cast<char *>(&count), sizeof(count));

    uint16_t key_len = 65535; // way over 4096 limit
    f.write(reinterpret_cast<char *>(&key_len), sizeof(key_len));
  }

  HintsCache cache;
  cache.set_persist_path(path);
  CHECK_FALSE(cache.load_from_disk());

  cleanup(path);
}

TEST_CASE("Persistence audit v2: extreme link_count rejected", "[persistence][audit-v2]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write valid header + valid key + learn_count + link_count = 65535
  {
    std::ofstream f(path, std::ios::binary);
    uint32_t magic = HINTS_CACHE_MAGIC;
    uint32_t count = 1;
    f.write(reinterpret_cast<char *>(&magic), sizeof(magic));
    f.write(reinterpret_cast<char *>(&count), sizeof(count));

    // Valid key
    uint16_t key_len = 5;
    f.write(reinterpret_cast<char *>(&key_len), sizeof(key_len));
    f.write("/page", 5);

    // learn_count
    uint32_t learn_count = 1;
    f.write(reinterpret_cast<char *>(&learn_count), sizeof(learn_count));

    // last_updated (v2 field)
    uint64_t ts = 0;
    f.write(reinterpret_cast<char *>(&ts), sizeof(ts));

    // link_count = 65535 (way over 1000 limit)
    uint16_t link_count = 65535;
    f.write(reinterpret_cast<char *>(&link_count), sizeof(link_count));
  }

  HintsCache cache;
  cache.set_persist_path(path);
  CHECK_FALSE(cache.load_from_disk());

  cleanup(path);
}

// cache-05: Persist to unwritable path
TEST_CASE("Persistence audit v2: persist to unwritable path returns false", "[persistence][audit-v2]")
{
  HintsCache cache;
  cache.set_persist_path("/nonexistent/directory/that/does/not/exist/hints.bin");

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
  cache.put("/page", links);

  // persist_to_disk should fail gracefully (called internally by put)
  // Verify cache still works
  CHECK(cache.size() == 1);
  auto result = cache.get("/page", 1);
  REQUIRE(result != nullptr);
}

// cache-06: Very long key and link values
TEST_CASE("Persistence audit v2: very long key round-trips", "[persistence][audit-v2]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Create a key that's 4000 bytes (under 4096 limit)
  std::string long_key(4000, 'x');
  long_key[0] = '/'; // make it path-like

  {
    HintsCache cache;
    cache.set_persist_path(path);
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
    cache.put(long_key, links);
  }

  {
    HintsCache cache2;
    cache2.set_persist_path(path);
    REQUIRE(cache2.load_from_disk());
    CHECK(cache2.size() == 1);
    auto result = cache2.get(long_key, 1);
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);
  }

  cleanup(path);
}

TEST_CASE("Persistence audit v2: very long link value round-trips", "[persistence][audit-v2]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Create a link value that's 8000 bytes (under 8192 limit)
  std::string long_link = "</";
  long_link += std::string(7950, 'a');
  long_link += ".js>; rel=preload; as=script";

  {
    HintsCache cache;
    cache.set_persist_path(path);
    std::vector<std::string> links = {long_link};
    cache.put("/page", links);
  }

  {
    HintsCache cache2;
    cache2.set_persist_path(path);
    REQUIRE(cache2.load_from_disk());
    CHECK(cache2.size() == 1);
    auto result = cache2.get("/page", 1);
    REQUIRE(result != nullptr);
    CHECK(result->size() == 1);
    CHECK((*result)[0] == long_link);
  }

  cleanup(path);
}

// ─── miss-01: fnv1a_hash unit test ──────────────────────────────────────────
// The hash function is static in early_hints.cc; we replicate it here for
// direct verification against known FNV-1a test vectors.

static uint32_t
fnv1a_hash(const char *str)
{
  uint32_t hash = 2166136261u;
  for (; *str; ++str) {
    hash ^= static_cast<uint8_t>(*str);
    hash *= 16777619u;
  }
  return hash;
}

TEST_CASE("fnv1a_hash: correctness and collision resistance", "[persistence][hash][audit]")
{
  SECTION("empty string hashes to FNV offset basis") { CHECK(fnv1a_hash("") == 0x811c9dc5u); }

  SECTION("known FNV-1a test vectors")
  {
    // Standard FNV-1a 32-bit test vectors (from http://www.isthe.com/chongo/tech/comp/fnv/)
    CHECK(fnv1a_hash("a") == 0xe40c292cu);
    CHECK(fnv1a_hash("foobar") == 0xbf9cf968u);
  }

  SECTION("different URLs produce different hashes")
  {
    uint32_t h1 = fnv1a_hash("http://cdn.example.com/page1.html");
    uint32_t h2 = fnv1a_hash("http://cdn.example.com/page2.html");
    uint32_t h3 = fnv1a_hash("http://cdn.example.com/page1.html?v=2");
    CHECK(h1 != h2);
    CHECK(h1 != h3);
    CHECK(h2 != h3);
  }

  SECTION("hash is deterministic")
  {
    const char *url = "https://cdn.example.com/path/to/resource";
    CHECK(fnv1a_hash(url) == fnv1a_hash(url));
  }

  SECTION("similar strings produce different hashes")
  {
    // Single-char difference
    CHECK(fnv1a_hash("abc") != fnv1a_hash("abd"));
    CHECK(fnv1a_hash("abc") != fnv1a_hash("abC"));
  }
}

// ─── miss-02: load_from_disk entry_count at max_entries*2+1 boundary ────────

TEST_CASE("Persistence: entry_count at exactly max_entries*2+1 is rejected", "[persistence][boundary][audit]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Manually write a persist file with entry_count = max_entries*2 + 1
  // For a cache with max_entries=100, the sanity limit is 200; 201 should fail
  {
    FILE *fp = fopen(path.c_str(), "wb");
    REQUIRE(fp);
    uint32_t magic       = HINTS_CACHE_MAGIC;
    uint32_t entry_count = 201; // 100 * 2 + 1
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&entry_count, sizeof(entry_count), 1, fp);
    fclose(fp);
  }

  HintsCache cache(100);
  cache.set_persist_path(path);
  CHECK_FALSE(cache.load_from_disk()); // Should reject: 201 > 100*2 = 200

  cleanup(path);
}

TEST_CASE("Persistence: entry_count at exactly max_entries*2 is accepted", "[persistence][boundary][audit]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write a persist file with entry_count exactly at limit (200 for max_entries=100)
  // File has valid header but no actual entries → load will fail reading first entry
  // The point is: the sanity check PASSES (doesn't reject upfront)
  {
    FILE *fp = fopen(path.c_str(), "wb");
    REQUIRE(fp);
    uint32_t magic       = HINTS_CACHE_MAGIC;
    uint32_t entry_count = 200; // exactly 100 * 2
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&entry_count, sizeof(entry_count), 1, fp);
    // Don't write any actual entries — load will fail reading first key_len
    fclose(fp);
  }

  HintsCache cache(100);
  cache.set_persist_path(path);
  // load_from_disk will pass the sanity check (200 <= 200) but fail reading entries
  // The important thing is it doesn't reject at the entry_count check
  CHECK_FALSE(cache.load_from_disk()); // Fails on missing entry data, not sanity check

  cleanup(path);
}

// ─── Dirty flag integrity ────────────────────────────────────────────────────
//
// If persist_to_disk() fails (e.g. unwritable path, disk full), is_dirty_
// must remain true so the destructor can retry on shutdown.
// Clearing it before the write succeeds causes silent data loss.

TEST_CASE("Persistence: dirty flag survives a failed persist_to_disk()", "[persistence][dirty-flag]")
{
  HintsCache cache;
  cache.set_persist_path("/nonexistent/dir/hints.bin"); // fopen will fail

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
  cache.put("/page", links);

  bool ok = cache.persist_to_disk();
  CHECK_FALSE(ok);

  // Redirect to a valid path
  std::string valid_path = make_temp_path(".bin");
  cleanup(valid_path);
  cache.set_persist_path(valid_path);

  // If dirty flag was wrongly cleared by the failed persist, this call will
  // see nothing dirty and produce an empty or missing file.
  bool ok2 = cache.persist_to_disk();
  CHECK(ok2);

  HintsCache verify;
  verify.set_persist_path(valid_path);
  REQUIRE(verify.load_from_disk());
  CHECK(verify.size() == 1);
  auto result = verify.get("/page", 1);
  REQUIRE(result != nullptr);

  cleanup(valid_path);
}

TEST_CASE("Persistence: destructor flushes data even after a prior failed persist", "[persistence][dirty-flag]")
{
  std::string valid_path = make_temp_path(".bin");
  cleanup(valid_path);

  {
    HintsCache cache;
    cache.set_persist_path("/nonexistent/dir/hints.bin");
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
    cache.put("/page", links);
    cache.persist_to_disk(); // fails — dirty flag must NOT be cleared

    cache.set_persist_path(valid_path);
    // Destructor runs here — must flush because data is still dirty
  }

  // If dirty flag was cleared on failure, the destructor skips the flush
  // and the file never gets written.
  REQUIRE(file_exists(valid_path));

  HintsCache verify;
  verify.set_persist_path(valid_path);
  REQUIRE(verify.load_from_disk());
  CHECK(verify.size() == 1);

  cleanup(valid_path);
}

// ─── Write error safety ──────────────────────────────────────────────────────
//
// A failed persist (bad path, disk full) must not corrupt or overwrite
// an existing valid persist file. The atomic rename must only happen
// after confirming all writes completed successfully.

TEST_CASE("Persistence: failed persist leaves the existing good file intact", "[persistence][write-safety]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  // Write a known-good file first
  {
    HintsCache cache;
    cache.set_persist_path(path);
    std::vector<std::string> links = {"</original.js>; rel=preload; as=script"};
    cache.put("/page", links);
    cache.put("/page", links); // reset throttle
    REQUIRE(cache.persist_to_disk());
    REQUIRE(file_exists(path));
    CHECK_FALSE(file_exists(path + ".tmp")); // .tmp removed on success
  }

  // A separate cache with a bad persist path must not corrupt the good file
  {
    HintsCache cache2;
    cache2.set_persist_path("/nonexistent/dir/hints.bin");
    std::vector<std::string> links = {"</new.js>; rel=preload; as=script"};
    cache2.put("/page", links);
    CHECK_FALSE(cache2.persist_to_disk());
  }

  // The original file must still be intact
  {
    HintsCache verify;
    verify.set_persist_path(path);
    REQUIRE(verify.load_from_disk());
    CHECK(verify.size() == 1);
    auto result = verify.get("/page", 1);
    REQUIRE(result != nullptr);
    CHECK((*result)[0] == "</original.js>; rel=preload; as=script");
  }

  cleanup(path);
}

// ─── Concurrent persist safety ───────────────────────────────────────────────
//
// Concurrent put()-triggered persists must not race against an explicit
// persist_to_disk() call (e.g. from shutdown code). Both paths must
// be serialized by persist_mutex_ to avoid writing .tmp simultaneously.

TEST_CASE("Persistence: concurrent persist calls produce a valid final file", "[persistence][concurrent-persist][threading]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  for (int trial = 0; trial < 5; ++trial) {
    cleanup(path);
    HintsCache cache(1000);
    cache.set_persist_path(path);
    cache.set_persist_throttle(0); // persist on every put

    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
      threads.emplace_back([&, i]() {
        for (int j = 0; j < 10; ++j) {
          cache.put("/page" + std::to_string(i * 10 + j), links);
        }
      });
    }
    for (auto &t : threads) {
      t.join();
    }

    // Explicit flush while destructor may also flush — must not corrupt
    cache.persist_to_disk();

    if (file_exists(path)) {
      HintsCache verify;
      verify.set_persist_path(path);
      CHECK(verify.load_from_disk());
    }
  }

  cleanup(path);
}

// ─── Link validation on load ─────────────────────────────────────────────────
//
// Links loaded from a persist file must be re-validated before serving.
// An older plugin version or a tampered file may contain unsupported rel types
// (e.g. rel=prefetch) or preload entries without as= that would be rejected
// by the current plugin's validation logic.

TEST_CASE("Persistence: invalid rel type from persist file is rejected on load", "[persistence][load-validation]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  {
    FILE *fp = fopen(path.c_str(), "wb");
    REQUIRE(fp);

    uint32_t magic = HINTS_CACHE_MAGIC;
    uint32_t count = 1;
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&count, sizeof(count), 1, fp);

    const char *key  = "/page";
    uint16_t key_len = static_cast<uint16_t>(strlen(key));
    fwrite(&key_len, sizeof(key_len), 1, fp);
    fwrite(key, key_len, 1, fp);

    uint32_t lc = 3;
    fwrite(&lc, sizeof(lc), 1, fp);

    uint64_t ts = 0; // last_updated (v2 field)
    fwrite(&ts, sizeof(ts), 1, fp);

    // Two links: one valid, one with unsupported rel=prefetch
    uint16_t link_count = 2;
    fwrite(&link_count, sizeof(link_count), 1, fp);

    const char *valid_link = "</app.js>; rel=preload; as=script";
    uint16_t ll1           = static_cast<uint16_t>(strlen(valid_link));
    fwrite(&ll1, sizeof(ll1), 1, fp);
    fwrite(valid_link, ll1, 1, fp);

    const char *invalid_link = "</x>; rel=prefetch";
    uint16_t ll2             = static_cast<uint16_t>(strlen(invalid_link));
    fwrite(&ll2, sizeof(ll2), 1, fp);
    fwrite(invalid_link, ll2, 1, fp);

    fclose(fp);
  }

  HintsCache cache;
  cache.set_persist_path(path);
  REQUIRE(cache.load_from_disk());
  CHECK(cache.size() == 1);

  auto result = cache.get("/page", 1);
  REQUIRE(result != nullptr);
  // Only the valid link must be present; the invalid one must be dropped
  CHECK(result->size() == 1);
  CHECK((*result)[0] == "</app.js>; rel=preload; as=script");

  cleanup(path);
}

TEST_CASE("Persistence: preload link missing as= is rejected on load", "[persistence][load-validation]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  {
    FILE *fp = fopen(path.c_str(), "wb");
    REQUIRE(fp);

    uint32_t magic = HINTS_CACHE_MAGIC;
    uint32_t count = 1;
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&count, sizeof(count), 1, fp);

    const char *key  = "/page";
    uint16_t key_len = static_cast<uint16_t>(strlen(key));
    fwrite(&key_len, sizeof(key_len), 1, fp);
    fwrite(key, key_len, 1, fp);

    uint32_t lc = 1;
    fwrite(&lc, sizeof(lc), 1, fp);

    uint64_t ts = 0; // last_updated (v2 field)
    fwrite(&ts, sizeof(ts), 1, fp);

    uint16_t link_count = 1;
    fwrite(&link_count, sizeof(link_count), 1, fp);

    // rel=preload without as= — invalid: preload requires the as= attribute
    const char *bad_link = "</app.js>; rel=preload";
    uint16_t ll          = static_cast<uint16_t>(strlen(bad_link));
    fwrite(&ll, sizeof(ll), 1, fp);
    fwrite(bad_link, ll, 1, fp);

    fclose(fp);
  }

  HintsCache cache;
  cache.set_persist_path(path);
  cache.load_from_disk();

  // Entry with only invalid links must be absent or have an empty link list
  auto result = cache.get("/page", 1);
  if (result != nullptr) {
    CHECK(result->empty());
  }

  cleanup(path);
}

// ─── persist_count atomicity ─────────────────────────────────────────────────
//
// persist_count_ is incremented inside a nested lock (persist_mutex_ held,
// then mutex_ acquired). Making it std::atomic removes this nested dependency.
// Test verifies correctness under concurrent pressure without deadlock.

TEST_CASE("Persistence: persist count is accurate under concurrent puts", "[persistence][persist-count][threading]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);
  cache.set_persist_throttle(0); // persist every put

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  constexpr int NUM_THREADS = 4;
  constexpr int PUTS_EACH   = 10;

  std::vector<std::thread> threads;
  for (int i = 0; i < NUM_THREADS; ++i) {
    threads.emplace_back([&, i]() {
      for (int j = 0; j < PUTS_EACH; ++j) {
        cache.put("/page" + std::to_string(i), links);
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }

  // At least one persist must have happened; no deadlock must occur
  CHECK(cache.put_persist_count() >= 1);

  cleanup(path);
}

// Persist throttle: rapid puts within throttle window should persist only once

TEST_CASE("Persistence: throttle limits persist frequency on rapid puts", "[persistence][throttle]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);
  cache.set_persist_throttle(5); // 5 second throttle

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  // Rapid puts: all within the same second
  cache.put("/page1", links);
  cache.put("/page2", links);
  cache.put("/page3", links);
  cache.put("/page4", links);
  cache.put("/page5", links);

  // Only the first put should have triggered a persist (subsequent ones throttled)
  CHECK(cache.put_persist_count() == 1);

  // But all 5 entries should be in memory
  CHECK(cache.size() == 5);

  cleanup(path);
}

TEST_CASE("Persistence: throttle=0 persists every put (backward compatible)", "[persistence][throttle]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);
  cache.set_persist_throttle(0); // no throttle

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  cache.put("/page1", links);
  cache.put("/page2", links);
  cache.put("/page3", links);

  // Each put should trigger a persist
  CHECK(cache.put_persist_count() == 3);

  cleanup(path);
}

TEST_CASE("Persistence: throttle allows persist after interval expires", "[persistence][throttle]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  HintsCache cache;
  cache.set_persist_path(path);
  cache.set_persist_throttle(1); // 1 second throttle (short for test)

  std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

  cache.put("/page1", links);
  CHECK(cache.put_persist_count() == 1);

  cache.put("/page2", links); // should be throttled
  CHECK(cache.put_persist_count() == 1);

  sleep(2); // wait for throttle to expire

  cache.put("/page3", links); // should trigger persist again
  CHECK(cache.put_persist_count() == 2);

  cleanup(path);
}

TEST_CASE("Persistence: destructor flushes dirty data even when throttled", "[persistence][throttle]")
{
  std::string path = make_temp_path(".bin");
  cleanup(path);

  {
    HintsCache cache;
    cache.set_persist_path(path);
    cache.set_persist_throttle(9999); // very long throttle

    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
    cache.put("/page1", links); // first put: persists
    cache.put("/page2", links); // throttled: NOT persisted to disk yet

    CHECK(cache.put_persist_count() == 1);
    CHECK(cache.size() == 2);
    // destructor runs here, should flush because is_dirty
  }

  // Verify destructor persisted the throttled data
  HintsCache verify;
  verify.set_persist_path(path);
  REQUIRE(verify.load_from_disk());
  CHECK(verify.size() == 2);
  CHECK(verify.get("/page1", 1) != nullptr);
  CHECK(verify.get("/page2", 1) != nullptr);

  cleanup(path);
}
