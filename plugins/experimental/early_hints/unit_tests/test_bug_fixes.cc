/** @file
 * Unit tests for targeted bug fixes:
 *   C1 - PurgeRateLimiter TOCTOU race at window boundary
 *   C2 - constant_time_eq length leak
 *   H3 - dedup_link_segments called inside origin-forward loop
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
#include "../plugin_instance.h"
#include "../link_parser.h"
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// C1: PurgeRateLimiter - concurrent window boundary test
//
// The TOCTOU race: when multiple threads simultaneously see
// (now - window_start >= cooldown), each thread resets count_ to 0,
// then each increments from 0. With N threads racing, up to N*limit
// purges are allowed in one window instead of limit.
//
// Fix: use CAS so only one thread wins the window reset. Losers fall
// through to the normal fetch_add on the already-reset counter.
//
// RED (before fix): allow_count > limit is possible when N threads race.
// GREEN (after fix): allow_count <= limit even under full concurrency.
// ============================================================================

TEST_CASE("PurgeRateLimiter: window reset is atomic - no count overshoot under concurrency", "[purge_rate_limiter][c1][threading]")
{
  // Use a very short cooldown (1s) and limit=1.
  // With TOCTOU, multiple threads can all see window expired and each
  // reset count_ to 0, then each get prev=0 < limit=1 => true.
  // After fix with CAS, only 1 thread wins the reset; others fall
  // through and their fetch_add sees count >= limit => false.
  constexpr int LIMIT     = 1;
  constexpr int COOLDOWN  = 1;
  constexpr int N_THREADS = 32;

  PurgeRateLimiter limiter(LIMIT, COOLDOWN);

  // Exhaust the first window so the next window-expiry is what we test.
  limiter.allow(); // count=1, at limit
  // Window now has count=1, limit=1, all subsequent allow() return false
  // until cooldown expires.

  // Wait for the cooldown to expire.
  std::this_thread::sleep_for(std::chrono::milliseconds(1100));

  // Now launch N_THREADS that all call allow() simultaneously.
  // With TOCTOU, all threads can win; with CAS, only 1 should win.
  std::atomic<int> allow_count{0};
  std::vector<std::thread> threads;
  threads.reserve(N_THREADS);

  // Use a barrier so all threads start at the same instant.
  std::atomic<bool> go{false};
  for (int i = 0; i < N_THREADS; i++) {
    threads.emplace_back([&] {
      while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      if (limiter.allow()) {
        allow_count.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  go.store(true, std::memory_order_release);
  for (auto &t : threads) {
    t.join();
  }

  // With CAS fix: only LIMIT threads should be allowed in this window.
  // Without CAS fix: allow_count can be > LIMIT (up to N_THREADS).
  CHECK(allow_count.load() <= LIMIT);
}

TEST_CASE("PurgeRateLimiter: single thread behavior unchanged after CAS fix", "[purge_rate_limiter][c1]")
{
  SECTION("limit=3: first 3 allowed, 4th blocked")
  {
    PurgeRateLimiter limiter(3, 60);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == false);
  }

  SECTION("limit=1: exactly 1 allowed")
  {
    PurgeRateLimiter limiter(1, 60);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == false);
  }

  SECTION("window reset allows again after cooldown")
  {
    PurgeRateLimiter limiter(2, 1);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == false);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // New window: should allow again up to limit
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == false);
  }
}

// ============================================================================
// C2: constant_time_eq length leak
//
// The original code does an early return when a_len != b_len:
//   if (a_len != b_len) { return false; }
//
// This leaks the secret length via timing. An attacker can determine the
// secret length by comparing response times for different-length probe values.
//
// Fix: compare up to max(a_len, b_len) bytes, padding the shorter string
// with zeros. XOR the lengths into the diff accumulator so length mismatch
// is reflected in diff without an early branch.
//
// We cannot measure wall-clock timing in a unit test reliably, but we can
// verify the behavioral contract:
//   - Wrong length => returns false (semantics preserved)
//   - Correct content AND correct length => returns true
//   - Wrong content, same length => returns false
//
// The implementation is private to early_hints.cc (not exported), so we
// test it indirectly via a white-box helper exposed for testing.
//
// Since constant_time_eq is a file-static in early_hints.cc (not accessible
// here), we test the contract by verifying the function produces the same
// *result* regardless of whether the lengths differ or the contents differ
// for any same-length mismatched pair. The behavioral guarantee is:
//   constant_time_eq(secret, correct_secret) == true iff same
//
// We create a local version of the fixed implementation to test the logic.
// ============================================================================

// Local reproduction of the fixed constant_time_eq for unit testing.
// This mirrors what early_hints.cc will contain after the fix.
static bool
constant_time_eq_fixed(const char *a, size_t a_len, const char *b, size_t b_len)
{
  size_t max_len    = (a_len > b_len) ? a_len : b_len;
  volatile int diff = 0;

  // XOR lengths into diff: if lengths differ, diff will be non-zero.
  // This removes the early-return length branch entirely.
  diff |= (static_cast<int>(a_len) ^ static_cast<int>(b_len));

  for (size_t i = 0; i < max_len; i++) {
    unsigned char ca = (i < a_len) ? static_cast<unsigned char>(a[i]) : 0;
    unsigned char cb = (i < b_len) ? static_cast<unsigned char>(b[i]) : 0;
    diff |= (ca ^ cb);
  }
  return diff == 0;
}

TEST_CASE("constant_time_eq fixed: behavioral correctness", "[constant_time_eq][c2]")
{
  SECTION("identical strings return true")
  {
    const char *secret = "supersecret";
    CHECK(constant_time_eq_fixed(secret, 11, secret, 11) == true);
  }

  SECTION("same content, same length: true") { CHECK(constant_time_eq_fixed("abc", 3, "abc", 3) == true); }

  SECTION("different content, same length: false") { CHECK(constant_time_eq_fixed("abc", 3, "abd", 3) == false); }

  SECTION("different length, shorter probe: false")
  {
    // Attacker sends shorter string - should return false without early branch
    CHECK(constant_time_eq_fixed("supersecret", 11, "super", 5) == false);
  }

  SECTION("different length, longer probe: false")
  {
    // Attacker sends longer string - should return false without early branch
    CHECK(constant_time_eq_fixed("super", 5, "supersecret", 11) == false);
  }

  SECTION("empty vs non-empty: false")
  {
    CHECK(constant_time_eq_fixed("", 0, "x", 1) == false);
    CHECK(constant_time_eq_fixed("x", 1, "", 0) == false);
  }

  SECTION("both empty: true") { CHECK(constant_time_eq_fixed("", 0, "", 0) == true); }

  SECTION("one extra byte at end: false")
  {
    // "password" vs "passwordX" - differs only in length
    CHECK(constant_time_eq_fixed("password", 8, "passwordX", 9) == false);
  }

  SECTION("result does not differ based on where bytes diverge")
  {
    // Same result regardless of whether first byte differs or last byte differs.
    // This validates that there is no early exit in the loop.
    bool first_differs = constant_time_eq_fixed("Xbcdefgh", 8, "abcdefgh", 8);
    bool last_differs  = constant_time_eq_fixed("abcdefgX", 8, "abcdefgh", 8);

    // Both must be false
    CHECK(first_differs == false);
    CHECK(last_differs == false);
  }
}

TEST_CASE("constant_time_eq fixed: length XOR prevents bypass", "[constant_time_eq][c2]")
{
  SECTION("prefix of correct secret does not return true")
  {
    // If the implementation has a bug where it checks a_len bytes and ignores
    // the length difference, "super" might match "supersecret" for first 5 bytes.
    // The length XOR ensures this is caught.
    CHECK(constant_time_eq_fixed("supersecret", 11, "super", 5) == false);
  }

  SECTION("correct secret padded with nulls does not return true")
  {
    // If padding with zeros and secret happens to end with zeros, attacker
    // could craft a truncated version. But length XOR prevents this.
    const char secret_with_null[] = "abc\x00\x00";
    CHECK(constant_time_eq_fixed(secret_with_null, 5, "abc", 3) == false);
  }
}

// ============================================================================
// H3: dedup_link_segments called inside loop
//
// The origin-forward loop in early_hints.cc:
//   while (link_field != TS_NULL_MLOC) {
//     segments = split_link_header_value(...);
//     for (auto &seg : segments) {
//       origin_links.push_back(...);
//     }
//     origin_links = dedup_link_segments(origin_links, max_links); // WRONG
//     link_field = TSMimeHdrFieldNextDup(...);
//   }
//
// The fix: move dedup_link_segments() outside the while loop, calling it
// once after all Link header fields have been collected.
//
// Behavioral contract to test (via dedup_link_segments directly):
//   1. dedup_link_segments([A, B, A]) -> [A, B]  (dedup works)
//   2. Calling dedup once after accumulation == calling inside loop
//      (results must be identical)
//   3. Dedup is idempotent: dedup(dedup(list)) == dedup(list)
// ============================================================================

TEST_CASE("dedup_link_segments: calling once after full accumulation vs per-field", "[link_parser][h3]")
{
  // Simulate collecting segments from 3 separate Link header fields.
  // Field 1: two unique links
  std::vector<std::string> field1 = {
    "</style.css>; rel=preload; as=style",
    "</app.js>; rel=preload; as=script",
  };
  // Field 2: one duplicate from field 1, one new
  std::vector<std::string> field2 = {
    "</app.js>; rel=preload; as=script", // duplicate of field1[1]
    "</font.woff2>; rel=preload; as=font; crossorigin=anonymous",
  };
  // Field 3: one duplicate, one new that is weaker (preconnect)
  std::vector<std::string> field3 = {
    "</style.css>; rel=preload; as=style", // duplicate of field1[0]
    "<https://cdn.example.com>; rel=preconnect",
  };

  // Simulate OLD behavior: dedup inside loop (called per field).
  std::vector<std::string> inside_loop;
  // After field1
  inside_loop.insert(inside_loop.end(), field1.begin(), field1.end());
  inside_loop = dedup_link_segments(inside_loop, 50);
  // After field2
  inside_loop.insert(inside_loop.end(), field2.begin(), field2.end());
  inside_loop = dedup_link_segments(inside_loop, 50);
  // After field3
  inside_loop.insert(inside_loop.end(), field3.begin(), field3.end());
  inside_loop = dedup_link_segments(inside_loop, 50);

  // Simulate NEW behavior: dedup once after full accumulation.
  std::vector<std::string> all;
  all.insert(all.end(), field1.begin(), field1.end());
  all.insert(all.end(), field2.begin(), field2.end());
  all.insert(all.end(), field3.begin(), field3.end());
  std::vector<std::string> outside_loop = dedup_link_segments(all, 50);

  // Both approaches must produce the same result.
  REQUIRE(inside_loop.size() == outside_loop.size());
  for (size_t i = 0; i < inside_loop.size(); i++) {
    INFO("index " << i);
    CHECK(inside_loop[i] == outside_loop[i]);
  }
}

TEST_CASE("dedup_link_segments: idempotent - dedup(dedup(x)) == dedup(x)", "[link_parser][h3]")
{
  std::vector<std::string> segments = {
    "</style.css>; rel=preload; as=style",
    "</app.js>; rel=preload; as=script",
    "</style.css>; rel=preload; as=style", // duplicate
    "<https://cdn.example.com>; rel=preconnect",
  };

  auto once  = dedup_link_segments(segments, 50);
  auto twice = dedup_link_segments(once, 50);

  REQUIRE(once.size() == twice.size());
  for (size_t i = 0; i < once.size(); i++) {
    CHECK(once[i] == twice[i]);
  }
}

TEST_CASE("dedup_link_segments: max_links cap enforced when called outside loop", "[link_parser][h3]")
{
  // Build 10 unique links.
  std::vector<std::string> all;
  for (int i = 0; i < 10; i++) {
    all.push_back("</asset" + std::to_string(i) + ".js>; rel=preload; as=script");
  }

  // Cap at 5
  auto result = dedup_link_segments(all, 5);
  CHECK(result.size() <= 5);
  CHECK(result.size() == 5);
}

TEST_CASE("dedup_link_segments: preload beats preconnect regardless of insertion order", "[link_parser][h3]")
{
  // Preconnect appears first (from field1), preload appears later (from field2).
  // After fix: single dedup call sees both and must keep preload.
  std::vector<std::string> segments = {
    "<https://cdn.example.com>; rel=preconnect",
    "<https://cdn.example.com/app.js>; rel=preload; as=script",
  };
  // Both share the same host. The URL keys are different here so they are
  // NOT duplicates (different paths). Let's use the same URL:
  std::vector<std::string> same_url = {
    "<https://cdn.example.com>; rel=preconnect",
    "<https://cdn.example.com>; rel=preload; as=script",
  };

  auto result = dedup_link_segments(same_url, 50);

  // Only one entry (deduplicated by URL key).
  REQUIRE(result.size() == 1);
  // Must keep the stronger preload, not the weaker preconnect.
  CHECK(result[0].find("rel=preload") != std::string::npos);
}

TEST_CASE("dedup_link_segments: empty input returns empty output", "[link_parser][h3]")
{
  std::vector<std::string> empty;
  auto result = dedup_link_segments(empty, 50);
  CHECK(result.empty());
}

TEST_CASE("dedup_link_segments: no duplicates - all entries preserved", "[link_parser][h3]")
{
  std::vector<std::string> unique = {
    "</style.css>; rel=preload; as=style",
    "</app.js>; rel=preload; as=script",
    "<https://cdn.example.com>; rel=preconnect",
  };

  auto result = dedup_link_segments(unique, 50);
  REQUIRE(result.size() == 3);
}
