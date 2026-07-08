/** @file
 * Unit tests for PurgeRateLimiter.
 *
 * Covers single-threaded allow/deny semantics, window reset after cooldown,
 * and concurrent window-boundary safety (atomic CAS on reset).
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
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

// ===================================================================================
// PurgeRateLimiter unit tests
//
// PurgeRateLimiter enforces a fixed sliding window per remap rule:
//   - allow() returns true if the call count within the current window is < limit.
//   - When the window expires (now - window_start >= cooldown), the count resets.
//   - Thread-safe: uses CAS on window_start so only one thread wins the reset.
//
// Constructor: PurgeRateLimiter(int limit, int cooldown_seconds)
//   - limit: max allowed purges per window [1,100]
//   - cooldown_seconds: window duration in seconds [1,300]
// ===================================================================================

TEST_CASE("PurgeRateLimiter: basic allow/deny behavior", "[purge_rate_limiter]")
{
  SECTION("allow() returns true up to limit, then false")
  {
    PurgeRateLimiter limiter(3, 60);

    CHECK(limiter.allow() == true);  // count=1
    CHECK(limiter.allow() == true);  // count=2
    CHECK(limiter.allow() == true);  // count=3
    CHECK(limiter.allow() == false); // count=4 > limit=3
    CHECK(limiter.allow() == false); // still blocked
  }

  SECTION("limit=1 allows exactly one purge per window")
  {
    PurgeRateLimiter limiter(1, 60);

    CHECK(limiter.allow() == true);  // count=1, at limit
    CHECK(limiter.allow() == false); // count=2 > limit=1
  }

  SECTION("limit=100 allows 100 purges")
  {
    PurgeRateLimiter limiter(100, 60);

    for (int i = 0; i < 100; i++) {
      CHECK(limiter.allow() == true);
    }
    CHECK(limiter.allow() == false); // 101st is blocked
  }
}

TEST_CASE("PurgeRateLimiter: window reset after cooldown", "[purge_rate_limiter]")
{
  SECTION("after cooldown expires, allow() resets and permits again")
  {
    PurgeRateLimiter limiter(2, 1);

    CHECK(limiter.allow() == true);  // count=1
    CHECK(limiter.allow() == true);  // count=2
    CHECK(limiter.allow() == false); // count=3 blocked

    std::this_thread::sleep_for(std::chrono::seconds(2));

    // New window: count resets to 0
    CHECK(limiter.allow() == true);  // count=1 in new window
    CHECK(limiter.allow() == true);  // count=2 in new window
    CHECK(limiter.allow() == false); // blocked again
  }
}

TEST_CASE("PurgeRateLimiter: constructed with limit and cooldown from config", "[purge_rate_limiter]")
{
  SECTION("default config values create a valid limiter")
  {
    PurgeRateLimiter limiter(3, 10);

    for (int i = 0; i < 3; i++) {
      CHECK(limiter.allow() == true);
    }
    CHECK(limiter.allow() == false);
  }
}

// ===================================================================================
// Concurrent window-boundary safety
//
// TOCTOU race: when multiple threads simultaneously see (now - window_start >= cooldown),
// without CAS each thread resets count_ to 0, then each increments from 0. With N
// racing threads and limit=1, up to N purges are allowed instead of 1.
//
// Fix: use CAS so only one thread wins the reset. Losers fall through to the normal
// fetch_add on the already-reset counter.
//
// This test verifies: allow_count <= LIMIT even under 32 concurrent threads racing
// exactly at window expiry.
// ===================================================================================

TEST_CASE("PurgeRateLimiter: window reset is atomic  -- no count overshoot under concurrent access",
          "[purge_rate_limiter][threading]")
{
  constexpr int LIMIT     = 1;
  constexpr int COOLDOWN  = 1;
  constexpr int N_THREADS = 32;

  PurgeRateLimiter limiter(LIMIT, COOLDOWN);

  // Exhaust the first window so the next window-expiry is what we test.
  limiter.allow(); // count=1, at limit

  // Wait for cooldown to expire so all threads race at the window boundary.
  std::this_thread::sleep_for(std::chrono::milliseconds(1100));

  std::atomic<int> allow_count{0};
  std::vector<std::thread> threads;
  threads.reserve(N_THREADS);

  // Barrier: all threads start simultaneously.
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

  // With CAS fix: at most LIMIT threads are allowed in this window.
  // Without CAS fix: allow_count can be > LIMIT (up to N_THREADS).
  CHECK(allow_count.load() <= LIMIT);
}

TEST_CASE("PurgeRateLimiter: single-thread behavior unchanged after CAS window-reset fix", "[purge_rate_limiter]")
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

    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == true);
    CHECK(limiter.allow() == false);
  }
}
