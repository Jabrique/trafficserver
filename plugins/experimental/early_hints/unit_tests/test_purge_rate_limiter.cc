/** @file
 * Unit tests for PurgeRateLimiter.
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
#include <thread>
#include <chrono>

// ===================================================================================
// PurgeRateLimiter unit tests
//
// PurgeRateLimiter enforces a fixed sliding window per remap rule:
//   - allow() returns true if the call count within the current window is < limit.
//   - When the window expires (now - window_start >= cooldown), the count resets.
//   - Thread-safe: uses atomic operations for count and window_start.
//
// Constructor: PurgeRateLimiter(int limit, int cooldown_seconds)
//   - limit: max allowed purges per window [1,100]
//   - cooldown_seconds: window duration in seconds [1,300]
//
// RED before fix: PurgeRateLimiter does not exist.
// GREEN after fix: all assertions pass.
// ===================================================================================

TEST_CASE("PurgeRateLimiter: basic allow/deny behavior", "[purge_rate_limiter]")
{
  SECTION("allow() returns true up to limit, then false")
  {
    // RED before fix: PurgeRateLimiter does not exist
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
    // cooldown=1 second, limit=2
    PurgeRateLimiter limiter(2, 1);

    CHECK(limiter.allow() == true);  // count=1
    CHECK(limiter.allow() == true);  // count=2
    CHECK(limiter.allow() == false); // count=3 blocked

    // Wait for the 1-second cooldown to expire
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
    // Simulate creation from default config (limit=3, cooldown=10)
    PurgeRateLimiter limiter(3, 10);

    // First 3 calls succeed
    for (int i = 0; i < 3; i++) {
      CHECK(limiter.allow() == true);
    }
    // 4th blocked
    CHECK(limiter.allow() == false);
  }
}
