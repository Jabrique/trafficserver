/** @file
 * Unit tests for constant_time_eq (crypto_utils.h).
 *
 * Tests the REAL implementation used for purge token validation, not a
 * local reproduction. The function must resist timing side-channel attacks:
 * it runs in constant time regardless of where bytes or lengths differ.
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
#include "../crypto_utils.h"

// --- Correctness: equal inputs -----------------------------------------------

TEST_CASE("constant_time_eq: equal inputs return true", "[crypto_utils]")
{
  SECTION("identical string pointers return true")
  {
    const char *secret = "supersecret";
    CHECK(constant_time_eq(secret, 11, secret, 11) == true);
  }

  SECTION("same content via different pointers return true") { CHECK(constant_time_eq("abc", 3, "abc", 3) == true); }

  SECTION("both empty return true") { CHECK(constant_time_eq("", 0, "", 0) == true); }

  SECTION("single identical byte return true") { CHECK(constant_time_eq("x", 1, "x", 1) == true); }

  SECTION("all-zero bytes of same length return true")
  {
    const char zeros_a[4] = {0, 0, 0, 0};
    const char zeros_b[4] = {0, 0, 0, 0};
    CHECK(constant_time_eq(zeros_a, 4, zeros_b, 4) == true);
  }
}

// --- Correctness: different content ------------------------------------------

TEST_CASE("constant_time_eq: different content returns false", "[crypto_utils]")
{
  SECTION("first byte differs") { CHECK(constant_time_eq("Xbc", 3, "abc", 3) == false); }

  SECTION("last byte differs") { CHECK(constant_time_eq("abX", 3, "abc", 3) == false); }

  SECTION("middle byte differs") { CHECK(constant_time_eq("aXc", 3, "abc", 3) == false); }

  SECTION("completely different same-length strings") { CHECK(constant_time_eq("foo", 3, "bar", 3) == false); }

  SECTION("empty vs non-empty return false")
  {
    CHECK(constant_time_eq("", 0, "x", 1) == false);
    CHECK(constant_time_eq("x", 1, "", 0) == false);
  }
}

// --- Length mismatch: no early return ----------------------------------------

TEST_CASE("constant_time_eq: different lengths return false without early branch", "[crypto_utils]")
{
  SECTION("shorter probe of correct prefix does not match")
  {
    // Attacker sends shorter string  -- if implementation does min(a_len, b_len)
    // bytes and skips length check, "super" would match "supersecret" for 5 bytes.
    // Length XOR in diff ensures this is caught.
    CHECK(constant_time_eq("supersecret", 11, "super", 5) == false);
  }

  SECTION("longer probe does not match") { CHECK(constant_time_eq("super", 5, "supersecret", 11) == false); }

  SECTION("one extra byte at end does not match")
  {
    CHECK(constant_time_eq("password", 8, "passwordX", 9) == false);
    CHECK(constant_time_eq("passwordX", 9, "password", 8) == false);
  }

  SECTION("completely different lengths with same first byte do not match")
  {
    CHECK(constant_time_eq("a", 1, "abcdefghij", 10) == false);
  }
}

// --- Security: timing-neutrality contract ------------------------------------

TEST_CASE("constant_time_eq: result is the same regardless of where bytes diverge", "[crypto_utils]")
{
  // We cannot measure nanosecond timing in a unit test reliably, but we can
  // verify the behavioral contract: both first-byte-differs and last-byte-differs
  // must return false. If the loop short-circuited at the first differing byte,
  // both would still return false  -- this test validates the contract holds
  // for all byte positions, not that the function takes the same CPU time.
  const size_t len = 16;
  char base[len + 1];
  char diff[len + 1];
  for (size_t i = 0; i < len; i++) {
    base[i] = 'a';
    diff[i] = 'a';
  }
  base[len] = '\0';
  diff[len] = '\0';

  for (size_t change_pos = 0; change_pos < len; change_pos++) {
    diff[change_pos] = 'X'; // differ at one position
    CHECK(constant_time_eq(base, len, diff, len) == false);
    diff[change_pos] = 'a'; // restore
  }
}

// --- Security: null-byte prefix/suffix bypass --------------------------------

TEST_CASE("constant_time_eq: embedded null bytes prevent spurious match", "[crypto_utils]")
{
  SECTION("null in correct secret does not allow truncated probe to match")
  {
    // secret is "abc\0\0" (5 bytes), probe is "abc" (3 bytes): length XOR fires.
    const char secret_with_null[] = "abc\x00\x00";
    CHECK(constant_time_eq(secret_with_null, 5, "abc", 3) == false);
  }

  SECTION("null byte at start of probe does not match non-null secret")
  {
    const char probe[] = {'\0', 'a', 'b', 'c'};
    CHECK(constant_time_eq("abc", 3, probe, 4) == false);
  }
}
