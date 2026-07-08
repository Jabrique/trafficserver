/** @file
 * Cryptographic utility functions for the Early Hints plugin.
 *
 * This header exposes security-critical utilities that must be unit-tested
 * directly against the real implementation, not against local reproductions.
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

#include <cstddef>

// Compare two byte sequences in constant time to prevent timing side-channel attacks.
// Uses a volatile XOR accumulator so the compiler cannot short-circuit the loop.
//
// Length handling: instead of an early return on length mismatch (which leaks the
// secret length via timing), XOR the lengths into diff and compare up to
// max(a_len, b_len) bytes, padding the shorter sequence with zero bytes.
// A length mismatch sets diff to non-zero without any branch on secret length.
inline bool
constant_time_eq(const char *a, size_t a_len, const char *b, size_t b_len)
{
  size_t max_len    = (a_len > b_len) ? a_len : b_len;
  volatile int diff = 0;

  // XOR lengths into diff: if lengths differ, diff is non-zero immediately.
  // This removes the early-return branch that previously leaked secret length.
  diff |= (static_cast<int>(a_len) ^ static_cast<int>(b_len));

  for (size_t i = 0; i < max_len; i++) {
    unsigned char ca = (i < a_len) ? static_cast<unsigned char>(a[i]) : 0;
    unsigned char cb = (i < b_len) ? static_cast<unsigned char>(b[i]) : 0;
    diff |= (ca ^ cb);
  }
  return diff == 0;
}
