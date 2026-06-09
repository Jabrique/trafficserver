/** @file
 * Plugin instance data for the early_hints plugin.
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

#include "config.h"
#include "hints_cache.h"
#include <atomic>
#include <ctime>

// PurgeRateLimiter: fixed-window per remap rule.
// Allows at most `limit` calls to allow() within a `cooldown` second window.
//
// Thread-safe: window reset uses compare_exchange_strong so only one thread
// wins the reset. Concurrent threads that also see window_start as expired
// find that the CAS fails (window_start was already updated by the winner)
// and fall through to a normal fetch_add on the already-reset counter.
//
// Without CAS: all N threads that see (now - ws >= cooldown) each store
// count_=0 and then each fetch_add from 0, allowing up to N*limit purges
// in a single window (TOCTOU race).
struct PurgeRateLimiter {
  explicit PurgeRateLimiter(int limit, int cooldown_seconds)
    : limit_(limit), cooldown_(cooldown_seconds), count_(0), window_start_(std::time(nullptr))
  {
  }

  // Returns true if this purge is allowed, false if rate-limited.
  bool
  allow()
  {
    time_t now = std::time(nullptr);
    time_t ws  = window_start_.load(std::memory_order_acquire);

    if (now - ws >= cooldown_) {
      // Window expired: use CAS to ensure only one thread wins the reset.
      // The winner atomically updates window_start_ from ws to now.
      // Losers see the CAS fail (ws was already changed) and fall through.
      if (window_start_.compare_exchange_strong(ws, now, std::memory_order_acq_rel, std::memory_order_relaxed)) {
        // This thread won the window reset: set count to 1 (our own request)
        // and report allowed if 1 <= limit.
        count_.store(1, std::memory_order_release);
        return 1 <= limit_;
      }
      // CAS failed: another thread already reset the window. Fall through
      // to the normal fetch_add below on the already-reset counter.
    }

    int prev = count_.fetch_add(1, std::memory_order_relaxed);
    return prev < limit_;
  }

  // Non-copyable: each remap instance owns its own limiter state
  PurgeRateLimiter(const PurgeRateLimiter &) = delete;
  PurgeRateLimiter &operator=(const PurgeRateLimiter &) = delete;

private:
  int limit_;
  int cooldown_;
  std::atomic<int> count_;
  std::atomic<time_t> window_start_;
};

// Plugin instance data stored in TSCont — owns config and cache.
struct PluginInstance {
  EarlyHintsConfig *config  = nullptr;
  HintsCache *cache         = nullptr;
  PurgeRateLimiter *limiter = nullptr; // non-null when purge header is configured

  ~PluginInstance()
  {
    delete config;
    delete cache;
    delete limiter;
  }

  // Noncopyable — prevent accidental double-free
  PluginInstance()                       = default;
  PluginInstance(const PluginInstance &) = delete;
  PluginInstance &operator=(const PluginInstance &) = delete;
};
