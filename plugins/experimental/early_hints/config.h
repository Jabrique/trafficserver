/** @file
 * Configuration parsing for the early_hints plugin.
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

#include <cstdint>
#include <string>
#include <vector>

#define PLUGIN_NAME "early_hints"

// Per-header framing overhead: "Link: " (6 bytes) + "\r\n" (2 bytes) = 8 bytes.
// Used when accounting for Link header size budget in 103 and 200 responses.
static constexpr int LINK_HEADER_OVERHEAD = 8;

// Validates a Link header value: structural checks (< > brackets), control chars,
// URL scheme allowlist (http/https/relative only), and valid rel= type.
// Single source of truth — used by both config.cc (manual --link) and early_hints.cc
// (origin-forward forwarding).
bool is_valid_link_value(const std::string &link);

// Validates an HTTP header field name per RFC 7230 §3.2 (tchar only, non-empty).
// Used by config.cc (--purge-header validation) and unit tests.
bool is_valid_header_name(const std::string &name);

// Validates that a Link header value with rel=preload or rel=modulepreload
// also contains a valid as= attribute (Fetch spec §8 destinations).
// Returns true if as= is valid, or if rel is not preload/modulepreload.
bool has_valid_as_for_preload(const std::string &link);

// Merges link vectors from manual config and auto-learned cache.
// Manual links added first (priority), cached links appended with URL deduplication.
// Result capped at max_links.
std::vector<std::string> merge_hint_links(const std::vector<std::string> &manual_links,
                                          const std::vector<std::string> *cached_links, int max_links);

// Normalizes a Link header value received from an origin response for use in 103 Early Hints.
// HTTP 103 only supports rel=preload, rel=preconnect, and rel=modulepreload.
// Converts rel=stylesheet to rel=preload; as=style so origin stylesheets generate
// valid preload hints. Returns an empty string if the link cannot be normalized.
std::string normalize_link_for_hint(const std::string &link);

class EarlyHintsConfig
{
public:
  enum Mode : uint8_t {
    MODE_MANUAL         = 0x01,
    MODE_AUTO_LEARN     = 0x02,
    MODE_ORIGIN_FORWARD = 0x04,
  };

  EarlyHintsConfig()  = default;
  ~EarlyHintsConfig() = default;

  bool init(int argc, const char *argv[]);

  uint8_t
  mode() const
  {
    return mode_;
  }

  int
  max_links() const
  {
    return max_links_;
  }

  bool
  persist_enabled() const
  {
    return persist_enabled_;
  }

  const std::string &
  persist_dir() const
  {
    return persist_dir_;
  }

  int
  header_size_limit() const
  {
    return header_size_limit_;
  }

  bool
  skip_bots() const
  {
    return skip_bots_;
  }

  bool
  navigate_only() const
  {
    return navigate_only_;
  }

  const char *
  debug_header() const
  {
    return debug_header_.empty() ? nullptr : debug_header_.c_str();
  }

  int
  scan_limit() const
  {
    return scan_limit_;
  }

  int
  min_hit_count() const
  {
    return min_hit_count_;
  }

  int
  max_cache_entries() const
  {
    return max_cache_entries_;
  }

  const std::vector<std::string> &
  manual_links() const
  {
    return manual_links_;
  }

  const std::vector<std::string> &
  crossorigin_whitelist() const
  {
    return crossorigin_whitelist_;
  }

  bool is_whitelisted_domain(const std::string &domain) const;
  bool is_preload_domain(const std::string &domain) const;

  const std::vector<std::string> &
  preload_whitelist() const
  {
    return preload_whitelist_;
  }

  int
  persist_throttle() const
  {
    return persist_throttle_;
  }

  int
  hints_ttl() const
  {
    return hints_ttl_;
  }

  int
  stale_evict_after() const
  {
    return stale_evict_after_;
  }

  const std::string &
  purge_header_name() const
  {
    return purge_header_name_;
  }

  const std::string &
  purge_secret() const
  {
    return purge_secret_;
  }

  int
  purge_limit() const
  {
    return purge_limit_;
  }

  int
  purge_cooldown() const
  {
    return purge_cooldown_;
  }

private:
  uint8_t mode_          = MODE_ORIGIN_FORWARD;
  int max_links_         = 10;
  int header_size_limit_ = 3072;
  bool skip_bots_        = true;
  bool navigate_only_    = true;
  std::string debug_header_;
  int scan_limit_        = 32768; // 32KB — covers large <head> sections; scanner also stops at <body>
  int min_hit_count_     = 2;
  int max_cache_entries_ = 10000;
  std::vector<std::string> manual_links_;
  std::vector<std::string> crossorigin_whitelist_;
  std::vector<std::string> preload_whitelist_;
  bool persist_enabled_ = false;
  int persist_throttle_ = 10;
  std::string persist_dir_;
  int hints_ttl_         = 604800; // 1 week default; 0 = disabled; range [0, 31536000]
  int stale_evict_after_ = 0;      // 0 = disabled; range [0, 31536000] seconds
  std::string purge_header_name_;  // empty = purge disabled
  std::string purge_secret_;       // required when purge_header_name_ is set
  int purge_limit_    = 3;         // max purges per window per remap; range [1, 500]
  int purge_cooldown_ = 10;        // window duration in seconds; range [1, 2592000] (1 month)

  bool parse_mode(const char *mode_str);
  static bool match_domain_list(const std::string &domain, const std::vector<std::string> &list);
};
