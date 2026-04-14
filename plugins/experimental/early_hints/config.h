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
  bool persist_enabled_ = true;
  std::string persist_dir_;

  bool parse_mode(const char *mode_str);
  static bool match_domain_list(const std::string &domain, const std::vector<std::string> &list);
};
