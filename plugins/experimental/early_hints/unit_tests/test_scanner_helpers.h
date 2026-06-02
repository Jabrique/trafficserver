/** @file
 * Shared helper functions for HtmlScanner unit tests.
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

#include "../html_scanner.h"
#include "../config.h"
#include "../hints_cache.h"
#include <string>
#include <vector>

// Helper to scan a complete HTML string
static inline std::vector<std::string>
scan_html(const std::string &html, int scan_limit = 131072, int max_links = 10)
{
  EarlyHintsConfig config;
  HtmlScanner scanner(scan_limit, max_links, &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  return scanner.get_links();
}

// Helper to scan HTML in small chunks (simulates streaming)
static inline std::vector<std::string>
scan_html_chunked(const std::string &html, int chunk_size, int scan_limit = 131072, int max_links = 10)
{
  EarlyHintsConfig config;
  HtmlScanner scanner(scan_limit, max_links, &config);
  for (size_t i = 0; i < html.size(); i += chunk_size) {
    size_t len = std::min(static_cast<size_t>(chunk_size), html.size() - i);
    scanner.feed(html.c_str() + i, static_cast<int64_t>(len));
  }
  return scanner.get_links();
}

// Helper to scan HTML split at a specific position (simulates chunk boundary)
static inline std::vector<std::string>
scan_html_split(const std::string &html, size_t split_pos, int scan_limit = 131072, int max_links = 10)
{
  EarlyHintsConfig config;
  HtmlScanner scanner(scan_limit, max_links, &config);
  if (split_pos >= html.size()) {
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  } else {
    scanner.feed(html.c_str(), static_cast<int64_t>(split_pos));
    scanner.feed(html.c_str() + split_pos, static_cast<int64_t>(html.size() - split_pos));
  }
  return scanner.get_links();
}

// Helper to scan HTML with a preload-whitelist domain (no-cors mode).
// Use this to test the preload-whitelist code path in build_link_header().
static inline std::vector<std::string>
scan_html_with_preload_domain(const std::string &html, const std::string &preload_domain, int scan_limit = 131072,
                              int max_links = 10)
{
  EarlyHintsConfig config;
  std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com", "--preload-whitelist",
                                    preload_domain.c_str()};
  config.init(static_cast<int>(argv.size()), argv.data());
  HtmlScanner scanner(scan_limit, max_links, &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  return scanner.get_links();
}

// Helper to scan HTML with a crossorigin-whitelist domain (CORS preload mode).
// Use this to test the crossorigin-whitelist code path in build_link_header().
static inline std::vector<std::string>
scan_html_with_crossorigin_domain(const std::string &html, const std::string &cors_domain, int scan_limit = 131072,
                                  int max_links = 10)
{
  EarlyHintsConfig config;
  std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com", "--crossorigin-whitelist",
                                    cors_domain.c_str()};
  config.init(static_cast<int>(argv.size()), argv.data());
  HtmlScanner scanner(scan_limit, max_links, &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  return scanner.get_links();
}
