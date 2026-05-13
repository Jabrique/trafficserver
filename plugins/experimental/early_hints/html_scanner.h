/** @file
 * Streaming HTML <head> scanner for auto-learning preloadable resources.
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

class EarlyHintsConfig;

class HtmlScanner
{
public:
  HtmlScanner(int scan_limit, int max_links, const EarlyHintsConfig *config);
  ~HtmlScanner() = default;

  /** Feed data chunk (streaming — called multiple times from transform). */
  void feed(const char *data, int64_t length);

  /** Check if scanning is complete (found </head> or limit reached). */
  bool
  is_done() const
  {
    return state_ == State::DONE;
  }

  /** Get discovered Link header values. */
  const std::vector<std::string> &
  get_links() const
  {
    return links_;
  }

  /** Reset for reuse. */
  void reset();

  // ── Public static helpers (exposed for direct unit testing — RFC 3986 compliance) ──
  //
  // extract_origin() and is_crossorigin() are placed in the public section so that
  // unit tests can call them directly without going through the full HTML scanning path.
  static std::string extract_origin(const std::string &url);
  static bool is_crossorigin(const std::string &href);

private:
  enum class State : uint8_t {
    INIT,             // Scanning for <head (case-insensitive)
    IN_HEAD,          // Inside <head>, scanning for <link, <script, </head
    IN_TAG,           // Inside a tag name (<link, <script, etc.)
    IN_ATTR_NAME,     // Reading attribute name
    IN_ATTR_SEP,      // After attr name, whitespace before possible '='
    IN_ATTR_VALUE,    // Reading attribute value (handling quotes)
    IN_COMMENT,       // Inside HTML comment (<!-- ... -->)
    IN_BOGUS_COMMENT, // Inside bogus comment (<![CDATA[, <!DOCTYPE, etc.) — skip until >
    IN_SCRIPT,        // Inside <script> body — skip until </script>
    DONE              // Found </head> or exceeded scan_limit
  };

  State state_     = State::INIT;
  int64_t scanned_ = 0;
  int64_t limit_;
  int max_links_;
  const EarlyHintsConfig *config_; // For cross-origin whitelist checks

  static constexpr int MAX_ATTR_VALUE_LEN = 4096;

  // Pattern matching buffer for tag detection
  std::string match_buf_;

  // Current tag being parsed
  std::string tag_name_;
  std::string attr_name_;
  std::string attr_value_;
  char quote_char_     = 0;
  bool in_closing_tag_ = false;
  int comment_dashes_  = 0;   // tracks consecutive '-' for --> detection
  int raw_close_pos_   = 0;   // position in "</tagname>" matching for raw text elements:
                              //   0-N = matching "</tagname" chars
                              //   N   = matched full name, checking separator
                              //   N+1 = confirmed close tag, scanning for '>'
  std::string raw_close_tag_; // e.g. "</script" or "</style" — set by state_after_open_tag()

  // Script data escaped state (HTML spec §13.2.6.2):
  // When <!-- appears inside <script>, the parser enters "escaped" mode.
  // In escaped mode, </script> does NOT close the script.
  // Only --> exits escaped mode, then the next </script> closes normally.
  bool script_escaped_    = false; // true when inside <!-- ... --> within script
  int script_comment_pos_ = 0;     // tracks position in "<!--" or "-->" matching

  // Collected attributes for current tag
  std::string href_;
  std::string rel_;
  std::string as_;
  std::string type_;
  std::string crossorigin_value_;
  std::string fetchpriority_;
  bool has_async_ = false;
  bool has_defer_ = false;

  // Results
  std::vector<std::string> links_;

  void process_tag();
  void build_link_header(const std::string &tag);
  void finish_attr();
  void reset_tag_state();
  State state_after_open_tag();

  static std::string tolower_str(const std::string &s);

  // Sanitize URL: reject control chars, header injection, and non-http(s) schemes
  static bool is_safe_url(const std::string &url);
};
