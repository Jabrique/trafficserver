/** @file
 * Unit tests for link-header security and correctness fixes:
 *   - angle-bracket injection guard in is_valid_link_value params portion
 *   - fetchpriority allowlist in normalize_link_for_hint
 *   - scheme_start removal (dead code) in is_valid_link_value
 *   - scheme_sep double-find refactor in html_scanner (behavioral coverage via config)
 *   - carriage-return word boundary parity between check_rel and has_rel_type
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
#include "../config.h"
#include "../link_parser.h"
#include <string>
#include <vector>

// ============================================================================
// Angle-bracket injection via params portion of a Link header value
//
// Root cause: carry_param extracts the value up to the next ';' or end-of-string.
// If origin sends:
//   <https://cdn.example.com/x.css>; rel=stylesheet; fetchpriority=high<https://evil.com/m.js>
// carry_param("fetchpriority") extracts "high<https://evil.com/m.js>" verbatim.
// is_valid_link_value() previously only scanned < > inside the URL portion.
//
// Guard A: is_valid_link_value() now rejects < > anywhere in the params portion.
// Guard B: normalize_link_for_hint allowlists fetchpriority to {high, low, auto}.
// ============================================================================

TEST_CASE("is_valid_link_value: rejects angle-bracket in params portion", "[is_valid_link_value][injection]")
{
  SECTION("injected < > in fetchpriority value is rejected")
  {
    // Origin-injected: fetchpriority value contains a second <url>
    std::string injected = "<https://cdn.example.com/x.css>; rel=preload; as=style; fetchpriority=high<https://evil.com/m.js>";
    CHECK(is_valid_link_value(injected) == false);
  }

  SECTION("injected > in fetchpriority value is rejected")
  {
    std::string injected = "<https://cdn.example.com/x.css>; rel=preload; as=style; fetchpriority=high>evil";
    CHECK(is_valid_link_value(injected) == false);
  }

  SECTION("injected < > in rel value is rejected")
  {
    // < in params rel portion
    std::string injected = "<https://cdn.example.com/x.css>; rel=preload<evil>; as=style";
    CHECK(is_valid_link_value(injected) == false);
  }

  SECTION("clean fetchpriority=high is accepted")
  {
    std::string clean = "<https://cdn.example.com/x.css>; rel=preload; as=style; fetchpriority=high";
    CHECK(is_valid_link_value(clean) == true);
  }

  SECTION("clean fetchpriority=low is accepted")
  {
    std::string clean = "<https://cdn.example.com/x.css>; rel=preload; as=style; fetchpriority=low";
    CHECK(is_valid_link_value(clean) == true);
  }

  SECTION("clean fetchpriority=auto is accepted")
  {
    std::string clean = "<https://cdn.example.com/x.css>; rel=preload; as=style; fetchpriority=auto";
    CHECK(is_valid_link_value(clean) == true);
  }

  SECTION("link without fetchpriority is unaffected")
  {
    std::string clean = "<https://cdn.example.com/x.css>; rel=preload; as=style";
    CHECK(is_valid_link_value(clean) == true);
  }

  SECTION("< > in URL portion itself is still rejected")
  {
    // Existing behavior: nested < inside URL portion is already rejected
    std::string bad_url = "<<https://cdn.example.com/x.css>>; rel=preload; as=style";
    CHECK(is_valid_link_value(bad_url) == false);
  }
}

TEST_CASE("normalize_link_for_hint: drops unsafe fetchpriority before emitting", "[normalize_link_for_hint][injection]")
{
  // Guard B: allowlist in normalize_link_for_hint drops unknown fetchpriority values.

  SECTION("stylesheet with safe fetchpriority=high preserved")
  {
    std::string link   = "<https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=high";
    std::string result = normalize_link_for_hint(link);
    CHECK(result.find("rel=preload") != std::string::npos);
    CHECK(result.find("fetchpriority=high") != std::string::npos);
    CHECK(result.find("<https://evil.com") == std::string::npos);
  }

  SECTION("stylesheet with injected fetchpriority dropped")
  {
    // Even if called with an already-constructed malicious value,
    // the allowlist drops the unsafe fetchpriority token.
    std::string link   = "<https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=high<https://evil.com>";
    std::string result = normalize_link_for_hint(link);
    // Either: empty result (rejected at is_valid_link_value level)
    // Or: result without the injected URL
    if (!result.empty()) {
      CHECK(result.find("<https://evil.com") == std::string::npos);
      CHECK(result.find("fetchpriority=high<") == std::string::npos);
    }
  }

  SECTION("stylesheet with unknown fetchpriority token dropped")
  {
    std::string link   = "<https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=critical";
    std::string result = normalize_link_for_hint(link);
    // Must not emit unknown fetchpriority token
    if (!result.empty()) {
      CHECK(result.find("fetchpriority=critical") == std::string::npos);
    }
  }
}

// ============================================================================
// is_valid_link_value: URL scheme and format validation
//
// These tests verify the function accepts and rejects the same inputs after
// the scheme_start dead-code removal. scheme_start was always 0 because:
//   - tab (0x09) is rejected by the control-char loop before scheme_start
//   - space (0x20) inside url_part is rejected by the space-in-URL check
// Observable behavior is unchanged; only the dead indirection was removed.
// ============================================================================

TEST_CASE("is_valid_link_value: URL scheme validation", "[is_valid_link_value][regression]")
{
  SECTION("standard https URL accepted")
  {
    CHECK(is_valid_link_value("<https://cdn.example.com/app.js>; rel=preload; as=script") == true);
  }

  SECTION("standard http URL accepted")
  {
    CHECK(is_valid_link_value("<http://cdn.example.com/app.js>; rel=preload; as=script") == true);
  }

  SECTION("relative URL accepted") { CHECK(is_valid_link_value("</app.js>; rel=preload; as=script") == true); }

  SECTION("URL with tab (0x09) rejected")
  {
    // Tab anywhere in the link is rejected by control-char loop
    std::string with_tab = "<https://cdn.example.com/\tapp.js>; rel=preload; as=script";
    CHECK(is_valid_link_value(with_tab) == false);
  }

  SECTION("URL with space in URL portion rejected")
  {
    std::string with_space = "<https://cdn.example.com/my file.js>; rel=preload; as=script";
    CHECK(is_valid_link_value(with_space) == false);
  }

  SECTION("ftp:// scheme rejected") { CHECK(is_valid_link_value("<ftp://cdn.example.com/file>; rel=preload; as=fetch") == false); }

  SECTION("file:// scheme rejected") { CHECK(is_valid_link_value("<file:///etc/passwd>; rel=preload; as=fetch") == false); }

  SECTION("http without :// rejected")
  {
    CHECK(is_valid_link_value("<http:\\cdn.example.com/app.js>; rel=preload; as=script") == false);
  }

  SECTION("backslash authority reference rejected")
  {
    CHECK(is_valid_link_value("<\\\\evil.com/x.js>; rel=preload; as=script") == false);
  }
}

// ============================================================================
// Carriage-return word-boundary parity
//
// link_parser.cc includes '\r' as a valid token boundary in has_rel_type().
// check_rel in config.cc previously did not include '\r'.
// In practice '\r' (0x0D < 0x20) is rejected earlier by the control-char
// loop, so there is no runtime difference. The fix adds '\r' to check_rel
// so both boundary checkers agree on what constitutes a token boundary.
//
// Tests verify:
//   1. Links containing \r are rejected by is_valid_link_value (pre-existing).
//   2. dedup_link_segments (which uses has_rel_type) correctly classifies
//      preload vs preconnect -- behavior is unchanged after the fix.
// ============================================================================

TEST_CASE("is_valid_link_value: carriage-return in link value is rejected", "[is_valid_link_value][regression]")
{
  SECTION("\\r anywhere in link value is rejected (0x0D < 0x20)")
  {
    std::string with_cr = "<https://cdn.example.com/app.js>; rel=preload\r; as=script";
    CHECK(is_valid_link_value(with_cr) == false);
  }

  SECTION("\\r before rel= is rejected")
  {
    std::string with_cr = "<https://cdn.example.com/app.js>;\r rel=preload; as=script";
    CHECK(is_valid_link_value(with_cr) == false);
  }

  SECTION("valid link without \\r is unaffected")
  {
    CHECK(is_valid_link_value("<https://cdn.example.com/app.js>; rel=preload; as=script") == true);
  }
}

TEST_CASE("dedup_link_segments: rel-strength logic is correct", "[link_parser][regression]")
{
  // dedup_link_segments uses has_rel_type internally for preload vs preconnect.
  // Strongest-wins must be unaffected for normal (non-CR) inputs.
  SECTION("preload beats preconnect for same URL")
  {
    std::vector<std::string> segs = {
      "<https://cdn.example.com>; rel=preconnect",
      "<https://cdn.example.com>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 50);
    REQUIRE(result.size() == 1);
    CHECK(result[0].find("rel=preload") != std::string::npos);
  }

  SECTION("preconnect kept when no stronger entry exists")
  {
    std::vector<std::string> segs = {
      "<https://cdn.example.com>; rel=preconnect",
    };
    auto result = dedup_link_segments(segs, 50);
    REQUIRE(result.size() == 1);
    CHECK(result[0].find("rel=preconnect") != std::string::npos);
  }
}
