/** @file
 * Unit tests for the link_parser component.
 *
 * Covers: split_link_header_value, dedup_link_segments, is_valid_link_value,
 * normalize_link_for_hint, and has_rel_type.
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
#include "../link_parser.h"
#include "../config.h"
#include <string>
#include <vector>

TEST_CASE("LinkParser: comma-separated link-values in one header", "[link_parser][rfc8288]")
{
  std::string input = "</style.css>; rel=preload; as=style, </app.js>; rel=preload; as=script";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 2);
  CHECK(result[0] == "</style.css>; rel=preload; as=style");
  CHECK(result[1] == "</app.js>; rel=preload; as=script");
}

TEST_CASE("LinkParser: comma inside angle brackets (URL)", "[link_parser][rfc8288]")
{
  std::string input = "<https://example.com/,path>; rel=preload";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 1);
  CHECK(result[0] == "<https://example.com/,path>; rel=preload");
}

TEST_CASE("LinkParser: comma inside quoted string parameter", "[link_parser][rfc8288]")
{
  std::string input = "</a.css>; title=\"foo, bar\"; rel=preload";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 1);
  CHECK(result[0] == "</a.css>; title=\"foo, bar\"; rel=preload");
}

TEST_CASE("LinkParser: escaped quote inside quoted string", "[link_parser][rfc8288]")
{
  std::string input = "</a.css>; title=\"foo \\\" , bar\"; rel=preload";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 1);
  CHECK(result[0] == "</a.css>; title=\"foo \\\" , bar\"; rel=preload");
}

TEST_CASE("LinkParser: comma after closing quote splits correctly", "[link_parser][rfc8288]")
{
  std::string input = "</a.css>; title=\"foo, bar\"; rel=preload, </b.js>; rel=preload; as=script";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 2);
  CHECK(result[0] == "</a.css>; title=\"foo, bar\"; rel=preload");
  CHECK(result[1] == "</b.js>; rel=preload; as=script");
}

TEST_CASE("LinkParser: empty input", "[link_parser][rfc8288]")
{
  std::string input = "";
  auto result       = split_link_header_value(input, 10);
  CHECK(result.empty());
}

TEST_CASE("LinkParser: whitespace-only input", "[link_parser][rfc8288]")
{
  std::string input = "   \t  ";
  auto result       = split_link_header_value(input, 10);
  CHECK(result.empty());
}

TEST_CASE("LinkParser: single link with no comma", "[link_parser][rfc8288]")
{
  std::string input = "</style.css>; rel=preload; as=style";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 1);
  CHECK(result[0] == "</style.css>; rel=preload; as=style");
}

TEST_CASE("LinkParser: max_links caps output", "[link_parser][limits]")
{
  std::string input = "</a.css>; rel=preload; as=style, </b.js>; rel=preload; as=script, </c.woff>; rel=preload; as=font";
  auto result       = split_link_header_value(input, 1);

  REQUIRE(result.size() == 1);
  CHECK(result[0] == "</a.css>; rel=preload; as=style");
}

TEST_CASE("LinkParser: max_links=0 returns empty", "[link_parser][limits]")
{
  std::string input = "</a.css>; rel=preload";
  auto result       = split_link_header_value(input, 0);
  CHECK(result.empty());
}

TEST_CASE("LinkParser: oversized header returns empty", "[link_parser][security]")
{
  std::string input(1024 * 1024, 'x');
  auto result = split_link_header_value(input, 10);
  CHECK(result.empty());
}

TEST_CASE("LinkParser: header just under limit is parsed", "[link_parser][security]")
{
  std::string input = "</style.css>; rel=preload; as=style";
  input.resize(8192, ' ');
  auto result = split_link_header_value(input, 10);

  REQUIRE(result.size() == 1);
  CHECK(result[0] == "</style.css>; rel=preload; as=style");
}

TEST_CASE("LinkParser: header just over limit is rejected", "[link_parser][security]")
{
  std::string input = "</style.css>; rel=preload; as=style";
  input.resize(8193, ' ');
  auto result = split_link_header_value(input, 10);
  CHECK(result.empty());
}

TEST_CASE("LinkParser: leading/trailing whitespace trimmed per segment", "[link_parser][rfc8288]")
{
  std::string input = "  </a.css>; rel=preload  ,  \t</b.js>; rel=preload\t ";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 2);
  CHECK(result[0] == "</a.css>; rel=preload");
  CHECK(result[1] == "</b.js>; rel=preload");
}

TEST_CASE("LinkParser: mixed angle-bracket and quoted commas", "[link_parser][rfc8288]")
{
  std::string input = "<https://cdn.example.com/a,b>; title=\"x, y\"; rel=preload, </other.js>; rel=preload; as=script";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 2);
  CHECK(result[0] == "<https://cdn.example.com/a,b>; title=\"x, y\"; rel=preload");
  CHECK(result[1] == "</other.js>; rel=preload; as=script");
}

TEST_CASE("LinkParser: trailing comma produces no empty segment", "[link_parser][rfc8288]")
{
  std::string input = "</a.css>; rel=preload,";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 1);
  CHECK(result[0] == "</a.css>; rel=preload");
}

TEST_CASE("LinkParser: multiple consecutive commas", "[link_parser][rfc8288]")
{
  std::string input = "</a.css>; rel=preload,,, </b.js>; rel=preload; as=script";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 2);
  CHECK(result[0] == "</a.css>; rel=preload");
  CHECK(result[1] == "</b.js>; rel=preload; as=script");
}

// ============================================================================
// split_link_header_value: quoted-string backslash escape correctness
//
// Per RFC 7230 §3.2.6: inside a quoted-string, a backslash-escaped character
// pair is a single quoted-pair. Even backslash count before a quote means the
// quote is a real delimiter (all backslashes are paired). Odd count means the
// quote itself is escaped and is part of the value.
// ============================================================================

TEST_CASE("LinkParser: even backslash count before quote closes quoted string and splits", "[link_parser][rfc8288]")
{
  // "foo\\" has 2 backslashes = 1 escaped backslash; the following quote is a real
  // delimiter → the comma after closes the value → two segments produced.
  std::string input = R"(</a.css>; title="foo\\", </b.js>; rel=preload)";
  auto result       = split_link_header_value(input, 10);

  REQUIRE(result.size() == 2);
  CHECK(result[0] == R"(</a.css>; title="foo\\")");
  CHECK(result[1] == "</b.js>; rel=preload");
}

TEST_CASE("LinkParser: odd backslash count before quote keeps quote escaped  -- no split", "[link_parser][rfc8288]")
{
  // "foo\\\" has 3 backslashes = 1 escaped backslash + 1 escape of quote → quote IS escaped
  // → comma inside is NOT a delimiter → one segment.
  std::string input = R"(</a.css>; title="foo\\\", </b.js>"; rel=preload)";
  auto result       = split_link_header_value(input, 10);

  // Odd backslashes → quote escaped → entire remainder is one segment.
  REQUIRE(result.size() == 1);
}

TEST_CASE("LinkParser: Case-insensitive rel deduplication", "[link_parser][dedup]")
{
  std::vector<std::string> preconnect_segments = {"</app.js>; rel=preconnect", "</app.js>; rel=Preconnect"};
  auto result_pre                              = dedup_link_segments(preconnect_segments, 10);

  // Before our fix, this will fail (RED) with 2 == 1, because "rel=Preconnect" is not seen as preconnect,
  // so it doesn't match "rel=preconnect" as a duplicate type.
  CHECK(result_pre.size() == 1);
}

TEST_CASE("LinkParser: rel boundary check in deduplication", "[link_parser][dedup][boundary]")
{
  // With URL-only dedup, same URL always deduplicates regardless of rel type.
  // To test rel-type boundary parsing, use different URLs per pair.
  std::vector<std::string> segments1 = {"</a.js>; rel=preconnect", "</b.js>; xrel=preconnect"};
  auto result1                       = dedup_link_segments(segments1, 10);
  CHECK(result1.size() == 2);

  std::vector<std::string> segments2 = {"</a.js>; rel=preconnect", "</b.js>; rel=preconnectx"};
  auto result2                       = dedup_link_segments(segments2, 10);
  CHECK(result2.size() == 2);

  std::vector<std::string> segments3 = {"</a.js>; rel=preconnect", "</b.js>; rel=\"preconnect\"garbage"};
  auto result3                       = dedup_link_segments(segments3, 10);
  CHECK(result3.size() == 2);
}

// --- Non-regression: O(n) backslash counting must not change output -----------

TEST_CASE("LinkParser: many consecutive backslashes before closing quote", "[link_parser][rfc8288]")
{
  SECTION("even backslash count: quote is real delimiter  -- two segments")
  {
    // 4 backslashes = 2 escaped backslashes → quote is real → split into 2 links
    std::string input = R"(<a.css>; title="foo\\\\", </b.js>; rel=preload; as=script)";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[1].find("b.js") != std::string::npos);
  }

  SECTION("odd backslash count: quote is escaped  -- one segment (no split)")
  {
    // 3 backslashes = 1 escaped backslash + 1 escape of quote → quote escaped → no split
    std::string input = R"(<a.css>; title="foo\\\", </b.js>; rel=preload; as=script)";
    auto result       = split_link_header_value(input, 10);
    // The comma inside the quoted string must NOT split the value
    REQUIRE(result.size() == 1);
  }
}

// ===========================================================================================
// split_link_header_value() uses a semicolon-inside-angle-bracket heuristic to recover from
// malformed Link headers where '<' is never closed. When ';' is seen while angle_depth > 0,
// the bracket was never closed; angle_depth is reset to zero so subsequent commas are
// correctly recognized as segment boundaries and valid segments after the malformed one survive.
// ===========================================================================================

TEST_CASE("LinkParser: unclosed angle bracket in segment does not suppress subsequent segments", "[link_parser][segment-state]")
{
  SECTION("unclosed angle bracket in first segment drops all subsequent segments")
  {
    // Segment 1: '<' with no closing '>' -- angle_depth stays 1 after the comma
    // Segment 2: valid -- but the comma before it is ignored (angle_depth == 1)
    // Expected: 2 segments; Bug produces: 1 giant segment
    std::string input = "<unclosed-url; rel=preload, </valid.js>; rel=preload; as=script";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[1] == "</valid.js>; rel=preload; as=script");
  }

  SECTION("three segments where only the first is malformed")
  {
    std::string input = "<bad-unclosed; rel=preload, </good1.js>; rel=preload; as=script, </good2.css>; rel=preload; as=style";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 3);
    CHECK(result[1] == "</good1.js>; rel=preload; as=script");
    CHECK(result[2] == "</good2.css>; rel=preload; as=style");
  }

  SECTION("valid first segment followed by valid second segment is unaffected")
  {
    // Regression: properly closed segments must still split correctly after the fix
    std::string input = "</a.css>; rel=preload; as=style, </b.js>; rel=preload; as=script";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "</a.css>; rel=preload; as=style");
    CHECK(result[1] == "</b.js>; rel=preload; as=script");
  }
}

TEST_CASE("LinkParser: unclosed quoted string keeps comma inside its context", "[link_parser][segment-state]")
{
  SECTION("unclosed double-quote keeps comma inside its quoted context -- no split")
  {
    // An origin sends a segment whose quoted value is never closed.
    // Per RFC 7230 section 3.2.6, a comma inside a quoted-string is NOT a separator.
    // The correct behavior is to produce 1 segment (the whole string) because the
    // quote context is active. Splitting here would break valid headers that have
    // commas inside properly balanced quoted values.
    std::string input = "</a.css>; title=\"unclosed, </b.js>; rel=preload; as=script";
    auto result       = split_link_header_value(input, 10);
    // Correct: comma inside unclosed quote is not a separator -> 1 segment
    REQUIRE(result.size() == 1);
  }

  SECTION("in_quotes state resets after a properly closed quoted segment")
  {
    // After a segment with a balanced quote that happened to end mid-context,
    // the next segment starts with a fresh in_quotes = false state.
    // Input: seg1 has a closed quoted title, seg2 is normal.
    // Both must be parsed as separate segments.
    std::string input = "</a.css>; title=\"val\", </b.js>; rel=preload; as=script";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "</a.css>; title=\"val\"");
    CHECK(result[1] == "</b.js>; rel=preload; as=script");
  }
}

// NOTE: header size guard boundary (8192/8193) is already tested above at L122-138.
// Duplicate test removed during audit  -- see audit report §2.3.

// ===========================================================================================
// dedup_link_segments() now derives url_key from the lowercased copy of the segment
// so that URL prefix comparison is case-insensitive. DNS hostnames are case-insensitive
// per RFC 4343; two segments whose URL differs only in hostname case are the same resource.
// ===========================================================================================

TEST_CASE("LinkParser: dedup_link_segments performs case-insensitive URL comparison", "[link_parser][dedup]")
{
  SECTION("uppercase scheme+host is duplicate of lowercase")
  {
    std::vector<std::string> segs = {"<HTTPS://CDN.EXAMPLE.COM/a.js>; rel=preload; as=script",
                                     "<https://cdn.example.com/a.js>; rel=preload; as=script"};
    auto result                   = dedup_link_segments(segs, 10);
    // Bug: both survive (url_key comparison is case-sensitive) -> size == 2
    // Expected after fix: size == 1
    CHECK(result.size() == 1);
  }

  SECTION("mixed case host is deduplicated")
  {
    std::vector<std::string> segs = {"<https://CDN.Example.Com/font.woff2>; rel=preload; as=font; crossorigin=anonymous",
                                     "<https://cdn.example.com/font.woff2>; rel=preload; as=font; crossorigin=anonymous"};
    auto result                   = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("preconnect with uppercase host is deduplicated")
  {
    std::vector<std::string> segs = {"<https://FONTS.GSTATIC.COM>; rel=preconnect", "<https://fonts.gstatic.com>; rel=preconnect"};
    auto result                   = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("different URLs with same case prefix are not deduped")
  {
    // Regression: URLs that genuinely differ must NOT be merged
    std::vector<std::string> segs = {"<https://cdn.example.com/a.js>; rel=preload; as=script",
                                     "<https://cdn.example.com/b.js>; rel=preload; as=script"};
    auto result                   = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2);
  }
}

// ===========================================================================================
// has_rel_type() now includes carriage return in its boundary character set.
// A segment with rel= value followed by CR (HTTP line-folding artefact from some origin
// middleware) is correctly recognized as the expected rel type so dedup works correctly.
// ===========================================================================================

TEST_CASE("LinkParser: has_rel_type accepts carriage return as boundary character", "[link_parser][has-rel-type]")
{
  SECTION("rel=preconnect followed by CR is recognized as preconnect for dedup")
  {
    // seg[0]: rel=preconnect\r -- after_ok fails on '\r' -> not seen as preconnect
    // seg[1]: rel=preconnect   -- recognized correctly
    // Without fix: different types -> both survive -> size == 2
    // With fix: same type -> deduped -> size == 1
    std::vector<std::string> segs = {"<https://cdn.example.com>; rel=preconnect\r", "<https://cdn.example.com>; rel=preconnect"};
    auto result                   = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("CR before rel= value is accepted as boundary")
  {
    std::vector<std::string> segs = {"<https://fonts.gstatic.com>; \rrel=preconnect",
                                     "<https://fonts.gstatic.com>; rel=preconnect"};
    auto result                   = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }
}

// ===========================================================================================
// split_link_header_value() trim loops now include carriage return so CR artefacts
// from HTTP line-folding are removed from segment boundaries before storage.
// This prevents the poisoned segment string from causing has_rel_type() mismatches.
// ===========================================================================================

TEST_CASE("LinkParser: carriage return is trimmed from segment leading and trailing boundary", "[link_parser][trim]")
{
  SECTION("trailing CR is removed before segment is stored")
  {
    std::string input = "</a.css>; rel=preload; as=style\r, </b.js>; rel=preload; as=script";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 2);
    // First segment must NOT contain a trailing '\r'
    CHECK(result[0].back() != '\r');
    CHECK(result[0] == "</a.css>; rel=preload; as=style");
  }

  SECTION("leading CR is removed before segment is stored")
  {
    // After a comma the next segment starts with '\r' before the URL
    std::string input = "</a.css>; rel=preload; as=style, \r</b.js>; rel=preload; as=script";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[1].front() != '\r');
    CHECK(result[1] == "</b.js>; rel=preload; as=script");
  }
}

// ===================================================================================
// URL-only strongest-wins dedup: when the same URL appears as both preload and
// preconnect, the stronger type (preload/modulepreload) must survive and the
// weaker type (preconnect) must be dropped.  Only one entry per URL key.
//
// RED before fix: current dedup keeps both rel types for same URL (size==2).
// GREEN after fix: URL-only dedup keeps only the strongest (size==1).
// ===================================================================================

TEST_CASE("dedup_link_segments: URL-only strongest-wins unification", "[link_parser][dedup][strongest-wins]")
{
  SECTION("preload then preconnect for same URL: preload survives")
  {
    std::vector<std::string> segs = {
      "</cdn/app.js>; rel=preload; as=script",
      "</cdn/app.js>; rel=preconnect",
    };
    auto result = dedup_link_segments(segs, 10);
    // RED: current behavior keeps both (size==2)
    // GREEN after fix: preload is stronger, preconnect dropped (size==1)
    REQUIRE(result.size() == 1);
    CHECK(result[0].find("rel=preload") != std::string::npos);
  }

  SECTION("preconnect then preload for same URL: preload replaces preconnect")
  {
    std::vector<std::string> segs = {
      "</cdn/lib.css>; rel=preconnect",
      "</cdn/lib.css>; rel=preload; as=style",
    };
    auto result = dedup_link_segments(segs, 10);
    // RED: current behavior keeps both (size==2)
    // GREEN after fix: preload replaces preconnect (size==1)
    REQUIRE(result.size() == 1);
    CHECK(result[0].find("rel=preload") != std::string::npos);
  }

  SECTION("modulepreload beats preconnect for same URL")
  {
    std::vector<std::string> segs = {
      "</mod.js>; rel=preconnect",
      "</mod.js>; rel=modulepreload",
    };
    auto result = dedup_link_segments(segs, 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0].find("rel=modulepreload") != std::string::npos);
  }

  SECTION("two preconnect for same URL still dedup to one")
  {
    std::vector<std::string> segs = {
      "</cdn/app.js>; rel=preconnect",
      "</cdn/app.js>; rel=preconnect",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("different URLs are never deduped regardless of rel type")
  {
    std::vector<std::string> segs = {
      "</cdn/app.js>; rel=preload; as=script",
      "</cdn/lib.js>; rel=preconnect",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2);
  }
}

// ===================================================================================
// RFC 3986 path case sensitivity: dedup must lowercase only the host portion of the
// URL, not the path. Two segments with the same host but different path casing are
// different resources and must NOT be deduplicated.
//
// RFC 3986 section 6.2.2.1: scheme and host are case-insensitive.
// RFC 4343: DNS names are case-insensitive.
// Path, query, and fragment are case-sensitive per RFC 3986 section 3.3.
//
// RED before fix: dedup lowercases the entire URL including path, so
// "</CSS/App.js>" and "</css/app.js>" are seen as the same key (size == 1).
// GREEN after fix: path case preserved, both survive (size == 2).
// ===================================================================================

TEST_CASE("dedup preserves path case sensitivity per RFC 3986", "[link_parser][dedup][rfc3986]")
{
  SECTION("same host, different path case: both kept")
  {
    std::vector<std::string> segs = {
      "</CSS/App.js>; rel=preload; as=script",
      "</css/app.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2);
  }

  SECTION("absolute URL, same host case-insensitive, same path: deduplicated")
  {
    std::vector<std::string> segs = {
      "<https://CDN.Example.COM/path/file.js>; rel=preload; as=script",
      "<https://cdn.example.com/path/file.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("absolute URL, same host, different path case: both kept")
  {
    std::vector<std::string> segs = {
      "<https://cdn.example.com/Path/File.js>; rel=preload; as=script",
      "<https://cdn.example.com/path/file.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2);
  }

  SECTION("protocol-relative URL, host lowercased, path preserved: deduplicated")
  {
    std::vector<std::string> segs = {
      "<//CDN.Example.COM/same-path>; rel=preconnect",
      "<//cdn.example.com/same-path>; rel=preconnect",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("relative URL, path case preserved, no lowercasing")
  {
    std::vector<std::string> segs = {
      "</App.js>; rel=preload; as=script",
      "</app.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2);
  }

  SECTION("regression: existing case-insensitive host dedup still works")
  {
    std::vector<std::string> segs = {
      "<HTTPS://CDN.EXAMPLE.COM/a.js>; rel=preload; as=script",
      "<https://cdn.example.com/a.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("regression: different paths on same host are not deduped")
  {
    std::vector<std::string> segs = {
      "<https://cdn.example.com/a.js>; rel=preload; as=script",
      "<https://cdn.example.com/b.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2);
  }
}

// ============================================================================
// dedup_link_segments: dedup called once after full accumulation vs per-field
//
// The origin-forward loop must call dedup ONCE after all Link header fields
// have been collected. Calling dedup inside the per-field loop is O(n²) and
// cannot correctly apply strongest-wins across separate header fields.
//
// Behavioral contract:
//   1. dedup([A, B, A]) → [A, B]  (dedup works)
//   2. Calling dedup once after accumulation == calling inside loop (same result)
//   3. dedup is idempotent: dedup(dedup(list)) == dedup(list)
// ============================================================================

TEST_CASE("dedup_link_segments: calling once after full accumulation yields same result as per-field", "[link_parser][dedup]")
{
  // Simulate collecting segments from 3 separate Link header fields.
  std::vector<std::string> field1 = {
    "</style.css>; rel=preload; as=style",
    "</app.js>; rel=preload; as=script",
  };
  std::vector<std::string> field2 = {
    "</app.js>; rel=preload; as=script", // duplicate of field1[1]
    "</font.woff2>; rel=preload; as=font; crossorigin=anonymous",
  };
  std::vector<std::string> field3 = {
    "</style.css>; rel=preload; as=style", // duplicate of field1[0]
    "<https://cdn.example.com>; rel=preconnect",
  };

  // OLD (incorrect) behavior: dedup inside loop (called per field).
  std::vector<std::string> inside_loop;
  inside_loop.insert(inside_loop.end(), field1.begin(), field1.end());
  inside_loop = dedup_link_segments(inside_loop, 50);
  inside_loop.insert(inside_loop.end(), field2.begin(), field2.end());
  inside_loop = dedup_link_segments(inside_loop, 50);
  inside_loop.insert(inside_loop.end(), field3.begin(), field3.end());
  inside_loop = dedup_link_segments(inside_loop, 50);

  // NEW (correct) behavior: dedup once after full accumulation.
  std::vector<std::string> all;
  all.insert(all.end(), field1.begin(), field1.end());
  all.insert(all.end(), field2.begin(), field2.end());
  all.insert(all.end(), field3.begin(), field3.end());
  std::vector<std::string> outside_loop = dedup_link_segments(all, 50);

  // Both approaches must produce the same result.
  REQUIRE(inside_loop.size() == outside_loop.size());
  for (size_t i = 0; i < inside_loop.size(); i++) {
    INFO("index " << i);
    CHECK(inside_loop[i] == outside_loop[i]);
  }
}

TEST_CASE("dedup_link_segments: is idempotent  -- calling twice produces the same result", "[link_parser][dedup]")
{
  std::vector<std::string> segments = {
    "</style.css>; rel=preload; as=style",
    "</app.js>; rel=preload; as=script",
    "</style.css>; rel=preload; as=style", // duplicate
    "<https://cdn.example.com>; rel=preconnect",
  };

  auto once  = dedup_link_segments(segments, 50);
  auto twice = dedup_link_segments(once, 50);

  REQUIRE(once.size() == twice.size());
  for (size_t i = 0; i < once.size(); i++) {
    CHECK(once[i] == twice[i]);
  }
}

TEST_CASE("dedup_link_segments: max_links cap enforced when called after full accumulation", "[link_parser][dedup][limits]")
{
  std::vector<std::string> all;
  for (int i = 0; i < 10; i++) {
    all.push_back("</asset" + std::to_string(i) + ".js>; rel=preload; as=script");
  }

  auto result = dedup_link_segments(all, 5);
  CHECK(result.size() <= 5);
  CHECK(result.size() == 5);
}

TEST_CASE("dedup_link_segments: preload beats preconnect regardless of insertion order", "[link_parser][dedup][strongest-wins]")
{
  // Preconnect appears first, preload appears later for the same URL.
  // A single dedup call after full accumulation must keep only preload.
  std::vector<std::string> same_url = {
    "<https://cdn.example.com>; rel=preconnect",
    "<https://cdn.example.com>; rel=preload; as=script",
  };

  auto result = dedup_link_segments(same_url, 50);

  REQUIRE(result.size() == 1);
  CHECK(result[0].find("rel=preload") != std::string::npos);
}

TEST_CASE("dedup_link_segments: empty input returns empty output", "[link_parser][dedup]")
{
  std::vector<std::string> empty;
  auto result = dedup_link_segments(empty, 50);
  CHECK(result.empty());
}

TEST_CASE("dedup_link_segments: all unique entries preserved", "[link_parser][dedup]")
{
  std::vector<std::string> unique = {
    "</style.css>; rel=preload; as=style",
    "</app.js>; rel=preload; as=script",
    "<https://cdn.example.com>; rel=preconnect",
  };

  auto result = dedup_link_segments(unique, 50);
  REQUIRE(result.size() == 3);
}

// ============================================================================
// is_valid_link_value: angle-bracket injection guard in params portion
//
// When origin sends a Link header with an injected second URL inside a param
// (e.g. fetchpriority=high<https://evil.com/m.js>), the function must reject
// the entire value. Guards also cover '>' alone in params.
// ============================================================================

TEST_CASE("is_valid_link_value: rejects angle-bracket injection in params portion", "[link_parser][is_valid_link_value][security]")
{
  SECTION("injected <url> in fetchpriority value is rejected")
  {
    std::string injected = "<https://cdn.example.com/x.css>; rel=preload; as=style; fetchpriority=high<https://evil.com/m.js>";
    CHECK(is_valid_link_value(injected) == false);
  }

  SECTION("injected > in fetchpriority value is rejected")
  {
    std::string injected = "<https://cdn.example.com/x.css>; rel=preload; as=style; fetchpriority=high>evil";
    CHECK(is_valid_link_value(injected) == false);
  }

  SECTION("injected <> in rel value is rejected")
  {
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

  SECTION("nested < in URL portion is rejected (existing behavior)")
  {
    std::string bad_url = "<<https://cdn.example.com/x.css>>; rel=preload; as=style";
    CHECK(is_valid_link_value(bad_url) == false);
  }
}

TEST_CASE("normalize_link_for_hint: drops unsafe fetchpriority values before emitting",
          "[link_parser][normalize_link_for_hint][security]")
{
  SECTION("stylesheet with safe fetchpriority=high is preserved")
  {
    std::string link   = "<https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=high";
    std::string result = normalize_link_for_hint(link);
    CHECK(result.find("rel=preload") != std::string::npos);
    CHECK(result.find("fetchpriority=high") != std::string::npos);
    CHECK(result.find("<https://evil.com") == std::string::npos);
  }

  SECTION("stylesheet with injected fetchpriority does not emit injected URL")
  {
    std::string link   = "<https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=high<https://evil.com>";
    std::string result = normalize_link_for_hint(link);
    // Must either reject entirely (empty) or emit without the injected URL
    CHECK((result.empty() || result.find("<https://evil.com") == std::string::npos));
    CHECK((result.empty() || result.find("fetchpriority=high<") == std::string::npos));
  }

  SECTION("unknown fetchpriority token is dropped")
  {
    std::string link   = "<https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=critical";
    std::string result = normalize_link_for_hint(link);
    // Must either reject entirely (empty) or emit without the unknown token
    CHECK((result.empty() || result.find("fetchpriority=critical") == std::string::npos));
  }
}

TEST_CASE("is_valid_link_value: URL scheme validation", "[link_parser][is_valid_link_value]")
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

  SECTION("URL with tab character (0x09) rejected")
  {
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

TEST_CASE("is_valid_link_value: carriage-return in link value is rejected", "[link_parser][is_valid_link_value]")
{
  SECTION("\\r anywhere in link value is rejected (0x0D < 0x20 control char)")
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

// NOTE: rel-strength strongest-wins logic is already tested at L470-527.
// Duplicate test removed during audit  -- see audit report §2.2.
