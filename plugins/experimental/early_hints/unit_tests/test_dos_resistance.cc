/** @file
 * DoS resistance tests for the early_hints plugin.
 *
 * Tests resource exhaustion and algorithmic complexity attack vectors:
 * 1. CPU exhaustion via millions of <link> tags
 * 2. Memory exhaustion via large link vectors
 * 3. Cache flooding via unique URLs
 * 4. Pathological input causing O(n²) scanner behavior
 * 5. Comment bomb (unclosed <!-- with megabytes of data)
 * 6. Attribute bomb (thousands of attributes on a single tag)
 * 7. Deeply nested HTML tags
 * 8. Slow loris (single-byte chunk feeding)
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
#include "../html_scanner.h"
#include "../hints_cache.h"
#include "../config.h"
#include <string>
#include <vector>
#include <chrono>
#include <cstring>

// --- Helpers -----------------------------------------------------------------

static std::vector<std::string>
dos_scan(const std::string &html, int scan_limit = 131072, int max_links = 10)
{
  EarlyHintsConfig config;
  HtmlScanner scanner(scan_limit, max_links, &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  return scanner.get_links();
}

// Feed data one byte at a time
static std::vector<std::string>
dos_scan_byte_by_byte(const std::string &html, int scan_limit = 131072, int max_links = 10)
{
  EarlyHintsConfig config;
  HtmlScanner scanner(scan_limit, max_links, &config);
  for (size_t i = 0; i < html.size(); i++) {
    scanner.feed(html.c_str() + i, 1);
    if (scanner.is_done()) {
      break;
    }
  }
  return scanner.get_links();
}

// -----------------------------------------------------------------------------
// DoS VECTOR 1: CPU exhaustion  -- millions of <link> tags
// -----------------------------------------------------------------------------
//
// Attack: An attacker sends a response with millions of valid <link> tags
// attempting to keep the scanner busy indefinitely.
//
// Defense: scan_limit caps the total bytes processed. max_links caps the
// number of links extracted. Once either limit is hit, the scanner stops.

TEST_CASE("DoS: CPU exhaustion via mass link tags", "[dos][scanner]")
{
  SECTION("scan_limit stops processing after limit bytes")
  {
    // Build HTML with many link tags that exceeds scan_limit
    const int scan_limit = 1024;
    std::string html     = "<head>";
    // Each link tag is ~70 bytes. 100 tags = ~7000 bytes >> 1024 limit
    for (int i = 0; i < 100; i++) {
      html += "<link rel=\"preload\" href=\"/file" + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, 100, &config);

    auto start = std::chrono::steady_clock::now();
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto elapsed = std::chrono::steady_clock::now() - start;

    // Scanner must have stopped early  -- should NOT have extracted all 100 links
    CHECK(scanner.is_done());
    CHECK(scanner.get_links().size() < 100);
    // Must complete in well under 100ms even on slow hardware
    CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() < 100);
  }

  SECTION("max_links caps extracted links even within scan_limit")
  {
    const int max_links  = 5;
    const int scan_limit = 1000000; // very large limit
    std::string html     = "<head>";
    for (int i = 0; i < 50; i++) {
      html += "<link rel=\"preload\" href=\"/f" + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, max_links, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    // Must not exceed max_links  -- with 50 tags and max_links=5, should extract exactly 5
    CHECK(scanner.get_links().size() == static_cast<size_t>(max_links));
  }

  SECTION("millions of tags bounded by scan_limit time")
  {
    // Simulate attacker payload: 1M link tags (~70 bytes each = 70MB)
    // With default scan_limit=131072, scanner stops after ~128KB
    const int scan_limit = 131072;
    const int max_links  = 10;

    // Build 2000 tags (enough to exceed 131072 bytes)
    std::string html = "<head>";
    for (int i = 0; i < 2000; i++) {
      html += "<link rel=\"preload\" href=\"/resource-with-a-long-path-" + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, max_links, &config);

    auto start = std::chrono::steady_clock::now();
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(scanner.is_done());
    CHECK(scanner.get_links().size() == static_cast<size_t>(max_links));
    // Processing 131KB of data should be well under 1 second
    CHECK(elapsed_ms < 1000);
  }
}

// -----------------------------------------------------------------------------
// DoS VECTOR 2: Memory exhaustion  -- response with many valid preload links
// -----------------------------------------------------------------------------
//
// Attack: HTML with 10,000 valid preload links to balloon links_ vector.
//
// Defense: max_links parameter caps the vector size. build_link_header()
// checks links_.size() >= max_links_ before appending.

TEST_CASE("DoS: Memory exhaustion via link vector growth", "[dos][scanner]")
{
  SECTION("links vector capped at max_links regardless of input")
  {
    // Default max_links=10, scan_limit high enough to parse many tags
    const int max_links  = 10;
    const int scan_limit = 10000000;
    std::string html     = "<head>";
    // 500 valid link tags within scan limit
    for (int i = 0; i < 500; i++) {
      html += "<link rel=\"preload\" href=\"/r" + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, max_links, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    REQUIRE(scanner.get_links().size() == static_cast<size_t>(max_links));
  }

  SECTION("max_links=1 restricts to single link")
  {
    std::string html = "<head>"
                       "<link rel=\"preload\" href=\"/a.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"/b.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"/c.js\" as=\"script\">"
                       "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 1, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.get_links().size() == 1);
    CHECK(scanner.get_links()[0].find("/a.js") != std::string::npos);
  }

  SECTION("links vector does not grow unbounded with large max_links")
  {
    // Even with max_links=10000, the vector is pre-reserved but only fills
    // up to the number of actually parsed valid links (bounded by scan_limit)
    const int max_links  = 10000;
    const int scan_limit = 4096; // small scan limit
    std::string html     = "<head>";
    for (int i = 0; i < 10000; i++) {
      html += "<link rel=\"preload\" href=\"/r" + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, max_links, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    // scan_limit of 4096 bytes limits how many tags get parsed
    // Each tag is ~60 bytes, so at most ~60 links could be extracted
    CHECK(scanner.get_links().size() < 100);
    CHECK(scanner.is_done());
  }
}

// -----------------------------------------------------------------------------
// DoS VECTOR 3: Cache flooding  -- requests to unique URLs
// -----------------------------------------------------------------------------
//
// Attack: Attacker sends requests to /page1, /page2, ..., /page1000000 to
// fill the cache with entries that will never be hit.
//
// Defense: HintsCache enforces max_entries limit. When at capacity, it
// evicts oldest entries first (by last_updated time), then drops new insertions if still full.

TEST_CASE("DoS: Cache flooding with unique URLs", "[dos][cache]")
{
  SECTION("cache respects max_entries limit")
  {
    const int max_entries = 100;
    HintsCache cache(max_entries);
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};

    // Insert 200 unique keys  -- only 100 should be stored
    for (int i = 0; i < 200; i++) {
      cache.put("/page" + std::to_string(i), links);
    }

    CHECK(cache.size() <= static_cast<size_t>(max_entries));
  }

  SECTION("cache does not grow beyond max_entries under sustained flood")
  {
    const int max_entries = 50;
    HintsCache cache(max_entries);
    std::vector<std::string> links = {"</x.js>; rel=preload; as=script"};

    // Simulate sustained flood: 1000 unique URLs
    for (int i = 0; i < 1000; i++) {
      cache.put("/flood/" + std::to_string(i), links);
    }

    CHECK(cache.size() <= static_cast<size_t>(max_entries));
  }

  SECTION("cache eviction works when oldest entries are removed")
  {
    const int max_entries = 10;
    HintsCache cache(max_entries);
    std::vector<std::string> links = {"</x.js>; rel=preload; as=script"};

    // Fill cache completely
    for (int i = 0; i < 10; i++) {
      cache.put("/old" + std::to_string(i), links);
    }
    CHECK(cache.size() == 10);

    // Insert more  -- oldest entries should be evicted to make room
    for (int i = 0; i < 20; i++) {
      cache.put("/new" + std::to_string(i), links);
    }
    CHECK(cache.size() <= static_cast<size_t>(max_entries));
  }

  SECTION("make_key strips query strings to reduce cache key diversity")
  {
    // Attacker tries /page?rand=1, /page?rand=2  -- should all map to same key
    std::string key1 = HintsCache::make_key("/page?rand=1", 12);
    std::string key2 = HintsCache::make_key("/page?rand=2", 12);
    std::string key3 = HintsCache::make_key("/page?rand=99999", 16);

    CHECK(key1 == "/page");
    CHECK(key2 == "/page");
    CHECK(key3 == "/page");
    CHECK(key1 == key2);
  }

  SECTION("make_key handles edge cases without crashing")
  {
    CHECK(HintsCache::make_key(nullptr, 0) == "/");
    CHECK(HintsCache::make_key("", 0) == "/");
    CHECK(HintsCache::make_key("?query", 6) == "/");
    CHECK(HintsCache::make_key("/", 1) == "/");
    CHECK(HintsCache::make_key("/path", 5) == "/path");
  }
}

// -----------------------------------------------------------------------------
// DoS VECTOR 4: Pathological input  -- O(n²) backtracking
// -----------------------------------------------------------------------------
//
// Attack: Craft input that causes the state machine to repeatedly re-scan
// the same data (e.g., repeated partial matches that reset).
//
// Defense: The scanner is a strict byte-by-byte state machine with no
// backtracking. Each byte is processed exactly once → O(n) guaranteed.

TEST_CASE("DoS: Pathological patterns for O(n²) backtracking", "[dos][scanner]")
{
  SECTION("repeated partial <head matches do not cause backtracking")
  {
    // "<hea" repeated 100000 times  -- each time match_buf_ resets
    std::string html;
    for (int i = 0; i < 100000; i++) {
      html += "<hea";
    }
    html += "<head><link rel=\"preload\" href=\"/x.js\" as=\"script\"></head>";

    auto start      = std::chrono::steady_clock::now();
    auto links      = dos_scan(html, static_cast<int>(html.size()), 10);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    // O(n) means ~400KB should process in well under 1 second
    CHECK(elapsed_ms < 1000);
    REQUIRE(links.size() == 1);
  }

  SECTION("repeated <!-- almost-close sequences are O(n)")
  {
    // "<!-- --X --X --X ... -->"  -- each --X resets comment_dashes_
    std::string html = "<head><!-- ";
    for (int i = 0; i < 50000; i++) {
      html += "--X";
    }
    html += "--><link rel=\"preload\" href=\"/y.js\" as=\"script\"></head>";

    auto start      = std::chrono::steady_clock::now();
    auto links      = dos_scan(html, static_cast<int>(html.size()), 10);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(elapsed_ms < 1000);
    REQUIRE(links.size() == 1);
  }

  SECTION("repeated </scrip (near-close) sequences in script are O(n)")
  {
    // Inside <script>, repeated "</scrip" that never fully matches "</script>"
    std::string html = "<head><script>";
    for (int i = 0; i < 50000; i++) {
      html += "</scrip ";
    }
    html += "</script><link rel=\"preload\" href=\"/z.js\" as=\"script\"></head>";

    auto start      = std::chrono::steady_clock::now();
    auto links      = dos_scan(html, static_cast<int>(html.size()), 10);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(elapsed_ms < 1000);
    REQUIRE(links.size() == 1);
  }

  SECTION("alternating < characters do not cause quadratic scan")
  {
    // "<" interspersed with random text  -- each '<' starts match_buf_
    // then next char kills it immediately
    std::string html = "<head>";
    for (int i = 0; i < 100000; i++) {
      html += "<X";
    }
    html += "<link rel=\"preload\" href=\"/w.js\" as=\"script\"></head>";

    auto start      = std::chrono::steady_clock::now();
    auto links      = dos_scan(html, static_cast<int>(html.size()), 10);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(elapsed_ms < 1000);
  }
}

// -----------------------------------------------------------------------------
// DoS VECTOR 5: Comment bomb  -- unclosed <!-- followed by megabytes
// -----------------------------------------------------------------------------
//
// Attack: Send "<!-- " followed by megabytes of padding with no "-->" close.
// The scanner stays in IN_COMMENT state consuming bytes until scan_limit.
//
// Defense: scan_limit causes the scanner to transition to DONE state.

TEST_CASE("DoS: Comment bomb (unclosed comment with large payload)", "[dos][scanner]")
{
  SECTION("unclosed comment stays in comment state until scan_limit")
  {
    const int scan_limit = 8192;
    std::string html     = "<head><!-- ";
    // 1MB of padding data after the comment open
    html.append(1000000, 'A');

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, 10, &config);

    auto start = std::chrono::steady_clock::now();
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(scanner.is_done());
    CHECK(scanner.get_links().empty());
    // Must stop quickly  -- not process all 1MB
    CHECK(elapsed_ms < 500);
  }

  SECTION("comment bomb with embedded dashes does not extract false links")
  {
    const int scan_limit = 16384;
    std::string html     = "<head><!-- ";
    // Embed things that look like link tags inside the comment
    for (int i = 0; i < 1000; i++) {
      html += "<link rel=\"preload\" href=\"/fake" + std::to_string(i) + ".js\" as=\"script\">";
    }
    // Never close the comment

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, 100, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    // No links should be extracted  -- they're all inside a comment
    CHECK(scanner.get_links().empty());
  }

  SECTION("comment bomb with near-close patterns")
  {
    // "<!-- --!--!--!..."  -- exercises comment end bang states repeatedly
    const int scan_limit = 4096;
    std::string html     = "<head><!-- ";
    for (int i = 0; i < 10000; i++) {
      html += "--!";
    }

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, 10, &config);

    auto start = std::chrono::steady_clock::now();
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(scanner.is_done());
    CHECK(elapsed_ms < 500);
  }
}

// -----------------------------------------------------------------------------
// DoS VECTOR 6: Attribute bomb  -- tag with thousands of attributes
// -----------------------------------------------------------------------------
//
// Attack: <link attr1="..." attr2="..." ... attr10000="..." href="..." rel="preload" as="script">
// Each attribute causes finish_attr() to run, and attr_value_ could grow large.
//
// Defense: MAX_ATTR_VALUE_LEN (4096) caps individual attribute values.
// scan_limit caps total bytes processed.

TEST_CASE("DoS: Attribute bomb (thousands of attributes per tag)", "[dos][scanner]")
{
  SECTION("thousands of attributes processed within time bounds")
  {
    std::string html = "<head><link ";
    // 5000 meaningless attributes
    for (int i = 0; i < 5000; i++) {
      html += "data-x" + std::to_string(i) + "=\"val\" ";
    }
    html += "rel=\"preload\" href=\"/target.js\" as=\"script\"></head>";

    auto start      = std::chrono::steady_clock::now();
    auto links      = dos_scan(html, static_cast<int>(html.size()), 10);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    // Should still extract the valid link
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/target.js") != std::string::npos);
    CHECK(elapsed_ms < 2000);
  }

  SECTION("single attribute exceeding MAX_ATTR_VALUE_LEN causes tag rejection")
  {
    // Build a link tag with an href value of 10000 characters.
    // New behavior: the tag is rejected entirely (not truncated and emitted).
    std::string long_path = "/";
    long_path.append(10000, 'A');

    std::string html = "<head><link rel=\"preload\" href=\"" + long_path +
                       "\" as=\"script\"><link rel=\"preload\" href=\"/ok.js\" as=\"script\"></head>";

    auto links = dos_scan(html, static_cast<int>(html.size()), 10);

    // Oversized tag is discarded; the following valid link is still extracted.
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok.js") != std::string::npos);
  }

  SECTION("unquoted oversized href causes tag rejection")
  {
    // Unquoted oversized values also cause rejection.
    std::string long_path = "/";
    long_path.append(10000, 'B');

    std::string html =
      "<head><link rel=preload href=" + long_path + " as=script><link rel=\"preload\" href=\"/ok2.js\" as=\"script\"></head>";

    auto links = dos_scan(html, static_cast<int>(html.size()), 10);

    // Oversized tag rejected; valid following link still extracted
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok2.js") != std::string::npos);
  }

  SECTION("many boolean attributes do not cause issues")
  {
    std::string html = "<head><script ";
    for (int i = 0; i < 3000; i++) {
      html += "data-flag" + std::to_string(i) + " ";
    }
    html += "src=\"/app.js\"></script></head>";

    auto links = dos_scan(html, static_cast<int>(html.size()), 10);

    // Script without async/defer should be extracted
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/app.js") != std::string::npos);
  }
}

// -----------------------------------------------------------------------------
// DoS VECTOR 7: Deeply nested HTML  -- repeated <head> tags
// -----------------------------------------------------------------------------
//
// Attack: <head><head><head>...  -- hundreds of nested opening tags.
// The scanner is not a full parser  -- it doesn't track nesting depth.
//
// Defense: The state machine treats the first <head> as entering IN_HEAD
// state. Subsequent <head> tags are treated as unknown tags inside <head>
// and ignored. </head> always ends scanning.

TEST_CASE("DoS: Deeply nested HTML tags", "[dos][scanner]")
{
  SECTION("nested <head> tags do not confuse the scanner")
  {
    std::string html;
    for (int i = 0; i < 1000; i++) {
      html += "<head>";
    }
    html += "<link rel=\"preload\" href=\"/nested.js\" as=\"script\">";
    for (int i = 0; i < 1000; i++) {
      html += "</head>";
    }

    EarlyHintsConfig config;
    HtmlScanner scanner(static_cast<int>(html.size()), 10, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    // First </head> should end scanning
    CHECK(scanner.is_done());
    // The link is between the innermost <head> and first </head>
    CHECK(scanner.get_links().size() == 1);
  }

  SECTION("deeply nested unknown tags inside <head> are handled")
  {
    std::string html = "<head>";
    for (int i = 0; i < 500; i++) {
      html += "<div><span><p>";
    }
    html += "<link rel=\"preload\" href=\"/deep.js\" as=\"script\">";
    html += "</head>";

    auto links = dos_scan(html, static_cast<int>(html.size()), 10);

    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/deep.js") != std::string::npos);
  }

  SECTION("1000 nested <script> tags")
  {
    // The scanner enters IN_SCRIPT on first <script>, then waits for </script>
    // Nested <script> inside script body are just text
    std::string html = "<head><script>";
    for (int i = 0; i < 1000; i++) {
      html += "<script>";
    }
    html += "</script>";
    html += "<link rel=\"preload\" href=\"/after.js\" as=\"script\">";
    html += "</head>";

    auto links = dos_scan(html, static_cast<int>(html.size()), 10);

    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.js") != std::string::npos);
  }
}

// -----------------------------------------------------------------------------
// DoS VECTOR 8: Slow loris  -- single-byte chunk feeding
// -----------------------------------------------------------------------------
//
// Attack: Feed the scanner one byte at a time to maximize per-call overhead.
//
// Defense: The state machine is designed for streaming. Each feed() call
// simply continues from the current state. O(1) overhead per call beyond
// the byte processing itself.

TEST_CASE("DoS: Slow loris (byte-at-a-time feeding)", "[dos][scanner]")
{
  SECTION("byte-by-byte produces same results as bulk feed")
  {
    std::string html = "<head>"
                       "<link rel=\"preload\" href=\"/a.js\" as=\"script\">"
                       "<link rel=\"stylesheet\" href=\"/b.css\">"
                       "<script src=\"/c.js\"></script>"
                       "</head>";

    auto bulk_links = dos_scan(html);
    auto byte_links = dos_scan_byte_by_byte(html);

    REQUIRE(bulk_links.size() == byte_links.size());
    for (size_t i = 0; i < bulk_links.size(); i++) {
      CHECK(bulk_links[i] == byte_links[i]);
    }
  }

  SECTION("byte-by-byte feeding performance is acceptable")
  {
    // 16KB of HTML fed one byte at a time
    std::string html = "<head>";
    for (int i = 0; i < 200; i++) {
      html += "<link rel=\"preload\" href=\"/r" + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head>";
    // Trim to ~16KB
    if (html.size() > 16384) {
      html.resize(16384);
    }

    auto start = std::chrono::steady_clock::now();
    dos_scan_byte_by_byte(html, static_cast<int>(html.size()), 10);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    // 16K calls to feed() should still complete in well under 1 second
    CHECK(elapsed_ms < 1000);
  }

  SECTION("byte-by-byte with comment does not hang")
  {
    std::string html = "<head><!-- some comment -->"
                       "<link rel=\"preload\" href=\"/ok.js\" as=\"script\">"
                       "</head>";

    auto links = dos_scan_byte_by_byte(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok.js") != std::string::npos);
  }

  SECTION("byte-by-byte crossing chunk boundaries in attributes")
  {
    // Attribute value split across bytes: href="/app.js" where each char
    // is a separate feed() call
    std::string html = "<head><link rel=\"preload\" href=\"/split.js\" as=\"script\"></head>";
    auto links       = dos_scan_byte_by_byte(html);

    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/split.js") != std::string::npos);
  }
}

// -----------------------------------------------------------------------------
// Combined stress tests
// -----------------------------------------------------------------------------

TEST_CASE("DoS: Combined stress scenarios", "[dos][combined]")
{
  SECTION("scan_limit enforced even with byte-by-byte feeding")
  {
    const int scan_limit = 256;
    std::string html     = "<head>";
    html.append(1000, 'X');
    html += "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(scan_limit, 10, &config);
    for (size_t i = 0; i < html.size(); i++) {
      scanner.feed(html.c_str() + i, 1);
      if (scanner.is_done()) {
        break;
      }
    }

    CHECK(scanner.is_done());
    CHECK(scanner.get_links().empty());
  }

  SECTION("cache flood + large link vectors combined")
  {
    const int max_entries = 50;
    HintsCache cache(max_entries);

    // Each entry has 10 links (simulating scanner output)
    std::vector<std::string> big_links;
    for (int i = 0; i < 10; i++) {
      big_links.push_back("</r" + std::to_string(i) + ".js>; rel=preload; as=script");
    }

    // Flood with 500 unique URLs each carrying 10 links
    for (int i = 0; i < 500; i++) {
      cache.put("/stress/" + std::to_string(i), big_links);
    }

    CHECK(cache.size() <= static_cast<size_t>(max_entries));
  }

  SECTION("alternating valid and malicious tags within scan_limit")
  {
    std::string html = "<head>";
    for (int i = 0; i < 50; i++) {
      // Valid link
      html += "<link rel=\"preload\" href=\"/good" + std::to_string(i) + ".js\" as=\"script\">";
      // Malicious: long comment
      html += "<!-- ";
      html.append(100, '-');
      html += "-->";
      // Malicious: long attribute value
      html += "<link rel=\"preload\" href=\"";
      html.append(500, 'A');
      html += "\" as=\"script\">";
    }
    html += "</head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(static_cast<int>(html.size()), 10, &config);

    auto start = std::chrono::steady_clock::now();
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    // Max 10 links extracted, processing completes in reasonable time
    CHECK(scanner.get_links().size() <= 10);
    CHECK(elapsed_ms < 2000);
  }

  SECTION("bogus comment bomb <!DOCTYPE repeated>")
  {
    std::string html = "<head>";
    for (int i = 0; i < 10000; i++) {
      html += "<!DOCTYPE html>";
    }
    html += "<link rel=\"preload\" href=\"/survived.js\" as=\"script\"></head>";

    auto links = dos_scan(html, static_cast<int>(html.size()), 10);

    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/survived.js") != std::string::npos);
  }

  SECTION("script with escaped comments bomb")
  {
    // <script> with <!-- ... --> cycling  -- exercises script_escaped_ toggling
    std::string html = "<head><script>";
    for (int i = 0; i < 1000; i++) {
      html += "<!-- escaped -->";
    }
    html += "</script><link rel=\"preload\" href=\"/esc.js\" as=\"script\"></head>";

    auto links = dos_scan(html, static_cast<int>(html.size()), 10);

    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/esc.js") != std::string::npos);
  }
}

// -----------------------------------------------------------------------------
// Regression: ensure scan_limit and max_links edge values work
// -----------------------------------------------------------------------------

TEST_CASE("DoS: Edge values for limits", "[dos][edge]")
{
  SECTION("scan_limit=0 immediately marks done")
  {
    std::string html = "<head><link rel=\"preload\" href=\"/x.js\" as=\"script\"></head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(0, 10, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.is_done());
    CHECK(scanner.get_links().empty());
  }

  SECTION("scan_limit=1 processes exactly 1 byte then stops")
  {
    std::string html = "<head><link rel=\"preload\" href=\"/x.js\" as=\"script\"></head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(1, 10, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.is_done());
    CHECK(scanner.get_links().empty());
  }

  SECTION("max_links=0 never collects any links")
  {
    std::string html = "<head><link rel=\"preload\" href=\"/x.js\" as=\"script\"></head>";

    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 0, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.get_links().empty());
  }

  SECTION("feed with null data does not crash")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);
    scanner.feed(nullptr, 100);
    scanner.feed("", 0);
    scanner.feed("<head>", -1);

    CHECK(scanner.get_links().empty());
  }

  SECTION("feed with zero length does nothing")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);
    scanner.feed("<head>", 0);
    CHECK_FALSE(scanner.is_done());
    CHECK(scanner.get_links().empty());
  }
}
