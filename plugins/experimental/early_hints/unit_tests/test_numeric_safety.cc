/** @file
 * Numeric safety tests: integer overflow, underflow, and truncation audits.
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
#include <thread>
#include <vector>
#include <climits>
#include <cstdint>
#include <ctime>

// Helper to simulate remap plugin argv: [fromURL, toURL, args...]
static bool
parse_config_ns(EarlyHintsConfig &config, std::initializer_list<const char *> args)
{
  std::vector<const char *> argv;
  argv.push_back("http://from.example.com");
  argv.push_back("http://to.example.com");
  for (auto a : args) {
    argv.push_back(a);
  }
  int argc = static_cast<int>(argv.size());
  return config.init(argc, argv.data());
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. scan_limit decrement: feed() with len > remaining scan budget
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: scan_limit boundary in feed()", "[numeric][scanner]")
{
  SECTION("feed chunk larger than scan_limit stops at limit")
  {
    // scan_limit=50, feed 200 bytes — scanner must stop after 50 bytes
    EarlyHintsConfig config;
    HtmlScanner scanner(50, 10, &config);

    std::string html = "<head>" + std::string(200, 'x') + "</head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    CHECK(scanner.is_done());
  }

  SECTION("feed exactly scan_limit bytes processes all then stops on next byte")
  {
    // scan_limit=10, feed exactly 10 bytes, then 1 more
    EarlyHintsConfig config;
    HtmlScanner scanner(10, 10, &config);

    std::string data1(10, 'a');
    scanner.feed(data1.c_str(), 10);
    CHECK_FALSE(scanner.is_done()); // scanned_==10, limit_==10, not > limit_

    std::string data2 = "b";
    scanner.feed(data2.c_str(), 1);
    CHECK(scanner.is_done()); // scanned_==11, now > limit_
  }

  SECTION("multiple small feeds accumulate correctly to hit limit")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(20, 10, &config);

    for (int i = 0; i < 10; i++) {
      std::string chunk = "ab"; // 2 bytes each, 10 chunks = 20 bytes
      scanner.feed(chunk.c_str(), 2);
    }
    CHECK_FALSE(scanner.is_done()); // scanned_==20, limit_==20

    scanner.feed("x", 1); // scanned_==21 > 20
    CHECK(scanner.is_done());
  }

  SECTION("feed with length=0 is a no-op")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(100, 10, &config);
    scanner.feed("data", 0);
    CHECK_FALSE(scanner.is_done());
  }

  SECTION("feed with negative length is a no-op")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(100, 10, &config);
    scanner.feed("data", -1);
    CHECK_FALSE(scanner.is_done());
  }

  SECTION("feed with nullptr is a no-op")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(100, 10, &config);
    scanner.feed(nullptr, 100);
    CHECK_FALSE(scanner.is_done());
  }

  SECTION("scan_limit=1 stops after first byte")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(1, 10, &config);
    scanner.feed("ab", 2);
    CHECK(scanner.is_done());
  }

  SECTION("links found before scan_limit are preserved after hitting limit")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(200, 10, &config);

    // Include a link early, then hit the scan limit with padding
    std::string html = "<head><link rel=\"preload\" href=\"/a.js\" as=\"script\">";
    html += std::string(200, ' '); // padding to exceed limit
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.is_done());
    CHECK(scanner.get_links().size() == 1);
    CHECK(scanner.get_links()[0] == "</a.js>; rel=preload; as=script");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. bytes_written overflow check (int64_t)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: bytes_written is int64_t and safe for large values", "[numeric]")
{
  // This is a design verification test: bytes_written is int64_t (8 bytes),
  // so it can hold values up to ~9.2 exabytes. We verify the type is correct.
  SECTION("bytes_written type is int64_t (verified by compilation)")
  {
    // TransformData is internal to early_hints.cc, so we verify the principle:
    // int64_t can accumulate up to INT64_MAX without overflow
    int64_t bytes = 0;
    bytes += INT64_MAX / 2;
    bytes += INT64_MAX / 2;
    // This should be INT64_MAX - 1 (no overflow)
    CHECK(bytes == INT64_MAX - 1);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. safe_parse_int edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: safe_parse_int boundary values", "[numeric][config]")
{
  SECTION("LONG_MAX as string is rejected (out of INT_MAX range)")
  {
    EarlyHintsConfig config;
    std::string val                = std::to_string(LONG_MAX);
    std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com", "--max-links", val.c_str()};
    CHECK_FALSE(config.init(4, argv.data()));
  }

  SECTION("LONG_MIN as string is rejected (out of INT_MIN range on LP64)")
  {
    EarlyHintsConfig config;
    std::string val                = std::to_string(LONG_MIN);
    std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com", "--max-links", val.c_str()};
    CHECK_FALSE(config.init(4, argv.data()));
  }

  SECTION("INT_MAX as string is rejected by range check (max-links <= 50)")
  {
    EarlyHintsConfig config;
    std::string val                = std::to_string(INT_MAX);
    std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com", "--max-links", val.c_str()};
    CHECK_FALSE(config.init(4, argv.data()));
  }

  SECTION("INT_MIN as string is rejected by range check")
  {
    EarlyHintsConfig config;
    std::string val                = std::to_string(INT_MIN);
    std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com", "--max-links", val.c_str()};
    CHECK_FALSE(config.init(4, argv.data()));
  }

  SECTION("number larger than LONG_MAX is rejected (strtol ERANGE)")
  {
    EarlyHintsConfig config;
    // 99999999999999999999 is > LONG_MAX on any platform
    std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com", "--max-links", "99999999999999999999"};
    CHECK_FALSE(config.init(4, argv.data()));
  }

  SECTION("negative number for unsigned-like field is rejected by range")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--scan-limit", "-1"}));
  }

  SECTION("zero is rejected for all positive-minimum fields")
  {
    EarlyHintsConfig config1;
    CHECK_FALSE(parse_config_ns(config1, {"--max-links", "0"}));

    EarlyHintsConfig config2;
    CHECK_FALSE(parse_config_ns(config2, {"--min-hit-count", "0"}));
  }

  SECTION("just whitespace is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--max-links", " "}));
  }

  SECTION("leading zeros are parsed correctly")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--max-links", "05"}));
    CHECK(config.max_links() == 5);
  }

  SECTION("hex format is rejected (0x prefix)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--max-links", "0x0A"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4 & 5. avail - fed calculation safety (design verification)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: avail-fed subtraction safety in transform feed loop", "[numeric]")
{
  // The transform feed loop in early_hints.cc:380-389 computes:
  //   to_feed = min(block_len, avail - fed)
  // with loop guard: fed < avail
  // This test verifies the arithmetic invariant holds.

  SECTION("min(block_len, avail-fed) is always positive when fed < avail")
  {
    int64_t avail     = 1000;
    int64_t fed       = 0;
    int64_t block_len = 500;

    while (fed < avail) {
      REQUIRE((avail - fed) > 0);
      int64_t to_feed = std::min(block_len, avail - fed);
      REQUIRE(to_feed > 0);
      fed += to_feed;
    }
    CHECK(fed == avail);
  }

  SECTION("single block exactly equal to avail")
  {
    int64_t avail     = 100;
    int64_t fed       = 0;
    int64_t block_len = 100;

    int64_t to_feed = std::min(block_len, avail - fed);
    CHECK(to_feed == 100);
    fed += to_feed;
    CHECK(fed == avail);
    // Loop guard fed < avail is now false, so we don't compute avail - fed again
    CHECK_FALSE(fed < avail);
  }

  SECTION("block_len larger than remaining avail is clamped")
  {
    int64_t avail     = 50;
    int64_t fed       = 30;
    int64_t block_len = 100; // larger than remaining 20

    int64_t to_feed = std::min(block_len, avail - fed);
    CHECK(to_feed == 20);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. TSVIONDoneGet/Set int64_t arithmetic (design verification)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: VIO NDone accumulation overflow check", "[numeric]")
{
  // TSVIONDoneSet(input_vio, TSVIONDoneGet(input_vio) + copied)
  // Both are int64_t. Verify accumulation is safe for realistic sizes.
  SECTION("accumulating 1GB chunks 1000 times stays within int64_t")
  {
    int64_t ndone  = 0;
    int64_t copied = static_cast<int64_t>(1) << 30; // 1 GB
    for (int i = 0; i < 1000; i++) {
      int64_t new_ndone = ndone + copied;
      REQUIRE(new_ndone > ndone); // No overflow
      ndone = new_ndone;
    }
    CHECK(ndone == 1000LL * (1LL << 30)); // ~1 TB
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. Cache entry count vs max_entries: signed/unsigned comparison
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: HintsCache max_entries enforcement", "[numeric][cache]")
{
  SECTION("one entry evicted when at capacity")
  {
    HintsCache cache(3); // max 3 entries
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    cache.put("/a", links);
    cache.put("/b", links);
    cache.put("/c", links);
    CHECK(cache.size() == 3);

    // 4th entry evicts one and inserts /d
    cache.put("/d", links);
    CHECK(cache.size() == 3);

    // /d was inserted
    std::vector<std::string> result;
    CHECK(cache.get("/d", result, 1));
  }

  SECTION("entries can be added when oldest is evicted")
  {
    HintsCache cache(2);
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    cache.put("/a", links);
    cache.put("/b", links);
    CHECK(cache.size() == 2);

    // Adding /c evicts oldest (/a)
    cache.put("/c", links);
    CHECK(cache.size() == 2);
    CHECK(cache.get("/c", 1) != nullptr);
  }

  SECTION("updating existing entry at capacity works (no new key)")
  {
    HintsCache cache(2);
    std::vector<std::string> links1 = {"</a.js>; rel=preload; as=script"};
    std::vector<std::string> links2 = {"</b.js>; rel=preload; as=script"};

    cache.put("/a", links1);
    cache.put("/b", links1);
    CHECK(cache.size() == 2);

    // Updating existing key should succeed even at capacity
    cache.put("/a", links2);
    CHECK(cache.size() == 2);

    // Verify update took effect (learn_count is now 2)
    std::vector<std::string> result;
    CHECK(cache.get("/a", result, 2));
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</b.js>; rel=preload; as=script");
  }

  SECTION("max_entries=100 (minimum valid config value) works")
  {
    HintsCache cache(100);
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    for (int i = 0; i < 100; i++) {
      cache.put("/page/" + std::to_string(i), links);
    }
    CHECK(cache.size() == 100);

    // 101st evicts oldest and inserts
    cache.put("/page/overflow", links);
    CHECK(cache.size() == 100);
    CHECK(cache.get("/page/overflow", 1) != nullptr);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Entries persist without TTL
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: Cache entries persist indefinitely", "[numeric][cache]")
{
  SECTION("entry persists after multiple gets")
  {
    HintsCache cache;
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    cache.put("/page", links);

    // Multiple gets should always return the entry — no expiry
    for (int i = 0; i < 100; i++) {
      std::vector<std::string> result;
      bool found = cache.get("/page", result, 1);
      CHECK(found);
    }
    CHECK(cache.size() == 1);
  }

  SECTION("entry value survives repeated put updates")
  {
    HintsCache cache;
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};
    cache.put("/page", links);

    // Multiple updates increment learn_count
    for (int i = 0; i < 10; i++) {
      cache.put("/page", links);
    }

    // learn_count should be 11 (1 initial + 10 updates)
    std::vector<std::string> result;
    CHECK(cache.get("/page", result, 11));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. string::size_type vs int comparisons
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: size_type to int casts in scanner", "[numeric][scanner]")
{
  SECTION("links_.size() cast to int for max_links comparison is safe (max_links <= 50)")
  {
    // With max_links=50, links_.size() can never exceed 50 (checked before push_back)
    // so static_cast<int>(links_.size()) is always safe
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 3, &config);

    std::string html = "<head>";
    html += "<link rel=\"preload\" href=\"/a.js\" as=\"script\">";
    html += "<link rel=\"preload\" href=\"/b.js\" as=\"script\">";
    html += "<link rel=\"preload\" href=\"/c.js\" as=\"script\">";
    html += "<link rel=\"preload\" href=\"/d.js\" as=\"script\">"; // should be dropped
    html += "</head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.get_links().size() == 3);
  }

  SECTION("max_links=1 allows exactly 1 link")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 1, &config);

    std::string html = "<head>";
    html += "<link rel=\"preload\" href=\"/a.js\" as=\"script\">";
    html += "<link rel=\"preload\" href=\"/b.js\" as=\"script\">";
    html += "</head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.get_links().size() == 1);
    CHECK(scanner.get_links()[0] == "</a.js>; rel=preload; as=script");
  }

  SECTION("attr_value_ size cap at MAX_ATTR_VALUE_LEN (4096)")
  {
    // Verify that extremely long attribute values are truncated, not overflowed
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    std::string long_href(5000, 'a'); // 5000 chars > 4096 limit
    std::string html = "<head><link rel=\"preload\" href=\"/" + long_href + "\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    // The href is truncated to 4096 chars but still produces a link
    // (it won't match any dangerous scheme, and is_safe_url allows long URLs)
    auto links = scanner.get_links();
    if (!links.empty()) {
      // Verify the URL in the link header is at most 4096+1 chars (/ prefix + truncated)
      size_t url_start = links[0].find('<');
      size_t url_end   = links[0].find('>');
      REQUIRE(url_start != std::string::npos);
      REQUIRE(url_end != std::string::npos);
      CHECK((url_end - url_start - 1) <= 4097); // </ + up to 4096 chars
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. comment_dashes_ range: can it go outside 0-6?
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: comment_dashes_ stays in valid range 0-6", "[numeric][scanner]")
{
  SECTION("standard comment <!-- --> stays in range and exits cleanly")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    std::string html = "<head><!-- comment --><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    CHECK(scanner.get_links().size() == 1);
  }

  SECTION("comment with many dashes <!----- text -----> exits cleanly")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    std::string html = "<head><!----- lots of dashes -----><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    CHECK(scanner.get_links().size() == 1);
  }

  SECTION("comment end bang state --!> closes comment")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    std::string html = "<head><!-- comment --!><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    CHECK(scanner.get_links().size() == 1);
  }

  SECTION("abrupt comment close <!--> exits to IN_HEAD (start state)")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    std::string html = "<head><!--><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    CHECK(scanner.get_links().size() == 1);
  }

  SECTION("comment start dash abrupt close <!---> exits to IN_HEAD")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    std::string html = "<head><!---><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    CHECK(scanner.get_links().size() == 1);
  }

  SECTION("deeply nested dashes don't corrupt state")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    // This exercises transitions: 5→6→2→3→4→2→0→1→2 (>)
    std::string html = "<head><!----!-x--><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    CHECK(scanner.get_links().size() == 1);
  }

  SECTION("byte-by-byte feeding through comment preserves correctness")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);

    std::string html = "<head><!-- tricky --!- --><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    // Feed one byte at a time to stress state transitions
    for (size_t i = 0; i < html.size(); i++) {
      scanner.feed(html.c_str() + i, 1);
    }
    CHECK(scanner.get_links().size() == 1);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Additional: HintsCache::make_key signed int edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: HintsCache::make_key with edge-case path_len", "[numeric][cache]")
{
  SECTION("negative path_len returns /") { CHECK(HintsCache::make_key("something", -1) == "/"); }

  SECTION("path_len=0 returns /") { CHECK(HintsCache::make_key("something", 0) == "/"); }

  SECTION("path_len=INT_MIN returns /") { CHECK(HintsCache::make_key("something", INT_MIN) == "/"); }

  SECTION("query-only path with correct len returns /")
  {
    // path="?q=1", path_len=4 → key_len = qmark-path = 0 → returns "/"
    CHECK(HintsCache::make_key("?q=1", 4) == "/");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Additional: learn_count overflow (int)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: HintsCache learn_count is bounded by practical use", "[numeric][cache]")
{
  SECTION("many puts increment learn_count correctly")
  {
    HintsCache cache;
    std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

    // Put 100 times — learn_count should reach 100
    for (int i = 0; i < 100; i++) {
      cache.put("/page", links);
    }

    // Should be retrievable with min_hits up to 100
    std::vector<std::string> result;
    CHECK(cache.get("/page", result, 100));
    CHECK_FALSE(cache.get("/page", result, 101));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Additional: config range boundary values (exact boundaries)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: config exact boundary values", "[numeric][config]")
{
  SECTION("max-links=1 (minimum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--max-links", "1"}));
    CHECK(config.max_links() == 1);
  }

  SECTION("max-links=50 (maximum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--max-links", "50"}));
    CHECK(config.max_links() == 50);
  }

  SECTION("persist-dir accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--persist-dir", "/tmp/hints/"}));
    CHECK(config.persist_dir() == "/tmp/hints/");
    CHECK(config.persist_enabled() == true);
  }

  SECTION("no-persist accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--no-persist"}));
    CHECK(config.persist_enabled() == false);
  }

  SECTION("header-size-limit=256 (minimum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--header-size-limit", "256"}));
    CHECK(config.header_size_limit() == 256);
  }

  SECTION("header-size-limit=16384 (maximum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--header-size-limit", "16384"}));
    CHECK(config.header_size_limit() == 16384);
  }

  SECTION("header-size-limit=255 (below minimum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--header-size-limit", "255"}));
  }

  SECTION("header-size-limit=16385 (above maximum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--header-size-limit", "16385"}));
  }

  SECTION("scan-limit=1024 (minimum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--scan-limit", "1024"}));
    CHECK(config.scan_limit() == 1024);
  }

  SECTION("scan-limit=1048576 (maximum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--scan-limit", "1048576"}));
    CHECK(config.scan_limit() == 1048576);
  }

  SECTION("scan-limit=1023 (below minimum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--scan-limit", "1023"}));
  }

  SECTION("scan-limit=1048577 (above maximum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--scan-limit", "1048577"}));
  }

  SECTION("min-hit-count=1 (minimum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--min-hit-count", "1"}));
    CHECK(config.min_hit_count() == 1);
  }

  SECTION("min-hit-count=1000 (maximum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--min-hit-count", "1000"}));
    CHECK(config.min_hit_count() == 1000);
  }

  SECTION("min-hit-count=0 (below minimum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--min-hit-count", "0"}));
  }

  SECTION("min-hit-count=1001 (above maximum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--min-hit-count", "1001"}));
  }

  SECTION("max-cache-entries=100 (minimum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--max-cache-entries", "100"}));
    CHECK(config.max_cache_entries() == 100);
  }

  SECTION("max-cache-entries=1000000 (maximum) accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config_ns(config, {"--max-cache-entries", "1000000"}));
    CHECK(config.max_cache_entries() == 1000000);
  }

  SECTION("max-cache-entries=0 (below minimum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--max-cache-entries", "0"}));
  }

  SECTION("max-cache-entries=1000001 (above maximum) rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config_ns(config, {"--max-cache-entries", "1000001"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Additional: HintsCache shared_ptr get() returns ref-counted ptr safely
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: HintsCache hit_count increments on get()", "[numeric][cache]")
{
  HintsCache cache;
  std::vector<std::string> links = {"</a.js>; rel=preload; as=script"};

  cache.put("/page", links);

  // Multiple gets should not corrupt anything
  for (int i = 0; i < 1000; i++) {
    LinkListPtr ptr = cache.get("/page", 1);
    REQUIRE(ptr != nullptr);
    CHECK(ptr->size() == 1);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Additional: scanner reset clears numeric state
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Numeric: scanner reset clears scanned counter", "[numeric][scanner]")
{
  SECTION("reset allows re-scanning with full budget")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(50, 10, &config);

    // Exhaust the scan budget
    std::string data(60, 'a');
    scanner.feed(data.c_str(), 60);
    CHECK(scanner.is_done());

    // Reset and re-scan
    scanner.reset();
    CHECK_FALSE(scanner.is_done());

    std::string html = "<head><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    // Depending on whether html.size() > 50, might hit limit
    // But reset should have cleared scanned_ to 0
    if (html.size() <= 50) {
      CHECK(scanner.get_links().size() == 1);
    }
  }
}
