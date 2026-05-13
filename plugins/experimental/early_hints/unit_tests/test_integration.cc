/** @file
 * Integration tests for cross-module interfaces in the early_hints plugin.
 *
 * Tests the data flow: Config → HtmlScanner → HintsCache → (103 response validation)
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
#include <cstring>

// is_valid_link_value is declared in config.h and defined in config.cc,
// which is compiled into this test binary. No local copy needed.

// Helper to parse config from remap-style argv
static bool
parse_config(EarlyHintsConfig &config, std::initializer_list<const char *> args)
{
  std::vector<const char *> argv;
  argv.push_back("http://from.example.com");
  argv.push_back("http://to.example.com");
  for (auto a : args) {
    argv.push_back(a);
  }
  return config.init(static_cast<int>(argv.size()), argv.data());
}

// ─── Contract 1: Scanner output format → HintsCache → is_valid_link_value ────

TEST_CASE("Integration: Scanner links pass is_valid_link_value after cache round-trip", "[integration]")
{
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn"}));

  SECTION("preload script")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);

    // Put into cache, then retrieve
    HintsCache cache;
    std::string key = HintsCache::make_key("/page", 5);
    cache.put(key, links);

    std::vector<std::string> retrieved;
    REQUIRE(cache.get(key, retrieved, 1));
    REQUIRE(retrieved.size() == 1);

    // Verify format survives round-trip and passes validation
    CHECK(retrieved[0] == links[0]);
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("preload style")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/style.css\" as=\"style\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);

    HintsCache cache;
    cache.put("/page", links);

    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("stylesheet converts to preload")
  {
    std::string html = "<html><head><link rel=\"stylesheet\" href=\"/main.css\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Scanner converts rel=stylesheet to rel=preload; as=style
    CHECK(links[0].find("rel=preload") != std::string::npos);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("modulepreload")
  {
    std::string html = "<html><head><link rel=\"modulepreload\" href=\"/mod.js\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=modulepreload") != std::string::npos);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("script tag as preload")
  {
    std::string html = "<html><head><script src=\"/bundle.js\"></script></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload; as=script") != std::string::npos);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("cross-origin preconnect passes validation")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"https://cdn.example.com/lib.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Non-whitelisted cross-origin becomes preconnect
    CHECK(links[0].find("rel=preconnect") != std::string::npos);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("font with crossorigin and type passes validation")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/font.woff2\" as=\"font\" type=\"font/woff2\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Font should auto-get crossorigin
    CHECK(links[0].find("crossorigin") != std::string::npos);
    CHECK(links[0].find("type=\"font/woff2\"") != std::string::npos);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("fetchpriority attribute passes validation")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/hero.jpg\" as=\"image\" fetchpriority=\"high\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("fetchpriority=high") != std::string::npos);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("multiple links round-trip through cache")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/a.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"/b.css\" as=\"style\">"
                       "<link rel=\"stylesheet\" href=\"/c.css\">"
                       "<script src=\"/d.js\"></script>"
                       "</head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 4);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    REQUIRE(retrieved.size() == 4);

    for (size_t i = 0; i < retrieved.size(); i++) {
      INFO("link index: " << i << " value: " << retrieved[i]);
      CHECK(retrieved[i] == links[i]);
      CHECK(is_valid_link_value(retrieved[i]));
    }
  }
}

// ─── Contract 2: Config → Scanner parameter propagation ─────────────────────

TEST_CASE("Integration: Config scan_limit propagates to Scanner", "[integration]")
{
  SECTION("scan_limit stops scanning before head close")
  {
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn", "--scan-limit", "1024"}));
    CHECK(config.scan_limit() == 1024);

    // Build HTML with <link> far beyond the scan limit
    std::string html = "<html><head>";
    // Pad with 1200 bytes of whitespace (exceeds 1024 limit)
    html.append(1200, ' ');
    html += "<link rel=\"preload\" href=\"/late.js\" as=\"script\">";
    html += "</head></html>";

    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    // Scanner should have hit limit and not found the late link
    CHECK(scanner.is_done());
    CHECK(scanner.get_links().empty());
  }

  SECTION("scan_limit allows link before limit")
  {
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn", "--scan-limit", "4096"}));

    std::string html = "<html><head><link rel=\"preload\" href=\"/early.js\" as=\"script\"></head></html>";

    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    REQUIRE(scanner.get_links().size() == 1);
    CHECK(scanner.get_links()[0].find("/early.js") != std::string::npos);
  }
}

TEST_CASE("Integration: Config max_links propagates to Scanner", "[integration]")
{
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn", "--max-links", "2"}));
  CHECK(config.max_links() == 2);

  std::string html = "<html><head>"
                     "<link rel=\"preload\" href=\"/a.js\" as=\"script\">"
                     "<link rel=\"preload\" href=\"/b.js\" as=\"script\">"
                     "<link rel=\"preload\" href=\"/c.js\" as=\"script\">"
                     "</head></html>";

  HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

  // Only 2 links should be collected due to max_links
  CHECK(scanner.get_links().size() == 2);
}

// ─── Contract 3: Config whitelist → Scanner cross-origin handling ────────────

TEST_CASE("Integration: Config whitelist affects Scanner cross-origin decisions", "[integration]")
{
  SECTION("whitelisted domain gets preload instead of preconnect")
  {
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"}));

    std::string html = "<html><head><link rel=\"preload\" href=\"https://cdn.example.com/app.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Whitelisted: full preload, not preconnect
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("cdn.example.com/app.js") != std::string::npos);
    CHECK(is_valid_link_value(links[0]));
  }

  SECTION("non-whitelisted domain gets preconnect")
  {
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"}));

    std::string html = "<html><head><link rel=\"preload\" href=\"https://evil.example.com/app.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(is_valid_link_value(links[0]));
  }

  SECTION("wildcard whitelist works through scanner")
  {
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn", "--crossorigin-whitelist", "*.example.com"}));

    std::string html = "<html><head><link rel=\"preload\" href=\"https://any.example.com/lib.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(is_valid_link_value(links[0]));
  }

  SECTION("whitelisted cross-origin preload round-trips through cache")
  {
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"}));

    std::string html = "<html><head><link rel=\"preload\" href=\"https://cdn.example.com/style.css\" as=\"style\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(retrieved[0] == links[0]);
    CHECK(is_valid_link_value(retrieved[0]));
  }
}

// ─── Contract 4: HintsCache::make_key matches transform handler key building ─

TEST_CASE("Integration: Cache key normalization matches transform handler", "[integration]")
{
  SECTION("simple path")
  {
    // TSUrlPathGet returns path WITHOUT leading '/'
    // Transform handler: cache_key = make_key(path, path_len); if (cache_key[0]!='/') cache_key = "/" + cache_key;
    std::string key = HintsCache::make_key("page/index.html", 15);
    // make_key returns "page/index.html" (no leading /)
    // Transform handler prepends /
    if (key[0] != '/') {
      key = "/" + key;
    }
    CHECK(key == "/page/index.html");
  }

  SECTION("path with query string stripped")
  {
    std::string key = HintsCache::make_key("page?q=1&r=2", 12);
    if (key[0] != '/') {
      key = "/" + key;
    }
    CHECK(key == "/page");
  }

  SECTION("root path (null from TSUrlPathGet)")
  {
    // TSUrlPathGet returns nullptr for root /
    std::string key = HintsCache::make_key(nullptr, 0);
    // make_key returns "/" for null
    CHECK(key == "/");
  }

  SECTION("root path (empty from TSUrlPathGet)")
  {
    std::string key = HintsCache::make_key("", 0);
    CHECK(key == "/");
  }

  SECTION("cache key consistency: scanner learns same key as lookup")
  {
    // Simulate: request comes in for /page?v=1, scanner learns on same key, next request for /page?v=2 retrieves
    const char *path1     = "page?v=1";
    int path1_len         = static_cast<int>(strlen(path1));
    std::string learn_key = HintsCache::make_key(path1, path1_len);
    if (learn_key[0] != '/') {
      learn_key = "/" + learn_key;
    }

    const char *path2      = "page?v=2";
    int path2_len          = static_cast<int>(strlen(path2));
    std::string lookup_key = HintsCache::make_key(path2, path2_len);
    if (lookup_key[0] != '/') {
      lookup_key = "/" + lookup_key;
    }

    // Both should resolve to /page (query stripped)
    CHECK(learn_key == lookup_key);
    CHECK(learn_key == "/page");

    // Verify actual cache round-trip with these keys
    HintsCache cache;
    std::vector<std::string> links = {"</app.js>; rel=preload; as=script"};
    cache.put(learn_key, links);

    std::vector<std::string> retrieved;
    REQUIRE(cache.get(lookup_key, retrieved, 1));
    CHECK(retrieved[0] == links[0]);
  }

  SECTION("path with fragment is not stripped (make_key only strips query)")
  {
    // make_key strips '?' but not '#' — this is correct since servers never see fragments
    // but documents the behavior at the interface
    std::string key = HintsCache::make_key("page#section", 12);
    if (key[0] != '/') {
      key = "/" + key;
    }
    CHECK(key == "/page#section");
  }
}

// ─── Contract 5: String format assumptions across interfaces ─────────────────

TEST_CASE("Integration: Scanner-produced links are well-formed for all consumers", "[integration]")
{
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn"}));

  SECTION("link format: starts with < and contains >")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(!links.empty());

    for (const auto &link : links) {
      CHECK(link[0] == '<');
      CHECK(link.find('>') != std::string::npos);
      // No control characters
      for (char c : link) {
        unsigned char uc = static_cast<unsigned char>(c);
        CHECK(uc >= 0x20);
        CHECK(uc != 0x7F);
      }
    }
  }

  SECTION("empty href is rejected by scanner (no empty URLs in cache)")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.get_links().empty());
  }

  SECTION("URL with CRLF is rejected by scanner (no injection in cache)")
  {
    // The scanner's is_safe_url rejects control chars
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\r\nEvil: header\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    CHECK(scanner.get_links().empty());
  }

  SECTION("scanner uses crossorigin=use-credentials correctly")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/api-data.json\" as=\"fetch\" crossorigin=\"use-credentials\">"
                       "</head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("crossorigin=use-credentials") != std::string::npos);
    CHECK(is_valid_link_value(links[0]));
  }
}

TEST_CASE("Integration: Streaming scanner produces same results as single-feed", "[integration]")
{
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn"}));

  std::string html = "<html><head>"
                     "<link rel=\"preload\" href=\"/a.js\" as=\"script\">"
                     "<link rel=\"stylesheet\" href=\"/b.css\">"
                     "<script src=\"/c.js\"></script>"
                     "</head></html>";

  // Single feed
  HtmlScanner single_scanner(config.scan_limit(), config.max_links(), &config);
  single_scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  auto single_links = single_scanner.get_links();

  // Chunked feed (simulates transform handler getting data in small blocks)
  for (int chunk_size : {1, 3, 7, 16, 64}) {
    INFO("chunk_size: " << chunk_size);
    HtmlScanner chunked_scanner(config.scan_limit(), config.max_links(), &config);
    for (size_t i = 0; i < html.size(); i += chunk_size) {
      size_t len = std::min(static_cast<size_t>(chunk_size), html.size() - i);
      chunked_scanner.feed(html.c_str() + i, static_cast<int64_t>(len));
    }
    auto chunked_links = chunked_scanner.get_links();

    REQUIRE(chunked_links.size() == single_links.size());
    for (size_t i = 0; i < single_links.size(); i++) {
      CHECK(chunked_links[i] == single_links[i]);
    }
  }

  // All links from streamed result should be cache-valid
  HintsCache cache;
  cache.put("/page", single_links);
  std::vector<std::string> retrieved;
  REQUIRE(cache.get("/page", retrieved, 1));
  for (const auto &link : retrieved) {
    CHECK(is_valid_link_value(link));
  }
}

// ─── Contract 3 (continued): Config change could invalidate cached links ─────

TEST_CASE("Integration: Cached links remain valid regardless of config changes", "[integration]")
{
  SECTION("links learned with whitelist stay valid after whitelist changes")
  {
    // Phase 1: Learn with whitelist allowing cdn.example.com
    EarlyHintsConfig config1;
    REQUIRE(parse_config(config1, {"--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"}));

    std::string html = "<html><head><link rel=\"preload\" href=\"https://cdn.example.com/app.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config1.scan_limit(), config1.max_links(), &config1);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // With whitelist: full preload URL
    CHECK(links[0].find("rel=preload") != std::string::npos);

    HintsCache cache;
    cache.put("/page", links);

    // Phase 2: "Config changes" — new config without whitelist
    // The cached link was a full preload for the cross-origin URL.
    // is_valid_link_value doesn't check whitelist — it only validates format.
    // So the cached link remains valid (safe to serve).
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }

  SECTION("preconnect links are always valid regardless of config")
  {
    // Non-whitelisted cross-origin produces preconnect
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn"}));

    std::string html = "<html><head><link rel=\"preload\" href=\"https://unknown.example.com/lib.js\" as=\"script\"></head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &links = scanner.get_links();
    REQUIRE(links.size() == 1);

    HintsCache cache;
    cache.put("/page", links);
    std::vector<std::string> retrieved;
    REQUIRE(cache.get("/page", retrieved, 1));
    CHECK(is_valid_link_value(retrieved[0]));
  }
}

// ─── Full pipeline: Config → Scanner → Cache → Validate → Serve ─────────────

TEST_CASE("Integration: Full pipeline simulates transform handler flow", "[integration]")
{
  SECTION("auto-learn: scan, cache, retrieve, validate, serve")
  {
    // Step 1: Config
    EarlyHintsConfig config;
    REQUIRE(parse_config(config, {"--mode", "auto-learn", "--max-links", "5", "--min-hit-count", "1"}));

    // Step 2: Build cache key (as TSRemapDoRemap does)
    const char *url_path  = "products/widget";
    int path_len          = static_cast<int>(strlen(url_path));
    std::string cache_key = HintsCache::make_key(url_path, path_len);
    if (cache_key[0] != '/') {
      cache_key = "/" + cache_key;
    }
    CHECK(cache_key == "/products/widget");

    // Step 3: Scanner processes HTML (as transform handler does)
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/widget.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"/widget.css\" as=\"style\">"
                       "<link rel=\"preload\" href=\"/hero.webp\" as=\"image\" fetchpriority=\"high\">"
                       "</head><body>content</body></html>";

    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    const auto &scanned_links = scanner.get_links();
    REQUIRE(scanned_links.size() == 3);

    // Step 4: Transform handler puts links into cache
    HintsCache cache;
    cache.put(cache_key, scanned_links);

    // Step 5: Next request — TSRemapDoRemap builds key and looks up cache
    const char *next_path = "products/widget?ref=123";
    int next_len          = static_cast<int>(strlen(next_path));
    std::string next_key  = HintsCache::make_key(next_path, next_len);
    if (next_key[0] != '/') {
      next_key = "/" + next_key;
    }
    CHECK(next_key == cache_key); // Query stripped, same key

    LinkListPtr cached = cache.get(next_key, config.min_hit_count());
    REQUIRE(cached != nullptr);
    REQUIRE(cached->size() == 3);

    // Step 6: Validate all links before serving (as send_103_response would)
    for (const auto &link : *cached) {
      CHECK(is_valid_link_value(link));
    }
  }
}

TEST_CASE("Integration: Cache min_hit_count from config gates serving", "[integration]")
{
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn", "--min-hit-count", "3"}));
  CHECK(config.min_hit_count() == 3);

  HintsCache cache;
  std::string key = "/page";

  // Simulate scanner output
  std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";
  HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  const auto &links = scanner.get_links();
  REQUIRE(links.size() == 1);

  // First put: learn_count = 1
  cache.put(key, links);
  CHECK(cache.get(key, config.min_hit_count()) == nullptr);

  // Second put: learn_count = 2
  cache.put(key, links);
  CHECK(cache.get(key, config.min_hit_count()) == nullptr);

  // Third put: learn_count = 3 — now meets threshold
  cache.put(key, links);
  LinkListPtr result = cache.get(key, config.min_hit_count());
  REQUIRE(result != nullptr);
  REQUIRE(result->size() == 1);
  CHECK(is_valid_link_value((*result)[0]));
}

TEST_CASE("Integration: Cache shared_ptr semantics — no deep copy overhead", "[integration]")
{
  // Verifies that get() returns a shared_ptr reference, not a copy,
  // matching the zero-copy design used in TSRemapDoRemap
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn"}));

  HintsCache cache;
  std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";
  HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

  cache.put("/page", scanner.get_links());

  LinkListPtr ptr1 = cache.get("/page", 1);
  LinkListPtr ptr2 = cache.get("/page", 1);
  REQUIRE(ptr1 != nullptr);
  REQUIRE(ptr2 != nullptr);
  // Both should point to the same underlying data
  CHECK(ptr1.get() == ptr2.get());
}

TEST_CASE("Integration: Config header_size_limit constrains what gets served", "[integration]")
{
  // Simulates the send_103_response logic with header_size_limit
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn", "--header-size-limit", "256"}));

  HintsCache cache;
  std::string html = "<html><head>"
                     "<link rel=\"preload\" href=\"/very-long-path-that-takes-up-space/bundle.js\" as=\"script\">"
                     "<link rel=\"preload\" href=\"/another-long-path/styles.css\" as=\"style\">"
                     "<link rel=\"preload\" href=\"/third-resource/font.woff2\" as=\"font\" type=\"font/woff2\">"
                     "</head></html>";
  HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

  const auto &links = scanner.get_links();
  REQUIRE(links.size() == 3);

  cache.put("/page", links);
  std::vector<std::string> retrieved;
  REQUIRE(cache.get("/page", retrieved, 1));

  // Simulate send_103_response header size accounting (matches production continue semantics)
  int total_size = 0;
  int count      = 0;
  for (const auto &link : retrieved) {
    if (count >= config.max_links()) {
      break;
    }
    int link_size = static_cast<int>(link.size()) + 8; // "Link: " (6) + value + "\r\n" (2)
    if (total_size + link_size > config.header_size_limit()) {
      continue; // skip oversized, try smaller links (matches production code)
    }
    CHECK(is_valid_link_value(link));
    total_size += link_size;
    count++;
  }

  // With 256-byte limit, at most 3 links fit (depends on link lengths)
  CHECK(count <= 3);
  CHECK(count >= 1);
  CHECK(total_size <= config.header_size_limit());
}

TEST_CASE("Integration: Oversized first link skipped, smaller subsequent links still sent", "[integration]")
{
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn", "--header-size-limit", "256", "--max-links", "10"}));

  HintsCache cache;

  // Create links where first is oversized but subsequent are small
  std::vector<std::string> links;
  // Oversized link (~200 bytes, exceeds 256 with overhead)
  std::string big_link = "</fonts/";
  big_link += std::string(200, 'a');
  big_link += ".woff2>; rel=preload; as=font; crossorigin=anonymous";
  links.push_back(big_link);
  // Small links that fit
  links.push_back("</css/main.css>; rel=preload; as=style");
  links.push_back("</js/app.js>; rel=preload; as=script");

  cache.put("/page", links);
  std::vector<std::string> retrieved;
  REQUIRE(cache.get("/page", retrieved, 1));
  REQUIRE(retrieved.size() == 3);

  // Simulate send_103_response with continue semantics
  int total_size = 0;
  int count      = 0;
  std::vector<std::string> accepted;
  for (const auto &link : retrieved) {
    if (count >= config.max_links()) {
      break;
    }
    int link_size = static_cast<int>(link.size()) + 8;
    if (total_size + link_size > config.header_size_limit()) {
      continue; // skip oversized
    }
    accepted.push_back(link);
    total_size += link_size;
    count++;
  }

  // First (oversized) link should be skipped, but 2 smaller links should be included
  REQUIRE(count == 2);
  CHECK(accepted[0].find("/css/main.css") != std::string::npos);
  CHECK(accepted[1].find("/js/app.js") != std::string::npos);
  CHECK(total_size <= config.header_size_limit());
}

TEST_CASE("Integration: Cache update overwrites stale scanner results", "[integration]")
{
  EarlyHintsConfig config;
  REQUIRE(parse_config(config, {"--mode", "auto-learn"}));

  HintsCache cache;

  // First scan: page has 2 resources
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/v1.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"/v1.css\" as=\"style\">"
                       "</head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    cache.put("/page", scanner.get_links());
  }

  // Second scan: page updated, now has different resources
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/v2.js\" as=\"script\">"
                       "</head></html>";
    HtmlScanner scanner(config.scan_limit(), config.max_links(), &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    cache.put("/page", scanner.get_links());
  }

  // Retrieved links should be the updated version
  std::vector<std::string> retrieved;
  REQUIRE(cache.get("/page", retrieved, 1));
  REQUIRE(retrieved.size() == 1);
  CHECK(retrieved[0].find("/v2.js") != std::string::npos);
  CHECK(is_valid_link_value(retrieved[0]));
}

// ─── Origin-forward dedup: simulate the dedup logic from early_hints.cc ──────
//
// The origin-forward dedup in early_hints.cc is inside an ATS-callback and
// cannot be invoked without a running ATS process.  We simulate its logic here
// using split_link_header_value + the same URL-key+rel-type check to verify
// correctness for edge cases not covered by the integration test.

#include "../link_parser.h"

// Mirrors the dedup logic in early_hints.cc handle_read_response_hdr().
static std::vector<std::string>
simulate_origin_forward(const std::vector<std::string> &raw_header_values, int max_links = 10)
{
  std::vector<std::string> origin_links;
  for (const auto &full_val : raw_header_values) {
    int remaining = max_links - static_cast<int>(origin_links.size());
    auto segments = split_link_header_value(full_val, remaining);
    for (auto &seg : segments) {
      if (is_valid_link_value(seg)) {
        size_t url_end = seg.find('>');
        bool is_dup    = false;
        if (url_end != std::string::npos) {
          std::string_view url_key = std::string_view(seg).substr(0, url_end + 1);
          bool is_preconnect       = seg.find("rel=preconnect") != std::string::npos;
          for (const auto &existing : origin_links) {
            if (existing.size() > url_key.size() && existing.compare(0, url_key.size(), url_key.data(), url_key.size()) == 0 &&
                (existing.find("rel=preconnect") != std::string::npos) == is_preconnect) {
              is_dup = true;
              break;
            }
          }
        }
        if (!is_dup) {
          origin_links.push_back(std::move(seg));
        }
        if (static_cast<int>(origin_links.size()) >= max_links) {
          break;
        }
      }
    }
    if (static_cast<int>(origin_links.size()) >= max_links) {
      break;
    }
  }
  return origin_links;
}

TEST_CASE("Origin-forward dedup: comma-separated duplicate values in one Link field", "[integration][origin_forward][dedup]")
{
  SECTION("two identical comma-separated segments → only one stored")
  {
    // Simulates: Link: </cdn/app.js>; rel=preload; as=script, </cdn/app.js>; rel=preload; as=script
    std::vector<std::string> headers = {"</cdn/app.js>; rel=preload; as=script, "
                                        "</cdn/app.js>; rel=preload; as=script"};
    auto result                      = simulate_origin_forward(headers);
    REQUIRE(result.size() == 1);
    CHECK(result[0].find("/cdn/app.js") != std::string::npos);
    CHECK(result[0].find("rel=preload") != std::string::npos);
  }

  SECTION("three comma-separated identical segments → only one stored")
  {
    std::vector<std::string> headers = {"</cdn/x.js>; rel=preload; as=script, "
                                        "</cdn/x.js>; rel=preload; as=script, "
                                        "</cdn/x.js>; rel=preload; as=script"};
    auto result                      = simulate_origin_forward(headers);
    REQUIRE(result.size() == 1);
  }

  SECTION("two distinct comma-separated values → both stored")
  {
    std::vector<std::string> headers = {"</cdn/app.js>; rel=preload; as=script, "
                                        "</cdn/style.css>; rel=preload; as=style"};
    auto result                      = simulate_origin_forward(headers);
    REQUIRE(result.size() == 2);
  }
}

TEST_CASE("Origin-forward dedup: same URL, different rel types are NOT deduplicated", "[integration][origin_forward][dedup]")
{
  SECTION("preload and preconnect for same URL — both preserved")
  {
    // Origin sends same URL once as preload and once as preconnect.
    // rel types differ → dedup must NOT fire → both entries kept.
    std::vector<std::string> headers = {
      "</cdn/app.js>; rel=preload; as=script",
      "</cdn/app.js>; rel=preconnect",
    };
    auto result = simulate_origin_forward(headers);
    REQUIRE(result.size() == 2);
    bool has_preload = false, has_preconnect = false;
    for (const auto &l : result) {
      if (l.find("rel=preload") != std::string::npos) {
        has_preload = true;
      }
      if (l.find("rel=preconnect") != std::string::npos) {
        has_preconnect = true;
      }
    }
    CHECK(has_preload);
    CHECK(has_preconnect);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Origin-forward dedup tautological comparison tests
//
// Bug in dedup_link_segments() (link_parser.cc), mirroring early_hints.cc:
//   bool is_preconnect = seg.find("rel=preconnect") != std::string::npos;
//   for (const auto &existing : result) {
//     if (url_match && (seg.find("rel=preconnect") != npos) == is_preconnect)
//
// The inner condition is (is_preconnect == is_preconnect) — ALWAYS TRUE.
// This means: if origin sends preload + preconnect for the same URL, the
// second entry is always incorrectly flagged as duplicate and dropped.
//
// Fix: change seg.find → existing.find in the inner comparison.
//
// These tests call dedup_link_segments() DIRECTLY (production code in
// link_parser.cc) — NOT a test helper. RED before fix, GREEN after fix.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("dedup_link_segments() tautological comparison drops different-rel entries", "[integration][dedup]")
{
  SECTION("BUG: preload then preconnect for same URL — preconnect incorrectly dropped")
  {
    // origin sends: preload first, then preconnect for same URL.
    // Correct dedup: different rel types → both preserved → size == 2.
    // Buggy dedup:  tautological condition always true → preconnect dropped → size == 1.
    std::vector<std::string> segs = {
      "</cdn/app.js>; rel=preload; as=script",
      "</cdn/app.js>; rel=preconnect",
    };
    auto result = dedup_link_segments(segs, 10);
    // RED before fix: dedup_link_segments has seg.find bug → result.size() == 1, CHECK fails
    // GREEN after fix: existing.find used → result.size() == 2, CHECK passes
    CHECK(result.size() == 2);
  }

  SECTION("BUG: preconnect then preload for same URL — preload incorrectly dropped")
  {
    std::vector<std::string> segs = {
      "</cdn/lib.css>; rel=preconnect",
      "</cdn/lib.css>; rel=preload; as=style",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2); // RED before fix, GREEN after
  }

  SECTION("CORRECT dedup: two identical preload entries — second must be dropped")
  {
    std::vector<std::string> segs = {
      "</cdn/app.js>; rel=preload; as=script",
      "</cdn/app.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1); // always correct — same-type dedup works in both versions
  }

  SECTION("CORRECT dedup: two identical preconnect entries — second must be dropped")
  {
    std::vector<std::string> segs = {
      "</cdn/app.js>; rel=preconnect",
      "</cdn/app.js>; rel=preconnect",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 1);
  }

  SECTION("Different URLs — no dedup regardless of rel type")
  {
    std::vector<std::string> segs = {
      "</cdn/app.js>; rel=preload; as=script",
      "</cdn/lib.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 10);
    CHECK(result.size() == 2);
  }

  SECTION("max_links cap respected during dedup")
  {
    std::vector<std::string> segs = {
      "</a.js>; rel=preload; as=script",
      "</b.js>; rel=preload; as=script",
      "</c.js>; rel=preload; as=script",
    };
    auto result = dedup_link_segments(segs, 2);
    CHECK(result.size() == 2);
  }
}
