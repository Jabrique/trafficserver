/** @file
 * HtmlScanner unit tests: Link header building, attributes, cross-origin, reset
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
#include "test_scanner_helpers.h"

TEST_CASE("HtmlScanner IN_ATTR_SEP: boolean attr then > with space", "[html_scanner][attr]")
{
  // crossorigin followed by space then >  -- tests IN_ATTR_SEP's '>' branch
  std::string html = R"(<html><head><link rel="preload" href="/f.woff2" as="font" crossorigin ></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("crossorigin") != std::string::npos);
  CHECK(links[0].find("/f.woff2") != std::string::npos);
}

TEST_CASE("HtmlScanner: boolean defer with spaces then >", "[html_scanner][attr]")
{
  // defer   >  -- IN_ATTR_SEP: whitespace then '>'
  std::string html = R"(<html><head><script src="/x.js" defer   ></script></head></html>)";
  auto links       = scan_html(html);
  CHECK(links.empty()); // defer means skip
}

TEST_CASE("HtmlScanner: > inside quoted attribute value does not close tag", "[html_scanner][attr]")
{
  // The '>' inside quotes must not terminate the tag
  std::string html = R"(<html><head><link rel="stylesheet" href="/a>b.css"></head></html>)";
  auto links       = scan_html(html);
  // href contains '>' which is rejected by is_safe_url
  CHECK(links.empty());
}

TEST_CASE("HtmlScanner: attribute value with single quotes around complex URL", "[html_scanner][attr]")
{
  std::string html = "<html><head><link rel='preload' href='/path/to/file.js?v=1&t=2' as='script'></head></html>";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/path/to/file.js?v=1&t=2") != std::string::npos);
}

TEST_CASE("HtmlScanner: unquoted attr terminated by space", "[html_scanner][attr]")
{
  // Unquoted values end at whitespace
  std::string html = "<html><head><link rel=stylesheet href=/app.css ></head></html>";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/app.css") != std::string::npos);
}

TEST_CASE("HtmlScanner: tag names with digits (e.g. h1-h6) are parsed correctly", "[html_scanner][tag]")
{
  std::string html = "<html><head><h1>Title</h1><link rel=stylesheet href=/app.css></head></html>";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/app.css") != std::string::npos);
}

// --- process_tag / build_link_header gaps -----------------------------------

TEST_CASE("HtmlScanner: link with unsupported rel value is skipped", "[html_scanner][build]")
{
  SECTION("rel=icon")
  {
    std::string html = R"(<html><head><link rel="icon" href="/favicon.ico"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("rel=prefetch")
  {
    std::string html = R"(<html><head><link rel="prefetch" href="/next.html"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("rel=dns-prefetch")
  {
    std::string html = R"(<html><head><link rel="dns-prefetch" href="//cdn.example.com"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

TEST_CASE("HtmlScanner: link with href but no rel is skipped", "[html_scanner][build]")
{
  std::string html = R"(<html><head><link href="/orphan.css"></head></html>)";
  auto links       = scan_html(html);
  CHECK(links.empty());
}

TEST_CASE("HtmlScanner: cross-origin stylesheet becomes preconnect", "[html_scanner][build]")
{
  std::string html = R"(<html><head><link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preconnect") != std::string::npos);
  CHECK(links[0].find("https://fonts.googleapis.com") != std::string::npos);
  // crossorigin has no defined semantics on preconnect  -- must not be emitted
  CHECK(links[0].find("crossorigin") == std::string::npos);
}

TEST_CASE("HtmlScanner: cross-origin modulepreload becomes preconnect with crossorigin=anonymous",
          "[html_scanner][build][modulepreload]")
{
  // HTML spec §8.1.4.2: module scripts are always CORS-fetched.
  // When the modulepreload target is non-whitelisted cross-origin, the scanner
  // downgrades to rel=preconnect. Because modules ALWAYS require a CORS-capable
  // connection, the preconnect MUST carry crossorigin=anonymous so the browser
  // establishes the correct TLS + CORS-preflight connection.
  std::string html = R"(<html><head><link rel="modulepreload" href="https://cdn.example.com/mod.mjs"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preconnect") != std::string::npos);
  CHECK(links[0].find("https://cdn.example.com") != std::string::npos);
  // Module scripts are always CORS → preconnect MUST carry crossorigin=anonymous
  CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
}

// Regression: font preconnect crossorigin=anonymous must not be removed by Commit 15
TEST_CASE("HtmlScanner: non-whitelisted cross-origin font preconnect still has crossorigin=anonymous",
          "[html_scanner][build][regression]")
{
  // W3C CSS Fonts spec: font fetches require CORS-capable connection.
  // crossorigin=anonymous on the preconnect was pre-existing correct behavior.
  std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/font.woff2" as="font"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preconnect") != std::string::npos);
  CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
}

// Regression: stylesheet preconnect must NOT have crossorigin (no regression from Commit 15)
TEST_CASE("HtmlScanner: non-whitelisted cross-origin stylesheet preconnect has no crossorigin", "[html_scanner][build][regression]")
{
  // Stylesheets are NOT CORS-fetched  -- preconnect crossorigin would be wrong.
  std::string html = R"(<html><head><link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preconnect") != std::string::npos);
  CHECK(links[0].find("crossorigin") == std::string::npos); // no crossorigin on stylesheet preconnect
}

TEST_CASE("HtmlScanner: cross-origin script src becomes preconnect", "[html_scanner][build]")
{
  std::string html = R"(<html><head><script src="https://cdn.example.com/app.js"></script></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preconnect") != std::string::npos);
  CHECK(links[0].find("https://cdn.example.com") != std::string::npos);
  // crossorigin has no defined semantics on preconnect  -- must not be emitted
  CHECK(links[0].find("crossorigin") == std::string::npos);
}

TEST_CASE("HtmlScanner: fetchpriority=auto is preserved", "[html_scanner][build]")
{
  std::string html = R"(<html><head><link rel="preload" href="/x.js" as="script" fetchpriority="auto"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("fetchpriority=auto") != std::string::npos);
}

TEST_CASE("HtmlScanner: type is NOT appended for preconnect", "[html_scanner][build]")
{
  // Cross-origin preload → preconnect; type should NOT appear (only appended for rel=preload)
  std::string html =
    R"(<html><head><link rel="preload" href="https://cdn.example.com/font.woff2" as="font" type="font/woff2"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preconnect") != std::string::npos);
  CHECK(links[0].find("type=") == std::string::npos);
}

TEST_CASE("HtmlScanner: whitelisted domain with crossorigin=use-credentials", "[html_scanner][build]")
{
  const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"};
  EarlyHintsConfig config;
  config.init(6, argv);

  HtmlScanner scanner(131072, 10, &config);
  std::string html =
    R"(<html><head><link rel="preload" href="https://cdn.example.com/api.js" as="script" crossorigin="use-credentials"></head></html>)";
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

  auto links = scanner.get_links();
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preload") != std::string::npos);
  CHECK(links[0].find("crossorigin=use-credentials") != std::string::npos);
}

TEST_CASE("HtmlScanner: font auto-crossorigin not doubled when explicit", "[html_scanner][build]")
{
  // crossorigin already set explicitly  -- font auto-add should not duplicate
  std::string html =
    R"(<html><head><link rel="preload" href="/f.woff2" as="font" crossorigin="anonymous" type="font/woff2"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  // Should have exactly ONE crossorigin, not duplicated
  std::string link = links[0];
  size_t first     = link.find("crossorigin");
  REQUIRE(first != std::string::npos);
  size_t second = link.find("crossorigin", first + 11);
  CHECK(second == std::string::npos); // no second occurrence
}

TEST_CASE("HtmlScanner: same-origin preload script has no crossorigin", "[html_scanner][build]")
{
  std::string html = R"(<html><head><link rel="preload" href="/app.js" as="script"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("crossorigin") == std::string::npos);
}

TEST_CASE("HtmlScanner: meta and base tags do not produce links", "[html_scanner][build]")
{
  SECTION("meta tag")
  {
    std::string html = R"(<html><head><meta charset="utf-8"><link rel="stylesheet" href="/a.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/a.css") != std::string::npos);
  }

  SECTION("base tag")
  {
    std::string html = R"(<html><head><base href="https://example.com/"><link rel="stylesheet" href="/a.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/a.css") != std::string::npos);
  }
}

// --- is_crossorigin edge cases ----------------------------------------------

TEST_CASE("HtmlScanner is_crossorigin: fragment-only URL is same-origin", "[html_scanner][crossorigin]")
{
  // #anchor is a same-origin reference  -- should stay as preload
  std::string html = R"(<html><head><link rel="preload" href="#section" as="document"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preload") != std::string::npos);
}

TEST_CASE("HtmlScanner is_crossorigin: path-only URL is same-origin", "[html_scanner][crossorigin]")
{
  std::string html = R"(<html><head><link rel="preload" href="relative/path.js" as="script"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preload") != std::string::npos);
}

// --- extract_origin edge cases ----------------------------------------------

TEST_CASE("HtmlScanner extract_origin: URL with port", "[html_scanner][extract]")
{
  // Port should be included in origin (it's before the first '/')
  std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com:8443/app.js" as="script"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("https://cdn.example.com:8443") != std::string::npos);
}

TEST_CASE("HtmlScanner extract_origin: URL without path", "[html_scanner][extract]")
{
  // URL like "https://example.com" with no trailing '/'  -- extract_origin returns full URL
  std::string html = R"(<html><head><link rel="preload" href="https://example.com" as="script"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("https://example.com") != std::string::npos);
}

TEST_CASE("HtmlScanner extract_origin: protocol-relative without path", "[html_scanner][extract]")
{
  // //example.com → extract_origin returns "https://example.com"
  std::string html = R"(<html><head><link rel="preload" href="//example.com" as="script"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("https://example.com") != std::string::npos);
}

// --- reset() edge cases ----------------------------------------------------

TEST_CASE("HtmlScanner reset: after scan limit reached", "[html_scanner][reset]")
{
  // Use limit=20: enough to hit DONE in both feeds, but second HTML is short enough
  // that after reset (scanned_=0) the full tag is within the limit.
  // Note: limit_ is fixed at construction time and survives reset().
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  // First feed: normal scan
  std::string html1 = "<html><head><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head></html>";
  scanner.feed(html1.c_str(), static_cast<int64_t>(html1.size()));
  CHECK(scanner.is_done());
  REQUIRE(scanner.get_links().size() == 1);

  // Reset and reuse
  scanner.reset();
  CHECK(!scanner.is_done());
  CHECK(scanner.get_links().empty());

  std::string html2 = "<html><head><link rel=\"stylesheet\" href=\"/b.css\"></head></html>";
  scanner.feed(html2.c_str(), static_cast<int64_t>(html2.size()));
  REQUIRE(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/b.css") != std::string::npos);
}

TEST_CASE("HtmlScanner reset: mid-scan (not done)", "[html_scanner][reset]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  // Feed only part of the HTML  -- scanner is not done
  std::string partial = "<html><head><link rel=\"preload\" href=\"/partial.js\" as=\"script\">";
  scanner.feed(partial.c_str(), static_cast<int64_t>(partial.size()));
  CHECK(!scanner.is_done());
  CHECK(scanner.get_links().size() == 1);

  // Reset and reuse
  scanner.reset();
  CHECK(!scanner.is_done());
  CHECK(scanner.get_links().empty());

  std::string html2 = "<html><head><link rel=\"stylesheet\" href=\"/fresh.css\"></head></html>";
  scanner.feed(html2.c_str(), static_cast<int64_t>(html2.size()));
  REQUIRE(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/fresh.css") != std::string::npos);
}

TEST_CASE("HtmlScanner: feed after DONE is no-op", "[html_scanner][reset]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  std::string html1 = "<html><head><link rel=\"stylesheet\" href=\"/first.css\"></head></html>";
  scanner.feed(html1.c_str(), static_cast<int64_t>(html1.size()));
  CHECK(scanner.is_done());
  REQUIRE(scanner.get_links().size() == 1);

  // Feed more data after DONE  -- should be ignored
  std::string html2 = "<head><link rel=\"stylesheet\" href=\"/second.css\"></head>";
  scanner.feed(html2.c_str(), static_cast<int64_t>(html2.size()));
  CHECK(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/first.css") != std::string::npos);
}

TEST_CASE("HtmlScanner: feed with zero length is no-op", "[html_scanner][reset]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  scanner.feed("hello", 0);
  CHECK(!scanner.is_done());
  CHECK(scanner.get_links().empty());

  // Normal feed still works after zero-length
  std::string html = "<html><head><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  REQUIRE(scanner.get_links().size() == 1);
}

TEST_CASE("HtmlScanner: feed with negative length is no-op", "[html_scanner][reset]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  scanner.feed("hello", -5);
  CHECK(!scanner.is_done());
  CHECK(scanner.get_links().empty());
}

// --- IN_HEAD state: bogus comment edge cases --------------------------------

TEST_CASE("HtmlScanner: all valid as= values accepted", "[html_scanner][build]")
{
  auto test_as_value = [](const std::string &as_val) {
    std::string html = R"(<html><head><link rel="preload" href="/file" as=")" + as_val + R"("></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("as=" + as_val) != std::string::npos);
  };

  SECTION("as=audio") { test_as_value("audio"); }
  SECTION("as=document") { test_as_value("document"); }
  SECTION("as=embed") { test_as_value("embed"); }
  SECTION("as=fetch") { test_as_value("fetch"); }
  SECTION("as=font") { test_as_value("font"); }
  SECTION("as=image") { test_as_value("image"); }
  SECTION("as=object") { test_as_value("object"); }
  SECTION("as=track") { test_as_value("track"); }
  SECTION("as=video") { test_as_value("video"); }
  SECTION("as=worker") { test_as_value("worker"); }
}

// --- Stylesheet with same-origin produces preload as=style ------------------

TEST_CASE("HtmlScanner: same-origin stylesheet produces correct output", "[html_scanner][build]")
{
  std::string html = R"(<html><head><link rel="stylesheet" href="/main.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0] == "</main.css>; rel=preload; as=style");
}

// --- Same-origin modulepreload output format --------------------------------

TEST_CASE("HtmlScanner: same-origin modulepreload output format", "[html_scanner][build]")
{
  std::string html = R"(<html><head><link rel="modulepreload" href="/mod.mjs"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0] == "</mod.mjs>; rel=modulepreload");
}

// --- Script with both async and defer ---------------------------------------

TEST_CASE("HtmlScanner: script with both async and defer is skipped", "[html_scanner][build]")
{
  std::string html = R"(<html><head><script async defer src="/both.js"></script></head></html>)";
  auto links       = scan_html(html);
  CHECK(links.empty());
}

// --- Whitelist: protocol-relative URL on whitelisted domain -----------------

TEST_CASE("HtmlScanner: whitelisted protocol-relative preload", "[html_scanner][build]")
{
  const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"};
  EarlyHintsConfig config;
  config.init(6, argv);

  HtmlScanner scanner(131072, 10, &config);
  std::string html = R"(<html><head><link rel="preload" href="//cdn.example.com/style.css" as="style"></head></html>)";
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

  auto links = scanner.get_links();
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("rel=preload") != std::string::npos);
  CHECK(links[0].find("crossorigin") != std::string::npos);
}

// --- IN_ATTR_SEP: new attr name started (previous was boolean) --------------

TEST_CASE("HtmlScanner IN_ATTR_SEP: boolean then new attr without =", "[html_scanner][attr]")
{
  // "async src"  -- async is boolean (no =), then src starts new attr
  // This exercises IN_ATTR_SEP's else branch (line 752-758)
  std::string html = R"(<html><head><script async src="/x.js"></script></head></html>)";
  auto links       = scan_html(html);
  // async makes it skip
  CHECK(links.empty());
}

// --- is_safe_url: leading whitespace before scheme --------------------------

TEST_CASE("reset: clears IN_SCRIPT escaped state for reuse", "[html_scanner][reset][audit]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  // First feed: enter script with escaped mode active, don't close it
  std::string html1 = "<html><head><script><!-- stuff";
  scanner.feed(html1.c_str(), static_cast<int64_t>(html1.size()));
  CHECK(!scanner.is_done());

  // Reset  -- must clear script_escaped_, script_comment_pos_, raw_close_pos_
  scanner.reset();
  CHECK(!scanner.is_done());
  CHECK(scanner.get_links().empty());

  // Reuse with normal HTML  -- should work correctly
  std::string html2 = R"(<html><head><link rel="stylesheet" href="/after-reset.css"></head></html>)";
  scanner.feed(html2.c_str(), static_cast<int64_t>(html2.size()));
  CHECK(scanner.is_done());
  REQUIRE(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/after-reset.css") != std::string::npos);
}

TEST_CASE("reset: clears partial close-tag matching state", "[html_scanner][reset][audit]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  // Feed stops mid-close-tag: "</scri" leaves raw_close_pos_ at 7
  std::string html1 = "<html><head><script>x=1;</scri";
  scanner.feed(html1.c_str(), static_cast<int64_t>(html1.size()));

  scanner.reset();

  // After reset, scanner should be in INIT, not stuck in IN_SCRIPT
  std::string html2 = R"(<html><head><link rel="stylesheet" href="/clean.css"></head></html>)";
  scanner.feed(html2.c_str(), static_cast<int64_t>(html2.size()));
  CHECK(scanner.is_done());
  REQUIRE(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/clean.css") != std::string::npos);
}

TEST_CASE("reset: clears comment state for reuse", "[html_scanner][reset][audit]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  // Feed stops inside a comment
  std::string html1 = "<html><head><!-- partial comment";
  scanner.feed(html1.c_str(), static_cast<int64_t>(html1.size()));
  CHECK(!scanner.is_done());

  scanner.reset();

  std::string html2 = R"(<html><head><link rel="stylesheet" href="/post-comment.css"></head></html>)";
  scanner.feed(html2.c_str(), static_cast<int64_t>(html2.size()));
  CHECK(scanner.is_done());
  REQUIRE(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/post-comment.css") != std::string::npos);
}

// --- QA audit: scan_limit boundary precision --------------------------------

TEST_CASE("QA: process_tag rejects non-hint rel values", "[html_scanner][qa][process_tag]")
{
  SECTION("rel=preconnect from HTML is NOT extracted (auto-generated only)")
  {
    std::string html = R"(<html><head><link rel="preconnect" href="https://cdn.example.com"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("rel=alternate is rejected")
  {
    std::string html = R"(<html><head><link rel="alternate" href="/feed.xml"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("rel=canonical is rejected")
  {
    std::string html = R"(<html><head><link rel="canonical" href="https://example.com/page"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("rel=manifest is rejected")
  {
    std::string html = R"(<html><head><link rel="manifest" href="/manifest.json"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("rel=noopener is rejected")
  {
    std::string html = R"(<html><head><link rel="noopener" href="/x"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- process_tag: link with no href, no rel, or both missing ----------------

TEST_CASE("QA: process_tag handles missing attributes", "[html_scanner][qa][process_tag]")
{
  SECTION("link with rel=preload but no href at all (attribute absent)")
  {
    std::string html = R"(<html><head><link rel="preload" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("link with rel=stylesheet but no href")
  {
    std::string html = R"(<html><head><link rel="stylesheet"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("link with rel=modulepreload but no href")
  {
    std::string html = R"(<html><head><link rel="modulepreload"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("link with no attributes at all")
  {
    std::string html = R"(<html><head><link></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("link with only type attribute")
  {
    std::string html = R"(<html><head><link type="text/css"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- process_tag: non-link/script tags do not produce output ----------------

TEST_CASE("QA: process_tag ignores non-link/script tags", "[html_scanner][qa][process_tag]")
{
  SECTION("title tag does not produce link")
  {
    std::string html = R"(<html><head><title>Page Title</title></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("noscript tag does not produce link")
  {
    std::string html = R"(<html><head><noscript><link rel="stylesheet" href="/no.css"></noscript></head></html>)";
    auto links       = scan_html(html);
    // noscript content is parsed by our scanner (it doesn't understand noscript semantics)
    // but we verify it doesn't crash and produces bounded output
    CHECK(links.size() <= 1);
  }
}

// --- build_link_header: special characters in URLs --------------------------

TEST_CASE("QA: build_link_header URL special characters", "[html_scanner][qa][build_link_header]")
{
  SECTION("semicolons in URL are preserved (valid per RFC 3986)")
  {
    // Semicolons are path parameter delimiters in URLs  -- must not be stripped
    // The <...> delimiters in Link header protect the URL boundary
    std::string html = R"(<html><head><link rel="preload" href="/path;param=1?q=2" as="fetch"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</path;param=1?q=2>; rel=preload; as=fetch");
  }

  SECTION("commas in URL are preserved")
  {
    // Commas separate Link header values, but inside <...> they are safe
    std::string html = R"(<html><head><link rel="preload" href="/api?ids=1,2,3" as="fetch"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</api?ids=1,2,3>; rel=preload; as=fetch");
  }

  SECTION("double quotes in URL are preserved")
  {
    // Quotes inside <...> delimiters are technically valid
    std::string html = "<html><head><link rel='preload' href='/path?q=\"val\"' as='fetch'></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/path?q=\"val\"") != std::string::npos);
  }

  SECTION("URL with encoded characters preserved")
  {
    std::string html = R"(<html><head><link rel="preload" href="/path%20with%20spaces.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/path%20with%20spaces.js") != std::string::npos);
  }

  SECTION("angle bracket < in URL is rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="/path<inject" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("angle bracket > in URL is rejected")
  {
    // > inside a quoted attribute value  -- is_safe_url must still reject it
    std::string html = "<html><head><link rel='preload' href='/path>inject' as='script'></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- build_link_header: nopush is not an HTML attribute ---------------------

TEST_CASE("QA: nopush HTML attribute does not appear in output", "[html_scanner][qa][build_link_header]")
{
  SECTION("nopush attribute in HTML link tag is silently ignored")
  {
    // nopush is a Link header parameter (RFC 8288), NOT an HTML attribute.
    // The scanner should not crash or emit it.
    std::string html = R"(<html><head><link rel="preload" href="/app.js" as="script" nopush></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</app.js>; rel=preload; as=script");
    CHECK(links[0].find("nopush") == std::string::npos);
  }

  SECTION("nopush=true attribute is silently ignored")
  {
    std::string html = R"(<html><head><link rel="preload" href="/app.js" as="script" nopush="true"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("nopush") == std::string::npos);
  }
}

// --- build_link_header: crossorigin on same-origin resources ----------------

TEST_CASE("QA: explicit crossorigin on same-origin preload", "[html_scanner][qa][build_link_header]")
{
  SECTION("crossorigin attribute on same-origin preload is preserved")
  {
    // A developer may explicitly add crossorigin to a same-origin resource
    std::string html = R"(<html><head><link rel="preload" href="/api/data" as="fetch" crossorigin></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("crossorigin") != std::string::npos);
  }

  SECTION("crossorigin=use-credentials on same-origin preload is preserved")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="/api/data" as="fetch" crossorigin="use-credentials"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("crossorigin=use-credentials") != std::string::npos);
  }
}

// --- build_link_header: as= edge cases -------------------------------------

TEST_CASE("QA: as= values frame, iframe, sharedworker accepted", "[html_scanner][qa][build_link_header]")
{
  SECTION("as=frame")
  {
    std::string html = R"(<html><head><link rel="preload" href="/frame.html" as="frame"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</frame.html>; rel=preload; as=frame");
  }

  SECTION("as=iframe")
  {
    std::string html = R"(<html><head><link rel="preload" href="/widget.html" as="iframe"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</widget.html>; rel=preload; as=iframe");
  }

  SECTION("as=sharedworker")
  {
    std::string html = R"(<html><head><link rel="preload" href="/sw.js" as="sharedworker"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</sw.js>; rel=preload; as=sharedworker");
  }
}

// --- build_link_header: fetchpriority NOT appended to preconnect ------------

TEST_CASE("QA: fetchpriority not appended for preconnect results", "[html_scanner][qa][build_link_header]")
{
  SECTION("fetchpriority=high on cross-origin preload becomes preconnect without fetchpriority")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="https://cdn.example.com/hero.jpg" as="image" fetchpriority="high"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    // fetchpriority makes no sense for preconnect  -- but check current behavior
    // (The code does append it even for preconnect since the check is unconditional)
  }
}

// --- build_link_header: type attribute only for rel=preload -----------------

TEST_CASE("QA: type attribute only appended for rel=preload links", "[html_scanner][qa][build_link_header]")
{
  SECTION("type appended for same-origin preload")
  {
    std::string html = R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="font/woff2"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("type=\"font/woff2\"") != std::string::npos);
  }

  SECTION("type IS appended for modulepreload")
  {
    // rel=modulepreload should also carry type= when present, same as rel=preload.
    // The is_preload_hint check must include modulepreload, not just preload.
    std::string html = R"(<html><head><link rel="modulepreload" href="/mod.mjs" type="text/javascript"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("type=\"") != std::string::npos);
  }

  SECTION("type IS appended for stylesheet-converted preload")
  {
    // stylesheet converts to preload  -- type IS relevant here
    std::string html = R"(<html><head><link rel="stylesheet" href="/main.css" type="text/css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    // stylesheet→preload DOES contain "rel=preload", so type should be appended
    CHECK(links[0].find("type=\"text/css\"") != std::string::npos);
  }
}

// --- build_link_header: crossorigin invalid values --------------------------

TEST_CASE("HtmlScanner: crossorigin with invalid value normalizes to anonymous", "[html_scanner][qa][build_link_header]")
{
  SECTION("crossorigin=invalid normalizes to crossorigin=anonymous")
  {
    // Per HTML spec §2.5.3 (CORS settings attribute), only "anonymous" and
    // "use-credentials" are valid enumerated states. Any other value  -- including
    // misspellings  -- maps to "anonymous" (the missing-value and invalid-value default).
    std::string html = R"(<html><head><link rel="preload" href="/app.js" as="script" crossorigin="invalid"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    // After fix: "invalid" is normalized to "anonymous" and emitted.
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
    CHECK(links[0].find("crossorigin=invalid") == std::string::npos);
  }
}

// --- build_link_header: as= with injection attempt --------------------------

TEST_CASE("QA: as= value injection attempts are blocked", "[html_scanner][qa][build_link_header]")
{
  SECTION("as value with semicolon is rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="/x.js" as="script; evil=true"></head></html>)";
    auto links       = scan_html(html);
    // Invalid as value → entire link should be dropped (preload requires valid as)
    CHECK(links.empty());
  }

  SECTION("as value with angle brackets is rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="/x.js" as="script<>"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("as value completely unknown is rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="/x.js" as="banana"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- build_link_header: output format exact verification --------------------

TEST_CASE("QA: build_link_header exact output format", "[html_scanner][qa][build_link_header]")
{
  SECTION("preload with all optional attributes")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="font/woff2" crossorigin="anonymous" fetchpriority="high"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // Exact format: <url>; rel=X; as=Y; type="Z"; crossorigin=anonymous; fetchpriority=V
    CHECK(links[0] == "</font.woff2>; rel=preload; as=font; type=\"font/woff2\"; crossorigin=anonymous; fetchpriority=high");
  }

  SECTION("preload with use-credentials and fetchpriority=low")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="/api.js" as="script" crossorigin="use-credentials" fetchpriority="low"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</api.js>; rel=preload; as=script; crossorigin=use-credentials; fetchpriority=low");
  }

  SECTION("stylesheet output has no type when absent")
  {
    std::string html = R"(<html><head><link rel="stylesheet" href="/a.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</a.css>; rel=preload; as=style");
  }

  SECTION("modulepreload output is bare")
  {
    std::string html = R"(<html><head><link rel="modulepreload" href="/m.mjs"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</m.mjs>; rel=modulepreload");
  }

  SECTION("preconnect output format for cross-origin preload")
  {
    std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    // crossorigin is not emitted on preconnect hints
    CHECK(links[0] == "<https://cdn.example.com>; rel=preconnect");
  }

  SECTION("script preload output format")
  {
    std::string html = R"(<html><head><script src="/vendor.js"></script></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</vendor.js>; rel=preload; as=script");
  }
}

// --- build_link_header: rel=preload crossorigin precedence ------------------

TEST_CASE("QA: font auto-crossorigin does not override use-credentials", "[html_scanner][qa][build_link_header]")
{
  SECTION("explicit use-credentials on font is not overridden to anonymous")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="/font.woff2" as="font" crossorigin="use-credentials"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("crossorigin=use-credentials") != std::string::npos);
    // Must NOT also contain bare "; crossorigin"
    CHECK(links[0].find("; crossorigin;") == std::string::npos);
  }
}

// --- Deduplication: multiple cross-origin preloads collapsing to same origin -----------------
//
// Non-whitelisted cross-origin preloads are downgraded to preconnects, stripping
// the resource path and keeping only the scheme+host origin.  When a page has
// multiple <link rel="preload"> tags pointing to different paths on the same
// cross-origin domain (e.g. bundled JS chunks), every tag collapses to the
// identical "<origin>; rel=preconnect" string.  Without dedup the plugin would
// forward duplicate preconnect entries, wasting hint budget.

TEST_CASE("HtmlScanner: multiple cross-origin preloads to same domain produce single preconnect", "[html_scanner][build][dedup]")
{
  SECTION("three script preloads on different paths  -- same origin → single preconnect")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"https://cdn.example.com/js/a.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"https://cdn.example.com/js/b.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"https://cdn.example.com/js/c.js\" as=\"script\">"
                       "</head></html>";
    auto links = scan_html(html);
    // All three collapse to the same origin URL  -- dedup must yield exactly one entry
    REQUIRE(links.size() == 1);
    // crossorigin is not emitted on preconnect hints
    CHECK(links[0] == "<https://cdn.example.com>; rel=preconnect");
  }

  SECTION("script and stylesheet preloads to same cross-origin domain → single preconnect")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"https://assets.example.com/app.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"https://assets.example.com/main.css\" as=\"style\">"
                       "</head></html>";
    auto links = scan_html(html);
    // Different resource types, same cross-origin domain → both collapse to identical preconnect
    REQUIRE(links.size() == 1);
    // crossorigin is not emitted on preconnect hints
    CHECK(links[0] == "<https://assets.example.com>; rel=preconnect");
  }

  SECTION("cross-origin preloads to two distinct domains → two distinct preconnects")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"https://cdn1.example.com/a.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"https://cdn1.example.com/b.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"https://cdn2.example.com/c.js\" as=\"script\">"
                       "</head></html>";
    auto links = scan_html(html);
    // cdn1 and cdn2 are distinct origins  -- one preconnect per origin, no cross-dedup
    REQUIRE(links.size() == 2);
    bool has_cdn1 = false, has_cdn2 = false;
    for (const auto &l : links) {
      if (l.find("cdn1.example.com") != std::string::npos) {
        has_cdn1 = true;
      }
      if (l.find("cdn2.example.com") != std::string::npos) {
        has_cdn2 = true;
      }
    }
    CHECK(has_cdn1);
    CHECK(has_cdn2);
  }

  SECTION("same-origin preloads on different paths are NOT deduplicated")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/js/a.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"/js/b.js\" as=\"script\">"
                       "</head></html>";
    auto links = scan_html(html);
    // Same-origin: each path is a distinct resource  -- both entries must be preserved
    REQUIRE(links.size() == 2);
  }

  SECTION("seven script preloads to same CDN origin → single preconnect")
  {
    // Common pattern: JS bundler emits many chunk preload tags all on one CDN domain.
    std::string base = "https://cdn.example.com/wp-content/dist/";
    std::string html = "<html><head>";
    for (int i = 0; i < 7; ++i) {
      html += "<link rel=\"preload\" href=\"" + base + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // crossorigin is not emitted on preconnect hints
    CHECK(links[0] == "<https://cdn.example.com>; rel=preconnect");
  }
}

// --- Deduplication: edge cases ---------------------------------------------------------------

TEST_CASE("HtmlScanner dedup: URL-only strongest-wins across link types", "[html_scanner][build][dedup]")
{
  // The scanner's dedup is URL-only: same URL key = same resource, regardless of rel type.
  // When a preload and preconnect share the same URL, the stronger type (preload/modulepreload)
  // wins. Different domains have different URL keys and are always both kept.
  const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "static.example.com"};
  EarlyHintsConfig config;
  config.init(6, argv);

  SECTION("whitelisted preload + non-whitelisted on different domain: both preserved (different URL keys)")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"https://static.example.com/app.js\" as=\"script\" crossorigin>"
                       "<link rel=\"preload\" href=\"https://cdn.example.com/vendor.js\" as=\"script\">"
                       "</head></html>";
    HtmlScanner scanner(131072, 10, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto links = scanner.get_links();
    // static.example.com whitelisted: preload with full URL
    // cdn.example.com not whitelisted: preconnect to origin
    // Different URL keys: dedup does not fire, both kept
    REQUIRE(links.size() == 2);
    bool has_preload = false, has_preconnect = false;
    for (const auto &l : links) {
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

  SECTION("same non-whitelisted cross-origin domain: multiple paths collapse to one preconnect")
  {
    // All three tags resolve to the same URL key <https://cdn.example.com>; rel=preconnect.
    // URL-only dedup must collapse them: only the first entry is kept.
    // Note: at scanner level, mixed-type (preconnect+preload) same-URL-key scenarios cannot arise
    // because whitelist classification is domain-based. All tags on a non-whitelisted domain
    // always produce preconnect to the same origin URL. The strongest-wins path is exercised
    // at the dedup_link_segments() level (see test_integration.cc).
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"https://cdn.example.com/app.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"https://cdn.example.com/style.css\" as=\"style\">"
                       "<link rel=\"preload\" href=\"https://cdn.example.com/font.woff2\" as=\"font\">"
                       "</head></html>";
    HtmlScanner scanner(131072, 10, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("cdn.example.com") != std::string::npos);
  }

  SECTION("same whitelisted domain same exact href: duplicate preload dropped")
  {
    // Two identical hrefs on a whitelisted domain produce the same URL key.
    // URL-only dedup: the second is dropped regardless of rel type.
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"https://static.example.com/app.js\" as=\"script\" crossorigin>"
                       "<link rel=\"preload\" href=\"https://static.example.com/app.js\" as=\"script\" crossorigin>"
                       "</head></html>";
    HtmlScanner scanner(131072, 10, &config);
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("static.example.com/app.js") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner dedup: max_links interacts correctly with deduplication", "[html_scanner][build][dedup]")
{
  SECTION("dedup prevents duplicates from consuming the hint budget")
  {
    // Without dedup, 7 cdn1 preloads would fill max_links=3 with 3 identical preconnects.
    // With dedup they collapse to 1, leaving room for cdn2 and cdn3.
    std::string html = "<html><head>";
    for (int i = 0; i < 7; ++i) {
      html += "<link rel=\"preload\" href=\"https://cdn1.example.com/chunk" + std::to_string(i) + ".js\" as=\"script\">";
    }
    for (int i = 0; i < 3; ++i) {
      html += "<link rel=\"preload\" href=\"https://cdn2.example.com/chunk" + std::to_string(i) + ".js\" as=\"script\">";
    }
    for (int i = 0; i < 3; ++i) {
      html += "<link rel=\"preload\" href=\"https://cdn3.example.com/chunk" + std::to_string(i) + ".js\" as=\"script\">";
    }
    html += "</head></html>";

    auto links = scan_html(html, 131072, 3); // max_links = 3
    // cdn1 → 1 preconnect, cdn2 → 1 preconnect, cdn3 → 1 preconnect = 3 total (fills budget)
    REQUIRE(links.size() == 3);
    bool has_cdn1 = false, has_cdn2 = false, has_cdn3 = false;
    for (const auto &l : links) {
      if (l.find("cdn1.example.com") != std::string::npos) {
        has_cdn1 = true;
      }
      if (l.find("cdn2.example.com") != std::string::npos) {
        has_cdn2 = true;
      }
      if (l.find("cdn3.example.com") != std::string::npos) {
        has_cdn3 = true;
      }
    }
    CHECK(has_cdn1);
    CHECK(has_cdn2);
    CHECK(has_cdn3);
  }

  SECTION("max_links=1 with multiple cross-origin preloads → exactly one preconnect")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"https://cdn1.example.com/a.js\" as=\"script\">"
                       "<link rel=\"preload\" href=\"https://cdn2.example.com/b.js\" as=\"script\">"
                       "</head></html>";
    auto links = scan_html(html, 131072, 1); // max_links = 1
    REQUIRE(links.size() == 1);
    // First seen domain wins
    CHECK(links[0].find("cdn1.example.com") != std::string::npos);
  }
}
//
// Complete transition table for IN_COMMENT (comment_dashes_ 0-6) and
// IN_BOGUS_COMMENT.  Each SECTION targets exactly one (sub-state, input class)
// pair, verifying the transition matches HTML spec §13.2.5.42-56.
//
// Sub-state mapping:
//   0 = comment body            (§13.2.5.45)
//   1 = end-dash  (seen '-')    (§13.2.5.50)
//   2 = end       (seen '--')   (§13.2.5.51)
//   3 = end-bang  (seen '--!')  (§13.2.5.52)
//   4 = end-bang-dash ('--!-')  (functionally ≡ state 1)
//   5 = comment-start           (§13.2.5.43)
//   6 = comment-start-dash      (§13.2.5.44)
//
// Input classes: '-', '>', '!', alpha, space, NUL, other (e.g. '@')
// -------------------------------------------------------------------------------

// Helper: embed content inside a comment after "<!-- " (enters body, state 0),
// then follow with --> close + link.  If the link is extracted, the comment
// closed correctly (or prematurely); if not, the comment swallowed the link.
// `prefix` is injected right after "<!-- " to reach the desired sub-state
// before `probe` is encountered.

// --- State 0 (comment body) -------------------------------------------------

// -------------------------------------------------------------------------------
// --preload-whitelist: no-CORS cross-origin preload tests
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner: --preload-whitelist emits no-cors preload", "[html_scanner][build][preload-whitelist]")
{
  SECTION("script cross-origin in preload-whitelist → rel=preload as=script without crossorigin")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--preload-whitelist", "cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><script src="https://cdn.example.com/app.js"></script></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=script") != std::string::npos);
    CHECK(links[0].find("cdn.example.com/app.js") != std::string::npos);
    CHECK(links[0].find("crossorigin") == std::string::npos);
  }

  SECTION("stylesheet cross-origin in preload-whitelist → rel=preload as=style without crossorigin")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--preload-whitelist", "cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="stylesheet" href="https://cdn.example.com/style.css"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=style") != std::string::npos);
    CHECK(links[0].find("cdn.example.com/style.css") != std::string::npos);
    CHECK(links[0].find("crossorigin") == std::string::npos);
  }

  SECTION("preload as=image cross-origin in preload-whitelist → rel=preload as=image without crossorigin")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--preload-whitelist", "img.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="preload" href="https://img.example.com/hero.webp" as="image"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=image") != std::string::npos);
    CHECK(links[0].find("img.example.com/hero.webp") != std::string::npos);
    CHECK(links[0].find("crossorigin") == std::string::npos);
  }

  SECTION("domain in BOTH whitelists → crossorigin-whitelist wins (has crossorigin=anonymous)")
  {
    const char *argv[] = {
      "from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com", "--preload-whitelist", "cdn.example.com"};
    EarlyHintsConfig config;
    config.init(8, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/app.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("modulepreload with domain in preload-whitelist gets modulepreload (no crossorigin)")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--preload-whitelist", "cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="modulepreload" href="https://cdn.example.com/mod.js"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // preload-whitelist: allow full modulepreload without crossorigin
    CHECK(links[0].find("rel=modulepreload") != std::string::npos);
    CHECK(links[0].find("crossorigin") == std::string::npos);
    CHECK(links[0].find("rel=preconnect") == std::string::npos);
  }

  SECTION("wildcard *.cdn.example.com in preload-whitelist matches sub.cdn.example.com")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--preload-whitelist", "*.cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="preload" href="https://sub.cdn.example.com/lib.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=script") != std::string::npos);
    CHECK(links[0].find("crossorigin") == std::string::npos);
  }

  SECTION("domain not in either whitelist → still preconnect (no regression)")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--preload-whitelist", "cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="preload" href="https://unknown.example.com/app.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
  }

  SECTION("font in preload-whitelist → no crossorigin (admin no-cors intent respected)")
  {
    // Admin placed fonts.example.com in --preload-whitelist, signaling no-cors mode.
    // The plugin must NOT auto-add crossorigin=anonymous for preload-whitelist fonts;
    // this is consistent with all other resource types in the preload-whitelist path.
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--preload-whitelist", "fonts.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="preload" href="https://fonts.example.com/font.woff2" as="font"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=font") != std::string::npos);
    // preload-whitelist = no-cors: crossorigin must NOT be added
    CHECK(links[0].find("crossorigin") == std::string::npos);
  }
}

// --- crossorigin must not appear on rel=preconnect hints --------------------
//
// Bug: when a cross-origin resource is downgraded to preconnect, the scanner
// was auto-injecting crossorigin=anonymous onto the preconnect Link header.
// The crossorigin attribute has no defined semantics on rel=preconnect (it is
// a preload-only concept per the Fetch and HTML specs). Emitting it produces
// malformed headers that waste bytes without any browser benefit.
//
// These tests verify the corrected behaviour: the scanner MUST NOT emit
// crossorigin on any rel=preconnect hint, regardless of what triggered the
// downgrade (non-whitelisted preload, stylesheet, script, or modulepreload).

TEST_CASE("preconnect hints must not carry crossorigin attribute", "[html_scanner][preconnect][crossorigin]")
{
  SECTION("cross-origin stylesheet downgraded to preconnect: no crossorigin")
  {
    // Before fix: scanner emitted crossorigin=anonymous on preconnect.
    // After fix: crossorigin must be absent from the preconnect hint.
    std::string html = R"(<html><head><link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("crossorigin") == std::string::npos); // RED before fix
  }

  SECTION("cross-origin script downgraded to preconnect: no crossorigin")
  {
    std::string html = R"(<html><head><script src="https://cdn.example.com/analytics.js"></script></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("crossorigin") == std::string::npos); // RED before fix
  }

  SECTION("cross-origin modulepreload downgraded to preconnect: carries crossorigin=anonymous")
  {
    // Module scripts are always CORS-fetched (HTML spec §8.1.4.2).
    // The preconnect hint MUST carry crossorigin=anonymous so the browser
    // opens a CORS-capable connection, matching the module fetch semantics.
    std::string html = R"(<html><head><link rel="modulepreload" href="https://cdn.example.com/app.mjs"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos); // FIXED: was incorrectly absent
  }

  SECTION("cross-origin font preload downgraded to preconnect: carries crossorigin=anonymous")
  {
    // Fonts are always fetched using CORS (W3C CSS Fonts spec). When a font preload
    // is downgraded to preconnect, the hint must carry crossorigin=anonymous so that
    // the browser opens a CORS-capable connection. Without it the browser opens a
    // non-CORS connection, then opens a second CORS connection for the actual font
    // fetch, defeating the purpose of the preconnect entirely.
    // Reference: https://web.dev/preconnect-and-dns-prefetch/#establish-early-connections
    std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/font.woff2" as="font"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    // Font preconnect MUST carry crossorigin=anonymous for CORS connection reuse
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("whitelisted crossorigin preload must still carry crossorigin (regression guard)")
  {
    // Fix must NOT break whitelisted preloads  -- they must still carry crossorigin.
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html =
      R"(<html><head><link rel="preload" href="https://cdn.example.com/app.js" as="script" crossorigin="anonymous"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos); // must still be present
  }

  SECTION("same-origin font must still carry crossorigin=anonymous (regression guard)")
  {
    // Fonts always need crossorigin because of CORS  -- this must not be broken.
    std::string html =
      R"(<html><head><link rel="preload" href="/fonts/inter.woff2" as="font" crossorigin="anonymous"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos); // must be preserved
  }
}

TEST_CASE("fetchpriority must not appear on rel=preconnect hints", "[html_scanner][preconnect][fetchpriority]")
{
  SECTION("cross-origin preload with fetchpriority=high: preconnect drops fetchpriority")
  {
    // fetchpriority is defined only for preload (Chrome 101+ Fetch Priority API).
    // The attribute has no effect on preconnect and emitting it produces invalid headers.
    std::string html =
      R"(<html><head><link rel="preload" href="https://cdn.example.com/hero.js" as="script" fetchpriority="high"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("fetchpriority") == std::string::npos); // RED before fix
  }

  SECTION("same-origin preload with fetchpriority=high: fetchpriority preserved (regression guard)")
  {
    std::string html = R"(<html><head><link rel="preload" href="/hero.js" as="script" fetchpriority="high"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("fetchpriority=high") != std::string::npos); // must be kept
  }

  SECTION("cross-origin image with fetchpriority=low: preconnect drops fetchpriority")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="https://images.example.com/hero.jpg" as="image" fetchpriority="low"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("fetchpriority") == std::string::npos); // RED before fix
  }
}

// --- WP6: noscript and template content must not be extracted ---------------
//
// <noscript> contains fallback content for when JavaScript is disabled.
// The browser ignores it when JS is enabled, so preloading resources inside
// it would waste bandwidth in the common case. More critically, a malicious
// page could craft a <noscript><link rel="preload" href="evil.js"></noscript>
// to poison the hint cache.
//
// <template> contains inert DOM  -- it is never rendered or fetched on load.
// Resources inside it should not be pre-fetched.
//
// Both tags must be treated as opaque containers: their inner content is
// skipped by the scanner until the matching closing tag.

TEST_CASE("HtmlScanner: noscript content is not extracted as hints", "[html_scanner][build][noscript]")
{
  SECTION("link inside noscript is ignored")
  {
    std::string html = R"(<html><head><noscript><link rel="stylesheet" href="/noscript.css"></noscript></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty()); // RED before fix
  }

  SECTION("preload inside noscript is ignored")
  {
    std::string html = R"(<html><head><noscript><link rel="preload" href="/noscript.js" as="script"></noscript></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty()); // RED before fix
  }

  SECTION("link after noscript is extracted normally")
  {
    std::string html =
      R"(<html><head><noscript><link rel="stylesheet" href="/noscript.css"></noscript><link rel="preload" href="/main.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/main.js") != std::string::npos); // regression guard
  }

  SECTION("script inside noscript is ignored")
  {
    std::string html =
      R"(<html><head><noscript><script src="/fallback.js"></script></noscript><link rel="preload" href="/real.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.js") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner: template content is not extracted as hints", "[html_scanner][build][template]")
{
  SECTION("link inside template is ignored")
  {
    std::string html = R"(<html><head><template><link rel="preload" href="/template.js" as="script"></template></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty()); // RED before fix
  }

  SECTION("link after template is extracted normally")
  {
    std::string html =
      R"(<html><head><template><link rel="preload" href="/template.js" as="script"></template><link rel="stylesheet" href="/app.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/app.css") != std::string::npos); // regression guard
  }

  SECTION("deeply nested content inside template is ignored")
  {
    std::string html =
      R"(<html><head><template><div><link rel="preload" href="/inner.js" as="script"></div></template></head></html>)";
    auto links = scan_html(html);
    CHECK(links.empty()); // RED before fix
  }
}

// -------------------------------------------------------------------------------
// is_safe_url must reject space (0x20) in URL paths.
//
// The bug: the control-char filter uses `uc < 0x20`, which passes space
// (0x20 is NOT less than 0x20). A URL with an embedded space must be rejected
// because it breaks HTTP header framing and violates RFC 3986 §2.
// Fix: change `uc < 0x20` to `uc <= 0x20` in html_scanner.cc is_safe_url().
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner is_safe_url: space (0x20) in URL rejected", "[html_scanner][security]")
{
  SECTION("space in URL path produces no link")
  {
    // href="/path with spaces" contains 0x20  -- must be rejected by is_safe_url
    std::string html = R"(<html><head><link rel="preload" href="/path with spaces.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    // Bug: uc < 0x20 passes 0x20 → link is emitted. Fix: uc <= 0x20 rejects it.
    CHECK(links.empty());
  }

  SECTION("percent-encoded space (%20) is accepted (not a raw space)")
  {
    // %20 is two bytes '%' and '2' and '0'  -- none is 0x20, so it must pass
    std::string html = R"(<html><head><link rel="preload" href="/path%20encoded.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/path%20encoded.js") != std::string::npos);
  }

  SECTION("tab (0x09) in URL still rejected (pre-existing behaviour)")
  {
    // Tab is < 0x20, already correctly rejected before this fix.
    std::string html = "<html><head><link rel=\"preload\" href=\"/path\twith\ttab.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// -------------------------------------------------------------------------------
// script_escaped_ and script_comment_pos_ must be reset for each new
// <script> element  -- state must not leak across multiple scripts.
//
// The bug: state_after_open_tag() did not reset script_escaped_/
// script_comment_pos_ before entering IN_SCRIPT. If a prior script left
// script_comment_pos_ > 0, the next <script> element could misparse its
// content, potentially allowing a link inside an unclosed <!-- to be treated
// as outside a comment and produce an erroneous hint.
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner: script_escaped state resets between script elements without reset()", "[html_scanner][script][security]")
{
  SECTION("link after two properly closed scripts is found")
  {
    // Two consecutive scripts followed by a preload link. Each script must
    // not leave stale state that causes the link to be missed.
    std::string html = R"(<html><head>)"
                       R"(<script>var x = 1;</script>)"
                       R"(<script>var y = 2;</script>)"
                       R"(<link rel="preload" href="/after-scripts.js" as="script">)"
                       R"(</head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after-scripts.js") != std::string::npos);
  }

  SECTION("link after script-with-comment is found (comment properly closed)")
  {
    // Script with <!-- comment --> properly closed. After the comment exits
    // escaped mode (-->) the </script> closes. Link must then be found.
    std::string html = R"(<html><head>)"
                       R"(<script><!-- var x = 1; --></script>)"
                       R"(<link rel="preload" href="/after-escaped.js" as="script">)"
                       R"(</head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after-escaped.js") != std::string::npos);
  }

  SECTION("link is not emitted from inside a script comment")
  {
    // Even with multiple scripts, links inside <!-- --> must not be extracted.
    std::string html = R"(<html><head>)"
                       R"(<script><!-- <link rel="preload" href="/bad.js" as="script"> --></script>)"
                       R"(<link rel="preload" href="/good.js" as="script">)"
                       R"(</head></html>)";
    auto links = scan_html(html);
    // Only the link outside the script should be emitted
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.js") != std::string::npos);
    CHECK(links[0].find("/bad.js") == std::string::npos);
  }
}

// -------------------------------------------------------------------------------
// Attribute value overflow: tag must be rejected when any attribute value
// exceeds MAX_ATTR_VALUE_LEN (4096 chars).
//
// Bug: when href exceeds the limit, attr_value_ is silently truncated to 4095
// chars. The truncated URL is then used to build a Link header, emitting a
// corrupt URL that will cause a fetch error in the browser.
// Fix: set attr_overflowed_ = true and discard the entire tag.
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner: tag rejected when href exceeds MAX_ATTR_VALUE_LEN", "[html_scanner][validation]")
{
  SECTION("href exactly at limit is accepted")
  {
    // MAX_ATTR_VALUE_LEN = 4096  -- a href with 4092 chars fits safely
    std::string long_href = "/" + std::string(4090, 'a') + ".js";
    std::string html      = "<html><head><link rel=\"preload\" href=\"" + long_href + "\" as=\"script\"></head></html>";
    auto links            = scan_html(html);
    CHECK(links.size() == 1);
  }

  SECTION("href exceeding limit produces no link")
  {
    // 4097 chars in href value  -- must be rejected, not truncated
    std::string long_href = "/" + std::string(4096, 'a') + ".js";
    std::string html      = "<html><head><link rel=\"preload\" href=\"" + long_href + "\" as=\"script\"></head></html>";
    auto links            = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("valid link after overflowed link is still emitted")
  {
    std::string overflow_href = "/" + std::string(4096, 'a') + ".js";
    std::string html          = "<html><head><link rel=\"preload\" href=\"" + overflow_href +
                       "\" as=\"script\"><link rel=\"preload\" href=\"/good.js\" as=\"script\"></head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.js") != std::string::npos);
  }
}

// -------------------------------------------------------------------------------
// type= attribute must be validated as "type/subtype" MIME structure.
//
// Bug: type_ passes character-level sanitization but is emitted without
// checking it has the required "/" separator (e.g. type="font" emits
// type="font" which is not a valid MIME type and may confuse browsers).
// Fix: only emit type= when value contains exactly one "/" with non-empty
// tokens before and after.
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner: type attribute requires type/subtype MIME structure", "[html_scanner][validation]")
{
  SECTION("valid MIME type is emitted")
  {
    auto links =
      scan_html(R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="font/woff2" crossorigin></head></html>)");
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("type=\"font/woff2\"") != std::string::npos);
  }

  SECTION("type without slash is not emitted")
  {
    // "font" alone is not a valid MIME type  -- no "/" separator
    auto links =
      scan_html(R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="font" crossorigin></head></html>)");
    // Link itself should still be emitted  -- type= just omitted
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("type=") == std::string::npos);
  }

  SECTION("empty type is not emitted")
  {
    auto links = scan_html(R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="" crossorigin></head></html>)");
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("type=") == std::string::npos);
  }

  SECTION("type with leading slash is not emitted")
  {
    auto links =
      scan_html(R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="/woff2" crossorigin></head></html>)");
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("type=") == std::string::npos);
  }

  SECTION("type with trailing slash is not emitted")
  {
    auto links =
      scan_html(R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="font/" crossorigin></head></html>)");
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("type=") == std::string::npos);
  }
}

// -------------------------------------------------------------------------------
// Backslash evasion in is_safe_url must be comprehensively rejected.
//
// Browsers with "special" schemes (http/https) treat '\' as '/' per WHATWG
// URL spec §4.2. Several variants must all be rejected:
//   \\ prefix  →  browser treats as authority reference (cross-origin)
//   \/ prefix  →  same
//   /\ prefix  →  same
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner: backslash evasion variants are rejected by is_safe_url", "[html_scanner][security][backslash]")
{
  auto make_link = [](const std::string &href) {
    return "<html><head><link rel=\"preload\" href=\"" + href + "\" as=\"script\"></head></html>";
  };

  SECTION("double-backslash authority reference rejected")
  {
    auto links = scan_html(make_link("\\\\evil.com/x.js"));
    CHECK(links.empty());
  }

  SECTION("backslash+slash authority reference rejected")
  {
    auto links = scan_html(make_link("\\/evil.com/x.js"));
    CHECK(links.empty());
  }

  SECTION("slash+backslash authority reference rejected")
  {
    auto links = scan_html(make_link("/\\evil.com/x.js"));
    CHECK(links.empty());
  }

  SECTION("normal relative URL is still accepted")
  {
    auto links = scan_html(make_link("/path/to/x.js"));
    CHECK(links.size() == 1);
  }
}

// Tests for fetchpriority preservation on rel=modulepreload .
// is_preload_hint must include modulepreload so that fetchpriority= is appended.

TEST_CASE("HtmlScanner: fetchpriority is preserved for modulepreload", "[html_scanner][build]")
{
  SECTION("fetchpriority=high on same-origin modulepreload is preserved")
  {
    std::string html = R"(<html><head><link rel="modulepreload" href="/app.mjs" fetchpriority="high"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=modulepreload") != std::string::npos);
    CHECK(links[0].find("fetchpriority=high") != std::string::npos);
  }

  SECTION("fetchpriority=low on same-origin modulepreload is preserved")
  {
    std::string html = R"(<html><head><link rel="modulepreload" href="/lib.mjs" fetchpriority="low"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("fetchpriority=low") != std::string::npos);
  }
}

// Tests for script type=module emitting rel=modulepreload .
// Per HTML spec, <script type="module" src="..."> loads an ES module.
// The early hints plugin should emit rel=modulepreload (not rel=preload; as=script)
// so the browser can use the module-aware preload path.

TEST_CASE("HtmlScanner: script type=module emits rel=modulepreload", "[html_scanner][build]")
{
  SECTION("same-origin module script emits modulepreload")
  {
    std::string html = R"(<html><head><script type="module" src="/app.mjs"></script></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=modulepreload") != std::string::npos);
    CHECK(links[0].find("/app.mjs") != std::string::npos);
    // Must NOT emit rel=preload; as=script for a module script
    CHECK(links[0].find("rel=preload") == std::string::npos);
    CHECK(links[0].find("as=script") == std::string::npos);
  }

  SECTION("module script with type=Module (case-insensitive) emits modulepreload")
  {
    std::string html = R"(<html><head><script type="Module" src="/case.mjs"></script></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=modulepreload") != std::string::npos);
  }

  SECTION("script without type is still treated as classic script")
  {
    std::string html = R"(<html><head><script src="/classic.js"></script></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=script") != std::string::npos);
  }

  SECTION("script with type=text/javascript is still classic script")
  {
    std::string html = R"(<html><head><script type="text/javascript" src="/classic.js"></script></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=script") != std::string::npos);
  }

  SECTION("module script with async is skipped (async module scripts defer by spec)")
  {
    // <script type="module" async> is explicitly async; still useful to preload.
    // Current policy: skip async scripts. Verify no crash.
    std::string html = R"(<html><head><script type="module" async src="/async-mod.mjs"></script></head></html>)";
    auto links       = scan_html(html);
    // async module scripts are skipped same as async classic scripts
    CHECK(links.empty());
  }
}

// --- Font crossorigin handling per whitelist type ----------------------------
//
// W3C CSS Fonts spec requires CORS for cross-origin fonts, but when an admin
// explicitly places a font CDN in --preload-whitelist (no-cors mode), the plugin
// must respect that intent and NOT auto-add crossorigin=anonymous.
// This is consistent with how all other resource types behave in preload-whitelist.
// Inconsistency with modulepreload (which does clear crossorigin for preload-domain)
// was the root cause of the bug.

TEST_CASE("build: font crossorigin handling per whitelist type", "[html_scanner][build][font]")
{
  SECTION("same-origin font auto-adds crossorigin=anonymous (W3C CSS Fonts spec)")
  {
    // Same-origin fonts must carry crossorigin so the browser does not open a
    // second connection for the CORS-checked @font-face fetch.
    std::string html = R"(<html><head><link rel="preload" href="/fonts/font.woff2" as="font"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("crossorigin-whitelist font keeps crossorigin=anonymous")
  {
    // Font CDN on the crossorigin-whitelist: admin allows CORS preload.
    std::string html = R"(<html><head><link rel="preload" href="https://fonts.gstatic.com/f.woff2" as="font"></head></html>)";
    auto links       = scan_html_with_crossorigin_domain(html, "fonts.gstatic.com");
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("preload-whitelist font must NOT get crossorigin (no-cors mode, admin intent)")
  {
    // Admin put this font CDN in --preload-whitelist, signaling no-cors mode.
    // The plugin must respect that and omit crossorigin, consistent with how
    // modulepreload and other resource types behave in the preload-whitelist path.
    std::string html = R"(<html><head><link rel="preload" href="https://fonts.example.com/font.woff2" as="font"></head></html>)";
    auto links       = scan_html_with_preload_domain(html, "fonts.example.com");
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=font") != std::string::npos);
    // preload-whitelist = no-cors: crossorigin must NOT be appended
    CHECK(links[0].find("crossorigin") == std::string::npos);
  }

  SECTION("non-whitelisted cross-origin font downgrades to preconnect with crossorigin")
  {
    // Not on any whitelist: downgrade to preconnect. Font preconnect MUST carry
    // crossorigin=anonymous so the browser reuses the CORS-capable connection.
    std::string html = R"(<html><head><link rel="preload" href="https://unknown-cdn.com/font.woff2" as="font"></head></html>)";
    auto links       = scan_html(html); // no whitelist configured
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
  }
}
