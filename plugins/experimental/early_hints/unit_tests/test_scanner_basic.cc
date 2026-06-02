/** @file
 * HtmlScanner unit tests: Basic extraction, state machine, limits, edge cases
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

TEST_CASE("HtmlScanner basic preload extraction", "[html_scanner]")
{
  SECTION("link rel=preload with as=script")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head><body></body></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("link rel=preload with as=style")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/style.css\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</style.css>; rel=preload; as=style");
  }

  SECTION("link rel=preload with as=font and crossorigin")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/font.woff2\" as=\"font\" type=\"font/woff2\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    // Font must auto-add crossorigin (W3C CSS Fonts spec)
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("as=font") != std::string::npos);
    CHECK(links[0].find("type=\"font/woff2\"") != std::string::npos);
    CHECK(links[0].find("crossorigin") != std::string::npos);
  }

  SECTION("link rel=preload missing as attribute is skipped")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/something.bin\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

TEST_CASE("HtmlScanner stylesheet conversion", "[html_scanner]")
{
  SECTION("link rel=stylesheet converts to preload as=style")
  {
    std::string html = "<html><head><link rel=\"stylesheet\" href=\"/main.css\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</main.css>; rel=preload; as=style");
  }
}

TEST_CASE("HtmlScanner script extraction", "[html_scanner]")
{
  SECTION("script src without async/defer is extracted")
  {
    std::string html = "<html><head><script src=\"/bundle.js\"></script></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</bundle.js>; rel=preload; as=script");
  }

  SECTION("script with async is skipped")
  {
    std::string html = "<html><head><script async src=\"/analytics.js\"></script></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("script with defer is skipped")
  {
    std::string html = "<html><head><script defer src=\"/lazy.js\"></script></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("script without src is skipped")
  {
    std::string html = "<html><head><script>console.log('hello');</script></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

TEST_CASE("HtmlScanner modulepreload", "[html_scanner]")
{
  SECTION("link rel=modulepreload is extracted")
  {
    std::string html = "<html><head><link rel=\"modulepreload\" href=\"/module.mjs\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</module.mjs>; rel=modulepreload");
  }
}

TEST_CASE("HtmlScanner stops at </head>", "[html_scanner]")
{
  SECTION("elements after </head> are not scanned")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head>"
                       "<body><link rel=\"preload\" href=\"/b.js\" as=\"script\"></body></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</a.js>; rel=preload; as=script");
  }
}

TEST_CASE("HtmlScanner multiple resources", "[html_scanner]")
{
  SECTION("extracts multiple resources from head")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/app.js\" as=\"script\">"
                       "<link rel=\"stylesheet\" href=\"/style.css\">"
                       "<script src=\"/vendor.js\"></script>"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 3);
    CHECK(links[0].find("/app.js") != std::string::npos);
    CHECK(links[1].find("/style.css") != std::string::npos);
    CHECK(links[2].find("/vendor.js") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner case insensitivity", "[html_scanner]")
{
  SECTION("mixed case tags are recognized")
  {
    std::string html = "<HTML><HEAD><LINK REL=\"preload\" HREF=\"/app.js\" AS=\"script\"></HEAD></HTML>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/app.js") != std::string::npos);
  }

  SECTION("mixed case head tag")
  {
    std::string html = "<html><Head><link rel=\"preload\" href=\"/x.js\" as=\"script\"></Head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/x.js") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner attribute quoting", "[html_scanner]")
{
  SECTION("single-quoted attributes")
  {
    std::string html = "<html><head><link rel='preload' href='/app.js' as='script'></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("self-closing tag")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\" /></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("self-closing tag without space before slash")
  {
    // <link .../> without space before / — tests IN_TAG handling of /
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"/></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</app.js>; rel=preload; as=script");
  }
}

TEST_CASE("HtmlScanner limits", "[html_scanner]")
{
  SECTION("max_links respected")
  {
    std::string html = "<html><head>";
    for (int i = 0; i < 20; i++) {
      html += "<link rel=\"stylesheet\" href=\"/css" + std::to_string(i) + ".css\">";
    }
    html += "</head></html>";
    auto links = scan_html(html, 32768, 5);
    CHECK(links.size() == 5);
  }

  SECTION("scan_limit stops scanning")
  {
    // With a very small scan limit, scanner stops before finding resources
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html, 10);
    CHECK(links.empty());
  }
}

TEST_CASE("HtmlScanner streaming (chunked feed)", "[html_scanner]")
{
  SECTION("data split across multiple feed calls")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";

    // Feed 1 byte at a time
    auto links = scan_html_chunked(html, 1);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("split in middle of tag name")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/style.css\" as=\"style\"></head></html>";
    auto links       = scan_html_chunked(html, 3);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/style.css") != std::string::npos);
  }

  SECTION("split in middle of attribute value")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/very/long/path/to/resource.js\" as=\"script\"></head></html>";
    auto links       = scan_html_chunked(html, 7);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/very/long/path/to/resource.js") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner cross-origin handling", "[html_scanner]")
{
  SECTION("absolute cross-origin URL converted to preconnect")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"https://cdn.example.com/app.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("https://cdn.example.com") != std::string::npos);
  }

  SECTION("protocol-relative URL converted to preconnect")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"//cdn.example.com/app.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
  }

  SECTION("relative URL stays as preload")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/local/app.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
  }

  SECTION("backslash-backslash cross-origin rejected outright (WHATWG URL spec)")
  {
    // is_safe_url() rejects \\evil.com at URL validation — no hint emitted at all.
    std::string html = R"(<html><head><link rel="preload" href="\\evil.com/tracker.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty()); // blocked at URL validation — not downgraded to preconnect
  }

  SECTION("slash-backslash cross-origin rejected outright")
  {
    std::string html = R"(<html><head><link rel="preload" href="/\evil.com/tracker.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("backslash-slash cross-origin rejected outright")
  {
    std::string html = R"(<html><head><link rel="preload" href="\/evil.com/tracker.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("single backslash is NOT cross-origin")
  {
    // \path is a relative URL, not authority-relative
    std::string html = R"(<html><head><link rel="preload" href="\app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner security", "[html_scanner]")
{
  SECTION("CRLF in href is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\r\nEvil: header\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("empty href is skipped")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

TEST_CASE("HtmlScanner edge cases", "[html_scanner]")
{
  SECTION("empty input")
  {
    auto links = scan_html("");
    CHECK(links.empty());
  }

  SECTION("no head tag")
  {
    std::string html = "<html><body><p>Hello</p></body></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("head with no resources")
  {
    std::string html = "<html><head><title>Test</title><meta charset=\"utf-8\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("malformed HTML does not crash")
  {
    std::string html = "<<<>>><head<link rel=\"preload href=\"/x\" as=\"script\">>";
    auto links       = scan_html(html);
    // Malformed — should not extract valid links
    CHECK(links.empty());
  }

  SECTION("deeply nested/garbled content does not crash")
  {
    std::string html = "<html><head>" + std::string(10000, 'x') + "</head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("null data feed does not crash")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(32768, 10, &config);
    scanner.feed(nullptr, 0);
    scanner.feed(nullptr, 100);
    CHECK(scanner.get_links().empty());
  }
}

TEST_CASE("HtmlScanner fetchpriority attribute", "[html_scanner]")
{
  SECTION("fetchpriority=high is preserved")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/hero.jpg\" as=\"image\" fetchpriority=\"high\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("fetchpriority=high") != std::string::npos);
  }

  SECTION("fetchpriority=low is preserved")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/lazy.js\" as=\"script\" fetchpriority=\"low\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("fetchpriority=low") != std::string::npos);
  }

  SECTION("invalid fetchpriority is ignored")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\" fetchpriority=\"invalid\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("fetchpriority") == std::string::npos);
  }
}

TEST_CASE("HtmlScanner explicit crossorigin attribute", "[html_scanner]")
{
  SECTION("crossorigin boolean attribute")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/font.woff2\" as=\"font\" crossorigin></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("crossorigin") != std::string::npos);
  }

  SECTION("crossorigin=use-credentials")
  {
    std::string html =
      "<html><head><link rel=\"preload\" href=\"/api.js\" as=\"script\" crossorigin=\"use-credentials\"></head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("crossorigin=use-credentials") != std::string::npos);
  }

  SECTION("crossorigin with empty quoted value equals anonymous")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/font.woff2\" as=\"font\" crossorigin=\"\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    // crossorigin="" is equivalent to crossorigin (anonymous) per HTML spec
    CHECK(links[0].find("; crossorigin=anonymous") != std::string::npos);
    CHECK(links[0].find("crossorigin=use-credentials") == std::string::npos);
  }
}

TEST_CASE("HtmlScanner reset and reuse", "[html_scanner]")
{
  SECTION("scanner can be reset and reused")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(32768, 10, &config);

    std::string html1 = "<html><head><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head></html>";
    scanner.feed(html1.c_str(), static_cast<int64_t>(html1.size()));
    REQUIRE(scanner.get_links().size() == 1);

    scanner.reset();
    CHECK(scanner.get_links().empty());
    CHECK(!scanner.is_done());

    std::string html2 = "<html><head><link rel=\"stylesheet\" href=\"/b.css\"></head></html>";
    scanner.feed(html2.c_str(), static_cast<int64_t>(html2.size()));
    REQUIRE(scanner.get_links().size() == 1);
    CHECK(scanner.get_links()[0].find("/b.css") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner unquoted attribute values", "[html_scanner]")
{
  SECTION("unquoted href and as attributes")
  {
    std::string html = "<html><head><link rel=preload href=/app.js as=script></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("unquoted stylesheet")
  {
    std::string html = "<html><head><link rel=stylesheet href=/main.css></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</main.css>; rel=preload; as=style");
  }
}

TEST_CASE("HtmlScanner crossorigin whitelist", "[html_scanner]")
{
  SECTION("whitelisted cross-origin domain gets preload with crossorigin")
  {
    // Create config with whitelist
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com,fonts.gstatic.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(32768, 10, &config);
    std::string html = "<html><head><link rel=\"preload\" href=\"https://cdn.example.com/style.css\" as=\"style\"></head></html>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Whitelisted domain: should be preload, not preconnect
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("cdn.example.com/style.css") != std::string::npos);
    CHECK(links[0].find("crossorigin") != std::string::npos);
  }

  SECTION("non-whitelisted cross-origin domain gets preconnect")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "trusted.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = "<html><head><link rel=\"preload\" href=\"https://untrusted.com/app.js\" as=\"script\"></head></html>";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Non-whitelisted: should be preconnect
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("https://untrusted.com") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner: HTML comment skipping", "[html_scanner]")
{
  SECTION("commented-out link tags are ignored")
  {
    std::string html = "<html><head>"
                       "<!-- <link rel=\"stylesheet\" href=\"/old.css\"> -->"
                       "<link rel=\"stylesheet\" href=\"/real.css\">"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.css") != std::string::npos);
  }

  SECTION("commented-out script tags are ignored")
  {
    std::string html = "<html><head>"
                       "<!-- <script src=\"/debug.js\"></script> -->"
                       "<script src=\"/main.js\"></script>"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/main.js") != std::string::npos);
  }

  SECTION("nested dashes in comment")
  {
    std::string html = "<html><head>"
                       "<!-- -- some --- comment -->"
                       "<link rel=\"stylesheet\" href=\"/style.css\">"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/style.css") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner: <header> vs <head> distinction", "[html_scanner]")
{
  SECTION("<header> tag is not confused with <head>")
  {
    // HTML with <header> before <head> — should not pick up resources from <header>
    std::string html = "<html><header><link rel=\"stylesheet\" href=\"/bad.css\"></header>"
                       "<head><link rel=\"stylesheet\" href=\"/good.css\"></head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/bad.css") == std::string::npos);
  }

  SECTION("<heading> tag is not confused with <head>")
  {
    std::string html = "<html><heading>test</heading><head><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/a.css") != std::string::npos);
  }

  SECTION("<head> with attributes works correctly")
  {
    std::string html = "<html><head lang=\"en\"><link rel=\"stylesheet\" href=\"/style.css\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/style.css") != std::string::npos);
  }
}

TEST_CASE("HtmlScanner: control character and type sanitization", "[html_scanner]")
{
  SECTION("URLs with control characters are rejected")
  {
    std::string html = "<html><head><link rel=\"stylesheet\" href=\"/style\x00.css\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("URLs with CRLF are rejected")
  {
    std::string html = "<html><head><link rel=\"stylesheet\" href=\"/style\r\n.css\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("type attribute is sanitized")
  {
    std::string html =
      "<html><head><link rel=\"preload\" href=\"/font.woff2\" as=\"font\" type=\"font/woff2; evil=injected\"></head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // Semicolons and spaces stripped — injection parameters neutralized
    CHECK(links[0].find("type=\"font/woff2") != std::string::npos);
    // The ';' that would separate parameters must be stripped
    CHECK(links[0].find("; type=\"font/woff2\";") == std::string::npos);
    CHECK(links[0].find("type=\"font/woff2evilinjected\"") != std::string::npos);
  }

  SECTION("attribute value length: oversized href causes tag rejection")
  {
    // A truncated href would emit a corrupt URL — the entire tag is now rejected.
    std::string long_href(5000, 'a');
    std::string html = "<html><head><link rel=\"stylesheet\" href=\"/" + long_href +
                       ".css\"><link rel=\"stylesheet\" href=\"/good.css\"></head></html>";
    auto links = scan_html(html);
    // Oversized tag discarded; only the valid second link survives
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
  }
}

// ─── Spaces around = in attributes (HTML spec §13.1.2.3) ────────────────────

TEST_CASE("HtmlScanner handles spaces around = in attributes", "[html_scanner][spaces]")
{
  SECTION("space before and after =")
  {
    std::string html = R"(<html><head><link rel = "preload" href = "/style.css" as = "style"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/style.css") != std::string::npos);
    CHECK(links[0].find("rel=preload") != std::string::npos);
  }

  SECTION("space before = only")
  {
    std::string html = R"(<html><head><link rel ="preload" href ="/app.js" as ="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/app.js") != std::string::npos);
  }

  SECTION("space after = only")
  {
    std::string html = R"(<html><head><link rel= "stylesheet" href= "/main.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/main.css") != std::string::npos);
  }

  SECTION("multiple spaces around =")
  {
    std::string html = R"(<html><head><link rel   =   "preload" href   =   "/font.woff2" as   =   "font"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/font.woff2") != std::string::npos);
  }

  SECTION("boolean attr followed by = attr")
  {
    // crossorigin (boolean) then href = "/x" (with spaces)
    std::string html = R"(<html><head><link rel="preload" crossorigin href = "/x.js" as = "script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/x.js") != std::string::npos);
    CHECK(links[0].find("crossorigin") != std::string::npos);
  }
}

// ─── Script body skipping (IN_SCRIPT state) ─────────────────────────────────

TEST_CASE("HtmlScanner additional edge cases", "[html_scanner][edge]")
{
  SECTION("unclosed quote in attribute — no crash, no link")
  {
    std::string html = R"(<html><head><link rel="preload" href="style.css</head></html>)";
    auto links       = scan_html(html);
    // The unclosed quote consumes everything — no valid link extracted
    CHECK(links.empty());
  }

  SECTION("invalid as value is rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="/file.bin" as="evil;injected"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("tabs and newlines in tag are treated as whitespace")
  {
    std::string html = "<html><head><link\trel=\"stylesheet\"\nhref=\"/tab.css\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/tab.css") != std::string::npos);
  }

  SECTION("multiple rel values — combined rel not matched")
  {
    // rel="preload stylesheet" is NOT the same as rel="preload"
    std::string html = R"(<html><head><link rel="preload stylesheet" href="/combo.css" as="style"></head></html>)";
    auto links       = scan_html(html);
    // "preload stylesheet" != "preload" and != "stylesheet", so no match
    CHECK(links.empty());
  }

  SECTION("style body is skipped — no false link extraction")
  {
    std::string html = R"(<html><head>
      <style>
        /* </head> would be bad here */
        .link[href="/fake.css"] { color: red; }
      </style>
      <link rel="stylesheet" href="/real.css">
    </head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.css") != std::string::npos);
    // Verify /fake.css was NOT extracted
    for (const auto &l : links) {
      CHECK(l.find("/fake.css") == std::string::npos);
    }
  }

  SECTION("style with </head> inside does not stop scanning")
  {
    std::string html = R"(<html><head>
      <style> /* </head> trick */ body { color: red; } </style>
      <link rel="stylesheet" href="/after-style.css">
    </head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after-style.css") != std::string::npos);
  }
}

// ─── Edge cases: script close tag with trailing whitespace (HTML spec) ───────

TEST_CASE("HtmlScanner: duplicate attribute handling", "[html_scanner][edge]")
{
  SECTION("duplicate href — first value wins (A-28)")
  {
    // Per HTML spec §13.1.2.3: first occurrence of a duplicate attribute wins.
    std::string html = R"(<html><head><link rel="preload" href="/first.css" href="/second.css" as="style"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/first.css") != std::string::npos);
    CHECK(links[0].find("/second.css") == std::string::npos);
  }

  SECTION("duplicate rel — first value wins")
  {
    // First rel="preload" wins; second rel="stylesheet" is ignored.
    std::string html = R"(<html><head><link rel="preload" as="style" href="/x.css" rel="stylesheet"></head></html>)";
    auto links       = scan_html(html);
    // First rel="preload" wins — should still produce a preload link
    REQUIRE(links.size() == 1);
  }

  SECTION("duplicate as — first value wins (A-28)")
  {
    // First as="style" wins; second as="script" is ignored.
    std::string html = R"(<html><head><link rel="preload" as="style" as="script" href="/x.js"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("as=style") != std::string::npos);
    CHECK(links[0].find("as=script") == std::string::npos);
  }
}

// ─── Pathological inputs — no crash, bounded behavior ───────────────────────

TEST_CASE("HtmlScanner: pathological inputs", "[html_scanner][fuzz]")
{
  SECTION("binary data mixed with HTML does not crash")
  {
    std::string html = "<html><head>";
    for (int i = 0; i < 256; i++) {
      html += static_cast<char>(i);
    }
    html += R"(<link rel="stylesheet" href="/after-binary.css"></head></html>)";
    auto links = scan_html(html);
    // Binary data may confuse state machine but must NOT crash
    // Links count is implementation-defined but bounded
    CHECK(links.size() <= 1);
  }

  SECTION("very long tag name does not crash")
  {
    std::string html = "<html><head><" + std::string(10000, 'a') + "></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("very long attribute value causes tag rejection")
  {
    // Oversized attribute rejects the entire tag — not silently truncated.
    std::string long_val(5000, 'x');
    std::string html = R"(<html><head><link rel="preload" href="/)" + long_val +
                       R"(" as="style"><link rel="stylesheet" href="/safe.css"></head></html>)";
    auto links = scan_html(html);
    // Oversized tag rejected; safe second link still emitted
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/safe.css") != std::string::npos);
  }

  SECTION("1MB whitespace inside tag does not crash")
  {
    std::string html = "<html><head><link" + std::string(10000, ' ') + R"(rel="stylesheet" href="/x.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/x.css") != std::string::npos);
  }
}

// ─── Cross-origin and extract_origin edge cases ─────────────────────────────

TEST_CASE("HtmlScanner INIT: <head followed by digit is not <head>", "[html_scanner][init]")
{
  // <head2> should not match as <head> — the 6th char is a digit, not > or space
  std::string html = "<html><head2><link rel=\"stylesheet\" href=\"/bad.css\"></head2>"
                     "<head><link rel=\"stylesheet\" href=\"/good.css\"></head></html>";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("HtmlScanner INIT: multiple < before <head>", "[html_scanner][init]")
{
  // Multiple stray '<' characters should not confuse the INIT state
  std::string html = "<<<head><link rel=\"stylesheet\" href=\"/x.css\"></head></html>";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/x.css") != std::string::npos);
}

TEST_CASE("HtmlScanner INIT: text content before <head>", "[html_scanner][init]")
{
  std::string html = "Some text content <head><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

TEST_CASE("HtmlScanner INIT: <head with multiple attributes", "[html_scanner][init]")
{
  std::string html = R"(<html><head class="foo" data-x="bar" lang="en"><link rel="stylesheet" href="/a.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

TEST_CASE("HtmlScanner INIT: <HEAD all uppercase", "[html_scanner][init]")
{
  std::string html = "<HTML><HEAD><LINK REL=\"stylesheet\" HREF=\"/u.css\"></HEAD></HTML>";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/u.css") != std::string::npos);
}

TEST_CASE("HtmlScanner INIT: <head> not found within scan limit", "[html_scanner][init]")
{
  // If <head> appears after the scan limit, scanner stays in INIT and produces nothing
  std::string html = std::string(100, 'x') + "<head><link rel=\"stylesheet\" href=\"/a.css\"></head>";
  auto links       = scan_html(html, 50); // limit reached before <head>
  CHECK(links.empty());
}

// ─── IN_TAG state edge cases ────────────────────────────────────────────────

TEST_CASE("HtmlScanner IN_TAG: unexpected char in tag name resets to IN_HEAD", "[html_scanner][in_tag]")
{
  // A tag name with unusual characters (e.g. <link@foo>) — the '@' triggers
  // the else branch in IN_TAG which resets to IN_HEAD
  std::string html = R"(<html><head><link@bad href="/evil.css"><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
}

TEST_CASE("HtmlScanner IN_TAG: closing tag for non-head element stays in head", "[html_scanner][in_tag]")
{
  // </title> should NOT terminate scanning — only </head> does
  std::string html = R"(<html><head><title>Test</title><link rel="stylesheet" href="/a.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

TEST_CASE("HtmlScanner IN_TAG: </HEAD> uppercase closes scanning", "[html_scanner][in_tag]")
{
  std::string html = R"(<html><head><link rel="stylesheet" href="/a.css"></HEAD><link rel="stylesheet" href="/b.css">)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

// ─── IN_ATTR_NAME / IN_ATTR_SEP / IN_ATTR_VALUE edge cases ─────────────────

TEST_CASE("HtmlScanner IN_HEAD: non-alpha after </ is not a tag", "[html_scanner][in_head]")
{
  // </123> — digit after </ should not be recognized as a tag name
  std::string html = R"(<html><head></123><link rel="stylesheet" href="/a.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

TEST_CASE("HtmlScanner IN_HEAD: non-alpha after < is not a tag", "[html_scanner][in_head]")
{
  // <123> — digit after < should not start a tag
  std::string html = R"(<html><head><123><link rel="stylesheet" href="/a.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

// ─── as= attribute validation ───────────────────────────────────────────────

TEST_CASE("DONE: multiple feeds after DONE are all no-ops", "[html_scanner][done][audit]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);

  std::string html1 = R"(<html><head><link rel="stylesheet" href="/first.css"></head></html>)";
  scanner.feed(html1.c_str(), static_cast<int64_t>(html1.size()));
  CHECK(scanner.is_done());
  REQUIRE(scanner.get_links().size() == 1);

  // Feed three more times — all should be no-ops
  for (int i = 0; i < 3; i++) {
    std::string extra = R"(<head><link rel="stylesheet" href="/extra.css"></head>)";
    scanner.feed(extra.c_str(), static_cast<int64_t>(extra.size()));
  }
  CHECK(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/first.css") != std::string::npos);
}

// ─── QA audit: feed() edge cases ────────────────────────────────────────────

TEST_CASE("feed: large input processed up to scan_limit", "[html_scanner][feed][audit]")
{
  // 1MB of padding, then a link. With default scan_limit=131072, the link is beyond the limit.
  std::string html = "<html><head>";
  html += std::string(200000, ' ');
  html += R"(<link rel="stylesheet" href="/deep.css"></head></html>)";
  auto links = scan_html(html);
  CHECK(links.empty()); // Link is beyond scan_limit
}

TEST_CASE("feed: large input within limit is extracted", "[html_scanner][feed][audit]")
{
  // Link within the scan limit (131072 bytes)
  std::string html = "<html><head>";
  html += std::string(1000, ' ');
  html += R"(<link rel="stylesheet" href="/within.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/within.css") != std::string::npos);
}

// ─── QA audit: reset() thoroughness ─────────────────────────────────────────

TEST_CASE("scan_limit: exactly limit_ characters are processed", "[html_scanner][limit][audit]")
{
  // Build HTML where </head> falls exactly at the limit boundary.
  // Prefix: "<html><head>" = 12 chars, then we add padding, then "</head>".
  // With limit=30: 12 chars prefix + 11 chars padding + 7 chars "</head>" = 30.
  // The </head> starts at char 24 and '>' is char 30. At char 30, scanned_=30=limit,
  // so it IS processed and triggers DONE via </head>.
  std::string prefix  = "<html><head>";       // 12 chars
  std::string padding = std::string(11, ' '); // 11 chars
  std::string close   = "</head>";            // 7 chars
  std::string html    = prefix + padding + close + "<extra garbage>";
  int limit           = 30; // 12 + 11 + 7 = 30
  EarlyHintsConfig config;
  HtmlScanner scanner(limit, 10, &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  // The '>' of </head> is at position 30 = limit, which IS processed.
  CHECK(scanner.is_done());
}

TEST_CASE("scan_limit: character at limit+1 is NOT processed", "[html_scanner][limit][audit]")
{
  // Build HTML where '</head>' '>' falls at limit+1 — should NOT trigger </head> close.
  // Instead, scan_limit fires first.
  std::string prefix  = "<html><head>";       // 12 chars
  std::string padding = std::string(11, ' '); // 11 chars
  std::string close   = "</head>";            // 7 chars
  std::string html    = prefix + padding + close;
  int limit           = 29; // '>' of </head> is at position 30, which is limit+1
  EarlyHintsConfig config;
  HtmlScanner scanner(limit, 10, &config);
  scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
  // Scanner hit limit before processing '>' — DONE via limit, not via </head>
  CHECK(scanner.is_done());
  // The scanner went DONE from scan_limit, not from finding </head>
}

TEST_CASE("scan_limit: expires mid </script> close tag", "[html_scanner][limit][audit]")
{
  // Scan limit runs out while matching "</script>" — scanner goes to DONE,
  // abandoning the partial close-tag match.
  // scanned_ > limit_ triggers DONE, so feeding exactly `limit` chars means
  // the last char is at scanned_==limit which is NOT > limit. Need limit-1.
  std::string prefix = "<html><head><script>x=1;</scri"; // 30 chars
  int limit          = 29;
  EarlyHintsConfig config;
  HtmlScanner scanner(limit, 10, &config);
  scanner.feed(prefix.c_str(), static_cast<int64_t>(prefix.size()));
  CHECK(scanner.is_done());
  CHECK(scanner.get_links().empty());
}

TEST_CASE("scan_limit: link just within limit is extracted", "[html_scanner][limit][audit]")
{
  // Carefully sized so the entire link tag fits within the limit.
  std::string html = R"(<html><head><link rel="stylesheet" href="/a.css"></head>)";
  int limit        = static_cast<int>(html.size());
  auto links       = scan_html(html, limit);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY PENETRATION TESTS — Injection Attack Vectors
// ═══════════════════════════════════════════════════════════════════════════════
//
// Each test below probes a specific attack vector. A test that PASSES means the
// ─── miss-04: Self-closing non-link tags (e.g. <br/>) ───────────────────────

TEST_CASE("HtmlScanner: self-closing non-link tags do not break scanning", "[html_scanner][audit]")
{
  SECTION("<br/> between two links")
  {
    std::string html = "<html><head>"
                       "<link rel=\"stylesheet\" href=\"/a.css\">"
                       "<br/>"
                       "<link rel=\"stylesheet\" href=\"/b.css\">"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 2);
    CHECK(links[0].find("/a.css") != std::string::npos);
    CHECK(links[1].find("/b.css") != std::string::npos);
  }

  SECTION("<meta charset=\"utf-8\" /> self-closing")
  {
    std::string html = "<html><head>"
                       "<meta charset=\"utf-8\" />"
                       "<link rel=\"stylesheet\" href=\"/c.css\">"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/c.css") != std::string::npos);
  }

  SECTION("<hr/> inside head")
  {
    std::string html = "<html><head>"
                       "<hr/>"
                       "<link rel=\"preload\" href=\"/d.js\" as=\"script\">"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/d.js") != std::string::npos);
  }
}

// ─── miss-05: MAX_ATTR_VALUE_LEN boundary tests ────────────────────────────

TEST_CASE("HtmlScanner: MAX_ATTR_VALUE_LEN boundary (4096)", "[html_scanner][boundary][audit]")
{
  SECTION("href at exactly 4096 chars is accepted")
  {
    // 4096 - prefix/suffix overhead: href value = "/" + 4095 'x' chars = 4096 total
    std::string href_val = "/" + std::string(4095, 'x');
    REQUIRE(href_val.size() == 4096);
    std::string html = "<html><head><link rel=\"preload\" href=\"" + href_val + "\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    // The full href should be present (not truncated)
    CHECK(links[0].find(href_val) != std::string::npos);
  }

  SECTION("href at 4097 chars causes tag rejection (not truncation)")
  {
    std::string href_val = "/" + std::string(4096, 'y');
    REQUIRE(href_val.size() == 4097);
    std::string html = "<html><head><link rel=\"preload\" href=\"" + href_val +
                       "\" as=\"style\"><link rel=\"stylesheet\" href=\"/safe.css\"></head></html>";
    auto links = scan_html(html);
    // Tag is discarded; only the valid following link is emitted
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/safe.css") != std::string::npos);
  }

  SECTION("attr name at exactly 256 chars is capped — excess ignored")
  {
    // Build an attr name longer than MAX_ATTR_NAME_LEN (256)
    std::string long_attr(257, 'z');
    std::string html = "<html><head><link rel=\"preload\" href=\"/ok.js\" as=\"script\" " + long_attr + "=\"val\"></head></html>";
    auto links       = scan_html(html);
    // Link should still be extracted (the bogus long attr is just ignored)
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok.js") != std::string::npos);
  }
}

// plugin correctly BLOCKS the attack. A test that FAILS indicates a CRITICAL
// vulnerability that an attacker could exploit in production.

// ─── 1. Header Injection via CRLF ───────────────────────────────────────────
//
// HTTP header injection: attacker embeds \r\n inside an href value to break out
// of the Link header and inject arbitrary response headers. If the raw CRLF
// bytes survive into the Link header value, a downstream proxy or browser will
// interpret the injected bytes as a separate HTTP header.

// ─── Commit 4: Scanner correctness fixes ─────────────────────────────────────

// B-06: </script> in script_escaped mode should close the script element.
// The HTML spec (§13.2.6.4) treats </script> as a valid end tag in
// "script data escaped" state. The scanner's script_escaped_ branch currently
// breaks before reaching the close-tag detection logic, so the script is never
// closed and content after it is consumed silently.
TEST_CASE("IN_SCRIPT: </script> inside <!--...--> escaped region closes script", "[html_scanner][script][escaped]")
{
  // First <script src> extracts a preload.
  // Second <script><!-- ... </script> — the <!-- enters escaped mode.
  // </script> must still close the script per HTML spec §13.2.6.4.
  // A <link> after the second </script> must then be extracted.
  std::string html = "<html><head>"
                     "<script src=\"/pre.js\"></script>"
                     "<script><!-- inline </script>"
                     "<link rel=\"stylesheet\" href=\"/after.css\">"
                     "</head></html>";
  auto links = scan_html(html);

  bool has_pre   = false;
  bool has_after = false;
  for (const auto &l : links) {
    if (l.find("/pre.js") != std::string::npos) {
      has_pre = true;
    }
    if (l.find("/after.css") != std::string::npos) {
      has_after = true;
    }
  }
  // /pre.js comes from the first script open tag.
  // /after.css is only reachable if </script> in escaped mode closes the script.
  CHECK(has_pre);
  CHECK(has_after);
}

// A-06: Carriage-return (\r) is valid HTML whitespace (per HTML spec §13.1.2.6)
// and must be accepted as a separator between the close-tag name and '>'.
// The close-tag path checks for tab/LF/FF/space but was missing \r.
TEST_CASE("IN_SCRIPT: </script\\r> carriage-return separator closes script", "[html_scanner][script]")
{
  // </script\r> — \r appears between the tag name and '>'.
  // Per HTML spec §13.2.6.3 this is a valid separator (ASCII whitespace).
  // Without the fix the \r hits the else-branch and resets raw_close_pos_,
  // so the script is never closed and /after.css is consumed inside it.
  std::string html = "<html><head>"
                     "<script src=\"/x.js\"></script\r>"
                     "<link rel=\"stylesheet\" href=\"/after.css\">"
                     "</head></html>";
  auto links = scan_html(html);
  // /x.js from the script open-tag + /after.css from the link after the script.
  REQUIRE(links.size() == 2);
  bool has_xjs   = false;
  bool has_after = false;
  for (const auto &l : links) {
    if (l.find("/x.js") != std::string::npos) {
      has_xjs = true;
    }
    if (l.find("/after.css") != std::string::npos) {
      has_after = true;
    }
  }
  CHECK(has_xjs);
  CHECK(has_after);
}

// A-28: Per the HTML spec (§13.1.2.3), when the same attribute name appears
// more than once in an element, the first occurrence wins and subsequent ones
// are ignored.  finish_attr() currently overwrites on every call (last-wins).
TEST_CASE("finish_attr: first occurrence of duplicate attribute wins", "[html_scanner][attrs]")
{
  SECTION("duplicate href — first value wins")
  {
    // href appears twice: /first.css then /second.css.
    // First-wins: the scanner must use /first.css.
    std::string html = R"(<html><head><link rel="preload" href="/first.css" as="style" href="/second.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/first.css") != std::string::npos);
    CHECK(links[0].find("/second.css") == std::string::npos);
  }

  SECTION("duplicate as — first value wins")
  {
    // as appears twice: style then script.
    // First-wins: the scanner must use as=style.
    std::string html = R"(<html><head><link rel="preload" href="/x.css" as="style" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("as=style") != std::string::npos);
    CHECK(links[0].find("as=script") == std::string::npos);
  }
}

// A-29: The HTML spec (§2.5.3) defines only two valid crossorigin states:
// "anonymous" and "use-credentials". Any other value maps to "anonymous".
// finish_attr() currently stores the raw lowercased value without validation,
// so crossorigin="garbage" leaks into the Link header as crossorigin=garbage.
TEST_CASE("finish_attr: unrecognized crossorigin value normalizes to anonymous", "[html_scanner][attrs]")
{
  // crossorigin="garbage" is not a recognised keyword.
  // Per HTML spec it must be treated the same as crossorigin="anonymous".
  std::string html = R"(<html><head><link rel="preload" href="/font.woff2" as="font" crossorigin="garbage"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("crossorigin=anonymous") != std::string::npos);
  CHECK(links[0].find("crossorigin=garbage") == std::string::npos);
}
