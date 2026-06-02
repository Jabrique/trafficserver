/** @file
 * HtmlScanner unit tests: Script/comment state machine, chunking, streaming
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

TEST_CASE("HtmlScanner skips tags inside script body", "[html_scanner][script]")
{
  SECTION("link inside inline script is ignored")
  {
    std::string html = R"(<html><head>
      <script>document.write('<link rel="preload" href="/evil.js" as="script">')</script>
      <link rel="stylesheet" href="/real.css">
    </head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.css") != std::string::npos);
    // /evil.js should NOT appear
    for (const auto &link : links) {
      CHECK(link.find("/evil.js") == std::string::npos);
    }
  }

  SECTION("script with src is processed then body skipped")
  {
    std::string html = R"(<html><head>
      <script src="/app.js"></script>
      <link rel="stylesheet" href="/style.css">
    </head></html>)";
    auto links       = scan_html(html);
    // Should have both: /app.js (from <script src>) and /style.css (from <link>)
    REQUIRE(links.size() == 2);
    bool has_app   = false;
    bool has_style = false;
    for (const auto &link : links) {
      if (link.find("/app.js") != std::string::npos) {
        has_app = true;
      }
      if (link.find("/style.css") != std::string::npos) {
        has_style = true;
      }
    }
    CHECK(has_app);
    CHECK(has_style);
  }

  SECTION("uppercase SCRIPT tag body is skipped")
  {
    std::string html = R"(<html><head>
      <SCRIPT>var x = '<link rel="preload" href="/bad.js" as="script">';</SCRIPT>
      <link rel="stylesheet" href="/good.css">
    </head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
  }

  SECTION("nested script-like content in script body")
  {
    std::string html = R"(<html><head>
      <script>
        var html = '</script' + '>';
        var more = '<link href="/trick.css">';
      </script>
      <link rel="stylesheet" href="/real.css">
    </head></html>)";
    auto links       = scan_html(html);
    bool has_real    = false;
    for (const auto &link : links) {
      if (link.find("/real.css") != std::string::npos) {
        has_real = true;
      }
    }
    CHECK(has_real);
  }

  SECTION("script close tag split across feed boundaries")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 4096, &config);
    // Split "</script>" across two feed() calls: "</scri" + "pt>"
    std::string part1 = "<html><head><script>var x = 1;</scri";
    std::string part2 = R"(pt><link rel="stylesheet" href="/after-script.css"></head></html>)";
    scanner.feed(part1.c_str(), part1.size());
    scanner.feed(part2.c_str(), part2.size());
    auto links    = scanner.get_links();
    bool has_link = false;
    for (const auto &l : links) {
      if (l.find("/after-script.css") != std::string::npos) {
        has_link = true;
      }
    }
    CHECK(has_link);
  }
}

// ─── Dangerous URL scheme rejection (is_safe_url) ────────────────────────────

TEST_CASE("HtmlScanner: script close tag with whitespace/slash", "[html_scanner][script][edge]")
{
  SECTION("</script > with trailing space before >")
  {
    std::string html = R"(<html><head>
      <script>var x = 1;</script >
      <link rel="stylesheet" href="/after.css">
    </head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("</script\\n> with newline before >")
  {
    std::string html = "<html><head><script>var x = 1;</script\n><link rel=\"stylesheet\" href=\"/after.css\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("</script\\t> with tab before >")
  {
    std::string html = "<html><head><script>var x = 1;</script\t><link rel=\"stylesheet\" href=\"/after.css\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("</script/> self-closing end tag")
  {
    std::string html = R"(<html><head><script>var x = 1;</script/><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("</scriptx> does NOT close script")
  {
    // </scriptx> is a different tag — scanner must stay in script mode
    std::string html = R"(<html><head><script>var x = '</scriptx>';</script><link rel="stylesheet" href="/x.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/x.css") != std::string::npos);
  }

  SECTION("</script-foo> does NOT close script")
  {
    std::string html =
      R"(<html><head><script>var x = '</script-foo>';</script><link rel="stylesheet" href="/x.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/x.css") != std::string::npos);
  }

  SECTION("</SCRIPT > mixed case with trailing space")
  {
    std::string html = R"(<html><head><script>var x = 1;</SCRIPT ><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("</script > split across feed boundaries")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);
    std::string part1 = "<html><head><script>x=1;</script";
    std::string part2 = R"( ><link rel="stylesheet" href="/split.css"></head></html>)";
    scanner.feed(part1.c_str(), part1.size());
    scanner.feed(part2.c_str(), part2.size());
    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/split.css") != std::string::npos);
  }

  SECTION("</style > also handled with trailing space")
  {
    std::string html = R"(<html><head>
      <style>body { color: red; }</style >
      <link rel="stylesheet" href="/after-style.css">
    </head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after-style.css") != std::string::npos);
  }
}

// ─── Edge cases: HTML comment abrupt-close (HTML spec §13.2.5.43-46) ────────

TEST_CASE("HtmlScanner: comment abrupt-close edge cases", "[html_scanner][comment][edge]")
{
  SECTION("<!-->  is an empty comment — does not swallow subsequent tags")
  {
    std::string html = R"(<html><head><!--><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("<!---> is an incorrectly-closed empty comment")
  {
    std::string html = R"(<html><head><!---><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("normal comment still works after fix")
  {
    std::string html = R"(<html><head><!-- normal comment --><link rel="stylesheet" href="/ok.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok.css") != std::string::npos);
  }

  SECTION("<!-- > (space then >) does NOT close comment")
  {
    std::string html =
      R"(<html><head><!-- ><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/bad.css") == std::string::npos);
  }

  SECTION("<!--> split across feed boundaries")
  {
    EarlyHintsConfig config;
    HtmlScanner scanner(131072, 10, &config);
    std::string part1 = "<html><head><!-";
    std::string part2 = R"(-><link rel="stylesheet" href="/split.css"></head></html>)";
    scanner.feed(part1.c_str(), part1.size());
    scanner.feed(part2.c_str(), part2.size());
    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/split.css") != std::string::npos);
  }

  SECTION("--!> is an incorrectly-closed comment per HTML spec section 13.2.5.51")
  {
    // Per HTML spec, --!> closes a comment just like -->
    std::string html = R"(<html><head><!-- comment --!><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("--!> with content between dashes and bang")
  {
    // Only --!> closes, not -!> or ---!>
    std::string html =
      R"(<html><head><!-- comment -!><link rel="stylesheet" href="/bad.css">--!><link rel="stylesheet" href="/good.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/bad.css") == std::string::npos);
  }

  SECTION("--!!> does NOT close comment (per HTML spec §13.2.5.56)")
  {
    // Per spec: -- enters end state, first ! enters bang state, second !
    // is 'anything else' → back to comment state. Then > doesn't close.
    std::string html =
      R"(<html><head><!-- comment --!!><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/bad.css") == std::string::npos);
  }

  SECTION("--!-> does NOT close comment (per HTML spec §13.2.5.56)")
  {
    // Per spec: --! enters bang state, - enters bang-dash state,
    // > is 'anything else' → back to comment state. Not a close.
    std::string html =
      R"(<html><head><!-- comment --!-><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/bad.css") == std::string::npos);
  }

  SECTION("--!--> DOES close comment (bang-dash then -- returns to end state)")
  {
    // Per spec: --! bang, - bang-dash, - back to end state, > closes.
    std::string html = R"(<html><head><!-- comment --!--><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("<!--!> does NOT close comment (per HTML spec §13.2.5.43)")
  {
    // Per HTML spec §13.2.5.43 "comment start state":
    // After "<!--", the next char '!' is "anything else" → reconsume in comment state.
    // So "<!--!>" is NOT a valid comment close. The comment stays open.
    std::string html =
      R"(<html><head><!--!><link rel="preload" href="/bad.js" as="script">--><link rel="preload" href="/good.css" as="style"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/bad.js") == std::string::npos);
  }

  SECTION("<!--!--> DOES close (start state → comment → close)")
  {
    // <!--: enter comment start state
    // !: anything else → comment state (dashes_=0)
    // -: dashes_=1
    // -: dashes_=2 (end state)
    // >: close
    std::string html = R"(<html><head><!--!--><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("<!---> closes (start dash → '>' abrupt close)")
  {
    // This is already tested above but verifying it still works after fix.
    // <!--: enter comment start state
    // -: comment start dash state
    // >: abrupt close
    std::string html = R"(<html><head><!---><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("<!---x...> start dash then non-dash enters comment body")
  {
    // <!--: enter comment start state
    // -: comment start dash state
    // x: anything else → comment state (dashes_=0)
    // ...>: '>' in comment state does nothing, comment stays open
    std::string html =
      R"(<html><head><!---x><link rel="preload" href="/bad.js" as="script">--><link rel="preload" href="/good.css" as="style"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/bad.js") == std::string::npos);
  }

  SECTION("<!-> is a bogus comment (single dash after <!)")
  {
    // Per HTML spec §13.2.5.42: "<!" followed by single "-" (not "<!--")
    // is a bogus comment — content until ">" is skipped.
    std::string html = R"(<html><head><!-bogus><link rel="stylesheet" href="/after.css"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("<!-<link ...> inside bogus comment is not parsed")
  {
    // The <link> is inside a bogus comment started by "<!-" and should be ignored.
    std::string html =
      R"(<html><head><!-<link rel="stylesheet" href="/evil.css"><link rel="stylesheet" href="/good.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/good.css") != std::string::npos);
    CHECK(links[0].find("/evil.css") == std::string::npos);
  }
}

// ─── Edge cases: CDATA and script-data-escaped (adversarial HTML) ────────────

TEST_CASE("Chunk splitting: tag name boundary", "[html_scanner][chunking]")
{
  // Split between '<' and 'link': chunk1 = "...<", chunk2 = "link ..."
  std::string html = "<html><head><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head></html>";
  auto ref         = scan_html(html);

  SECTION("split right after '<' of <link>")
  {
    // Find the '<' of '<link'
    size_t pos = html.find("<link");
    REQUIRE(pos != std::string::npos);
    auto links = scan_html_split(html, pos + 1); // chunk1 ends with '<'
    CHECK(links == ref);
  }

  SECTION("split inside tag name: <li | nk")
  {
    size_t pos = html.find("<link");
    auto links = scan_html_split(html, pos + 3); // chunk1 ends with "<li"
    CHECK(links == ref);
  }
}

TEST_CASE("Chunk splitting: attribute name boundary", "[html_scanner][chunking]")
{
  std::string html = "<html><head><link rel=\"preload\" href=\"/a.css\" as=\"style\"></head></html>";
  auto ref         = scan_html(html);

  SECTION("split inside attribute name: hre | f")
  {
    size_t pos = html.find("href");
    REQUIRE(pos != std::string::npos);
    auto links = scan_html_split(html, pos + 3); // "hre" | "f=\"/a.css\"..."
    CHECK(links == ref);
  }

  SECTION("split between attr name and '=': href | =\"/a.css\"")
  {
    size_t pos = html.find("href=");
    auto links = scan_html_split(html, pos + 4); // "href" | "=\"/a.css\"..."
    CHECK(links == ref);
  }

  SECTION("split between '=' and quote: href= | \"/a.css\"")
  {
    size_t pos = html.find("href=\"");
    auto links = scan_html_split(html, pos + 5); // 'href=' | '"/a.css"...'
    CHECK(links == ref);
  }
}

TEST_CASE("Chunk splitting: attribute value boundary", "[html_scanner][chunking]")
{
  std::string html = "<html><head><link rel=\"preload\" href=\"/very/long/path.js\" as=\"script\"></head></html>";
  auto ref         = scan_html(html);

  SECTION("split inside quoted attribute value")
  {
    size_t pos = html.find("/very/long");
    auto links = scan_html_split(html, pos + 5); // "/very" | "/long/path.js\"..."
    CHECK(links == ref);
  }

  SECTION("split at closing quote: /path.js | \"")
  {
    size_t pos = html.find("path.js\"");
    auto links = scan_html_split(html, pos + 7); // before closing quote
    CHECK(links == ref);
  }
}

TEST_CASE("Chunk splitting: comment boundaries", "[html_scanner][chunking]")
{
  SECTION("split inside <!-- opener: <!- | -")
  {
    std::string html = "<html><head><!-- comment --><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    auto ref         = scan_html(html);
    size_t pos       = html.find("<!--");
    auto links       = scan_html_split(html, pos + 3); // "<!-" | "- comment..."
    CHECK(links == ref);
  }

  SECTION("split inside --> closer: -- | >")
  {
    std::string html = "<html><head><!-- comment --><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    auto ref         = scan_html(html);
    size_t pos       = html.find("--><link");
    auto links       = scan_html_split(html, pos + 2); // "--" | "><link..."
    CHECK(links == ref);
  }

  SECTION("split inside --!> closer: -- | !>")
  {
    std::string html = "<html><head><!-- comment --!><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    auto ref         = scan_html(html);
    size_t pos       = html.find("--!>");
    auto links       = scan_html_split(html, pos + 2); // "--" | "!><link..."
    CHECK(links == ref);
  }

  SECTION("split <!--> abrupt close: <!- | ->")
  {
    std::string html = "<html><head><!--><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    auto ref         = scan_html(html);
    size_t pos       = html.find("<!-->");
    auto links       = scan_html_split(html, pos + 3); // "<!-" | "-><link..."
    CHECK(links == ref);
  }
}

TEST_CASE("Chunk splitting: close tag </script> boundary", "[html_scanner][chunking]")
{
  std::string html = "<html><head><script>var x=1;</script><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
  auto ref         = scan_html(html);

  SECTION("split at </ | script>")
  {
    size_t pos = html.find("</script>");
    auto links = scan_html_split(html, pos + 2); // "</" | "script>..."
    CHECK(links == ref);
  }

  SECTION("split at </sc | ript>")
  {
    size_t pos = html.find("</script>");
    auto links = scan_html_split(html, pos + 4); // "</sc" | "ript>..."
    CHECK(links == ref);
  }

  SECTION("split at </script | >")
  {
    size_t pos = html.find("</script>");
    auto links = scan_html_split(html, pos + 8); // "</script" | ">..."
    CHECK(links == ref);
  }
}

TEST_CASE("Chunk splitting: script escaped <!-- boundary", "[html_scanner][chunking]")
{
  // Per HTML spec §13.2.6.4 ("script data escaped end tag name" state),
  // </script> IS a valid end tag in escaped mode and MUST close the script element.
  // After B-06 fix: the first </script> closes the script, exposing /evil.css.
  // Then --> and the second </script> are stray in IN_HEAD and ignored.
  std::string html = "<html><head><script><!--</script>"
                     "<link rel=\"preload\" href=\"/evil.css\" as=\"style\">"
                     "--></script><link rel=\"preload\" href=\"/real.css\" as=\"style\"></head></html>";
  auto ref = scan_html(html);
  REQUIRE(ref.size() == 2); // Both links exposed: /evil.css and /real.css
  bool has_evil = false, has_real = false;
  for (const auto &l : ref) {
    if (l.find("/evil.css") != std::string::npos)
      has_evil = true;
    if (l.find("/real.css") != std::string::npos)
      has_real = true;
  }
  CHECK(has_evil);
  CHECK(has_real);

  SECTION("split at <! | -- inside script (escaped entry)")
  {
    size_t pos = html.find("<!--");
    auto links = scan_html_split(html, pos + 2); // "<!" | "--</script>..."
    CHECK(links == ref);
  }

  SECTION("split at <!- | - inside script")
  {
    size_t pos = html.find("<!--");
    auto links = scan_html_split(html, pos + 3); // "<!-" | "-</script>..."
    CHECK(links == ref);
  }

  SECTION("split at --> exit: -- | > inside script escaped")
  {
    size_t pos = html.find("--></script><link");
    auto links = scan_html_split(html, pos + 2); // "--" | "></script>..."
    CHECK(links == ref);
  }
}

TEST_CASE("Chunk splitting: CDATA bogus comment boundary", "[html_scanner][chunking]")
{
  std::string html = "<html><head><![CDATA[<link href=\"/evil.css\">]]>"
                     "<link rel=\"stylesheet\" href=\"/real.css\"></head></html>";
  auto ref = scan_html(html);
  REQUIRE(ref.size() == 1);
  CHECK(ref[0].find("/real.css") != std::string::npos);

  SECTION("split at <! | [CDATA[...")
  {
    size_t pos = html.find("<![CDATA[");
    auto links = scan_html_split(html, pos + 2); // "<!" | "[CDATA[..."
    CHECK(links == ref);
  }

  SECTION("split at <![ | CDATA[...")
  {
    size_t pos = html.find("<![CDATA[");
    auto links = scan_html_split(html, pos + 3); // "<![" | "CDATA[..."
    CHECK(links == ref);
  }
}

TEST_CASE("Chunk splitting: <head> tag in INIT state", "[html_scanner][chunking]")
{
  std::string html = "<html><head><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
  auto ref         = scan_html(html);

  SECTION("split at <hea | d>")
  {
    size_t pos = html.find("<head>");
    auto links = scan_html_split(html, pos + 4); // "<hea" | "d>..."
    CHECK(links == ref);
  }

  SECTION("split at <head | >")
  {
    size_t pos = html.find("<head>");
    auto links = scan_html_split(html, pos + 5); // "<head" | ">..."
    CHECK(links == ref);
  }

  SECTION("split <head with attributes: <head | lang=...")
  {
    std::string html2 = "<html><head lang=\"en\"><link rel=\"stylesheet\" href=\"/b.css\"></head></html>";
    auto ref2         = scan_html(html2);
    size_t pos        = html2.find("<head ");
    auto links        = scan_html_split(html2, pos + 5); // "<head" | " lang=\"en\">..."
    CHECK(links == ref2);
  }
}

TEST_CASE("Chunk splitting: scan limit hit mid-token", "[html_scanner][chunking]")
{
  SECTION("limit hit inside tag name")
  {
    // Place the limit so it expires inside the <link tag name
    std::string html = "<html><head><link rel=\"preload\" href=\"/x.js\" as=\"script\"></head></html>";
    size_t link_pos  = html.find("<link");
    // Set limit to link_pos + 2 so scanner stops at "<li" — never finishes the tag
    auto links = scan_html(html, static_cast<int>(link_pos + 2));
    CHECK(links.empty());
  }

  SECTION("limit hit inside attribute value")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/x.js\" as=\"script\"></head></html>";
    size_t href_pos  = html.find("/x.js");
    // Limit expires inside the href value — tag never closes, no link emitted
    auto links = scan_html(html, static_cast<int>(href_pos + 2));
    CHECK(links.empty());
  }

  SECTION("limit hit inside comment")
  {
    std::string html = "<html><head><!-- long comment --><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    size_t comm_pos  = html.find("long");
    auto links       = scan_html(html, static_cast<int>(comm_pos + 2));
    CHECK(links.empty()); // never exited comment
  }

  SECTION("limit hit inside script body")
  {
    std::string html = "<html><head><script>var x = 1;</script><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    size_t body_pos  = html.find("var x");
    auto links       = scan_html(html, static_cast<int>(body_pos + 2));
    CHECK(links.empty()); // never exited script
  }

  SECTION("limit hit mid-token across chunks produces same result")
  {
    std::string html = "<html><head><link rel=\"stylesheet\" href=\"/a.css\"></head></html>";
    int lim          = 20; // limit expires early
    auto single      = scan_html(html, lim);
    auto chunked     = scan_html_chunked(html, 1, lim);
    CHECK(single == chunked);
  }
}

TEST_CASE("Chunk splitting: single-byte feed produces identical results", "[html_scanner][chunking]")
{
  // For each complex HTML input, verify 1-byte-at-a-time == single feed
  auto check_single_byte_equivalence = [](const std::string &html) {
    auto single  = scan_html(html);
    auto chunked = scan_html_chunked(html, 1);
    CHECK(single == chunked);
  };

  SECTION("basic preload link")
  {
    check_single_byte_equivalence("<html><head><link rel=\"preload\" href=\"/a.js\" as=\"script\"></head></html>");
  }

  SECTION("HTML with comments")
  {
    check_single_byte_equivalence("<html><head><!-- comment --><link rel=\"stylesheet\" href=\"/a.css\"></head></html>");
  }

  SECTION("HTML with script body")
  {
    check_single_byte_equivalence(
      "<html><head><script src=\"/app.js\"></script><link rel=\"stylesheet\" href=\"/s.css\"></head></html>");
  }

  SECTION("HTML with script escaped state")
  {
    check_single_byte_equivalence("<html><head><script><!--</script>fake--></script>"
                                  "<link rel=\"preload\" href=\"/r.css\" as=\"style\"></head></html>");
  }

  SECTION("HTML with CDATA bogus comment")
  {
    check_single_byte_equivalence("<html><head><![CDATA[evil]]><link rel=\"stylesheet\" href=\"/r.css\"></head></html>");
  }

  SECTION("HTML with --!> comment close")
  {
    check_single_byte_equivalence("<html><head><!-- comment --!><link rel=\"stylesheet\" href=\"/a.css\"></head></html>");
  }

  SECTION("HTML with abrupt-close comment <!-->")
  {
    check_single_byte_equivalence("<html><head><!--><link rel=\"stylesheet\" href=\"/a.css\"></head></html>");
  }

  SECTION("HTML with style body")
  {
    check_single_byte_equivalence("<html><head><style>.x{}</style><link rel=\"stylesheet\" href=\"/a.css\"></head></html>");
  }

  SECTION("HTML with unquoted attributes")
  {
    check_single_byte_equivalence("<html><head><link rel=preload href=/a.js as=script></head></html>");
  }

  SECTION("HTML with spaces around =")
  {
    check_single_byte_equivalence("<html><head><link rel = \"preload\" href = \"/a.js\" as = \"script\"></head></html>");
  }

  SECTION("HTML with multiple resources")
  {
    check_single_byte_equivalence("<html><head>"
                                  "<link rel=\"preload\" href=\"/a.js\" as=\"script\">"
                                  "<link rel=\"stylesheet\" href=\"/b.css\">"
                                  "<script src=\"/c.js\"></script>"
                                  "</head></html>");
  }

  SECTION("HTML with boolean attributes")
  {
    check_single_byte_equivalence("<html><head><link rel=\"preload\" href=\"/f.woff2\" as=\"font\" crossorigin></head></html>");
  }
}

TEST_CASE("Chunk splitting: every byte boundary produces identical results", "[html_scanner][chunking]")
{
  // The ultimate stress test: for a representative HTML string, split at EVERY
  // possible byte boundary and verify each produces the same result.
  std::string html = "<html><head><!-- c --><script src=\"/a.js\"></script>"
                     "<link rel=\"stylesheet\" href=\"/b.css\"></head></html>";
  auto ref = scan_html(html);
  REQUIRE(ref.size() == 2);

  for (size_t split = 0; split <= html.size(); split++) {
    auto links = scan_html_split(html, split);
    INFO("split at byte " << split << " ('" << (split < html.size() ? std::string(1, html[split]) : "END") << "')");
    CHECK(links == ref);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// GAP AUDIT: Additional coverage tests
// ═════════════════════════════════════════════════════════════════════════════

// ─── INIT state edge cases ──────────────────────────────────────────────────

TEST_CASE("HtmlScanner IN_HEAD: <!> immediately closed", "[html_scanner][bogus]")
{
  // <!> is "<!x>" where x='>' — should be consumed as bogus (per spec, <!> is actually
  // handled by the inline check at line 470-472: c != '-' and c == '>' → clear match_buf_)
  std::string html = R"(<html><head><!><link rel="stylesheet" href="/a.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

TEST_CASE("HtmlScanner IN_HEAD: <!DOCTYPE html> inside head as bogus comment", "[html_scanner][bogus]")
{
  std::string html = R"(<html><head><!DOCTYPE html><link rel="stylesheet" href="/a.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: opening <script> inside script body is ignored", "[html_scanner][script][audit]")
{
  // Per HTML spec, raw text elements do not nest. A <script> open tag inside
  // script body is just text — only </script> closes the block.
  std::string html = R"(<html><head><script>
    var x = '<script>alert(1)</script>';
  </script><link rel="stylesheet" href="/legit.css"></head></html>)";
  auto links       = scan_html(html);
  // The '</script>' inside the string closes the script per the spec (and per our scanner).
  // The outer </script> then becomes stray text. /legit.css should still be found.
  bool has_legit = false;
  for (const auto &l : links) {
    if (l.find("/legit.css") != std::string::npos) {
      has_legit = true;
    }
  }
  CHECK(has_legit);
}

TEST_CASE("IN_SCRIPT: </ScRiPt> mixed case closes script", "[html_scanner][script][audit]")
{
  std::string html = R"(<html><head><script>var x = 1;</ScRiPt>)"
                     R"(<link rel="stylesheet" href="/found.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/found.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: malformed </script without > stays in script", "[html_scanner][script][audit]")
{
  // If the close tag never gets a '>', the scanner stays in IN_SCRIPT until scan_limit.
  // Use a small limit so the test doesn't loop forever.
  std::string html = "<html><head><script>var x = 1;</script";
  auto links       = scan_html(html, 200);
  CHECK(links.empty());
}

TEST_CASE("IN_SCRIPT: </script with space then > closes script", "[html_scanner][script][audit]")
{
  // Per HTML spec §13.2.6.3: tab/LF/FF/space after tag name is valid separator.
  std::string html = R"(<html><head><script>x=1;</script ><link rel="stylesheet" href="/sp.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/sp.css") != std::string::npos);
}

// dup-01: removed duplicate "</script with newline then >" — already tested above (line ~128)

TEST_CASE("IN_SCRIPT: </script with form-feed then > closes script", "[html_scanner][script][audit]")
{
  std::string html = "<html><head><script>x=1;</script\f><link rel=\"stylesheet\" href=\"/ff.css\"></head></html>";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ff.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: </script with trailing attrs then > closes script", "[html_scanner][script][audit]")
{
  // </script type="text/javascript"> — trailing content after whitespace, waiting for >
  std::string html = R"(<html><head><script>x=1;</script type="text/javascript">)"
                     R"(<link rel="stylesheet" href="/attr.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/attr.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: partial </scri at EOF then resumed in next feed", "[html_scanner][script][audit]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(131072, 10, &config);
  // Feed ends mid-close-tag: "</scri"
  std::string part1 = "<html><head><script>x=1;</scri";
  scanner.feed(part1.c_str(), static_cast<int64_t>(part1.size()));
  CHECK(!scanner.is_done());

  // Next feed completes the close tag and has a link
  std::string part2 = R"(pt><link rel="stylesheet" href="/resumed.css"></head></html>)";
  scanner.feed(part2.c_str(), static_cast<int64_t>(part2.size()));
  CHECK(scanner.is_done());
  REQUIRE(scanner.get_links().size() == 1);
  CHECK(scanner.get_links()[0].find("/resumed.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: failed close tag match then real close tag", "[html_scanner][script][audit]")
{
  // "</scriXt>" fails matching, then "</script>" succeeds.
  std::string html = R"(<html><head><script>var x = '</scriXt>';</script>)"
                     R"(<link rel="stylesheet" href="/retry.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/retry.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: < in middle of close tag match restarts", "[html_scanner][script][audit]")
{
  // "</scr<ipt>" — the '<' at position 5 restarts matching from '<'.
  // The real close is later.
  std::string html = R"(<html><head><script>x="</scr<ipt>";</script>)"
                     R"(<link rel="stylesheet" href="/restart.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/restart.css") != std::string::npos);
}

// ─── QA audit: IN_SCRIPT escaped mode gap tests ─────────────────────────────

TEST_CASE("IN_SCRIPT: --> in non-escaped mode has no effect", "[html_scanner][script][audit]")
{
  // Without a preceding <!--, --> is just text in script body.
  std::string html = R"(<html><head><script>var x = '-->';</script>)"
                     R"(<link rel="stylesheet" href="/noesc.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/noesc.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: --!> in escaped mode does NOT exit escaped", "[html_scanner][script][audit]")
{
  // Per HTML spec §13.2.6.6: in escaped dash-dash state, '!' goes back to escaped.
  // So --!> does NOT exit escaped mode.
  // However, per §13.2.6.4: </script> in escaped mode IS a valid end tag (B-06 fix).
  // After <!--, the first --!> should NOT exit escaped. But </script> after it closes.
  std::string html = R"(<html><head><script><!--)"
                     R"(--!></script><link rel="preload" href="/evil.css" as="style">)"
                     R"(--></script><link rel="stylesheet" href="/real.css"></head></html>)";
  auto links = scan_html(html);
  // --!> does NOT exit escaped → </script> in escaped mode closes (B-06 fix).
  // → /evil.css is exposed after the first </script>.
  // --> and second </script> are stray in IN_HEAD.
  // → /real.css is also exposed.
  REQUIRE(links.size() == 2);
  bool has_evil = false, has_real = false;
  for (const auto &l : links) {
    if (l.find("/evil.css") != std::string::npos)
      has_evil = true;
    if (l.find("/real.css") != std::string::npos)
      has_real = true;
  }
  CHECK(has_evil);
  CHECK(has_real);
}

TEST_CASE("IN_SCRIPT: double <!-- does not stack", "[html_scanner][script][audit]")
{
  // Second <!-- while already in escaped mode is ignored (scanner only tracks -->).
  // A single --> should exit escaped mode.
  std::string html = R"(<html><head><script><!-- <!-- --></script>)"
                     R"(<link rel="stylesheet" href="/double.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/double.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: <script> inside escaped mode does not affect state", "[html_scanner][script][audit]")
{
  // Our scanner doesn't implement double-escaped state (not needed for link extraction).
  // <script> inside escaped mode is ignored; only --> exits escaped.
  std::string html = R"(<html><head><script><!-- <script> --></script>)"
                     R"(<link rel="stylesheet" href="/esc-script.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/esc-script.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: <!-- immediately followed by --> exits escaped", "[html_scanner][script][audit]")
{
  std::string html = R"(<html><head><script><!---->)</script>)"
                     R"(<link rel="stylesheet" href="/quick.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/quick.css") != std::string::npos);
}

TEST_CASE("IN_SCRIPT: <!- (incomplete comment open) does not enter escaped", "[html_scanner][script][audit]")
{
  // "<!-X" doesn't complete "<!--", so no escaped mode. </script> still works.
  std::string html = R"(<html><head><script><!-X</script>)"
                     R"(<link rel="stylesheet" href="/partial-comment.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/partial-comment.css") != std::string::npos);
}

// ─── QA audit: DONE state gap tests ─────────────────────────────────────────

TEST_CASE("QA: comment state 0 × null byte stays in body", "[html_scanner][comment][qa]")
{
  // NUL inside comment body must not break the parser — stays in state 0.
  // The link after --> must still be found.
  std::string html = "<html><head><!-- x";
  html += '\0';
  html += R"(y --><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: comment state 0 × '>' stays in body", "[html_scanner][comment][qa]")
{
  // '>' in state 0 must NOT close the comment.
  std::string html =
    R"(<html><head><!-- text > more text <link rel="stylesheet" href="/bad.css"> --><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 0 × '!' stays in body", "[html_scanner][comment][qa]")
{
  // '!' in state 0 does nothing — stays in body.
  std::string html = R"(<html><head><!-- hello!world --><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: comment state 0 × '@' (other) stays in body", "[html_scanner][comment][qa]")
{
  std::string html = R"(<html><head><!-- @todo --><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

// ─── State 1 (end-dash: seen one '-') ───────────────────────────────────────

TEST_CASE("QA: comment state 1 × '>' does NOT close (-> in body)", "[html_scanner][comment][qa]")
{
  // A single dash then '>' must NOT close.  Only '-->' closes.
  // "<!-- abc -> <link bad> -->"  — the "->" must not end the comment.
  std::string html =
    R"(<html><head><!-- abc -><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 1 × space resets to body", "[html_scanner][comment][qa]")
{
  // "- " (dash then space) in comment → back to body.
  std::string html = R"(<html><head><!-- a- b --><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: comment state 1 × null resets to body", "[html_scanner][comment][qa]")
{
  // dash then NUL → back to body.
  std::string html = "<html><head><!-- a-";
  html += '\0';
  html += R"( --><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: comment state 1 × '@' (other) resets to body", "[html_scanner][comment][qa]")
{
  std::string html = R"(<html><head><!-- a-@ --><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

// ─── State 2 (end: seen '--') ───────────────────────────────────────────────

TEST_CASE("QA: comment state 2 × alpha resets to body (--a)", "[html_scanner][comment][qa]")
{
  // "--a" inside a comment: end state sees alpha → back to body.
  // The comment must NOT close on the subsequent ">".
  std::string html =
    R"(<html><head><!-- --a><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 2 × null resets to body", "[html_scanner][comment][qa]")
{
  std::string html = "<html><head><!-- --";
  html += '\0';
  html += R"(><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 2 × '@' (other) resets to body", "[html_scanner][comment][qa]")
{
  std::string html =
    R"(<html><head><!-- --@><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

// ─── State 3 (end-bang: seen '--!') ─────────────────────────────────────────

TEST_CASE("QA: comment state 3 × alpha resets to body (--!a)", "[html_scanner][comment][qa]")
{
  // "--!a" → bang then alpha → back to body; "> " does not close.
  std::string html =
    R"(<html><head><!-- --!a><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 3 × space resets to body (--! )", "[html_scanner][comment][qa]")
{
  std::string html =
    R"(<html><head><!-- --! ><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 3 × null resets to body", "[html_scanner][comment][qa]")
{
  std::string html = "<html><head><!-- --!";
  html += '\0';
  html += R"(><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

// ─── State 4 (end-bang-dash: seen '--!-') ───────────────────────────────────

TEST_CASE("QA: comment state 4 × '!' resets to body (--!-!)", "[html_scanner][comment][qa]")
{
  // "--!-!" → bang-dash then bang → back to body; need --> to close.
  std::string html =
    R"(<html><head><!-- --!-!><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 4 × alpha resets to body (--!-a)", "[html_scanner][comment][qa]")
{
  std::string html =
    R"(<html><head><!-- --!-a><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 4 × space resets to body (--!- )", "[html_scanner][comment][qa]")
{
  std::string html =
    R"(<html><head><!-- --!- ><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 4 × null resets to body", "[html_scanner][comment][qa]")
{
  std::string html = "<html><head><!-- --!-";
  html += '\0';
  html += R"(><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

// ─── State 5 (comment-start) ───────────────────────────────────────────────

TEST_CASE("QA: comment state 5 × null enters body", "[html_scanner][comment][qa]")
{
  // NUL right after "<!--" is "anything else" → body.
  std::string html = "<html><head><!--";
  html += '\0';
  html += R"(--><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: comment state 5 × '@' (other) enters body", "[html_scanner][comment][qa]")
{
  // '@' right after "<!--" → body; then --> closes.
  std::string html = R"(<html><head><!--@--><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

// ─── State 6 (comment-start-dash) ──────────────────────────────────────────

TEST_CASE("QA: comment state 6 × '-' enters end state (<!---->)", "[html_scanner][comment][qa]")
{
  // "<!---->" is a valid empty comment per spec: start→start-dash→end→close.
  std::string html = R"(<html><head><!----><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: comment state 6 × '!' enters body (<!---!)", "[html_scanner][comment][qa]")
{
  // "<!---!" → start-dash then '!' (anything else) → body.
  // The subsequent ">" does NOT close the comment.
  std::string html =
    R"(<html><head><!---!><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 6 × space enters body (<!--- )", "[html_scanner][comment][qa]")
{
  // "<!--- " → start-dash then space → body; need --> to close.
  std::string html =
    R"(<html><head><!--- ><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

TEST_CASE("QA: comment state 6 × null enters body", "[html_scanner][comment][qa]")
{
  std::string html = "<html><head><!---";
  html += '\0';
  html += R"(><link rel="stylesheet" href="/bad.css">--><link rel="stylesheet" href="/good.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/good.css") != std::string::npos);
  CHECK(links[0].find("/bad.css") == std::string::npos);
}

// ─── IN_BOGUS_COMMENT state ────────────────────────────────────────────────

TEST_CASE("QA: bogus comment × null stays in bogus", "[html_scanner][bogus][qa]")
{
  // NUL inside bogus comment must not break parser.
  std::string html = "<html><head><!bogus";
  html += '\0';
  html += R"(stuff><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: bogus comment × '-' stays in bogus", "[html_scanner][bogus][qa]")
{
  // Dashes inside bogus comment are NOT special.
  std::string html = R"(<html><head><!bogus--><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("QA: bogus comment × '!' stays in bogus", "[html_scanner][bogus][qa]")
{
  std::string html = R"(<html><head><!bogus!><link rel="stylesheet" href="/ok.css"></head></html>)";
  auto links       = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

// ─── No infinite loops: deeply nested dash sequences ────────────────────────

TEST_CASE("QA: no infinite loop with long dash sequences", "[html_scanner][comment][qa]")
{
  SECTION("50 consecutive dashes inside comment still closes on -->")
  {
    std::string html = "<html><head><!--";
    html += std::string(50, '-');
    html += R"(><link rel="stylesheet" href="/ok.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok.css") != std::string::npos);
  }

  SECTION("alternating --!--!--!-- eventually closes on -->")
  {
    // --!--!--!--> should close: each --! cycle goes 2→3, then - goes 3→4,
    // then - goes 4→2, then ! goes 2→3, ..., final --> from state 2 closes.
    std::string html = "<html><head><!--";
    for (int i = 0; i < 10; ++i) {
      html += "--!";
    }
    html += R"(--><link rel="stylesheet" href="/ok.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok.css") != std::string::npos);
  }

  SECTION("long bogus comment with mixed content closes on first >")
  {
    std::string html = "<html><head><!xyzzy";
    html += std::string(100, '-');
    html += "!!!---";
    html += R"(><link rel="stylesheet" href="/ok.css"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/ok.css") != std::string::npos);
  }
}

// ─── Single-byte equivalence for new edge cases ─────────────────────────────

TEST_CASE("QA: single-byte feed equivalence for comment edge cases", "[html_scanner][comment][qa][chunking]")
{
  auto check_single_byte_equivalence = [](const std::string &html) {
    auto single  = scan_html(html);
    auto chunked = scan_html_chunked(html, 1);
    CHECK(single == chunked);
  };

  SECTION("<!---->") { check_single_byte_equivalence(R"(<html><head><!----><link rel="stylesheet" href="/a.css"></head></html>)"); }
  SECTION("<!---!>")
  {
    check_single_byte_equivalence(R"(<html><head><!---!>bad--><link rel="stylesheet" href="/a.css"></head></html>)");
  }
  SECTION("--a>")
  {
    check_single_byte_equivalence(R"(<html><head><!-- --a>bad--><link rel="stylesheet" href="/a.css"></head></html>)");
  }
  SECTION("--!a>")
  {
    check_single_byte_equivalence(R"(<html><head><!-- --!a>bad--><link rel="stylesheet" href="/a.css"></head></html>)");
  }
  SECTION("--!-!>")
  {
    check_single_byte_equivalence(R"(<html><head><!-- --!-!>bad--><link rel="stylesheet" href="/a.css"></head></html>)");
  }
  SECTION("->")
  {
    check_single_byte_equivalence(R"(<html><head><!-- ->bad--><link rel="stylesheet" href="/a.css"></head></html>)");
  }
}

// ============================================================================
// R5 Bug Regression Tests — TDD RED phase
// ============================================================================
