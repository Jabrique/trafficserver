/** @file
 * HtmlScanner unit tests: Security, pentest, scheme validation, regression (R5/R6)
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

TEST_CASE("HtmlScanner rejects dangerous URL schemes", "[html_scanner][security]")
{
  SECTION("javascript: scheme rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"javascript:alert(1)\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("JAVASCRIPT: uppercase rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"JAVASCRIPT:alert(1)\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("data: scheme rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"data:text/html,&lt;script&gt;\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("vbscript: scheme rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"vbscript:MsgBox(1)\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("blob: scheme rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"blob:https://evil.com/abc123\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("mixed case jAvAsCrIpT: rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"jAvAsCrIpT:alert(1)\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("href with > character rejected (Link header injection)")
  {
    std::string html = R"(<html><head><link rel="preload" href="/foo>; rel=preload, </evil" as="script"></head></html>)";
    auto links       = scan_html(html);
    // href contains > which would break Link header format  -- must be rejected
    CHECK(links.empty());
  }

  SECTION("href with < character rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="/foo<bar" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("whitespace-only href rejected")
  {
    // A href of all spaces is useless and wastes header budget
    std::string html = R"(<html><head><link rel="preload" href="   " as="style"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("tab-only href rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"\t\t\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- Allowlist bypass: schemes that pass the denylist but shouldn't ----------

TEST_CASE("HtmlScanner rejects non-http/https URL schemes (allowlist)", "[html_scanner][security][allowlist]")
{
  SECTION("file: scheme rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="file:///etc/passwd" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("ftp: scheme rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="ftp://evil.com/malware.exe" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("ws: websocket scheme rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="ws://evil.com/socket" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("wss: secure websocket scheme rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="wss://evil.com/socket" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("feed:javascript: nested scheme rejected")
  {
    std::string html = R"html(<html><head><link rel="preload" href="feed:javascript:alert(1)" as="script"></head></html>)html";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("jar: scheme rejected")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="jar:https://evil.com/malware.jar!/exploit" as="script"></head></html>)";
    auto links = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("view-source: pseudo-scheme rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="view-source:https://evil.com" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("http: scheme still allowed")
  {
    std::string html = R"(<html><head><link rel="preload" href="http://cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("https: scheme still allowed")
  {
    std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("relative URL still allowed")
  {
    std::string html = R"(<html><head><link rel="preload" href="/assets/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("protocol-relative URL still allowed")
  {
    std::string html = R"(<html><head><link rel="preload" href="//cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("bare relative path still allowed")
  {
    std::string html = R"(<html><head><link rel="preload" href="images/hero.webp" as="image"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("leading-space javascript: still rejected")
  {
    std::string html = R"html(<html><head><link rel="preload" href="   javascript:alert(1)" as="script"></head></html>)html";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("JAVASCRIPT: uppercase still rejected")
  {
    std::string html = R"html(<html><head><link rel="preload" href="JAVASCRIPT:alert(1)" as="script"></head></html>)html";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("data: still rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="data:text/html,evil" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("blob: still rejected")
  {
    std::string html = R"(<html><head><link rel="preload" href="blob:https://evil.com/abc" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("vbscript: still rejected")
  {
    std::string html = R"html(<html><head><link rel="preload" href="vbscript:MsgBox(1)" as="script"></head></html>)html";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- Additional edge cases ---------------------------------------------------

TEST_CASE("HtmlScanner: CDATA bogus comment handling", "[html_scanner][security][edge]")
{
  SECTION("CDATA section treated as bogus comment  -- inner link ignored")
  {
    // Per HTML spec §13.2.5.42, <![CDATA[ in HTML context is a bogus comment.
    // Everything until the first > is consumed. Links inside should NOT be extracted.
    std::string html = R"(<html><head><![CDATA[<link rel="preload" href="/evil.css" as="style">]]>)"
                       R"(<link rel="preload" href="/real.css" as="style"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.css") != std::string::npos);
    CHECK(links[0].find("/evil.css") == std::string::npos);
  }
}

TEST_CASE("HtmlScanner: script data escaped state", "[html_scanner][security][edge]")
{
  SECTION("</script> in escaped mode closes the script")
  {
    // Per HTML spec §13.2.6.4 ("script data escaped end tag name" state),
    // </script> IS a valid end tag in escaped mode and MUST close the script element.
    // After fix: the first </script> closes the script  -- /evil.css is exposed.
    // --> and the second </script> are stray in IN_HEAD and ignored.
    // /real.css is then also extracted after the second </script>.
    std::string html = R"(<html><head><script><!--</script>)"
                       R"(<link rel="preload" href="/evil.css" as="style">)"
                       R"(--></script><link rel="preload" href="/real.css" as="style"></head></html>)";
    auto links = scan_html(html);
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
}

// --- Edge cases: duplicate attributes (first-vs-last wins) ------------------

TEST_CASE("HtmlScanner: extract_origin authority terminators", "[html_scanner][security]")
{
  SECTION("fragment in URL does not leak into origin")
  {
    // Attacker tries to bypass whitelist: https://attacker.com#.cdn.example.com/x
    // extract_origin must stop at '#' and return https://attacker.com
    std::string html =
      R"(<html><head><link rel="preload" href="https://attacker.com#.cdn.example.com/evil.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // Without whitelist, cross-origin → preconnect to origin only
    CHECK(links[0].find("attacker.com#") == std::string::npos);
    CHECK(links[0].find("https://attacker.com>") != std::string::npos);
  }

  SECTION("query string in URL does not leak into origin")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="https://attacker.com?.cdn.example.com/evil.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("attacker.com?") == std::string::npos);
    CHECK(links[0].find("https://attacker.com>") != std::string::npos);
  }

  SECTION("protocol-relative with fragment stops at #")
  {
    std::string html = R"(<html><head><link rel="preload" href="//cdn.example.com#frag/path" as="style"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("https://cdn.example.com>") != std::string::npos);
    CHECK(links[0].find("#frag") == std::string::npos);
  }
}

TEST_CASE("html_scanner script injection via digit after close tag name", "[html_scanner][security]")
{
  // Per HTML spec, </script0> is NOT a valid close tag (digit after tag name).
  // The scanner must stay in IN_SCRIPT and not parse fake tags inside script content.
  SECTION("digit after </script does not exit script state")
  {
    std::string html = R"(<html><head><script>x="</script0><link rel=preload href=//evil.com/x as=font>";</script>)"
                       R"(<link rel="preload" href="/real.css" as="style"></head></html>)";
    auto links = scan_html(html);
    // Only the real link after </script> should be found, not the fake one inside the script
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.css") != std::string::npos);
    CHECK(links[0].find("evil.com") == std::string::npos);
  }

  SECTION("punctuation after </script does not exit script state")
  {
    std::string html = R"(<html><head><script>x="</script.><link rel=preload href=//evil.com/x as=font>";</script>)"
                       R"(<link rel="preload" href="/real.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.js") != std::string::npos);
    CHECK(links[0].find("evil.com") == std::string::npos);
  }

  SECTION("slash after </script is valid close tag")
  {
    // </script/> should be treated as valid end tag (self-closing end tag parse error but accepted)
    std::string html = R"(<html><head><script>x=1;</script/><link rel="preload" href="/after.css" as="style"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }

  SECTION("tab after </script is valid close tag")
  {
    std::string html = "<html><head><script>x=1;</script\t><link rel=\"preload\" href=\"/after.css\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/after.css") != std::string::npos);
  }
}

// --- Exhaustive chunk-boundary splitting tests ------------------------------
//
// These tests verify that the state machine produces identical results
// regardless of where the input is split across feed() calls.
// Each test feeds the SAME HTML both as a single call and as two explicit
// chunks at a critical byte boundary, then compares results.

TEST_CASE("HtmlScanner is_safe_url: leading whitespace before javascript:", "[html_scanner][security]")
{
  std::string html = "<html><head><link rel=\"preload\" href=\"   javascript:alert(1)\" as=\"script\"></head></html>";
  auto links       = scan_html(html);
  CHECK(links.empty());
}

TEST_CASE("HtmlScanner is_safe_url: tab before data:", "[html_scanner][security]")
{
  std::string html = "<html><head><link rel=\"preload\" href=\"\tdata:text/html,evil\" as=\"script\"></head></html>";
  auto links       = scan_html(html);
  CHECK(links.empty());
}

// --- BUG REGRESSION: extract_origin must handle backslash-prefixed URLs -----

// --- FINDING: extract_origin does NOT normalize backslash URLs --------------
// is_crossorigin() correctly detects \\, \/, /\ as cross-origin (WHATWG URL spec),
// but extract_origin() doesn't handle these  -- it only looks for "://" and "//".
// Result: preconnect Link header contains raw backslashes instead of proper origin.
// BUG FIX: extract_origin must normalize backslash-prefixed URLs to proper origins.
// Per WHATWG URL spec §4.2, browsers treat \ as / in special schemes.

TEST_CASE("HtmlScanner: backslash cross-origin URLs are rejected by URL sanitization", "[html_scanner][security][regression]")
{
  SECTION("double-backslash URL rejected at URL validation (not preconnected)")
  {
    // is_safe_url() now rejects \\evil.com before is_crossorigin() is evaluated.
    // This is a stricter defense: no hint of any kind is emitted for these URLs.
    std::string html = R"(<html><head><link rel="preload" href="\\evil.com/tracker.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty()); // URL rejected outright  -- no preconnect emitted
  }

  SECTION("slash-backslash URL rejected at URL validation")
  {
    std::string html = R"(<html><head><link rel="preload" href="/\evil.com/tracker.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("backslash-slash URL rejected at URL validation")
  {
    std::string html = R"(<html><head><link rel="preload" href="\/evil.com/tracker.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- QA audit: IN_SCRIPT state gap tests -------------------------------------

TEST_CASE("PENTEST: Header Injection via CRLF in href", "[pentest][header_injection]")
{
  SECTION("raw CRLF in href to inject arbitrary header")
  {
    // Attack: href="/style.css\r\nX-Evil: injected"
    // If this gets into Link: </style.css\r\nX-Evil: injected>; ...
    // the response would contain a rogue X-Evil header.
    std::string evil_href = "/style.css\r\nX-Evil: injected";
    std::string html      = "<html><head><link rel=\"preload\" href=\"" + evil_href + "\" as=\"style\"></head></html>";
    auto links            = scan_html(html);
    // MUST be empty  -- CRLF bytes must be rejected by is_safe_url()
    CHECK(links.empty());
    // Double-check: if any link was emitted, it must NOT contain \r or \n
    for (const auto &link : links) {
      CHECK(link.find('\r') == std::string::npos);
      CHECK(link.find('\n') == std::string::npos);
    }
  }

  SECTION("URL-encoded CRLF (%0d%0a) in href  -- literal passthrough")
  {
    // Attack: href="/style.css%0d%0aX-Evil: injected"
    // The scanner operates on raw bytes, not URL-decoded values. %0d%0a as
    // literal ASCII characters are safe in a URL context (they're percent-
    // encoded). The real danger is raw 0x0d/0x0a bytes (tested above).
    // This test verifies the scanner does NOT reject valid percent-encoded URLs.
    std::string html = R"(<html><head><link rel="preload" href="/style.css%0d%0aX-Evil:%20injected" as="style"></head></html>)";
    auto links       = scan_html(html);
    // Percent-encoded sequences are safe  -- browsers don't decode them in header context.
    // The link SHOULD be emitted (it's a valid URL).
    REQUIRE(links.size() == 1);
    // Verify the emitted value does NOT contain actual CRLF bytes
    CHECK(links[0].find('\r') == std::string::npos);
    CHECK(links[0].find('\n') == std::string::npos);
  }

  SECTION("bare CR without LF in href is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/x\ry\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("bare LF without CR in href is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/x\ny\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("CRLF after valid path to inject second Link value")
  {
    // Attack: try to close the first Link value and start a second
    std::string evil_href = "/legit.js>; rel=preload; as=script\r\nLink: </evil.js>; rel=preload; as=script";
    std::string html      = "<html><head><link rel=\"preload\" href=\"" + evil_href + "\" as=\"script\"></head></html>";
    auto links            = scan_html(html);
    // Must reject: the href contains '>' which breaks Link header framing, AND contains CRLF
    CHECK(links.empty());
  }

  SECTION("null byte in href is rejected")
  {
    std::string html = std::string("<html><head><link rel=\"preload\" href=\"/app") + '\0' + ".js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("DEL (0x7F) character in href is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app\x7Fjs\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("vertical tab (0x0B) in href is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app\x0Bjs\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("form feed (0x0C) in href is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/app\x0Cjs\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }
}

// --- 2. HTML Parser Confusion ------------------------------------------------
//
// Attempt to confuse the state machine so it extracts attacker-controlled URLs.

TEST_CASE("PENTEST: HTML Parser Confusion  -- nested/malformed tags", "[pentest][parser_confusion]")
{
  SECTION("nested <link inside <link  -- attempt to inject via tag nesting")
  {
    // Attack: <link <link href="/real" ...> href="/evil" ...>
    // If parser re-enters tag parsing on the inner '<', it might pick up /real
    // from the nested context. The outer /evil should not be extracted.
    std::string html =
      R"(<html><head><link <link href="/real.js" rel="preload" as="script"> href="/evil.js" rel="preload" as="script"></head></html>)";
    auto links = scan_html(html);
    // The '<' inside the tag is unexpected  -- parser should reset or handle safely.
    // /evil.js must NOT appear as a valid link.
    for (const auto &link : links) {
      CHECK(link.find("/evil.js") == std::string::npos);
    }
  }

  SECTION("null byte inside tag name  -- <link\\0 ...>")
  {
    // Attack: null byte to confuse C string processing vs std::string processing
    std::string html = std::string("<html><head><link") + '\0' + " rel=\"preload\" href=\"/null.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    // Null byte breaks tag name parsing  -- the tag should not be recognized as <link>.
    // Any extracted URL must not be /null.js (attacker-influenced content after NUL).
    // Most importantly: no crash.
    for (const auto &link : links) {
      CHECK(link.find("/null.js") == std::string::npos);
    }
  }

  SECTION("UTF-8 BOM before <html> does not prevent scanning")
  {
    // BOM = EF BB BF  -- should be treated as whitespace/noise before <html>
    std::string bom  = "\xEF\xBB\xBF";
    std::string html = bom + "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    // Scanner should still find <head> and extract the link
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/app.js") != std::string::npos);
  }

  SECTION("extremely long tag name (>64KB)  -- no crash, no extraction")
  {
    // Attack: huge tag name to trigger buffer overflow or excessive memory use
    std::string huge_tag(70000, 'a');
    std::string html = "<html><head><" + huge_tag + " rel=\"preload\" href=\"/exploit.js\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    // Tag name doesn't match "link" or "script"  -- no link should be extracted.
    // Must not crash or cause OOM.
    CHECK(links.empty());
  }

  SECTION("HTML entities in attribute values  -- no entity decoding")
  {
    // Attack: use HTML entities to sneak past scheme checks
    // &#60; = '<', &#62; = '>'  -- if decoded, this becomes <script>
    std::string html = R"EH(<html><head><link rel="preload" href="&#106;avascript:alert(1)" as="script"></head></html>)EH";
    auto links       = scan_html(html);
    // The scanner does NOT decode HTML entities (by design  -- it's not a full parser).
    // The href value is literally "&#106;avascript:alert(1)".
    // This does NOT start with "javascript:" so it passes scheme check.
    // Browsers will entity-decode attribute values in HTML context, so the actual
    // URL would be "javascript:alert(1)". However, Link headers are NOT HTML  --
    // they're HTTP headers. Browsers do NOT entity-decode HTTP header values.
    // Therefore the literal "&#106;avascript:..." is harmless in a Link header.
    // Must either reject entirely (empty) or contain the literal entity, not decoded form.
    CHECK((links.empty() || links[0].find("&#106;") != std::string::npos));
    CHECK((links.empty() || links[0].find("javascript:") == std::string::npos));
  }

  SECTION("tag name with digits  -- <link2> is not <link>")
  {
    std::string html = R"(<html><head><link2 rel="preload" href="/trick.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("attribute value with embedded > to break out of tag")
  {
    // Attack: close the tag prematurely with > inside unquoted attribute
    std::string html = R"(<html><head><link rel=preload href=/legit.js>; rel=preload as=script></head></html>)";
    auto links       = scan_html(html);
    // The > after /legit.js closes the tag. "as" was never set, so preload
    // requires as= → no link emitted (or if emitted, missing as=).
    // Key: the injected "; rel=preload" after > must NOT create a second link.
    CHECK(links.size() <= 1);
    for (const auto &link : links) {
      CHECK(link.find("; rel=preload as=script") == std::string::npos);
    }
  }
}

// --- 3. Cache Poisoning -----------------------------------------------------
//
// Test the HintsCache::make_key normalization to verify attackers cannot
// poison one URL's cache entry to serve different hints for another URL.

TEST_CASE("PENTEST: Cache Key Isolation", "[pentest][cache_poisoning]")
{
  SECTION("query string is stripped  -- different query params share same key")
  {
    // This is expected behavior (documented) but important to verify:
    // /page.html?v=1 and /page.html?v=2 share the same cache key.
    std::string key1 = HintsCache::make_key("/page.html?v=1", 14);
    std::string key2 = HintsCache::make_key("/page.html?v=2", 14);
    // These SHOULD be equal  -- query string is intentionally stripped
    CHECK(key1 == key2);
    CHECK(key1 == "/page.html");
  }

  SECTION("fragment is NOT stripped  -- different fragments get different keys")
  {
    // Fragments (#) are not query strings  -- verify they're part of the key
    // Note: make_key only strips at '?', not at '#'
    std::string key1 = HintsCache::make_key("/page.html#section1", 19);
    std::string key2 = HintsCache::make_key("/page.html#section2", 19);
    // Fragment IS included in the key (make_key only strips query strings)
    CHECK(key1 != key2);
  }

  SECTION("different paths produce different keys")
  {
    std::string key1 = HintsCache::make_key("/index.html", 11);
    std::string key2 = HintsCache::make_key("/about.html", 11);
    CHECK(key1 != key2);
  }

  SECTION("path traversal in key  -- ../admin vs /admin")
  {
    // make_key does NOT normalize path traversal  -- verify they produce different keys
    std::string key1 = HintsCache::make_key("/foo/../admin", 13);
    std::string key2 = HintsCache::make_key("/admin", 6);
    // Without path normalization, these should be different keys.
    // If they were the same, an attacker could poison /admin's hints
    // by requesting /foo/../admin.
    CHECK(key1 != key2);
  }

  SECTION("null path returns safe default")
  {
    std::string key = HintsCache::make_key(nullptr, 0);
    CHECK(key == "/");
  }

  SECTION("empty path returns safe default")
  {
    std::string key = HintsCache::make_key("", 0);
    CHECK(key == "/");
  }

  SECTION("query-string-only path returns safe default")
  {
    std::string key = HintsCache::make_key("?foo=bar", 8);
    CHECK(key == "/");
  }

  SECTION("cache entry isolation  -- different paths serve different hints")
  {
    HintsCache cache(100);
    std::vector<std::string> links_page1 = {"</a.js>; rel=preload; as=script"};
    std::vector<std::string> links_page2 = {"</b.css>; rel=preload; as=style"};

    cache.put("/page1", links_page1);
    cache.put("/page2", links_page2);

    // Put multiple times to exceed default min_hits of 2
    cache.put("/page1", links_page1);
    cache.put("/page2", links_page2);

    std::vector<std::string> out;
    CHECK(cache.get("/page1", out, 1));
    REQUIRE(out.size() == 1);
    CHECK(out[0].find("/a.js") != std::string::npos);

    out.clear();
    CHECK(cache.get("/page2", out, 1));
    REQUIRE(out.size() == 1);
    CHECK(out[0].find("/b.css") != std::string::npos);
  }
}

// --- 4. XSS via Link Header  -- dangerous URL schemes ------------------------
//
// Test that javascript:, data:, vbscript:, blob: URLs are blocked from
// appearing in Link headers. While browsers shouldn't execute these from Link
// headers, defense-in-depth requires blocking them.

TEST_CASE("PENTEST: XSS via Link Header  -- scheme filtering", "[pentest][xss]")
{
  SECTION("javascript: URL blocked from Link header (scanner)")
  {
    std::string html = R"EH(<html><head><link rel="preload" href="javascript:alert(document.cookie)" as="script"></head></html>)EH";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("data: URI blocked from Link header (scanner)")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" as="script"></head></html>)";
    auto links = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("javascript: with leading whitespace bypass attempt")
  {
    // Browsers strip leading whitespace from URLs  -- test that we do too
    std::string html = R"EH(<html><head><link rel="preload" href="   javascript:alert(1)" as="script"></head></html>)EH";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("javascript: with leading tab bypass attempt")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"\tjavascript:alert(1)\" as=\"script\"></head></html>";
    auto links       = scan_html(html);
    // Tab is a control char (< 0x20) → rejected by is_safe_url
    CHECK(links.empty());
  }

  SECTION("jAvAsCrIpT: mixed case bypass attempt")
  {
    std::string html = R"EH(<html><head><link rel="preload" href="jAvAsCrIpT:alert(1)" as="script"></head></html>)EH";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("data: URI with MIME type attempting HTML injection")
  {
    std::string html =
      R"EH(<html><head><link rel="preload" href="data:text/html,<img src=x onerror=alert(1)>" as="document"></head></html>)EH";
    auto links = scan_html(html);
    // data: blocked, AND href contains '<' and '>' which are also blocked
    CHECK(links.empty());
  }

  SECTION("blob: URL blocked")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="blob:https://evil.com/550e8400-e29b-41d4-a716-446655440000" as="script"></head></html>)";
    auto links = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("vbscript: URL blocked")
  {
    std::string html = R"EH(<html><head><link rel="preload" href="vbscript:MsgBox(1)" as="script"></head></html>)EH";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("javascript: in config --link value is rejected")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "<javascript:alert(1)>; rel=preload; as=script"};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("data: in config --link value is rejected")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "<data:text/html,evil>; rel=preload; as=script"};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("CRLF in config --link value is rejected")
  {
    EarlyHintsConfig config;
    std::string evil_link = std::string("</style.css\r\nX-Evil: injected>; rel=preload; as=style");
    const char *argv[]    = {"from", "to", "--mode", "manual", "--link", evil_link.c_str()};
    CHECK(config.init(6, argv) == false);
  }
}

// --- 5. Parameter Injection via as= / type= / crossorigin= -----------------
//
// Verify that crafted attribute values cannot inject extra Link header params.

TEST_CASE("PENTEST: Link Header Parameter Injection", "[pentest][param_injection]")
{
  SECTION("as= with semicolon to inject extra param")
  {
    // Attack: as="script; nonce=abc" → Link: <...>; rel=preload; as=script; nonce=abc
    std::string html = R"(<html><head><link rel="preload" href="/app.js" as="script; nonce=abc"></head></html>)";
    auto links       = scan_html(html);
    // "script; nonce=abc" is NOT a valid fetch destination → as_ should be cleared
    CHECK(links.empty());
  }

  SECTION("as= with comma to inject second Link value")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="/app.js" as="script, </evil>; rel=preload; as=script"></head></html>)";
    auto links = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("type= with semicolon is sanitized")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="font/woff2; evil=injected"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // Semicolons and equals must be stripped from type value (prevents header injection)
    CHECK(links[0].find("; evil=injected") == std::string::npos);
    // The type sanitizer strips semicolons, equals, spaces  -- only keeps alnum/+/./-
    // So "; evil=injected" won't appear as a separate parameter
    bool no_injected_param = (links[0].find("; evil=injected") == std::string::npos);
    CHECK(no_injected_param);
  }

  SECTION("type= with angle brackets is sanitized")
  {
    std::string html = R"(<html><head><link rel="preload" href="/font.woff2" as="font" type="font/woff2<>"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find('<') == 0); // only the opening < of the URL
    // Count angle brackets  -- should be exactly the Link header framing ones
    int open_count = 0, close_count = 0;
    for (char c : links[0]) {
      if (c == '<')
        open_count++;
      if (c == '>')
        close_count++;
    }
    CHECK(open_count == 1);
    CHECK(close_count == 1);
  }

  SECTION("crossorigin= with injection attempt")
  {
    // Only "anonymous" and "use-credentials" are valid  -- anything else gets lowercased
    // but the build_link_header only emits known values
    std::string html =
      R"(<html><head><link rel="preload" href="/x.js" as="script" crossorigin="use-credentials; evil=param"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // The crossorigin value is lowercased and compared to "anonymous" or "use-credentials"
    // "use-credentials; evil=param" does not match either → no crossorigin emitted
    CHECK(links[0].find("evil") == std::string::npos);
  }

  SECTION("fetchpriority= with injection attempt")
  {
    std::string html =
      R"(<html><head><link rel="preload" href="/x.js" as="script" fetchpriority="high; evil=param"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // "high; evil=param" is not "high", "low", or "auto" → fetchpriority not emitted
    CHECK(links[0].find("fetchpriority") == std::string::npos);
    CHECK(links[0].find("evil") == std::string::npos);
  }
}

// --- 6. Config Validation  -- manual --link injection -------------------------

TEST_CASE("PENTEST: Config --link validation", "[pentest][config_injection]")
{
  SECTION("--link with control characters rejected")
  {
    EarlyHintsConfig config;
    std::string evil   = std::string("</app.js\x01>; rel=preload; as=script");
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", evil.c_str()};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("--link with null byte rejected")
  {
    EarlyHintsConfig config;
    std::string evil   = std::string("</app") + '\0' + ".js>; rel=preload; as=script";
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", evil.c_str()};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("--link without valid rel= rejected")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "</app.js>; rel=evil; as=script"};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("--link with nested angle brackets rejected")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "<<evil>>; rel=preload; as=script"};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("--link with empty URL rejected")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "<>; rel=preload; as=script"};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("--link without angle brackets rejected")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "/app.js; rel=preload; as=script"};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("--link with DEL character rejected")
  {
    EarlyHintsConfig config;
    std::string evil   = "</app\x7F.js>; rel=preload; as=script";
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", evil.c_str()};
    CHECK(config.init(6, argv) == false);
  }
}

// --- 7. Whitelist Bypass Attempts -------------------------------------------

TEST_CASE("PENTEST: Cross-origin whitelist bypass", "[pentest][whitelist_bypass]")
{
  SECTION("subdomain of non-wildcard entry is NOT whitelisted")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"};
    config.init(6, argv);
    // "evil.cdn.example.com" should NOT match "cdn.example.com" (exact match only)
    CHECK(config.is_whitelisted_domain("evil.cdn.example.com") == false);
    CHECK(config.is_whitelisted_domain("cdn.example.com") == true);
  }

  SECTION("wildcard *.example.com does not match bare example.com")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "*.example.com"};
    config.init(6, argv);
    // *.example.com should match sub.example.com but NOT example.com itself
    CHECK(config.is_whitelisted_domain("sub.example.com") == true);
    CHECK(config.is_whitelisted_domain("example.com") == false);
  }

  SECTION("wildcard *.example.com does not match .example.com (empty subdomain)")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "*.example.com"};
    config.init(6, argv);
    // ".example.com" has empty subdomain  -- should NOT match (size check: domain must be > suffix)
    CHECK(config.is_whitelisted_domain(".example.com") == false);
  }

  SECTION("case-insensitive whitelist matching")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "CDN.EXAMPLE.COM"};
    config.init(6, argv);
    CHECK(config.is_whitelisted_domain("cdn.example.com") == true);
    CHECK(config.is_whitelisted_domain("Cdn.Example.Com") == true);
  }

  SECTION("fragment-based origin bypass attempt")
  {
    // Attack: https://attacker.com#.cdn.example.com → extract_origin must return
    // "https://attacker.com" NOT "https://attacker.com#.cdn.example.com"
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "*.cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html =
      R"(<html><head><link rel="preload" href="https://attacker.com#.cdn.example.com/evil.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Must be preconnect (non-whitelisted), not preload
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("attacker.com>") != std::string::npos);
    // Must NOT contain the fragment
    CHECK(links[0].find("#.cdn.example.com") == std::string::npos);
  }

  SECTION("query-string-based origin bypass attempt")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "*.cdn.example.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html =
      R"(<html><head><link rel="preload" href="https://attacker.com?.cdn.example.com/evil.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));
    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("attacker.com>") != std::string::npos);
  }
}

// --- 8. is_valid_link_value (config parser) robustness ---------------------

TEST_CASE("PENTEST: is_valid_link_value edge cases", "[pentest][config_validation]")
{
  SECTION("rel=preload substring match  -- 'notrel=preload' should NOT match")
  {
    // Verify word-boundary checking: "notrel=preload" should NOT be accepted
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "</app.js>; notrel=preload; as=script"};
    CHECK(config.init(6, argv) == false);
  }

  SECTION("rel=preload with valid boundary chars works")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "</app.js>; rel=preload; as=script"};
    CHECK(config.init(6, argv) == true);
  }

  SECTION("rel=stylesheet accepted")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "</style.css>; rel=stylesheet"};
    CHECK(config.init(6, argv) == true);
  }

  SECTION("rel=modulepreload accepted")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "</mod.mjs>; rel=modulepreload"};
    CHECK(config.init(6, argv) == true);
  }

  SECTION("rel=preconnect accepted")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from", "to", "--mode", "manual", "--link", "<https://cdn.example.com>; rel=preconnect"};
    CHECK(config.init(6, argv) == true);
  }
}

// -------------------------------------------------------------------------------
// QA audit gap tests: process_tag() and build_link_header()
// -------------------------------------------------------------------------------

// --- process_tag: rel values that must be rejected --------------------------

TEST_CASE("HtmlScanner: body tag implicitly closes head", "[html_scanner]")
{
  SECTION("link before body is extracted, link after body is not")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/before.css\" as=\"style\">"
                       "<body>"
                       "<link rel=\"preload\" href=\"/after.css\" as=\"style\">"
                       "</body></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</before.css>; rel=preload; as=style");
  }

  SECTION("body tag case-insensitive")
  {
    std::string html = "<html><head>"
                       "<link rel=\"stylesheet\" href=\"/a.css\">"
                       "<BODY>"
                       "<link rel=\"stylesheet\" href=\"/b.css\">"
                       "</BODY></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
  }

  SECTION("body without closing head")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/x.js\" as=\"script\">"
                       "<body><div>content</div></body></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</x.js>; rel=preload; as=script");
  }
}

TEST_CASE("HtmlScanner: tag name buffer is capped at max length", "[html_scanner]")
{
  SECTION("extremely long tag name does not cause excessive memory use")
  {
    // Create a tag with a 10000-char name, followed by a valid link
    std::string long_tag(10000, 'a');
    std::string html = "<html><head><" + long_tag +
                       ">"
                       "<link rel=\"preload\" href=\"/after.js\" as=\"script\">"
                       "</head></html>";
    auto links = scan_html(html);
    // Scanner should still work correctly after encountering the long tag
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</after.js>; rel=preload; as=script");
  }

  SECTION("long tag name is truncated internally")
  {
    // Verify the scanner doesn't store more than 256 chars for tag_name
    // by checking it doesn't crash and still processes subsequent tags
    std::string long_tag(500, 'x');
    std::string html = "<html><head><" + long_tag +
                       " href=\"/bad.js\">"
                       "<link rel=\"stylesheet\" href=\"/ok.css\">"
                       "</head></html>";
    auto links = scan_html(html);
    // The long tag won't match "link" or "script", so only the real link is found
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</ok.css>; rel=preload; as=style");
  }
}

TEST_CASE("HtmlScanner: attribute name buffer is capped at max length", "[html_scanner]")
{
  SECTION("extremely long attribute name")
  {
    std::string long_attr(10000, 'z');
    std::string html = "<html><head>"
                       "<link " +
                       long_attr +
                       "=\"foo\" rel=\"preload\" href=\"/a.js\" as=\"script\">"
                       "</head></html>";
    auto links = scan_html(html);
    // Should still extract the link even after a long attribute name
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</a.js>; rel=preload; as=script");
  }
}

TEST_CASE("HtmlScanner: script comment position counter is bounded", "[html_scanner]")
{
  SECTION("thousands of dashes in escaped script mode")
  {
    // <script><!-- + 5000 dashes + > should still be inside comment
    // (only --> exits escaped mode; ---...---> does too since >=2 dashes before >)
    std::string dashes(5000, '-');
    std::string html = "<html><head>"
                       "<script><!--" +
                       dashes +
                       ">still in comment--></script>"
                       "<link rel=\"stylesheet\" href=\"/a.css\">"
                       "</head></html>";
    auto links = scan_html(html);
    // The link after </script> should be found
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</a.css>; rel=preload; as=style");
  }

  SECTION("dashes before close in escaped mode - correct exit")
  {
    std::string html = "<html><head>"
                       "<script><!-- var x = 1; --></script>"
                       "<link rel=\"stylesheet\" href=\"/b.css\">"
                       "</head></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0] == "</b.css>; rel=preload; as=style");
  }
}

// ============================================================================
// R6 Regression Tests
// ============================================================================

TEST_CASE("HtmlScanner: backslash authority confusion bypass is rejected", "[scanner][security]")
{
  // SECURITY: Browser treats \ as / in authority of special schemes (WHATWG §4.2).
  // extract_origin must treat \ as authority delimiter to prevent whitelist bypass.
  // Attack: https://evil.com\@whitelisted.com/evil.js
  //   Browser sees: host=evil.com, path=/@whitelisted.com/evil.js
  //   Plugin must NOT extract authority as evil.com\@whitelisted.com

  SECTION("backslash in full URL stops authority extraction  -- prevents whitelist bypass")
  {
    // Setup: whitelisted.com is in whitelist, evil.com is NOT
    const char *argv[] = {"from", "to", "--mode", "auto-learn", "--crossorigin-whitelist", "whitelisted.com"};
    EarlyHintsConfig config;
    config.init(6, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html =
      R"(<html><head><link rel="preload" href="https://evil.com\@whitelisted.com/evil.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // evil.com is NOT whitelisted → must be preconnect (safe fallback), NOT preload
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    CHECK(links[0].find("rel=preload") == std::string::npos);
  }

  SECTION("backslash without userinfo trick")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn"};
    EarlyHintsConfig config;
    config.init(4, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="preload" href="https://example.com\path/file.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    REQUIRE(links.size() == 1);
    // Origin must be https://example.com (not https://example.com\path)
    CHECK(links[0].find("https://example.com>") != std::string::npos);
  }

  SECTION("backslash in protocol-relative rejected outright by is_safe_url")
  {
    const char *argv[] = {"from", "to", "--mode", "auto-learn"};
    EarlyHintsConfig config;
    config.init(4, argv);

    HtmlScanner scanner(131072, 10, &config);
    std::string html = R"(<html><head><link rel="preload" href="\\cdn.example.com/path/x.js" as="script"></head></html>)";
    scanner.feed(html.c_str(), static_cast<int64_t>(html.size()));

    auto links = scanner.get_links();
    // \\cdn.example.com is now caught by is_safe_url and rejected  -- no hint emitted
    CHECK(links.empty());
  }
}

TEST_CASE("HtmlScanner: body tag with attributes closes head", "[scanner]")
{
  SECTION("<body class='main'> with single-quoted attr")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/a.js\" as=\"script\">"
                       "<body class='main'>"
                       "<link rel=\"stylesheet\" href=\"/should-not-be-found.css\">"
                       "</body></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/a.js") != std::string::npos);
  }

  SECTION("<body id=x> with unquoted attr")
  {
    std::string html = "<html><head>"
                       "<link rel=\"stylesheet\" href=\"/found.css\">"
                       "<body id=main>"
                       "<link rel=\"stylesheet\" href=\"/not-found.css\">"
                       "</body></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
  }

  SECTION("<body data-x > with trailing space attr")
  {
    std::string html = "<html><head>"
                       "<link rel=\"stylesheet\" href=\"/found.css\">"
                       "<body data-x >"
                       "<link rel=\"stylesheet\" href=\"/not-found.css\">"
                       "</body></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
  }

  SECTION("<body onload=\"init()\"> with complex attr")
  {
    std::string html = "<html><head>"
                       "<link rel=\"preload\" href=\"/style.css\" as=\"style\">"
                       "<body onload=\"init()\">"
                       "<link rel=\"stylesheet\" href=\"/no.css\">"
                       "</body></html>";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
  }
}

TEST_CASE("HtmlScanner: empty script body does not emit links", "[scanner]")
{
  std::string html = "<html><head>"
                     "<script></script>"
                     "<link rel=\"stylesheet\" href=\"/after-script.css\">"
                     "</head></html>";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/after-script.css") != std::string::npos);
}

TEST_CASE("HtmlScanner: </script> inside <style> does not close style element", "[scanner]")
{
  std::string html = "<html><head>"
                     "<style>/* </script> */</style>"
                     "<link rel=\"stylesheet\" href=\"/after-style.css\">"
                     "</head></html>";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/after-style.css") != std::string::npos);
}

TEST_CASE("HtmlScanner: </head> with attributes closes head", "[scanner]")
{
  std::string html = "<html><head>"
                     "<link rel=\"stylesheet\" href=\"/a.css\">"
                     "</head lang=\"en\">"
                     "<link rel=\"stylesheet\" href=\"/should-not.css\">"
                     "</html>";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/a.css") != std::string::npos);
}

TEST_CASE("HtmlScanner: </head> inside script body is ignored", "[scanner]")
{
  std::string html = "<html><head>"
                     "<script>var x = '</head><head>';</script>"
                     "<link rel=\"stylesheet\" href=\"/ok.css\">"
                     "</head></html>";
  auto links = scan_html(html);
  REQUIRE(links.size() == 1);
  CHECK(links[0].find("/ok.css") != std::string::npos);
}

TEST_CASE("HtmlScanner: multiple head tags treated as one head", "[scanner]")
{
  std::string html = "<html><head>"
                     "<link rel=\"stylesheet\" href=\"/a.css\">"
                     "<head>"
                     "<link rel=\"stylesheet\" href=\"/b.css\">"
                     "</head></html>";
  auto links = scan_html(html);
  REQUIRE(links.size() == 2);
}

TEST_CASE("HtmlScanner: scan limit hit mid-body tag stops scanning", "[scanner]")
{
  // scan_limit hits exactly in the middle of <body>
  std::string html = "<html><head><link rel=\"stylesheet\" href=\"/a.css\"><body class=\"x\">";
  HtmlScanner scanner(10, 50, nullptr); // limit at 50, <body> starts around byte 49
  scanner.feed(html.data(), html.size());
  auto links = scanner.get_links();
  // Should have found /a.css before hitting limit or body
  CHECK(links.size() <= 1);
  CHECK(scanner.is_done());
}

// -------------------------------------------------------------------------------
// is_crossorigin + extract_origin: RFC 3986 false positive prevention
// Bug: href.find("://") matches anywhere in string, so a same-origin proxy URL
// like /proxy?url=https://cdn.example.com/x.js is treated as cross-origin.
// Fix: detect scheme only when :// is preceded by valid RFC 3986 scheme chars
// (ALPHA prefix at position 0), not when it appears inside a query string.
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner: is_crossorigin false positive on query string containing ://", "[html_scanner][crossorigin][rfc3986]")
{
  SECTION("proxy URL with :// in query string treated as same-origin (BUG: treated as cross-origin)")
  {
    // /proxy?url=https://cdn.example.com/x.js is a same-origin URL.
    // Current is_crossorigin finds "://" and returns true. Should return false.
    std::string html =
      R"(<html><head><link rel="preload" href="/proxy?url=https://cdn.example.com/app.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // Same-origin proxy URL must produce rel=preload (same-origin), NOT rel=preconnect
    CHECK(links[0].find("rel=preload") != std::string::npos);
    CHECK(links[0].find("/proxy?url=https://cdn.example.com/app.js") != std::string::npos);
    CHECK(links[0].find("rel=preconnect") == std::string::npos);
  }

  SECTION("script src proxy with :// in query treated as same-origin (BUG)")
  {
    std::string html = R"(<html><head><script src="/loader?src=https://cdn.example.com/lib.js"></script></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload; as=script") != std::string::npos);
    CHECK(links[0].find("/loader?src=https://cdn.example.com/lib.js") != std::string::npos);
    CHECK(links[0].find("rel=preconnect") == std::string::npos);
  }

  SECTION("genuine cross-origin URL still detected as cross-origin after fix")
  {
    std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    // Genuine cross-origin, no whitelist: must be preconnect
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
  }

  SECTION("absolute URL without ALPHA prefix :// is treated as same-origin (relative with colon)")
  {
    // Edge case: a URL like "?foo=bar://baz" has :// but no alpha scheme prefix
    std::string html = R"(<html><head><link rel="preload" href="?foo=bar://baz/style.css" as="style"></head></html>)";
    auto links       = scan_html(html);
    // This is a relative URL (query-only). Must be same-origin preload, not preconnect.
    REQUIRE(!links.empty());
    CHECK(links[0].find("rel=preconnect") == std::string::npos);
  }
}

// -------------------------------------------------------------------------------
// extract_origin(): RFC 3986 §3.1 scheme detection  -- integration tests
//
// Bug: extract_origin() uses url.find("://") naively. For a same-origin proxy URL
// /proxy?url=https://cdn.example.com/x.js, url.find("://") returns 16 (inside
// query string), causing extract_origin to return "/proxy?url=https://cdn.example.com"
//  -- a completely wrong "origin".
//
// Although extract_origin() is currently protected by is_crossorigin() gate
// (which already uses RFC 3986 detection), extract_origin() itself must be
// consistent for defensive correctness and future-proofing.
//
// Fix: Use RFC 3986 §3.1 scheme detection in extract_origin()  -- only detect
// scheme:// when it starts from position 0 with ALPHA prefix, not when ://
// appears anywhere in the string.
// -------------------------------------------------------------------------------

TEST_CASE("HtmlScanner: extract_origin integration  -- proxy URL must emit same-origin preload",
          "[html_scanner][extract_origin][rfc3986]")
{
  // We test extract_origin indirectly via the end-to-end scanner behaviour.
  // A proxy URL /proxy?url=https://cdn.example.com/app.js must produce:
  //   <link> => rel=preload; as=script (same-origin preload of the full proxy URL)
  //   NOT: <https://cdn.example.com>; rel=preconnect (wrong  -- cross-origin of inner URL)
  //   NOT: </proxy?url=https://cdn.example.com>; rel=preconnect (wrong  -- broken origin)
  //
  // If extract_origin were called for this URL (hypothetical future regression):
  //   - Buggy: url.find("://") = 16, extracts "/proxy?url=https://cdn.example.com"
  //   - Fixed: detects no scheme at pos 0, returns url as-is

  SECTION("proxy URL with :// in query string  -- preload uses full URL, not broken origin")
  {
    // This confirms extract_origin is NOT called (is_crossorigin returns false).
    // If it WERE called, the buggy version would produce a broken result.
    std::string html =
      R"(<html><head><link rel="preload" href="/proxy?url=https://cdn.example.com/app.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    // Must use the full URL in the preload (same-origin, not cross-origin path)
    CHECK(links[0].find("/proxy?url=https://cdn.example.com/app.js") != std::string::npos);
    // Must NOT contain a bare cdn.example.com origin (that would mean extract_origin was called)
    CHECK(links[0].find("cdn.example.com>") == std::string::npos);
    // Must NOT contain the broken partial origin "/proxy?url=https://cdn.example.com"
    CHECK(links[0].find("/proxy?url=https://cdn.example.com>") == std::string::npos);
  }

  SECTION("stylesheet proxy URL with :// in query  -- same-origin preload, not preconnect")
  {
    std::string html = R"(<html><head><link rel="stylesheet" href="/assets?src=https://fonts.googleapis.com/css2"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload; as=style") != std::string::npos);
    CHECK(links[0].find("/assets?src=https://fonts.googleapis.com/css2") != std::string::npos);
    CHECK(links[0].find("fonts.googleapis.com>") == std::string::npos);
  }

  SECTION("script proxy URL  -- correct same-origin preload")
  {
    std::string html =
      R"(<html><head><script src="/loader?url=https://unpkg.com/react@18/umd/react.production.min.js"></script></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload; as=script") != std::string::npos);
    CHECK(links[0].find("/loader?url=https://unpkg.com") != std::string::npos);
    CHECK(links[0].find("unpkg.com>") == std::string::npos);
  }

  SECTION("genuine cross-origin URL  -- extract_origin produces correct scheme+host (regression guard)")
  {
    // After fix: https://cdn.example.com/app.js must still yield https://cdn.example.com as origin
    // (is_crossorigin=true, no whitelist → preconnect to origin only)
    std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preconnect") != std::string::npos);
    // extract_origin must strip the path and return https://cdn.example.com
    CHECK(links[0].find("<https://cdn.example.com>") != std::string::npos);
    CHECK(links[0].find("/app.js") == std::string::npos);
  }

  SECTION("URL with :// only in path segment  -- same-origin preload")
  {
    // Unusual but valid: /api/v2://rpc/endpoint
    // The :// is not at position 0 after ALPHA, so this is same-origin
    std::string html = R"(<html><head><link rel="preload" href="/api/v2://rpc/endpoint.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("rel=preload; as=script") != std::string::npos);
    CHECK(links[0].find("/api/v2://rpc/endpoint.js") != std::string::npos);
    CHECK(links[0].find("rel=preconnect") == std::string::npos);
  }
}

// -------------------------------------------------------------------------------
// Direct unit tests for extract_origin() RFC 3986 compliance
//
// These tests call HtmlScanner::extract_origin() DIRECTLY (now public).
// They will be RED before the fix because the current implementation uses
// url.find("://") which matches anywhere  -- not just at the scheme position.
//
// BUG TRACE: extract_origin("/proxy?url=https://cdn.example.com/app.js")
//   Step 1: url.find("://") = 16 (finds :// inside query string at "https://")
//   Step 2: scheme_end = 16, host_start = 19
//   Step 3: find_authority_end(url, 19) → finds '/' at position 33
//   Step 4: returns url.substr(0, 33) = "/proxy?url=https://cdn.example.com"
//   WRONG! Should return url as-is because there is no scheme at position 0.
//
// These tests call HtmlScanner::extract_origin() DIRECTLY.

TEST_CASE("extract_origin() direct test  -- RFC 3986 scheme detection", "[html_scanner][rfc3986][extract_origin][direct]")
{
  SECTION("BUG: proxy URL with :// in query string must return URL as-is")
  {
    std::string url    = "/proxy?url=https://cdn.example.com/app.js";
    std::string result = HtmlScanner::extract_origin(url);
    // After fix: must return the URL as-is (no scheme at pos 0)
    CHECK(result == url);
    // After fix: must NOT return the broken partial string
    CHECK(result != "/proxy?url=https://cdn.example.com");
  }

  SECTION("BUG: path URL with :// in middle must return URL as-is")
  {
    std::string url    = "/api/v1://service/endpoint";
    std::string result = HtmlScanner::extract_origin(url);
    CHECK(result == url);
  }

  SECTION("BUG: stylesheet proxy URL with :// in query must return URL as-is")
  {
    std::string url    = "/assets?src=https://fonts.googleapis.com/css2";
    std::string result = HtmlScanner::extract_origin(url);
    CHECK(result == url);
    CHECK(result != "/assets?src=https://fonts.googleapis.com");
  }

  SECTION("CORRECT: genuine https absolute URL  -- strip path to origin")
  {
    std::string url    = "https://cdn.example.com/app.js";
    std::string result = HtmlScanner::extract_origin(url);
    CHECK(result == "https://cdn.example.com");
  }

  SECTION("CORRECT: genuine https URL with query  -- stop at ?")
  {
    std::string url    = "https://cdn.example.com/style.css?v=abc123";
    std::string result = HtmlScanner::extract_origin(url);
    CHECK(result == "https://cdn.example.com");
  }

  SECTION("CORRECT: http URL  -- strips path to origin")
  {
    std::string url    = "http://static.example.com/bundle.js";
    std::string result = HtmlScanner::extract_origin(url);
    CHECK(result == "http://static.example.com");
  }

  SECTION("CORRECT: protocol-relative URL  -- returns https://host")
  {
    std::string url    = "//cdn.example.com/app.js";
    std::string result = HtmlScanner::extract_origin(url);
    CHECK(result == "https://cdn.example.com");
  }

  SECTION("CORRECT: relative path  -- returns as-is")
  {
    std::string url    = "/assets/app.js";
    std::string result = HtmlScanner::extract_origin(url);
    CHECK(result == "/assets/app.js");
  }
}

// --- is_safe_url() backslash authority bypass --------------------------------
// Bug: http:\attacker.com passes is_safe_url()  -- scheme detected as "http" but
// colon is not followed by "//", so the URL is misidentified as same-origin.
// Per WHATWG URL spec §4.2, browsers treat http:\ as http:// in special schemes.
// Fix: after detecting a scheme, verify the separator is "://" not just ":".
// Regression: existing http:// and https:// URLs must still be accepted.

TEST_CASE("is_safe_url() rejects http:\\authority without :// separator", "[security]")
{
  SECTION("http:\\evil.com: browser normalizes to http://evil.com")
  {
    // Per WHATWG URL section 4.2, http:\evil.com resolves to http://evil.com in browser.
    // Must be rejected: scheme without "://" is a cross-origin evasion vector.
    std::string html = R"(<html><head><link rel="preload" href="http:\evil.com/track.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("https:\\evil.com  -- browser normalizes to https://evil.com")
  {
    std::string html = R"(<html><head><link rel="preload" href="https:\evil.com/track.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(links.empty());
  }

  SECTION("http:/evil.com  -- single slash after colon")
  {
    // http:/evil.com: after scheme detection, only one slash  -- relative path on same origin?
    // Browser treats as same-origin: http://example.com/evil.com/. Should be allowed.
    // But plugin must NOT emit cross-origin hint without whitelist.
    // Since this has no authority component it resolves same-origin  -- allowed as relative.
    std::string html = R"(<html><head><link rel="preload" href="http:/evil.com/path.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    // http: scheme without "//": per WHATWG treated as http://evil.com.
    // Reject: scheme without proper "://" authority separator is attacker vector.
    CHECK(links.empty());
  }

  SECTION("http://cdn.example.com  -- correct URL still accepted")
  {
    std::string html = R"(<html><head><link rel="preload" href="http://cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("https://cdn.example.com  -- correct URL still accepted")
  {
    std::string html = R"(<html><head><link rel="preload" href="https://cdn.example.com/app.css" as="style"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("relative /path still accepted")
  {
    std::string html = R"(<html><head><link rel="preload" href="/assets/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }

  SECTION("protocol-relative //host still accepted")
  {
    std::string html = R"(<html><head><link rel="preload" href="//cdn.example.com/app.js" as="script"></head></html>)";
    auto links       = scan_html(html);
    CHECK(!links.empty());
  }
}

// Tests for HTML scanner raw-text element skip (title, textarea, xmp).
// Per HTML5 spec section 13.2.6.1, these are RCDATA elements whose content
// is not parsed as markup. A <link> inside <title> is display text.

TEST_CASE("HTML scanner skips link parsing inside RCDATA elements", "[security]")
{
  SECTION("<link> inside <title> is NOT a hint  -- RCDATA content")
  {
    // HTML5 spec section 13.2.6.1: <title> content is RCDATA, not parsed as HTML tags.
    // A <link rel=preload> inside <title> is literal text displayed to the user,
    // not a resource hint. Extracting it as a hint is a misparse.
    std::string html = R"(<html><head><title><link rel="preload" href="/evil.js" as="script"></title>)"
                       R"(<link rel="preload" href="/real.css" as="style"></head></html>)";
    auto links = scan_html(html);
    // /evil.js inside <title> must NOT be extracted
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.css") != std::string::npos);
    CHECK(links[0].find("/evil.js") == std::string::npos);
  }

  SECTION("<link> inside <textarea> is NOT a hint  -- RCDATA content")
  {
    std::string html = R"(<html><head></head><body>)"
                       R"(<textarea><link rel="preload" href="/evil.css" as="style"></textarea>)"
                       R"(<link rel="preload" href="/real.js" as="script"></body></html>)";
    auto links = scan_html(html);
    for (const auto &link : links) {
      CHECK(link.find("/evil.css") == std::string::npos);
    }
  }

  SECTION("<link> inside <xmp> is NOT a hint  -- obsolete raw text element")
  {
    // <xmp> is an obsolete raw text element (HTML5 section 13.2.6, section 8.1.2.6).
    // Its content must not be parsed as markup.
    std::string html = R"(<html><head></head><body>)"
                       R"(<xmp><link rel="preload" href="/evil.js" as="script"></xmp>)"
                       R"(<link rel="preload" href="/real.css" as="style"></body></html>)";
    auto links = scan_html(html);
    for (const auto &link : links) {
      CHECK(link.find("/evil.js") == std::string::npos);
    }
  }

  SECTION("Normal links after closing </title> are extracted correctly")
  {
    std::string html = R"(<html><head><title>Page Title with /fake.js content</title>)"
                       R"(<link rel="preload" href="/real.css" as="style">)"
                       R"(<link rel="preload" href="/real.js" as="script"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 2);
    bool has_css = false, has_js = false;
    for (const auto &l : links) {
      if (l.find("/real.css") != std::string::npos)
        has_css = true;
      if (l.find("/real.js") != std::string::npos)
        has_js = true;
    }
    CHECK(has_css);
    CHECK(has_js);
  }

  SECTION("<script> still suppresses inner links (existing behavior preserved)")
  {
    std::string html = R"(<html><head><script>var x = '<link rel="preload" href="/evil.js" as="script">';</script>)"
                       R"(<link rel="preload" href="/real.css" as="style"></head></html>)";
    auto links = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/real.css") != std::string::npos);
  }
}

// --- is_crossorigin() boundary: href.size() >= 2 for exact // --------------

TEST_CASE("HtmlScanner: exact '//' href is not emitted as a same-origin preload hint", "[html_scanner][security]")
{
  // href="//" is a degenerate protocol-relative URL with no host.
  // is_crossorigin() must detect it as cross-origin (size >= 2).
  // With the off-by-one bug (> 2), size==2 falls through as same-origin and
  // a broken preload hint is emitted. After fix (>= 2), it is correctly
  // treated as cross-origin; since no CDN whitelist is configured, no hint
  // is emitted.
  std::string html = R"(<html><head><link rel="preload" href="//" as="script"></head></html>)";
  auto links       = scan_html(html);
  // Before fix: broken hint emitted (// treated as same-origin)
  // After fix:  no hint emitted (// treated as cross-origin, not whitelisted)
  CHECK(links.empty());
}

// --- Non-regression: whitespace rejection must survive dead-code removal -----

TEST_CASE("HtmlScanner is_safe_url: whitespace rejection is handled by control-char loop", "[html_scanner][security][regression]")
{
  // The control-char loop (uc <= 0x20) rejects space and tab before any scheme
  // check. Removing the redundant find_first_not_of block must not change this.
  SECTION("leading space in URL is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\" /style.css\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty()); // space char rejected by is_safe_url
  }

  SECTION("tab in URL is rejected")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"\t/style.css\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    CHECK(links.empty()); // tab (0x09 <= 0x20) rejected by is_safe_url
  }

  SECTION("clean relative URL is accepted (no regression)")
  {
    std::string html = "<html><head><link rel=\"preload\" href=\"/style.css\" as=\"style\"></head></html>";
    auto links       = scan_html(html);
    REQUIRE(links.size() == 1);
    CHECK(links[0].find("/style.css") != std::string::npos);
  }
}
