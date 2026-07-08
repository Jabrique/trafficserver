/** @file
 * Unit tests for static helper functions in early_hints.cc:
 *   - is_bot_user_agent()   (GAP-1)
 *   - is_navigate_request() (GAP-2)
 *   - is_html_response()    (GAP-3)
 *
 * Strategy: #include "early_hints.cc" to access static functions,
 * with ATS API mocks defined in test_plugin_hooks_mocks.cc.
 * The g_mock_headers map (defined in the mocks file) is populated
 * before each test to simulate specific request/response headers.
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
#include <map>
#include <string>
#include <cstring>

// Include the plugin implementation to access static functions.
// ATS API functions are satisfied by test_plugin_hooks_mocks.cc.
#include "early_hints.cc"

// --- Mock control state (defined in test_plugin_hooks_mocks.cc) -------------

extern std::map<std::string, std::string> g_mock_headers;
extern void set_mock_header(const std::string &name, const std::string &value);
extern void clear_mock_headers();

// --- Convenience: null buffer/loc handles for all calls ---------------------
// The mock TSMimeHdrFieldFind ignores bufp and hdr  -- only the name matters.
static TSMBuffer kBuf = nullptr;
static TSMLoc kHdr    = nullptr;

// --- is_bot_user_agent()  -- GAP-1 --------------------------------------------

TEST_CASE("is_bot_user_agent: no UA header → not a bot (conservative)", "[plugin_hooks][bot]")
{
  clear_mock_headers();
  // No User-Agent header set → TSMimeHdrFieldFind returns TS_NULL_MLOC
  CHECK(is_bot_user_agent(kBuf, kHdr) == false);
}

TEST_CASE("is_bot_user_agent: empty UA string → not a bot", "[plugin_hooks][bot]")
{
  clear_mock_headers();
  set_mock_header("User-Agent", "");
  // ua_len == 0 → the ua_str guard fails → not a bot
  CHECK(is_bot_user_agent(kBuf, kHdr) == false);
}

TEST_CASE("is_bot_user_agent: all known bot signatures match (case-insensitive)", "[plugin_hooks][bot]")
{
  clear_mock_headers();
  // Each signature from bot_signatures[]  -- verified as lowercase substring.
  // Plugin uses strcasestr so mixed-case values also match.
  struct TestPair {
    const char *ua;
    const char *desc;
  };
  static const TestPair cases[] = {
    {"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "googlebot"},
    {"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bingbot"},
    {"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "yandexbot"},
    {"Baiduspider+(+http://www.baidu.com/search/spider.html)", "baiduspider"},
    {"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)", "duckduckbot"},
    {"Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp", "slurp"},
    {"ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)", "ia_archiver"},
    {"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "facebookexternalhit"},
    {"Twitterbot/1.0", "twitterbot"},
    {"LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)", "linkedinbot"},
    {"Embedly/0.2", "embedly"},
    {"ShowyouBot", "showyoubot"},
    {"Outbrain/0.9", "outbrain"},
    {"Pinterest/0.1 +http://pinterest.com/", "pinterest"},
    {"Applebot/0.1 (+http://www.apple.com/go/applebot)", "applebot"},
    {"SemrushBot/7.0", "semrushbot"},
    {"AhrefsBot/7.0; +https://ahrefs.com/robot/", "ahrefsbot"},
    {"MJ12bot/v1.4.8 (http://majestic12.co.uk/bot.php?+)", "mj12bot"},
    {"DotBot/1.2 http://opensiteexplorer.org/dotbot", "dotbot"},
    {"curl/7.88.1", "curl/"},
    {"Wget/1.21.4 (linux-gnu)", "wget/"},
    {"python-requests/2.28.2", "python-requests/"},
    {"Go-http-client/1.1", "go-http-client/"},
    {"Apache-HttpClient/4.5 (Java/11.0.20)", "apache-httpclient/"},
    {"Java/11.0.20", "java/"},
    {"libwww-perl/6.67", "libwww-perl/"},
  };
  for (const auto &tc : cases) {
    SECTION(tc.desc)
    {
      clear_mock_headers();
      set_mock_header("User-Agent", tc.ua);
      INFO("UA: " << tc.ua);
      CHECK(is_bot_user_agent(kBuf, kHdr) == true);
    }
  }
}

TEST_CASE("is_bot_user_agent: signatures match case-insensitively", "[plugin_hooks][bot]")
{
  clear_mock_headers();

  SECTION("GooGlEbOt in UA → is bot (strcasestr)")
  {
    set_mock_header("User-Agent", "GooGlEbOt/2.1 (custom)");
    CHECK(is_bot_user_agent(kBuf, kHdr) == true);
  }

  SECTION("BINGBOT uppercase → is bot")
  {
    set_mock_header("User-Agent", "BINGBOT/2.0");
    CHECK(is_bot_user_agent(kBuf, kHdr) == true);
  }

  SECTION("PYTHON-REQUESTS uppercase → is bot")
  {
    set_mock_header("User-Agent", "PYTHON-REQUESTS/2.28");
    CHECK(is_bot_user_agent(kBuf, kHdr) == true);
  }
}

TEST_CASE("is_bot_user_agent: UA length boundary (512 byte threshold)", "[plugin_hooks][bot]")
{
  clear_mock_headers();

  SECTION("UA exactly 512 bytes → NOT bot (at boundary, not over)")
  {
    // Fill with a real-looking browser UA padded to exactly 512 bytes.
    // At 512 bytes it is NOT a bot (condition is ua_len > 512, i.e. >= 513).
    std::string ua(512, 'A');
    set_mock_header("User-Agent", ua);
    CHECK(is_bot_user_agent(kBuf, kHdr) == false);
  }

  SECTION("UA exactly 513 bytes → bot (just over threshold)")
  {
    std::string ua(513, 'A');
    set_mock_header("User-Agent", ua);
    CHECK(is_bot_user_agent(kBuf, kHdr) == true);
  }

  SECTION("UA 1000 bytes → bot (well over threshold)")
  {
    std::string ua(1000, 'B');
    set_mock_header("User-Agent", ua);
    CHECK(is_bot_user_agent(kBuf, kHdr) == true);
  }
}

TEST_CASE("is_bot_user_agent: non-matching UAs are not bots", "[plugin_hooks][bot]")
{
  clear_mock_headers();

  SECTION("Chrome real browser UA")
  {
    set_mock_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    CHECK(is_bot_user_agent(kBuf, kHdr) == false);
  }

  SECTION("Firefox real browser UA")
  {
    set_mock_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0");
    CHECK(is_bot_user_agent(kBuf, kHdr) == false);
  }

  SECTION("Safari iOS UA")
  {
    set_mock_header("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                                  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
    CHECK(is_bot_user_agent(kBuf, kHdr) == false);
  }

  SECTION("NotABot/1.0  -- does not contain any signature")
  {
    set_mock_header("User-Agent", "NotABot/1.0");
    CHECK(is_bot_user_agent(kBuf, kHdr) == false);
  }
}

TEST_CASE("is_bot_user_agent: substring match semantics (strcasestr)", "[plugin_hooks][bot]")
{
  clear_mock_headers();

  SECTION("'My App (googlebot-like)' → is bot (substring match)")
  {
    set_mock_header("User-Agent", "My App (googlebot-like) 1.0");
    // strcasestr finds "googlebot" inside the UA → is_bot
    CHECK(is_bot_user_agent(kBuf, kHdr) == true);
  }

  SECTION("'curl_like_app/1.0' without 'curl/' → not a bot")
  {
    // bot_signatures has "curl/" (with slash). "curl_like_app" doesn't contain "curl/"
    set_mock_header("User-Agent", "curl_like_app/1.0");
    CHECK(is_bot_user_agent(kBuf, kHdr) == false);
  }

  SECTION("'supercurl/1.0' contains 'curl/' → is bot (strcasestr finds it)")
  {
    set_mock_header("User-Agent", "supercurl/1.0");
    CHECK(is_bot_user_agent(kBuf, kHdr) == true);
  }
}

// --- is_navigate_request()  -- GAP-2 ------------------------------------------

TEST_CASE("is_navigate_request: no Sec-Fetch-Mode header → navigate (conservative allow)", "[plugin_hooks][navigate]")
{
  clear_mock_headers();
  // Absent header: older browsers and non-browser clients (curl) don't send it.
  // Plugin must allow them through (return true = is navigate).
  CHECK(is_navigate_request(kBuf, kHdr) == true);
}

TEST_CASE("is_navigate_request: Sec-Fetch-Mode navigate → true", "[plugin_hooks][navigate]")
{
  clear_mock_headers();

  SECTION("exact lowercase 'navigate'")
  {
    set_mock_header("Sec-Fetch-Mode", "navigate");
    CHECK(is_navigate_request(kBuf, kHdr) == true);
  }

  SECTION("title case 'Navigate'")
  {
    set_mock_header("Sec-Fetch-Mode", "Navigate");
    CHECK(is_navigate_request(kBuf, kHdr) == true);
  }

  SECTION("all caps 'NAVIGATE'")
  {
    set_mock_header("Sec-Fetch-Mode", "NAVIGATE");
    CHECK(is_navigate_request(kBuf, kHdr) == true);
  }

  SECTION("leading space ' navigate'")
  {
    set_mock_header("Sec-Fetch-Mode", " navigate");
    CHECK(is_navigate_request(kBuf, kHdr) == true);
  }

  SECTION("trailing space 'navigate '")
  {
    set_mock_header("Sec-Fetch-Mode", "navigate ");
    CHECK(is_navigate_request(kBuf, kHdr) == true);
  }

  SECTION("both sides '  navigate  '")
  {
    set_mock_header("Sec-Fetch-Mode", "  navigate  ");
    CHECK(is_navigate_request(kBuf, kHdr) == true);
  }

  SECTION("tab padding '\\tnavigate\\t'")
  {
    set_mock_header("Sec-Fetch-Mode", "\tnavigate\t");
    CHECK(is_navigate_request(kBuf, kHdr) == true);
  }
}

TEST_CASE("is_navigate_request: non-navigate values → false", "[plugin_hooks][navigate]")
{
  clear_mock_headers();

  SECTION("cors")
  {
    set_mock_header("Sec-Fetch-Mode", "cors");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("no-cors")
  {
    set_mock_header("Sec-Fetch-Mode", "no-cors");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("same-origin")
  {
    set_mock_header("Sec-Fetch-Mode", "same-origin");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("nested-navigate")
  {
    // Length is 15 chars, not 8  -- length check prevents false match.
    set_mock_header("Sec-Fetch-Mode", "nested-navigate");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("websocket")
  {
    set_mock_header("Sec-Fetch-Mode", "websocket");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("empty string")
  {
    set_mock_header("Sec-Fetch-Mode", "");
    // val_len == 0 → the guard fires → is_nav = false → not a navigate
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("'navigatex'  -- extra char after (trimmed length=9, not 8)")
  {
    set_mock_header("Sec-Fetch-Mode", "navigatex");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("'xnavigate'  -- leading non-space char (length=9 after trim, not 8)")
  {
    set_mock_header("Sec-Fetch-Mode", "xnavigate");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }
}

TEST_CASE("is_navigate_request: trimming does not confuse adjacent values", "[plugin_hooks][navigate]")
{
  clear_mock_headers();

  SECTION("only spaces → empty after trim → false")
  {
    set_mock_header("Sec-Fetch-Mode", "   ");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("only tabs → empty after trim → false")
  {
    set_mock_header("Sec-Fetch-Mode", "\t\t");
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }

  SECTION("space between navigate words → not a match ('navigate x')")
  {
    set_mock_header("Sec-Fetch-Mode", "navigate x");
    // After trim: "navigate x", length=10, not 8 → false
    CHECK(is_navigate_request(kBuf, kHdr) == false);
  }
}

// --- is_html_response()  -- GAP-3 ---------------------------------------------

TEST_CASE("is_html_response: no Content-Type header → false", "[plugin_hooks][html]")
{
  clear_mock_headers();
  // No Content-Type set → TSMimeHdrFieldFind returns TS_NULL_MLOC → false
  CHECK(is_html_response(kBuf, kHdr) == false);
}

TEST_CASE("is_html_response: Content-Type text/html variants → true", "[plugin_hooks][html]")
{
  clear_mock_headers();

  SECTION("exact 'text/html'")
  {
    set_mock_header("Content-Type", "text/html");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("with charset: 'text/html;charset=utf-8'")
  {
    set_mock_header("Content-Type", "text/html;charset=utf-8");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("with space separator: 'text/html '")
  {
    set_mock_header("Content-Type", "text/html ");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("with tab separator: 'text/html\\t'")
  {
    set_mock_header("Content-Type", "text/html\t");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("case-insensitive: 'TEXT/HTML'")
  {
    set_mock_header("Content-Type", "TEXT/HTML");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("case-insensitive: 'Text/Html;charset=utf-8'")
  {
    set_mock_header("Content-Type", "Text/Html;charset=utf-8");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }
}

TEST_CASE("is_html_response: Content-Type boundary  -- char at position 9 matters", "[plugin_hooks][html]")
{
  clear_mock_headers();

  SECTION("'text/htmlx' → false (char at [9]='x' is not ';', ' ', or '\\t')")
  {
    // The check: ct_len == 9 OR ct_str[9] ∈ {';', ' ', '\t'}
    // "text/htmlx" has ct_len=10 and ct_str[9]='x' → NOT html.
    set_mock_header("Content-Type", "text/htmlx");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("'text/html5' → false (digit at [9] is not a valid separator)")
  {
    set_mock_header("Content-Type", "text/html5");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }
}

TEST_CASE("is_html_response: non-HTML Content-Type → false", "[plugin_hooks][html]")
{
  clear_mock_headers();

  SECTION("application/json")
  {
    set_mock_header("Content-Type", "application/json");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("text/plain")
  {
    set_mock_header("Content-Type", "text/plain");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("text/css")
  {
    set_mock_header("Content-Type", "text/css");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("application/javascript")
  {
    set_mock_header("Content-Type", "application/javascript");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }
}

TEST_CASE("is_html_response: Content-Encoding absent → true (identity implied)", "[plugin_hooks][html]")
{
  clear_mock_headers();
  set_mock_header("Content-Type", "text/html");
  // No Content-Encoding header → no compression → is_html = true
  CHECK(is_html_response(kBuf, kHdr) == true);
}

TEST_CASE("is_html_response: Content-Encoding identity variants → true", "[plugin_hooks][html]")
{
  clear_mock_headers();
  set_mock_header("Content-Type", "text/html");

  SECTION("exact 'identity'")
  {
    set_mock_header("Content-Encoding", "identity");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("case-insensitive 'IDENTITY'")
  {
    set_mock_header("Content-Encoding", "IDENTITY");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("'identity ' with trailing space (whitespace trimmed)")
  {
    set_mock_header("Content-Encoding", "identity ");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("'  identity  ' with both sides whitespace (trimmed)")
  {
    set_mock_header("Content-Encoding", "  identity  ");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }

  SECTION("'\\tidentity\\t' with tabs trimmed")
  {
    set_mock_header("Content-Encoding", "\tidentity\t");
    CHECK(is_html_response(kBuf, kHdr) == true);
  }
}

TEST_CASE("is_html_response: compressed Content-Encoding → false", "[plugin_hooks][html]")
{
  clear_mock_headers();
  set_mock_header("Content-Type", "text/html");

  SECTION("gzip")
  {
    set_mock_header("Content-Encoding", "gzip");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("GZIP (case-insensitive)")
  {
    set_mock_header("Content-Encoding", "GZIP");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("br (brotli)")
  {
    set_mock_header("Content-Encoding", "br");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("deflate")
  {
    set_mock_header("Content-Encoding", "deflate");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("zstd")
  {
    set_mock_header("Content-Encoding", "zstd");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }

  SECTION("compress")
  {
    set_mock_header("Content-Encoding", "compress");
    CHECK(is_html_response(kBuf, kHdr) == false);
  }
}

TEST_CASE("is_html_response: Content-Encoding empty string → not identity → false", "[plugin_hooks][html]")
{
  clear_mock_headers();
  set_mock_header("Content-Type", "text/html");
  // ce_len == 0 → the ce_str guard fires → is_compressed = false → return true
  // Because the guard is: if (ce_str && ce_len > 0) { ... }
  // Empty string means ce_len == 0 → block not entered → is_compressed stays false → true
  set_mock_header("Content-Encoding", "");
  CHECK(is_html_response(kBuf, kHdr) == true);
}

TEST_CASE("is_html_response: Content-Type missing but Content-Encoding present → false", "[plugin_hooks][html]")
{
  clear_mock_headers();
  // Content-Type absent → returns false immediately at the ct_field == TS_NULL_MLOC guard.
  // Content-Encoding is irrelevant when Content-Type is missing.
  set_mock_header("Content-Encoding", "identity");
  CHECK(is_html_response(kBuf, kHdr) == false);
}
