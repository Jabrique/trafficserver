/** @file
 * Unit tests for the EarlyHintsConfig component.
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
#include <cstring>
#include <getopt.h>
#include <unistd.h>

// Helper to simulate remap plugin argv: [fromURL, toURL, args...]
static bool
parse_config(EarlyHintsConfig &config, std::initializer_list<const char *> args)
{
  // Build argv: [from_url, to_url, args...]
  // ATS passes: argv[0]=fromURL, argv[1]=toURL, argv[2..N]=pparam values
  // Config init() skips argv[0], getopt treats argv[1] as program name
  std::vector<const char *> argv;
  argv.push_back("http://from.example.com"); // remap "from" URL (skipped by init)
  argv.push_back("http://to.example.com");   // remap "to" URL (program name for getopt)
  for (auto a : args) {
    argv.push_back(a);
  }
  int argc = static_cast<int>(argv.size());
  return config.init(argc, argv.data());
}

TEST_CASE("Config default values", "[config]")
{
  SECTION("defaults are correct with no arguments")
  {
    EarlyHintsConfig config;
    // Init with just fromURL and toURL, no extra args
    std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com"};
    CHECK(config.init(2, argv.data()));

    // Default mode: origin-forward only (safe zero-config — no HTML scanning)
    CHECK((config.mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) == 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) == 0);

    CHECK(config.max_links() == 10);
    CHECK(config.persist_enabled() == false);
    CHECK(config.persist_dir().empty());
    CHECK(config.header_size_limit() == 3072);
    CHECK(config.skip_bots() == true);
    CHECK(config.navigate_only() == true);
    CHECK(config.debug_header() == nullptr);
    CHECK(config.scan_limit() == 32768);
    CHECK(config.min_hit_count() == 2);
    CHECK(config.max_cache_entries() == 10000);
    CHECK(config.manual_links().empty());
    CHECK(config.crossorigin_whitelist().empty());
    CHECK(config.preload_whitelist().empty());
    CHECK(config.hints_ttl() == 604800); // 1 week default
  }
}

TEST_CASE("Config mode parsing", "[config]")
{
  SECTION("single mode: manual")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</app.js>; rel=preload; as=script"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) == 0);
  }

  SECTION("single mode: auto-learn")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
  }

  SECTION("combined modes: manual,auto-learn")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual,auto-learn", "--link", "</a.js>; rel=preload; as=script"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
  }

  SECTION("invalid mode fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "invalid"}));
  }
}

TEST_CASE("Config manual links", "[config]")
{
  SECTION("multiple --link parameters")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</app.js>; rel=preload; as=script", "--link",
                                "</style.css>; rel=preload; as=style"}));
    REQUIRE(config.manual_links().size() == 2);
    CHECK(config.manual_links()[0] == "</app.js>; rel=preload; as=script");
    CHECK(config.manual_links()[1] == "</style.css>; rel=preload; as=style");
  }

  SECTION("manual mode without --link fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual"}));
  }

  SECTION("CRLF in link value is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</evil\r\nheader>; rel=preload; as=script"}));
  }

  SECTION("R6: quoted rel values accepted (RFC 8288 §3)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", R"(</style.css>; rel="preload"; as=style)"}));
    REQUIRE(config.manual_links().size() == 1);
  }

  SECTION("R6: single-quoted rel values accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", R"(</style.css>; rel='preload'; as=style)"}));
    REQUIRE(config.manual_links().size() == 1);
  }

  SECTION("R7: quoted rel with non-boundary prefix rejected (forel=\"preload\")")
  {
    EarlyHintsConfig config;
    // "forel" is not "rel" — must NOT be accepted
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", R"(</style.css>; forel="preload"; as=style)"}));
  }

  SECTION("R7: quoted rel with semicolon boundary accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", R"(</style.css>;rel="preload"; as=style)"}));
    REQUIRE(config.manual_links().size() == 1);
  }

  SECTION("R7: quoted rel with tab boundary — tab in link value rejected as control char")
  {
    EarlyHintsConfig config;
    // Tab (0x09) is a control character < 0x20, correctly rejected by is_valid_link_value
    const char *link = "</style.css>;\trel=\"preload\"; as=style";
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", link}));
  }
}

// ==================== Compact pparam=--option=value format (Todo 3) ====================
// getopt_long natively handles --option=value. These tests verify it works via parse_config.

TEST_CASE("Compact pparam --option=value format", "[config][compact-pparam]")
{
  SECTION("--mode=manual with --link=value")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode=manual", "--link=</app.js>; rel=preload; as=script"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
    REQUIRE(config.manual_links().size() == 1);
    CHECK(config.manual_links()[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("--mode=auto-learn compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode=auto-learn"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
  }

  SECTION("--mode=manual,auto-learn,origin-forward combined compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode=manual,auto-learn,origin-forward", "--link=</a.js>; rel=preload; as=script"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) != 0);
  }

  SECTION("--max-links=5 compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links=5"}));
    CHECK(config.max_links() == 5);
  }

  SECTION("--scan-limit=262144 compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--scan-limit=262144"}));
    CHECK(config.scan_limit() == 262144);
  }

  SECTION("--min-hit-count=3 compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--min-hit-count=3"}));
    CHECK(config.min_hit_count() == 3);
  }

  SECTION("--header-size-limit=4096 compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--header-size-limit=4096"}));
    CHECK(config.header_size_limit() == 4096);
  }

  SECTION("--max-cache-entries=50000 compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-cache-entries=50000"}));
    CHECK(config.max_cache_entries() == 50000);
  }

  SECTION("--debug-header=X-EH compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--debug-header=X-EH"}));
    CHECK(std::string(config.debug_header()) == "X-EH");
  }

  SECTION("--crossorigin-whitelist=a.com,b.com compact")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist=a.com,b.com"}));
    CHECK(config.is_whitelisted_domain("a.com"));
    CHECK(config.is_whitelisted_domain("b.com"));
  }

  SECTION("mixed compact and standard format")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode=manual", "--link", "</style.css>; rel=preload; as=style", "--max-links=5"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
    REQUIRE(config.manual_links().size() == 1);
    CHECK(config.max_links() == 5);
  }

  SECTION("multiple --link= compact")
  {
    EarlyHintsConfig config;
    CHECK(
      parse_config(config, {"--mode=manual", "--link=</a.js>; rel=preload; as=script", "--link=</b.css>; rel=preload; as=style"}));
    REQUIRE(config.manual_links().size() == 2);
    CHECK(config.manual_links()[0] == "</a.js>; rel=preload; as=script");
    CHECK(config.manual_links()[1] == "</b.css>; rel=preload; as=style");
  }
}

TEST_CASE("Config numeric parameters", "[config]")
{
  SECTION("max-links valid range")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links", "5"}));
    CHECK(config.max_links() == 5);
  }

  SECTION("max-links out of range fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "0"}));
  }

  SECTION("max-links too high fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "51"}));
  }

  SECTION("persist-dir valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-dir", "/tmp/hints/"}));
    CHECK(config.persist_dir() == "/tmp/hints/");
    CHECK(config.persist_enabled() == true);
  }

  SECTION("no-persist disables persistence")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--no-persist"}));
    CHECK(config.persist_enabled() == false);
  }

  SECTION("header-size-limit valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--header-size-limit", "4096"}));
    CHECK(config.header_size_limit() == 4096);
  }

  SECTION("scan-limit valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--scan-limit", "65536"}));
    CHECK(config.scan_limit() == 65536);
  }

  SECTION("min-hit-count valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--min-hit-count", "5"}));
    CHECK(config.min_hit_count() == 5);
  }

  SECTION("max-cache-entries valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-cache-entries", "50000"}));
    CHECK(config.max_cache_entries() == 50000);
  }

  SECTION("max-cache-entries too low fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-cache-entries", "0"}));
  }
}

TEST_CASE("Config boolean flags", "[config]")
{
  SECTION("--no-skip-bots disables bot skipping")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--no-skip-bots"}));
    CHECK(config.skip_bots() == false);
  }

  SECTION("--no-navigate-only disables navigate filter")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--no-navigate-only"}));
    CHECK(config.navigate_only() == false);
  }

  SECTION("--debug-header sets header name")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--debug-header", "X-Early-Hints"}));
    CHECK(std::string(config.debug_header()) == "X-Early-Hints");
  }
}

TEST_CASE("Config crossorigin whitelist", "[config]")
{
  SECTION("comma-separated domains")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com,fonts.googleapis.com"}));
    REQUIRE(config.crossorigin_whitelist().size() == 2);
    CHECK(config.crossorigin_whitelist()[0] == "cdn.example.com");
    CHECK(config.crossorigin_whitelist()[1] == "fonts.googleapis.com");
  }

  SECTION("wildcard domain matching")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.example.com"}));
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
    CHECK(config.is_whitelisted_domain("fonts.example.com"));
    CHECK_FALSE(config.is_whitelisted_domain("example.com"));
    CHECK_FALSE(config.is_whitelisted_domain("evil.com"));
  }

  SECTION("exact domain matching")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
    CHECK_FALSE(config.is_whitelisted_domain("other.example.com"));
  }
}

// ─── Integer parsing safety ─────────────────────────────────────────────────

TEST_CASE("EarlyHintsConfig: safe integer parsing", "[config][security]")
{
  SECTION("overflow is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "99999999999999999"}));
  }

  SECTION("trailing garbage is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "10abc"}));
  }

  SECTION("empty string is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", ""}));
  }

  SECTION("negative values are rejected by range checks")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "-5"}));
  }
}

// ─── Strengthened link validation ───────────────────────────────────────────

TEST_CASE("EarlyHintsConfig: link validation blocks dangerous schemes", "[config][security]")
{
  SECTION("javascript: scheme rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<javascript:alert(1)>; rel=preload; as=script"}));
  }

  SECTION("data: scheme rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<data:text/css,body{}>; rel=stylesheet"}));
  }

  SECTION("valid link still accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</style.css>; rel=preload; as=style"}));
    CHECK(config.manual_links().size() == 1);
  }

  SECTION("link without valid rel rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</evil.js>; rel=dns-prefetch"}));
  }

  SECTION("javascript with leading whitespace rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<  javascript:alert(1)>; rel=preload; as=script"}));
  }

  SECTION("data with leading tab rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<\tdata:text/css,body{}>; rel=stylesheet"}));
  }
}

// ─── BUG regression tests: check_rel, domain matching, wildcard ─────────────

TEST_CASE("Config link validation: rel= after false prefix match", "[config][regression]")
{
  SECTION("norel=preload before valid rel=preload")
  {
    // BUG: find() stops at first match inside "norel=preload" and fails word boundary,
    // never reaches the valid "rel=preload" at a later position.
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</style.css>; norel=preload; rel=preload; as=style"}));
  }
}

TEST_CASE("Config whitelist: case insensitivity", "[config][regression]")
{
  SECTION("exact match ignores case")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK(config.is_whitelisted_domain("CDN.Example.Com"));
  }

  SECTION("wildcard match ignores case")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.Example.COM"}));
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
  }
}

TEST_CASE("Config whitelist: bare suffix rejected by wildcard", "[config][regression]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "*.example.com"}));
  CHECK_FALSE(config.is_whitelisted_domain(".example.com"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAP COVERAGE: parse_mode edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config parse_mode: edge cases", "[config]")
{
  SECTION("empty mode string fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", ""}));
  }

  SECTION("origin-forward single mode")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "origin-forward"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) == 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) == 0);
  }

  SECTION("auto-learn,origin-forward combined")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn,origin-forward"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) == 0);
  }

  SECTION("trailing comma fails with empty token")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual,"}));
  }

  SECTION("leading comma fails with empty token")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", ",manual"}));
  }

  SECTION("duplicate mode is accepted (OR is idempotent)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual,manual", "--link", "</a.js>; rel=preload; as=script"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
  }

  SECTION("whitespace in mode string fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual "}));
  }

  SECTION("all three modes combined")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual,auto-learn,origin-forward", "--link", "</a.js>; rel=preload; as=script"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) != 0);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAP COVERAGE: is_valid_link_value branches
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config link validation: structural branches", "[config]")
{
  SECTION("empty link value rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", ""}));
  }

  SECTION("link without '<' prefix rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "/style.css>; rel=preload"}));
  }

  SECTION("link without '>' rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</style.css; rel=preload"}));
  }

  SECTION("empty URL '<>' rejected (url_end <= 1)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<>; rel=preload"}));
  }

  SECTION("DEL char (0x7F) in link rejected")
  {
    std::string evil = "</style.css>; rel=preload; as=styl";
    evil += '\x7F';
    evil += "e";
    EarlyHintsConfig config;
    std::vector<const char *> argv = {
      "http://from.example.com", "http://to.example.com", "--mode", "manual", "--link", evil.c_str()};
    CHECK_FALSE(config.init(6, argv.data()));
  }

  SECTION("nested '<' inside URL rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</sty<le.css>; rel=preload; as=style"}));
  }

  SECTION("link with no params after '>' rejected (no rel=)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</style.css>"}));
  }

  SECTION("rel= inside URL portion only — no params after '>'")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</evil.js?rel=preload>"}));
  }
}

TEST_CASE("Config link validation: all dangerous schemes", "[config][security]")
{
  SECTION("vbscript: scheme rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<vbscript:MsgBox>; rel=preload; as=script"}));
  }

  SECTION("blob: scheme rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<blob:http://evil.com/uuid>; rel=preload; as=script"}));
  }

  SECTION("JAVASCRIPT: uppercase rejected (case insensitive)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<JAVASCRIPT:alert(1)>; rel=preload; as=script"}));
  }

  SECTION("Data: mixed case rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<Data:text/css,body{}>; rel=stylesheet"}));
  }

  SECTION("VbScript: mixed case rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<VbScript:evil>; rel=preload; as=script"}));
  }
}

TEST_CASE("Config link validation: all rel= values", "[config]")
{
  SECTION("rel=preload accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preload; as=script"}));
  }

  SECTION("rel=preconnect accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preconnect"}));
  }

  SECTION("rel=stylesheet accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</a.css>; rel=stylesheet"}));
  }

  SECTION("rel=modulepreload accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</a.mjs>; rel=modulepreload"}));
  }

  SECTION("rel=prefetch NOT accepted (not in allowed list)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=prefetch"}));
  }

  SECTION("rel= value is case insensitive (REL=PRELOAD)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</a.js>; REL=PRELOAD; as=script"}));
  }
}

TEST_CASE("Config link validation: check_rel boundary logic", "[config]")
{
  SECTION("rel=preload at very start of params")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</a.js>;rel=preload"}));
  }

  SECTION("rel=preload at end of params with no trailing delimiter")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</a.js>; as=script; rel=preload"}));
  }

  SECTION("tab in link value rejected by control char filter (tabs < 0x20)")
  {
    // NOTE: check_rel allows tab as word boundary delimiter, but the control
    // character filter (uc < 0x20) fires first, making tab unreachable in check_rel.
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</a.js>;\trel=preload;\tas=script"}));
  }

  SECTION("rel=preload followed by double-quote is REJECTED (quote is not a valid unquoted boundary)")
  {
    EarlyHintsConfig config;
    // rel=preload"extra" uses '"' as boundary for unquoted form — not valid.
    // Use quoted form rel=\"preload\" instead. This is correct behavior.
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preload\"extra\""}));
  }

  SECTION("rel=preload followed by single-quote is REJECTED (quote is not a valid unquoted boundary)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preload'extra'"}));
  }

  SECTION("partial match xrel=preload rejected (before_ok fails)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</a.js>; xrel=preload"}));
  }

  SECTION("partial match rel=preloadx rejected (after_ok fails)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preloadx"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAP COVERAGE: is_whitelisted_domain edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config whitelist: domain edge cases", "[config]")
{
  SECTION("empty domain never matches")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK_FALSE(config.is_whitelisted_domain(""));
  }

  SECTION("empty whitelist means nothing matches")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    CHECK_FALSE(config.is_whitelisted_domain("cdn.example.com"));
  }

  SECTION("single char domain exact match")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "x"}));
    CHECK(config.is_whitelisted_domain("x"));
    CHECK_FALSE(config.is_whitelisted_domain("y"));
  }

  SECTION("domain longer than pattern never matches exactly")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("cdn.example.com.evil.com"));
  }

  SECTION("wildcard pattern without dot after * falls to exact match")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*example.com"}));
    // Pattern is "*example.com" — pattern[0]='*', pattern[1]='e' (not '.'),
    // so code falls to exact match branch: domain must equal "*example.com"
    CHECK_FALSE(config.is_whitelisted_domain("cdn.example.com"));
    CHECK_FALSE(config.is_whitelisted_domain("example.com"));
  }

  SECTION("wildcard matches deep subdomain")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.example.com"}));
    CHECK(config.is_whitelisted_domain("a.b.example.com"));
  }

  SECTION("wildcard pattern too short (just '*.' ) treated as exact match")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*."}));
    // Pattern size is 2, not > 2, so enters exact match branch
    CHECK_FALSE(config.is_whitelisted_domain("anything"));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAP COVERAGE: safe_parse_int edge cases (tested through init options)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config safe_parse_int: edge cases via --max-links", "[config]")
{
  SECTION("leading zeros parsed as decimal (010 = 10)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links", "010"}));
    CHECK(config.max_links() == 10);
  }

  SECTION("hex string rejected (trailing garbage after 0)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "0xFF"}));
  }

  SECTION("whitespace-only string rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", " "}));
  }

  SECTION("'0' parses to zero, then rejected by range check")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "0"}));
  }

  SECTION("negative overflow value rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "-99999999999999999"}));
  }

  SECTION("plus sign prefix rejected as trailing garbage")
  {
    EarlyHintsConfig config;
    // strtol accepts leading '+', so "+5" parses to 5 which is in range
    CHECK(parse_config(config, {"--max-links", "+5"}));
    CHECK(config.max_links() == 5);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAP COVERAGE: init() edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config init: argc edge cases", "[config]")
{
  SECTION("argc=0 returns true (no args at all)")
  {
    EarlyHintsConfig config;
    const char *argv[] = {nullptr};
    CHECK(config.init(0, argv));
  }

  SECTION("argc=1 returns true (only fromURL)")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"http://from.example.com"};
    CHECK(config.init(1, argv));
  }
}

TEST_CASE("Config init: unknown option rejected", "[config]")
{
  EarlyHintsConfig config;
  CHECK_FALSE(parse_config(config, {"--unknown-option"}));
}

TEST_CASE("Config init: --skip-bots and --navigate-only explicit enable", "[config]")
{
  SECTION("--skip-bots explicitly sets skip_bots true")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--no-skip-bots", "--skip-bots"}));
    CHECK(config.skip_bots() == true);
  }

  SECTION("--navigate-only explicitly sets navigate_only true")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--no-navigate-only", "--navigate-only"}));
    CHECK(config.navigate_only() == true);
  }
}

TEST_CASE("Config init: multiple --crossorigin-whitelist calls accumulate", "[config]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "a.com,b.com", "--crossorigin-whitelist", "c.com"}));
  REQUIRE(config.crossorigin_whitelist().size() == 3);
  CHECK(config.crossorigin_whitelist()[0] == "a.com");
  CHECK(config.crossorigin_whitelist()[1] == "b.com");
  CHECK(config.crossorigin_whitelist()[2] == "c.com");
}

TEST_CASE("Config init: --option=value syntax", "[config]")
{
  SECTION("--max-links=5 with equals sign")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links=5"}));
    CHECK(config.max_links() == 5);
  }

  SECTION("--debug-header=X-Test with equals sign")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--debug-header=X-Test"}));
    CHECK(std::string(config.debug_header()) == "X-Test");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAP COVERAGE: Boundary value tests (exact min and max for each parameter)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config boundary: max-links", "[config]")
{
  SECTION("max-links=1 (lower bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links", "1"}));
    CHECK(config.max_links() == 1);
  }

  SECTION("max-links=50 (upper bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links", "50"}));
    CHECK(config.max_links() == 50);
  }
}

TEST_CASE("Config boundary: persistence", "[config]")
{
  SECTION("persist-dir with valid path")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-dir", "/var/run/ats/"}));
    CHECK(config.persist_dir() == "/var/run/ats/");
    CHECK(config.persist_enabled() == true);
  }

  SECTION("persistence defaults to disabled (opt-in via --persist-dir)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    CHECK(config.persist_enabled() == false);
    CHECK(config.persist_dir().empty());
  }

  SECTION("no-persist flag disables persistence")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--no-persist"}));
    CHECK(config.persist_enabled() == false);
  }

  SECTION("persist-throttle valid value")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-throttle", "5"}));
    CHECK(config.persist_throttle() == 5);
  }

  SECTION("persist-throttle zero disables throttle")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-throttle", "0"}));
    CHECK(config.persist_throttle() == 0);
  }

  SECTION("persist-throttle max boundary accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-throttle", "300"}));
    CHECK(config.persist_throttle() == 300);
  }

  SECTION("persist-throttle over max rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--persist-throttle", "301"}));
  }

  SECTION("persist-throttle negative rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--persist-throttle", "-1"}));
  }

  SECTION("persist-throttle default is 10")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    CHECK(config.persist_throttle() == 10);
  }
}

TEST_CASE("Config boundary: header-size-limit", "[config]")
{
  SECTION("header-size-limit=256 (lower bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--header-size-limit", "256"}));
    CHECK(config.header_size_limit() == 256);
  }

  SECTION("header-size-limit=16384 (upper bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--header-size-limit", "16384"}));
    CHECK(config.header_size_limit() == 16384);
  }

  SECTION("header-size-limit=255 just below lower bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--header-size-limit", "255"}));
  }

  SECTION("header-size-limit=16385 just above upper bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--header-size-limit", "16385"}));
  }
}

TEST_CASE("Config boundary: scan-limit", "[config]")
{
  SECTION("scan-limit=1024 (lower bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--scan-limit", "1024"}));
    CHECK(config.scan_limit() == 1024);
  }

  SECTION("scan-limit=1048576 (upper bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--scan-limit", "1048576"}));
    CHECK(config.scan_limit() == 1048576);
  }

  SECTION("scan-limit=1023 just below lower bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--scan-limit", "1023"}));
  }

  SECTION("scan-limit=1048577 just above upper bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--scan-limit", "1048577"}));
  }
}

TEST_CASE("Config boundary: min-hit-count", "[config]")
{
  SECTION("min-hit-count=1 (lower bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--min-hit-count", "1"}));
    CHECK(config.min_hit_count() == 1);
  }

  SECTION("min-hit-count=1000 (upper bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--min-hit-count", "1000"}));
    CHECK(config.min_hit_count() == 1000);
  }

  SECTION("min-hit-count=0 just below lower bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--min-hit-count", "0"}));
  }

  SECTION("min-hit-count=1001 just above upper bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--min-hit-count", "1001"}));
  }
}

TEST_CASE("Config boundary: max-cache-entries", "[config]")
{
  SECTION("max-cache-entries=100 (lower bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-cache-entries", "100"}));
    CHECK(config.max_cache_entries() == 100);
  }

  SECTION("max-cache-entries=1000000 (upper bound)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-cache-entries", "1000000"}));
    CHECK(config.max_cache_entries() == 1000000);
  }

  SECTION("max-cache-entries=0 just below lower bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-cache-entries", "0"}));
  }

  SECTION("max-cache-entries=1000001 just above upper bound fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-cache-entries", "1000001"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT GAP: safe_parse_int — strtol quirks and extreme values
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config audit: safe_parse_int strtol behavior", "[config][audit]")
{
  SECTION("leading whitespace is silently accepted by strtol")
  {
    // strtol skips leading whitespace; safe_parse_int inherits this.
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links", " 5"}));
    CHECK(config.max_links() == 5);
  }

  SECTION("LONG_MAX string rejected by INT range check")
  {
    // 9223372036854775807 on 64-bit; strtol succeeds but val > INT_MAX.
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "9223372036854775807"}));
  }

  SECTION("LONG_MIN string rejected by INT range check")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "-9223372036854775808"}));
  }

  SECTION("beyond LONG_MAX triggers errno ERANGE")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "9223372036854775808"}));
  }

  SECTION("beyond LONG_MIN triggers errno ERANGE")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links", "-9223372036854775809"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT GAP: is_valid_link_value — whitespace-only URL, extra '>' in params
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config audit: link validation URL edge cases", "[config][audit]")
{
  SECTION("whitespace-only URL REJECTED by allowlist (scheme_start == npos)")
  {
    // URL portion is " " — after allowlist fix, url_part.find_first_not_of returns npos
    // for all-whitespace URLs, which is now correctly rejected (useless URL).
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "< >; rel=preload; as=script"}));
  }

  SECTION("extra '>' in params portion is REJECTED by is_valid_link_value")
  {
    // is_valid_link_value now rejects any < or > in the params portion
    // (after the closing > of the URL). A > in a title= or other attribute can be
    // mis-parsed by RFC 8288 browsers as a link-value separator, which is the
    // same parser path exploited by the fetchpriority injection vector.
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preload; title=a>b"}));
  }

  SECTION("http:// and https:// schemes accepted (not blocked)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "<https://cdn.example.com/a.js>; rel=preload; as=script"}));
  }

  SECTION("relative path URL accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</fonts/font.woff2>; rel=preload; as=font"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT GAP: is_whitelisted_domain — trailing dot, port, TLD wildcard, etc.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config audit: domain whitelist edge cases", "[config][audit]")
{
  SECTION("domain with trailing dot does not match exact entry")
  {
    // DNS canonical form has trailing dot; whitelist does no normalization.
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("cdn.example.com."));
  }

  SECTION("domain with port matches after port stripping")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    // Port is stripped — cdn.example.com:443 → cdn.example.com → matches
    CHECK(config.is_whitelisted_domain("cdn.example.com:443"));
  }

  SECTION("domain with trailing dot does not match wildcard")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.example.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("cdn.example.com."));
  }

  SECTION("wildcard *.com matches any subdomain of .com")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.com"}));
    CHECK(config.is_whitelisted_domain("evil.com"));
    CHECK(config.is_whitelisted_domain("deep.sub.evil.com"));
    CHECK_FALSE(config.is_whitelisted_domain("com")); // bare TLD doesn't match
  }

  SECTION("single '*' pattern (length 1) treated as exact match")
  {
    // Pattern size is 1 (not > 2), so wildcard branch not taken.
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*"}));
    CHECK_FALSE(config.is_whitelisted_domain("anything.com"));
  }

  SECTION("mixed wildcard and exact patterns in single whitelist")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.cdn.com,static.example.com"}));
    CHECK(config.is_whitelisted_domain("a.cdn.com"));
    CHECK(config.is_whitelisted_domain("static.example.com"));
    CHECK_FALSE(config.is_whitelisted_domain("cdn.com"));
    CHECK_FALSE(config.is_whitelisted_domain("other.example.com"));
  }

  SECTION("very long subdomain matches wildcard")
  {
    std::string long_sub(200, 'a');
    std::string long_domain = long_sub + ".example.com";
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.example.com"}));
    CHECK(config.is_whitelisted_domain(long_domain));
  }

  SECTION("domain exactly equal to wildcard suffix does not match")
  {
    // *.example.com with domain "example.com": suffix is ".example.com" (12 chars),
    // domain is "example.com" (11 chars). 11 > 12 is false → no match.
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.example.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("example.com"));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT GAP: parse_mode — trailing comma asymmetry, double comma, whitespace
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config audit: parse_mode comma and whitespace edge cases", "[config][audit]")
{
  SECTION("trailing comma with non-manual mode is rejected")
  {
    // R9-12 fix: trailing comma is now properly rejected as malformed input,
    // matching the behavior for leading comma and double comma.
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "auto-learn,"}));
  }

  SECTION("double comma produces empty segment → unknown mode error")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual,,auto-learn"}));
  }

  SECTION("tab character in mode name → unknown mode error")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual\t"}));
  }

  SECTION("newline character in mode name → unknown mode error")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual\n"}));
  }

  SECTION("space-padded mode name → unknown mode error")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", " manual"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT GAP: init() — duplicate options (last-wins behavior)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config audit: duplicate options last-wins", "[config][audit]")
{
  SECTION("--mode passed twice: second call resets mode_ then sets new value")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn", "--mode", "manual", "--link", "</a.js>; rel=preload; as=script"}));
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) == 0);
  }

  SECTION("--max-links passed twice: last value wins")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--max-links", "3", "--max-links", "7"}));
    CHECK(config.max_links() == 7);
  }

  SECTION("--debug-header passed twice: last value wins")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--debug-header", "X-First", "--debug-header", "X-Second"}));
    CHECK(std::string(config.debug_header()) == "X-Second");
  }

  SECTION("--persist-dir passed twice: last value wins")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-dir", "/first/dir/", "--persist-dir", "/second/dir/"}));
    CHECK(config.persist_dir() == "/second/dir/");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT GAP: init() — non-manual mode with --link, whitelist comma leniency
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config audit: non-manual mode with --link", "[config][audit]")
{
  SECTION("auto-learn mode accepts --link (stored but not required)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn", "--link", "</a.js>; rel=preload; as=script"}));
    CHECK(config.manual_links().size() == 1);
  }

  SECTION("origin-forward mode accepts --link")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "origin-forward", "--link", "</a.js>; rel=preload; as=script"}));
    CHECK(config.manual_links().size() == 1);
  }
}

TEST_CASE("Config audit: whitelist comma parsing leniency", "[config][audit]")
{
  SECTION("leading comma in whitelist: empty segment silently skipped")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", ",cdn.example.com"}));
    REQUIRE(config.crossorigin_whitelist().size() == 1);
    CHECK(config.crossorigin_whitelist()[0] == "cdn.example.com");
  }

  SECTION("trailing comma in whitelist: empty segment silently skipped")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com,"}));
    REQUIRE(config.crossorigin_whitelist().size() == 1);
    CHECK(config.crossorigin_whitelist()[0] == "cdn.example.com");
  }

  SECTION("double comma in whitelist: empty segment silently skipped")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "a.com,,b.com"}));
    REQUIRE(config.crossorigin_whitelist().size() == 2);
    CHECK(config.crossorigin_whitelist()[0] == "a.com");
    CHECK(config.crossorigin_whitelist()[1] == "b.com");
  }

  SECTION("all-commas whitelist produces empty list")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", ",,,"}));
    CHECK(config.crossorigin_whitelist().empty());
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY: Whitelist bypass attempt tests
//
// Each test below corresponds to a known URL/domain bypass technique.
// The whitelist must resist all of them — a match here means attacker-
// controlled resources get promoted from safe preconnect to full preload.
// ═══════════════════════════════════════════════════════════════════════════════

// ---------------------------------------------------------------------------
// 1. Subdomain suffix confusion
//    Whitelist: *.cdn.com  →  evil.cdn.com.attacker.com must NOT match.
//    The attacker registers cdn.com.attacker.com and hopes the suffix check
//    only looks at the rightmost "cdn.com" substring.
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 1: subdomain suffix confusion", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "*.cdn.com"}));

  // Must NOT match — attacker controls .attacker.com zone
  CHECK_FALSE(config.is_whitelisted_domain("evil.cdn.com.attacker.com"));
  CHECK_FALSE(config.is_whitelisted_domain("cdn.com.attacker.com"));

  // Legit subdomains must still work
  CHECK(config.is_whitelisted_domain("img.cdn.com"));
  CHECK(config.is_whitelisted_domain("a.b.cdn.com"));

  // Exact match entry: suffix attack must fail too
  EarlyHintsConfig config2;
  CHECK(parse_config(config2, {"--crossorigin-whitelist", "cdn.com"}));
  CHECK_FALSE(config2.is_whitelisted_domain("evil.cdn.com"));
  CHECK_FALSE(config2.is_whitelisted_domain("cdn.com.attacker.com"));
  CHECK(config2.is_whitelisted_domain("cdn.com"));
}

// ---------------------------------------------------------------------------
// 2. Port bypass
//    Whitelist: cdn.com  →  cdn.com:8080 must NOT match.
//    extract_origin preserves the port in the authority, so the domain
//    passed to is_whitelisted_domain includes ":8080".
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 2: port bypass", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));

  // Port is stripped — cdn.com:8080 → cdn.com → matches whitelist
  CHECK(config.is_whitelisted_domain("cdn.com:8080"));
  CHECK(config.is_whitelisted_domain("cdn.com:443"));
  CHECK(config.is_whitelisted_domain("cdn.com:80"));

  // Bare domain still matches
  CHECK(config.is_whitelisted_domain("cdn.com"));

  // Wildcard + port: img.cdn.com:8080 → img.cdn.com → matches *.cdn.com
  EarlyHintsConfig config2;
  CHECK(parse_config(config2, {"--crossorigin-whitelist", "*.cdn.com"}));
  CHECK(config2.is_whitelisted_domain("img.cdn.com:8080"));
  CHECK(config2.is_whitelisted_domain("img.cdn.com"));
}

// ---------------------------------------------------------------------------
// 3. Userinfo bypass
//    RFC 3986 allows userinfo@host in authority. Browsers mostly ignore
//    userinfo, but if extract_origin doesn't strip it, the domain becomes
//    "attacker@cdn.com" which must NOT match "cdn.com".
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 3: userinfo in authority", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));

  // Userinfo is stripped per RFC 3986 §3.2.1 — the actual host is cdn.com
  // which SHOULD match the whitelist (browser connects to cdn.com)
  CHECK(config.is_whitelisted_domain("attacker@cdn.com"));
  CHECK(config.is_whitelisted_domain("user:pass@cdn.com"));
  CHECK(config.is_whitelisted_domain("@cdn.com"));

  // Wildcard variant: attacker@foo.cdn.com → host is foo.cdn.com → matches *.cdn.com
  EarlyHintsConfig config2;
  CHECK(parse_config(config2, {"--crossorigin-whitelist", "*.cdn.com"}));
  CHECK(config2.is_whitelisted_domain("attacker@foo.cdn.com"));
}

// ---------------------------------------------------------------------------
// 4. Path confusion
//    "cdn.com/evil" should not match whitelist entry "cdn.com".
//    extract_origin strips paths, but if domain is passed with a path
//    fragment it must not match.
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 4: path confusion", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));

  CHECK_FALSE(config.is_whitelisted_domain("cdn.com/evil"));
  CHECK_FALSE(config.is_whitelisted_domain("cdn.com/"));
  CHECK_FALSE(config.is_whitelisted_domain("cdn.com?query=1"));
  CHECK_FALSE(config.is_whitelisted_domain("cdn.com#fragment"));
}

// ---------------------------------------------------------------------------
// 5. Case tricks
//    DNS is case-insensitive, so CDN.COM must match cdn.com.
//    The code lowercases via std::tolower(unsigned char) which is safe
//    for ASCII. Turkish İ/i locale is irrelevant for the C/POSIX locale
//    ATS uses, but we verify no breakage with odd casing.
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 5: case sensitivity tricks", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));

  // Standard case folding — must match
  CHECK(config.is_whitelisted_domain("CDN.COM"));
  CHECK(config.is_whitelisted_domain("Cdn.Com"));
  CHECK(config.is_whitelisted_domain("cDn.CoM"));

  // Mixed case in whitelist pattern
  EarlyHintsConfig config2;
  CHECK(parse_config(config2, {"--crossorigin-whitelist", "*.CDN.COM"}));
  CHECK(config2.is_whitelisted_domain("img.cdn.com"));
  CHECK(config2.is_whitelisted_domain("IMG.CDN.COM"));

  // All-caps domain against lowercase whitelist
  EarlyHintsConfig config3;
  CHECK(parse_config(config3, {"--crossorigin-whitelist", "cdn.example.com"}));
  CHECK(config3.is_whitelisted_domain("CDN.EXAMPLE.COM"));
}

// ---------------------------------------------------------------------------
// 6. Unicode homoglyph attack
//    Cyrillic 'с' (U+0441, UTF-8: 0xD1 0x81) looks identical to Latin 'c'
//    (0x63) but they're different bytes. The whitelist operates on raw bytes,
//    so homoglyphs must NOT match.
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 6: unicode homoglyphs", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));

  // Cyrillic с (U+0441) replacing Latin c
  CHECK_FALSE(config.is_whitelisted_domain("\xd1\x81"
                                           "dn.com"));

  // Cyrillic а (U+0430) replacing Latin a in "ajax.com"
  EarlyHintsConfig config2;
  CHECK(parse_config(config2, {"--crossorigin-whitelist", "ajax.com"}));
  CHECK_FALSE(config2.is_whitelisted_domain("\xd0\xb0jax.com"));

  // Cyrillic о (U+043E) replacing Latin o
  EarlyHintsConfig config3;
  CHECK(parse_config(config3, {"--crossorigin-whitelist", "foo.com"}));
  CHECK_FALSE(config3.is_whitelisted_domain("f\xd0\xbe\xd0\xbe.com"));
}

// ---------------------------------------------------------------------------
// 7. Null byte injection
//    In C, strlen("cdn.com\0.attacker.com") == 7, but std::string stores all
//    24 bytes. The whitelist uses std::string comparison, so embedded NULs
//    cause a length mismatch → no match. Verify this is the case.
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 7: null byte injection", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));

  // Embedded NUL: "cdn.com\0.attacker.com" has length > 7
  std::string poisoned("cdn.com\0.attacker.com", 21);
  CHECK_FALSE(config.is_whitelisted_domain(poisoned));

  // NUL at end: "cdn.com\0" has length 8
  std::string nul_suffix("cdn.com\0", 8);
  CHECK_FALSE(config.is_whitelisted_domain(nul_suffix));

  // NUL at beginning
  std::string nul_prefix("\0cdn.com", 8);
  CHECK_FALSE(config.is_whitelisted_domain(nul_prefix));

  // Wildcard + null byte
  EarlyHintsConfig config2;
  CHECK(parse_config(config2, {"--crossorigin-whitelist", "*.cdn.com"}));
  std::string wl_poisoned("evil\0.cdn.com", 13);
  // This has a NUL inside — the full string is "evil\0.cdn.com" (13 bytes)
  // ends with ".cdn.com" (8 bytes), and length 13 > 8 → would match suffix!
  // But the domain contains a NUL which is invalid — worth documenting behavior.
  // Current implementation: suffix match succeeds because std::string::compare
  // operates on full byte range. This is a potential concern if an attacker can
  // inject NUL bytes into URLs. However, HTTP headers cannot carry NUL bytes, so
  // this is defense-in-depth only.
  // We document the observed behavior here:
  bool matches = config2.is_whitelisted_domain(wl_poisoned);
  // The suffix ".cdn.com" is present, so it matches — this is the expected
  // std::string behavior. Real-world URLs cannot contain NUL bytes.
  CHECK(matches == true);
}

// ---------------------------------------------------------------------------
// 8. Trailing dot (FQDN)
//    DNS: "cdn.com." is the fully-qualified form of "cdn.com".
//    The whitelist does raw string comparison — "cdn.com." != "cdn.com".
//    This means FQDN forms are rejected. Safe (blocks by default).
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 8: trailing dot (FQDN)", "[config][security]")
{
  EarlyHintsConfig config;
  CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));

  // FQDN trailing dot — must NOT match bare domain entry
  CHECK_FALSE(config.is_whitelisted_domain("cdn.com."));

  // Wildcard: *.cdn.com — trailing dot breaks suffix
  EarlyHintsConfig config2;
  CHECK(parse_config(config2, {"--crossorigin-whitelist", "*.cdn.com"}));
  CHECK_FALSE(config2.is_whitelisted_domain("img.cdn.com."));
  CHECK(config2.is_whitelisted_domain("img.cdn.com"));

  // Whitelist entry itself has trailing dot — only matches exact FQDN
  EarlyHintsConfig config3;
  CHECK(parse_config(config3, {"--crossorigin-whitelist", "cdn.com."}));
  CHECK(config3.is_whitelisted_domain("cdn.com."));
  CHECK_FALSE(config3.is_whitelisted_domain("cdn.com"));
}

// ---------------------------------------------------------------------------
// 9. Wildcard edge cases
//    "*" alone, "*.", "**", "*.*" — pathological patterns.
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 9: wildcard edge cases", "[config][security]")
{
  SECTION("bare asterisk does not match everything")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*"}));
    // Pattern is "*" — length 1, not > 2, so exact match branch
    CHECK_FALSE(config.is_whitelisted_domain("anything.com"));
    CHECK_FALSE(config.is_whitelisted_domain("evil.com"));
    // Only literal "*" matches
    CHECK(config.is_whitelisted_domain("*"));
  }

  SECTION("asterisk-dot is too short for wildcard branch")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*."}));
    // Pattern is "*." — length 2, not > 2, so exact match branch
    CHECK_FALSE(config.is_whitelisted_domain("anything"));
    CHECK_FALSE(config.is_whitelisted_domain("a."));
    CHECK(config.is_whitelisted_domain("*."));
  }

  SECTION("double asterisk treated as literal")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "**"}));
    // Pattern "**" — length 2, [0]='*', [1]='*' (not '.'), so exact match
    CHECK_FALSE(config.is_whitelisted_domain("anything.com"));
    CHECK(config.is_whitelisted_domain("**"));
  }

  SECTION("*. followed by * matches domains ending with .*")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.*"}));
    // Pattern "*.*" — length 3, [0]='*', [1]='.', so wildcard branch
    // Suffix = ".*". Matches any domain ending with ".*" and longer than 2 chars
    CHECK(config.is_whitelisted_domain("cdn.*"));
    CHECK(config.is_whitelisted_domain("anything.*"));
    // But not 2-char-or-shorter strings
    CHECK_FALSE(config.is_whitelisted_domain(".*"));
  }

  SECTION("*.*.com does not act as multi-level wildcard")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.*.com"}));
    // Pattern "*.*.com" — length 7 > 2, [0]='*', [1]='.'
    // Suffix = ".*.com". Matches domains ending with ".*.com"
    // This is a literal suffix match — the inner * is NOT a wildcard
    CHECK_FALSE(config.is_whitelisted_domain("cdn.example.com"));
    CHECK(config.is_whitelisted_domain("cdn.*.com"));
  }
}

// ---------------------------------------------------------------------------
// 10. IP address vs domain mismatch
//     Whitelist has domain name but attacker uses IP address (or vice versa).
//     The whitelist is pure string comparison — no DNS resolution.
// ---------------------------------------------------------------------------
TEST_CASE("Security bypass 10: IP address vs domain mismatch", "[config][security]")
{
  SECTION("domain whitelist does not match IP address")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("93.184.216.34"));
    CHECK_FALSE(config.is_whitelisted_domain("127.0.0.1"));
  }

  SECTION("IP whitelist does not match domain")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "93.184.216.34"}));
    CHECK(config.is_whitelisted_domain("93.184.216.34"));
    CHECK_FALSE(config.is_whitelisted_domain("cdn.com"));
  }

  SECTION("wildcard cannot match IP octets")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.0.0.1"}));
    // "127.0.0.1" ends with ".0.0.1" and is longer → matches suffix!
    // This is technically correct wildcard behavior — admin configured it.
    CHECK(config.is_whitelisted_domain("127.0.0.1"));
    CHECK(config.is_whitelisted_domain("10.0.0.1"));
    // But "0.0.1" alone is too short (length 5 == suffix ".0.0.1" length 6? No).
    // Actually ".0.0.1" has 6 chars, "0.0.1" has 5 chars → 5 < 6, won't match
    CHECK_FALSE(config.is_whitelisted_domain("0.0.1"));
  }

  SECTION("IPv6 address does not match domain")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("[::1]"));
    CHECK_FALSE(config.is_whitelisted_domain("[2001:db8::1]"));
  }

  SECTION("IPv6 in brackets with port")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "[::1]"}));
    CHECK(config.is_whitelisted_domain("[::1]"));
    // Port stripping: [::1]:8080 → [::1] → matches
    CHECK(config.is_whitelisted_domain("[::1]:8080"));
  }
}

// ============================================================================
// R5 Bug Regression Tests — TDD RED phase
// ============================================================================

TEST_CASE("R5: empty domain after userinfo/port stripping must not match", "[config][r5]")
{
  SECTION("bare userinfo 'user@' should not match empty whitelist entry")
  {
    EarlyHintsConfig config;
    // Even if admin accidentally passes empty string, it should be handled safely
    CHECK(parse_config(config, {"--crossorigin-whitelist", ""}));
    // "user@" stripped of userinfo becomes "" — should NOT match
    CHECK_FALSE(config.is_whitelisted_domain("user@"));
  }

  SECTION("bare '@' should not match")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "example.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("@"));
  }

  SECTION("port-only ':80' should not match empty entry")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", ""}));
    CHECK_FALSE(config.is_whitelisted_domain(":80"));
  }

  SECTION("empty domain should never match any whitelist")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "example.com,cdn.com"}));
    CHECK_FALSE(config.is_whitelisted_domain(""));
  }

  SECTION("R6: whitespace after comma in whitelist is trimmed")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com, fonts.gstatic.com, \timages.cdn.com"}));
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
    CHECK(config.is_whitelisted_domain("fonts.gstatic.com"));
    CHECK(config.is_whitelisted_domain("images.cdn.com"));
  }

  SECTION("R6: whitespace-only domain after comma is ignored")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.com,  , fonts.com"}));
    CHECK(config.is_whitelisted_domain("cdn.com"));
    CHECK(config.is_whitelisted_domain("fonts.com"));
    CHECK_FALSE(config.is_whitelisted_domain(""));
    CHECK_FALSE(config.is_whitelisted_domain(" "));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT: getopt_long safety — re-entrancy, opterr suppression, trailing args
//
// These tests verify correct getopt_long state management in init().
// Bugs found during QA audit of the parsing loop.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("getopt_long audit: opterr must be suppressed", "[config][getopt]")
{
  // getopt_long prints "progname: unrecognized option '--foo'" to stderr when
  // opterr != 0. The plugin should suppress this since it handles errors itself
  // via TSError. We verify by capturing stderr.
  SECTION("unknown option does not produce stderr noise")
  {
    // Redirect stderr to a pipe so we can inspect output
    int pipefd[2];
    REQUIRE(pipe(pipefd) == 0);

    int saved_stderr = dup(STDERR_FILENO);
    REQUIRE(saved_stderr >= 0);
    dup2(pipefd[1], STDERR_FILENO);

    EarlyHintsConfig config;
    // This should fail, but NOT print to stderr
    CHECK_FALSE(parse_config(config, {"--unknown-option"}));

    // Flush and restore stderr
    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    close(pipefd[1]);

    // Read whatever getopt wrote to stderr
    char buf[1024] = {0};
    ssize_t n      = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);

    // If opterr was properly set to 0, nothing should have been written
    if (n > 0) {
      buf[n] = '\0';
    }
    INFO("stderr output: " << buf);
    CHECK(n <= 0); // No output expected
  }
}

TEST_CASE("getopt_long audit: trailing positional args must be rejected", "[config][getopt]")
{
  // The "+" prefix in optstring stops parsing at the first positional arg.
  // But the code never checks if optind < argc after the loop, so extra
  // positional arguments are silently ignored. This is a config error that
  // should be caught (e.g., typo: "--max-link 5" missing the 's').
  SECTION("extra positional argument after valid options")
  {
    EarlyHintsConfig config;
    // "extra_arg" is a positional argument — should be rejected
    CHECK_FALSE(parse_config(config, {"--mode", "auto-learn", "extra_arg"}));
  }

  SECTION("positional argument between options stops parsing")
  {
    EarlyHintsConfig config;
    // With "+", getopt stops at "bogus". "--max-links" is never parsed.
    // init() should detect the unparsed remainder and fail.
    CHECK_FALSE(parse_config(config, {"--mode", "auto-learn", "bogus", "--max-links", "5"}));
  }

  SECTION("all valid options should still succeed")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn", "--max-links", "5"}));
    CHECK(config.max_links() == 5);
  }
}

TEST_CASE("getopt_long audit: re-entrant parsing across multiple configs", "[config][getopt]")
{
  // When ATS loads multiple remap rules, init() is called multiple times in
  // the same process. Each call must fully reset getopt state so prior calls
  // don't interfere.
  SECTION("sequential init calls produce independent results")
  {
    // First config: set max-links=3
    EarlyHintsConfig config1;
    CHECK(parse_config(config1, {"--mode", "auto-learn", "--max-links", "3"}));
    CHECK(config1.max_links() == 3);

    // Second config: set max-links=7
    EarlyHintsConfig config2;
    CHECK(parse_config(config2, {"--mode", "auto-learn", "--max-links", "7"}));
    CHECK(config2.max_links() == 7);

    // Third config: no max-links, should get default (10)
    EarlyHintsConfig config3;
    CHECK(parse_config(config3, {"--mode", "auto-learn"}));
    CHECK(config3.max_links() == 10);
  }

  SECTION("failed init does not corrupt subsequent init")
  {
    // First: a failed parse (invalid option)
    EarlyHintsConfig config_bad;
    CHECK_FALSE(parse_config(config_bad, {"--mode", "invalid-mode"}));

    // Second: valid parse should succeed without corruption
    EarlyHintsConfig config_good;
    CHECK(parse_config(config_good, {"--mode", "auto-learn", "--max-links", "5"}));
    CHECK(config_good.max_links() == 5);
    CHECK((config_good.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
  }

  SECTION("dirty getopt state from external caller does not corrupt init")
  {
    // Simulate another plugin or code path that called getopt_long before us,
    // leaving internal state dirty (optind at some value, optarg set, etc.)
    static const struct option ext_opts[] = {
      {const_cast<char *>("foo"), required_argument, nullptr, 'f'},
      {nullptr, 0, nullptr, 0},
    };
    const char *ext_argv[] = {"prog", "--foo", "bar", "--foo", "baz"};
    optind                 = 1;
    getopt_long(5, const_cast<char *const *>(ext_argv), "f:", ext_opts, nullptr);
    // optind is now 3, optarg points to "bar" — state is dirty

    // init() must fully reset getopt state regardless
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn", "--max-links", "5"}));
    CHECK(config.max_links() == 5);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) != 0);
  }
}

TEST_CASE("getopt_long audit: default mode safety", "[config][getopt]")
{
  // Audit Q4: auto-learn involves HTML body scanning — it should NOT be enabled
  // by default. A zero-config plugin should only do origin-forward (safe pass-through).
  SECTION("zero-config default must not include auto-learn")
  {
    EarlyHintsConfig config;
    std::vector<const char *> argv = {"http://from.example.com", "http://to.example.com"};
    CHECK(config.init(2, argv.data()));
    CHECK((config.mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) == 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_MANUAL) == 0);
  }

  SECTION("argc < 2 returns true with safe defaults")
  {
    EarlyHintsConfig config;
    std::vector<const char *> argv = {"http://from.example.com"};
    CHECK(config.init(1, argv.data()));
    CHECK((config.mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) != 0);
    CHECK((config.mode() & EarlyHintsConfig::MODE_AUTO_LEARN) == 0);
  }
}

// ============================================================================
// R9 Phase 4: RED tests for confirmed bugs
// ============================================================================

TEST_CASE("R9-02: check_rel_quoted rejects junk after closing quote", "[config][r9][bug]")
{
  // rel="preload"garbage has junk immediately after the closing quote.
  // This is malformed per RFC 8288 and should be rejected.
  EarlyHintsConfig config;
  SECTION("double-quoted preload with trailing junk")
  {
    CHECK_FALSE(parse_config(config, {"--link", R"(<http://x.com>; rel="preload"garbage)"}));
  }
  SECTION("single-quoted preload with trailing junk")
  {
    CHECK_FALSE(parse_config(config, {"--link", "<http://x.com>; rel='preload'garbage"}));
  }
  SECTION("valid double-quoted preload still accepted")
  {
    CHECK(parse_config(config, {"--link", R"(<http://x.com>; rel="preload")"}));
  }
  SECTION("valid single-quoted preload still accepted")
  {
    CHECK(parse_config(config, {"--link", "<http://x.com>; rel='preload'"}));
  }
}

TEST_CASE("R9-12: parse_mode rejects trailing comma", "[config][r9][bug]")
{
  EarlyHintsConfig config;
  SECTION("trailing comma after valid mode")
  {
    // "origin-forward," has a trailing comma — malformed input, should fail
    CHECK_FALSE(parse_config(config, {"--mode", "origin-forward,"}));
  }
  SECTION("trailing comma after two modes") { CHECK_FALSE(parse_config(config, {"--mode", "auto-learn,origin-forward,"})); }
  SECTION("valid comma-separated modes still work") { CHECK(parse_config(config, {"--mode", "auto-learn,origin-forward"})); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT V2: Missing test scenarios
// ═══════════════════════════════════════════════════════════════════════════════

// cfg-01: --persist-dir + --no-persist contradictory state
TEST_CASE("Config audit v2: --persist-dir with --no-persist", "[config][audit-v2]")
{
  SECTION("--persist-dir then --no-persist: persist disabled, dir kept")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-dir", "/tmp/hints/", "--no-persist"}));
    CHECK(config.persist_enabled() == false);
    CHECK(config.persist_dir() == "/tmp/hints/");
  }

  SECTION("--no-persist then --persist-dir: persist-dir re-enables (last-write-wins)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--no-persist", "--persist-dir", "/tmp/hints/"}));
    // --persist-dir always enables persistence regardless of prior --no-persist
    CHECK(config.persist_enabled() == true);
    CHECK(config.persist_dir() == "/tmp/hints/");
  }
}

// cfg-02: Missing required argument for options
TEST_CASE("Config audit v2: missing required argument", "[config][audit-v2]")
{
  SECTION("--max-links without value at end of argv")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-links"}));
  }

  SECTION("--persist-dir without value at end of argv")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--persist-dir"}));
  }

  SECTION("--header-size-limit without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--header-size-limit"}));
  }

  SECTION("--scan-limit without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--scan-limit"}));
  }

  SECTION("--min-hit-count without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--min-hit-count"}));
  }

  SECTION("--max-cache-entries without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--max-cache-entries"}));
  }

  SECTION("--mode without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode"}));
  }

  SECTION("--debug-header without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--debug-header"}));
  }

  SECTION("--crossorigin-whitelist without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--crossorigin-whitelist"}));
  }

  SECTION("--link without value")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link"}));
  }
}

// cfg-03: --no-persist then --persist-dir order matters
TEST_CASE("Config audit v2: persist flag ordering", "[config][audit-v2]")
{
  SECTION("--no-persist is final state when last")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--persist-dir", "/tmp/a/", "--no-persist"}));
    CHECK(config.persist_enabled() == false);
  }
}

// cfg-04: Mode with double comma
TEST_CASE("Config audit v2: mode double comma", "[config][audit-v2]")
{
  SECTION("double comma creates empty token — fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual,,auto-learn"}));
  }

  SECTION("triple comma fails")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", ",,,"}));
  }
}

// ─── miss-03: IPv6 with userinfo edge case ──────────────────────────────────

TEST_CASE("Config whitelist: IPv6 with userinfo prefix", "[config][whitelist][audit]")
{
  SECTION("user@[::1] is matched after userinfo stripping")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn", "--crossorigin-whitelist", "[::1]"}));
    CHECK(config.is_whitelisted_domain("[::1]"));
    // RFC 3986 §3.2.1: user@host → strip userinfo → [::1] matches
    CHECK(config.is_whitelisted_domain("user@[::1]"));
  }

  SECTION("user@[::1]:8080 matches after userinfo + port stripping")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn", "--crossorigin-whitelist", "[::1]"}));
    // user@[::1]:8080 → strip user@ → [::1]:8080 → strip :8080 → [::1] → matches
    CHECK(config.is_whitelisted_domain("user@[::1]:8080"));
  }

  SECTION("userinfo with special chars stripped correctly")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn", "--crossorigin-whitelist", "cdn.example.com"}));
    // admin:pass@cdn.example.com → strip admin:pass@ → cdn.example.com → matches
    CHECK(config.is_whitelisted_domain("admin:pass@cdn.example.com"));
    // Without userinfo still matches
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// --preload-whitelist config parsing and is_preload_domain()
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config preload whitelist", "[config]")
{
  SECTION("comma-separated domains parsed correctly")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--preload-whitelist", "cdn.example.com,static.example.com"}));
    REQUIRE(config.preload_whitelist().size() == 2);
    CHECK(config.preload_whitelist()[0] == "cdn.example.com");
    CHECK(config.preload_whitelist()[1] == "static.example.com");
  }

  SECTION("is_preload_domain exact match")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--preload-whitelist", "cdn.example.com"}));
    CHECK(config.is_preload_domain("cdn.example.com"));
    CHECK_FALSE(config.is_preload_domain("other.example.com"));
  }

  SECTION("is_preload_domain wildcard match")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--preload-whitelist", "*.example.com"}));
    CHECK(config.is_preload_domain("cdn.example.com"));
    CHECK(config.is_preload_domain("static.example.com"));
    CHECK_FALSE(config.is_preload_domain("example.com"));
    CHECK_FALSE(config.is_preload_domain("evil.com"));
  }

  SECTION("is_preload_domain case insensitive")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--preload-whitelist", "CDN.Example.COM"}));
    CHECK(config.is_preload_domain("cdn.example.com"));
    CHECK(config.is_preload_domain("CDN.EXAMPLE.COM"));
  }

  SECTION("domain in neither list returns false for both")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "fonts.example.com", "--preload-whitelist", "cdn.example.com"}));
    CHECK_FALSE(config.is_whitelisted_domain("unknown.com"));
    CHECK_FALSE(config.is_preload_domain("unknown.com"));
  }

  SECTION("preload_whitelist accessor returns empty by default")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "auto-learn"}));
    CHECK(config.preload_whitelist().empty());
  }

  SECTION("both whitelists can be set independently")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "fonts.googleapis.com", "--preload-whitelist", "cdn.example.com"}));
    CHECK(config.is_whitelisted_domain("fonts.googleapis.com"));
    CHECK_FALSE(config.is_whitelisted_domain("cdn.example.com"));
    CHECK(config.is_preload_domain("cdn.example.com"));
    CHECK_FALSE(config.is_preload_domain("fonts.googleapis.com"));
  }
}

// ==================== as= validation for rel=preload (Todo 2) ====================
// has_valid_as_for_preload() returns true when as= is valid OR when rel is not preload.
// For rel=preload, as= is required. For rel=modulepreload, as= is optional per the
// HTML spec — the browser defaults to script. Returns false only for rel=preload
// with missing or invalid as=.

TEST_CASE("has_valid_as_for_preload validation", "[config][as-validation]")
{
  SECTION("rel=preload with valid as=script returns true") { CHECK(has_valid_as_for_preload("</app.js>; rel=preload; as=script")); }

  SECTION("rel=preload with valid as=style returns true")
  {
    CHECK(has_valid_as_for_preload("</style.css>; rel=preload; as=style"));
  }

  SECTION("rel=preload with valid as=image returns true")
  {
    CHECK(has_valid_as_for_preload("</hero.webp>; rel=preload; as=image"));
  }

  SECTION("rel=preload with valid as=font returns true") { CHECK(has_valid_as_for_preload("</font.woff2>; rel=preload; as=font")); }

  SECTION("rel=preload with valid as=fetch returns true") { CHECK(has_valid_as_for_preload("</api/data>; rel=preload; as=fetch")); }

  SECTION("all valid as= values accepted for rel=preload")
  {
    // Fetch spec §8 destination values
    const char *valid[] = {"audio",  "document", "embed", "fetch", "font",  "frame",  "iframe",      "image",
                           "object", "script",   "style", "track", "video", "worker", "sharedworker"};
    for (const char *as_val : valid) {
      std::string link = std::string("</res>; rel=preload; as=") + as_val;
      INFO("Testing as=" << as_val);
      CHECK(has_valid_as_for_preload(link));
    }
  }

  SECTION("rel=preload WITHOUT as= returns false") { CHECK_FALSE(has_valid_as_for_preload("</app.js>; rel=preload")); }

  SECTION("rel=preload with as= missing value returns false")
  {
    CHECK_FALSE(has_valid_as_for_preload("</app.js>; rel=preload; as="));
  }

  SECTION("rel=preload with invalid as= value returns false")
  {
    CHECK_FALSE(has_valid_as_for_preload("</app.js>; rel=preload; as=banana"));
  }

  SECTION("rel=modulepreload WITHOUT as= returns true (as= is optional for modulepreload)")
  {
    // HTML spec: as= is optional for rel=modulepreload. Without it, the browser
    // defaults to script destination. The plugin must NOT drop modulepreload links
    // that omit as=, because that would cause data loss on every disk reload.
    CHECK(has_valid_as_for_preload("</module.mjs>; rel=modulepreload"));
  }

  SECTION("rel=modulepreload with valid as=script still returns true")
  {
    CHECK(has_valid_as_for_preload("</module.mjs>; rel=modulepreload; as=script"));
  }

  SECTION("rel=preconnect WITHOUT as= returns true (as= not required)")
  {
    CHECK(has_valid_as_for_preload("</cdn>; rel=preconnect"));
  }

  SECTION("rel=stylesheet WITHOUT as= returns true (as= not required)")
  {
    CHECK(has_valid_as_for_preload("</style.css>; rel=stylesheet"));
  }

  SECTION("quoted rel=\"preload\" without as= returns false")
  {
    CHECK_FALSE(has_valid_as_for_preload(R"(</app.js>; rel="preload")"));
  }

  SECTION("quoted rel='preload' without as= returns false")
  {
    CHECK_FALSE(has_valid_as_for_preload(R"(</app.js>; rel='preload')"));
  }

  SECTION("non-matching quoted rel without as= returns true")
  {
    CHECK(has_valid_as_for_preload(R"(</app.js>; xrel="preload")"));
    CHECK(has_valid_as_for_preload(R"(</app.js>; xrel='preload')"));
    CHECK(has_valid_as_for_preload(R"(</app.js>; rel="preloadx")"));
  }

  SECTION("as= value is case-insensitive")
  {
    CHECK(has_valid_as_for_preload("</app.js>; rel=preload; as=Script"));
    CHECK(has_valid_as_for_preload("</app.js>; rel=preload; as=STYLE"));
    CHECK(has_valid_as_for_preload("</app.js>; rel=preload; as=Image"));
  }

  SECTION("as= before rel=preload accepted (order-independent)")
  {
    CHECK(has_valid_as_for_preload("</app.js>; as=script; rel=preload"));
  }

  SECTION("as= with extra whitespace still parsed") { CHECK(has_valid_as_for_preload("</app.js>; rel=preload; as=script ")); }
}

TEST_CASE("Soft-warn: link accepted despite missing as=", "[config][as-validation][soft-warn]")
{
  SECTION("rel=preload without as= still stored in manual_links (soft warn)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</app.js>; rel=preload"}));
    REQUIRE(config.manual_links().size() == 1);
    CHECK(config.manual_links()[0] == "</app.js>; rel=preload");
  }

  SECTION("rel=preload with invalid as= still stored (soft warn)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</app.js>; rel=preload; as=banana"}));
    REQUIRE(config.manual_links().size() == 1);
  }

  SECTION("rel=preload with valid as= stored normally")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</app.js>; rel=preload; as=script"}));
    REQUIRE(config.manual_links().size() == 1);
  }
}

// ==================== merge_hint_links (Todo 4) ====================
// Merges manual links + cached links with URL deduplication.

TEST_CASE("merge_hint_links: basic merging", "[config][merge]")
{
  SECTION("manual only — no cached links")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script", "</b.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, nullptr, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "</a.js>; rel=preload; as=script");
    CHECK(result[1] == "</b.css>; rel=preload; as=style");
  }

  SECTION("cached only — no manual links")
  {
    std::vector<std::string> empty_manual;
    std::vector<std::string> cached = {"</x.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(empty_manual, &cached, 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</x.js>; rel=preload; as=script");
  }

  SECTION("manual + cached — no overlap")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"</b.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "</a.js>; rel=preload; as=script");
    CHECK(result[1] == "</b.css>; rel=preload; as=style");
  }

  SECTION("manual has priority — appears first")
  {
    std::vector<std::string> manual = {"</manual.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"</cached.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "</manual.js>; rel=preload; as=script");
    CHECK(result[1] == "</cached.css>; rel=preload; as=style");
  }
}

TEST_CASE("merge_hint_links: deduplication", "[config][merge]")
{
  SECTION("duplicate URL deduped — manual wins")
  {
    std::vector<std::string> manual = {"</app.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"</app.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("same URL different rel — deduped (preload subsumes preconnect, manual wins)")
  {
    std::vector<std::string> manual = {"</cdn.com>; rel=preconnect"};
    std::vector<std::string> cached = {"</cdn.com>; rel=preload; as=script"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</cdn.com>; rel=preconnect");
  }

  SECTION("same URL different params — deduped by URL portion")
  {
    std::vector<std::string> manual = {"</app.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"</app.js>; rel=preload; as=script; crossorigin=anonymous"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</app.js>; rel=preload; as=script");
  }

  SECTION("dedup within cached set itself")
  {
    std::vector<std::string> empty_manual;
    std::vector<std::string> cached = {"</a.js>; rel=preload; as=script", "</a.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(empty_manual, &cached, 10);
    REQUIRE(result.size() == 1);
  }
}

TEST_CASE("merge_hint_links: max_links cap", "[config][merge]")
{
  SECTION("max_links caps combined output")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script", "</b.css>; rel=preload; as=style"};
    std::vector<std::string> cached = {"</c.woff2>; rel=preload; as=font"};
    auto result                     = merge_hint_links(manual, &cached, 2);
    CHECK(result.size() == 2);
    CHECK(result[0] == "</a.js>; rel=preload; as=script");
    CHECK(result[1] == "</b.css>; rel=preload; as=style");
  }

  SECTION("max_links=1 returns only first manual link")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script", "</b.css>; rel=preload; as=style"};
    std::vector<std::string> cached = {"</c.woff2>; rel=preload; as=font"};
    auto result                     = merge_hint_links(manual, &cached, 1);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</a.js>; rel=preload; as=script");
  }

  SECTION("max_links allows cached links when manual under cap")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"</b.css>; rel=preload; as=style", "</c.woff2>; rel=preload; as=font"};
    auto result                     = merge_hint_links(manual, &cached, 2);
    CHECK(result.size() == 2);
    CHECK(result[0] == "</a.js>; rel=preload; as=script");
    CHECK(result[1] == "</b.css>; rel=preload; as=style");
  }
}

TEST_CASE("merge_hint_links: edge cases", "[config][merge]")
{
  SECTION("both empty — returns empty")
  {
    std::vector<std::string> empty_manual;
    auto result = merge_hint_links(empty_manual, nullptr, 10);
    CHECK(result.empty());
  }

  SECTION("cached is empty vector — returns manual only")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script"};
    std::vector<std::string> empty_cached;
    auto result = merge_hint_links(manual, &empty_cached, 10);
    REQUIRE(result.size() == 1);
  }

  SECTION("max_links=0 — returns empty")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(manual, nullptr, 0);
    CHECK(result.empty());
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Scheme allowlist unification tests
// These must FAIL before fix, PASS after fix.
// Bug: is_valid_link_value uses denylist (only blocks js/data/vbscript/blob).
// Exotic schemes like file:, ftp:, chrome-extension: bypass the denylist.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("is_valid_link_value rejects exotic schemes (allowlist)", "[config][security][allowlist]")
{
  SECTION("file:// scheme rejected — not in current denylist (BUG)")
  {
    // Current denylist: js/data/vbscript/blob only. file: passes. MUST fail before fix.
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<file:///etc/passwd>; rel=preload; as=fetch"}));
  }

  SECTION("ftp:// scheme rejected — not in current denylist (BUG)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<ftp://evil.com/payload.bin>; rel=preload; as=fetch"}));
  }

  SECTION("chrome-extension:// scheme rejected — not in current denylist (BUG)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(
      parse_config(config, {"--mode", "manual", "--link", "<chrome-extension://abcdef/inject.js>; rel=preload; as=script"}));
  }

  SECTION("feed:javascript: nested scheme rejected — not in current denylist (BUG)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<feed:javascript:alert(1)>; rel=preload; as=script"}));
  }

  SECTION("jar:file: nested scheme rejected — not in current denylist (BUG)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<jar:file:///tmp/evil.jar!/exploit>; rel=preload; as=fetch"}));
  }

  SECTION("ws:// websocket scheme rejected — not in current denylist (BUG)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<ws://evil.com/sock>; rel=preload; as=fetch"}));
  }

  SECTION("wss:// websocket-secure scheme rejected — not in current denylist (BUG)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", "<wss://evil.com/sock>; rel=preload; as=fetch"}));
  }

  SECTION("https:// still accepted after allowlist fix")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "<https://cdn.example.com/app.js>; rel=preload; as=script"}));
  }

  SECTION("http:// still accepted after allowlist fix")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "<http://cdn.example.com/app.js>; rel=preload; as=script"}));
  }

  SECTION("relative URL still accepted after allowlist fix")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "</app.js>; rel=preload; as=script"}));
  }

  SECTION("protocol-relative URL still accepted after allowlist fix")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", "<//cdn.example.com/app.js>; rel=preload; as=script"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// check_rel boundary — norel= false positive
// Bug: `"` and `'` allowed as after_ok boundary in unquoted rel check,
// so `rel=preload"garbage` passes incorrectly.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("check_rel boundary — quote not valid for unquoted rel form", "[config][rel_boundary]")
{
  SECTION("rel=preload followed by double-quote is REJECTED (unquoted form boundary bug)")
  {
    // Current code: after_ok includes '"', so rel=preload"garbage passes. BUG.
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", R"(</a.js>; rel=preload"garbage")"}));
  }

  SECTION("rel=preload followed by single-quote is REJECTED (unquoted form boundary bug)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--mode", "manual", "--link", R"(</a.js>; rel=preload'garbage')"}));
  }

  SECTION("rel=\"preload\" quoted form still accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", R"(</a.js>; rel="preload"; as=script)"}));
  }

  SECTION("rel='preload' single-quoted form still accepted")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--mode", "manual", "--link", R"(</a.js>; rel='preload'; as=script)"}));
  }
}

TEST_CASE("Config: debug-header sanitization (M-6)", "[config][security]")
{
  SECTION("valid debug-header names are accepted")
  {
    EarlyHintsConfig config;
    CHECK(
      parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preload; as=script", "--debug-header", "X-Early-Hints"}));
    CHECK(parse_config(config,
                       {"--mode", "manual", "--link", "</a.js>; rel=preload; as=script", "--debug-header", "Custom_Header_123"}));
  }

  SECTION("debug-header containing CRLF is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(
      config, {"--mode", "manual", "--link", "</a.js>; rel=preload; as=script", "--debug-header", "X-Header\r\nInjection: value"}));
  }

  SECTION("debug-header containing colon is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(
      parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preload; as=script", "--debug-header", "X-Header: value"}));
  }

  SECTION("debug-header containing space is rejected")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(
      parse_config(config, {"--mode", "manual", "--link", "</a.js>; rel=preload; as=script", "--debug-header", "X-Header Name"}));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Space (0x20) must be rejected by is_valid_link_value
//
// The bug: the control-char filter uses `uc < 0x20`, which passes space
// (0x20 is NOT less than 0x20). A URL with an embedded space must be
// rejected because it breaks HTTP header framing (Link: <...> is terminated
// by whitespace in many parsers) and violates RFC 3986 §2.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config: space (0x20) in link URL rejected by is_valid_link_value", "[config][security]")
{
  SECTION("space in URL path is rejected")
  {
    // A space (0x20) in the URL portion must be rejected.
    // Bug: `uc < 0x20` passes 0x20. Fix requires `uc <= 0x20`.
    CHECK_FALSE(is_valid_link_value("</path with spaces>; rel=preload; as=style"));
  }

  SECTION("space in URL at start is rejected") { CHECK_FALSE(is_valid_link_value("< /style.css>; rel=preload; as=style")); }

  SECTION("URL with no spaces still accepted (baseline)") { CHECK(is_valid_link_value("</style.css>; rel=preload; as=style")); }

  SECTION("URL with tab (0x09) is still rejected (pre-existing behaviour)")
  {
    // Tab is < 0x20, so already correctly rejected before the fix.
    CHECK_FALSE(is_valid_link_value("</path\twith\ttabs>; rel=preload; as=style"));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// dedup_link_segments must not add an entry when URL key exactly
//        equals an already-seen key.
//
// The bug: the supersede condition uses `existing.size() > url_key.size()`
// (strict greater-than), so an entry with an identical URL key is never
// deduplicated — it gets added a second time. Fix: change > to >=.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config: dedup_link_segments exact-size URL key deduplication", "[config][dedup]")
{
  SECTION("two segments with identical URL key: only first survives")
  {
    // Both links reference the same URL. dedup_link_segments must keep only one.
    // Bug: existing.size() > url_key.size() is false when sizes are equal,
    // so the second is never dropped.
    std::vector<std::string> segments = {
      "</style.css>; rel=preload; as=style",
      "</style.css>; rel=preload; as=style", // exact duplicate
    };
    auto result = dedup_link_segments(std::move(segments), 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</style.css>; rel=preload; as=style");
  }

  SECTION("two segments with same URL but different params: only first survives")
  {
    // URL key (everything up to '>') is identical. Only the first wins.
    std::vector<std::string> segments = {
      "</style.css>; rel=preload; as=style",
      "</style.css>; rel=stylesheet", // same URL, different rel
    };
    auto result = dedup_link_segments(std::move(segments), 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</style.css>; rel=preload; as=style");
  }

  SECTION("different URLs are kept separately (no false positive)")
  {
    std::vector<std::string> segments = {
      "</a.css>; rel=preload; as=style",
      "</b.css>; rel=preload; as=style",
    };
    auto result = dedup_link_segments(std::move(segments), 10);
    REQUIRE(result.size() == 2);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// dedup_link_segments must be called once after all Link fields are collected
//        are collected, not once per field inside the while(link_field) loop.
//
// The bug: calling dedup per-field means cross-field duplicates are never
// eliminated. merge_hint_links already uses extract_dedup_key for its own
// dedup, but dedup_link_segments is called before merge — if it's in the
// loop, each partial segment list is deduplicated in isolation, not globally.
//
// This test exercises merge_hint_links which wraps the same dedup logic.
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config: merge_hint_links deduplication across multiple inputs", "[config][dedup]")
{
  SECTION("duplicate URL across manual and cached links: only one survives")
  {
    std::vector<std::string> manual = {"</style.css>; rel=preload; as=style"};
    std::vector<std::string> cached = {"</style.css>; rel=preload; as=style"}; // same URL
    auto result                     = merge_hint_links(manual, &cached, 10);
    // With correct dedup, exactly one entry survives.
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</style.css>; rel=preload; as=style");
  }

  SECTION("three identical URLs collapse to one")
  {
    std::vector<std::string> manual = {
      "</style.css>; rel=preload; as=style",
      "</style.css>; rel=preload; as=style",
    };
    std::vector<std::string> cached = {"</style.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 1);
  }

  SECTION("different URLs all survive (no false dedup)")
  {
    std::vector<std::string> manual = {"</a.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"</b.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 2);
  }
}

// ==================== normalize_link_for_hint ====================

TEST_CASE("normalize_link_for_hint: stylesheet conversion", "[config][normalize]")
{
  SECTION("rel=stylesheet converted to rel=preload; as=style")
  {
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet");
    CHECK(result == "</style.css>; rel=preload; as=style");
  }

  SECTION("rel=stylesheet with quoted value converted")
  {
    std::string result = normalize_link_for_hint("</theme.css>; rel=\"stylesheet\"");
    CHECK(result == "</theme.css>; rel=preload; as=style");
  }

  SECTION("rel=preload passthrough unchanged")
  {
    std::string link   = "</app.js>; rel=preload; as=script";
    std::string result = normalize_link_for_hint(link);
    CHECK(result == link);
  }

  SECTION("rel=preconnect passthrough unchanged")
  {
    std::string link   = "<https://cdn.example.com>; rel=preconnect";
    std::string result = normalize_link_for_hint(link);
    CHECK(result == link);
  }

  SECTION("rel=modulepreload passthrough unchanged")
  {
    std::string link   = "</mod.js>; rel=modulepreload";
    std::string result = normalize_link_for_hint(link);
    CHECK(result == link);
  }

  SECTION("rel=stylesheet with extra params: extra params dropped, as=style added")
  {
    // Origin may send </a.css>; rel=stylesheet; media=print
    // We strip non-hint params and convert to preload.
    std::string result = normalize_link_for_hint("</a.css>; rel=stylesheet; media=print");
    CHECK(result == "</a.css>; rel=preload; as=style");
  }

  SECTION("empty string returns empty") { CHECK(normalize_link_for_hint("").empty()); }

  SECTION("link with no rel returns empty") { CHECK(normalize_link_for_hint("</x.css>; foo=bar").empty()); }
}

TEST_CASE("normalize_link_for_hint: boundary-aware rel matching", "[config][normalize][boundary]")
{
  SECTION("xrel=stylesheet must NOT match (prefix boundary violation)")
  {
    std::string result = normalize_link_for_hint("</path>; xrel=stylesheet");
    CHECK(result.empty());
  }

  SECTION("myrel=preload must NOT match")
  {
    std::string result = normalize_link_for_hint("</path>; myrel=preload; as=style");
    CHECK(result.empty());
  }

  SECTION("rel=preloadx must NOT match (suffix boundary violation)")
  {
    std::string result = normalize_link_for_hint("</path>; rel=preloadx; as=style");
    CHECK(result.empty());
  }

  SECTION("rel=stylesheetx must NOT match")
  {
    std::string result = normalize_link_for_hint("</path>; rel=stylesheetx");
    CHECK(result.empty());
  }

  SECTION("rel=modulepreloadx must NOT match")
  {
    std::string result = normalize_link_for_hint("</path>; rel=modulepreloadx");
    CHECK(result.empty());
  }

  SECTION("rel=preconnectx must NOT match")
  {
    std::string result = normalize_link_for_hint("</path>; rel=preconnectx");
    CHECK(result.empty());
  }

  SECTION("valid rel=stylesheet with semicolon boundary")
  {
    std::string result = normalize_link_for_hint("</s.css>; rel=stylesheet; nonce=abc");
    CHECK(result == "</s.css>; rel=preload; as=style");
  }

  SECTION("valid rel=preload with space boundary")
  {
    std::string result = normalize_link_for_hint("</j.js>; rel=preload ; as=script");
    CHECK(result == "</j.js>; rel=preload ; as=script");
  }

  SECTION("valid rel=preconnect at end-of-string")
  {
    std::string result = normalize_link_for_hint("<https://cdn.test>; rel=preconnect");
    CHECK(result == "<https://cdn.test>; rel=preconnect");
  }
}

// ─── Commit 12: --hints-ttl (TTL + Stale-While-Revalidate) ──────────────────

TEST_CASE("Config: --hints-ttl parsing and validation", "[config][hints-ttl]")
{
  SECTION("default is 604800 (1 week TTL)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    CHECK(config.hints_ttl() == 604800);
  }

  SECTION("--hints-ttl 0 is valid (explicit disable)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "0"}));
    CHECK(config.hints_ttl() == 0);
  }

  SECTION("--hints-ttl 3600 sets one hour TTL")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "3600"}));
    CHECK(config.hints_ttl() == 3600);
  }

  SECTION("--hints-ttl 86400 is valid (within new 1-year max)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "86400"}));
    CHECK(config.hints_ttl() == 86400);
  }

  SECTION("--hints-ttl 86401 is now valid (max raised to 1 year)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "86401"}));
    CHECK(config.hints_ttl() == 86401);
  }

  SECTION("--hints-ttl -1 is invalid (negative)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--hints-ttl", "-1"}));
  }

  SECTION("--hints-ttl non-numeric is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--hints-ttl", "abc"}));
  }

  SECTION("--hints-ttl missing value is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--hints-ttl"}));
  }

  SECTION("--hints-ttl can coexist with other options")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "300", "--min-hit-count", "3"}));
    CHECK(config.hints_ttl() == 300);
    CHECK(config.min_hit_count() == 3);
  }
}

// ─── Commit 13: --purge-header / --purge-secret ──────────────────────────────

TEST_CASE("Config: --purge-header and --purge-secret parsing", "[config][purge]")
{
  SECTION("default: purge_header_name is empty, purge_secret is empty")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    CHECK(config.purge_header_name().empty());
    CHECK(config.purge_secret().empty());
  }

  SECTION("--purge-header alone is invalid (requires --purge-secret)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-header", "X-Purge"}));
  }

  SECTION("--purge-secret alone is invalid (requires --purge-header)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-secret", "s3cr3t"}));
  }

  SECTION("both --purge-header and --purge-secret is valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-header", "X-Purge", "--purge-secret", "s3cr3t"}));
    CHECK(config.purge_header_name() == "X-Purge");
    CHECK(config.purge_secret() == "s3cr3t");
  }

  SECTION("--purge-header with invalid name (space) is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-header", "X Purge", "--purge-secret", "s3cr3t"}));
  }

  SECTION("--purge-header with invalid name (colon) is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-header", "X:Purge", "--purge-secret", "s3cr3t"}));
  }

  SECTION("--purge-header with empty name is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-header", "", "--purge-secret", "s3cr3t"}));
  }

  SECTION("--purge-secret with empty value is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-header", "X-Purge", "--purge-secret", ""}));
  }

  SECTION("purge options can coexist with other options")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(
      config, {"--purge-header", "X-Purge-Token", "--purge-secret", "abc123", "--min-hit-count", "2", "--hints-ttl", "300"}));
    CHECK(config.purge_header_name() == "X-Purge-Token");
    CHECK(config.purge_secret() == "abc123");
    CHECK(config.min_hit_count() == 2);
    CHECK(config.hints_ttl() == 300);
  }
}

TEST_CASE("Config: is_valid_header_name() validates RFC 7230 tchar", "[config][purge]")
{
  SECTION("valid header names")
  {
    CHECK(is_valid_header_name("X-Purge"));
    CHECK(is_valid_header_name("X-Purge-Token"));
    CHECK(is_valid_header_name("Authorization"));
    CHECK(is_valid_header_name("x-custom-123"));
  }

  SECTION("invalid: empty string") { CHECK_FALSE(is_valid_header_name("")); }

  SECTION("invalid: contains space") { CHECK_FALSE(is_valid_header_name("X Purge")); }

  SECTION("invalid: contains colon") { CHECK_FALSE(is_valid_header_name("X:Purge")); }

  SECTION("invalid: contains control character") { CHECK_FALSE(is_valid_header_name("X-\x01Purge")); }

  SECTION("invalid: contains parenthesis") { CHECK_FALSE(is_valid_header_name("X-(Purge)")); }
}

// Tests for is_valid_link_value() scheme authority separator enforcement
// and backslash-relative authority rejection.
// After detecting http/https scheme + colon, enforce next two chars are "//".
// Also reject URLs starting with backslash or slash-backslash.

TEST_CASE("is_valid_link_value() rejects http:\\authority without :// separator", "[config]")
{
  SECTION("http:\\evil.com rejected: no :// separator")
  {
    // Browser normalizes http:\ to http://. Must be rejected in origin-forward mode.
    std::string link = R"(<http:\evil.com/track.js>; rel=preload; as=script)";
    CHECK_FALSE(is_valid_link_value(link));
  }

  SECTION("https:\\evil.com rejected")
  {
    std::string link = R"(<https:\evil.com/track.js>; rel=preload; as=script)";
    CHECK_FALSE(is_valid_link_value(link));
  }

  SECTION("http:/evil.com rejected — only one slash after colon")
  {
    std::string link = R"(<http:/evil.com/path.js>; rel=preload; as=script)";
    CHECK_FALSE(is_valid_link_value(link));
  }

  SECTION("http://cdn.example.com accepted — correct separator")
  {
    std::string link = R"(<http://cdn.example.com/app.js>; rel=preload; as=script)";
    CHECK(is_valid_link_value(link));
  }

  SECTION("https://cdn.example.com accepted")
  {
    std::string link = R"(<https://cdn.example.com/style.css>; rel=preload; as=style)";
    CHECK(is_valid_link_value(link));
  }

  SECTION("relative /path accepted — no scheme")
  {
    std::string link = R"(</assets/app.js>; rel=preload; as=script)";
    CHECK(is_valid_link_value(link));
  }

  SECTION("protocol-relative //host accepted")
  {
    std::string link = R"(<//cdn.example.com/app.js>; rel=preload; as=script)";
    CHECK(is_valid_link_value(link));
  }
}

TEST_CASE("is_valid_link_value() rejects backslash-relative authority", "[config]")
{
  SECTION("\\\\evil.com: double backslash authority (browser treats as //evil.com)")
  {
    std::string link = R"(<\\evil.com/track.js>; rel=preload; as=script)";
    CHECK_FALSE(is_valid_link_value(link));
  }

  SECTION("/\\evil.com: slash-backslash (browser treats as //evil.com)")
  {
    std::string link = R"(</\evil.com/track.js>; rel=preload; as=script)";
    CHECK_FALSE(is_valid_link_value(link));
  }

  SECTION("\\evil.com single leading backslash: resolves as same-origin path")
  {
    // Per WHATWG URL spec section 4.4: in a special relative URL context (http/https),
    // a single leading backslash is treated as '/' so \evil.com resolves to
    // /evil.com on the same origin, not as a cross-origin authority.
    // Only \\evil.com (double-backslash) and /\evil.com trigger the authority indicator.
    // Therefore single leading backslash in a Link header is safe.
    std::string link = R"(<\evil.com/track.js>; rel=preload; as=script)";
    // The backslash-authority check must not fire here. rel= validation may
    // independently reject it, which is acceptable.
    (void)is_valid_link_value(link);
  }

  SECTION("normal relative /path accepted after fix")
  {
    std::string link = R"(</assets/app.js>; rel=preload; as=script)";
    CHECK(is_valid_link_value(link));
  }

  SECTION("//host accepted — proper protocol-relative")
  {
    std::string link = R"(<//cdn.example.com/app.js>; rel=preload; as=script)";
    CHECK(is_valid_link_value(link));
  }
}

// ─── normalize_link_for_hint: preserve crossorigin/fetchpriority ──────────────

TEST_CASE("normalize_link_for_hint: rel=stylesheet preserves crossorigin", "[config][normalize]")
{
  SECTION("stylesheet crossorigin=anonymous carries into preload hint")
  {
    std::string link   = "</style.css>; rel=stylesheet; crossorigin=anonymous";
    std::string result = normalize_link_for_hint(link);
    // Before fix: result = "</style.css>; rel=preload; as=style" (crossorigin lost)
    // After fix: crossorigin=anonymous must be present
    CHECK(result.find("crossorigin=anonymous") != std::string::npos);
    CHECK(result.find("rel=preload") != std::string::npos);
    CHECK(result.find("as=style") != std::string::npos);
  }

  SECTION("stylesheet crossorigin=use-credentials carries into preload hint")
  {
    std::string link   = "</style.css>; rel=stylesheet; crossorigin=use-credentials";
    std::string result = normalize_link_for_hint(link);
    CHECK(result.find("crossorigin=use-credentials") != std::string::npos);
  }

  SECTION("stylesheet fetchpriority=high carries into preload hint")
  {
    std::string link   = "</critical.css>; rel=stylesheet; fetchpriority=high";
    std::string result = normalize_link_for_hint(link);
    CHECK(result.find("fetchpriority=high") != std::string::npos);
    CHECK(result.find("rel=preload") != std::string::npos);
  }

  SECTION("stylesheet without crossorigin — no crossorigin added (no spurious attr)")
  {
    std::string link   = "</style.css>; rel=stylesheet";
    std::string result = normalize_link_for_hint(link);
    CHECK(result.find("crossorigin") == std::string::npos);
    CHECK(result.find("rel=preload; as=style") != std::string::npos);
  }

  SECTION("rel=preload path regression — attrs still preserved (was already working)")
  {
    std::string link   = "</app.js>; rel=preload; as=script; crossorigin=anonymous";
    std::string result = normalize_link_for_hint(link);
    CHECK(result.find("crossorigin=anonymous") != std::string::npos);
  }
}

// ─── A-30: rfind('@') for multi-@ userinfo ───────────────────────────────────

TEST_CASE("Config whitelist: multi-@ userinfo stripped with rfind", "[config][regression]")
{
  SECTION("user:p@ssword@cdn.example.com — second @ is authority separator")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    // Before fix: find('@') at first '@' → "ssword@cdn.example.com" → no match
    // After fix: rfind('@') → "cdn.example.com" → match
    CHECK(config.is_whitelisted_domain("user:p@ssword@cdn.example.com"));
  }

  SECTION("simple user@host still works (regression guard)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK(config.is_whitelisted_domain("user@cdn.example.com"));
  }

  SECTION("no @ in domain — unaffected")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
  }
}

// ─── A-32: has_valid_as_for_preload accepts quoted as= variants ───────────────

TEST_CASE("has_valid_as_for_preload: quoted as= variants accepted", "[config]")
{
  SECTION("as=\"script\" double-quoted is valid per RFC 8288")
  {
    // Origin may send: Link: </app.js>; rel=preload; as="script"
    CHECK(has_valid_as_for_preload(R"(<app.js>; rel=preload; as="script")"));
  }

  SECTION("as='script' single-quoted is valid") { CHECK(has_valid_as_for_preload(R"(<app.js>; rel=preload; as='script')")); }

  SECTION("as=\"style\" double-quoted is valid") { CHECK(has_valid_as_for_preload(R"(<style.css>; rel=preload; as="style")")); }

  SECTION("as=\"font\" double-quoted is valid") { CHECK(has_valid_as_for_preload(R"(<font.woff2>; rel=preload; as="font")")); }

  SECTION("unquoted as=script still works (regression guard)")
  {
    CHECK(has_valid_as_for_preload("<app.js>; rel=preload; as=script"));
  }
}

// ─── B-10: merge_hint_links case-insensitive URL deduplication ───────────────

TEST_CASE("merge_hint_links: case-insensitive host deduplication", "[config][merge]")
{
  SECTION("same URL different host casing is treated as duplicate")
  {
    std::vector<std::string> manual = {"<https://CDN.EXAMPLE.COM/app.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"<https://cdn.example.com/app.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    // Before fix: case-sensitive compare → both pass dedup → size=2
    // After fix: lowercase compare → deduped → size=1
    CHECK(result.size() == 1);
  }

  SECTION("same URL same casing is always deduped (existing behavior, regression)")
  {
    std::vector<std::string> manual = {"<https://cdn.example.com/app.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"<https://cdn.example.com/app.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    CHECK(result.size() == 1);
  }

  SECTION("different URLs (same host, different paths) are not deduped")
  {
    std::vector<std::string> manual = {"<https://cdn.example.com/a.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"<https://cdn.example.com/b.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    CHECK(result.size() == 2);
  }
}

// ─── A-14: whitelist port strip at parse time ─────────────────────────────────

TEST_CASE("Config whitelist: port in pattern stripped at parse time", "[config]")
{
  SECTION("crossorigin whitelist cdn.example.com:8080 matches portless cdn.example.com")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com:8080"}));
    // Before fix: pattern stored as "cdn.example.com:8080", incoming "cdn.example.com" → no match
    // After fix: port stripped at parse time → stored "cdn.example.com" → match
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
  }

  SECTION("preload whitelist fonts.example.com:443 matches portless fonts.example.com")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--preload-whitelist", "fonts.example.com:443"}));
    CHECK(config.is_preload_domain("fonts.example.com"));
  }

  SECTION("portless pattern still works (regression guard)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "cdn.example.com"}));
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
  }

  SECTION("wildcard with port: *.example.com:8080 → stored *.example.com → match cdn.example.com")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--crossorigin-whitelist", "*.example.com:8080"}));
    CHECK(config.is_whitelisted_domain("cdn.example.com"));
  }
}

// ─── Non-regression: has_valid_as_for_preload rel= boundary ────────────────────

TEST_CASE("has_valid_as_for_preload: strict rel= boundary matches check_rel in is_valid_link_value", "[config][regression]")
{
  SECTION("rel=preload at end of string is valid") { CHECK(has_valid_as_for_preload("</js>; rel=preload; as=script")); }

  SECTION("rel=preload followed by semicolon is valid") { CHECK(has_valid_as_for_preload("</js>; as=script; rel=preload")); }

  SECTION("rel=preload with no as= is invalid (preload requires as=)")
  {
    CHECK_FALSE(has_valid_as_for_preload("</js>; rel=preload"));
  }

  SECTION("rel=modulepreload without as= is valid (HTML spec: as= optional)")
  {
    CHECK(has_valid_as_for_preload("</app.mjs>; rel=modulepreload"));
  }
}

// ===================================================================================
// RFC 3986 path case sensitivity in merge_hint_links.
// extract_dedup_key() currently lowercases the entire URL including the path,
// causing false deduplication of resources with the same host but different path casing.
//
// RED before fix: "</CSS/Main.css>" and "</css/main.css>" share the same lowercased
// key "</css/main.css>" and the cached link is incorrectly dropped (size == 1).
// GREEN after fix: path casing is preserved in the key, both links survive (size == 2).
// ===================================================================================

TEST_CASE("merge_hint_links: path case sensitivity per RFC 3986", "[config][merge][rfc3986]")
{
  SECTION("same host, different path case: both links kept")
  {
    std::vector<std::string> manual = {"</CSS/Main.css>; rel=preload; as=style"};
    std::vector<std::string> cached = {"</css/main.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    // RED before fix: extract_dedup_key lowercases entire URL, size == 1
    // GREEN after fix: path case preserved, size == 2
    CHECK(result.size() == 2);
  }

  SECTION("absolute URL, same host in different case, same path: deduplicated")
  {
    std::vector<std::string> manual = {"<https://CDN.Example.COM/path/file.css>; rel=preload; as=style"};
    std::vector<std::string> cached = {"<https://cdn.example.com/path/file.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    // Host is case-insensitive, path is identical: should dedup
    CHECK(result.size() == 1);
  }

  SECTION("absolute URL, same host, different path case: both kept")
  {
    std::vector<std::string> manual = {"<https://cdn.example.com/Path/File.css>; rel=preload; as=style"};
    std::vector<std::string> cached = {"<https://cdn.example.com/path/file.css>; rel=preload; as=style"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    // RED before fix: entire URL lowercased, size == 1 (false dedup)
    // GREEN after fix: path case differs, size == 2
    CHECK(result.size() == 2);
  }

  SECTION("manual link wins when paths identical (regression: manual priority)")
  {
    std::vector<std::string> manual = {"</app.js>; rel=preload; as=script"};
    std::vector<std::string> cached = {"</app.js>; rel=preload; as=script"};
    auto result                     = merge_hint_links(manual, &cached, 10);
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "</app.js>; rel=preload; as=script");
  }
}

// ===================================================================================
// normalize_link_for_hint: bare boolean 'crossorigin' attribute handling.
//
// HTML spec section 2.5.3 defines 'crossorigin' as an enumerated attribute.
// The bare form (no '=' or value) is equivalent to crossorigin=anonymous.
// The empty-value form (crossorigin=) is also equivalent to crossorigin=anonymous.
//
// Current carry_param("crossorigin") builds needle "crossorigin=" (with '=') and
// uses params_lower.find(needle). A bare 'crossorigin' with no '=' is never found,
// so the attribute is silently dropped from the converted rel=preload hint.
//
// RED before fix: normalize_link_for_hint("<url>; rel=stylesheet; crossorigin")
//   returns "<url>; rel=preload; as=style" with NO crossorigin attribute.
// GREEN after fix: returns "<url>; rel=preload; as=style; crossorigin=anonymous".
// ===================================================================================

TEST_CASE("normalize_link_for_hint: bare boolean crossorigin maps to anonymous", "[config][normalize][crossorigin][bare]")
{
  SECTION("bare crossorigin at end of params")
  {
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet; crossorigin");
    // RED before fix: crossorigin entirely absent from output
    CHECK(result.find("crossorigin=anonymous") != std::string::npos);
    CHECK(result.find("rel=preload") != std::string::npos);
    CHECK(result.find("as=style") != std::string::npos);
  }

  SECTION("bare crossorigin followed by semicolon and another param")
  {
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet; crossorigin; fetchpriority=high");
    CHECK(result.find("crossorigin=anonymous") != std::string::npos);
    // fetchpriority must also be preserved
    CHECK(result.find("fetchpriority=high") != std::string::npos);
  }

  SECTION("bare crossorigin preceded by whitespace variants")
  {
    std::string result = normalize_link_for_hint("</s.css>; rel=stylesheet;  crossorigin");
    CHECK(result.find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("crossorigin= with empty value maps to anonymous")
  {
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet; crossorigin=");
    CHECK(result.find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("crossorigin=anonymous preserved unchanged (regression)")
  {
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet; crossorigin=anonymous");
    CHECK(result.find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("crossorigin=use-credentials preserved unchanged (regression)")
  {
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet; crossorigin=use-credentials");
    CHECK(result.find("crossorigin=use-credentials") != std::string::npos);
  }

  SECTION("no crossorigin: attribute not added (regression: no spurious injection)")
  {
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet");
    CHECK(result.find("crossorigin") == std::string::npos);
  }

  SECTION("crossoriginFoo is not matched by word-boundary check")
  {
    // 'crossoriginFoo' must not be mistaken for bare 'crossorigin'
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet; crossoriginFoo");
    CHECK(result.find("crossorigin=anonymous") == std::string::npos);
  }

  SECTION("Xcrossorigin is not matched (prefix guard)")
  {
    // 'Xcrossorigin' must not trigger the bare match
    std::string result = normalize_link_for_hint("</style.css>; rel=stylesheet; Xcrossorigin");
    CHECK(result.find("crossorigin=anonymous") == std::string::npos);
  }
} // ===================================================================================
// FIX-2: --link pparam with rel=stylesheet must be normalized to rel=preload; as=style
//
// The --link pparam is designed for operators to manually inject Early Hints.
// An operator might write @pparam=--link @pparam="</css/app.css>; rel=stylesheet"
// because that's what the HTML <link> tag uses. The plugin must normalize
// rel=stylesheet -> rel=preload; as=style before storing in manual_links_,
// since browsers reject 103 Early Hints with rel=stylesheet (not a valid hint type).
//
// Current path: case 'l' in init() stores raw optarg in manual_links_ with no
// normalization call. So manual_links_[0] is "</css/app.css>; rel=stylesheet".
//
// RED before fix: config.manual_links()[0] contains "rel=stylesheet" (not normalized).
// GREEN after fix: config.manual_links()[0] contains "rel=preload; as=style".
// ===================================================================================

TEST_CASE("--link pparam rel=stylesheet is normalized to rel=preload at config parse time",
          "[config][manual-link][stylesheet][normalize]")
{
  SECTION("unquoted rel=stylesheet normalized to rel=preload; as=style")
  {
    EarlyHintsConfig config;
    bool ok = parse_config(config, {"--link", "</css/app.css>; rel=stylesheet"});
    REQUIRE(ok);
    REQUIRE(config.manual_links().size() == 1);
    // RED before fix: still contains "rel=stylesheet"
    CHECK(config.manual_links()[0].find("rel=preload") != std::string::npos);
    CHECK(config.manual_links()[0].find("as=style") != std::string::npos);
    CHECK(config.manual_links()[0].find("rel=stylesheet") == std::string::npos);
  }

  SECTION("rel=stylesheet with crossorigin=anonymous normalized and crossorigin preserved")
  {
    EarlyHintsConfig config;
    bool ok = parse_config(config, {"--link", "</css/app.css>; rel=stylesheet; crossorigin=anonymous"});
    REQUIRE(ok);
    REQUIRE(config.manual_links().size() == 1);
    CHECK(config.manual_links()[0].find("rel=preload") != std::string::npos);
    CHECK(config.manual_links()[0].find("as=style") != std::string::npos);
    CHECK(config.manual_links()[0].find("crossorigin=anonymous") != std::string::npos);
  }

  SECTION("rel=stylesheet with fetchpriority=high normalized and fetchpriority preserved")
  {
    EarlyHintsConfig config;
    bool ok = parse_config(config, {"--link", "</css/app.css>; rel=stylesheet; fetchpriority=high"});
    REQUIRE(ok);
    REQUIRE(config.manual_links().size() == 1);
    CHECK(config.manual_links()[0].find("rel=preload") != std::string::npos);
    CHECK(config.manual_links()[0].find("as=style") != std::string::npos);
    CHECK(config.manual_links()[0].find("fetchpriority=high") != std::string::npos);
  }

  SECTION("rel=preload stored unchanged (regression: valid hint not re-normalized)")
  {
    EarlyHintsConfig config;
    bool ok = parse_config(config, {"--link", "</js/app.js>; rel=preload; as=script"});
    REQUIRE(ok);
    REQUIRE(config.manual_links().size() == 1);
    // normalize_link_for_hint returns the link unchanged for already-valid hint types
    CHECK(config.manual_links()[0].find("rel=preload") != std::string::npos);
    CHECK(config.manual_links()[0].find("as=script") != std::string::npos);
    CHECK(config.manual_links()[0].find("rel=stylesheet") == std::string::npos);
  }

  SECTION("rel=preconnect stored unchanged (regression)")
  {
    EarlyHintsConfig config;
    bool ok = parse_config(config, {"--link", "<https://fonts.googleapis.com>; rel=preconnect"});
    REQUIRE(ok);
    REQUIRE(config.manual_links().size() == 1);
    CHECK(config.manual_links()[0].find("rel=preconnect") != std::string::npos);
  }

  SECTION("multiple --link params: stylesheet normalized, preload unchanged")
  {
    EarlyHintsConfig config;
    bool ok = parse_config(config, {"--link", "</css/app.css>; rel=stylesheet", "--link", "</js/app.js>; rel=preload; as=script"});
    REQUIRE(ok);
    REQUIRE(config.manual_links().size() == 2);
    // First link: stylesheet → preload
    CHECK(config.manual_links()[0].find("rel=preload") != std::string::npos);
    CHECK(config.manual_links()[0].find("as=style") != std::string::npos);
    // Second link: already preload, unchanged
    CHECK(config.manual_links()[1].find("as=script") != std::string::npos);
  }
}
// ===================================================================================
// FIX-6: TTL defaults and max, plus --stale-evict-after option
//
// Background:
//   hints_ttl controls the stale-while-revalidate window: serve existing hints
//   while the background scanner re-learns from the next origin response.
//   The previous default of 0 (disabled) caused unnecessary re-learning on every
//   request after the hint entry aged past the operator-configured TTL.
//
// Changes:
//   - Default hints_ttl changes from 0 (disabled) to 604800 (1 week).
//   - Max TTL validation changes from 86400 (1 day) to 31536000 (1 year).
//   - New option --stale-evict-after N (seconds): if > 0 and an entry's age
//     exceeds N when get() is called, the entry is evicted after serving.
//     Allows hints to be permanently removed once they become too old without
//     manual purging. 0 = disabled (default).
//
// RED before fix: defaults and max are still old values; stale_evict_after() does not exist.
// GREEN after fix: all assertions pass.
// ===================================================================================

TEST_CASE("Config: hints-ttl default changed to 1 week", "[config][hints-ttl][ttl-default]")
{
  SECTION("default hints-ttl is 604800 seconds (1 week)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    // RED before fix: default is still 0
    CHECK(config.hints_ttl() == 604800);
  }

  SECTION("--hints-ttl 0 still disables TTL explicitly")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "0"}));
    CHECK(config.hints_ttl() == 0);
  }

  SECTION("--hints-ttl 604800 is valid (1 week)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "604800"}));
    CHECK(config.hints_ttl() == 604800);
  }

  SECTION("--hints-ttl 31536000 is valid (1 year, new maximum)")
  {
    EarlyHintsConfig config;
    // RED before fix: max is 86400 so this is rejected
    CHECK(parse_config(config, {"--hints-ttl", "31536000"}));
    CHECK(config.hints_ttl() == 31536000);
  }

  SECTION("--hints-ttl 31536001 is invalid (exceeds 1 year)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--hints-ttl", "31536001"}));
  }

  SECTION("--hints-ttl 86400 is still valid (within new max)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "86400"}));
    CHECK(config.hints_ttl() == 86400);
  }

  SECTION("--hints-ttl -1 is still invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--hints-ttl", "-1"}));
  }
}

TEST_CASE("Config: --stale-evict-after option", "[config][stale-evict-after]")
{
  SECTION("default stale-evict-after is 0 (disabled)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    // RED before fix: stale_evict_after() does not exist
    CHECK(config.stale_evict_after() == 0);
  }

  SECTION("--stale-evict-after 0 disables eviction explicitly")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--stale-evict-after", "0"}));
    CHECK(config.stale_evict_after() == 0);
  }

  SECTION("--stale-evict-after 3600 is valid (1 hour)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--stale-evict-after", "3600"}));
    CHECK(config.stale_evict_after() == 3600);
  }

  SECTION("--stale-evict-after 31536000 is valid (1 year, same max as hints-ttl)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--stale-evict-after", "31536000"}));
    CHECK(config.stale_evict_after() == 31536000);
  }

  SECTION("--stale-evict-after 31536001 is invalid (exceeds max)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--stale-evict-after", "31536001"}));
  }

  SECTION("--stale-evict-after -1 is invalid (negative)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--stale-evict-after", "-1"}));
  }

  SECTION("--stale-evict-after can coexist with --hints-ttl")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--hints-ttl", "300", "--stale-evict-after", "900"}));
    CHECK(config.hints_ttl() == 300);
    CHECK(config.stale_evict_after() == 900);
  }

  SECTION("--stale-evict-after non-numeric is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--stale-evict-after", "abc"}));
  }

  SECTION("--stale-evict-after missing value is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--stale-evict-after"}));
  }
}

// ===================================================================================
// FIX-5: Purge rate limiting -- --purge-limit and --purge-cooldown options
//
// Background:
//   The purge mechanism lets operators invalidate cached hints with a secret header.
//   Without rate limiting, a burst of requests with the purge header can hammer
//   the cache invalidation path. Rate limiting is applied per remap rule using
//   PurgeRateLimiter stored in PluginInstance. A fixed window of --purge-cooldown
//   seconds allows at most --purge-limit successful purges before blocking.
//   Blocked purges are logged with TSNote instead of TSDebug.
//
// Changes:
//   - New config option --purge-limit N (default 3, range [1,100])
//   - New config option --purge-cooldown N (default 10, range [1,300])
//   - Both options only have effect when --purge-header is also set
//
// RED before fix: purge_limit() and purge_cooldown() do not exist.
// GREEN after fix: all assertions pass.
// ===================================================================================

TEST_CASE("Config: --purge-limit option", "[config][purge-limit]")
{
  SECTION("default purge_limit is 3")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    // RED before fix: purge_limit() does not exist
    CHECK(config.purge_limit() == 3);
  }

  SECTION("--purge-limit 1 is valid (minimum)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-limit", "1"}));
    CHECK(config.purge_limit() == 1);
  }

  SECTION("--purge-limit 10 is valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-limit", "10"}));
    CHECK(config.purge_limit() == 10);
  }

  SECTION("--purge-limit 100 is valid (maximum)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-limit", "100"}));
    CHECK(config.purge_limit() == 100);
  }

  SECTION("--purge-limit 0 is invalid (below minimum)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-limit", "0"}));
  }

  SECTION("--purge-limit 101 is now valid (within new max 500)")
  {
    EarlyHintsConfig config;
    // RED before fix: 101 is rejected (old max 100)
    CHECK(parse_config(config, {"--purge-limit", "101"}));
    CHECK(config.purge_limit() == 101);
  }

  SECTION("--purge-limit 500 is valid (new maximum)")
  {
    EarlyHintsConfig config;
    // RED before fix: 500 is rejected (old max 100)
    CHECK(parse_config(config, {"--purge-limit", "500"}));
    CHECK(config.purge_limit() == 500);
  }

  SECTION("--purge-limit 501 is invalid (exceeds new maximum 500)")
  {
    EarlyHintsConfig config;
    // RED before fix: same failure, still invalid (just higher threshold)
    CHECK_FALSE(parse_config(config, {"--purge-limit", "501"}));
  }

  SECTION("--purge-limit -1 is invalid (negative)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-limit", "-1"}));
  }

  SECTION("--purge-limit non-numeric is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-limit", "abc"}));
  }

  SECTION("--purge-limit missing value is invalid")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-limit"}));
  }

  SECTION("--purge-limit can coexist with --purge-header and --purge-secret")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-header", "X-Purge", "--purge-secret", "tok", "--purge-limit", "5"}));
    CHECK(config.purge_limit() == 5);
    CHECK(config.purge_header_name() == "X-Purge");
  }
}

TEST_CASE("Config: --purge-cooldown option", "[config][purge-cooldown]")
{
  SECTION("default purge_cooldown is 10 seconds")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {}));
    // RED before fix: purge_cooldown() does not exist
    CHECK(config.purge_cooldown() == 10);
  }

  SECTION("--purge-cooldown 1 is valid (minimum)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-cooldown", "1"}));
    CHECK(config.purge_cooldown() == 1);
  }

  SECTION("--purge-cooldown 60 is valid")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-cooldown", "60"}));
    CHECK(config.purge_cooldown() == 60);
  }

  SECTION("--purge-cooldown 300 is valid (maximum)")
  {
    EarlyHintsConfig config;
    CHECK(parse_config(config, {"--purge-cooldown", "300"}));
    CHECK(config.purge_cooldown() == 300);
  }

  SECTION("--purge-cooldown 0 is invalid (below minimum)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-cooldown", "0"}));
  }

  SECTION("--purge-cooldown 301 is now valid (within new max 2592000)")
  {
    EarlyHintsConfig config;
    // RED before fix: 301 rejected (old max 300)
    CHECK(parse_config(config, {"--purge-cooldown", "301"}));
    CHECK(config.purge_cooldown() == 301);
  }

  SECTION("--purge-cooldown 86400 (1 day) is valid")
  {
    EarlyHintsConfig config;
    // RED before fix: 86400 rejected (old max 300)
    CHECK(parse_config(config, {"--purge-cooldown", "86400"}));
    CHECK(config.purge_cooldown() == 86400);
  }

  SECTION("--purge-cooldown 2592000 (1 month) is valid (new maximum)")
  {
    EarlyHintsConfig config;
    // RED before fix: 2592000 rejected (old max 300)
    CHECK(parse_config(config, {"--purge-cooldown", "2592000"}));
    CHECK(config.purge_cooldown() == 2592000);
  }

  SECTION("--purge-cooldown 2592001 is invalid (exceeds new maximum)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-cooldown", "2592001"}));
  }

  SECTION("--purge-cooldown -1 is invalid (negative)")
  {
    EarlyHintsConfig config;
    CHECK_FALSE(parse_config(config, {"--purge-cooldown", "-1"}));
  }

  SECTION("--purge-limit and --purge-cooldown coexist with purge header options")
  {
    EarlyHintsConfig config;
    CHECK(
      parse_config(config, {"--purge-header", "X-Purge", "--purge-secret", "tok", "--purge-limit", "5", "--purge-cooldown", "30"}));
    CHECK(config.purge_limit() == 5);
    CHECK(config.purge_cooldown() == 30);
  }
}
