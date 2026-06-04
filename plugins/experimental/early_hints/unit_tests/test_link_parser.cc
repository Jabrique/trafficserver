#include <catch.hpp>
#include "../link_parser.h"
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
// R9 Phase 4: RED tests for confirmed bugs
// ============================================================================

TEST_CASE("R9-01: double-backslash before quote should close quoted string", "[link_parser][r9][bug]")
{
  // "foo\\" is an escaped backslash followed by a real closing quote.
  // Two backslashes = one escaped backslash, so the quote IS a real delimiter.
  // The comma after should split into two segments.
  std::string input = R"(</a.css>; title="foo\\", </b.js>; rel=preload)";
  auto result       = split_link_header_value(input, 10);

  // BUG: code sees single backslash before quote and thinks quote is escaped,
  // so comma is treated as inside the quoted string → only 1 segment.
  // CORRECT: even number of backslashes means quote is NOT escaped → 2 segments.
  REQUIRE(result.size() == 2);
  CHECK(result[0] == R"(</a.css>; title="foo\\")");
  CHECK(result[1] == "</b.js>; rel=preload");
}

TEST_CASE("R9-01b: triple-backslash before quote keeps quote escaped", "[link_parser][r9][bug]")
{
  // "foo\\\" has THREE backslashes: escaped-backslash + escaped-quote.
  // Odd number of backslashes means quote IS escaped → stays in quotes.
  std::string input = R"(</a.css>; title="foo\\\", </b.js>"; rel=preload)";
  auto result       = split_link_header_value(input, 10);

  // Odd backslashes → quote is escaped → entire remainder is one segment.
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

// ─── Non-regression: O(n) backslash counting must not change output ───────────

TEST_CASE("LinkParser: many consecutive backslashes before closing quote", "[link_parser][rfc8288]")
{
  SECTION("even backslash count: quote is real delimiter — two segments")
  {
    // 4 backslashes = 2 escaped backslashes → quote is real → split into 2 links
    std::string input = R"(<a.css>; title="foo\\\\", </b.js>; rel=preload; as=script)";
    auto result       = split_link_header_value(input, 10);
    REQUIRE(result.size() == 2);
    CHECK(result[1].find("b.js") != std::string::npos);
  }

  SECTION("odd backslash count: quote is escaped — one segment (no split)")
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

// ===========================================================================================
// The MAX_LINK_FIELD_LEN guard compared via static_cast<int>(size()) which is
// implementation-defined for values exceeding INT_MAX. The comparison is now
// performed entirely in the unsigned domain to guarantee defined behavior.
// ===========================================================================================

TEST_CASE("LinkParser: header size guard uses unsigned comparison at boundary", "[link_parser][size-guard]")
{
  SECTION("header exactly at limit is accepted")
  {
    // Build a valid-looking header padded to exactly MAX_LINK_FIELD_LEN (8192) bytes.
    // The URL is valid; trailing spaces are harmless whitespace.
    std::string input = "</a.css>; rel=preload; as=style";
    input.resize(8192, ' ');
    auto result = split_link_header_value(input, 10);
    // One segment (the link, padded with spaces that are trimmed)
    REQUIRE(result.size() == 1);
    CHECK(result[0].find("/a.css") != std::string::npos);
  }

  SECTION("header one byte over limit is rejected")
  {
    std::string input = "</a.css>; rel=preload; as=style";
    input.resize(8193, ' ');
    auto result = split_link_header_value(input, 10);
    CHECK(result.empty());
  }
}

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
