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
  std::vector<std::string> segments1 = {"</app.js>; rel=preconnect", "</app.js>; xrel=preconnect"};
  auto result1                       = dedup_link_segments(segments1, 10);
  CHECK(result1.size() == 2);

  std::vector<std::string> segments2 = {"</app.js>; rel=preconnect", "</app.js>; rel=preconnectx"};
  auto result2                       = dedup_link_segments(segments2, 10);
  CHECK(result2.size() == 2);

  std::vector<std::string> segments3 = {"</app.js>; rel=preconnect", "</app.js>; rel=\"preconnect\"garbage"};
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
