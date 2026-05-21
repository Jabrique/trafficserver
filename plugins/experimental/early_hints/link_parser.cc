#include "link_parser.h"
#include <algorithm>
#include <cctype>

std::vector<std::string>
split_link_header_value(const std::string &header_value, int max_links)
{
  std::vector<std::string> result;

  if (header_value.empty() || max_links <= 0) {
    return result;
  }

  // Defense against oversized Link headers from malicious origins.
  if (static_cast<int>(header_value.size()) > MAX_LINK_FIELD_LEN) {
    return result;
  }

  const std::string &full_val = header_value;
  size_t pos                  = 0;
  int angle_depth             = 0;
  bool in_quotes              = false;
  size_t start                = 0;

  while (pos <= full_val.size()) {
    if (pos < full_val.size()) {
      char ch = full_val[pos];
      if (!in_quotes && ch == '<') {
        angle_depth++;
      } else if (!in_quotes && ch == '>' && angle_depth > 0) {
        angle_depth--;
      } else if (angle_depth == 0 && ch == '"') {
        // Count consecutive backslashes before this quote.
        // Odd count = quote is escaped; even count = quote is real delimiter.
        int backslash_count = 0;
        for (size_t bp = pos; bp > 0 && full_val[bp - 1] == '\\'; bp--) {
          backslash_count++;
        }
        if (in_quotes && (backslash_count % 2) != 0) {
          // Odd backslashes: quote is escaped — do not toggle
        } else {
          in_quotes = !in_quotes;
        }
      }
    }
    if (pos == full_val.size() || (full_val[pos] == ',' && angle_depth == 0 && !in_quotes)) {
      size_t end = pos;
      while (start < end && (full_val[start] == ' ' || full_val[start] == '\t')) {
        start++;
      }
      while (end > start && (full_val[end - 1] == ' ' || full_val[end - 1] == '\t')) {
        end--;
      }
      if (end > start) {
        result.push_back(full_val.substr(start, end - start));
        if (static_cast<int>(result.size()) >= max_links) {
          break;
        }
      }
      start = pos + 1;
    }
    pos++;
  }

  return result;
}

static bool
has_rel_type(const std::string &seg_lower, const std::string &rel_type)
{
  std::string needle1 = "rel=" + rel_type;
  std::string needle2 = "rel=\"" + rel_type + "\"";
  std::string needle3 = "rel='" + rel_type + "'";

  auto match_needle = [&](const std::string &needle) -> bool {
    size_t pos = 0;
    while ((pos = seg_lower.find(needle, pos)) != std::string::npos) {
      bool before_ok = (pos == 0) || seg_lower[pos - 1] == ';' || seg_lower[pos - 1] == ' ' || seg_lower[pos - 1] == '\t';
      size_t after   = pos + needle.size();
      bool after_ok = (after >= seg_lower.size()) || seg_lower[after] == ';' || seg_lower[after] == ' ' || seg_lower[after] == '\t';
      if (before_ok && after_ok) {
        return true;
      }
      pos += needle.size();
    }
    return false;
  };

  return match_needle(needle1) || match_needle(needle2) || match_needle(needle3);
}

std::vector<std::string>
dedup_link_segments(std::vector<std::string> segments, int max_links)
{
  std::vector<std::string> result;
  result.reserve(segments.size());

  for (auto &seg : segments) {
    size_t url_end = seg.find('>');
    bool is_dup    = false;
    if (url_end != std::string::npos) {
      std::string_view url_key = std::string_view(seg).substr(0, url_end + 1);

      // Case-insensitive check by lowercasing the search string
      std::string seg_lower = seg;
      std::transform(seg_lower.begin(), seg_lower.end(), seg_lower.begin(), [](unsigned char c) { return std::tolower(c); });
      bool is_preconnect = has_rel_type(seg_lower, "preconnect");

      for (const auto &existing : result) {
        if (existing.size() >= url_key.size() && existing.compare(0, url_key.size(), url_key.data(), url_key.size()) == 0) {
          // Compare the existing entry's rel type against the incoming segment's rel type case-insensitively
          std::string existing_lower = existing;
          std::transform(existing_lower.begin(), existing_lower.end(), existing_lower.begin(),
                         [](unsigned char c) { return std::tolower(c); });
          bool existing_preconnect = has_rel_type(existing_lower, "preconnect");
          if (existing_preconnect == is_preconnect) {
            is_dup = true;
            break;
          }
        }
      }
    }
    if (!is_dup) {
      result.push_back(std::move(seg));
    }
    if (static_cast<int>(result.size()) >= max_links) {
      break;
    }
  }
  return result;
}
