#include "link_parser.h"

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
      bool is_preconnect       = seg.find("rel=preconnect") != std::string::npos;
      for (const auto &existing : result) {
        if (existing.size() > url_key.size() && existing.compare(0, url_key.size(), url_key.data(), url_key.size()) == 0) {
          // FIX (WP3): compare existing entry's rel type against incoming seg's rel type.
          // Before fix: (seg.find("rel=preconnect") != npos) == is_preconnect was
          // always true (tautological) — dropping different-rel-type entries for the
          // same URL. Fix uses existing.find() to compare the cached entry's rel type.
          if ((existing.find("rel=preconnect") != std::string::npos) == is_preconnect) {
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
