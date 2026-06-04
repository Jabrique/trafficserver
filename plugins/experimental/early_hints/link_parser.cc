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
  if (header_value.size() > static_cast<size_t>(MAX_LINK_FIELD_LEN)) {
    return result;
  }

  const std::string &full_val = header_value;
  size_t pos                  = 0;
  int angle_depth             = 0;
  bool in_quotes              = false;
  size_t start                = 0;
  int consecutive_backslashes = 0; // forward-tracked; reset on any non-backslash char

  while (pos <= full_val.size()) {
    if (pos < full_val.size()) {
      char ch = full_val[pos];
      if (!in_quotes && ch == '<') {
        angle_depth++;
        consecutive_backslashes = 0;
      } else if (!in_quotes && ch == '>' && angle_depth > 0) {
        angle_depth--;
        consecutive_backslashes = 0;
      } else if (angle_depth == 0 && ch == '"') {
        // Odd consecutive backslashes immediately before this quote = escaped quote.
        // Even (incl. 0) = real delimiter.  consecutive_backslashes was tracked
        // forward as we scanned, so this check is O(1).
        if (in_quotes && (consecutive_backslashes % 2) != 0) {
          // Escaped quote — do not toggle
        } else {
          in_quotes = !in_quotes;
        }
        consecutive_backslashes = 0;
      } else if (!in_quotes && angle_depth > 0 && ch == ';') {
        // RFC 8288 section 3: ';' separates link-params and only appears AFTER the closing '>'
        // of the URI-Reference. A ';' with angle_depth > 0 means the origin omitted the
        // closing '>' -- the URL angle bracket was never closed. Reset angle_depth so that
        // subsequent commas are correctly recognized as segment boundaries rather than being
        // swallowed inside an unbounded angle-bracket context.
        angle_depth             = 0;
        consecutive_backslashes = 0;
      } else if (ch == '\\') {
        consecutive_backslashes++;
      } else {
        consecutive_backslashes = 0;
      }
    }
    if (pos == full_val.size() || (full_val[pos] == ',' && angle_depth == 0 && !in_quotes)) {
      size_t end = pos;
      while (start < end && (full_val[start] == ' ' || full_val[start] == '\t' || full_val[start] == '\r')) {
        start++;
      }
      while (end > start && (full_val[end - 1] == ' ' || full_val[end - 1] == '\t' || full_val[end - 1] == '\r')) {
        end--;
      }
      if (end > start) {
        result.push_back(full_val.substr(start, end - start));
        if (static_cast<int>(result.size()) >= max_links) {
          break;
        }
      }
      start                   = pos + 1;
      consecutive_backslashes = 0;
      angle_depth             = 0;
      in_quotes               = false;
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
      bool before_ok = (pos == 0) || seg_lower[pos - 1] == ';' || seg_lower[pos - 1] == ' ' || seg_lower[pos - 1] == '\t' ||
                       seg_lower[pos - 1] == '\r';
      size_t after  = pos + needle.size();
      bool after_ok = (after >= seg_lower.size()) || seg_lower[after] == ';' || seg_lower[after] == ' ' ||
                      seg_lower[after] == '\t' || seg_lower[after] == '\r';
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
    if (url_end == std::string::npos) {
      result.push_back(std::move(seg));
      if (static_cast<int>(result.size()) >= max_links) {
        break;
      }
      continue;
    }

    // Case-insensitive URL key for DNS hostname comparison (RFC 4343).
    std::string seg_lower = seg;
    std::transform(seg_lower.begin(), seg_lower.end(), seg_lower.begin(), [](unsigned char c) { return std::tolower(c); });
    std::string_view url_key = std::string_view(seg_lower).substr(0, url_end + 1);

    // Determine strength: preload/modulepreload are strong, preconnect is weak.
    bool incoming_is_preload = !has_rel_type(seg_lower, "preconnect");

    bool is_dup    = false;
    size_t dup_idx = 0;
    for (size_t i = 0; i < result.size(); ++i) {
      std::string existing_lower = result[i];
      std::transform(existing_lower.begin(), existing_lower.end(), existing_lower.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      size_t ex_url_end = existing_lower.find('>');
      if (ex_url_end != std::string::npos) {
        std::string_view ex_url_key = std::string_view(existing_lower).substr(0, ex_url_end + 1);
        if (ex_url_key == url_key) {
          is_dup  = true;
          dup_idx = i;
          break;
        }
      }
    }

    if (!is_dup) {
      result.push_back(std::move(seg));
    } else if (incoming_is_preload && has_rel_type(result[dup_idx], "preconnect")) {
      // Incoming is stronger (preload/modulepreload) than existing (preconnect): replace.
      result[dup_idx] = std::move(seg);
    }
    // else: existing is same strength or stronger, skip incoming.

    if (static_cast<int>(result.size()) >= max_links) {
      break;
    }
  }
  return result;
}
