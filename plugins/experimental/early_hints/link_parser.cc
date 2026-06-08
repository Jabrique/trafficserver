#include "link_parser.h"
#include <algorithm>
#include <cctype>
#include <unordered_map>

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

std::string
lowercase_url_host(const std::string &url_key)
{
  // Find the start of the authority (host). The url_key is the <URL> portion
  // of a Link segment, for example "<https://CDN.Example.COM/Path>".
  // Only the scheme and host are case-insensitive per RFC 3986 section 6.2.2.1
  // and RFC 4343. The path (everything after the first '/' following the host)
  // is case-sensitive and must be preserved as-is.
  std::string result = url_key;

  size_t scheme_end = result.find("://");
  size_t host_start;
  if (scheme_end != std::string::npos) {
    // Absolute URL: lowercase from '<' through the host (up to the first
    // path character '/', query '?', fragment '#', or closing '>').
    host_start = scheme_end + 3; // skip past '://'
  } else if (result.size() >= 3 && result[0] == '<' && result[1] == '/' && result[2] == '/') {
    // Protocol-relative URL "<//host/path>": lowercase just the host portion.
    host_start = 3; // skip '<' and '//'
  } else {
    // Relative URL (e.g., "</path/File.js>"): no host present, no lowercasing.
    return result;
  }

  // Lowercase from the beginning up to (but not including) the end of the host.
  // The host ends at the first '/', '?', '#', or '>' after host_start.
  size_t host_end = result.find_first_of("/?#>", host_start);
  if (host_end == std::string::npos) {
    host_end = result.size();
  }

  // Lowercase scheme and host together (safe: scheme chars are ASCII alpha).
  for (size_t i = 0; i < host_end; ++i) {
    result[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(result[i])));
  }

  return result;
}

std::vector<std::string>
dedup_link_segments(std::vector<std::string> segments, int max_links)
{
  std::vector<std::string> result;
  result.reserve(segments.size());

  // O(1) per-entry dedup: url_key -> index in result vector.
  // Allows instant lookup and in-place strongest-wins replacement.
  std::unordered_map<std::string, size_t> url_index;
  url_index.reserve(segments.size());

  for (auto &seg : segments) {
    size_t url_end = seg.find('>');
    if (url_end == std::string::npos) {
      result.push_back(std::move(seg));
      if (static_cast<int>(result.size()) >= max_links) {
        break;
      }
      continue;
    }

    // Build a URL key that lowercases only the scheme and host portion.
    // Path is case-sensitive per RFC 3986 section 6.2.2.1, so it is preserved.
    std::string url_key = lowercase_url_host(seg.substr(0, url_end + 1));

    // For has_rel_type() we need a lowercased copy of the params portion only
    // (the rel= attribute appears after the '>' closing the URL).
    std::string params_lower = seg.substr(url_end + 1);
    std::transform(params_lower.begin(), params_lower.end(), params_lower.begin(), [](unsigned char c) { return std::tolower(c); });
    // Determine strength: preload/modulepreload are strong, preconnect is weak.
    bool incoming_is_preload = !has_rel_type(params_lower, "preconnect");

    auto it = url_index.find(url_key);
    if (it == url_index.end()) {
      // New URL: add to result and record its index.
      url_index.emplace(std::move(url_key), result.size());
      result.push_back(std::move(seg));
    } else if (incoming_is_preload) {
      // Check if existing entry is a weaker preconnect. If so, replace with
      // the stronger incoming link (preload/modulepreload beats preconnect).
      size_t existing_idx   = it->second;
      std::string ex_params = result[existing_idx].substr(result[existing_idx].find('>') + 1);
      std::transform(ex_params.begin(), ex_params.end(), ex_params.begin(), [](unsigned char c) { return std::tolower(c); });
      if (has_rel_type(ex_params, "preconnect")) {
        result[existing_idx] = std::move(seg);
      }
    }
    // else: existing is same strength or stronger (preload beats preconnect),
    // or incoming is weak (preconnect), so skip.

    if (static_cast<int>(result.size()) >= max_links) {
      break;
    }
  }
  return result;
}
