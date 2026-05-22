/** @file
 * Configuration parsing for the early_hints plugin.
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

#include "config.h"
#include <ts/ts.h>
#include <getopt.h>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <climits>
#include <algorithm>
#include <unordered_set>

// Validate header name according to RFC 7230 token (tchar) standard
static bool
is_valid_header_name(const std::string &name)
{
  if (name.empty()) {
    return false;
  }
  for (char c : name) {
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' ||
          c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' ||
          c == '|' || c == '~')) {
      return false;
    }
  }
  return true;
}

// Safe integer parsing — returns false on overflow, trailing garbage, or empty input
static bool
safe_parse_int(const char *str, int *out)
{
  if (str == nullptr || *str == '\0') {
    return false;
  }
  char *endptr = nullptr;
  errno        = 0;
  long val     = strtol(str, &endptr, 10);
  if (errno != 0 || endptr == str || *endptr != '\0') {
    return false;
  }
  if (val < INT_MIN || val > INT_MAX) {
    return false;
  }
  *out = static_cast<int>(val);
  return true;
}

bool
is_valid_link_value(const std::string &link)
{
  if (link.empty() || link[0] != '<') {
    return false;
  }
  size_t url_end = link.find('>');
  if (url_end == std::string::npos || url_end <= 1) {
    return false; // No '>' found, or empty URL between '<>'
  }

  // Reject control characters (NUL, CRLF, tab, etc.) and DEL anywhere in the link value.
  // Control chars in headers risk header injection and protocol violations (RFC 7230 §3.2.6).
  for (char c : link) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (uc < 0x20 || uc == 0x7F) {
      return false;
    }
  }

  // Additionally reject space (0x20) inside the URL portion only.
  // Space in the URL breaks HTTP header framing (whitespace-delimited parsers) and
  // violates RFC 3986 §2 which disallows unencoded spaces in URIs.
  // Space is valid in the params ("; rel=preload; as=style") per RFC 8288 §3.
  for (size_t i = 1; i < url_end; ++i) {
    if (link[i] == ' ') {
      return false;
    }
  }

  // Reject nested '<' or extra '>' inside the URL portion
  std::string url_part = link.substr(1, url_end - 1);
  for (char c : url_part) {
    if (c == '<' || c == '>') {
      return false;
    }
  }

  // Allowlist URL scheme check — same RFC 3986 §3.1 logic as is_safe_url() in html_scanner.cc.
  // A denylist (blocking js/data/vbscript/blob) is fragile: any new or exotic scheme
  // (file:, ftp:, chrome-extension:, feed:javascript:, jar:, ws:, wss:, etc.) bypasses it.
  // An allowlist is inherently safe against unknown schemes.
  //
  // Strip leading whitespace — browsers do this per WHATWG URL spec,
  // so "  javascript:..." resolves to "javascript:...".
  size_t scheme_start = url_part.find_first_not_of(" \t");
  if (scheme_start == std::string::npos) {
    return false; // all whitespace — useless URL
  }

  // Detect whether url_part has a scheme per RFC 3986 §3.1:
  //   scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  // If the first character is ALPHA and we find ':', only http: and https: are allowed.
  // Everything else (relative path, protocol-relative //host, fragment-only) has no scheme.
  const char *s    = url_part.c_str() + scheme_start;
  size_t remaining = url_part.size() - scheme_start;
  if (remaining > 0 && std::isalpha(static_cast<unsigned char>(s[0]))) {
    for (size_t i = 1; i < remaining; i++) {
      char c = s[i];
      if (c == ':') {
        // Found a scheme — only http and https are allowed.
        // Lowercase for case-insensitive comparison.
        std::string scheme_lower(s, i);
        for (char &ch : scheme_lower) {
          ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        if (scheme_lower == "http" || scheme_lower == "https") {
          break; // safe — continue to rel= check
        }
        return false; // exotic scheme: file:, ftp:, chrome-extension:, etc.
      }
      // Valid scheme chars: ALPHA / DIGIT / "+" / "-" / "."
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.') {
        break; // not a valid scheme char — relative URL, no scheme
      }
    }
  }
  // No scheme (relative URL) or http/https scheme — allowed.

  // Must contain a valid rel= value — search only in params portion (after '>'), not the URL
  std::string params_lower;
  if (url_end + 1 < link.size()) {
    std::string params_part = link.substr(url_end + 1);
    params_lower.reserve(params_part.size());
    for (char c : params_part) {
      params_lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
  }

  auto check_rel = [&](const char *rel_str) -> bool {
    size_t rel_len = strlen(rel_str);
    size_t pos     = 0;
    while ((pos = params_lower.find(rel_str, pos)) != std::string::npos) {
      // Verify word boundary before match
      bool before_ok = (pos == 0) || params_lower[pos - 1] == ';' || params_lower[pos - 1] == ' ' || params_lower[pos - 1] == '\t';
      size_t end     = pos + rel_len;
      // After-boundary: only ';', space, tab, or end-of-string for the unquoted form.
      // '"' and '\'' are NOT valid unquoted boundaries — rel=preload"garbage" must be rejected.
      // Quoted forms (rel="preload") are handled separately by check_rel_quoted.
      bool after_ok =
        end >= params_lower.size() || params_lower[end] == ';' || params_lower[end] == ' ' || params_lower[end] == '\t';
      if (before_ok && after_ok) {
        return true;
      }
      pos += rel_len;
    }
    return false;
  };

  // Also check quoted variants: rel="preload", rel='preload' (RFC 8288 §3)
  auto check_rel_quoted = [&](const char *rel_type) -> bool {
    std::string dq          = std::string("rel=\"") + rel_type + "\"";
    std::string sq          = std::string("rel='") + rel_type + "'";
    auto has_boundary_match = [&](const std::string &needle) -> bool {
      size_t pos = 0;
      while ((pos = params_lower.find(needle, pos)) != std::string::npos) {
        bool before_ok =
          (pos == 0) || params_lower[pos - 1] == ';' || params_lower[pos - 1] == ' ' || params_lower[pos - 1] == '\t';
        size_t after = pos + needle.size();
        bool after_ok =
          (after >= params_lower.size()) || params_lower[after] == ';' || params_lower[after] == ' ' || params_lower[after] == '\t';
        if (before_ok && after_ok) {
          return true;
        }
        pos += needle.size();
      }
      return false;
    };
    return has_boundary_match(dq) || has_boundary_match(sq);
  };

  return check_rel("rel=preload") || check_rel("rel=preconnect") || check_rel("rel=stylesheet") || check_rel("rel=modulepreload") ||
         check_rel_quoted("preload") || check_rel_quoted("preconnect") || check_rel_quoted("stylesheet") ||
         check_rel_quoted("modulepreload");
}

bool
has_valid_as_for_preload(const std::string &link)
{
  if (link.empty()) {
    return true;
  }

  // Extract params portion (after '>')
  size_t url_end = link.find('>');
  if (url_end == std::string::npos || url_end + 1 >= link.size()) {
    return true; // No params — nothing to validate
  }

  std::string params;
  params.reserve(link.size() - url_end);
  for (size_t i = url_end + 1; i < link.size(); ++i) {
    params += static_cast<char>(std::tolower(static_cast<unsigned char>(link[i])));
  }

  // Check if rel=preload or rel=modulepreload is present
  auto has_rel = [&](const char *rel_str) -> bool {
    size_t rel_len = strlen(rel_str);
    size_t pos     = 0;
    while ((pos = params.find(rel_str, pos)) != std::string::npos) {
      bool before_ok = (pos == 0) || params[pos - 1] == ';' || params[pos - 1] == ' ' || params[pos - 1] == '\t';
      size_t end     = pos + rel_len;
      bool after_ok  = end >= params.size() || params[end] == ';' || params[end] == ' ' || params[end] == '\t' ||
                      params[end] == '"' || params[end] == '\'';
      if (before_ok && after_ok) {
        return true;
      }
      pos += rel_len;
    }
    return false;
  };

  bool needs_as = has_rel("rel=preload") || has_rel("rel=modulepreload") || has_rel("rel=\"preload\"") ||
                  has_rel("rel='preload'") || has_rel("rel=\"modulepreload\"") || has_rel("rel='modulepreload'");

  if (!needs_as) {
    return true; // rel=preconnect, rel=stylesheet etc — as= not required
  }

  // Valid fetch destinations per Fetch spec §8
  static const char *valid_as[] = {"audio",  "document", "embed",        "fetch", "font",  "frame", "iframe", "image",
                                   "object", "script",   "sharedworker", "style", "track", "video", "worker"};

  // Search for as=<value> with word boundaries
  for (const char *as_val : valid_as) {
    std::string needle = std::string("as=") + as_val;
    size_t pos         = 0;
    while ((pos = params.find(needle, pos)) != std::string::npos) {
      bool before_ok = (pos == 0) || params[pos - 1] == ';' || params[pos - 1] == ' ' || params[pos - 1] == '\t';
      size_t end     = pos + needle.size();
      bool after_ok  = end >= params.size() || params[end] == ';' || params[end] == ' ' || params[end] == '\t';
      if (before_ok && after_ok) {
        return true;
      }
      pos += needle.size();
    }
  }

  return false;
}

// Extracts URL key from a Link header value: everything up to and including '>'.
// Used for deduplication — two links with the same <URL> are duplicates regardless of rel type,
// because rel=preload subsumes rel=preconnect for the same resource.
static std::string
extract_dedup_key(const std::string &link)
{
  size_t url_end = link.find('>');
  if (url_end != std::string::npos) {
    return link.substr(0, url_end + 1);
  }
  return link;
}

std::vector<std::string>
merge_hint_links(const std::vector<std::string> &manual_links, const std::vector<std::string> *cached_links, int max_links)
{
  std::vector<std::string> result;
  if (max_links <= 0) {
    return result;
  }

  result.reserve(static_cast<size_t>(max_links));

  // Track URL keys for deduplication
  std::unordered_set<std::string> seen_keys;
  seen_keys.reserve(static_cast<size_t>(max_links));

  auto add_link = [&](const std::string &link) -> bool {
    if (static_cast<int>(result.size()) >= max_links) {
      return false;
    }
    std::string key = extract_dedup_key(link);
    if (seen_keys.find(key) != seen_keys.end()) {
      return true; // duplicate, skip but continue
    }
    seen_keys.insert(std::move(key));
    result.push_back(link);
    return true;
  };

  // Manual links first (priority)
  for (const auto &link : manual_links) {
    if (!add_link(link)) {
      return result;
    }
  }

  // Cached links appended with dedup
  if (cached_links) {
    for (const auto &link : *cached_links) {
      if (!add_link(link)) {
        return result;
      }
    }
  }

  return result;
}

bool
EarlyHintsConfig::parse_mode(const char *mode_str)
{
  mode_ = 0;

  std::string modes(mode_str);

  // Reject trailing comma (e.g. "manual,") — the empty token after it
  // would otherwise be silently skipped by the loop below.
  if (!modes.empty() && modes.back() == ',') {
    TSError("[%s] trailing comma in mode: %s", PLUGIN_NAME, mode_str);
    return false;
  }

  size_t pos = 0;
  while (pos < modes.size()) {
    size_t comma = modes.find(',', pos);
    if (comma == std::string::npos) {
      comma = modes.size();
    }

    std::string m = modes.substr(pos, comma - pos);
    if (m == "manual") {
      mode_ |= MODE_MANUAL;
    } else if (m == "auto-learn") {
      mode_ |= MODE_AUTO_LEARN;
    } else if (m == "origin-forward") {
      mode_ |= MODE_ORIGIN_FORWARD;
    } else {
      TSError("[%s] unknown mode: %s", PLUGIN_NAME, m.c_str());
      return false;
    }

    pos = comma + 1;
  }

  if (mode_ == 0) {
    TSError("[%s] no valid mode specified", PLUGIN_NAME);
    return false;
  }

  return true;
}

bool
EarlyHintsConfig::match_domain_list(const std::string &domain, const std::vector<std::string> &list)
{
  // DNS domains are case-insensitive — normalize to lowercase for comparison
  std::string domain_lower;
  domain_lower.reserve(domain.size());
  for (char c : domain) {
    domain_lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }

  // Strip userinfo (RFC 3986 §3.2.1): "user@host" → "host"
  size_t at_pos = domain_lower.find('@');
  if (at_pos != std::string::npos) {
    domain_lower = domain_lower.substr(at_pos + 1);
  }
  // For IPv6 literals like [::1]:8080, look for port after closing bracket
  if (!domain_lower.empty() && domain_lower[0] == '[') {
    size_t bracket_pos = domain_lower.find(']');
    if (bracket_pos != std::string::npos && bracket_pos + 1 < domain_lower.size() && domain_lower[bracket_pos + 1] == ':') {
      domain_lower = domain_lower.substr(0, bracket_pos + 1);
    }
  } else {
    size_t colon_pos = domain_lower.find(':');
    if (colon_pos != std::string::npos) {
      domain_lower = domain_lower.substr(0, colon_pos);
    }
  }

  for (const auto &pattern : list) {
    // Patterns are pre-lowercased at init time, no per-call conversion needed
    if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
      // Wildcard match: *.example.com matches foo.example.com but NOT .example.com
      std::string suffix = pattern.substr(1); // .example.com
      if (domain_lower.size() > suffix.size() &&
          domain_lower.compare(domain_lower.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return true;
      }
    } else if (domain_lower == pattern) {
      return true;
    }
  }
  return false;
}

bool
EarlyHintsConfig::is_whitelisted_domain(const std::string &domain) const
{
  return match_domain_list(domain, crossorigin_whitelist_);
}

bool
EarlyHintsConfig::is_preload_domain(const std::string &domain) const
{
  return match_domain_list(domain, preload_whitelist_);
}

bool
EarlyHintsConfig::init(int argc, const char *argv[])
{
  // clang-format off
  static const struct option longopt[] = {
    {const_cast<char *>("mode"),                    required_argument, nullptr, 'm'},
    {const_cast<char *>("link"),                     required_argument, nullptr, 'l'},
    {const_cast<char *>("max-links"),                required_argument, nullptr, 'x'},
    {const_cast<char *>("persist-dir"),              required_argument, nullptr, 'p'},
    {const_cast<char *>("no-persist"),               no_argument,       nullptr, 'P'},
    {const_cast<char *>("header-size-limit"),        required_argument, nullptr, 'z'},
    {const_cast<char *>("skip-bots"),                no_argument,       nullptr, 'b'},
    {const_cast<char *>("no-skip-bots"),             no_argument,       nullptr, 'B'},
    {const_cast<char *>("navigate-only"),            no_argument,       nullptr, 'n'},
    {const_cast<char *>("no-navigate-only"),         no_argument,       nullptr, 'N'},
    {const_cast<char *>("debug-header"),             required_argument, nullptr, 'd'},
    {const_cast<char *>("scan-limit"),               required_argument, nullptr, 's'},
    {const_cast<char *>("min-hit-count"),            required_argument, nullptr, 'h'},
    {const_cast<char *>("crossorigin-whitelist"),    required_argument, nullptr, 'w'},
    {const_cast<char *>("preload-whitelist"),         required_argument, nullptr, 'W'},
    {const_cast<char *>("max-cache-entries"),        required_argument, nullptr, 'c'},
    {const_cast<char *>("persist-throttle"),          required_argument, nullptr, 't'},
    {const_cast<char *>("hints-ttl"),                 required_argument, nullptr, 'T'},
    {nullptr, 0, nullptr, 0},
  };
  // clang-format on

  // CRITICAL: ATS passes pargv where pargv[0]=fromURL and pargv[1]=toURL (both
  // heap-allocated, freed by ATS after this returns). getopt_long with GNU libc
  // permutes argv by default, which can move heap pointers around. Two mitigations:
  // 1. Skip argv[0] (fromURL) so getopt treats argv[1] (toURL) as program name
  // 2. Use "+" prefix in optstring to disable GNU permutation
  // This matches the pattern used by cachekey plugin.
  if (argc < 2) {
    return true; // No parameters beyond fromURL
  }
  int local_argc          = argc - 1;
  const char **local_argv = argv + 1;

  // Reset getopt state for re-entrant parsing.
  // On glibc, optind=0 triggers a full internal state reset (__getopt_initialized).
  // On BSD/macOS, optreset=1 is required instead.  Match the pattern ATS uses in
  // RemapPluginInfo.cc so this function is safe even outside the remap-load path.
#if defined(freebsd) || defined(darwin)
  optreset = 1;
#endif
#if defined(__GLIBC__)
  optind = 0;
#else
  optind = 1;
#endif
  opterr = 0; // suppress getopt's default stderr messages; we use TSError

  for (;;) {
    int opt = getopt_long(local_argc, const_cast<char *const *>(local_argv), "+", longopt, nullptr);
    if (opt == -1) {
      break;
    }

    switch (opt) {
    case 'm':
      if (!parse_mode(optarg)) {
        return false;
      }
      break;
    case 'l':
      if (!is_valid_link_value(std::string(optarg))) {
        TSError("[%s] invalid --link value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (!has_valid_as_for_preload(std::string(optarg))) {
        TSError("[%s] WARNING: --link has rel=preload without valid as= attribute, "
                "browser will ignore preload (double-fetch risk): %s",
                PLUGIN_NAME, optarg);
      }
      manual_links_.emplace_back(optarg);
      break;
    case 'x':
      if (!safe_parse_int(optarg, &max_links_)) {
        TSError("[%s] invalid --max-links value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (max_links_ < 1 || max_links_ > 50) {
        TSError("[%s] max-links must be between 1 and 50, got %d", PLUGIN_NAME, max_links_);
        return false;
      }
      break;
    case 'p':
      persist_dir_     = optarg;
      persist_enabled_ = true; // --persist-dir opts in to persistence
      break;
    case 'P':
      persist_enabled_ = false;
      break;
    case 'z':
      if (!safe_parse_int(optarg, &header_size_limit_)) {
        TSError("[%s] invalid --header-size-limit value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (header_size_limit_ < 256 || header_size_limit_ > 16384) {
        TSError("[%s] header-size-limit must be between 256 and 16384, got %d", PLUGIN_NAME, header_size_limit_);
        return false;
      }
      break;
    case 'b':
      skip_bots_ = true;
      break;
    case 'B':
      skip_bots_ = false;
      break;
    case 'n':
      navigate_only_ = true;
      break;
    case 'N':
      navigate_only_ = false;
      break;
    case 'd':
      if (!is_valid_header_name(optarg)) {
        TSError("[%s] invalid --debug-header value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      debug_header_ = optarg;
      break;
    case 's':
      if (!safe_parse_int(optarg, &scan_limit_)) {
        TSError("[%s] invalid --scan-limit value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (scan_limit_ < 1024 || scan_limit_ > 1048576) {
        TSError("[%s] scan-limit must be between 1024 and 1048576, got %d", PLUGIN_NAME, scan_limit_);
        return false;
      }
      break;
    case 'h':
      if (!safe_parse_int(optarg, &min_hit_count_)) {
        TSError("[%s] invalid --min-hit-count value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (min_hit_count_ < 1 || min_hit_count_ > 1000) {
        TSError("[%s] min-hit-count must be between 1 and 1000, got %d", PLUGIN_NAME, min_hit_count_);
        return false;
      }
      break;
    case 'w': {
      std::string domains(optarg);
      size_t pos = 0;
      while (pos < domains.size()) {
        size_t comma = domains.find(',', pos);
        if (comma == std::string::npos) {
          comma = domains.size();
        }
        // Trim leading whitespace
        size_t start = pos;
        while (start < comma && (domains[start] == ' ' || domains[start] == '\t')) {
          start++;
        }
        // Trim trailing whitespace
        size_t end = comma;
        while (end > start && (domains[end - 1] == ' ' || domains[end - 1] == '\t')) {
          end--;
        }
        std::string d = domains.substr(start, end - start);
        if (!d.empty()) {
          std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c) { return std::tolower(c); });
          crossorigin_whitelist_.push_back(d);
        }
        pos = comma + 1;
      }
      break;
    }
    case 'W': {
      std::string domains(optarg);
      size_t pos = 0;
      while (pos < domains.size()) {
        size_t comma = domains.find(',', pos);
        if (comma == std::string::npos) {
          comma = domains.size();
        }
        size_t start = pos;
        while (start < comma && (domains[start] == ' ' || domains[start] == '\t')) {
          start++;
        }
        size_t end = comma;
        while (end > start && (domains[end - 1] == ' ' || domains[end - 1] == '\t')) {
          end--;
        }
        std::string d = domains.substr(start, end - start);
        if (!d.empty()) {
          std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c) { return std::tolower(c); });
          preload_whitelist_.push_back(d);
        }
        pos = comma + 1;
      }
      break;
    }
    case 'c':
      if (!safe_parse_int(optarg, &max_cache_entries_)) {
        TSError("[%s] invalid --max-cache-entries value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (max_cache_entries_ < 1 || max_cache_entries_ > 1000000) {
        TSError("[%s] max-cache-entries must be between 1 and 1000000, got %d", PLUGIN_NAME, max_cache_entries_);
        return false;
      }
      break;
    case 't':
      if (!safe_parse_int(optarg, &persist_throttle_)) {
        TSError("[%s] invalid --persist-throttle value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (persist_throttle_ < 0 || persist_throttle_ > 300) {
        TSError("[%s] persist-throttle must be between 0 and 300 seconds, got %d", PLUGIN_NAME, persist_throttle_);
        return false;
      }
      break;
    case 'T':
      if (!safe_parse_int(optarg, &hints_ttl_)) {
        TSError("[%s] invalid --hints-ttl value: %s", PLUGIN_NAME, optarg);
        return false;
      }
      if (hints_ttl_ < 0 || hints_ttl_ > 86400) {
        TSError("[%s] hints-ttl must be between 0 and 86400 seconds (0=disabled), got %d", PLUGIN_NAME, hints_ttl_);
        return false;
      }
      break;
    default:
      TSError("[%s] unknown option", PLUGIN_NAME);
      return false;
    }
  }

  // Validate: manual mode requires at least one --link
  if ((mode_ & MODE_MANUAL) && manual_links_.empty()) {
    TSError("[%s] manual mode requires at least one --link parameter", PLUGIN_NAME);
    return false;
  }

  // Reject trailing positional arguments that getopt_long did not consume.
  // With "+" prefix, getopt stops at the first non-option argument, silently
  // ignoring it and everything after.  This catches typos like "--max-link 5"
  // (missing 's') which would otherwise be silently lost.
  if (optind < local_argc) {
    TSError("[%s] unexpected argument: %s", PLUGIN_NAME, local_argv[optind]);
    return false;
  }

  TSDebug(PLUGIN_NAME,
          "config: mode=0x%02x max_links=%d header_size_limit=%d skip_bots=%d navigate_only=%d "
          "scan_limit=%d min_hit_count=%d max_cache_entries=%d persist_throttle=%d manual_links=%zu crossorigin_whitelist=%zu "
          "preload_whitelist=%zu persist=%s persist_dir=%s",
          mode_, max_links_, header_size_limit_, skip_bots_, navigate_only_, scan_limit_, min_hit_count_, max_cache_entries_,
          persist_throttle_, manual_links_.size(), crossorigin_whitelist_.size(), preload_whitelist_.size(),
          persist_enabled_ ? "on" : "off", persist_dir_.empty() ? "(auto)" : persist_dir_.c_str());

  return true;
}

// Normalize a Link header value from an origin response for use in HTTP 103 Early Hints.
// HTTP 103 only supports rel=preload, rel=preconnect, and rel=modulepreload.
// rel=stylesheet is converted to rel=preload; as=style so origin stylesheets
// generate valid preload hints. Other rel types (rel=dns-prefetch etc.) are dropped.
// Returns an empty string if the link cannot be represented as a hint.

// Boundary-aware parameter match: ensures the needle is delimited by
// start-of-string, ';', space, or tab on both sides. Prevents "xrel=stylesheet"
// from matching "rel=stylesheet".
static bool
has_param_match(const std::string &haystack, const char *needle)
{
  size_t needle_len = strlen(needle);
  size_t pos        = 0;
  while ((pos = haystack.find(needle, pos)) != std::string::npos) {
    bool before_ok = (pos == 0) || haystack[pos - 1] == ';' || haystack[pos - 1] == ' ' || haystack[pos - 1] == '\t';
    size_t end     = pos + needle_len;
    bool after_ok  = end >= haystack.size() || haystack[end] == ';' || haystack[end] == ' ' || haystack[end] == '\t';
    if (before_ok && after_ok) {
      return true;
    }
    pos += needle_len;
  }
  return false;
}

std::string
normalize_link_for_hint(const std::string &link)
{
  if (link.empty() || link[0] != '<') {
    return {};
  }

  size_t url_end = link.find('>');
  if (url_end == std::string::npos || url_end < 1) {
    return {};
  }

  // Extract <URL> portion including brackets
  std::string url_part = link.substr(0, url_end + 1);

  // Build lowercase version of the params to classify rel type
  std::string params_lower = link.substr(url_end + 1);
  std::transform(params_lower.begin(), params_lower.end(), params_lower.begin(), [](unsigned char c) { return std::tolower(c); });

  // Check for stylesheet — convert to preload; as=style.
  if (has_param_match(params_lower, "rel=stylesheet") || has_param_match(params_lower, "rel=\"stylesheet\"") ||
      has_param_match(params_lower, "rel='stylesheet'")) {
    return url_part + "; rel=preload; as=style";
  }

  // rel=preload, rel=preconnect, rel=modulepreload — return unchanged
  if (has_param_match(params_lower, "rel=preload") || has_param_match(params_lower, "rel=preconnect") ||
      has_param_match(params_lower, "rel=modulepreload") || has_param_match(params_lower, "rel=\"preload\"") ||
      has_param_match(params_lower, "rel=\"preconnect\"") || has_param_match(params_lower, "rel=\"modulepreload\"") ||
      has_param_match(params_lower, "rel='preload'") || has_param_match(params_lower, "rel='preconnect'") ||
      has_param_match(params_lower, "rel='modulepreload'")) {
    return link;
  }

  return {};
}
