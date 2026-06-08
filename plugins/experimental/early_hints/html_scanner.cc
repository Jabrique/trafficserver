/** @file
 * Streaming HTML <head> scanner for auto-learning preloadable resources.
 *
 * Extracts preloadable resources from HTML <head> via a byte-by-byte state machine.
 * NOT a full HTML parser — optimized for speed and safety.
 *
 * What it extracts:
 * - <link rel="preload" href="..." as="...">
 * - <link rel="stylesheet" href="...">  → converts to rel=preload; as=style
 * - <link rel="modulepreload" href="...">
 * - <script src="..."> (without async or defer) → rel=preload; as=script
 * - crossorigin attribute (boolean and valued)
 * - fetchpriority attribute (Chrome 101+)
 * - type attribute (commonly used for fonts, but applies to any preload)
 * - Auto-adds crossorigin for as=font (W3C CSS Fonts spec requirement)
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

#include "html_scanner.h"
#include "config.h"
#include "link_parser.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <strings.h>

static constexpr size_t MAX_TAG_NAME_LEN  = 256;
static constexpr size_t MAX_ATTR_NAME_LEN = 256;

HtmlScanner::HtmlScanner(int scan_limit, int max_links, const EarlyHintsConfig *config)
  : limit_(scan_limit), max_links_(max_links), config_(config)
{
  links_.reserve(max_links);
  match_buf_.reserve(16);
  tag_name_.reserve(16);
  attr_name_.reserve(32);
  attr_value_.reserve(256);
  href_.reserve(256);
}

void
HtmlScanner::reset()
{
  state_   = State::INIT;
  scanned_ = 0;
  links_.clear();
  dedup_index_.clear();
  match_buf_.clear();
  reset_tag_state();
  raw_close_pos_ = 0;
  raw_close_tag_.clear();
  script_escaped_     = false;
  script_comment_pos_ = 0;
}

void
HtmlScanner::reset_tag_state()
{
  tag_name_.clear();
  attr_name_.clear();
  attr_value_.clear();
  quote_char_     = 0;
  in_closing_tag_ = false;
  comment_dashes_ = 0;
  // NOTE: raw_close_pos_ and raw_close_tag_ are NOT cleared here.
  // They are set by state_after_open_tag() which is called BEFORE
  // reset_tag_state(), and must survive into IN_SCRIPT state.
  href_.clear();
  rel_.clear();
  as_.clear();
  type_.clear();
  crossorigin_value_.clear();
  fetchpriority_.clear();
  has_async_       = false;
  has_defer_       = false;
  attr_overflowed_ = false;
}

std::string
HtmlScanner::tolower_str(const std::string &s)
{
  std::string result;
  result.reserve(s.size());
  for (char c : s) {
    result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return result;
}

bool
HtmlScanner::is_safe_url(const std::string &url)
{
  if (url.empty()) {
    return false;
  }

  for (char c : url) {
    unsigned char uc = static_cast<unsigned char>(c);
    // Reject control characters (CRLF injection, null bytes) and space (0x20).
    // Space breaks HTTP header framing — the Link header value is whitespace-delimited
    // in many parsers, and RFC 3986 §2 disallows unencoded spaces in URIs.
    if (uc <= 0x20 || uc == 0x7F) {
      return false;
    }
    // Reject Link header delimiters — '>' terminates the URI-Reference in
    // RFC 8288 and '<' could start a nested link-value.  Allowing either
    // character lets an attacker break out of the URL portion and inject
    // arbitrary Link header parameters or additional link-values.
    if (c == '<' || c == '>') {
      return false;
    }
  }

  // Allowlist approach: only permit http:, https:, and relative URLs.
  // A denylist (blocking javascript:, data:, etc.) is fragile — any new or
  // exotic scheme (file:, ftp:, feed:javascript:, jar:, view-source:, etc.)
  // bypasses the filter.  An allowlist is inherently safe against unknown schemes.
  //
  // Note: the control-char loop above already rejects space (0x20) and tab (0x09),
  // so any URL reaching here starts with a non-whitespace character.
  // Browsers strip leading whitespace per WHATWG URL spec, but we reject it
  // instead: browsers pct-encode whitespace before sending href over HTTP,
  // so raw whitespace here indicates malformed input.
  const char *s    = url.c_str();
  size_t remaining = url.size();

  // First char must be ALPHA to start a scheme (RFC 3986 §3.1)
  if (remaining > 0 && std::isalpha(static_cast<unsigned char>(s[0]))) {
    for (size_t i = 1; i < remaining; i++) {
      char c = s[i];
      if (c == ':') {
        // Found a scheme, only allow http and https.
        // Additionally enforce "://" authority separator per WHATWG URL section 4.2:
        // browsers normalize http:\\evil.com and http:/evil.com to http://evil.com,
        // so a bare colon without "//" is a cross-origin evasion vector.
        if ((i == 4 && strncasecmp(s, "http:", 5) == 0) || (i == 5 && strncasecmp(s, "https:", 6) == 0)) {
          // Require "://" to reject http:\ and http:/ (single slash)
          if (i + 2 < remaining && s[i + 1] == '/' && s[i + 2] == '/') {
            return true;
          }
          return false; // http:\ or http:/ missing authority separator
        }
        return false;
      }
      // Valid scheme chars: ALPHA / DIGIT / "+" / "-" / "."
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.') {
        break; // Not a valid scheme char — URL has no scheme (relative URL)
      }
    }
  }

  // No scheme found — relative URL (e.g., "/app.js", "images/foo.png").
  // However, reject backslash-based authority references: browsers with "special"
  // schemes (http/https) treat '\' as '/' per WHATWG URL spec §4.2, so
  // \\evil.com, \/evil.com, and /\evil.com all resolve as cross-origin.
  // Explicitly reject these before returning safe.
  if (remaining >= 2) {
    char c0 = s[0];
    char c1 = s[1];
    if ((c0 == '\\' && (c1 == '\\' || c1 == '/')) || (c0 == '/' && c1 == '\\')) {
      return false; // backslash authority reference — cross-origin evasion
    }
  }

  return true;
}

bool
HtmlScanner::is_crossorigin(const std::string &href)
{
  if (href.empty()) {
    return false;
  }

  // Protocol-relative URL: //example.com/path
  // Also detect backslash variants: browsers with "special" schemes (http/https)
  // treat '\' as '/' per WHATWG URL spec §4.2, so \\evil.com, \/evil.com, and
  // /\evil.com all resolve as cross-origin authority references.
  if (href.size() >= 2 && (href[0] == '/' || href[0] == '\\') && (href[1] == '/' || href[1] == '\\')) {
    return true;
  }

  // Absolute URL: must have a scheme per RFC 3986 §3.1:
  //   scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
  // We require the scheme to start from the beginning of the URL.
  // This prevents false positives when "://" appears inside a query string,
  // e.g. /proxy?url=https://cdn.example.com — that is a same-origin URL.
  const char *s = href.c_str();
  size_t n      = href.size();
  if (n > 0 && std::isalpha(static_cast<unsigned char>(s[0]))) {
    for (size_t i = 1; i < n; i++) {
      char c = s[i];
      if (c == ':' && i + 2 < n && s[i + 1] == '/' && s[i + 2] == '/') {
        // Found scheme:// starting from position 0 — this is cross-origin.
        return true;
      }
      // Valid scheme chars: ALPHA / DIGIT / "+" / "-" / "."
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.') {
        break; // Not a scheme char — no scheme at start, relative URL
      }
    }
  }

  // Relative URL (path starts with /, relative path, or :// only in query) — same-origin
  return false;
}

std::string
HtmlScanner::extract_origin(const std::string &url)
{
  // Extract scheme + host from URL (e.g., "https://fonts.gstatic.com" from full URL).
  // Per RFC 3986, the authority ends at the first '/', '?', or '#'.
  auto find_authority_end = [](const std::string &s, size_t start) -> size_t {
    for (size_t i = start; i < s.size(); i++) {
      if (s[i] == '/' || s[i] == '?' || s[i] == '#' || s[i] == '\\') {
        return i;
      }
    }
    return std::string::npos;
  };

  // RFC 3986 §3.1 scheme detection: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) "://"
  // Only recognize scheme:// when it starts from position 0 of the URL (ALPHA at pos 0).
  // This prevents false positives when :// appears inside a query string or path,
  // e.g. /proxy?url=https://cdn.example.com — that is a relative (same-origin) URL,
  // NOT an absolute URL with scheme "proxy?url=https".
  //
  // Naive url.find("://") would return 16 for /proxy?url=https://... and incorrectly
  // extract "/proxy?url=https://cdn.example.com" as the "origin".
  size_t scheme_end = std::string::npos;
  if (!url.empty() && std::isalpha(static_cast<unsigned char>(url[0]))) {
    for (size_t i = 1; i < url.size(); i++) {
      char c = url[i];
      if (c == ':' && i + 2 < url.size() && url[i + 1] == '/' && url[i + 2] == '/') {
        // Found scheme:// starting at position 0 — valid absolute URL
        scheme_end = i;
        break;
      }
      // Valid scheme chars per RFC 3986 §3.1: ALPHA / DIGIT / "+" / "-" / "."
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.') {
        break; // Not a valid scheme char — no scheme at start, relative URL
      }
    }
  }

  if (scheme_end == std::string::npos) {
    // No absolute scheme at position 0.
    // Per WHATWG URL spec §4.2, browsers treat \ as / in the authority
    // component of special schemes. Normalize \\, \/, /\ to // before
    // protocol-relative parsing to match browser behavior.
    if (url.size() > 2 && (url[0] == '/' || url[0] == '\\') && (url[1] == '/' || url[1] == '\\')) {
      std::string normalized = "//" + url.substr(2);
      size_t auth_end        = find_authority_end(normalized, 2);
      if (auth_end == std::string::npos) {
        return "https:" + normalized;
      }
      return "https:" + normalized.substr(0, auth_end);
    }
    // Relative URL (path, query-only, etc.) — return as-is.
    // Callers must NOT call extract_origin for relative URLs; is_crossorigin()
    // guards this. If called anyway (defensive), return url unchanged.
    return url;
  }

  size_t host_start = scheme_end + 3;
  size_t auth_end   = find_authority_end(url, host_start);
  if (auth_end == std::string::npos) {
    return url;
  }
  return url.substr(0, auth_end);
}

void
HtmlScanner::finish_attr()
{
  std::string name = tolower_str(attr_name_);

  // Per HTML spec §13.1.2.3, when the same attribute name appears more
  // than once in an element the FIRST occurrence wins; subsequent duplicates
  // must be silently ignored.  All branches below guard with an empty-check so
  // that a second appearance of the same attribute is a no-op.
  if (name == "href" || name == "src") {
    if (href_.empty()) {
      href_ = attr_value_;
    }
  } else if (name == "rel") {
    if (rel_.empty()) {
      rel_ = tolower_str(attr_value_);
    }
  } else if (name == "as") {
    if (as_.empty()) {
      // Validate against the set of known fetch destinations (Fetch spec §8).
      // Passing an unsanitized value through to the Link header would allow
      // parameter injection via ';', ',' or '<'/'>' embedded in the value.
      std::string val = tolower_str(attr_value_);
      if (val == "audio" || val == "document" || val == "embed" || val == "fetch" || val == "font" || val == "frame" ||
          val == "iframe" || val == "image" || val == "object" || val == "script" || val == "style" || val == "track" ||
          val == "video" || val == "worker" || val == "sharedworker") {
        as_ = val;
      }
      // Unknown/malicious value — leave as_ empty (dropped).
    }
  } else if (name == "type") {
    if (type_.empty()) {
      // Sanitize: only allow safe MIME-type characters to prevent header injection
      std::string safe_type;
      for (char c : attr_value_) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '/' || c == '+' || c == '.' || c == '-') {
          safe_type += c;
        }
      }
      // Lowercase: MIME types are case-insensitive per RFC 2045, consistent with
      // rel_, as_, fetchpriority_. Also makes type="Module" match "module" for
      // script module detection.
      type_ = tolower_str(safe_type);
    }
  } else if (name == "crossorigin") {
    if (crossorigin_value_.empty()) {
      // Per HTML spec §2.5.3 only two enumerated states are valid:
      // "anonymous" (the default, including empty-string) and "use-credentials".
      // Any other value — including misspellings — maps to "anonymous".
      std::string cv     = attr_value_.empty() ? "anonymous" : tolower_str(attr_value_);
      crossorigin_value_ = (cv == "use-credentials") ? "use-credentials" : "anonymous";
    }
  } else if (name == "fetchpriority") {
    if (fetchpriority_.empty()) {
      fetchpriority_ = tolower_str(attr_value_);
    }
  } else if (name == "async") {
    has_async_ = true; // boolean presence attr — no first-wins guard needed
  } else if (name == "defer") {
    has_defer_ = true; // boolean presence attr — no first-wins guard needed
  }

  attr_name_.clear();
  attr_value_.clear();
}

void
HtmlScanner::build_link_header(const std::string &tag)
{
  if (href_.empty() || !is_safe_url(href_)) {
    return;
  }

  // Already at max capacity
  if (static_cast<int>(links_.size()) >= max_links_) {
    return;
  }

  std::string result;

  if (tag == "link") {
    if (rel_ == "preload") {
      // <link rel="preload" href="..." as="...">
      if (as_.empty()) {
        return; // preload requires as attribute
      }

      if (is_crossorigin(href_)) {
        std::string origin = extract_origin(href_);
        if (origin.find("://") == std::string::npos) {
          return; // degenerate cross-origin URL (e.g. bare "//") — no valid absolute origin
        }
        size_t scheme_sep  = origin.find("://");
        std::string domain = (scheme_sep != std::string::npos) ? origin.substr(scheme_sep + 3) : origin;
        if (config_ && config_->is_whitelisted_domain(domain)) {
          // crossorigin-whitelist: allow preload with crossorigin
          result = "<" + href_ + ">; rel=preload; as=" + as_;
          if (crossorigin_value_.empty()) {
            crossorigin_value_ = "anonymous";
          }
        } else if (config_ && config_->is_preload_domain(domain)) {
          // preload-whitelist: full preload without crossorigin (no-cors fetch mode)
          result = "<" + href_ + ">; rel=preload; as=" + as_;
          crossorigin_value_.clear();
        } else {
          // Non-whitelisted cross-origin: downgrade to preconnect for connection warm-up.
          // crossorigin is meaningful here only for font resources: fonts are always CORS-fetched
          // (W3C CSS Fonts spec), so the preconnect must establish a CORS-capable connection.
          // For other resource types (script, style) the fetch mode is not predictably CORS,
          // so we omit crossorigin to avoid establishing the wrong connection pool.
          result = "<" + origin + ">; rel=preconnect";
          if (as_ == "font") {
            // Font: always CORS — preconnect must carry crossorigin so the browser reuses
            // this connection for the subsequent CORS font fetch instead of opening a new one.
            crossorigin_value_ = "anonymous";
          } else {
            crossorigin_value_.clear();
          }
        }
      } else {
        // Same-origin: normal preload.
        // Fonts require crossorigin=anonymous per W3C CSS Fonts spec so the browser
        // does not open a second connection for the CORS-checked @font-face fetch.
        result = "<" + href_ + ">; rel=preload; as=" + as_;
        if (as_ == "font" && crossorigin_value_.empty()) {
          crossorigin_value_ = "anonymous";
        }
      }
    } else if (rel_ == "stylesheet") {
      // <link rel="stylesheet" href="..."> → preload as style
      if (is_crossorigin(href_)) {
        std::string origin = extract_origin(href_);
        if (origin.find("://") == std::string::npos) {
          return; // degenerate cross-origin URL — no valid absolute origin
        }
        size_t scheme_sep  = origin.find("://");
        std::string domain = (scheme_sep != std::string::npos) ? origin.substr(scheme_sep + 3) : origin;
        if (config_ && config_->is_whitelisted_domain(domain)) {
          // crossorigin-whitelist: preload with crossorigin
          result = "<" + href_ + ">; rel=preload; as=style";
          as_    = "style";
          if (crossorigin_value_.empty()) {
            crossorigin_value_ = "anonymous";
          }
        } else if (config_ && config_->is_preload_domain(domain)) {
          // preload-whitelist: full preload without crossorigin
          result = "<" + href_ + ">; rel=preload; as=style";
          as_    = "style";
          crossorigin_value_.clear();
        } else {
          // Non-whitelisted: preconnect only — crossorigin not valid on preconnect
          result = "<" + origin + ">; rel=preconnect";
          crossorigin_value_.clear();
        }
      } else {
        result = "<" + href_ + ">; rel=preload; as=style";
        as_    = "style";
      }
    } else if (rel_ == "modulepreload") {
      // <link rel="modulepreload" href="...">
      // Module preloads are always CORS-fetched (HTML spec §8.1.4.2) so crossorigin=anonymous
      // is always implied. Apply the same whitelist logic as rel=preload.
      if (is_crossorigin(href_)) {
        std::string origin = extract_origin(href_);
        if (origin.find("://") == std::string::npos) {
          return; // degenerate cross-origin URL — no valid absolute origin
        }
        size_t scheme_sep  = origin.find("://");
        std::string domain = (scheme_sep != std::string::npos) ? origin.substr(scheme_sep + 3) : origin;
        if (config_ && config_->is_whitelisted_domain(domain)) {
          // crossorigin-whitelist: allow preload with crossorigin for module
          result = "<" + href_ + ">; rel=modulepreload";
          if (crossorigin_value_.empty()) {
            crossorigin_value_ = "anonymous";
          }
        } else if (config_ && config_->is_preload_domain(domain)) {
          // preload-whitelist: full modulepreload without crossorigin
          result = "<" + href_ + ">; rel=modulepreload";
          crossorigin_value_.clear();
        } else {
          // Non-whitelisted: preconnect only — module scripts are always CORS-fetched
          // (HTML spec §8.1.4.2), so the preconnect MUST carry crossorigin=anonymous
          // to establish a CORS-capable connection (same requirement as rel=preload as=font).
          result             = "<" + origin + ">; rel=preconnect";
          crossorigin_value_ = "anonymous";
        }
      } else {
        result = "<" + href_ + ">; rel=modulepreload";
      }
    } else {
      return; // Unsupported rel value
    }
  } else if (tag == "script") {
    // <script type="module" src="..."> -- ES module. Emit rel=modulepreload.
    // Per HTML spec, modules are always CORS-fetched and deferred implicitly.
    // type_ is stored lowercased by finish_attr(), so compare lowercase.
    if (!type_.empty() && type_ == "module") {
      if (href_.empty() || has_async_) {
        return; // no src or explicitly async -- skip
      }
      if (is_crossorigin(href_)) {
        std::string origin = extract_origin(href_);
        if (origin.find("://") == std::string::npos) {
          return; // degenerate cross-origin URL — no valid absolute origin
        }
        size_t scheme_sep  = origin.find("://");
        std::string domain = (scheme_sep != std::string::npos) ? origin.substr(scheme_sep + 3) : origin;
        if (config_ && config_->is_whitelisted_domain(domain)) {
          result = "<" + href_ + ">; rel=modulepreload";
          if (crossorigin_value_.empty()) {
            crossorigin_value_ = "anonymous";
          }
        } else if (config_ && config_->is_preload_domain(domain)) {
          result = "<" + href_ + ">; rel=modulepreload";
          crossorigin_value_.clear();
        } else {
          // Non-whitelisted cross-origin module: preconnect with crossorigin=anonymous
          // (module scripts are always CORS-fetched per HTML spec).
          result             = "<" + origin + ">; rel=preconnect";
          crossorigin_value_ = "anonymous";
        }
      } else {
        result = "<" + href_ + ">; rel=modulepreload";
      }
    } else {
      // Classic script: <script src="..."> without async or defer
      if (href_.empty() || has_async_ || has_defer_) {
        return;
      }
      if (is_crossorigin(href_)) {
        std::string origin = extract_origin(href_);
        if (origin.find("://") == std::string::npos) {
          return; // degenerate cross-origin URL — no valid absolute origin
        }
        size_t scheme_sep  = origin.find("://");
        std::string domain = (scheme_sep != std::string::npos) ? origin.substr(scheme_sep + 3) : origin;
        if (config_ && config_->is_whitelisted_domain(domain)) {
          result = "<" + href_ + ">; rel=preload; as=script";
          as_    = "script";
          if (crossorigin_value_.empty()) {
            crossorigin_value_ = "anonymous";
          }
        } else if (config_ && config_->is_preload_domain(domain)) {
          result = "<" + href_ + ">; rel=preload; as=script";
          as_    = "script";
          crossorigin_value_.clear();
        } else {
          // Non-whitelisted: preconnect only
          result = "<" + origin + ">; rel=preconnect";
          crossorigin_value_.clear();
        }
      } else {
        result = "<" + href_ + ">; rel=preload; as=script";
        as_    = "script";
      }
    } // end else { // Classic script }
  } else {
    return;
  }

  if (result.empty()) {
    return;
  }

  // (font crossorigin is handled inside each whitelist branch and the same-origin
  //  branch above; the preload-whitelist path explicitly keeps no-cors mode)

  // Cache the rel=preload / rel=modulepreload check once -- used by both
  // type= and fetchpriority= guards. rel=modulepreload output does NOT
  // contain the substring "rel=preload", so it must be checked separately.
  const bool is_preload_hint =
    (result.find("rel=preload") != std::string::npos || result.find("rel=modulepreload") != std::string::npos);

  // Append type attribute — validate as "type/subtype" MIME structure before
  // emitting. A MIME type without a "/" separator (e.g. type="font") is invalid
  // and must not be forwarded as a Link hint. Also reject empty, leading-slash,
  // and trailing-slash values.
  if (!type_.empty() && is_preload_hint) {
    size_t slash_pos = type_.find('/');
    bool valid_mime  = (slash_pos != std::string::npos && slash_pos > 0 && slash_pos < type_.size() - 1 &&
                       type_.find('/', slash_pos + 1) == std::string::npos);
    if (valid_mime) {
      result += "; type=\"" + type_ + "\"";
    }
  }

  // Append crossorigin — RFC 8288 §3 requires all link-params to use
  // token "=" (token / quoted-string) form; bare "; crossorigin" without
  // a value is not valid.
  if (!crossorigin_value_.empty()) {
    if (crossorigin_value_ == "anonymous") {
      result += "; crossorigin=anonymous";
    } else if (crossorigin_value_ == "use-credentials") {
      result += "; crossorigin=use-credentials";
    }
  }

  // Append fetchpriority (Chrome 101+ Fetch Priority API).
  // This attribute is only meaningful on preload hints — omit it from preconnect.
  if (!fetchpriority_.empty() && is_preload_hint &&
      (fetchpriority_ == "high" || fetchpriority_ == "low" || fetchpriority_ == "auto")) {
    result += "; fetchpriority=" + fetchpriority_;
  }

  // Deduplicate: non-whitelisted cross-origin preloads are downgraded to preconnects.
  // URL-only strongest-wins dedup: same URL key = same resource.
  // If a preload/modulepreload and preconnect share the same URL, the stronger
  // type wins (preload > preconnect). This prevents sending redundant hints
  // when the same origin appears both as a whitelisted preload and as a
  // preconnect derived from a non-whitelisted cross-origin resource.
  // Host comparison is case-insensitive (RFC 4343); path is case-sensitive (RFC 3986 section 6.2.2.1).
  {
    size_t url_end = result.find('>');
    if (url_end != std::string::npos) {
      std::string result_url_key = lowercase_url_host(result.substr(0, url_end + 1));
      // Scanner constructs rel= values in lowercase, so a literal find is safe.
      bool incoming_is_preload = result.find("rel=preconnect") == std::string::npos;

      auto it = dedup_index_.find(result_url_key);
      if (it == dedup_index_.end()) {
        // New URL: record index and add to links_.
        dedup_index_.emplace(std::move(result_url_key), links_.size());
      } else {
        size_t existing_idx = it->second;
        if (incoming_is_preload && links_[existing_idx].find("rel=preconnect") != std::string::npos) {
          // Incoming is stronger: replace existing preconnect with preload.
          links_[existing_idx] = std::move(result);
        }
        // Same URL already queued (same or stronger type): skip.
        return;
      }
    }
  }

  links_.push_back(std::move(result));
}

void
HtmlScanner::process_tag()
{
  std::string tag = tolower_str(tag_name_);

  // <body> implicitly closes <head> per HTML spec §13.2.5.6
  if (tag == "body") {
    state_ = State::DONE;
    return;
  }

  // If any attribute value exceeded MAX_ATTR_VALUE_LEN, the tag is tainted:
  // a truncated href would produce a corrupt URL in the Link header. Discard.
  if (attr_overflowed_) {
    return;
  }

  // Only process <link> and <script> tags
  if (tag == "link" || tag == "script") {
    build_link_header(tag);
  }
}

// Determine next state after processing an opening tag.
// <script> and <style> are raw text elements per HTML spec §13.1.2.6 —
// skip body until the matching closing tag.
HtmlScanner::State
HtmlScanner::state_after_open_tag()
{
  if (tag_name_.size() == 6 && strncasecmp(tag_name_.c_str(), "script", 6) == 0) {
    raw_close_pos_      = 0;
    raw_close_tag_      = "</script";
    script_escaped_     = false;
    script_comment_pos_ = 0;
    return State::IN_SCRIPT;
  }
  if (tag_name_.size() == 5 && strncasecmp(tag_name_.c_str(), "style", 5) == 0) {
    raw_close_pos_      = 0;
    raw_close_tag_      = "</style";
    script_escaped_     = false;
    script_comment_pos_ = 0;
    return State::IN_SCRIPT;
  }
  // <noscript> contains fallback content for JS-disabled environments. When JS
  // is enabled (the common case) the browser ignores it entirely, so preloading
  // resources inside it wastes bandwidth. Skip the body to prevent cache poisoning.
  if (tag_name_.size() == 8 && strncasecmp(tag_name_.c_str(), "noscript", 8) == 0) {
    raw_close_pos_      = 0;
    raw_close_tag_      = "</noscript";
    script_escaped_     = false;
    script_comment_pos_ = 0;
    return State::IN_SCRIPT;
  }
  // <template> contains inert DOM — it is never rendered or fetched on page load.
  // Resources referenced inside it must not be pre-fetched via Early Hints.
  if (tag_name_.size() == 8 && strncasecmp(tag_name_.c_str(), "template", 8) == 0) {
    raw_close_pos_      = 0;
    raw_close_tag_      = "</template";
    script_escaped_     = false;
    script_comment_pos_ = 0;
    return State::IN_SCRIPT;
  }
  // RCDATA elements per HTML5 spec section 13.2.6.1: <title>, <textarea>, and the
  // obsolete <xmp> element have content that is NOT parsed as HTML markup.
  // A <link rel=preload> inside <title>...</title> is literal text shown to
  // the user, not a resource hint.  Parsing it as a hint is a spec violation
  // and could leak unintended URLs.
  if (tag_name_.size() == 5 && strncasecmp(tag_name_.c_str(), "title", 5) == 0) {
    raw_close_pos_      = 0;
    raw_close_tag_      = "</title";
    script_escaped_     = false;
    script_comment_pos_ = 0;
    return State::IN_SCRIPT;
  }
  if (tag_name_.size() == 8 && strncasecmp(tag_name_.c_str(), "textarea", 8) == 0) {
    raw_close_pos_      = 0;
    raw_close_tag_      = "</textarea";
    script_escaped_     = false;
    script_comment_pos_ = 0;
    return State::IN_SCRIPT;
  }
  if (tag_name_.size() == 3 && strncasecmp(tag_name_.c_str(), "xmp", 3) == 0) {
    raw_close_pos_      = 0;
    raw_close_tag_      = "</xmp";
    script_escaped_     = false;
    script_comment_pos_ = 0;
    return State::IN_SCRIPT;
  }
  return State::IN_HEAD;
}

void
HtmlScanner::feed(const char *data, int64_t length)
{
  if (state_ == State::DONE || data == nullptr || length <= 0) {
    return;
  }

  for (int64_t i = 0; i < length && state_ != State::DONE; i++) {
    char c = data[i];
    scanned_++;

    if (scanned_ > limit_) {
      state_ = State::DONE;
      return;
    }

    switch (state_) {
    case State::INIT:
      // Looking for <head> or <head ...> (case-insensitive)
      // Must NOT match <header>, <heading>, etc.
      if (c == '<') {
        match_buf_.clear();
        match_buf_ += c;
      } else if (!match_buf_.empty()) {
        // Cap buffer growth: only accumulate up to 6 chars (enough for the
        // "<head" + separator check).  Beyond that we just scan for '>'.
        if (match_buf_.size() <= 6) {
          match_buf_ += c;
        }
        if (match_buf_.size() <= 5) {
          // Building up: <head or <HEAD etc. — compare without allocation
          static const char head_tag[] = "<head";
          if (std::tolower(static_cast<unsigned char>(c)) != head_tag[match_buf_.size() - 1]) {
            match_buf_.clear();
          }
          // At exactly size 5 ("<head"), keep building to verify next char
        } else if (match_buf_.size() == 6) {
          // The 6th char (after "<head") must be > or whitespace, NOT alpha
          // This distinguishes <head> from <header>, <heading>, etc.
          if (c == '>') {
            state_ = State::IN_HEAD;
            match_buf_.clear();
          } else if (std::isspace(static_cast<unsigned char>(c))) {
            // <head ...> with attributes — keep scanning for >
          } else {
            // <header> or other — not a <head> tag
            match_buf_.clear();
          }
        } else {
          // size > 6: we're inside <head ...>, looking for >
          if (c == '>') {
            state_ = State::IN_HEAD;
            match_buf_.clear();
          }
          // Keep reading until we find >
        }
      }
      break;

    case State::IN_HEAD:
      if (c == '<') {
        if (match_buf_ == "<!-") {
          // <!- followed by non-'-' (the '<' here) → bogus comment per spec §13.2.5.42
          state_ = State::IN_BOGUS_COMMENT;
          match_buf_.clear();
        } else {
          match_buf_.clear();
          match_buf_ += c;
          in_closing_tag_ = false;
        }
      } else if (!match_buf_.empty()) {
        if (match_buf_.size() == 1 && c == '!') {
          // Could be start of <!-- comment
          match_buf_ += c;
        } else if (match_buf_ == "<!" && c == '-') {
          match_buf_ += c;
        } else if (match_buf_ == "<!" && c != '-') {
          // Per HTML spec §13.2.5.42: <![CDATA[, <!DOCTYPE, etc. in HTML
          // context are "bogus comments" — skip everything until next '>'.
          if (c == '>') {
            // Immediately closed: <!x>
            match_buf_.clear();
          } else {
            state_ = State::IN_BOGUS_COMMENT;
            match_buf_.clear();
          }
        } else if (match_buf_ == "<!-" && c == '-') {
          // Entering HTML comment <!-- -->
          // Use comment start state (5) per HTML spec §13.2.5.43:
          //   5: comment start (next char after "<!--")
          //      '>' → abrupt close, '-' → start dash (6), else → comment body (0)
          //   6: comment start dash (seen one '-' in start state)
          //      '>' → abrupt close, '-' → end state (2), else → comment body (0)
          state_          = State::IN_COMMENT;
          comment_dashes_ = 5;
          match_buf_.clear();
        } else if (match_buf_ == "<!-" && c != '-') {
          // Per HTML spec §13.2.5.42: "<!" followed by a single "-" (not
          // "<!--") is a bogus comment.  Skip until '>'.
          if (c == '>') {
            match_buf_.clear();
          } else {
            state_ = State::IN_BOGUS_COMMENT;
            match_buf_.clear();
          }
        } else if (match_buf_.size() == 1 && c == '/') {
          in_closing_tag_ = true;
          match_buf_ += c;
        } else if (match_buf_.size() == 1 || (match_buf_.size() == 2 && in_closing_tag_)) {
          // Start of tag name
          if (std::isalpha(static_cast<unsigned char>(c))) {
            tag_name_.clear();
            tag_name_ += c;
            match_buf_.clear();

            state_ = State::IN_TAG;
          } else {
            match_buf_.clear();
            in_closing_tag_ = false;
          }
        } else {
          // Unexpected sequence (e.g., <!D for doctype inside head) — skip
          match_buf_.clear();
          in_closing_tag_ = false;
        }
      }
      break;

    case State::IN_COMMENT:
      // HTML spec §13.2.5.43-56 comment sub-states encoded in comment_dashes_:
      //   0: normal comment body
      //   1: seen one '-'
      //   2: seen '--' (comment end state; extra '-' stays here)
      //   3: seen '--!' (comment end bang state)
      //   4: seen '--!-' (comment end bang dash state)
      //   5: comment start state (just entered after "<!--")
      //   6: comment start dash state (seen '-' in start state)
      switch (comment_dashes_) {
      case 0:
        if (c == '-') {
          comment_dashes_ = 1;
        }
        break;
      case 1:
        comment_dashes_ = (c == '-') ? 2 : 0;
        break;
      case 2: // Comment end state (--): '>' closes, '!' enters bang, '-' stays, else resets
        if (c == '>') {
          state_          = State::IN_HEAD;
          comment_dashes_ = 0;
        } else if (c == '!') {
          comment_dashes_ = 3;
        } else if (c != '-') {
          comment_dashes_ = 0;
        }
        break;
      case 3: // Comment end bang state (--!): '>' closes, '-' enters bang-dash, else resets
        if (c == '>') {
          state_          = State::IN_HEAD;
          comment_dashes_ = 0;
        } else if (c == '-') {
          comment_dashes_ = 4;
        } else {
          comment_dashes_ = 0;
        }
        break;
      case 4: // Comment end bang dash state (--!-): '-' returns to end state, else resets
        comment_dashes_ = (c == '-') ? 2 : 0;
        break;
      case 5: // Comment start state (§13.2.5.43): '>' abrupt close, '-' → start dash, else → body
        if (c == '>') {
          state_          = State::IN_HEAD;
          comment_dashes_ = 0;
        } else if (c == '-') {
          comment_dashes_ = 6;
        } else {
          comment_dashes_ = 0;
        }
        break;
      case 6: // Comment start dash state (§13.2.5.44): '>' abrupt close, '-' → end state, else → body
        if (c == '>') {
          state_          = State::IN_HEAD;
          comment_dashes_ = 0;
        } else if (c == '-') {
          comment_dashes_ = 2;
        } else {
          comment_dashes_ = 0;
        }
        break;
      }
      break;

    case State::IN_BOGUS_COMMENT:
      // Per HTML spec §13.2.5.42: bogus comment ends at next '>'
      if (c == '>') {
        state_ = State::IN_HEAD;
      }
      break;

    case State::IN_SCRIPT: {
      // Skip raw text content until the matching close tag (case-insensitive).
      // HTML spec §13.2.6.2-6.3: if <!-- appears inside <script>, we enter
      // "script data escaped" state.  Per §13.2.6.4 ("script data escaped"
      // end tag name" state), </script> IS a valid end tag in escaped mode and
      // MUST close the script element.  Only --> additionally exits escaped mode
      // while keeping the script open.
      int tag_len = static_cast<int>(raw_close_tag_.size());

      if (script_escaped_) {
        // Track --> to exit escaped mode (returns to script data state).
        if (c == '-') {
          if (script_comment_pos_ < 2) {
            script_comment_pos_++;
          }
        } else if (c == '>' && script_comment_pos_ >= 2) {
          // --> complete: exit escaped mode, stay in IN_SCRIPT.
          script_escaped_     = false;
          script_comment_pos_ = 0;
          raw_close_pos_      = 0;
          break;
        } else {
          script_comment_pos_ = 0;
        }

        // Track </script> close-tag sequence even in escaped mode.
        // Per HTML spec §13.2.6.4, </script> is a valid end tag in escaped
        // state and must close the script element.
        if (raw_close_pos_ == 0) {
          if (c == '<') {
            raw_close_pos_ = 1;
          }
        } else if (raw_close_pos_ == 1) {
          if (c == '/') {
            raw_close_pos_ = 2;
          } else if (c != '<') {
            raw_close_pos_ = 0;
          }
        } else if (raw_close_pos_ >= 2 && raw_close_pos_ < tag_len) {
          char expected = raw_close_tag_[raw_close_pos_];
          if (std::tolower(static_cast<unsigned char>(c)) == std::tolower(static_cast<unsigned char>(expected))) {
            raw_close_pos_++;
          } else {
            raw_close_pos_ = (c == '<') ? 1 : 0;
          }
        } else if (raw_close_pos_ == tag_len) {
          // Matched full close-tag name in escaped mode — check for valid separator.
          if (c == '>') {
            state_              = State::IN_HEAD;
            script_escaped_     = false;
            script_comment_pos_ = 0;
            raw_close_pos_      = 0;
          } else if (c == '/' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == ' ') {
            raw_close_pos_ = tag_len + 1;
          } else if (c == '<') {
            raw_close_pos_ = 1;
          } else {
            raw_close_pos_ = 0;
          }
        } else {
          // raw_close_pos_ > tag_len: inside trailing content, waiting for >
          if (c == '>') {
            state_              = State::IN_HEAD;
            script_escaped_     = false;
            script_comment_pos_ = 0;
            raw_close_pos_      = 0;
          } else if (c == '<') {
            raw_close_pos_ = 1;
          }
        }
        break;
      }

      // Not escaped — track both <!-- (comment open) and </script> (close tag).
      // Per HTML spec §13.2.6.4: '<' branches to either path:
      //   '<' + '/' → close-tag matching
      //   '<' + '!' → comment-open matching (then need --)
      //   '<' + other → back to normal script data
      if (raw_close_pos_ == 0 && script_comment_pos_ == 0) {
        // Idle: looking for '<'
        if (c == '<') {
          raw_close_pos_      = 1; // '<' could start either path
          script_comment_pos_ = 0;
        }
      } else if (raw_close_pos_ == 1 && script_comment_pos_ == 0) {
        // Saw '<': next char decides which path
        if (c == '/') {
          raw_close_pos_ = 2; // start close-tag path: "</..."
        } else if (c == '!') {
          script_comment_pos_ = 1; // start comment-open path: "<!"
          raw_close_pos_      = 0;
        } else {
          raw_close_pos_ = (c == '<') ? 1 : 0;
        }
      } else if (script_comment_pos_ > 0) {
        // Comment-open path: matching "<!" then "--"
        if (script_comment_pos_ == 1 && c == '-') {
          script_comment_pos_ = 2; // "<!-"
        } else if (script_comment_pos_ == 2 && c == '-') {
          // "<!--" complete — enter escaped mode
          script_escaped_     = true;
          script_comment_pos_ = 0;
        } else {
          // Failed to match "<!--"
          script_comment_pos_ = 0;
          raw_close_pos_      = (c == '<') ? 1 : 0;
        }
      } else if (raw_close_pos_ >= 2 && raw_close_pos_ < tag_len) {
        // Close-tag path: matching "</script" byte by byte
        char expected = raw_close_tag_[raw_close_pos_];
        if (std::tolower(static_cast<unsigned char>(c)) == std::tolower(static_cast<unsigned char>(expected))) {
          raw_close_pos_++;
        } else {
          raw_close_pos_ = (c == '<') ? 1 : 0;
        }
      } else if (raw_close_pos_ == tag_len) {
        // Matched full close tag name — next char determines if valid end tag.
        // Per HTML spec §13.2.6.3: tab/LF/FF/space, '/', '>' are valid.
        if (c == '>') {
          state_              = State::IN_HEAD;
          raw_close_pos_      = 0;
          script_comment_pos_ = 0;
        } else if (c == '/' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
                   c == ' ') { // \r is valid ASCII whitespace per HTML spec §13.2.6
          raw_close_pos_ = tag_len + 1;
        } else if (c == '<') {
          raw_close_pos_ = 1;
        } else {
          raw_close_pos_ = 0;
        }
      } else {
        // pos > tag_len: Inside trailing content of close tag, waiting for >
        if (c == '>') {
          state_              = State::IN_HEAD;
          raw_close_pos_      = 0;
          script_comment_pos_ = 0;
        } else if (c == '<') {
          raw_close_pos_ = 1;
        }
      }
      break;
    }

    case State::IN_TAG:
      if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') {
        if (tag_name_.size() < MAX_TAG_NAME_LEN) {
          tag_name_ += c;
        }
      } else if (c == '>') {
        // Tag closed — check if it's </head>
        if (in_closing_tag_) {
          if (tag_name_.size() == 4 && strncasecmp(tag_name_.c_str(), "head", 4) == 0) {
            state_ = State::DONE;
            return;
          }
        } else {
          process_tag();
        }
        // If process_tag set state to DONE (e.g., <body>), stop immediately
        if (state_ == State::DONE) {
          return;
        }
        // Check BEFORE reset: opening <script> enters raw text mode
        State next = in_closing_tag_ ? State::IN_HEAD : state_after_open_tag();
        reset_tag_state();
        state_ = next;
        // Self-closing: <link ... />
        // Don't do anything yet, wait for >
      } else if (std::isspace(static_cast<unsigned char>(c))) {
        // After tag name, before attributes
        if (!tag_name_.empty()) {
          state_ = State::IN_ATTR_NAME;
          attr_name_.clear();
        }
      } else {
        // Unexpected character in tag name
        reset_tag_state();
        state_ = State::IN_HEAD;
      }
      break;

    case State::IN_ATTR_NAME:
      if (c == '=') {
        state_ = State::IN_ATTR_VALUE;
        attr_value_.clear();
        quote_char_ = 0;
      } else if (c == '>') {
        // Boolean attribute at end of tag (e.g., <script async>)
        if (!attr_name_.empty()) {
          attr_value_.clear();
          finish_attr();
        }
        if (in_closing_tag_) {
          if (tag_name_.size() == 4 && strncasecmp(tag_name_.c_str(), "head", 4) == 0) {
            state_ = State::DONE;
            return;
          }
        } else {
          process_tag();
        }
        if (state_ == State::DONE) {
          return;
        }
        {
          State next = in_closing_tag_ ? State::IN_HEAD : state_after_open_tag();
          reset_tag_state();
          state_ = next;
        }
      } else if (std::isspace(static_cast<unsigned char>(c))) {
        if (!attr_name_.empty()) {
          // Space after attr name — could be boolean attr OR space before '='
          // Transition to IN_ATTR_SEP to disambiguate
          state_ = State::IN_ATTR_SEP;
        }
        // If attr_name_ is empty, stay here (whitespace between attrs)
      } else {
        if (attr_name_.size() < MAX_ATTR_NAME_LEN) {
          attr_name_ += c;
        }
      }
      break;

    case State::IN_ATTR_SEP:
      // After attr name + whitespace: waiting for '=' or next attr/tag end
      // Handles HTML spec §13.1.2.3: optional whitespace around '='
      if (c == '=') {
        // It was "name = value", not a boolean attr
        state_ = State::IN_ATTR_VALUE;
        attr_value_.clear();
        quote_char_ = 0;
      } else if (c == '>') {
        // Boolean attribute at end of tag
        attr_value_.clear();
        finish_attr();
        if (in_closing_tag_) {
          if (tag_name_.size() == 4 && strncasecmp(tag_name_.c_str(), "head", 4) == 0) {
            state_ = State::DONE;
            return;
          }
        } else {
          process_tag();
        }
        if (state_ == State::DONE) {
          return;
        }
        {
          State next = in_closing_tag_ ? State::IN_HEAD : state_after_open_tag();
          reset_tag_state();
          state_ = next;
        }
      } else if (std::isspace(static_cast<unsigned char>(c))) {
        // More whitespace — keep waiting
      } else {
        // New attribute name started — previous was boolean
        attr_value_.clear();
        finish_attr();
        attr_name_.clear();
        attr_name_ += c;
        state_ = State::IN_ATTR_NAME;
      }
      break;

    case State::IN_ATTR_VALUE:
      if (quote_char_ == 0) {
        // Haven't seen a quote yet
        if (c == '"' || c == '\'') {
          quote_char_ = c;
        } else if (std::isspace(static_cast<unsigned char>(c))) {
          if (attr_value_.empty()) {
            // Leading whitespace after '=' — skip (HTML spec §13.1.2.3)
          } else {
            // Unquoted attribute value ended
            finish_attr();
            state_ = State::IN_ATTR_NAME;
            attr_name_.clear();
          }
        } else if (c == '>') {
          // Unquoted attribute value ended at tag close
          finish_attr();
          if (in_closing_tag_) {
            if (tag_name_.size() == 4 && strncasecmp(tag_name_.c_str(), "head", 4) == 0) {
              state_ = State::DONE;
              return;
            }
          } else {
            process_tag();
          }
          if (state_ == State::DONE) {
            return;
          }
          {
            State next = in_closing_tag_ ? State::IN_HEAD : state_after_open_tag();
            reset_tag_state();
            state_ = next;
          }
        } else {
          // Unquoted attribute value
          if (static_cast<int>(attr_value_.size()) < MAX_ATTR_VALUE_LEN) {
            attr_value_ += c;
          } else {
            // Value exceeds limit — mark tag as tainted so the whole tag is rejected.
            // Silently truncating would emit a corrupt URL in the Link header.
            attr_overflowed_ = true;
          }
        }
      } else {
        // Inside quoted value
        if (c == quote_char_) {
          // End of quoted value
          finish_attr();
          quote_char_ = 0;
          state_      = State::IN_ATTR_NAME;
          attr_name_.clear();
        } else {
          if (static_cast<int>(attr_value_.size()) < MAX_ATTR_VALUE_LEN) {
            attr_value_ += c;
          } else {
            // Value exceeds limit — mark tag as tainted.
            attr_overflowed_ = true;
          }
        }
      }
      break;

    case State::DONE:
      return;
    }
  }
}
