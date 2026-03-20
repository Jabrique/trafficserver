/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include "manifest.h"
#include "config.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

/**
 * Extract JWS token from Set-Cookie header.
 *
 * BUG #4 FIX: Refactored extraction logic into reusable helper function.
 * This allows us to extract tokens from both Set-Cookie (renewal) and
 * original validated tokens for manifest injection.
 *
 * Set-Cookie format: "param_name=JWS_TOKEN; Path=/; HttpOnly; Secure"
 * Extracts only the JWS_TOKEN part (between '=' and ';').
 *
 * @param set_cookie_header Full Set-Cookie header value
 * @return Allocated JWS token string (caller must free()), or NULL on error
 */
char *
extract_jws_from_set_cookie(const char *set_cookie_header)
{
  /* Defensive: Check NULL input */
  if (!set_cookie_header) {
    return NULL;
  }

  /* Defensive: Check empty string */
  if (set_cookie_header[0] == '\0') {
    return NULL;
  }

  /* Find the '=' sign (separates param_name from token) */
  const char *token_start = strchr(set_cookie_header, '=');
  if (!token_start) {
    /* Invalid format: no '=' sign */
    return NULL;
  }

  /* Skip the '=' to get to token start */
  token_start++;

  /* Find the ';' sign (separates token from cookie attributes) */
  const char *token_end = strchr(token_start, ';');
  if (!token_end) {
    /* No semicolon found - token extends to end of string */
    token_end = set_cookie_header + strlen(set_cookie_header);
  }

  /* Calculate token length */
  size_t token_len = token_end - token_start;

  /* Defensive: Empty token */
  if (token_len == 0) {
    return NULL;
  }

  /* Allocate memory for token (+1 for null terminator) */
  char *jws_token = (char *)malloc(token_len + 1);
  if (!jws_token) {
    /* Memory allocation failed */
    return NULL;
  }

  /* Copy token to new buffer */
  memcpy(jws_token, token_start, token_len);
  jws_token[token_len] = '\0';

  return jws_token;
}

manifest_type_t
detect_manifest_type(const char *uri, const char *content_type)
{
  if (!uri) {
    return MANIFEST_TYPE_UNKNOWN;
  }

  /* Find path end (before query string '?' or fragment '#') */
  size_t uri_len  = strlen(uri);
  size_t path_len = uri_len;
  for (size_t i = 0; i < uri_len; i++) {
    if (uri[i] == '?' || uri[i] == '#') {
      path_len = i;
      break;
    }
  }

  /* Check file extension at end of path (not full URI) */
  if (path_len >= 5 && strncmp(uri + path_len - 5, ".m3u8", 5) == 0) {
    return MANIFEST_TYPE_HLS_M3U8;
  }
  if (path_len >= 4 && strncmp(uri + path_len - 4, ".mpd", 4) == 0) {
    return MANIFEST_TYPE_DASH_MPD;
  }

  /* Check Content-Type header */
  if (content_type) {
    if (strstr(content_type, "application/vnd.apple.mpegurl") || strstr(content_type, "application/x-mpegURL")) {
      return MANIFEST_TYPE_HLS_M3U8;
    }
    if (strstr(content_type, "application/dash+xml")) {
      return MANIFEST_TYPE_DASH_MPD;
    }
  }

  return MANIFEST_TYPE_UNKNOWN;
}

bool
is_segment_url(const char *line)
{
  if (!line || !*line) {
    return false;
  }

  /* Skip whitespace */
  while (isspace(*line)) {
    line++;
  }

  /* Empty line or comment */
  if (!*line || *line == '#') {
    return false;
  }

  /* It's a URL line */
  return true;
}

bool
is_init_segment(const char *line)
{
  if (!line) {
    return false;
  }

  /* Check for EXT-X-MAP tag (init segment) */
  return strstr(line, "#EXT-X-MAP:") != NULL;
}

char *
extract_uri_from_map_tag(const char *map_line)
{
  if (!map_line) {
    return NULL;
  }

  /* Find URI=" or URI=' */
  const char *uri_start = strstr(map_line, "URI=\"");
  char quote            = '"';
  if (!uri_start) {
    uri_start = strstr(map_line, "URI='");
    quote     = '\'';
  }
  if (!uri_start) {
    return NULL;
  }

  uri_start += 5; /* Skip URI=" or URI=' */

  /* Find closing quote */
  const char *uri_end = strchr(uri_start, quote);
  if (!uri_end) {
    return NULL;
  }

  size_t uri_len = uri_end - uri_start;
  char *uri      = malloc(uri_len + 1);
  if (!uri) {
    return NULL;
  }

  memcpy(uri, uri_start, uri_len);
  uri[uri_len] = '\0';
  return uri;
}

static char *
duplicate_string(const char *str)
{
  if (!str) {
    return NULL;
  }
  size_t len = strlen(str);
  char *copy = malloc(len + 1);
  if (!copy) {
    return NULL;
  }
  memcpy(copy, str, len);
  copy[len] = '\0';
  return copy;
}

/* Forward declaration */
char *strip_param_from_url(const char *url, const char *param_name);

char *
inject_token_into_map_tag(const char *map_line, const char *token, const char *param_name, const char *access_token_name,
                          bool replace_access_token)
{
  if (!map_line || !token || !param_name) {
    return NULL;
  }

  /* Extract the URI from the tag */
  char *original_uri = extract_uri_from_map_tag(map_line);
  if (!original_uri) {
    /* Can't parse URI, return copy of original line */
    return duplicate_string(map_line);
  }

  /* Strip access token if replace is enabled */
  char *uri_to_process = original_uri;
  if (replace_access_token && access_token_name) {
    char *stripped_uri = strip_param_from_url(original_uri, access_token_name);
    if (stripped_uri) {
      free(original_uri);
      uri_to_process = stripped_uri;
      PluginDebug("HLS: Replaced access token '%s' in EXT-X-MAP", access_token_name);
    }
  }

  /* Strip existing session token to prevent duplication */
  char *uri_without_session = strip_param_from_url(uri_to_process, param_name);
  if (uri_without_session) {
    free(uri_to_process);
    uri_to_process = uri_without_session;
    PluginDebug("HLS: Stripped existing session token '%s' from EXT-X-MAP", param_name);
  }

  /* Add token to the URI */
  char *new_uri = add_token_to_url(uri_to_process, token, param_name);
  free(uri_to_process);
  if (!new_uri) {
    return duplicate_string(map_line);
  }

  /* Find the URI quote positions in the original line */
  const char *uri_quote_start = strstr(map_line, "URI=\"");
  char quote                  = '"';
  if (!uri_quote_start) {
    uri_quote_start = strstr(map_line, "URI='");
    quote           = '\'';
  }
  if (!uri_quote_start) {
    free(new_uri);
    return duplicate_string(map_line);
  }

  uri_quote_start += 5; /* Point to char after URI=" */
  const char *uri_quote_end = strchr(uri_quote_start, quote);
  if (!uri_quote_end) {
    free(new_uri);
    return duplicate_string(map_line);
  }

  /* Build new line: before_URI + "URI=\"" + new_uri + "\"" + after_quote */
  size_t prefix_len = (uri_quote_start - 5) - map_line;                      /* Length before URI=" */
  size_t suffix_len = strlen(uri_quote_end + 1);                             /* Length after closing quote */
  size_t new_len    = prefix_len + 5 + strlen(new_uri) + 1 + suffix_len + 1; /* prefix + URI=" + new_uri + " + suffix + \0 */

  char *new_line = malloc(new_len);
  if (!new_line) {
    free(new_uri);
    return duplicate_string(map_line);
  }

  snprintf(new_line, new_len, "%.*sURI=\"%s\"%s", (int)prefix_len, map_line, new_uri, uri_quote_end + 1);
  free(new_uri);
  return new_line;
}

/* Strip a query parameter from URL
 * Returns new URL without the specified parameter, or NULL on error
 * Caller must free the returned string
 */
char *
strip_param_from_url(const char *url, const char *param_name)
{
  if (!url || !param_name) {
    return NULL;
  }

  size_t url_len        = strlen(url);
  size_t param_name_len = strlen(param_name);

  /* Find query string start */
  const char *query_start = strchr(url, '?');
  if (!query_start) {
    /* No query string, return copy of original URL */
    return duplicate_string(url);
  }

  /* Calculate base URL length (before '?') */
  size_t base_len = query_start - url;

  /* Build search pattern: "param_name=" */
  char search_pattern[300]; /* 256 for param name + 10 for safety */
  if (param_name_len > 256) {
    PluginError("Parameter name too long: %zu", param_name_len);
    return duplicate_string(url);
  }
  snprintf(search_pattern, sizeof(search_pattern), "%s=", param_name);
  size_t pattern_len = strlen(search_pattern);

  /* Search for parameter in query string */
  const char *param_pos = query_start + 1; /* Start after '?' */
  const char *found     = NULL;

  while ((param_pos = strstr(param_pos, search_pattern)) != NULL) {
    /* Check if this is the start of the query string or after '&' */
    if (param_pos == query_start + 1 || *(param_pos - 1) == '&') {
      found = param_pos;
      break;
    }
    param_pos += pattern_len;
  }

  if (!found) {
    /* Parameter not found, return copy of original URL */
    return duplicate_string(url);
  }

  /* Find the end of this parameter value */
  /* Stop at '&' (next param) or '#' (fragment identifier per RFC 3986) */
  const char *param_end = found;
  while (*param_end && *param_end != '&' && *param_end != '#') {
    param_end++;
  }

  /* Build new URL without this parameter */
  size_t new_size = url_len + 1; /* Overestimate, will be smaller */
  char *new_url   = malloc(new_size);
  if (!new_url) {
    PluginError("Failed to allocate memory for URL");
    return duplicate_string(url);
  }

  /* Copy base URL (before '?') */
  memcpy(new_url, url, base_len);
  size_t pos = base_len;

  /* Check if parameter is first in query string */
  bool is_first_param = (found == query_start + 1);

  if (is_first_param) {
    /* Parameter is first: skip it and handle remaining params */
    if (*param_end == '&') {
      /* More params after this one: "?param=value&other=..." -> "?other=..." */
      new_url[pos++]        = '?';
      const char *remaining = param_end + 1; /* Skip the '&' */
      strcpy(new_url + pos, remaining);
    } else if (*param_end == '#') {
      /* Fragment after param: "?param=value#frag" -> "#frag" */
      strcpy(new_url + pos, param_end);
    } else if (param_end > query_start + 1) {
      /* Only this param: "?param=value" -> "" */
      new_url[pos] = '\0';
    }
  } else {
    /* Parameter is not first: remove it and preceding '&' */
    /* Copy everything from '?' up to (but not including) the '&' before param */
    size_t before_len = (found - 1) - query_start; /* -1 to exclude '&' before param */
    memcpy(new_url + pos, query_start, before_len);
    pos += before_len;

    /* Copy everything after this param */
    if (*param_end == '&') {
      /* More params after: keep them */
      strcpy(new_url + pos, param_end);
    } else if (*param_end == '#') {
      /* Fragment after param: "?a=1&param=value#frag" -> "?a=1#frag" */
      strcpy(new_url + pos, param_end);
    } else {
      /* This was the last param */
      new_url[pos] = '\0';
    }
  }

  return new_url;
}

char *
add_token_to_url(const char *url, const char *token, const char *param_name)
{
  if (!url || !token || !param_name) {
    return NULL;
  }

  /* Skip leading/trailing whitespace */
  while (isspace(*url)) {
    url++;
  }
  size_t url_len = strlen(url);
  while (url_len > 0 && isspace(url[url_len - 1])) {
    url_len--;
  }

  if (url_len == 0) {
    return NULL;
  }

  size_t token_len      = strlen(token);
  size_t param_name_len = strlen(param_name);

  /* Security: Check for integer overflow in size calculation
   * Same limits as DASH injection for consistency
   */
  if (url_len > 8192 || token_len > 4096 || param_name_len > 256) {
    PluginError("HLS: URL/token/param too long (url=%zu, token=%zu, param=%zu)", url_len, token_len, param_name_len);
    return NULL;
  }

  /* RFC 3986: Fragment identifier (#fragment) must come AFTER query string
   * URL structure: scheme://authority/path?query#fragment
   * We need to detect fragment and insert token before it
   */
  size_t base_url_len       = url_len;
  const char *fragment_part = NULL;
  size_t fragment_len       = 0;

  /* Find fragment separator */
  for (size_t i = 0; i < url_len; i++) {
    if (url[i] == '#') {
      base_url_len  = i;
      fragment_part = &url[i + 1]; /* Skip '#' */
      fragment_len  = url_len - i - 1;
      break;
    }
  }

  /* Determine if BASE URL (without fragment) already has query parameters */
  const char *query_start = NULL;
  for (size_t i = 0; i < base_url_len; i++) {
    if (url[i] == '?') {
      query_start = &url[i];
      break;
    }
  }
  char separator = query_start ? '&' : '?';

  /* Calculate new size: base_url + separator + param=token + # + fragment */
  size_t new_size = base_url_len + 1 + param_name_len + 1 + token_len;
  if (fragment_part) {
    new_size += 1 + fragment_len; /* '#' + fragment */
  }
  new_size += 1; /* null terminator */

  char *new_url = malloc(new_size);
  if (!new_url) {
    PluginError("HLS: Failed to allocate %zu bytes for URL", new_size);
    return NULL;
  }

  /* Build new URL: base_url + separator + param=token + #fragment */
  if (fragment_part) {
    snprintf(new_url, new_size, "%.*s%c%s=%s#%.*s", (int)base_url_len, url, separator, param_name, token, (int)fragment_len,
             fragment_part);
  } else {
    snprintf(new_url, new_size, "%.*s%c%s=%s", (int)base_url_len, url, separator, param_name, token);
  }

  return new_url;
}

char *
inject_token_hls(const char *manifest_body, size_t body_len, const char *token, const char *param_name,
                 const char *access_token_name, struct manifest_injection_config *cfg, size_t *new_len)
{
  if (!manifest_body || !token || !param_name || !cfg || !new_len) {
    return NULL;
  }

  *new_len = 0;

  /* Estimate output size generously: input + token_length * 50 potential segments */
  size_t token_addition_size = strlen(token) + strlen(param_name) + 2; /* ?param=token or &param=token */

  /* Security: Prevent integer overflow in size calculation */
  size_t token_total;
  if (__builtin_mul_overflow(token_addition_size, 50, &token_total)) {
    PluginError("HLS: Token size too large for manifest injection");
    return NULL;
  }

  size_t estimated_size;
  if (__builtin_add_overflow(body_len, token_total, &estimated_size)) {
    PluginError("HLS: Manifest body too large for injection (body=%zu, token_total=%zu)", body_len, token_total);
    return NULL;
  }

  char *output = malloc(estimated_size + 1); /* +1 for null terminator */
  if (!output) {
    PluginError("HLS: Failed to allocate %zu bytes for output", estimated_size + 1);
    return NULL;
  }

  size_t output_pos      = 0;
  const char *line_start = manifest_body;
  const char *line_end;

  while (line_start < manifest_body + body_len) {
    /* Find line end */
    line_end = line_start;
    while (line_end < manifest_body + body_len && *line_end != '\n' && *line_end != '\r') {
      line_end++;
    }

    size_t line_len = line_end - line_start;

    /* Copy line to temp buffer for processing */
    char line_buf[4096];
    if (line_len >= sizeof(line_buf)) {
      line_len = sizeof(line_buf) - 1;
    }
    memcpy(line_buf, line_start, line_len);
    line_buf[line_len] = '\0';

    /* Check if this is an init segment tag */
    bool is_map_tag = is_init_segment(line_buf);

    /* Handle EXT-X-MAP tags specially - they contain the URI inline */
    if (is_map_tag && cfg->inject_to_init_segments) {
      char *new_line = inject_token_into_map_tag(line_buf, token, param_name, access_token_name, cfg->replace_access_token);
      if (new_line) {
        size_t new_line_len = strlen(new_line);

        /* Ensure we have space */
        if (output_pos + new_line_len + 2 > estimated_size) {
          /* Security: Prevent integer overflow in realloc size calculation */
          size_t new_size;
          if (__builtin_mul_overflow(estimated_size, 2, &new_size)) {
            PluginError("HLS: Output buffer size overflow during realloc");
            free(new_line);
            free(output);
            return NULL;
          }
          char *new_output = realloc(output, new_size);
          if (!new_output) {
            free(new_line);
            free(output);
            return NULL;
          }
          output         = new_output;
          estimated_size = new_size;
        }

        /* Append modified line */
        memcpy(output + output_pos, new_line, new_line_len);
        output_pos += new_line_len;
        free(new_line);
      } else {
        /* Failed to modify, keep original */
        if (output_pos + line_len > estimated_size) {
          size_t new_size;
          if (__builtin_mul_overflow(estimated_size, 2, &new_size)) {
            PluginError("HLS: Output buffer size overflow");
            free(output);
            return NULL;
          }
          char *new_output = realloc(output, new_size);
          if (!new_output) {
            free(output);
            return NULL;
          }
          output         = new_output;
          estimated_size = new_size;
        }
        memcpy(output + output_pos, line_start, line_len);
        output_pos += line_len;
      }
    }
    /* Check if this is a regular segment URL that needs token injection */
    else if (is_segment_url(line_buf) && !is_map_tag && cfg->inject_to_segments) {
      /* Regular media segment */
      /* First, replace access token if configured */
      char *url_to_process = NULL;
      if (cfg->replace_access_token && access_token_name) {
        url_to_process = strip_param_from_url(line_buf, access_token_name);
        PluginDebug("HLS: Replaced access token '%s' in segment URL", access_token_name);
      } else {
        url_to_process = duplicate_string(line_buf);
      }

      /* Second, strip existing session token to prevent duplication */
      if (url_to_process) {
        char *url_without_session = strip_param_from_url(url_to_process, param_name);
        if (url_without_session) {
          free(url_to_process);
          url_to_process = url_without_session;
          PluginDebug("HLS: Stripped existing session token '%s' from segment URL", param_name);
        }
      }

      char *new_url = NULL;
      if (url_to_process) {
        new_url = add_token_to_url(url_to_process, token, param_name);
        free(url_to_process);
      }

      if (new_url) {
        size_t new_url_len = strlen(new_url);

        /* Ensure we have space */
        if (output_pos + new_url_len + 2 > estimated_size) {
          size_t new_size;
          if (__builtin_mul_overflow(estimated_size, 2, &new_size)) {
            PluginError("HLS: Output buffer size overflow");
            free(new_url);
            free(output);
            return NULL;
          }
          char *new_output = realloc(output, new_size);
          if (!new_output) {
            free(new_url);
            free(output);
            return NULL;
          }
          output         = new_output;
          estimated_size = new_size;
        }

        /* Append modified URL */
        memcpy(output + output_pos, new_url, new_url_len);
        output_pos += new_url_len;
        free(new_url);
      } else {
        /* Failed to add token, keep original */
        if (output_pos + line_len > estimated_size) {
          size_t new_size;
          if (__builtin_mul_overflow(estimated_size, 2, &new_size)) {
            PluginError("HLS: Output buffer size overflow");
            free(output);
            return NULL;
          }
          char *new_output = realloc(output, new_size);
          if (!new_output) {
            free(output);
            return NULL;
          }
          output         = new_output;
          estimated_size = new_size;
        }
        memcpy(output + output_pos, line_start, line_len);
        output_pos += line_len;
      }
    } else {
      /* Keep line as-is */
      if (output_pos + line_len > estimated_size) {
        size_t new_size;
        if (__builtin_mul_overflow(estimated_size, 2, &new_size)) {
          PluginError("HLS: Output buffer size overflow");
          free(output);
          return NULL;
        }
        char *new_output = realloc(output, new_size);
        if (!new_output) {
          free(output);
          return NULL;
        }
        output         = new_output;
        estimated_size = new_size;
      }
      memcpy(output + output_pos, line_start, line_len);
      output_pos += line_len;
    }

    /* Copy line ending */
    while (line_end < manifest_body + body_len && (*line_end == '\n' || *line_end == '\r')) {
      if (output_pos + 1 > estimated_size) {
        size_t new_size;
        if (__builtin_mul_overflow(estimated_size, 2, &new_size)) {
          PluginError("HLS: Output buffer size overflow");
          free(output);
          return NULL;
        }
        char *new_output = realloc(output, new_size);
        if (!new_output) {
          free(output);
          return NULL;
        }
        output         = new_output;
        estimated_size = new_size;
      }
      output[output_pos++] = *line_end;
      line_end++;
    }

    line_start = line_end;
  }

  output[output_pos] = '\0';
  *new_len           = output_pos;
  return output;
}

/* Helper function to add token to URL */
/* Helper to add token parameter to a URL
 * NOTE: This returns a plain URL string with & characters.
 * When set as XML content via xmlNodeSetContent(), libxml2 will
 * automatically escape & as &amp; during serialization.
 */
static char *
add_token_to_dash_url(const char *url, const char *token, const char *param_name)
{
  if (!url || !token || !param_name) {
    return NULL;
  }

  size_t url_len        = strlen(url);
  size_t token_len      = strlen(token);
  size_t param_name_len = strlen(param_name);

  /* Security: Check for integer overflow in size calculation
   * Maximum reasonable URL length is 8KB (spec allows up to 2KB for most browsers)
   * Token length should be < 4KB (JWTs are typically < 1KB)
   */
  if (url_len > 8192 || token_len > 4096 || param_name_len > 256) {
    PluginError("DASH: URL/token/param too long (url=%zu, token=%zu, param=%zu)", url_len, token_len, param_name_len);
    return NULL;
  }

  /* RFC 3986: Fragment identifier (#fragment) must come AFTER query string
   * URL structure: scheme://authority/path?query#fragment
   * We need to detect fragment and insert token before it
   */
  size_t base_url_len       = url_len;
  const char *fragment_part = NULL;
  size_t fragment_len       = 0;

  /* Find fragment separator */
  for (size_t i = 0; i < url_len; i++) {
    if (url[i] == '#') {
      base_url_len  = i;
      fragment_part = &url[i + 1]; /* Skip '#' */
      fragment_len  = url_len - i - 1;
      break;
    }
  }

  /* Determine if BASE URL (without fragment) already has query parameters */
  const char *query_start = NULL;
  for (size_t i = 0; i < base_url_len; i++) {
    if (url[i] == '?') {
      query_start = &url[i];
      break;
    }
  }
  char separator = query_start ? '&' : '?';

  /* Calculate new size: base_url + separator + param=token + # + fragment */
  size_t new_size = base_url_len + 1 + param_name_len + 1 + token_len;
  if (fragment_part) {
    new_size += 1 + fragment_len; /* '#' + fragment */
  }
  new_size += 1; /* null terminator */

  char *new_url = malloc(new_size);
  if (!new_url) {
    PluginError("DASH: Failed to allocate %zu bytes for URL", new_size);
    return NULL;
  }

  /* Build new URL: base_url + separator + param=token + #fragment */
  if (fragment_part) {
    snprintf(new_url, new_size, "%.*s%c%s=%s#%.*s", (int)base_url_len, url, separator, param_name, token, (int)fragment_len,
             fragment_part);
  } else {
    snprintf(new_url, new_size, "%.*s%c%s=%s", (int)base_url_len, url, separator, param_name, token);
  }

  return new_url;
}

/* Helper function to add token to DASH URL with optional access token replacement */
static char *
add_token_to_dash_url_with_replace(const char *url, const char *token, const char *param_name, const char *access_token_name,
                                   bool replace_access_token)
{
  if (!url || !token || !param_name) {
    return NULL;
  }

  /* Strip access token if replace is enabled */
  char *url_to_process = NULL;
  if (replace_access_token && access_token_name) {
    url_to_process = strip_param_from_url(url, access_token_name);
    if (url_to_process) {
      PluginDebug("DASH: Replaced access token '%s' in URL", access_token_name);
    }
  }

  if (!url_to_process) {
    url_to_process = duplicate_string(url);
  }

  /* Strip existing session token to prevent duplication */
  if (url_to_process) {
    char *url_without_session = strip_param_from_url(url_to_process, param_name);
    if (url_without_session) {
      free(url_to_process);
      url_to_process = url_without_session;
      PluginDebug("DASH: Stripped existing session token '%s' from URL", param_name);
    }
  }

  char *new_url = NULL;
  if (url_to_process) {
    new_url = add_token_to_dash_url(url_to_process, token, param_name);
    free(url_to_process);
  }

  return new_url;
}

/* Recursively process XML nodes to inject tokens */
static void
process_dash_node(xmlNode *node, const char *token, const char *param_name, const char *access_token_name,
                  struct manifest_injection_config *cfg)
{
  if (!node || !token || !param_name || !cfg) {
    return;
  }

  for (xmlNode *cur = node; cur; cur = cur->next) {
    if (cur->type == XML_ELEMENT_NODE) {
      /* Handle BaseURL elements */
      if (xmlStrcmp(cur->name, (const xmlChar *)"BaseURL") == 0) {
        xmlChar *content = xmlNodeGetContent(cur);
        if (content) {
          char *url_with_token = add_token_to_dash_url_with_replace((const char *)content, token, param_name, access_token_name,
                                                                    cfg->replace_access_token);
          if (url_with_token) {
            /* xmlNodeSetContent on ELEMENT nodes calls xmlStringGetNodeList which
             * parses entity references. Pre-encode with xmlEncodeSpecialChars to
             * ensure bare & in URLs are properly represented as &amp; entities. */
            xmlChar *encoded = xmlEncodeSpecialChars(cur->doc, (const xmlChar *)url_with_token);
            if (encoded) {
              xmlNodeSetContent(cur, encoded);
              xmlFree(encoded);
            } else {
              xmlNodeSetContent(cur, (const xmlChar *)url_with_token);
            }
            PluginDebug("DASH: Injected token into BaseURL: %s", url_with_token);
            free(url_with_token);
          }
          xmlFree(content);
        }
      }

      /* Handle SegmentTemplate elements */
      if (xmlStrcmp(cur->name, (const xmlChar *)"SegmentTemplate") == 0) {
        /* Inject into media attribute if configured */
        if (cfg->inject_to_segments) {
          xmlChar *media = xmlGetProp(cur, (const xmlChar *)"media");
          if (media) {
            char *media_with_token = add_token_to_dash_url_with_replace((const char *)media, token, param_name, access_token_name,
                                                                        cfg->replace_access_token);
            if (media_with_token) {
              xmlSetProp(cur, (const xmlChar *)"media", (const xmlChar *)media_with_token);
              PluginDebug("DASH: Injected token into SegmentTemplate media: %s", media_with_token);
              free(media_with_token);
            }
            xmlFree(media);
          }
        }

        /* Inject into initialization attribute if configured */
        if (cfg->inject_to_init_segments) {
          xmlChar *init = xmlGetProp(cur, (const xmlChar *)"initialization");
          if (init) {
            char *init_with_token = add_token_to_dash_url_with_replace((const char *)init, token, param_name, access_token_name,
                                                                       cfg->replace_access_token);
            if (init_with_token) {
              xmlSetProp(cur, (const xmlChar *)"initialization", (const xmlChar *)init_with_token);
              PluginDebug("DASH: Injected token into SegmentTemplate initialization: %s", init_with_token);
              free(init_with_token);
            }
            xmlFree(init);
          }
        }
      }

      /* Handle SegmentList with SegmentURL elements */
      if (xmlStrcmp(cur->name, (const xmlChar *)"SegmentURL") == 0 && cfg->inject_to_segments) {
        xmlChar *media = xmlGetProp(cur, (const xmlChar *)"media");
        if (media) {
          char *media_with_token = add_token_to_dash_url_with_replace((const char *)media, token, param_name, access_token_name,
                                                                      cfg->replace_access_token);
          if (media_with_token) {
            xmlSetProp(cur, (const xmlChar *)"media", (const xmlChar *)media_with_token);
            PluginDebug("DASH: Injected token into SegmentURL media: %s", media_with_token);
            free(media_with_token);
          }
          xmlFree(media);
        }
      }

      /* Handle Initialization element */
      if (xmlStrcmp(cur->name, (const xmlChar *)"Initialization") == 0 && cfg->inject_to_init_segments) {
        xmlChar *source_url = xmlGetProp(cur, (const xmlChar *)"sourceURL");
        if (source_url) {
          char *url_with_token = add_token_to_dash_url_with_replace((const char *)source_url, token, param_name, access_token_name,
                                                                    cfg->replace_access_token);
          if (url_with_token) {
            xmlSetProp(cur, (const xmlChar *)"sourceURL", (const xmlChar *)url_with_token);
            PluginDebug("DASH: Injected token into Initialization sourceURL: %s", url_with_token);
            free(url_with_token);
          }
          xmlFree(source_url);
        }
      }
    }

    /* Recursively process children */
    process_dash_node(cur->children, token, param_name, access_token_name, cfg);
  }
}

char *
inject_token_dash(const char *manifest_body, size_t body_len, const char *token, const char *param_name,
                  const char *access_token_name, struct manifest_injection_config *cfg, size_t *new_len)
{
  if (!manifest_body || !token || !param_name || !cfg || !new_len) {
    return NULL;
  }

  *new_len = 0;

  /* Parse the MPD XML with security options:
   * - XML_PARSE_NONET: Forbid network access (prevents SSRF)
   * - XML_PARSE_HUGE: Allow large documents
   *
   * Note: We do NOT use XML_PARSE_NOBLANKS to preserve original formatting.
   * Whitespace text nodes are ignored during processing (we only process XML_ELEMENT_NODE).
   */
  int parse_options = XML_PARSE_NONET | XML_PARSE_HUGE;

  xmlDocPtr doc = xmlReadMemory(manifest_body, (int)body_len, "mpd.xml", NULL, parse_options);
  if (!doc) {
    PluginError("DASH: Failed to parse MPD XML");
    return NULL;
  }

  /* Get root element */
  xmlNode *root = xmlDocGetRootElement(doc);
  if (!root) {
    PluginError("DASH: MPD has no root element");
    xmlFreeDoc(doc);
    return NULL;
  }

  /* Verify this is an MPD document */
  if (xmlStrcmp(root->name, (const xmlChar *)"MPD") != 0) {
    PluginError("DASH: Root element is not MPD (got: %s)", (const char *)root->name);
    xmlFreeDoc(doc);
    return NULL;
  }

  PluginDebug("DASH: Processing MPD manifest, injecting token into segments");

  /* Process the XML tree to inject tokens */
  process_dash_node(root, token, param_name, access_token_name, cfg);

  /* Serialize the modified XML back to string */
  xmlChar *xml_output = NULL;
  int xml_size        = 0;
  xmlDocDumpMemory(doc, &xml_output, &xml_size);

  if (!xml_output || xml_size <= 0) {
    PluginError("DASH: Failed to serialize modified MPD");
    xmlFreeDoc(doc);
    return NULL;
  }

  /* Copy to regular malloc'd buffer (Traffic Server uses malloc/free, not xmlMalloc/xmlFree) */
  char *output = malloc(xml_size + 1);
  if (!output) {
    PluginError("DASH: Failed to allocate output buffer");
    xmlFree(xml_output);
    xmlFreeDoc(doc);
    return NULL;
  }

  memcpy(output, xml_output, xml_size);
  output[xml_size] = '\0';
  *new_len         = xml_size;

  /* Cleanup */
  xmlFree(xml_output);
  xmlFreeDoc(doc);

  PluginDebug("DASH: Successfully injected tokens into MPD manifest (%d bytes)", xml_size);
  return output;
}
