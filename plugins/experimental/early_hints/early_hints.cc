/** @file
 * HTTP 103 Early Hints plugin for Apache Traffic Server.
 *
 * Sends 103 Early Hints responses to HTTP/2 clients before the final response,
 * enabling browsers to preload critical resources and reduce page load times.
 *
 * Three operating modes:
 * - manual: Admin specifies Link headers per remap rule
 * - auto-learn: Plugin scans HTML <head> for preloadable resources
 * - origin-forward: Plugin caches Link headers from origin responses
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

#include <ts/ts.h>
#include <ts/remap.h>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <strings.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdio>
#include <sys/stat.h>

#include "config.h"
#include "hints_cache.h"
#include "html_scanner.h"
#include "link_parser.h"
#include "plugin_instance.h"

// Global arg index for per-request state
static int arg_idx = -1;

// Statistics
static int stat_103_sent             = -1;
static int stat_103_skipped_h1       = -1;
static int stat_103_skipped_bot      = -1;
static int stat_103_skipped_no_hints = -1;
static int stat_103_skipped_non_nav  = -1;
static int stat_hints_learned        = -1;

// Per-request state stored via TSUserArgSet
struct RequestData {
  PluginInstance *instance = nullptr; // NOT owned
  std::string cache_key;
  std::string debug_status;
  LinkListPtr cached_links; // Ref-counted, reused across hooks — no deep copy
};

// Transform data for auto-learn HTML scanning
struct TransformData {
  HtmlScanner *scanner = nullptr; // owned
  HintsCache *cache    = nullptr; // NOT owned
  std::string cache_key;
  TSIOBuffer output_buffer       = nullptr;
  TSIOBufferReader output_reader = nullptr;
  TSVIO output_vio               = nullptr;
  int64_t bytes_written          = 0;
  bool initialized               = false;
  bool cache_written             = false;
  bool errored                   = false;
};

// Known bot User-Agent substrings
static const char *bot_signatures[] = {"googlebot",
                                       "bingbot",
                                       "yandexbot",
                                       "baiduspider",
                                       "duckduckbot",
                                       "slurp",
                                       "ia_archiver",
                                       "facebookexternalhit",
                                       "twitterbot",
                                       "linkedinbot",
                                       "embedly",
                                       "showyoubot",
                                       "outbrain",
                                       "pinterest",
                                       "applebot",
                                       "semrushbot",
                                       "ahrefsbot",
                                       "mj12bot",
                                       "dotbot",
                                       "curl/",
                                       "wget/",
                                       "python-requests/",
                                       "go-http-client/",
                                       "apache-httpclient/",
                                       "java/",
                                       "libwww-perl/",
                                       nullptr};

// ─── Utility Functions ──────────────────────────────────────────────────────

static bool
is_bot_user_agent(TSMBuffer bufp, TSMLoc hdr_loc)
{
  TSMLoc field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, TS_MIME_FIELD_USER_AGENT, TS_MIME_LEN_USER_AGENT);
  if (field_loc == TS_NULL_MLOC) {
    return false; // No UA = not a bot (conservative: don't block unknown clients)
  }

  int ua_len         = 0;
  const char *ua_str = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, -1, &ua_len);
  bool is_bot        = false;

  if (ua_str && ua_len > 0) {
    // Real browsers have UAs of ~100-200 bytes. UAs > 512 bytes are abnormal
    // and likely padded to evade detection — treat as bot.
    if (ua_len > 512) {
      is_bot = true;
    } else {
      char ua_buf[513];
      memcpy(ua_buf, ua_str, ua_len);
      ua_buf[ua_len] = '\0';

      for (int i = 0; bot_signatures[i] != nullptr; i++) {
        if (strcasestr(ua_buf, bot_signatures[i]) != nullptr) {
          is_bot = true;
          break;
        }
      }
    }
  }

  TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  return is_bot;
}

static bool
is_navigate_request(TSMBuffer bufp, TSMLoc hdr_loc)
{
  TSMLoc field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, "Sec-Fetch-Mode", 14);
  if (field_loc == TS_NULL_MLOC) {
    return true; // Absent header = allow (older browsers, curl)
  }

  int val_len         = 0;
  const char *val_str = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, -1, &val_len);
  bool is_nav         = false;

  if (val_str && val_len > 0) {
    // Trim leading/trailing whitespace (proxies may add it)
    const char *start = val_str;
    const char *end   = val_str + val_len;
    while (start < end && (*start == ' ' || *start == '\t')) {
      start++;
    }
    while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t')) {
      end--;
    }
    int trimmed_len = static_cast<int>(end - start);
    if (trimmed_len == 8 && strncasecmp(start, "navigate", 8) == 0) {
      is_nav = true;
    }
  }

  TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  return is_nav;
}

static bool
is_valid_link_value(const std::string &link)
{
  // Must start with < and contain >
  if (link.empty() || link[0] != '<') {
    return false;
  }
  size_t url_end = link.find('>');
  if (url_end == std::string::npos || url_end <= 1) {
    return false; // No '>' found, or empty URL between '<>'
  }

  // Reject any control characters (NUL, CRLF, etc.) and DEL
  for (char c : link) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (uc < 0x20 || uc == 0x7F) {
      return false;
    }
  }

  // Reject nested '<' or extra '>' inside the URL portion (between first < and first >).
  // These would break RFC 8288 URI-Reference parsing and could allow injection.
  std::string url_part = link.substr(1, url_end - 1);
  for (char c : url_part) {
    if (c == '<' || c == '>') {
      return false;
    }
  }

  // Block dangerous URL schemes inside the URL portion.
  // Strip leading whitespace — browsers do this per WHATWG URL spec, so
  // "  javascript:..." resolves to "javascript:...".
  std::string url_lower;
  url_lower.reserve(url_part.size());
  for (char c : url_part) {
    url_lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  size_t scheme_start = url_lower.find_first_not_of(" \t");
  if (scheme_start != std::string::npos &&
      (url_lower.compare(scheme_start, 11, "javascript:") == 0 || url_lower.compare(scheme_start, 5, "data:") == 0 ||
       url_lower.compare(scheme_start, 9, "vbscript:") == 0 || url_lower.compare(scheme_start, 5, "blob:") == 0)) {
    return false;
  }

  // Must contain rel=preload, rel=preconnect, rel=stylesheet, or rel=modulepreload
  // Search only in the params portion (after '>'), not in the URL
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
      bool after_ok  = end >= params_lower.size() || params_lower[end] == ';' || params_lower[end] == ' ' ||
                      params_lower[end] == '\t' || params_lower[end] == '"' || params_lower[end] == '\'';
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

static bool
send_103_response(TSHttpTxn txnp, const std::vector<std::string> &links, int max_links, int header_size_limit)
{
  if (links.empty()) {
    return false;
  }

  // Build array of Link values respecting limits.
  // Size accounting: "Link: " (6) + value + "\r\n" (2) = 8 overhead per header.
  std::vector<const char *> link_ptrs;
  link_ptrs.reserve(links.size());
  int total_size = 0;
  int count      = 0;

  for (const auto &link : links) {
    if (count >= max_links) {
      break;
    }
    int link_size = static_cast<int>(link.size()) + 8; // "Link: " + value + "\r\n"
    if (total_size + link_size > header_size_limit) {
      continue; // skip oversized link, try remaining smaller ones
    }
    link_ptrs.push_back(link.c_str());
    total_size += link_size;
    count++;
  }

  if (link_ptrs.empty()) {
    return false;
  }

  TSReturnCode rc = TSHttpTxnSendEarlyHints(txnp, link_ptrs.data(), static_cast<int>(link_ptrs.size()));
  if (rc == TS_SUCCESS) {
    TSStatIntIncrement(stat_103_sent, 1);
    TSDebug(PLUGIN_NAME, "sent 103 with %d Link headers", count);
    return true;
  } else {
    TSDebug(PLUGIN_NAME, "failed to send 103 (non-H2 client?)");
    return false;
  }
}

static void
add_link_headers_to_response(TSMBuffer bufp, TSMLoc hdr_loc, const std::vector<std::string> &links, int max_links,
                             int header_size_limit)
{
  int count     = 0;
  int total_len = 0;
  for (const auto &link : links) {
    if (count >= max_links) {
      break;
    }
    // "Link: " (6) + value + "\r\n" (2)
    int entry_len = 6 + static_cast<int>(link.size()) + 2;
    if (header_size_limit > 0 && total_len + entry_len > header_size_limit) {
      continue; // skip oversized link, try remaining smaller ones (consistent with send_103_response)
    }
    TSMLoc field_loc;
    if (TSMimeHdrFieldCreateNamed(bufp, hdr_loc, "Link", 4, &field_loc) == TS_SUCCESS) {
      TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field_loc, -1, link.c_str(), static_cast<int>(link.size()));
      TSMimeHdrFieldAppend(bufp, hdr_loc, field_loc);
      TSHandleMLocRelease(bufp, hdr_loc, field_loc);
      count++;
      total_len += entry_len;
    }
  }
}

// ─── Transform Handler (auto-learn HTML scanning) ───────────────────────────

static void
early_hints_transform_do(TSCont contp)
{
  TransformData *data = static_cast<TransformData *>(TSContDataGet(contp));
  if (!data || data->errored) {
    return;
  }

  TSVIO input_vio = TSVConnWriteVIOGet(contp);
  if (!input_vio) {
    return;
  }

  // Initialize output on first call
  if (!data->initialized) {
    TSVConn output_conn = TSTransformOutputVConnGet(contp);
    if (!output_conn) {
      data->errored = true;
      return;
    }
    data->output_buffer = TSIOBufferCreate();
    if (!data->output_buffer) {
      data->errored = true;
      return;
    }
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
    if (!data->output_reader) {
      TSIOBufferDestroy(data->output_buffer);
      data->output_buffer = nullptr;
      data->errored       = true;
      return;
    }
    data->output_vio = TSVConnWrite(output_conn, contp, data->output_reader, INT64_MAX);
    if (!data->output_vio) {
      TSIOBufferDestroy(data->output_buffer);
      data->output_buffer = nullptr;
      data->output_reader = nullptr;
      data->errored       = true;
      return;
    }
    data->initialized = true;
  }

  // Check end-of-stream
  if (!TSVIOBufferGet(input_vio)) {
    // No more data — finalize
    if (!data->cache_written && data->scanner && !data->scanner->get_links().empty()) {
      data->cache->put(data->cache_key, data->scanner->get_links());
      data->cache_written = true;
      TSStatIntIncrement(stat_hints_learned, 1);
      TSDebug(PLUGIN_NAME, "learned %zu links for %s", data->scanner->get_links().size(), data->cache_key.c_str());
    }
    TSVIONBytesSet(data->output_vio, data->bytes_written);
    TSVIOReenable(data->output_vio);
    return;
  }

  // Check if there's data to process
  int64_t toread = TSVIONTodoGet(input_vio);
  if (toread <= 0) {
    TSVIONBytesSet(data->output_vio, data->bytes_written);
    TSVIOReenable(data->output_vio);
    TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
    return;
  }

  // Process available data
  TSIOBufferReader input_reader = TSVIOReaderGet(input_vio);
  if (!input_reader) {
    TSVIOReenable(data->output_vio);
    return;
  }

  int64_t avail = TSIOBufferReaderAvail(input_reader);
  if (avail > 0) {
    // Clamp avail to toread to prevent byte overshoot
    if (avail > toread) {
      avail = toread;
    }

    // Copy data through unchanged (passthrough) — do this FIRST to determine
    // the actual consumed byte count before feeding the scanner.
    int64_t copied = TSIOBufferCopy(data->output_buffer, input_reader, avail, 0);
    if (copied <= 0 && avail > 0) {
      // Copy failed — mark errored and finalize output VIO so downstream doesn't stall.
      TSDebug(PLUGIN_NAME, "TSIOBufferCopy failed for %lld avail bytes", (long long)avail);
      data->errored = true;
      TSIOBufferReaderConsume(input_reader, avail);
      TSVIONBytesSet(data->output_vio, data->bytes_written);
      TSVIOReenable(data->output_vio);
      return;
    }

    // Feed scanner only the bytes that will actually be consumed.
    // This prevents double-feed when TSIOBufferCopy returns a partial result —
    // unconsumed bytes remain in the reader and would be re-fed on next call.
    if (data->scanner && !data->scanner->is_done()) {
      int64_t fed           = 0;
      TSIOBufferBlock block = TSIOBufferReaderStart(input_reader);
      while (block != nullptr && fed < copied) {
        int64_t block_len     = 0;
        const char *block_buf = TSIOBufferBlockReadStart(block, input_reader, &block_len);
        if (block_buf && block_len > 0) {
          int64_t to_feed = std::min(block_len, copied - fed);
          data->scanner->feed(block_buf, to_feed);
          fed += to_feed;
        }
        block = TSIOBufferBlockNext(block);
      }
    }

    TSIOBufferReaderConsume(input_reader, copied);
    data->bytes_written += copied;
    TSVIONDoneSet(input_vio, TSVIONDoneGet(input_vio) + copied);
  }

  // Check if more data pending
  toread = TSVIONTodoGet(input_vio);
  if (toread > 0) {
    TSVIOReenable(data->output_vio);
    TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_READY, input_vio);
  } else {
    // All done — update hints cache
    if (!data->cache_written && data->scanner && !data->scanner->get_links().empty()) {
      data->cache->put(data->cache_key, data->scanner->get_links());
      data->cache_written = true;
      TSStatIntIncrement(stat_hints_learned, 1);
      TSDebug(PLUGIN_NAME, "learned %zu links for %s (final)", data->scanner->get_links().size(), data->cache_key.c_str());
    }
    TSVIONBytesSet(data->output_vio, data->bytes_written);
    TSVIOReenable(data->output_vio);
    TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
  }
}

static int
early_hints_transform(TSCont contp, TSEvent event, void * /* edata ATS_UNUSED */)
{
  // FIRST: Check if VConn is closed — cleanup immediately
  if (TSVConnClosedGet(contp)) {
    TransformData *data = static_cast<TransformData *>(TSContDataGet(contp));
    if (data) {
      delete data->scanner;
      if (data->output_buffer) {
        TSIOBufferDestroy(data->output_buffer);
      }
      data->~TransformData();
      TSfree(data);
    }
    TSContDataSet(contp, nullptr);
    TSContDestroy(contp);
    return 0;
  }

  switch (event) {
  case TS_EVENT_ERROR: {
    TransformData *data = static_cast<TransformData *>(TSContDataGet(contp));
    if (data) {
      data->errored = true;
    }
    TSVIO input_vio = TSVConnWriteVIOGet(contp);
    if (input_vio) {
      TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
    }
    break;
  }
  case TS_EVENT_VCONN_WRITE_COMPLETE: {
    TSVConn output_conn = TSTransformOutputVConnGet(contp);
    if (output_conn) {
      TSVConnShutdown(output_conn, 0, 1);
    }
    break;
  }
  case TS_EVENT_VCONN_WRITE_READY:
  default:
    early_hints_transform_do(contp);
    break;
  }

  return 0;
}

// ─── Hook Handler ───────────────────────────────────────────────────────────

static int
early_hints_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);

  RequestData *req_data = static_cast<RequestData *>(TSUserArgGet(txnp, arg_idx));
  if (!req_data) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  }

  PluginInstance *inst     = req_data->instance;
  EarlyHintsConfig *config = inst->config;
  HintsCache *cache        = inst->cache;

  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR: {
    TSMBuffer server_bufp;
    TSMLoc server_hdr_loc;

    if (TSHttpTxnServerRespGet(txnp, &server_bufp, &server_hdr_loc) != TS_SUCCESS) {
      TSDebug(PLUGIN_NAME, "failed to get server response");
      break;
    }

    TSHttpStatus status = TSHttpHdrStatusGet(server_bufp, server_hdr_loc);
    if (status != TS_HTTP_STATUS_OK) {
      TSDebug(PLUGIN_NAME, "skipping non-200 response (status=%d)", status);
      TSHandleMLocRelease(server_bufp, TS_NULL_MLOC, server_hdr_loc);
      break;
    }

    // Origin-forward mode: extract Link headers from origin response
    if (config->mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) {
      TSMLoc link_field = TSMimeHdrFieldFind(server_bufp, server_hdr_loc, "Link", 4);
      std::vector<std::string> origin_links;

      while (link_field != TS_NULL_MLOC) {
        int val_len         = 0;
        const char *val_str = TSMimeHdrFieldValueStringGet(server_bufp, server_hdr_loc, link_field, -1, &val_len);
        if (val_str && val_len > 0) {
          std::string full_val(val_str, val_len);
          int remaining = config->max_links() - static_cast<int>(origin_links.size());
          auto segments = split_link_header_value(full_val, remaining);
          for (auto &seg : segments) {
            if (is_valid_link_value(seg)) {
              origin_links.push_back(std::move(seg));
              if (static_cast<int>(origin_links.size()) >= config->max_links()) {
                break;
              }
            }
          }
        }
        TSMLoc next = TSMimeHdrFieldNextDup(server_bufp, server_hdr_loc, link_field);
        TSHandleMLocRelease(server_bufp, server_hdr_loc, link_field);
        link_field = next;

        if (static_cast<int>(origin_links.size()) >= config->max_links()) {
          // Release remaining dup chain
          while (link_field != TS_NULL_MLOC) {
            next = TSMimeHdrFieldNextDup(server_bufp, server_hdr_loc, link_field);
            TSHandleMLocRelease(server_bufp, server_hdr_loc, link_field);
            link_field = next;
          }
          break;
        }
      }

      if (!origin_links.empty()) {
        cache->put(req_data->cache_key, origin_links);
        TSStatIntIncrement(stat_hints_learned, 1);
        TSDebug(PLUGIN_NAME, "learned %zu origin Link headers for %s", origin_links.size(), req_data->cache_key.c_str());
      }
    }

    // Auto-learn mode: set up HTML scanning transform
    if (config->mode() & EarlyHintsConfig::MODE_AUTO_LEARN) {
      // Check Content-Type: text/html
      TSMLoc ct_field = TSMimeHdrFieldFind(server_bufp, server_hdr_loc, TS_MIME_FIELD_CONTENT_TYPE, TS_MIME_LEN_CONTENT_TYPE);
      bool is_html    = false;

      if (ct_field != TS_NULL_MLOC) {
        int ct_len         = 0;
        const char *ct_str = TSMimeHdrFieldValueStringGet(server_bufp, server_hdr_loc, ct_field, -1, &ct_len);
        if (ct_str && ct_len >= 9 && strncasecmp(ct_str, "text/html", 9) == 0 &&
            (ct_len == 9 || ct_str[9] == ';' || ct_str[9] == ' ' || ct_str[9] == '\t')) {
          is_html = true;
        }
        TSHandleMLocRelease(server_bufp, server_hdr_loc, ct_field);
      }

      // Skip scanning if response body is compressed — the scanner expects uncompressed HTML
      bool is_compressed = false;
      if (is_html) {
        TSMLoc ce_field =
          TSMimeHdrFieldFind(server_bufp, server_hdr_loc, TS_MIME_FIELD_CONTENT_ENCODING, TS_MIME_LEN_CONTENT_ENCODING);
        if (ce_field != TS_NULL_MLOC) {
          int ce_len         = 0;
          const char *ce_str = TSMimeHdrFieldValueStringGet(server_bufp, server_hdr_loc, ce_field, -1, &ce_len);
          if (ce_str && ce_len > 0 && !(ce_len == 8 && strncasecmp(ce_str, "identity", 8) == 0)) {
            is_compressed = true;
            TSDebug(PLUGIN_NAME, "skipping auto-learn: response is compressed (Content-Encoding present)");
          }
          TSHandleMLocRelease(server_bufp, server_hdr_loc, ce_field);
        }
      }

      if (is_html && !is_compressed) {
        // Create transform for HTML scanning
        TransformData *tdata = static_cast<TransformData *>(TSmalloc(sizeof(TransformData)));
        new (tdata) TransformData();
        tdata->scanner   = new HtmlScanner(config->scan_limit(), config->max_links(), config);
        tdata->cache     = cache;
        tdata->cache_key = req_data->cache_key;

        TSVConn connp = TSTransformCreate(early_hints_transform, txnp);
        if (!connp) {
          TSDebug(PLUGIN_NAME, "TSTransformCreate failed, skipping HTML scanning");
          delete tdata->scanner;
          tdata->~TransformData();
          TSfree(tdata);
        } else {
          TSContDataSet(connp, tdata);
          TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
          TSDebug(PLUGIN_NAME, "added HTML scanning transform for %s", req_data->cache_key.c_str());
        }
      }
    }

    TSHandleMLocRelease(server_bufp, TS_NULL_MLOC, server_hdr_loc);
    break;
  }

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR: {
    TSMBuffer resp_bufp;
    TSMLoc resp_hdr_loc;

    if (TSHttpTxnClientRespGet(txnp, &resp_bufp, &resp_hdr_loc) != TS_SUCCESS) {
      break;
    }

    // Only add Link headers to successful responses (2xx).
    // Adding them to 4xx/5xx/3xx is misleading — the resources don't apply.
    TSHttpStatus resp_status = TSHttpHdrStatusGet(resp_bufp, resp_hdr_loc);
    if (resp_status >= 200 && resp_status < 300) {
      // Add Link headers to final 2xx response (for browser compatibility)
      // Reuse links already looked up in TSRemapDoRemap to avoid double cache lookup.
      // For auto-learn, cached_links may be null if this is the first request (learning
      // happened during the transform), so re-query the cache as fallback.
      const std::vector<std::string> *links_ptr = nullptr;
      if (config->mode() & EarlyHintsConfig::MODE_MANUAL) {
        links_ptr = &config->manual_links();
      } else if (req_data->cached_links) {
        links_ptr = req_data->cached_links.get();
      } else if (!req_data->cache_key.empty()) {
        // Fallback: transform may have just populated the cache during this request.
        // Use min_hit_count=1 intentionally: if the transform just learned during THIS request,
        // learn_count is 1. Using config->min_hit_count() (default 2) would prevent showing
        // links in the 200 response on the first learning request. The 103 in TSRemapDoRemap
        // still respects config->min_hit_count() — this fallback is only for 200 compatibility.
        req_data->cached_links = cache->get(req_data->cache_key, 1);
        if (req_data->cached_links) {
          links_ptr = req_data->cached_links.get();
        }
      }

      if (links_ptr && !links_ptr->empty()) {
        add_link_headers_to_response(resp_bufp, resp_hdr_loc, *links_ptr, config->max_links(), config->header_size_limit());
      }
    }

    // Add debug header for ALL response codes (intentionally outside the 2xx check).
    // Debugging non-2xx responses is important for understanding plugin behavior
    // on error pages, redirects, etc.
    if (config->debug_header()) {
      TSMLoc field_loc;
      const char *hdr_name = config->debug_header();
      int hdr_name_len     = static_cast<int>(strlen(hdr_name));

      if (TSMimeHdrFieldCreateNamed(resp_bufp, resp_hdr_loc, hdr_name, hdr_name_len, &field_loc) == TS_SUCCESS) {
        const char *status_str = req_data->debug_status.c_str();
        int status_len         = static_cast<int>(req_data->debug_status.size());
        TSMimeHdrFieldValueStringSet(resp_bufp, resp_hdr_loc, field_loc, -1, status_str, status_len);
        TSMimeHdrFieldAppend(resp_bufp, resp_hdr_loc, field_loc);
        TSHandleMLocRelease(resp_bufp, resp_hdr_loc, field_loc);
      }
    }

    TSHandleMLocRelease(resp_bufp, TS_NULL_MLOC, resp_hdr_loc);
    break;
  }

  case TS_EVENT_HTTP_TXN_CLOSE: {
    // Cleanup per-request state — call destructor for std::string members
    req_data->~RequestData();
    TSfree(req_data);
    TSUserArgSet(txnp, arg_idx, nullptr);
    break;
  }

  default:
    break;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}

// ─── Remap Plugin Entry Points ──────────────────────────────────────────────

TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    snprintf(errbuf, errbuf_size, "[early_hints] api_info is null");
    errbuf[errbuf_size - 1] = '\0';
    return TS_ERROR;
  }

  if (api_info->size < sizeof(TSRemapInterface)) {
    snprintf(errbuf, errbuf_size, "[early_hints] Incorrect size of TSRemapInterface structure");
    return TS_ERROR;
  }

  if (api_info->tsremap_version < TSREMAP_VERSION) {
    snprintf(errbuf, errbuf_size, "[early_hints] Incorrect API version %ld.%ld", api_info->tsremap_version >> 16,
             (api_info->tsremap_version & 0xffff));
    return TS_ERROR;
  }

  if (TSUserArgIndexReserve(TS_USER_ARGS_TXN, PLUGIN_NAME, "early_hints per-request state", &arg_idx) != TS_SUCCESS) {
    snprintf(errbuf, errbuf_size, "[early_hints] Failed to reserve TXN user argument slot");
    return TS_ERROR;
  }

  // Register statistics
  stat_103_sent = TSStatCreate("plugin.early_hints.103_sent", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_103_skipped_h1 =
    TSStatCreate("plugin.early_hints.103_skipped_h1", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_103_skipped_bot =
    TSStatCreate("plugin.early_hints.103_skipped_bot", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_103_skipped_no_hints =
    TSStatCreate("plugin.early_hints.103_skipped_no_hints", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_103_skipped_non_nav =
    TSStatCreate("plugin.early_hints.103_skipped_non_nav", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_hints_learned =
    TSStatCreate("plugin.early_hints.hints_learned", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  TSDebug(PLUGIN_NAME, "plugin initialized, arg_idx=%d", arg_idx);
  return TS_SUCCESS;
}

// FNV-1a hash for generating unique persist filenames per remap
static uint32_t
fnv1a_hash(const char *str)
{
  uint32_t hash = 2166136261u;
  for (; *str; ++str) {
    hash ^= static_cast<uint8_t>(*str);
    hash *= 16777619u;
  }
  return hash;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  EarlyHintsConfig *config = new EarlyHintsConfig();

  if (!config->init(argc, const_cast<const char **>(argv))) {
    snprintf(errbuf, errbuf_size, "[early_hints] Failed to parse configuration");
    delete config;
    return TS_ERROR;
  }

  HintsCache *cache = new HintsCache(config->max_cache_entries());

  // Set up disk persistence (default ON, disable with --no-persist)
  if (config->persist_enabled()) {
    // Determine directory: --persist-dir or ATS runtime dir
    std::string dir = config->persist_dir();
    if (dir.empty()) {
      const char *runtime_dir = TSRuntimeDirGet();
      if (runtime_dir) {
        dir = runtime_dir;
      }
    }
    if (!dir.empty()) {
      // Ensure directory exists (create if needed)
      struct stat st;
      if (stat(dir.c_str(), &st) != 0) {
        if (mkdir(dir.c_str(), 0755) != 0) {
          TSError("[%s] failed to create persist dir: %s", PLUGIN_NAME, dir.c_str());
        }
      }
      // Generate unique filename from remap from-URL (argv[0])
      const char *from_url = (argc > 0 && argv[0]) ? argv[0] : "default";
      char filename[64];
      snprintf(filename, sizeof(filename), "early_hints_%08x.bin", fnv1a_hash(from_url));
      std::string persist_path = dir + "/" + filename;
      cache->set_persist_path(persist_path);
      cache->load_from_disk();
      TSDebug(PLUGIN_NAME, "persistence enabled: %s", persist_path.c_str());
    }
  }

  PluginInstance *inst = new PluginInstance();
  inst->config         = config;
  inst->cache          = cache;

  TSCont contp = TSContCreate(early_hints_handler, nullptr);
  if (!contp) {
    TSError("[%s] TSContCreate failed", PLUGIN_NAME);
    delete inst;
    return TS_ERROR;
  }
  TSContDataSet(contp, static_cast<void *>(inst));
  *ih = static_cast<void *>(contp);

  TSDebug(PLUGIN_NAME, "new instance created: mode=0x%02x", config->mode());
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *ih)
{
  if (!ih) {
    return;
  }

  TSCont contp         = static_cast<TSCont>(ih);
  PluginInstance *inst = static_cast<PluginInstance *>(TSContDataGet(contp));

  if (inst) {
    // Persist cache to disk on graceful shutdown
    if (inst->cache) {
      inst->cache->persist_to_disk();
    }
    delete inst;
  }

  TSContDestroy(contp);
}

TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo * /* rri ATS_UNUSED */)
{
  if (!ih) {
    return TSREMAP_NO_REMAP;
  }

  TSCont contp         = static_cast<TSCont>(ih);
  PluginInstance *inst = static_cast<PluginInstance *>(TSContDataGet(contp));
  if (!inst || !inst->config || !inst->cache) {
    return TSREMAP_NO_REMAP;
  }
  EarlyHintsConfig *config = inst->config;
  HintsCache *cache        = inst->cache;

  // Check if a prior plugin has set an error status (e.g., auth denied)
  TSHttpStatus prior_status = TSHttpTxnStatusGet(rh);
  if (prior_status != TS_HTTP_STATUS_NONE && prior_status >= TS_HTTP_STATUS_BAD_REQUEST) {
    TSDebug(PLUGIN_NAME, "skipping: prior plugin set error status %d", prior_status);
    return TSREMAP_NO_REMAP;
  }

  // Check method: only GET and HEAD
  TSMBuffer req_bufp;
  TSMLoc req_hdr_loc;
  if (TSHttpTxnClientReqGet(rh, &req_bufp, &req_hdr_loc) != TS_SUCCESS) {
    return TSREMAP_NO_REMAP;
  }

  int method_len     = 0;
  const char *method = TSHttpHdrMethodGet(req_bufp, req_hdr_loc, &method_len);
  bool is_get_head =
    (method_len == static_cast<int>(strlen(TS_HTTP_METHOD_GET)) && strncmp(method, TS_HTTP_METHOD_GET, method_len) == 0) ||
    (method_len == static_cast<int>(strlen(TS_HTTP_METHOD_HEAD)) && strncmp(method, TS_HTTP_METHOD_HEAD, method_len) == 0);

  if (!is_get_head) {
    TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, req_hdr_loc);
    return TSREMAP_NO_REMAP;
  }

  // Build cache key from URL path
  TSMLoc url_loc;
  std::string cache_key;
  if (TSHttpHdrUrlGet(req_bufp, req_hdr_loc, &url_loc) == TS_SUCCESS) {
    int path_len     = 0;
    const char *path = TSUrlPathGet(req_bufp, url_loc, &path_len);
    cache_key        = HintsCache::make_key(path, path_len);
    if (cache_key[0] != '/') {
      cache_key = "/" + cache_key;
    }
    TSHandleMLocRelease(req_bufp, req_hdr_loc, url_loc);
  }

  // Check if another remap plugin instance already claimed this transaction (first-wins).
  // This prevents hook duplication, config contamination, and duplicate 103 responses.
  RequestData *req_data = static_cast<RequestData *>(TSUserArgGet(rh, arg_idx));
  if (req_data) {
    TSDebug(PLUGIN_NAME, "another early_hints instance already claimed this txn, skipping");
    TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, req_hdr_loc);
    return TSREMAP_NO_REMAP;
  }
  req_data = static_cast<RequestData *>(TSmalloc(sizeof(RequestData)));
  new (req_data) RequestData();
  req_data->instance     = inst;
  req_data->cache_key    = cache_key;
  req_data->debug_status = "skipped";

  TSUserArgSet(rh, arg_idx, req_data);

  // Check protocol: H2 only
  if (TSHttpTxnClientProtocolStackContains(rh, "h2") == nullptr) {
    TSStatIntIncrement(stat_103_skipped_h1, 1);
    req_data->debug_status = "skipped-h1";
    TSDebug(PLUGIN_NAME, "skipping: non-H2 client");
    goto register_hooks;
  }

  // Check navigate mode
  if (config->navigate_only() && !is_navigate_request(req_bufp, req_hdr_loc)) {
    TSStatIntIncrement(stat_103_skipped_non_nav, 1);
    req_data->debug_status = "skipped-non-navigate";
    TSDebug(PLUGIN_NAME, "skipping: non-navigate request");
    goto register_hooks;
  }

  // Check bot detection
  if (config->skip_bots() && is_bot_user_agent(req_bufp, req_hdr_loc)) {
    TSStatIntIncrement(stat_103_skipped_bot, 1);
    req_data->debug_status = "skipped-bot";
    TSDebug(PLUGIN_NAME, "skipping: bot User-Agent");
    goto register_hooks;
  }

  if (config->mode() & EarlyHintsConfig::MODE_MANUAL) {
    // Manual mode: send configured links immediately
    if (send_103_response(rh, config->manual_links(), config->max_links(), config->header_size_limit())) {
      req_data->debug_status = "sent";
    } else {
      req_data->debug_status = "send-failed";
    }
  } else {
    // Auto-learn / origin-forward: lookup hints cache (single lookup, reused in SEND_RESPONSE_HDR)
    req_data->cached_links = cache->get(cache_key, config->min_hit_count());
    if (req_data->cached_links) {
      if (send_103_response(rh, *req_data->cached_links, config->max_links(), config->header_size_limit())) {
        req_data->debug_status = "sent";
      } else {
        req_data->debug_status = "send-failed";
      }
    } else {
      TSStatIntIncrement(stat_103_skipped_no_hints, 1);
      req_data->debug_status = "no-hints";
      TSDebug(PLUGIN_NAME, "no hints available for %s", cache_key.c_str());
    }
  }

register_hooks:
  TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, req_hdr_loc);

  // Always register hooks for learning and response header modification
  TSHttpTxnHookAdd(rh, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  TSHttpTxnHookAdd(rh, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
  TSHttpTxnHookAdd(rh, TS_HTTP_TXN_CLOSE_HOOK, contp);

  return TSREMAP_NO_REMAP;
}

void
TSRemapDone()
{
  // No global cleanup needed — per-instance cleanup in TSRemapDeleteInstance
}
