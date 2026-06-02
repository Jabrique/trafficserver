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
#include <cerrno>

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

static inline void
increment_stat(int stat_id, int64_t amount)
{
  if (stat_id >= 0) {
    TSStatIntIncrement(stat_id, amount);
  }
}

// Per-request state stored via TSUserArgSet
struct RequestData {
  PluginInstance *instance = nullptr; // NOT owned
  std::string cache_key;
  std::string debug_status;
  LinkListPtr cached_links; // Non-null when hints are serveable (request_count >= min_hits)
  // True when entry EXISTS in cache (links != nullptr), regardless of request_count.
  // Used by READ_RESPONSE_HDR and READ_CACHE_HDR to skip scanner when already learned.
  // Set once in TSRemapDoRemap, valid for all subsequent hooks in this transaction.
  bool has_learned = false;
  // True when a TTL is configured and the cached hints are older than hints_ttl.
  // Set in TSRemapDoRemap. When true:
  //   READ_CACHE_HDR (ATS cache hit / frozen body): call touch() to refresh TTL, skip scanner.
  //   READ_RESPONSE_HDR (origin response): re-attach scanner even though has_learned=true.
  bool needs_relearn = false;
  // Guards stat_hints_learned against double-count in combined mode:
  // origin-forward and auto-learn may both fire for the same request.
  bool stat_learned_emitted = false;
};

// Transform data for auto-learn HTML scanning
struct TransformData {
  HtmlScanner *scanner      = nullptr; // owned
  HintsCache *cache         = nullptr; // NOT owned
  RequestData *req_data_ref = nullptr; // NOT owned — for combined mode stat guard
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

// ─── HTTP Response Handling ──────────────────────────────────────────────────

static bool
send_103_response(TSHttpTxn txnp, const std::vector<std::string> &links, int max_links, int header_size_limit)
{
  if (links.empty()) {
    TSDebug(PLUGIN_NAME, "send_103: no links to send (empty vector)");
    return false;
  }

  TSDebug(PLUGIN_NAME, "send_103: building response from %zu candidate links (max_links=%d, header_size_limit=%d)", links.size(),
          max_links, header_size_limit);

  // Build array of Link values respecting limits.
  // Size accounting: LINK_HEADER_OVERHEAD (8) = "Link: " (6) + "\r\n" (2) per header.
  std::vector<const char *> link_ptrs;
  link_ptrs.reserve(links.size());
  int total_size = 0;
  int count      = 0;

  for (const auto &link : links) {
    if (count >= max_links) {
      TSDebug(PLUGIN_NAME, "send_103: max_links limit reached (%d), skipping remaining %zu links", max_links,
              links.size() - static_cast<size_t>(count));
      break;
    }
    int link_size = static_cast<int>(link.size()) + LINK_HEADER_OVERHEAD;
    if (total_size + link_size > header_size_limit) {
      TSDebug(PLUGIN_NAME, "send_103: skipping oversized link (%d bytes would exceed %d/%d limit): %s", link_size,
              total_size + link_size, header_size_limit, link.c_str());
      continue; // skip oversized link, try remaining smaller ones
    }
    TSDebug(PLUGIN_NAME, "send_103: link[%d] selected (%d bytes, total=%d/%d): %s", count, link_size, total_size + link_size,
            header_size_limit, link.c_str());
    link_ptrs.push_back(link.c_str());
    total_size += link_size;
    count++;
  }

  if (link_ptrs.empty()) {
    TSDebug(PLUGIN_NAME, "send_103: all links filtered out (size/limit constraints)");
    return false;
  }

  TSDebug(PLUGIN_NAME, "send_103: calling TSHttpTxnSendEarlyHints with %d links (%d bytes total)", count, total_size);
  TSReturnCode rc = TSHttpTxnSendEarlyHints(txnp, link_ptrs.data(), static_cast<int>(link_ptrs.size()));
  if (rc == TS_SUCCESS) {
    increment_stat(stat_103_sent, 1);
    TSDebug(PLUGIN_NAME, "sent 103 Early Hints with %d Link headers (%d bytes)", count, total_size);
    return true;
  } else {
    TSDebug(PLUGIN_NAME, "failed to send 103: TSHttpTxnSendEarlyHints returned TS_ERROR (client may not support H2)");
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
    int entry_len = LINK_HEADER_OVERHEAD + static_cast<int>(link.size());
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
      // Free reader before destroying buffer: reader holds a reference into buffer.
      TSIOBufferReaderFree(data->output_reader);
      data->output_reader = nullptr;
      TSIOBufferDestroy(data->output_buffer);
      data->output_buffer = nullptr;
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
      if (!data->req_data_ref || !data->req_data_ref->stat_learned_emitted) {
        increment_stat(stat_hints_learned, 1);
        if (data->req_data_ref) {
          data->req_data_ref->stat_learned_emitted = true;
        }
      }
      TSDebug(PLUGIN_NAME, "learned %zu links for %s via HTML scanning", data->scanner->get_links().size(),
              data->cache_key.c_str());
      for (size_t i = 0; i < data->scanner->get_links().size(); ++i) {
        TSDebug(PLUGIN_NAME, "  learned link[%zu]: %s", i, data->scanner->get_links()[i].c_str());
      }
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
      TSDebug(PLUGIN_NAME, "TSIOBufferCopy failed for %s: avail=%lld bytes, scanner may have incomplete data",
              data->cache_key.c_str(), (long long)avail);
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
      if (!data->req_data_ref || !data->req_data_ref->stat_learned_emitted) {
        increment_stat(stat_hints_learned, 1);
        if (data->req_data_ref) {
          data->req_data_ref->stat_learned_emitted = true;
        }
      }
      TSDebug(PLUGIN_NAME, "learned %zu links for %s via HTML scanning (final flush)", data->scanner->get_links().size(),
              data->cache_key.c_str());
      for (size_t i = 0; i < data->scanner->get_links().size(); ++i) {
        TSDebug(PLUGIN_NAME, "  learned link[%zu]: %s", i, data->scanner->get_links()[i].c_str());
      }
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
      data->scanner = nullptr;
      // output_reader must be freed before output_buffer: the reader holds an
      // internal reference into the buffer, and TSIOBufferDestroy with a live
      // reader is undefined behavior per ATS API contract.
      if (data->output_reader) {
        TSIOBufferReaderFree(data->output_reader);
        data->output_reader = nullptr;
      }
      if (data->output_buffer) {
        TSIOBufferDestroy(data->output_buffer);
        data->output_buffer = nullptr;
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
      TSDebug(PLUGIN_NAME, "READ_RESPONSE_HDR: failed to get server response for %s", req_data->cache_key.c_str());
      break;
    }

    TSHttpStatus status = TSHttpHdrStatusGet(server_bufp, server_hdr_loc);
    if (status != TS_HTTP_STATUS_OK) {
      TSDebug(PLUGIN_NAME, "READ_RESPONSE_HDR: skipping non-200 response (status=%d) for %s", status, req_data->cache_key.c_str());
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
            std::string normalized = normalize_link_for_hint(seg);
            if (!normalized.empty() && is_valid_link_value(normalized) && has_valid_as_for_preload(normalized)) {
              origin_links.push_back(std::move(normalized));
            }
          }
          // Deduplicate: origins occasionally emit the same Link header field
          // more than once (e.g. middleware that appends headers idempotently).
          // dedup_link_segments() stores only the first occurrence of each
          // <URL> + rel type pair and caps the result at max_links.
          origin_links = dedup_link_segments(std::move(origin_links), config->max_links());
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
        if (!req_data->stat_learned_emitted) {
          increment_stat(stat_hints_learned, 1);
          req_data->stat_learned_emitted = true;
        }
        TSDebug(PLUGIN_NAME, "learned %zu origin Link headers for %s", origin_links.size(), req_data->cache_key.c_str());
        for (size_t i = 0; i < origin_links.size(); ++i) {
          TSDebug(PLUGIN_NAME, "  origin link[%zu]: %s", i, origin_links[i].c_str());
        }
      } else {
        TSDebug(PLUGIN_NAME, "origin-forward: no valid Link headers found in origin response for %s", req_data->cache_key.c_str());
      }
    }

    // Auto-learn mode: set up HTML scanning transform
    if (config->mode() & EarlyHintsConfig::MODE_AUTO_LEARN) {
      // Scanner skip: if hints have been learned for this URL (entry exists in cache
      // regardless of request_count), skip scanning — the HTML content won't change.
      // has_learned is set in TSRemapDoRemap via peek() to avoid double-counting request_count.
      bool already_learned = req_data->has_learned;

      if (already_learned && !req_data->needs_relearn) {
        TSDebug(PLUGIN_NAME, "READ_RESPONSE_HDR: already learned hints for %s, skipping scanner", req_data->cache_key.c_str());
        // For origin responses (ATS cache disabled or cache miss), READ_CACHE_HDR will not fire.
        // Call get() here to increment request_count and set cached_links if threshold is met.
        // (For ATS cache hits, READ_CACHE_HDR already called get(); cached_links may be non-null.)
        if (req_data->cached_links == nullptr) {
          req_data->cached_links = cache->get(req_data->cache_key, config->min_hit_count());
          TSDebug(PLUGIN_NAME, "READ_RESPONSE_HDR: get() for %s → %s", req_data->cache_key.c_str(),
                  req_data->cached_links ? "hints ready" : "below threshold");
        }
      } else {
        // Two cases: !already_learned (first learn) OR already_learned+needs_relearn (TTL expired).
        // Both paths need a scanner. Only the debug message differs.
        if (already_learned) {
          TSDebug(PLUGIN_NAME, "READ_RESPONSE_HDR: TTL expired for %s, re-scanning origin response", req_data->cache_key.c_str());
          // Stale cached_links already set in TSRemapDoRemap (SWR: serve stale while re-learning).
        }
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
            if (ce_str && ce_len > 0) {
              // Trim leading/trailing whitespace before comparing.
              // Some origins add a trailing space: "identity " — exact
              // length check without trim would incorrectly mark as compressed.
              const char *ce_p = ce_str;
              int ce_l         = ce_len;
              while (ce_l > 0 && (*ce_p == ' ' || *ce_p == '\t')) {
                ce_p++;
                ce_l--;
              }
              while (ce_l > 0 && (ce_p[ce_l - 1] == ' ' || ce_p[ce_l - 1] == '\t')) {
                ce_l--;
              }
              if (!(ce_l == 8 && strncasecmp(ce_p, "identity", 8) == 0)) {
                is_compressed = true;
                TSDebug(PLUGIN_NAME, "auto-learn: skipping for %s, response is compressed (Content-Encoding: %.*s)",
                        req_data->cache_key.c_str(), ce_len, ce_str);
              }
            }
            TSHandleMLocRelease(server_bufp, server_hdr_loc, ce_field);
          }
        }

        if (is_html && !is_compressed) {
          // Create transform for HTML scanning
          TransformData *tdata = static_cast<TransformData *>(TSmalloc(sizeof(TransformData)));
          new (tdata) TransformData();
          tdata->scanner      = new HtmlScanner(config->scan_limit(), config->max_links(), config);
          tdata->cache        = cache;
          tdata->cache_key    = req_data->cache_key;
          tdata->req_data_ref = req_data; // for combined mode stat guard

          TSVConn connp = TSTransformCreate(early_hints_transform, txnp);
          if (!connp) {
            TSDebug(PLUGIN_NAME, "TSTransformCreate failed for %s, skipping HTML scanning", req_data->cache_key.c_str());
            delete tdata->scanner;
            tdata->~TransformData();
            TSfree(tdata);
          } else {
            TSContDataSet(connp, tdata);
            TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
            TSDebug(PLUGIN_NAME, "added HTML scanning transform for %s (scan_limit=%d)", req_data->cache_key.c_str(),
                    config->scan_limit());
          }
        }
      }
    }

    TSHandleMLocRelease(server_bufp, TS_NULL_MLOC, server_hdr_loc);
    break;
  }

  case TS_EVENT_HTTP_READ_CACHE_HDR: {
    // ATS Cache Interception (Read-Cache Hook)
    TSMBuffer cache_bufp;
    TSMLoc cache_hdr_loc;

    if (TSHttpTxnCachedRespGet(txnp, &cache_bufp, &cache_hdr_loc) != TS_SUCCESS) {
      TSDebug(PLUGIN_NAME, "READ_CACHE_HDR: failed to get cached response for %s", req_data->cache_key.c_str());
      break;
    }

    TSHttpStatus status = TSHttpHdrStatusGet(cache_bufp, cache_hdr_loc);
    if (status != TS_HTTP_STATUS_OK) {
      TSDebug(PLUGIN_NAME, "READ_CACHE_HDR: skipping non-200 cached response (status=%d) for %s", status,
              req_data->cache_key.c_str());
      TSHandleMLocRelease(cache_bufp, TS_NULL_MLOC, cache_hdr_loc);
      break;
    }

    // ATS Cache Read Interception: Only attach HTML scanner if Auto-Learn is enabled.
    // Skip scanner if entry already learned (links exist regardless of request_count).
    if (config->mode() & EarlyHintsConfig::MODE_AUTO_LEARN) {
      bool already_learned = req_data->has_learned;

      if (already_learned) {
        if (req_data->needs_relearn) {
          // TTL expired but HTML body is frozen in ATS cache — cannot re-scan.
          // Just refresh the TTL so the entry remains valid for another hints_ttl period.
          cache->touch(req_data->cache_key);
          req_data->needs_relearn = false;
          TSDebug(PLUGIN_NAME, "READ_CACHE_HDR: TTL refresh (touch) for frozen %s", req_data->cache_key.c_str());
        } else {
          TSDebug(PLUGIN_NAME, "READ_CACHE_HDR: already learned hints for %s, skipping scanner", req_data->cache_key.c_str());
        }
      } else {
        // Not learned yet — we lost memory state but ATS has the cached response!
        // Re-learn it from ATS Cache without contacting the Origin server.
        TSMLoc ct_field = TSMimeHdrFieldFind(cache_bufp, cache_hdr_loc, TS_MIME_FIELD_CONTENT_TYPE, TS_MIME_LEN_CONTENT_TYPE);
        bool is_html    = false;

        if (ct_field != TS_NULL_MLOC) {
          int ct_len         = 0;
          const char *ct_str = TSMimeHdrFieldValueStringGet(cache_bufp, cache_hdr_loc, ct_field, -1, &ct_len);
          if (ct_str && ct_len >= 9 && strncasecmp(ct_str, "text/html", 9) == 0 &&
              (ct_len == 9 || ct_str[9] == ';' || ct_str[9] == ' ' || ct_str[9] == '\t')) {
            is_html = true;
          }
          TSHandleMLocRelease(cache_bufp, cache_hdr_loc, ct_field);
        }

        bool is_compressed = false;
        if (is_html) {
          TSMLoc ce_field =
            TSMimeHdrFieldFind(cache_bufp, cache_hdr_loc, TS_MIME_FIELD_CONTENT_ENCODING, TS_MIME_LEN_CONTENT_ENCODING);
          if (ce_field != TS_NULL_MLOC) {
            int ce_len         = 0;
            const char *ce_str = TSMimeHdrFieldValueStringGet(cache_bufp, cache_hdr_loc, ce_field, -1, &ce_len);
            if (ce_str && ce_len > 0) {
              // Trim leading/trailing whitespace (same rationale as READ_RESPONSE_HDR).
              const char *ce_p = ce_str;
              int ce_l         = ce_len;
              while (ce_l > 0 && (*ce_p == ' ' || *ce_p == '\t')) {
                ce_p++;
                ce_l--;
              }
              while (ce_l > 0 && (ce_p[ce_l - 1] == ' ' || ce_p[ce_l - 1] == '\t')) {
                ce_l--;
              }
              if (!(ce_l == 8 && strncasecmp(ce_p, "identity", 8) == 0)) {
                is_compressed = true;
                TSDebug(PLUGIN_NAME, "auto-learn (cache): skipping for %s, response is compressed", req_data->cache_key.c_str());
              }
            }
            TSHandleMLocRelease(cache_bufp, cache_hdr_loc, ce_field);
          }
        }

        if (is_html && !is_compressed) {
          TransformData *tdata = static_cast<TransformData *>(TSmalloc(sizeof(TransformData)));
          new (tdata) TransformData();
          tdata->scanner      = new HtmlScanner(config->scan_limit(), config->max_links(), config);
          tdata->cache        = cache;
          tdata->cache_key    = req_data->cache_key;
          tdata->req_data_ref = req_data; // for combined mode stat guard

          TSVConn connp = TSTransformCreate(early_hints_transform, txnp);
          if (!connp) {
            TSDebug(PLUGIN_NAME, "TSTransformCreate failed for %s (cache), skipping HTML scanning", req_data->cache_key.c_str());
            delete tdata->scanner;
            tdata->~TransformData();
            TSfree(tdata);
          } else {
            TSContDataSet(connp, tdata);
            TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
            TSDebug(PLUGIN_NAME, "added HTML scanning transform for %s from ATS cache (scan_limit=%d)", req_data->cache_key.c_str(),
                    config->scan_limit());
          }
        }
      }
    }

    // Commit 14: Origin-Forward self-healing from ATS cached response headers.
    // When origin-forward mode is active and the hints entry was evicted from RAM
    // (or never written — e.g. after a plugin restart), repopulate it from the
    // Link headers stored in the ATS cached response. Same split/normalize/validate/
    // dedup pipeline as READ_RESPONSE_HDR origin-forward path.
    // Only runs when cached_links==nullptr (TSRemapDoRemap found no serveable entry)
    // AND has_learned==false (entry does not exist in the hints cache).
    // Guarding on !has_learned prevents overwriting existing HTML-learned hints
    // with origin Link headers on requests where the entry is below threshold.
    if ((config->mode() & EarlyHintsConfig::MODE_ORIGIN_FORWARD) && !req_data->cached_links && !req_data->has_learned) {
      TSMLoc link_field = TSMimeHdrFieldFind(cache_bufp, cache_hdr_loc, "Link", 4);
      std::vector<std::string> origin_links;

      while (link_field != TS_NULL_MLOC) {
        int val_len         = 0;
        const char *val_str = TSMimeHdrFieldValueStringGet(cache_bufp, cache_hdr_loc, link_field, -1, &val_len);
        if (val_str && val_len > 0) {
          std::string full_val(val_str, val_len);
          int remaining = config->max_links() - static_cast<int>(origin_links.size());
          auto segments = split_link_header_value(full_val, remaining);
          for (auto &seg : segments) {
            std::string normalized = normalize_link_for_hint(seg);
            if (!normalized.empty() && is_valid_link_value(normalized) && has_valid_as_for_preload(normalized)) {
              origin_links.push_back(std::move(normalized));
            }
          }
          origin_links = dedup_link_segments(std::move(origin_links), config->max_links());
        }
        TSMLoc next = TSMimeHdrFieldNextDup(cache_bufp, cache_hdr_loc, link_field);
        TSHandleMLocRelease(cache_bufp, cache_hdr_loc, link_field);
        link_field = next;

        if (static_cast<int>(origin_links.size()) >= config->max_links()) {
          while (link_field != TS_NULL_MLOC) {
            next = TSMimeHdrFieldNextDup(cache_bufp, cache_hdr_loc, link_field);
            TSHandleMLocRelease(cache_bufp, cache_hdr_loc, link_field);
            link_field = next;
          }
          break;
        }
      }

      if (!origin_links.empty()) {
        cache->put(req_data->cache_key, origin_links);
        TSDebug(PLUGIN_NAME, "READ_CACHE_HDR: self-healed %zu origin-forward links for %s from ATS cache", origin_links.size(),
                req_data->cache_key.c_str());
      }
    }

    TSHandleMLocRelease(cache_bufp, TS_NULL_MLOC, cache_hdr_loc);
    break;
  }

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR: {
    TSMBuffer resp_bufp;
    TSMLoc resp_hdr_loc;

    if (TSHttpTxnClientRespGet(txnp, &resp_bufp, &resp_hdr_loc) != TS_SUCCESS) {
      TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: TSHttpTxnClientRespGet failed for %s", req_data->cache_key.c_str());
      break;
    }

    // Only add Link headers to 200 OK responses. Partial (206), no-content (204),
    // redirects, and errors don't correspond to a loadable document — adding
    // preload hints to them would cause spurious fetches in the browser.
    TSHttpStatus resp_status = TSHttpHdrStatusGet(resp_bufp, resp_hdr_loc);
    if (resp_status == TS_HTTP_STATUS_OK) {
      // Build merged links from all active modes — same approach as TSRemapDoRemap.
      // For auto-learn/origin-forward, try cached links from remap first;
      // if not available, fallback to fresh cache lookup (transform may have just learned).
      const std::vector<std::string> *cached_ptr = nullptr;

      if (config->mode() & (EarlyHintsConfig::MODE_AUTO_LEARN | EarlyHintsConfig::MODE_ORIGIN_FORWARD)) {
        if (req_data->cached_links) {
          TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: using cached links (from remap) for %s", req_data->cache_key.c_str());
          cached_ptr = req_data->cached_links.get();
        } else if (!req_data->cache_key.empty()) {
          // Fallback: transform may have just populated the cache during this request.
          // Use peek() (not get()) to avoid double-incrementing request_count.
          // get() was already called in TSRemapDoRemap; calling it again here would
          // count this request twice toward min_hit_count, making the threshold
          // effectively lower than configured.
          TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: fallback peek for %s (transform may have just learned)",
                  req_data->cache_key.c_str());
          req_data->cached_links = cache->peek(req_data->cache_key);
          if (req_data->cached_links) {
            // Enforce min_hit_count for the 200 Link header path.
            // peek() returns data regardless of request_count by design, but we
            // should only serve hints in the 200 response once the URL is popular
            // enough (request_count >= min_hit_count).  get_count() is non-incrementing.
            int count = cache->get_count(req_data->cache_key);
            if (count >= config->min_hit_count()) {
              TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: fallback peek hit for %s, %zu links (count=%d)", req_data->cache_key.c_str(),
                      req_data->cached_links->size(), count);
              cached_ptr = req_data->cached_links.get();
            } else {
              TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: fallback peek hit for %s below threshold (count=%d < min=%d), not serving",
                      req_data->cache_key.c_str(), count, config->min_hit_count());
              req_data->cached_links = nullptr; // do not serve below threshold
            }
          } else {
            TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: fallback peek miss for %s", req_data->cache_key.c_str());
          }
        }
      }

      // Merge: manual links first (priority), then cached links with URL dedup
      std::vector<std::string> empty_vec;
      const std::vector<std::string> &manual_ref =
        (config->mode() & EarlyHintsConfig::MODE_MANUAL) ? config->manual_links() : empty_vec;

      std::vector<std::string> merged = merge_hint_links(manual_ref, cached_ptr, config->max_links());

      TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: merged %zu links for %s (manual=%zu, cached=%zu)", merged.size(),
              req_data->cache_key.c_str(), (config->mode() & EarlyHintsConfig::MODE_MANUAL) ? config->manual_links().size() : 0ul,
              cached_ptr ? cached_ptr->size() : 0ul);

      if (!merged.empty()) {
        TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: adding %zu Link headers to 200 response for %s", merged.size(),
                req_data->cache_key.c_str());
        add_link_headers_to_response(resp_bufp, resp_hdr_loc, merged, config->max_links(), config->header_size_limit());
      } else {
        TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: no links to add for %s", req_data->cache_key.c_str());
      }
    } else {
      TSDebug(PLUGIN_NAME, "SEND_RESPONSE_HDR: skipping Link headers for non-2xx response (status=%d) to %s", resp_status,
              req_data->cache_key.c_str());
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

static int
get_or_create_stat(const char *name)
{
  int id = -1;
  if (TSStatFindName(name, &id) == TS_SUCCESS) {
    return id;
  }
  id = TSStatCreate(name, TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  if (id == TS_ERROR) {
    TSError("[%s] Failed to create statistic: %s", PLUGIN_NAME, name);
  }
  return id;
}

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

  // Register statistics safely
  stat_103_sent             = get_or_create_stat("plugin.early_hints.103_sent");
  stat_103_skipped_h1       = get_or_create_stat("plugin.early_hints.103_skipped_h1");
  stat_103_skipped_bot      = get_or_create_stat("plugin.early_hints.103_skipped_bot");
  stat_103_skipped_no_hints = get_or_create_stat("plugin.early_hints.103_skipped_no_hints");
  stat_103_skipped_non_nav  = get_or_create_stat("plugin.early_hints.103_skipped_non_nav");
  stat_hints_learned        = get_or_create_stat("plugin.early_hints.hints_learned");

  TSDebug(PLUGIN_NAME, "plugin initialized, arg_idx=%d", arg_idx);
  return TS_SUCCESS;
}

// FNV-1a hash for generating unique persist filenames per remap (64-bit)
static uint64_t
fnv1a_hash(const char *str)
{
  uint64_t hash = 14695981039346656037ULL;
  for (; *str; ++str) {
    hash ^= static_cast<uint8_t>(*str);
    hash *= 1099511628211ULL;
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
      // 0750: owner rwx, group rx, no world access — persist dir contains URL path data.
      // On EEXIST, verify via stat() that the path is actually a directory.
      // A file at that path (planted by attacker or leftover crash) must block persistence.
      bool dir_ready = false;
      if (mkdir(dir.c_str(), 0750) == 0) {
        dir_ready = true;
      } else if (errno == EEXIST) {
        struct stat st;
        if (stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
          dir_ready = true;
        } else {
          TSError("[%s] persist dir path '%s' exists but is not a directory — persistence disabled", PLUGIN_NAME, dir.c_str());
        }
      }
      if (!dir_ready) {
        TSError("[%s] failed to create persist dir '%s' — persistence disabled", PLUGIN_NAME, dir.c_str());
      } else {
        // Generate unique filename from remap from-URL (argv[0])
        const char *from_url = (argc > 0 && argv[0]) ? argv[0] : "default";
        char filename[64];
        snprintf(filename, sizeof(filename), "early_hints_%016llx.bin", static_cast<unsigned long long>(fnv1a_hash(from_url)));
        std::string persist_path = dir + "/" + filename;
        cache->set_persist_path(persist_path);
        cache->set_persist_throttle(config->persist_throttle());
        cache->load_from_disk();
        TSDebug(PLUGIN_NAME, "persistence enabled: %s", persist_path.c_str());
      }
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

  TSDebug(PLUGIN_NAME, "new instance created: mode=0x%02x, max_links=%d, header_size_limit=%d, skip_bots=%d, navigate_only=%d",
          config->mode(), config->max_links(), config->header_size_limit(), config->skip_bots(), config->navigate_only());
  TSDebug(PLUGIN_NAME, "  scan_limit=%d, min_hit_count=%d, max_cache_entries=%d, persist=%d", config->scan_limit(),
          config->min_hit_count(), config->max_cache_entries(), config->persist_enabled());
  TSDebug(PLUGIN_NAME, "  debug_header=%s", config->debug_header() ? config->debug_header() : "(none)");
  if (config->mode() & EarlyHintsConfig::MODE_MANUAL) {
    TSDebug(PLUGIN_NAME, "  manual mode: %zu configured links", config->manual_links().size());
    for (size_t i = 0; i < config->manual_links().size(); ++i) {
      TSDebug(PLUGIN_NAME, "    manual link[%zu]: %s", i, config->manual_links()[i].c_str());
    }
  }
  if (!config->crossorigin_whitelist().empty()) {
    TSDebug(PLUGIN_NAME, "  crossorigin whitelist: %zu domains", config->crossorigin_whitelist().size());
    for (const auto &d : config->crossorigin_whitelist()) {
      TSDebug(PLUGIN_NAME, "    whitelisted: %s", d.c_str());
    }
  }
  if (!config->preload_whitelist().empty()) {
    TSDebug(PLUGIN_NAME, "  preload whitelist: %zu domains", config->preload_whitelist().size());
    for (const auto &d : config->preload_whitelist()) {
      TSDebug(PLUGIN_NAME, "    preload domain: %s", d.c_str());
    }
  }
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
    // The HintsCache destructor persists to disk if is_dirty_ is true.
    // Do not call persist_to_disk() explicitly here: a concurrent put()-triggered
    // persist may already be in progress under persist_mutex_, and this call would
    // race against it, writing .tmp simultaneously and potentially corrupting the file.
    delete inst;
  }

  TSContDestroy(contp);
}

TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo * /* rri ATS_UNUSED */)
{
  if (!ih) {
    TSDebug(PLUGIN_NAME, "TSRemapDoRemap: ih is NULL, skipping");
    return TSREMAP_NO_REMAP;
  }

  TSCont contp         = static_cast<TSCont>(ih);
  PluginInstance *inst = static_cast<PluginInstance *>(TSContDataGet(contp));
  if (!inst || !inst->config || !inst->cache) {
    TSDebug(PLUGIN_NAME, "TSRemapDoRemap: instance data missing (inst=%p)", static_cast<void *>(inst));
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
    TSDebug(PLUGIN_NAME, "TSRemapDoRemap: TSHttpTxnClientReqGet failed");
    return TSREMAP_NO_REMAP;
  }

  int method_len     = 0;
  const char *method = TSHttpHdrMethodGet(req_bufp, req_hdr_loc, &method_len);
  bool is_get_head =
    (method_len == static_cast<int>(strlen(TS_HTTP_METHOD_GET)) && strncmp(method, TS_HTTP_METHOD_GET, method_len) == 0) ||
    (method_len == static_cast<int>(strlen(TS_HTTP_METHOD_HEAD)) && strncmp(method, TS_HTTP_METHOD_HEAD, method_len) == 0);

  if (!is_get_head) {
    TSDebug(PLUGIN_NAME, "TSRemapDoRemap: skipping non-GET/HEAD method: %.*s", method_len, method);
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
  TSDebug(PLUGIN_NAME, "TSRemapDoRemap: cache_key=%s, mode=0x%02x", cache_key.c_str(), config->mode());

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
    // Set has_learned so READ_RESPONSE/CACHE_HDR can skip the HTML scanner
    // when this URL has already been learned. Without this, the scanner
    // attaches on every H1 response even for well-known pages, wasting CPU.
    if (!cache_key.empty() && (config->mode() & (EarlyHintsConfig::MODE_AUTO_LEARN | EarlyHintsConfig::MODE_ORIGIN_FORWARD))) {
      req_data->has_learned = (cache->peek(cache_key) != nullptr);
    }
    increment_stat(stat_103_skipped_h1, 1);
    req_data->debug_status = "skipped-h1";
    TSDebug(PLUGIN_NAME, "skipping 103 for %s: client is not H2 (103 requires HTTP/2 or HTTP/3 informational response support)",
            cache_key.c_str());
    goto register_hooks;
  }

  // Check navigate mode
  if (config->navigate_only() && !is_navigate_request(req_bufp, req_hdr_loc)) {
    if (!cache_key.empty() && (config->mode() & (EarlyHintsConfig::MODE_AUTO_LEARN | EarlyHintsConfig::MODE_ORIGIN_FORWARD))) {
      req_data->has_learned = (cache->peek(cache_key) != nullptr);
    }
    increment_stat(stat_103_skipped_non_nav, 1);
    req_data->debug_status = "skipped-non-navigate";
    TSDebug(PLUGIN_NAME, "skipping 103 for %s: non-navigate request (Sec-Fetch-Mode != navigate)", cache_key.c_str());
    goto register_hooks;
  }

  // Check bot detection
  if (config->skip_bots() && is_bot_user_agent(req_bufp, req_hdr_loc)) {
    if (!cache_key.empty() && (config->mode() & (EarlyHintsConfig::MODE_AUTO_LEARN | EarlyHintsConfig::MODE_ORIGIN_FORWARD))) {
      req_data->has_learned = (cache->peek(cache_key) != nullptr);
    }
    increment_stat(stat_103_skipped_bot, 1);
    req_data->debug_status = "skipped-bot";
    TSDebug(PLUGIN_NAME, "skipping 103 for %s: bot User-Agent detected", cache_key.c_str());
    goto register_hooks;
  }

  // Purge header check: if --purge-header is configured and the request carries the correct
  // secret, invalidate the cached hints entry for this URL so it can be re-learned.
  // The purging request itself continues through normal processing: get() will find no entry,
  // no 103 is sent, and the scanner attaches on READ_RESPONSE_HDR to re-learn the page.
  if (!config->purge_header_name().empty()) {
    TSMLoc purge_field_loc = TSMimeHdrFieldFind(req_bufp, req_hdr_loc, config->purge_header_name().c_str(),
                                                static_cast<int>(config->purge_header_name().size()));
    if (purge_field_loc != TS_NULL_MLOC) {
      int val_len               = 0;
      const char *val           = TSMimeHdrFieldValueStringGet(req_bufp, req_hdr_loc, purge_field_loc, -1, &val_len);
      const std::string &secret = config->purge_secret();
      // Note: not constant-time — acceptable for internal CDN use (per ATS remap_purge.c precedent)
      bool token_ok = val && val_len == static_cast<int>(secret.size()) && memcmp(val, secret.c_str(), val_len) == 0;
      TSHandleMLocRelease(req_bufp, req_hdr_loc, purge_field_loc);
      if (token_ok) {
        cache->remove(cache_key);
        TSDebug(PLUGIN_NAME, "purge: removed hints entry for %s", cache_key.c_str());
      } else {
        TSDebug(PLUGIN_NAME, "purge: bad or missing token for %s, ignoring", cache_key.c_str());
      }
    }
  }

  // Build merged links from all active modes
  {
    const std::vector<std::string> *cached_ptr = nullptr;

    // Look up cached links if auto-learn or origin-forward is active
    if (config->mode() & (EarlyHintsConfig::MODE_AUTO_LEARN | EarlyHintsConfig::MODE_ORIGIN_FORWARD)) {
      TSDebug(PLUGIN_NAME, "mode decision for %s: auto-learn/origin-forward active, looking up cache (min_hit_count=%d)",
              cache_key.c_str(), config->min_hit_count());
      req_data->cached_links = cache->get(cache_key, config->min_hit_count());
      if (req_data->cached_links) {
        // Serveable: entry exists and request_count >= min_hit_count
        req_data->has_learned = true;
        TSDebug(PLUGIN_NAME, "cache hit (serveable) for %s: %zu cached links", cache_key.c_str(), req_data->cached_links->size());
        cached_ptr = req_data->cached_links.get();

        // TTL check: if hints_ttl is set and the entry is stale, schedule a re-learn.
        // Stale-While-Revalidate: serve the existing (possibly stale) hints NOW,
        // but flag the request so the scanner re-runs on the next origin response.
        if (config->hints_ttl() > 0) {
          time_t age = cache->get_age(cache_key);
          if (age >= 0 && age >= config->hints_ttl()) {
            req_data->needs_relearn = true;
            TSDebug(PLUGIN_NAME, "cache hit STALE for %s: age=%lds >= ttl=%ds, will re-learn", cache_key.c_str(),
                    static_cast<long>(age), config->hints_ttl());
          }
        }
      } else {
        // get() returned null: either entry doesn't exist OR request_count < min_hit_count.
        // peek() distinguishes the two cases without incrementing request_count again.
        req_data->has_learned = (cache->peek(cache_key) != nullptr);
        if (req_data->has_learned) {
          TSDebug(PLUGIN_NAME, "cache entry exists for %s but below min_hit_count=%d — no 103 yet", cache_key.c_str(),
                  config->min_hit_count());
        } else {
          TSDebug(PLUGIN_NAME, "cache miss for %s — scanner will run on response", cache_key.c_str());
        }
      }
    }

    // Merge: manual links first (priority), then cached links with URL dedup
    std::vector<std::string> empty_vec;
    const std::vector<std::string> &manual_ref =
      (config->mode() & EarlyHintsConfig::MODE_MANUAL) ? config->manual_links() : empty_vec;

    std::vector<std::string> merged = merge_hint_links(manual_ref, cached_ptr, config->max_links());

    TSDebug(PLUGIN_NAME, "merged %zu links for %s (manual=%zu, cached=%zu)", merged.size(), cache_key.c_str(),
            (config->mode() & EarlyHintsConfig::MODE_MANUAL) ? config->manual_links().size() : 0ul,
            cached_ptr ? cached_ptr->size() : 0ul);

    if (!merged.empty()) {
      if (send_103_response(rh, merged, config->max_links(), config->header_size_limit())) {
        req_data->debug_status = "sent";
      } else {
        req_data->debug_status = "send-failed";
      }
    } else {
      increment_stat(stat_103_skipped_no_hints, 1);
      req_data->debug_status = "no-hints";
      TSDebug(PLUGIN_NAME, "no hints available for %s after merge", cache_key.c_str());
    }
  }

register_hooks:
  TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, req_hdr_loc);

  // Always register hooks for learning and response header modification
  TSDebug(PLUGIN_NAME, "registering hooks for %s: READ_RESPONSE_HDR + SEND_RESPONSE_HDR + TXN_CLOSE (status=%s)", cache_key.c_str(),
          req_data->debug_status.c_str());
  TSHttpTxnHookAdd(rh, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  TSHttpTxnHookAdd(rh, TS_HTTP_READ_CACHE_HDR_HOOK, contp);
  TSHttpTxnHookAdd(rh, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
  TSHttpTxnHookAdd(rh, TS_HTTP_TXN_CLOSE_HOOK, contp);

  return TSREMAP_NO_REMAP;
}

void
TSRemapDone()
{
  // No global cleanup needed — per-instance cleanup in TSRemapDeleteInstance
}
