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
#include "session.h"
#include "config.h"
#include "jwt.h"

#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifndef URI_SIGNING_UNIT_TEST
#include "ts/ts.h"
#endif

/**
 * Convert binary hash to hex string.
 *
 * @param hash Binary hash data
 * @param hash_len Length of hash in bytes
 * @return Allocated hex string (lowercase), caller must free()
 */
static char *
hash_to_hex(const unsigned char *hash, size_t hash_len)
{
  char *hex = malloc(hash_len * 2 + 1);
  if (!hex) {
    return NULL;
  }

  for (size_t i = 0; i < hash_len; i++) {
    sprintf(hex + (i * 2), "%02x", hash[i]);
  }
  hex[hash_len * 2] = '\0';
  return hex;
}

#ifndef URI_SIGNING_UNIT_TEST
/**
 * Extract header value from request.
 *
 * @param txn Transaction handle
 * @param header_name Header name to extract
 * @param header_name_len Length of header name
 * @return Allocated header value string, or NULL if not found. Caller must TSfree().
 */
static char *
extract_header(TSHttpTxn txn, const char *header_name, int header_name_len)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  TSMLoc field_loc;
  char *value = NULL;

  if (TSHttpTxnClientReqGet(txn, &bufp, &hdr_loc) != TS_SUCCESS) {
    PluginDebug("Failed to get client request");
    return NULL;
  }

  field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, header_name, header_name_len);
  if (field_loc != TS_NULL_MLOC) {
    int value_len;
    const char *value_ptr = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, -1, &value_len);
    if (value_ptr && value_len > 0) {
      value = TSstrndup(value_ptr, value_len);
    }
    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  }

  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  return value;
}
#endif

char *
generate_salt(
#ifndef URI_SIGNING_UNIT_TEST
  TSHttpTxn txn,
#endif
  struct salt_config *cfg, const char *session_id, const char *user_agent, const char *client_ip)
{
  if (!cfg || !cfg->enabled) {
    return NULL;
  }

  char *session_id_value = NULL;
  char *user_agent_value = NULL;
  char *client_ip_value  = NULL;
  bool need_free_session = false;
  bool need_free_ua      = false;
  bool need_free_ip      = false;

#ifndef URI_SIGNING_UNIT_TEST
  /* Extract headers from request if not provided (production mode) */
  if (cfg->bind_session_id && !session_id) {
    session_id_value  = extract_header(txn, "X-Playback-Session-Id", 21);
    need_free_session = true;
  } else {
    session_id_value = (char *)session_id;
  }

  if (cfg->bind_user_agent && !user_agent) {
    user_agent_value = extract_header(txn, "User-Agent", 10);
    need_free_ua     = true;
  } else {
    user_agent_value = (char *)user_agent;
  }

  if (cfg->bind_client_ip && !client_ip) {
    /* Get client IP from connection */
    struct sockaddr const *client_addr = TSHttpTxnClientAddrGet(txn);
    if (client_addr) {
      if (client_addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)client_addr;
        client_ip_value             = TSmalloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &addr_in->sin_addr, client_ip_value, INET_ADDRSTRLEN);
        need_free_ip = true;
      } else if (client_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)client_addr;
        client_ip_value               = TSmalloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip_value, INET6_ADDRSTRLEN);
        need_free_ip = true;
      }
    }
  } else {
    client_ip_value = (char *)client_ip;
  }
#else
  /* Unit test mode: use provided values */
  session_id_value = (char *)session_id;
  user_agent_value = (char *)user_agent;
  client_ip_value  = (char *)client_ip;
#endif

  /* Build concatenated string for hashing */
  size_t total_len   = 0;
  size_t session_len = 0, ua_len = 0, ip_len = 0;

  if (cfg->bind_session_id && session_id_value) {
    session_len = strlen(session_id_value);
    /* Security: Limit header length to prevent DOS and overflow */
    if (session_len > 4096) {
      PluginError("Session ID too long: %zu bytes (max 4096)", session_len);
      goto cleanup_and_return_null;
    }
    total_len += session_len;
  }

  if (cfg->bind_user_agent && user_agent_value) {
    ua_len = strlen(user_agent_value);
    if (ua_len > 2048) {
      PluginError("User-Agent too long: %zu bytes (max 2048)", ua_len);
      goto cleanup_and_return_null;
    }
    total_len += ua_len;
  }

  if (cfg->bind_client_ip && client_ip_value) {
    ip_len = strlen(client_ip_value);
    if (ip_len > 64) { /* IPv6 max is ~45 chars */
      PluginError("Client IP too long: %zu bytes (max 64)", ip_len);
      goto cleanup_and_return_null;
    }
    total_len += ip_len;
  }

  if (total_len == 0) {
    PluginDebug("No headers available for salt generation");
    goto cleanup_and_return_null;
  }

  /* Security: total_len already validated via individual limits, cannot overflow */
  char *concat = malloc(total_len + 1);
  if (!concat) {
    PluginError("Failed to allocate %zu bytes for salt concatenation", total_len + 1);
    goto cleanup_and_return_null;
  }

  /* Use safe string operations with known lengths */
  char *pos = concat;
  if (cfg->bind_session_id && session_id_value) {
    memcpy(pos, session_id_value, session_len);
    pos += session_len;
  }
  if (cfg->bind_user_agent && user_agent_value) {
    memcpy(pos, user_agent_value, ua_len);
    pos += ua_len;
  }
  if (cfg->bind_client_ip && client_ip_value) {
    memcpy(pos, client_ip_value, ip_len);
    pos += ip_len;
  }
  *pos = '\0'; /* Null terminate */

  PluginDebug("Generating salt from: %s (len=%zu)", concat, total_len);

  /* Compute SHA256 hash */
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256((unsigned char *)concat, total_len, hash);
  free(concat);

#ifndef URI_SIGNING_UNIT_TEST
  if (need_free_session)
    TSfree(session_id_value);
  if (need_free_ua)
    TSfree(user_agent_value);
  if (need_free_ip)
    TSfree(client_ip_value);
#endif

  /* Convert hash to hex string */
  char *hex = hash_to_hex(hash, SHA256_DIGEST_LENGTH);
  if (hex) {
    PluginDebug("Generated salt: %s", hex);
  }
  return hex;

cleanup_and_return_null:
#ifndef URI_SIGNING_UNIT_TEST
  if (need_free_session)
    TSfree(session_id_value);
  if (need_free_ua)
    TSfree(user_agent_value);
  if (need_free_ip)
    TSfree(client_ip_value);
#endif
  return NULL;
}

bool
validate_salt(struct jwt *jwt,
#ifndef URI_SIGNING_UNIT_TEST
              TSHttpTxn txn,
#endif
              struct salt_config *cfg, const char *matched_token_name, const char *access_token_name, const char *session_id,
              const char *user_agent, const char *client_ip)
{
  if (!jwt) {
    PluginDebug("Salt validation failed: NULL JWT");
    return false;
  }

  if (!cfg || !cfg->enabled) {
    /* Salt validation disabled, always pass */
    PluginDebug("Salt validation disabled, skipping");
    return true;
  }

  if (!jwt->cdnisalt) {
    /* Token doesn't have salt claim - check if this is an access token or renewal token
     * based on which parameter name was matched.
     *
     * Security rationale:
     * - Access tokens from origin may not have salt (origin doesn't know device context)
     * - Renewal tokens from CDN MUST have salt when salt.enabled=true (device binding required)
     * - We distinguish by comparing matched parameter name with access token name
     */
    if (matched_token_name && access_token_name && strcmp(matched_token_name, access_token_name) == 0) {
      /* Token was extracted using access token parameter name - this is an access token */
      PluginDebug("Salt validation skipped: access token without cdnisalt (matched_name=%s, access_name=%s)", matched_token_name,
                  access_token_name);
      return true; /* Allow access tokens without salt */
    }

    /* Token was extracted using renewal token parameter name, or names not provided */
    PluginDebug("Salt validation FAILED: renewal token missing required cdnisalt (matched_name=%s, access_name=%s)",
                matched_token_name ? matched_token_name : "<NULL>", access_token_name ? access_token_name : "<NULL>");
    return false; /* Reject renewal tokens without salt */
  }

  /* Security: Validate salt format and length
   * Expected: SHA256 hex digest = exactly 64 characters
   * This prevents DoS attacks using extremely long salt strings
   */
  size_t salt_len = strlen(jwt->cdnisalt);
  if (salt_len != 64) {
    PluginDebug("Salt validation failed: invalid salt length %zu (expected 64)", salt_len);
    return false;
  }

  /* Security: Validate salt contains only hex characters [0-9a-f]
   * This prevents injection attacks and ensures format consistency
   */
  for (size_t i = 0; i < salt_len; i++) {
    char c = jwt->cdnisalt[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      PluginDebug("Salt validation failed: invalid character '%c' at position %zu", c, i);
      return false;
    }
  }

  /* Generate salt from current request */
  char *current_salt = generate_salt(
#ifndef URI_SIGNING_UNIT_TEST
    txn,
#endif
    cfg, session_id, user_agent, client_ip);

  if (!current_salt) {
    PluginDebug("Salt validation failed: could not generate current salt");
    return false;
  }

  /* Compare salts */
  bool match = (strcmp(current_salt, jwt->cdnisalt) == 0);
  if (match) {
    PluginDebug("Salt validation passed: %s", current_salt);
  } else {
    PluginDebug("Salt validation failed: expected=%s, got=%s", jwt->cdnisalt, current_salt);
  }

  free(current_salt);
  return match;
}
