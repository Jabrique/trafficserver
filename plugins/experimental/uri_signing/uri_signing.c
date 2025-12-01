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
#include "config.h"
#include "parse.h"
#include "jwt.h"
#include "timing.h"
#include "session.h"
#include "transform.h"
#include "manifest.h"

#include <ts/remap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <cjose/cjose.h>

/* Plugin registration. */
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    strncpy(errbuf, "[tsremap_init] - Invalid TSRemapInterface argument", (size_t)(errbuf_size - 1));
    return TS_ERROR;
  }

  if (api_info->tsremap_version < TSREMAP_VERSION) {
    snprintf(errbuf, errbuf_size, "[TSRemapInit] - Incorrect API version %ld.%ld", api_info->tsremap_version >> 16,
             (api_info->tsremap_version & 0xffff));
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "plugin is successfully initialized");
  return TS_SUCCESS;
}

/* Create a new remap instance. *ih is passed to DoRemap and DeleteInstance. */
TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  if (argc != 3) {
    snprintf(errbuf, errbuf_size,
             "[TSRemapNewKeyInstance] - Argument count wrong (%d)... Need exactly two pparam= (config file name).", argc);
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "Initializing remap function of %s -> %s with config from %s", argv[0], argv[1], argv[2]);

  char const *const fname = argv[2];

  if (0 == strlen(fname)) {
    snprintf(errbuf, errbuf_size, "[TSRemapNewKeyInstance] - Invalid config file name for %s -> %s", argv[0], argv[1]);
    return TS_ERROR;
  }

  char *config_file = NULL;
  if ('/' == fname[0]) {
    config_file = strdup(fname);
  } else {
    char const *const config_dir = TSConfigDirGet();
    size_t const config_file_ct  = snprintf(NULL, 0, "%s/%s", config_dir, fname);
    config_file                  = malloc(config_file_ct + 1);
    (void)snprintf(config_file, config_file_ct + 1, "%s/%s", config_dir, fname);
  }

  TSDebug(PLUGIN_NAME, "config file name: %s", config_file);
  struct config *cfg = read_config_from_path(config_file);
  if (!cfg) {
    snprintf(errbuf, errbuf_size, "Unable to open config file: \"%s\"", config_file);
    free(config_file);
    return TS_ERROR;
  }
  free(config_file);

  /* BUG #6 FIX (Part 1): Validate signer configuration at plugin load time */
  struct renewal_token_config *renewal_cfg = config_get_renewal_token(cfg);
  if (renewal_cfg && (renewal_cfg->salt.enabled || renewal_cfg->manifest_injection.enabled)) {
    /* Renewal features enabled, signer REQUIRED */
    struct signer *signer = config_signer(cfg);
    if (!signer || !signer->issuer || !signer->jwk || !signer->alg) {
      snprintf(errbuf, errbuf_size,
               "renewal_token enabled but signer not fully configured "
               "(missing renewal_kid, issuer, or keys)");
      config_delete(cfg);
      return TS_ERROR; /* Refuse to load plugin */
    }
  }

  *ih = cfg;

  return TS_SUCCESS;
}

/* Delete remap instance. */
void
TSRemapDeleteInstance(void *ih)
{
  config_delete(ih);
}

int
add_cookie(TSCont cont, TSEvent event, void *edata)
{
  struct timer t;
  start_timer(&t);

  TSHttpTxn txn = (TSHttpTxn)edata;
  char *cookie  = TSContDataGet(cont);
  TSMBuffer buffer;
  TSMLoc hdr;
  TSMLoc field;
  if (!cookie) {
    goto fail;
  }

  if (TSHttpTxnClientRespGet(txn, &buffer, &hdr) == TS_ERROR) {
    goto fail;
  }

  if (TSMimeHdrFieldCreateNamed(buffer, hdr, "Set-Cookie", 10, &field) != TS_SUCCESS) {
    goto fail_hdr;
  }

  if (TSMimeHdrFieldAppend(buffer, hdr, field) != TS_SUCCESS) {
    goto fail_field;
  }

  if (TSMimeHdrFieldValueStringInsert(buffer, hdr, field, 0, cookie, -1) != TS_SUCCESS) {
    goto fail_field;
  }

  PluginDebug("Added cookie to request: %s", cookie);

fail_field:
  TSHandleMLocRelease(buffer, hdr, field);
fail_hdr:
  TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
fail:
  free(cookie);
  TSContDestroy(cont);
  TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);

  PluginDebug("Spent %" PRId64 " ns uri_signing cookie.", mark_timer(&t));
  return 0;
}

TSCont
cont_new(char *cookie)
{
  TSCont cont = TSContCreate(add_cookie, NULL);
  if (!cont) {
    PluginError("Cannot create continuation!");
    free(cookie); /* Nobody else is going to do it at this point. */
    return NULL;
  }
  TSContDataSet(cont, cookie);
  return cont;
}

/* Execute remap request. */
TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  struct timer t;
  start_timer(&t);

  const int max_cpi       = 20;
  int64_t checkpoints[20] = {0};
  int cpi                 = 0;
  int url_ct              = 0;
  const char *url         = NULL;
  char *strip_uri         = NULL;
  TSRemapStatus status    = TSREMAP_NO_REMAP;
  bool checked_auth       = false;
  char *original_jws_str  = NULL; /* BUG #4 FIX: Save original JWT for manifest injection */

  struct config *cfg             = (struct config *)ih;
  const char *access_token_name  = config_get_token_name(cfg);
  const char *renewal_token_name = config_get_renewal_token_name(cfg);
  const char *matched_token_name = NULL; /* Track which token name was matched */

  TSMBuffer mbuf;
  TSMLoc ul;
  TSReturnCode rc = TSHttpTxnPristineUrlGet(txnp, &mbuf, &ul);
  if (rc != TS_SUCCESS) {
    PluginError("Failed call to TSHttpTxnPristineUrlGet()");
    goto fail;
  }
  url = TSUrlStringGet(mbuf, ul, &url_ct);

  TSHandleMLocRelease(mbuf, TS_NULL_MLOC, ul);

  PluginDebug("Processing request for %.*s.", url_ct, url);
  PluginDebug("Token names: URL=%s, Cookie=%s", access_token_name, renewal_token_name);
  checkpoints[cpi++] = mark_timer(&t);

  int strip_size = url_ct + 1;
  strip_uri      = (char *)TSmalloc(strip_size);
  memset(strip_uri, 0, strip_size);

  /* Try to extract JWT from URI - check access token name first */
  size_t strip_ct;
  cjose_jws_t *jws = get_jws_from_uri(url, url_ct, access_token_name, strip_uri, strip_size, &strip_ct, &original_jws_str);
  if (jws) {
    matched_token_name = access_token_name;
    PluginDebug("Found token in URL with parameter name: %s", access_token_name);
  } else if (renewal_token_name && strcmp(renewal_token_name, access_token_name) != 0) {
    /* Also check renewal token name in URL if it differs from access token name */
    /* This maintains backward compatibility with tests that pass renewal tokens via URL */
    jws = get_jws_from_uri(url, url_ct, renewal_token_name, strip_uri, strip_size, &strip_ct, &original_jws_str);
    if (jws) {
      matched_token_name = renewal_token_name;
      PluginDebug("Found token in URL with parameter name: %s", renewal_token_name);
    }
  }

  checkpoints[cpi++] = mark_timer(&t);

  int checked_cookies = 0;
  if (!jws) {
  check_cookies:
    /* There is no valid token in the url */
    strncpy(strip_uri, url, url_ct);
    strip_ct = url_ct;
    ++checked_cookies;

    TSMLoc field;
    TSMBuffer buffer;
    TSMLoc hdr;

    if (TSHttpTxnClientReqGet(txnp, &buffer, &hdr) == TS_ERROR) {
      goto fail;
    }

    field = TSMimeHdrFieldFind(buffer, hdr, "Cookie", 6);
    if (field == TS_NULL_MLOC) {
      TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
      if (!checked_auth) {
        goto check_auth;
      } else {
        goto fail;
      }
    }

    const char *client_cookie;
    int client_cookie_ct;
    client_cookie = TSMimeHdrFieldValueStringGet(buffer, hdr, field, 0, &client_cookie_ct);

    TSHandleMLocRelease(buffer, hdr, field);
    TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);

    if (!client_cookie || !client_cookie_ct) {
      if (!checked_auth) {
        goto check_auth;
      } else {
        goto fail;
      }
    }

    /* Extract JWT from cookie with renewal token name (for cookie-based session tokens) */
    size_t client_cookie_sz_ct = client_cookie_ct;

  check_more_cookies:
    if (cpi < max_cpi) {
      checkpoints[cpi++] = mark_timer(&t);
    }

    /* Check for renewal/session token in cookies */
    jws = get_jws_from_cookie(&client_cookie, &client_cookie_sz_ct, renewal_token_name, &original_jws_str);
    if (jws) {
      matched_token_name = renewal_token_name;
      PluginDebug("Found token in cookie with name: %s", renewal_token_name);
    }
  } else {
    /* There has been a JWS found in the url */
    /* Strip the token from the URL for upstream if configured to do so */
    if (config_strip_token((struct config *)ih)) {
      if ((int)strip_ct != url_ct) {
        int map_url_ct      = 0;
        char *map_url       = NULL;
        char *map_strip_uri = NULL;
        map_url             = TSUrlStringGet(rri->requestBufp, rri->requestUrl, &map_url_ct);

        PluginDebug("Stripping Token from requestUrl: %s", map_url);

        int map_strip_size = map_url_ct + 1;
        map_strip_uri      = (char *)TSmalloc(map_strip_size);
        memset(map_strip_uri, 0, map_strip_size);
        size_t map_strip_ct = 0;

        /* Re-extract token from mapped URL to get stripped version using the matched token name */
        cjose_jws_t *map_jws =
          get_jws_from_uri(map_url, map_url_ct, matched_token_name, map_strip_uri, map_strip_size, &map_strip_ct, NULL);
        if (map_jws) {
          cjose_jws_release(map_jws);
        }

        char const *strip_uri_start = map_strip_uri;

        /* map_strip_uri is null terminated */
        size_t const mlen         = strlen(strip_uri_start);
        char const *strip_uri_end = strip_uri_start + mlen;

        PluginDebug("Stripping token from upstream url to: %.*s", (int)mlen, strip_uri_start);

        TSParseResult parse_rc = TSUrlParse(rri->requestBufp, rri->requestUrl, &strip_uri_start, strip_uri_end);
        if (map_url != NULL) {
          TSfree(map_url);
        }
        if (map_strip_uri != NULL) {
          TSfree(map_strip_uri);
        }

        if (parse_rc != TS_PARSE_DONE) {
          PluginDebug("Error in TSUrlParse");
          goto fail;
        }
        status = TSREMAP_DID_REMAP;
      }
    }
  }
check_auth:
  /* Check auth_dir and pass through if configured */
  if (uri_matches_auth_directive((struct config *)ih, url, url_ct)) {
    PluginDebug("Auth directive matched for %.*s", url_ct, url);
    if (url != NULL) {
      TSfree((void *)url);
    }
    if (strip_uri != NULL) {
      TSfree(strip_uri);
    }
    return TSREMAP_NO_REMAP;
  }
  checked_auth = true;

  if (!jws) {
    goto fail;
  }

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }

  /* BUG #4 FIX: original_jws_str is now saved by get_jws_from_uri/cookie */
  PluginDebug("Original JWT string saved for manifest injection (length=%zu)", original_jws_str ? strlen(original_jws_str) : 0);

  struct jwt *jwt = validate_jws(jws, (struct config *)ih, strip_uri, strip_ct);
  cjose_jws_release(jws);

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }
  if (!jwt) {
    if (!checked_cookies) {
      goto check_cookies;
    } else {
      goto check_more_cookies;
    }
  }

  /* Validate salt if renewal_token configuration exists and salt is enabled */
  struct renewal_token_config *renewal_cfg = config_get_renewal_token((struct config *)ih);
  if (renewal_cfg && renewal_cfg->salt.enabled) {
    if (!validate_salt(jwt, txnp, &renewal_cfg->salt, matched_token_name, access_token_name, NULL, NULL, NULL)) {
      PluginDebug("Salt validation failed for %.*s", url_ct, url);
      jwt_delete(jwt);
      if (!checked_cookies) {
        goto check_cookies;
      } else {
        goto check_more_cookies;
      }
    }
    PluginDebug("Salt validation passed for %.*s", url_ct, url);
  }

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }

  /* There has been a validated JWT found in either the cookie or url */

  /* Generate salt for renewal token if enabled */
  char *generated_salt = NULL;
  if (renewal_cfg && renewal_cfg->salt.enabled) {
    generated_salt = generate_salt(txnp, &renewal_cfg->salt, NULL, NULL, NULL);
    if (generated_salt) {
      PluginDebug("Generated salt for renewal token: %s", generated_salt);
    }
  }

  struct signer *signer = config_signer((struct config *)ih);
  /* Use renewal token name for the cookie, or access token name if not configured */
  const char *cookie_token_name = renewal_token_name;
  char *cookie                  = NULL;

  /* BUG #6 FIX (Part 2): Runtime NULL check for defense in depth */
  if (!signer || !signer->issuer || !signer->jwk || !signer->alg) {
    PluginError("CRITICAL: Signer not configured for renewal (issuer: %s)", jwt->iss ? jwt->iss : "unknown");
    /* Do NOT renew, but continue serving (use existing token) */
  } else {
    /* BUG #9 FIX: Access tokens always renew to create session token.
     * Threshold optimization only applies to session tokens. */
    double current_time  = (double)time(NULL);
    double time_to_exp   = jwt->exp - current_time;
    double threshold     = renewal_cfg ? renewal_cfg->renewal_threshold : 0.0;
    bool is_access_token = (matched_token_name == access_token_name);

    if (should_renew_token(is_access_token, threshold, time_to_exp)) {
      PluginDebug("Renewing token: is_access=%d, threshold=%.0f, exp in %.0f sec", is_access_token, threshold, time_to_exp);
      cookie = renew(jwt, signer->issuer, signer->jwk, signer->alg, cookie_token_name, strip_uri, strip_ct, generated_salt);
    } else {
      PluginDebug("Skipping renewal: session token still fresh (exp in %.0f sec > threshold %.0f sec)", time_to_exp, threshold);
    }
  }

  if (generated_salt) {
    free(generated_salt);
  }

  jwt_delete(jwt);

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }
  if (cookie) {
    PluginDebug("Scheduling cookie callback for %.*s", url_ct, url);
    TSCont cont = cont_new(cookie);
    TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, cont);
  }

  /* BUG #4 FIX: Manifest injection decoupled from renewal */
  /* Works for both renewable and non-renewable tokens */
  if (renewal_cfg && renewal_cfg->manifest_injection.enabled) {
    /* CRITICAL: Cache behavior configuration.
     *
     * cache_untransformed=true (RECOMMENDED, DEFAULT):
     *   - ATS caches the clean manifest from origin (shared cache)
     *   - Transform runs on every request to inject per-user tokens
     *   - Origin load: ↓99.99%, Cache efficiency: ↑99.99%
     *   - Edge CPU: ↑10-20% (acceptable trade-off)
     *
     * cache_untransformed=false (LEGACY):
     *   - ATS caches transformed manifest with per-user tokens (cache pollution)
     *   - One cache entry per unique token = high origin load
     *   - Only use if edge CPU is critical constraint
     *
     * Example with 10,000 concurrent users:
     *   true:  1 origin request, 1 shared cache entry
     *   false: 10,000 origin requests, 10,000 cache entries
     *
     * See docs/HOOKS_AND_TRANSFORM.md for detailed explanation.
     */
    if (renewal_cfg->manifest_injection.cache_untransformed) {
      TSHttpTxnUntransformedRespCache(txnp, 1);
      PluginDebug("Cache untransformed enabled: clean manifest will be cached");
    } else {
      PluginDebug("Cache untransformed disabled: transformed manifest will be cached (cache pollution warning!)");
    }

    const char *renewal_token_name = config_get_renewal_token_name((struct config *)ih);
    if (!renewal_token_name) {
      renewal_token_name = "cr-session-token"; /* Default */
    }

    /* BUG #4 FIX: Priority logic for token selection */
    char *renewal_jws_token        = NULL;
    const char *token_for_manifest = NULL;

    if (cookie) {
      /* Priority 1: Extract renewal token from Set-Cookie header using helper function */
      renewal_jws_token = extract_jws_from_set_cookie(cookie);
      if (renewal_jws_token) {
        token_for_manifest = renewal_jws_token;
        PluginDebug("Using renewal token for manifest injection (token length %zu)", strlen(renewal_jws_token));
      }
    }

    if (!token_for_manifest && original_jws_str) {
      /* Priority 2: Use original validated token from request */
      /* This fixes BUG #4: Non-renewable tokens (cdnistt=0) now get manifest injection */
      token_for_manifest = original_jws_str;
      PluginDebug("Using original validated token for manifest injection (no renewal, token length %zu)", strlen(original_jws_str));
    }

    if (token_for_manifest) {
      setup_manifest_transform(txnp, token_for_manifest, renewal_token_name, access_token_name, &renewal_cfg->manifest_injection);
      PluginDebug("Manifest transform scheduled for %.*s", url_ct, url);
    } else {
      /* This should not happen - we always have either renewal or original token */
      PluginDebug("WARNING: No token available for manifest injection (this should not happen)");
    }

    /* Clean up allocated tokens - transform has made its own copy */
    if (renewal_jws_token) {
      free(renewal_jws_token); /* From extract_jws_from_set_cookie() - uses malloc */
    }
    if (original_jws_str) {
      TSfree(original_jws_str); /* From get_jws_from_uri/cookie() - uses TSmalloc */
      original_jws_str = NULL;
    }
  }

  int64_t last_mark = 0;
  for (int i = 0; i < cpi; ++i) {
    PluginDebug("Spent %" PRId64 " ns in checkpoint %d.", checkpoints[i] - last_mark, i);
    last_mark = checkpoints[i];
  }
  PluginDebug("Spent %" PRId64 " ns uri_signing verification of %.*s.", mark_timer(&t), url_ct, url);

  TSfree((void *)url);
  if (strip_uri != NULL) {
    TSfree(strip_uri);
  }
  return status;
fail:
  TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_FORBIDDEN);
  if (url != NULL) {
    PluginDebug("Invalid JWT for %.*s", url_ct, url);
    PluginDebug("Spent %" PRId64 " ns uri_signing verification of %.*s.", mark_timer(&t), url_ct, url);
    TSfree((void *)url);
  }
  if (strip_uri != NULL) {
    TSfree(strip_uri);
  }
  if (original_jws_str != NULL) {
    TSfree(original_jws_str);
  }

  return TSREMAP_DID_REMAP;
}
