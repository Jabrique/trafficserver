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
#include "timing.h"
#include "jwt.h"
#include "normalize.h"

#include <cjose/cjose.h>
#include <jansson.h>

#include <string.h>
#include <search.h>
#include <errno.h>
#include <regex.h>

#define JSONError(err) PluginError("json-err: %s:%d:%d: %s", (err).source, (err).line, (err).column, (err).text)

#define AUTH_DENY 0
#define AUTH_ALLOW 1
struct auth_directive {
  char auth;
  char *container;
  regex_t compiled_regex;
  bool regex_compiled; /* true if compiled_regex is valid and must be regfree'd */
};

struct config {
  struct hsearch_data *issuers;
  cjose_jwk_t ***jwkis;
  char **issuer_names;
  struct signer signer;
  struct auth_directive *auth_directives;
  char *id;
  bool strip_token;
  char *token_name;                           /* Access token parameter name (default: "cr-access-token") */
  struct renewal_token_config *renewal_token; /* Renewal token configuration (Auth Level 2) */
};

cjose_jwk_t **
find_keys(struct config *cfg, const char *issuer)
{
  ENTRY *entry;
  if (!hsearch_r((ENTRY){.key = (char *)issuer}, FIND, &entry, cfg->issuers) || !entry) {
    PluginDebug("Unable to locate any keys at %p for issuer %s in %p->%p", entry, issuer, cfg, cfg->issuers);
    return NULL;
  }

  int n = 0;
  for (cjose_jwk_t **jwks = entry->data; *jwks; ++jwks, ++n) {
    ;
  }
  PluginDebug("Located %d keys for issuer %s in %p->%p", n, issuer, cfg, cfg->issuers);
  return entry->data;
}

cjose_jwk_t *
find_key_by_kid(struct config *cfg, const char *issuer, const char *kid)
{
  const char *this_kid;
  cjose_jwk_t **jwkis = find_keys(cfg, issuer);
  if (!jwkis) {
    return NULL;
  }
  for (cjose_jwk_t **jwks = jwkis; *jwks; ++jwks) {
    if ((this_kid = cjose_jwk_get_kid(*jwks, NULL)) && !strcmp(this_kid, kid)) {
      return *jwks;
    }
  }
  return NULL;
}

const char *
config_get_id(struct config *cfg)
{
  return cfg->id;
}

bool
config_strip_token(struct config *cfg)
{
  return cfg->strip_token;
}

const char *
config_get_token_name(struct config *cfg)
{
  if (!cfg || !cfg->token_name) {
    /* Return default token name if config is NULL or not initialized */
    return "cr-access-token";
  }
  return cfg->token_name;
}

struct renewal_token_config *
config_get_renewal_token(struct config *cfg)
{
  if (!cfg) {
    return NULL;
  }
  return cfg->renewal_token;
}

const char *
config_get_renewal_token_name(struct config *cfg)
{
  if (!cfg || !cfg->renewal_token || !cfg->renewal_token->token_name) {
    /* Return default session token name for cookies */
    return "cr-session-token";
  }
  return cfg->renewal_token->token_name;
}

bool
should_renew_token(bool is_access_token, double threshold, double time_to_exp)
{
  /* Access tokens always renew — first contact must create a session token */
  if (is_access_token) {
    return true;
  }

  /* Session token: threshold=0.0 means "always renew" (backward compatible) */
  if (threshold <= 0.0) {
    return true;
  }

  /* Session token: only renew when approaching expiry */
  return time_to_exp <= threshold;
}

struct config *
config_new(size_t n)
{
  PluginDebug("Creating new config object with size %ld", n);
  struct config *cfg = malloc(sizeof *cfg);
  if (!cfg) {
    PluginError("Failed to allocate config structure (%zu bytes)", sizeof *cfg);
    return NULL;
  }

  cfg->issuers = calloc(1, sizeof *cfg->issuers);
  if (!cfg->issuers) {
    PluginError("Failed to allocate issuers hash table");
    free(cfg);
    return NULL;
  }

  if (!hcreate_r(n * 2, cfg->issuers)) {
    PluginError("Unable to create config table (%d)!", errno);
    free(cfg->issuers);
    free(cfg);
    return NULL;
  }
  PluginDebug("Created table with size %d", cfg->issuers->size);

  cfg->jwkis = malloc((n + 1) * sizeof *cfg->jwkis);
  if (!cfg->jwkis) {
    PluginError("Failed to allocate jwkis array (%zu bytes)", (n + 1) * sizeof *cfg->jwkis);
    hdestroy_r(cfg->issuers);
    free(cfg->issuers);
    free(cfg);
    return NULL;
  }
  cfg->jwkis[n] = NULL;

  cfg->issuer_names = malloc((n + 1) * sizeof *cfg->issuer_names);
  if (!cfg->issuer_names) {
    PluginError("Failed to allocate issuer_names array (%zu bytes)", (n + 1) * sizeof *cfg->issuer_names);
    free(cfg->jwkis);
    hdestroy_r(cfg->issuers);
    free(cfg->issuers);
    free(cfg);
    return NULL;
  }
  cfg->issuer_names[n] = NULL;

  cfg->signer.issuer = NULL;
  cfg->signer.jwk    = NULL;
  cfg->signer.alg    = NULL;

  cfg->auth_directives = NULL;
  cfg->id              = NULL;

  cfg->strip_token = false;
  cfg->token_name  = NULL;

  cfg->renewal_token = NULL;

  PluginDebug("New config object created at %p", cfg);
  return cfg;
}

void
config_delete(struct config *cfg)
{
  if (!cfg) {
    return;
  }
  hdestroy_r(cfg->issuers);
  free(cfg->issuers);

  for (cjose_jwk_t ***jwkis = cfg->jwkis; *jwkis; ++jwkis) {
    for (cjose_jwk_t **jwks = *jwkis; *jwks; ++jwks) {
      cjose_jwk_release(*jwks);
    }
    free(*jwkis);
  }
  free(cfg->jwkis);

  if (cfg->id) {
    free(cfg->id);
  }

  if (cfg->token_name) {
    free(cfg->token_name);
  }

  if (cfg->renewal_token) {
    if (cfg->renewal_token->token_name) {
      free(cfg->renewal_token->token_name);
    }
    free(cfg->renewal_token);
  }

  for (char **name = cfg->issuer_names; *name; ++name) {
    free(*name);
  }
  free(cfg->issuer_names);

  if (cfg->signer.alg) {
    free(cfg->signer.alg);
  }

  if (cfg->auth_directives) {
    for (struct auth_directive *ad = cfg->auth_directives; ad->container; ++ad) {
      if (ad->regex_compiled) {
        regfree(&ad->compiled_regex);
      }
      free(ad->container);
    }
    free(cfg->auth_directives);
  }
  free(cfg);
}

cjose_jwk_t *
load_jwk(json_t *obj, cjose_err *err)
{
  char *s = json_dumps(obj, JSON_COMPACT);
  if (!s) {
    PluginError("Failed to re-serialize JSON sub-object.");
    return NULL;
  }

  cjose_jwk_t *jwk = cjose_jwk_import(s, strlen(s), err);
  free(s);
  return jwk;
}

static struct config *
read_config_from_json(json_t *const issuer_json)
{
  if (!json_is_object(issuer_json)) {
    PluginError("Config file is not a valid JSON object");
    goto issuer_fail;
  }

  size_t issuers_ct = json_object_size(issuer_json);
  if (!issuers_ct) {
    PluginError("Config file contains no issuers.");
    goto issuer_fail;
  }

  struct config *cfg = config_new(issuers_ct);
  if (!cfg) {
    PluginError("Unable to allocate config.");
    goto issuer_fail;
  }

  cjose_jwk_t ***jwkis = cfg->jwkis;
  char **issuer        = cfg->issuer_names;
  const char *json_issuer;
  json_t *jwks;
  json_object_foreach(issuer_json, json_issuer, jwks)
  {
    *issuer = strdup(json_issuer);

    json_t *ad_json = json_object_get(jwks, "auth_directives");
    if (ad_json) {
      PluginDebug("Loading auth_directives.");
      size_t ad_ct = json_array_size(ad_json);
      if (ad_ct) {
        PluginDebug("Loading %d new auth_directives.", (int)ad_ct);
        struct auth_directive *ad = cfg->auth_directives;
        if (cfg->auth_directives) {
          /* We've already got directives, so extend them. */
          PluginDebug("Extending existing auth_directives.");
          size_t ad_old_ct = 0;
          while (ad->container) {
            ++ad;
            ++ad_old_ct;
          }
          struct auth_directive *new_ad = realloc(cfg->auth_directives, (ad_ct + ad_old_ct + 1) * sizeof *cfg->auth_directives);
          if (!new_ad) {
            PluginError("Failed to extend auth_directives (realloc %zu bytes)",
                        (ad_ct + ad_old_ct + 1) * sizeof *cfg->auth_directives);
            goto cfg_fail;
          }
          cfg->auth_directives = new_ad;
          ad                   = cfg->auth_directives + ad_old_ct;
        } else {
          ad = cfg->auth_directives = malloc((ad_ct + 1) * sizeof *cfg->auth_directives);
          if (!ad) {
            PluginError("Failed to allocate auth_directives (%zu bytes)", (ad_ct + 1) * sizeof *cfg->auth_directives);
            goto cfg_fail;
          }
        }
        json_t *ad_obj;
        for (size_t idx = 0; (idx < ad_ct) && (ad_obj = json_array_get(ad_json, idx)); ++idx) {
          json_t *uri_json  = json_object_get(ad_obj, "uri");
          json_t *auth_json = json_object_get(ad_obj, "auth");
          if (!uri_json) {
            PluginError("auth_directive at index %zu missing 'uri' field, skipping", idx);
            continue;
          }
          const char *uri    = json_string_value(uri_json);
          ad->container      = strdup(uri ? uri : "");
          ad->auth           = AUTH_DENY;
          ad->regex_compiled = false;
          if (auth_json) {
            const char *auth = json_string_value(auth_json);
            if (!auth) {
              auth = "";
            }
            if (!strcmp(auth, "allow")) {
              ad->auth = AUTH_ALLOW;
            } else if (!strcmp(auth, "deny")) {
              ad->auth = AUTH_DENY;
            } else {
              PluginError("auth_directive has unknown auth parameter '%s', defaulting to deny: %s", auth, uri);
            }
          } else {
            PluginError("auth_directive is missing auth parameter, defaulting to deny: %s", uri);
          }

          /* Pre-compile regex at config load time to avoid per-request regcomp() overhead.
           * Pattern format is "regex:<pattern>" — extract part after "regex:" prefix. */
          if (ad->container && !strncmp(ad->container, "regex:", 6)) {
            const char *pattern = ad->container + 6;
            int comp_err;
            if (pattern[0] == '^') {
              comp_err = regcomp(&ad->compiled_regex, pattern, REG_EXTENDED | REG_NOSUB);
            } else {
              size_t pattern_len     = strlen(pattern);
              char *anchored_pattern = malloc(pattern_len + 2);
              if (anchored_pattern) {
                anchored_pattern[0] = '^';
                memcpy(anchored_pattern + 1, pattern, pattern_len + 1);
                comp_err = regcomp(&ad->compiled_regex, anchored_pattern, REG_EXTENDED | REG_NOSUB);
                free(anchored_pattern);
              } else {
                PluginError("Failed to allocate anchored pattern for auth_directive regex");
                comp_err = -1;
              }
            }
            if (comp_err == 0) {
              ad->regex_compiled = true;
              PluginDebug("Pre-compiled regex for auth_directive: %s", ad->container);
            } else {
              PluginError("Failed to compile regex for auth_directive: %s", ad->container);
            }
          }

          PluginDebug("Adding auth_directive %d for %s.", (int)ad->auth, ad->container);
          ++ad;
        }
        ad->container      = NULL;
        ad->regex_compiled = false;
      }
    } else {
      PluginDebug("No auth_directives to load for %s.", *issuer);
    }

    json_t *key_ary = json_object_get(jwks, "keys");
    if (!key_ary) {
      PluginError("Failed to get keys member from jwk for issuer %s", *issuer);
      *jwkis = NULL;
      goto cfg_fail;
    }
    PluginDebug("Created table with size %d", cfg->issuers->size);

    const char *renewal_kid  = NULL;
    json_t *renewal_kid_json = json_object_get(jwks, "renewal_kid");
    if (renewal_kid_json) {
      renewal_kid = json_string_value(renewal_kid_json);
    }

    json_t *id_json = json_object_get(jwks, "id");
    const char *id;
    if (id_json) {
      id = json_string_value(id_json);
      if (id) {
        /* Security: Limit ID length to prevent DoS via memory exhaustion */
        size_t id_len = strlen(id);
        if (id_len > 1024) {
          PluginError("Config ID too long: %zu bytes (max 1024)", id_len);
          goto cfg_fail;
        }
        cfg->id = malloc(id_len + 1);
        if (!cfg->id) {
          PluginError("Failed to allocate %zu bytes for config ID", id_len + 1);
          goto cfg_fail;
        }
        strcpy(cfg->id, id);
        PluginDebug("Found Id in the config: %s", cfg->id);
      }
    }

    json_t *strip_json = json_object_get(jwks, "strip_token");
    if (strip_json) {
      cfg->strip_token = json_boolean_value(strip_json);
    }

    /* Get token parameter name from config */
    if (!cfg->token_name) {
      json_t *token_name_json = json_object_get(jwks, "access_token_name");
      const char *token_name  = NULL;
      if (token_name_json) {
        token_name = json_string_value(token_name_json);
      }
      /* Use default if not specified or empty */
      if (!token_name || strlen(token_name) == 0) {
        token_name = "cr-access-token";
      }
      cfg->token_name = strdup(token_name);
      if (!cfg->token_name) {
        PluginError("Failed to allocate memory for token_name");
        goto cfg_fail;
      }
      PluginDebug("Token parameter name: %s", cfg->token_name);
    }

    /* Parse renewal_token configuration (Auth Level 2) */
    json_t *renewal_token_json = json_object_get(jwks, "renewal_token");
    if (renewal_token_json && !cfg->renewal_token) {
      PluginDebug("Parsing renewal_token configuration");
      cfg->renewal_token = malloc(sizeof *cfg->renewal_token);
      if (!cfg->renewal_token) {
        PluginError("Failed to allocate renewal_token config");
        goto cfg_fail;
      }

      /* Initialize with defaults */
      cfg->renewal_token->token_name                                 = NULL;
      cfg->renewal_token->renewal_threshold                          = 0.0; /* Default: always renew if cdnistt=1 */
      cfg->renewal_token->salt.enabled                               = false;
      cfg->renewal_token->salt.bind_session_id                       = true; /* Default: bind session ID */
      cfg->renewal_token->salt.bind_user_agent                       = false;
      cfg->renewal_token->salt.bind_client_ip                        = false;
      cfg->renewal_token->manifest_injection.enabled                 = false;
      cfg->renewal_token->manifest_injection.inject_to_segments      = true;
      cfg->renewal_token->manifest_injection.inject_to_init_segments = false;
      cfg->renewal_token->manifest_injection.replace_access_token    = true; /* Default: replace access token (recommended) */
      cfg->renewal_token->manifest_injection.hls_support             = true;
      cfg->renewal_token->manifest_injection.dash_support            = true;
      cfg->renewal_token->manifest_injection.cache_untransformed     = true; /* Default: cache clean manifest (recommended) */

      /* Parse renewal token name */
      json_t *rt_token_name_json = json_object_get(renewal_token_json, "token_name");
      if (rt_token_name_json) {
        const char *rt_token_name = json_string_value(rt_token_name_json);
        if (rt_token_name && strlen(rt_token_name) > 0) {
          cfg->renewal_token->token_name = strdup(rt_token_name);
          if (!cfg->renewal_token->token_name) {
            PluginError("Failed to allocate memory for renewal_token token_name");
            free(cfg->renewal_token);
            cfg->renewal_token = NULL;
            goto cfg_fail;
          }
        }
      }

      /* Parse renewal threshold */
      json_t *rt_threshold_json = json_object_get(renewal_token_json, "renewal_threshold");
      if (rt_threshold_json) {
        if (json_is_number(rt_threshold_json)) {
          double threshold = json_number_value(rt_threshold_json);
          if (threshold >= 0.0) {
            cfg->renewal_token->renewal_threshold = threshold;
            PluginDebug("Renewal threshold: %.2f seconds", threshold);
          } else {
            PluginError("Invalid renewal_threshold: %.2f (must be >= 0.0), using default 0.0", threshold);
          }
        } else {
          PluginError("renewal_threshold must be a number, using default 0.0");
        }
      }

      /* Parse salt configuration */
      json_t *salt_json = json_object_get(renewal_token_json, "salt");
      if (salt_json) {
        json_t *salt_enabled = json_object_get(salt_json, "enabled");
        if (salt_enabled) {
          cfg->renewal_token->salt.enabled = json_boolean_value(salt_enabled);
        }

        json_t *bind_session_id = json_object_get(salt_json, "bind_session_id");
        if (bind_session_id) {
          cfg->renewal_token->salt.bind_session_id = json_boolean_value(bind_session_id);
        }

        json_t *bind_user_agent = json_object_get(salt_json, "bind_user_agent");
        if (bind_user_agent) {
          cfg->renewal_token->salt.bind_user_agent = json_boolean_value(bind_user_agent);
        }

        json_t *bind_client_ip = json_object_get(salt_json, "bind_client_ip");
        if (bind_client_ip) {
          cfg->renewal_token->salt.bind_client_ip = json_boolean_value(bind_client_ip);
        }

        /* Set default token name if salt is enabled and name not specified */
        if (cfg->renewal_token->salt.enabled && !cfg->renewal_token->token_name) {
          cfg->renewal_token->token_name = strdup("cr-session-token");
          if (!cfg->renewal_token->token_name) {
            PluginError("Failed to allocate memory for default renewal_token token_name");
            free(cfg->renewal_token);
            cfg->renewal_token = NULL;
            goto cfg_fail;
          }
        }

        PluginDebug("Salt config: enabled=%d, session_id=%d, user_agent=%d, client_ip=%d", cfg->renewal_token->salt.enabled,
                    cfg->renewal_token->salt.bind_session_id, cfg->renewal_token->salt.bind_user_agent,
                    cfg->renewal_token->salt.bind_client_ip);
      }

      /* Parse manifest_injection configuration */
      json_t *manifest_json = json_object_get(renewal_token_json, "manifest_injection");
      if (manifest_json) {
        json_t *mi_enabled = json_object_get(manifest_json, "enabled");
        if (mi_enabled) {
          cfg->renewal_token->manifest_injection.enabled = json_boolean_value(mi_enabled);
        }

        json_t *inject_segments = json_object_get(manifest_json, "inject_to_segments");
        if (inject_segments) {
          cfg->renewal_token->manifest_injection.inject_to_segments = json_boolean_value(inject_segments);
        }

        json_t *inject_init = json_object_get(manifest_json, "inject_to_init_segments");
        if (inject_init) {
          cfg->renewal_token->manifest_injection.inject_to_init_segments = json_boolean_value(inject_init);
        }

        /* Support both new name (replace_access_token) and old name (strip_access_token_from_upstream) for backward compatibility
         */
        json_t *replace_token = json_object_get(manifest_json, "replace_access_token");
        if (replace_token) {
          cfg->renewal_token->manifest_injection.replace_access_token = json_boolean_value(replace_token);
        } else {
          /* Fallback to old name for backward compatibility */
          json_t *strip_access = json_object_get(manifest_json, "strip_access_token_from_upstream");
          if (strip_access) {
            cfg->renewal_token->manifest_injection.replace_access_token = json_boolean_value(strip_access);
            PluginDebug("Warning: 'strip_access_token_from_upstream' is deprecated, use 'replace_access_token' instead");
          }
        }

        json_t *hls_support = json_object_get(manifest_json, "hls_support");
        if (hls_support) {
          cfg->renewal_token->manifest_injection.hls_support = json_boolean_value(hls_support);
        }

        json_t *dash_support = json_object_get(manifest_json, "dash_support");
        if (dash_support) {
          cfg->renewal_token->manifest_injection.dash_support = json_boolean_value(dash_support);
        }

        json_t *cache_untransformed = json_object_get(manifest_json, "cache_untransformed");
        if (cache_untransformed) {
          cfg->renewal_token->manifest_injection.cache_untransformed = json_boolean_value(cache_untransformed);
        }

        PluginDebug("Manifest injection config: enabled=%d, hls=%d, dash=%d, cache_untransformed=%d",
                    cfg->renewal_token->manifest_injection.enabled, cfg->renewal_token->manifest_injection.hls_support,
                    cfg->renewal_token->manifest_injection.dash_support,
                    cfg->renewal_token->manifest_injection.cache_untransformed);
      }

      PluginDebug("Renewal token configuration loaded: %s",
                  cfg->renewal_token->token_name ? cfg->renewal_token->token_name : "(use access token name)");
    }

    size_t jwks_ct     = json_array_size(key_ary);
    cjose_jwk_t **jwks = (*jwkis++ = malloc((jwks_ct + 1) * sizeof *jwks));
    PluginDebug("Created table with size %d", cfg->issuers->size);
    if (!hsearch_r(((ENTRY){*issuer, jwks}), ENTER, &(ENTRY *){0}, cfg->issuers)) {
      PluginDebug("Failed to store keys for issuer %s", *issuer);
    } else {
      PluginDebug("Stored keys for %s at %16p", *issuer, jwks);
    }

    json_t *jwk_obj;
    cjose_err jwk_err;
    memset(&jwk_err, 0, sizeof(cjose_err));
    for (size_t idx = 0; (idx < jwks_ct) && (jwk_obj = json_array_get(key_ary, idx)); ++idx, ++jwks) {
      if ((*jwks = load_jwk(jwk_obj, &jwk_err))) {
        const char *kid = cjose_jwk_get_kid(*jwks, NULL);
        PluginDebug("Stored jwk %ld for issuer %s, kid %s, cfg %p->%p", idx, *issuer, kid ? kid : "<no kid>", cfg, cfg->issuers);
        if (renewal_kid && kid && !strcmp(kid, renewal_kid)) {
          if (cfg->signer.issuer) {
            PluginError("Cannot load multiple renewal keys for a single remap. iss:\"%s\", kid:\"%s\"; iss:\"%s\", kid:\"%s\"",
                        cfg->signer.issuer, cjose_jwk_get_kid(cfg->signer.jwk, NULL), *issuer, kid);
            goto cfg_fail;
          } else {
            cfg->signer.issuer = *issuer;
            cfg->signer.jwk    = *jwks;

            const char *jwk_alg = json_string_value(json_object_get(jwk_obj, "alg"));
            if (!jwk_alg) {
              PluginError("Cannot load JWK algorithm for renewal key.");
              goto cfg_fail;
            }
            cfg->signer.alg = strdup(jwk_alg);
          }
        }
      } else {
        PluginError("Failed to load jwk %ld for issuer %s: %s", idx, *issuer, jwk_err.message);
        goto cfg_fail;
      }
    }
    *jwks = NULL;
    ++issuer;
  }
  /* Only require signer if renewal_token is configured */
  if (cfg->renewal_token && !cfg->signer.issuer) {
    PluginError("Cannot load remap with renewal_token configured but no signing key (renewal_kid not found).");
    goto cfg_fail;
  }

  /* Ensure token_name is set (use default if not configured) */
  if (!cfg->token_name) {
    cfg->token_name = strdup("cr-access-token");
    PluginDebug("Using default token parameter name: cr-access-token");
  }

  json_decref(issuer_json);
  PluginDebug("Loaded config file successfully.");
  return cfg;
cfg_fail:
  config_delete(cfg);
issuer_fail:
  json_decref(issuer_json);
  return NULL;
}

struct config *
read_config_from_path(char const *const path)
{
  json_error_t err;
  memset(&err, 0, sizeof(json_error_t));
  json_t *issuer_json = json_load_file(path, 0, &err);
  if (!issuer_json) {
    JSONError(err);
    return NULL;
  }
  return read_config_from_json(issuer_json);
}

struct config *
read_config_from_string(char const *const buffer)
{
  json_error_t err;
  memset(&err, 0, sizeof(json_error_t));
  json_t *issuer_json = json_loads(buffer, 0, &err);
  if (!issuer_json) {
    JSONError(err);
    return NULL;
  }
  return read_config_from_json(issuer_json);
}

struct signer *
config_signer(struct config *cfg)
{
  if (!cfg) {
    return NULL;
  }
  return &cfg->signer;
}

bool
uri_matches_auth_directive(struct config *cfg, const char *uri, size_t uri_ct)
{
  if (!cfg || !cfg->auth_directives || !uri) {
    return false;
  }

  char *uri_s = malloc(uri_ct + 1);
  if (!uri_s) {
    return false;
  }
  memcpy(uri_s, uri, uri_ct);
  uri_s[uri_ct] = 0;

  /* Normalize URI once for all compiled regex matches */
  int buff_ct      = uri_ct + 2;
  char *normal_uri = (char *)TSmalloc(buff_ct);
  memset(normal_uri, 0, buff_ct);
  bool have_normal = (normalize_uri(uri_s, uri_ct, normal_uri, buff_ct) == 0);

  for (const struct auth_directive *ad = cfg->auth_directives; ad->container; ++ad) {
    if (ad->regex_compiled && have_normal) {
      /* Fast path: use pre-compiled regex, skip per-request regcomp */
      if (regexec(&ad->compiled_regex, normal_uri, 0, NULL, 0) == 0) {
        TSfree(normal_uri);
        free(uri_s);
        return (ad->auth == AUTH_ALLOW);
      }
    } else {
      /* Fallback for hash patterns or normalization failure */
      if (jwt_check_uri(ad->container, uri_s)) {
        TSfree(normal_uri);
        free(uri_s);
        return (ad->auth == AUTH_ALLOW);
      }
    }
  }
  TSfree(normal_uri);
  free(uri_s);
  return false;
}
