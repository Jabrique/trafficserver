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

#pragma once

#include <stdbool.h>
#include <stdlib.h>

struct config;
struct _cjose_jwk_int;
struct signer {
  char *issuer;
  struct _cjose_jwk_int *jwk;
  char *alg;
};

struct salt_config {
  bool enabled;
  bool bind_session_id;
  bool bind_user_agent;
  bool bind_client_ip;
};

struct manifest_injection_config {
  bool enabled;
  bool inject_to_segments;
  bool inject_to_init_segments;
  bool replace_access_token; /* Replace access token with session token in manifest URLs.
                              * true = clean URLs with only session token (recommended)
                              * false = keep both access and session tokens */
  bool hls_support;
  bool dash_support;
  bool cache_untransformed; /* Cache clean manifest from origin, not transformed output.
                             * true = shared cache (recommended), false = per-token cache */
};

struct renewal_token_config {
  char *token_name;
  struct salt_config salt;
  struct manifest_injection_config manifest_injection;
};

struct config *read_config_from_path(const char *const path);
struct config *read_config_from_string(const char *const buffer);
void config_delete(struct config *g);
struct signer *config_signer(struct config *);
struct _cjose_jwk_int **find_keys(struct config *cfg, const char *issuer);
struct _cjose_jwk_int *find_key_by_kid(struct config *cfg, const char *issuer, const char *kid);
bool uri_matches_auth_directive(struct config *cfg, const char *uri, size_t uri_ct);
const char *config_get_id(struct config *cfg);
bool config_strip_token(struct config *cfg);
const char *config_get_token_name(struct config *cfg);
struct renewal_token_config *config_get_renewal_token(struct config *cfg);
const char *config_get_renewal_token_name(struct config *cfg);
