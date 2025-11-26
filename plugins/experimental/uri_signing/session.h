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

#ifndef URI_SIGNING_UNIT_TEST
#include "ts/ts.h"
#endif

struct salt_config;
struct jwt;

/**
 * Generate salt from request headers based on configuration.
 *
 * Combines configured header values (Session-ID, User-Agent, Client-IP)
 * and returns their SHA256 hash as a hex string.
 *
 * @param txn Transaction handle (NULL in unit tests)
 * @param cfg Salt configuration (which headers to include)
 * @param session_id Optional session ID value (for unit tests)
 * @param user_agent Optional user agent value (for unit tests)
 * @param client_ip Optional client IP value (for unit tests)
 * @return Allocated hex string of SHA256 hash, or NULL on error. Caller must free().
 */
char *generate_salt(
#ifndef URI_SIGNING_UNIT_TEST
  TSHttpTxn txn,
#endif
  struct salt_config *cfg, const char *session_id, const char *user_agent, const char *client_ip);

/**
 * Validate that token's cdnisalt matches current request.
 *
 * Generates salt from current request and compares with token's cdnisalt claim.
 * For tokens without cdnisalt: allows access tokens, rejects renewal tokens.
 *
 * @param jwt Token to validate
 * @param txn Transaction handle (NULL in unit tests)
 * @param cfg Salt configuration
 * @param matched_token_name The parameter name that matched this token (e.g., "cr-access-token")
 * @param access_token_name The configured access token parameter name for comparison
 * @param session_id Optional session ID value (for unit tests)
 * @param user_agent Optional user agent value (for unit tests)
 * @param client_ip Optional client IP value (for unit tests)
 * @return true if salt matches or salt disabled, false if mismatch
 */
bool validate_salt(struct jwt *jwt,
#ifndef URI_SIGNING_UNIT_TEST
                   TSHttpTxn txn,
#endif
                   struct salt_config *cfg, const char *matched_token_name, const char *access_token_name, const char *session_id,
                   const char *user_agent, const char *client_ip);
