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

#include <ts/ts.h>
#include "config.h"

/**
 * Transform continuation data for manifest token injection.
 */
struct transform_data {
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;

  char *token;                           /* Renewal token to inject */
  char *param_name;                      /* Token parameter name (session token) */
  char *access_token_name;               /* Access token parameter name to replace */
  struct manifest_injection_config *cfg; /* Injection configuration */

  char *accumulated_data;      /* Accumulated manifest content */
  size_t accumulated_size;     /* Size of accumulated data */
  size_t accumulated_capacity; /* Capacity of accumulated buffer */

  bool is_manifest;    /* Whether this is a manifest response */
  bool transform_done; /* Whether transformation is complete */
};

/**
 * Setup manifest transform hook for a transaction.
 *
 * This should be called after successful JWT validation to set up the
 * response transformation pipeline for manifest injection.
 *
 * @param txnp Transaction handle
 * @param token Renewal token (JWS string) to inject into manifests
 * @param param_name Token parameter name (e.g., "cr-session-token")
 * @param access_token_name Access token parameter name to replace (may be NULL)
 * @param cfg Manifest injection configuration
 */
void setup_manifest_transform(TSHttpTxn txnp, const char *token, const char *param_name, const char *access_token_name,
                              struct manifest_injection_config *cfg);
