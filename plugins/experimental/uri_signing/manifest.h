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

typedef enum { MANIFEST_TYPE_UNKNOWN = 0, MANIFEST_TYPE_HLS_M3U8, MANIFEST_TYPE_DASH_MPD } manifest_type_t;

struct manifest_injection_config;

/**
 * Extract JWS token from Set-Cookie header.
 *
 * BUG #4 FIX: Helper function to extract token from Set-Cookie format.
 * Format: "param_name=JWS_TOKEN; Path=/; HttpOnly"
 *
 * @param set_cookie_header Full Set-Cookie header value
 * @return Allocated JWS token string (caller must free()), or NULL on error
 */
char *extract_jws_from_set_cookie(const char *set_cookie_header);

/**
 * Detect manifest type from URI and Content-Type.
 *
 * @param uri Request URI
 * @param content_type Content-Type header value (may be NULL)
 * @return Detected manifest type
 */
manifest_type_t detect_manifest_type(const char *uri, const char *content_type);

/**
 * Check if a line in HLS manifest is a segment URL.
 *
 * @param line Line from M3U8 file
 * @return true if line is a segment URL (not a tag or comment)
 */
bool is_segment_url(const char *line);

/**
 * Check if a line in HLS manifest is an initialization segment tag.
 *
 * @param line Line from M3U8 file
 * @return true if line contains EXT-X-MAP (init segment)
 */
bool is_init_segment(const char *line);

/**
 * Extract URI from EXT-X-MAP tag.
 *
 * @param map_line Line containing EXT-X-MAP tag
 * @return Allocated URI string, caller must free(), or NULL on error
 */
char *extract_uri_from_map_tag(const char *map_line);

/**
 * Inject token into EXT-X-MAP tag URI.
 *
 * @param map_line Original EXT-X-MAP tag line
 * @param token Token value (JWS string)
 * @param param_name Token parameter name (session token)
 * @param access_token_name Access token parameter name to replace (may be NULL)
 * @param replace_access_token Whether to replace access token before injection
 * @return Allocated modified line, caller must free()
 */
char *inject_token_into_map_tag(const char *map_line, const char *token, const char *param_name, const char *access_token_name,
                                bool replace_access_token);

/**
 * Remove a query parameter from URL.
 *
 * Removes the specified parameter while preserving fragments (RFC 3986).
 * If parameter not found, returns duplicate of original URL.
 *
 * @param url Original URL
 * @param param_name Parameter name to remove
 * @return Allocated string with parameter removed, caller must free()
 */
char *strip_param_from_url(const char *url, const char *param_name);

/**
 * Add token parameter to URL.
 *
 * @param url Original URL
 * @param token Token value (JWS string)
 * @param param_name Parameter name (e.g., "cr-session-token")
 * @return Allocated string with token appended, caller must free()
 */
char *add_token_to_url(const char *url, const char *token, const char *param_name);

/**
 * Inject token into HLS M3U8 manifest.
 *
 * Adds token parameter to media segment URLs and optionally init segments.
 * If replace_access_token is enabled, strips access_token_name before injection.
 *
 * @param manifest_body Original manifest content
 * @param body_len Length of manifest
 * @param token Token value (JWS string)
 * @param param_name Token parameter name (session token)
 * @param access_token_name Access token parameter name to replace (may be NULL)
 * @param cfg Injection configuration
 * @param new_len Output: length of new manifest
 * @return Allocated string with injected tokens, caller must free()
 */
char *inject_token_hls(const char *manifest_body, size_t body_len, const char *token, const char *param_name,
                       const char *access_token_name, struct manifest_injection_config *cfg, size_t *new_len);

/**
 * Inject token into DASH MPD manifest.
 *
 * Adds token parameter to BaseURL and SegmentTemplate URLs.
 * If replace_access_token is enabled, strips access_token_name before injection.
 *
 * @param manifest_body Original manifest content
 * @param body_len Length of manifest
 * @param token Token value (JWS string)
 * @param param_name Token parameter name (session token)
 * @param access_token_name Access token parameter name to replace (may be NULL)
 * @param cfg Injection configuration
 * @param new_len Output: length of new manifest
 * @return Allocated string with injected tokens, caller must free()
 */
char *inject_token_dash(const char *manifest_body, size_t body_len, const char *token, const char *param_name,
                        const char *access_token_name, struct manifest_injection_config *cfg, size_t *new_len);
