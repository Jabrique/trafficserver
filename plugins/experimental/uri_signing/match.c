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

#include <regex.h>
#include "common.h"
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

bool
match_hash(const char *needle, const char *haystack)
{
  return false;
}

bool
match_regex(const char *pattern, const char *uri)
{
  regex_t preg;

  PluginDebug("Testing regex pattern /%s/ against \"%s\"", pattern, uri);

  /* Anchor pattern at start to preserve re_match() semantics:
   * re_match(pat, str, len, 0, 0) matches from position 0 only.
   * regexec() searches anywhere — prepend ^ to get equivalent behavior.
   * Skip prepending if pattern already starts with ^ to avoid ^^pattern. */
  int comp_err;
  if (pattern[0] == '^') {
    comp_err = regcomp(&preg, pattern, REG_EXTENDED | REG_NOSUB);
  } else {
    size_t pattern_len     = strlen(pattern);
    char *anchored_pattern = malloc(pattern_len + 2);
    if (!anchored_pattern) {
      PluginDebug("Regex: failed to allocate anchored pattern");
      return false;
    }
    anchored_pattern[0] = '^';
    memcpy(anchored_pattern + 1, pattern, pattern_len + 1);
    comp_err = regcomp(&preg, anchored_pattern, REG_EXTENDED | REG_NOSUB);
    free(anchored_pattern);
  }
  if (comp_err) {
    char errbuf[128];
    regerror(comp_err, &preg, errbuf, sizeof(errbuf));
    PluginDebug("Regex Compilation ERROR: %s", errbuf);
    return false;
  }

  int match_ret = regexec(&preg, uri, 0, NULL, 0);
  regfree(&preg);

  return match_ret == 0;
}
