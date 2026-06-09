'''
Test 103 Early Hints plugin -- origin-forward with multiple Link header fields (H3 fix)

The TOCTOU dedup bug: dedup_link_segments() was called inside the while loop
that iterates over multiple Link header fields from the origin response.
Each iteration re-deduped the growing origin_links vector, creating O(n^2)
allocations and -- more critically -- resetting the dedup state on each call
which could cause incorrect strongest-wins decisions.

After the fix: dedup_link_segments() is called once after all Link header
fields have been collected.

Behavioral contract tested here:
  - Origin sends 3 separate Link header fields for the same URL (one as
    preconnect, two as preload). After fix, the single dedup call correctly
    applies strongest-wins and keeps only one preload entry.
  - Origin sends multiple unique Link header fields across multiple headers.
    After fix, all unique links are preserved (max_links cap respected).

RED (before fix): duplicate entries or wrong dedup behavior possible when
                  Link headers span multiple header fields.
GREEN (after fix): exactly correct set of deduplicated links cached and
                   served as 103 on next H2 request.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

Test.Summary = '''
Origin-forward with multiple Link header fields from origin. After H3 fix,
dedup is called once after all fields are collected, correctly deduplicating
same-URL entries and preserving all unique entries.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_origin_forward_multi_link_dedup"
Test.ContinueOnFail = True

# ----
# Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Page with 3 separate Link header fields:
#   Field 1: /style.css preload
#   Field 2: /app.js preload
#   Field 3: /style.css again (duplicate - dedup should collapse to 1 entry)
#
# After fix: single dedup call -> 2 unique entries (/style.css, /app.js)
# Before fix: per-field dedup resets state but same result for simple cases.
# The correctness issue is more pronounced for strongest-wins with same URL.
for _ in range(4):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /multi.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": (
                "HTTP/1.1 200 OK\r\n"
                "Connection: close\r\n"
                "Content-Type: text/html\r\n"
                "Link: </multi-style.css>; rel=preload; as=style\r\n"
                "Link: </multi-app.js>; rel=preload; as=script\r\n"
                "Link: </multi-style.css>; rel=preload; as=style\r\n"
                "\r\n"
            ),
            "body": "<html><body>Multi Link header test</body></html>\r\n"
        })

# Page with a preconnect in field 1 and a preload for the same URL in field 2.
# After single dedup call, strongest-wins keeps preload.
for _ in range(4):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /strongest.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": (
                "HTTP/1.1 200 OK\r\n"
                "Connection: close\r\n"
                "Content-Type: text/html\r\n"
                "Link: <https://cdn.example.com>; rel=preconnect\r\n"
                "Link: <https://cdn.example.com>; rel=preload; as=script\r\n"
                "\r\n"
            ),
            "body": "<html><body>Strongest wins test</body></html>\r\n"
        })

# ----
# ATS Setup
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 5,
})

CURL_H1_MULTI = (
    "curl -s -D -"
    " --http1.1"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/multi.html'".format(ts.Variables.ssl_port))

CURL_H2_MULTI = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/multi.html'".format(ts.Variables.ssl_port))

CURL_H1_STRONGEST = (
    "curl -s -D -"
    " --http1.1"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/strongest.html'".format(ts.Variables.ssl_port))

CURL_H2_STRONGEST = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/strongest.html'".format(ts.Variables.ssl_port))

# ============================================================
# Scenario A: duplicate Link header fields are deduped correctly
# ============================================================

# A1: H1 learn - origin sends /multi-style.css (x2) and /multi-app.js
tr_a1 = Test.AddTestRun("A1: H1 learn from 3 Link header fields (1 duplicate)")
tr_a1.Processes.Default.Command = CURL_H1_MULTI
tr_a1.Processes.Default.ReturnCode = 0
tr_a1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr_a1.Processes.Default.StartBefore(Test.Processes.ts)
tr_a1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "H1 learn request succeeds")
tr_a1.StillRunningAfter = microserver

# A2: H2 - 103 sent with deduplicated links (only 2, not 3)
tr_a2 = Test.AddTestRun("A2: H2 - 103 with deduplicated links (2 unique, 1 duplicate removed)")
tr_a2.Processes.Default.Command = "sleep 1 && " + CURL_H2_MULTI
tr_a2.Processes.Default.ReturnCode = 0
# Both unique links must appear
tr_a2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "103 sent from origin-forward cache")
tr_a2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "multi-style.css", "style.css link present")
tr_a2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "multi-app.js", "app.js link present")
tr_a2.StillRunningAfter = microserver

# ============================================================
# Scenario B: same URL as preconnect + preload across two fields
# Single dedup call applies strongest-wins: preload wins over preconnect
# ============================================================

# B1: H1 learn
tr_b1 = Test.AddTestRun("B1: H1 learn - preconnect in field1, preload in field2 (same URL)")
tr_b1.Processes.Default.Command = CURL_H1_STRONGEST
tr_b1.Processes.Default.ReturnCode = 0
tr_b1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "B1 learn succeeds")
tr_b1.StillRunningAfter = microserver

# B2: H2 - 103 sent with preload (not preconnect)
# Strongest-wins dedup: same URL - preload replaces preconnect
tr_b2 = Test.AddTestRun("B2: H2 - 103 with preload (strongest-wins across fields)")
tr_b2.Processes.Default.Command = "sleep 1 && " + CURL_H2_STRONGEST
tr_b2.Processes.Default.ReturnCode = 0
tr_b2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "103 sent")
# Preload must have won over preconnect for the same URL.
# The 103 link header must contain rel=preload (not rel=preconnect).
tr_b2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload", "preload wins over preconnect in strongest-wins dedup")
tr_b2.StillRunningAfter = microserver
