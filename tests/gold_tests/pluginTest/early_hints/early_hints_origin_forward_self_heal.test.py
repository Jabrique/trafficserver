'''
Test 103 Early Hints plugin  -- origin-forward self-healing from ATS cache
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
Test HTTP 103 Early Hints plugin origin-forward self-healing from ATS cache.
Verifies:
- When hints entry is evicted from RAM (via LRU with --max-cache-entries=1),
  and ATS has the response cached, READ_CACHE_HDR re-extracts Link headers
  from the ATS cached response headers (self-healing).
- After self-healing, the next request serves 103 again without going to origin.
Both /page.html and /decoy.html share ONE plugin instance (same remap rule base)
so that the LRU eviction of /page.html by /decoy.html is observable.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_origin_forward_self_heal"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Main page with Link preload header (origin-forward mode reads from headers)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </style.css>; rel=preload; as=style\r\n\r\n",
        "body": "<html><body>Page</body></html>\r\n"
    })

# Decoy page to trigger LRU eviction of /page.html hints entry
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /decoy.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </decoy.css>; rel=preload; as=style\r\n\r\n",
        "body": "<html><body>Decoy</body></html>\r\n"
    })

# ----
# Setup ATS (cache ENABLED  -- needed so READ_CACHE_HDR fires on subsequent requests)
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=True)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # Single catch-all rule for the entire origin  -- /page.html and /decoy.html
    # both go through ONE plugin instance so they share the same HintsCache.
    # max-cache-entries=1: hints RAM holds only 1 entry. Requesting /decoy.html
    # evicts /page.html (LRU). The next /page.html ATS cache hit triggers
    # READ_CACHE_HDR self-healing from ATS cached Link headers.
    'map https://127.0.0.1:{0}/ http://127.0.0.1:{1}/'.format(
        ts.Variables.ssl_port, microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--max-cache-entries @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 5,
})

# ----
# TR1: H2 GET /page.html  -- origin fetch, Link header extracted → hints entry created (rc=0)
# ----
tr1 = Test.AddTestRun("Self-heal: TR1 H2 GET /page.html  -- origin, link learned (no 103: rc=0)")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
# First request: no hints entry → get() returns null → no 103.
# READ_RESPONSE_HDR: extracts Link header → put() (rc=0).
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "TR1: first request, no entry yet → no-hints")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 GET /page.html  -- ATS cache hit, 103 served (rc=0→1 >= 1)
# ----
tr2 = Test.AddTestRun("Self-heal: TR2 H2 GET /page.html  -- ATS cache hit, 103 sent")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# ATS cache hit: get() rc=0→1 >= 1 → links returned → 103 sent
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "TR2: ATS cache hit + hints in RAM → 103 sent")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header present in TR2")
tr2.StillRunningAfter = microserver

# ----
# TR3: H2 GET /decoy.html  -- origin fetch, hints for /decoy.html learned.
# max-cache-entries=1 → /page.html entry is LRU-evicted from hints RAM.
# ----
tr3 = Test.AddTestRun("Self-heal: TR3 H2 GET /decoy.html  -- LRU evicts /page.html hints entry")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/decoy.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# /decoy.html: get() returns null (no entry). READ_RESPONSE_HDR: put() creates
# /decoy.html entry (rc=0). max-cache-entries=1 → /page.html LRU-evicted.
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "TR3: /decoy.html first request → no-hints")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr3.StillRunningAfter = microserver

# ----
# TR4: H2 GET /page.html  -- hints evicted from RAM, but ATS has the response cached.
# TSRemapDoRemap: get() returns null → cached_links=nullptr → no 103 this request.
# READ_CACHE_HDR self-heals: re-extracts Link header from ATS cached response → put().
# ----
tr4 = Test.AddTestRun(
    "Self-heal: TR4 H2 GET /page.html  -- hints evicted, ATS cache hit → READ_CACHE_HDR self-heals (no 103)")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# /page.html hints evicted → get() returns null → no 103.
# READ_CACHE_HDR fires (ATS cache hit): self-heals via put() from cached Link headers.
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "TR4: hints evicted → no 103 this request; self-heal happens in READ_CACHE_HDR")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr4.StillRunningAfter = microserver

# ----
# TR5: H2 GET /page.html  -- after self-healing, 103 served again
# ----
tr5 = Test.AddTestRun("Self-heal: TR5 H2 GET /page.html  -- after self-heal → 103 served again")
tr5.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
# After TR4 put() from READ_CACHE_HDR, get() rc=0→1 >= 1 → 103 sent
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "TR5: after self-heal → 103 sent again")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header present after self-heal")
tr5.StillRunningAfter = microserver
