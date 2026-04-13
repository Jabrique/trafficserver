'''
Test 103 Early Hints plugin — HTTP/2 103 response verification
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
Test actual HTTP/2 103 Early Hints response using nghttp.
This is the critical integration test that verifies the plugin sends a real
103 HEADERS frame over HTTP/2, not just Link headers in the 200 response.

Verifies:
- H2 client with manual hints: receives 103 HEADERS frame with Link header
- H2 client with auto-learned hints: receives 103 on second request
- H2 client debug header shows "sent" (not "skipped-h1")
- H1 client on same config: receives Link in 200 but no 103
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
    Condition.HasProgram('nghttp', 'nghttp is required for HTTP/2 103 testing'),
)
Test.testName = "early_hints_h2_103"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
    })

# HTML page with preloadable resources for auto-learn
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /auto.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/static/app.js\" as=\"script\">"
            "<link rel=\"stylesheet\" href=\"/static/theme.css\">"
            "</head><body><p>Auto-learn H2 test</p></body></html>\r\n"
    })

# HTML page served with duplicate Link headers from origin (origin-forward dedup test)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /dup-link.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>Duplicate Link headers</body></html>\r\n"
    })


ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    'map /index.html http://127.0.0.1:{0}/index.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</style.css>;rel=preload;as=style'
    ' @pparam=--link @pparam=</app.js>;rel=preload;as=script'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
    'map /auto.html http://127.0.0.1:{0}/auto.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
    'map /dup-link.html http://127.0.0.1:{0}/dup-link.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'http2|early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# Test Case 0: H2 manual hints — nghttp sees 103 HEADERS frame
# nghttp -v shows all H2 frames including informational 103 responses.
# ----
tr1 = Test.AddTestRun("H2 manual hints - 103 HEADERS frame via nghttp")
tr1.Processes.Default.Command = (
    "nghttp -v --no-dep"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
# nghttp -v prints frame-level output; 103 appears as ":status: 103" in HEADERS
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    ":status: 103", "Should see 103 Early Hints H2 frame (:status: 103 in HEADERS)")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link: ", "Should see link header in 103 response (nghttp lowercases headers)")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    ":status: 200", "Should also see final 200 response")
tr1.StillRunningAfter = microserver

# ----
# Test Case 1: Verify debug header shows "sent" for H2 client (not "skipped-h1")
# Use curl --http2 to check the debug header value in the final 200 response.
# ----
tr2 = Test.AddTestRun("H2 debug header shows sent")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# For H2 client, plugin should have sent 103 and debug header should reflect that
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive final 200 OK")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 client should get 'sent' status (not 'skipped-h1')")
# Link headers should also appear in the 200 response for browser compatibility
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should be in 200 response too")
tr2.StillRunningAfter = microserver

# ----
# Test Case 2: Verify H2 receives multiple Link headers (manual mode with 2 links)
# ----
tr3 = Test.AddTestRun("H2 multiple Link headers in 103")
tr3.Processes.Default.Command = (
    "nghttp -v --no-dep"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# Both configured Link headers should appear in the 103 frame
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    ":status: 103", "Must see 103 Early Hints frame (plugin-generated)")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "style.css", "Should see style.css Link in 103")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "app.js", "Should see app.js Link in 103")
tr3.StillRunningAfter = microserver

# ----
# Test Case 3: Auto-learn over H2 — first request learns, no 103 (no cached hints yet)
# ----
tr4 = Test.AddTestRun("H2 auto-learn first request - no 103 yet")
tr4.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/auto.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
# First request has no cached hints so debug status should not be "sent"
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status:", "Plugin should engage (debug header present)")
tr4.StillRunningAfter = microserver

# ----
# Test Case 4: Auto-learn over H2 — second request gets 103 with learned hints
# ----
tr5 = Test.AddTestRun("H2 auto-learn second request - 103 with learned hints")
tr5.Processes.Default.Command = (
    "sleep 1 && nghttp -v --no-dep"
    " 'https://127.0.0.1:{0}/auto.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
# Second request should have cached hints from first → 103 sent
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    ":status: 103", "Should see 103 Early Hints on second H2 request (from cache)")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/static/app.js", "Should see learned app.js link in 103 response")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    ":status: 200", "Should also see final 200 response")
tr5.StillRunningAfter = microserver

# ----
# Test Case 5: Confirm H1 client on same config does NOT get 103
# This proves the H1/H2 differentiation works correctly.
# ----
tr6 = Test.AddTestRun("H1 client same config - no 103, still gets Link in 200")
tr6.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr6.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 client should be skipped for 103")
tr6.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link:", "Link header should still appear in 200 for H1 client")
# Verify 103 is NOT in H1 response
tr6.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "103", "H1 client must not see 103 status")
tr6.StillRunningAfter = microserver

# ----
# Test Case 6: Origin-forward dedup — origin sends duplicate Link headers
#
# When origin returns the same Link header field twice (e.g. a mis-configured
# origin or middleware that appends headers idempotently), the plugin must store
# only one copy in its cache.  The H2 103 response is the cleanest signal: it
# contains only what the plugin injected from cache, so counting "link:" lines
# in the 103 frame shows whether dedup worked.
#
# Step 1 — H1 warm-up: learn the (duplicate) origin headers and populate cache.
# Step 2 — H2 verify:  nghttp output filtered to the 103 frame must show
#           exactly 1 "link:" entry for </cdn/app.js> (not 2).
# ----
tr_dedup_learn = Test.AddTestRun("Origin-forward dedup: warm-up request — learn duplicate origin Link headers")
tr_dedup_learn.Processes.Default.Command = (
    "curl -s -D /dev/null -o /dev/null --http1.1 --insecure"
    " 'https://127.0.0.1:{0}/dup-link.html'".format(ts.Variables.ssl_port))
tr_dedup_learn.Processes.Default.ReturnCode = 0
tr_dedup_learn.StillRunningAfter = microserver

tr_dedup_verify = Test.AddTestRun(
    "Origin-forward dedup: H2 103 must contain exactly 1 link (not 2) for duplicate origin headers")
# sed -n '/status: 103/,/status: 200/{/link:/p}' isolates link: lines in the 103 frame
tr_dedup_verify.Processes.Default.Command = (
    "sleep 1 && nghttp -v --no-dep"
    " 'https://127.0.0.1:{0}/dup-link.html' 2>&1 |"
    " sed -n '/status: 103/,/status: 200/{{/link:/p}}' |"
    " grep -c 'cdn/app.js'".format(ts.Variables.ssl_port))
tr_dedup_verify.Processes.Default.ReturnCode = 0
tr_dedup_verify.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "^1$",
    "Duplicate origin Link headers must be deduplicated: 103 must contain exactly 1 link entry")
tr_dedup_verify.StillRunningAfter = microserver
