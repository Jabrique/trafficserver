'''
Test 103 Early Hints plugin — origin-forward mode
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
Test HTTP 103 Early Hints plugin in origin-forward mode.
Verifies:
- Origin sends Link headers → cached → appear in 200 on next request
- Origin without Link headers → no hints
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_origin_forward"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Page with Link headers from origin
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /with-links.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/style.css>; rel=preload; as=style\r\n"
            "\r\n",
        "body": "<html><body>With Link headers</body></html>\r\n"
    })

# Page without Link headers
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /no-links.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><body>No Link headers</body></html>\r\n"
    })

# ----
# Setup ATS
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
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# Test Case 0: First request with Link headers — learn them
# ----
tr1 = Test.AddTestRun("First request - learn origin Link headers")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/with-links.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin must engage — debug header proves plugin is loaded and processing
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage on first request (debug header present)")
tr1.StillRunningAfter = microserver

# ----
# Test Case 1: Second request — forwarded hints with specific Link content
# The origin also sends Link headers, so to distinguish plugin-injected hints from
# passthrough, we verify the debug header confirms the plugin processed hints.
# ----
tr2 = Test.AddTestRun("Second request - forwarded hints in 200")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/with-links.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </cdn/style.css>", "Should have forwarded origin Link header for style.css")
# Verify plugin engaged and had cached hints — skipped-h1 means plugin ran and found hints
# but skipped 103 because of H1 client. This proves the origin-forward cache is working.
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin should have cached hints from first request")
tr2.StillRunningAfter = microserver

# ----
# Test Case 2: H2 second request — PROVES caching via 103
# If the plugin cache is working, an H2 request should find cached hints (learned from
# TR0's origin Link header in READ_RESPONSE_HDR) and send 103 BEFORE contacting origin.
# The debug header "sent" proves TSHttpTxnSendEarlyHints succeeded from cache.
# This is the ironclad caching proof — 103 is sent at remap time, before origin fetch.
# ----
tr_h2_proof = Test.AddTestRun("H2 caching proof - 103 sent from cache")
tr_h2_proof.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/with-links.html'".format(ts.Variables.ssl_port))
tr_h2_proof.Processes.Default.ReturnCode = 0
# H2 client: plugin looks up cache → finds hints from TR0 → sends 103 → status = "sent"
tr_h2_proof.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should trigger 103 from cached origin Link headers")
tr_h2_proof.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive final 200 OK")
tr_h2_proof.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should appear in 200 response")
tr_h2_proof.StillRunningAfter = microserver

# ----
# Test Case 3: Page without Link headers — no hints
# ----
tr3 = Test.AddTestRun("No Link headers - no hints")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/no-links.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin must engage — debug header proves plugin is running
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage even when no origin Link headers")
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "Page without origin Link should not have Link headers")
tr3.StillRunningAfter = microserver
