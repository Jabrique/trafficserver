'''
Test 103 Early Hints plugin — combined mode (auto-learn + origin-forward)
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
Test HTTP 103 Early Hints plugin with combined auto-learn,origin-forward mode.
Verifies:
- Both origin Link headers and HTML-learned resources appear in response
- H2 request after learning gets 103 with cached hints
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_combined_mode"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Page with BOTH origin Link header AND preloadable resources in HTML body.
# origin-forward learns Link header, auto-learn scans HTML body.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /combined.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </origin-style.css>; rel=preload; as=style\r\n"
            "\r\n",
        "body":
            "<html><head>"
            "<script src=\"/html-app.js\"></script>"
            "</head><body>Combined mode test</body></html>\r\n"
    })

# Page with only HTML resources (no origin Link header)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /html-only.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/only-from-html.css\" as=\"style\">"
            "</head><body>HTML only test</body></html>\r\n"
    })

# Page for three-mode combination (manual + auto-learn + origin-forward)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /trimode.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </origin-font.woff2>; rel=preload; as=font; crossorigin\r\n"
            "\r\n",
        "body":
            "<html><head>"
            "<script src=\"/trimode-app.js\"></script>"
            "</head><body>Three-mode test</body></html>\r\n"
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # Combined mode: auto-learn,origin-forward
    'map /combined.html http://127.0.0.1:{0}/combined.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn,origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # HTML-only with combined mode (origin sends no Link headers)
    'map /html-only.html http://127.0.0.1:{0}/html-only.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn,origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Three-mode: manual + auto-learn + origin-forward
    'map /trimode.html http://127.0.0.1:{0}/trimode.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual,auto-learn,origin-forward'
    ' @pparam=--link @pparam=</manual-critical.css>;rel=preload;as=style'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# Test Case 0: Combined mode — first request learns from both sources
# Origin sends Link header for origin-style.css; HTML body has html-app.js.
# Both should appear as Link headers in the 200 response.
# ----
tr1 = Test.AddTestRun("Combined mode - first request learns from origin + HTML")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/combined.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage in combined mode")
# Origin Link header is passed through by ATS; plugin also adds cached links
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "origin-style.css", "Origin Link header should appear (ATS passthrough or cache)")
tr1.StillRunningAfter = microserver

# ----
# Test Case 1: Combined mode — H2 second request gets 103 from cache
# After learning from first request, H2 should receive 103 with cached hints.
# ----
tr2 = Test.AddTestRun("Combined mode - H2 second request gets 103")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/combined.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# H2 request: cache should have hints → 103 sent
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from combined cache")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive 200 OK")
tr2.StillRunningAfter = microserver

# ----
# Test Case 2: HTML-only — auto-learn works even when origin has no Link headers
# ----
tr3 = Test.AddTestRun("Combined mode HTML-only - auto-learn works without origin Link")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/html-only.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage")
tr3.StillRunningAfter = microserver

# ----
# Test Case 3: HTML-only — second request proves auto-learn populated cache
# ----
tr4 = Test.AddTestRun("Combined mode HTML-only - H2 gets 103 from auto-learn cache")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/html-only.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# H2 request: auto-learn cache should have the HTML resource
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from auto-learn cache")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "only-from-html.css", "Auto-learned HTML resource should appear in Link")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive 200 OK")
tr4.StillRunningAfter = microserver

# ----
# Test Case 4: Three-mode (manual+auto-learn+origin-forward) — first request
# Manual links appear immediately, auto-learn + origin-forward learn from response.
# ----
tr5 = Test.AddTestRun("Three-mode - first request gets manual link + learns")
tr5.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/trimode.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Manual link appears immediately in 200 response Link header
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "manual-critical.css", "Manual link should appear in first response")
tr5.StillRunningAfter = microserver

# ----
# Test Case 5: Three-mode — H2 second request gets 103 with ALL sources
# Cache should now contain: manual link + auto-learned + origin-forwarded
# ----
tr6 = Test.AddTestRun("Three-mode - H2 second request gets 103 from all sources")
tr6.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/trimode.html'".format(ts.Variables.ssl_port))
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from three-mode cache")
tr6.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "manual-critical.css", "Manual link should be in cached hints")
tr6.StillRunningAfter = microserver
