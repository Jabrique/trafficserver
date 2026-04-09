'''
Test 103 Early Hints plugin — edge cases
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
Test HTTP 103 Early Hints plugin edge cases.
Verifies:
- HTML without <head>: no hints learned
- Non-navigate request over H1: H1 skip fires first (navigate-only not directly testable with H1)
- HEAD request: processed by plugin (not rejected)
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_edge_cases"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# HTML page without <head> tag
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /no-head.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><body><p>No head section</p></body></html>\r\n"
    })

# Normal page for edge case tests
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/main.js\" as=\"script\">"
            "</head><body>Edge case test</body></html>\r\n"
    })

# ----
# Setup ATS — navigate_only enabled (default), skip_bots disabled
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# Test Case 0: HTML without <head> — nothing learned (two requests)
# ----
tr1 = Test.AddTestRun("HTML without head - first request to learn")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/no-head.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200")
# Plugin must engage — debug header proves plugin loaded and processing
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage on no-head HTML (debug header present)")
tr1.StillRunningAfter = microserver

tr2 = Test.AddTestRun("HTML without head - verify no hints on second request")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/no-head.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200")
# Plugin engages but finds nothing to learn — debug header must be present
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage (debug header present)")
# No Link headers — HTML without <head> produces no hints
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "HTML without head should not have Link headers")
tr2.StillRunningAfter = microserver

# ----
# Test Case 1: Non-navigate request skipped (Sec-Fetch-Mode: cors)
# NOTE: H1 check fires before navigate-only check. With H1, debug header
# shows skipped-h1 regardless of Sec-Fetch-Mode. To properly test
# navigate-only, we'd need an H2 client. This test verifies the plugin
# correctly identifies H1 and sets the debug header.
# ----
tr3 = Test.AddTestRun("Non-navigate over H1 - H1 skip takes precedence")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " -H 'Sec-Fetch-Mode: cors'"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# H1 skip fires first — verify the exact debug header value
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 skip fires before navigate-only check")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr3.StillRunningAfter = microserver

# ----
# Test Case 3: H2 non-navigate request — REAL navigate-only test
# Over H2, the H1 check passes (is H2), then the navigate-only check at plugin
# line 911-916 fires for non-navigate requests. This is the isolated test that
# verifies navigate-only filtering works — unlike TR2 which only tests H1 skip.
# ----
tr_nav_h2 = Test.AddTestRun("H2 non-navigate - skipped-non-navigate")
tr_nav_h2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'Sec-Fetch-Mode: cors'"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr_nav_h2.Processes.Default.ReturnCode = 0
# H2 + Sec-Fetch-Mode: cors → navigate-only check fires → "skipped-non-navigate"
tr_nav_h2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: skipped-non-navigate",
    "H2 non-navigate should be detected and skipped for 103")
tr_nav_h2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should still receive 200 OK")
# Verify 103 was NOT sent
tr_nav_h2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "x-early-hints-status: sent", "Non-navigate request must NOT trigger 103 sending")
tr_nav_h2.StillRunningAfter = microserver

# ----
# Test Case 4: HEAD request still processed (GET/HEAD allowed)
# ----
tr4 = Test.AddTestRun("HEAD request allowed")
tr4.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " -I"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# HEAD should work normally and plugin should engage (debug header present)
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "HEAD should get 200 OK")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage for HEAD requests")
tr4.StillRunningAfter = microserver
