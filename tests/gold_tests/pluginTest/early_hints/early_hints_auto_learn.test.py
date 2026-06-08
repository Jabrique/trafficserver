'''
Test 103 Early Hints plugin — auto-learn mode
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
Test HTTP 103 Early Hints plugin in auto-learn mode.
Verifies:
- First request (H1): plugin engages, scans body (no Link in first 200 -- transform
  runs after SEND_RESPONSE_HDR so learned hints cannot appear in same response).
- Second request (H2): plugin finds learned hints and sends 103 Early Hints.
- Non-HTML response: no hints learned.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_auto_learn"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# HTML page with preloadable resources in <head>. Two copies needed: one for the
# H1 learning pass (TR1), one for the H2 serving pass (TR2) where the origin may
# be contacted again if ATS cache is disabled.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/assets/main.css\" as=\"style\">"
            "<script src=\"/assets/vendor.js\"></script>"
            "</head><body><p>Auto-learn test</p></body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/assets/main.css\" as=\"style\">"
            "<script src=\"/assets/vendor.js\"></script>"
            "</head><body><p>Auto-learn test</p></body></html>\r\n"
    })

# JSON response (non-HTML, should NOT be scanned)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /api/data HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
        "body": "{\"key\": \"value\"}\r\n"
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
    ' @pparam=--mode @pparam=auto-learn'
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
# Test Case 0: First request -- auto-learn transform scans HTML and learns hints.
# The body transform runs AFTER SEND_RESPONSE_HDR, so learned links cannot appear
# in the first request's 200 response headers. Only plugin engagement is verified.
# ----
tr1 = Test.AddTestRun("First request - plugin learns, no Link header yet")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Debug header confirms plugin engaged and skipped 103 for H1 client
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 client: plugin engaged but skipped 103")
# No Link header on first request (body scan runs after SEND_RESPONSE_HDR)
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link: </assets/main.css>",
    "First request must not add Link header: body scan runs after SEND_RESPONSE_HDR")
tr1.StillRunningAfter = microserver

# ----
# Test Case 1: Second request (H2) -- plugin finds cached hints from TR1 and sends 103.
# H2 triggers get() which increments request_count. With min-hit-count=1, the first
# H2 request (count=1 >= 1) sends 103 Early Hints with the resources learned by TR1.
# The 103 must contain both learned resources.
# ----
tr2 = Test.AddTestRun("H2 cache hit - 103 sent with learned hints")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Should receive 103 Early Hints from learned resources")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should receive final 200 OK")
# Both resources learned by the HTML scanner must appear in the 103.
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/assets/main.css", "Learned stylesheet must appear in 103 Link header")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/assets/vendor.js", "Learned script must appear in 103 Link header")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: sent", "Plugin must confirm 103 was sent")
tr2.StillRunningAfter = microserver

# ----
# Test Case 2: Non-HTML response — no hints learned
# ----
tr3 = Test.AddTestRun("Non-HTML response no scanning")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/api/data'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin engages but correctly skips non-HTML; debug header confirms plugin is loaded and running
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage (debug header present) even for non-HTML")
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "Non-HTML response should not have Link headers")
tr3.StillRunningAfter = microserver
