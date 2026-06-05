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
- First request: plugin engages and scans body (debug header = skipped-h1), no Link header yet
- Second request: learned hints appear as Link headers in 200 response
- Non-HTML response: no hints learned
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

# HTML page with preloadable resources in <head>
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
# Test Case 1: Second request — learned hints with specific resources
# Verify the exact resources that were learned from the HTML.
# ----
tr2 = Test.AddTestRun("Second request - learned hints in 200")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Verify specific learned resources from the HTML <head>
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </assets/main.css>", "Should have learned stylesheet from HTML (in Link header)")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </assets/vendor.js>", "Should have learned script from HTML (in Link header)")
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
