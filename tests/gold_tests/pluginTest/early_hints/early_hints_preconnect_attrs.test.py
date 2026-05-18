'''
Test 103 Early Hints plugin — preconnect attribute correctness
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
Validates that crossorigin and fetchpriority attributes are not emitted on
rel=preconnect Early Hints, and that same-origin preloads continue to carry
those attributes correctly.

A rel=preconnect hint tells the browser to warm up a TCP/TLS connection to a
third-party origin. The crossorigin and fetchpriority attributes are defined
only for preload hints and have no semantics on preconnect. Emitting them
wastes bytes and produces malformed Link headers.

This test covers four resource types that trigger the preconnect downgrade
path: stylesheet, script, modulepreload, and font preload.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_preconnect_attrs"
Test.ContinueOnFail = True

# ----
# Origin server: serves pages that reference cross-origin resources which
# the plugin cannot serve as full preload (no whitelist configured), so it
# will downgrade them to preconnect hints.
# ----
microserver = Test.MakeOriginServer("microserver")

# Page with a cross-origin stylesheet — downgraded to preconnect
STYLESHEET_PAGE = (
    "<html><head>"
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">'
    "</head><body>Fonts page</body></html>\r\n"
)

# Page with a cross-origin script — downgraded to preconnect
SCRIPT_PAGE = (
    "<html><head>"
    '<script src="https://cdn.example.com/analytics.js"></script>'
    "</head><body>Analytics page</body></html>\r\n"
)

# Page with a same-origin preload + fetchpriority (regression guard)
SAME_ORIGIN_PAGE = (
    "<html><head>"
    '<link rel="preload" href="/hero.js" as="script" fetchpriority="high">'
    "</head><body>Perf page</body></html>\r\n"
)

# Queue responses: 2 learns per URL then serves
for _ in range(3):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /fonts.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
            "body": STYLESHEET_PAGE
        })

for _ in range(3):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /analytics.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
            "body": SCRIPT_PAGE
        })

for _ in range(3):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /perf.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
            "body": SAME_ORIGIN_PAGE
        })

# ----
# ATS with auto-learn, no whitelist (forces preconnect downgrade for cross-origin)
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=2'
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
# TC0/TC1: Learn cross-origin stylesheet page (2 requests to reach min-hit-count=2)
# ----
tr0 = Test.AddTestRun("Preconnect-attrs: Learn stylesheet page (request 1)")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/fonts.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK expected")
tr0.StillRunningAfter = microserver

tr0b = Test.AddTestRun("Preconnect-attrs: Learn stylesheet page (request 2)")
tr0b.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/fonts.html'".format(ts.Variables.ssl_port))
tr0b.Processes.Default.ReturnCode = 0
tr0b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK expected")
tr0b.StillRunningAfter = microserver

# ----
# TC1: Serve stylesheet page — 103 must include preconnect WITHOUT crossorigin
# ----
tr1 = Test.AddTestRun("Preconnect-attrs: Stylesheet preconnect hint must not carry crossorigin")
tr1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/fonts.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "103 must be sent for fonts page")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preconnect", "fonts.googleapis.com must appear as preconnect")
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "crossorigin", "crossorigin must NOT be present on preconnect hints")
tr1.StillRunningAfter = microserver

# ----
# TC2/TC3: Learn cross-origin script page then verify
# ----
tr2 = Test.AddTestRun("Preconnect-attrs: Learn script page (request 1)")
tr2.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/analytics.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK expected")
tr2.StillRunningAfter = microserver

tr2b = Test.AddTestRun("Preconnect-attrs: Learn script page (request 2)")
tr2b.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/analytics.html'".format(ts.Variables.ssl_port))
tr2b.Processes.Default.ReturnCode = 0
tr2b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK expected")
tr2b.StillRunningAfter = microserver

tr3 = Test.AddTestRun("Preconnect-attrs: Script preconnect hint must not carry crossorigin")
tr3.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/analytics.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "103 must be sent for analytics page")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preconnect", "cdn.example.com must appear as preconnect")
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "crossorigin", "crossorigin must NOT be present on script preconnect hints")
tr3.StillRunningAfter = microserver

# ----
# TC4/TC5: Same-origin preload regression guard (fetchpriority must be preserved)
# ----
tr4 = Test.AddTestRun("Preconnect-attrs: Learn same-origin perf page (request 1)")
tr4.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/perf.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK expected")
tr4.StillRunningAfter = microserver

tr4b = Test.AddTestRun("Preconnect-attrs: Learn same-origin perf page (request 2)")
tr4b.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/perf.html'".format(ts.Variables.ssl_port))
tr4b.Processes.Default.ReturnCode = 0
tr4b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK expected")
tr4b.StillRunningAfter = microserver

tr5 = Test.AddTestRun("Preconnect-attrs: Same-origin preload must carry fetchpriority (regression guard)")
tr5.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/perf.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "103 must be sent for perf page")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "fetchpriority=high", "fetchpriority must be kept on same-origin preload")
tr5.StillRunningAfter = microserver
