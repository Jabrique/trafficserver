'''
Test 103 Early Hints plugin — WP2 SISA: extract_origin() RFC 3986 compliance
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
WP2 SISA: extract_origin() must use RFC 3986 §3.1 scheme detection.

Bug: extract_origin() uses url.find("://") naively. For a URL like
/loader?url=https://cdn.example.com/app.js — a same-origin endpoint that
proxies external resources — is_crossorigin() correctly returns false (fixed
in WP2 main), BUT if extract_origin() were ever called for this URL it would
produce "/loader?url=https://cdn.example.com" (wrong) instead of returning
the URL as-is.

This gold test validates the end-to-end behavior: the scanner must produce
a clean rel=preload hint with the FULL proxy URL, not any broken fragment
derived from the inner URL. The hint header must contain the full proxy path.

These tests must PASS after the extract_origin() fix.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_extract_origin_rfc3986"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Page with a JavaScript loader that proxies external bundles via local endpoint
# The proxy URL has :// inside the query string (same-origin but looks cross-origin to naive check)
PROXY_PAGE_BODY = (
    "<html><head>"
    '<script src="/loader?url=https://cdn.example.com/react.js"></script>'
    '<link rel="stylesheet" href="/assets?src=https://fonts.googleapis.com/css2">'
    "</head><body>App</body></html>\r\n"
)

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /proxy-app.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": PROXY_PAGE_BODY
    })

# Second request — serves cached hints
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /proxy-app.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": PROXY_PAGE_BODY
    })

# Genuine cross-origin page for regression guard
CROSS_ORIGIN_BODY = (
    "<html><head>"
    '<link rel="preload" href="https://fonts.gstatic.com/font.woff2" as="font">'
    "</head><body>Fonts</body></html>\r\n"
)

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /cross-origin.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": CROSS_ORIGIN_BODY
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /cross-origin.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": CROSS_ORIGIN_BODY
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
# TC0: Learn phase — proxy app page
# ----
tr0 = Test.AddTestRun("WP2-SISA: Learn proxy app page")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/proxy-app.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200 OK")
tr0.StillRunningAfter = microserver

# ----
# TC1: Serve — verify proxy URL script produces same-origin rel=preload hint
#
# BUG (before fix): is_crossorigin() was already fixed in WP2 main, but if
# extract_origin() were invoked defensively, it would corrupt the hint to
# something like </loader?url=https://cdn.example.com>; rel=preconnect
# instead of </loader?url=https://cdn.example.com/react.js>; rel=preload; as=script
#
# EXPECTED AFTER FIX:
#   Link: </loader?url=https://cdn.example.com/react.js>; rel=preload; as=script
#   NOT:  <https://cdn.example.com>; rel=preconnect  (false cross-origin)
#   NOT:  </loader?url=https://cdn.example.com>; rel=preconnect (broken origin)
# ----
tr1 = Test.AddTestRun("WP2-SISA: Proxy script URL must produce full same-origin rel=preload hint")
tr1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/proxy-app.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Hints must be served on second request")
# The full proxy URL must appear in the hint, not a fragment of it
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload; as=script",
    "Proxy script URL must produce rel=preload; as=script (same-origin)")
# BUG guard: the inner CDN origin must NOT appear as a standalone preconnect
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "cdn.example.com>; rel=preconnect",
    "Proxy URL must NOT generate cross-origin preconnect to inner CDN host")
# BUG guard: the broken partial origin must NOT appear
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "loader?url=https://cdn.example.com>",
    "extract_origin must NOT strip path from a non-absolute proxy URL")
tr1.StillRunningAfter = microserver

# ----
# TC2+3: Regression guard — genuine cross-origin still produces correct preconnect
# ----
tr2 = Test.AddTestRun("WP2-SISA: Learn genuine cross-origin (regression guard)")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/cross-origin.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200 OK")
tr2.StillRunningAfter = microserver

tr3 = Test.AddTestRun("WP2-SISA: Genuine cross-origin font still gets crossorigin preconnect")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/cross-origin.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Genuine cross-origin must produce preconnect")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "fonts.gstatic.com>; rel=preconnect",
    "Font CDN origin must appear as preconnect — regression guard for WP2 fix")
tr3.StillRunningAfter = microserver
