'''
Test 103 Early Hints plugin  -- is_crossorigin false positive on :// in query string
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
is_crossorigin false positive when :// appears in URL query string.

Bug: href.find("://") matches anywhere in the URL string, so a same-origin
proxy URL like /proxy?url=https://cdn.example.com/app.js is incorrectly
treated as cross-origin, producing a rel=preconnect hint to
https://cdn.example.com instead of a same-origin rel=preload hint for
the full proxy URL.

Fix: detect scheme only when :// is preceded by valid RFC 3986 ALPHA chars
from the very start of the URL  -- not when it appears inside a query string.

These tests document the expected behavior after the RFC 3986 fix.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_crossorigin_qstring"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Page with proxy URL containing :// in query string  -- must produce same-origin preload
# BUG: current is_crossorigin returns true for /proxy?url=https://... → preconnect to cdn
# FIX: must return false (same-origin) → preload for full /proxy?url=... URL
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /proxy-page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            '<link rel="preload" href="/proxy?url=https://cdn.example.com/app.js" as="script">'
            "</head><body>Proxy page</body></html>\r\n"
    })

# Second request to get cached hints served
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /proxy-page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            '<link rel="preload" href="/proxy?url=https://cdn.example.com/app.js" as="script">'
            "</head><body>Proxy page</body></html>\r\n"
    })

# Genuine cross-origin page  -- must still produce preconnect (control case)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /cross-origin.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            '<link rel="preload" href="https://cdn.example.com/lib.js" as="script">'
            "</head><body>Cross-origin page</body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /cross-origin.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            '<link rel="preload" href="https://cdn.example.com/lib.js" as="script">'
            "</head><body>Cross-origin page</body></html>\r\n"
    })

# ----
# Setup ATS  -- auto-learn mode
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
# TC0: Learn  -- proxy URL with :// in query string
# ----
tr0 = Test.AddTestRun("Crossorigin-fix: Learn proxy URL (same-origin with :// in query string)")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/proxy-page.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200 OK")
tr0.StillRunningAfter = microserver

# ----
# TC1: Serve  -- verify proxy URL produces same-origin rel=preload (not rel=preconnect)
# BUG: /proxy?url=https://... is treated as cross-origin → gets preconnect hint to cdn.example.com
# FIX: is_crossorigin returns false → full proxy URL gets rel=preload; as=script
# ----
tr1 = Test.AddTestRun("Crossorigin-fix: Proxy URL must produce rel=preload (same-origin), NOT rel=preconnect")
tr1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/proxy-page.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
# MUST have 103 sent with the full proxy URL as preload
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Proxy URL hint must be learned and served")
# BUG check: before fix, hint is preconnect to cdn.example.com (wrong  -- cross-origin false positive)
# PASS check: after fix, hint is preload for full /proxy?url=... (correct  -- same-origin)
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload; as=script", "Proxy URL must produce rel=preload not rel=preconnect")
# This ExcludesExpression proves the false positive is fixed
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "cdn.example.com>; rel=preconnect",
    "BUG: before fix, :// in query causes false cross-origin preconnect to cdn.example.com")
tr1.StillRunningAfter = microserver

# ----
# TC2+3: Control  -- genuine cross-origin URL still produces preconnect (regression guard)
# ----
tr2 = Test.AddTestRun("Crossorigin-fix: Control  -- genuine cross-origin learn phase")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/cross-origin.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200 OK")
tr2.StillRunningAfter = microserver

tr3 = Test.AddTestRun("Crossorigin-fix: Control  -- genuine cross-origin still gets preconnect after fix")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/cross-origin.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Genuine cross-origin must still produce preconnect hint")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn.example.com>; rel=preconnect",
    "Genuine https://cdn.example.com/lib.js must still produce preconnect  -- not broken by fix")
tr3.StillRunningAfter = microserver
