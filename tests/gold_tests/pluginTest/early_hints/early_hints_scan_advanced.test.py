'''
Test 103 Early Hints plugin — advanced scanning scenarios
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
Test HTTP 103 Early Hints plugin advanced scanning scenarios.
Verifies:
- scan-limit: resources past the byte limit are not extracted
- Cross-origin URLs: converted to preconnect (non-whitelisted)
- Content-Type charset: text/html; charset=utf-8 still scanned
- Content-Encoding identity: treated as uncompressed (scanned)
- URL safety: javascript: scheme blocked, safe URLs kept
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_scan_advanced"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# scan-limit test: resource at byte ~61, then 980 bytes of padding, then another resource
# Scanner with scan-limit=1024 should find /early.css but NOT /late.js
scan_padding = 'A' * 980
scan_html = (
    '<html><head>'
    '<link rel="preload" href="/early.css" as="style">'
    '<!-- ' + scan_padding + ' -->'
    '<link rel="preload" href="/late.js" as="script">'
    '</head><body>Scan limit test</body></html>\r\n'
)

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /scanlimit.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": scan_html
    })

# Cross-origin test: one local resource + one external resource (no whitelist)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /crossorigin.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/local.js" as="script">'
            '<link rel="preload" href="https://cdn.external.com/style.css" as="style">'
            '</head><body>Cross-origin test</body></html>\r\n'
    })

# Content-Type charset test: text/html; charset=utf-8 (scanner should still run)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /charset.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/charset-style.css" as="style">'
            '</head><body>Charset test</body></html>\r\n'
    })

# Content-Encoding: identity test (scanner should still run — identity = uncompressed)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /identity.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\n"
            "Content-Type: text/html\r\nContent-Encoding: identity\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/identity-style.css" as="style">'
            '</head><body>Identity encoding test</body></html>\r\n'
    })

# URL safety test: javascript: scheme (blocked) + safe relative URL (kept)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /urlsafety.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="javascript:alert(1)" as="script">'
            '<link rel="preload" href="/safe.js" as="script">'
            '</head><body>URL safety test</body></html>\r\n'
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # scan-limit=1024: scanner stops after 1024 bytes
    'map /scanlimit.html http://127.0.0.1:{0}/scanlimit.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--scan-limit @pparam=1024'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Cross-origin: no whitelist — external URLs become preconnect
    'map /crossorigin.html http://127.0.0.1:{0}/crossorigin.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Charset: auto-learn should parse text/html; charset=utf-8
    'map /charset.html http://127.0.0.1:{0}/charset.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Identity encoding: Content-Encoding: identity → still scan
    'map /identity.html http://127.0.0.1:{0}/identity.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # URL safety: auto-learn with HTML containing javascript: + safe URL
    'map /urlsafety.html http://127.0.0.1:{0}/urlsafety.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
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
# TR1: scan-limit — early resource found, late resource NOT found
# ----
tr1 = Test.AddTestRun("scan-limit=1024: early.css found, late.js not found")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/scanlimit.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </early.css>", "Resource before scan-limit should be extracted")
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "late.js", "Resource after scan-limit must NOT be extracted")
tr1.StillRunningAfter = microserver

# ----
# TR2: cross-origin — local resource = preload, external = preconnect
# ----
tr2 = Test.AddTestRun("cross-origin: local.js preload, cdn.external.com preconnect")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/crossorigin.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </local.js>; rel=preload; as=script", "Same-origin resource should be preload")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preconnect", "Cross-origin resource should be converted to preconnect")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn.external.com", "Preconnect should reference external origin")
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "/style.css", "Full external path must NOT appear (only origin for preconnect)")
tr2.StillRunningAfter = microserver

# ----
# TR3: cross-origin H2 — verify 103 contains preconnect
# ----
tr3 = Test.AddTestRun("cross-origin H2: 103 with preconnect link")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/crossorigin.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from learned cache")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preconnect", "103 should contain preconnect for cross-origin")
tr3.StillRunningAfter = microserver

# ----
# TR4: Content-Type charset — text/html; charset=utf-8 still scanned
# ----
tr4 = Test.AddTestRun("charset: text/html; charset=utf-8 still triggers scanning")
tr4.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/charset.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </charset-style.css>", "Scanner should run despite charset parameter")
tr4.StillRunningAfter = microserver

# ----
# TR5: Content-Encoding identity — treated as uncompressed, scanner runs
# ----
tr5 = Test.AddTestRun("identity encoding: Content-Encoding: identity still scanned")
tr5.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/identity.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </identity-style.css>", "Scanner should run for identity encoding")
tr5.StillRunningAfter = microserver

# ----
# TR6: URL safety — javascript: blocked, /safe.js kept
# ----
tr6 = Test.AddTestRun("URL safety: javascript: blocked, /safe.js kept")
tr6.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/urlsafety.html'".format(ts.Variables.ssl_port))
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr6.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </safe.js>", "Safe relative URL should be extracted")
tr6.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "javascript", "javascript: scheme must be blocked by URL safety check")
tr6.StillRunningAfter = microserver
