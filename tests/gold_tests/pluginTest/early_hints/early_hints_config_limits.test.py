'''
Test 103 Early Hints plugin — config limit enforcement
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
Test HTTP 103 Early Hints plugin config limit enforcement.
Verifies:
- max-links: only configured number of links in response
- header-size-limit: oversized cumulative links skipped
- Content-Encoding: gzip response skips HTML scanning
- Content-Encoding: br (brotli) response skips HTML scanning
- Non-HTML Content-Type skips HTML scanning
- Malformed HTML: plugin does not crash
- HEAD request: handled without crash
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_config_limits"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Simple HTML page (for manual mode tests — plugin doesn't scan body in manual mode)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
    })

# Page with Content-Encoding: gzip header but UNCOMPRESSED HTML body.
# Plugin should detect Content-Encoding and skip scanning entirely.
# If scanner ran, it would find /gzip-resource.js — but it must NOT.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /gzip.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Content-Encoding: gzip\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/gzip-resource.js\" as=\"script\">"
            "</head><body>Gzip test</body></html>\r\n"
    })

# Malformed HTML: missing quotes, truncated tags
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /malformed.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=preload href=/ok-resource.js as=script>"
            "<link rel=\"preload href=\"/broken.css\" as=\"style\">"
            "</head><body>Malformed</body></html>\r\n"
    })

# Page with Content-Encoding: br (brotli) — should skip scanning
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /brotli.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Content-Encoding: br\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/brotli-resource.js\" as=\"script\">"
            "</head><body>Brotli test</body></html>\r\n"
    })

# Non-HTML response (JSON) — scanner should not engage
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /api/data.json HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
        "body": '{"link": "<link rel=preload href=/fake.js>", "data": "test"}\r\n'
    })

# Page for HEAD request test
microserver.addResponse(
    "sessionfile.log", {
        "headers": "HEAD /headtest.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": ""
    })

# Page for as= validation test (response body irrelevant — manual mode)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /as-warn.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><body>as= validation test</body></html>\r\n"
    })

# ----
# Setup ATS with multiple remap rules for different configs
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # max-links=1: 3 manual links configured, only first should appear
    'map /maxlinks.html http://127.0.0.1:{0}/page.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--max-links @pparam=1'
    ' @pparam=--link @pparam=</a.css>;rel=preload;as=style'
    ' @pparam=--link @pparam=</b.js>;rel=preload;as=script'
    ' @pparam=--link @pparam=</c.woff2>;rel=preload;as=font'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # header-size-limit=256: links 1+2 fit, link 3 overflows
    'map /sizelimit.html http://127.0.0.1:{0}/page.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--header-size-limit @pparam=256'
    ' @pparam=--link @pparam=</assets/css/main-bundle.very-long-hash-abc123def456.min.css>;rel=preload;as=style'
    ' @pparam=--link @pparam=</assets/js/vendor-bundle.very-long-hash-abc123def456.min.js>;rel=preload;as=script'
    ' @pparam=--link @pparam=</assets/fonts/roboto-regular.very-long-hash-abc123def456.woff2>;rel=preload;as=font'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Content-Encoding test: auto-learn should skip scanning for compressed responses
    'map /gzip.html http://127.0.0.1:{0}/gzip.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Malformed HTML test: plugin should handle bad HTML without crashing
    'map /malformed.html http://127.0.0.1:{0}/malformed.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Content-Encoding: br (brotli) — auto-learn should skip scanning
    'map /brotli.html http://127.0.0.1:{0}/brotli.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Non-HTML Content-Type — scanner should not engage
    'map /api/data.json http://127.0.0.1:{0}/api/data.json'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # HEAD request test
    'map /headtest.html http://127.0.0.1:{0}/headtest.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</head-style.css>;rel=preload;as=style'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # as= validation: rel=preload without as= (soft-warn, link still accepted)
    'map /as-warn.html http://127.0.0.1:{0}/as-warn.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</no-as-resource.css>;rel=preload'
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

# Override default diags_log check: we expect a WARNING from as= soft-warn (logged via TSError)
ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "WARNING.*--link has rel=preload without valid as=",
    "Plugin should log as= soft-warn for /no-as-resource.css")
ts.Disk.diags_log.Content += Testers.ExcludesExpression(
    "FATAL:", "Diags log should not contain FATAL errors")

# ----
# Test Case 0: max-links=1 — only first link appears
# ----
tr1 = Test.AddTestRun("max-links=1 limits to first link only")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/maxlinks.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </a.css>", "First link should be present (within max-links=1)")
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "b.js", "Second link must be excluded by max-links=1")
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "c.woff2", "Third link must be excluded by max-links=1")
tr1.StillRunningAfter = microserver

# ----
# Test Case 1: header-size-limit=256 — first 2 links fit, 3rd skipped
# ----
tr2 = Test.AddTestRun("header-size-limit=256 skips oversized third link")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/sizelimit.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </assets/css/main-bundle", "First link fits within size limit")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </assets/js/vendor-bundle", "Second link fits within size limit")
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "roboto-regular", "Third link must be skipped (cumulative exceeds 256 byte limit)")
tr2.StillRunningAfter = microserver

# ----
# Test Case 2: Content-Encoding gzip — first request (learn phase skipped)
# ----
tr3 = Test.AddTestRun("Content-Encoding gzip - learn phase")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/gzip.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage")
tr3.StillRunningAfter = microserver

# ----
# Test Case 3: Content-Encoding gzip — second request verifies nothing learned
# ----
tr4 = Test.AddTestRun("Content-Encoding gzip - verify no links learned")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/gzip.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
# Plugin-specific: debug header proves plugin engaged
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged on gzip response (H1 skip)")
# The critical assertion: no Link headers means scanner was correctly skipped
tr4.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "gzip-resource", "Scanner must not have run on gzip response (no links learned)")
tr4.StillRunningAfter = microserver

# ----
# Test Case 4: Malformed HTML — plugin doesn't crash, returns 200
# ----
tr5 = Test.AddTestRun("Malformed HTML - plugin handles gracefully")
tr5.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/malformed.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Malformed HTML should not crash plugin — 200 returned")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage even with malformed HTML")
tr5.StillRunningAfter = microserver

# ----
# Test Case 5: Content-Encoding: br (brotli) — learn phase skipped
# ----
tr6 = Test.AddTestRun("Content-Encoding brotli - learn phase")
tr6.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/brotli.html'".format(ts.Variables.ssl_port))
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr6.StillRunningAfter = microserver

# ----
# Test Case 6: Content-Encoding: br — second request verifies nothing learned
# ----
tr7 = Test.AddTestRun("Content-Encoding brotli - verify no links learned")
tr7.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/brotli.html'".format(ts.Variables.ssl_port))
tr7.Processes.Default.ReturnCode = 0
tr7.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr7.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "brotli-resource", "Scanner must not have run on brotli response (no links learned)")
tr7.StillRunningAfter = microserver

# ----
# Test Case 7: Non-HTML Content-Type (JSON) — first request
# ----
tr8 = Test.AddTestRun("Non-HTML JSON - learn phase")
tr8.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/api/data.json'".format(ts.Variables.ssl_port))
tr8.Processes.Default.ReturnCode = 0
tr8.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr8.StillRunningAfter = microserver

# ----
# Test Case 8: Non-HTML — second request verifies nothing learned
# ----
tr9 = Test.AddTestRun("Non-HTML JSON - verify no links learned")
tr9.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/api/data.json'".format(ts.Variables.ssl_port))
tr9.Processes.Default.ReturnCode = 0
tr9.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr9.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "fake.js", "Scanner must not have run on JSON response (no links learned)")
tr9.StillRunningAfter = microserver

# ----
# Test Case 9: HEAD request — manual mode, should not crash
# ----
tr10 = Test.AddTestRun("HEAD request - plugin handles without crash")
tr10.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --head"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/headtest.html'".format(ts.Variables.ssl_port))
tr10.Processes.Default.ReturnCode = 0
tr10.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "HEAD request should return 200 without crash")
tr10.StillRunningAfter = microserver

# ----
# Test Case 10: as= validation — rel=preload without as= still accepted (soft-warn)
# Link appears in 200 response because soft-warn does not reject the link.
# ----
tr11 = Test.AddTestRun("as= validation - rel=preload without as= still works")
tr11.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/as-warn.html'".format(ts.Variables.ssl_port))
tr11.Processes.Default.ReturnCode = 0
tr11.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Link is still accepted despite missing as= (soft-warn behavior)
tr11.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "no-as-resource.css", "Link without as= should still appear in 200 (soft-warn, not reject)")
tr11.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage for as= validation test")
tr11.StillRunningAfter = microserver
