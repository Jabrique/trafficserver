'''
Test 103 Early Hints plugin — --preload-whitelist (no-CORS cross-origin preload)
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
Test HTTP 103 Early Hints plugin --preload-whitelist feature.
Verifies:
- --preload-whitelist: trusted domain gets preload WITHOUT crossorigin
- --crossorigin-whitelist takes priority over --preload-whitelist for same domain
- modulepreload obeys --preload-whitelist (emits rel=modulepreload)
- Unwhitelisted cross-origin still gets preconnect (no regression)
- H2 103 sent with correct no-CORS preload from cache
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_preload_whitelist"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Test 1: HTML with cross-origin script and stylesheet on preload-whitelisted domain
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /preload-wl.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<script src="https://cdn.preload.com/app.js"></script>'
            '<link rel="stylesheet" href="https://cdn.preload.com/style.css">'
            '<link rel="preload" href="https://cdn.preload.com/hero.webp" as="image">'
            '<link rel="preload" href="/local.css" as="style">'
            '</head><body>Preload whitelist test</body></html>\r\n'
    })

# Test 2: HTML with modulepreload on preload-whitelisted domain (should emit modulepreload)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /module-wl.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="modulepreload" href="https://cdn.preload.com/mod.js">'
            '</head><body>Modulepreload test</body></html>\r\n'
    })

# Test 3: HTML with cross-origin on domain in BOTH whitelists (crossorigin should win)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /both-wl.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="https://cdn.both.com/app.js" as="script">'
            '</head><body>Both whitelists test</body></html>\r\n'
    })

# Test 4: HTML with unwhitelisted cross-origin (should still be preconnect — no regression)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /no-wl.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="https://unknown.example.com/thing.js" as="script">'
            '</head><body>No whitelist test</body></html>\r\n'
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # Preload whitelist: cdn.preload.com gets full preload without crossorigin
    'map /preload-wl.html http://127.0.0.1:{0}/preload-wl.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--preload-whitelist @pparam=cdn.preload.com'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Module whitelist: same domain in preload-whitelist (modulepreload obeys it)
    'map /module-wl.html http://127.0.0.1:{0}/module-wl.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--preload-whitelist @pparam=cdn.preload.com'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Both whitelists: cdn.both.com in both → crossorigin-whitelist wins
    'map /both-wl.html http://127.0.0.1:{0}/both-wl.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--crossorigin-whitelist @pparam=cdn.both.com'
    ' @pparam=--preload-whitelist @pparam=cdn.both.com'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # No whitelist: unwhitelisted domain should still get preconnect
    'map /no-wl.html http://127.0.0.1:{0}/no-wl.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--preload-whitelist @pparam=cdn.preload.com'
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

# ====================================================================
# TR1: Preload whitelist -- H1 learn: plugin scans body and learns preload-whitelisted resources
# Body transform runs after SEND_RESPONSE_HDR, so learned links cannot appear
# in this same response. Only plugin engagement is verified here.
# ====================================================================
tr1 = Test.AddTestRun("Preload whitelist: H1 learn -- script, style, image learned without crossorigin")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/preload-wl.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin engaged on H1 learn request
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip)")
# No Link header on first request (body scan runs after SEND_RESPONSE_HDR)
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "First (learn) request must not add Link headers: body scan runs after SEND_RESPONSE_HDR")
# crossorigin must never appear for preload-whitelisted resources (no-CORS preload)
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "crossorigin", "Preload-whitelisted resources must NOT have crossorigin attribute")
tr1.StillRunningAfter = microserver

# ====================================================================
# TR2: Preload whitelist — H2 103 from cache with correct preloads
# ====================================================================
tr2 = Test.AddTestRun("Preload whitelist H2: 103 sent with no-CORS preloads from cache")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/preload-wl.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn.preload.com/app.js", "Script preload should persist in cache")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn.preload.com/style.css", "Style preload should persist in cache")
tr2.StillRunningAfter = microserver

# ====================================================================
# TR3: Modulepreload -- H1 learn: preload-whitelist allows modulepreload emission
# Body transform runs after SEND_RESPONSE_HDR: no Link headers on learn request.
# ====================================================================
tr3 = Test.AddTestRun("Modulepreload: H1 learn -- preload-whitelist allows modulepreload")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/module-wl.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin engaged on H1 learn request
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip)")
# No Link header on first request
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "First (learn) request must not add Link headers")
tr3.StillRunningAfter = microserver

# ====================================================================
# TR3b: Modulepreload H2 -- 103 with rel=modulepreload from cache
# ====================================================================
tr3b = Test.AddTestRun("Modulepreload H2: 103 with rel=modulepreload from cache")
tr3b.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/module-wl.html'".format(ts.Variables.ssl_port))
tr3b.Processes.Default.ReturnCode = 0
tr3b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr3b.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=modulepreload", "Modulepreload on preload-whitelisted domain should emit rel=modulepreload")
tr3b.StillRunningAfter = microserver

# ====================================================================
# TR4: Both whitelists -- H1 learn: crossorigin-whitelist wins (has crossorigin)
# Body transform runs after SEND_RESPONSE_HDR: no Link headers on learn request.
# ====================================================================
tr4 = Test.AddTestRun("Both whitelists: H1 learn -- crossorigin-whitelist wins")
tr4.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/both-wl.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin engaged on H1 learn request
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip)")
# No Link header on first request
tr4.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "First (learn) request must not add Link headers")
tr4.StillRunningAfter = microserver

# ====================================================================
# TR4b: Both whitelists H2 -- crossorigin-whitelist wins, crossorigin=anonymous present
# ====================================================================
tr4b = Test.AddTestRun("Both whitelists H2: crossorigin-whitelist wins, crossorigin=anonymous in 103")
tr4b.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/both-wl.html'".format(ts.Variables.ssl_port))
tr4b.Processes.Default.ReturnCode = 0
tr4b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr4b.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn.both.com/app.js", "Should have full URL (preload, not preconnect)")
tr4b.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "crossorigin=anonymous", "crossorigin-whitelist should win, crossorigin=anonymous present")
tr4b.StillRunningAfter = microserver

# ====================================================================
# TR5: No whitelist -- H1 learn: unwhitelisted domain gets preconnect (regression check)
# Body transform runs after SEND_RESPONSE_HDR: no Link headers on learn request.
# ====================================================================
tr5 = Test.AddTestRun("No whitelist: H1 learn -- unwhitelisted domain learned as preconnect")
tr5.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/no-wl.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin engaged on H1 learn request
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip)")
# No Link header on first request
tr5.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "First (learn) request must not add Link headers")
tr5.StillRunningAfter = microserver

# ====================================================================
# TR5b: No whitelist H2 -- preconnect in 103 (no regression)
# ====================================================================
tr5b = Test.AddTestRun("No whitelist H2: preconnect in 103 (no regression)")
tr5b.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/no-wl.html'".format(ts.Variables.ssl_port))
tr5b.Processes.Default.ReturnCode = 0
tr5b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr5b.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "unknown.example.com>; rel=preconnect", "Unwhitelisted domain should get preconnect")
tr5b.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "unknown.example.com/thing.js", "Unwhitelisted full path must NOT appear (only origin for preconnect)")
tr5b.StillRunningAfter = microserver
