'''
Test 103 Early Hints plugin — crossorigin whitelist, protocol-relative URLs, origin Link validation
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
Test HTTP 103 Early Hints plugin crossorigin whitelist and origin Link validation.
Verifies:
- --crossorigin-whitelist: trusted domain gets preload, untrusted gets preconnect
- Protocol-relative URL (//cdn.com/...) detected as cross-origin → preconnect
- Origin-forward mode: invalid Link headers rejected, valid ones cached
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_whitelist"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Whitelist test: HTML with trusted + untrusted cross-origin resources
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /whitelist.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="https://cdn.trusted.com/style.css" as="style">'
            '<link rel="preload" href="https://cdn.untrusted.com/app.js" as="script">'
            '<link rel="preload" href="/local.css" as="style">'
            '</head><body>Whitelist test</body></html>\r\n'
    })

# Protocol-relative URL test: //cdn.proto.com/...
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /proto-relative.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="//cdn.proto.com/style.css" as="style">'
            '<link rel="preload" href="/local-proto.js" as="script">'
            '</head><body>Protocol-relative test</body></html>\r\n'
    })

# Origin invalid Link test: one invalid + one valid Link header from origin
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /origin-links.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: not-a-valid-link-header\r\n"
            "Link: </valid-origin.css>; rel=preload; as=style\r\n\r\n",
        "body": "<html><body>Origin links test</body></html>\r\n"
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # Whitelist: cdn.trusted.com is whitelisted (preload), cdn.untrusted.com is not (preconnect)
    'map /whitelist.html http://127.0.0.1:{0}/whitelist.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--crossorigin-whitelist @pparam=cdn.trusted.com'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Protocol-relative: no whitelist
    'map /proto-relative.html http://127.0.0.1:{0}/proto-relative.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Origin invalid Link: origin-forward mode
    'map /origin-links.html http://127.0.0.1:{0}/origin-links.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
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
# TR1: Whitelist -- H1 learn: plugin scans body and learns trust-classified resources
# Body transform runs after SEND_RESPONSE_HDR, so learned links cannot appear
# in this same response. Only plugin engagement is verified here.
# ----
tr1 = Test.AddTestRun("Whitelist: H1 learn -- trusted and untrusted CDN resources learned")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/whitelist.html'".format(ts.Variables.ssl_port))
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
tr1.StillRunningAfter = microserver

# ----
# TR2: Whitelist — H2 sent with correct link types from cache
# ----
tr2 = Test.AddTestRun("Whitelist H2: 103 sent with correct trust boundaries")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/whitelist.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn.trusted.com/style.css", "Trusted CDN preload should persist in cache")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preconnect", "Untrusted CDN preconnect should persist in cache")
tr2.StillRunningAfter = microserver

# ----
# TR3: Protocol-relative URL -- H1 learn: //cdn.proto.com detected as cross-origin
# Body transform runs after SEND_RESPONSE_HDR: no Link headers on learn request.
# ----
tr3 = Test.AddTestRun("Protocol-relative: H1 learn -- //cdn.proto.com detected as cross-origin")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/proto-relative.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin engaged on H1 learn request
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip)")
# No Link header on first request (body scan runs after SEND_RESPONSE_HDR)
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "First (learn) request must not add Link headers")
tr3.StillRunningAfter = microserver

# ----
# TR3b: Protocol-relative H2 -- verify 103 contains preconnect for //cdn.proto.com
# ----
tr3b = Test.AddTestRun("Protocol-relative H2: 103 with preconnect for cdn.proto.com")
tr3b.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/proto-relative.html'".format(ts.Variables.ssl_port))
tr3b.Processes.Default.ReturnCode = 0
tr3b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
# Protocol-relative becomes preconnect (with scheme prefix added)
tr3b.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn.proto.com>; rel=preconnect", "Protocol-relative URL should become preconnect")
# Local resource still preload
tr3b.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "local-proto.js", "Local resource should still be preloaded")
tr3b.StillRunningAfter = microserver

# ----
# TR4: Origin invalid Link -- H1 first request: plugin learns only valid Link (origin-forward mode)
# Body transform runs after SEND_RESPONSE_HDR: plugin adds learned links to this 200 response.
# In origin-forward mode, the plugin reads Link headers from origin and caches valid ones.
# The 200 response serves the origin Link headers directly (ATS passthrough), not plugin-added.
# The plugin-learned valid link is served in 103 on subsequent H2 requests (TR5).
# ----
tr4 = Test.AddTestRun("Origin invalid Link: first request learns and caches only valid Link")
tr4.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/origin-links.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Plugin engaged (H1, origin-forward: no 103 but still processes)
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip)")
tr4.StillRunningAfter = microserver

# ----
# TR5: Origin invalid Link — H2 103 sent with only valid Link from cache
# ----
tr5 = Test.AddTestRun("Origin invalid Link: H2 103 with only valid Link")
tr5.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/origin-links.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cached valid Link")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "valid-origin.css", "Valid origin Link should be in 103 response")
# Note: invalid Link appears in 200 section (origin passthrough) but NOT in 103 section.
# The 103 is entirely generated by the plugin from its validated cache.
tr5.StillRunningAfter = microserver
