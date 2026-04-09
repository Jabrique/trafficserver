'''
Test 103 Early Hints plugin — HTML resource type handling
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
Test HTTP 103 Early Hints plugin resource type handling.
Verifies:
- <link rel="stylesheet"> converted to rel=preload; as=style
- <script async/defer> NOT preloaded (bandwidth waste prevention)
- <link as="font"> gets auto crossorigin=anonymous (W3C spec)
- fetchpriority attribute passed through to Link header
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_resource_types"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# HTML page with diverse resource types
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /resources.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="stylesheet" href="/theme.css">'
            '<link rel="preload" href="/font.woff2" as="font">'
            '<link rel="preload" href="/hero.webp" as="image" fetchpriority="high">'
            '<script src="/sync.js"></script>'
            '<script async src="/async-analytics.js"></script>'
            '<script defer src="/defer-init.js"></script>'
            '</head><body>Resource types test</body></html>\r\n'
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    'map /resources.html http://127.0.0.1:{0}/resources.html'.format(microserver.Variables.Port) +
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
# TR1: H1 learn — verify resource type conversion in 200 response Link headers
# ----
tr1 = Test.AddTestRun("Resource types: stylesheet, font, sync/async/defer scripts")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/resources.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")

# Stylesheet → preload as=style
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload; as=style", "Stylesheet should be converted to preload as=style")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/theme.css", "Stylesheet href should be preserved")

# Font gets auto crossorigin=anonymous (W3C CSS Fonts spec)
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "as=font; crossorigin=anonymous", "Font must have crossorigin=anonymous per W3C spec")

# fetchpriority passthrough
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "fetchpriority=high", "fetchpriority=high should be passed through to Link header")

# Sync script preloaded
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/sync.js", "Synchronous script should be preloaded")

# Async script NOT preloaded (critical: wastes bandwidth if sent)
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "async-analytics", "Async script must NOT be preloaded (bandwidth waste)")

# Defer script NOT preloaded
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "defer-init", "Deferred script must NOT be preloaded (loads after DOM)")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 request — verify 103 sent with correct resource types from cache
# ----
tr2 = Test.AddTestRun("H2: 103 sent with correct resource types")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/resources.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should receive 103 from cached hints")

# Verify correct types in H2 response (lowercase headers)
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "theme.css", "Stylesheet should appear in cached hints")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "font.woff2", "Font should appear in cached hints")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "sync.js", "Sync script should appear in cached hints")

# Async/defer still excluded from cache
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "async-analytics", "Async script must NOT appear in cached 103 hints")
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "defer-init", "Deferred script must NOT appear in cached 103 hints")
tr2.StillRunningAfter = microserver
