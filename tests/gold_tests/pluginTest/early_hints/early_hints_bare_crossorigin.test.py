'''
Test 103 Early Hints plugin -- bare crossorigin attribute normalization
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
Test HTTP 103 Early Hints plugin bare crossorigin attribute normalization.
HTML spec section 2.5.3: bare 'crossorigin' (no value) means crossorigin=anonymous.
Verifies that when origin sends Link: rel=stylesheet; crossorigin (bare boolean),
the 103 Early Hints response forwarded to the H2 client contains crossorigin=anonymous.

Flow:
  TR1 (H1): First request learns origin Link header. Plugin stores normalized form
            rel=preload; as=style; crossorigin=anonymous in its in-memory cache.
  TR2 (H2): Second request. Plugin finds cached hints (request_count >= min_hit_count)
            and sends 103 Early Hints before the origin response. The 103 Link header
            must contain crossorigin=anonymous proving the bare attribute was normalized.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_bare_crossorigin"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Origin sends a stylesheet link with bare crossorigin (no =value).
# After normalization, it becomes rel=preload; as=style; crossorigin=anonymous.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html\r\n"
            "Link: </fonts/Inter.woff2>; rel=stylesheet; crossorigin\r\n"
            "\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
    })

# Second request (for H2 cache hit verification)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html\r\n"
            "Link: </fonts/Inter.woff2>; rel=stylesheet; crossorigin\r\n"
            "\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
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
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 5,
})

# ----
# TR1: H1 learning pass -- plugin normalizes origin Link header and caches it.
# request_count is NOT incremented by put(), so only the learning happens here.
# ----
tr1 = Test.AddTestRun("H1 learning pass: origin sends bare crossorigin, plugin caches normalized form")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK on learning pass")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin should be loaded and skipping 103 for H1")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 request -- plugin finds cached normalized link, sends 103 Early Hints.
# request_count is incremented by get() in TSRemapDoRemap for H2 clients.
# The 103 Link header must contain crossorigin=anonymous (not bare 'crossorigin').
# This proves normalize_link_for_hint() correctly maps bare crossorigin to anonymous.
# ----
tr2 = Test.AddTestRun("H2 cache hit: 103 sent with crossorigin=anonymous from normalized bare crossorigin")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D -"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# 103 + 200 both arrive; curl -D - prints all response headers including 103.
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Should receive 103 Early Hints from cached normalized link")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should receive final 200 OK")
# The 103 Link header must have rel=preload; as=style (stylesheet converted).
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload", "Origin stylesheet link normalized to rel=preload in 103")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "as=style", "as=style attribute present in 103 Link header")
# The bare 'crossorigin' must become crossorigin=anonymous.
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "crossorigin=anonymous", "Bare crossorigin normalized to crossorigin=anonymous in 103")
# Status must show hint was sent (not skipped).
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: sent", "Plugin should have sent 103 from cache")
tr2.StillRunningAfter = microserver
