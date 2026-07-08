'''
Test 103 Early Hints plugin  -- fetchpriority injection security and valid forwarding
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
Test HTTP 103 Early Hints plugin fetchpriority handling in origin-forward mode.
Verifies:
- Valid fetchpriority tokens (high, low, auto) are preserved in 103 response.
- Unknown or malformed fetchpriority tokens are silently dropped.
- A Link header with < > in params portion is rejected entirely (injection guard).
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_fetchpriority"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Page 1: stylesheet with fetchpriority=high (valid token, must be forwarded)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /high.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=high\r\n"
            "\r\n",
        "body": "<html><body>fetchpriority=high</body></html>\r\n"
    })

# Page 2: stylesheet with fetchpriority=auto (valid token, must be forwarded)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /auto.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=auto\r\n"
            "\r\n",
        "body": "<html><body>fetchpriority=auto</body></html>\r\n"
    })

# Page 3: stylesheet with fetchpriority=critical (unknown token, must be dropped)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /unknown.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <https://cdn.example.com/style.css>; rel=stylesheet; fetchpriority=critical\r\n"
            "\r\n",
        "body": "<html><body>fetchpriority=critical (unknown)</body></html>\r\n"
    })

# Page 4: malformed Link with > in params (injection attempt, whole header rejected)
# is_valid_link_value rejects any < or > in the params portion.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /inject.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <https://cdn.example.com/style.css>; rel=preload; as=style; title=a>b\r\n"
            "\r\n",
        "body": "<html><body>injection attempt</body></html>\r\n"
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
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# TR0: Learn fetchpriority=high  -- first H1 request (no 103 on H1)
# ----
tr0 = Test.AddTestRun("Learn: stylesheet with fetchpriority=high")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/high.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr0.StillRunningAfter = microserver

# ----
# TR1: H2 request for fetchpriority=high  -- should get 103 with fetchpriority=high preserved
# ----
tr1 = Test.AddTestRun("H2: fetchpriority=high preserved in 103")
tr1.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/high.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Plugin should send 103 with cached hints")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "fetchpriority=high", "fetchpriority=high must be present in forwarded hint")
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "fetchpriority=critical", "Unknown token must not appear")
tr1.StillRunningAfter = microserver

# ----
# TR2: Learn fetchpriority=auto  -- H1 first request
# ----
tr2 = Test.AddTestRun("Learn: stylesheet with fetchpriority=auto")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/auto.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr2.StillRunningAfter = microserver

# ----
# TR3: H2 request for fetchpriority=auto
# ----
tr3 = Test.AddTestRun("H2: fetchpriority=auto preserved in 103")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/auto.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Plugin should send 103")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "fetchpriority=auto", "fetchpriority=auto must be preserved")
tr3.StillRunningAfter = microserver

# ----
# TR4: Learn fetchpriority=critical (unknown token)  -- H1 first request
# ----
tr4 = Test.AddTestRun("Learn: stylesheet with unknown fetchpriority=critical")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/unknown.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr4.StillRunningAfter = microserver

# ----
# TR5: H2 for unknown fetchpriority  -- hint sent but without fetchpriority=critical
# ----
tr5 = Test.AddTestRun("H2: unknown fetchpriority=critical silently dropped")
tr5.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/unknown.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
# The plugin normalizes rel=stylesheet to rel=preload; as=style and drops unknown fetchpriority.
# Verify the 103 was sent and that the plugin's preload hint is clean (no unknown token).
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: sent", "Plugin sends 103 even when fetchpriority is dropped")
# The 103 link must be normalized to rel=preload without fetchpriority=critical.
# (Origin's 200 passthrough may still carry rel=stylesheet; fetchpriority=critical, but
# the plugin's own hint stored and forwarded as rel=preload must not carry the unknown token.)
tr5.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "rel=preload; as=style; fetchpriority=critical",
    "Plugin preload hint must not carry unknown fetchpriority token")
tr5.StillRunningAfter = microserver

# ----
# TR6: Learn injection attempt  -- H1 first request (Link with > in params)
# ----
tr6 = Test.AddTestRun("Learn: Link with > in params (injection attempt)")
tr6.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/inject.html'".format(ts.Variables.ssl_port))
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr6.StillRunningAfter = microserver

# ----
# TR7: H2 for injection page  -- no 103 because the injected header was rejected
# ----
tr7 = Test.AddTestRun("H2: Link with > in params not forwarded as hint")
tr7.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/inject.html'".format(ts.Variables.ssl_port))
tr7.Processes.Default.ReturnCode = 0
# The malformed Link was rejected by is_valid_link_value  -- nothing to cache.
# Plugin reports no-hints or no-cached.
tr7.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "x-early-hints-status: sent", "Injected Link must not result in a 103 being sent")
tr7.StillRunningAfter = microserver
