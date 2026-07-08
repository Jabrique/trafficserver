'''
Test 103 Early Hints plugin -- modulepreload handling

Covers three correctness fixes for rel=modulepreload:

  has_valid_as_for_preload(): rel=modulepreload must not require as= because
    the HTML spec makes it optional (browser defaults to script destination).
    Without this fix, modulepreload links without as= are dropped on disk reload.

  is_preload_hint check: must include rel=modulepreload so that fetchpriority=
    and type= attributes are preserved. Previously only rel=preload was checked.

  script type=module: <script type="module" src="..."> should emit
    rel=modulepreload in the 103 hint, not rel=preload; as=script.

These tests FAIL before the fix and PASS after the fix.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may not
#  use this file except in compliance with the License. You may
#  obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
#  either express or implied.  See the License for the specific
#  language governing permissions and limitations under the License.

Test.Summary = '''
modulepreload correctness: as= optional, fetchpriority preserved, script type=module.

1. <link rel=modulepreload href=/mod.mjs> (no as=) must be cached and served as 103.
2. <link rel=modulepreload fetchpriority=high> must preserve fetchpriority in 103.
3. <script type="module" src="/app.mjs"> must emit rel=modulepreload hint (not rel=preload; as=script).
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_modulepreload"
Test.ContinueOnFail = True

# ------------------------------------------------------------------------------
# Origin server
# ------------------------------------------------------------------------------
ms = Test.MakeOriginServer("ms")

# Page 1: modulepreload without as=  -- C-01 fix
# Without fix: has_valid_as_for_preload drops it on disk reload.
# With fix: learned and served as 103 hint.
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /c01-no-as.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"modulepreload\" href=\"/mod.mjs\">"
            "</head><body>C-01 test</body></html>\r\n"
    })

ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /c01-no-as.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"modulepreload\" href=\"/mod.mjs\">"
            "</head><body>C-01 test</body></html>\r\n"
    })

# Page 2: modulepreload with fetchpriority=high  -- B-05 fix
# Without fix: is_preload_hint is false for modulepreload, fetchpriority dropped.
# With fix: fetchpriority=high preserved in Link hint.
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /b05-fetchpriority.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"modulepreload\" href=\"/critical.mjs\" fetchpriority=\"high\">"
            "</head><body>B-05 test</body></html>\r\n"
    })

ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /b05-fetchpriority.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"modulepreload\" href=\"/critical.mjs\" fetchpriority=\"high\">"
            "</head><body>B-05 test</body></html>\r\n"
    })

# Page 3: script type=module  -- A-24 fix
# Without fix: <script type="module" src=...> emits rel=preload; as=script.
# With fix: emits rel=modulepreload.
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a24-module-script.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<script type=\"module\" src=\"/app.mjs\"></script>"
            "</head><body>A-24 test</body></html>\r\n"
    })

ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a24-module-script.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<script type=\"module\" src=\"/app.mjs\"></script>"
            "</head><body>A-24 test</body></html>\r\n"
    })

# ------------------------------------------------------------------------------
# ATS setup  -- auto-learn mode, min-hit-count=1, H2
# ------------------------------------------------------------------------------
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(ms.Variables.Port) +
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

# ==============================================================================
# C-01: modulepreload without as= is cached and served as Link hint
# ==============================================================================

tr_c01_1 = Test.AddTestRun("C-01 request 1: learn modulepreload without as=")
tr_c01_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/c01-no-as.html'".format(ts.Variables.ssl_port))
tr_c01_1.Processes.Default.ReturnCode = 0
tr_c01_1.Processes.Default.StartBefore(ms, ready=When.PortOpen(ms.Variables.Port))
tr_c01_1.Processes.Default.StartBefore(Test.Processes.ts)
tr_c01_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "first request must succeed")
tr_c01_1.StillRunningAfter = ms

tr_c01_2 = Test.AddTestRun("C-01 request 2: modulepreload without as= appears in Link hint (H2)")
tr_c01_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/c01-no-as.html'".format(ts.Variables.ssl_port))
tr_c01_2.Processes.Default.ReturnCode = 0
tr_c01_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "rel=modulepreload",
    "modulepreload without as= must be cached and appear in 103/Link hint")
tr_c01_2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/mod.mjs", "/mod.mjs must be in the hint")
tr_c01_2.StillRunningAfter = ms

# ==============================================================================
# B-05: fetchpriority=high preserved for modulepreload hint
# ==============================================================================

tr_b05_1 = Test.AddTestRun("B-05 request 1: learn modulepreload with fetchpriority=high")
tr_b05_1.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/b05-fetchpriority.html'".format(ts.Variables.ssl_port))
tr_b05_1.Processes.Default.ReturnCode = 0
tr_b05_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "first request must succeed")
tr_b05_1.StillRunningAfter = ms

tr_b05_2 = Test.AddTestRun("B-05 request 2: fetchpriority=high preserved in 103/Link hint (H2)")
tr_b05_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/b05-fetchpriority.html'".format(ts.Variables.ssl_port))
tr_b05_2.Processes.Default.ReturnCode = 0
tr_b05_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "fetchpriority=high",
    "fetchpriority=high must be preserved in the modulepreload hint")
tr_b05_2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=modulepreload", "rel=modulepreload must be in the hint")
tr_b05_2.StillRunningAfter = ms

# ==============================================================================
# <script type="module" src=...> emits rel=modulepreload (not rel=preload; as=script)
# ==============================================================================

tr_a24_1 = Test.AddTestRun("request 1: learn script type=module")
tr_a24_1.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/a24-module-script.html'".format(ts.Variables.ssl_port))
tr_a24_1.Processes.Default.ReturnCode = 0
tr_a24_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "first request must succeed")
tr_a24_1.StillRunningAfter = ms

tr_a24_2 = Test.AddTestRun("request 2: script type=module emits rel=modulepreload (H2)")
tr_a24_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/a24-module-script.html'".format(ts.Variables.ssl_port))
tr_a24_2.Processes.Default.ReturnCode = 0
tr_a24_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "rel=modulepreload",
    "<script type=module> must emit rel=modulepreload hint")
tr_a24_2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/app.mjs", "/app.mjs must be in the hint")
# Must NOT emit rel=preload; as=script for a module script
tr_a24_2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "as=script",
    "module script must NOT emit as=script -- wrong hint type")
tr_a24_2.StillRunningAfter = ms
