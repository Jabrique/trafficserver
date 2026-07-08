'''
Test 103 Early Hints plugin  -- navigate-only mode (GAP-2 closure).

Validates the is_navigate_request() logic end-to-end:
- navigate_only enabled (default):
    Sec-Fetch-Mode: navigate  → 103 sent
    Sec-Fetch-Mode: cors      → 103 skipped (status: skipped-non-nav)
    No Sec-Fetch-Mode header  → 103 sent (conservative allow for older browsers)
- navigate_only disabled (--no-navigate-only):
    Sec-Fetch-Mode: cors      → 103 sent (bypass active)

All test runs use H2, manual mode (predictable links), --skip-bots disabled,
and --debug-header to observe plugin decisions without curl 103 parsing.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may not
#  use this file except in compliance with the License.  You may
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
Test HTTP 103 Early Hints plugin navigate-only mode.
Verifies:
- Sec-Fetch-Mode: navigate  → 103 sent      (navigate_only enabled)
- Sec-Fetch-Mode: cors      → 103 skipped   (navigate_only enabled)
- No Sec-Fetch-Mode header  → 103 sent      (conservative allow)
- Sec-Fetch-Mode: cors      → 103 sent      (navigate_only disabled)
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_navigate_only"
Test.ContinueOnFail = True

# ----
# Setup: single microserver, two ATS instances
# ----
microserver = Test.MakeOriginServer("microserver")

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
    })

# ----
# ATS instance A: navigate_only ENABLED (default when --skip-bots is set without --no-navigate-only)
# ----
ts_nav = Test.MakeATSProcess("ts_nav", select_ports=True, enable_tls=True, enable_cache=False)
ts_nav.addDefaultSSLFiles()
ts_nav.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts_nav.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</style.css>;rel=preload;as=style'
    ' @pparam=--no-skip-bots'
    # navigate_only is TRUE by default  -- do NOT pass --no-navigate-only
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts_nav.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts_nav.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts_nav.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 5,
})

# ----
# ATS instance B: navigate_only DISABLED (--no-navigate-only)
# ----
ts_no_nav = Test.MakeATSProcess("ts_no_nav", select_ports=True, enable_tls=True, enable_cache=False)
ts_no_nav.addDefaultSSLFiles()
ts_no_nav.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts_no_nav.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</style.css>;rel=preload;as=style'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts_no_nav.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts_no_nav.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts_no_nav.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 5,
})

# -------------------------------------------------------------------------------
# TC1: navigate_only=ON + Sec-Fetch-Mode: navigate → 103 SENT
# -------------------------------------------------------------------------------
tr1 = Test.AddTestRun("TC1: navigate request → 103 sent (navigate_only on)")
tr1.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " -H 'Sec-Fetch-Mode: navigate'"
    " 'https://127.0.0.1:{0}/page.html'".format(ts_nav.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(ts_nav)
# Plugin must send 103 for navigate requests.
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "navigate mode: Sec-Fetch-Mode=navigate must trigger 103")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Final response must be 200 OK")
tr1.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# TC2: navigate_only=ON + Sec-Fetch-Mode: cors → 103 SKIPPED (skipped-non-nav)
# -------------------------------------------------------------------------------
tr2 = Test.AddTestRun("TC2: cors request → 103 skipped (navigate_only on)")
tr2.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " -H 'Sec-Fetch-Mode: cors'"
    " 'https://127.0.0.1:{0}/page.html'".format(ts_nav.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# Plugin must skip 103 for non-navigate fetch modes.
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: skipped-non-nav", "cors mode must be skipped with skipped-non-nav status")
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "x-early-hints-status: sent", "103 must NOT be sent for cors mode")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Final 200 must still be returned")
tr2.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# TC3: navigate_only=ON + No Sec-Fetch-Mode header → 103 SENT (conservative allow)
# -------------------------------------------------------------------------------
tr3 = Test.AddTestRun("TC3: no Sec-Fetch-Mode → 103 sent (conservative allow)")
tr3.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    # No -H 'Sec-Fetch-Mode'  -- curl does not send this header by default
    " 'https://127.0.0.1:{0}/page.html'".format(ts_nav.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# Absent header: is_navigate_request() returns true → plugin proceeds with 103.
# Older browsers and curl don't send Sec-Fetch-Mode; must not be blocked.
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "absent Sec-Fetch-Mode must conservatively allow 103")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Final 200 must still be returned")
tr3.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# TC4: navigate_only=OFF + Sec-Fetch-Mode: cors → 103 SENT (bypass active)
# -------------------------------------------------------------------------------
tr4 = Test.AddTestRun("TC4: cors request with --no-navigate-only → 103 sent (bypass)")
tr4.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " -H 'Sec-Fetch-Mode: cors'"
    " 'https://127.0.0.1:{0}/page.html'".format(ts_no_nav.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.StartBefore(ts_no_nav)
# --no-navigate-only: Sec-Fetch-Mode is ignored, 103 must be sent for all modes.
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "--no-navigate-only must bypass Sec-Fetch-Mode check")
tr4.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "x-early-hints-status: skipped-non-nav", "non-nav skip must not fire when navigate_only is off")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Final 200 must still be returned")
tr4.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# TC5: navigate_only=ON + Sec-Fetch-Mode: same-origin → 103 SKIPPED
# -------------------------------------------------------------------------------
tr5 = Test.AddTestRun("TC5: same-origin mode → 103 skipped (navigate_only on)")
tr5.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " -H 'Sec-Fetch-Mode: same-origin'"
    " 'https://127.0.0.1:{0}/page.html'".format(ts_nav.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: skipped-non-nav", "same-origin mode must be skipped")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Final 200 must still be returned")
tr5.StillRunningAfter = microserver
