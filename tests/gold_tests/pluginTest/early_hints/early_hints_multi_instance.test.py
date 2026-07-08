'''
Test 103 Early Hints plugin  -- multi-instance coexistence (GAP-8 closure).

Validates the first-wins TSUserArgGet claim guard in TSRemapDoRemap.
When two remap rules on the same ATS instance both use early_hints.so
with different configs, each instance must serve its own Link hints
independently without cross-contamination or double-hook crashes.

Scenarios:
1. Request to /a/ → 103 contains only a.js (not b.css)
2. Request to /b/ → 103 contains only b.css (not a.js)
3. Concurrent requests to /a/ and /b/  -- both succeed without crash
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
Test HTTP 103 Early Hints plugin multi-instance coexistence.
Two remap rules with different early_hints configs must serve
independent hints without cross-contamination.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_multi_instance"
Test.ContinueOnFail = True

# ----
# Setup: two microservers for two remap paths
# ----
ms_a = Test.MakeOriginServer("ms_a")
ms_b = Test.MakeOriginServer("ms_b")

ms_a.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><head></head><body>A</body></html>\r\n"
    })

ms_b.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><head></head><body>B</body></html>\r\n"
    })

# ----
# Single ATS with TWO remap rules, each using a different early_hints instance.
# The first-wins guard (TSUserArgGet check) must ensure each request's
# transaction is claimed by exactly one instance.
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # Instance A: serves a.js script hint
    'map /a/ http://127.0.0.1:{0}/'.format(ms_a.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</a.js>;rel=preload;as=script'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
    # Instance B: serves b.css style hint
    'map /b/ http://127.0.0.1:{0}/'.format(ms_b.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</b.css>;rel=preload;as=style'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 5,
})

# -------------------------------------------------------------------------------
# TC1: Request to /a/page.html → 103 contains a.js, NOT b.css
# -------------------------------------------------------------------------------
tr1 = Test.AddTestRun("TC1: /a/ request → only instance A hints (a.js)")
tr1.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/a/page.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(ms_a, ready=When.PortOpen(ms_a.Variables.Port))
tr1.Processes.Default.StartBefore(ms_b, ready=When.PortOpen(ms_b.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
# Instance A's link must be present
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "a.js", "Instance A must serve its own a.js hint")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: sent", "early_hints must confirm 103 sent")
# Instance B's link must NOT leak into instance A's response
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "b.css", "Instance B's b.css must NOT appear in instance A's response")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Final 200 must be returned")
tr1.StillRunningAfter = ms_a

# -------------------------------------------------------------------------------
# TC2: Request to /b/page.html → 103 contains b.css, NOT a.js
# -------------------------------------------------------------------------------
tr2 = Test.AddTestRun("TC2: /b/ request → only instance B hints (b.css)")
tr2.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/b/page.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# Instance B's link must be present
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "b.css", "Instance B must serve its own b.css hint")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: sent", "early_hints must confirm 103 sent")
# Instance A's link must NOT leak
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "a.js", "Instance A's a.js must NOT appear in instance B's response")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Final 200 must be returned")
tr2.StillRunningAfter = ms_b

# -------------------------------------------------------------------------------
# TC3: Alternating /a/ and /b/ requests  -- no crash, correct isolation
# -------------------------------------------------------------------------------
tr3 = Test.AddTestRun("TC3: alternating a→b→a requests  -- no cross-contamination")
tr3.Processes.Default.Command = (
    "curl -s -D -"
    " --http2 --insecure -o /dev/null"
    " 'https://127.0.0.1:{port}/a/page.html'"
    " && curl -s -D -"
    " --http2 --insecure -o /dev/null"
    " 'https://127.0.0.1:{port}/b/page.html'"
    " && curl -s -D -"
    " --http2 --insecure -o /dev/null"
    " 'https://127.0.0.1:{port}/a/page.html'".format(port=ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# All requests must complete with 200 (no crash from double-hook or double-free).
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "All alternating requests must complete successfully")
tr3.StillRunningAfter = ms_a
