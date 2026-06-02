'''
Test 103 Early Hints plugin — HTML scanner boundary correctness.

Covers:
  - An href of exactly "//" (degenerate protocol-relative URL, no host)
    must NOT be emitted as a preload hint. With the off-by-one bug
    (href.size() > 2), size==2 falls through as same-origin and a broken
    hint is emitted. After fix (>= 2), it is detected as cross-origin
    and dropped because no CDN whitelist is configured.
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
Test HTML scanner boundary: "//" href must not produce a preload hint.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_scanner_boundary"
Test.ContinueOnFail = True

# ─── Origin server ────────────────────────────────────────────────────────────

ms = Test.MakeOriginServer("ms")

# Page with href="//" — a degenerate protocol-relative URL with no host.
# The scanner must detect this as cross-origin (size >= 2 fix) and
# not emit a preload hint since no CDN whitelist is configured.
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /page-slash-slash.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": '<html><head><link rel="preload" href="//" as="script"></head></html>\r\n'
    })

# ─── ATS setup ────────────────────────────────────────────────────────────────

ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

# auto-learn mode, no crossorigin whitelist — "//" should produce no hint
ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(ms.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=x-early-hints-status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ─── TC-1: First request — learn page (scanner runs) ─────────────────────────

tr1 = Test.AddTestRun("Slash-slash href: first request — scanner runs, learns page")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1 --insecure"
    " 'https://127.0.0.1:{0}/page-slash-slash.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(ms, ready=When.PortOpen(ms.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr1.StillRunningAfter = ms

# ─── TC-2: Second H2 request — must NOT emit broken <//>  preload hint ────────

tr2 = Test.AddTestRun('Slash-slash href: second H2 request — no broken <//>  hint emitted')
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/page-slash-slash.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# Before fix: scanner emits <//>; rel=preload; as=script (broken, // treated as same-origin)
# After fix:  // is cross-origin, no CDN whitelist, no hint emitted → status skipped-threshold
#             or no 103 at all.
tr2.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "<//>;",
    'Slash-slash href: broken <//>  hint must NOT appear in any response header')
tr2.StillRunningAfter = ms
