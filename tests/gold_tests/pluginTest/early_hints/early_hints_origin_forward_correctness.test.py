'''
Test 103 Early Hints plugin — origin-forward correctness.

Covers:
  - rel=stylesheet with crossorigin= converted to rel=preload; as=style
    and the crossorigin attribute must be preserved in the converted hint.
  - Origin sends Link with quoted as= (as="script") — must be forwarded,
    not dropped by has_valid_as_for_preload().
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
Test HTTP 103 Early Hints plugin origin-forward correctness.
Stylesheet crossorigin preserved as preload crossorigin.
Quoted as="script" forwarded (not dropped).
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_origin_forward_correctness"
Test.ContinueOnFail = True

# ─── Origin server ────────────────────────────────────────────────────────────

ms = Test.MakeOriginServer("ms")

# Stylesheet with crossorigin=anonymous.
# Plugin converts rel=stylesheet → rel=preload; as=style.
# The crossorigin attribute must carry over — without it the browser
# double-fetches the stylesheet because preload and actual fetch use
# different CORS modes.
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /page-stylesheet-cors.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </style-cors.css>; rel=stylesheet; crossorigin=anonymous\r\n"
            "\r\n",
        "body": "<html><body>stylesheet-cors</body></html>\r\n"
    })

# Preload with quoted as= attribute (as="script").
# RFC 8288 allows quoted parameter values. has_valid_as_for_preload() must
# recognise as="script" and not drop the link.
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /page-quoted-as.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            'Link: </app-quoted-as.js>; rel=preload; as="script"\r\n'
            "\r\n",
        "body": "<html><body>quoted-as</body></html>\r\n"
    })

# ─── ATS setup ────────────────────────────────────────────────────────────────

ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(ms.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
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

# ─── Stylesheet crossorigin — learn ───────────────────────────────────────────

tr_cors_1 = Test.AddTestRun(
    "Stylesheet crossorigin: first request — learn origin Link header")
tr_cors_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1 --insecure"
    " 'https://127.0.0.1:{0}/page-stylesheet-cors.html'".format(ts.Variables.ssl_port))
tr_cors_1.Processes.Default.ReturnCode = 0
tr_cors_1.Processes.Default.StartBefore(ms, ready=When.PortOpen(ms.Variables.Port))
tr_cors_1.Processes.Default.StartBefore(Test.Processes.ts)
tr_cors_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_cors_1.StillRunningAfter = ms

# ─── Stylesheet crossorigin — verify 103 preserves crossorigin ────────────────
#
# The assertion checks for the combined string "rel=preload; as=style; crossorigin".
# This pattern can only appear in the converted preload hint — the origin sends
# "rel=stylesheet; crossorigin" (different rel value) so the check is specific.

tr_cors_2 = Test.AddTestRun(
    "Stylesheet crossorigin: 103 preload hint must carry crossorigin=anonymous")
tr_cors_2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/page-stylesheet-cors.html'".format(ts.Variables.ssl_port))
tr_cors_2.Processes.Default.ReturnCode = 0
tr_cors_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "Stylesheet crossorigin: 103 must be sent for cached stylesheet hint")
# This combined pattern can ONLY appear if crossorigin was carried into the
# converted preload hint — it cannot come from the origin's rel=stylesheet header.
tr_cors_2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload; as=style; crossorigin",
    "Stylesheet crossorigin: crossorigin must be present in the converted rel=preload hint")
tr_cors_2.StillRunningAfter = ms

# ─── Quoted as= — learn ───────────────────────────────────────────────────────

tr_quoted_1 = Test.AddTestRun(
    'Quoted as=: first request — learn origin Link with as="script"')
tr_quoted_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1 --insecure"
    " 'https://127.0.0.1:{0}/page-quoted-as.html'".format(ts.Variables.ssl_port))
tr_quoted_1.Processes.Default.ReturnCode = 0
tr_quoted_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_quoted_1.StillRunningAfter = ms

# ─── Quoted as= — verify 103 forwards the link ────────────────────────────────

tr_quoted_2 = Test.AddTestRun(
    'Quoted as=: 103 must forward link with quoted as="script"')
tr_quoted_2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/page-quoted-as.html'".format(ts.Variables.ssl_port))
tr_quoted_2.Processes.Default.ReturnCode = 0
# Quoted as="script" must pass validation and cause 103 to be sent.
# If the link is dropped (validation rejects quoted as=), no 103 → assertion fails.
tr_quoted_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    'Quoted as=: 103 must be sent — quoted as= link must not be dropped by validation')
tr_quoted_2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "app-quoted-as",
    'Quoted as=: 103 Link header must contain app-quoted-as.js')
tr_quoted_2.StillRunningAfter = ms
