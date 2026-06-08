'''
Test 103 Early Hints plugin -- manual --link rel=stylesheet normalization
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
Test HTTP 103 Early Hints plugin --link pparam rel=stylesheet normalization.
An operator may specify @pparam=--link @pparam="</css/app.css>; rel=stylesheet" using
HTML <link> tag syntax. The plugin must convert rel=stylesheet -> rel=preload; as=style
before sending the 103 Early Hints response, since rel=stylesheet is not a valid hint type.

Flow:
  TR1 (H2): H2 request. Plugin sends 103 Early Hints from the configured --link.
            The 103 Link header must contain rel=preload; as=style (normalized from
            rel=stylesheet), not the raw rel=stylesheet from the pparam.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_manual_stylesheet"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html\r\n"
            "\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

# Configure manual mode with a stylesheet link (operator-authored rel=stylesheet).
# Plugin must normalize it to rel=preload; as=style before sending 103.
ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</css/app.css>;rel=stylesheet'
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
# TR1: H2 request -- 103 must contain rel=preload; as=style (not rel=stylesheet)
# ----
tr1 = Test.AddTestRun("H2: manual rel=stylesheet pparam normalized to rel=preload in 103")
tr1.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
# Plugin must send 103 Early Hints.
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Should receive 103 Early Hints from manual link")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive final 200 OK")
# The 103 must have rel=preload; as=style (normalized from rel=stylesheet).
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload", "rel=stylesheet pparam normalized to rel=preload in 103")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "as=style", "as=style attribute present in 103 Link header")
# rel=stylesheet must NOT appear (it was normalized away).
tr1.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "rel=stylesheet", "rel=stylesheet must not appear in 103 (browsers reject it as a hint)")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: sent", "Plugin sent 103 successfully")
tr1.StillRunningAfter = microserver
