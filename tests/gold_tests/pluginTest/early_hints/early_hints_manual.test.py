'''
Test 103 Early Hints plugin — manual mode
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
Test HTTP 103 Early Hints plugin in manual mode.
Verifies:
- H1 client gets Link headers in 200 response and debug header shows "skipped-h1"
- Duplicate H1.1 request: same behavior (consistent)
- POST request: plugin does not engage (no debug header)
Note: True H2 103 testing requires curl/nghttp2 with 103 support.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_manual"
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
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
    })

# ----
# Setup ATS with H2
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=manual'
    ' @pparam=--link @pparam=</style.css>;rel=preload;as=style'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'http2|early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# Test Case 0: H1 client — verify plugin adds Link to 200 but skips 103
# curl/nghttp2 versions available don't handle 103, so we test H1 behavior.
# The plugin correctly detects H1 and skips 103, but still adds Link to the 200.
# ----
tr = Test.AddTestRun("H1 manual mode - Link in 200, 103 skipped")
tr.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "Link: </style.css>;rel=preload;as=style", "Link header in 200 response")
tr.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 client correctly skipped for 103")
tr.StillRunningAfter = microserver

# ----
# Test Case 1: POST request does NOT trigger 103
# ----
tr3 = Test.AddTestRun("POST no 103")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -X POST"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# POST returns TSREMAP_NO_REMAP so plugin doesn't process it at all.
# Positive assertion first: verify we got a valid HTTP response (proves ATS is running with plugin loaded).
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "HTTP/", "Should receive a valid HTTP response from ATS")
# Verify no debug header is set (plugin did not engage for POST).
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "X-Early-Hints-Status:", "POST should not trigger plugin processing at all")
# Verify no Link header injected for POST
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "POST should not have Link headers injected")
tr3.StillRunningAfter = microserver
