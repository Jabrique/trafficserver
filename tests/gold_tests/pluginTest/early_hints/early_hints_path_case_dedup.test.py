'''
Test 103 Early Hints plugin -- path case sensitivity in URL deduplication
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
Test HTTP 103 Early Hints plugin URL dedup path case sensitivity.
Verifies that two Link headers with the same host but different path casing
are treated as different resources and both forwarded (not deduplicated).
This matches RFC 3986 section 6.2.2.1: host is case-insensitive, path is not.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_path_case_dedup"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Origin sends two Link headers with same host but different path casing.
# Both are distinct resources per RFC 3986 and must both appear in the response.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html\r\n"
            "Link: </CSS/App.js>; rel=preload; as=script\r\n"
            "Link: </css/app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><head><title>Test</title></head><body>Hello</body></html>\r\n"
    })

# Second request for H1 check
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html\r\n"
            "Link: </CSS/App.js>; rel=preload; as=script\r\n"
            "Link: </css/app.js>; rel=preload; as=script\r\n"
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
# TR1: H1 request -- verify both path-cased links appear in 200 response, not deduped
# ----
tr1 = Test.AddTestRun("Path case dedup: both links forwarded to 200 response")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/index.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
# ATS combines multiple Link values into a single comma-separated Link header.
# Both path-cased URLs must appear: dedup must NOT collapse them into one.
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    r"</CSS/App.js>", "Uppercase path URL present in Link header")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    r"</css/app.js>", "Lowercase path URL present in Link header")
tr1.StillRunningAfter = microserver
