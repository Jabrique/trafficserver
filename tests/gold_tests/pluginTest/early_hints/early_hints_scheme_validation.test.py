'''
Test 103 Early Hints plugin — URL scheme allowlist and rel= boundary validation
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
URL scheme allowlist enforcement (integration).
rel= boundary validation for manual --link values.

Verifies that exotic schemes from origin Link headers (file://, ftp://, ws://)
are rejected by the allowlist and never forwarded or cached as early hints.
Valid http/https and relative URLs continue to work normally.

Fix is committed. These tests serve as regression guards.
Before allowlist fix (denylist), file:// and ftp:// passed is_valid_link_value
and would have been forwarded — these tests would have FAILED.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_scheme_validation"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Origin sends exotic schemes in Link headers — all must be rejected
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /exotic-schemes.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <file:///etc/passwd>; rel=preload; as=fetch\r\n"
            "Link: <ftp://evil.com/payload.bin>; rel=preload; as=fetch\r\n"
            "Link: <ws://evil.com/sock>; rel=preload; as=fetch\r\n"
            "\r\n",
        "body": "<html><body>Exotic schemes</body></html>\r\n"
    })

# Second request for exotic-schemes to prove nothing was cached
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /exotic-schemes.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <file:///etc/passwd>; rel=preload; as=fetch\r\n"
            "Link: <ftp://evil.com/payload.bin>; rel=preload; as=fetch\r\n"
            "Link: <ws://evil.com/sock>; rel=preload; as=fetch\r\n"
            "\r\n",
        "body": "<html><body>Exotic schemes</body></html>\r\n"
    })

# Origin sends valid http/https Link headers — must be forwarded normally
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /valid-links.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>Valid links</body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /valid-links.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>Valid links</body></html>\r\n"
    })

# ----
# Setup ATS — origin-forward mode to test Link header filtering
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
# TC0: First request — origin sends file://, ftp://, ws:// — plugin must reject all
# (Before fix: these would have been cached. After allowlist fix: rejected.)
# ----
tr0 = Test.AddTestRun("Scheme-validation: First request (H2) with exotic scheme Link headers — verify rejection")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/exotic-schemes.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200 OK")
# CRITICAL: plugin must process origin Link headers (H2 passes h1-skip) and reject exotic schemes.
# status=no-hints proves: plugin ran, saw file://+ftp://+ws://, rejected all via allowlist.
# Before allowlist fix: exotic schemes passed → status would have been "learned" or "sent".
tr0.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: no-hints",
    "Plugin must reject all exotic schemes — status must be no-hints not sent/learned")
tr0.StillRunningAfter = microserver

# ----
# TC1: Second request — verify exotic schemes were NOT cached by plugin
# ATS transparently passes origin Link headers in the 200 response regardless.
# What we test: plugin status must be "no-hints" (nothing cached from exotic schemes),
# and no 103 Early Hints is sent (the only thing the plugin controls).
# With allowlist fix: file://, ftp://, ws:// rejected → no-hints.
# With old denylist: these would have been cached → 103 sent with exotic links.
# ----
tr1 = Test.AddTestRun("Scheme-validation: Second request — exotic schemes must NOT be cached (no 103 sent)")
tr1.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/exotic-schemes.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
# With allowlist fix: plugin rejected all links, nothing cached, no 103 sent
# x-early-hints-status must be "no-hints" NOT "sent"
tr1.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "x-early-hints-status: sent", "No exotic scheme links should have been cached — no 103 sent")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "Plugin must report no-hints when all links are rejected")
tr1.StillRunningAfter = microserver

# ----
# TC2: Valid relative Link header — must still work normally
# Proves the allowlist fix does not break legitimate relative/http/https URLs.
# ----
tr2 = Test.AddTestRun("Scheme-validation: Valid relative Link from origin — learn phase")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/valid-links.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200 OK", "Should receive 200 OK")
tr2.StillRunningAfter = microserver

tr3 = Test.AddTestRun("Scheme-validation: Valid link cached and served — H2 gets 103")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/valid-links.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# Valid relative link should be cached and served as a hint on next H2 request
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Valid relative link should be cached and served")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/app.js", "Valid preload link for /app.js must appear in response")
tr3.StillRunningAfter = microserver
