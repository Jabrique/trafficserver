'''
Test 103 Early Hints plugin — cache behavior and min-hit-count threshold
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
Test HTTP 103 Early Hints plugin cache behavior.
Verifies:
- min-hit-count threshold: cache.get() returns null until learn_count >= min_hits
- 103 is only sent after sufficient learning rounds
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_cache_behavior"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# HTML with a resource for min-hit-count testing
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /counted.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/counted.css" as="style">'
            '</head><body>Hit count test</body></html>\r\n'
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # min-hit-count=3: cache.get() returns null until learn_count >= 3
    # Each request triggers scanner → cache.put() → learn_count++
    # After 3 learns, 103 is sent on H2 requests.
    'map /counted.html http://127.0.0.1:{0}/counted.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=3'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# TR1: First H1 request — learn_count becomes 1
# ----
tr1 = Test.AddTestRun("min-hit-count: H1 request 1 — learn_count=1")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/counted.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 request should show skipped-h1")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 request — learn_count=1 < 3 → "no-hints" (threshold not met)
# Scanner runs on response → learn_count becomes 2
# ----
tr2 = Test.AddTestRun("min-hit-count: H2 request — learn_count=1 < 3 → no-hints")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/counted.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# learn_count=1 < min_hits=3 → cache.get() returns null → "no-hints"
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "Below min-hit-count threshold — no 103 sent")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should still receive 200 OK")
tr2.StillRunningAfter = microserver

# ----
# TR3: H1 request 3 — learn_count becomes 3 (threshold reached)
# ----
tr3 = Test.AddTestRun("min-hit-count: H1 request 3 — learn_count=3")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/counted.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 request should show skipped-h1")
tr3.StillRunningAfter = microserver

# ----
# TR4: H2 request — learn_count=3 >= 3 → "sent" (threshold met!)
# ----
tr4 = Test.AddTestRun("min-hit-count: H2 request — learn_count=3 >= 3 → sent!")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/counted.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# learn_count=3 >= min_hits=3 → cache.get() returns links → 103 sent
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Threshold met — 103 should be sent")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive 200 OK")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should be present in response")
tr4.StillRunningAfter = microserver
