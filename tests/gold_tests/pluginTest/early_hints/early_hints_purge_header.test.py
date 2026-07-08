'''
Test 103 Early Hints plugin  -- purge header invalidation
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
Test HTTP 103 Early Hints plugin purge-header invalidation.
Verifies:
- Correct token in purge header removes hints entry (no 103 on that request)
- Scanner re-runs on the purging request response to re-learn hints
- Wrong/missing token leaves hints intact (103 still served on next request)
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_purge_header"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /purge.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/style.css" as="style">'
            '</head><body>Purge test</body></html>\r\n'
    })

# ----
# Setup ATS (cache disabled  -- every request hits origin so scanner always runs)
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # min-hit-count=1: 103 sent after first learn.
    # purge-header=X-Purge-Token, purge-secret=s3cr3t:
    #   request with correct token → remove() entry → no 103, scanner re-learns
    #   request with wrong token → entry untouched → 103 still served
    'map /purge.html http://127.0.0.1:{0}/purge.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--purge-header @pparam=X-Purge-Token'
    ' @pparam=--purge-secret @pparam=s3cr3t'
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

# ----
# TR1: H1 request  -- scanner learns /style.css (first learn, request_count = 0→1)
# ----
tr1 = Test.AddTestRun("Purge: H1 request 1  -- scanner learns /style.css")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/purge.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 request: skipped-h1")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 request  -- no purge header → entry intact → 103 sent (rc=1 >= 1)
# ----
tr2 = Test.AddTestRun("Purge: H2 request without purge header  -- 103 sent (intact)")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/purge.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "No purge token: 103 should be sent")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should be present")
tr2.StillRunningAfter = microserver

# ----
# TR3: H2 request with WRONG token  -- entry intact → 103 still sent
# ----
tr3 = Test.AddTestRun("Purge: H2 request with wrong token  -- hints intact → 103 still sent")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'X-Purge-Token: wrongtoken'"
    " 'https://127.0.0.1:{0}/purge.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# Wrong token: cache entry NOT removed → get() still returns links → 103 sent
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Wrong token: entry intact → 103 still sent")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should be present with wrong token")
tr3.StillRunningAfter = microserver

# ----
# TR4: H2 request with CORRECT token  -- entry removed → no 103, scanner re-learns
# ----
tr4 = Test.AddTestRun("Purge: H2 request with correct token  -- entry removed → no 103 this request")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'X-Purge-Token: s3cr3t'"
    " 'https://127.0.0.1:{0}/purge.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# Correct token: cache entry removed → get() returns null → no 103
# (request_count resets to 0 on re-learn; below min_hit_count on this same request)
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "Correct token: entry removed → no 103 this request")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should still receive 200 OK")
tr4.StillRunningAfter = microserver

# ----
# TR5: H2 request after purge  -- scanner re-learned on TR4 → 103 served again
# ----
tr5 = Test.AddTestRun("Purge: H2 request after re-learn  -- 103 served again")
tr5.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/purge.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
# After TR4 re-learned (rc=0→1 >= 1), TR5 sees rc=1→2 >= 1 → 103 sent again
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "After re-learn: 103 served again")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should be present after re-learn")
tr5.StillRunningAfter = microserver
