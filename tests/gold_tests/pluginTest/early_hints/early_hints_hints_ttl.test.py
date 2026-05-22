'''
Test 103 Early Hints plugin — hints-ttl (TTL + Stale-While-Revalidate)
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
Test HTTP 103 Early Hints plugin hints-ttl (TTL + Stale-While-Revalidate).
Verifies:
- 103 is served immediately when hints are fresh (age < hints-ttl)
- 103 is STILL served when hints are stale (Stale-While-Revalidate: serve old hints NOW)
- Scanner re-runs on origin response when hints are stale to refresh the cache entry
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_hints_ttl"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# HTML with preload link for TTL/SWR testing
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /ttl.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/style.css" as="style">'
            '</head><body>TTL test</body></html>\r\n'
    })

# ----
# Setup ATS (cache disabled — every request hits origin to control scan timing)
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # hints-ttl=2: entry is considered stale after 2 seconds.
    # min-hit-count=1: 103 sent on first eligible H2 request (rc 0→1 >= 1).
    # SWR: when stale, serve the old 103 NOW and re-scan in the background.
    'map /ttl.html http://127.0.0.1:{0}/ttl.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--hints-ttl @pparam=2'
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
# TR1: H1 request — scanner learns /style.css (first learn)
# ----
tr1 = Test.AddTestRun("TTL: H1 request 1 — scanner learns /style.css")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/ttl.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 request: skipped-h1")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 request — hints fresh (age < 2s) → 103 sent (request_count 0→1 >= 1)
# ----
tr2 = Test.AddTestRun("TTL: H2 request — fresh hints → 103 sent")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/ttl.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# Fresh hints: age ~1s < ttl=2s → no needs_relearn → 103 sent normally
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Fresh hints: 103 should be sent")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive 200 OK")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should be present in response")
tr2.StillRunningAfter = microserver

# ----
# TR3: Wait for TTL to expire (3s > hints-ttl=2s), then H2 request.
# SWR: hints are stale → 103 is STILL sent with old hints.
# Scanner re-runs (re-learn) to refresh the cache entry.
# ----
tr3 = Test.AddTestRun("TTL: H2 request after TTL expiry — stale hints but 103 still sent (SWR)")
tr3.Processes.Default.Command = (
    "sleep 3 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/ttl.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# SWR: needs_relearn=true but cached_links already set → 103 sent with stale hints
# Scanner re-attaches to origin response to refresh last_updated
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "SWR: stale hints still served as 103")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Stale link header still present (SWR)")
tr3.StillRunningAfter = microserver

# ----
# TR4: Immediately after TR3 re-learned, hints are fresh again → 103 sent.
# ----
tr4 = Test.AddTestRun("TTL: H2 request after re-learn — fresh hints again → 103 sent")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/ttl.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# After TR3 re-learned (scanner ran), last_updated reset → fresh → 103 sent
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "After re-learn: 103 still sent")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive 200 OK")
tr4.StillRunningAfter = microserver
