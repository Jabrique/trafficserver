'''
Test 103 Early Hints plugin  -- cache behavior and min-hit-count threshold
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
- min-hit-count threshold: cache.get() returns null until request_count >= min_hits
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

# min-hit-count=3: need 4 origin responses (TR1 H1-learn, TR2 H2-count1, TR3 H2-count2, TR4 H2-serve).
# H1 clients do NOT increment request_count (design: H1 traffic must not inflate counter for 103).
# Only H2 requests call cache.get() at remap time and increment request_count.
counted_response = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
    "body": (
        '<html><head>'
        '<link rel="preload" href="/counted.css" as="style">'
        '</head><body>Hit count test</body></html>\r\n'
    )
}
# 4 responses: TR1 (H1 learn), TR2 (H2 count=1), TR3 (H2 count=2), TR4 (H2 count=3 serve)
for _ in range(4):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /counted.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, counted_response)


# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # min-hit-count=3: cache.get() returns null until request_count >= 3
    # Each request triggers scanner → cache.put(); request_count incremented by get()
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
# TR1: First H1 request  -- learns hints (request_count stays 0 since H1 skips get())
# ----
tr1 = Test.AddTestRun("min-hit-count: H1 request 1  -- learn, count=0")
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
# TR2: H2 request  -- cache.get() increments request_count to 1 < 3 → no-hints
# ----
tr2 = Test.AddTestRun("min-hit-count: H2 request  -- request_count=1 < 3 → no-hints")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/counted.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
# cache.get() returns null (count=1 < min_hits=3) → no-hints
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "Below min-hit-count threshold  -- no 103 sent")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should still receive 200 OK")
tr2.StillRunningAfter = microserver

# ----
# TR3: H2 request  -- cache.get() increments request_count to 2 < 3 → still no-hints
# (H1 clients deliberately skip get(); only H2 increments request_count)
# ----
tr3 = Test.AddTestRun("min-hit-count: H2 request 3  -- request_count=2 < 3 → no-hints")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/counted.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# cache.get() returns null (count=2 < min_hits=3) → no-hints
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "Still below threshold  -- no 103 sent")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr3.StillRunningAfter = microserver

# ----
# TR4: H2 request  -- cache.get() increments request_count to 3 >= 3 → 103 sent!
# ----
tr4 = Test.AddTestRun("min-hit-count: H2 request  -- request_count=3 >= 3 → sent!")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/counted.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# cache.get() returns links (count=3 >= min_hits=3) → 103 sent
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Threshold met  -- 103 should be sent")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Should also receive 200 OK")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:", "Link header should be present in response")
tr4.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# Cache intercept (READ_CACHE_HDR_HOOK re-learning)
# Verify that the plugin intercepts READ_CACHE_HDR_HOOK and re-learns hints
# from the ATS cache if they were evicted from the plugin's memory.
# -------------------------------------------------------------------------------

server_intercept = Test.MakeOriginServer("server_intercept")

req_intercept_a = {"headers": "GET /pageA.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
res_intercept_a = {
    "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nCache-Control: max-age=3600\r\nContent-Type: text/html\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": '<html><head><link rel="preload" href="/appA.js" as="script"></head><body>A</body></html>'
}
req_intercept_b = {"headers": "GET /pageB.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
res_intercept_b = {
    "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nCache-Control: max-age=3600\r\nContent-Type: text/html\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": '<html><head><link rel="preload" href="/appB.js" as="script"></head><body>B</body></html>'
}

for _ in range(3):
    server_intercept.addResponse("sessionlog.json", req_intercept_a, res_intercept_a)
server_intercept.addResponse("sessionlog.json", req_intercept_b, res_intercept_b)

ts_intercept = Test.MakeATSProcess("ts_intercept", select_ports=True, enable_tls=True)
ts_intercept.addDefaultSSLFiles()
ts_intercept.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints.*',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts_intercept.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts_intercept.Variables.SSLDir),
    'proxy.config.http.cache.http': 1,
    'proxy.config.http.insert_request_via_str': 1,
    'proxy.config.http.insert_response_via_str': 2,
    'proxy.config.http.server_ports': '{0} {1}:ssl'.format(ts_intercept.Variables.port, ts_intercept.Variables.ssl_port)
})
ts_intercept.Disk.ssl_multicert_config.AddLine(
    'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts_intercept.Disk.remap_config.AddLine(
    'map https://www.example.com http://127.0.0.1:{0}'
    ' @plugin=early_hints.so @pparam=--mode=auto-learn'
    ' @pparam=--max-cache-entries=1 @pparam=--min-hit-count=1'
    ' @pparam=--no-persist'.format(server_intercept.Variables.Port))

tr_intercept_1 = Test.AddTestRun("Cache intercept: request A  -- origin hit, learn A")
tr_intercept_1.Processes.Default.StartBefore(server_intercept)
tr_intercept_1.Processes.Default.StartBefore(ts_intercept)
tr_intercept_1.Processes.Default.Command = (
    'curl -s -v -k --http2 https://127.0.0.1:{0}/pageA.html -H "Host: www.example.com"'
    .format(ts_intercept.Variables.ssl_port))
tr_intercept_1.Processes.Default.ReturnCode = 0
tr_intercept_1.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 200", "Should get 200 OK")

tr_intercept_2 = Test.AddTestRun("Cache intercept: request B  -- origin hit, learn B, evict A")
tr_intercept_2.Processes.Default.Command = (
    'curl -s -v -k --http2 https://127.0.0.1:{0}/pageB.html -H "Host: www.example.com"'
    .format(ts_intercept.Variables.ssl_port))
tr_intercept_2.Processes.Default.ReturnCode = 0
tr_intercept_2.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 200", "Should get 200 OK")

tr_intercept_3 = Test.AddTestRun("Cache intercept: request A again  -- cache hit, memory evicted, re-learn from cache")
tr_intercept_3.Processes.Default.Command = (
    'sleep 1 && curl -s -v -k --http2 https://127.0.0.1:{0}/pageA.html -H "Host: www.example.com"'
    .format(ts_intercept.Variables.ssl_port))
tr_intercept_3.Processes.Default.ReturnCode = 0
tr_intercept_3.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 200", "Should get 200 OK")

tr_intercept_4 = Test.AddTestRun("Cache intercept: request A third time  -- plugin serves 103 hint")
tr_intercept_4.Processes.Default.Command = (
    'sleep 1 && curl -s -v -k --http2 https://127.0.0.1:{0}/pageA.html -H "Host: www.example.com"'
    .format(ts_intercept.Variables.ssl_port))
tr_intercept_4.Processes.Default.ReturnCode = 0
tr_intercept_4.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 200", "Should get 200 OK")
tr_intercept_4.Processes.Default.Streams.stderr += Testers.ContainsExpression(
    "link: </appA.js>; rel=preload; as=script",
    "Should contain the hint in 103 or Link header")
