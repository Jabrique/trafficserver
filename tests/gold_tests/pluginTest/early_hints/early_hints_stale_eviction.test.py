'''
Test 103 Early Hints plugin -- stale-evict-after option
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
Test HTTP 103 Early Hints plugin --stale-evict-after option.
Verifies that once a cache entry exceeds the stale-evict-after threshold,
get() serves the entry one final time and then removes it.

Flow:
  TR1 (H1): First request. Plugin scans body and learns hints.
            --min-hit-count 1 so hints are served starting from the first get().
  TR2 (H2): Second request. Plugin serves 103 Early Hints from the learned entry.
            --stale-evict-after 2 is set; entry age is still < 2s so NOT evicted.
  sleep 3s: Entry age grows past the 2-second eviction threshold.
  TR3 (H2): Third request. Entry is stale (age > 2s). Plugin serves 103 Early Hints
            from the stale entry one final time, then evicts it from the cache.
  TR4 (H2): Fourth request immediately after TR3. Entry has been evicted.
            Plugin must NOT send 103 Early Hints (no entry in cache).
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_stale_eviction"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

HTML_BODY = (
    "<html><head>"
    "<link rel=\"preload\" href=\"/assets/stale.css\" as=\"style\">"
    "</head><body><p>Stale eviction test</p></body></html>\r\n"
)

# TR1: H1 learning request
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /stale.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": HTML_BODY
    })

# TR2: second H2 request -- origin contacted again (cache disabled)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /stale.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": HTML_BODY
    })

# TR3: third H2 request after sleep (stale entry served + evicted)
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /stale.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": HTML_BODY
    })

# TR4: fourth H2 request immediately after eviction -- no 103 expected
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /stale.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": HTML_BODY
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

# auto-learn mode with stale-evict-after=2 and min-hit-count=1 so hints are
# served from the first request. stale-evict-after=2 means an entry older than
# 2 seconds is served once more then removed.
ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--stale-evict-after @pparam=2'
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
# TR1: H1 request -- learn hints (no 103 from H1)
# ----
tr1 = Test.AddTestRun("H1: first request -- plugin scans body and learns hints")
tr1.Processes.Default.Command = (
    "curl -s -D -"
    " --http1.1"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/stale.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
# H1 does not receive 103; the transform learns links after SEND_RESPONSE_HDR
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "H1 request gets 200 response")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 request -- entry fresh, 103 served, NOT evicted
# ----
tr2 = Test.AddTestRun("H2: second request -- 103 served, entry not yet stale")
tr2.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/stale.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Plugin sends 103 Early Hints (entry fresh, not yet stale)")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "stale.css", "103 contains the learned link")
tr2.StillRunningAfter = microserver

# ----
# Sleep 3s so entry age > stale-evict-after (2s)
# ----
tr_sleep = Test.AddTestRun("Sleep 3s to make entry older than stale-evict-after=2s")
tr_sleep.Processes.Default.Command = "sleep 3"
tr_sleep.Processes.Default.ReturnCode = 0

# ----
# TR3: H2 request -- entry stale, served once then evicted
# ----
tr3 = Test.AddTestRun("H2: third request -- stale entry served once then evicted")
tr3.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/stale.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# Stale entry is still served on this request before eviction
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Stale entry served one final time before eviction")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "stale.css", "103 contains the stale link")
tr3.StillRunningAfter = microserver

# ----
# TR4: H2 request immediately after eviction -- NO 103
# ----
tr4 = Test.AddTestRun("H2: fourth request -- entry evicted, no 103 sent")
tr4.Processes.Default.Command = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/stale.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
# Entry was evicted by TR3 -- no 103 on this request
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Request succeeds with 200 after eviction")
tr4.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "103", "No 103 Early Hints after cache entry was evicted by stale-evict-after")
tr4.StillRunningAfter = microserver
