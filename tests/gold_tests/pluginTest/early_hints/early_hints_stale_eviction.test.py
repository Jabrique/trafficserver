'''
Test 103 Early Hints plugin -- stale-evict-after combined threshold semantics
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
Test HTTP 103 Early Hints plugin --stale-evict-after combined threshold semantics.

Configuration: --hints-ttl=1 --stale-evict-after=2 --min-hit-count=2
  eviction threshold = hints_ttl + stale_evict_after = 1 + 2 = 3s.

Flow:
  TR1 (H1): Learn (count=0).
  TR2 (H2): Warm-up (count=1 < 2, no 103).
  TR3 (H2): First serve (count=2 >= 2, age~0s << 3s). 103 sent.
  sleep 2s: Entry becomes stale (age=2 >= hints-ttl=1). age(2) < threshold(3).
  TR4 (H2): Stale entry served (count=3, age=2 < 3). 103 sent. NOT evicted.
            Stale-while-revalidate: scanner re-attaches, put() resets last_updated.
  TR5 (H2): Entry re-learned in TR4 (fresh again). 103 served (count=4). NOT evicted.
            Multi-serve confirmed: TWO 103 responses during the stale-grace window.
  sleep 4s: age from TR4 re-learn: now-T_relearn = 4s > threshold(3).
  TR6 (H2): age > threshold. 103 served one final time. Entry EVICTED.
            Scanner bypassed (has_learned=True, needs_relearn=False: entry gone).
  TR7 (H2): Cache miss after eviction. count=0 -> 1 < min-hit-count=2. No 103.
            Eviction confirmed.
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


def make_response():
    return ({
        "headers": "GET /stale.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": HTML_BODY
    })


for _ in range(7):
    microserver.addResponse("sessionfile.log", *make_response())

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

# hints-ttl=1, stale-evict-after=2 -> eviction threshold = 3s.
# min-hit-count=2: after re-learn (count=0), TR7 needs count>=2 -> no 103.
#
# Key timing:
#   T=0s    TR1 learns (last_updated=0)
#   T~0s    TR2/TR3 serve (age<1s < threshold=3)
#   sleep 2s -> age=2 (stale: age >= hints-ttl=1)
#   T=2s    TR4: stale, age=2 < 3 (not evicted). Scanner re-learns -> last_updated=T=2s
#   T~2s    TR5: fresh after re-learn (age~0), 103 served (count=4)
#   sleep 4s -> age from TR4 re-learn = 4s > threshold=3s
#   T=6s    TR6: age=4 > 3 -> EVICTED. Scanner bypassed (has_learned, entry gone).
#   T~6s    TR7: cache miss, count=0->1 < 2, no 103. Eviction confirmed.
ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=2'
    ' @pparam=--hints-ttl @pparam=1'
    ' @pparam=--stale-evict-after @pparam=2'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 10,
})


def h2_curl():
    return (
        "curl -s -D -"
        " --http2"
        " --insecure"
        " -o /dev/null"
        " 'https://127.0.0.1:{0}/stale.html'".format(ts.Variables.ssl_port))


def h1_curl():
    return (
        "curl -s -D -"
        " --http1.1"
        " --insecure"
        " -o /dev/null"
        " 'https://127.0.0.1:{0}/stale.html'".format(ts.Variables.ssl_port))


# ----
# TR1: H1 learn (count=0 after put())
# ----
tr1 = Test.AddTestRun("H1: TR1 -- learn hints (count=0 after put)")
tr1.Processes.Default.Command = h1_curl()
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "H1 gets 200 response")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 warm-up (count=1 < 2, no 103)
# ----
tr2 = Test.AddTestRun("H2: TR2 -- warm-up (count=1 < min-hit-count=2, no 103)")
tr2.Processes.Default.Command = h2_curl()
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Warm-up request gets 200")
tr2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "103", "No 103 during warm-up (count < min-hit-count)")
tr2.StillRunningAfter = microserver

# ----
# TR3: H2 first 103 (count=2 >= 2, age~0 < threshold=3)
# ----
tr3 = Test.AddTestRun("H2: TR3 -- first 103 (count=2, age fresh, not stale)")
tr3.Processes.Default.Command = h2_curl()
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "First 103 (count=2 >= 2, entry fresh)")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "stale.css", "103 contains learned link")
tr3.StillRunningAfter = microserver

# ----
# Sleep 2s: entry becomes stale (age=2 >= hints-ttl=1). age(2) < threshold(3).
# ----
tr_sleep1 = Test.AddTestRun("Sleep 2s: entry becomes stale (age=2 >= hints-ttl=1) but age < threshold=3")
tr_sleep1.Processes.Default.Command = "sleep 2"
tr_sleep1.Processes.Default.ReturnCode = 0

# ----
# TR4: H2 stale entry served (count=3, age=2 < 3: not evicted).
#       Stale-while-revalidate: scanner re-attaches, put() resets last_updated.
# ----
tr4 = Test.AddTestRun("H2: TR4 -- stale serve (age=2 < threshold=3, not evicted). Re-learn starts.")
tr4.Processes.Default.Command = h2_curl()
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Stale entry served (age < threshold, not evicted)")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "stale.css", "Stale link served during grace window")
tr4.StillRunningAfter = microserver

# ----
# TR5: H2 immediately after TR4. Re-learn reset last_updated. Entry is fresh.
#       103 served again. Multi-serve during stale/grace window confirmed.
# ----
tr5 = Test.AddTestRun("H2: TR5 -- multi-serve confirmed (103 again after stale-revalidate refresh)")
tr5.Processes.Default.Command = h2_curl()
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "103 served again -- multi-serve during grace window verified")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "stale.css", "Link served after stale-revalidate refresh")
tr5.StillRunningAfter = microserver

# ----
# Sleep 4s: age from TR4 re-learn now = 4s > threshold=3s.
# ----
tr_sleep2 = Test.AddTestRun("Sleep 4s: age from TR4 re-learn (4s) now exceeds combined threshold (3s)")
tr_sleep2.Processes.Default.Command = "sleep 4"
tr_sleep2.Processes.Default.ReturnCode = 0

# ----
# TR6: H2 threshold exceeded (age=4 > 3). Served once then EVICTED.
#       Scanner bypassed: has_learned=True, needs_relearn=False (entry gone after eviction).
# ----
tr6 = Test.AddTestRun("H2: TR6 -- threshold exceeded, final serve + eviction (age > threshold)")
tr6.Processes.Default.Command = h2_curl()
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Final stale serve (age > combined threshold, entry evicted after)")
tr6.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "stale.css", "Stale link served one last time before eviction")

# ----
# TR7: H2 after eviction. Cache miss. count=0->1 < min-hit-count=2. No 103.
#       Scanner re-attaches (has_learned=False, cache miss) but TSRemapDoRemap
#       already decided no 103 before scanner runs.
# ----
tr7 = Test.AddTestRun("H2: TR7 -- after eviction, cache miss, count=1 < 2, no 103")
tr7.Processes.Default.Command = h2_curl()
tr7.Processes.Default.ReturnCode = 0
tr7.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Request succeeds after eviction")
tr7.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "103", "No 103: cache miss, re-learned entry at count=1 < min-hit-count=2")
