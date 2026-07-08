'''
Test 103 Early Hints plugin -- purge rate limiting
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
Test HTTP 103 Early Hints plugin --purge-limit and --purge-cooldown options.

The rate limiter allows at most --purge-limit successful purges within a
--purge-cooldown second window per remap rule. Excess purge attempts within
the same window are rejected (TSNote logged, cache NOT invalidated).

Flow:
  TR1 (H1):  First request. Plugin scans and learns hints.
  TR2 (H2):  Hints active, 103 sent.

  Purge 1:   X-Purge header with correct secret. Allowed (count=1 <= limit=2).
             Cache entry removed. Next request re-learns via scanner.
  TR3 (H1):  Re-learn after purge 1.
  TR4 (H2):  Hints active again after re-learning. 103 sent.

  Purge 2:   Allowed (count=2, at limit).
             Cache entry removed. Re-learn again.
  TR5 (H1):  Re-learn after purge 2.
  TR6 (H2):  Hints active again. 103 sent.

  Purge 3:   RATE LIMITED (count would be 3 > limit=2).
             Cache NOT invalidated. Hints must still be served.
  TR7 (H2):  Rate limit confirmed: hints STILL present, 103 sent.

RED before fix: --purge-limit and --purge-cooldown are unknown options.
                Plugin fails to parse config -> remap rule fails to load.
                All requests fail (no 200/103 response).
GREEN after fix: Plugin accepts the options, enforces the rate limit,
                 TR7 still receives 103 (purge 3 was rejected).
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_purge_rate_limit"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

HTML_BODY = (
    "<html><head>"
    "<link rel=\"preload\" href=\"/assets/rate.css\" as=\"style\">"
    "</head><body><p>Purge rate limit test</p></body></html>\r\n"
)

# Multiple responses for re-learn cycles
for _ in range(8):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /rate.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
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

# --purge-limit 2: allow at most 2 purges per --purge-cooldown window.
# RED: --purge-limit and --purge-cooldown are unknown options before fix.
#      Plugin rejects the config -> remap rule fails to load -> requests fail.
ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--purge-header @pparam=X-Purge'
    ' @pparam=--purge-secret @pparam=supersecret'
    ' @pparam=--purge-limit @pparam=2'
    ' @pparam=--purge-cooldown @pparam=60'
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

CURL_H1 = (
    "curl -s -D -"
    " --http1.1"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/rate.html'".format(ts.Variables.ssl_port))

CURL_H2 = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/rate.html'".format(ts.Variables.ssl_port))

CURL_PURGE = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -H 'X-Purge: supersecret'"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/rate.html'".format(ts.Variables.ssl_port))

# ----
# TR1: H1 learn pass (min-hit-count=1, so hints serve from first get)
# ----
tr1 = Test.AddTestRun("H1: first request -- plugin learns hints")
tr1.Processes.Default.Command = CURL_H1
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "H1 learning request succeeds with 200")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 -- 103 served from learned hints
# ----
tr2 = Test.AddTestRun("H2: hints active, 103 sent")
tr2.Processes.Default.Command = CURL_H2
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "Plugin sends 103 Early Hints")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rate.css", "103 contains the learned link")
tr2.StillRunningAfter = microserver

# ----
# Purge 1: allowed (count=1 <= limit=2)
# ----
tr_purge1 = Test.AddTestRun("Purge 1: allowed (count=1, within limit=2)")
tr_purge1.Processes.Default.Command = CURL_PURGE
tr_purge1.Processes.Default.ReturnCode = 0
tr_purge1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Purge 1 request returns 200")
tr_purge1.StillRunningAfter = microserver

# ----
# TR3: H1 re-learn after purge 1
# ----
tr3 = Test.AddTestRun("H1: re-learn after purge 1")
tr3.Processes.Default.Command = CURL_H1
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Re-learn request after purge 1 succeeds")
tr3.StillRunningAfter = microserver

# ----
# TR4: H2 -- hints re-learned and active
# ----
tr4 = Test.AddTestRun("H2: hints re-learned after purge 1, 103 sent again")
tr4.Processes.Default.Command = CURL_H2
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "103 sent after re-learning")
tr4.StillRunningAfter = microserver

# ----
# Purge 2: allowed (count=2, at limit)
# ----
tr_purge2 = Test.AddTestRun("Purge 2: allowed (count=2, at limit=2)")
tr_purge2.Processes.Default.Command = CURL_PURGE
tr_purge2.Processes.Default.ReturnCode = 0
tr_purge2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Purge 2 request returns 200")
tr_purge2.StillRunningAfter = microserver

# ----
# TR5: H1 re-learn after purge 2
# ----
tr5 = Test.AddTestRun("H1: re-learn after purge 2")
tr5.Processes.Default.Command = CURL_H1
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Re-learn after purge 2 succeeds")
tr5.StillRunningAfter = microserver

# ----
# TR6: H2 -- hints active again
# ----
tr6 = Test.AddTestRun("H2: hints active again after purge 2 re-learn")
tr6.Processes.Default.Command = CURL_H2
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "103 sent after second re-learn")
tr6.StillRunningAfter = microserver

# ----
# Purge 3: RATE LIMITED (count=3 > limit=2, within cooldown window)
# ----
tr_purge3 = Test.AddTestRun("Purge 3: RATE LIMITED -- third purge within cooldown window blocked")
tr_purge3.Processes.Default.Command = CURL_PURGE
tr_purge3.Processes.Default.ReturnCode = 0
tr_purge3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Purge 3 request returns 200 (rate limited but connection still OK)")
tr_purge3.StillRunningAfter = microserver

# ----
# TR7: H2 -- rate limit confirmed: hints NOT evicted by purge 3, 103 still served
# ----
tr7 = Test.AddTestRun("H2: hints NOT evicted -- rate-limited purge was rejected, 103 still sent")
tr7.Processes.Default.Command = CURL_H2
tr7.Processes.Default.ReturnCode = 0
# Rate limiter blocked purge 3, so hints are still in cache
tr7.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "103 still sent: rate-limited purge did not evict cache entry")
tr7.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rate.css", "103 still contains the learned link after blocked purge")
tr7.StillRunningAfter = microserver
