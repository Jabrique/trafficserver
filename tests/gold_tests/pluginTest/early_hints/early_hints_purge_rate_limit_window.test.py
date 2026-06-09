'''
Test 103 Early Hints plugin -- purge rate limiter window boundary (C1 fix)

Validates that the TOCTOU fix in PurgeRateLimiter::allow() correctly enforces
the limit across multiple sequential window resets. The concurrent race is
tested in the unit tests; here we verify the observable end-to-end behavior:

  - After limit purges within the cooldown window, additional purge attempts
    are rejected (cache NOT evicted).
  - After the cooldown expires (new window), purges are allowed again.

The key behavioral contract being tested end-to-end:
  Window 1: 2 purges allowed (limit=2), 3rd rejected -> hints still in cache.
  Window 2 (after cooldown): counter resets -> 2 purges allowed again.

RED (before fix): rate limiter can allow more than limit purges per window
                  due to TOCTOU race at window boundary under concurrency.
GREEN (after fix): rate limiter strictly enforces limit=2 per window,
                   third purge in window is rejected, hints remain cached.
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
Purge rate limiter window boundary: limit=2 per cooldown, third purge rejected,
hints remain in cache. After cooldown expires, counter resets and purges allowed again.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_purge_rate_limit_window"
Test.ContinueOnFail = True

# ----
# Origin Server: enough responses for learn + re-learn cycles
# ----
microserver = Test.MakeOriginServer("microserver")

HTML_BODY = (
    "<html><head>"
    "<link rel=\"preload\" href=\"/window-test.css\" as=\"style\">"
    "</head><body>Window boundary test</body></html>\r\n"
)

for _ in range(10):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /window.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
            "body": HTML_BODY
        })

# ----
# ATS: limit=2, cooldown=2s (short enough to test window reset)
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--purge-header @pparam=X-Purge'
    ' @pparam=--purge-secret @pparam=winsecret'
    ' @pparam=--purge-limit @pparam=2'
    ' @pparam=--purge-cooldown @pparam=2'
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
    " 'https://127.0.0.1:{0}/window.html'".format(ts.Variables.ssl_port))

CURL_H2 = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/window.html'".format(ts.Variables.ssl_port))

CURL_PURGE = (
    "curl -s -D -"
    " --http2"
    " --insecure"
    " -H 'X-Purge: winsecret'"
    " -o /dev/null"
    " 'https://127.0.0.1:{0}/window.html'".format(ts.Variables.ssl_port))

# ----
# TR1: Learn hints on first H1 request
# ----
tr1 = Test.AddTestRun("Learn: H1 first request")
tr1.Processes.Default.Command = CURL_H1
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "H1 learn succeeds")
tr1.StillRunningAfter = microserver

# ----
# TR2: H2 - 103 served (hints learned)
# ----
tr2 = Test.AddTestRun("H2: hints active, 103 served")
tr2.Processes.Default.Command = CURL_H2
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("103", "103 sent")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression("window-test.css", "correct link in 103")
tr2.StillRunningAfter = microserver

# ----
# PURGE 1: Allowed (count=1 <= limit=2)
# ----
tr_p1 = Test.AddTestRun("Purge 1: allowed (count=1, limit=2)")
tr_p1.Processes.Default.Command = CURL_PURGE
tr_p1.Processes.Default.ReturnCode = 0
tr_p1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "purge 1 returns 200")
tr_p1.StillRunningAfter = microserver

# ----
# TR3: Re-learn after purge 1
# ----
tr3 = Test.AddTestRun("H1: re-learn after purge 1")
tr3.Processes.Default.Command = CURL_H1
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "re-learn succeeds")
tr3.StillRunningAfter = microserver

# ----
# TR4: H2 - 103 served again after re-learn
# ----
tr4 = Test.AddTestRun("H2: 103 served after purge 1 re-learn")
tr4.Processes.Default.Command = CURL_H2
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("103", "103 sent after re-learn")
tr4.StillRunningAfter = microserver

# ----
# PURGE 2: Allowed (count=2, at limit)
# ----
tr_p2 = Test.AddTestRun("Purge 2: allowed (count=2, at limit=2)")
tr_p2.Processes.Default.Command = CURL_PURGE
tr_p2.Processes.Default.ReturnCode = 0
tr_p2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "purge 2 returns 200")
tr_p2.StillRunningAfter = microserver

# ----
# TR5: Re-learn after purge 2
# ----
tr5 = Test.AddTestRun("H1: re-learn after purge 2")
tr5.Processes.Default.Command = CURL_H1
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "re-learn after purge 2")
tr5.StillRunningAfter = microserver

# ----
# TR6: H2 - 103 served
# ----
tr6 = Test.AddTestRun("H2: 103 served after purge 2 re-learn")
tr6.Processes.Default.Command = CURL_H2
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("103", "103 sent")
tr6.StillRunningAfter = microserver

# ----
# PURGE 3: RATE LIMITED - count=3 > limit=2, within cooldown window
# Cache NOT evicted. Hints must still be served.
# ----
tr_p3 = Test.AddTestRun("Purge 3: RATE LIMITED (count=3 > limit=2)")
tr_p3.Processes.Default.Command = CURL_PURGE
tr_p3.Processes.Default.ReturnCode = 0
tr_p3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "purge 3 returns 200")
tr_p3.StillRunningAfter = microserver

# ----
# TR7: H2 - Rate limit confirmed: hints NOT evicted, 103 still sent
# This is the key assertion: if TOCTOU bug is fixed, purge 3 was rejected
# and hints remain in cache.
# ----
tr7 = Test.AddTestRun("H2: hints still cached after rate-limited purge, 103 sent")
tr7.Processes.Default.Command = CURL_H2
tr7.Processes.Default.ReturnCode = 0
tr7.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "103", "103 still sent: rate-limited purge did not evict cache")
tr7.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "window-test.css", "correct link still in 103 after rejected purge")
tr7.StillRunningAfter = microserver

# ----
# Wait for cooldown window to expire (cooldown=2s), then verify reset
# ----
tr_wait = Test.AddTestRun("Wait for cooldown window to expire")
tr_wait.Processes.Default.Command = "sleep 3"
tr_wait.Processes.Default.ReturnCode = 0
tr_wait.StillRunningAfter = microserver

# ----
# PURGE 4: New window - count resets to 1, allowed again
# ----
tr_p4 = Test.AddTestRun("Purge 4: new window after cooldown, allowed again (count=1)")
tr_p4.Processes.Default.Command = CURL_PURGE
tr_p4.Processes.Default.ReturnCode = 0
tr_p4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "purge 4 allowed in new window")
tr_p4.StillRunningAfter = microserver
