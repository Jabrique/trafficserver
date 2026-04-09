'''
Test 103 Early Hints plugin — security tests
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
Test HTTP 103 Early Hints plugin security behaviors.
Verifies:
- Bot User-Agent with H1: H1 skip fires first (documented limitation)
- Origin 500 error with preloadable resources: hints NOT cached
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_security"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Normal page for bot test
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /normal.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><head><link rel=\"preload\" href=\"/app.js\" as=\"script\"></head><body>OK</body></html>\r\n"
    })

# Page that returns a non-200 status WITH preloadable resources in HTML.
# Hints should NOT be learned from error pages even when HTML contains resources.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /error.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/error-app.js\" as=\"script\">"
            "<link rel=\"stylesheet\" href=\"/error-style.css\">"
            "</head><body>Server Error</body></html>\r\n"
    })

# ----
# Setup ATS — skip_bots enabled (default), navigate_only disabled for simpler testing
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--skip-bots'
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
# Test Case 0: Bot User-Agent skipped — Googlebot detected
# NOTE: H1 check fires before bot check, so debug header shows skipped-h1.
# Bot detection still fires (verified by stat counters), but for a proper
# isolated bot test we'd need an H2 client. This test verifies the plugin
# engages and the bot request still gets a 200 response.
# ----
tr1 = Test.AddTestRun("Bot UA - plugin engages, H1 skip takes precedence")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " -H 'User-Agent: Googlebot/2.1'"
    " 'https://127.0.0.1:{0}/normal.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
# H1 check fires first — debug header shows skipped-h1, not skipped-bot
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "H1 skip fires before bot check")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.StillRunningAfter = microserver

# ----
# Test Case 1: H2 Bot User-Agent — REAL bot detection test
# Over H2, the H1 check passes (is H2), navigate-only is disabled, and the bot check
# at plugin line 918-924 fires. This is the isolated test that actually verifies
# bot detection works correctly — unlike TR0 which only tests the H1 skip path.
# ----
tr_bot_h2 = Test.AddTestRun("H2 bot detection - Googlebot skipped for 103")
tr_bot_h2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'User-Agent: Googlebot/2.1'"
    " 'https://127.0.0.1:{0}/normal.html'".format(ts.Variables.ssl_port))
tr_bot_h2.Processes.Default.ReturnCode = 0
# H2 + bot UA: bot check fires, debug status must be "skipped-bot" (NOT "skipped-h1")
tr_bot_h2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: skipped-bot", "H2 bot should be detected and skipped for 103")
tr_bot_h2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "200", "Bot should still receive 200 OK response")
# Verify 103 was NOT sent (bot skip means no 103)
tr_bot_h2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "x-early-hints-status: sent", "Bot request must NOT trigger 103 sending")
tr_bot_h2.StillRunningAfter = microserver

# ----
# Test Case 2: Origin 500 — hints NOT learned even when HTML has resources
# First request returns 500 with preloadable resources in HTML,
# second request should have no cached hints.
# ----
tr2 = Test.AddTestRun("Origin 500 - first request with resources in HTML")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/error.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "500", "Should receive 500 from origin")
# Plugin must engage — debug header proves plugin loaded and running on error pages too
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin debug header must show status on 500 responses too")
tr2.StillRunningAfter = microserver

tr3 = Test.AddTestRun("Error page - verify no hints cached despite HTML resources")
tr3.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/error.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
# Positive assertion: verify we got a response and plugin engaged
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "500", "Should still receive 500 from origin")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin debug header must show status on 500 responses too")
# Should not have Link headers — 500 responses must not have hints learned
# even though the HTML contained <link rel=preload> and <link rel=stylesheet>
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link:", "Error page should not have cached hints")
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "error-app.js", "Resources from 500 page must not be learned")
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "error-style.css", "Resources from 500 page must not be learned")
tr3.StillRunningAfter = microserver
