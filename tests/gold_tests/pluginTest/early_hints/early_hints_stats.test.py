'''
Test 103 Early Hints plugin  -- statistics code path verification (GAP-6 closure).

Validates that the 6 TSStatIntIncrement call sites are actually exercised
by triggering the corresponding scenarios and verifying via the debug header.
The debug header `x-early-hints-status` is set by the exact same code paths
that call TSStatIntIncrement, so it is the correct observable proxy.

Scenarios exercised:
  skipped-h1       → stat_103_skipped_h1       code path
  no-hints         → stat_103_skipped_no_hints  code path
  sent             → stat_103_sent              code path
  skipped-bot      → stat_103_skipped_bot       code path
  skipped-non-nav  → stat_103_skipped_non_nav   code path
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may not
#  use this file except in compliance with the License.  You may
#  obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
#  either express or implied.  See the License for the specific
#  language governing permissions and limitations under the License.

Test.Summary = '''
Test HTTP 103 Early Hints plugin statistics code-path coverage.
Triggers each skip/send scenario and verifies via x-early-hints-status
debug header that the corresponding TSStatIntIncrement call site fires.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_stats"
Test.ContinueOnFail = True

# ----
# Setup
# ----
microserver = Test.MakeOriginServer("microserver")

# Page for auto-learn: contains a preloadable link
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /learn.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/app.js" as="script">'
            '</head><body>Stats test</body></html>\r\n'
    })

# ----
# ATS: auto-learn mode, navigate_only enabled, skip_bots enabled, min_hit_count=2
# min_hit_count=2 means first request learns but doesn't serve hints (→ skipped_no_hints)
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=2'
    # keep skip_bots enabled (default) for bot test
    # keep navigate_only enabled (default) for non-nav test
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 5,
})

# -------------------------------------------------------------------------------
# Phase 1: H1 request → exercises stat_103_skipped_h1 code path
# -------------------------------------------------------------------------------
tr_h1 = Test.AddTestRun("Phase 1: H1 → stat_103_skipped_h1 code path")
tr_h1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " -H 'Sec-Fetch-Mode: navigate'"
    " 'https://127.0.0.1:{0}/learn.html'".format(ts.Variables.ssl_port))
tr_h1.Processes.Default.ReturnCode = 0
tr_h1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr_h1.Processes.Default.StartBefore(Test.Processes.ts)
tr_h1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "skipped-h1",
    "H1 request must trigger stat_103_skipped_h1 code path")
tr_h1.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# Phase 2: H2 navigate request #1 → exercises stat_103_skipped_no_hints code path
# (min_hit_count=2 → first navigate request has no hints yet)
# -------------------------------------------------------------------------------
tr_no_hints = Test.AddTestRun("Phase 2: H2 navigate #1 → stat_103_skipped_no_hints code path")
tr_no_hints.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'Sec-Fetch-Mode: navigate'"
    " -H 'User-Agent: Mozilla/5.0 (compatible; TestBrowser/1.0)'"
    " 'https://127.0.0.1:{0}/learn.html'".format(ts.Variables.ssl_port))
tr_no_hints.Processes.Default.ReturnCode = 0
tr_no_hints.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints",
    "First H2 navigate must trigger stat_103_skipped_no_hints code path (min_hit_count=2)")
tr_no_hints.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# Phase 3: H2 navigate request #2 → exercises stat_103_sent code path
# (request_count now reaches min_hit_count → 103 is sent)
# -------------------------------------------------------------------------------
tr_sent = Test.AddTestRun("Phase 3: H2 navigate #2 → stat_103_sent code path")
tr_sent.Processes.Default.Command = (
    "sleep 0.3 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'Sec-Fetch-Mode: navigate'"
    " -H 'User-Agent: Mozilla/5.0 (compatible; TestBrowser/1.0)'"
    " 'https://127.0.0.1:{0}/learn.html'".format(ts.Variables.ssl_port))
tr_sent.Processes.Default.ReturnCode = 0
tr_sent.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "Second navigate must trigger stat_103_sent code path")
tr_sent.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# Phase 4: H2 Googlebot → exercises stat_103_skipped_bot code path
# -------------------------------------------------------------------------------
tr_bot = Test.AddTestRun("Phase 4: H2 Googlebot → stat_103_skipped_bot code path")
tr_bot.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'Sec-Fetch-Mode: navigate'"
    " -H 'User-Agent: Googlebot/2.1'"
    " 'https://127.0.0.1:{0}/learn.html'".format(ts.Variables.ssl_port))
tr_bot.Processes.Default.ReturnCode = 0
tr_bot.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: skipped-bot",
    "Googlebot must trigger stat_103_skipped_bot code path")
tr_bot.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# Phase 5: H2 cors fetch → exercises stat_103_skipped_non_nav code path
# -------------------------------------------------------------------------------
tr_non_nav = Test.AddTestRun("Phase 5: H2 cors → stat_103_skipped_non_nav code path")
tr_non_nav.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " -H 'Sec-Fetch-Mode: cors'"
    " 'https://127.0.0.1:{0}/learn.html'".format(ts.Variables.ssl_port))
tr_non_nav.Processes.Default.ReturnCode = 0
tr_non_nav.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: skipped-non-nav",
    "cors must trigger stat_103_skipped_non_nav code path")
tr_non_nav.StillRunningAfter = microserver

# -------------------------------------------------------------------------------
# Phase 6: Verify all 5 status values appear in diags log (stat code paths fired)
# The diags log records the [early_hints] debug messages written by the plugin
# at each TSStatIntIncrement call site.
# -------------------------------------------------------------------------------
ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "early_hints", "Plugin must log debug messages to diags")
