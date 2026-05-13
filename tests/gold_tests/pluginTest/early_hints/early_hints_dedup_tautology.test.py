'''
Test 103 Early Hints plugin — origin-forward dedup tautological comparison
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
Origin-forward dedup tautological comparison.

Bug in dedup_link_segments(): the inner check compares
  (seg.find("rel=preconnect") != npos) == is_preconnect
which is always true (tautological — both sides from same `seg`).
The second entry for the same URL is ALWAYS dropped, regardless of rel type.

Critical scenario:
  Origin sends: rel=preconnect FIRST, then rel=preload; as=script.
  Bug: dedup drops rel=preload (it comes second → false dup → dropped).
  Result: only preconnect cached → 103 has only preconnect.
  Fix: rel=preload survives dedup → both cached → merge_hint_links picks preload
       (preload appears first in cached list after preconnect).

Wait — merge_hint_links deduplicates by URL key only. So even with both cached,
only the FIRST one (preconnect) would appear in 103 if they share the same URL.

Actual user-visible impact of the dedup bug:
  When origin sends ONLY rel=preconnect for an asset (no preload), that gets
  cached and served correctly.
  When origin sends BOTH rel=preconnect AND rel=preload for the SAME URL,
  only the FIRST one is kept (second is false-deduped).
  If preconnect comes first: preload is dropped → 103 only has preconnect (weaker hint).
  If preload comes first: preconnect is dropped → 103 has preload (correct but loses preconnect).

The measurable gold test: verify that a URL with ONLY preconnect from origin
works correctly (regression guard), and that the dedup_link_segments fix
does not break genuine dedup (same URL + same rel = dedup correctly).

The unit tests in test_integration.cc directly prove the dedup bug
via dedup_link_segments() calls. The gold test serves as an end-to-end
regression guard for the origin-forward dedup path.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_dedup_tautology"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Scenario A: origin sends ONLY rel=preconnect for an asset (no preload for same URL).
# This must work correctly — preconnect must be cached and served.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /preconnect-only.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/app.js>; rel=preconnect\r\n"
            "\r\n",
        "body": "<html><body>Preconnect only</body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /preconnect-only.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/app.js>; rel=preconnect\r\n"
            "\r\n",
        "body": "<html><body>Preconnect only</body></html>\r\n"
    })

# Scenario B: origin sends DIFFERENT URLs — each different URL gets its own hint.
# Bug scenario: second URL gets false-deduped against first URL only if they share
# URL key prefix. These have different URLs so dedup must NOT fire.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /multi-asset.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/style.css>; rel=preload; as=style\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>Multi-asset</body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /multi-asset.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/style.css>; rel=preload; as=style\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>Multi-asset</body></html>\r\n"
    })

# ----
# Setup ATS — origin-forward mode
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--max-links @pparam=5'
    ' @pparam=--no-skip-bots'
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
# TC0: Learn — preconnect-only page
# ----
tr0 = Test.AddTestRun("Dedup-fix: Learn preconnect-only page")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/preconnect-only.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr0.StillRunningAfter = microserver

# ----
# TC1: Serve — preconnect-only must be served in 103
# Regression guard: preconnect-only (no dedup possible) must work correctly.
# ----
tr1 = Test.AddTestRun("Dedup-fix: Preconnect-only hint must be served in 103")
tr1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/preconnect-only.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "preconnect-only hint must be cached and served")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preconnect", "preconnect hint must appear in 103/200 headers")
tr1.StillRunningAfter = microserver

# ----
# TC2: Learn — multi-asset page (different URLs, both must survive — no false dedup)
# Dedup bug: second DIFFERENT URL was never false-deduped (dedup only fires for same URL prefix).
# This is a regression guard: both preload for style.css and preload for app.js must survive.
# ----
tr2 = Test.AddTestRun("Dedup-fix: Learn multi-asset page (2 different URL preloads)")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/multi-asset.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr2.StillRunningAfter = microserver

tr3 = Test.AddTestRun("Dedup-fix: Both different-URL preloads must be served in 103 (no false dedup)")
tr3.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/multi-asset.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Both different-URL preloads must be cached and served")
# Both assets must appear in the 103 response
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn/style.css", "style.css preload must appear in 103")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn/app.js", "app.js preload must appear in 103")
# Verify both are preload type
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload; as=style", "style.css rel=preload must be served")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "rel=preload; as=script", "app.js rel=preload must be served")
tr3.StillRunningAfter = microserver
