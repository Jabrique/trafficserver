'''
Test 103 Early Hints plugin — backslash URL bypass and RCDATA element safety

Covers audit findings:
  B-01: is_valid_link_value() does not reject http:\\authority (origin-forward path)
  B-02: is_valid_link_value() does not reject \\\\authority or /\\authority (backslash-relative)
  A-21: <title>, <textarea>, <xmp> content is parsed as HTML — RCDATA spec violation
  (A-22 is the scanner-path equivalent of B-01/B-02 — covered by unit tests A-22/A-21)
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may not
#  use this file except in compliance with the License. You may
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
Backslash URL authority bypass (B-01, B-02) and RCDATA element safety (A-21).

B-01/B-02: Origin-forward mode must reject Link headers with:
  - http:\\\\evil.com  (backslash after scheme, no "://")
  - \\\\evil.com       (double-backslash authority, WHATWG → //evil.com)
  - /\\\\evil.com      (slash-backslash authority, WHATWG → //evil.com)

A-21: Auto-learn mode must NOT extract <link> tags inside <title>.
  Per HTML5 spec §13.2.6.1, these are RCDATA elements — their content is NOT markup.

These tests FAIL before the fix and PASS after the fix.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_backslash_rcdata"
Test.ContinueOnFail = True

# ──────────────────────────────────────────────────────────────────────────────
# Origin server for B-01/B-02 tests (origin-forward mode)
# ──────────────────────────────────────────────────────────────────────────────
ms_origin = Test.MakeOriginServer("ms_origin")

# B-01: http:\evil.com in Link header — must be rejected
ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /b01-http-backslash.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <http:\\evil.com/track.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>B-01 test</body></html>\r\n"
    })

ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /b01-http-backslash.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <http:\\evil.com/track.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>B-01 test</body></html>\r\n"
    })

# B-02: \\evil.com — double-backslash authority
ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /b02-dbs.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <\\\\evil.com/track.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>B-02 dbs test</body></html>\r\n"
    })

ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /b02-dbs.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <\\\\evil.com/track.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>B-02 dbs test</body></html>\r\n"
    })

# B-02: /\evil.com — slash-backslash authority
ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /b02-sb.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </\\evil.com/track.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>B-02 sb test</body></html>\r\n"
    })

ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /b02-sb.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </\\evil.com/track.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>B-02 sb test</body></html>\r\n"
    })

# Regression: valid relative Link header — must still work
ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /valid.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>Valid</body></html>\r\n"
    })

ms_origin.addResponse(
    "sessionfile.log", {
        "headers": "GET /valid.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>Valid</body></html>\r\n"
    })

# ──────────────────────────────────────────────────────────────────────────────
# Origin server for A-21 (auto-learn mode — HTML body scanning)
# ──────────────────────────────────────────────────────────────────────────────
ms_a21 = Test.MakeOriginServer("ms_a21")

# A-21: HTML with <link> inside <title> — scanner must skip RCDATA content
ms_a21.addResponse(
    "sessionfile.log", {
        "headers": "GET /a21-title.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": (
            "<html><head>"
            "<title><link rel=\"preload\" href=\"/title-fake.js\" as=\"script\"></title>"
            "<link rel=\"preload\" href=\"/real.css\" as=\"style\">"
            "</head><body>A-21 title test</body></html>\r\n"
        )
    })

ms_a21.addResponse(
    "sessionfile.log", {
        "headers": "GET /a21-title.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": (
            "<html><head>"
            "<title><link rel=\"preload\" href=\"/title-fake.js\" as=\"script\"></title>"
            "<link rel=\"preload\" href=\"/real.css\" as=\"style\">"
            "</head><body>A-21 title test</body></html>\r\n"
        )
    })

# ──────────────────────────────────────────────────────────────────────────────
# ATS #1: origin-forward mode — B-01/B-02 and regression tests
# ──────────────────────────────────────────────────────────────────────────────
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(ms_origin.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
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

# ──────────────────────────────────────────────────────────────────────────────
# ATS #2: auto-learn mode — A-21 test
# ──────────────────────────────────────────────────────────────────────────────
ts_a21 = Test.MakeATSProcess("ts_a21", select_ports=True, enable_tls=True, enable_cache=False)
ts_a21.addDefaultSSLFiles()
ts_a21.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts_a21.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(ms_a21.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')
ts_a21.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts_a21.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts_a21.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ──────────────────────────────────────────────────────────────────────────────
# TC-B01: http:\evil.com in Link header — must be rejected (B-01)
# Before fix: is_valid_link_value() accepts http:\ → cached → 103 with evil.com
# After fix:  rejected → no-hints on both requests
# ──────────────────────────────────────────────────────────────────────────────
tr_b01_1 = Test.AddTestRun("B-01: First H2 with http:\\evil.com Link — rejected, no-hints")
tr_b01_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/b01-http-backslash.html'".format(ts.Variables.ssl_port))
tr_b01_1.Processes.Default.ReturnCode = 0
tr_b01_1.Processes.Default.StartBefore(ms_origin, ready=When.PortOpen(ms_origin.Variables.Port))
tr_b01_1.Processes.Default.StartBefore(Test.Processes.ts)
tr_b01_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_b01_1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: no-hints",
    "B-01: http:\\evil.com must be rejected — no-hints, not learned")
tr_b01_1.StillRunningAfter = ms_origin

tr_b01_2 = Test.AddTestRun("B-01: Second H2 — evil.com must NOT appear in 103")
tr_b01_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/b01-http-backslash.html'".format(ts.Variables.ssl_port))
tr_b01_2.Processes.Default.ReturnCode = 0
tr_b01_2.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "x-early-hints-status: sent",
    "B-01: No 103 should be sent — http:\\evil.com must not be cached")
# Note: ATS transparently passes origin Link headers in the 200 response.
# We only test what the plugin controls: whether a 103 Early Hints was sent.
tr_b01_2.StillRunningAfter = ms_origin

# ──────────────────────────────────────────────────────────────────────────────
# TC-B02a: \\evil.com in Link header — double-backslash authority bypass (B-02)
# ──────────────────────────────────────────────────────────────────────────────
tr_b02a_1 = Test.AddTestRun("B-02a: First H2 with \\\\evil.com — rejected, no-hints")
tr_b02a_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/b02-dbs.html'".format(ts.Variables.ssl_port))
tr_b02a_1.Processes.Default.ReturnCode = 0
tr_b02a_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_b02a_1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "x-early-hints-status: no-hints",
    "B-02a: \\\\evil.com must be rejected by is_valid_link_value()")
tr_b02a_1.StillRunningAfter = ms_origin

tr_b02a_2 = Test.AddTestRun("B-02a: Second H2 — \\\\evil.com not in 103")
tr_b02a_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/b02-dbs.html'".format(ts.Variables.ssl_port))
tr_b02a_2.Processes.Default.ReturnCode = 0
tr_b02a_2.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "x-early-hints-status: sent",
    "B-02a: No 103 should be sent — \\\\evil.com must not be cached")
# Note: origin Link header appears in 200 response passthrough — only 103 is plugin-controlled.
tr_b02a_2.StillRunningAfter = ms_origin

# ──────────────────────────────────────────────────────────────────────────────
# TC-B02b: /\evil.com in Link header — slash-backslash authority bypass (B-02)
# ──────────────────────────────────────────────────────────────────────────────
tr_b02b = Test.AddTestRun("B-02b: /\\evil.com slash-backslash — rejected, no-hints")
tr_b02b.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/b02-sb.html'".format(ts.Variables.ssl_port))
tr_b02b.Processes.Default.ReturnCode = 0
tr_b02b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints",
    "B-02b: /\\evil.com must be rejected — WHATWG normalizes /\\ to //")
# Note: ATS passes origin Link headers in 200 regardless; only 103 is plugin-controlled.
tr_b02b.StillRunningAfter = ms_origin

# ──────────────────────────────────────────────────────────────────────────────
# TC-VALID: Valid relative Link header still works (regression guard)
# ──────────────────────────────────────────────────────────────────────────────
tr_valid_1 = Test.AddTestRun("Regression: valid relative Link header — learn phase (H1)")
tr_valid_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1 --insecure"
    " 'https://127.0.0.1:{0}/valid.html'".format(ts.Variables.ssl_port))
tr_valid_1.Processes.Default.ReturnCode = 0
tr_valid_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Valid page should return 200")
tr_valid_1.StillRunningAfter = ms_origin

tr_valid_2 = Test.AddTestRun("Regression: valid Link cached and served as 103 (H2)")
tr_valid_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/valid.html'".format(ts.Variables.ssl_port))
tr_valid_2.Processes.Default.ReturnCode = 0
tr_valid_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "Regression: valid relative link must be cached and served as 103")
tr_valid_2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/app.js",
    "Regression: /app.js must appear in 103 hint")
tr_valid_2.StillRunningAfter = ms_origin

# ──────────────────────────────────────────────────────────────────────────────
# TC-A21: HTML with <link> inside <title> — RCDATA element (A-21)
# Uses separate ATS (ts_a21) with auto-learn mode.
# Before fix: scanner extracts /title-fake.js from <title> content → 103 sends it
# After fix:  RCDATA skip → only /real.css extracted → /title-fake.js never in 103
# Both learn and serve phases use H2 to ensure plugin is fully active.
# ──────────────────────────────────────────────────────────────────────────────
tr_a21_learn = Test.AddTestRun("A-21: First H2 — learn phase (scan HTML, skip title)")
tr_a21_learn.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a21-title.html'".format(ts_a21.Variables.ssl_port))
tr_a21_learn.Processes.Default.ReturnCode = 0
tr_a21_learn.Processes.Default.StartBefore(ms_a21, ready=When.PortOpen(ms_a21.Variables.Port))
tr_a21_learn.Processes.Default.StartBefore(ts_a21)
tr_a21_learn.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK from auto-learn ATS")
# Before fix: title-fake.js AND real.css both learned → status: "learned"
# After fix:  only real.css learned → status: "learned" (still ok here, check in serve phase)
tr_a21_learn.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "title-fake.js",
    "A-21: title-fake.js must NOT appear in any header during learn phase")
tr_a21_learn.StillRunningAfter = ms_a21

tr_a21_serve = Test.AddTestRun("A-21: Second H2 — serve phase: title-fake.js absent, real.css present")
tr_a21_serve.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a21-title.html'".format(ts_a21.Variables.ssl_port))
tr_a21_serve.Processes.Default.ReturnCode = 0
tr_a21_serve.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "A-21: /real.css should be cached and served as 103")
# CRITICAL: /title-fake.js must NEVER appear — it was inside <title> RCDATA
tr_a21_serve.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "title-fake.js",
    "A-21: Link inside <title> must NOT be extracted — RCDATA content is not markup")
tr_a21_serve.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/real.css",
    "A-21: /real.css (outside <title>) must be extracted and served as 103 hint")
tr_a21_serve.StillRunningAfter = ms_a21
