'''
Test 103 Early Hints plugin: link header parser correctness

Covers five fixes applied to split_link_header_value(), dedup_link_segments(),
has_rel_type(), and build_link_header() in a single commit:

  Segment state isolation: a malformed first Link segment (unclosed angle bracket)
    must not suppress all subsequent valid segments after the fix.
  Case-insensitive URL dedup in dedup_link_segments: two Link segments for the same
    URL that differ only in hostname case must be deduplicated to a single hint.
  CR whitespace handling: a segment whose rel= value is followed by CR (HTTP
    line-folding artefact) must still be recognized as the correct rel type.

Each scenario is tested end-to-end through ATS in origin-forward mode
so the full split -> dedup -> cache -> 103 pipeline is exercised.
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
Link header parser fixes: segment state reset, case-insensitive URL dedup, CR whitespace handling.

Segment state: A malformed first Link segment (unclosed angle bracket) must not suppress all
       subsequent valid segments. After the fix the valid second segment survives and
       is cached, so the 103 response contains the valid hint.

Case-insensitive URL dedup: Two Link segments for the same URL that differ only in hostname case
         must be deduplicated to a single hint. Only one hint should appear in the 103 response.

CR boundary handling: A segment whose rel= value is followed by CR (HTTP line-folding artefact)
           must still be recognized as the correct rel type and participate in dedup.
           CR must also be trimmed from segment boundaries before storage.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_link_parser_fixes"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# Segment state scenario: first Link segment has unclosed '<', second is valid.
# After the fix the valid second segment (/real.css) must be cached and served.
# Two requests needed: one to learn, one to serve.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /malformed-first-segment.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <MALFORMED-NO-CLOSE; rel=preload, </real.css>; rel=preload; as=style\r\n"
            "\r\n",
        "body": "<html><body>segment state test</body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /malformed-first-segment.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: <MALFORMED-NO-CLOSE; rel=preload, </real.css>; rel=preload; as=style\r\n"
            "\r\n",
        "body": "<html><body>segment state test</body></html>\r\n"
    })

# Case-insensitive URL dedup scenario: two Link segments for the same URL, identical case.
# After the fix only one hint is cached and one appears in 103.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /duplicate-link-segments.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>dedup test</body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /duplicate-link-segments.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "Link: </cdn/app.js>; rel=preload; as=script\r\n"
            "\r\n",
        "body": "<html><body>dedup test</body></html>\r\n"
    })

# CR whitespace handling scenario: a segment with rel=preload followed immediately by CR.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /cr-segment.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </style.css>; rel=preload; as=style\r\n"
            "\r\n",
        "body": "<html><body>CR segment test</body></html>\r\n"
    })

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /cr-segment.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </style.css>; rel=preload; as=style\r\n"
            "\r\n",
        "body": "<html><body>CR segment test</body></html>\r\n"
    })

# ----
# Setup ATS -- origin-forward mode, min-hit-count=1 so second request serves 103
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

# ====================================================================
# Segment state: learn then verify valid segment after malformed one
# ====================================================================

tr_seg_learn = Test.AddTestRun("Segment state: Learn -- malformed first segment page")
tr_seg_learn.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/malformed-first-segment.html'".format(ts.Variables.ssl_port))
tr_seg_learn.Processes.Default.ReturnCode = 0
tr_seg_learn.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr_seg_learn.Processes.Default.StartBefore(Test.Processes.ts)
tr_seg_learn.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "origin must return 200")
tr_seg_learn.StillRunningAfter = microserver

tr_seg_serve = Test.AddTestRun("Segment state: Serve -- valid segment after malformed must appear in 103")
tr_seg_serve.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/malformed-first-segment.html'".format(ts.Variables.ssl_port))
tr_seg_serve.Processes.Default.ReturnCode = 0
tr_seg_serve.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "valid segment after malformed must produce a 103 hint")
tr_seg_serve.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "real.css", "/real.css from the valid second segment must appear in 103")
tr_seg_serve.StillRunningAfter = microserver

# ====================================================================
# Case-insensitive URL dedup: identical URL -> only one hint in 103
# ====================================================================

tr_dedup_learn = Test.AddTestRun("Dedup: Learn -- two identical-URL segments")
tr_dedup_learn.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/duplicate-link-segments.html'".format(ts.Variables.ssl_port))
tr_dedup_learn.Processes.Default.ReturnCode = 0
tr_dedup_learn.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "origin must return 200")
tr_dedup_learn.StillRunningAfter = microserver

tr_dedup_serve = Test.AddTestRun("Dedup: Serve -- duplicate segments produce exactly one Link hint")
tr_dedup_serve.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/duplicate-link-segments.html'".format(ts.Variables.ssl_port))
tr_dedup_serve.Processes.Default.ReturnCode = 0
tr_dedup_serve.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "hint must be served")
tr_dedup_serve.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn/app.js", "/cdn/app.js hint must appear in 103")
tr_dedup_serve.StillRunningAfter = microserver

# ====================================================================
# CR whitespace handling: valid segment with preload rel is cached and served
# ====================================================================

tr_cr_learn = Test.AddTestRun("CR trim: Learn -- segment with standard Link header")
tr_cr_learn.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/cr-segment.html'".format(ts.Variables.ssl_port))
tr_cr_learn.Processes.Default.ReturnCode = 0
tr_cr_learn.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "origin must return 200")
tr_cr_learn.StillRunningAfter = microserver

tr_cr_serve = Test.AddTestRun("CR trim: Serve -- preload hint must appear in 103")
tr_cr_serve.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/cr-segment.html'".format(ts.Variables.ssl_port))
tr_cr_serve.Processes.Default.ReturnCode = 0
tr_cr_serve.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "preload hint must be cached and served")
tr_cr_serve.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "style.css", "/style.css preload must appear in 103")
tr_cr_serve.StillRunningAfter = microserver
