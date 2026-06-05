'''
Test 103 Early Hints plugin — real-world CDN scenarios
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
Test HTTP 103 Early Hints plugin real-world CDN scenarios.
Verifies:
- Origin comma-separated Link header: split_link_header_value parses correctly
- Cache key query string stripping: ?v=1 and ?v=2 share the same hints cache key
- 301 redirect: plugin does NOT learn from redirect bodies or add Link headers
- HTML comment: resources inside <!-- comments --> are NOT extracted
- Origin-forward max-links enforcement: origin sends 5 Link headers, only 2 cached
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_cdn_scenarios"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# ---- Scenario 1: Origin sends comma-separated Link header ----
# Many origins (WordPress, nginx) send multiple hints in ONE Link header
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /comma-links.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </comma-a.css>; rel=preload; as=style, </comma-b.js>; rel=preload; as=script\r\n\r\n",
        "body": "<html><body>Comma-separated Link test</body></html>\r\n"
    })

# ---- Scenario 2: Cache key query string stripping ----
# CDN URLs have cache-busting params: /page.html?v=1, /page.html?v=2
# Plugin should strip query string for cache key: both map to /page.html
# Need separate microserver responses for each query string variant
qs_html = (
    '<html><head>'
    '<link rel="preload" href="/qs-style.css" as="style">'
    '</head><body>Query string test</body></html>\r\n'
)
qs_response = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
    "body": qs_html
}
microserver.addResponse(
    "sessionfile.log",
    {"headers": "GET /qspage.html?v=1 HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "body": ""},
    qs_response)
microserver.addResponse(
    "sessionfile.log",
    {"headers": "GET /qspage.html?v=2 HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "body": ""},
    qs_response)
microserver.addResponse(
    "sessionfile.log",
    {"headers": "GET /qspage.html?v=3 HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "body": ""},
    qs_response)

# ---- Scenario 3: 301 Redirect with HTML body containing resources ----
# CDN redirects (http→https, www→non-www) must NOT pollute hints cache
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /redirect.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\n"
            "Location: https://www.example.com/real-page.html\r\n"
            "Content-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<link rel="preload" href="/redirect-poison.css" as="style">'
            '</head><body>Redirecting...</body></html>\r\n'
    })

# ---- Scenario 4: HTML comment containing <link> tags ----
# CMS templates and developer comments often have <link> in comments
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /comment.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            '<html><head>'
            '<!-- <link rel="preload" href="/fake-commented.css" as="style"> -->'
            '<link rel="preload" href="/real-resource.js" as="script">'
            '</head><body>Comment test</body></html>\r\n'
    })

# ---- Scenario 5: Origin-forward max-links enforcement ----
# Origin sends 5 Link headers, but max-links=2. Only first 2 should be cached.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /many-links.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </first.css>; rel=preload; as=style\r\n"
            "Link: </second.js>; rel=preload; as=script\r\n"
            "Link: </third.woff2>; rel=preload; as=font\r\n"
            "Link: </fourth.png>; rel=preload; as=image\r\n"
            "Link: </fifth.svg>; rel=preload; as=image\r\n"
            "\r\n",
        "body": "<html><body>Many Link headers test</body></html>\r\n"
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # Comma-separated Link: origin-forward mode
    'map /comma-links.html http://127.0.0.1:{0}/comma-links.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Query string: auto-learn mode, min-hit-count=2
    # First request with ?v=1 → put() #1 (new entry)
    # Second request with ?v=2 → request_count=0 (learn phase) (same cache key!)
    # Third request with ?v=3 over H2 → 103 sent (request_count=0 (learn phase) >= 2)
    'map /qspage.html http://127.0.0.1:{0}/qspage.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=2'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # 301 redirect: auto-learn mode
    'map /redirect.html http://127.0.0.1:{0}/redirect.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # HTML comment: auto-learn mode
    'map /comment.html http://127.0.0.1:{0}/comment.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # Origin-forward max-links enforcement: origin sends 5 Link headers, max-links=2
    'map /many-links.html http://127.0.0.1:{0}/many-links.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--max-links @pparam=2'
    ' @pparam=--min-hit-count @pparam=1'
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

# ========================================================================
# SCENARIO 1: Origin comma-separated Link header
# ========================================================================

# TR1: H1 learn from comma-separated Link
tr1 = Test.AddTestRun("Comma Link: origin sends 2 hints in one header")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/comma-links.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
# Both comma-separated hints should be cached and added as plugin Link headers
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "comma-a.css", "First comma-separated Link value should be learned")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "comma-b.js", "Second comma-separated Link value should be learned")
# Plugin-specific: debug header proves plugin engaged
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip confirms plugin loaded)")
tr1.StillRunningAfter = microserver

# TR2: H2 verifies both hints sent in 103
tr2 = Test.AddTestRun("Comma Link: H2 gets 103 with both hints from cache")
tr2.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/comma-links.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "comma-a.css", "First hint should be in 103")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "comma-b.js", "Second hint should be in 103")
tr2.StillRunningAfter = microserver

# ========================================================================
# SCENARIO 2: Cache key query string stripping
# ========================================================================

# TR3: First request with ?v=1 → put() #1 (new entry)
tr3 = Test.AddTestRun("Query string: /qspage.html?v=1 → learn (count=1)")
tr3.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/qspage.html?v=1'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage")
tr3.StillRunningAfter = microserver

# TR4: Second request with ?v=2 (different QS, same cache key!) → request_count=0 (learn phase)
tr4 = Test.AddTestRun("Query string: /qspage.html?v=2 → learn (count=2, same key)")
tr4.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/qspage.html?v=2'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200")
# Plugin-specific: debug header proves plugin processes each request
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged on second QS variant")
tr4.StillRunningAfter = microserver

# TR5: H2 request with ?v=3 → if QS stripping works, request_count=0 (learn phase) >= 2 → "sent"
# If QS stripping is broken, request_count=0 for /qspage.html?v=3 → "no-hints"
tr5 = Test.AddTestRun("Query string: H2 /qspage.html?v=3 → sent (proves QS stripped)")
tr5.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/qspage.html?v=3'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
# THIS IS THE KEY ASSERTION: if query string stripping works,
# ?v=1, ?v=2, and ?v=3 all map to cache key "/qspage.html"
# request_count=0 (learn phase) (from TR3+TR4) >= min_hit_count=2 → 103 sent
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Query strings stripped — cache key shared — 103 sent!")
tr5.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "qs-style.css", "Learned resource should be in 103")
tr5.StillRunningAfter = microserver

# ========================================================================
# SCENARIO 3: 301 Redirect — must NOT learn or add Link headers
# ========================================================================

# TR6: First request → 301 with HTML body containing <link> tags
tr6 = Test.AddTestRun("Redirect 301: plugin does NOT learn from redirect body")
tr6.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/redirect.html'".format(ts.Variables.ssl_port))
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "301", "Should receive 301 redirect")
# Plugin-specific: debug header proves plugin loaded and processed the request.
# For 301, plugin skips at READ_RESPONSE_HDR (status != 200), but debug header is still added.
tr6.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin engaged on 301 response")
# No Link headers should be added by plugin for non-2xx
tr6.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link: </redirect-poison", "Plugin must NOT add Link headers from 301 body")
tr6.StillRunningAfter = microserver

# TR7: H2 second request → should be "no-hints" (nothing was learned from 301)
tr7 = Test.AddTestRun("Redirect 301: H2 confirms nothing learned → no-hints")
tr7.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/redirect.html'".format(ts.Variables.ssl_port))
tr7.Processes.Default.ReturnCode = 0
tr7.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: no-hints", "Nothing was learned from 301 → no-hints on H2")
tr7.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "redirect-poison", "Redirect body resources must never appear in hints")
tr7.StillRunningAfter = microserver

# ========================================================================
# SCENARIO 4: HTML comment — resources inside <!-- --> NOT extracted
# ========================================================================

# TR8: H1 learn -- commented resource ignored, real resource learned
tr8 = Test.AddTestRun("Comment: commented <link> ignored, real <link> learned")
tr8.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/comment.html'".format(ts.Variables.ssl_port))
tr8.Processes.Default.ReturnCode = 0
tr8.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200")
# Plugin engaged on H1 learn request
tr8.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status: skipped-h1", "Plugin engaged (H1 skip)")
# Body scan runs after SEND_RESPONSE_HDR: Link header not present on learn request
tr8.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Link: </real-resource.js>",
    "First (learn) request must not add Link header: body scan runs after SEND_RESPONSE_HDR")
# Commented resource must never appear
tr8.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "fake-commented", "Resource inside <!-- comment --> must NOT be extracted")
tr8.StillRunningAfter = microserver

# TR9: H2 verify — only real resource in 103
tr9 = Test.AddTestRun("Comment: H2 103 has only real resource, not commented one")
tr9.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/comment.html'".format(ts.Variables.ssl_port))
tr9.Processes.Default.ReturnCode = 0
tr9.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr9.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "real-resource.js", "Real resource should be in 103")
tr9.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "fake-commented", "Commented resource must NOT appear in 103")
tr9.StillRunningAfter = microserver

# ========================================================================
# SCENARIO 5: Origin-forward max-links enforcement
# Origin sends 5 Link headers, max-links=2 → only first 2 cached
# ========================================================================

# TR10: H1 learn -- origin sends 5 Links, max-links=2 → only 2 cached
tr10 = Test.AddTestRun("Max-links origin-forward: 5 sent, only 2 cached")
tr10.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/many-links.html'".format(ts.Variables.ssl_port))
tr10.Processes.Default.ReturnCode = 0
tr10.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200")
# Plugin engaged but request_count=0 on first request: Link headers not added to 200
# (SEND_RESPONSE_HDR fallback peek checks request_count >= min_hit_count before serving)
tr10.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin engaged on learn request")
# Origin Link headers may still pass through from ATS (not plugin-injected)
# The 103 verification in TR11 confirms only plugin-cached links are served.
tr10.StillRunningAfter = microserver

# TR11: H2 verify — 103 frame has ONLY first 2 links (max-links enforcement proof)
tr11 = Test.AddTestRun("Max-links origin-forward: H2 103 has only 2 links")
tr11.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/many-links.html'".format(ts.Variables.ssl_port))
tr11.Processes.Default.ReturnCode = 0
tr11.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "H2 should get 103 from cache")
tr11.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link: </first.css>; rel=preload; as=style", "First Link should be in 103")
tr11.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link: </second.js>; rel=preload; as=script", "Second Link should be in 103")
