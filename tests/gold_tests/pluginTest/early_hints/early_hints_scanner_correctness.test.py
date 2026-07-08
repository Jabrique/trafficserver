'''
Test 103 Early Hints plugin  -- HTML scanner correctness fixes

Covers four scanner bugs found in html_scanner.cc:

  In "script data escaped" state (after <!--), </script> does NOT
        close the script element. Per HTML spec §13.2.6.4 it should.
        Result: content after the second </script> is never scanned.

  After the close-tag name (e.g. </script), carriage-return (\\r)
        is valid HTML whitespace but was missing from the separator list.
        </script\\r> failed to close the script, consuming content after it.

  finish_attr() overwrites attribute values on every call (last-wins).
        Per HTML spec §13.1.2.3 the first occurrence wins; subsequent
        duplicate attribute names must be ignored.

  crossorigin="garbage" is not one of the two valid keywords.
        Per HTML spec §2.5.3, any unrecognised value maps to "anonymous".
        The raw lowercased value was leaked into the Link header.

These tests FAIL before the fix and PASS after the fix.
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
Scanner correctness: </script> in escaped mode, \\r separator,
first-wins duplicate attrs (HTML spec §13.1.2.3), crossorigin normalization (HTML spec §2.5.3).
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_scanner_correctness"
Test.ContinueOnFail = True

# --- Origin server ------------------------------------------------------------
ms = Test.MakeOriginServer("ms")

# script_escaped mode  -- </script> must close the script.
# The <script><!-- inline </script> enters escaped mode after <!--.
# Before fix: </script> is ignored in escaped mode → /after-b06.css never scanned.
# After fix:  </script> closes the script → /after-b06.css is scanned & preloaded.
_b06_body = (
    "<html><head>"
    "<script><!-- inline content </script>"
    "<link rel=\"stylesheet\" href=\"/after-b06.css\">"
    "</head><body>B-06</body></html>\r\n"
)
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /b06-escaped-close.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _b06_body
    })
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /b06-escaped-close.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _b06_body
    })

# </script\r>  -- carriage-return separator must close the script.
# Before fix: \r resets raw_close_pos_ → script never closed → /after-a06.css lost.
# After fix:  \r is a valid separator → script closed → /after-a06.css preloaded.
_a06_body = (
    "<html><head>"
    "<script src=\"/x-a06.js\"></script\r>"
    "<link rel=\"stylesheet\" href=\"/after-a06.css\">"
    "</head><body>A-06</body></html>\r\n"
)
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a06-cr-separator.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a06_body
    })
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a06-cr-separator.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a06_body
    })

# Duplicate href attribute  -- first value must win.
# href="/first-a28.css" then href="/second-a28.css"  -- scanner must use /first-a28.css.
# Before fix: last-wins → /second-a28.css in 103.
# After fix:  first-wins → /first-a28.css in 103.
_a28_body = (
    "<html><head>"
    "<link rel=\"preload\" href=\"/first-a28.css\" as=\"style\" href=\"/second-a28.css\">"
    "</head><body>A-28</body></html>\r\n"
)
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a28-first-wins.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a28_body
    })
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a28-first-wins.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a28_body
    })

# crossorigin="garbage" must normalize to anonymous in the Link header.
# Before fix: Link header contains crossorigin=garbage (raw value passed through).
# After fix:  Link header contains crossorigin=anonymous (normalized per HTML spec).
_a29_body = (
    "<html><head>"
    "<link rel=\"preload\" href=\"/font-a29.woff2\" as=\"font\""
    " crossorigin=\"garbage\">"
    "</head><body>A-29</body></html>\r\n"
)
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a29-crossorigin-norm.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a29_body
    })
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a29-crossorigin-norm.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a29_body
    })

# --- ATS: auto-learn mode (scans HTML response bodies) -----------------------
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(ms.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
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

# --- TC-B06-1: First request  -- learn the page (no 103 yet) ------------------
tr_b06_1 = Test.AddTestRun("Script-escaped mode: first request  -- scanner learns /after-b06.css from post-script link")
tr_b06_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/b06-escaped-close.html'".format(ts.Variables.ssl_port))
tr_b06_1.Processes.Default.ReturnCode = 0
tr_b06_1.Processes.Default.StartBefore(ms, ready=When.PortOpen(ms.Variables.Port))
tr_b06_1.Processes.Default.StartBefore(Test.Processes.ts)
tr_b06_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_b06_1.StillRunningAfter = ms

# --- TC-B06-2: Second request  -- 103 must include /after-b06.css -------------
# If </script> in escaped mode was not closing the script (escaped-mode bug),
# /after-b06.css would never have been scanned and no 103 is sent.
tr_b06_2 = Test.AddTestRun("Script-escaped mode: second request  -- 103 must contain /after-b06.css")
tr_b06_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/b06-escaped-close.html'".format(ts.Variables.ssl_port))
tr_b06_2.Processes.Default.ReturnCode = 0
tr_b06_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "103 should be sent  -- scanner must have learned /after-b06.css")
tr_b06_2.StillRunningAfter = ms

# --- First request  -- learn with </script\r> HTML ------------------
tr_a06_1 = Test.AddTestRun("First request  -- scanner learns /after-a06.css through </script\\r>")
tr_a06_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a06-cr-separator.html'".format(ts.Variables.ssl_port))
tr_a06_1.Processes.Default.ReturnCode = 0
tr_a06_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_a06_1.StillRunningAfter = ms

# --- Second request  -- 103 must include /after-a06.css -------------
# If </script\r> failed to close the script (CR-separator bug),
# /after-a06.css would be consumed inside the open script state.
# Note: /x-a06.js IS learned from the open tag regardless  -- so checking
# "sent" alone is insufficient. We must check the specific URL.
tr_a06_2 = Test.AddTestRun("CR separator: second request  -- 103 must contain /after-a06.css")
tr_a06_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a06-cr-separator.html'".format(ts.Variables.ssl_port))
tr_a06_2.Processes.Default.ReturnCode = 0
# The 103 body must include /after-a06.css  -- only possible if </script\r>
# correctly closed the script and exposed the subsequent <link> to the scanner.
# -o /dev/null discards the HTML body (which always contains "after-a06.css" text)
# so this assertion only matches the 103 Link header, not the body.
tr_a06_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "after-a06",
    "</script\r> must close script  -- /after-a06.css must appear in 103 Link header")
tr_a06_2.StillRunningAfter = ms

# --- First request  -- learn with duplicate href ---------------------
tr_a28_1 = Test.AddTestRun("Duplicate attr: first request  -- duplicate href, scanner must use first value")
tr_a28_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a28-first-wins.html'".format(ts.Variables.ssl_port))
tr_a28_1.Processes.Default.ReturnCode = 0
tr_a28_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_a28_1.StillRunningAfter = ms

# --- Second request  -- 103 must use /first-a28.css, not /second-a28.css
tr_a28_2 = Test.AddTestRun("Duplicate attr: second request  -- 103 must reference /first-a28.css (first-wins)")
tr_a28_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a28-first-wins.html'".format(ts.Variables.ssl_port))
tr_a28_2.Processes.Default.ReturnCode = 0
# -o /dev/null discards the HTML body. The body always contains BOTH /first-a28.css
# and /second-a28.css (as HTML attributes), so assertions must only match Link headers.
# Before fix (last-wins): 103 Link has </second-a28.css>  -- ContainsExpression("first-a28") FAILS.
# After fix (first-wins): 103 Link has </first-a28.css>  -- both assertions PASS.
tr_a28_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "first-a28",
    "103 Link header must contain /first-a28.css (first-wins rule)")
tr_a28_2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "second-a28",
    "/second-a28.css must NOT appear in 103 Link header  -- it is a duplicate attr value")
tr_a28_2.StillRunningAfter = ms

# --- First request  -- learn with crossorigin=garbage ----------------
tr_a29_1 = Test.AddTestRun("crossorigin normalization: first request  -- crossorigin=garbage font, scanner normalizes")
tr_a29_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a29-crossorigin-norm.html'".format(ts.Variables.ssl_port))
tr_a29_1.Processes.Default.ReturnCode = 0
tr_a29_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_a29_1.StillRunningAfter = ms

# --- Second request  -- 103 must have crossorigin=anonymous ----------
tr_a29_2 = Test.AddTestRun("crossorigin normalization: second request  -- 103 Link header must have crossorigin=anonymous, not garbage")
tr_a29_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D -"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a29-crossorigin-norm.html'".format(ts.Variables.ssl_port))
tr_a29_2.Processes.Default.ReturnCode = 0
tr_a29_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "crossorigin=anonymous",
    "103 must use crossorigin=anonymous after normalization")
tr_a29_2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "crossorigin=garbage",
    "crossorigin=garbage must not appear in Link header  -- must be normalized")
tr_a29_2.StillRunningAfter = ms

# --- font + preload-whitelist must NOT get crossorigin -----------------
# A separate ATS instance with --preload-whitelist fonts.example.com to test that
# the plugin respects admin no-cors intent for font preloads.
# Before fix: global auto-add at build_link_header() fires after preload-whitelist
#             clears crossorigin_value_, re-adding crossorigin=anonymous (wrong).
# After fix:  auto-add is in the same-origin branch only; preload-whitelist keeps
#             the cleared value and no crossorigin appears in the 103 Link header.

ms_a07 = Test.MakeOriginServer("ms_a07")

_a07_body = (
    "<html><head>"
    "<link rel=\"preload\" href=\"https://fonts.example.com/font.woff2\" as=\"font\">"
    "</head><body>A-07</body></html>\r\n"
)
ms_a07.addResponse(
    "sessionfile.log", {
        "headers": "GET /a07-font-preload-whitelist.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a07_body
    })
ms_a07.addResponse(
    "sessionfile.log", {
        "headers": "GET /a07-font-preload-whitelist.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _a07_body
    })

ts_a07 = Test.MakeATSProcess("ts_a07", select_ports=True, enable_tls=True, enable_cache=False)
ts_a07.addDefaultSSLFiles()
ts_a07.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts_a07.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(ms_a07.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--preload-whitelist @pparam=fonts.example.com'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')
ts_a07.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts_a07.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts_a07.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# --- First request  -- learn with preload-whitelist font --------------
tr_a07_1 = Test.AddTestRun(
    "Font preload whitelist: first request  -- scanner learns font from whitelisted origin")
tr_a07_1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a07-font-preload-whitelist.html'".format(ts_a07.Variables.ssl_port))
tr_a07_1.Processes.Default.ReturnCode = 0
tr_a07_1.Processes.Default.StartBefore(ms_a07, ready=When.PortOpen(ms_a07.Variables.Port))
tr_a07_1.Processes.Default.StartBefore(ts_a07)
tr_a07_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200", "Should receive 200 OK")
tr_a07_1.StillRunningAfter = ms_a07

# --- Second request  -- 103 must NOT contain crossorigin -------------
# preload-whitelist = no-cors mode.  crossorigin=anonymous must NOT appear.
# Before fix: bug re-adds crossorigin=anonymous after preload-whitelist clears it.
# After fix:  no crossorigin in 103 Link header.
tr_a07_2 = Test.AddTestRun(
    "Font preload whitelist: second request  -- 103 Link must NOT have crossorigin")
tr_a07_2.Processes.Default.Command = (
    "sleep 1 && curl -s -D -"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/a07-font-preload-whitelist.html'".format(ts_a07.Variables.ssl_port))
tr_a07_2.Processes.Default.ReturnCode = 0
# font.woff2 must appear in the 103 Link header (sent) but WITHOUT crossorigin
tr_a07_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "103 must be sent for the font preload")
tr_a07_2.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "crossorigin",
    "preload-whitelist font must NOT have crossorigin in 103 Link header")
tr_a07_2.StillRunningAfter = ms_a07
