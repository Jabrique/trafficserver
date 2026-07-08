'''
Test 103 Early Hints plugin  -- noscript and template content isolation
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
Validates that the scanner does not extract resource hints from inside
<noscript> or <template> elements, but continues to extract hints that
appear after those elements in the normal <head> flow.

<noscript> contains fallback HTML for when JavaScript is disabled. The
browser ignores it when JS is on, so preloading its resources wastes
bandwidth and can poison the hint cache from attacker-controlled content.

<template> contains inert DOM that is never rendered or fetched on load.
Resources inside it must not be pre-fetched via Early Hints.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_noscript_template"
Test.ContinueOnFail = True

microserver = Test.MakeOriginServer("microserver")

# Page with link inside noscript only  -- no real hints
NOSCRIPT_ONLY_PAGE = (
    "<html><head>"
    '<noscript><link rel="stylesheet" href="/noscript.css"></noscript>'
    "</head><body>No real hints</body></html>\r\n"
)

# Page with link inside noscript AND a real preload after it
NOSCRIPT_PLUS_REAL_PAGE = (
    "<html><head>"
    '<noscript><link rel="preload" href="/noscript.js" as="script"></noscript>'
    '<link rel="preload" href="/real.js" as="script">'
    "</head><body>Mixed</body></html>\r\n"
)

# Page with link inside template only  -- no real hints
TEMPLATE_ONLY_PAGE = (
    "<html><head>"
    '<template><link rel="preload" href="/template.js" as="script"></template>'
    "</head><body>No real hints</body></html>\r\n"
)

for _ in range(3):
    microserver.addResponse(
        "sessionfile.log",
        {"headers": "GET /noscript_only.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "body": ""},
        {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", "body": NOSCRIPT_ONLY_PAGE})

for _ in range(3):
    microserver.addResponse(
        "sessionfile.log",
        {"headers": "GET /noscript_plus_real.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "body": ""},
        {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", "body": NOSCRIPT_PLUS_REAL_PAGE})

for _ in range(3):
    microserver.addResponse(
        "sessionfile.log",
        {"headers": "GET /template_only.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "body": ""},
        {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", "body": TEMPLATE_ONLY_PAGE})

ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}/'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=2'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
})

# -- TC0/1: Learn noscript-only page twice, verify no 103 sent --------------
tr0 = Test.AddTestRun("noscript-template: Learn noscript-only (1)")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/noscript_only.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK")
tr0.StillRunningAfter = microserver

tr0b = Test.AddTestRun("noscript-template: Learn noscript-only (2)")
tr0b.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/noscript_only.html'".format(ts.Variables.ssl_port))
tr0b.Processes.Default.ReturnCode = 0
tr0b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK")
tr0b.StillRunningAfter = microserver

tr1 = Test.AddTestRun("noscript-template: noscript-only page must NOT produce 103 hints")
tr1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/noscript_only.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
# No x-early-hints-status: sent  -- scanner must have found no learnable links
tr1.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "x-early-hints-status: sent", "no 103 should be sent for noscript-only page")
tr1.StillRunningAfter = microserver

# -- TC2/3: Mixed page  -- only real preload after noscript is extracted -------
tr2 = Test.AddTestRun("noscript-template: Learn mixed noscript+real (1)")
tr2.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/noscript_plus_real.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK")
tr2.StillRunningAfter = microserver

tr2b = Test.AddTestRun("noscript-template: Learn mixed noscript+real (2)")
tr2b.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/noscript_plus_real.html'".format(ts.Variables.ssl_port))
tr2b.Processes.Default.ReturnCode = 0
tr2b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK")
tr2b.StillRunningAfter = microserver

tr3 = Test.AddTestRun("noscript-template: mixed page sends 103 only for post-noscript link")
tr3.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/noscript_plus_real.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "103 must be sent for mixed page")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/real.js", "real.js must appear in 103 Link header")
tr3.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "noscript.js", "noscript.js must NOT appear in 103 Link header")
tr3.StillRunningAfter = microserver

# -- TC4/5: Template-only page  -- no hints extracted --------------------------
tr4 = Test.AddTestRun("noscript-template: Learn template-only (1)")
tr4.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/template_only.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK")
tr4.StillRunningAfter = microserver

tr4b = Test.AddTestRun("noscript-template: Learn template-only (2)")
tr4b.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/template_only.html'".format(ts.Variables.ssl_port))
tr4b.Processes.Default.ReturnCode = 0
tr4b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "200 OK")
tr4b.StillRunningAfter = microserver

tr5 = Test.AddTestRun("noscript-template: template-only page must NOT produce 103 hints")
tr5.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null --http2 --insecure "
    "'https://127.0.0.1:{0}/template_only.html'".format(ts.Variables.ssl_port))
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "x-early-hints-status: sent", "no 103 should be sent for template-only page")
tr5.StillRunningAfter = microserver
