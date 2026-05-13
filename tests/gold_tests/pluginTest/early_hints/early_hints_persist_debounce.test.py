'''
Test 103 Early Hints plugin — Cache Persistence Debounce
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
Cache persistence end-to-end regression guard.

Bug: HintsCache::put() calls persist_to_disk() on every put() call,
even when the new links are identical to what is already stored.
Fix: equality-check debounce — only persist when content changes.

Gold test verifies:
  - With --persist-dir, a persist .bin file is created after warm-up.
  - After repeated identical hits, the file remains valid (not corrupted).
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_persist_debounce"
Test.ContinueOnFail = True

import os

# Use Test.RunDirectory which autest always provides
persist_dir = os.path.join(Test.RunDirectory, "eh_persist")

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

for _ in range(6):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers":
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
                "Link: </cdn/app.js>; rel=preload; as=script\r\n"
                "\r\n",
            "body": "<html><body>Test page</body></html>\r\n"
        })

# ----
# Setup ATS — origin-forward mode with --persist-dir
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

remap_line = (
    'map / http://127.0.0.1:{port}/'
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--max-links @pparam=5'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--persist-dir @pparam={pdir}'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status').format(
        port=microserver.Variables.Port, pdir=persist_dir)

ts.Disk.remap_config.AddLine(remap_line)

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': ts.Variables.SSLDir,
    'proxy.config.ssl.server.private_key.path': ts.Variables.SSLDir,
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# TC0: Create persist dir before ATS starts, learn first request
# ----
tr0 = Test.AddTestRun("Persistence: Create persist dir and learn phase")
tr0.Processes.Default.Command = (
    "mkdir -p {pdir}"
    " && curl -s -D - -o /dev/null --http2 --insecure"
    " 'https://127.0.0.1:{port}/page.html'").format(
        pdir=persist_dir, port=ts.Variables.ssl_port)
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr0.StillRunningAfter = microserver

# ----
# TC1: Second request — cached hint served as 103
# ----
tr1 = Test.AddTestRun("Persistence: Second request receives 103 with cached hint")
tr1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{port}/page.html'").format(port=ts.Variables.ssl_port)
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Hint must be served as 103 after warm-up")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn/app.js", "app.js hint must appear in 103")
tr1.StillRunningAfter = microserver

# ----
# TC2: Persist .bin file must exist in persist_dir after warm-up
# The plugin names the file early_hints_<hash>.bin
# ----
tr2 = Test.AddTestRun("Persistence: Persist .bin file created in persist_dir")
tr2.Processes.Default.Command = (
    "sleep 1"
    " && ls {pdir}/early_hints_*.bin 2>/dev/null | grep -q early_hints"
    " && echo 'persist-file-ok'").format(pdir=persist_dir)
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "persist-file-ok", "early_hints_*.bin must be created in persist_dir")
tr2.StillRunningAfter = microserver

# ----
# TC3: Repeated identical hits — persist file stays non-empty
# ----
tr3 = Test.AddTestRun("Persistence: Persist file valid after repeated identical hits")
tr3.Processes.Default.Command = (
    "for i in $$(seq 1 4); do"
    " curl -s -D - -o /dev/null --http2 --insecure"
    " 'https://127.0.0.1:{port}/page.html' > /dev/null ; done"
    " && BIN=$$(ls {pdir}/early_hints_*.bin 2>/dev/null | head -1)"
    " && test -n \"$$BIN\" && test -s \"$$BIN\""
    " && echo 'debounce-ok'").format(port=ts.Variables.ssl_port, pdir=persist_dir)
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "debounce-ok", "persist file must remain valid after repeated identical hits")
tr3.StillRunningAfter = microserver
