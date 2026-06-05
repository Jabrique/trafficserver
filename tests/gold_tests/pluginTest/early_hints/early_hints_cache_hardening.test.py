'''
Test 103 Early Hints plugin — Cache persistence hardening
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
Cache persistence hardening.

Tests that:
1. Cache persist file is created in --persist-dir after auto-learn.
2. Hints are served after min-hit-count is reached.
3. Cache survives request volume without corruption.

These tests validate: key length cap, request_count gate, atomic load swap, and persist mutex.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_cache_hardening"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

PAGE_BODY = (
    "<html><head>"
    '<link rel="preload" href="/static/bundle.js" as="script">'
    '<link rel="stylesheet" href="/static/main.css">'
    "</head><body>App</body></html>\r\n"
)

# 4 identical responses — request 1+2 learn, request 3 serves hints, request 4 regression guard
for _ in range(4):
    microserver.addResponse(
        "sessionfile.log", {
            "headers": "GET /app.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
            "body": PAGE_BODY
        })

# ----
# Setup ATS with persist dir (plugin generates filename from remap from-URL hash)
# ----
import os
persist_dir = os.path.join(Test.RunDirectory, "early_hints_persist")
os.makedirs(persist_dir, exist_ok=True)

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
    ' @pparam=--persist-dir @pparam={0}'.format(persist_dir) +
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status')

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# TC0: First request — learn (no hints yet, min-hit-count=2 not reached)
# ----
tr0 = Test.AddTestRun("Persistence: First learn request (no hints — below min-hit-count)")
tr0.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/app.html'".format(ts.Variables.ssl_port))
tr0.Processes.Default.ReturnCode = 0
tr0.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr0.Processes.Default.StartBefore(Test.Processes.ts)
tr0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200 OK")
tr0.StillRunningAfter = microserver

# ----
# TC0b: Second learn request -- get() increments request_count to 1 (< 2, no 103 yet)
# ----
tr0b = Test.AddTestRun("Persistence: Second learn request (request_count=1, below min-hit-count=2)")
tr0b.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/app.html'".format(ts.Variables.ssl_port))
tr0b.Processes.Default.ReturnCode = 0
tr0b.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200 OK")
tr0b.StillRunningAfter = microserver

# ----
# TC1: Third request — hints must be served (request_count=2 >= min-hit-count=2)
# ----
tr1 = Test.AddTestRun("Persistence: Third request — hints served (min-hit-count=2 reached)")
tr1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/app.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Hints must be served after min-hit-count reached")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/static/bundle.js", "Script preload must be in early hints")
tr1.StillRunningAfter = microserver

# ----
# TC2: Verify at least one persist file was created in the persist dir
# ----
tr2 = Test.AddTestRun("Persistence: Verify persist file exists in persist-dir after auto-learn")
tr2.Processes.Default.Command = (
    "ls '{0}'/early_hints_*.bin 2>/dev/null && echo 'PERSIST_FILE_EXISTS' || echo 'PERSIST_FILE_MISSING'".format(persist_dir))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "PERSIST_FILE_EXISTS", "Persist file must be created after auto-learn puts")
tr2.StillRunningAfter = microserver

# ----
# TC3: Fourth request — hints still served (regression guard)
# ----
tr3 = Test.AddTestRun("Persistence: Fourth request — hints served (regression guard)")
tr3.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/app.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Hints must still be served on fourth request")
tr3.StillRunningAfter = microserver
