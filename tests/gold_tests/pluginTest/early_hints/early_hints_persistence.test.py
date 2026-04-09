'''
Test 103 Early Hints plugin — hints cache disk persistence
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
Test HTTP 103 Early Hints plugin hints cache persistence.
Verifies:
- Persistence is ON by default (auto-persist to runtime dir)
- File is auto-created after auto-learn with hashed filename
- --no-persist disables persistence
- --persist-dir allows custom directory
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_persistence"
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
microserver = Test.MakeOriginServer("microserver")

# HTML page with preloadable resources
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /persist.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/persist-style.css\" as=\"style\">"
            "<script src=\"/persist-app.js\"></script>"
            "</head><body>Persistence test</body></html>\r\n"
    })

# Same page for the no-persist test
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /nopersist.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/nopersist-style.css\" as=\"style\">"
            "</head><body>No persist test</body></html>\r\n"
    })

# Page for --persist-dir custom directory test
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /customdir.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body":
            "<html><head>"
            "<link rel=\"preload\" href=\"/custom-style.css\" as=\"style\">"
            "</head><body>Custom dir test</body></html>\r\n"
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    # Default persistence (ON by default): hints auto-persist to runtime dir
    'map /persist.html http://127.0.0.1:{0}/persist.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',

    # With --no-persist: hints will NOT be persisted
    'map /nopersist.html http://127.0.0.1:{0}/nopersist.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status'
    ' @pparam=--no-persist',

    # With --persist-dir: custom directory for persistence file
    'map /customdir.html http://127.0.0.1:{0}/customdir.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status'
    ' @pparam=--persist-dir @pparam=' + ts.Variables.RUNTIMEDIR + '/custom_hints',
])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# ----
# TR1: Learn hints (H1 request — learn phase)
# ----
tr1 = Test.AddTestRun("Persist: H1 learn request triggers auto-learn")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/persist.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(Test.Processes.ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage and learn")
tr1.StillRunningAfter = microserver

# ----
# TR2: Verify hints were learned (H2 request — should get 103)
# ----
tr2 = Test.AddTestRun("Persist: H2 request gets 103 from learned hints")
tr2.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/persist.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Hints should be sent from cache")
tr2.StillRunningAfter = microserver

# ----
# TR3: Verify auto-persist file was created in runtime dir
# ----
tr3 = Test.AddTestRun("Persist: verify auto-persist .bin file exists in runtime dir")
tr3.Processes.Default.Command = (
    "ls " + ts.Variables.RUNTIMEDIR + "/early_hints_*.bin 2>/dev/null"
    " && echo 'PERSIST_FILE_EXISTS'")
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "PERSIST_FILE_EXISTS", "Auto-persist file should exist in runtime dir after auto-learn")
tr3.StillRunningAfter = microserver

# ----
# TR4: Also learn hints for the no-persist path
# ----
tr4 = Test.AddTestRun("NoPersist: H1 learn request")
tr4.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/nopersist.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr4.StillRunningAfter = microserver

# ----
# TR5: Verify --no-persist did NOT create a second .bin file
#      (only 1 .bin should exist — from the persist remap, not the no-persist one)
# ----
tr5 = Test.AddTestRun("NoPersist: verify only 1 .bin file exists (no-persist has none)")
tr5.Processes.Default.Command = (
    "sleep 1 && ls " + ts.Variables.RUNTIMEDIR + "/early_hints_*.bin 2>/dev/null | wc -l")
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "1", "Only 1 persist file should exist — --no-persist remap has none")
tr5.StillRunningAfter = microserver

# ----
# TR6: Learn hints for the --persist-dir custom directory path
# ----
tr6 = Test.AddTestRun("PersistDir: H1 learn request with custom directory")
tr6.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/customdir.html'".format(ts.Variables.ssl_port))
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr6.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "X-Early-Hints-Status:", "Plugin should engage and learn")
tr6.StillRunningAfter = microserver

# ----
# TR7: Verify --persist-dir created .bin file in custom directory
# ----
tr7 = Test.AddTestRun("PersistDir: verify .bin file in custom_hints directory")
tr7.Processes.Default.Command = (
    "sleep 1 && ls " + ts.Variables.RUNTIMEDIR + "/custom_hints/early_hints_*.bin 2>/dev/null"
    " && echo 'CUSTOM_DIR_FILE_EXISTS'")
tr7.Processes.Default.ReturnCode = 0
tr7.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "CUSTOM_DIR_FILE_EXISTS", "Persist file should exist in custom_hints subdirectory")
tr7.StillRunningAfter = microserver

# ----
# TR8: Verify runtime dir still has only 1 .bin (custom-dir one is elsewhere)
# ----
tr8 = Test.AddTestRun("PersistDir: runtime dir still has only 1 .bin")
tr8.Processes.Default.Command = (
    "ls " + ts.Variables.RUNTIMEDIR + "/early_hints_*.bin 2>/dev/null | wc -l")
tr8.Processes.Default.ReturnCode = 0
tr8.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "1", "Runtime dir should still have only 1 .bin — custom dir file is elsewhere")
tr8.StillRunningAfter = microserver
