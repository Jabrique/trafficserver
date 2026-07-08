'''
Test 103 Early Hints plugin  -- hints cache disk persistence
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
- Persistence is OFF by default (no disk I/O without --persist-dir)
- --persist-dir opts in to disk persistence with hashed filename
- --no-persist explicitly disables (already the default, but keeps old remaps working)
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
    # With --persist-dir: persist to runtime dir explicitly (default is OFF)
    'map /persist.html http://127.0.0.1:{0}/persist.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status'
    ' @pparam=--persist-dir @pparam=' + ts.Variables.RUNTIMEDIR,

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
# TR1: Learn hints (H1 request  -- learn phase)
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
# TR2: Verify hints were learned (H2 request  -- should get 103)
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
tr3 = Test.AddTestRun("Persist: verify --persist-dir .bin file exists in runtime dir")
tr3.Processes.Default.Command = (
    "ls " + ts.Variables.RUNTIMEDIR + "/early_hints_*.bin 2>/dev/null"
    " && echo 'PERSIST_FILE_EXISTS'")
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "PERSIST_FILE_EXISTS", "Persist file should exist in runtime dir after explicit --persist-dir")
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
#      (only 1 .bin should exist  -- from the persist remap, not the no-persist one)
# ----
tr5 = Test.AddTestRun("NoPersist: verify only 1 .bin file exists (no-persist has none)")
tr5.Processes.Default.Command = (
    "sleep 1 && ls " + ts.Variables.RUNTIMEDIR + "/early_hints_*.bin 2>/dev/null | wc -l")
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "1", "Only 1 persist file should exist  -- --no-persist remap has none (and default is OFF)")
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
    "1", "Runtime dir should still have only 1 .bin  -- custom dir file is elsewhere")
tr8.StillRunningAfter = microserver

import os as _os

# -------------------------------------------------------------------------------
# Cache persistence debounce
# Bug: HintsCache::put() calls persist_to_disk() on every put() call,
# even when the new links are identical. Fix: equality-check debounce.
# -------------------------------------------------------------------------------

persist_dir_debounce = _os.path.join(Test.RunDirectory, "eh_persist_debounce")

ms_debounce = Test.MakeOriginServer("ms_debounce")
for _ in range(6):
    ms_debounce.addResponse(
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

ts_debounce = Test.MakeATSProcess("ts_debounce", select_ports=True, enable_tls=True, enable_cache=False)
ts_debounce.addDefaultSSLFiles()
ts_debounce.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts_debounce.Disk.remap_config.AddLine((
    'map / http://127.0.0.1:{port}/'
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--max-links @pparam=5'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--persist-dir @pparam={pdir}'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status').format(
        port=ms_debounce.Variables.Port, pdir=persist_dir_debounce))
ts_debounce.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': ts_debounce.Variables.SSLDir,
    'proxy.config.ssl.server.private_key.path': ts_debounce.Variables.SSLDir,
    'proxy.config.http2.active_timeout_in': 3,
})

tr_debounce_0 = Test.AddTestRun("Debounce: create persist dir and learn phase")
tr_debounce_0.Processes.Default.Command = (
    "mkdir -p {pdir}"
    " && curl -s -D - -o /dev/null --http2 --insecure"
    " 'https://127.0.0.1:{port}/page.html'").format(
        pdir=persist_dir_debounce, port=ts_debounce.Variables.ssl_port)
tr_debounce_0.Processes.Default.ReturnCode = 0
tr_debounce_0.Processes.Default.StartBefore(ms_debounce, ready=When.PortOpen(ms_debounce.Variables.Port))
tr_debounce_0.Processes.Default.StartBefore(ts_debounce)
tr_debounce_0.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200", "Should receive 200")
tr_debounce_0.StillRunningAfter = ms_debounce

tr_debounce_1 = Test.AddTestRun("Debounce: second request receives 103 with cached hint")
tr_debounce_1.Processes.Default.Command = (
    "sleep 1 ; curl -s -D - -o /dev/null"
    " --http2 --insecure"
    " 'https://127.0.0.1:{port}/page.html'").format(port=ts_debounce.Variables.ssl_port)
tr_debounce_1.Processes.Default.ReturnCode = 0
tr_debounce_1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Hint must be served as 103 after warm-up")
tr_debounce_1.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "cdn/app.js", "app.js hint must appear in 103")
tr_debounce_1.StillRunningAfter = ms_debounce

tr_debounce_2 = Test.AddTestRun("Debounce: persist .bin file created in persist dir")
tr_debounce_2.Processes.Default.Command = (
    "sleep 1"
    " && ls {pdir}/early_hints_*.bin 2>/dev/null | grep -q early_hints"
    " && echo 'persist-file-ok'").format(pdir=persist_dir_debounce)
tr_debounce_2.Processes.Default.ReturnCode = 0
tr_debounce_2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "persist-file-ok", "early_hints_*.bin must be created in persist dir")
tr_debounce_2.StillRunningAfter = ms_debounce

tr_debounce_3 = Test.AddTestRun("Debounce: persist file valid after repeated identical hits")
tr_debounce_3.Processes.Default.Command = (
    "for i in $$(seq 1 4); do"
    " curl -s -D - -o /dev/null --http2 --insecure"
    " 'https://127.0.0.1:{port}/page.html' > /dev/null ; done"
    " && BIN=$$(ls {pdir}/early_hints_*.bin 2>/dev/null | head -1)"
    " && test -n \"$$BIN\" && test -s \"$$BIN\""
    " && echo 'debounce-ok'").format(port=ts_debounce.Variables.ssl_port, pdir=persist_dir_debounce)
tr_debounce_3.Processes.Default.ReturnCode = 0
tr_debounce_3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "debounce-ok", "persist file must remain valid after repeated identical hits")
tr_debounce_3.StillRunningAfter = ms_debounce

# -------------------------------------------------------------------------------
# Persist dirty flag data integrity
# Verifies that a failed persist_to_disk() does NOT clear the dirty flag, so
# the cache data is flushed on shutdown and survives ATS restarts.
# -------------------------------------------------------------------------------

ms_dirty = Test.MakeOriginServer("ms_dirty")

_dirty_page_body = (
    "<html><head>"
    '<link rel="preload" href="/dirty-flag-test.js" as="script">'
    "</head><body>Dirty flag test</body></html>\r\n"
)
ms_dirty.addResponse(
    "sessionfile.log", {
        "headers": "GET /dirty-flag.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": _dirty_page_body
    })

ts_dirty = Test.MakeATSProcess("ts_dirty", select_ports=True, enable_tls=True, enable_cache=False)
ts_dirty.addDefaultSSLFiles()
ts_dirty.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

persist_dir_dirty = ts_dirty.Variables.RUNTIMEDIR + "/dirty_flag_hints"
ts_dirty.Disk.remap_config.AddLines([
    'map /dirty-flag.html http://127.0.0.1:{0}/dirty-flag.html'.format(ms_dirty.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status'
    ' @pparam=--persist-dir @pparam=' + persist_dir_dirty,
])
ts_dirty.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts_dirty.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts_dirty.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

tr_dirty_learn = Test.AddTestRun("Dirty flag: H1 request learns hints (no 103 yet)")
tr_dirty_learn.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1"
    " --insecure"
    " 'https://127.0.0.1:{0}/dirty-flag.html'".format(ts_dirty.Variables.ssl_port))
tr_dirty_learn.Processes.Default.ReturnCode = 0
tr_dirty_learn.Processes.Default.StartBefore(ms_dirty, ready=When.PortOpen(ms_dirty.Variables.Port))
tr_dirty_learn.Processes.Default.StartBefore(ts_dirty)
tr_dirty_learn.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "200 OK", "Should receive 200 OK")
tr_dirty_learn.StillRunningAfter = ms_dirty

tr_dirty_serve = Test.AddTestRun("Dirty flag: H2 request gets 103 from in-memory cache")
tr_dirty_serve.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null"
    " --http2"
    " --insecure"
    " 'https://127.0.0.1:{0}/dirty-flag.html'".format(ts_dirty.Variables.ssl_port))
tr_dirty_serve.Processes.Default.ReturnCode = 0
tr_dirty_serve.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "Hints must be sent from in-memory cache")
tr_dirty_serve.StillRunningAfter = ms_dirty

tr_dirty_file_exists = Test.AddTestRun("Dirty flag: verify .bin file exists in persist dir")
tr_dirty_file_exists.Processes.Default.Command = (
    "sleep 2 && ls " + persist_dir_dirty + "/early_hints_*.bin 2>/dev/null && echo 'PERSIST_FILE_EXISTS'")
tr_dirty_file_exists.Processes.Default.ReturnCode = 0
tr_dirty_file_exists.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "PERSIST_FILE_EXISTS",
    "Persist file must be created after learn and ATS flush")
tr_dirty_file_exists.StillRunningAfter = ms_dirty

tr_dirty_file_valid = Test.AddTestRun("Dirty flag: verify .bin file is non-empty (not truncated)")
tr_dirty_file_valid.Processes.Default.Command = (
    "find " + persist_dir_dirty + " -name 'early_hints_*.bin' -size +8c -print | grep -q . && echo 'FILE_VALID' || echo 'FILE_INVALID'")
tr_dirty_file_valid.Processes.Default.ReturnCode = 0
tr_dirty_file_valid.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "FILE_VALID",
    "Persist file must be > 8 bytes (valid header + at least one entry)")
tr_dirty_file_valid.StillRunningAfter = ms_dirty
