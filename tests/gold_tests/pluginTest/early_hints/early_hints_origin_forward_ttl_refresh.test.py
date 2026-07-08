'''
Test 103 Early Hints plugin -- origin-forward TTL refresh from ATS cache
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
Test HTTP 103 Early Hints plugin origin-forward TTL refresh via touch().
Verifies that when a hints entry is stale (age > hints-ttl) but the ATS
cache is still fresh (READ_CACHE_HDR fires), the plugin calls touch() to
reset last_updated, exactly mirroring auto-learn stale behaviour.

Sequence:
  TR1: H1 GET  -- origin fetch, Link extracted, entry created (rc=0)
  TR2: H2 GET  -- ATS cache hit, rc 0->1 >= 1, 103 sent (fresh entry)
  sleep 3s     -- hints entry becomes stale (hints-ttl=2), ATS cache still live
  TR3: H2 GET  -- ATS cache hit, entry stale (needs_relearn=true, has_learned=true)
                  READ_CACHE_HDR fires origin-forward touch() path, 103 still sent
  TR4: H2 GET  -- entry fresh again (touch reset last_updated), 103 served
  (origin contact count must remain 1 -- no re-fetches after TR1)
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_origin_forward_ttl_refresh"
Test.ContinueOnFail = True

microserver = Test.MakeOriginServer("microserver")

microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /page.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n"
            "Link: </style.css>; rel=preload; as=style\r\n"
            "Cache-Control: max-age=60\r\n\r\n",
        "body": "<html><body>Origin-forward TTL refresh test</body></html>\r\n"
    })

ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=True)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

ts.Disk.remap_config.AddLines([
    'map https://127.0.0.1:{0}/ http://127.0.0.1:{1}/'.format(
        ts.Variables.ssl_port, microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=origin-forward'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--hints-ttl @pparam=2'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status',
])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 8,
})

# TR1: H1 origin fetch -- Link extracted, entry created (rc=0, not yet serving)
tr1 = Test.AddTestRun("TR1: H1 origin fetch -- Link extracted, entry created")
tr1.Processes.Default.Command = (
    "curl -s -D - -o /dev/null"
    " --http1.1 --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr1.Processes.Default.StartBefore(ts)
tr1.Processes.Default.Streams.stdout.Content = Testers.ExcludesExpression(
    "x-early-hints-status: sent", "H1 must not receive 103")
tr1.StillRunningAfter = microserver

# TR2: H2 ATS cache hit -- rc 0->1, 103 served (entry fresh, age < hints-ttl=2s)
tr2 = Test.AddTestRun("TR2: H2 ATS cache hit -- 103 served (entry fresh)")
tr2.Processes.Default.Command = (
    "curl -s -D -"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "103 must be sent while entry is fresh")
tr2.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:.*rel=preload.*as=style", "103 must carry the style preload link")
tr2.StillRunningAfter = microserver

# sleep 3s: hints-ttl=2 expires, ATS cache still fresh (max-age=60)
tr_sleep = Test.AddTestRun("sleep 3s -- hints TTL expires, ATS cache remains live")
tr_sleep.Processes.Default.Command = "sleep 3"
tr_sleep.Processes.Default.ReturnCode = 0

# TR3: H2 ATS cache hit -- entry stale (needs_relearn=true)
#      READ_CACHE_HDR fires origin-forward touch() path: TTL reset, 103 still served (SWR)
tr3 = Test.AddTestRun("TR3: H2 ATS cache hit -- stale entry, touch() fires, 103 still served")
tr3.Processes.Default.Command = (
    "curl -s -D -"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "103 must still be sent on stale+ATS-cache-hit (SWR)")
tr3.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:.*rel=preload.*as=style", "same style link must still appear in 103")
tr3.StillRunningAfter = microserver

# TR4: H2 ATS cache hit -- entry fresh again after touch() reset last_updated in TR3
tr4 = Test.AddTestRun("TR4: H2 ATS cache hit -- entry fresh after touch(), 103 served")
tr4.Processes.Default.Command = (
    "curl -s -D -"
    " --http2 --insecure"
    " 'https://127.0.0.1:{0}/page.html'".format(ts.Variables.ssl_port))
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent", "103 must be sent after touch() refreshed TTL")
tr4.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "link:.*rel=preload.*as=style", "link header must still be correct after TTL refresh")
tr4.StillRunningAfter = microserver
