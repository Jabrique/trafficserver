'''
Test 103 Early Hints plugin — persist file link validation on load

Verifies that links loaded from a persist file are re-validated before serving.
In the buggy version: invalid links (rel=prefetch) from disk are trusted blindly.
In the fixed version: each link is validated; invalid ones are logged as rejected.

Approach: pre-craft a persist .bin file containing 1 valid + 1 invalid (rel=prefetch)
link BEFORE ATS starts. The file is placed in the correct path using the same FNV-1a
64-bit hash the plugin computes from argv[0] (the remap from-URL).

Key assertion: ATS diags log must contain "rejecting invalid persisted link"
  - BUGGY code: absent (test FAILS = RED)
  - FIXED code: present (test PASSES = Green)
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may not
#  use this file except in compliance with the License.  You may
#  obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
#  implied.  See the License for the specific language governing
#  permissions and limitations under the License.

import os
import struct

Test.Summary = '''
Verify that links loaded from a persist file are validated before serving.
Invalid rel types (e.g. rel=prefetch) must be logged as rejected during load.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_persist_load_validation"
Test.ContinueOnFail = True

# ─── FNV-1a 64-bit hash (mirrors fnv1a_hash() in early_hints.cc) ─────────────
def fnv1a_64(s):
    h = 14695981039346656037
    for c in s.encode('utf-8'):
        h ^= c
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h

HINTS_CACHE_MAGIC = 0x45480002  # v2 format (includes last_updated per entry)

# ─── Setup origin ─────────────────────────────────────────────────────────────
microserver = Test.MakeOriginServer("microserver")

# Plain page — no <link> tags. Any hint served must come from the persist file.
microserver.addResponse(
    "sessionfile.log", {
        "headers": "GET /load-valid.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><body>Load validation test</body></html>\r\n"
    })

# ─── Setup ATS ────────────────────────────────────────────────────────────────
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

persist_dir = ts.Variables.RUNTIMEDIR + "/lv_hints"

# ATS normalizes a path-only from-URL (e.g. /load-valid.html) to 'http:///load-valid.html'
# when passing argv[0] to TSRemapNewInstance. This is consistent across all runs.
from_url = "http:///load-valid.html"
file_hash = fnv1a_64(from_url)
persist_filename = "early_hints_{:016x}.bin".format(file_hash)
persist_filepath = os.path.join(persist_dir, persist_filename)

ts.Disk.remap_config.AddLines([
    'map /load-valid.html http://127.0.0.1:{0}/load-valid.html'.format(microserver.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status'
    ' @pparam=--persist-dir @pparam=' + persist_dir,
])
ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http2.active_timeout_in': 3,
})

# KEY ASSERTION: the rejection message is logged at TSDebug (DIAG) level,
# which goes to traffic.out, not diags.log.
# In the BUGGY version: no validation → absent → FAILS (RED).
# In the FIXED version: invalid link rejected + logged → PASSES (Green).
ts.Disk.File(ts.Variables.LOGDIR + "/traffic.out", id="traffic_out").Content = \
    Testers.ContainsExpression(
        r"rejecting invalid persisted link",
        "ATS must log rejection of the invalid rel=prefetch link on load from disk")

# ─── Build the persist binary in test setup ───────────────────────────────────
# Craft a .bin file with learn_count=5 (> min_hit_count=1) so hints are served.
# Contains: 1 valid link + 1 invalid (rel=prefetch) link.
valid_link   = "</valid-asset.js>; rel=preload; as=script"
invalid_link = "</bad-asset.js>; rel=prefetch"

vb = valid_link.encode('utf-8')
ib = invalid_link.encode('utf-8')
kb = b"/load-valid.html"

persist_bytes  = struct.pack('<II', HINTS_CACHE_MAGIC, 1)          # magic + 1 entry
persist_bytes += struct.pack('<H', len(kb)) + kb                    # key
persist_bytes += struct.pack('<I', 5)                               # learn_count=5
persist_bytes += struct.pack('<Q', 1700000000)                      # last_updated (v2 field)
persist_bytes += struct.pack('<H', 2)                               # 2 links
persist_bytes += struct.pack('<H', len(vb)) + vb                   # link 1: valid
persist_bytes += struct.pack('<H', len(ib)) + ib                   # link 2: invalid

# Create persist dir and write file in a setup TestRun BEFORE ATS starts
tr_setup = Test.AddTestRun("Setup: write persist .bin with valid+invalid link before ATS")
tr_setup.Setup.MakeDir(persist_dir)
# Use python3 to write the binary file — avoids issues with null bytes in shell
import base64
b64_content = base64.b64encode(persist_bytes).decode('ascii')
tr_setup.Processes.Default.Command = (
    "python3 -c \""
    "import base64; "
    "open('{0}', 'wb').write(base64.b64decode('{1}'))\""
    " && echo SETUP_DONE".format(persist_filepath, b64_content))
tr_setup.Processes.Default.ReturnCode = 0
tr_setup.Processes.Default.StartBefore(microserver, ready=When.PortOpen(microserver.Variables.Port))
tr_setup.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "SETUP_DONE", "Persist file must be written before ATS starts")
tr_setup.StillRunningAfter = microserver

# ─── TR1: H2 request — ATS loads persist file (with invalid link) and serves 103
tr1 = Test.AddTestRun("Load: H2 request gets 103 from pre-crafted persist cache")
tr1.Processes.Default.Command = (
    "sleep 2 && curl -s -D - -o /dev/null --http2 --insecure"
    " 'https://127.0.0.1:{0}/load-valid.html'".format(ts.Variables.ssl_port))
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.StartBefore(Test.Processes.ts)
# learn_count=5 > min_hit_count=1 → hints must be served.
# The valid link must still make it through (invalid one dropped, not whole entry).
tr1.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "103 must be served from pre-crafted persist cache (valid link present, invalid rejected)")
tr1.StillRunningAfter = microserver
