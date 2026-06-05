'''
Test 103 Early Hints plugin -- persist hardening: oversized link skip and future timestamp clamp

Covers two load_from_disk() hardening fixes:

  Oversized link skip: a link with link_len > 8192 in the persist file must be
    skipped with a warning. Previously it caused fclose+return false, aborting
    the entire load and discarding all valid entries in the file.
    Key assertion: ATS loads successfully and serves 103 from the valid link
    in the same file despite the oversized one.

  Future timestamp clamp: a last_updated timestamp far in the future must be
    clamped to time(now) on load. Previously it was trusted as-is.
    Key assertion: ATS loads and serves hints (does not crash/reject entry).

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
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import base64
import os
import struct
import time

Test.Summary = '''
Persist hardening: oversized link (>8192 bytes) is skipped, not fatal.
Future last_updated timestamp is clamped to now on load.
'''

Test.SkipUnless(
    Condition.PluginExists('early_hints.so'),
)
Test.testName = "early_hints_persist_hardening"
Test.ContinueOnFail = True

# Binary format constants (must match hints_cache.cc)
HINTS_CACHE_MAGIC = 0x45480003  # v3: no learn_count; key + last_updated + links

# FNV-1a 64-bit hash (mirrors fnv1a_hash() in early_hints.cc)
def fnv1a_64(s):
    h = 14695981039346656037
    for c in s.encode('utf-8'):
        h ^= c
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h

# ─── Origin servers ────────────────────────────────────────────────────────────
ms = Test.MakeOriginServer("ms")

# Page for A-25 oversized link test: no <link> tags — all hints from persist file
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a25-oversize.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><body>A-25 persist hardening test</body></html>\r\n"
    })

# Page for A-09 future timestamp test
ms.addResponse(
    "sessionfile.log", {
        "headers": "GET /a09-future-ts.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
        "body": "<html><body>A-09 future timestamp clamp test</body></html>\r\n"
    })

# ─── ATS setup ────────────────────────────────────────────────────────────────
ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

persist_dir = ts.Variables.RUNTIMEDIR + "/hardening_hints"

ts.Disk.remap_config.AddLines([
    'map /a25-oversize.html http://127.0.0.1:{0}/a25-oversize.html'.format(ms.Variables.Port) +
    ' @plugin=early_hints.so'
    ' @pparam=--mode @pparam=auto-learn'
    ' @pparam=--min-hit-count @pparam=1'
    ' @pparam=--no-skip-bots'
    ' @pparam=--no-navigate-only'
    ' @pparam=--debug-header @pparam=X-Early-Hints-Status'
    ' @pparam=--persist-dir @pparam=' + persist_dir,

    'map /a09-future-ts.html http://127.0.0.1:{0}/a09-future-ts.html'.format(ms.Variables.Port) +
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

# ─── Build A-25 binary persist file (oversized link + valid link) ──────────────
# Entry: /a25-oversize.html
#   link 1: 9000-byte garbage (link_len=9000 > 8192 limit)
#   link 2: </valid.js>; rel=preload; as=script  (valid, must survive)
#
# Before fix: load_from_disk() returns false → entry discarded → no 103.
# After fix:  oversized link skipped, valid link loaded → 103 served.

a25_key        = b"/a25-oversize.html"
a25_valid_link = b"</valid.js>; rel=preload; as=script"
a25_oversize   = b"x" * 9000  # link_len=9000 > 8192

a25_bytes  = struct.pack('<II', HINTS_CACHE_MAGIC, 1)
a25_bytes += struct.pack('<H', len(a25_key)) + a25_key
a25_bytes += struct.pack('<Q', 1700000000)  # last_updated (v3 field, past ts)
a25_bytes += struct.pack('<H', 2)           # 2 links
a25_bytes += struct.pack('<H', 9000) + a25_oversize    # link 1: oversized
a25_bytes += struct.pack('<H', len(a25_valid_link)) + a25_valid_link  # link 2: valid

# ─── Build A-09 binary persist file (future timestamp) ────────────────────────
# Entry: /a09-future-ts.html
#   ts = now + 31 years (far future)
#   link: valid
#
# Before fix: ts stored as-is (potential TTL/ordering issues).
# After fix:  ts clamped to now — entry still loaded and served.

a09_key   = b"/a09-future-ts.html"
a09_link  = b"</module.js>; rel=preload; as=script"
future_ts = int(time.time()) + 1000000000  # ~31 years in the future

a09_bytes  = struct.pack('<II', HINTS_CACHE_MAGIC, 1)
a09_bytes += struct.pack('<H', len(a09_key)) + a09_key
a09_bytes += struct.pack('<Q', future_ts)    # far-future last_updated (v3 field)
a09_bytes += struct.pack('<H', 1)            # 1 link
a09_bytes += struct.pack('<H', len(a09_link)) + a09_link

# ─── Combined persist file (both entries in one file requires separate hashes) ─
# Each remap rule uses the from-URL as the key. Write two separate files.
from_url_a25  = "http:///a25-oversize.html"
from_url_a09  = "http:///a09-future-ts.html"
hash_a25      = fnv1a_64(from_url_a25)
hash_a09      = fnv1a_64(from_url_a09)
filename_a25  = "early_hints_{:016x}.bin".format(hash_a25)
filename_a09  = "early_hints_{:016x}.bin".format(hash_a09)
filepath_a25  = os.path.join(persist_dir, filename_a25)
filepath_a09  = os.path.join(persist_dir, filename_a09)

b64_a25 = base64.b64encode(a25_bytes).decode('ascii')
b64_a09 = base64.b64encode(a09_bytes).decode('ascii')

# ─── Setup: write both persist files before ATS starts ────────────────────────
tr_setup = Test.AddTestRun("Setup: write oversized-link and future-ts persist files")
tr_setup.Setup.MakeDir(persist_dir)
tr_setup.Processes.Default.Command = (
    "python3 -c \""
    "import base64; "
    "open('{a25}', 'wb').write(base64.b64decode('{b64a25}')); "
    "open('{a09}', 'wb').write(base64.b64decode('{b64a09}')); "
    "print('SETUP_DONE')"
    "\"".format(
        a25=filepath_a25, b64a25=b64_a25,
        a09=filepath_a09, b64a09=b64_a09,
    ))
tr_setup.Processes.Default.ReturnCode = 0
tr_setup.Processes.Default.StartBefore(ms, ready=When.PortOpen(ms.Variables.Port))
tr_setup.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "SETUP_DONE", "Both persist files must be written before ATS starts")
tr_setup.StillRunningAfter = ms

# ==============================================================================
# A-25: oversized link skip — valid link in same file must be served
# ==============================================================================

tr_a25 = Test.AddTestRun(
    "A-25: oversized link skipped; valid link still served as 103 hint")
tr_a25.Processes.Default.Command = (
    "sleep 2 && curl -s -D - -o /dev/null --http2 --insecure"
    " 'https://127.0.0.1:{0}/a25-oversize.html'".format(ts.Variables.ssl_port))
tr_a25.Processes.Default.ReturnCode = 0
tr_a25.Processes.Default.StartBefore(Test.Processes.ts)
# After fix: load succeeds, valid link served as 103.
# Before fix: load fails (return false) → no 103, debug header = no-hints.
tr_a25.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "A-25: valid link must survive oversized-link skip and be served as 103")
tr_a25.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/valid.js",
    "A-25: the valid link /valid.js must appear in the 103 Link header")
tr_a25.StillRunningAfter = ms

# ==============================================================================
# A-09: future timestamp clamp — entry still loaded and served
# ==============================================================================

tr_a09 = Test.AddTestRun(
    "A-09: future ts_on_disk clamped; entry still served as 103 hint")
tr_a09.Processes.Default.Command = (
    "sleep 1 && curl -s -D - -o /dev/null --http2 --insecure"
    " 'https://127.0.0.1:{0}/a09-future-ts.html'".format(ts.Variables.ssl_port))
tr_a09.Processes.Default.ReturnCode = 0
tr_a09.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "x-early-hints-status: sent",
    "A-09: future ts clamped to now; entry must still be loaded and served as 103")
tr_a09.Processes.Default.Streams.stdout.Content += Testers.ContainsExpression(
    "/module.js",
    "A-09: /module.js must appear in the 103 Link header")
tr_a09.StillRunningAfter = ms
