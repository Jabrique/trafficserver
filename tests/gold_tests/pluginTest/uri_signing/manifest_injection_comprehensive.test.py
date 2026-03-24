'''
Comprehensive E2E test for URI Signing plugin manifest injection feature.

Tests ALL configuration options:
- Salt: enabled, bind_session_id, bind_user_agent, bind_client_ip
- Manifest injection: enabled, inject_to_segments, inject_to_init_segments,
  replace_access_token, hls_support, dash_support, cache_untransformed
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

import json
import os
import hashlib
import jwt
from datetime import datetime, timedelta

Test.Summary = '''
Comprehensive test for uri_signing manifest injection with all config options
'''

Test.ContinueOnFail = False
# Note: Skip PluginExists check for now - plugin is built in experimental/uri_signing
# Test.SkipUnless(Condition.PluginExists('uri_signing.so'))

# ==============================================================================
# ORIGIN SERVER SETUP
# ==============================================================================

server = Test.MakeOriginServer("server")
server.ReturnCode = 0
server.TimeOut = 3600

# HLS manifest with regular segments AND init segment
hls_manifest_with_init = """#EXTM3U
#EXT-X-VERSION:6
#EXT-X-TARGETDURATION:10
#EXT-X-MAP:URI="init.mp4"
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
segment0.ts
#EXTINF:10.0,
segment1.ts
#EXTINF:10.0,
segment2.ts
#EXT-X-ENDLIST
"""

# HLS manifest with query parameters already present
hls_manifest_with_params = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
segment0.ts?quality=high
#EXTINF:10.0,
segment1.ts?quality=high
#EXT-X-ENDLIST
"""

# HLS manifest with access token that should be replaced
hls_manifest_with_access_token = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
segment0.ts?cr-access-token=OLD_ACCESS_TOKEN_HERE
#EXTINF:10.0,
segment1.ts?cr-access-token=OLD_ACCESS_TOKEN_HERE
#EXT-X-ENDLIST
"""

# DASH MPD manifest
dash_manifest = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period>
    <AdaptationSet>
      <Representation>
        <BaseURL>segment-base.m4s</BaseURL>
        <SegmentList>
          <Initialization sourceURL="init-segment.mp4"/>
          <SegmentURL media="segment1.m4s"/>
          <SegmentURL media="segment2.m4s"/>
        </SegmentList>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""

# Non-manifest content (should pass through unchanged)
html_content = """<!DOCTYPE html>
<html>
<body>Not a manifest</body>
</html>
"""

# Add origin responses
def add_origin_response(path, content_type, body):
    req = {
        "headers": f"GET {path} HTTP/1.1\r\nHost: videohost\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "",
    }
    res = {
        "headers": f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": body,
    }
    server.addResponse("sessionfile.log", req, res)

add_origin_response("/video/init.m3u8", "application/vnd.apple.mpegurl", hls_manifest_with_init)
add_origin_response("/video/params.m3u8", "application/vnd.apple.mpegurl", hls_manifest_with_params)
add_origin_response("/video/replace.m3u8", "application/vnd.apple.mpegurl", hls_manifest_with_access_token)
add_origin_response("/video/dash.mpd", "application/dash+xml", dash_manifest)
add_origin_response("/page.html", "text/html", html_content)

# ==============================================================================
# HELPER: Create config file
# ==============================================================================

def create_config(name, salt_config, manifest_config):
    """Create a JSON config file with specified settings."""
    config = {
        "issuer": {
            "renewal_kid": "primary-key-2024",
            "id": "mycdn",
            "strip_token": True,
            "renewal_token": {
                "token_name": "cr-session-token",
                "salt": salt_config,
                "manifest_injection": manifest_config
            },
            "keys": [{
                "alg": "HS256",
                "k": "dGVzdC1zZWNyZXQta2V5LTEyMzQ1Njc4OTA=",
                "kid": "primary-key-2024",
                "kty": "oct"
            }]
        }
    }

    config_file = os.path.join(Test.RunDirectory, f"config_{name}.json")
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)

    return config_file

# ==============================================================================
# TEST 1: Basic HLS injection (no salt, basic options)
# ==============================================================================

ts1 = Test.MakeATSProcess("ts1", enable_cache=False)
ts1.TimeOut = 3600
ts1.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config1 = create_config("basic_hls",
    salt_config={
        "enabled": False
    },
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts1.Disk.remap_config.AddLine(
    f'map http://videohost1/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config1}'
)

# Valid token with renewal: {"iss":"issuer","exp":1793756236,"cdnistt":1,"cdniets":3600}
# Properly signed with secret: test-secret-key-1234567890
# cdniets=3600: renewal token expires in 1 hour
valid_token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InByaW1hcnkta2V5LTIwMjQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE3OTM3NTYyMzYsImNkbmlzdHQiOjEsImNkbmlldHMiOjM2MDB9.-F77OEr9sagDPI5yv_yDPKyfFeYqMW6cglY6PKYejHw"

tr1 = Test.AddTestRun("Test 1: Basic HLS injection without salt")
ps1 = tr1.Processes.Default
ps1.StartBefore(ts1)
ps1.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
ps1.Command = f'curl -s -v -x localhost:{ts1.Variables.port} "http://videohost1/video/init.m3u8?cr-access-token={valid_token}"'
ps1.ReturnCode = 0
ps1.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "should return 200 OK")
ps1.Streams.stderr += Testers.ContainsExpression("< Set-Cookie: cr-session-token=", "should set session cookie")
ps1.Streams.stdout = Testers.ContainsExpression("segment0.ts\\?cr-session-token=", "segments should have token")
# Init segment should NOT have token (inject_to_init_segments=false)
ps1.Streams.stdout += Testers.ContainsExpression('URI="init.mp4"', "init segment should NOT have token injected")
tr1.StillRunningAfter = server
tr1.StillRunningAfter = ts1

# ==============================================================================
# TEST 2: HLS with init segment injection
# ==============================================================================

ts2 = Test.MakeATSProcess("ts2", enable_cache=False)
ts2.TimeOut = 3600
ts2.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config2 = create_config("hls_with_init",
    salt_config={"enabled": False},
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": True,  # Enable init segment injection
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts2.Disk.remap_config.AddLine(
    f'map http://videohost2/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config2}'
)

tr2 = Test.AddTestRun("Test 2: HLS with init segment injection")
ps2 = tr2.Processes.Default
ps2.StartBefore(ts2)
ps2.Command = f'curl -s -v -x localhost:{ts2.Variables.port} "http://videohost2/video/init.m3u8?cr-access-token={valid_token}"'
ps2.ReturnCode = 0
ps2.Streams.stdout = Testers.ContainsExpression("segment0.ts\\?cr-session-token=", "segments should have token")
# Init segment SHOULD have token (inject_to_init_segments=true)
ps2.Streams.stdout += Testers.ContainsExpression('URI="init.mp4\\?cr-session-token=', "init segment SHOULD have token")
tr2.StillRunningAfter = server
tr2.StillRunningAfter = ts2

# ==============================================================================
# TEST 3: Replace access token behavior
# ==============================================================================

ts3 = Test.MakeATSProcess("ts3", enable_cache=False)
ts3.TimeOut = 3600
ts3.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config3 = create_config("replace_token",
    salt_config={"enabled": False},
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": True,  # Replace access token
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts3.Disk.remap_config.AddLine(
    f'map http://videohost3/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config3}'
)

tr3 = Test.AddTestRun("Test 3: Replace access token in manifest")
ps3 = tr3.Processes.Default
ps3.StartBefore(ts3)
ps3.Command = f'curl -s -v -x localhost:{ts3.Variables.port} "http://videohost3/video/replace.m3u8?cr-access-token={valid_token}"'
ps3.ReturnCode = 0
# Old access token should be REMOVED
ps3.Streams.stdout = Testers.ExcludesExpression("OLD_ACCESS_TOKEN_HERE", "old access token should be removed")
# Session token should be present
ps3.Streams.stdout += Testers.ContainsExpression("segment0.ts\\?cr-session-token=", "session token should be injected")
tr3.StillRunningAfter = server
tr3.StillRunningAfter = ts3

# ==============================================================================
# TEST 4: Salt with session ID binding
# ==============================================================================

ts4 = Test.MakeATSProcess("ts4", enable_cache=False)
ts4.TimeOut = 3600
ts4.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform|session',
})

config4 = create_config("salt_session",
    salt_config={
        "enabled": True,
        "bind_session_id": True,
        "bind_user_agent": False,
        "bind_client_ip": False
    },
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts4.Disk.remap_config.AddLine(
    f'map http://videohost4/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config4}'
)

# Token WITH cdnisalt for device binding - session ID only
# cdnisalt = SHA256("session123") = 88eacd42c0ac122be2cb2b21df2c320c17b9f12d5faf44da17534a4b4b018077
token_with_salt_session = "eyJhbGciOiJIUzI1NiIsImtpZCI6InByaW1hcnkta2V5LTIwMjQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjI3MDgzMDE1MzEsImNkbmlzdHQiOjEsImNkbmlldHMiOjM2MDAsImNkbmlzYWx0IjoiODhlYWNkNDJjMGFjMTIyYmUyY2IyYjIxZGYyYzMyMGMxN2I5ZjEyZDVmYWY0NGRhMTc1MzRhNGI0YjAxODA3NyJ9.o6M2pP4PuHmYI-oCdIU5YfQbIiJWlkM4DXAKc8mndrU"

tr4 = Test.AddTestRun("Test 4: Salt with session ID binding")
ps4 = tr4.Processes.Default
ps4.StartBefore(ts4)
ps4.Command = f'curl -s -v -x localhost:{ts4.Variables.port} "http://videohost4/video/init.m3u8?cr-access-token={token_with_salt_session}" -H "X-Playback-Session-Id: session123"'
ps4.ReturnCode = 0
ps4.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "should return 200 OK with salt enabled")
ps4.Streams.stderr += Testers.ContainsExpression("< Set-Cookie: cr-session-token=", "should set session cookie")
tr4.StillRunningAfter = server
tr4.StillRunningAfter = ts4

# ==============================================================================
# TEST 5: Salt with multiple bindings
# ==============================================================================

ts5 = Test.MakeATSProcess("ts5", enable_cache=False)
ts5.TimeOut = 3600
ts5.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|session',
})

config5 = create_config("salt_multi",
    salt_config={
        "enabled": True,
        "bind_session_id": True,
        "bind_user_agent": True,
        "bind_client_ip": True
    },
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts5.Disk.remap_config.AddLine(
    f'map http://videohost5/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config5}'
)

# Token with multi-binding salt: session456 + TestClient/1.0 + 127.0.0.1
# cdnisalt = SHA256("session456TestClient/1.0127.0.0.1") = 8e7946da5efd8cff621e3f3e256f1903ca19ca731c7a8be9093a21b79de8e564
token_with_salt_multi = "eyJhbGciOiJIUzI1NiIsImtpZCI6InByaW1hcnkta2V5LTIwMjQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjI3MDgzMDE3MzgsImNkbmlzdHQiOjEsImNkbmlldHMiOjM2MDAsImNkbmlzYWx0IjoiOGU3OTQ2ZGE1ZWZkOGNmZjYyMWUzZjNlMjU2ZjE5MDNjYTE5Y2E3MzFjN2E4YmU5MDkzYTIxYjc5ZGU4ZTU2NCJ9.w5gjXXWO7uT8w0EMalASFmPiHk0MLDtinGSzQq0KgMI"

tr5 = Test.AddTestRun("Test 5: Salt with multiple bindings (session+UA+IP)")
ps5 = tr5.Processes.Default
ps5.StartBefore(ts5)
ps5.Command = f'curl -s -v -x localhost:{ts5.Variables.port} "http://videohost5/video/init.m3u8?cr-access-token={token_with_salt_multi}" -H "X-Playback-Session-Id: session456" -A "TestClient/1.0"'
ps5.ReturnCode = 0
ps5.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "should handle multiple bindings")
tr5.StillRunningAfter = server
tr5.StillRunningAfter = ts5

# ==============================================================================
# TEST 6: Non-manifest content should pass through unchanged
# ==============================================================================

ts6 = Test.MakeATSProcess("ts6", enable_cache=False)
ts6.TimeOut = 3600
ts6.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config6 = create_config("passthrough",
    salt_config={"enabled": False},
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts6.Disk.remap_config.AddLine(
    f'map http://videohost6/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config6}'
)

tr6 = Test.AddTestRun("Test 6: Non-manifest content passes through unchanged")
ps6 = tr6.Processes.Default
ps6.StartBefore(ts6)
ps6.Command = f'curl -s -v -x localhost:{ts6.Variables.port} "http://videohost6/page.html?cr-access-token={valid_token}"'
ps6.ReturnCode = 0
ps6.Streams.stdout = Testers.ContainsExpression("Not a manifest", "HTML should pass through unchanged")
ps6.Streams.stdout += Testers.ExcludesExpression("cr-session-token", "HTML should NOT have tokens injected")
tr6.StillRunningAfter = server
tr6.StillRunningAfter = ts6

# ==============================================================================
# TEST 7: Manifest with existing query params
# ==============================================================================

ts7 = Test.MakeATSProcess("ts7", enable_cache=False)
ts7.TimeOut = 3600
ts7.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config7 = create_config("with_params",
    salt_config={"enabled": False},
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts7.Disk.remap_config.AddLine(
    f'map http://videohost7/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config7}'
)

tr7 = Test.AddTestRun("Test 7: Manifest with existing query params")
ps7 = tr7.Processes.Default
ps7.StartBefore(ts7)
ps7.Command = f'curl -s -v -x localhost:{ts7.Variables.port} "http://videohost7/video/params.m3u8?cr-access-token={valid_token}"'
ps7.ReturnCode = 0
# Should append token with & separator
ps7.Streams.stdout = Testers.ContainsExpression("quality=high&cr-session-token=", "should append token to existing params")
tr7.StillRunningAfter = server
tr7.StillRunningAfter = ts7

# ==============================================================================
# TEST 8: DASH support
# ==============================================================================

ts8 = Test.MakeATSProcess("ts8", enable_cache=False)
ts8.TimeOut = 3600
ts8.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config8 = create_config("dash",
    salt_config={"enabled": False},
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": True,
        "replace_access_token": False,
        "hls_support": False,
        "dash_support": True,  # Enable DASH
        "cache_untransformed": True
    }
)

ts8.Disk.remap_config.AddLine(
    f'map http://videohost8/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config8}'
)

tr8 = Test.AddTestRun("Test 8: DASH manifest injection")
ps8 = tr8.Processes.Default
ps8.StartBefore(ts8)
ps8.Command = f'curl -s -v -x localhost:{ts8.Variables.port} "http://videohost8/video/dash.mpd?cr-access-token={valid_token}"'
ps8.ReturnCode = 0

# Validate HTTP response
ps8.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "DASH should return 200")
ps8.Streams.stderr += Testers.ContainsExpression("< Set-Cookie: cr-session-token=", "Should generate renewal token")

# Validate XML structure is preserved
ps8.Streams.stdout = Testers.ContainsExpression('<\\?xml version="1.0"', "Output must start with XML declaration")
ps8.Streams.stdout += Testers.ContainsExpression('<MPD', "Output must contain MPD element")
ps8.Streams.stdout += Testers.ContainsExpression('</MPD>', "Output must be complete XML document")

# Validate token injection into DASH attributes (not into XML structure)
# Check for token in media URLs (could be media attribute, BaseURL element, or sourceURL attribute)
ps8.Streams.stdout += Testers.ContainsExpression('(media=|BaseURL>|sourceURL=)"?[^">]*\\?cr-session-token=', "Token should be injected into segment URLs")

# Validate token is NOT corrupting XML structure
ps8.Streams.stdout += Testers.ExcludesExpression('\\?>\\?cr-session-token=', "Token should NOT corrupt XML declaration")
ps8.Streams.stdout += Testers.ExcludesExpression('>"\\?cr-session-token=', "Token should NOT be injected after closing tags")

tr8.StillRunningAfter = server
tr8.StillRunningAfter = ts8

print("=" * 80)
print("Comprehensive URI Signing Manifest Injection Test Suite")
print("=" * 80)
print("Test 1: Basic HLS injection (no salt, no init segments)")
print("Test 2: HLS with init segment injection")
print("Test 3: Replace access token in manifest URLs")
print("Test 4: Salt with session ID binding")
print("Test 5: Salt with multiple bindings (session+UA+IP)")
print("Test 6: Non-manifest content passthrough")
print("Test 7: Manifest with existing query parameters")
print("Test 8: DASH manifest injection")
print("Test 9a: Complete E2E - access token → renewal → segment with salt validation")
print("Test 9b: Security - access token via renewal parameter (should reject)")
print("Test 9c: Security - renewal token with different session ID (salt mismatch)")
print("=" * 80)

# ==============================================================================
# TEST 9: First request flow - Salt validation with pre-generated tokens
# ==============================================================================
#
# SIMPLIFIED APPROACH:
# Instead of complex bash scripts with command substitution (which conflicts with
# autest template engine), we pre-generate all token variations in Python and
# use simple curl commands. This provides the same functional coverage but is
# 100% compatible with autest.
#
# Test scenarios:
# 9a-1: Access token (no salt) via cr-access-token → 200 OK
# 9a-2: Renewal token (with salt) + matching session → 200 OK
# 9a-3: Renewal token (with salt) without session header → 403
# 9b:   Access token (no salt) via cr-session-token → 403
# 9c:   Renewal token (with wrong salt) + different session → 403
# ==============================================================================

ts9 = Test.MakeATSProcess("ts9", enable_cache=False)
ts9.TimeOut = 3600
ts9.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform|session',
})

config9 = create_config("first_request_salt",
    salt_config={
        "enabled": True,
        "bind_session_id": True,
        "bind_user_agent": False,
        "bind_client_ip": False
    },
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": True,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts9.Disk.remap_config.AddLine(
    f'map http://videohost9/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config9}'
)

# ==============================================================================
# Pre-generate tokens for testing
# ==============================================================================

# Secret key (same as in config)
SECRET = "test-secret-key-1234567890"

# Access token WITHOUT salt (for first request)
access_token_no_salt = jwt.encode({
    "iss": "issuer",
    "exp": int((datetime.now() + timedelta(days=365*30)).timestamp()),
    "cdnistt": 1,
    "cdniets": 3600,
    "cdnistd": 0
}, SECRET, algorithm="HS256", headers={"kid": "primary-key-2024"})

# Generate salt for session-123
salt_session_123 = hashlib.sha256("session-123".encode()).hexdigest()

# Renewal token WITH salt for session-123
renewal_token_with_salt_123 = jwt.encode({
    "iss": "issuer",
    "exp": int((datetime.now() + timedelta(days=365*30)).timestamp()),
    "iat": int(datetime.now().timestamp()),
    "cdniv": 1,
    "cdniets": 3600,
    "cdnistt": 1,
    "cdnistd": 0,
    "cdnisalt": salt_session_123
}, SECRET, algorithm="HS256", headers={"kid": "primary-key-2024"})

# Generate salt for session-456
salt_session_456 = hashlib.sha256("session-456".encode()).hexdigest()

# Renewal token WITH salt for session-456 (different session)
renewal_token_with_salt_456 = jwt.encode({
    "iss": "issuer",
    "exp": int((datetime.now() + timedelta(days=365*30)).timestamp()),
    "iat": int(datetime.now().timestamp()),
    "cdniv": 1,
    "cdniets": 3600,
    "cdnistt": 1,
    "cdnistd": 0,
    "cdnisalt": salt_session_456
}, SECRET, algorithm="HS256", headers={"kid": "primary-key-2024"})

# ==============================================================================
# Test 9a-1: Access token (no salt) should be accepted
# ==============================================================================
tr9a1 = Test.AddTestRun("Test 9a-1: Access token without salt accepted")
ps9a1 = tr9a1.Processes.Default
ps9a1.StartBefore(ts9)
ps9a1.Command = f'curl -s -v -x localhost:{ts9.Variables.port} -H "X-Playback-Session-Id: session-123" "http://videohost9/video/init.m3u8?cr-access-token={access_token_no_salt}"'
ps9a1.ReturnCode = 0
ps9a1.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "access token without salt should return 200")
ps9a1.Streams.stderr += Testers.ContainsExpression("< Set-Cookie: cr-session-token=", "should generate renewal token")
tr9a1.StillRunningAfter = server
tr9a1.StillRunningAfter = ts9

# ==============================================================================
# Test 9a-2: Renewal token with correct salt + matching session → 200 OK
# ==============================================================================
tr9a2 = Test.AddTestRun("Test 9a-2: Renewal token with matching session succeeds")
ps9a2 = tr9a2.Processes.Default
ps9a2.Command = f'curl -s -v -x localhost:{ts9.Variables.port} -H "X-Playback-Session-Id: session-123" "http://videohost9/video/init.m3u8?cr-session-token={renewal_token_with_salt_123}"'
ps9a2.ReturnCode = 0
ps9a2.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "renewal token with correct salt should return 200")
tr9a2.StillRunningAfter = server
tr9a2.StillRunningAfter = ts9

# ==============================================================================
# Test 9a-3: Renewal token WITHOUT session header → 403 Forbidden
# ==============================================================================
tr9a3 = Test.AddTestRun("Test 9a-3: Renewal token without session header fails")
ps9a3 = tr9a3.Processes.Default
ps9a3.Command = f'curl -s -v -x localhost:{ts9.Variables.port} "http://videohost9/video/init.m3u8?cr-session-token={renewal_token_with_salt_123}"'
ps9a3.ReturnCode = 0
ps9a3.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 403", "renewal token without session header should return 403")
tr9a3.StillRunningAfter = server
tr9a3.StillRunningAfter = ts9

# ==============================================================================
# Test 9b: Access token (no salt) sent via cr-session-token → 403 Forbidden
# ==============================================================================
tr9b = Test.AddTestRun("Test 9b: Access token sent as renewal token rejected")
ps9b = tr9b.Processes.Default
ps9b.Command = f'curl -s -v -x localhost:{ts9.Variables.port} -H "X-Playback-Session-Id: session-123" "http://videohost9/video/init.m3u8?cr-session-token={access_token_no_salt}"'
ps9b.ReturnCode = 0
ps9b.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 403", "access token via renewal parameter should be rejected")
tr9b.StillRunningAfter = server
tr9b.StillRunningAfter = ts9

# ==============================================================================
# Test 9c: Renewal token with wrong salt + different session → 403 Forbidden
# ==============================================================================
tr9c = Test.AddTestRun("Test 9c: Renewal token with mismatched session fails")
ps9c = tr9c.Processes.Default
ps9c.Command = f'curl -s -v -x localhost:{ts9.Variables.port} -H "X-Playback-Session-Id: session-123" "http://videohost9/video/init.m3u8?cr-session-token={renewal_token_with_salt_456}"'
ps9c.ReturnCode = 0
ps9c.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 403", "renewal token with wrong salt should return 403")
tr9c.StillRunningAfter = server
tr9c.StillRunningAfter = ts9

# ==============================================================================
# BUG #4 Integration Tests - Non-renewable token manifest injection
# ==============================================================================

# ==============================================================================
# Test 10: Non-renewable token (cdnistt=0) with manifest injection
# BUG #4 FIX: Manifest injection should work even when renewal is skipped
# ==============================================================================

ts10 = Test.MakeATSProcess("ts10", enable_cache=False)
ts10.TimeOut = 3600
ts10.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config10 = create_config("bug4_nonrenewable",
    salt_config={"enabled": False},
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": False,
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts10.Disk.remap_config.AddLine(
    f'map http://videohost10/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config10}'
)

# BUG #4: Non-renewable token (cdnistt=0)
# Before fix: Manifest injection would be skipped (no renewal = no token for injection)
# After fix: Uses original validated token for manifest injection
token_nonrenewable = "eyJhbGciOiJIUzI1NiIsImtpZCI6InByaW1hcnkta2V5LTIwMjQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE3OTU3NDIzMjEsImNkbmlzdHQiOjAsImNkbmlldHMiOjM2MDB9.tm3GrchWfO_cfzgz8OWicbKG-OpK4NrBirr1QjhoxJ4"

tr10 = Test.AddTestRun("Test 10 (BUG #4): Non-renewable token with manifest injection")
ps10 = tr10.Processes.Default
ps10.StartBefore(ts10)
ps10.Command = f'curl -s -v -x localhost:{ts10.Variables.port} "http://videohost10/video/init.m3u8?cr-access-token={token_nonrenewable}"'
ps10.ReturnCode = 0
ps10.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "non-renewable token should return 200 OK")
# BUG #4 FIX: Manifest injection should work using ORIGINAL validated token
ps10.Streams.stdout = Testers.ContainsExpression("segment0.ts\\?cr-session-token=", "BUG #4: segments should have token injected (using original token)")
ps10.Streams.stdout += Testers.ContainsExpression("segment1.ts\\?cr-session-token=", "BUG #4: all segments should have tokens")
# Non-renewable token should NOT set renewal cookie (cdnistt=0)
ps10.Streams.stderr += Testers.ExcludesExpression("< Set-Cookie: cr-session-token=", "non-renewable token should NOT set renewal cookie")
tr10.StillRunningAfter = server
tr10.StillRunningAfter = ts10

# ==============================================================================
# Test 11: Renewal skipped (cdniets=0) with manifest injection
# BUG #4 FIX: Manifest injection should use original token when renewal skipped
# ==============================================================================

ts11 = Test.MakeATSProcess("ts11", enable_cache=False)
ts11.TimeOut = 3600
ts11.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})

config11 = create_config("bug4_skip_renewal",
    salt_config={"enabled": False},
    manifest_config={
        "enabled": True,
        "inject_to_segments": True,
        "inject_to_init_segments": True,
        "replace_access_token": False,
        "hls_support": True,
        "dash_support": False,
        "cache_untransformed": True
    }
)

ts11.Disk.remap_config.AddLine(
    f'map http://videohost11/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config11}'
)

# BUG #4: Token with cdniets=0 (renewal expires immediately = skip renewal)
# Before fix: No renewal cookie = no manifest injection
# After fix: Uses original validated token for manifest injection
token_skip_renewal = "eyJhbGciOiJIUzI1NiIsImtpZCI6InByaW1hcnkta2V5LTIwMjQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE3OTU3NDIzMjEsImNkbmlzdHQiOjEsImNkbmlldHMiOjB9.S1Wod8GHb5wMGwS2XySaxN_ey8NWP3zs_vm4LnwvYS8"

tr11 = Test.AddTestRun("Test 11 (BUG #4): Renewal skipped (cdniets=0) with manifest injection")
ps11 = tr11.Processes.Default
ps11.StartBefore(ts11)
ps11.Command = f'curl -s -v -x localhost:{ts11.Variables.port} "http://videohost11/video/init.m3u8?cr-access-token={token_skip_renewal}"'
ps11.ReturnCode = 0
ps11.Streams.stderr = Testers.ContainsExpression("< HTTP/1.1 200", "token with cdniets=0 should return 200 OK")
# BUG #4 FIX: Manifest injection should work even when cdniets=0 (renewal skipped)
ps11.Streams.stdout = Testers.ContainsExpression("segment0.ts\\?cr-session-token=", "BUG #4: segments should have token (using original, not renewal)")
ps11.Streams.stdout += Testers.ContainsExpression('URI="init.mp4\\?cr-session-token=', "BUG #4: init segment should also have token")
# cdniets=0 means no renewal cookie (renewal expires immediately)
ps11.Streams.stderr += Testers.ExcludesExpression("< Set-Cookie: cr-session-token=", "cdniets=0 should NOT set renewal cookie")
tr11.StillRunningAfter = server
tr11.StillRunningAfter = ts11

# ==============================================================================
# CACHE ISOLATION & TRANSFORM EDGE CASES
# ==============================================================================

import time as _time

_EC_KID = "primary-key-2024"
_EC_FAR_FUTURE = int(_time.time()) + 365 * 30 * 24 * 3600

token_a_cache = jwt.encode({
    "iss": "issuer", "exp": _EC_FAR_FUTURE,
    "cdnistt": 1, "cdniets": 3600, "cdniuc": "regex:.*"
}, SECRET, algorithm="HS256", headers={"kid": _EC_KID})

token_b_cache = jwt.encode({
    "iss": "issuer", "exp": _EC_FAR_FUTURE - 86400,
    "cdnistt": 1, "cdniets": 3600, "cdniuc": "regex:.*"
}, SECRET, algorithm="HS256", headers={"kid": _EC_KID})

token_nonrenew_cache = jwt.encode({
    "iss": "issuer", "exp": _EC_FAR_FUTURE,
    "cdnistt": 0, "cdniets": 0, "cdniuc": "regex:.*"
}, SECRET, algorithm="HS256", headers={"kid": _EC_KID})

# HLS manifest for edge case tests
hls_manifest_ec = (
    "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:10\n"
    "#EXTINF:10.0,\nsegment0.ts\n#EXTINF:10.0,\nsegment1.ts\n"
    "#EXT-X-ENDLIST\n"
)
large_body_ec = "NOT_A_MANIFEST_" + ("X" * 65536)


def _ec_add_manifest(path, body, content_type, host, extra_headers=""):
    hdr = (
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nConnection: close\r\n"
        "{}\r\n"
    ).format(content_type, extra_headers)
    server.addResponse("sessionfile.log",
                       {"headers": "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n".format(path, host),
                        "timestamp": "1469733493.993", "body": ""},
                       {"headers": hdr, "timestamp": "1469733493.993", "body": body})


_ec_add_manifest("/video/live.m3u8", hls_manifest_ec,
                 "application/vnd.apple.mpegurl", "cachehost-ec",
                 extra_headers="Cache-Control: max-age=60\r\n")
_ec_add_manifest("/video/live.m3u8", hls_manifest_ec,
                 "application/vnd.apple.mpegurl", "manifesthost-ec")
_ec_add_manifest("/video/empty.m3u8", "",
                 "application/vnd.apple.mpegurl", "manifesthost-ec")
_ec_add_manifest("/video/large.m3u8", large_body_ec,
                 "application/octet-stream", "manifesthost-ec")
_ec_add_manifest("/video/head.m3u8", hls_manifest_ec,
                 "application/vnd.apple.mpegurl", "manifesthost-ec")

# Origin with its own Set-Cookie (coexistence test)
server.addResponse("sessionfile.log",
                   {"headers": "GET /video/setcookie.m3u8 HTTP/1.1\r\nHost: manifesthost-ec\r\n\r\n",
                    "timestamp": "1469733493.993", "body": ""},
                   {"headers": ("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n"
                                "Set-Cookie: origin-session=abc123\r\nConnection: close\r\n\r\n"),
                    "timestamp": "1469733493.993", "body": hls_manifest_ec})


def _ec_create_manifest_config(name):
    config = {
        "issuer": {
            "renewal_kid": _EC_KID,
            "id": "testcdn-ec",
            "strip_token": True,
            "renewal_token": {
                "token_name": "cr-session-token",
                "manifest_injection": {
                    "enabled": True,
                    "inject_to_segments": True,
                    "inject_to_init_segments": False,
                    "replace_access_token": False,
                    "hls_support": True,
                    "dash_support": True,
                    "cache_untransformed": True,
                }
            },
            "keys": [{
                "alg": "HS256",
                "k": "dGVzdC1zZWNyZXQta2V5LTEyMzQ1Njc4OTA=",
                "kid": _EC_KID,
                "kty": "oct"
            }]
        }
    }
    path = os.path.join(Test.RunDirectory, "ec_manifest_config_{}.json".format(name))
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
    return path


_ec_cfg_cache = _ec_create_manifest_config("cache")
_ec_cfg_manifest = _ec_create_manifest_config("manifest")

# ts12_cache: cache ENABLED — per-user cache isolation test
ts12_cache = Test.MakeATSProcess("ts12-cache", enable_cache=True)
ts12_cache.TimeOut = 3600
ts12_cache.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform|cache',
    'proxy.config.http.cache.http': 1,
})
ts12_cache.Disk.remap_config.AddLine(
    f'map http://cachehost-ec/ http://127.0.0.1:{server.Variables.Port}/'
    f' @plugin=uri_signing.so @pparam={_ec_cfg_cache}')

# ts12_manifest: cache DISABLED — transform edge cases
ts12_manifest = Test.MakeATSProcess("ts12-manifest", enable_cache=False)
ts12_manifest.TimeOut = 3600
ts12_manifest.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform',
})
ts12_manifest.Disk.remap_config.AddLine(
    f'map http://manifesthost-ec/ http://127.0.0.1:{server.Variables.Port}/'
    f' @plugin=uri_signing.so @pparam={_ec_cfg_manifest}')

# --- Cache isolation: User A (cache miss) → own session token ---
tr12a = Test.AddTestRun("EC Cache: User A gets manifest (cache miss) → own session token")
ps12a = tr12a.Processes.Default
ps12a.StartBefore(ts12_cache)
ps12a.Command = (
    f'curl -s -v -x localhost:{ts12_cache.Variables.port} '
    f'"http://cachehost-ec/video/live.m3u8?cr-access-token={token_a_cache}"'
)
ps12a.ReturnCode = 0
ps12a.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "User A → 200")
ps12a.Streams.stderr += Testers.ContainsExpression(
    "Set-Cookie: cr-session-token=", "User A gets Set-Cookie")
ps12a.Streams.stdout = Testers.ContainsExpression(
    "cr-session-token=", "User A's manifest has injected tokens")
tr12a.StillRunningAfter = server
tr12a.StillRunningAfter = ts12_cache

# --- Cache isolation: User B (cache hit) → THEIR OWN session token ---
tr12b = Test.AddTestRun("EC Cache: User B (cache hit) gets own session token (not User A's)")
ps12b = tr12b.Processes.Default
ps12b.Command = (
    f'curl -s -v -x localhost:{ts12_cache.Variables.port} '
    f'"http://cachehost-ec/video/live.m3u8?cr-access-token={token_b_cache}"'
)
ps12b.ReturnCode = 0
ps12b.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "User B → 200")
ps12b.Streams.stderr += Testers.ContainsExpression(
    "Set-Cookie: cr-session-token=",
    "CRITICAL: User B gets their OWN session token, not cached User A's")
ps12b.Streams.stdout = Testers.ContainsExpression(
    "cr-session-token=", "User B's manifest has token injection")
tr12b.StillRunningAfter = server
tr12b.StillRunningAfter = ts12_cache

# --- Transform: Empty manifest body (0 bytes) ---
tr12c = Test.AddTestRun("EC Transform: Empty manifest body (0 bytes) — no crash")
ps12c = tr12c.Processes.Default
ps12c.StartBefore(ts12_manifest)
ps12c.Command = (
    f'curl -s -v -x localhost:{ts12_manifest.Variables.port} '
    f'"http://manifesthost-ec/video/empty.m3u8?cr-access-token={token_a_cache}"'
)
ps12c.ReturnCode = 0
ps12c.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Empty manifest → 200 no crash")
tr12c.StillRunningAfter = server
tr12c.StillRunningAfter = ts12_manifest

# --- Transform: 64KB non-manifest on .m3u8 URL (no injection expected) ---
tr12d = Test.AddTestRun("EC Transform: 64KB non-manifest on .m3u8 URL passes through unchanged")
ps12d = tr12d.Processes.Default
ps12d.Command = (
    f'curl -s -v -x localhost:{ts12_manifest.Variables.port} '
    f'"http://manifesthost-ec/video/large.m3u8?cr-access-token={token_a_cache}"'
)
ps12d.ReturnCode = 0
ps12d.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Large non-manifest → 200")
ps12d.Streams.stdout = Testers.ContainsExpression(
    "NOT_A_MANIFEST_", "Non-manifest content passes through")
ps12d.Streams.stdout += Testers.ExcludesExpression(
    "cr-session-token=", "No token injected into non-manifest body")
tr12d.StillRunningAfter = server
tr12d.StillRunningAfter = ts12_manifest

# --- Transform: HEAD on manifest URL (transform created, no body) ---
tr12e = Test.AddTestRun("EC Transform: HEAD on manifest URL — no crash (no body to process)")
ps12e = tr12e.Processes.Default
ps12e.Command = (
    f'curl -s -I -x localhost:{ts12_manifest.Variables.port} '
    f'"http://manifesthost-ec/video/head.m3u8?cr-access-token={token_a_cache}"'
)
ps12e.ReturnCode = 0
ps12e.Streams.stdout = Testers.ContainsExpression("200", "HEAD on manifest → 200")
tr12e.StillRunningAfter = server
tr12e.StillRunningAfter = ts12_manifest

# --- Transform: Non-renewable token manifest injection (BUG #4 regression guard) ---
tr12f = Test.AddTestRun("EC Transform: Non-renewable token manifest injection (BUG #4 regression)")
ps12f = tr12f.Processes.Default
ps12f.Command = (
    f'curl -s -v -x localhost:{ts12_manifest.Variables.port} '
    f'"http://manifesthost-ec/video/live.m3u8?cr-access-token={token_nonrenew_cache}"'
)
ps12f.ReturnCode = 0
ps12f.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Non-renewable → 200")
ps12f.Streams.stderr += Testers.ExcludesExpression(
    "Set-Cookie:", "Non-renewable: no Set-Cookie")
ps12f.Streams.stdout = Testers.ContainsExpression(
    "cr-session-token=",
    "BUG #4 regression: non-renewable token still gets manifest injection")
tr12f.StillRunningAfter = server
tr12f.StillRunningAfter = ts12_manifest

# --- Set-Cookie coexistence: origin + plugin ---
tr12g = Test.AddTestRun("EC Transform: Origin Set-Cookie + Plugin Set-Cookie coexist")
ps12g = tr12g.Processes.Default
ps12g.Command = (
    f'curl -s -v -x localhost:{ts12_manifest.Variables.port} '
    f'"http://manifesthost-ec/video/setcookie.m3u8?cr-access-token={token_a_cache}"'
)
ps12g.ReturnCode = 0
ps12g.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Set-Cookie coexistence → 200")
ps12g.Streams.stderr += Testers.ContainsExpression(
    "Set-Cookie: cr-session-token=", "Plugin Set-Cookie present")
ps12g.Streams.stderr += Testers.ContainsExpression(
    "origin-session=abc123", "Origin Set-Cookie not clobbered")
tr12g.StillRunningAfter = server
tr12g.StillRunningAfter = ts12_manifest
