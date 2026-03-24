'''
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
Test uri_signing plugin
'''

Test.ContinueOnFail = False

# Skip if plugins not present.
Test.SkipUnless(Condition.PluginExists('uri_signing.so'))

server = Test.MakeOriginServer("server")

# Default origin test
req_header = {
    "headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "",
}
res_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "",
}
server.addResponse("sessionfile.log", req_header, res_header)

# Test case for normal
req_header = {
    "headers": "GET /someasset.ts HTTP/1.1\r\nHost: somehost\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "",
}

res_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "somebody",
}

server.addResponse("sessionfile.log", req_header, res_header)

# Test case for crossdomain
req_header = {
    "headers": "GET /crossdomain.xml HTTP/1.1\r\nHost: somehost\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "",
}

res_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "<crossdomain></crossdomain>",
}

server.addResponse("sessionfile.log", req_header, res_header)

# http://user:password@host:port/path;params?query#fragment

# Define default ATS
ts = Test.MakeATSProcess("ts", enable_cache=False)
#ts = Test.MakeATSProcess("ts", "traffic_server_valgrind.sh")

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'uri_signing|http',
        #  'proxy.config.diags.debug.tags': 'uri_signing',
    })

# Use unchanged incoming URL.
ts.Disk.remap_config.AddLine(
    'map http://somehost/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
    ' @plugin=uri_signing.so @pparam={}/config.json'.format(Test.RunDirectory))

# Install configuration
ts.Setup.CopyAs('config.json', Test.RunDirectory)
ts.Setup.CopyAs('run_sign.sh', Test.RunDirectory)
ts.Setup.CopyAs('signer.json', Test.RunDirectory)
#ts.Setup.CopyAs('traffic_server_valgrind.sh', Test.RunDirectory)

curl_and_args = 'curl -q -v -x localhost:{} '.format(ts.Variables.port)

# 0 - reject unsigned request
tr = Test.AddTestRun("unsigned request")
ps = tr.Processes.Default
ps.StartBefore(ts)
ps.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
ps.Command = curl_and_args + 'http://somehost/someasset.ts'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 1 - accept a passthru request
tr = Test.AddTestRun("passthru request")
ps = tr.Processes.Default
ps.Command = curl_and_args + 'http://somehost/crossdomain.xml'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/200.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 2 - good token, signed "forever" (run_sign.sh 0)
tr = Test.AddTestRun("good signed")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9.zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/200.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 3 - expired token (run_sign.sh 1)
tr = Test.AddTestRun("expired signed")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjF9.GkdlOPHQc6BqS4Q6x79GeYuVFO2zuGbaPZZsJfD6ir8"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 4 - good token, different key (run_sign.sh 2)
tr = Test.AddTestRun("good token, second key")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9.ozH4sNwgcOlTZT0l4RQlVCH_osxz9yI1HCBesEv-jYg"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/200.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 5 - good token, inline
tr = Test.AddTestRun("good signed")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9.zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY/someasset.ts"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/200.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 6 - expired token, inline
tr = Test.AddTestRun("expired signed")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjF9.GkdlOPHQc6BqS4Q6x79GeYuVFO2zuGbaPZZsJfD6ir8/someasset.ts"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 7 - good token, param
tr = Test.AddTestRun("good signed, param")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts;cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9.zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/200.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 8 - expired token, param
tr = Test.AddTestRun("expired signed, param")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts;cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjF9.GkdlOPHQc6BqS4Q6x79GeYuVFO2zuGbaPZZsJfD6ir8"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 9 - let's cookie this
tr = Test.AddTestRun("good signed cookie")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts" -H "Cookie: cr-session-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9.zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/200.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 10 - expired cookie token
tr = Test.AddTestRun("expired signed cooked")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts" -H "Cookie: cr-session-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjF9.GkdlOPHQc6BqS4Q6x79GeYuVFO2zuGbaPZZsJfD6ir8"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 11 - multiple cookies (only cr-session-token is checked to avoid infinite loop)
tr = Test.AddTestRun("multiple cookies, only session token checked")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts" -H "Cookie: cr-session-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjF9.GkdlOPHQc6BqS4Q6x79GeYuVFO2zuGbaPZZsJfD6ir8;cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9.zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 12 - Check missing iss from the payload
tr = Test.AddTestRun("Missing iss field in the payload")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIkhTMjU2Igp9.ewogICJleHAiOiAxOTIzMDU2MDg0Cn0.zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    "Initial JWT Failure: iss is missing, must be present", "should fail the validation")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# BUG #8 Integration Tests - Missing/Invalid exp validation

# 13 - BUG #8 Test 1: Missing exp claim
tr = Test.AddTestRun("BUG #8: Token missing exp claim (should reject)")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIifQ.a2-6SvnP6ApYdicwpIIDIquevg5qWB3_RxwXt-VpnUg"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    "Initial JWT Failure: invalid exp claim", "should reject token without exp claim")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 14 - BUG #8 Test 2: Invalid exp value (string instead of number)
tr = Test.AddTestRun("BUG #8: Token with exp as string (should reject)")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOiJub3QtYS1udW1iZXIifQ.lv9pNd-mbY1IdVwD3mHncWkUutNsQgxov8K45VMHEgM"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    "Initial JWT Failure: invalid exp claim", "should reject token with invalid exp type")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# 15 - BUG #8 Test 3: Null exp value
tr = Test.AddTestRun("BUG #8: Token with exp as null (should reject)")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOm51bGx9.vzxjKU6fwP6_rS44Ijk-vYak2NgEc4e3WR7Tg0zH6rM"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    "Initial JWT Failure: invalid exp claim", "should reject token with null exp")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# BUG #5 Integration Tests - Negative cdniets validation

# ============================================================================
# BUG FIXES - Integration Tests
# ============================================================================

# 16 - BUG #5: Negative cdniets REJECTED (DoS prevention)
# Severity: P1 HIGH - DoS Attack Vector
# Tests that tokens with negative cdniets values are rejected at JWT validation
tr = Test.AddTestRun("BUG #5: Token with negative cdniets (should reject)")
ps = tr.Processes.Default
ps.Command = curl_and_args + '"http://somehost/someasset.ts?cr-access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODQsImNkbmlldHMiOi0zNjAwLCJjZG5pc3R0IjoxfQ.9bMqy44XXKo-bzwTy5tlNWDl8c0YcXFebAScWsdMjbg"'
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    "Initial JWT Failure: negative cdniets: -3600", "should reject token with negative cdniets")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# BUG #6: NULL Signer Crash Prevention (P1 HIGH - Service Outage)
# Unit tests verify config validation (fail-fast when renewal_kid missing)
# Integration tests coverage:
#   - manifest_injection_comprehensive.test.py (11 test runs)
#   - manifest_format_variations.test.py (14 test runs)
# These tests verify signer is non-NULL when renewal_kid is properly configured,
# serving as regression tests for BUG #6. Config validation is thoroughly tested
# in unit_tests/uri_signing_test.cc::BUG #6 (3 sections, 7 assertions).

# ==============================================================================
# RENEWAL THRESHOLD OPTIMIZATION - Integration Tests
# ==============================================================================
# Feature: renewal_threshold config option optimizes Set-Cookie header overhead
# by skipping token renewal when tokens are still fresh.
#
# Test Coverage (from COMPREHENSIVE_TEST_SCENARIOS_RENEWAL_OPTIMIZATION.md):
# 1. Expired token (exp < now) → 403 Forbidden (jwt_validate rejects)
# 2. Threshold=0.0 (default) + fresh token → Renew (backward compatible)
# 3. Threshold=3600 + fresh token (exp >> threshold) → Skip renewal (optimization)
# 4. Non-renewable token (cdnistt=0) → Never renew
# ==============================================================================

import json
import time
import os
from datetime import datetime, timedelta

# TESTING: Using python-jose to prove compatibility!
from jose import jwt  # python-jose library (should also work!)

# ==============================================================================
# Configuration Setup
# ==============================================================================

# Secret key (plain text for jwt.encode(), base64 for JWK config)
# NOTE: CRITICAL - jwt.encode() with PLAIN TEXT secret (NOT base64!)
# NOTE: JWK "k" parameter requires BASE64URL-encoded secret (RFC 7517)
# NOTE: python-jose ALSO needs plain text secret (same as PyJWT)
SECRET = "threshold-test-secret-key"  # ← PLAIN TEXT for jwt.encode()
SECRET_BASE64 = "dGhyZXNob2xkLXRlc3Qtc2VjcmV0LWtleQ=="  # ← BASE64 for JWK config
ISSUER = "issuer"
KID = "1"

# Config: threshold=0.0 (default, always renew)
config_threshold_default = {
    ISSUER: {
        "id": ISSUER,
        "renewal_kid": KID,
        "strip_token": True,
        "keys": [{
            "alg": "HS256",
            "k": SECRET_BASE64,  # Base64-encoded secret (same pattern as manifest tests)
            "kid": KID,
            "kty": "oct"
        }],
        "renewal_token": {
            "token_name": "cr-session-token",
            "renewal_threshold": 0.0  # Default: always renew
        }
    }
}

# Config: threshold=3600 (1 hour)
config_threshold_3600 = {
    ISSUER: {
        "id": ISSUER,
        "renewal_kid": KID,
        "strip_token": True,
        "keys": [{
            "alg": "HS256",
            "k": SECRET_BASE64,  # Base64-encoded secret
            "kid": KID,
            "kty": "oct"
        }],
        "renewal_token": {
            "token_name": "cr-session-token",
            "renewal_threshold": 3600.0  # 1 hour threshold
        }
    }
}

# ==============================================================================
# Token Generation (using python-jose with PLAIN TEXT secret)
# ==============================================================================

# Token 1: Expired token (exp in the past)
token_expired = jwt.encode({
    "iss": ISSUER,
    "exp": 1,  # Unix epoch + 1 second (expired in 1970)
    "cdnistt": 1,
    "cdniets": 3600,
    "cdniuc": "regex:.*"  # Note: "regex", not "uri-regex"!
}, SECRET, algorithm="HS256", headers={"kid": KID})  # SECRET = plain text!

# Token 2: Fresh renewable token (exp in 30 years, like manifest tests)
token_fresh_renewable = jwt.encode({
    "iss": ISSUER,
    "exp": int((datetime.now() + timedelta(days=365*30)).timestamp()),
    "cdnistt": 1,  # Renewable
    "cdniets": 3600,
    "cdniuc": "regex:.*"  # Note: "regex", not "uri-regex"!
}, SECRET, algorithm="HS256", headers={"kid": KID})

# Token 3: Fresh non-renewable token (exp in 30 years, cdnistt=0)
token_fresh_non_renewable = jwt.encode({
    "iss": ISSUER,
    "exp": int((datetime.now() + timedelta(days=365*30)).timestamp()),
    "cdnistt": 0,  # Non-renewable
    "cdniets": 3600,
    "cdniuc": "regex:.*"  # Note: "regex", not "uri-regex"!
}, SECRET, algorithm="HS256", headers={"kid": KID})

# ==============================================================================
# ATS Setup: threshold=0.0 (backward compatibility mode)
# ==============================================================================

ts_threshold_0 = Test.MakeATSProcess("ts-threshold-0", enable_cache=False)
ts_threshold_0.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing',
})

config_file_0 = os.path.join(Test.RunDirectory, "config_threshold_0.json")
with open(config_file_0, 'w') as f:
    json.dump(config_threshold_default, f, indent=2)

ts_threshold_0.Disk.remap_config.AddLine(
    'map http://thresholdhost/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
    ' @plugin=uri_signing.so @pparam={}'.format(config_file_0)
)

# ==============================================================================
# ATS Setup: threshold=3600 (optimization enabled)
# ==============================================================================

ts_threshold_3600 = Test.MakeATSProcess("ts-threshold-3600", enable_cache=False)
ts_threshold_3600.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing',
})

config_file_3600 = os.path.join(Test.RunDirectory, "config_threshold_3600.json")
with open(config_file_3600, 'w') as f:
    json.dump(config_threshold_3600, f, indent=2)

ts_threshold_3600.Disk.remap_config.AddLine(
    'map http://thresholdhost/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
    ' @plugin=uri_signing.so @pparam={}'.format(config_file_3600)
)

# ==============================================================================
# Origin Server Response for Threshold Tests
# ==============================================================================

req_threshold = {
    "headers": "GET /threshold-test HTTP/1.1\r\nHost: thresholdhost\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "",
}
res_threshold = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "threshold-test-success",
}
server.addResponse("sessionfile.log", req_threshold, res_threshold)

# ==============================================================================
# TEST 17: Expired token → 403 Forbidden (jwt_validate rejects)
# ==============================================================================

tr = Test.AddTestRun("THRESHOLD: Expired token (exp < now) → 403 Forbidden")
ps = tr.Processes.Default
ps.StartBefore(ts_threshold_0)
ps.Command = 'curl -q -v -x localhost:{} "http://thresholdhost/threshold-test?cr-access-token={}"'.format(
    ts_threshold_0.Variables.port, token_expired)
ps.ReturnCode = 0
ps.Streams.stderr = "gold/403.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_threshold_0

# ==============================================================================
# TEST 18: threshold=0.0 + fresh token → MUST renew (backward compatible)
# ==============================================================================

tr = Test.AddTestRun("THRESHOLD: threshold=0.0 + fresh token → MUST renew")
ps = tr.Processes.Default
ps.Command = 'curl -q -v -x localhost:{} "http://thresholdhost/threshold-test?cr-access-token={}"'.format(
    ts_threshold_0.Variables.port, token_fresh_renewable)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("Set-Cookie: cr-session-token=",
    "threshold=0.0 should ALWAYS renew (backward compatible)")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_threshold_0

# ==============================================================================
# TEST 19: threshold=3600 + ACCESS token → MUST renew (BUG #9 fix)
# Access tokens always create session tokens regardless of threshold.
# ==============================================================================

tr = Test.AddTestRun("THRESHOLD: Access token + threshold=3600 → MUST renew (BUG #9 fix)")
ps = tr.Processes.Default
ps.StartBefore(ts_threshold_3600)
ps.Command = 'curl -q -v -x localhost:{} "http://thresholdhost/threshold-test?cr-access-token={}"'.format(
    ts_threshold_3600.Variables.port, token_fresh_renewable)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("Set-Cookie: cr-session-token=",
    "Access token must ALWAYS create session token, even with large threshold")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_threshold_3600

# ==============================================================================
# TEST 20: Non-renewable token (cdnistt=0) → NEVER renew
# ==============================================================================

tr = Test.AddTestRun("THRESHOLD: Non-renewable token (cdnistt=0) → NEVER renew")
ps = tr.Processes.Default
ps.Command = 'curl -q -v -x localhost:{} "http://thresholdhost/threshold-test?cr-access-token={}"'.format(
    ts_threshold_0.Variables.port, token_fresh_non_renewable)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ExcludesExpression("Set-Cookie:",
    "Non-renewable token (cdnistt=0) should NEVER renew")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_threshold_0

# ==============================================================================
# BUG #9: Access token must ALWAYS create session token (ignore threshold)
# BUG #10: Manifest injection must use session token, not fallback to access token
# ==============================================================================
# CURRENT BEHAVIOR (BUGGY):
#   Access token + threshold=3600 + fresh token → SKIP renewal → No Set-Cookie
# EXPECTED BEHAVIOR (AFTER FIX):
#   Access token + threshold=3600 + fresh token → ALWAYS renew → Set-Cookie issued
#   Session token + threshold=3600 + fresh → SKIP renewal (correct)
# ==============================================================================

# Token for BUG #9 tests: session token (simulates what CDN generates)
# This token has cdnistt=1 so it can be renewed, and uses far-future exp
token_session = jwt.encode({
    "iss": ISSUER,
    "exp": int((datetime.now() + timedelta(days=365*30)).timestamp()),
    "cdnistt": 1,
    "cdniets": 300,
    "cdniuc": "regex:.*"
}, SECRET, algorithm="HS256", headers={"kid": KID})

# TEST 21: BUG #9 - Access token + threshold>0 → MUST renew (create session token)
tr = Test.AddTestRun("BUG #9: Access token + threshold=3600 → MUST issue Set-Cookie")
ps = tr.Processes.Default
ps.Command = 'curl -q -v -x localhost:{} "http://thresholdhost/threshold-test?cr-access-token={}"'.format(
    ts_threshold_3600.Variables.port, token_fresh_renewable)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("Set-Cookie: cr-session-token=",
    "BUG #9: Access token must ALWAYS create session token, even with threshold=3600")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_threshold_3600

# TEST 22: BUG #9 - Session token + threshold>0 + fresh → SKIP renewal
tr = Test.AddTestRun("BUG #9: Session token + threshold=3600 + fresh → NO Set-Cookie")
ps = tr.Processes.Default
ps.Command = 'curl -q -v -x localhost:{} "http://thresholdhost/threshold-test" -H "Cookie: cr-session-token={}"'.format(
    ts_threshold_3600.Variables.port, token_session)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ExcludesExpression("Set-Cookie:",
    "BUG #9: Session token still fresh → skip renewal (threshold optimization)")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_threshold_3600
# ==============================================================================
# AUTH DIRECTIVE & BEHAVIORAL EDGE CASES
# ==============================================================================

# Token constants (same tokens used in tests 2 and 3 above)
_EC_TOKEN_VALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9.zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY"
_EC_TOKEN_EXPIRED = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjF9.GkdlOPHQc6BqS4Q6x79GeYuVFO2zuGbaPZZsJfD6ir8"
_EC_LONG_PATH = "/longpath" + "a" * 500


def _ec_add(path, body, host, status="200 OK", method="GET"):
    server.addResponse("sessionfile.log",
                       {"headers": "{} {} HTTP/1.1\r\nHost: {}\r\n\r\n".format(method, path, host),
                        "timestamp": "1469733493.993", "body": ""},
                       {"headers": "HTTP/1.1 {}\r\nConnection: close\r\n\r\n".format(status),
                        "timestamp": "1469733493.993", "body": body})


# Origin responses for edgehost (auth+strip tests)
_ec_add("/someasset.ts", "somebody", "edgehost")
_ec_add("/crossdomain.xml", "<crossdomain/>", "edgehost")
_ec_add("/style.css", "body{}", "edgehost")
_ec_add("/headtest.ts", "head-body-data", "edgehost")
_ec_add("/nonexistent", "Not Found", "edgehost", "404 Not Found")
_ec_add(_EC_LONG_PATH, "long-url-response", "edgehost")
_ec_add("/someasset.ts", "post-response", "edgehost", method="POST")
_ec_add("/someasset.ts?quality=high&bitrate=1000", "somebody", "edgehost")
_ec_add("/someasset.ts?before=1&after=2", "somebody", "edgehost")

# Origin responses for multihost (multi-issuer tests)
_ec_add("/style.css", "body{}", "multihost")
_ec_add("/app.js", "console.log(1)", "multihost")
_ec_add("/data.json", "{}", "multihost")


def _ec_write_config(name, config_dict):
    path = os.path.join(Test.RunDirectory, "ec_config_{}.json".format(name))
    with open(path, 'w') as f:
        json.dump(config_dict, f, indent=2)
    return path


_ec_config_edge = _ec_write_config("edge", {
    "issuer": {
        "id": "issuer",
        "renewal_kid": "1",
        "strip_token": True,
        "auth_directives": [
            {"auth": "allow", "uri": "regex:.*crossdomain\\.xml"},
            {"auth": "allow", "uri": "regex:.*\\.css"},
        ],
        "keys": [
            {"alg": "HS256", "k": "SECRET00", "kid": "0", "kty": "oct"},
            {"alg": "HS256", "k": "SECRET01", "kid": "1", "kty": "oct"},
        ]
    }
})

_ec_config_multi = _ec_write_config("multi", {
    "issuer-css": {
        "auth_directives": [{"auth": "allow", "uri": "regex:.*\\.css$"}],
        "keys": [{"alg": "HS256", "k": "SECRET00", "kid": "0", "kty": "oct"}]
    },
    "issuer-js": {
        "auth_directives": [{"auth": "allow", "uri": "regex:.*\\.js$"}],
        "keys": [{"alg": "HS256", "k": "SECRET01", "kid": "1", "kty": "oct"}]
    }
})

ts_edge = Test.MakeATSProcess("ts-edge", enable_cache=False)
ts_edge.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing',
})
ts_edge.Disk.remap_config.AddLine(
    'map http://edgehost/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
    ' @plugin=uri_signing.so @pparam={}'.format(_ec_config_edge))

ts_multi_ec = Test.MakeATSProcess("ts-multi-ec", enable_cache=False)
ts_multi_ec.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing',
})
ts_multi_ec.Disk.remap_config.AddLine(
    'map http://multihost/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
    ' @plugin=uri_signing.so @pparam={}'.format(_ec_config_multi))

_EC_PORT = ts_edge.Variables.port
_EC_PORT_MULTI = ts_multi_ec.Variables.port

# --- Keep-alive: no state leakage between 3 requests on same connection ---
tr = Test.AddTestRun("EC: Keep-alive no state leakage between requests")
ps = tr.Processes.Default
ps.StartBefore(ts_edge)
ps.Command = (
    'curl -s -v '
    '-x localhost:{port} '
    '"http://edgehost/someasset.ts?cr-access-token={token}" '
    '"http://edgehost/someasset.ts" '
    '"http://edgehost/crossdomain.xml"'
).format(port=_EC_PORT, token=_EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Req 1 valid token → 200")
ps.Streams.stderr += Testers.ContainsExpression("HTTP/1.1 403", "Req 2 no token → 403 (no state leak)")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

# --- Auth-allow: token (even expired) on auth-allowed URL → 200 ---
tr = Test.AddTestRun("EC: Token on auth-allow URL with strip_token → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{} "http://edgehost/crossdomain.xml?cr-access-token={}"'
).format(_EC_PORT, _EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "auth-allow + token → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Expired token on auth-allow URL → 200 (auth-allow bypasses validation)")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{} "http://edgehost/crossdomain.xml?cr-access-token={}"'
).format(_EC_PORT, _EC_TOKEN_EXPIRED)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "auth-allow bypasses token validation")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: CSS file allowed without token (auth_directive extension match)")
ps = tr.Processes.Default
ps.Command = 'curl -s -v -x localhost:{} "http://edgehost/style.css"'.format(_EC_PORT)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "CSS allowed without token")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

# --- Token priority: URL vs Cookie ---
tr = Test.AddTestRun("EC: URL token takes priority over Cookie token")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} '
    '"http://edgehost/someasset.ts?cr-access-token={valid}" '
    '-H "Cookie: cr-session-token={valid}"'
).format(port=_EC_PORT, valid=_EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Both valid → 200 (URL wins)")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Valid URL token + expired Cookie → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} '
    '"http://edgehost/someasset.ts?cr-access-token={valid}" '
    '-H "Cookie: cr-session-token={expired}"'
).format(port=_EC_PORT, valid=_EC_TOKEN_VALID, expired=_EC_TOKEN_EXPIRED)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Valid URL overrides expired cookie")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: No URL token + valid Cookie → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} "http://edgehost/someasset.ts" '
    '-H "Cookie: cr-session-token={valid}"'
).format(port=_EC_PORT, valid=_EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Valid cookie without URL token → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

# --- Error handling ---
tr = Test.AddTestRun("EC: HEAD on protected URL without token → 403")
ps = tr.Processes.Default
ps.Command = 'curl -s -I -x localhost:{} "http://edgehost/someasset.ts"'.format(_EC_PORT)
ps.ReturnCode = 0
ps.Streams.stdout = Testers.ContainsExpression("403", "HEAD without token → 403")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: HEAD on protected URL with token → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -I -x localhost:{} "http://edgehost/headtest.ts?cr-access-token={}"'
).format(_EC_PORT, _EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stdout = Testers.ContainsExpression("200", "HEAD with valid token → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Valid token + origin returns 404 → plugin passes through (not 403)")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{} "http://edgehost/nonexistent?cr-access-token={}"'
).format(_EC_PORT, _EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 404", "Origin 404 passed through")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Long URL (500+ char path) with valid token → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} "http://edgehost{path}?cr-access-token={token}"'
).format(port=_EC_PORT, path=_EC_LONG_PATH, token=_EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Long URL with valid token → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Garbage token string → 403")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{} '
    '"http://edgehost/someasset.ts?cr-access-token=NOT.A.VALID.JWT.TOKEN"'
).format(_EC_PORT)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 403", "Garbage token → 403")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Empty token value → 403")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{} "http://edgehost/someasset.ts?cr-access-token="'
).format(_EC_PORT)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 403", "Empty token → 403")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: POST with valid token → 200 (method-agnostic)")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -X POST -H "Content-Length: 0" -x localhost:{} '
    '"http://edgehost/someasset.ts?cr-access-token={}"'
).format(_EC_PORT, _EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "POST with valid token → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: OPTIONS without token → 403")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -X OPTIONS -x localhost:{} "http://edgehost/someasset.ts"'
).format(_EC_PORT)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 403", "OPTIONS without token → 403")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

# --- Cookie edge cases ---
_ec_big_cookie = "; ".join(
    ["adtracker{}=val{}".format(i, i) for i in range(20)] +
    ["cr-session-token={}".format(_EC_TOKEN_VALID)])

tr = Test.AddTestRun("EC: Valid token among 20 irrelevant cookies → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} "http://edgehost/someasset.ts" '
    '-H "Cookie: {cookie}"'
).format(port=_EC_PORT, cookie=_ec_big_cookie)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Valid token in large cookie header → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Session token at beginning of cookie header → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} "http://edgehost/someasset.ts" '
    '-H "Cookie: cr-session-token={token}; other=val"'
).format(port=_EC_PORT, token=_EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Token at start of cookie → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Only irrelevant cookies (no session token) → 403")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} "http://edgehost/someasset.ts" '
    '-H "Cookie: analytics=abc; prefs=dark; lang=en"'
).format(port=_EC_PORT)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 403", "Only irrelevant cookies → 403")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

# --- URL param positioning ---
tr = Test.AddTestRun("EC: Token after other query params → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} '
    '"http://edgehost/someasset.ts?quality=high&bitrate=1000&cr-access-token={token}"'
).format(port=_EC_PORT, token=_EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Token after other params → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

tr = Test.AddTestRun("EC: Token in middle of query string → 200")
ps = tr.Processes.Default
ps.Command = (
    'curl -s -v -x localhost:{port} '
    '"http://edgehost/someasset.ts?before=1&cr-access-token={token}&after=2"'
).format(port=_EC_PORT, token=_EC_TOKEN_VALID)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "Token in middle of query string → 200")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_edge

# --- Multi-issuer: realloc code path in config.c ---
tr = Test.AddTestRun("EC: Multi-issuer CSS auth_directive → 200 (realloc path)")
ps = tr.Processes.Default
ps.StartBefore(ts_multi_ec)
ps.Command = 'curl -s -v -x localhost:{} "http://multihost/style.css"'.format(_EC_PORT_MULTI)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "CSS allowed by issuer-css")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_multi_ec

tr = Test.AddTestRun("EC: Multi-issuer JS auth_directive → 200")
ps = tr.Processes.Default
ps.Command = 'curl -s -v -x localhost:{} "http://multihost/app.js"'.format(_EC_PORT_MULTI)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 200", "JS allowed by issuer-js")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_multi_ec

tr = Test.AddTestRun("EC: Multi-issuer no matching directive → 403")
ps = tr.Processes.Default
ps.Command = 'curl -s -v -x localhost:{} "http://multihost/data.json"'.format(_EC_PORT_MULTI)
ps.ReturnCode = 0
ps.Streams.stderr = Testers.ContainsExpression("HTTP/1.1 403", "JSON not allowed → 403")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_multi_ec
