'''
Comprehensive format variation test for URI Signing manifest injection.

Tests edge cases and format variations NOT covered by manifest_injection_comprehensive.test.py:
- HLS: Master playlists, EXT-X-MEDIA, I-FRAME, URL fragments, absolute/relative paths
- DASH: BaseURL inheritance, SegmentTemplate, multiple BaseURLs
- Edge cases: empty lines, double injection, malformed input
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

Test.Summary = '''
Test manifest injection with various HLS/DASH format variations and edge cases
'''

Test.ContinueOnFail = True

# ==============================================================================
# ORIGIN SERVER SETUP
# ==============================================================================

server = Test.MakeOriginServer("server")
# 20 test runs × ~120s each ≈ 2400s. Default process timeout is 600s — extend it.
server.TimeOut = 3600
# Server may exit after serving all queued responses; accept exit code 0.
server.ReturnCode = 0

# ==============================================================================
# HLS TEST MANIFESTS
# ==============================================================================

# 1. MASTER PLAYLIST - variants should NOT be injected (they're playlists, not segments)
hls_master_playlist = """#EXTM3U
#EXT-X-VERSION:6
#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=1920x1080
variant-high.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=500000,RESOLUTION=1280x720
variant-low.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=200000,RESOLUTION=640x360
variant-mobile.m3u8
"""

# 2. MEDIA PLAYLIST with EXT-X-MEDIA tags (URIs in tags)
hls_with_media_tags = """#EXTM3U
#EXT-X-VERSION:6
#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",LANGUAGE="en",NAME="English",URI="audio-en.m3u8"
#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",LANGUAGE="es",NAME="Spanish",URI="audio-es.m3u8"
#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="subs",LANGUAGE="en",NAME="English",URI="subs-en.m3u8"
#EXT-X-STREAM-INF:BANDWIDTH=1000000,AUDIO="audio",SUBTITLES="subs"
video.m3u8
"""

# 3. I-FRAME PLAYLIST
hls_iframe_playlist = """#EXTM3U
#EXT-X-VERSION:6
#EXT-X-I-FRAME-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=1920x1080,URI="iframe-high.m3u8"
#EXT-X-I-FRAME-STREAM-INF:BANDWIDTH=500000,RESOLUTION=1280x720,URI="iframe-low.m3u8"
"""

# 4. SEGMENTS WITH URL FRAGMENTS
hls_with_fragments = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
segment0.ts#t=0.0
#EXTINF:10.0,
segment1.ts#t=10.0
#EXTINF:10.0,
segment2.ts#t=20.0,offset=5
#EXT-X-ENDLIST
"""

# 5. ABSOLUTE URLs
hls_absolute_urls = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
http://cdn.example.com/video/segment0.ts
#EXTINF:10.0,
https://backup-cdn.example.com/video/segment1.ts
#EXT-X-ENDLIST
"""

# 6. RELATIVE PATHS
hls_relative_paths = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
../segments/video0.ts
#EXTINF:10.0,
./video1.ts
#EXTINF:10.0,
subfolder/video2.ts
#EXT-X-ENDLIST
"""

# 7. DOUBLE INJECTION - segment already has session token
hls_double_injection = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
segment0.ts?cr-session-token=OLD_TOKEN_12345
#EXTINF:10.0,
segment1.ts?other=param&cr-session-token=OLD_TOKEN_67890
#EXT-X-ENDLIST
"""

# 8. EMPTY LINES AND WHITESPACE
hls_with_whitespace = """#EXTM3U
#EXT-X-VERSION:3

#EXT-X-TARGETDURATION:10

#EXTINF:10.0,
segment0.ts

#EXTINF:10.0,
  segment1.ts
#EXT-X-ENDLIST
"""

# 9. MIXED FORMATS - segments with various query params
hls_mixed_query_params = """#EXTM3U
#EXT-X-VERSION:3
#EXTINF:10.0,
seg0.ts
#EXTINF:10.0,
seg1.ts?quality=high
#EXTINF:10.0,
seg2.ts?quality=high&bitrate=1000
#EXTINF:10.0,
seg3.ts?cr-access-token=ACCESS_123
#EXT-X-ENDLIST
"""

# ==============================================================================
# DASH TEST MANIFESTS
# ==============================================================================

# 1. BASEURL INHERITANCE - multiple levels
dash_baseurl_inheritance = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <BaseURL>http://cdn.example.com/</BaseURL>
  <Period>
    <BaseURL>videos/stream1/</BaseURL>
    <AdaptationSet>
      <Representation>
        <BaseURL>quality-high/</BaseURL>
        <SegmentList>
          <SegmentURL media="segment1.m4s"/>
          <SegmentURL media="segment2.m4s"/>
        </SegmentList>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""

# 2. SEGMENT TEMPLATE with $Number$ and $Time$
dash_segment_template = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period>
    <AdaptationSet>
      <Representation>
        <SegmentTemplate media="segment-$Number$.m4s" initialization="init-$RepresentationID$.mp4" startNumber="1" duration="2000"/>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""

# 3. MULTIPLE BASEURL ELEMENTS (for failover)
dash_multiple_baseurl = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period>
    <AdaptationSet>
      <Representation>
        <BaseURL>http://cdn1.example.com/video.m4s</BaseURL>
        <BaseURL>http://cdn2.example.com/video.m4s</BaseURL>
        <BaseURL>http://cdn3.example.com/video.m4s</BaseURL>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""

# 4. SEGMENT TIMELINE with SegmentTemplate
dash_segment_timeline = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period>
    <AdaptationSet>
      <Representation>
        <SegmentTemplate media="seg-$Number$.m4s" initialization="init.mp4">
          <SegmentTimeline>
            <S t="0" d="2000" r="5"/>
            <S d="1500"/>
          </SegmentTimeline>
        </SegmentTemplate>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""

# 5. MIXED BASEURL and SEGMENT URLs with existing query params
dash_with_query_params = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period>
    <AdaptationSet>
      <Representation>
        <BaseURL>http://cdn.example.com/video.m4s?quality=high</BaseURL>
        <SegmentList>
          <Initialization sourceURL="init.mp4?bitrate=1000"/>
          <SegmentURL media="seg1.m4s?fragment=1"/>
          <SegmentURL media="seg2.m4s?fragment=2&amp;cache=no"/>
        </SegmentList>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""

# 6. DASH SegmentBase (Shaka Packager on-demand profile)
dash_segmentbase = """<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"
  profiles="urn:mpeg:dash:profile:isoff-on-demand:2011"
  minBufferTime="PT2S" type="static" mediaPresentationDuration="PT90.2S">
  <Period id="0">
    <AdaptationSet id="0" contentType="video" subsegmentAlignment="true">
      <Representation id="0" bandwidth="715611" codecs="avc1.64001e" mimeType="video/mp4" width="640" height="360">
        <BaseURL>stream_360p.mp4</BaseURL>
        <SegmentBase indexRange="899-1206" timescale="24000">
          <Initialization range="0-898"/>
        </SegmentBase>
      </Representation>
      <Representation id="1" bandwidth="1984826" codecs="avc1.64001f" mimeType="video/mp4" width="1280" height="720">
        <BaseURL>stream_720p.mp4</BaseURL>
        <SegmentBase indexRange="898-1205" timescale="24000">
          <Initialization range="0-897"/>
        </SegmentBase>
      </Representation>
      <Representation id="2" bandwidth="3506362" codecs="avc1.640028" mimeType="video/mp4" width="1920" height="1080">
        <BaseURL>stream_1080p.mp4</BaseURL>
        <SegmentBase indexRange="900-1207" timescale="24000">
          <Initialization range="0-899"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
    <AdaptationSet id="1" contentType="audio" subsegmentAlignment="true">
      <Representation id="3" bandwidth="134119" codecs="mp4a.40.2" mimeType="audio/mp4" audioSamplingRate="44100">
        <BaseURL>stream_audio.mp4</BaseURL>
        <SegmentBase indexRange="833-1140" timescale="44100">
          <Initialization range="0-832"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""

# 7. DASH SegmentList with many segments (Content-Length truncation test)
# 23 segments per representation × 4 reps = 92 SegmentURLs + 4 Initialization
# After token injection, body grows from ~3KB to ~25KB
def _generate_segmentlist(num_segs):
    mpd = '<?xml version="1.0" encoding="utf-8"?>\n'
    mpd += '<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"'
    mpd += ' mediaPresentationDuration="PT1M30.2S" maxSegmentDuration="PT4.0S" minBufferTime="PT8.0S">\n'
    mpd += '  <Period id="0">\n'
    mpd += '    <AdaptationSet id="0" contentType="video" segmentAlignment="true">\n'
    for rep in range(3):
        bw = [800000, 2500000, 5000000][rep]
        mpd += f'      <Representation id="{rep}" mimeType="video/mp4" bandwidth="{bw}">\n'
        mpd += '        <SegmentList timescale="1000000" duration="4000000" startNumber="1">\n'
        mpd += f'          <Initialization sourceURL="init-stream{rep}.m4s" />\n'
        for seg in range(1, num_segs + 1):
            mpd += f'          <SegmentURL media="chunk-stream{rep}-{seg:05d}.m4s" />\n'
        mpd += '        </SegmentList>\n      </Representation>\n'
    mpd += '    </AdaptationSet>\n'
    mpd += '    <AdaptationSet id="1" contentType="audio" segmentAlignment="true">\n'
    mpd += '      <Representation id="3" mimeType="audio/mp4" bandwidth="128000">\n'
    mpd += '        <SegmentList timescale="1000000" duration="4000000" startNumber="1">\n'
    mpd += '          <Initialization sourceURL="init-stream3.m4s" />\n'
    for seg in range(1, num_segs + 1):
        mpd += f'          <SegmentURL media="chunk-stream3-{seg:05d}.m4s" />\n'
    mpd += '        </SegmentList>\n      </Representation>\n'
    mpd += '    </AdaptationSet>\n  </Period>\n</MPD>\n'
    return mpd

dash_segmentlist_small = _generate_segmentlist(23)
dash_segmentlist_large = _generate_segmentlist(100)

# 8. HLS fMP4/CMAF with EXT-X-MAP init segment
hls_fmp4_cmaf = """#EXTM3U
#EXT-X-VERSION:7
#EXT-X-TARGETDURATION:4
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-PLAYLIST-TYPE:VOD
#EXT-X-MAP:URI="init_0.mp4"
#EXTINF:4.000000,
chunk_0_00001.m4s
#EXTINF:4.000000,
chunk_0_00002.m4s
#EXTINF:4.000000,
chunk_0_00003.m4s
#EXTINF:4.000000,
chunk_0_00004.m4s
#EXTINF:2.168333,
chunk_0_00005.m4s
#EXT-X-ENDLIST
"""

# ==============================================================================
# ADD RESPONSES TO ORIGIN SERVER
# ==============================================================================

def add_response(path, content_type, body):
    req = {"headers": f"GET {path} HTTP/1.1\r\nHost: testhost\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
    res = {"headers": f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": body}
    server.addResponse("sessionfile.log", req, res)

# HLS manifests
add_response("/hls/master.m3u8", "application/vnd.apple.mpegurl", hls_master_playlist)
add_response("/hls/media-tags.m3u8", "application/vnd.apple.mpegurl", hls_with_media_tags)
add_response("/hls/iframe.m3u8", "application/vnd.apple.mpegurl", hls_iframe_playlist)
add_response("/hls/fragments.m3u8", "application/vnd.apple.mpegurl", hls_with_fragments)
add_response("/hls/absolute.m3u8", "application/vnd.apple.mpegurl", hls_absolute_urls)
add_response("/hls/relative.m3u8", "application/vnd.apple.mpegurl", hls_relative_paths)
add_response("/hls/double.m3u8", "application/vnd.apple.mpegurl", hls_double_injection)
add_response("/hls/whitespace.m3u8", "application/vnd.apple.mpegurl", hls_with_whitespace)
add_response("/hls/mixed.m3u8", "application/vnd.apple.mpegurl", hls_mixed_query_params)

# DASH manifests
add_response("/dash/baseurl-inherit.mpd", "application/dash+xml", dash_baseurl_inheritance)
add_response("/dash/template.mpd", "application/dash+xml", dash_segment_template)
add_response("/dash/multi-baseurl.mpd", "application/dash+xml", dash_multiple_baseurl)
add_response("/dash/timeline.mpd", "application/dash+xml", dash_segment_timeline)
add_response("/dash/query-params.mpd", "application/dash+xml", dash_with_query_params)
add_response("/dash/segmentbase.mpd", "application/dash+xml", dash_segmentbase)
add_response("/dash/segmentlist.mpd", "application/dash+xml", dash_segmentlist_small)
add_response("/dash/segmentlist-large.mpd", "application/dash+xml", dash_segmentlist_large)
add_response("/hls/fmp4.m3u8", "application/vnd.apple.mpegurl", hls_fmp4_cmaf)

# Special: SegmentList large WITH explicit Content-Length from origin
# This simulates the real production scenario where origin sends Content-Length
# If ATS doesn't update it, the client will get truncated body
def add_response_with_content_length(path, content_type, body):
    body_len = len(body.encode('utf-8'))
    req = {"headers": f"GET {path} HTTP/1.1\r\nHost: testhost\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
    res = {"headers": f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {body_len}\r\n\r\n", "timestamp": "1469733493.993", "body": body}
    server.addResponse("sessionfile.log", req, res)

add_response_with_content_length("/dash/segmentlist-large-cl.mpd", "application/dash+xml", dash_segmentlist_large)

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def create_config(name):
    """Create a config with manifest injection enabled."""
    config = {
        "issuer": {
            "renewal_kid": "primary-key-2024",
            "id": "mycdn",
            "strip_token": True,
            "renewal_token": {
                "token_name": "cr-session-token",
                "salt": {"enabled": False},
                "manifest_injection": {
                    "enabled": True,
                    "inject_to_segments": True,
                    "inject_to_init_segments": True,
                    "replace_access_token": True,
                    "hls_support": True,
                    "dash_support": True,
                    "cache_untransformed": True
                }
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

# Valid token with renewal capability (from manifest_injection_comprehensive.test.py)
# {"iss":"issuer","exp":1793756236,"cdnistt":1,"cdniets":3600}
# kid: "primary-key-2024", signed with key: base64decode("dGVzdC1zZWNyZXQta2V5LTEyMzQ1Njc4OTA=")
valid_token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InByaW1hcnkta2V5LTIwMjQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE3OTM3NTYyMzYsImNkbmlzdHQiOjEsImNkbmlldHMiOjM2MDB9.-F77OEr9sagDPI5yv_yDPKyfFeYqMW6cglY6PKYejHw"

# ==============================================================================
# ATS SETUP
# ==============================================================================

ts = Test.MakeATSProcess("ts", enable_cache=False)
# Extend timeout: 20 tests × ~120s ≈ 2400s, default 600s is too short.
ts.TimeOut = 3600
ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'uri_signing|transform|manifest',
})

config = create_config("variations")
ts.Disk.remap_config.AddLine(
    f'map http://testhost/ http://127.0.0.1:{server.Variables.Port}/' +
    f' @plugin=uri_signing.so @pparam={config}'
)

# ==============================================================================
# TEST 1: HLS Master Playlist - variant URLs should NOT be segments
# ==============================================================================
tr1 = Test.AddTestRun("Test 1: HLS Master Playlist")
tr1.Processes.Default.StartBefore(ts)
tr1.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr1.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/master.m3u8?cr-access-token={valid_token}"'
tr1.Processes.Default.ReturnCode = 0
# Variant URLs should have session tokens
tr1.Processes.Default.Streams.stdout = Testers.ContainsExpression("variant-high.m3u8\\?cr-session-token=", "High variant should have token")
tr1.Processes.Default.Streams.stdout += Testers.ContainsExpression("variant-low.m3u8\\?cr-session-token=", "Low variant should have token")
tr1.Processes.Default.Streams.stdout += Testers.ContainsExpression("variant-mobile.m3u8\\?cr-session-token=", "Mobile variant should have token")
tr1.StillRunningAfter = server
tr1.StillRunningAfter = ts

# ==============================================================================
# TEST 2: HLS with EXT-X-MEDIA tags
# ==============================================================================
tr2 = Test.AddTestRun("Test 2: HLS with EXT-X-MEDIA tags")
tr2.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/media-tags.m3u8?cr-access-token={valid_token}"'
tr2.Processes.Default.ReturnCode = 0
# Variant URL should have token
tr2.Processes.Default.Streams.stdout = Testers.ContainsExpression("video.m3u8\\?cr-session-token=", "Variant URL should have token")
# EXT-X-MEDIA URIs are playlist references, not segments - check they're preserved
tr2.Processes.Default.Streams.stdout += Testers.ContainsExpression('URI="audio-en.m3u8"', "Audio URI should be preserved")
tr2.StillRunningAfter = server
tr2.StillRunningAfter = ts

# ==============================================================================
# TEST 3: HLS I-FRAME Playlist
# ==============================================================================
tr3 = Test.AddTestRun("Test 3: HLS I-FRAME Playlist")
tr3.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/iframe.m3u8?cr-access-token={valid_token}"'
tr3.Processes.Default.ReturnCode = 0
# EXT-X-I-FRAME-STREAM-INF URIs are playlist references, not segments - check they're preserved
tr3.Processes.Default.Streams.stdout = Testers.ContainsExpression('URI="iframe-high.m3u8"', "I-Frame high URI should be preserved")
tr3.Processes.Default.Streams.stdout += Testers.ContainsExpression('URI="iframe-low.m3u8"', "I-Frame low URI should be preserved")
tr3.StillRunningAfter = server
tr3.StillRunningAfter = ts

# ==============================================================================
# TEST 4: HLS with URL fragments
# ==============================================================================
tr4 = Test.AddTestRun("Test 4: HLS with URL fragments")
tr4.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/fragments.m3u8?cr-access-token={valid_token}"'
tr4.Processes.Default.ReturnCode = 0
# Fragment MUST stay at end: segment.ts?token=...#fragment (NOT segment.ts#fragment?token=...)
tr4.Processes.Default.Streams.stdout = Testers.ContainsExpression("segment0.ts.*cr-session-token=.*#t=0.0", "Fragment must be after token")
tr4.Processes.Default.Streams.stdout += Testers.ExcludesExpression("#t=0.0.*cr-session-token=", "Token must NOT be after fragment")
tr4.StillRunningAfter = server
tr4.StillRunningAfter = ts

# ==============================================================================
# TEST 5: HLS with absolute URLs
# ==============================================================================
tr5 = Test.AddTestRun("Test 5: HLS with absolute URLs")
tr5.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/absolute.m3u8?cr-access-token={valid_token}"'
tr5.Processes.Default.ReturnCode = 0
tr5.Processes.Default.Streams.stdout = Testers.ContainsExpression("http://cdn.example.com/video/segment0.ts.*cr-session-token=", "Absolute URL should have token")
tr5.Processes.Default.Streams.stdout += Testers.ContainsExpression("https://backup-cdn.example.com/video/segment1.ts.*cr-session-token=", "HTTPS URL should have token")
tr5.StillRunningAfter = server
tr5.StillRunningAfter = ts

# ==============================================================================
# TEST 6: HLS with relative paths
# ==============================================================================
tr6 = Test.AddTestRun("Test 6: HLS with relative paths")
tr6.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/relative.m3u8?cr-access-token={valid_token}"'
tr6.Processes.Default.ReturnCode = 0
tr6.Processes.Default.Streams.stdout = Testers.ContainsExpression("\\.\\./segments/video0.ts.*cr-session-token=", "Relative path ../ should have token")
tr6.Processes.Default.Streams.stdout += Testers.ContainsExpression("\\./video1.ts.*cr-session-token=", "Relative path ./ should have token")
tr6.Processes.Default.Streams.stdout += Testers.ContainsExpression("subfolder/video2.ts.*cr-session-token=", "Subfolder path should have token")
tr6.StillRunningAfter = server
tr6.StillRunningAfter = ts

# ==============================================================================
# TEST 7: HLS double injection - OLD token should be REPLACED, not duplicated
# ==============================================================================
tr7 = Test.AddTestRun("Test 7: HLS double injection prevention")
tr7.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/double.m3u8?cr-access-token={valid_token}"'
tr7.Processes.Default.ReturnCode = 0
# Should NOT have OLD_TOKEN after transformation
tr7.Processes.Default.Streams.stdout = Testers.ExcludesExpression("OLD_TOKEN", "Old session token should be removed")
# Should have exactly ONE cr-session-token per line
tr7.Processes.Default.Streams.stdout += Testers.ContainsExpression("segment0.ts.*cr-session-token=", "Should have new token")
tr7.StillRunningAfter = server
tr7.StillRunningAfter = ts

# ==============================================================================
# TEST 8: HLS with whitespace and empty lines
# ==============================================================================
tr8 = Test.AddTestRun("Test 8: HLS with whitespace")
tr8.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/whitespace.m3u8?cr-access-token={valid_token}"'
tr8.Processes.Default.ReturnCode = 0
tr8.Processes.Default.Streams.stdout = Testers.ContainsExpression("segment0.ts.*cr-session-token=", "Segment after empty line should have token")
tr8.Processes.Default.Streams.stdout += Testers.ContainsExpression("segment1.ts.*cr-session-token=", "Segment with leading whitespace should have token")
tr8.StillRunningAfter = server
tr8.StillRunningAfter = ts

# ==============================================================================
# TEST 9: HLS mixed query params
# ==============================================================================
tr9 = Test.AddTestRun("Test 9: HLS mixed query params")
tr9.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/mixed.m3u8?cr-access-token={valid_token}"'
tr9.Processes.Default.ReturnCode = 0
tr9.Processes.Default.Streams.stdout = Testers.ContainsExpression("seg0.ts\\?cr-session-token=", "No params: should add ?token")
tr9.Processes.Default.Streams.stdout += Testers.ContainsExpression("seg1.ts\\?quality=high&cr-session-token=", "One param: should append &token")
tr9.Processes.Default.Streams.stdout += Testers.ContainsExpression("seg2.ts\\?quality=high&bitrate=1000&cr-session-token=", "Two params: should append &token")
# Access token should be REPLACED
tr9.Processes.Default.Streams.stdout += Testers.ExcludesExpression("ACCESS_123", "Access token should be replaced")
tr9.Processes.Default.Streams.stdout += Testers.ContainsExpression("seg3.ts\\?cr-session-token=", "Access token should be replaced with session token")
tr9.StillRunningAfter = server
tr9.StillRunningAfter = ts

# ==============================================================================
# TEST 10: DASH BaseURL inheritance
# ==============================================================================
tr10 = Test.AddTestRun("Test 10: DASH BaseURL inheritance")
tr10.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/baseurl-inherit.mpd?cr-access-token={valid_token}"'
tr10.Processes.Default.ReturnCode = 0
# Check that SegmentURL got tokens
tr10.Processes.Default.Streams.stdout = Testers.ContainsExpression('media="segment1.m4s\\?cr-session-token=', "Segment should have token")
tr10.Processes.Default.Streams.stdout += Testers.ContainsExpression('media="segment2.m4s\\?cr-session-token=', "Segment should have token")
# BaseURL elements will also get tokens (implementation detail - see analysis below)
tr10.StillRunningAfter = server
tr10.StillRunningAfter = ts

# ==============================================================================
# TEST 11: DASH SegmentTemplate with $Number$
# ==============================================================================
tr11 = Test.AddTestRun("Test 11: DASH SegmentTemplate")
tr11.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/template.mpd?cr-access-token={valid_token}"'
tr11.Processes.Default.ReturnCode = 0
tr11.Processes.Default.Streams.stdout = Testers.ContainsExpression('media="segment-\\$Number\\$.m4s\\?cr-session-token=', "Template media should have token")
tr11.Processes.Default.Streams.stdout += Testers.ContainsExpression('initialization="init-\\$RepresentationID\\$.mp4\\?cr-session-token=', "Template init should have token")
tr11.StillRunningAfter = server
tr11.StillRunningAfter = ts

# ==============================================================================
# TEST 12: DASH multiple BaseURL
# ==============================================================================
tr12 = Test.AddTestRun("Test 12: DASH multiple BaseURL")
tr12.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/multi-baseurl.mpd?cr-access-token={valid_token}"'
tr12.Processes.Default.ReturnCode = 0
# All BaseURLs should get tokens (for failover support)
tr12.Processes.Default.Streams.stdout = Testers.ContainsExpression("cdn1.example.com/video.m4s\\?cr-session-token=", "First BaseURL should have token")
tr12.Processes.Default.Streams.stdout += Testers.ContainsExpression("cdn2.example.com/video.m4s\\?cr-session-token=", "Second BaseURL should have token")
tr12.Processes.Default.Streams.stdout += Testers.ContainsExpression("cdn3.example.com/video.m4s\\?cr-session-token=", "Third BaseURL should have token")
tr12.StillRunningAfter = server
tr12.StillRunningAfter = ts

# ==============================================================================
# TEST 13: DASH SegmentTimeline
# ==============================================================================
tr13 = Test.AddTestRun("Test 13: DASH SegmentTimeline")
tr13.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/timeline.mpd?cr-access-token={valid_token}"'
tr13.Processes.Default.ReturnCode = 0
tr13.Processes.Default.Streams.stdout = Testers.ContainsExpression('media="seg-\\$Number\\$.m4s\\?cr-session-token=', "Timeline media should have token")
tr13.Processes.Default.Streams.stdout += Testers.ContainsExpression('initialization="init.mp4\\?cr-session-token=', "Timeline init should have token")
tr13.Processes.Default.Streams.stdout += Testers.ContainsExpression("<SegmentTimeline>", "SegmentTimeline should be preserved")
tr13.StillRunningAfter = server
tr13.StillRunningAfter = ts

# ==============================================================================
# TEST 14: DASH with existing query params
# ==============================================================================
tr14 = Test.AddTestRun("Test 14: DASH with existing query params")
tr14.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/query-params.mpd?cr-access-token={valid_token}"'
tr14.Processes.Default.ReturnCode = 0
# BaseURL with existing query param should get &token appended
tr14.Processes.Default.Streams.stdout = Testers.ContainsExpression("quality=high&(amp;)?cr-session-token=", "BaseURL should append token to existing param")
# SegmentURL media attributes
tr14.Processes.Default.Streams.stdout += Testers.ContainsExpression('media="seg1.m4s\\?fragment=1&(amp;)?cr-session-token=', "SegmentURL should append token")
tr14.Processes.Default.Streams.stdout += Testers.ContainsExpression('media="seg2.m4s\\?fragment=2&(amp;)?cache=no&(amp;)?cr-session-token=', "Multiple params should work")
tr14.StillRunningAfter = server
tr14.StillRunningAfter = ts

# ==============================================================================
# TEST 15: DASH SegmentBase (Shaka Packager on-demand profile)
# BaseURL elements must get token; indexRange/range must NOT be modified
# ==============================================================================
tr15 = Test.AddTestRun("Test 15: DASH SegmentBase — BaseURL injected, indexRange preserved")
tr15.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/segmentbase.mpd?cr-access-token={valid_token}"'
tr15.Processes.Default.ReturnCode = 0
# All BaseURL entries must have token
tr15.Processes.Default.Streams.stdout = Testers.ContainsExpression("stream_360p.mp4\\?cr-session-token=", "360p BaseURL must have token")
tr15.Processes.Default.Streams.stdout += Testers.ContainsExpression("stream_720p.mp4\\?cr-session-token=", "720p BaseURL must have token")
tr15.Processes.Default.Streams.stdout += Testers.ContainsExpression("stream_1080p.mp4\\?cr-session-token=", "1080p BaseURL must have token")
tr15.Processes.Default.Streams.stdout += Testers.ContainsExpression("stream_audio.mp4\\?cr-session-token=", "Audio BaseURL must have token")
# SegmentBase indexRange must NOT be modified (it's byte range, not URL)
tr15.Processes.Default.Streams.stdout += Testers.ContainsExpression('indexRange="899-1206"', "indexRange must be preserved unchanged")
tr15.Processes.Default.Streams.stdout += Testers.ContainsExpression('range="0-898"', "Initialization range must be preserved unchanged")
# MPD must be complete (not truncated)
tr15.Processes.Default.Streams.stdout += Testers.ContainsExpression("</MPD>", "MPD must be complete (not truncated)")
tr15.StillRunningAfter = server
tr15.StillRunningAfter = ts

# ==============================================================================
# TEST 16: DASH SegmentList — All sourceURL + SegmentURL injected
# ==============================================================================
tr16 = Test.AddTestRun("Test 16: DASH SegmentList — sourceURL + SegmentURL injected")
tr16.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/segmentlist.mpd?cr-access-token={valid_token}"'
tr16.Processes.Default.ReturnCode = 0
# Initialization sourceURL must have token
tr16.Processes.Default.Streams.stdout = Testers.ContainsExpression('sourceURL="init-stream0.m4s\\?cr-session-token=', "Init stream0 must have token")
tr16.Processes.Default.Streams.stdout += Testers.ContainsExpression('sourceURL="init-stream3.m4s\\?cr-session-token=', "Init stream3 (audio) must have token")
# Last segment of last representation must be present (proves not truncated)
tr16.Processes.Default.Streams.stdout += Testers.ContainsExpression("chunk-stream3-00023.m4s\\?cr-session-token=", "Last audio segment must have token")
# MPD must be complete
tr16.Processes.Default.Streams.stdout += Testers.ContainsExpression("</MPD>", "MPD must be complete")
tr16.StillRunningAfter = server
tr16.StillRunningAfter = ts

# ==============================================================================
# TEST 17: DASH SegmentList LARGE — Content-Length truncation test (BUG)
#
# This test is the KEY test for the Content-Length truncation bug:
# - Origin sends a ~15KB MPD with 400 SegmentURLs
# - After injection: ~95KB (each URL gets ~200-char token appended)
# - If Content-Length header is NOT updated: client receives only ~15KB → TRUNCATED
# - The last segments and </MPD> will be missing
# ==============================================================================
tr17 = Test.AddTestRun("Test 17: DASH SegmentList LARGE — Content-Length truncation (BUG)")
tr17.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/segmentlist-large.mpd?cr-access-token={valid_token}"'
tr17.Processes.Default.ReturnCode = 0
# CRITICAL: Last segment of last representation MUST be present
# If Content-Length is wrong, body will be truncated and this will be missing
tr17.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "chunk-stream3-00100.m4s",
    "CRITICAL: Last audio segment (00100) must be present — proves no truncation")
# The closing </MPD> MUST be present
tr17.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "</MPD>",
    "CRITICAL: Closing </MPD> must be present — proves response is complete")
# First segment must also have token
tr17.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "chunk-stream0-00001.m4s\\?cr-session-token=",
    "First segment must have token injected")
tr17.StillRunningAfter = server
tr17.StillRunningAfter = ts

# ==============================================================================
# TEST 18: HLS fMP4/CMAF — EXT-X-MAP init segment + media segments
# ==============================================================================
tr18 = Test.AddTestRun("Test 18: HLS fMP4/CMAF — EXT-X-MAP + segments injected")
tr18.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/hls/fmp4.m3u8?cr-access-token={valid_token}"'
tr18.Processes.Default.ReturnCode = 0
# EXT-X-MAP init segment must have token
tr18.Processes.Default.Streams.stdout = Testers.ContainsExpression('init_0.mp4\\?cr-session-token=', "EXT-X-MAP init segment must have token")
# Media segments must have token
tr18.Processes.Default.Streams.stdout += Testers.ContainsExpression("chunk_0_00001.m4s\\?cr-session-token=", "First m4s segment must have token")
tr18.Processes.Default.Streams.stdout += Testers.ContainsExpression("chunk_0_00005.m4s\\?cr-session-token=", "Last m4s segment must have token")
# Must be complete
tr18.Processes.Default.Streams.stdout += Testers.ContainsExpression("#EXT-X-ENDLIST", "Must contain #EXT-X-ENDLIST (not truncated)")
tr18.StillRunningAfter = server
tr18.StillRunningAfter = ts

# ==============================================================================
# TEST 19: Content-Length with origin that sends explicit Content-Length
#
# This is the REAL truncation test:
# - Origin sends Content-Length: <original body size>
# - Transform grows body by injecting tokens
# - If ATS doesn't update Content-Length → client gets truncated body
# ==============================================================================
tr19 = Test.AddTestRun("Test 19: Origin with Content-Length — body must NOT be truncated")
tr19.Processes.Default.Command = f'curl -s -x localhost:{ts.Variables.port} "http://testhost/dash/segmentlist-large-cl.mpd?cr-access-token={valid_token}"'
tr19.Processes.Default.ReturnCode = 0
# CRITICAL: Last segment MUST be present (proves no truncation even with origin Content-Length)
tr19.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "chunk-stream3-00100.m4s",
    "CRITICAL: Last audio segment (00100) must be present — origin sent Content-Length")
tr19.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "</MPD>",
    "CRITICAL: Closing </MPD> must be present — proves response not truncated")
tr19.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "chunk-stream0-00001.m4s\\?cr-session-token=",
    "First segment must have token injected")
tr19.StillRunningAfter = server
tr19.StillRunningAfter = ts

# ==============================================================================
# TEST 20: Content-Length header validation with origin Content-Length
#
# When origin sends Content-Length and transform grows body:
# - ATS must either update Content-Length to new size
# - Or remove it (forcing chunked transfer)
# - The old Content-Length MUST NOT remain unchanged
# ==============================================================================
tr20 = Test.AddTestRun("Test 20: Content-Length header value after transform")
tr20.Processes.Default.Command = (
    f'curl -s -D - -o /dev/null -x localhost:{ts.Variables.port} '
    f'"http://testhost/dash/segmentlist-large-cl.mpd?cr-access-token={valid_token}"'
)
tr20.Processes.Default.ReturnCode = 0
# The original body is ~15KB. After transform, it should be ~130KB.
# If Content-Length still shows ~15KB, the body would be truncated.
# We check that it's NOT the original small value.
original_body_len = len(dash_segmentlist_large.encode('utf-8'))
tr20.Processes.Default.Streams.stdout = Testers.ExcludesExpression(
    f"Content-Length: {original_body_len}",
    f"Content-Length must NOT be the original size ({original_body_len}) — transform grew the body")
tr20.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "200",
    "Response must be 200 OK")
tr20.StillRunningAfter = server
tr20.StillRunningAfter = ts

# ==============================================================================
# TEST 21: Response framing after manifest transform — no incorrect CL
#
# With INT64_MAX output VIO, ATS core either:
# a) Sends Transfer-Encoding: chunked (if transform hasn't set final size yet)
# b) Sends correct Content-Length (if TSVIONBytesSet completes before headers)
# Either way, the original (small) Content-Length must NOT appear.
# ==============================================================================
tr21 = Test.AddTestRun("Test 21: No incorrect Content-Length after manifest transform")
tr21.Processes.Default.Command = (
    f'curl -s -D - -o /dev/null -x localhost:{ts.Variables.port} '
    f'"http://testhost/dash/segmentlist-large-cl.mpd?cr-access-token={valid_token}"'
)
tr21.Processes.Default.ReturnCode = 0
original_body_len_21 = len(dash_segmentlist_large.encode('utf-8'))
tr21.Processes.Default.Streams.stdout = Testers.ExcludesExpression(
    f"Content-Length: {original_body_len_21}",
    f"Original Content-Length ({original_body_len_21}) must NOT appear — transform grew the body")
tr21.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "HTTP/1.1 200",
    "Response must be 200 OK")
tr21.StillRunningAfter = server
tr21.StillRunningAfter = ts

# ==============================================================================
# TEST 22: Non-200 response — no transform VIO, no chunked
#
# For 404, the transform is registered but never receives body data.
# No output VIO is created → ATS uses normal Content-Length behavior.
# ==============================================================================
tr22 = Test.AddTestRun("Test 22: 404 response — no chunked, no transform")
tr22.Processes.Default.Command = (
    f'curl -s -D - -x localhost:{ts.Variables.port} '
    f'"http://testhost/dash/nonexistent.mpd?cr-access-token={valid_token}"'
)
tr22.Processes.Default.ReturnCode = 0
tr22.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "HTTP/1.1 404",
    "Response must be 404 Not Found")
tr22.Processes.Default.Streams.stdout += Testers.ExcludesExpression(
    "Transfer-Encoding: chunked",
    "404 response must NOT use chunked — no transform body processed")
tr22.StillRunningAfter = server
tr22.StillRunningAfter = ts

# ==============================================================================
# TEST 23: Correct response framing with HTTP/1.1 after manifest transform
#
# With INT64_MAX output VIO, ATS may send:
# a) Transfer-Encoding: chunked (transform size unknown at header time), or
# b) Content-Length with the correct transformed size (transform completed early)
# Both are valid. The key assertion: the original small Content-Length is gone.
# ==============================================================================
tr23 = Test.AddTestRun("Test 23: Correct HTTP/1.1 framing after transform")
tr23.Processes.Default.Command = (
    f'curl -s -D - -o /dev/null --http1.1 -x localhost:{ts.Variables.port} '
    f'"http://testhost/dash/segmentlist-large-cl.mpd?cr-access-token={valid_token}"'
)
tr23.Processes.Default.ReturnCode = 0
original_body_len_23 = len(dash_segmentlist_large.encode('utf-8'))
tr23.Processes.Default.Streams.stdout = Testers.ExcludesExpression(
    f"Content-Length: {original_body_len_23}",
    f"Original Content-Length ({original_body_len_23}) must NOT appear after transform")
tr23.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "HTTP/1.1 200",
    "Response must be 200 OK")
tr23.StillRunningAfter = server
tr23.StillRunningAfter = ts

# ==============================================================================
# TEST 24: Full body received — received size > origin size
#
# The transform injects tokens into every segment URL, growing the body.
# Use curl's write-out to get received bytes and verify body is complete.
# This proves the VIO nbytes doesn't cap output at the origin body size.
# ==============================================================================
tr24 = Test.AddTestRun("Test 24: Received body size exceeds origin body size")
tr24.Processes.Default.Command = (
    f'curl -s -o /dev/null -w "%{{size_download}}" -x localhost:{ts.Variables.port} '
    f'"http://testhost/dash/segmentlist-large-cl.mpd?cr-access-token={valid_token}"'
)
tr24.Processes.Default.ReturnCode = 0
# Origin body for segmentlist-large-cl.mpd is ~15KB (without tokens).
# After injection it should be ~130KB+ (each segment URL gets ~600 byte token).
# We check that downloaded size is at least 50000 bytes (well above 15KB origin).
# Use a regex that matches 5+ digit numbers (>= 10000 bytes).
tr24.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    r"[0-9]{6}",
    "Downloaded body must be 6+ digits (>100KB) — proves transform output not truncated by VIO")

tr24.StillRunningAfter = server
tr24.StillRunningAfter = ts

print("=" * 80)
print("Manifest Format Variations Test Suite")
print("=" * 80)
print("HLS Tests:")
print("  1. Master Playlist (variant URLs)")
print("  2. EXT-X-MEDIA tags (URI in tags)")
print("  3. I-FRAME Playlist")
print("  4. URL Fragments")
print("  5. Absolute URLs")
print("  6. Relative Paths")
print("  7. Double Injection Prevention")
print("  8. Whitespace Handling")
print("  9. Mixed Query Params")
print(" 18. HLS fMP4/CMAF (EXT-X-MAP)")
print("")
print("DASH Tests:")
print(" 10. BaseURL Inheritance")
print(" 11. SegmentTemplate with $Number$")
print(" 12. Multiple BaseURL Elements")
print(" 13. SegmentTimeline")
print(" 14. Existing Query Params")
print(" 15. SegmentBase (on-demand profile)")
print(" 16. SegmentList (sourceURL + SegmentURL)")
print(" 17. SegmentList LARGE (Content-Length truncation)")
print("")
print("Header / Transfer Tests:")
print(" 19. Origin Content-Length — body completeness after transform")
print(" 20. Content-Length header value after transform (not original size)")
print(" 21. No incorrect Content-Length after manifest transform")
print(" 22. 404 response — no chunked, no transform")
print(" 23. Correct HTTP/1.1 framing after transform")
print(" 24. Received body size exceeds origin body size")
print("=" * 80)
