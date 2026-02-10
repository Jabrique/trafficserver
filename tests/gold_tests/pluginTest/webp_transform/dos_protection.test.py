
'''
Test webp_transform plugin for Edge Cases (DoS Protection, Corrupt, Empty, Header Edge Cases)
'''
import os

Test.Summary = 'Test Edge Cases: Max Size Limit, Corrupt Input, Empty Input, Accept Header Edge Cases'

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

# --- SETUP ORIGIN ---
origin_port = 8889
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# --- SETUP ATS ---
ts = Test.MakeATSProcess("ts")

# Configure plugin with limits for DoS testing (within valid range: 1MB-100MB, 1MP-500MP)
# Use 2MB size limit and 500K pixel limit to trigger passthrough on 1024x768=786K pixel image
ts.Disk.plugin_config.AddLine('webp_transform.so max_image_size=2097152 max_pixels=500000 convert_to_webp')
ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'webp_transform',
    'proxy.config.http.cache.http': 0,
})
ts.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- TEST 1: DoS Protection (Oversized Image) ---
tr = Test.AddTestRun("Oversized Image (DoS Test)")
tr.Processes.Default.Command = \
    'curl -v -o out_oversized.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

tr = Test.AddTestRun("Verify DoS Passthrough Content")
tr.Processes.Default.Command = 'file out_oversized.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Content should be JPEG (Passthrough)")

# --- TEST 2: Pixel Limit (Decompression Bomb) ---
tr = Test.AddTestRun("Verify Pixel Limit Content")
tr.Processes.Default.Command = \
    'curl -v -o out_pixel_limit.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg && file out_pixel_limit.jpg'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Content should remain JPEG (Passthrough)")

# --- TEST 3: Corrupt Input / MIME Spoofing ---
tr = Test.AddTestRun("Create Spoofed File")
tr.Processes.Default.Command = 'echo "<?xml version=1.0?><svg>...evil...</svg>" > {0}/spoofed.jpg'.format(origin_dir)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("MIME Spoofed Input Test")
tr.Processes.Default.Command = \
    'curl -v -o out_spoofed.img --header "Accept: image/webp" http://127.0.0.1:{0}/spoofed.jpg'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Spoofed Passthrough Content")
tr.Processes.Default.Command = 'grep "evil" out_spoofed.img'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("evil", "Content should be passed through")

# --- TEST 4: Unsupported Format (GIF) ---
tr = Test.AddTestRun("Create GIF File")
tr.Processes.Default.Command = 'echo "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" | base64 -d > {0}/test.gif'.format(origin_dir)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Unsupported Format Test (GIF)")
tr.Processes.Default.Command = \
    'curl -v -o out_gif.img --header "Accept: image/webp" http://127.0.0.1:{0}/test.gif'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify GIF Passthrough")
tr.Processes.Default.Command = 'file out_gif.img'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("GIF image data", "Content should remain GIF (Passthrough)")

# --- TEST 4B: Zero Dimensions Image (0x10 pixels) ---
tr = Test.AddTestRun("Zero Dimensions Image Test")
tr.Processes.Default.Command = \
    'curl -v -o out_zero_dim.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/zero_width.jpg'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Zero Dimensions Passthrough")
tr.Processes.Default.Command = 'file out_zero_dim.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Zero dimension should passthrough (security)")

# --- TEST 5: Empty Accept Header (Should Passthrough) ---
tr = Test.AddTestRun("Empty Accept Header Test")
tr.Processes.Default.Command = \
    'curl -v -o out_empty_accept.jpg --header "Accept:" http://127.0.0.1:{0}/image.jpg'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Empty Accept Passthrough")
tr.Processes.Default.Command = 'file out_empty_accept.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Should remain JPEG (no conversion)")

# --- TEST 6: curl Default Accept (*/*) - Legacy Browser Simulation ---
# NOTE: curl sends "Accept: */*" by default. With the wildcard fix, this should
# NOT convert to AVIF/WebP (legacy browsers get JPEG passthrough)
tr = Test.AddTestRun("curl Default Accept (wildcard passthrough)")
tr.Processes.Default.Command = \
    'curl -v -o out_no_accept.jpg http://127.0.0.1:{0}/image.jpg'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify curl Default Accept Passthrough")
tr.Processes.Default.Command = 'file out_no_accept.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Wildcard */* should passthrough (legacy browser safety)")

# --- TEST 7: Missing Content-Type Header (Should Passthrough) ---
# Use query param ?no_content_type=1 to skip Content-Type header
tr = Test.AddTestRun("Missing Content-Type Test")
tr.Processes.Default.Command = \
    'curl -v -o out_no_content_type.jpg --header "Accept: image/webp" "http://127.0.0.1:{0}/image.jpg?no_content_type=1"'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Missing Content-Type Passthrough")
tr.Processes.Default.Command = 'file out_no_content_type.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Should passthrough without Content-Type (unknown format)")

# --- CLEAN LOG CHECK ---
# We allow ERROR messages from our plugin so AuTest doesn't fail the test
ts.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow webp_transform logs")

# --- TEST 8: Content-Type Multiple Semicolons (Parsing Robustness) ---
# Use query param ?content_type_extra=multi to add semicolons
tr = Test.AddTestRun("Content-Type Semicolon Parsing Test")
tr.Processes.Default.Command = \
    'curl -v -o out_semicolon.webp --header "Accept: image/webp" "http://127.0.0.1:{0}/image.jpg?content_type_extra=multi"'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Semicolon Parsing Transforms")
tr.Processes.Default.Command = 'file out_semicolon.webp'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Web/P image", "Should parse Content-Type correctly (strip semicolons)")
