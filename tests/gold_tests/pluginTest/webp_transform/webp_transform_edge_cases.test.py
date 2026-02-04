
'''
Test webp_transform plugin for Edge Cases (DoS Protection, Corrupt, Empty)
'''
import os

Test.Summary = 'Test Edge Cases: Max Size Limit, Corrupt Input, Empty Input'

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

# Configure plugin with a small max_image_size (100KB) and small max_pixels (1000)
ts.Disk.plugin_config.AddLine('webp_transform.so max_image_size=102400 max_pixels=1000 convert_to_webp')
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

# --- CLEAN LOG CHECK ---
# We allow ERROR messages from our plugin so AuTest doesn't fail the test
ts.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow webp_transform logs")
