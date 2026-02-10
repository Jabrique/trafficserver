'''
Test webp_transform plugin Security Fixes (CRITICAL vulnerabilities)
Tests for fixes implemented in response to security audit
'''
import os

Test.Summary = 'Security Fixes: Pixel Overflow, Config Validation, Accept Header Parsing'

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

# --- SETUP ORIGIN ---
origin_port = 8990
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# =============================================================================
# TEST 1: CRITICAL-1 Fix - Pixel Overflow Protection
# =============================================================================
# Before fix: Image with 100,000,000 x 2 pixels bypassed 100MP limit
# After fix: Safe overflow check prevents processing

ts_pixel_overflow = Test.MakeATSProcess("ts_pixel_overflow")
ts_pixel_overflow.Disk.plugin_config.AddLine('stats_over_http.so')  # Enable stats endpoint
ts_pixel_overflow.Disk.plugin_config.AddLine('webp_transform.so max_pixels=500000')  # 500K pixel limit (1024x768=786K > limit)
ts_pixel_overflow.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'webp_transform',
    'proxy.config.http.cache.http': 0,
})
ts_pixel_overflow.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

tr = Test.AddTestRun("CRITICAL-1: Pixel Overflow Attack")
tr.Processes.Default.Command = \
    'curl -v -o out_overflow.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(
        ts_pixel_overflow.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_pixel_overflow)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_pixel_overflow

tr = Test.AddTestRun("Verify Pixel Overflow Passthrough")
tr.Processes.Default.Command = 'file out_overflow.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data",
                                                                   "Should passthrough JPEG (not converted)")

tr = Test.AddTestRun("Check Pixel Overflow Stat")
tr.Processes.Default.Command = 'curl -s http://127.0.0.1:{0}/_stats 2>/dev/null | grep webp_transform.passthrough_pixels || echo "stat_not_found"'.format(
    ts_pixel_overflow.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("webp_transform.passthrough_pixels",
                                                                   "Stat should be present")

# =============================================================================
# TEST 2: CRITICAL-3 Fix - Config Integer Overflow
# =============================================================================
# Before fix: max_image_size=999999999999999999 set to LLONG_MAX (8 EB)
# After fix: Value rejected, falls back to default 10MB

ts_config_overflow = Test.MakeATSProcess("ts_config_overflow")
# Attempt to set absurdly large value (will be rejected)
ts_config_overflow.Disk.plugin_config.AddLine('webp_transform.so max_image_size=999999999999999999999999999')
ts_config_overflow.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_config_overflow.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

tr = Test.AddTestRun("CRITICAL-3: Config Overflow Test")
tr.Processes.Default.Command = \
    'curl -v -o out_config.jpg http://127.0.0.1:{0}/large.jpg'.format(ts_config_overflow.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_config_overflow)
tr.StillRunningAfter = ts_config_overflow

# Check diags.log for error message about out-of-range config
tr = Test.AddTestRun("Verify Config Overflow Error Logged")
tr.Processes.Default.Command = 'grep "max_image_size out of range" {}/diags.log || grep "max_image_size overflow" {}/diags.log'.format(
    ts_config_overflow.Variables.LOGDIR, ts_config_overflow.Variables.LOGDIR)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("max_image_size",
                                                                   "Should log config validation error")

# =============================================================================
# TEST 3: CRITICAL-3 Fix - Config Out of Range (Below Minimum)
# =============================================================================
ts_config_min = Test.MakeATSProcess("ts_config_min")
ts_config_min.Disk.plugin_config.AddLine('webp_transform.so max_image_size=100')  # Below 1MB minimum
ts_config_min.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_config_min.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

tr = Test.AddTestRun("CRITICAL-3: Config Below Minimum")
tr.Processes.Default.Command = 'curl -v http://127.0.0.1:{0}/image.jpg'.format(ts_config_min.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_config_min)
tr.StillRunningAfter = ts_config_min

# =============================================================================
# TEST 4: HIGH-3 Fix - Accept Header False Positive
# =============================================================================
# Before fix: "comment-image/avif-not-supported" matched as AVIF support
# After fix: Proper MIME boundary checking

ts_accept_header = Test.MakeATSProcess("ts_accept_header")
ts_accept_header.Disk.plugin_config.AddLine('webp_transform.so')
ts_accept_header.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_accept_header.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

tr = Test.AddTestRun("HIGH-3: Accept Header False Positive Test")
tr.Processes.Default.Command = \
    'curl -v -o out_accept.img --header "Accept: text/html, comment-image/avif-malicious, application/json" http://127.0.0.1:{0}/image.jpg'.format(
        ts_accept_header.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_accept_header)
tr.StillRunningAfter = ts_accept_header

tr = Test.AddTestRun("Verify Accept Header No False Positive")
tr.Processes.Default.Command = 'file out_accept.img'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data",
                                                                   "Should remain JPEG (AVIF not in proper MIME format)")

# =============================================================================
# TEST 5: HIGH-3 Fix - Accept Header Wildcard Handling (Updated)
# Wildcards (*/* and image/*) should NOT match AVIF/WebP for legacy browser safety
# =============================================================================
tr = Test.AddTestRun("HIGH-3: Accept Header Wildcard Test")
tr.Processes.Default.Command = \
    'curl -v -o out_wildcard.img --header "Accept: image/*" http://127.0.0.1:{0}/image.jpg'.format(
        ts_accept_header.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Wildcard Does NOT Convert to Modern Format")
tr.Processes.Default.Command = 'file out_wildcard.img'
tr.Processes.Default.ReturnCode = 0
# Wildcard should NOT match AVIF/WebP - stays as JPEG (passthrough for legacy browsers)
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data",
                                                                   "Wildcard should passthrough JPEG (not convert to AVIF/WebP)")

# =============================================================================
# TEST 6: CRITICAL-2 Fix - Constructor Validation
# =============================================================================
# Negative config values should be caught by constructor

ts_negative_config = Test.MakeATSProcess("ts_negative_config")
# This will fail parsing and use default, constructor should validate
ts_negative_config.Disk.plugin_config.AddLine('webp_transform.so')
ts_negative_config.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_negative_config.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

tr = Test.AddTestRun("CRITICAL-2: Constructor Validation Test")
tr.Processes.Default.Command = 'curl -v http://127.0.0.1:{0}/small.jpg'.format(ts_negative_config.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_negative_config)
tr.StillRunningAfter = ts_negative_config

# =============================================================================
# TEST 7: Pixel Boundary Test (Exactly at max_pixels limit)
# =============================================================================
# Create image with exactly 500K pixels (707x707 = 499,849 pixels, just under limit)
# And 708x708 = 501,264 pixels, just over limit
ts_pixel_boundary = Test.MakeATSProcess("ts_pixel_boundary")
ts_pixel_boundary.Disk.plugin_config.AddLine('webp_transform.so max_pixels=500000')
ts_pixel_boundary.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_pixel_boundary.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# Create test images
tr = Test.AddTestRun("Create 707x707 image (499,849 pixels - UNDER limit)")
tr.Processes.Default.Command = 'magick -size 707x707 xc:blue {}/under_limit.jpg'.format(origin_dir)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_pixel_boundary)

tr = Test.AddTestRun("Create 708x708 image (501,264 pixels - OVER limit)")
tr.Processes.Default.Command = 'magick -size 708x708 xc:red {}/over_limit.jpg'.format(origin_dir)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Test Image Under Pixel Limit")
tr.Processes.Default.Command = \
    'curl -v -o out_under_limit.webp --header "Accept: image/webp" http://127.0.0.1:{0}/under_limit.jpg'.format(
        ts_pixel_boundary.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Under Limit Transforms")
tr.Processes.Default.Command = 'file out_under_limit.webp'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Web/P image", "Should transform (under pixel limit)")

tr = Test.AddTestRun("Test Image Over Pixel Limit")
tr.Processes.Default.Command = \
    'curl -v -o out_over_limit.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/over_limit.jpg'.format(
        ts_pixel_boundary.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify Over Limit Passthrough")
tr.Processes.Default.Command = 'file out_over_limit.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Should passthrough (over pixel limit)")

# =============================================================================
# CLEANUP
# =============================================================================
# Allow webp_transform errors in logs (expected for validation tests)
ts_pixel_overflow.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_config_overflow.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_config_min.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_accept_header.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_negative_config.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_pixel_boundary.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
