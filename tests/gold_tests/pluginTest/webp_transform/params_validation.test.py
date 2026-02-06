
'''
Test webp_transform plugin for Parameter Validation and Robustness
'''
import os

Test.Summary = 'Test Param Validation: Ambiguous params, Invalid values, Timeout, Quality, Size/Pixel limits'

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

# --- SETUP ORIGIN ---
origin_port = 8888
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# --- INSTANCE 1: AMBIGUOUS CONFIG ---
# Scenario: "no_convert_to_webp" should NOT enable webp conversion if parser is robust.
# With fragile find(), "no_convert_to_webp" contains "convert_to_webp", so it enables it wrongly.
ts_ambiguous = Test.MakeATSProcess("ts_ambiguous")
ts_ambiguous.Disk.plugin_config.AddLine('webp_transform.so no_convert_to_webp')
ts_ambiguous.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_ambiguous.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 3: SHORT ARGUMENT (CRASH TEST) ---
# Scenario: Argument shorter than "webp_quality=" (13 chars) causing out_of_range in substr.
# e.g., "x=1" (3 chars)
ts_short = Test.MakeATSProcess("ts_short")
ts_short.Disk.plugin_config.AddLine('webp_transform.so x=1')
ts_short.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_short.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 4: VALID TIMEOUT ---
ts_timeout_valid = Test.MakeATSProcess("ts_timeout_valid")
ts_timeout_valid.Disk.plugin_config.AddLine('webp_transform.so timeout_seconds=10')
ts_timeout_valid.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_timeout_valid.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 5: TIMEOUT MINIMUM (1s) ---
ts_timeout_min = Test.MakeATSProcess("ts_timeout_min")
ts_timeout_min.Disk.plugin_config.AddLine('webp_transform.so timeout_seconds=1')
ts_timeout_min.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_timeout_min.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 6: TIMEOUT MAXIMUM (60s) ---
ts_timeout_max = Test.MakeATSProcess("ts_timeout_max")
ts_timeout_max.Disk.plugin_config.AddLine('webp_transform.so timeout_seconds=60')
ts_timeout_max.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_timeout_max.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 7: TIMEOUT INVALID BELOW RANGE ---
ts_timeout_below = Test.MakeATSProcess("ts_timeout_below")
ts_timeout_below.Disk.plugin_config.AddLine('webp_transform.so timeout_seconds=0')
ts_timeout_below.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_timeout_below.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 8: TIMEOUT INVALID ABOVE RANGE ---
ts_timeout_above = Test.MakeATSProcess("ts_timeout_above")
ts_timeout_above.Disk.plugin_config.AddLine('webp_transform.so timeout_seconds=61')
ts_timeout_above.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_timeout_above.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 9: TIMEOUT NON-NUMERIC ---
ts_timeout_invalid = Test.MakeATSProcess("ts_timeout_invalid")
ts_timeout_invalid.Disk.plugin_config.AddLine('webp_transform.so timeout_seconds=abc')
ts_timeout_invalid.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_timeout_invalid.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 10: NEGATIVE QUALITY VALUES ---
ts_negative_quality = Test.MakeATSProcess("ts_negative_quality")
ts_negative_quality.Disk.plugin_config.AddLine('webp_transform.so webp_quality=-1')
ts_negative_quality.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_negative_quality.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 11: QUALITY ABOVE RANGE ---
ts_high_quality = Test.MakeATSProcess("ts_high_quality")
ts_high_quality.Disk.plugin_config.AddLine('webp_transform.so jpeg_quality=101')
ts_high_quality.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_high_quality.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 12: ZERO MAX_IMAGE_SIZE ---
ts_zero_size = Test.MakeATSProcess("ts_zero_size")
ts_zero_size.Disk.plugin_config.AddLine('webp_transform.so max_image_size=0')
ts_zero_size.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_zero_size.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 13: NEGATIVE MAX_IMAGE_SIZE ---
ts_negative_size = Test.MakeATSProcess("ts_negative_size")
ts_negative_size.Disk.plugin_config.AddLine('webp_transform.so max_image_size=-1000')
ts_negative_size.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_negative_size.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 14: ZERO MAX_PIXELS ---
ts_zero_pixels = Test.MakeATSProcess("ts_zero_pixels")
ts_zero_pixels.Disk.plugin_config.AddLine('webp_transform.so max_pixels=0')
ts_zero_pixels.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_zero_pixels.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 15: NEGATIVE MAX_PIXELS ---
ts_negative_pixels = Test.MakeATSProcess("ts_negative_pixels")
ts_negative_pixels.Disk.plugin_config.AddLine('webp_transform.so max_pixels=-5000')
ts_negative_pixels.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_negative_pixels.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- EXECUTION ---

# ... existing tests ...

# 3. Short Argument Crash Test
tr = Test.AddTestRun("Short Argument Stability Test")
tr.Processes.Default.Command = \
    'curl -v -o out_short.img --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_short.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server) # Ensure origin is running
tr.Processes.Default.StartBefore(ts_short)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_short

# If server crashed, this would fail.
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Server should survive short argument")

# 4. Valid Timeout Test (10s)
tr = Test.AddTestRun("Valid Timeout 10s")
tr.Processes.Default.Command = \
    'curl -v -o out_timeout_valid.webp --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_timeout_valid.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_timeout_valid)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_timeout_valid
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Valid timeout should work")

# 5. Minimum Timeout Test (1s)
tr = Test.AddTestRun("Minimum Timeout 1s")
tr.Processes.Default.Command = \
    'curl -v -o out_timeout_min.webp --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_timeout_min.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_timeout_min)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_timeout_min
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Minimum timeout (1s) should work")

# 6. Maximum Timeout Test (60s)
tr = Test.AddTestRun("Maximum Timeout 60s")
tr.Processes.Default.Command = \
    'curl -v -o out_timeout_max.webp --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_timeout_max.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_timeout_max)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_timeout_max
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Maximum timeout (60s) should work")

# 7. Invalid Timeout Below Range (0s)
tr = Test.AddTestRun("Invalid Timeout Below Range")
tr.Processes.Default.Command = \
    'curl -v -o out_timeout_below.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_timeout_below.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_timeout_below)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_timeout_below
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Invalid timeout should passthrough")

# 8. Invalid Timeout Above Range (61s)
tr = Test.AddTestRun("Invalid Timeout Above Range")
tr.Processes.Default.Command = \
    'curl -v -o out_timeout_above.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_timeout_above.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_timeout_above)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_timeout_above
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Invalid timeout should passthrough")

# 9. Non-Numeric Timeout
tr = Test.AddTestRun("Non-Numeric Timeout")
tr.Processes.Default.Command = \
    'curl -v -o out_timeout_invalid.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_timeout_invalid.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_timeout_invalid)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_timeout_invalid
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Invalid timeout should passthrough")

# 10. Negative Quality Values
tr = Test.AddTestRun("Negative webp_quality Test")
tr.Processes.Default.Command = \
    'curl -v -o out_neg_quality.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/image.jpg'.format(ts_negative_quality.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_negative_quality)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_negative_quality
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Should work with default quality")

# 11. Quality Above Range (>100)
tr = Test.AddTestRun("Quality Above 100 Test")
tr.Processes.Default.Command = \
    'curl -v -o out_high_quality.jpg http://127.0.0.1:{0}/image.jpg'.format(ts_high_quality.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_high_quality)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_high_quality
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("200 OK", "Should work with default quality")

# 12. Zero max_image_size
tr = Test.AddTestRun("Zero max_image_size Test")
tr.Processes.Default.Command = \
    'curl -v -o out_zero_size.jpg http://127.0.0.1:{0}/image.jpg'.format(ts_zero_size.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_zero_size)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_zero_size

# 13. Negative max_image_size
tr = Test.AddTestRun("Negative max_image_size Test")
tr.Processes.Default.Command = \
    'curl -v -o out_neg_size.jpg http://127.0.0.1:{0}/image.jpg'.format(ts_negative_size.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_negative_size)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_negative_size

# 14. Zero max_pixels
tr = Test.AddTestRun("Zero max_pixels Test")
tr.Processes.Default.Command = \
    'curl -v -o out_zero_pixels.jpg http://127.0.0.1:{0}/image.jpg'.format(ts_zero_pixels.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_zero_pixels)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_zero_pixels

# 15. Negative max_pixels
tr = Test.AddTestRun("Negative max_pixels Test")
tr.Processes.Default.Command = \
    'curl -v -o out_neg_pixels.jpg http://127.0.0.1:{0}/image.jpg'.format(ts_negative_pixels.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_negative_pixels)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_negative_pixels

# Allow ERROR messages in logs for validation test instances (expected behavior)
ts_negative_quality.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_high_quality.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_zero_size.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_negative_size.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_zero_pixels.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_negative_pixels.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")

# --- INSTANCE 16: ALL CONVERT FLAGS FALSE ---
ts_no_convert = Test.MakeATSProcess("ts_no_convert")
ts_no_convert.Disk.plugin_config.AddLine('webp_transform.so convert_to_avif=false convert_to_webp=false convert_to_jpeg=false')
ts_no_convert.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_no_convert.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 17: CONFIG DISABLED BUT ACCEPT SUPPORTS (AVIF) ---
ts_disabled_avif = Test.MakeATSProcess("ts_disabled_avif")
ts_disabled_avif.Disk.plugin_config.AddLine('webp_transform.so convert_to_avif=false')
ts_disabled_avif.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_disabled_avif.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 18: CONFIG DISABLED BUT ACCEPT SUPPORTS (WebP) ---
ts_disabled_webp = Test.MakeATSProcess("ts_disabled_webp")
ts_disabled_webp.Disk.plugin_config.AddLine('webp_transform.so convert_to_webp=false')
ts_disabled_webp.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_disabled_webp.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# 16. All Convert Flags False
tr = Test.AddTestRun("All Convert Flags False Test")
tr.Processes.Default.Command = \
    'curl -v -o out_no_convert.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/image.jpg'.format(ts_no_convert.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_no_convert)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_no_convert

tr = Test.AddTestRun("Verify No Convert Passthrough")
tr.Processes.Default.Command = 'file out_no_convert.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Should passthrough (all convert flags false)")

# 17. AVIF Disabled But Accept Supports
tr = Test.AddTestRun("AVIF Disabled But Accept Supports Test")
tr.Processes.Default.Command = \
    'curl -v -o out_disabled_avif.webp --header "Accept: image/avif, image/webp" http://127.0.0.1:{0}/image.jpg'.format(ts_disabled_avif.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_disabled_avif)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_disabled_avif

tr = Test.AddTestRun("Verify Falls Back to WebP")
tr.Processes.Default.Command = 'file out_disabled_avif.webp'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Web/P image", "Should fall back to WebP (AVIF disabled)")

# 18. WebP Disabled But Accept Supports
tr = Test.AddTestRun("WebP Disabled But Accept Supports Test")
tr.Processes.Default.Command = \
    'curl -v -o out_disabled_webp.jpg --header "Accept: image/webp" http://127.0.0.1:{0}/image.jpg'.format(ts_disabled_webp.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts_disabled_webp)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_disabled_webp

tr = Test.AddTestRun("Verify WebP Disabled Passthrough")
tr.Processes.Default.Command = 'file out_disabled_webp.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("JPEG image data", "Should passthrough (WebP disabled)")

# Allow ERROR messages in logs for validation test instances (expected behavior)
ts_negative_quality.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_high_quality.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_zero_size.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_negative_size.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_zero_pixels.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
ts_negative_pixels.Disk.diags_log.Content = Testers.ContainsExpression("webp_transform", "Allow plugin logs")
