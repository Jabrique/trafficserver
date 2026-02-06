
'''
Test webp_transform plugin for Boolean Configuration Parsing and Default Retention
'''
import os

Test.Summary = 'Verify boolean parameter parsing (true/false/1/0) and fix for default reset bug'

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

# --- SETUP ORIGIN ---
origin_port = 8890
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# --- SCENARIO 1: Default Retention (Fix for reset bug) ---
# Config: Only change quality. Defaults (convert_to_*) should remain TRUE.
ts_default = Test.MakeATSProcess("ts_default")
ts_default.Disk.plugin_config.AddLine('webp_transform.so webp_quality=50')
ts_default.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_default.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- SCENARIO 2: Explicit False/0 ---
# Config: Disable JPEG conversion explicitly.
ts_disable = Test.MakeATSProcess("ts_disable")
ts_disable.Disk.plugin_config.AddLine('webp_transform.so convert_to_jpeg=false convert_to_webp=0')
ts_disable.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_disable.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- SCENARIO 3: Explicit True/1 & Legacy ---
# Config: Enable WebP explicitly with different formats.
ts_enable = Test.MakeATSProcess("ts_enable")
ts_enable.Disk.plugin_config.AddLine('webp_transform.so convert_to_avif=true convert_to_webp=1 convert_to_jpeg')
ts_enable.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_enable.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- SCENARIO 4: Robustness (Invalid/Conflict) ---
# Config: Invalid boolean and conflict (Last wins).
ts_robust = Test.MakeATSProcess("ts_robust")
ts_robust.Disk.plugin_config.AddLine('webp_transform.so convert_to_webp=invalid convert_to_jpeg=true convert_to_jpeg=false')
ts_robust.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_robust.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- EXECUTION ---

# 1. Test Default Retention (Bug fix check)
tr = Test.AddTestRun("Test Default Retention")
tr.Processes.Default.Command = \
    'curl -v -o /dev/null --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_default.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_default)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_default
# Expectation for fix: Should be webp.
# But current code will fail and return jpeg.
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("< Content-[Tt]ype: image/webp", "Should still convert to webp by default")

# 2. Test Explicit False
tr = Test.AddTestRun("Test Explicit False")
tr.Processes.Default.Command = \
    'curl -v -o /dev/null --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg && '.format(ts_disable.Variables.port) + \
    'curl -v -o /dev/null --header "Accept: image/jpeg" http://127.0.0.1:{0}/large.webp'.format(ts_disable.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_disable)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_disable
# Request 1: Accept webp but convert_to_webp=0 -> Should NOT be webp (Pass-through JPEG)
# Request 2: Accept jpeg but source is webp and convert_to_jpeg=false -> Should NOT be jpeg
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("< Content-[Tt]ype: image/jpeg", "WebP conversion should be disabled")
tr.Processes.Default.Streams.stderr += Testers.ContainsExpression("< Content-[Tt]ype: image/webp", "JPEG conversion should be disabled")

# 3. Test Explicit True and Legacy
tr = Test.AddTestRun("Test Explicit True and Legacy")
tr.Processes.Default.Command = \
    'curl -v -o /dev/null --header "Accept: image/avif" http://127.0.0.1:{0}/large.jpg && '.format(ts_enable.Variables.port) + \
    'curl -v -o /dev/null --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_enable.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_enable)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_enable
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("< Content-[Tt]ype: image/avif", "AVIF should be enabled (=true)")
tr.Processes.Default.Streams.stderr += Testers.ContainsExpression("< Content-[Tt]ype: image/webp", "WebP should be enabled (=1)")

# 4. Test Robustness and Conflict
tr = Test.AddTestRun("Test Robustness and Conflict")
tr.Processes.Default.Command = \
    'curl -v -o /dev/null --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg && '.format(ts_robust.Variables.port) + \
    'curl -v -o /dev/null --header "Accept: image/jpeg" http://127.0.0.1:{0}/large.webp'.format(ts_robust.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_robust)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_robust
# Request 1: convert_to_webp=invalid -> Should fallback to TRUE (default)
# Request 2: convert_to_jpeg=true then =false -> Last wins (false)
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("< Content-[Tt]ype: image/webp", "Should fallback to true on invalid input")
tr.Processes.Default.Streams.stderr += Testers.ContainsExpression("< Content-[Tt]ype: image/webp", "JPEG should be disabled (last win)")

# Final check for crashes
ts_robust.Disk.diags_log.Content = Testers.ExcludesExpression("FATAL|Segmentation", "No crashes allowed")
