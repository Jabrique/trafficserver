
'''
Test webp_transform plugin for Configuration Robustness and Stability
'''
import os

Test.Summary = 'Test Config Robustness (Ambiguous params) and Stability (Invalid values)'

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
