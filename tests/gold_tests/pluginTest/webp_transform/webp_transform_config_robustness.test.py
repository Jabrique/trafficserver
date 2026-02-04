
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
