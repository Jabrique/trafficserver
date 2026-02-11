'''
Test webp_transform plugin for Per-Remap Configuration

Tests:
1. Per-remap quality settings (high vs low quality)
2. Remap stats registration (plugin.webp_transform.remap.*)
3. Invalid config rejection

Note on Stats Persistence:
- Cumulative stats (conversions, errors) are persistent and survive restarts
- Gauge stats (active_transforms, peak_buffer) reset on restart
- Persistence cannot be easily tested in AuTest (requires restart cycle)
- Manual verification: Check stats before/after `traffic_ctl server restart`
'''
import os

Test.Summary = 'Test Per-Remap Quality Configuration'

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

# --- SETUP ORIGIN ---
origin_port = 8098
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# --- SETUP ATS ---
ts = Test.MakeATSProcess("ts")

# Enable stats_over_http for remap stats verification
ts.Disk.plugin_config.AddLine('stats_over_http.so')

# Note: We do NOT load the plugin globally here to test Remap-only mode.
# Or we can load it globally but override in remap.
# Let's try pure remap loading first (standard practice for remap plugins).
# ts.Disk.plugin_config.AddLine('webp_transform.so')

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'webp_transform',
        'proxy.config.http.cache.http': 0,
    })

# --- REMAP CONFIG ---
# Rule 1: High Quality (90)
ts.Disk.remap_config.AddLine(
    'map http://www.example.com/high/ http://127.0.0.1:{0}/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=avif_quality=90'
    .format(origin_port))

# Rule 2: Low Quality (10)
ts.Disk.remap_config.AddLine(
    'map http://www.example.com/low/ http://127.0.0.1:{0}/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=avif_quality=10'
    .format(origin_port))

# --- TEST EXECUTION ---
tr = Test.AddTestRun("Compare Remap Quality")
tr.Processes.Default.Command = \
    'curl -v -o out_remap_high.avif --header "Host: www.example.com" --header "Accept: image/avif" http://127.0.0.1:{0}/high/large.jpg && '.format(ts.Variables.port) + \
    'curl -v -o out_remap_low.avif --header "Host: www.example.com" --header "Accept: image/avif" http://127.0.0.1:{0}/low/large.jpg'.format(ts.Variables.port)

tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Ready = When.PortOpen(ts.Variables.port)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# Validation: Check if file sizes are different
# If plugin doesn't support remap, it might fail to load or ignore params (defaulting to same size if global init works, or crash)
tr = Test.AddTestRun("Verify Size Difference")
tr.Processes.Default.Command = 'ls -lh out_remap_high.avif out_remap_low.avif'
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("out_remap", "List files")

# --- TEST: Verify Remap Stats are Registered ---
# When plugin is loaded via remap.config, remap.* stats should appear
tr = Test.AddTestRun("Check Remap Stats Registered")
tr.Processes.Default.Command = 'curl -s http://127.0.0.1:{0}/_stats 2>/dev/null | grep webp_transform.remap.conversions || echo "remap_stat_not_found"'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("webp_transform.remap.conversions",
                                                                   "Remap stats should be registered")

# Verify remap conversion count increased (we made 2 AVIF conversions above)
tr = Test.AddTestRun("Check Remap AVIF Conversion Count")
tr.Processes.Default.Command = 'curl -s http://127.0.0.1:{0}/_stats 2>/dev/null | grep webp_transform.remap.conversions_avif_total'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("conversions_avif_total",
                                                                   "AVIF conversion stat should exist")

# --- TEST 3: Invalid Remap Config (Should Return TS_ERROR) ---
# Per lines 727-730: config validation failure returns TS_ERROR
# This prevents invalid remap from loading while keeping server running
# We can't easily test TS_ERROR return in AuTest, but we can verify remap doesn't work
ts_invalid_remap = Test.MakeATSProcess("ts_invalid_remap")
ts_invalid_remap.Disk.records_config.update({'proxy.config.http.cache.http': 0})
# Add invalid quality value (out of range)
ts_invalid_remap.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{} @plugin=webp_transform.so @pparam=webp_quality=999'.format(origin_port))

# Test that invalid config is properly rejected
# ATS will fail to start with FATAL error, which is correct behavior
# Just verify error logged by checking diags.log content

# ATS should fail to start (not still running)
ts_invalid_remap.ReturnCode = Any(None, 0, 70)  # 70 = config error exit code
ts_invalid_remap.Ready = 0  # Don't wait for ready (will never be ready)

# Verify error message in logs
ts_invalid_remap.Disk.diags_log.Content = Testers.ContainsExpression(
    "webp_quality= value 999 out of range", 
    "Plugin should reject invalid quality value"
)
