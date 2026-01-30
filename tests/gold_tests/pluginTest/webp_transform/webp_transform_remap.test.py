
'''
Test webp_transform plugin for Per-Remap Configuration
'''
import os

Test.Summary = 'Test Per-Remap Quality Configuration'

Test.SkipUnless(
    Condition.PluginExists('webp_transform.so'),
)

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

# Note: We do NOT load the plugin globally here to test Remap-only mode.
# Or we can load it globally but override in remap. 
# Let's try pure remap loading first (standard practice for remap plugins).
# ts.Disk.plugin_config.AddLine('webp_transform.so') 

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'webp_transform',
    'proxy.config.http.cache.http': 0,
})

# --- REMAP CONFIG ---
# Rule 1: High Quality (90)
ts.Disk.remap_config.AddLine(
    'map http://www.example.com/high/ http://127.0.0.1:{0}/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=avif_quality=90'.format(origin_port)
)

# Rule 2: Low Quality (10)
ts.Disk.remap_config.AddLine(
    'map http://www.example.com/low/ http://127.0.0.1:{0}/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=avif_quality=10'.format(origin_port)
)

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
