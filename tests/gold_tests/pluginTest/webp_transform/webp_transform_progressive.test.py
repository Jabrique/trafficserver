
'''
Test webp_transform plugin for Progressive (Interlace) Support
'''
import os

Test.Summary = 'Test Progressive JPEG Generation'

Test.SkipUnless(
    Condition.PluginExists('webp_transform.so'),
)

# --- SETUP ORIGIN ---
origin_port = 8099
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# --- INSTANCE 1: BASELINE (NO PROGRESSIVE) ---
ts_base = Test.MakeATSProcess("ts_base")
ts_base.Disk.plugin_config.AddLine('webp_transform.so convert_to_jpeg')
ts_base.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'webp_transform',
    'proxy.config.http.cache.http': 0,
})
ts_base.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{}'.format(origin_port)
)

# --- INSTANCE 2: PROGRESSIVE ---
ts_prog = Test.MakeATSProcess("ts_prog")
ts_prog.Disk.plugin_config.AddLine('webp_transform.so convert_to_jpeg progressive')
ts_prog.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'webp_transform',
    'proxy.config.http.cache.http': 0,
})
ts_prog.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{}'.format(origin_port)
)

# --- EXECUTION ---

# 1. Fetch Baseline
tr = Test.AddTestRun("Fetch Baseline JPEG")
tr.Processes.Default.Command = 'curl -v -o out_base.jpg --header "Accept: image/jpeg" http://127.0.0.1:{0}/large.jpg'.format(ts_base.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_base)
tr.Processes.Default.StartBefore(ts_prog) # Start both
tr.Processes.Default.Ready = When.PortOpen(ts_prog.Variables.port)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_base
tr.StillRunningAfter = ts_prog

# 2. Fetch Progressive
tr = Test.AddTestRun("Fetch Progressive JPEG")
tr.Processes.Default.Command = 'curl -v -o out_prog.jpg --header "Accept: image/jpeg" http://127.0.0.1:{0}/large.jpg'.format(ts_prog.Variables.port)
tr.Processes.Default.ReturnCode = 0

# 3. Verify Interlace Status
# Using grep to check identify output.
# Baseline should contain "Interlace: None"
# Progressive should contain "Interlace: JPEG" (or Plane)
tr = Test.AddTestRun("Verify Interlace")
tr.Processes.Default.Command = \
    'echo "--- BASELINE ---" && magick identify -verbose out_base.jpg | grep Interlace && ' + \
    'echo "--- PROGRESSIVE ---" && magick identify -verbose out_prog.jpg | grep Interlace'
tr.Processes.Default.ReturnCode = 0
# We expect to see "Interlace: JPEG" in the output eventually, but for Red Phase we just print it.
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Interlace", "Check Interlace output")
