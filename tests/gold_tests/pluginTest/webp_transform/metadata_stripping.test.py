'''
Test webp_transform plugin for Metadata Stripping Options
'''
import os

Test.Summary = 'Test Granular Metadata Stripping (none/icc/all)'

Test.SkipUnless(
    Condition.PluginExists('webp_transform.so'),
)

# --- SETUP ORIGIN ---
origin_port = 8090
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# --- CONFIGURATIONS ---

# 1. NONE (Strip All)
ts_none = Test.MakeATSProcess("ts_none")
ts_none.Disk.plugin_config.AddLine('webp_transform.so convert_to_jpeg metadata=none progressive')
ts_none.Disk.records_config.update({ 'proxy.config.http.cache.http': 0 })
ts_none.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# 2. ICC (Keep Color Profile only)
ts_icc = Test.MakeATSProcess("ts_icc")
ts_icc.Disk.plugin_config.AddLine('webp_transform.so convert_to_jpeg metadata=icc progressive')
ts_icc.Disk.records_config.update({ 'proxy.config.http.cache.http': 0 })
ts_icc.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# 3. ALL (Keep Everything - Default)
ts_all = Test.MakeATSProcess("ts_all")
ts_all.Disk.plugin_config.AddLine('webp_transform.so convert_to_jpeg metadata=all progressive')
ts_all.Disk.records_config.update({ 'proxy.config.http.cache.http': 0 })
ts_all.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- EXECUTION ---

tr = Test.AddTestRun("Fetch Metadata Variations")
tr.Processes.Default.Command = \
    'curl -v -o out_none.jpg --header "Accept: image/jpeg" http://127.0.0.1:{0}/iptc_std.jpg && '.format(ts_none.Variables.port) + \
    'curl -v -o out_icc.jpg --header "Accept: image/jpeg" http://127.0.0.1:{0}/iptc_std.jpg && '.format(ts_icc.Variables.port) + \
    'curl -v -o out_all.jpg --header "Accept: image/jpeg" http://127.0.0.1:{0}/iptc_std.jpg'.format(ts_all.Variables.port)

tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_none)
tr.Processes.Default.StartBefore(ts_icc)
tr.Processes.Default.StartBefore(ts_all)
tr.Processes.Default.Ready = When.PortOpen(ts_all.Variables.port)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_none
tr.StillRunningAfter = ts_icc
tr.StillRunningAfter = ts_all

# --- VERIFICATION ---

# 1. NONE: Must NOT have EXIF/IPTC
tr = Test.AddTestRun("Verify NONE (Full Strip)")
tr.Processes.Default.Command = 'magick identify -verbose out_none.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ExcludesExpression("Profile-exif", "Should not have EXIF")
tr.Processes.Default.Streams.stdout += Testers.ExcludesExpression("Profile-iptc", "Should not have IPTC")

# 2. ICC: Must HAVE ICC but NO EXIF
tr = Test.AddTestRun("Verify ICC (Safe Strip)")
tr.Processes.Default.Command = 'magick identify -verbose out_icc.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Profile-icc", "Should have ICC")
tr.Processes.Default.Streams.stdout += Testers.ExcludesExpression("Profile-exif", "Should not have EXIF")

# 3. ALL: Must HAVE EXIF
tr = Test.AddTestRun("Verify ALL (No Strip)")
tr.Processes.Default.Command = 'magick identify -verbose out_all.jpg'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Profile-exif", "Should have EXIF")