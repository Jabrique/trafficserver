'''
Test webp_transform plugin for Configurable Quality (All Formats)
'''
import os

Test.Summary = 'Test Configurable Quality for AVIF, WebP, and JPEG'

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

# --- SETUP ORIGIN ---
origin_port = 8096
origin_dir = os.path.join(Test.TestDirectory, "origin")
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")

server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# --- INSTANCE 1: ALL LOW QUALITY (10) ---
ts_low = Test.MakeATSProcess("ts_low")
ts_low.Disk.plugin_config.AddLine(
    'webp_transform.so convert_to_avif convert_to_webp convert_to_jpeg avif_quality=10 webp_quality=10 jpeg_quality=10 progressive')
ts_low.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_low.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- INSTANCE 2: EXPLICIT DEFAULTS (50/75/85) ---
ts_def = Test.MakeATSProcess("ts_def")
ts_def.Disk.plugin_config.AddLine(
    'webp_transform.so convert_to_avif convert_to_webp convert_to_jpeg avif_quality=50 webp_quality=75 jpeg_quality=85 progressive')
ts_def.Disk.records_config.update({'proxy.config.http.cache.http': 0})
ts_def.Disk.remap_config.AddLine('map / http://127.0.0.1:{}'.format(origin_port))

# --- TEST EXECUTION ---

tr = Test.AddTestRun("Fetch Images with Different Quality")
tr.Processes.Default.Command = \
    'curl -v -o avif_low.avif --header "Host: www.example.com" --header "Accept: image/avif" http://127.0.0.1:{0}/large.jpg && '.format(ts_low.Variables.port) + \
    'curl -v -o avif_def.avif --header "Host: www.example.com" --header "Accept: image/avif" http://127.0.0.1:{0}/large.jpg && '.format(ts_def.Variables.port) + \
    'curl -v -o webp_low.webp --header "Host: www.example.com" --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg && '.format(ts_low.Variables.port) + \
    'curl -v -o webp_def.webp --header "Host: www.example.com" --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(ts_def.Variables.port)

tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_low)
tr.Processes.Default.StartBefore(ts_def)
tr.Processes.Default.Ready = When.PortOpen(ts_def.Variables.port)
tr.StillRunningAfter = server
tr.StillRunningAfter = ts_low
tr.StillRunningAfter = ts_def

# --- VERIFICATION (ASSERT SIZE DIFFERENCE) ---

tr = Test.AddTestRun("Verify Size Difference")
# Using double dollar $$ to escape for AuTest and echo for explicit verification
tr.Processes.Default.Command = \
    'low=$$(stat -c%s avif_low.avif) && def=$$(stat -c%s avif_def.avif) && [ $$low -lt $$def ] && echo "AVIF_OK" ; ' + \
    'low=$$(stat -c%s webp_low.webp) && def=$$(stat -c%s webp_def.webp) && [ $$low -lt $$def ] && echo "WEBP_OK"'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("AVIF_OK", "AVIF size check")
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression("WEBP_OK", "WebP size check")
