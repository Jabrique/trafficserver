'''
Advanced Transcoding Benchmark (WebP/AVIF Inputs)
'''
import os

Test.Summary = 'Advanced Transcoding Benchmark'

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

ts = Test.MakeATSProcess("ts")
# Aktifkan semua konversi termasuk convert_to_jpeg (untuk fallback)
ts.Disk.plugin_config.AddLine('webp_transform.so convert_to_avif convert_to_webp convert_to_jpeg')
ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'webp_transform',
        'proxy.config.http.cache.http': 0,
    })

origin_port = 8094
# Use Test.TestDirectory for robust path resolution
origin_dir = os.path.join(Test.TestDirectory, "origin")

# Use custom origin server script to ensure correct MIME types (avif/webp)
origin_script = os.path.join(Test.TestDirectory, "origin_server.py")
server = Test.Processes.Process("origin_server")
server.Command = "python3 {} {} {}".format(origin_script, origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)  # Allow SIGINT (-2) and SIGTERM (-15)

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{}'.format(origin_port))

# 1. Input WebP -> Request AVIF (Upgrade)
tr = Test.AddTestRun("WebP -> AVIF (Upgrade)")
tr.Processes.Default.Command = 'curl -v -o out_from_webp.avif --header "Host: www.example.com" --header "Accept: image/avif" http://127.0.0.1:{0}/large.webp'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Ready = When.PortOpen(ts.Variables.port)
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("Content-type: image/avif", "Check Content-Type")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# 2. Input WebP -> Request JPEG (Fallback)
tr = Test.AddTestRun("WebP -> JPEG (Fallback)")
tr.Processes.Default.Command = 'curl -v -o out_from_webp.jpg --header "Host: www.example.com" --header "Accept: image/jpeg" http://127.0.0.1:{0}/large.webp'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
# Content-Type header should match regex because curl case varies
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("Content-type: image/jpeg", "Check Content-Type")

# 3. Input AVIF -> Request WebP (Compat)
tr = Test.AddTestRun("AVIF -> WebP (Compat)")
tr.Processes.Default.Command = 'curl -v -o out_from_avif.webp --header "Host: www.example.com" --header "Accept: image/webp" http://127.0.0.1:{0}/large.avif'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("Content-type: image/webp", "Check Content-Type")

# 4. Input AVIF -> Request JPEG (Fallback)
tr = Test.AddTestRun("AVIF -> JPEG (Fallback)")
tr.Processes.Default.Command = 'curl -v -o out_from_avif.jpg --header "Host: www.example.com" --header "Accept: image/jpeg" http://127.0.0.1:{0}/large.avif'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression("Content-type: image/jpeg", "Check Content-Type")
