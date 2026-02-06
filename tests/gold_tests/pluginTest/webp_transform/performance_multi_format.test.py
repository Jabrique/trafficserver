'''
Benchmark test for webp_transform plugin (JPEG & PNG -> WebP vs AVIF)
'''
import os

Test.Summary = '''
Benchmark webp_transform plugin compression for multiple formats
'''

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

ts = Test.MakeATSProcess("ts")
# Aktifkan semua konversi dengan explicit defaults
ts.Disk.plugin_config.AddLine(
    'webp_transform.so convert_to_avif convert_to_webp convert_to_jpeg avif_quality=50 webp_quality=75 jpeg_quality=85')
ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'webp_transform',
        'proxy.config.http.cache.http': 0,
    })

origin_port = 8093
origin_dir = os.path.join(Test.TestDirectory, "origin")

server = Test.Processes.Process("origin_server")
server.Command = "python3 -m http.server {} --bind 127.0.0.1 --directory {}".format(origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{}'.format(origin_port))

# --- SCENARIO 1: JPEG Input (Fractal) ---
tr = Test.AddTestRun("JPEG: Get Original")
tr.Processes.Default.Command = 'curl -v -o out_fractal.jpg --header "Host: www.example.com" --header "Accept: image/jpeg" http://127.0.0.1:{0}/large.jpg'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Ready = When.PortOpen(ts.Variables.port)
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

tr = Test.AddTestRun("JPEG: Get WebP")
tr.Processes.Default.Command = 'curl -v -o out_fractal.webp --header "Host: www.example.com" --header "Accept: image/webp" http://127.0.0.1:{0}/large.jpg'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("JPEG: Get AVIF")
tr.Processes.Default.Command = 'curl -v -o out_fractal.avif --header "Host: www.example.com" --header "Accept: image/avif" http://127.0.0.1:{0}/large.jpg'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

# --- SCENARIO 2: PNG Input (Logo) ---
tr = Test.AddTestRun("PNG: Get Original")
tr.Processes.Default.Command = 'curl -v -o out_logo.png --header "Host: www.example.com" --header "Accept: image/png" http://127.0.0.1:{0}/logo.png'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("PNG: Get WebP")
tr.Processes.Default.Command = 'curl -v -o out_logo.webp --header "Host: www.example.com" --header "Accept: image/webp" http://127.0.0.1:{0}/logo.png'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("PNG: Get AVIF")
tr.Processes.Default.Command = 'curl -v -o out_logo.avif --header "Host: www.example.com" --header "Accept: image/avif" http://127.0.0.1:{0}/logo.png'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

# --- COMPARE RESULTS ---
tr = Test.AddTestRun("Compare Sizes Report")
tr.Processes.Default.Command = 'echo "--- REPORT ---" && ls -lh out_fractal.* out_logo.*'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("out", "List output files")

