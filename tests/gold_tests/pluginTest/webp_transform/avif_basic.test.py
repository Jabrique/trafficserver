'''
Test the webp_transform plugin for AVIF support using real JPEG and python http.server
'''
import os

Test.Summary = '''
Test webp_transform plugin for AVIF conversion
'''

Test.SkipUnless(Condition.PluginExists('webp_transform.so'),)

# 1. Setup ATS
ts = Test.MakeATSProcess("ts")
ts.Disk.plugin_config.AddLine('webp_transform.so convert_to_avif')
ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'webp_transform',
        'proxy.config.http.cache.http': 0,
    })

# 2. Setup Origin Server (Python http.server) to serve raw binary files correctly
origin_port = 8090
origin_dir = os.path.join(Test.TestDirectory, "origin")

server = Test.Processes.Process("origin_server")
# Run python http server on specific port and directory
server.Command = "python3 -m http.server {} --bind 127.0.0.1 --directory {}".format(origin_port, origin_dir)
server.Ready = When.PortOpen(origin_port)
server.ReturnCode = Any(None, 0, -2, -15)

# 3. Configure Remap
ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{}'.format(origin_port))

# 4. Test Run
tr = Test.AddTestRun("Test AVIF Content-Type Detection and Conversion")
tr.Processes.Default.Command = 'curl --verbose --header "Host: www.example.com" --header "Accept: image/avif,image/webp,*/*" http://127.0.0.1:{0}/image.jpg'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Ready = When.PortOpen(ts.Variables.port)

# Expect the response Content-Type to be image/avif using flexible match
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-type: image/avif", "Verify response header contains Content-type: image/avif")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
