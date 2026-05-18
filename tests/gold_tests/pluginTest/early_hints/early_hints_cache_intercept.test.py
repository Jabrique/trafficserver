import os
import time

Test.Summary = '''
Test Early Hints ATS Cache Interception (WP7)
Verify that the plugin intercepts READ_CACHE_HDR_HOOK and re-learns hints
from the ATS cache if they were evicted from the plugin's memory.
'''

Test.SkipUnless(
    Condition.HasProgram("curl", "curl needs to be installed on system for this test to work"),
    Condition.HasProgram("nghttp", "nghttp needs to be installed on system for this test to work")
)

ts = Test.MakeATSProcess("ts", select_ports=True, enable_tls=True)
server = Test.MakeOriginServer("server")

# -- ORIGIN SERVER SETUP --
req_a = {"headers": "GET /pageA.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
res_a = {"headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nCache-Control: max-age=3600\r\nContent-Type: text/html\r\n\r\n", 
         "timestamp": "1469733493.993", 
         "body": "<html><head><link rel=\"preload\" href=\"/appA.js\" as=\"script\"></head><body>A</body></html>"}

req_b = {"headers": "GET /pageB.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
res_b = {"headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nCache-Control: max-age=3600\r\nContent-Type: text/html\r\n\r\n", 
         "timestamp": "1469733493.993", 
         "body": "<html><head><link rel=\"preload\" href=\"/appB.js\" as=\"script\"></head><body>B</body></html>"}

server.addResponse("sessionlog.json", req_a, res_a)
server.addResponse("sessionlog.json", req_b, res_b)

# -- ATS CONFIGURATION --
ts.addDefaultSSLFiles()
ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'early_hints.*',
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.http.cache.http': 1,
    'proxy.config.http.insert_request_via_str': 1,
    'proxy.config.http.insert_response_via_str': 2,
    'proxy.config.http.server_ports': '{0} {1}:ssl'.format(ts.Variables.port, ts.Variables.ssl_port)
})

ts.Disk.ssl_multicert_config.AddLine(
    'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key'
)

# Configure plugin with --max-cache-entries 1 and --min-hit-count 1
ts.Disk.remap_config.AddLine(
    'map https://www.example.com http://127.0.0.1:{0} @plugin=early_hints.so @pparam=--mode=auto-learn @pparam=--max-cache-entries=1 @pparam=--min-hit-count=1 @pparam=--no-persist'.format(server.Variables.Port)
)

# ----
# TC1: Request A (Origin Hit, Learn A)
# ----
tr1 = Test.AddTestRun("Request A - Origin Hit")
tr1.Processes.Default.StartBefore(server)
tr1.Processes.Default.StartBefore(ts)
tr1.Processes.Default.Command = 'curl -s -v -k --http2 https://127.0.0.1:{0}/pageA.html -H "Host: www.example.com"'.format(ts.Variables.ssl_port)
tr1.Processes.Default.ReturnCode = 0
tr1.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 200", "Should get 200 OK")

# ----
# TC2: Request B (Origin Hit, Learn B, Evict A!)
# ----
tr2 = Test.AddTestRun("Request B - Evict A")
tr2.Processes.Default.Command = 'curl -s -v -k --http2 https://127.0.0.1:{0}/pageB.html -H "Host: www.example.com"'.format(ts.Variables.ssl_port)
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 200", "Should get 200 OK")

# ----
# TC3: Request A again (Cache Hit for A). Memory lost A, so no 103 yet, BUT intercepts by parsing cache.
# ----
tr3 = Test.AddTestRun("Request A - Cache Hit, Cache Intercept")
tr3.Processes.Default.Command = 'sleep 1 && curl -s -v -k --http2 https://127.0.0.1:{0}/pageA.html -H "Host: www.example.com"'.format(ts.Variables.ssl_port)
tr3.Processes.Default.ReturnCode = 0
# Should be a cache hit (TCP_HIT)
tr3.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 200", "Should get 200 OK")

# ----
# TC4: Request A third time. Plugin should now serve 103!
# ----
tr4 = Test.AddTestRun("Request A - Serve 103")
tr4.Processes.Default.Command = 'sleep 1 && curl -s -v -k --http2 https://127.0.0.1:{0}/pageA.html -H "Host: www.example.com"'.format(ts.Variables.ssl_port)
tr4.Processes.Default.ReturnCode = 0
tr4.Processes.Default.Streams.stderr = Testers.ContainsExpression("HTTP/2 103", "Should get 103 Early Hints")
tr4.Processes.Default.Streams.stderr = Testers.ContainsExpression("link: </appA.js>; rel=preload; as=script", "Should contain the hint")

