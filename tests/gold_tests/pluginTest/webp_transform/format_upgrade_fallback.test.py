'''
Advanced Transcoding Benchmark (WebP/AVIF Inputs)
Including Legacy Browser Wildcard Fallback Tests

Tests format upgrades/downgrades AND legacy browser behavior where
wildcard Accept headers (*/* or image/*) should fallback to JPEG.
'''
import os

Test.Summary = 'Format Upgrade/Fallback and Legacy Browser Tests'

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


# --- TEST 5: PNG -> WebP Transformation ---
tr = Test.AddTestRun("PNG to WebP Upgrade")
tr.Processes.Default.Command = \
    'curl -v -o out_png.webp --header "Host: www.example.com" --header "Accept: image/webp" http://127.0.0.1:{0}/test.png'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun("Verify PNG to WebP")
tr.Processes.Default.Command = 'file out_png.webp'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Web/P image", "PNG should convert to WebP")

# =============================================================================
# LEGACY BROWSER WILDCARD FALLBACK TESTS
#
# Bug: acceptsImageType() treats */* as accepting AVIF/WebP, causing old
# browsers to receive formats they cannot display → auto-download.
#
# Fix: Wildcard (*/* or image/*) should only match universal formats (JPEG/PNG)
# Modern formats (AVIF/WebP) require explicit Accept header listing.
#
# Research sources: MDN Web Docs, Can I Use, Google WebP FAQ
# =============================================================================

# --- TEST: IE 11 / Firefox 47-63 style (only */*) ---
tr = Test.AddTestRun("Legacy: */* only + WebP input -> JPEG")
tr.Processes.Default.Command = '''curl -v -o legacy_wildcard.jpg \
    --header "Host: www.example.com" \
    --header "Accept: */*" \
    http://127.0.0.1:{0}/large.webp'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/jpeg", "IE11/old Firefox with */* should get JPEG")

tr = Test.AddTestRun("Legacy: */* only + AVIF input -> JPEG")
tr.Processes.Default.Command = '''curl -v -o legacy_wildcard_avif.jpg \
    --header "Host: www.example.com" \
    --header "Accept: */*" \
    http://127.0.0.1:{0}/large.avif'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/jpeg", "Legacy browser with */* should get JPEG from AVIF")

# --- TEST: Safari 13.1+ document request style ---
tr = Test.AddTestRun("Legacy: Document Accept */*;q=0.8 + WebP -> JPEG")
tr.Processes.Default.Command = '''curl -v -o legacy_doc.jpg \
    --header "Host: www.example.com" \
    --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    http://127.0.0.1:{0}/large.webp'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/jpeg", "Document request with */*;q=0.8 should get JPEG")

# --- TEST: Safari <14 style (no webp/avif, only image/*) ---
tr = Test.AddTestRun("Legacy: Safari <14 style + WebP -> JPEG")
tr.Processes.Default.Command = '''curl -v -o legacy_safari13.jpg \
    --header "Host: www.example.com" \
    --header "Accept: image/png,image/svg+xml,image/*;q=0.8,video/*;q=0.8,*/*;q=0.5" \
    http://127.0.0.1:{0}/large.webp'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/jpeg", "Safari <14 without webp should get JPEG")

# --- TEST: Edge Legacy 12-17 style (image/jxr,*/*) ---
tr = Test.AddTestRun("Legacy: Edge 12-17 style + WebP -> JPEG")
tr.Processes.Default.Command = '''curl -v -o legacy_edge.jpg \
    --header "Host: www.example.com" \
    --header "Accept: image/jxr,*/*" \
    http://127.0.0.1:{0}/large.webp'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/jpeg", "Edge Legacy should get JPEG")

# --- TEST: image/* wildcard only ---
tr = Test.AddTestRun("Legacy: image/* only + WebP -> JPEG")
tr.Processes.Default.Command = '''curl -v -o legacy_imagestar.jpg \
    --header "Host: www.example.com" \
    --header "Accept: image/*" \
    http://127.0.0.1:{0}/large.webp'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/jpeg", "image/* wildcard should get JPEG")

# =============================================================================
# MODERN BROWSER VERIFICATION (ensure fix doesn't break explicit support)
# =============================================================================

# --- TEST: Chrome 85+ style (explicit avif,webp) ---
tr = Test.AddTestRun("Modern: Chrome 85+ explicit avif,webp + WebP -> AVIF")
tr.Processes.Default.Command = '''curl -v -o modern_chrome.avif \
    --header "Host: www.example.com" \
    --header "Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8" \
    http://127.0.0.1:{0}/large.webp'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/avif", "Chrome 85+ with explicit avif should get AVIF")

# --- TEST: Firefox 65-91 style (webp only, no avif) ---
tr = Test.AddTestRun("Modern: Firefox 65-91 webp only + JPEG -> WebP")
tr.Processes.Default.Command = '''curl -v -o modern_ff65.webp \
    --header "Host: www.example.com" \
    --header "Accept: image/webp,*/*" \
    http://127.0.0.1:{0}/large.jpg'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/webp", "Firefox 65-91 with explicit webp should get WebP")

# --- TEST: Safari 14+ style (webp, no avif) ---
tr = Test.AddTestRun("Modern: Safari 14+ webp + JPEG -> WebP")
tr.Processes.Default.Command = '''curl -v -o modern_safari14.webp \
    --header "Host: www.example.com" \
    --header "Accept: image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5" \
    http://127.0.0.1:{0}/large.jpg'''.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    "Content-[Tt]ype: image/webp", "Safari 14+ with explicit webp should get WebP")
