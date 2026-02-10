# WebP & AVIF Transform Plugin

This plugin serves as a Universal Image Transcoder, automatically converting images (JPEG, PNG, WebP, AVIF) into the most efficient format supported by the user's browser (AVIF or WebP), or falling back to JPEG for legacy compatibility.

It supports both **Global** and **Per-Remap** configurations.

## Key Features

1.  **Bandwidth Savings:** Converts massive JPEG/PNG images to tiny AVIF/WebP.
2.  **Modernization:** Automatically converts WebP content to AVIF when browser supports it.
3.  **Compatibility:** Automatically downgrades modern AVIF content to WebP or JPEG for older browsers.
4.  **Adjustable Quality:** Fine-tune the compression level per format.
5.  **Progressive Rendering:** Support for Progressive JPEG to improve perceived load speed.
6.  **Metadata Stripping:** Granular control over EXIF/IPTC/XMP removal for privacy and size optimization.

### Internal Benchmark Results (120KB JPEG Source)
- **Original JPEG:** 120 KB
- **WebP (Q=75):** 40 KB (~66% savings)
- **AVIF (Q=50):** 15 KB (~87% savings)
- **Metadata Stripping:** Up to 30KB+ additional savings per image.

**Note**: Results vary based on image content, complexity, and quality settings. Your mileage may vary.

## Supported Image Formats

### Input Formats (Can Be Read)
The plugin can process the following input formats:
- **JPEG** (.jpg, .jpeg) - `image/jpeg`
- **PNG** (.png) - `image/png`
- **WebP** (.webp) - `image/webp`
- **AVIF** (.avif) - `image/avif`

### Output Formats (Can Be Generated)
The plugin can generate the following output formats:
- **JPEG** - `image/jpeg`
- **WebP** - `image/webp`
- **AVIF** - `image/avif`

**Important**: PNG is supported as **INPUT only**, not OUTPUT. PNG images can be converted to JPEG/WebP/AVIF, but the plugin cannot output PNG format.

### Unsupported Formats (Passthrough)
The following formats are **not supported** and will be served unchanged (passthrough):
- **GIF** (.gif) - Animated images
- **BMP** (.bmp) - Bitmap images
- **TIFF** (.tif, .tiff) - Tagged Image File Format
- **SVG** (.svg) - Vector graphics
- **Any other non-JPEG/PNG/WebP/AVIF format**

When an unsupported format is detected:
1. Plugin logs a security alert: `"Unsupported format spoofed as image"`
2. The `passthrough_invalid_total` metric is incremented
3. Original image is served unchanged to the client

## System Prerequisites

For AVIF conversion to work, your server must have **ImageMagick 7** installed and compiled with **libheif** support.

**Installation Guide (Rocky Linux 9 / RHEL 9):**
```bash
sudo dnf install https://rpms.remirepo.net/enterprise/remi-release-9.rpm
sudo dnf --enablerepo=remi install ImageMagick7 ImageMagick7-heic ImageMagick7-c++-devel
```

## Configuration

### 1. Global Configuration
Add the following line to `plugin.config` to apply the plugin to **all** traffic:

```
# Basic activation (All features ON by default)
webp_transform.so

# High performance with custom quality and metadata stripping
webp_transform.so convert_to_avif convert_to_webp metadata=icc progressive avif_quality=40 webp_quality=60
```

### 2. Per-Remap Configuration
Add the plugin to specific rules in `remap.config` using `@pparam`:

```
# High quality photography site
map http://photo.com/ http://origin/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=avif_quality=90

# High performance for thumbnails (Extreme stripping)
map http://img.com/thumbs/ http://origin/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=progressive @pparam=avif_quality=20 @pparam=metadata=none
```

### Configuration Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `convert_to_avif[=BOOL]` | Enables upgrade to AVIF. | `true` |
| `convert_to_webp[=BOOL]` | Enables upgrade/fallback to WebP. | `true` |
| `convert_to_jpeg[=BOOL]` | Enables fallback to JPEG. | `true` |
| `progressive` | Enables Progressive JPEG rendering. | Off |
| `avif_quality=N` | Set AVIF quality (1-100). | 50 |
| `webp_quality=N` | Set WebP quality (1-100). | 75 |
| `jpeg_quality=N` | Set JPEG quality (1-100). | 85 |
| `max_image_size=N` | Max image size in bytes. **Valid range: 1KB-100MB** (1024-104857600). Images exceeding this bypass transformation (DoS protection). | 10MB |
| `max_pixels=N` | Max total pixels (width × height) to process. **Valid range: 1K-500MP** (1000-500000000). Prevents decompression bombs. | 100MP |
| `timeout=N` | ImageMagick processing timeout in seconds. **Valid range: 1-60 seconds**. Operations exceeding this abort and passthrough. | 5 |
| `metadata=MODE` | Metadata stripping mode (see below). | `all` |

**Note on Boolean Values:**
For arguments marked with `[=BOOL]`, you can use `true`/`false`, `1`/`0`, or `on`/`off`. If no value is provided (e.g., just `convert_to_webp`), it defaults to `true`.

### Metadata Modes
- `none`: Removes **ALL** metadata (EXIF, XMP, IPTC, ICC). Maximum size reduction but may affect color accuracy.
- `icc`: Removes EXIF/XMP/IPTC but **preserves ICC Color Profile**. Safe for color accuracy.
- `all`: Keeps all original metadata (Default).

## How It Works

The plugin uses a smart logic matrix to determine the best output format:

1.  **Detection:** Plugin checks the browser's `Accept` header.
2.  **Selection:**
    - If `image/avif` supported -> Targets **AVIF**.
    - If not, but `image/webp` supported -> Targets **WebP**.
    - If neither supported -> Targets **JPEG** (only if input was WebP or AVIF).
3.  **Transformation Logic (Self-Transformation):**
    - The plugin normally **only** re-encodes if the Format Changes (e.g. JPEG -> AVIF).
    - **Exception:** If `progressive` is enabled OR `metadata` is set to `none`/`icc`, the plugin will force a re-encoding even if the format matches (e.g. JPEG -> Progressive JPEG), applying the configured quality and stripping logic in the process.
4.  **Header Sync:** The plugin automatically updates the `Content-Type` and adds `Vary: Accept` to ensure correct caching.

### Accept Header Parsing

The plugin parses the client's `Accept` header to determine browser capabilities:

**Exact Match**:
- `Accept: image/avif` → AVIF transformation (if enabled)
- `Accept: image/webp` → WebP transformation (if enabled)
- `Accept: image/jpeg` → No transformation unless downgrade needed

**Wildcard Support**:
- `Accept: image/*` → Transforms to AVIF (highest priority format)
- `Accept: */*` → Transforms to AVIF (highest priority format)

**Multiple Types**:
- `Accept: image/avif, image/webp, image/jpeg` → AVIF (first match in priority order)
- `Accept: text/html, image/webp` → WebP (non-image types ignored)

**Priority Order** (when multiple formats accepted):
1. **AVIF** (if `convert_to_avif=true` and browser supports `image/avif` or wildcards)
2. **WebP** (if `convert_to_webp=true` and browser supports `image/webp` or wildcards)
3. **JPEG** (if `convert_to_jpeg=true` and input is WebP/AVIF)

**Important Limitations**:
- **Quality factors (q=) are NOT supported**: The plugin does not parse or respect quality preference values like `image/avif;q=0.9`. First match in priority order wins.
- **Missing Accept header**: If no Accept header is sent, no transformation occurs (passthrough).
- **Empty Accept header**: Same as missing header (passthrough).

### Same-Format Transformation

Normally, the plugin **skips transformation** if the input format already matches the target format (e.g., JPEG → JPEG).

**Exceptions** (force re-encoding in same format):

1. **Progressive JPEG**: If `progressive=true` and input is JPEG, the plugin re-encodes to Progressive JPEG
2. **Metadata Stripping**: If `metadata=none` or `metadata=icc`, the plugin re-encodes in the same format to strip metadata

**Priority**: Progressive JPEG takes precedence over metadata stripping for JPEG inputs.

⚠️ **CRITICAL LIMITATION**: The `progressive` parameter **ONLY affects JPEG images**. For PNG/WebP/AVIF formats, the parameter is **silently ignored** because ImageMagick's `PlaneInterlace` setting (used internally) only produces progressive encoding for JPEG format.

**Examples**:
- **JPEG → JPEG** with `progressive=true` → Re-encodes to Progressive JPEG ✓
- **JPEG → JPEG** with `progressive=true, metadata=none` → Re-encodes (progressive + metadata stripping) ✓
- **PNG → PNG** with `progressive=true, metadata=all` → Passthrough (progressive ignored for PNG) ✗
- **PNG → PNG** with `metadata=icc` → Re-encodes PNG to strip ICC profile ✓
- **WebP → WebP** with `progressive=true, metadata=all` → Passthrough (progressive ignored for WebP) ✗
- **WebP → WebP** with `metadata=none` → Re-encodes WebP to strip metadata ✓
- **AVIF → AVIF** with `progressive=true, metadata=all` → Passthrough (progressive ignored for AVIF) ✗
- **AVIF → AVIF** with `metadata=icc` → Re-encodes AVIF to strip ICC profile ✓

**Note**: If you need progressive-like rendering for WebP, use WebP's native features at the encoder level, not this plugin.

### Passthrough Conditions

The plugin serves the original image **unchanged (passthrough)** when any of these conditions occur:

1. **Unsupported Input Format**: Image format is not JPEG/PNG/WebP/AVIF (e.g., GIF, BMP, TIFF)
2. **Size Limit Exceeded**: Image size exceeds `max_image_size` after buffering starts (default 10MB)
3. **Pixel Limit Exceeded**: Width × Height exceeds `max_pixels` (default 100MP)
4. **No Transformation Needed**: Input format matches target format AND no progressive/metadata changes required
5. **Missing Accept Header**: Browser doesn't send an Accept header
6. **Accept Header Mismatch**: Browser doesn't support any output format (rare with wildcards)
7. **Processing Error**: ImageMagick timeout, exception, or internal error
8. **Empty Output**: Transformation produces an empty blob (ImageMagick failure)
9. **Out of Memory (OOM)**: Server runs out of memory during transformation

**Metrics Tracking**: Each passthrough condition increments a specific metric:
- `passthrough_invalid_total` → Unsupported format (#1)
- `passthrough_size_bytes` → Size limit exceeded (#2)
- `passthrough_pixels_exceeded` → Pixel limit exceeded (#3)
- `transform_errors_total` → Errors (#7, #8, #9)

**Error Propagation on Passthrough**:
When transformation fails and passthrough occurs:
- ✅ Original `Content-Type` header is preserved
- ✅ Original `Content-Length` header is preserved
- ✅ Original response body is served **byte-for-byte** unchanged
- ❌ `Vary: Accept` header is **NOT** added (only added on successful transformation)

## Security & Hardening

This plugin implements defense-in-depth against malicious images:

### DoS Protection Layers
1. **Size Limit**: Images exceeding `max_image_size` (default 10MB) abort transformation after buffering starts → prevents bandwidth exhaustion
2. **Pixel Bomb**: Images >100MP (default) rejected → prevents decompression bombs (tiny compressed → huge uncompressed)
3. **Timeout Protection**: ImageMagick operations timeout after `timeout` seconds (default 5s, configurable 1-60s) → prevents thread starvation from pathological images
4. **Config Validation**: Invalid parameters abort plugin initialization with different blast radius:

**Global Plugin Mode** (`plugin.config`):
```
# Example invalid configuration
webp_transform.so max_image_size=999999999999999
```
- ❌ **Impact**: ENTIRE plugin disabled for ALL traffic across all virtual hosts
- ✅ **Mitigation**: All requests served without transformation (passthrough original images)
- ✅ **Traffic Server**: Continues working normally (no crash, no service disruption)
- ❌ **Client Impact**: None (images served unchanged - no broken images)
- 📝 **Error Log**: `[webp_transform] Config validation failed - ABORTING plugin initialization`
- 📊 **Metrics**: All `plugin.webp_transform.*` metrics remain at 0 (plugin not loaded)

**Per-Remap Mode** (`remap.config`):
```
# Remap 1 - INVALID config (plugin disabled for this remap only)
map http://site1.com/ http://origin/ \
    @plugin=webp_transform.so @pparam=max_pixels=9999999999999

# Remap 2 - VALID config (plugin works normally)
map http://site2.com/ http://origin/ \
    @plugin=webp_transform.so @pparam=max_pixels=50000000
```
- ❌ **Impact**: ONLY Remap 1 fails to initialize (isolated failure)
- ✅ **Remap 2**: Works normally (transformations active for site2.com)
- ✅ **Remap 1**: Requests served without transformation (passthrough for site1.com)
- ✅ **Traffic Server**: Continues working normally (both sites accessible)
- ❌ **Client Impact**: Site1.com serves original images (no optimization), Site2.com serves optimized images
- 📝 **Error Log**: `[webp_transform] Config validation failed for remap instance`
- 📊 **Metrics**: Site2.com metrics increment normally, Site1.com metrics remain at 0

**Client Experience on Invalid Config**:
- Browser receives original images (JPEG/PNG/WebP/AVIF unchanged)
- No broken images - 100% uptime maintained
- Transparent fallback to origin format

**Operational Recommendations**:
- Always test config changes in staging environment first
- Use `traffic_ctl config reload` to apply changes (no restart needed)
- Monitor error logs after reload: `tail -f /var/log/trafficserver/error.log | grep webp_transform`
- Verify plugin loaded by checking metrics: `traffic_ctl metric match plugin.webp_transform`
- Set up alerts for all metrics remaining at 0 (indicates plugin failed to load)

### Input Validation
- **MIME Boundary Checking**: Accept header parsing uses strict boundary detection (space/comma/tab) to prevent spoofing like `Accept: comment-image/avif-hacked`
- **Output Validation**: Transformed images validated before sending (non-empty check)
- **Safe Overflow Arithmetic**: Pixel count uses overflow-safe multiplication (prevents `width * height` overflow)

### Exception Safety
- **Granular Handlers**: Separate catch blocks for warnings, errors, codec errors, OOM
- **Safe Fallback**: ALL errors → passthrough original image (no service disruption)
- **OOM Tracking**: Out-of-memory errors tracked separately (`oom_errors_total` metric)

### Monitoring for Attacks
Watch these metrics for anomalies:
- `passthrough_size_bytes` spike → potential DoS attempt (large file flood)
- `oom_errors_total` > 0 → memory exhaustion attack or insufficient resources
- `transform_errors_total` spike → malformed image flood

**Production Recommendations**:
- Set `max_image_size` conservatively (10MB default is safe)
- Set `max_pixels` to prevent extreme images (100MP default is safe)
- Tune `timeout` based on workload: CDN (2-3s), content-heavy (10-15s), internal (20-30s)
- Monitor `oom_errors_total` and alert if > 0

## Performance Characteristics

### Blocking Behavior
- **Synchronous Transformation**: Image processing is **blocking**. Each request waits for the transformation to complete before responding to the client.
- **Timeout Protection**: Operations timeout after `timeout` seconds (default 5s, configurable 1-60s via config parameter) to prevent thread starvation from pathological images.
- **No Concurrent Limit**: The plugin does not limit concurrent transformations per client (relies on ATS connection limits).

### Memory Usage
- **Peak Memory per Request**: Approximately **3x image size**
  - Input buffer (up to `max_image_size`)
  - ImageMagick uncompressed pixels in memory
  - Output blob
- **Example**: A 10MB JPEG may use ~30MB RAM during transformation
- **Tracking**: Monitor `peak_buffer_mb` metric for actual usage patterns across all active transformations
- **Release**: Memory is automatically released after transformation completes (or on error)

### Latency Expectations
- **Small Images** (<1MB): Typically 100-500 milliseconds
- **Medium Images** (1-5MB): Typically 500ms-2 seconds
- **Large Images** (5-10MB): 1-5 seconds depending on server load and CPU
- **Timeout**: Any operation exceeding 5 seconds is aborted (passthrough)

**Factors Affecting Latency**:
- Image complexity (high detail images take longer to encode)
- Server CPU load (busy servers process slower)
- Output format (AVIF encoding typically slower than WebP/JPEG)
- Quality settings (higher quality = more CPU time)

**Recommendation**: For high-traffic sites, ensure adequate RAM (monitor `oom_errors_total`) and CPU cores. Consider reducing `max_image_size` to improve latency.

## Monitoring & Statistics

The plugin exposes several metrics to monitor its operation and security status. You can view these statistics using `traffic_ctl`:

```bash
traffic_ctl metric match plugin.webp_transform
```

### Available Metrics

| Metric Name | Description |
| :--- | :--- |
| `plugin.webp_transform.conversions_webp_total` | Total successful conversions to WebP. |
| `plugin.webp_transform.conversions_jpeg_total` | Total successful conversions to JPEG. |
| `plugin.webp_transform.conversions_avif_total` | Total successful conversions to AVIF. |
| `plugin.webp_transform.transform_errors_total` | Total processing errors encountered. |
| `plugin.webp_transform.passthrough_size_bytes` | Total images passed through due to size limit (DoS protection). |
| `plugin.webp_transform.passthrough_pixels_exceeded` | Total images passed through due to pixel limit (Decompression bomb protection). |
| `plugin.webp_transform.passthrough_invalid_total` | Total images passed through due to invalid or unsupported format. |
| `plugin.webp_transform.oom_errors_total` | **NEW:** Total out-of-memory errors during transformation. Monitor this! |
| `plugin.webp_transform.peak_buffer_mb` | **NEW:** Peak buffer size in MB across all transformations. |
| `plugin.webp_transform.active_transforms` | **NEW:** Current number of active transformations (real-time counter). |

**Note**: Metric names were updated to Prometheus-style convention in February 2026. Old names (`convert_to_webp`, `errors`, etc.) no longer exist.

## Troubleshooting

### Common Configuration Errors

#### "Config validation failed: max_image_size out of range"
**Cause**: Value outside valid range (1KB-100MB)  
**Fix**: Use value between 1024 and 104857600  
**Example**: `@pparam=max_image_size=5242880` (5MB)

#### "Config validation failed: max_pixels out of range"
**Cause**: Value outside valid range (1K-500MP)  
**Fix**: Use value between 1000 and 500000000  
**Example**: `@pparam=max_pixels=50000000` (50MP)

### Runtime Issues

#### High `transform_errors_total` Metric
**Possible Causes**:
- ImageMagick timeout (5s) exceeded on slow/busy servers
- Corrupt or malformed images
- ImageMagick library issues

**Diagnosis**: Enable debug logging to see specific errors

#### High `oom_errors_total` Metric
**Cause**: Server running out of memory during transformation  
**Impact**: Images served as-is (passthrough)  
**Fix**: Reduce `max_pixels` OR increase server RAM  
**Analysis**: Check `peak_buffer_mb` to see memory patterns

#### High `passthrough_invalid_total` Metric
**Cause**: Many unsupported formats (GIF, BMP, TIFF) or corrupt images  
**Impact**: Normal behavior - plugin only handles JPEG/PNG/WebP/AVIF  
**Action**: No fix needed unless unexpectedly high

### Debug Logging

Enable detailed logging in `records.config`:
```bash
CONFIG proxy.config.diags.debug.enabled INT 1
CONFIG proxy.config.diags.debug.tags STRING webp_transform
```

Then monitor `traffic.out`:
```
[webp_transform] Image pixel count exceeds configured limit
[webp_transform] Image processing timeout (5s) - possible DoS attack
[webp_transform] Config validation failed: max_image_size out of range
[webp_transform] Transcoding from type 0 to 2
```

**Note**: Debug messages are sanitized for security. Pixel counts and image dimensions are not logged to prevent information leakage.

## Testing & Verification

We use **AuTest** (Gold Testing System) to verify the plugin's functionality.

### Test Suite
The tests are located in `tests/gold_tests/pluginTest/webp_transform/` with **86 test cases** covering critical code paths.

- `remap_per_map.test.py`: Per-remap configurations and validation
- `quality_settings.test.py`: Quality settings and backward compatibility
- `format_upgrade_fallback.test.py`: Complex transcoding logic (Upgrade/Fallback, PNG support)
- `avif_basic.test.py`: Basic AVIF support
- `params_boolean.test.py`: Boolean parameter parsing and default retention
- `params_validation.test.py`: Plugin stability against invalid configurations
- `dos_protection.test.py`: Security (DoS, decompression bomb, MIME spoofing, Content-Type edge cases)
- `security_audit_fixes.test.py`: Security hardening (pixel boundary, config validation, MIME boundary, Accept wildcards)
- `progressive_jpeg.test.py`: Progressive JPEG generation
- `metadata_stripping.test.py`: Metadata handling (all/icc/none modes)
- `performance_multi_format.test.py`: Multi-format compression benchmarks

### Running Tests
```bash
cd tests

# Option 1: With autest-site (newer AuTest versions)
pipenv run autest run --autest-site ../autest-site --ats-bin /opt/trafficserver/bin -f webp_transform

# Option 2: Legacy syntax (older AuTest versions)
pipenv run autest -D gold_tests --ats-bin /opt/trafficserver/bin -f webp_transform
```
