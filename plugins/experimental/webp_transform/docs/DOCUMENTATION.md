# WebP & AVIF Transform Plugin

This plugin serves as a Universal Image Transcoder, automatically converting images (JPEG, PNG, WebP, AVIF) into the most efficient format supported by the user's browser (AVIF or WebP), or falling back to JPEG for legacy compatibility.

It supports both **Global** and **Per-Remap** configurations.

## Key Features

1.  **Bandwidth Savings:** Converts massive JPEG/PNG images to tiny AVIF/WebP.
2.  **Modernization:** Automatically upgrades legacy WebP content to AVIF.
3.  **Compatibility:** Automatically downgrades modern AVIF content to WebP or JPEG for older browsers.
4.  **Adjustable Quality:** Fine-tune the compression level per format.
5.  **Progressive Rendering:** Support for Progressive JPEG to improve perceived load speed.
6.  **Metadata Stripping:** Granular control over EXIF/IPTC/XMP removal for privacy and size optimization.

### Internal Benchmark Results (120KB JPEG Source)
- **Original JPEG:** 120 KB
- **WebP (Q=75):** 40 KB (~66% savings)
- **AVIF (Q=50):** 15 KB (~87% savings)
- **Metadata Stripping:** Up to 30KB+ additional savings per image.

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
| `max_image_size=N` | Max image size in bytes before aborting (DoS Protection). | 10MB |
| `max_pixels=N` | Max total pixels (width x height) to process (Bomb Protection). | 100MP |
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
    - If neither supported -> Targets **JPEG** (if input was modern).
3.  **Transformation Logic (Self-Transformation):**
    - The plugin normally **only** re-encodes if the Format Changes (e.g. JPEG -> AVIF).
    - **Exception:** If `progressive` is enabled OR `metadata` is set to `none`/`icc`, the plugin will force a re-encoding even if the format matches (e.g. JPEG -> Progressive JPEG), applying the configured quality and stripping logic in the process.
4.  **Header Sync:** The plugin automatically updates the `Content-Type` and adds `Vary: Accept` to ensure correct caching.

## Monitoring & Statistics

The plugin exposes several metrics to monitor its operation and security status. You can view these statistics using `traffic_ctl`:

```bash
traffic_ctl metric match plugin.webp_transform
```

### Available Metrics

| Metric Name | Description |
| :--- | :--- |
| `plugin.webp_transform.convert_to_webp` | Total successful conversions to WebP. |
| `plugin.webp_transform.convert_to_jpeg` | Total successful conversions to JPEG. |
| `plugin.webp_transform.convert_to_avif` | Total successful conversions to AVIF. |
| `plugin.webp_transform.errors` | Total processing errors encountered. |
| `plugin.webp_transform.passthrough_size` | Total images passed through due to size limit (DoS protection). |
| `plugin.webp_transform.passthrough_pixels` | Total images passed through due to pixel limit (Decompression bomb protection). |
| `plugin.webp_transform.passthrough_invalid` | Total images passed through due to invalid or unsupported format. |

## Testing & Verification

We use **AuTest** (Gold Testing System) to verify the plugin's functionality.

### Test Suite
The tests are located in `tests/gold_tests/pluginTest/webp_transform/`.

- `webp_transform_remap.test.py`: Verifies per-remap configurations.
- `webp_transform_quality.test.py`: Verifies quality settings and backward compatibility.
- `webp_transform_advanced.test.py`: Verifies complex transcoding logic (Upgrade/Fallback).
- `webp_transform_avif.test.py`: Verifies basic AVIF support.
- `webp_transform_config_boolean.test.py`: Verifies boolean parameter parsing and default retention.
- `webp_transform_config_robustness.test.py`: Verifies plugin stability against invalid configurations.
- `webp_transform_edge_cases.test.py`: Verifies security features (DoS protection, decompression bomb, MIME spoofing).

### Running Tests
```bash
cd tests
pipenv run autest -D gold_tests --ats-bin /opt/trafficserver/bin -f webp_transform
```
