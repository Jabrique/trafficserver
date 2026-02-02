# WebP & AVIF Transform Plugin

This plugin serves as a Universal Image Transcoder, automatically converting images (JPEG, PNG, WebP, AVIF) into the most efficient format supported by the user's browser (AVIF or WebP), or falling back to JPEG for legacy compatibility.

It supports both **Global** and **Per-Remap** configurations.

## Key Features

1.  **Bandwidth Savings:** Converts massive JPEG/PNG images to tiny AVIF/WebP.
2.  **Modernization:** Automatically upgrades legacy WebP content to AVIF.
3.  **Compatibility:** Automatically downgrades modern AVIF content to WebP or JPEG for older browsers.
4.  **Adjustable Quality:** Fine-tune the compression level per format.
5.  **Progressive Rendering:** Support for Progressive JPEG to improve perceived load speed.

### Internal Benchmark Results (120KB JPEG Source)
- **Original JPEG:** 120 KB
- **WebP (Q=75):** 40 KB (~66% savings)
- **AVIF (Q=50):** 15 KB (~87% savings)
- **AVIF (Q=10):** 1.7 KB (Maximum compression)

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
# Basic activation
webp_transform.so convert_to_avif convert_to_webp convert_to_jpeg

# High performance with custom quality and progressive enabled
webp_transform.so convert_to_avif convert_to_webp progressive avif_quality=40 webp_quality=60
```

### 2. Per-Remap Configuration
Add the plugin to specific rules in `remap.config` using `@pparam`:

```
# High quality photography site
map http://photo.com/ http://origin/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=avif_quality=90

# High performance for thumbnails
map http://img.com/thumbs/ http://origin/ @plugin=webp_transform.so @pparam=convert_to_avif @pparam=progressive @pparam=avif_quality=20
```

### Configuration Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `convert_to_avif` | Enables upgrade to AVIF. | On |
| `convert_to_webp` | Enables upgrade/fallback to WebP. | On |
| `convert_to_jpeg` | Enables fallback to JPEG. | On |
| `progressive` | Enables Progressive JPEG rendering. | Off |
| `avif_quality=N` | Set AVIF quality (1-100). | 50 |
| `webp_quality=N` | Set WebP quality (1-100). | 75 |
| `jpeg_quality=N` | Set JPEG quality (1-100). | 85 |

## How It Works

The plugin uses a smart logic matrix to determine the best output format:

1.  **Detection:** Plugin checks the browser's `Accept` header.
2.  **Selection:**
    - If `image/avif` supported -> Targets **AVIF**.
    - If not, but `image/webp` supported -> Targets **WebP**.
    - If neither supported -> Targets **JPEG** (if input was modern).
3.  **Transformation Logic (Self-Transformation):**
    - The plugin only re-encodes if the **Format Changes** (e.g., JPEG to AVIF).
    - **Exception:** If `progressive` is enabled, the plugin will force a re-encoding even if the format remains the same (e.g., JPEG to Progressive JPEG), applying the configured quality in the process.

## Testing & Verification

We use **AuTest** (Gold Testing System) to verify the plugin's functionality.

### Test Suite
The tests are located in `tests/gold_tests/pluginTest/webp_transform/`.

- `webp_transform_progressive.test.py`: Verifies Progressive JPEG generation.
- `webp_transform_remap.test.py`: Verifies per-remap configurations.
- `webp_transform_quality.test.py`: Verifies quality settings and defaults.
- `webp_transform_advanced.test.py`: Verifies complex transcoding logic.
- `webp_transform_avif.test.py`: Verifies basic AVIF support.

### Running Tests
```bash
cd tests
pipenv run autest -D gold_tests --ats-bin /opt/trafficserver/bin -f webp_transform
```

### Viewing Benchmark Results
Run the benchmark test with `-C none` and check `tests/_sandbox/webp_transform_benchmark/` for generated files.
