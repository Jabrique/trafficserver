# WebP & AVIF Transform Plugin

This plugin serves as a Universal Image Transcoder, automatically converting images (JPEG, PNG, WebP, AVIF) into the most efficient format supported by the user's browser (AVIF or WebP), or falling back to JPEG for legacy compatibility.

## Why Use This Plugin?

1.  **Bandwidth Savings:** Converts massive JPEG/PNG images to tiny AVIF/WebP.
2.  **Modernization:** Automatically upgrades legacy WebP content to AVIF.
3.  **Compatibility:** Automatically downgrades modern AVIF content to WebP or JPEG for older browsers.

### Internal Benchmark Results

**Scenario 1: Complex Fractal Image (120KB JPEG)**
- **Original JPEG:** 120 KB
- **WebP:** 74 KB (~38% savings)
- **AVIF:** 15 KB (~87% savings)

**Scenario 2: Traffic Control Logo (115KB PNG)**
- **Original PNG:** 115 KB
- **WebP:** 64 KB (~44% savings)
- **AVIF:** 27 KB (~76% savings)

*Note: Results achieved using default plugin quality settings (WebP=75, AVIF=50).*

## System Prerequisites

For AVIF conversion to work, your server must have **ImageMagick 7** installed and compiled with **libheif** support.

### Checking Server Support
Run this command in your terminal:
```bash
magick -list format | grep -E "AVIF|HEIC"
```
You should see output similar to `AVIF  HEIC  rw+`.

**Installation Guide (Rocky Linux 9 / RHEL 9):**
```bash
sudo dnf install https://rpms.remirepo.net/enterprise/remi-release-9.rpm
sudo dnf --enablerepo=remi install ImageMagick7 ImageMagick7-heic ImageMagick7-c++-devel
```

## Configuration

Add the following line to your Apache Traffic Server `plugin.config` file:

```
# Enable full universal transcoding (AVIF > WebP > JPEG)
webp_transform.so convert_to_avif convert_to_webp convert_to_jpeg
```

### Configuration Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `convert_to_avif` | Enables upgrade to AVIF. | On |
| `convert_to_webp` | Enables upgrade/fallback to WebP. | On |
| `convert_to_jpeg` | Enables fallback to JPEG. | On |
| `avif_quality=N` | Set AVIF quality (1-100). | 50 |
| `webp_quality=N` | Set WebP quality (1-100). | 75 |
| `jpeg_quality=N` | Set JPEG quality (1-100). | 85 |

## How It Works

The plugin uses a smart logic matrix to determine the best output format:

| Input Format | Browser Support | Output Format | Reason |
| :--- | :--- | :--- | :--- |
| **JPEG / PNG** | AVIF | **AVIF** | Maximum Optimization |
| **JPEG / PNG** | WebP (No AVIF) | **WebP** | Optimization |
| **WebP** | AVIF | **AVIF** | Upgrade |
| **WebP** | No WebP/AVIF | **JPEG** | Fallback (Legacy Support) |
| **AVIF** | WebP (No AVIF) | **WebP** | Compatibility Fallback |
| **AVIF** | No WebP/AVIF | **JPEG** | Compatibility Fallback |

## Troubleshooting

**Q: My images are not converting.**
A: Check if the browser sends the correct `Accept` header. Check `diags.log` for any `ImageMagick++ error`.

**Q: Do I need `convert_to_jpeg`?**
A: Only if your Origin Server serves WebP or AVIF images and you have users with very old browsers (e.g., IE11) that don't support them.

## Testing & Verification

We use **AuTest** (Gold Testing System) to verify the plugin's functionality.

### Test Files Location
The tests are located in `tests/gold_tests/pluginTest/webp_transform/`.

- `webp_transform_avif.test.py`: Verifies basic JPEG to AVIF conversion.
- `webp_transform_advanced.test.py`: Verifies complex transcoding logic (WebP->AVIF, AVIF->WebP, Fallbacks).
- `webp_transform_benchmark.test.py`: Performs real transcoding on sample images and verifies file size reduction.
- `webp_transform_quality.test.py`: Verifies quality configuration settings.

### How to Run Tests
From the root of the Traffic Server repository:

```bash
cd tests
# Setup Python environment (first time only)
pipenv install

# Run all webp_transform tests
# Note: Adjust --ats-bin to your traffic_server binary location (e.g., /opt/trafficserver/bin)
pipenv run autest -D gold_tests --ats-bin /opt/trafficserver/bin -f webp_transform
```

### Viewing Benchmark Results
To see the actual file size reduction achieved during the benchmark:

1.  Run the benchmark test with the `-C none` flag to prevent AuTest from deleting the output files:
    ```bash
    pipenv run autest -D gold_tests --ats-bin /opt/trafficserver/bin -f webp_transform_benchmark -C none
    ```
2.  Navigate to the test sandbox directory:
    ```bash
    cd tests/_sandbox/webp_transform_benchmark/
    ```
3.  Check the file sizes:
    ```bash
    ls -lh out_fractal.* out_logo.*
    ```

### Understanding Output

- **PASSED**: The test logic executed correctly, headers were modified as expected, and the transcoding process completed without errors.
- **FAILED**: Check the `Reason` in the output. Common failures include:
    - `File differences`: The response header did not match the expected `Content-Type`.
    - `ReturnCode`: The server process crashed or exited unexpectedly.
    - `Diags log ... contains errors`: ImageMagick failed to decode/encode the image (often due to missing libraries in the OS).

### Manual Verification
You can also manually verify using `curl` against a running Traffic Server:

```bash
# Check if server returns AVIF
curl -v -o test.avif --header "Accept: image/avif" http://localhost:8080/image.jpg

# Check the response header
< Content-Type: image/avif
```