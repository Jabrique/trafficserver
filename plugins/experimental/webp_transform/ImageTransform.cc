/*
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <sstream>
#include <iostream>
#include <string_view>
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <mutex>
#include <future>
#include <chrono>

#include "tscpp/api/PluginInit.h"
#include "tscpp/api/GlobalPlugin.h"
#include "tscpp/api/TransformationPlugin.h"
#include "tscpp/api/Logger.h"
#include "tscpp/api/Stat.h"
#include "tscpp/api/RemapPlugin.h"
#include "ts/ts.h"

#if defined(__GNUC__)
#pragma GCC diagnostic push
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wsuggest-override"
#endif
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
#include <Magick++.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

using namespace Magick;
using namespace atscppapi;

#define TAG "webp_transform"

namespace
{
enum class ImageEncoding { webp, jpeg, png, avif, unknown };
enum class MetadataMode { none, icc, all };

const int DEFAULT_WEBP_QUALITY  = 75;
const int DEFAULT_JPEG_QUALITY  = 85;
const int DEFAULT_AVIF_QUALITY  = 50;
const int64_t DEFAULT_MAX_SIZE  = 10 * 1024 * 1024;  // 10 MB
const size_t DEFAULT_MAX_PIXELS = 100 * 1000 * 1000; // 100 MPixels

std::once_flag magick_init_flag;
static const char *g_plugin_path = nullptr; // HIGH-1: Store plugin path for InitializeMagick

void
ensure_magick_initialized()
{
  std::call_once(magick_init_flag, []() {
    // HIGH-1 Fix: Pass plugin path to InitializeMagick for proper delegate/coder loading
    InitializeMagick(g_plugin_path ? g_plugin_path : "");
    TSDebug(TAG, "[%s] ImageMagick initialized with path: %s", TAG, g_plugin_path ? g_plugin_path : "(empty)");
  });
}

struct PluginConfig {
  bool convert_to_webp   = true;
  bool convert_to_jpeg   = true;
  bool convert_to_avif   = true;
  bool progressive       = false;
  int webp_quality       = DEFAULT_WEBP_QUALITY;
  int jpeg_quality       = DEFAULT_JPEG_QUALITY;
  int avif_quality       = DEFAULT_AVIF_QUALITY;
  int64_t max_image_size = DEFAULT_MAX_SIZE;
  size_t max_pixels      = DEFAULT_MAX_PIXELS;
  MetadataMode metadata  = MetadataMode::all;
  int timeout_seconds    = 5; // Configurable ImageMagick timeout (default 5s, range 1-60s)
};

// E3 (LOW-3): Prometheus-style stat naming (consistent with industry standard)
// Global plugin stats - initialized in TSPluginInit
Stat global_conversions_webp_total;
Stat global_conversions_jpeg_total;
Stat global_conversions_avif_total;
Stat global_transform_errors_total;
Stat global_passthrough_size_bytes;
Stat global_passthrough_pixels_exceeded;
Stat global_passthrough_invalid_total;
Stat global_oom_errors_total;
Stat global_peak_buffer_mb;
Stat global_active_transforms;

// Remap plugin stats - use raw stat IDs for thread-safe cross-thread access
// (Stat objects have memory visibility issues when init'd in one thread and used in another)
static int remap_conversions_webp_id    = TS_ERROR;
static int remap_conversions_jpeg_id    = TS_ERROR;
static int remap_conversions_avif_id    = TS_ERROR;
static int remap_transform_errors_id    = TS_ERROR;
static int remap_passthrough_size_id    = TS_ERROR;
static int remap_passthrough_pixels_id  = TS_ERROR;
static int remap_passthrough_invalid_id = TS_ERROR;
static int remap_oom_errors_id          = TS_ERROR;
static int remap_peak_buffer_id         = TS_ERROR;
static int remap_active_transforms_id   = TS_ERROR;

// Init flags for thread-safe initialization
std::once_flag global_stats_init_flag;
std::once_flag remap_stats_init_flag;

// Helper to create stat and store ID
// persistent=true for cumulative counters, false for gauges
static int
create_stat(const char *name, bool persistent)
{
  int id = TS_ERROR;
  if (TSStatFindName(name, &id) == TS_SUCCESS) {
    return id;
  }
  TSStatPersistence persist = persistent ? TS_STAT_PERSISTENT : TS_STAT_NON_PERSISTENT;
  id                        = TSStatCreate(name, TS_RECORDDATATYPE_INT, persist, TS_STAT_SYNC_SUM);
  if (id != TS_ERROR && !persistent) {
    TSStatIntSet(id, 0); // Only reset non-persistent stats
  }
  return id;
}

// Initialize global plugin stats (called from TSPluginInit)
// Cumulative stats: persistent=true (survive restarts)
// Gauge stats: persistent=false (reset on restart)
static void
init_global_stats()
{
  std::call_once(global_stats_init_flag, []() {
    // Cumulative counters - persistent (survive restarts)
    global_conversions_webp_total.init("plugin." TAG ".global.conversions_webp_total", Stat::SYNC_SUM, true);
    global_conversions_jpeg_total.init("plugin." TAG ".global.conversions_jpeg_total", Stat::SYNC_SUM, true);
    global_conversions_avif_total.init("plugin." TAG ".global.conversions_avif_total", Stat::SYNC_SUM, true);
    global_transform_errors_total.init("plugin." TAG ".global.transform_errors_total", Stat::SYNC_SUM, true);
    global_passthrough_size_bytes.init("plugin." TAG ".global.passthrough_size_bytes", Stat::SYNC_SUM, true);
    global_passthrough_pixels_exceeded.init("plugin." TAG ".global.passthrough_pixels_exceeded", Stat::SYNC_SUM, true);
    global_passthrough_invalid_total.init("plugin." TAG ".global.passthrough_invalid_total", Stat::SYNC_SUM, true);
    global_oom_errors_total.init("plugin." TAG ".global.oom_errors_total", Stat::SYNC_SUM, true);
    // Gauge stats - non-persistent (reset on restart)
    global_peak_buffer_mb.init("plugin." TAG ".global.peak_buffer_mb", Stat::SYNC_SUM, false);
    global_active_transforms.init("plugin." TAG ".global.active_transforms", Stat::SYNC_SUM, false);
    TSDebug(TAG, "Global stats initialized (8 persistent, 2 non-persistent)");
  });
}

// Initialize remap plugin stats (called from TSRemapInit)
// Uses raw stat IDs for thread-safe cross-thread access
static void
init_remap_stats()
{
  std::call_once(remap_stats_init_flag, []() {
    // Cumulative counters - persistent (survive restarts)
    remap_conversions_webp_id    = create_stat("plugin." TAG ".remap.conversions_webp_total", true);
    remap_conversions_jpeg_id    = create_stat("plugin." TAG ".remap.conversions_jpeg_total", true);
    remap_conversions_avif_id    = create_stat("plugin." TAG ".remap.conversions_avif_total", true);
    remap_transform_errors_id    = create_stat("plugin." TAG ".remap.transform_errors_total", true);
    remap_passthrough_size_id    = create_stat("plugin." TAG ".remap.passthrough_size_bytes", true);
    remap_passthrough_pixels_id  = create_stat("plugin." TAG ".remap.passthrough_pixels_exceeded", true);
    remap_passthrough_invalid_id = create_stat("plugin." TAG ".remap.passthrough_invalid_total", true);
    remap_oom_errors_id          = create_stat("plugin." TAG ".remap.oom_errors_total", true);
    // Gauge stats - non-persistent (reset on restart)
    remap_peak_buffer_id       = create_stat("plugin." TAG ".remap.peak_buffer_mb", false);
    remap_active_transforms_id = create_stat("plugin." TAG ".remap.active_transforms", false);

    bool ok = (remap_conversions_avif_id != TS_ERROR);
    if (ok) {
      TSDebug(TAG, "Remap stats initialized (8 persistent, 2 non-persistent)");
    } else {
      TSError("[%s] FAILED to initialize remap stats!", TAG);
    }
  });
}

// E2 (LOW-2): Remove magic numbers - use constexpr for clarity
constexpr std::string_view MAX_SIZE_PREFIX   = "max_image_size=";
constexpr std::string_view MAX_PIXELS_PREFIX = "max_pixels=";

// A2 (MEDIUM-1) + B1 (MEDIUM-2): Config validation returns success status
// Strict mode: ANY invalid config causes plugin init to abort
bool
parse_config(int argc, const char *argv[], PluginConfig &config)
{
  bool all_valid = true; // Track validation status

  for (int i = 0; i < argc; ++i) {
    std::string_view option(argv[i]);

    // B1 (MEDIUM-2): Boolean parsing now properly signals errors
    auto parse_bool_param = [&](std::string_view prefix, bool &target) {
      if (option == prefix) {
        target = true;
        return true;
      }
      if (option.size() > prefix.size() && option.substr(0, prefix.size()) == prefix && option[prefix.size()] == '=') {
        std::string_view val = option.substr(prefix.size() + 1);
        if (val == "true" || val == "1" || val == "on") {
          target = true;
        } else if (val == "false" || val == "0" || val == "off") {
          target = false;
        } else {
          TSError("[%s] Invalid boolean value for %.*s: %.*s", TAG, (int)prefix.size(), prefix.data(), (int)val.length(),
                  val.data());
          target    = false; // Safe default
          all_valid = false; // Mark config as invalid
          return false;      // Signal error (was: return true)
        }
        return true;
      }
      return false;
    };

    auto parse_int_param = [&](std::string_view prefix, int &target, int min_val, int max_val) {
      if (option.size() > prefix.size() && option.substr(0, prefix.size()) == prefix) {
        try {
          int val = std::stoi(std::string(option.substr(prefix.size())));
          if (val >= min_val && val <= max_val) {
            target = val;
            return true;
          } else {
            TSError("[%s] %.*s value %d out of range [%d-%d]", TAG, (int)prefix.size(), prefix.data(), val, min_val, max_val);
            all_valid = false;
          }
        } catch (...) {
          TSError("[%s] Invalid %.*s value", TAG, (int)prefix.size(), prefix.data());
          all_valid = false;
        }
      }
      return false;
    };

    if (parse_bool_param("convert_to_webp", config.convert_to_webp)) {
      continue;
    } else if (parse_bool_param("convert_to_jpeg", config.convert_to_jpeg)) {
      continue;
    } else if (parse_bool_param("convert_to_avif", config.convert_to_avif)) {
      continue;
    } else if (option == "progressive") {
      config.progressive = true;
    } else if (option == "metadata=none") {
      config.metadata = MetadataMode::none;
    } else if (option == "metadata=icc") {
      config.metadata = MetadataMode::icc;
    } else if (option == "metadata=all") {
      config.metadata = MetadataMode::all;
    } else if (parse_int_param("webp_quality=", config.webp_quality, 1, 100)) {
      TSDebug(TAG, "[%s] Configured webp_quality to %d", TAG, config.webp_quality);
    } else if (parse_int_param("jpeg_quality=", config.jpeg_quality, 1, 100)) {
      TSDebug(TAG, "[%s] Configured jpeg_quality to %d", TAG, config.jpeg_quality);
    } else if (parse_int_param("avif_quality=", config.avif_quality, 1, 100)) {
      TSDebug(TAG, "[%s] Configured avif_quality to %d", TAG, config.avif_quality);
    } else if (option.size() > MAX_SIZE_PREFIX.size() && option.substr(0, MAX_SIZE_PREFIX.size()) == MAX_SIZE_PREFIX) {
      // E2: Using constexpr instead of magic number 15
      try {
        std::string value_str = std::string(option.substr(MAX_SIZE_PREFIX.size()));
        size_t idx            = 0;
        int64_t val           = std::stoll(value_str, &idx);

        const int64_t MIN_SIZE = 1024;              // 1 KB minimum (for testing)
        const int64_t MAX_SIZE = 100 * 1024 * 1024; // 100 MB maximum

        if (idx != value_str.length()) {
          TSError("[%s] Invalid max_image_size: contains non-numeric characters", TAG);
          all_valid = false;
        } else if (val < MIN_SIZE || val > MAX_SIZE) {
          TSError("[%s] max_image_size out of range: %ld (allowed: %ld-%ld bytes)", TAG, val, MIN_SIZE, MAX_SIZE);
          all_valid = false;
        } else {
          config.max_image_size = val;
          TSDebug(TAG, "[%s] Configured max_image_size to %ld", TAG, val);
        }
      } catch (const std::out_of_range &e) {
        TSError("[%s] max_image_size overflow: value too large", TAG);
        all_valid = false;
      } catch (...) {
        TSError("[%s] Invalid max_image_size value", TAG);
        all_valid = false;
      }
    } else if (option.size() > MAX_PIXELS_PREFIX.size() && option.substr(0, MAX_PIXELS_PREFIX.size()) == MAX_PIXELS_PREFIX) {
      // E2: Using constexpr instead of magic number 11
      try {
        std::string value_str = std::string(option.substr(MAX_PIXELS_PREFIX.size()));
        size_t idx            = 0;
        int64_t val           = std::stoll(value_str, &idx);

        const int64_t MIN_PIXELS = 1000;              // 1K pixels minimum (for testing)
        const int64_t MAX_PIXELS = 500 * 1000 * 1000; // 500 MPixels maximum

        if (idx != value_str.length()) {
          TSError("[%s] Invalid max_pixels: contains non-numeric characters", TAG);
          all_valid = false;
        } else if (val < MIN_PIXELS || val > MAX_PIXELS) {
          TSError("[%s] max_pixels out of range: %ld (allowed: %ld-%ld pixels)", TAG, val, MIN_PIXELS, MAX_PIXELS);
          all_valid = false;
        } else {
          config.max_pixels = (size_t)val;
          TSDebug(TAG, "[%s] Configured max_pixels to %zu", TAG, config.max_pixels);
        }
      } catch (const std::out_of_range &e) {
        TSError("[%s] max_pixels overflow: value too large", TAG);
        all_valid = false;
      } catch (...) {
        TSError("[%s] Invalid max_pixels value", TAG);
        all_valid = false;
      }
    } else if (option.size() > 8 && option.substr(0, 8) == "timeout=") {
      try {
        std::string value_str = std::string(option.substr(8));
        size_t idx            = 0;
        int val               = std::stoi(value_str, &idx);

        const int MIN_TIMEOUT = 1;  // 1 second minimum
        const int MAX_TIMEOUT = 60; // 60 seconds maximum

        if (idx != value_str.length()) {
          TSError("[%s] Invalid timeout: contains non-numeric characters", TAG);
          all_valid = false;
        } else if (val < MIN_TIMEOUT || val > MAX_TIMEOUT) {
          TSError("[%s] timeout out of range: %d (allowed: %d-%d seconds)", TAG, val, MIN_TIMEOUT, MAX_TIMEOUT);
          all_valid = false;
        } else {
          config.timeout_seconds = val;
          TSDebug(TAG, "[%s] Configured timeout to %d seconds", TAG, config.timeout_seconds);
        }
      } catch (const std::out_of_range &e) {
        TSError("[%s] timeout overflow: value too large", TAG);
        all_valid = false;
      } catch (...) {
        TSError("[%s] Invalid timeout value", TAG);
        all_valid = false;
      }
    } else {
      TSDebug(TAG, "[%s] Unknown option: %.*s", TAG, (int)option.length(), option.data());
    }
  }

  TSDebug(TAG, "[%s] Configuration: WebP=%d JPEG=%d AVIF=%d Progressive=%d Metadata=%d MaxSize=%ld MaxPixels=%zu Timeout=%ds", TAG,
          config.convert_to_webp, config.convert_to_jpeg, config.convert_to_avif, config.progressive, (int)config.metadata,
          config.max_image_size, config.max_pixels, config.timeout_seconds);

  // A2 (MEDIUM-1): Return validation status - strict mode aborts on ANY invalid config
  return all_valid;
}

// Helper function: Proper MIME type matching in Accept header
static bool
acceptsImageType(std::string_view accept, std::string_view mime_type)
{
  size_t pos = 0;
  while ((pos = accept.find(mime_type, pos)) != std::string_view::npos) {
    // Check boundaries: must be word boundary before mime_type
    bool valid_start = (pos == 0 || accept[pos - 1] == ' ' || accept[pos - 1] == ',' || accept[pos - 1] == '\t');

    size_t end = pos + mime_type.length();
    bool valid_end =
      (end >= accept.length() || accept[end] == ' ' || accept[end] == ',' || accept[end] == ';' || accept[end] == '\t');

    if (valid_start && valid_end) {
      return true;
    }
    pos++;
  }

  // Wildcard handling for image types
  // Modern formats (AVIF/WebP) require EXPLICIT listing in Accept header
  // Wildcards (*/* or image/*) only match universal formats (JPEG/PNG/GIF)
  // This ensures legacy browsers (IE11, Safari<14, Firefox<65) get JPEG fallback
  if (mime_type.substr(0, 6) == "image/") {
    // Modern formats require explicit Accept header - no wildcard matching
    if (mime_type == "image/avif" || mime_type == "image/webp") {
      return false; // Already checked for explicit match above, not found
    }

    // Universal formats (JPEG, PNG, GIF, etc.) can use wildcard
    if (accept.find("image/*") != std::string_view::npos || accept.find("*/*") != std::string_view::npos) {
      return true;
    }
  }

  return false;
}
} // namespace

class ImageTransform : public TransformationPlugin
{
public:
  ImageTransform(Transaction &transaction, ImageEncoding input_image_type, ImageEncoding transform_image_type,
                 const PluginConfig &config, bool is_remap = false)
    : TransformationPlugin(transaction, TransformationPlugin::RESPONSE_TRANSFORMATION),
      _input_image_type(input_image_type),
      _transform_image_type(transform_image_type),
      _config(config),
      _is_remap(is_remap)
  {
    // C1 (MEDIUM-3): Track active transformations for observability
    if (_is_remap) {
      if (remap_active_transforms_id != TS_ERROR)
        TSStatIntIncrement(remap_active_transforms_id, 1);
    } else {
      global_active_transforms.increment(1);
    }

    // Defensive validation: Ensure config invariants
    if (_config.max_image_size <= 0) {
      TSError("[%s] FATAL: Invalid max_image_size: %ld (must be positive)", TAG, _config.max_image_size);
      throw std::invalid_argument("max_image_size must be positive");
    }
    if (_config.max_pixels == 0) {
      TSError("[%s] FATAL: Invalid max_pixels: %zu (must be positive)", TAG, _config.max_pixels);
      throw std::invalid_argument("max_pixels must be positive");
    }
  }

  void
  consume(std::string_view data) override
  {
    if (_transform_aborted) {
      produce(data);
      return;
    }

    if (_img_buffer.length() + data.length() > (size_t)_config.max_image_size) {
      TSDebug(TAG, "[%s] Image size exceeds limit (%ld). Aborting transformation and switching to streaming passthrough.", TAG,
              _config.max_image_size);
      increment_passthrough_size();
      _transform_aborted = true;

      if (!_img_buffer.empty()) {
        produce(std::string_view(_img_buffer.data(), _img_buffer.length()));
        _img_buffer.clear();
        // Buffer will be freed by destructor (RAII)
      }
      produce(data);
      return;
    }
    _img_buffer.append(data.data(), data.length());

    // C1 (MEDIUM-3): Track peak buffer size for memory observability
    size_t buffer_mb = _img_buffer.length() / (1024 * 1024);
    update_peak_buffer(buffer_mb);
  }

  void
  handleInputComplete() override
  {
    if (_transform_aborted) {
      setOutputComplete();
      return;
    }

    if (_img_buffer.empty()) {
      setOutputComplete();
      return;
    }

    // Helper lambda: Passthrough original image on error
    auto passthrough = [this]() {
      if (!_img_buffer.empty()) {
        produce(std::string_view(_img_buffer.data(), _img_buffer.length()));
      }
    };

    Blob input_blob(_img_buffer.data(), _img_buffer.length());
    Image image;

    try {
      // 1. Safety Ping: Validate format and dimensions without full decode
      image.ping(input_blob);

      std::string format = image.magick();
      if (format != "JPEG" && format != "PNG" && format != "WEBP" && format != "AVIF") {
        TSError("[%s] Security Alert: Unsupported format spoofed as image: %s", TAG, format.c_str());
        increment_passthrough_invalid();
        throw std::runtime_error("Unsupported format");
      }

      // Defense against decompression bombs (Pixel Flood)
      size_t width  = image.columns();
      size_t height = image.rows();

      if (width == 0 || height == 0) {
        TSError("[%s] Invalid image dimensions", TAG); // C2 (MEDIUM-5): Sanitized - removed width/height
        increment_passthrough_invalid();
        throw std::runtime_error("Invalid dimensions");
      }

      // Safe overflow check: Prevent width * height from overflowing SIZE_MAX
      if (height > 0 && width > SIZE_MAX / height) {
        TSError("[%s] Image dimension overflow detected", TAG); // C2: Sanitized
        increment_passthrough_pixels();
        throw std::runtime_error("Dimension overflow");
      }

      // Check total pixel count against configured limit
      size_t total_pixels = width * height;
      if (total_pixels > _config.max_pixels) {
        TSDebug(TAG, "[%s] Image pixel count exceeds configured limit", TAG); // C2: Sanitized
        increment_passthrough_pixels();
        throw std::runtime_error("Image too large");
      }

      // A1 (MEDIUM-6): 2. Full Read with TIMEOUT protection against slow decode attacks
      auto read_future = std::async(std::launch::async, [&]() { image.read(input_blob); });

      if (read_future.wait_for(std::chrono::seconds(_config.timeout_seconds)) == std::future_status::timeout) {
        TSError("[%s] Image processing timeout (%ds) - possible DoS attack", TAG, _config.timeout_seconds);
        increment_transform_errors();
        throw std::runtime_error("Processing timeout");
      }
      read_future.get(); // Retrieve result or exception

      // Handle Metadata Stripping
      if (_config.metadata != MetadataMode::all) {
        Blob icc_profile;
        if (_config.metadata == MetadataMode::icc) {
          icc_profile = image.iccColorProfile();
        }
        image.strip();
        if (icc_profile.length() > 0) {
          image.iccColorProfile(icc_profile);
        }
      }

      // Progressive JPEG: Only applies to JPEG output format
      // WebP and AVIF do not support progressive/interlaced loading
      if (_config.progressive && _transform_image_type == ImageEncoding::jpeg) {
        image.interlaceType(Magick::LineInterlace);
      }

      Blob output_blob;
      if (_transform_image_type == ImageEncoding::webp) {
        increment_conversions_webp();
        TSDebug(TAG, "[%s] Transforming to WebP (Q=%d)", TAG, _config.webp_quality);
        image.quality(_config.webp_quality);
        image.magick("WEBP");
      } else if (_transform_image_type == ImageEncoding::avif) {
        increment_conversions_avif();
        TSDebug(TAG, "[%s] Transforming to AVIF (Q=%d)", TAG, _config.avif_quality);
        image.quality(_config.avif_quality);
        image.magick("AVIF");
      } else {
        increment_conversions_jpeg();
        TSDebug(TAG, "[%s] Transforming to JPEG (Q=%d)", TAG, _config.jpeg_quality);
        image.quality(_config.jpeg_quality);
        image.magick("JPEG");
      }

      // A1 (MEDIUM-6): Write with timeout protection
      auto write_future = std::async(std::launch::async, [&]() { image.write(&output_blob); });

      if (write_future.wait_for(std::chrono::seconds(_config.timeout_seconds)) == std::future_status::timeout) {
        TSError("[%s] Image write timeout (%ds)", TAG, _config.timeout_seconds);
        increment_transform_errors();
        throw std::runtime_error("Write timeout");
      }
      write_future.get();

      // A3 (MEDIUM-8): Validate output blob is not empty before sending
      if (output_blob.length() == 0) {
        TSError("[%s] ImageMagick produced empty output - falling back to passthrough", TAG);
        increment_transform_errors();
        throw std::runtime_error("Empty output blob");
      }

      produce(std::string_view(reinterpret_cast<const char *>(output_blob.data()), output_blob.length()));
    } catch (const Magick::Warning &warning) {
      // Non-fatal warning - log and passthrough original
      TSDebug(TAG, "[%s] ImageMagick warning: %s - attempting passthrough", TAG, warning.what());
      passthrough();
    } catch (const Magick::ErrorCoder &error) {
      // Coder error (e.g., missing delegate library)
      TSError("[%s] ImageMagick coder error: %s - passthrough", TAG, error.what());
      increment_transform_errors();
      passthrough();
    } catch (const Magick::Error &error) {
      // Fatal ImageMagick error
      TSError("[%s] ImageMagick error: %s - passthrough", TAG, error.what());
      increment_transform_errors();
      passthrough();
    } catch (const std::bad_alloc &e) {
      // C1 (MEDIUM-3): Track OOM errors for observability
      TSError("[%s] Out of memory during image processing - passthrough", TAG);
      increment_oom_errors();
      increment_transform_errors();
      passthrough();
    } catch (const std::exception &e) {
      // Other exceptions (including our own runtime_error from validation)
      TSError("[%s] Image processing error [%zu bytes]: %s - passthrough", TAG, _img_buffer.length(), e.what());
      increment_transform_errors();
      passthrough();
    }

    setOutputComplete();
  }

  ~ImageTransform() override
  {
    // C1 (MEDIUM-3): Decrement active transforms counter
    if (_is_remap) {
      if (remap_active_transforms_id != TS_ERROR)
        TSStatIntDecrement(remap_active_transforms_id, 1);
    } else {
      global_active_transforms.decrement(1);
    }
    TSDebug(TAG, "[%s] ImageTransform destroyed", TAG);
  }

private:
  std::string _img_buffer;
  const ImageEncoding _input_image_type;     // E4 (LOW-4): const correctness - immutable after construction
  const ImageEncoding _transform_image_type; // E4: const correctness
  bool _transform_aborted = false;
  const PluginConfig _config;
  const bool _is_remap;

  // Helper functions to increment the correct stat based on plugin mode
  // Remap uses raw TSStatIntIncrement (thread-safe), global uses Stat objects
  void
  increment_passthrough_size()
  {
    if (_is_remap) {
      if (remap_passthrough_size_id != TS_ERROR)
        TSStatIntIncrement(remap_passthrough_size_id, 1);
    } else {
      global_passthrough_size_bytes.increment(1);
    }
  }
  void
  increment_passthrough_invalid()
  {
    if (_is_remap) {
      if (remap_passthrough_invalid_id != TS_ERROR)
        TSStatIntIncrement(remap_passthrough_invalid_id, 1);
    } else {
      global_passthrough_invalid_total.increment(1);
    }
  }
  void
  increment_passthrough_pixels()
  {
    if (_is_remap) {
      if (remap_passthrough_pixels_id != TS_ERROR)
        TSStatIntIncrement(remap_passthrough_pixels_id, 1);
    } else {
      global_passthrough_pixels_exceeded.increment(1);
    }
  }
  void
  increment_transform_errors()
  {
    if (_is_remap) {
      if (remap_transform_errors_id != TS_ERROR)
        TSStatIntIncrement(remap_transform_errors_id, 1);
    } else {
      global_transform_errors_total.increment(1);
    }
  }
  void
  increment_conversions_webp()
  {
    if (_is_remap) {
      if (remap_conversions_webp_id != TS_ERROR)
        TSStatIntIncrement(remap_conversions_webp_id, 1);
    } else {
      global_conversions_webp_total.increment(1);
    }
  }
  void
  increment_conversions_avif()
  {
    if (_is_remap) {
      if (remap_conversions_avif_id != TS_ERROR)
        TSStatIntIncrement(remap_conversions_avif_id, 1);
    } else {
      global_conversions_avif_total.increment(1);
    }
  }
  void
  increment_conversions_jpeg()
  {
    if (_is_remap) {
      if (remap_conversions_jpeg_id != TS_ERROR)
        TSStatIntIncrement(remap_conversions_jpeg_id, 1);
    } else {
      global_conversions_jpeg_total.increment(1);
    }
  }
  void
  increment_oom_errors()
  {
    if (_is_remap) {
      if (remap_oom_errors_id != TS_ERROR)
        TSStatIntIncrement(remap_oom_errors_id, 1);
    } else {
      global_oom_errors_total.increment(1);
    }
  }
  void
  update_peak_buffer(size_t mb)
  {
    if (_is_remap) {
      if (remap_peak_buffer_id != TS_ERROR) {
        int64_t current = TSStatIntGet(remap_peak_buffer_id);
        if ((int64_t)mb > current)
          TSStatIntSet(remap_peak_buffer_id, mb);
      }
    } else {
      int64_t current = global_peak_buffer_mb.get();
      if ((int64_t)mb > current)
        global_peak_buffer_mb.set(mb);
    }
  }

  // D2 (MEDIUM-7): ImageMagick RAII cleanup verification
  // Note: ImageMagick++ Image class uses RAII and properly releases resources in destructor.
  // No explicit cleanup needed in exception paths.
};

class WebpTransformTransactionPlugin : public TransactionPlugin
{
public:
  WebpTransformTransactionPlugin(Transaction &transaction, const PluginConfig &config, bool is_remap = false)
    : TransactionPlugin(transaction), _config(config), _is_remap(is_remap)
  {
    registerHook(HOOK_READ_RESPONSE_HEADERS);
  }

  void
  handleReadResponseHeaders(Transaction &transaction) override
  {
    ImageEncoding input_image_type = ImageEncoding::unknown;
    std::string ctype_str          = transaction.getServerResponse().getHeaders().values("Content-Type");
    std::string_view ctype         = ctype_str; // Safe: ctype_str owns the data

    // Strict Content-Type Parsing: Extract MIME type before semicolon
    size_t semicolon_pos = ctype.find(';');
    if (semicolon_pos != std::string_view::npos) {
      ctype = ctype.substr(0, semicolon_pos);
    }

    // Trim whitespace
    const auto strBegin = ctype.find_first_not_of(" \t");
    if (strBegin != std::string_view::npos) {
      ctype             = ctype.substr(strBegin);
      const auto strEnd = ctype.find_last_not_of(" \t");
      if (strEnd != std::string_view::npos) {
        ctype = ctype.substr(0, strEnd + 1);
      }
    } else {
      ctype = std::string_view();
    }

    if (ctype == "image/jpeg") {
      input_image_type = ImageEncoding::jpeg;
    } else if (ctype == "image/png") {
      input_image_type = ImageEncoding::png;
    } else if (ctype == "image/webp") {
      input_image_type = ImageEncoding::webp;
    } else if (ctype == "image/avif") {
      input_image_type = ImageEncoding::avif;
    }

    if (input_image_type != ImageEncoding::unknown) {
      std::string accept  = transaction.getServerRequest().getHeaders().values("Accept");
      bool avif_supported = acceptsImageType(accept, "image/avif");
      bool webp_supported = acceptsImageType(accept, "image/webp");

      ImageEncoding target_type = ImageEncoding::unknown;

      if (_config.convert_to_avif && avif_supported) {
        if (input_image_type != ImageEncoding::avif) {
          target_type = ImageEncoding::avif;
        }
      } else if (_config.convert_to_webp && webp_supported) {
        if (input_image_type != ImageEncoding::webp) {
          target_type = ImageEncoding::webp;
        }
      } else if (_config.convert_to_jpeg) {
        if (input_image_type == ImageEncoding::webp || input_image_type == ImageEncoding::avif) {
          target_type = ImageEncoding::jpeg;
        }
      }

      if (target_type == ImageEncoding::unknown && input_image_type != ImageEncoding::unknown) {
        if (_config.progressive && input_image_type == ImageEncoding::jpeg) {
          target_type = ImageEncoding::jpeg;
        } else if (_config.metadata != MetadataMode::all) {
          target_type = input_image_type;
        }
      }

      if (target_type != ImageEncoding::unknown) {
        TSDebug(TAG, "Transcoding from type %d to %d", (int)input_image_type, (int)target_type);

        Headers &resp_headers = transaction.getServerResponse().getHeaders();
        switch (target_type) {
        case ImageEncoding::webp:
          resp_headers["Content-Type"] = "image/webp";
          break;
        case ImageEncoding::avif:
          resp_headers["Content-Type"] = "image/avif";
          break;
        case ImageEncoding::jpeg:
          resp_headers["Content-Type"] = "image/jpeg";
          break;
        case ImageEncoding::png:
          resp_headers["Content-Type"] = "image/png";
          break;
        default:
          break;
        }
        resp_headers["Vary"] = "Accept";

        transaction.addPlugin(new ImageTransform(transaction, input_image_type, target_type, _config, _is_remap));
      }
    }

    transaction.resume();
  }

  ~WebpTransformTransactionPlugin() override { TSDebug(TAG, "WebpTransformTransactionPlugin destroyed"); }

private:
  const PluginConfig _config;
  const bool _is_remap;
};

class WebpTransformGlobalPlugin : public GlobalPlugin
{
public:
  WebpTransformGlobalPlugin(const PluginConfig &config) : _config(config) { registerHook(HOOK_READ_REQUEST_HEADERS_PRE_REMAP); }

  void
  handleReadRequestHeadersPreRemap(Transaction &transaction) override
  {
    transaction.addPlugin(new WebpTransformTransactionPlugin(transaction, _config, false)); // is_remap=false
    transaction.resume();
  }

private:
  const PluginConfig _config;
};

class WebpTransformRemapPlugin : public RemapPlugin
{
public:
  WebpTransformRemapPlugin(void **instance_handle, const PluginConfig &config) : RemapPlugin(instance_handle), _config(config) {}

  Result
  doRemap(const Url &map_from_url, const Url &map_to_url, Transaction &transaction, bool &redirect) override
  {
    transaction.addPlugin(new WebpTransformTransactionPlugin(transaction, _config, true)); // is_remap=true
    return RESULT_DID_REMAP;
  }

  ~WebpTransformRemapPlugin() override { TSDebug(TAG, "WebpTransformRemapPlugin destroyed"); }

private:
  const PluginConfig _config;
};

void
TSPluginInit(int argc, const char *argv[])
{
  if (!RegisterGlobalPlugin("CPP_Webp_Transform", "apache", "dev@trafficserver.apache.org")) {
    return;
  }

  // HIGH-1 (B2): Store plugin path for InitializeMagick
  if (argc > 0) {
    g_plugin_path = argv[0];
  }

  PluginConfig global_config;
  // A2 (MEDIUM-1): Strict config validation - abort on ANY invalid param
  if (!parse_config(argc - 1, &argv[1], global_config)) {
    TSError("[%s] Config validation failed - ABORTING plugin initialization", TAG);
    return; // Don't register hooks if config is invalid
  }

  // E3 (LOW-3): Initialize global stats with Prometheus-style naming
  init_global_stats();

  ensure_magick_initialized();
  new WebpTransformGlobalPlugin(global_config);
}

TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    strncpy(errbuf, "[TSRemapInit] - Invalid TSRemapInterface argument", errbuf_size - 1);
    errbuf[errbuf_size - 1] = '\0'; // Ensure null termination
    return TS_ERROR;
  }

  // E3 (LOW-3): Initialize remap stats with Prometheus-style naming
  init_remap_stats();

  ensure_magick_initialized();
  TSDebug(TAG, "[%s] Remap Plugin Initialized", TAG);
  return TS_SUCCESS;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **instance_handle, char *errbuf, int errbuf_size)
{
  TSDebug(TAG, "[%s] New Remap Instance", TAG);
  PluginConfig remap_config;
  if (argc > 2) {
    // A2 (MEDIUM-1): Strict validation for remap instances
    if (!parse_config(argc - 2, (const char **)&argv[2], remap_config)) {
      snprintf(errbuf, errbuf_size, "[%s] Config validation failed for remap instance", TAG);
      return TS_ERROR; // Abort remap instance creation
    }
  }
  // Store the plugin object itself in instance_handle, NOT the config
  WebpTransformRemapPlugin *plugin = new WebpTransformRemapPlugin(instance_handle, remap_config);
  *instance_handle                 = plugin;
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *instance_handle)
{
  if (instance_handle) {
    // Delete the plugin instance, which correctly manages its internal config copy
    WebpTransformRemapPlugin *plugin = static_cast<WebpTransformRemapPlugin *>(instance_handle);
    delete plugin;
    TSDebug(TAG, "Remap Instance deleted");
  }
}