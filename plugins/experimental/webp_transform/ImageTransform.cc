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

#include "tscpp/api/PluginInit.h"
#include "tscpp/api/GlobalPlugin.h"
#include "tscpp/api/TransformationPlugin.h"
#include "tscpp/api/Logger.h"
#include "tscpp/api/Stat.h"
#include "tscpp/api/RemapPlugin.h"

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

void
ensure_magick_initialized()
{
  std::call_once(magick_init_flag, []() {
    InitializeMagick("");
    TSDebug(TAG, "ImageMagick initialized");
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
};

Stat stat_convert_to_webp;
Stat stat_convert_to_jpeg;
Stat stat_convert_to_avif;
Stat stat_transform_errors;
Stat stat_passthrough_size;
Stat stat_passthrough_pixels;
Stat stat_passthrough_invalid;

void
parse_config(int argc, const char *argv[], PluginConfig &config)
{
  for (int i = 0; i < argc; ++i) {
    std::string_view option(argv[i]);

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
          }
        } catch (...) {
          TSError("[%s] Invalid %.*s value", TAG, (int)prefix.size(), prefix.data());
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
      TSDebug(TAG, "Configured webp_quality to %d", config.webp_quality);
    } else if (parse_int_param("jpeg_quality=", config.jpeg_quality, 1, 100)) {
      TSDebug(TAG, "Configured jpeg_quality to %d", config.jpeg_quality);
    } else if (parse_int_param("avif_quality=", config.avif_quality, 1, 100)) {
      TSDebug(TAG, "Configured avif_quality to %d", config.avif_quality);
    } else if (option.size() > 15 && option.substr(0, 15) == "max_image_size=") {
      try {
        int64_t val = std::stoll(std::string(option.substr(15)));
        if (val > 0) {
          config.max_image_size = val;
          TSDebug(TAG, "Configured max_image_size to %ld", val);
        }
      } catch (...) {
        TSError("[%s] Invalid max_image_size value", TAG);
      }
    } else if (option.size() > 11 && option.substr(0, 11) == "max_pixels=") {
      try {
        int64_t val = std::stoll(std::string(option.substr(11)));
        if (val > 0) {
          config.max_pixels = (size_t)val;
          TSDebug(TAG, "Configured max_pixels to %zu", config.max_pixels);
        }
      } catch (...) {
        TSError("[%s] Invalid max_pixels value", TAG);
      }
    } else {
      TSDebug(TAG, "Unknown option: %.*s", (int)option.length(), option.data());
    }
  }

  TSDebug(TAG, "Configuration: WebP=%d JPEG=%d AVIF=%d Progressive=%d Metadata=%d MaxSize=%ld MaxPixels=%zu",
          config.convert_to_webp, config.convert_to_jpeg, config.convert_to_avif, config.progressive, (int)config.metadata,
          config.max_image_size, config.max_pixels);
}
} // namespace

class ImageTransform : public TransformationPlugin
{
public:
  ImageTransform(Transaction &transaction, ImageEncoding input_image_type, ImageEncoding transform_image_type,
                 const PluginConfig &config)
    : TransformationPlugin(transaction, TransformationPlugin::RESPONSE_TRANSFORMATION),
      _input_image_type(input_image_type),
      _transform_image_type(transform_image_type),
      _config(config)
  {
  }

  void
  consume(std::string_view data) override
  {
    if (_transform_aborted) {
      produce(data);
      return;
    }

    if (_img_buffer.length() + data.length() > (size_t)_config.max_image_size) {
      TSDebug(TAG, "Image size exceeds limit (%ld). Aborting transformation and switching to streaming passthrough.",
              _config.max_image_size);
      stat_passthrough_size.increment(1);
      _transform_aborted = true;

      if (!_img_buffer.empty()) {
        produce(std::string_view(_img_buffer.data(), _img_buffer.length()));
        _img_buffer.clear();
        _img_buffer.shrink_to_fit();
      }
      produce(data);
      return;
    }
    _img_buffer.append(data.data(), data.length());
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

    Blob input_blob(_img_buffer.data(), _img_buffer.length());
    Image image;

    try {
      // 1. Safety Ping: Validate format and dimensions without full decode
      image.ping(input_blob);

      std::string format = image.magick();
      if (format != "JPEG" && format != "PNG" && format != "WEBP" && format != "AVIF") {
        TSError("[%s] Security Alert: Unsupported format spoofed as image: %s", TAG, format.c_str());
        stat_passthrough_invalid.increment(1);
        throw std::runtime_error("Unsupported format");
      }

      // Defense against decompression bombs (Pixel Flood)
      size_t width  = image.columns();
      size_t height = image.rows();

      if (width == 0 || height == 0) {
        TSError("[%s] Invalid image dimensions: %zux%zu", TAG, width, height);
        stat_passthrough_invalid.increment(1);
        throw std::runtime_error("Invalid dimensions");
      }

      // Safe overflow check for pixel count
      if (width > _config.max_pixels / height) {
        TSError("[%s] Image dimensions too large: %zux%zu (max=%zu pixels)", TAG, width, height, _config.max_pixels);
        stat_passthrough_pixels.increment(1);
        throw std::runtime_error("Image too large");
      }

      // 2. Full Read
      image.read(input_blob);

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

      if (_config.progressive) {
        image.interlaceType(Magick::PlaneInterlace);
      }

      Blob output_blob;
      if (_transform_image_type == ImageEncoding::webp) {
        stat_convert_to_webp.increment(1);
        TSDebug(TAG, "Transforming to WebP (Q=%d)", _config.webp_quality);
        image.quality(_config.webp_quality);
        image.magick("WEBP");
      } else if (_transform_image_type == ImageEncoding::avif) {
        stat_convert_to_avif.increment(1);
        TSDebug(TAG, "Transforming to AVIF (Q=%d)", _config.avif_quality);
        image.quality(_config.avif_quality);
        image.magick("AVIF");
      } else {
        stat_convert_to_jpeg.increment(1);
        TSDebug(TAG, "Transforming to JPEG (Q=%d)", _config.jpeg_quality);
        image.quality(_config.jpeg_quality);
        image.magick("JPEG");
      }
      image.write(&output_blob);
      produce(std::string_view(reinterpret_cast<const char *>(output_blob.data()), output_blob.length()));
    } catch (const std::exception &e) {
      TSError("[%s] Image processing error [%zu bytes]: %s. Falling back to passthrough.", TAG, _img_buffer.length(), e.what());
      stat_transform_errors.increment(1);
      if (!_img_buffer.empty()) {
        produce(std::string_view(_img_buffer.data(), _img_buffer.length()));
      }
    }

    setOutputComplete();
  }

  ~ImageTransform() override { TSDebug(TAG, "ImageTransform destroyed"); }

private:
  std::string _img_buffer;
  ImageEncoding _input_image_type;
  ImageEncoding _transform_image_type;
  bool _transform_aborted = false;
  const PluginConfig _config;
};

class WebpTransformTransactionPlugin : public TransactionPlugin
{
public:
  WebpTransformTransactionPlugin(Transaction &transaction, const PluginConfig &config)
    : TransactionPlugin(transaction), _config(config)
  {
    registerHook(HOOK_READ_RESPONSE_HEADERS);
  }

  void
  handleReadResponseHeaders(Transaction &transaction) override
  {
    ImageEncoding input_image_type = ImageEncoding::unknown;
    std::string ctype              = transaction.getServerResponse().getHeaders().values("Content-Type");

    // Strict Content-Type Parsing
    size_t semicolon_pos = ctype.find(';');
    if (semicolon_pos != std::string::npos) {
      ctype = ctype.substr(0, semicolon_pos);
    }
    // Trim whitespace
    const auto strBegin = ctype.find_first_not_of(" \t");
    if (strBegin == std::string::npos) {
      ctype = "";
    } else {
      const auto strEnd = ctype.find_last_not_of(" \t");
      ctype             = ctype.substr(strBegin, strEnd - strBegin + 1);
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
      bool avif_supported = accept.find("image/avif") != std::string::npos;
      bool webp_supported = accept.find("image/webp") != std::string::npos;

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

        transaction.addPlugin(new ImageTransform(transaction, input_image_type, target_type, _config));
      }
    }

    transaction.resume();
  }

  ~WebpTransformTransactionPlugin() override { TSDebug(TAG, "WebpTransformTransactionPlugin destroyed"); }

private:
  const PluginConfig _config;
};

class WebpTransformGlobalPlugin : public GlobalPlugin
{
public:
  WebpTransformGlobalPlugin(const PluginConfig &config) : _config(config) { registerHook(HOOK_READ_REQUEST_HEADERS_PRE_REMAP); }

  void
  handleReadRequestHeadersPreRemap(Transaction &transaction) override
  {
    transaction.addPlugin(new WebpTransformTransactionPlugin(transaction, _config));
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
    transaction.addPlugin(new WebpTransformTransactionPlugin(transaction, _config));
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

  PluginConfig global_config;
  parse_config(argc - 1, &argv[1], global_config);

  stat_convert_to_webp.init("plugin." TAG ".convert_to_webp", Stat::SYNC_SUM, false);
  stat_convert_to_jpeg.init("plugin." TAG ".convert_to_jpeg", Stat::SYNC_SUM, false);
  stat_convert_to_avif.init("plugin." TAG ".convert_to_avif", Stat::SYNC_SUM, false);
  stat_transform_errors.init("plugin." TAG ".errors", Stat::SYNC_SUM, false);
  stat_passthrough_size.init("plugin." TAG ".passthrough_size", Stat::SYNC_SUM, false);
  stat_passthrough_pixels.init("plugin." TAG ".passthrough_pixels", Stat::SYNC_SUM, false);
  stat_passthrough_invalid.init("plugin." TAG ".passthrough_invalid", Stat::SYNC_SUM, false);

  ensure_magick_initialized();
  new WebpTransformGlobalPlugin(global_config);
}

TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    strncpy(errbuf, "[TSRemapInit] - Invalid TSRemapInterface argument", errbuf_size - 1);
    return TS_ERROR;
  }
  ensure_magick_initialized();
  TSDebug(TAG, "Remap Plugin Initialized");
  return TS_SUCCESS;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **instance_handle, char *errbuf, int errbuf_size)
{
  TSDebug(TAG, "New Remap Instance");
  PluginConfig remap_config;
  if (argc > 2) {
    parse_config(argc - 2, (const char **)&argv[2], remap_config);
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