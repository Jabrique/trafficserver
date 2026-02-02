/**
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

const int DEFAULT_WEBP_QUALITY = 75;
const int DEFAULT_JPEG_QUALITY = 85;
const int DEFAULT_AVIF_QUALITY = 50;

struct PluginConfig {
  bool convert_to_webp  = true; // Default to TRUE for global/legacy behavior
  bool convert_to_jpeg  = true; // Default to TRUE
  bool convert_to_avif  = true; // Default to TRUE
  bool progressive      = false;
  int webp_quality      = DEFAULT_WEBP_QUALITY;
  int jpeg_quality      = DEFAULT_JPEG_QUALITY;
  int avif_quality      = DEFAULT_AVIF_QUALITY;
  MetadataMode metadata = MetadataMode::all;
};

Stat stat_convert_to_webp;
Stat stat_convert_to_jpeg;
Stat stat_convert_to_avif;

void
parse_config(int argc, const char *argv[], PluginConfig &config)
{
  if (argc > 0) {
    // If arguments are provided, reset defaults to FALSE and only enable what's specified
    config.convert_to_webp = false;
    config.convert_to_jpeg = false;
    config.convert_to_avif = false;

    for (int i = 0; i < argc; ++i) {
      std::string option(argv[i]);
      if (option.find("convert_to_webp") != std::string::npos) {
        TSDebug(TAG, "Configured to convert to webp");
        config.convert_to_webp = true;
      } else if (option.find("convert_to_jpeg") != std::string::npos) {
        TSDebug(TAG, "Configured to convert to jpeg");
        config.convert_to_jpeg = true;
      } else if (option.find("convert_to_avif") != std::string::npos) {
        TSDebug(TAG, "Configured to convert to avif");
        config.convert_to_avif = true;
      } else if (option.find("progressive") != std::string::npos) {
        TSDebug(TAG, "Configured to use progressive rendering");
        config.progressive = true;
      } else if (option.find("metadata=none") != std::string::npos) {
        config.metadata = MetadataMode::none;
        TSDebug(TAG, "Configured metadata mode: none");
      } else if (option.find("metadata=icc") != std::string::npos) {
        config.metadata = MetadataMode::icc;
        TSDebug(TAG, "Configured metadata mode: icc");
      } else if (option.find("metadata=all") != std::string::npos) {
        config.metadata = MetadataMode::all;
        TSDebug(TAG, "Configured metadata mode: all");
      } else if (option.find("webp_quality=") != std::string::npos) {
        int val = std::stoi(option.substr(option.find("=") + 1));
        if (val > 0 && val <= 100) {
          config.webp_quality = val;
          TSDebug(TAG, "Configured webp_quality to %d", val);
        }
      } else if (option.find("jpeg_quality=") != std::string::npos) {
        int val = std::stoi(option.substr(option.find("=") + 1));
        if (val > 0 && val <= 100) {
          config.jpeg_quality = val;
          TSDebug(TAG, "Configured jpeg_quality to %d", val);
        }
      } else if (option.find("avif_quality=") != std::string::npos) {
        int val = std::stoi(option.substr(option.find("=") + 1));
        if (val > 0 && val <= 100) {
          config.avif_quality = val;
          TSDebug(TAG, "Configured avif_quality to %d", val);
        }
      } else {
        TSDebug(TAG, "Unknown option: %s", option.c_str());
      }
    }
  }

  TSDebug(TAG, "Configuration: WebP=%d JPEG=%d AVIF=%d Progressive=%d Metadata=%d", config.convert_to_webp, config.convert_to_jpeg,
          config.convert_to_avif, config.progressive, (int)config.metadata);
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
    _img.write(data.data(), data.length());
  }

  void
  handleInputComplete() override
  {
    std::string input_data = _img.str();
    Blob input_blob(input_data.data(), input_data.length());
    Image image;

    try {
      image.read(input_blob);

      // Handle Metadata Stripping
      if (_config.metadata != MetadataMode::all) {
        Blob icc_profile;

        // 1. Backup ICC profile if needed
        if (_config.metadata == MetadataMode::icc) {
          icc_profile = image.iccColorProfile();
        }

        // 2. Strip everything (EXIF, XMP, IPTC, etc.)
        image.strip();

        // 3. Restore ICC profile
        if (icc_profile.length() > 0) {
          image.iccColorProfile(icc_profile);
        }
      }

      // Handle Interlacing
      if (_config.progressive) {
        image.interlaceType(Magick::PlaneInterlace);
      }

      Blob output_blob;
      if (_transform_image_type == ImageEncoding::webp) {
        stat_convert_to_webp.increment(1);
        TSDebug(TAG, "Transforming to webp");
        image.quality(_config.webp_quality);
        image.magick("WEBP");
      } else if (_transform_image_type == ImageEncoding::avif) {
        stat_convert_to_avif.increment(1);
        TSDebug(TAG, "Transforming to AVIF");
        image.quality(_config.avif_quality);
        image.magick("AVIF");
      } else {
        stat_convert_to_jpeg.increment(1);
        TSDebug(TAG, "Transforming to jpeg");
        image.quality(_config.jpeg_quality);
        image.magick("JPEG");
      }
      image.write(&output_blob);
      produce(std::string_view(reinterpret_cast<const char *>(output_blob.data()), output_blob.length()));
    } catch (Magick::Warning &warning) {
      TSError("ImageMagick++ warning: %s", warning.what());
      produce(std::string_view(reinterpret_cast<const char *>(input_blob.data()), input_blob.length()));
    } catch (Magick::Error &error) {
      TSError("ImageMagick++ error: %s input_data.length(): %zd", error.what(), input_data.length());
      produce(std::string_view(reinterpret_cast<const char *>(input_blob.data()), input_blob.length()));
    }

    setOutputComplete();
  }

  ~ImageTransform() override = default;

private:
  std::stringstream _img;
  ImageEncoding _input_image_type;
  ImageEncoding _transform_image_type;
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

    if (ctype.find("image/jpeg") != std::string::npos) {
      input_image_type = ImageEncoding::jpeg;
    } else if (ctype.find("image/png") != std::string::npos) {
      input_image_type = ImageEncoding::png;
    } else if (ctype.find("image/webp") != std::string::npos) {
      input_image_type = ImageEncoding::webp;
    } else if (ctype.find("image/avif") != std::string::npos) {
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
          // If metadata stripping is requested, re-encode to apply it
          target_type = input_image_type;
        }
      }

      if (target_type != ImageEncoding::unknown) {
        TSDebug(TAG, "Transcoding from type %d to %d", (int)input_image_type, (int)target_type);

        // UPDATE HEADERS HERE
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

  InitializeMagick("");
  new WebpTransformGlobalPlugin(global_config);
}

TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    strncpy(errbuf, "[TSRemapInit] - Invalid TSRemapInterface argument", errbuf_size - 1);
    return TS_ERROR;
  }
  InitializeMagick("");
  TSDebug(TAG, "Remap Plugin Initialized");
  return TS_SUCCESS;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **instance_handle, char *errbuf, int errbuf_size)
{
  TSDebug(TAG, "New Remap Instance");
  PluginConfig *remap_config = new PluginConfig();
  if (argc > 2) {
    parse_config(argc - 2, (const char **)&argv[2], *remap_config);
  }
  new WebpTransformRemapPlugin(instance_handle, *remap_config);
  return TS_SUCCESS;
}