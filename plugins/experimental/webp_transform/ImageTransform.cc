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

const int DEFAULT_WEBP_QUALITY = 75;
const int DEFAULT_JPEG_QUALITY = 85;
const int DEFAULT_AVIF_QUALITY = 50;

struct PluginConfig {
  bool convert_to_webp = false;
  bool convert_to_jpeg = false;
  bool convert_to_avif = false;
  int webp_quality     = DEFAULT_WEBP_QUALITY;
  int jpeg_quality     = DEFAULT_JPEG_QUALITY;
  int avif_quality     = DEFAULT_AVIF_QUALITY;
};

Stat stat_convert_to_webp;
Stat stat_convert_to_jpeg;
Stat stat_convert_to_avif;

void
parse_config(int argc, const char *argv[], PluginConfig &config)
{
  if (argc >= 1) {
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
  } else {
    TSDebug(TAG, "Default configuration is to convert webp, jpeg and avif");
    config.convert_to_webp = true;
    config.convert_to_jpeg = true;
    config.convert_to_avif = true;
  }
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
    TransformationPlugin::registerHook(HOOK_READ_RESPONSE_HEADERS);
  }

  void
  handleReadResponseHeaders(Transaction &transaction) override
  {
    switch (_transform_image_type) {
    case ImageEncoding::webp:
      transaction.getServerResponse().getHeaders()["Content-Type"] = "image/webp";
      break;
    case ImageEncoding::avif:
      transaction.getServerResponse().getHeaders()["Content-Type"] = "image/avif";
      break;
    case ImageEncoding::jpeg:
      transaction.getServerResponse().getHeaders()["Content-Type"] = "image/jpeg";
      break;
    case ImageEncoding::png:
      transaction.getServerResponse().getHeaders()["Content-Type"] = "image/png";
      break;
    case ImageEncoding::unknown:
      // do nothing
      break;
    }

    transaction.getServerResponse().getHeaders()["Vary"] = "Accept"; // to have a separate cache entry

    TSDebug(TAG, "url %s", transaction.getServerRequest().getUrl().getUrlString().c_str());
    transaction.resume();
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

      Blob output_blob;
      if (_transform_image_type == ImageEncoding::webp) {
        stat_convert_to_webp.increment(1);
        TSDebug(TAG, "Transforming jpeg or png to webp");
        image.quality(_config.webp_quality);
        image.magick("WEBP");
      } else if (_transform_image_type == ImageEncoding::avif) {
        stat_convert_to_avif.increment(1);
        TSDebug(TAG, "Transforming to AVIF");
        image.quality(_config.avif_quality);
        image.magick("AVIF");
      } else {
        stat_convert_to_jpeg.increment(1);
        TSDebug(TAG, "Transforming webp to jpeg");
        image.quality(_config.jpeg_quality);
        image.magick("JPEG");
      }
      image.write(&output_blob);
      produce(std::string_view(reinterpret_cast<const char *>(output_blob.data()), output_blob.length()));
    } catch (Magick::Warning &warning) {
      TSError("ImageMagick++ warning: %s", warning.what());
      produce(std::string_view(reinterpret_cast<const char *>(input_blob.data()), input_blob.length()));
      _transform_image_type = _input_image_type; // Revert to original encoding on error
    } catch (Magick::Error &error) {
      TSError("ImageMagick++ error: %s _image_type: %d input_data.length(): %zd", error.what(), (int)_transform_image_type,
              input_data.length());
      produce(std::string_view(reinterpret_cast<const char *>(input_blob.data()), input_blob.length()));
      _transform_image_type = _input_image_type; // Revert to original encoding on error
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

/**
 * TransactionPlugin to handle detection and attachment of TransformationPlugin
 */
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

    bool input_is_jpeg = ctype.find("image/jpeg") != std::string::npos;
    bool input_is_png  = ctype.find("image/png") != std::string::npos;
    bool input_is_webp = ctype.find("image/webp") != std::string::npos;
    bool input_is_avif = ctype.find("image/avif") != std::string::npos;

    if (input_is_jpeg) {
      input_image_type = ImageEncoding::jpeg;
    } else if (input_is_png) {
      input_image_type = ImageEncoding::png;
    } else if (input_is_webp) {
      input_image_type = ImageEncoding::webp;
    } else if (input_is_avif) {
      input_image_type = ImageEncoding::avif;
    }

    TSDebug(TAG, "Content-Type: %s input_image_type: %d", ctype.c_str(), (int)input_image_type);

    if (input_image_type != ImageEncoding::unknown) {
      std::string accept  = transaction.getServerRequest().getHeaders().values("Accept");
      bool avif_supported = accept.find("image/avif") != std::string::npos;
      bool webp_supported = accept.find("image/webp") != std::string::npos;

      TSDebug(TAG, "Accept: %s avif: %d webp: %d", accept.c_str(), avif_supported, webp_supported);

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

      if (target_type != ImageEncoding::unknown) {
        TSDebug(TAG, "Transcoding from type %d to %d", (int)input_image_type, (int)target_type);
        transaction.addPlugin(new ImageTransform(transaction, input_image_type, target_type, _config));
      } else {
        TSDebug(TAG, "Nothing to convert");
      }
    }

    transaction.resume();
  }

private:
  const PluginConfig _config;
};

/**
 * GlobalPlugin to attach TransactionPlugin to all transactions
 */
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

/**
 * RemapPlugin to attach TransactionPlugin to specific remap rules
 */
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
TSRemapNewInstance(int argc, char *argv[], void **instance_handle, char *errbuf, int errbuf_size)
{
  TSDebug(TAG, "New Remap Instance");
  PluginConfig *remap_config = new PluginConfig();
  // argv[0] is from_url, argv[1] is to_url, params start from argv[2]
  if (argc > 2) {
    parse_config(argc - 2, (const char **)&argv[2], *remap_config);
  } else {
    // Default for remap if no params provided
    remap_config->convert_to_webp = true;
    remap_config->convert_to_jpeg = true;
    remap_config->convert_to_avif = true;
  }

  new WebpTransformRemapPlugin(instance_handle, *remap_config);
  return TS_SUCCESS;
}