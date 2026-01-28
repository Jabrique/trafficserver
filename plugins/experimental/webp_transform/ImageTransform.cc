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
#include "tscpp/api/PluginInit.h"
#include "tscpp/api/GlobalPlugin.h"
#include "tscpp/api/TransformationPlugin.h"
#include "tscpp/api/Logger.h"
#include "tscpp/api/Stat.h"

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
GlobalPlugin *plugin;

enum class ImageEncoding { webp, jpeg, png, avif, unknown };

bool config_convert_to_webp = false;
bool config_convert_to_jpeg = false;
bool config_convert_to_avif = false;

Stat stat_convert_to_webp;
Stat stat_convert_to_jpeg;
Stat stat_convert_to_avif;
} // namespace

class ImageTransform : public TransformationPlugin
{
public:
  ImageTransform(Transaction &transaction, ImageEncoding input_image_type, ImageEncoding transform_image_type)
    : TransformationPlugin(transaction, TransformationPlugin::RESPONSE_TRANSFORMATION),
      _input_image_type(input_image_type),
      _transform_image_type(transform_image_type)
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

    TS_DEBUG(TAG, "url %s", transaction.getServerRequest().getUrl().getUrlString().c_str());
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
        image.magick("WEBP");
      } else if (_transform_image_type == ImageEncoding::avif) {
        stat_convert_to_avif.increment(1);
        TSDebug(TAG, "Transforming to AVIF");
        image.magick("AVIF");
      } else {
        stat_convert_to_jpeg.increment(1);
        TSDebug(TAG, "Transforming webp to jpeg");
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
};

class GlobalHookPlugin : public GlobalPlugin
{
public:
  GlobalHookPlugin() { registerHook(HOOK_READ_RESPONSE_HEADERS); }
  void
  handleReadResponseHeaders(Transaction &transaction) override
  {
    // This variable stores the incoming image type
    ImageEncoding input_image_type = ImageEncoding::unknown;

    // This method tries to optimize the amount of string searching at the expense of double checking some of the booleans

    std::string ctype = transaction.getServerResponse().getHeaders().values("Content-Type");

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

      // Logic Matrix: Determine Target Format based on Support and Config
      if (config_convert_to_avif && avif_supported) {
        // Upgrade to AVIF if input is not already AVIF
        if (input_image_type != ImageEncoding::avif) {
          target_type = ImageEncoding::avif;
        }
      } else if (config_convert_to_webp && webp_supported) {
        // Fallback/Upgrade to WebP if AVIF is not an option
        // Prevent degrading AVIF to WebP unless necessary (e.g. browser doesn't support AVIF)
        if (input_image_type != ImageEncoding::webp) {
          target_type = ImageEncoding::webp;
        }
      } else if (config_convert_to_jpeg) {
        // Ultimate Fallback to JPEG for legacy browsers
        // Only if input is modern (WebP/AVIF) and browser supports neither
        if (input_image_type == ImageEncoding::webp || input_image_type == ImageEncoding::avif) {
          target_type = ImageEncoding::jpeg;
        }
      }

      if (target_type != ImageEncoding::unknown) {
        TSDebug(TAG, "Transcoding from type %d to %d", (int)input_image_type, (int)target_type);
        transaction.addPlugin(new ImageTransform(transaction, input_image_type, target_type));
      } else {
        TSDebug(TAG, "Nothing to convert");
      }
    }

    transaction.resume();
  }
};

void
TSPluginInit(int argc, const char *argv[])
{
  if (!RegisterGlobalPlugin("CPP_Webp_Transform", "apache", "dev@trafficserver.apache.org")) {
    return;
  }

  if (argc >= 2) {
    for (int i = 1; i < argc; ++i) {
      std::string option(argv[i]);
      if (option.find("convert_to_webp") != std::string::npos) {
        TSDebug(TAG, "Configured to convert to webp");
        config_convert_to_webp = true;
      }
      if (option.find("convert_to_jpeg") != std::string::npos) {
        TSDebug(TAG, "Configured to convert to jpeg");
        config_convert_to_jpeg = true;
      }
      if (option.find("convert_to_avif") != std::string::npos) {
        TSDebug(TAG, "Configured to convert to avif");
        config_convert_to_avif = true;
      }
    }

    if (config_convert_to_webp == false && config_convert_to_jpeg == false && config_convert_to_avif == false) {
      TSDebug(TAG, "Unknown option: %s", argv[1]);
      TSError("Unknown option: %s", argv[1]);
    }
  } else {
    TSDebug(TAG, "Default configuration is to convert webp, jpeg and avif");
    config_convert_to_webp = true;
    config_convert_to_jpeg = true;
    config_convert_to_avif = true;
  }

  stat_convert_to_webp.init("plugin." TAG ".convert_to_webp", Stat::SYNC_SUM, false);
  stat_convert_to_jpeg.init("plugin." TAG ".convert_to_jpeg", Stat::SYNC_SUM, false);
  stat_convert_to_avif.init("plugin." TAG ".convert_to_avif", Stat::SYNC_SUM, false);

  InitializeMagick("");
  plugin = new GlobalHookPlugin();
}
