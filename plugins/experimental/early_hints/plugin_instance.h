/** @file
 * Plugin instance data for the early_hints plugin.
 *
 * @section license License
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "config.h"
#include "hints_cache.h"

// Plugin instance data stored in TSCont — owns config and cache.
struct PluginInstance {
  EarlyHintsConfig *config = nullptr;
  HintsCache *cache        = nullptr;

  ~PluginInstance()
  {
    delete config;
    delete cache;
  }

  // Noncopyable — prevent accidental double-free
  PluginInstance()                       = default;
  PluginInstance(const PluginInstance &) = delete;
  PluginInstance &operator=(const PluginInstance &) = delete;
};
