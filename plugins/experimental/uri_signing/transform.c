/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include "transform.h"
#include "manifest.h"
#include "config.h"

#include <ts/ts.h>
#include <string.h>
#include <stdlib.h>

/**
 * Detect manifest type from accumulated content buffer.
 * More reliable than Content-Type headers which may be missing or incorrect.
 *
 * @param data Accumulated content buffer
 * @param size Size of accumulated data
 * @return Detected manifest type (HLS, DASH, or UNKNOWN)
 */
static manifest_type_t
detect_manifest_type_from_content(const char *data, size_t size)
{
  if (!data || size < 10) {
    return MANIFEST_TYPE_UNKNOWN;
  }

  /* HLS: Must start with #EXTM3U */
  if (size >= 7 && strncmp(data, "#EXTM3U", 7) == 0) {
    PluginDebug("Transform: Detected HLS manifest (#EXTM3U)");
    return MANIFEST_TYPE_HLS_M3U8;
  }

  /* DASH: Look for <?xml and MPD in first 500 bytes */
  size_t check_size = (size < 500) ? size : 500;
  if (strncmp(data, "<?xml", 5) == 0 || strncmp(data, "<MPD", 4) == 0) {
    /* Additional check: ensure it contains "MPD" somewhere early */
    for (size_t i = 0; i < check_size - 3; i++) {
      if (strncmp(data + i, "MPD", 3) == 0) {
        PluginDebug("Transform: Detected DASH manifest (XML with MPD)");
        return MANIFEST_TYPE_DASH_MPD;
      }
    }
  }

  return MANIFEST_TYPE_UNKNOWN;
}

static void
cleanup_transform_data(struct transform_data *data)
{
  if (!data) {
    return;
  }

  if (data->output_buffer) {
    TSIOBufferDestroy(data->output_buffer);
  }
  if (data->token) {
    TSfree(data->token);
  }
  if (data->param_name) {
    TSfree(data->param_name);
  }
  if (data->access_token_name) {
    TSfree(data->access_token_name);
  }
  if (data->accumulated_data) {
    TSfree(data->accumulated_data);
  }

  TSfree(data);
}

static void
handle_transform(TSCont contp)
{
  TSVIO write_vio;
  struct transform_data *data;
  int64_t towrite;

  /* Get the write VIO for the write operation that was performed on us */
  write_vio = TSVConnWriteVIOGet(contp);

  /* Get our data structure */
  data = TSContDataGet(contp);
  if (!data) {
    PluginError("Transform: NULL data in handle_transform");
    return;
  }

  /* Initialize output VIO on first call */
  if (!data->output_vio) {
    TSVConn output_vconn;

    /* Create IO buffers */
    data->output_buffer = TSIOBufferCreate();
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);

    /* Use INT64_MAX because we don't know the final output size yet.
     * The transform injects tokens which grows the body beyond the original
     * Content-Length. ATS core interprets INT64_MAX as unknown size, which
     * sets transform_response_cl = UNDEFINED, enabling chunked encoding
     * for HTTP/1.1 and preventing Content-Length mismatch for HTTP/2.
     * The actual size is set via TSVIONBytesSet() after injection completes. */
    output_vconn     = TSTransformOutputVConnGet(contp);
    data->output_vio = TSVConnWrite(output_vconn, contp, data->output_reader, INT64_MAX);

    PluginDebug("Transform: Output VIO initialized");
  }

  /* Check if the upstream VIO is closed */
  if (!TSVIOBufferGet(write_vio)) {
    /* No more data from upstream, process what we have */
    if (data->accumulated_size > 0 && !data->transform_done) {
      PluginDebug("Transform: Processing accumulated manifest (%zu bytes)", data->accumulated_size);

      /* Detect manifest type from content */
      manifest_type_t manifest_type = detect_manifest_type_from_content(data->accumulated_data, data->accumulated_size);

      char *new_manifest = NULL;
      size_t new_len     = 0;

      /* Route to appropriate injection function based on manifest type and config */
      if (manifest_type == MANIFEST_TYPE_HLS_M3U8 && data->token && data->param_name && data->cfg && data->cfg->hls_support) {
        PluginDebug("Transform: Attempting HLS token injection");
        new_manifest = inject_token_hls(data->accumulated_data, data->accumulated_size, data->token, data->param_name,
                                        data->access_token_name, data->cfg, &new_len);
      } else if (manifest_type == MANIFEST_TYPE_DASH_MPD && data->token && data->param_name && data->cfg &&
                 data->cfg->dash_support) {
        PluginDebug("Transform: Attempting DASH token injection");
        new_manifest = inject_token_dash(data->accumulated_data, data->accumulated_size, data->token, data->param_name,
                                         data->access_token_name, data->cfg, &new_len);
      }

      if (new_manifest && new_len > 0) {
        PluginDebug("Transform: Injected tokens, new size = %zu", new_len);
        TSIOBufferWrite(data->output_buffer, new_manifest, new_len);
        free(new_manifest); /* inject_token_hls/dash() use malloc */
      } else {
        /* Injection failed or not manifest, write original */
        if (manifest_type == MANIFEST_TYPE_UNKNOWN) {
          PluginDebug("Transform: Not a manifest, passing through unchanged");
        } else {
          PluginDebug("Transform: Injection not applicable (type=%d, cfg: hls=%d dash=%d), writing original manifest",
                      manifest_type, data->cfg ? data->cfg->hls_support : 0, data->cfg ? data->cfg->dash_support : 0);
        }
        TSIOBufferWrite(data->output_buffer, data->accumulated_data, data->accumulated_size);
      }

      data->transform_done = true;
    }

    /* Set the output VIO to the correct size and reenable */
    TSVIONBytesSet(data->output_vio, TSIOBufferReaderAvail(data->output_reader));
    TSVIOReenable(data->output_vio);
    return;
  }

  /* Determine how much data we have left to read */
  towrite = TSVIONTodoGet(write_vio);
  if (towrite > 0) {
    int64_t avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
    if (towrite > avail) {
      towrite = avail;
    }

    if (towrite > 0) {
      /* Ensure we have capacity in accumulation buffer */
      if (data->accumulated_size + towrite > data->accumulated_capacity) {
        size_t new_capacity = data->accumulated_capacity * 2;
        while (new_capacity < data->accumulated_size + towrite) {
          new_capacity *= 2;
        }
        char *new_buffer = TSmalloc(new_capacity);
        if (!new_buffer) {
          PluginError("Transform: Failed to allocate buffer");
          /* Fall back to passthrough */
          TSIOBufferCopy(data->output_buffer, TSVIOReaderGet(write_vio), towrite, 0);
          TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);
          TSVIONDoneSet(write_vio, TSVIONDoneGet(write_vio) + towrite);
          TSVIOReenable(data->output_vio);
          return;
        }
        if (data->accumulated_data && data->accumulated_size > 0) {
          memcpy(new_buffer, data->accumulated_data, data->accumulated_size);
          TSfree(data->accumulated_data);
        }
        data->accumulated_data     = new_buffer;
        data->accumulated_capacity = new_capacity;
      }

      /* Read data into accumulation buffer */
      TSIOBufferReader reader = TSVIOReaderGet(write_vio);
      TSIOBufferBlock block   = TSIOBufferReaderStart(reader);
      int64_t copied          = 0;

      while (block && copied < towrite) {
        int64_t block_avail;
        const char *block_start = TSIOBufferBlockReadStart(block, reader, &block_avail);
        int64_t to_copy         = (towrite - copied < block_avail) ? (towrite - copied) : block_avail;

        memcpy(data->accumulated_data + data->accumulated_size, block_start, to_copy);
        data->accumulated_size += to_copy;
        copied += to_copy;

        block = TSIOBufferBlockNext(block);
      }

      PluginDebug("Transform: Accumulated %zu bytes total", data->accumulated_size);

      /* Consume the data from input */
      TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);
      TSVIONDoneSet(write_vio, TSVIONDoneGet(write_vio) + towrite);
    }
  }

  /* Check if there's more data to read */
  if (TSVIONTodoGet(write_vio) > 0) {
    if (towrite > 0) {
      /* Re-enable output to let downstream consume data */
      TSVIOReenable(data->output_vio);
      /* Tell upstream we're ready for more data */
      TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
    }
  } else {
    /* No more data to read, process accumulated data */
    if (data->accumulated_size > 0 && !data->transform_done) {
      PluginDebug("Transform: Processing final accumulated manifest (%zu bytes)", data->accumulated_size);

      /* Detect manifest type from content */
      manifest_type_t manifest_type = detect_manifest_type_from_content(data->accumulated_data, data->accumulated_size);

      char *new_manifest = NULL;
      size_t new_len     = 0;

      /* Route to appropriate injection function based on manifest type and config */
      if (manifest_type == MANIFEST_TYPE_HLS_M3U8 && data->token && data->param_name && data->cfg && data->cfg->hls_support) {
        PluginDebug("Transform: Attempting HLS token injection");
        new_manifest = inject_token_hls(data->accumulated_data, data->accumulated_size, data->token, data->param_name,
                                        data->access_token_name, data->cfg, &new_len);
      } else if (manifest_type == MANIFEST_TYPE_DASH_MPD && data->token && data->param_name && data->cfg &&
                 data->cfg->dash_support) {
        PluginDebug("Transform: Attempting DASH token injection");
        new_manifest = inject_token_dash(data->accumulated_data, data->accumulated_size, data->token, data->param_name,
                                         data->access_token_name, data->cfg, &new_len);
      }

      if (new_manifest && new_len > 0) {
        PluginDebug("Transform: Injected tokens, new size = %zu", new_len);
        TSIOBufferWrite(data->output_buffer, new_manifest, new_len);
        free(new_manifest); /* inject_token_hls/dash() use malloc */
      } else {
        /* Injection failed or not manifest, write original */
        if (manifest_type == MANIFEST_TYPE_UNKNOWN) {
          PluginDebug("Transform: Not a manifest, passing through unchanged");
        } else {
          PluginDebug("Transform: Injection not applicable (type=%d, cfg: hls=%d dash=%d), writing original manifest",
                      manifest_type, data->cfg ? data->cfg->hls_support : 0, data->cfg ? data->cfg->dash_support : 0);
        }
        TSIOBufferWrite(data->output_buffer, data->accumulated_data, data->accumulated_size);
      }

      data->transform_done = true;
    }

    /* Set final output size and reenable */
    TSVIONBytesSet(data->output_vio, TSIOBufferReaderAvail(data->output_reader));
    TSVIOReenable(data->output_vio);

    /* Tell upstream we're done */
    TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);
  }
}

static int
manifest_transform_handler(TSCont contp, TSEvent event, void *edata)
{
  /* Check if transformation is closed */
  if (TSVConnClosedGet(contp)) {
    cleanup_transform_data(TSContDataGet(contp));
    TSContDestroy(contp);
    return 0;
  }

  switch (event) {
  case TS_EVENT_ERROR: {
    TSVIO write_vio = TSVConnWriteVIOGet(contp);
    TSContCall(TSVIOContGet(write_vio), TS_EVENT_ERROR, write_vio);
    break;
  }
  case TS_EVENT_VCONN_WRITE_COMPLETE:
    /* Downstream finished reading, shutdown write */
    TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
    break;
  case TS_EVENT_VCONN_WRITE_READY:
  default:
    /* Process more data */
    handle_transform(contp);
    break;
  }

  return 0;
}

/* NOTE: is_manifest_response() removed - it was called at wrong timing (REMAP phase)
 * when server response doesn't exist yet. We now detect manifests from content
 * in is_manifest_content() which is more reliable. */

void
setup_manifest_transform(TSHttpTxn txnp, const char *token, const char *param_name, const char *access_token_name,
                         struct manifest_injection_config *cfg)
{
  if (!token || !param_name || !cfg || !cfg->enabled) {
    PluginDebug("Transform: Not setting up (disabled or missing parameters)");
    return;
  }

  /* NOTE: We no longer check is_manifest_response() here because:
   * 1. TSRemapDoRemap() runs in REMAP phase, BEFORE origin response exists
   * 2. TSHttpTxnServerRespGet() returns empty/NULL at this timing
   * 3. We'll detect manifest type from actual content in handle_transform()
   * This fixes critical bug where transforms were always skipped.
   */

  PluginDebug("Transform: Setting up manifest transform (will detect type from content)");

  /* Allocate transform data */
  struct transform_data *data = TSmalloc(sizeof(struct transform_data));
  if (!data) {
    PluginError("Transform: Failed to allocate transform data");
    return;
  }
  memset(data, 0, sizeof(struct transform_data));

  /* Copy configuration */
  data->token             = TSstrdup(token);
  data->param_name        = TSstrdup(param_name);
  data->access_token_name = access_token_name ? TSstrdup(access_token_name) : NULL;
  data->cfg               = cfg; /* Config lifetime exceeds transaction */

  /* Allocate accumulation buffer (start with 16KB) */
  data->accumulated_capacity = 16384;
  data->accumulated_data     = TSmalloc(data->accumulated_capacity);
  data->accumulated_size     = 0;
  data->is_manifest          = true;
  data->transform_done       = false;

  /* Create transformation continuation */
  TSVConn connp = TSTransformCreate(manifest_transform_handler, txnp);
  if (!connp) {
    PluginError("Transform: Failed to create transform continuation");
    cleanup_transform_data(data);
    return;
  }
  TSContDataSet(connp, data);

  /* Hook the transform into the transaction */
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);

  PluginDebug("Transform: Manifest transform hooked to transaction");
}
