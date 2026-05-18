/** @file
 * ATS API mocks and Catch2 main for transform event handler tests.
 *
 * Provides mock implementations of all ATS API functions used by early_hints.cc,
 * with controllable state for test assertions.
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

#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <ts/ts.h>
#include <ts/remap.h>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <pthread.h>

// ─── Mock control state (accessible from test_transform.cc) ─────────────────

void *mock_cont_data                     = nullptr;
int mock_vconn_closed                    = 0;
int mock_mutex_destroy_count             = 0;
TSReturnCode mock_user_arg_reserve_rc    = TS_SUCCESS;
void *mock_user_arg_set_value            = nullptr;
int mock_hook_add_count                  = 0;
TSHttpStatus mock_txn_status             = static_cast<TSHttpStatus>(200);
void *mock_output_vconn                  = nullptr;
void *mock_input_vio                     = nullptr;
int mock_vconn_shutdown_called           = 0;
int mock_cont_call_count                 = 0;
int mock_transform_do_vio_reenable_count = 0;
int mock_cont_destroy_count              = 0;
int mock_iobuffer_destroy_count          = 0;

// Configurable return values for VIO mocks
void *mock_vio_buffer       = nullptr; // TSVIOBufferGet return
int64_t mock_vio_ntodo      = 0;       // TSVIONTodoGet return
void *mock_vio_reader       = nullptr; // TSVIOReaderGet return
int64_t mock_reader_avail   = 0;       // TSIOBufferReaderAvail return
int64_t mock_vio_ndone      = 0;       // TSVIONDoneGet return/accumulator
int64_t mock_vio_nbytes_set = -1;      // last value passed to TSVIONBytesSet

// Computed NTodoGet mode: when enabled, NTodoGet returns nbytes_total - ndone
// (mirrors real ATS behavior where NTodo = nbytes - ndone)
bool mock_vio_ntodo_use_computed = false;
int64_t mock_vio_nbytes_total    = 0; // total bytes for computed mode

// Configurable block data for scanner feed testing
const char *mock_block_data = nullptr;
int64_t mock_block_data_len = 0;

// Configurable TSIOBufferCopy return: -1 means default (return nbytes)
int64_t mock_iobuffer_copy_return = -1;
// Track bytes consumed from reader
int64_t mock_reader_consumed = 0;

// Configurable TSHttpTxnSendEarlyHints return code and call tracking
TSReturnCode mock_send_early_hints_rc = TS_SUCCESS;
int mock_send_early_hints_count       = 0;
int mock_send_early_hints_last_nlinks = 0;

// --- Field append tracking (R11) ---
int mock_field_append_count = 0;

// ─── ATS API Mock Implementations ──────────────────────────────────────────

extern "C" {

// --- Memory management ---

void *
_TSmalloc(size_t size, const char * /* path */)
{
  return malloc(size);
}

void *
_TSrealloc(void *ptr, size_t size, const char * /* path */)
{
  return realloc(ptr, size);
}

char *
_TSstrdup(const char *str, int64_t length, const char * /* path */)
{
  if (!str) {
    return nullptr;
  }
  if (length < 0) {
    length = strlen(str);
  }
  char *result = static_cast<char *>(malloc(length + 1));
  memcpy(result, str, length);
  result[length] = '\0';
  return result;
}

void
_TSfree(void *ptr)
{
  free(ptr);
}

// --- Logging ---

void
TSDebug(const char * /* tag */, const char * /* fmt */, ...)
{
}

void
TSError(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  std::vfprintf(stderr, fmt, args);
  va_end(args);
  std::fprintf(stderr, "\n");
}

// --- Statistics ---

int
TSStatCreate(const char * /* name */, TSRecordDataType /* type */, TSStatPersistence /* persist */, TSStatSync /* sync */)
{
  static int counter = 0;
  return counter++;
}

void
TSStatIntIncrement(int /* id */, int64_t /* amount */)
{
}

// --- Mutex ---

TSMutex
TSMutexCreate()
{
  pthread_mutex_t *m = static_cast<pthread_mutex_t *>(malloc(sizeof(pthread_mutex_t)));
  pthread_mutex_init(m, nullptr);
  return reinterpret_cast<TSMutex>(m);
}

void
TSMutexLock(TSMutex mutexp)
{
  pthread_mutex_lock(reinterpret_cast<pthread_mutex_t *>(mutexp));
}

void
TSMutexUnlock(TSMutex mutexp)
{
  pthread_mutex_unlock(reinterpret_cast<pthread_mutex_t *>(mutexp));
}

void
TSMutexDestroy(TSMutex mutexp)
{
  pthread_mutex_destroy(reinterpret_cast<pthread_mutex_t *>(mutexp));
  free(reinterpret_cast<void *>(mutexp));
  mock_mutex_destroy_count++;
}

// --- Continuation ---

void *TSContDataGet(TSCont /* contp */)
{
  return mock_cont_data;
}

void
TSContDataSet(TSCont /* contp */, void *data)
{
  mock_cont_data = data;
}

TSCont TSContCreate(TSEventFunc /* handler */, TSMutex /* mutexp */)
{
  return reinterpret_cast<TSCont>(0x1234);
}

void TSContDestroy(TSCont /* contp */)
{
  mock_cont_destroy_count++;
}

int
TSContCall(TSCont /* contp */, TSEvent /* event */, void * /* edata */)
{
  mock_cont_call_count++;
  return 0;
}

// --- VConnection ---

int TSVConnClosedGet(TSVConn /* connp */)
{
  return mock_vconn_closed;
}

TSVIO
TSVConnWriteVIOGet(TSVConn /* connp */)
{
  return static_cast<TSVIO>(mock_input_vio);
}

TSVConn TSTransformOutputVConnGet(TSVConn /* connp */)
{
  return static_cast<TSVConn>(mock_output_vconn);
}

TSVIO
TSVConnWrite(TSVConn /* connp */, TSCont /* contp */, TSIOBufferReader /* readerp */, int64_t /* nbytes */)
{
  return reinterpret_cast<TSVIO>(0x5678);
}

void
TSVConnShutdown(TSVConn /* connp */, int /* read */, int /* write */)
{
  mock_vconn_shutdown_called++;
}

TSVConn TSTransformCreate(TSEventFunc /* event_funcp */, TSHttpTxn /* txnp */)
{
  return reinterpret_cast<TSVConn>(0x9ABC);
}

// --- VIO ---

TSCont TSVIOContGet(TSVIO /* viop */)
{
  return reinterpret_cast<TSCont>(0xAAAA);
}

int64_t TSVIONBytesGet(TSVIO /* viop */)
{
  return 0;
}

int64_t TSVIONDoneGet(TSVIO /* viop */)
{
  return mock_vio_ndone;
}

int64_t TSVIONTodoGet(TSVIO /* viop */)
{
  if (mock_vio_ntodo_use_computed) {
    int64_t todo = mock_vio_nbytes_total - mock_vio_ndone;
    return todo > 0 ? todo : 0;
  }
  return mock_vio_ntodo;
}

void
TSVIONBytesSet(TSVIO /* viop */, int64_t nbytes)
{
  mock_vio_nbytes_set = nbytes;
}

void
TSVIONDoneSet(TSVIO /* viop */, int64_t ndone)
{
  mock_vio_ndone = ndone;
}

void TSVIOReenable(TSVIO /* viop */)
{
  mock_transform_do_vio_reenable_count++;
}

TSIOBuffer TSVIOBufferGet(TSVIO /* viop */)
{
  return static_cast<TSIOBuffer>(mock_vio_buffer);
}

TSIOBufferReader TSVIOReaderGet(TSVIO /* viop */)
{
  return static_cast<TSIOBufferReader>(mock_vio_reader);
}

// --- IO Buffer ---

TSIOBuffer
TSIOBufferCreate()
{
  return reinterpret_cast<TSIOBuffer>(malloc(1));
}

void
TSIOBufferDestroy(TSIOBuffer bufp)
{
  mock_iobuffer_destroy_count++;
  free(bufp);
}

TSIOBufferReader TSIOBufferReaderAlloc(TSIOBuffer /* bufp */)
{
  return reinterpret_cast<TSIOBufferReader>(0xBBBB);
}

void TSIOBufferReaderFree(TSIOBufferReader /* readerp */) {}

int64_t
TSIOBufferCopy(TSIOBuffer /* bufp */, TSIOBufferReader /* readerp */, int64_t nbytes, int64_t /* offset */)
{
  if (mock_iobuffer_copy_return == -1) {
    return nbytes; // default: success
  }
  if (mock_iobuffer_copy_return < 0) {
    return mock_iobuffer_copy_return; // negative error codes returned as-is
  }
  return std::min(mock_iobuffer_copy_return, nbytes);
}

int64_t TSIOBufferReaderAvail(TSIOBufferReader /* readerp */)
{
  return mock_reader_avail;
}

void
TSIOBufferReaderConsume(TSIOBufferReader /* readerp */, int64_t nbytes)
{
  mock_reader_consumed += nbytes;
}

TSIOBufferBlock TSIOBufferReaderStart(TSIOBufferReader /* readerp */)
{
  // Return a non-null sentinel if mock_block_data is set (single-block simulation)
  if (mock_block_data && mock_block_data_len > 0) {
    return reinterpret_cast<TSIOBufferBlock>(0xF00D);
  }
  return nullptr;
}

TSIOBufferBlock TSIOBufferBlockNext(TSIOBufferBlock /* blockp */)
{
  return nullptr; // single-block simulation — always one block
}

const char *
TSIOBufferBlockReadStart(TSIOBufferBlock /* blockp */, TSIOBufferReader /* readerp */, int64_t *avail)
{
  if (mock_block_data && mock_block_data_len > 0) {
    if (avail) {
      *avail = mock_block_data_len;
    }
    return mock_block_data;
  }
  if (avail) {
    *avail = 0;
  }
  return nullptr;
}

int64_t
TSIOBufferWrite(TSIOBuffer /* bufp */, const void * /* buf */, int64_t nbytes)
{
  return nbytes;
}

// --- HTTP Transaction ---

TSReturnCode
TSHttpTxnClientReqGet(TSHttpTxn /* txnp */, TSMBuffer * /* bufpp */, TSMLoc * /* obj */)
{
  return TS_SUCCESS;
}

TSReturnCode
TSHttpTxnServerRespGet(TSHttpTxn /* txnp */, TSMBuffer * /* bufpp */, TSMLoc * /* obj */)
{
  return TS_SUCCESS;
}

TSReturnCode
TSHttpTxnClientRespGet(TSHttpTxn /* txnp */, TSMBuffer * /* bufpp */, TSMLoc * /* obj */)
{
  return TS_SUCCESS;
}

TSReturnCode
TSHttpTxnTransformRespGet(TSHttpTxn /* txnp */, TSMBuffer * /* bufpp */, TSMLoc * /* obj */)
{
  return TS_SUCCESS;
}

void TSHttpTxnHookAdd(TSHttpTxn /* txnp */, TSHttpHookID /* id */, TSCont /* contp */)
{
  mock_hook_add_count++;
}

void TSHttpTxnReenable(TSHttpTxn /* txnp */, TSEvent /* event */) {}

const char *
TSHttpTxnClientProtocolStackContains(TSHttpTxn /* txnp */, const char * /* tag */)
{
  return nullptr;
}

TSHttpStatus TSHttpTxnStatusGet(TSHttpTxn /* txnp */)
{
  return mock_txn_status;
}

TSReturnCode
TSHttpTxnSendEarlyHints(TSHttpTxn /* txnp */, const char ** /* links */, int num_links)
{
  mock_send_early_hints_count++;
  mock_send_early_hints_last_nlinks = num_links;
  return mock_send_early_hints_rc;
}

// --- MIME / Headers ---

TSMLoc
TSMimeHdrFieldFind(TSMBuffer /* bufp */, TSMLoc /* hdr */, const char * /* name */, int /* length */)
{
  return TS_NULL_MLOC;
}

TSMLoc TSMimeHdrFieldNextDup(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc /* field */)
{
  return TS_NULL_MLOC;
}

const char *
TSMimeHdrFieldValueStringGet(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc /* field */, int /* idx */, int *value_len_ptr)
{
  if (value_len_ptr) {
    *value_len_ptr = 0;
  }
  return "";
}

TSReturnCode TSHandleMLocRelease(TSMBuffer /* bufp */, TSMLoc /* parent */, TSMLoc /* mloc */)
{
  return TS_SUCCESS;
}

TSReturnCode
TSMimeHdrFieldCreateNamed(TSMBuffer /* bufp */, TSMLoc /* hdr */, const char * /* name */, int /* name_len */, TSMLoc * /* locp */)
{
  return TS_SUCCESS;
}

TSReturnCode TSMimeHdrFieldAppend(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc /* field */)
{
  mock_field_append_count++;
  return TS_SUCCESS;
}

TSReturnCode
TSMimeHdrFieldValueStringSet(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc /* field */, int /* idx */, const char * /* value */,
                             int /* length */)
{
  return TS_SUCCESS;
}

TSReturnCode TSMimeHdrFieldDestroy(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc /* field */)
{
  return TS_SUCCESS;
}

// --- URL ---

TSReturnCode
TSHttpHdrUrlGet(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc * /* locp */)
{
  return TS_SUCCESS;
}

const char *
TSUrlPathGet(TSMBuffer /* bufp */, TSMLoc /* url */, int *length)
{
  if (length) {
    *length = 1;
  }
  return "/";
}

TSHttpStatus TSHttpHdrStatusGet(TSMBuffer /* bufp */, TSMLoc /* hdr */)
{
  return static_cast<TSHttpStatus>(200);
}

const char *
TSHttpHdrMethodGet(TSMBuffer /* bufp */, TSMLoc /* hdr */, int *length)
{
  if (length) {
    *length = 3;
  }
  return "GET";
}

// --- Plugin registration ---

TSReturnCode
TSPluginRegister(const TSPluginRegistrationInfo * /* info */)
{
  return TS_SUCCESS;
}

// --- User args ---

TSReturnCode
TSUserArgIndexReserve(TSUserArgType /* type */, const char * /* name */, const char * /* description */, int *arg_idx)
{
  if (mock_user_arg_reserve_rc == TS_SUCCESS && arg_idx) {
    *arg_idx = 0;
  }
  return mock_user_arg_reserve_rc;
}

void
TSUserArgSet(void * /* data */, int /* arg_idx */, void *arg)
{
  mock_user_arg_set_value = arg;
}

void *
TSUserArgGet(void * /* data */, int /* arg_idx */)
{
  return mock_user_arg_set_value;
}

} // extern "C"

// ─── ATS global constants referenced by early_hints.cc ──────────────────────

extern "C" {
const char *TS_MIME_FIELD_USER_AGENT       = "User-Agent";
int TS_MIME_LEN_USER_AGENT                 = 10;
const char *TS_MIME_FIELD_CONTENT_TYPE     = "Content-Type";
int TS_MIME_LEN_CONTENT_TYPE               = 12;
const char *TS_MIME_FIELD_CONTENT_ENCODING = "Content-Encoding";
int TS_MIME_LEN_CONTENT_ENCODING           = 16;
const char *TS_HTTP_METHOD_GET             = "GET";
const char *TS_HTTP_METHOD_HEAD            = "HEAD";
}

// ─── Runtime dir mock ───────────────────────────────────────────────────────

const char *
TSRuntimeDirGet()
{
  return "/tmp";
}

extern "C" {
TSReturnCode mock_cached_resp_get_rc = TS_SUCCESS;
TSReturnCode
TSHttpTxnCachedRespGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset)
{
  if (mock_cached_resp_get_rc == TS_SUCCESS) {
    *bufp   = reinterpret_cast<TSMBuffer>(0xCAFE);
    *offset = reinterpret_cast<TSMLoc>(0xBABE);
  }
  return mock_cached_resp_get_rc;
}
}
