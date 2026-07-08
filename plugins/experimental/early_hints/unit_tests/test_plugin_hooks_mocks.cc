/** @file
 * Catch2 main + ATS API mocks for test_plugin_hooks binary.
 *
 * Provides mock implementations for all ATS API functions used by the
 * static utility functions in early_hints.cc:
 *   - is_bot_user_agent()
 *   - is_navigate_request()
 *   - is_html_response()
 *
 * A configurable MIME header map (g_mock_headers) lets tests inject
 * specific header values without a real ATS environment. Tests call
 * set_mock_header() / clear_mock_headers() to control mock state.
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
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <atomic>
#include <map>
#include <string>
#include <pthread.h>

// --- Configurable MIME header map ------------------------------------------
// Tests set this map to inject specific headers. The map key is the
// canonical header name (e.g. "User-Agent"), value is the header value string.
std::map<std::string, std::string> g_mock_headers;

// Helper: set a header value for the current test.
void
set_mock_header(const std::string &name, const std::string &value)
{
  g_mock_headers[name] = value;
}

// Helper: remove all injected headers (call in test teardown or fixture).
void
clear_mock_headers()
{
  g_mock_headers.clear();
}

// Track TSMutexDestroy calls for destructor verification tests.
std::atomic<int> g_mutex_destroy_count{0};

extern "C" {

// --- Memory management ------------------------------------------------------

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
_TSstrdup(const char *str, int64_t /* length */, const char * /* path */)
{
  return strdup(str);
}

void
_TSfree(void *ptr)
{
  free(ptr);
}

// --- Mutex (real pthreads for thread-safety correctness) --------------------

TSMutex
TSMutexCreate()
{
  auto *m = new pthread_mutex_t;
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
  g_mutex_destroy_count++;
  pthread_mutex_destroy(reinterpret_cast<pthread_mutex_t *>(mutexp));
  delete reinterpret_cast<pthread_mutex_t *>(mutexp);
}

// --- Debug / Error logging (no-op) -----------------------------------------

void
TSDebug(const char * /* tag */, const char * /* fmt */, ...)
{
}

void
TSError(const char * /* fmt */, ...)
{
}

// --- Stats (mock) -----------------------------------------------------------

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

// --- MIME Header API  -- driven by g_mock_headers -----------------------------
//
// TSMimeHdrFieldFind: returns a non-null TSMLoc (pointer to the stored value
// string inside g_mock_headers) when the named header exists, TS_NULL_MLOC otherwise.
// The TSMLoc is used as an opaque handle by TSMimeHdrFieldValueStringGet.
//
// TS_MIME_FIELD_* constants are defined at the bottom of this file.

TSMLoc
TSMimeHdrFieldFind(TSMBuffer /* bufp */, TSMLoc /* hdr */, const char *name, int length)
{
  if (!name || length <= 0) {
    return TS_NULL_MLOC;
  }
  std::string key(name, static_cast<size_t>(length));
  auto it = g_mock_headers.find(key);
  if (it == g_mock_headers.end()) {
    return TS_NULL_MLOC;
  }
  // Return a stable pointer to the value string as the field handle.
  // This pointer remains valid for the lifetime of g_mock_headers entry.
  return reinterpret_cast<TSMLoc>(const_cast<std::string *>(&it->second));
}

const char *
TSMimeHdrFieldValueStringGet(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc field, int /* idx */, int *value_len_ptr)
{
  if (!field) {
    if (value_len_ptr) {
      *value_len_ptr = 0;
    }
    return nullptr;
  }
  const auto *val = reinterpret_cast<const std::string *>(field);
  if (value_len_ptr) {
    *value_len_ptr = static_cast<int>(val->size());
  }
  return val->c_str();
}

TSReturnCode TSHandleMLocRelease(TSMBuffer /* bufp */, TSMLoc /* parent */, TSMLoc /* mloc */)
{
  return TS_SUCCESS; // no-op: g_mock_headers owns the strings
}

// --- HTTP Transaction stubs -------------------------------------------------
// These are referenced transitively by early_hints.cc includes but not
// exercised by the functions under test in this binary.

TSReturnCode
TSHttpTxnClientReqGet(TSHttpTxn /* txnp */, TSMBuffer * /* bufpp */, TSMLoc * /* obj */)
{
  return TS_SUCCESS;
}

void TSHttpTxnReenable(TSHttpTxn /* txnp */, TSEvent /* event */) {}

TSHttpStatus TSHttpTxnStatusGet(TSHttpTxn /* txnp */)
{
  return static_cast<TSHttpStatus>(0); // TS_HTTP_STATUS_NONE
}

// --- Plugin registration stub -----------------------------------------------

TSReturnCode
TSPluginRegister(const TSPluginRegistrationInfo * /* info */)
{
  return TS_SUCCESS;
}

// --- User args stubs --------------------------------------------------------

TSReturnCode
TSUserArgIndexReserve(TSUserArgType /* type */, const char * /* name */, const char * /* description */, int *arg_idx)
{
  if (arg_idx) {
    *arg_idx = 0;
  }
  return TS_SUCCESS;
}

void
TSUserArgSet(void * /* data */, int /* arg_idx */, void * /* arg */)
{
}

void *
TSUserArgGet(void * /* data */, int /* arg_idx */)
{
  return nullptr;
}

// --- Hook stubs -------------------------------------------------------------

void TSHttpTxnHookAdd(TSHttpTxn /* txnp */, TSHttpHookID /* id */, TSCont /* contp */) {}

// --- Statistics: TSStatFindName needed by early_hints.cc TSRemapNewInstance --

#include <unordered_map>
static std::unordered_map<std::string, int> g_mock_stats;

TSReturnCode
TSStatFindName(const char *name, int *id)
{
  auto it = g_mock_stats.find(name);
  if (it != g_mock_stats.end()) {
    *id = it->second;
    return TS_SUCCESS;
  }
  return TS_ERROR;
}

// --- Debug helpers: TSNote and _TSAssert ------------------------------------

void
TSNote(const char * /* fmt */, ...)
{
}

int
_TSAssert(const char *text, const char *file, int line)
{
  std::fprintf(stderr, "TSAssert failed: %s at %s:%d\n", text, file, line);
  abort();
}

// --- Continuation API -------------------------------------------------------

void *g_mock_cont_data = nullptr;

void *TSContDataGet(TSCont /* contp */)
{
  return g_mock_cont_data;
}

void
TSContDataSet(TSCont /* contp */, void *data)
{
  g_mock_cont_data = data;
}

TSCont TSContCreate(TSEventFunc /* handler */, TSMutex /* mutexp */)
{
  return reinterpret_cast<TSCont>(0x1234);
}

void TSContDestroy(TSCont /* contp */) {}

int
TSContCall(TSCont /* contp */, TSEvent /* event */, void * /* edata */)
{
  return 0;
}

// --- VConnection / VIO API --------------------------------------------------

int TSVConnClosedGet(TSVConn /* connp */)
{
  return 0;
}

TSVIO
TSVConnWriteVIOGet(TSVConn /* connp */)
{
  return nullptr;
}

TSVConn TSTransformOutputVConnGet(TSVConn /* connp */)
{
  return nullptr;
}

TSVIO
TSVConnWrite(TSVConn /* connp */, TSCont /* contp */, TSIOBufferReader /* readerp */, int64_t /* nbytes */)
{
  return reinterpret_cast<TSVIO>(0x5678);
}

void
TSVConnShutdown(TSVConn /* connp */, int /* read */, int /* write */)
{
}

TSVConn TSTransformCreate(TSEventFunc /* event_funcp */, TSHttpTxn /* txnp */)
{
  return reinterpret_cast<TSVConn>(0x9ABC);
}

TSCont TSVIOContGet(TSVIO /* viop */)
{
  return reinterpret_cast<TSCont>(0xAAAA);
}

int64_t TSVIONDoneGet(TSVIO /* viop */)
{
  return 0;
}

int64_t TSVIONTodoGet(TSVIO /* viop */)
{
  return 0;
}

void TSVIONBytesSet(TSVIO /* viop */, int64_t /* nbytes */) {}

void TSVIONDoneSet(TSVIO /* viop */, int64_t /* ndone */) {}

void TSVIOReenable(TSVIO /* viop */) {}

TSIOBuffer TSVIOBufferGet(TSVIO /* viop */)
{
  return nullptr;
}

TSIOBufferReader TSVIOReaderGet(TSVIO /* viop */)
{
  return nullptr;
}

// --- IOBuffer API -----------------------------------------------------------

TSIOBuffer
TSIOBufferCreate()
{
  return reinterpret_cast<TSIOBuffer>(malloc(1));
}

void
TSIOBufferDestroy(TSIOBuffer bufp)
{
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
  return nbytes;
}

int64_t TSIOBufferReaderAvail(TSIOBufferReader /* readerp */)
{
  return 0;
}

void TSIOBufferReaderConsume(TSIOBufferReader /* readerp */, int64_t /* nbytes */) {}

TSIOBufferBlock TSIOBufferReaderStart(TSIOBufferReader /* readerp */)
{
  return nullptr;
}

TSIOBufferBlock TSIOBufferBlockNext(TSIOBufferBlock /* blockp */)
{
  return nullptr;
}

const char *
TSIOBufferBlockReadStart(TSIOBufferBlock /* blockp */, TSIOBufferReader /* readerp */, int64_t *avail)
{
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

// --- HTTP transaction API ---------------------------------------------------

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

TSReturnCode
TSHttpTxnCachedRespGet(TSHttpTxn /* txnp */, TSMBuffer *bufp, TSMLoc *offset)
{
  if (bufp) {
    *bufp = reinterpret_cast<TSMBuffer>(0xCAFE);
  }
  if (offset) {
    *offset = reinterpret_cast<TSMLoc>(0xBABE);
  }
  return TS_SUCCESS;
}

const char *
TSHttpTxnClientProtocolStackContains(TSHttpTxn /* txnp */, const char * /* tag */)
{
  return nullptr;
}

TSReturnCode
TSHttpTxnSendEarlyHints(TSHttpTxn /* txnp */, const char ** /* links */, int /* num_links */)
{
  return TS_SUCCESS;
}

// --- MIME field helpers (beyond TSMimeHdrFieldFind already mocked) -----------

TSMLoc TSMimeHdrFieldNextDup(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc /* field */)
{
  return TS_NULL_MLOC;
}

TSReturnCode
TSMimeHdrFieldCreateNamed(TSMBuffer /* bufp */, TSMLoc /* hdr */, const char * /* name */, int /* name_len */, TSMLoc * /* locp */)
{
  return TS_SUCCESS;
}

TSReturnCode TSMimeHdrFieldAppend(TSMBuffer /* bufp */, TSMLoc /* hdr */, TSMLoc /* field */)
{
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

// --- URL API ----------------------------------------------------------------

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

} // extern "C"

// --- ATS MIME/HTTP constants (extern "C" linkage, defined once per binary) --

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

// --- Runtime dir stub -------------------------------------------------------

const char *
TSRuntimeDirGet()
{
  return "/tmp";
}
