/** @file
 * Unit tests for the early_hints transform event handler.
 *
 * Tests the error flag and null VConn guard behaviors that protect
 * against crashes in edge-case event sequences.
 *
 * Strategy: #include "early_hints.cc" to access static functions,
 * with ATS API mocks defined in test_transform_mocks.cc.
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

#include <catch.hpp>

// Include the implementation to access static functions (TransformData, early_hints_transform, etc.)
#include "early_hints.cc"

// ─── Mock control state (defined in test_transform_mocks.cc) ────────────────

// These extern globals control mock behavior for the tests.
extern void *mock_cont_data;
extern int mock_vconn_closed;
extern int mock_mutex_destroy_count;
extern TSReturnCode mock_user_arg_reserve_rc;
extern void *mock_user_arg_set_value;
extern int mock_hook_add_count;
extern TSHttpStatus mock_txn_status;
extern void *mock_output_vconn;
extern void *mock_input_vio;
extern int mock_vconn_shutdown_called;
extern int mock_cont_call_count;
extern int mock_transform_do_vio_reenable_count;
extern int mock_cont_destroy_count;
extern int mock_iobuffer_destroy_count;
extern void *mock_vio_buffer;
extern int64_t mock_vio_ntodo;
extern void *mock_vio_reader;
extern int64_t mock_reader_avail;
extern int64_t mock_vio_ndone;
extern int64_t mock_vio_nbytes_set;
extern const char *mock_block_data;
extern int64_t mock_block_data_len;
extern bool mock_vio_ntodo_use_computed;
extern int64_t mock_vio_nbytes_total;
extern int64_t mock_iobuffer_copy_return;
extern int64_t mock_reader_consumed;
extern TSReturnCode mock_send_early_hints_rc;
extern int mock_send_early_hints_count;
extern int mock_send_early_hints_last_nlinks;
extern int mock_field_append_count;

// Helper: reset all mock state to defaults
static void
reset_mocks()
{
  mock_cont_data                       = nullptr;
  mock_vconn_closed                    = 0;
  mock_mutex_destroy_count             = 0;
  mock_user_arg_reserve_rc             = TS_SUCCESS;
  mock_user_arg_set_value              = nullptr;
  mock_hook_add_count                  = 0;
  mock_txn_status                      = static_cast<TSHttpStatus>(200);
  mock_output_vconn                    = nullptr;
  mock_input_vio                       = nullptr;
  mock_vconn_shutdown_called           = 0;
  mock_cont_call_count                 = 0;
  mock_transform_do_vio_reenable_count = 0;
  mock_cont_destroy_count              = 0;
  mock_iobuffer_destroy_count          = 0;
  mock_vio_buffer                      = nullptr;
  mock_vio_ntodo                       = 0;
  mock_vio_reader                      = nullptr;
  mock_reader_avail                    = 0;
  mock_vio_ndone                       = 0;
  mock_vio_nbytes_set                  = -1;
  mock_block_data                      = nullptr;
  mock_block_data_len                  = 0;
  mock_vio_ntodo_use_computed          = false;
  mock_vio_nbytes_total                = 0;
  mock_iobuffer_copy_return            = -1; // default: return nbytes (full copy)
  mock_reader_consumed                 = 0;
  mock_send_early_hints_rc             = TS_SUCCESS;
  mock_send_early_hints_count          = 0;
  mock_send_early_hints_last_nlinks    = 0;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

TEST_CASE("Transform: error flag prevents subsequent processing", "[transform][error]")
{
  reset_mocks();
  // Create a TransformData with errored = false
  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  // Set up mock: TSContDataGet returns our TransformData
  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD); // non-null sentinel

  SECTION("ERROR event sets errored flag")
  {
    mock_cont_call_count = 0;

    // Simulate TS_EVENT_ERROR
    TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
    early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);

    // errored flag should be set
    CHECK(data.errored == true);

    // TSContCall should have been called to propagate the error
    CHECK(mock_cont_call_count == 1);
  }

  SECTION("WRITE_READY after ERROR is a no-op due to errored flag")
  {
    // Pre-set errored flag (simulating a previous ERROR event)
    data.errored = true;

    // Set up mock state so the function WOULD proceed without the errored check:
    // - non-null output_vconn so init doesn't bail early
    // - null TSVIOBufferGet (returns nullptr by default) triggers TSVIOReenable
    mock_output_vconn = reinterpret_cast<void *>(0xCCCC);

    // Reset counters
    mock_transform_do_vio_reenable_count = 0;
    mock_cont_call_count                 = 0;

    // Simulate TS_EVENT_VCONN_WRITE_READY — should be a no-op due to errored flag
    TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
    early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

    // early_hints_transform_do should have returned early due to errored flag:
    // - No VIO reenable calls (would be 1 without errored check)
    // - No TSContCall
    CHECK(mock_transform_do_vio_reenable_count == 0);
    CHECK(mock_cont_call_count == 0);
  }
}

TEST_CASE("Transform: null output VConn in WRITE_COMPLETE does not crash", "[transform][null-vconn]")
{
  reset_mocks();
  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;

  SECTION("WRITE_COMPLETE with null output VConn skips shutdown")
  {
    mock_output_vconn          = nullptr; // TSTransformOutputVConnGet returns null
    mock_vconn_shutdown_called = 0;

    TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
    early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_COMPLETE, nullptr);

    // TSVConnShutdown should NOT have been called
    CHECK(mock_vconn_shutdown_called == 0);
  }

  SECTION("WRITE_COMPLETE with valid output VConn calls shutdown")
  {
    mock_output_vconn          = reinterpret_cast<void *>(0xBEEF); // non-null
    mock_vconn_shutdown_called = 0;

    TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
    early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_COMPLETE, nullptr);

    // TSVConnShutdown SHOULD have been called
    CHECK(mock_vconn_shutdown_called == 1);
  }
}

// ─── T1/T2: VConn closed cleanup paths ─────────────────────────────────────

TEST_CASE("Transform: VConn closed with data cleans up and destroys cont", "[transform][vconn-closed]")
{
  reset_mocks();

  // Allocate TransformData the same way early_hints.cc does (TSmalloc + placement new)
  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = nullptr;
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate(); // will be freed by cleanup

  mock_cont_data              = data;
  mock_vconn_closed           = 1; // VConn is closed
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1); // output_buffer was destroyed
}

TEST_CASE("Transform: VConn closed with null data just destroys cont", "[transform][vconn-closed]")
{
  reset_mocks();

  mock_cont_data          = nullptr; // no TransformData
  mock_vconn_closed       = 1;
  mock_cont_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
}

// ─── ERROR event edge cases ─────────────────────────────────────────

TEST_CASE("Transform: ERROR event with null data does not crash", "[transform][error]")
{
  reset_mocks();

  mock_cont_data    = nullptr;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);

  CHECK(ret == 0);
  // Should still propagate error via TSContCall since input_vio is non-null
  CHECK(mock_cont_call_count == 1);
}

TEST_CASE("Transform: ERROR event with null input_vio skips TSContCall", "[transform][error]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = nullptr; // TSVConnWriteVIOGet returns null

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);

  CHECK(data.errored == true);
  CHECK(mock_cont_call_count == 0); // no TSContCall since input_vio is null
}

// ─── T9: Default/unknown event delegates to _do ────────────────────────────

TEST_CASE("Transform: unknown event delegates to transform_do", "[transform][default-event]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_output_vconn = nullptr; // _do will bail at null output_conn

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  // Use an event value outside the switch cases (cast an arbitrary int)
  int ret = early_hints_transform(fake_contp, static_cast<TSEvent>(99999), nullptr);

  CHECK(ret == 0);
  // _do was entered but returned early at null output_conn — no crash
  CHECK(data.initialized == false);
}

// ─── _do with null data ────────────────────────────────────────────────

TEST_CASE("Transform_do: null data is safe early return", "[transform_do]")
{
  reset_mocks();

  mock_cont_data                       = nullptr;
  mock_vconn_closed                    = 0;
  mock_transform_do_vio_reenable_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(mock_transform_do_vio_reenable_count == 0);
  CHECK(mock_cont_call_count == 0);
}

// ─── _do with uninitialized + null output_conn ─────────────────────────

TEST_CASE("Transform_do: uninitialized with null output_conn returns early", "[transform_do]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_output_vconn = nullptr;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(data.initialized == false);
  CHECK(mock_transform_do_vio_reenable_count == 0);
}

// ─── D4: _do init path with valid output_conn ──────────────────────────────

TEST_CASE("Transform_do: initializes output buffers on first call", "[transform_do]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_output_vconn = reinterpret_cast<void *>(0xCCCC);
  mock_vio_buffer   = nullptr; // TSVIOBufferGet → null → EOS path after init

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(data.initialized == true);
  CHECK(data.output_buffer != nullptr);
  CHECK(data.output_reader != nullptr);
  CHECK(data.output_vio != nullptr);

  // Cleanup allocated buffer to avoid leak
  TSIOBufferDestroy(data.output_buffer);
}

// ─── D5/D6: EOS path ──────────────────────────────────────────────────────

TEST_CASE("Transform_do: EOS finalizes and sets nbytes", "[transform_do][eos]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 42;
  data.cache_written = false;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = nullptr; // EOS

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(mock_vio_nbytes_set == 42);
  CHECK(mock_transform_do_vio_reenable_count == 1);

  TSIOBufferDestroy(data.output_buffer);
}

// ─── D7: toread <= 0 → complete ────────────────────────────────────────────

TEST_CASE("Transform_do: toread zero sends WRITE_COMPLETE", "[transform_do]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 100;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA); // non-null → not EOS
  mock_vio_ntodo    = 0;                                // toread <= 0

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(mock_vio_nbytes_set == 100);
  CHECK(mock_transform_do_vio_reenable_count == 1);
  CHECK(mock_cont_call_count == 1); // WRITE_COMPLETE propagated

  TSIOBufferDestroy(data.output_buffer);
}

// ─── D8: null input_reader → reenable only ─────────────────────────────────

TEST_CASE("Transform_do: null input_reader reenables and returns", "[transform_do]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA); // not EOS
  mock_vio_ntodo    = 100;                              // toread > 0
  mock_vio_reader   = nullptr;                          // TSVIOReaderGet → null

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(mock_transform_do_vio_reenable_count == 1);
  CHECK(mock_cont_call_count == 0); // no TSContCall — just reenable
  CHECK(data.bytes_written == 0);   // no data processed

  TSIOBufferDestroy(data.output_buffer);
}

// ─── D9/D10/D11: Data processing with avail > 0, more data pending ────────

TEST_CASE("Transform_do: data passthrough with more data pending", "[transform_do][data]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr; // no scanner — pure passthrough
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo    = 200;                              // toread = 200 (more than avail)
  mock_vio_reader   = reinterpret_cast<void *>(0xCCCC); // non-null reader
  mock_reader_avail = 50;                               // 50 bytes available
  mock_vio_ndone    = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(data.bytes_written == 50);
  CHECK(mock_vio_ndone == 50);                      // NDoneSet was called with 0 + 50
  CHECK(mock_transform_do_vio_reenable_count == 1); // output reenabled
  CHECK(mock_cont_call_count == 1);                 // WRITE_READY propagated upstream

  TSIOBufferDestroy(data.output_buffer);
}

// ─── D12: Data processing, final chunk (toread goes to 0 after copy) ──────

TEST_CASE("Transform_do: avail clamped to toread when avail exceeds remaining", "[transform_do][data]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;
  data.cache_written = false;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA);
  // Both the first TSVIONTodoGet (= 50) and second (= 0 after consuming 50) use same mock.
  // Since TSVIONTodoGet returns mock_vio_ntodo, and NDoneSet updates mock_vio_ndone but
  // NTodoGet doesn't decrement, we need the second call to return 0.
  // The mock always returns mock_vio_ntodo, so after consuming data, NTodoGet still returns
  // whatever we set. We set it to 50 initially; after avail=50 is consumed, the second
  // NTodoGet call should return 0. Since our mock is static, set ntodo = 0 — the first check
  // (toread <= 0) is bypassed by the avail > 0 path. Wait — the first NTodoGet call happens
  // BEFORE the avail path. So we need ntodo > 0 for the first call and 0 for the second.
  //
  // Workaround: Set avail to match toread exactly. The mock returns the same value for both
  // NTodoGet calls (50), but after consuming 50 bytes, NTodoGet returns 50 again (not 0).
  // This means the "else" branch (toread <= 0) won't trigger.
  //
  // Since NTodoGet = nbytes - ndone, and our mock doesn't compute this, we must accept
  // that testing the exact "second NTodoGet returns 0" requires a stateful mock. Instead,
  // we test the reachability by setting ntodo = 0 for the toread <= 0 immediate path (D7).
  //
  // For the D12 "after copy, toread <= 0" branch, we need a two-call mock. For now, this is
  // adequately covered by D7. The data copy + WRITE_READY (D11) is already covered above.
  // Let's verify the avail-clamping behavior instead.
  mock_vio_ntodo    = 30; // less than avail
  mock_vio_reader   = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail = 50; // avail (50) > toread (30) → clamped to 30

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // avail should have been clamped to toread (30)
  CHECK(data.bytes_written == 30);

  TSIOBufferDestroy(data.output_buffer);
}

// ─── D9: Scanner feed with block data ──────────────────────────────────────

TEST_CASE("Transform_do: scanner feed processes block data", "[transform_do][scanner]")
{
  reset_mocks();

  // Create a real EarlyHintsConfig for the scanner
  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = &scanner;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  // Provide block data containing an HTML head with a link
  const char *html = "<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head>";
  int64_t html_len = static_cast<int64_t>(strlen(html));

  mock_cont_data      = &data;
  mock_vconn_closed   = 0;
  mock_input_vio      = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer     = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo      = html_len + 100; // more to come
  mock_vio_reader     = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail   = html_len;
  mock_block_data     = html;
  mock_block_data_len = html_len;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(data.bytes_written == html_len);
  // The scanner should have found the link
  CHECK(scanner.get_links().size() == 1);
  // After </head>, scanner should be done
  CHECK(scanner.is_done() == true);

  // Don't delete scanner — it's stack-allocated
  data.scanner = nullptr;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── Sequence: ERROR then WRITE_READY ──────────────────────────────────────

TEST_CASE("Transform: ERROR then WRITE_READY sequence", "[transform][sequence]")
{
  reset_mocks();

  // Allocate properly for cleanup
  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_output_vconn = reinterpret_cast<void *>(0xCCCC);

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // First: ERROR
  early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);
  CHECK(data.errored == true);
  CHECK(mock_cont_call_count == 1);

  // Second: WRITE_READY — should be no-op due to errored flag
  mock_cont_call_count                 = 0;
  mock_transform_do_vio_reenable_count = 0;
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  // _do returned immediately — no reenable, no TSContCall
  CHECK(mock_transform_do_vio_reenable_count == 0);
  CHECK(mock_cont_call_count == 0);
  // Output was never initialized (errored before init)
  CHECK(data.initialized == false);
}

// ─── Sequence: WRITE_COMPLETE then WRITE_READY ─────────────────────────────

TEST_CASE("Transform: WRITE_COMPLETE then WRITE_READY sequence", "[transform][sequence]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_output_vconn = reinterpret_cast<void *>(0xBEEF);
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // WRITE_COMPLETE first — shuts down output
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_COMPLETE, nullptr);
  CHECK(mock_vconn_shutdown_called == 1);

  // WRITE_READY after — _do runs but output_conn is still "valid" in mock,
  // so it initializes. This tests that the handler doesn't crash.
  mock_output_vconn = reinterpret_cast<void *>(0xBEEF);
  mock_vio_buffer   = nullptr; // EOS
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  // Should have initialized and hit EOS
  CHECK(data.initialized == true);

  TSIOBufferDestroy(data.output_buffer);
}

// ─── D2: _do with errored data (direct call) ──────────────────────────────

TEST_CASE("Transform_do: errored data is safe early return", "[transform_do][error]")
{
  reset_mocks();

  TransformData data;
  data.errored       = true;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = nullptr;
  data.output_vio    = nullptr;
  data.bytes_written = 0;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_output_vconn = reinterpret_cast<void *>(0xCCCC);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo    = 100;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Should return immediately — no reenable, no cont call, no bytes
  CHECK(mock_transform_do_vio_reenable_count == 0);
  CHECK(mock_cont_call_count == 0);
  CHECK(data.bytes_written == 0);
}

// ─── D6: EOS with scanner links writes to cache ───────────────────────────

TEST_CASE("Transform_do: EOS with scanner links writes to cache", "[transform_do][eos][cache]")
{
  reset_mocks();

  // Create real config, scanner, and cache
  EarlyHintsConfig config;
  HtmlScanner *scanner = new HtmlScanner(64 * 1024, 20, &config);
  HintsCache cache;

  // Feed scanner some HTML with links to populate get_links()
  const char *html = "<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head>";
  scanner->feed(html, static_cast<int64_t>(strlen(html)));
  REQUIRE(scanner->get_links().size() == 1);

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = scanner;
  data.cache         = &cache;
  data.cache_key     = "/test-page";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 100;
  data.cache_written = false;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = nullptr; // EOS

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Cache should have been written
  CHECK(data.cache_written == true);
  CHECK(mock_vio_nbytes_set == 100);
  CHECK(mock_transform_do_vio_reenable_count == 1);

  // Verify cache actually received the data
  std::vector<std::string> cached_links;
  bool found = cache.get("/test-page", cached_links, 1);
  CHECK(found == true);
  CHECK(cached_links.size() == 1);

  data.scanner = nullptr; // prevent double free
  delete scanner;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── D15: EOS with cache_written=true skips double write ──────────────────

TEST_CASE("Transform_do: EOS with cache_written skips double write", "[transform_do][eos][cache]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner *scanner = new HtmlScanner(64 * 1024, 20, &config);
  HintsCache cache;

  const char *html = "<html><head><link rel=\"stylesheet\" href=\"/a.css\"></head>";
  scanner->feed(html, static_cast<int64_t>(strlen(html)));
  REQUIRE(scanner->get_links().size() == 1);

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = scanner;
  data.cache         = &cache;
  data.cache_key     = "/already-cached";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 50;
  data.cache_written = true; // already written

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = nullptr; // EOS

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Cache put should NOT have been called again (cache_written was already true)
  CHECK(data.cache_written == true);
  CHECK(mock_vio_nbytes_set == 50);
  CHECK(mock_transform_do_vio_reenable_count == 1);

  // Verify cache has no entry (put was never called — it was "already written" by prior logic)
  std::vector<std::string> cached_links;
  bool found = cache.get("/already-cached", cached_links, 1);
  CHECK(found == false);

  data.scanner = nullptr;
  delete scanner;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── D14: avail == 0 skips processing, falls through to pending check ─────

TEST_CASE("Transform_do: avail zero skips processing block", "[transform_do][data]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA); // not EOS
  mock_vio_ntodo    = 100;                              // toread > 0
  mock_vio_reader   = reinterpret_cast<void *>(0xCCCC); // non-null reader
  mock_reader_avail = 0;                                // no bytes available

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // No data processed
  CHECK(data.bytes_written == 0);
  // Falls through to second toread check (still > 0) → WRITE_READY
  CHECK(mock_transform_do_vio_reenable_count == 1);
  CHECK(mock_cont_call_count == 1); // WRITE_READY propagated

  TSIOBufferDestroy(data.output_buffer);
}

// ─── T16: VConn closed with scanner properly deletes scanner ──────────────

TEST_CASE("Transform: VConn closed with scanner cleans up scanner", "[transform][vconn-closed]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner *scanner = new HtmlScanner(64 * 1024, 20, &config);

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = scanner;
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();

  mock_cont_data              = data;
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);
  // Scanner was deleted (no leak) — if delete crashed, we wouldn't reach here
}

// ─── T17: VConn closed with data but no output_buffer ─────────────────────

TEST_CASE("Transform: VConn closed with data but no output_buffer", "[transform][vconn-closed]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = false;
  data->scanner       = nullptr;
  data->cache         = nullptr;
  data->output_buffer = nullptr; // never initialized

  mock_cont_data              = data;
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 0); // output_buffer was null — no destroy
}

// ─── D17: Scanner is_done skips feed ──────────────────────────────────────

TEST_CASE("Transform_do: scanner is_done skips feed", "[transform_do][scanner]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);

  // Feed enough HTML to finish the scanner (</head> triggers DONE)
  const char *html = "<html><head></head>";
  scanner.feed(html, static_cast<int64_t>(strlen(html)));
  REQUIRE(scanner.is_done() == true);

  size_t links_before = scanner.get_links().size();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = &scanner;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  // Provide block data that would be fed to scanner if it weren't done
  const char *body    = "<link rel=\"stylesheet\" href=\"/new.css\">";
  int64_t body_len    = static_cast<int64_t>(strlen(body));
  mock_cont_data      = &data;
  mock_vconn_closed   = 0;
  mock_input_vio      = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer     = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo      = body_len + 100;
  mock_vio_reader     = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail   = body_len;
  mock_block_data     = body;
  mock_block_data_len = body_len;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Data was copied through (passthrough works)
  CHECK(data.bytes_written == body_len);
  // Scanner links unchanged — feed was skipped because is_done() == true
  CHECK(scanner.get_links().size() == links_before);

  data.scanner = nullptr;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── T7: ERROR with null data and null input_vio ──────────────────────────

TEST_CASE("Transform: ERROR with null data and null input_vio", "[transform][error]")
{
  reset_mocks();

  mock_cont_data    = nullptr;
  mock_vconn_closed = 0;
  mock_input_vio    = nullptr;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_call_count == 0); // no TSContCall — both null
}

// ─── D7b: Negative toread sends WRITE_COMPLETE ───────────────────────────

TEST_CASE("Transform_do: negative toread sends WRITE_COMPLETE", "[transform_do]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 200;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA); // not EOS
  mock_vio_ntodo    = -5;                               // negative toread

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(mock_vio_nbytes_set == 200);
  CHECK(mock_transform_do_vio_reenable_count == 1);
  CHECK(mock_cont_call_count == 1); // WRITE_COMPLETE propagated

  TSIOBufferDestroy(data.output_buffer);
}

// ─── D13: Final chunk with computed toread→0, cache write + COMPLETE ──────

TEST_CASE("Transform_do: final chunk completes with cache write (computed ntodo)", "[transform_do][data][cache]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner *scanner = new HtmlScanner(64 * 1024, 20, &config);
  HintsCache cache;

  // Pre-feed scanner with HTML containing a link
  const char *head = "<html><head><link rel=\"stylesheet\" href=\"/main.css\">";
  scanner->feed(head, static_cast<int64_t>(strlen(head)));
  REQUIRE(scanner->get_links().size() == 1);

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = scanner;
  data.cache         = &cache;
  data.cache_key     = "/final-chunk-test";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;
  data.cache_written = false;

  // Use computed NTodoGet: total=50, ndone starts at 0
  // First NTodoGet returns 50 (enough to proceed)
  // After processing 50 bytes, NDoneSet sets ndone=50, so second NTodoGet returns 0
  mock_cont_data              = &data;
  mock_vconn_closed           = 0;
  mock_input_vio              = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer             = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo_use_computed = true;
  mock_vio_nbytes_total       = 50;
  mock_vio_ndone              = 0;
  mock_vio_reader             = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail           = 50;

  // No block data for scanner — scanner already has links from pre-feed
  mock_block_data     = nullptr;
  mock_block_data_len = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // After processing: ndone=50, nbytes_total=50 → toread=0 → else branch
  CHECK(data.bytes_written == 50);
  CHECK(data.cache_written == true);
  CHECK(mock_vio_nbytes_set == 50);
  CHECK(mock_transform_do_vio_reenable_count == 1);
  CHECK(mock_cont_call_count == 1); // WRITE_COMPLETE propagated

  // Verify cache has the learned link
  std::vector<std::string> cached_links;
  bool found = cache.get("/final-chunk-test", cached_links, 1);
  CHECK(found == true);
  CHECK(cached_links.size() == 1);

  data.scanner = nullptr;
  delete scanner;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── D19: Final chunk with cache_written prevents double write ────────────

TEST_CASE("Transform_do: final chunk with cache_written prevents double write", "[transform_do][data][cache]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner *scanner = new HtmlScanner(64 * 1024, 20, &config);
  HintsCache cache;

  const char *head = "<html><head><link rel=\"stylesheet\" href=\"/dup.css\">";
  scanner->feed(head, static_cast<int64_t>(strlen(head)));
  REQUIRE(scanner->get_links().size() == 1);

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = scanner;
  data.cache         = &cache;
  data.cache_key     = "/no-double-write";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;
  data.cache_written = true; // already written

  mock_cont_data              = &data;
  mock_vconn_closed           = 0;
  mock_input_vio              = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer             = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo_use_computed = true;
  mock_vio_nbytes_total       = 30;
  mock_vio_ndone              = 0;
  mock_vio_reader             = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail           = 30;
  mock_block_data             = nullptr;
  mock_block_data_len         = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Data processed and completed
  CHECK(data.bytes_written == 30);
  CHECK(mock_cont_call_count == 1); // WRITE_COMPLETE
  // Cache was NOT written again (was already true)
  CHECK(data.cache_written == true);
  std::vector<std::string> cached_links;
  bool found = cache.get("/no-double-write", cached_links, 1);
  CHECK(found == false); // put was never called

  data.scanner = nullptr;
  delete scanner;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── D20: Scanner feed with data and computed final chunk ─────────────────

TEST_CASE("Transform_do: scanner feed during final chunk (computed ntodo)", "[transform_do][scanner][data]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);
  HintsCache cache;

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = &scanner;
  data.cache         = &cache;
  data.cache_key     = "/feed-final";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;
  data.cache_written = false;

  const char *html = "<html><head><link rel=\"preload\" href=\"/font.woff2\" as=\"font\"></head>";
  int64_t html_len = static_cast<int64_t>(strlen(html));

  mock_cont_data              = &data;
  mock_vconn_closed           = 0;
  mock_input_vio              = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer             = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo_use_computed = true;
  mock_vio_nbytes_total       = html_len; // exactly matches avail
  mock_vio_ndone              = 0;
  mock_vio_reader             = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail           = html_len;
  mock_block_data             = html;
  mock_block_data_len         = html_len;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Scanner should have found the preload link
  CHECK(scanner.get_links().size() == 1);
  // Toread goes to 0 → else branch → cache write
  CHECK(data.bytes_written == html_len);
  CHECK(data.cache_written == true);
  CHECK(mock_cont_call_count == 1); // WRITE_COMPLETE

  // Verify cache
  std::vector<std::string> cached_links;
  bool found = cache.get("/feed-final", cached_links, 1);
  CHECK(found == true);

  data.scanner = nullptr;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── EOS: scanner with no links does NOT write cache ──────────────────────

TEST_CASE("Transform_do: EOS with scanner but no links skips cache write", "[transform_do][eos][cache]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner *scanner = new HtmlScanner(64 * 1024, 20, &config);
  HintsCache cache;

  // Feed scanner HTML with NO links
  const char *html = "<html><head><title>No links</title></head>";
  scanner->feed(html, static_cast<int64_t>(strlen(html)));
  REQUIRE(scanner->get_links().empty());

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = scanner;
  data.cache         = &cache;
  data.cache_key     = "/no-links";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 75;
  data.cache_written = false;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = nullptr; // EOS

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // cache_written stays false (no links to write)
  CHECK(data.cache_written == false);
  CHECK(mock_vio_nbytes_set == 75);
  CHECK(mock_transform_do_vio_reenable_count == 1);

  data.scanner = nullptr;
  delete scanner;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── EOS: null scanner does NOT write cache ───────────────────────────────

TEST_CASE("Transform_do: EOS with null scanner skips cache write", "[transform_do][eos]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 33;
  data.cache_written = false;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = nullptr; // EOS

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  CHECK(data.cache_written == false);
  CHECK(mock_vio_nbytes_set == 33);
  CHECK(mock_transform_do_vio_reenable_count == 1);

  TSIOBufferDestroy(data.output_buffer);
}

// ─── Bug fix: TSIOBufferCopy partial copy must not cause VIO accounting divergence ───

TEST_CASE("Transform: partial TSIOBufferCopy uses actual copied bytes for accounting", "[transform][partial-copy][regression]")
{
  reset_mocks();

  HintsCache cache;
  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = &cache;
  data.cache_key     = "/test";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;
  data.cache_written = false;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAABB); // non-null = data available
  mock_vio_reader   = reinterpret_cast<void *>(0xCCDD); // non-null reader
  mock_reader_avail = 1000;
  mock_vio_ndone    = 0;

  // Use computed NTodoGet so it reflects real ATS behavior
  mock_vio_ntodo_use_computed = true;
  mock_vio_nbytes_total       = 2000;

  SECTION("partial copy: only copied bytes are accounted in bytes_written and NDone")
  {
    // TSIOBufferCopy returns only 500 of 1000 requested
    mock_iobuffer_copy_return = 500;
    mock_reader_consumed      = 0;

    TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
    early_hints_transform_do(fake_contp);

    // bytes_written must reflect actual copied amount, not full avail
    CHECK(data.bytes_written == 500);
    // Reader must consume only what was actually copied
    CHECK(mock_reader_consumed == 500);
    // NDone must match actual progress
    CHECK(mock_vio_ndone == 500);
  }

  SECTION("zero copy sets errored flag and consumes input to avoid infinite loop")
  {
    mock_iobuffer_copy_return = 0;
    mock_reader_consumed      = 0;

    TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
    early_hints_transform_do(fake_contp);

    // R9-11 fix: zero copy now sets errored=true and consumes input
    CHECK(data.errored == true);
    CHECK(mock_reader_consumed == 1000);
    // ndone is NOT updated — error path returns before VIO update
    CHECK(mock_vio_ndone == 0);
  }

  TSIOBufferDestroy(data.output_buffer);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error Recovery Path Audit Tests
// ═══════════════════════════════════════════════════════════════════════════════

// ─── EP1: ERROR event with initialized output buffers → cleanup on VConn close ─

TEST_CASE("Error path: ERROR with initialized output cleaned up on VConn close", "[error-path][lifecycle]")
{
  reset_mocks();

  // Allocate TransformData the way production code does
  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = new HtmlScanner(64 * 1024, 20, nullptr);
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();
  data->output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data->output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data->bytes_written = 42;

  mock_cont_data    = data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // Step 1: ERROR event — sets flag, propagates
  early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);
  CHECK(data->errored == true);
  CHECK(mock_cont_call_count == 1);

  // Step 2: VConn closes — full cleanup must happen
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  int ret = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);
  // data and scanner freed — no leak (would crash if double-freed)
}

// ─── EP2: Double ERROR events are idempotent ────────────────────────────────

TEST_CASE("Error path: double ERROR events are idempotent", "[error-path][idempotent]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = true;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // First ERROR
  early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);
  CHECK(data.errored == true);
  CHECK(mock_cont_call_count == 1);

  // Second ERROR — should still propagate but not crash
  mock_cont_call_count = 0;
  early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);
  CHECK(data.errored == true);      // still true
  CHECK(mock_cont_call_count == 1); // propagated again (idempotent)
}

// ─── EP3: Null input_vio in transform_do → safe early return ────────────────

TEST_CASE("Error path: null input_vio in transform_do returns safely", "[error-path][null-vio]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = nullptr; // TSVConnWriteVIOGet returns null
  mock_output_vconn = reinterpret_cast<void *>(0xCCCC);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo    = 100;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Should return early — no crash, no processing
  CHECK(data.bytes_written == 0);
  CHECK(mock_transform_do_vio_reenable_count == 0);
  CHECK(mock_cont_call_count == 0);

  TSIOBufferDestroy(data.output_buffer);
}

TEST_CASE("Error path: null input_vio during uninitialized state", "[error-path][null-vio]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = nullptr;
  mock_output_vconn = reinterpret_cast<void *>(0xCCCC);

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Should return early before init — not even attempt to initialize
  CHECK(data.initialized == false);
  CHECK(mock_transform_do_vio_reenable_count == 0);
}

// ─── EP4: VConn close when errored with fully initialized output ────────────

TEST_CASE("Error path: VConn close with errored + initialized state", "[error-path][vconn-closed]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = true; // previously errored
  data->initialized   = true;
  data->scanner       = new HtmlScanner(64 * 1024, 20, nullptr);
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();
  data->output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data->output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data->bytes_written = 500;

  mock_cont_data              = data;
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_COMPLETE, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);
}

// ─── EP5: Scanner feed with zero-length and negative-length data ────────────

TEST_CASE("Error path: scanner feed with zero-length data", "[error-path][scanner]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);

  // Zero length should be a no-op, not crash
  scanner.feed("some data", 0);
  CHECK(scanner.is_done() == false);
  CHECK(scanner.get_links().empty());
}

TEST_CASE("Error path: scanner feed with negative length", "[error-path][scanner]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);

  // Negative length should be safe (no crash)
  scanner.feed("some data", -1);
  CHECK(scanner.is_done() == false);
  CHECK(scanner.get_links().empty());
}

TEST_CASE("Error path: scanner feed with null data pointer", "[error-path][scanner]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);

  // Null data with positive length — should not crash
  // (In practice, length 0 prevents any access)
  scanner.feed(nullptr, 0);
  CHECK(scanner.is_done() == false);
  CHECK(scanner.get_links().empty());
}

// ─── EP6: TSIOBufferCopy returns negative → fallback path ───────────────────

TEST_CASE("Error path: TSIOBufferCopy returns negative uses fallback", "[error-path][copy-fail]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  mock_cont_data              = &data;
  mock_vconn_closed           = 0;
  mock_input_vio              = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer             = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo_use_computed = true;
  mock_vio_nbytes_total       = 200;
  mock_vio_ndone              = 0;
  mock_vio_reader             = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail           = 100;
  mock_iobuffer_copy_return   = -1; // default = return nbytes (success)
  mock_reader_consumed        = 0;

  // Override: simulate copy returning -5 (error)
  mock_iobuffer_copy_return = -5;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Copy error path (R10-01): errored set, input consumed, output VIO finalized
  CHECK(data.errored == true);
  CHECK(data.bytes_written == 0);                   // no bytes successfully written
  CHECK(mock_reader_consumed == 100);               // avail bytes consumed to prevent stall
  CHECK(mock_vio_nbytes_set == 0);                  // output VIO finalized with bytes_written (0)
  CHECK(mock_transform_do_vio_reenable_count == 1); // output VIO reenabled

  TSIOBufferDestroy(data.output_buffer);
}

// ─── EP7: Full lifecycle: ERROR → WRITE_READY → WRITE_COMPLETE → close ─────

TEST_CASE("Error path: full lifecycle ERROR → blocked → close", "[error-path][lifecycle]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = false;
  data->scanner       = nullptr;
  data->cache         = nullptr;

  mock_cont_data    = data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_output_vconn = reinterpret_cast<void *>(0xCCCC);

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // 1. ERROR arrives
  early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);
  CHECK(data->errored == true);

  // 2. WRITE_READY arrives (stale event) — blocked by errored flag
  mock_cont_call_count                 = 0;
  mock_transform_do_vio_reenable_count = 0;
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(mock_transform_do_vio_reenable_count == 0);

  // 3. WRITE_COMPLETE arrives
  mock_vconn_shutdown_called = 0;
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_COMPLETE, nullptr);
  CHECK(mock_vconn_shutdown_called == 1);

  // 4. VConn closes — cleanup
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  int ret = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  // output_buffer was never created (errored before init) — no destroy
  CHECK(mock_iobuffer_destroy_count == 0);
}

// ─── EP8: VConn close mid-stream with partial data ──────────────────────────

TEST_CASE("Error path: VConn close mid-stream with bytes_written", "[error-path][vconn-closed]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner *scanner = new HtmlScanner(64 * 1024, 20, &config);
  HintsCache cache;

  // Pre-feed scanner
  const char *html = "<html><head><link rel=\"stylesheet\" href=\"/mid.css\">";
  scanner->feed(html, static_cast<int64_t>(strlen(html)));

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = scanner;
  data->cache         = &cache;
  data->cache_key     = "/mid-stream";
  data->output_buffer = TSIOBufferCreate();
  data->output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data->output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data->bytes_written = 2048; // partial data already processed
  data->cache_written = false;

  mock_cont_data              = data;
  mock_vconn_closed           = 1; // VConn closed unexpectedly
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);

  // Cache was NOT written (incomplete stream — scanner had links but VConn closed)
  // The cache_written flag stays false — learned links are properly discarded
  std::vector<std::string> cached_links;
  bool found = cache.get("/mid-stream", cached_links, 1);
  CHECK(found == false);
}

// ─── EP9: Config init failure leaves object in safe-to-destruct state ───────

TEST_CASE("Error path: config init failure is safe to destruct", "[error-path][config]")
{
  SECTION("invalid mode string")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from_url", "to_url", "--mode", "invalid_mode"};
    bool ok            = config.init(4, argv);
    CHECK(ok == false);
    // config destructor runs here — must not crash
  }

  SECTION("invalid numeric option")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from_url", "to_url", "--max-links", "not_a_number"};
    bool ok            = config.init(4, argv);
    CHECK(ok == false);
    // Partially parsed — mode_ still at default, max_links_ unchanged
    // Destructor safe
  }

  SECTION("out of range option")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from_url", "to_url", "--max-links", "999"};
    bool ok            = config.init(4, argv);
    CHECK(ok == false);
    // Default state for other fields preserved
  }

  SECTION("manual mode without links")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from_url", "to_url", "--mode", "manual"};
    bool ok            = config.init(4, argv);
    CHECK(ok == false);
    // Validation catches missing --link but mode_ was already set
    // Destructor is still safe
  }

  SECTION("partial parse with valid then invalid")
  {
    EarlyHintsConfig config;
    const char *argv[] = {"from_url", "to_url", "--max-links", "5", "--header-size-limit", "garbage"};
    bool ok            = config.init(6, argv);
    CHECK(ok == false);
    // max_links_ was set to 5, header-size-limit parse failed
    CHECK(config.max_links() == 5);
    // Destructor runs — no leak
  }
}

// ─── EP10: ERROR event with null input_vio skips downstream signal ──────────

TEST_CASE("Error path: ERROR with null input_vio does not hang transaction", "[error-path][error]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = true;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = nullptr; // No input VIO available

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);

  CHECK(ret == 0);
  CHECK(data.errored == true);
  // No TSContCall since input_vio is null — can't propagate, but flag is set
  CHECK(mock_cont_call_count == 0);
  // Subsequent WRITE_READY should be blocked by errored flag
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(mock_transform_do_vio_reenable_count == 0);
}

// ─── EP11: transform_do called with errored=true and valid data paths ───────

TEST_CASE("Error path: transform_do with errored skips all processing paths", "[error-path][errored]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);
  HintsCache cache;

  TransformData data;
  data.errored       = true; // pre-errored
  data.initialized   = true;
  data.scanner       = &scanner;
  data.cache         = &cache;
  data.cache_key     = "/should-not-write";
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;
  data.cache_written = false;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo    = 500;
  mock_vio_reader   = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail = 200;

  const char *html    = "<html><head><link rel=\"stylesheet\" href=\"/skip.css\"></head>";
  mock_block_data     = html;
  mock_block_data_len = static_cast<int64_t>(strlen(html));

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // errored=true → early return, no processing at all
  CHECK(data.bytes_written == 0);
  CHECK(data.cache_written == false);
  CHECK(mock_transform_do_vio_reenable_count == 0);
  CHECK(mock_cont_call_count == 0);
  CHECK(scanner.get_links().empty()); // scanner never fed

  data.scanner = nullptr;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── EP12: VConn close with output_reader but null output_buffer ────────────

TEST_CASE("Error path: VConn close output_reader set but output_buffer null", "[error-path][vconn-closed]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = nullptr;
  data->cache         = nullptr;
  data->output_buffer = nullptr; // somehow null
  data->output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data->output_vio    = reinterpret_cast<TSVIO>(0x5678);

  mock_cont_data              = data;
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 0); // null buffer → no destroy call
}

// ─── EP13: WRITE_COMPLETE with null output_conn then VConn close ────────────

TEST_CASE("Error path: WRITE_COMPLETE null output then VConn close", "[error-path][lifecycle]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = nullptr;
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();

  mock_cont_data    = data;
  mock_vconn_closed = 0;
  mock_output_vconn = nullptr; // null output conn

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // WRITE_COMPLETE with null output_conn — skips shutdown, no crash
  mock_vconn_shutdown_called = 0;
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_COMPLETE, nullptr);
  CHECK(mock_vconn_shutdown_called == 0);

  // Then VConn closes — full cleanup
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  int ret = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);
}

// ─── EP14: Scanner feed after reset — verifies no stale state ───────────────

TEST_CASE("Error path: scanner feed after reset has no stale state", "[error-path][scanner]")
{
  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);

  // First scan finds links
  const char *html1 = "<html><head><link rel=\"stylesheet\" href=\"/a.css\"></head>";
  scanner.feed(html1, static_cast<int64_t>(strlen(html1)));
  CHECK(scanner.get_links().size() == 1);
  CHECK(scanner.is_done() == true);

  // Reset and scan again — no stale links from first scan
  scanner.reset();
  CHECK(scanner.get_links().empty());
  CHECK(scanner.is_done() == false);

  const char *html2 = "<html><head><link rel=\"stylesheet\" href=\"/b.css\"></head>";
  scanner.feed(html2, static_cast<int64_t>(strlen(html2)));
  CHECK(scanner.get_links().size() == 1);
  // Should be /b.css, not /a.css
  CHECK(scanner.get_links()[0].find("/b.css") != std::string::npos);
}

// ─── EP15: Multiple VConn close events (idempotency) ────────────────────────

TEST_CASE("Error path: second VConn close event after cleanup", "[error-path][vconn-closed]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = nullptr;
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();

  mock_cont_data              = data;
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // First close — cleans up
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);

  // After first close, data was freed and TSContDestroy was called.
  // In real ATS, the cont would be destroyed so no second event arrives.
  // But verify the handler doesn't double-free if data is null:
  mock_cont_data              = nullptr;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  int ret = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(ret == 0);
  CHECK(mock_cont_destroy_count == 1);     // cont destroyed again (in real ATS, impossible)
  CHECK(mock_iobuffer_destroy_count == 0); // no buffer to destroy
}

// ─── EP16: Cache put with empty key ─────────────────────────────────────────

TEST_CASE("Error path: cache put with empty key is safe", "[error-path][cache]")
{
  HintsCache cache;
  std::vector<std::string> links = {"</style.css>; rel=preload; as=style"};

  // Empty key should not crash
  cache.put("", links);
  CHECK(cache.size() == 1);

  // Retrievable
  std::vector<std::string> out;
  bool found = cache.get("", out, 1);
  CHECK(found == true);
  CHECK(out.size() == 1);
}

TEST_CASE("Error path: cache put with empty links is safe", "[error-path][cache]")
{
  HintsCache cache;
  std::vector<std::string> empty_links;

  // Empty links should not crash
  cache.put("/empty", empty_links);
  CHECK(cache.size() == 1);

  // Retrievable but empty
  std::vector<std::string> out;
  bool found = cache.get("/empty", out, 1);
  CHECK(found == true);
  CHECK(out.empty());
}

// ─── EP17: transform_do with null input_vio via full event handler ──────────

TEST_CASE("Error path: WRITE_READY with null input_vio via event handler", "[error-path][null-vio]")
{
  reset_mocks();

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = nullptr;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = nullptr; // null input VIO

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  int ret           = early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(ret == 0);
  CHECK(data.bytes_written == 0);
  CHECK(mock_transform_do_vio_reenable_count == 0);

  TSIOBufferDestroy(data.output_buffer);
}

// ─── EP18: HintsCache make_key edge cases ───────────────────────────────────

TEST_CASE("Error path: HintsCache make_key null and edge inputs", "[error-path][cache]")
{
  // null path
  CHECK(HintsCache::make_key(nullptr, 0) == "/");
  CHECK(HintsCache::make_key(nullptr, 10) == "/");

  // zero length
  CHECK(HintsCache::make_key("/test", 0) == "/");

  // negative length
  CHECK(HintsCache::make_key("/test", -1) == "/");

  // path with query string stripped
  CHECK(HintsCache::make_key("/page?q=1", 9) == "/page");
}

// ─── Bug: scanner re-feed on partial TSIOBufferCopy ─────────────────────────
//
// When TSIOBufferCopy returns fewer bytes than avail, the scanner must only
// be fed the bytes that are actually consumed. Otherwise, next iteration
// re-reads unconsumed bytes from the reader, re-feeding them to the scanner,
// corrupting its streaming HTML parse state.

TEST_CASE("Transform: partial copy must limit scanner feed to copied bytes", "[transform][partial-copy][scanner][regression]")
{
  reset_mocks();

  EarlyHintsConfig config;
  HtmlScanner scanner(64 * 1024, 20, &config);

  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.scanner       = &scanner;
  data.cache         = nullptr;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);
  data.bytes_written = 0;
  data.cache_written = false;

  // HTML with a complete link tag — 56 bytes total
  const char *html = "<html><head><link rel=\"stylesheet\" href=\"/a.css\"></head>";
  int64_t html_len = static_cast<int64_t>(strlen(html));

  mock_cont_data              = &data;
  mock_vconn_closed           = 0;
  mock_input_vio              = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer             = reinterpret_cast<void *>(0xAAAA);
  mock_vio_ntodo_use_computed = true;
  mock_vio_nbytes_total       = html_len + 1000; // plenty more to come
  mock_vio_ndone              = 0;
  mock_vio_reader             = reinterpret_cast<void *>(0xCCCC);
  mock_reader_avail           = html_len;
  mock_block_data             = html;
  mock_block_data_len         = html_len;

  // TSIOBufferCopy returns only 20 of html_len bytes (partial copy)
  mock_iobuffer_copy_return = 20;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // Only 20 bytes were consumed — scanner must NOT have seen the full HTML.
  // With 20 bytes ("<html><head><link re"), the link tag is incomplete,
  // so no links should be found and scanner should NOT be done.
  CHECK(data.bytes_written == 20);
  CHECK(scanner.get_links().size() == 0);
  CHECK(scanner.is_done() == false);

  data.scanner = nullptr;
  TSIOBufferDestroy(data.output_buffer);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Lifetime audit TDD tests
// ═══════════════════════════════════════════════════════════════════════════════

// ─── LIFETIME BUG #1: Stale cont-data pointer after cleanup ─────────────────
//
// After the VConn-closed cleanup path frees TransformData, TSContDataSet(contp,
// nullptr) is never called. If ATS delivers a queued event to the continuation
// between TSfree(data) and TSContDestroy(contp) completing, TSContDataGet
// returns a dangling pointer → use-after-free.
//
// This test asserts that after cleanup, TSContDataGet returns nullptr.

TEST_CASE("Lifetime: cont-data is nulled after VConn-closed cleanup", "[lifetime][use-after-free]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = nullptr;
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();

  mock_cont_data    = data;
  mock_vconn_closed = 1;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  // After cleanup, cont data MUST be null to prevent use-after-free
  // if the handler is re-entered before TSContDestroy completes.
  CHECK(mock_cont_data == nullptr);
}

// ─── LIFETIME BUG #1b: Double VConn-closed must not crash ───────────────────
//
// If two events arrive after VConn close (race), the second call must see
// null data and skip cleanup. This depends on bug #1 being fixed.

TEST_CASE("Lifetime: double VConn-closed does not double-free", "[lifetime][double-free]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = new HtmlScanner(1024, 10, nullptr);
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();

  mock_cont_data              = data;
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // First close — should clean up everything
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);

  // Second close — data must be null, so cleanup is skipped (no double-free)
  // This will crash or fail if bug #1 is not fixed.
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);
  CHECK(mock_cont_destroy_count == 2);     // cont destroyed again (idempotent)
  CHECK(mock_iobuffer_destroy_count == 1); // buffer NOT destroyed again
}

// ─── LIFETIME BUG #2: scanner not nulled after delete ───────────────────────
//
// In the cleanup path, `delete data->scanner` frees the scanner but the
// pointer remains non-null. If anything accesses data->scanner between
// delete and TSfree(data), it's a use-after-free. Best practice: null it.
// This test verifies the scanner pointer is nulled (or data is nulled).

TEST_CASE("Lifetime: scanner pointer is safe after VConn-closed cleanup", "[lifetime][scanner]")
{
  reset_mocks();

  EarlyHintsConfig config;
  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = new HtmlScanner(1024, 10, &config);
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();

  mock_cont_data    = data;
  mock_vconn_closed = 1;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  // After cleanup, cont data must be null (scanner is inside freed memory,
  // so we can't inspect it — but the null data check prevents access).
  CHECK(mock_cont_data == nullptr);
}

// ─── LIFETIME: uninitialized TransformData cleanup (never triggered) ────────
//
// If the transform VConn closes before any event triggers initialization,
// output_buffer is still nullptr. Cleanup must handle this gracefully.

TEST_CASE("Lifetime: cleanup of never-initialized TransformData", "[lifetime][never-init]")
{
  reset_mocks();

  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  // All defaults: initialized=false, output_buffer=nullptr, scanner=nullptr

  mock_cont_data              = data;
  mock_vconn_closed           = 1;
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 0); // no buffer to destroy
  CHECK(mock_cont_data == nullptr);        // data pointer nulled
}

// ─── LIFETIME: ERROR then VConn-close must not leak ─────────────────────────
//
// ERROR sets errored=true but does not free anything. The subsequent
// VConn-close must still perform full cleanup.

TEST_CASE("Lifetime: ERROR followed by VConn-close cleans up fully", "[lifetime][error-then-close]")
{
  reset_mocks();

  EarlyHintsConfig config;
  void *buf           = TSmalloc(sizeof(TransformData));
  TransformData *data = new (buf) TransformData();
  data->errored       = false;
  data->initialized   = true;
  data->scanner       = new HtmlScanner(1024, 10, &config);
  data->cache         = nullptr;
  data->output_buffer = TSIOBufferCreate();

  mock_cont_data              = data;
  mock_vconn_closed           = 0; // not closed yet
  mock_input_vio              = reinterpret_cast<void *>(0xDEAD);
  mock_cont_destroy_count     = 0;
  mock_iobuffer_destroy_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // Step 1: ERROR event — sets errored flag, does NOT free
  early_hints_transform(fake_contp, TS_EVENT_ERROR, nullptr);
  CHECK(mock_cont_destroy_count == 0);     // not destroyed yet
  CHECK(mock_iobuffer_destroy_count == 0); // not freed yet

  // Step 2: VConn closes — must perform full cleanup despite errored=true
  mock_vconn_closed = 1;
  early_hints_transform(fake_contp, TS_EVENT_VCONN_WRITE_READY, nullptr);

  CHECK(mock_cont_destroy_count == 1);
  CHECK(mock_iobuffer_destroy_count == 1);
  CHECK(mock_cont_data == nullptr); // data pointer nulled
}

// ═══════════════════════════════════════════════════════════════════════════════
// R10 TDD RED Tests — Phase 4
// ═══════════════════════════════════════════════════════════════════════════════

// ─── R10-01: TSIOBufferCopy error path must finalize output VIO ─────────────
//
// BUG: When TSIOBufferCopy returns 0 for non-zero avail, the code sets
// errored=true and consumes input (R9-11 fix), but does NOT finalize the output
// VIO. The output VIO still expects INT64_MAX bytes, so the downstream
// transform/HttpSM stalls until transaction timeout.
//
// The normal completion paths (EOS at line 397 and toread<=0 at line 405) both
// call TSVIONBytesSet + TSVIOReenable. The error path must do the same.

TEST_CASE("R10-01: copy error path must finalize output VIO to prevent downstream stall", "[r10][error-path]")
{
  reset_mocks();

  // Set up an initialized TransformData with output buffers
  TransformData data;
  data.errored       = false;
  data.initialized   = true;
  data.bytes_written = 42; // simulate 42 bytes already written before error
  data.scanner       = new HtmlScanner(64 * 1024, 20, nullptr);
  data.cache         = nullptr;
  data.cache_key     = "/test";
  data.cache_written = false;
  data.output_buffer = TSIOBufferCreate();
  data.output_reader = reinterpret_cast<TSIOBufferReader>(0xBBBB);
  data.output_vio    = reinterpret_cast<TSVIO>(0x5678);

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_vio_buffer   = reinterpret_cast<void *>(0xAABB); // non-null = data available
  mock_vio_reader   = reinterpret_cast<void *>(0xCCDD);
  mock_reader_avail = 500;
  mock_vio_ndone    = 0;

  mock_vio_ntodo_use_computed = true;
  mock_vio_nbytes_total       = 2000;

  // Force TSIOBufferCopy to return 0 → triggers error path
  mock_iobuffer_copy_return            = 0;
  mock_reader_consumed                 = 0;
  mock_vio_nbytes_set                  = -1; // sentinel: not yet called
  mock_transform_do_vio_reenable_count = 0;

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);
  early_hints_transform_do(fake_contp);

  // R9-11 assertions still hold:
  CHECK(data.errored == true);
  CHECK(mock_reader_consumed == 500);

  // R10-01: output VIO MUST be finalized so downstream doesn't stall.
  // TSVIONBytesSet should be called with bytes_written (42) to tell downstream
  // "this is all you're getting", and TSVIOReenable must wake up downstream.
  CHECK(mock_vio_nbytes_set == 42);
  CHECK(mock_transform_do_vio_reenable_count >= 1);

  delete data.scanner;
  TSIOBufferDestroy(data.output_buffer);
}

// ─── R10-03: Transform init failure must set errored to prevent retry loop ──
//
// BUG: When transform initialization fails (e.g., null output_conn from
// TSTransformOutputVConnGet), the function returns without setting errored=true.
// On the next callback, !data->errored passes, !data->initialized passes, and
// init is retried — creating a futile retry loop on every callback until the
// transaction times out.

TEST_CASE("R10-03: init failure with null output_conn must set errored flag", "[r10][init-fail]")
{
  reset_mocks();

  TransformData data;
  data.errored     = false;
  data.initialized = false;
  data.scanner     = nullptr;
  data.cache       = nullptr;

  mock_cont_data    = &data;
  mock_vconn_closed = 0;
  mock_input_vio    = reinterpret_cast<void *>(0xDEAD);
  mock_output_vconn = nullptr; // Force init failure: no output VConn

  TSCont fake_contp = reinterpret_cast<TSCont>(0x1234);

  // First call: init fails because output_conn is null
  early_hints_transform_do(fake_contp);
  CHECK(data.initialized == false); // init didn't succeed — expected

  // BUG: errored should be true to prevent futile retry loop.
  // Current code returns without setting errored, so this WILL FAIL (RED).
  CHECK(data.errored == true);
}

// =============================================================================
// R11 Tests
// =============================================================================

TEST_CASE("R11-02: add_link_headers_to_response should skip oversized links like send_103", "[r11]")
{
  // Setup: 3 links where the 2nd exceeds size limit but the 3rd fits.
  // send_103_response uses `continue` (skips oversized, tries rest) — correct.
  // add_link_headers_to_response uses `break` (stops entirely) — inconsistent BUG.
  std::vector<std::string> links;
  links.push_back("<https://a.com/s.js>; rel=preload; as=script"); // ~47 chars → entry_len = 55
  // Construct a link that pushes total over limit (150+ chars)
  links.push_back(
    "<https://cdn.example.com/assets/very/deeply/nested/path/to/some/large/javascript/bundle/main.min.js>; rel=preload; as=script");
  links.push_back("<https://a.com/t.css>; rel=preload; as=style"); // ~46 chars → entry_len = 54

  // Calculate: link1 entry_len = 6 + 47 + 2 = 55
  // link2 entry_len = 6 + 123 + 2 = 131
  // link3 entry_len = 6 + 46 + 2 = 54
  // header_size_limit = 120: link1 (55) fits, link1+link2 (55+131=186 > 120) oversized,
  //                           link1+link3 (55+54=109 < 120) fits
  int header_size_limit = 120;

  mock_field_append_count = 0;
  TSMBuffer bufp          = reinterpret_cast<TSMBuffer>(0x1234);
  TSMLoc hdr_loc          = reinterpret_cast<TSMLoc>(0x5678);

  add_link_headers_to_response(bufp, hdr_loc, links, 50, header_size_limit);

  // With `continue` (consistent with send_103): link1 + link3 = 2 fields
  // With `break` (current bug): stops at link2 → only link1 = 1 field
  REQUIRE(mock_field_append_count == 2);
}

TEST_CASE("R11-02: send_103 and add_link_headers produce same link count for mixed sizes", "[r11]")
{
  // Verify that both functions produce the same count when given identical inputs.
  std::vector<std::string> links;
  links.push_back("<https://a.com/small.js>; rel=preload; as=script");
  links.push_back(
    "<https://cdn.example.com/assets/very/deeply/nested/path/to/some/large/javascript/bundle/main.min.js>; rel=preload; as=script");
  links.push_back("<https://a.com/tiny.css>; rel=preload; as=style");

  int header_size_limit = 130;
  int max_links         = 50;

  // Count links from send_103_response (uses continue — correct)
  mock_send_early_hints_rc          = TS_SUCCESS;
  mock_send_early_hints_count       = 0;
  mock_send_early_hints_last_nlinks = 0;
  TSHttpTxn fake_txn                = reinterpret_cast<TSHttpTxn>(0xBEEF);
  send_103_response(fake_txn, links, max_links, header_size_limit);
  int send_103_count = mock_send_early_hints_last_nlinks;

  // Count links from add_link_headers_to_response (uses break — BUG)
  mock_field_append_count = 0;
  TSMBuffer bufp          = reinterpret_cast<TSMBuffer>(0x1234);
  TSMLoc hdr_loc          = reinterpret_cast<TSMLoc>(0x5678);
  add_link_headers_to_response(bufp, hdr_loc, links, max_links, header_size_limit);
  int add_headers_count = mock_field_append_count;

  // Both should produce the same number of links — this WILL FAIL (RED)
  REQUIRE(send_103_count == add_headers_count);
}
