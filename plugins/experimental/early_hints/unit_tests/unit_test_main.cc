/** @file
 * Catch2 main + ATS API mocks for test_early_hints binary.
 *
 * Provides mock implementations of TSMutex, TSmalloc/TSfree, TSDebug, TSError,
 * TSStatCreate, TSStatIntIncrement used by config.cc, hints_cache.cc, html_scanner.cc.
 *
 * @section license License
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements.  See the NOTICE file for additional information.
 */

#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <atomic>
#include <pthread.h>

// Track TSMutexDestroy calls for destructor verification tests
std::atomic<int> g_mutex_destroy_count{0};

extern "C" {

// ─── Memory management ──────────────────────────────────────────────────────

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

// ─── Mutex (real pthreads for thread-safety tests) ──────────────────────────

typedef void *TSMutex;

TSMutex
TSMutexCreate()
{
  auto *m = new pthread_mutex_t;
  pthread_mutex_init(m, nullptr);
  return static_cast<TSMutex>(m);
}

void
TSMutexLock(TSMutex mutexp)
{
  pthread_mutex_lock(static_cast<pthread_mutex_t *>(mutexp));
}

void
TSMutexUnlock(TSMutex mutexp)
{
  pthread_mutex_unlock(static_cast<pthread_mutex_t *>(mutexp));
}

void
TSMutexDestroy(TSMutex mutexp)
{
  g_mutex_destroy_count++;
  pthread_mutex_destroy(static_cast<pthread_mutex_t *>(mutexp));
  delete static_cast<pthread_mutex_t *>(mutexp);
}

// ─── Debug / Error logging (no-op) ─────────────────────────────────────────

void
TSDebug(const char * /* tag */, const char * /* fmt */, ...)
{
}

void
TSError(const char * /* fmt */, ...)
{
}

// _TSAssert is used by TSAssert() macro in production ATS code.
// In unit tests, delegate to abort() so the assertion fires visibly
// rather than crashing with an unresolved symbol.
void
_TSAssert(const char *text, const char *file, int line)
{
  fprintf(stderr, "TSAssert failed: %s at %s:%d\n", text, file, line);
  abort();
}

// ─── Stats (mock) ───────────────────────────────────────────────────────────

int
TSStatCreate(const char * /* name */, int /* type */, int /* persist */, int /* sync */)
{
  static int counter = 0;
  return counter++;
}

void
TSStatIntIncrement(int /* id */, int64_t /* amount */)
{
}

} // extern "C"
