#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

pkglib_LTLIBRARIES += experimental/early_hints/early_hints.la

experimental_early_hints_early_hints_la_SOURCES = \
  experimental/early_hints/early_hints.cc \
  experimental/early_hints/config.cc \
  experimental/early_hints/hints_cache.cc \
  experimental/early_hints/html_scanner.cc \
  experimental/early_hints/link_parser.cc

check_PROGRAMS += experimental/early_hints/test_early_hints

experimental_early_hints_test_early_hints_CPPFLAGS = \
  $(AM_CPPFLAGS) \
  -I$(abs_top_srcdir)/plugins/experimental/early_hints \
  -I$(abs_top_srcdir)/tests/include

experimental_early_hints_test_early_hints_LDADD = -lpthread

experimental_early_hints_test_early_hints_SOURCES = \
  experimental/early_hints/unit_tests/unit_test_main.cc \
  experimental/early_hints/unit_tests/test_scanner_basic.cc \
  experimental/early_hints/unit_tests/test_scanner_build.cc \
  experimental/early_hints/unit_tests/test_scanner_parser.cc \
  experimental/early_hints/unit_tests/test_scanner_security.cc \
  experimental/early_hints/unit_tests/test_config.cc \
  experimental/early_hints/unit_tests/test_hints_cache.cc \
  experimental/early_hints/unit_tests/test_dos_resistance.cc \
  experimental/early_hints/unit_tests/test_integration.cc \
  experimental/early_hints/unit_tests/test_numeric_safety.cc \
  experimental/early_hints/unit_tests/test_link_parser.cc \
  experimental/early_hints/unit_tests/test_persistence.cc \
  experimental/early_hints/link_parser.cc \
  experimental/early_hints/config.cc \
  experimental/early_hints/hints_cache.cc \
  experimental/early_hints/html_scanner.cc

check_PROGRAMS += experimental/early_hints/test_transform

experimental_early_hints_test_transform_CPPFLAGS = \
  $(AM_CPPFLAGS) \
  -I$(abs_top_srcdir)/plugins/experimental/early_hints \
  -I$(abs_top_srcdir)/tests/include

experimental_early_hints_test_transform_LDADD = -lpthread

experimental_early_hints_test_transform_SOURCES = \
  experimental/early_hints/unit_tests/test_transform_mocks.cc \
  experimental/early_hints/unit_tests/test_transform.cc \
  experimental/early_hints/config.cc \
  experimental/early_hints/hints_cache.cc \
  experimental/early_hints/html_scanner.cc \
  experimental/early_hints/link_parser.cc
