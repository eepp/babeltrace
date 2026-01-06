# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(top_srcdir)/src/plugins


noinst_PROGRAMS =

if ENABLE_DEBUG_INFO
noinst_PROGRAMS += dwarf-test bin-info-test

dwarf_test_SOURCES = dwarf-test.cpp
dwarf_test_LDADD = \
	$(top_builddir)/src/plugins/lttng-utils/debug-info/libdebug-info.la \
	$(top_builddir)/src/fd-cache/libfd-cache.la \
	$(top_builddir)/src/logging/liblogging.la \
	$(top_builddir)/src/common/libcommon.la \
	$(ELFUTILS_LIBS)

bin_info_test_SOURCES = bin-info-test.cpp
bin_info_test_LDADD = \
	$(top_builddir)/src/plugins/lttng-utils/debug-info/libdebug-info.la \
	$(top_builddir)/src/fd-cache/libfd-cache.la \
	$(top_builddir)/src/logging/liblogging.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/lib/libbabeltrace2.la \
	$(ELFUTILS_LIBS)

endif # ENABLE_DEBUG_INFO

EXTRA_DIST = \
	test_bin_info.py \
	test_dwarf.py \
	test_succeed_debug_info.py
