# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(top_srcdir)/src/plugins

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

dist_check_SCRIPTS = \
	test-bin-info-i386-linux-gnu.sh \
	test-bin-info-powerpc64le-linux-gnu.sh \
	test-bin-info-powerpc-linux-gnu.sh \
	test-bin-info-x86-64-linux-gnu.sh \
	test-succeed.sh

noinst_PROGRAMS =

if ENABLE_DEBUG_INFO
noinst_PROGRAMS += dwarf-test test-bin-info

dwarf_test_SOURCES = dwarf-test.cpp
dwarf_test_LDADD = \
	$(top_builddir)/src/plugins/lttng-utils/debug-info/libdebug-info.la \
	$(top_builddir)/src/fd-cache/libfd-cache.la \
	$(top_builddir)/src/logging/liblogging.la \
	$(top_builddir)/src/common/libcommon.la \
	$(ELFUTILS_LIBS)

test_bin_info_LDADD = \
	$(top_builddir)/src/plugins/lttng-utils/debug-info/libdebug-info.la \
	$(top_builddir)/src/fd-cache/libfd-cache.la \
	$(top_builddir)/src/logging/liblogging.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/lib/libbabeltrace2.la \
	$(ELFUTILS_LIBS) \
	$(LIBTAP)
test_bin_info_SOURCES = test-bin-info.cpp
nodist_EXTRA_test_bin_info_SOURCES = dummy.cpp

endif # ENABLE_DEBUG_INFO

EXTRA_DIST = test_dwarf.py
