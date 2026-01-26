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
	bins/i386-linux-gnu/build-id/.build-id/cd/d98cdd87f7fe64c13b6daad553987eafd40cbb.debug \
	bins/i386-linux-gnu/build-id/libhello-so \
	bins/i386-linux-gnu/debug-link/libhello-so \
	bins/i386-linux-gnu/debug-link/libhello-so.debug \
	bins/i386-linux-gnu/dwarf-full/libhello-so \
	bins/i386-linux-gnu/elf-only/libhello-so \
	bins/libhello.c \
	bins/libhello.h \
	bins/main.c \
	bins/Makefile \
	bins/powerpc-linux-gnu/build-id/.build-id/cd/d98cdd87f7fe64c13b6daad553987eafd40cbb.debug \
	bins/powerpc-linux-gnu/build-id/libhello-so \
	bins/powerpc-linux-gnu/debug-link/libhello-so \
	bins/powerpc-linux-gnu/debug-link/libhello-so.debug \
	bins/powerpc-linux-gnu/dwarf-full/libhello-so \
	bins/powerpc-linux-gnu/elf-only/libhello-so \
	bins/powerpc64le-linux-gnu/build-id/.build-id/cd/d98cdd87f7fe64c13b6daad553987eafd40cbb.debug \
	bins/powerpc64le-linux-gnu/build-id/libhello-so \
	bins/powerpc64le-linux-gnu/debug-link/libhello-so \
	bins/powerpc64le-linux-gnu/debug-link/libhello-so.debug \
	bins/powerpc64le-linux-gnu/dwarf-full/libhello-so \
	bins/powerpc64le-linux-gnu/elf-only/libhello-so \
	bins/README.md \
	bins/tp.c \
	bins/tp.h \
	bins/x86-64-linux-gnu/build-id/.build-id/cd/d98cdd87f7fe64c13b6daad553987eafd40cbb.debug \
	bins/x86-64-linux-gnu/build-id/libhello-so \
	bins/x86-64-linux-gnu/debug-link/libhello-so \
	bins/x86-64-linux-gnu/debug-link/libhello-so.debug \
	bins/x86-64-linux-gnu/dwarf-full/libhello-so \
	bins/x86-64-linux-gnu/elf-only/libhello-so \
	test_bin_info.py \
	test_dwarf.py \
	test_succeed_debug_info.py \
	trace-debug-info-mip0.expect \
	trace-debug-info-mip1.expect
