# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test-ctf-writer

test_ctf_writer_SOURCES = test-ctf-writer.cpp
test_ctf_writer_LDADD = \
	$(top_builddir)/tests/utils/libtestcommon.la \
	$(top_builddir)/src/ctf-writer/libbabeltrace2-ctf-writer.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/logging/liblogging.la


EXTRA_DIST = test_ctf_writer_trace.py
