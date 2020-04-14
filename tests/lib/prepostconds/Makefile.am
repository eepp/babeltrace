# SPDX-License-Identifier: MIT

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

prepostconds_triggers_SOURCES = prepostconds-triggers.c utils.c utils.h
prepostconds_triggers_LDADD = \
	$(top_builddir)/src/common/libbabeltrace2-common.la \
	$(top_builddir)/src/logging/libbabeltrace2-logging.la \
	$(top_builddir)/src/lib/libbabeltrace2.la

noinst_PROGRAMS = prepostconds-triggers

dist_check_SCRIPTS = test_prepostconds test.py
