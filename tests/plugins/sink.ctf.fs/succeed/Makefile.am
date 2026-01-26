# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

EXTRA_DIST = \
	test_succeed_sink_ctf.py \
	trace-double-ctf1.expect \
	trace-double-ctf2.expect \
	trace-float-ctf1.expect \
	trace-float-ctf2.expect \
	trace-meta-variant-no-underscore-ctf1.expect \
	trace-meta-variant-one-underscore-ctf1.expect \
	trace-meta-variant-reserved-keywords-ctf1.expect \
	trace-meta-variant-same-with-underscore-ctf1.expect \
	trace-meta-variant-two-underscores-ctf1.expect

# CTF trace generators
GEN_TRACE_LDADD = \
	$(top_builddir)/src/ctf-writer/libbabeltrace2-ctf-writer.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/logging/liblogging.la

gen_trace_float_SOURCES = gen-trace-float.c
gen_trace_float_LDADD = $(GEN_TRACE_LDADD)
gen_trace_double_SOURCES = gen-trace-double.c
gen_trace_double_LDADD = $(GEN_TRACE_LDADD)

noinst_PROGRAMS = \
	gen-trace-float \
	gen-trace-double
