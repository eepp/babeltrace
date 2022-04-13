# SPDX-License-Identifier: MIT

SUBDIRS = metadata bfcr msg-iter

noinst_LTLIBRARIES = libbabeltrace2-plugin-ctf-common-src.la
libbabeltrace2_plugin_ctf_common_src_la_SOURCES = ctf-common-src.cpp
libbabeltrace2_plugin_ctf_common_src_la_LIBADD =	\
	$(builddir)/metadata/tsdl/libctf-parser.la	\
	$(builddir)/metadata/tsdl/libctf-ast.la		\
	$(builddir)/bfcr/libctf-bfcr.la			\
	$(builddir)/msg-iter/libctf-msg-iter.la
