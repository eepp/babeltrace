# SPDX-License-Identifier: MIT

SUBDIRS = metadata bfcr msg-iter item-seq

noinst_LTLIBRARIES = libbabeltrace2-plugin-ctf-common-src.la

libbabeltrace2_plugin_ctf_common_src_la_SOURCES = \
	pkt-props.hpp pkt-props.cpp

libbabeltrace2_plugin_ctf_common_src_la_LIBADD =	\
	$(builddir)/metadata/libctf-src-metadata.la	\
	$(builddir)/bfcr/libctf-bfcr.la			\
	$(builddir)/msg-iter/libctf-msg-iter.la		\
	$(builddir)/item-seq/libctf-src-item-seq.la
