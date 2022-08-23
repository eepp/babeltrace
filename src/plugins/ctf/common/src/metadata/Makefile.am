# SPDX-License-Identifier: MIT

SUBDIRS = tsdl json

noinst_LTLIBRARIES = libctf-src-metadata.la

libctf_src_metadata_la_SOURCES = \
	ctf-ir.hpp ctf-ir.cpp \
	normalize-clk-offset.hpp normalize-clk-offset.cpp

libctf_src_metadata_la_LIBADD = \
	$(builddir)/tsdl/libctf-parser.la \
	$(builddir)/tsdl/libctf-ast.la \
	$(builddir)/json/libctf-src-metadata-json.la
