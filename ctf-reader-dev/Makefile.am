AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(top_srcdir)/include -I$(builddir)

SUBDIRS = metadata .

bin_PROGRAMS = ctf-reader-dev

ctf_reader_dev_SOURCES = \
	test.c

ctf_reader_dev_LDFLAGS = $(LD_NO_AS_NEEDED)
ctf_reader_dev_LDADD = \
	$(top_builddir)/lib/libbabeltrace.la \
	metadata/libctf-parser.la \
	metadata/libctf-ast.la \
	$(top_builddir)/compat/libcompat.la \
	$(top_builddir)/formats/ctf/ir/libctf-ir.la
