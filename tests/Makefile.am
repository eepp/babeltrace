# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

SUBDIRS = \
	utils \
	lib \
	bitfield \
	ctf-writer \
	plugins \
	param-validation \
	python-plugin-provider

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

COMMON_TEST_LDADD = \
	$(top_builddir)/tests/utils/tap/libtap.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/logging/liblogging.la

# Directories added to EXTRA_DIST will be recursively copied to the distribution.
EXTRA_DIST = $(srcdir)/data \
	     bindings/python/bt2/.coveragerc \
	     conftest.py \
	     bindings/python/bt2/pytest_interrupter.py

dist_check_SCRIPTS = \
	bindings/python/bt2/test-python-bt2.sh \
	bindings/python/bt2/test_clock_class.py \
	bindings/python/bt2/test_component.py \
	bindings/python/bt2/test_component_class.py \
	bindings/python/bt2/test_connection.py \
	bindings/python/bt2/test_event.py \
	bindings/python/bt2/test_event_class.py \
	bindings/python/bt2/test_field.py \
	bindings/python/bt2/test_field_class.py \
	bindings/python/bt2/test_graph.py \
	bindings/python/bt2/test_integer_range_set.py \
	bindings/python/bt2/test_message.py \
	bindings/python/bt2/test_message_iterator.py \
	bindings/python/bt2/test_mip1.py \
	bindings/python/bt2/test_package.py \
	bindings/python/bt2/test_packet.py \
	bindings/python/bt2/test_plugin.py \
	bindings/python/bt2/test_port.py \
	bindings/python/bt2/test_query_executor.py \
	bindings/python/bt2/test_stream.py \
	bindings/python/bt2/test_stream_class.py \
	bindings/python/bt2/test_trace.py \
	bindings/python/bt2/test_trace_collection_message_iterator.py \
	bindings/python/bt2/test_value.py \
	bindings/python/bt2/utils.py \
	plugins/src.ctf.lttng-live/test-live.sh \
	plugins/src.ctf.lttng-live/test-query.sh \
	plugins/src.ctf.lttng-live/test_query.py \
	pytest-tests.sh \
	pytest-tests-tap.sh

noinst_PROGRAMS =

TESTS_BINDINGS = bindings/python/bt2/test-python-bt2.sh

TESTS_PLUGINS = \
	plugins/src.ctf.fs/succeed/test-succeed.sh \
	plugins/src.ctf.fs/query/test-query-trace-info.sh \
	plugins/src.ctf.fs/query/test-query-metadata-info.sh \
	plugins/src.ctf.fs/query/test-query-metadata-info-py.sh \
	plugins/src.ctf.lttng-live/test-query.sh \
	plugins/src.ctf.lttng-live/test-live.sh \
	plugins/src.ctf.fs/field/test-field.sh

noinst_PROGRAMS += \
	cpp-common/test-c-string-view

cpp_common_test_c_string_view_SOURCES = \
	cpp-common/test-c-string-view.cpp

cpp_common_test_c_string_view_LDADD = \
	$(COMMON_TEST_LDADD)

noinst_PROGRAMS += \
	cpp-common/test-uuid

cpp_common_test_uuid_SOURCES = \
	cpp-common/test-uuid.cpp

cpp_common_test_uuid_LDADD = \
	$(COMMON_TEST_LDADD) \
	$(top_builddir)/src/cpp-common/vendor/fmt/libfmt.la

noinst_PROGRAMS += \
	cpp-common/test-unicode-conv

cpp_common_test_unicode_conv_SOURCES = \
	cpp-common/test-unicode-conv.cpp

cpp_common_test_unicode_conv_LDADD = \
	$(top_builddir)/src/cpp-common/libcpp-common.la \
	$(top_builddir)/src/cpp-common/vendor/fmt/libfmt.la \
	$(top_builddir)/src/lib/libbabeltrace2.la \
	$(COMMON_TEST_LDADD)

if ENABLE_TEST_TAP_OUTPUT
LOG_DRIVER_FLAGS = --merge --comments
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' \
	     BT_TESTS_SRCDIR='$(abs_top_srcdir)/tests' \
	     BT_TESTS_BUILDDIR='$(abs_top_builddir)/tests' \
	     $(SHELL) $(srcdir)/utils/tap-driver.sh
TESTS_PYTEST = pytest-tests-tap.sh
else
LOG_DRIVER = env \
	     BT_TESTS_SRCDIR='$(abs_top_srcdir)/tests' \
	     BT_TESTS_BUILDDIR='$(abs_top_builddir)/tests' \
	     $(SHELL) $(top_srcdir)/config/test-driver
TESTS_PYTEST = pytest-tests.sh
endif

TESTS = \
	$(TESTS_BINDINGS) \
	$(TESTS_PLUGINS) \
	$(TESTS_PYTEST)

define check_target
check-$(1):
	$(MAKE) $(AM_MAKEFLAGS) TESTS="$2" check
endef

$(eval $(call check_target,bindings,$(TESTS_BINDINGS)))
$(eval $(call check_target,plugins,$(TESTS_PLUGINS)))
$(eval $(call check_target,pytest,$(TESTS_PYTEST)))

check-no-bitfield:
	$(MAKE) $(AM_MAKEFLAGS) BT_TESTS_NO_BITFIELD=1 check
