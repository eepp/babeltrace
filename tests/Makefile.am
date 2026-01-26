# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

SUBDIRS = \
	utils \
	lib \
	bitfield \
	cli \
	ctf-writer \
	plugins \
	param-validation \
	python-plugin-provider

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

COMMON_TEST_LDADD = \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/logging/liblogging.la

EXTRA_DIST = $(srcdir)/common-data \
	     bindings/python/bt2/conftest.py \
	     bindings/python/bt2/test_clock_class.py \
	     bindings/python/bt2/test_clock_offset.py \
	     bindings/python/bt2/test_clock_snapshot.py \
	     bindings/python/bt2/test_component_class.py \
	     bindings/python/bt2/test_component_descriptor.py \
	     bindings/python/bt2/test_component.py \
	     bindings/python/bt2/test_connection.py \
	     bindings/python/bt2/test_error.py \
	     bindings/python/bt2/test_event_class.py \
	     bindings/python/bt2/test_event.py \
	     bindings/python/bt2/test_field_class.py \
	     bindings/python/bt2/test_field.py \
	     bindings/python/bt2/test_graph.py \
	     bindings/python/bt2/test_integer_range_set.py \
	     bindings/python/bt2/test_interrupter.py \
	     bindings/python/bt2/test_message_iterator.py \
	     bindings/python/bt2/test_message.py \
	     bindings/python/bt2/test_mip1.py \
	     bindings/python/bt2/test_mip.py \
	     bindings/python/bt2/test_package.py \
	     bindings/python/bt2/test_packet.py \
	     bindings/python/bt2/test_plugin.py \
	     bindings/python/bt2/test_port.py \
	     bindings/python/bt2/test_query_executor.py \
	     bindings/python/bt2/test_stream_class.py \
	     bindings/python/bt2/test_stream.py \
	     bindings/python/bt2/test_trace_class.py \
	     bindings/python/bt2/test_trace_collection_message_iterator.py \
	     bindings/python/bt2/test_trace.py \
	     bindings/python/bt2/test_value.py \
	     bindings/python/bt2/utils.py \
	     conftest.py

noinst_PROGRAMS =

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

# pytest-based test execution
check-local:
	source $(builddir)/utils/env.sh && \
	bt-pytest $${BT_TESTS_PYTEST_EXTRA_ARGS:-} \
		-vv -rA --capture=tee-sys --log-cli-level=INFO "$(srcdir)"
