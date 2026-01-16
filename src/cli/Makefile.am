# SPDX-FileCopyrightText: 2019-2024 EfficiOS, Inc.
#
# SPDX-License-Identifier: MIT

# Path to the plugins build directory.
PLUGINS_PATH = $(abs_top_builddir)/src/plugins

# Takes a plugin name and outputs the needed LDFLAGS to embed it.
#
# The --whole-archive option is important here. From the GNU linker's
# documentation:
#
#     For each archive mentioned on the command line after the
#     --whole-archive option, include every object file in the archive in
#     the link, rather than searching the archive for the required object
#     files.
#
# In our case, we find the plugins thanks to special sections in the
# binary that are filled by plugin objects. If the linker discards those
# symbols because the CLI does not use them directly, the CLI reports
# no plugins found (plugins are effectively not embedded).
plugin_archive_builtin = $(LD_WHOLE_ARCHIVE)$(PLUGINS_PATH)/$(1)/.libs/libbabeltrace-plugin-$(1)-builtin.a$(LD_NO_WHOLE_ARCHIVE)

LTTNG_UTILS_PLUGIN_PATH =

if ENABLE_DEBUG_INFO
LTTNG_UTILS_PLUGIN_PATH += :$(PLUGINS_PATH)/lttng-utils
endif

if BABELTRACE_BUILD_WITH_MINGW
IN_TREE_PLUGIN_PATH := $(shell cygpath -pm "$(PLUGINS_PATH)/ctf:$(PLUGINS_PATH)/text:$(PLUGINS_PATH)/utils$(LTTNG_UTILS_PLUGIN_PATH)")
else
IN_TREE_PLUGIN_PATH = $(PLUGINS_PATH)/ctf:$(PLUGINS_PATH)/text:$(PLUGINS_PATH)/utils$(LTTNG_UTILS_PLUGIN_PATH)
endif

AM_CPPFLAGS += '-DCONFIG_IN_TREE_PLUGIN_PATH="$(IN_TREE_PLUGIN_PATH)"'

if ENABLE_PYTHON_PLUGINS
AM_CPPFLAGS += '-DCONFIG_IN_TREE_PROVIDER_DIR="$(abs_top_builddir)/src/python-plugin-provider/.libs"'
endif

bin_PROGRAMS = babeltrace2
noinst_PROGRAMS = babeltrace2-for-tests

babeltrace2_SOURCES = \
	babeltrace2.c \
	babeltrace2-cfg.c \
	babeltrace2-cfg.h \
	babeltrace2-cfg-cli-args.c \
	babeltrace2-cfg-cli-args.h \
	babeltrace2-cfg-cli-args-connect.c \
	babeltrace2-cfg-cli-args-connect.h \
	babeltrace2-cfg-cli-args-default.h \
	babeltrace2-cfg-cli-args-default.c \
	babeltrace2-log-level.c \
	babeltrace2-log-level.h \
	babeltrace2-plugins.c \
	babeltrace2-plugins.h \
	babeltrace2-query.c \
	babeltrace2-query.h \
	logging.cpp \
	logging.h

# -Wl,--no-as-needed is needed for recent gold linker who seems to think
# it knows better and considers libraries with constructors having
# side-effects as dead code.
babeltrace2_LDFLAGS = $(AM_LDFLAGS) $(LD_NO_AS_NEEDED)

EXTRA_babeltrace2_DEPENDENCIES =

# Libraries needed by the CLI itself.
babeltrace2_LDADD = \
	$(top_builddir)/src/argpar/libargpar.la \
	$(top_builddir)/src/autodisc/libautodisc.la \
	$(top_builddir)/src/param-parse/libparam-parse.la \
	$(top_builddir)/src/string-format/libstring-format.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/logging/liblogging.la

if ENABLE_BUILT_IN_PLUGINS
# Use the convenience library version of libbabeltrace2 so that its
# BT_PLUGIN_MODULE() accessor functions can see the plugin descriptor
# sections from the statically linked builtin plugin libraries.
babeltrace2_LDADD += $(top_builddir)/src/lib/libbabeltrace2-builtin.la
else
babeltrace2_LDADD += $(top_builddir)/src/lib/libbabeltrace2.la
endif

if ENABLE_BUILT_IN_PLUGINS

# Built-in plugins (using the -builtin convenience libraries)
babeltrace2_LDFLAGS += $(call plugin_archive_builtin,ctf)
babeltrace2_LDFLAGS += $(call plugin_archive_builtin,text)
babeltrace2_LDFLAGS += $(call plugin_archive_builtin,utils)

if ENABLE_DEBUG_INFO
babeltrace2_LDFLAGS += $(call plugin_archive_builtin,lttng-utils)
endif

# Shared convenience libraries used by plugins and libbabeltrace2 (for static
# linking). These are added here (instead of in each builtin plugin's LIBADD)
# to avoid duplicate symbols when linking multiple builtin plugins with
# --whole-archive.
babeltrace2_LDADD += \
	$(top_builddir)/src/plugins/common/param-validation/libparam-validation.la \
	$(top_builddir)/src/plugins/common/muxing/libmuxing.la \
	$(top_builddir)/src/clock-correlation-validator/libclock-correlation-validator.la \
	$(top_builddir)/src/cpp-common/libcpp-common.la \
	$(top_builddir)/src/cpp-common/vendor/fmt/libfmt.la \
	$(top_builddir)/src/ctfser/libctfser.la \
	$(top_builddir)/src/compat/libcompat.la

if ENABLE_DEBUG_INFO
babeltrace2_LDADD += $(ELFUTILS_LIBS)
endif

EXTRA_babeltrace2_DEPENDENCIES += \
	$(PLUGINS_PATH)/ctf/libbabeltrace-plugin-ctf-builtin.la \
	$(PLUGINS_PATH)/text/libbabeltrace-plugin-text-builtin.la \
	$(PLUGINS_PATH)/utils/libbabeltrace-plugin-utils-builtin.la

if ENABLE_DEBUG_INFO
EXTRA_babeltrace2_DEPENDENCIES += \
	$(PLUGINS_PATH)/lttng-utils/libbabeltrace-plugin-lttng-utils-builtin.la
endif # ENABLE_DEBUG_INFO
endif # ENABLE_BUILT_IN_PLUGINS

if BABELTRACE_BUILD_WITH_MINGW
babeltrace2_LDADD += -lws2_32 -lrpcrt4 -lintl -liconv -lole32 -lpthread
endif

# Only used for in-tree execution and tests
babeltrace2_for_tests_SOURCES = $(babeltrace2_SOURCES)
babeltrace2_for_tests_LDFLAGS = $(babeltrace2_LDFLAGS)
babeltrace2_for_tests_LDADD = $(babeltrace2_LDADD)
babeltrace2_for_tests_CFLAGS = $(AM_CFLAGS) -DBT_SET_DEFAULT_IN_TREE_CONFIGURATION
EXTRA_babeltrace2_for_tests_DEPENDENCIES = $(EXTRA_babeltrace2_DEPENDENCIES)
