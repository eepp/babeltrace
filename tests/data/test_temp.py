# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

import os
import sys
import logging

import bt2
import pytest
import normand
import moultipart
import bt_tests_utils


@pytest.fixture
def something():
    return 23


def _log_env_var(name):
    logging.info(
        "`{}` environment variable: `{}`".format(name, os.environ.get(name, ""))
    )


def test_it_works(something, src_root_dir, build_root_dir, data_dir):
    logging.info("Source directory: `{}`".format(src_root_dir))
    logging.info("Root build directory: `{}`".format(build_root_dir))
    logging.info("Test data directory: `{}`".format(data_dir))
    _log_env_var("ASAN_OPTIONS")
    _log_env_var("BABELTRACE_PLUGIN_PATH")
    _log_env_var("BT_TESTS_BUILDDIR")
    _log_env_var("BT_TESTS_CC_BIN")
    _log_env_var("BT_TESTS_PYTHON_BIN")
    _log_env_var("BT_TESTS_PYTHON_CONFIG_BIN")
    _log_env_var("BT_TESTS_SRCDIR")
    _log_env_var("DYLD_LIBRARY_PATH")
    _log_env_var("LD_LIBRARY_PATH")
    _log_env_var("LD_PRELOAD")
    _log_env_var("LIBBABELTRACE2_PLUGIN_PROVIDER_DIR")
    _log_env_var("PATH")
    logging.info("`sys.path` value: {}".format(sys.path))
    logging.info("`bt2` package version: {}".format(bt2.__version__))
    assert something == 23
