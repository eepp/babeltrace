#!/bin/bash
#
# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

BT_TESTS_PYTEST_EXTRA_ARGS="${BT_TESTS_PYTEST_EXTRA_ARGS:-} --tap" "$(dirname "$0")/pytest-tests.sh"
