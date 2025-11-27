#!/bin/bash
#
# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

if [[ -z "${BT_TESTS_SRCDIR:-}" ]]; then
    BT_TESTS_SRCDIR="$(dirname "$0")"
fi

if [[ -z "${BT_TESTS_BUILDDIR:-}" ]]; then
    BT_TESTS_BUILDDIR=$BT_TESTS_SRCDIR
fi

if ! type -t bt-pytest &>/dev/null; then
    # shellcheck disable=SC1090,SC1091
    source "$BT_TESTS_BUILDDIR/utils/pytest-env.sh"
fi

tests=(
    "$BT_TESTS_SRCDIR"/bindings/python/bt2/pytest_*.py
    "$BT_TESTS_SRCDIR/cpp-common/"
    "$BT_TESTS_SRCDIR/data/test_temp.py"
    "$BT_TESTS_SRCDIR/lib/conds/"
    "$BT_TESTS_SRCDIR/lib/test-fields.cpp"
    "$BT_TESTS_SRCDIR/lib/test-plugin-init-fail.cpp"
    "$BT_TESTS_SRCDIR/lib/test-remove-destruction-listener-in-destruction-listener.cpp"
    "$BT_TESTS_SRCDIR/plugins/sink.ctf.fs/test_assume_single_trace.py"
)

# shellcheck disable=SC2086
bt-pytest ${BT_TESTS_PYTEST_EXTRA_ARGS:-} \
    -vv -rA --capture=tee-sys --log-cli-level=INFO \
    "${tests[@]}" | tee "$BT_TESTS_BUILDDIR/pytest-tests.log"
