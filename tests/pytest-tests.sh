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
    "$BT_TESTS_SRCDIR/cli/"
    "$BT_TESTS_SRCDIR/cpp-common/"
    "$BT_TESTS_SRCDIR/ctf-writer/"
    "$BT_TESTS_SRCDIR/data/test_temp.py"
    "$BT_TESTS_SRCDIR/lib/"
    "$BT_TESTS_SRCDIR/param-validation/"
    "$BT_TESTS_SRCDIR/plugins/flt.lttng-utils.debug-info"
    "$BT_TESTS_SRCDIR/plugins/flt.utils.muxer"
    "$BT_TESTS_SRCDIR/plugins/flt.utils.trimmer"
    "$BT_TESTS_SRCDIR/plugins/sink.ctf.fs"
    "$BT_TESTS_SRCDIR/plugins/sink.text.details"
    "$BT_TESTS_SRCDIR/plugins/sink.text.pretty"
    "$BT_TESTS_SRCDIR/plugins/src.ctf.fs/succeed/"
    "$BT_TESTS_SRCDIR/plugins/src.ctf.fs/test_deterministic_ordering.py"
    "$BT_TESTS_SRCDIR/plugins/src.ctf.fs/test_fail_src_ctf.py"
    "$BT_TESTS_SRCDIR/plugins/src.ctf.fs/test_query_metadata_info.py"
    "$BT_TESTS_SRCDIR/plugins/src.ctf.fs/test_query_support_info.py"
    "$BT_TESTS_SRCDIR/plugins/src.ctf.fs/test_query_trace_info.py"
    "$BT_TESTS_SRCDIR/plugins/src.ctf.lttng-live/test_query_live.py"
    "$BT_TESTS_SRCDIR/python-plugin-provider"
)

if [[ ${BT_TESTS_NO_BITFIELD:-} != 1 ]]; then
    tests+=("$BT_TESTS_SRCDIR/bitfield/")
fi

# shellcheck disable=SC2086
bt-pytest ${BT_TESTS_PYTEST_EXTRA_ARGS:-} \
    -vv -rA --capture=tee-sys --log-cli-level=INFO \
    "${tests[@]}" | tee "$BT_TESTS_BUILDDIR/pytest-tests.log"
