#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2020 EfficiOS Inc.
#

# This file tests corner cases related to stream names:
#
#   - two streams with the same name
#   - a stream named "metadata"

SH_TAP=1

if [ -n "${BT_TESTS_SRCDIR:-}" ]; then
	UTILSSH="$BT_TESTS_SRCDIR/utils/utils.sh"
else
	UTILSSH="$(dirname "$0")/../../utils/utils.sh"
fi

# shellcheck source=../../utils/utils.sh
source "$UTILSSH"

# Directory containing the Python test source.
data_dir="$BT_TESTS_DATADIR/plugins/sink.ctf.fs/stream-names"

temp_stdout=$(mktemp)
temp_expected_stdout=$(mktemp)
temp_stderr=$(mktemp)
temp_output_dir=$(mktemp -d)
trace_dir="$temp_output_dir/trace"

plan_tests 11

bt_cli --stdout-file "$temp_stdout" --stderr-file "$temp_stderr" -- \
	"--plugin-path=${data_dir}" \
	-c src.foo.TheSource \
	-c sink.ctf.fs -p "path=\"${temp_output_dir}\"" -p 'ctf-version="1"'
ok "$?" "run babeltrace"

# Check stdout.
if [ "$BT_TESTS_OS_TYPE" = "mingw" ]; then
	# shellcheck disable=SC2028
	echo "Created CTF trace \`$(cygpath -m "${temp_output_dir}")\\trace\`." > "$temp_expected_stdout"
else
	echo "Created CTF trace \`${trace_dir}\`." > "$temp_expected_stdout"
fi
bt_diff "$temp_expected_stdout" "$temp_stdout"
ok "$?" "expected message on stdout"

# Check stderr.
bt_diff "/dev/null" "$temp_stderr"
ok "$?" "stderr is empty"

# Verify only the expected files exist.
files=("$trace_dir"/*)
num_files=${#files[@]}
is "$num_files" "4" "expected number of files in output directory"

test -f "$trace_dir/metadata"
ok "$?" "metadata file exists"

test -f "$trace_dir/metadata-0"
ok "$?" "metadata-0 file exists"

test -f "$trace_dir/the-stream"
ok "$?" "the-stream file exists"

test -f "$trace_dir/the-stream-0"
ok "$?" "the-stream-0 file exists"

# Read back the output trace to make sure it's properly formed.
cat <<- 'END' > "$temp_expected_stdout"
the-event: 
the-event: 
the-event: 
END
bt_test_cli "read back output trace" --expect-stdout "$temp_expected_stdout" -- \
	"$trace_dir"

rm -f "$temp_stdout"
rm -f "$temp_stderr"
rm -f "$temp_expected_stdout"
rm -f "$trace_dir/metadata"
rm -f "$trace_dir/metadata-0"
rm -f "$trace_dir/the-stream"
rm -f "$trace_dir/the-stream-0"
rmdir "$trace_dir"
rmdir "$temp_output_dir"
