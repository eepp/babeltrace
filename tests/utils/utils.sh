#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Michael Jeanson <mjeanson@efficios.com>
# Copyright (C) 2019-2023 Philippe Proulx <pproulx@efficios.com>

# Source this file at the beginning of a shell script test to access
# useful testing variables and functions:
#
#     SH_TAP=1
#
#     if [[ -n ${BT_TESTS_SRCDIR:-} ]]; then
#         UTILSSH=$BT_TESTS_SRCDIR/utils/utils.sh
#     else
#         UTILSSH=$(dirname "$0")/../utils/utils.sh
#     fi
#
#     # shellcheck source=../utils/utils.sh
#     source "$UTILSSH"
#
# Make sure the relative path to `utils.sh` (this file) above is
# correct (twice).

# An unbound variable is an error
set -u

# Prints a message using `diag` if `SH_TAP` is `1`, or using `echo`
# otherwise.
if [[ ${SH_TAP:-} == 1 ]]; then
	_bt_print() {
		diag "$@"
	}
else
	_bt_print() {
		echo "$@"
	}
fi

# Sets the variable named `$1` to `$2` if it's not set, and exports it.
_bt_tests_set_var_def() {
	local -r varname=$1
	local -r val=$2

	if [[ -z ${!varname:-} ]]; then
		eval "$varname='$val'"
	fi

	export "${varname?}"
}

# Name of the OS on which we're running, if not set.
#
# One of:
#
# `mingw`:          MinGW (Windows)
# `darwin`:         macOS
# `linux`:          Linux
# `cygwin`:         Cygwin (Windows)
# `unsupported`:    Anything else
#
# See <https://en.wikipedia.org/wiki/Uname#Examples> for possible values
# of `uname -s`.
#
# Do some translation to ease our life down the road for comparison.
# Export it so that executed commands can use it.
if [[ -z ${BT_TESTS_OS_TYPE:-} ]]; then
	BT_TESTS_OS_TYPE=$(uname -s)

	case $BT_TESTS_OS_TYPE in
	MINGW*)
		BT_TESTS_OS_TYPE=mingw
		;;
	Darwin)
		BT_TESTS_OS_TYPE=darwin
		;;
	Linux)
		BT_TESTS_OS_TYPE=linux
		;;
	CYGWIN*)
		BT_TESTS_OS_TYPE=cygwin
		;;
	*)
		BT_TESTS_OS_TYPE=unsupported
		;;
	esac
fi

export BT_TESTS_OS_TYPE

# Sets and exports, if not set:
#
# • `BT_TESTS_SRCDIR` to the base source directory of tests.
# • `BT_TESTS_BUILDDIR` to the base build directory of tests.
_set_vars_srcdir_builddir() {
	# If `readlink -f` is available, then get a resolved absolute path
	# to the tests source directory. Otherwise, make do with a relative
	# path.
	local -r scriptdir=$(dirname "${BASH_SOURCE[0]}")
	local testsdir

	if readlink -f . &> /dev/null; then
		testsdir=$(readlink -f "$scriptdir/..")
	else
		testsdir=$scriptdir/..
	fi

	# Base source directory of tests
	_bt_tests_set_var_def BT_TESTS_SRCDIR "$testsdir"

	# Base build directory of tests
	_bt_tests_set_var_def BT_TESTS_BUILDDIR "$testsdir"
}

_set_vars_srcdir_builddir
unset -f _set_vars_srcdir_builddir

# Sources the generated environment file (`env.sh`) if it exists.
_source_env_sh() {
	local -r env_sh_path=$BT_TESTS_BUILDDIR/utils/env.sh

	if [[ -f $env_sh_path ]]; then
		# shellcheck disable=SC1090,SC1091
		. "$env_sh_path"
	fi
}

_source_env_sh
unset -f _source_env_sh

# Path to the `babeltrace2-for-tests` command, if not set
if [[ -z ${BT_TESTS_BT2_BIN:-} ]]; then
	BT_TESTS_BT2_BIN=$BT_TESTS_BUILDDIR/../src/cli/babeltrace2-for-tests

	if [[ $BT_TESTS_OS_TYPE == mingw ]]; then
		BT_TESTS_BT2_BIN+=.exe
	fi
fi

export BT_TESTS_BT2_BIN

# This doesn't need to be exported, but it needs to remain set for
# bt_run_in_py_env() to use it.
#
# TODO: Remove when `tests/bindings/python/bt2/test_plugin.py` is fixed.
_bt_tests_plugins_path=$BT_TESTS_BUILDDIR/../src/plugins

# Colon-separated list of project plugin paths, if not set
_bt_tests_set_var_def BT_TESTS_BABELTRACE_PLUGIN_PATH \
	"$BT_TESTS_SRCDIR/utils/python:$_bt_tests_plugins_path/ctf:$_bt_tests_plugins_path/utils:$_bt_tests_plugins_path/text:$_bt_tests_plugins_path/lttng-utils"

# Directory containing the Python plugin provider library, if not set
_bt_tests_set_var_def BT_TESTS_PROVIDER_DIR "$BT_TESTS_BUILDDIR/../src/python-plugin-provider/.libs"

# Directory containing the built `bt2` Python package, if not set
_bt_tests_set_var_def BT_TESTS_PYTHONPATH "$BT_TESTS_BUILDDIR/../src/bindings/python/bt2/build/build_lib"

# Name of the `awk` command to use when testing, if not set
_bt_tests_set_var_def BT_TESTS_AWK_BIN awk

# Name of the `grep` command to use when testing, if not set
_bt_tests_set_var_def BT_TESTS_GREP_BIN grep

# Name of the `python3` command to use when testing, if not set
_bt_tests_set_var_def BT_TESTS_PYTHON_BIN python3

# Major and minor version of the `python3` command to use when testing.
#
# This doesn't need to be exported, but it needs to remain set for
# bt_run_in_py_utils_env() to use it.
_bt_tests_py3_version=$($BT_TESTS_PYTHON_BIN -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')

# Name of the `python3-config` command to use when testing, if not set
_bt_tests_set_var_def BT_TESTS_PYTHON_CONFIG_BIN python3-config

# Name of the `sed` command to use when testing, if not set
_bt_tests_set_var_def BT_TESTS_SED_BIN sed

# Name of the `cc` command to use when testing, if not set
_bt_tests_set_var_def BT_TESTS_CC_BIN cc

# Done with _bt_tests_set_var_def()
unset -f _bt_tests_set_var_def

# Whether or not to enable AddressSanitizer, `0` (disabled) if not set.
#
# This doesn't need to be exported from the point of view of this file,
# but the sourced `env.sh` above does export it.
if [[ -z ${BT_TESTS_ENABLE_ASAN:-} ]]; then
	BT_TESTS_ENABLE_ASAN=0
fi

# Directory containing test data
BT_TESTS_DATADIR=$BT_TESTS_SRCDIR/data

# Directory containing test CTF traces
BT_CTF_TRACES_PATH=$BT_TESTS_DATADIR/ctf-traces

# Source the shell TAP utilities if `SH_TAP` is `1`
if [[ ${SH_TAP:-} == 1 ]]; then
	# shellcheck source=./tap/tap.sh
	. "$BT_TESTS_SRCDIR/utils/tap/tap.sh"
fi

# Removes the CR characters from the file having the path `$1`.
#
# This is sometimes needed on Windows with text files.
#
# We can't use the `--string-trailing-cr` option of `diff` because
# Solaris doesn't have it.
bt_remove_cr() {
	"$BT_TESTS_SED_BIN" -i'' -e 's/\r//g' "$1"
}

# Prints `$1` without CR characters.
bt_remove_cr_inline() {
    "$BT_TESTS_SED_BIN" 's/\r//g' "$1"
}

# Writes the contents of the file `$1` to the file `$2` without the
# CR and LF characters.
bt_remove_crlf() {
	tr -d '\r\n' < "$1" > "$2"
}

# Runs the `$BT_TESTS_BT2_BIN` command within an environment which can
# import the `bt2` Python package, optionally redirecting the standard
# output and error streams to specified files.
#
# Usage
# ─────
#     bt_cli [--stdout-file STDOUT] [--stderr-file STDERR] -- ARGS...
#
# This function forwards the arguments ARGS to `$BT_TESTS_BT2_BIN`.
#
# Options
# ───────
# --stdout-file STDOUT:
#     Redirect the standard output stream to the file STDOUT instead
#     of `/dev/null`.
#
# --stderr-file STDERR:
#     Redirect the standard error stream to the file STDERR instead
#     of `/dev/null`.
#
# ┌───────────────────────────────────────────────────┐
# │ NOTE: This function doesn't accept options in the │
# │ `--opt=val` format.                               │
# └───────────────────────────────────────────────────┘
#
# Exit status
# ───────────
# Exit status of the executed `$BT_TESTS_BT2_BIN` command.
bt_cli() {
	local stdout_file=/dev/null
	local stderr_file=/dev/null

	while (($# > 0)); do
		case $1 in
		--stdout-file)
			stdout_file=$2
			shift 2
			;;
		--stderr-file)
			stderr_file=$2
			shift 2
			;;
		--)
			shift
			break
			;;
		*)
			echo "ERROR: bt_cli() received unexpected argument \`$1\`" >&2
			return 1
			;;
		esac
	done

	local -ra bt_cli_args=("$@")

	_bt_print "Running: \`$BT_TESTS_BT2_BIN ${bt_cli_args[*]}\`" >&2
	bt_run_in_py_env "$BT_TESTS_BT2_BIN" "${bt_cli_args[@]}" 1>"$stdout_file" 2>"$stderr_file"
}

# Runs bt_cli(), checks some aspects of the result, and then records TAP
# test results.
#
# Usage
# ─────
#     bt_test_cli [--expect-stdout STDOUT] [--expect-stderr-re STDERR]
#                 [--expect-exit-status STATUS] NAME -- ARGS...
#
# The mandatory NAME argument is a prefix of the TAP test names.
#
# This function forwards the arguments ARGS to bt_cli().
#
# Options
# ───────
# --expect-stdout STDOUT:
#     Compare the standard output stream to the file STDOUT, and then
#     record a pass if they're identical, or a failure otherwise.
#
# --expect-stderr-re STDERR:
#     Record a pass if the BRE regular expression STDERR matches the
#     standard error stream, or a failure otherwise.
#
#     If not specified: record a pass if the standard error stream is
#     empty, or a failure otherwise.
#
# --expect-exit-status STATUS:
#     Record a pass if the exit status of bt_cli() is STATUS, or a
#     failure otherwise.
#
#     If not specified: record a pass if the exit status is 0.
#
# ┌───────────────────────────────────────────────────┐
# │ NOTE: This function doesn't accept options in the │
# │ `--opt=val` format.                               │
# └───────────────────────────────────────────────────┘
#
# Exit status
# ───────────
# 0:
#     All checks pass.
#
# Another value:
#     At least one check fails.
bt_test_cli() {
	local test_name=""
	local expected_stdout_file=""
	local expected_stderr_re=""
	local expected_exit_status=0

	while (($# > 0)); do
		case $1 in
		--expect-stdout)
			expected_stdout_file=$2
			shift 2
			;;
		--expect-stderr-re)
			expected_stderr_re=$2
			shift 2
			;;
		--expect-exit-status)
			expected_exit_status=$2
			shift 2
			;;
		--)
			shift
			break
			;;
		--*)
			echo "ERROR: bt_test_cli(): received unexpected option \`$1\`" >&2
			return 1
			;;
		*)
			if [[ -z $test_name ]]; then
				test_name=$1
				shift

				if [[ -z $test_name ]]; then
					echo "ERROR: bt_test_cli(): empty test name" >&2
					return 1
				fi
			else
				echo "ERROR: bt_test_cli(): received unexpected argument \`$1\`" >&2
				return 1
			fi
			;;
		esac
	done

	if [[ -z $test_name ]]; then
		echo "ERROR: bt_test_cli(): missing test name" >&2
		return 1
	fi

	# Run bt_cli().
	local -r actual_stdout_file=$(mktemp -t actual-stdout.XXXXXX)
	local -r actual_stderr_file=$(mktemp -t actual-stderr.XXXXXX)
	local -r bt_cli_args=(
		--stdout-file "$actual_stdout_file"
		--stderr-file "$actual_stderr_file"
	)
	local ret=0

	bt_cli "${bt_cli_args[@]}" -- "$@"

	# Check exit status.
	if ! is $? "$expected_exit_status" "$test_name: exit status is expected"; then
		ret=1
	fi

	# Check standard output.
	if [[ -n $expected_stdout_file ]]; then
		bt_diff "$expected_stdout_file" "$actual_stdout_file"

		if ! ok $? "$test_name: standard output is expected"; then
			ret=1
		fi
	fi

	# Check standard error.
	if [[ -n $expected_stderr_re ]]; then
		bt_grep --silent "$expected_stderr_re" "$actual_stderr_file"
	else
		[[ ! -s $actual_stderr_file ]]
	fi

	if ! ok $? "$test_name: standard error is expected"; then
		ret=1
		diag "standard error contents:"
		diag_file "$actual_stderr_file"
	fi

	rm -f "$actual_stdout_file" "$actual_stderr_file"
	return $ret
}

# Checks the differences between:
#
# • The (expected) contents of the file having the path `$1`.
# • The contents of another file having the path `$2`.
#
# Both files are passed through bt_remove_cr_inline() to remove
# CR characters.
#
# ┌──────────────────────────────────────────────────────────────────┐
# │ NOTE: A common activity being to update an existing expectation  │
# │ file from an actual output when developing features and fixing   │
# │ bugs, and knowing that this function processes the majority of   │
# │ expectation and result files, this function overwrites `$1` with │
# │ `$2` when the `BT_TESTS_DIFF_WRITE_EXPECTED` variable isn't `0`  │
# │ and `diff` finds differences.                                    │
# └──────────────────────────────────────────────────────────────────┘
#
# Returns 0 if there's no difference, or not zero otherwise.
bt_diff() {
	local -r expected_file=$1
	local -r actual_file=$2

	if [[ ! -e $expected_file ]]; then
		echo "ERROR: expected file \`$expected_file\` doesn't exist" >&2
		return 1
	fi

	if [[ ! -e $actual_file ]]; then
		echo "ERROR: actual file \`$actual_file\` doesn't exist" >&2
		return 1
	fi

	diff -u <(bt_remove_cr_inline "$expected_file") <(bt_remove_cr_inline "$actual_file") 1>&2

	local -r ret=$?

	if [[ $ret != 0 && -f $expected_file && ${BT_TESTS_DIFF_WRITE_EXPECTED:-0} != 0 ]]; then
		cp "$actual_file" "$expected_file"
	fi

	return $ret
}

# Checks the difference between:
#
# • What the `$BT_TESTS_BT2_BIN` command prints to its standard output
#   when given the third and following arguments of this function.
#
# • The file having the path `$1`.
#
# as well as the difference between:
#
# • What the `$BT_TESTS_BT2_BIN` command prints to its standard error
#   when given the third and following arguments of this function.
#
# • The file having the path `$2`.
#
# Returns 0 if there's no difference, or 1 otherwise, also printing said
# difference to the standard error.
bt_diff_cli() {
	local -r expected_stdout_file=$1
	local -r expected_stderr_file=$2

	shift 2

	local -r args=("$@")
	local -r temp_stdout_output_file=$(mktemp -t actual-stdout.XXXXXX)
	local -r temp_stderr_output_file=$(mktemp -t actual-stderr.XXXXXX)

	bt_cli --stdout-file "$temp_stdout_output_file" --stderr-file "$temp_stderr_output_file" -- "${args[@]}"
	bt_diff "$expected_stdout_file" "$temp_stdout_output_file"

	local -r ret_stdout=$?

	bt_diff "$expected_stderr_file" "$temp_stderr_output_file"

	local -r ret_stderr=$?

	rm -f "$temp_stdout_output_file" "$temp_stderr_output_file"
	return $((ret_stdout || ret_stderr))
}

# Checks the difference between:
#
# • The content of the file having the path `$1`.
#
# • What the `$BT_TESTS_BT2_BIN` command prints to the standard output
#   when executed with:
#
#   1. The CTF trace directory `$2`.
#   2. The arguments `-c` and `sink.text.details`.
#   3. The third and following arguments of this function.
#
# Returns 0 if there's no difference, or 1 otherwise, also printing said
# difference to the standard error.
bt_diff_details_ctf_single() {
	local -r expected_stdout_file=$1
	local -r trace_dir=$2

	shift 2

	local -r extra_details_args=("$@")

	# Compare using the CLI with `sink.text.details`
	bt_diff_cli "$expected_stdout_file" /dev/null "$trace_dir" \
		-c sink.text.details "${extra_details_args[@]+${extra_details_args[@]}}"
}

# Like bt_diff_details_ctf_single(), except that `$1` is the path to a
# program which generates the CTF trace to compare to.
#
# The program `$1` receives the path to a temporary, empty directory
# where to write the CTF trace as its first argument.
bt_diff_details_ctf_gen_single() {
	local -r ctf_gen_prog_path=$1
	local -r expected_stdout_file=$2

	shift 2

	local -r gen_extra_details_args=("$@")
	local -r temp_trace_dir=$(mktemp -d)

	# Run the CTF trace generator program to get a CTF trace
	if ! "$ctf_gen_prog_path" "$temp_trace_dir" 2>/dev/null; then
		echo "ERROR: \`$ctf_gen_prog_path $temp_trace_dir\` failed" >&2
		rm -rf "$temp_trace_dir"
		return 1
	fi

	# Compare using the CLI with `sink.text.details`
	bt_diff_details_ctf_single "$expected_stdout_file" "$temp_trace_dir" \
		"${gen_extra_details_args[@]+${gen_extra_details_args[@]}}"

	local -r ret=$?

	rm -rf "$temp_trace_dir"
	return $ret
}

# Like `grep`, but using `$BT_TESTS_GREP_BIN`.
bt_grep() {
	"$BT_TESTS_GREP_BIN" "$@"
}

# Only if `tap.sh` is sourced because bt_grep_ok() uses ok()
if [[ ${SH_TAP:-} == 1 ]]; then
	# ok() with the test name `$3` on the result of bt_grep() matching
	# the pattern `$1` within the file `$2`.
	bt_grep_ok() {
		local -r pattern=$1
		local -r file=$2
		local -r test_name=$3

		bt_grep --silent "$pattern" "$file"

		local -r ret=$?

		if ! ok $ret "$test_name"; then
			{
				diag "Pattern \`$pattern\` doesn't match the contents of \`$file\`:"
				diag '--- 8< ---'
				cat "$file"
				diag '--- >8 ---'
			} >&2
		fi

		return $ret
	}
fi

# Forwards the arguments to `coverage run`.
_bt_tests_check_coverage() {
	coverage run "$@"
}

# Executes a command within an environment which can import the testing
# Python modules (in `tests/utils/python`).
bt_run_in_py_utils_env() {
	local our_pythonpath=$BT_TESTS_SRCDIR/utils/python:$BT_TESTS_SRCDIR/utils/python/vendor

	if [[ $_bt_tests_py3_version == 3.5 ]]; then
		# Add a local directory containing a `typing.py` to `PYTHONPATH`
		# for Python 3.5 which offers a partial `typing` module.
		our_pythonpath=$our_pythonpath:$BT_TESTS_SRCDIR/utils/python/vendor/typing
	fi

	PYTHONPATH=$our_pythonpath${PYTHONPATH:+:}${PYTHONPATH:-} "$@"
}

# Executes a command within an environment which can import the testing
# Python modules (in `tests/utils/python`) and the `bt2` Python package.
bt_run_in_py_env() {
	local -x BABELTRACE_PLUGIN_PATH=$BT_TESTS_BABELTRACE_PLUGIN_PATH
	local -x LIBBABELTRACE2_PLUGIN_PROVIDER_DIR=$BT_TESTS_PROVIDER_DIR
	local -x BT_TESTS_DATADIR=$BT_TESTS_DATADIR
	local -x BT_CTF_TRACES_PATH=$BT_CTF_TRACES_PATH
	local -x BT_PLUGINS_PATH=$_bt_tests_plugins_path
	local -x PYTHONPATH=$BT_TESTS_PYTHONPATH${PYTHONPATH:+:}${PYTHONPATH:-}
	local -r main_lib_path=$BT_TESTS_BUILDDIR/../src/lib/.libs

	# Set the library search path so that the Python 3 interpreter can
	# load `libbabeltrace2`.
	if [[ $BT_TESTS_OS_TYPE == mingw || $BT_TESTS_OS_TYPE == cygwin ]]; then
		local -x PATH=$main_lib_path${PATH:+:}${PATH:-}
	elif [[ $BT_TESTS_OS_TYPE == darwin ]]; then
		local -x DYLD_LIBRARY_PATH=$main_lib_path${DYLD_LIBRARY_PATH:+:}${DYLD_LIBRARY_PATH:-}
	else
		local -x LD_LIBRARY_PATH=$main_lib_path${LD_LIBRARY_PATH:+:}${LD_LIBRARY_PATH:-}
	fi

	# On Windows, an embedded Python 3 interpreter needs a way to locate
	# the path to its internal modules: set the `PYTHONHOME` variable to
	# the prefix from `python3-config`.
	if [[ $BT_TESTS_OS_TYPE == mingw ]]; then
		local -x PYTHONHOME

		PYTHONHOME=$($BT_TESTS_PYTHON_CONFIG_BIN --prefix)
	fi

	# If AddressSanitizer is used, we must preload `libasan.so` so that
	# libasan doesn't complain about not being the first loaded library.
	#
	# Python and sed (executed as part of the Libtool wrapper) produce
	# some leaks, so we must unfortunately disable leak detection.
	#
	# Append it to existing `ASAN_OPTIONS` variable, such that we
	# override the user's value if it contains `detect_leaks=1`.
	if [[ ${BT_TESTS_ENABLE_ASAN:-} == 1 ]]; then
		if $BT_TESTS_CC_BIN --version | head -n 1 | bt_grep -q '^gcc'; then
			local -r lib_asan=$($BT_TESTS_CC_BIN -print-file-name=libasan.so)
			local -r lib_stdcxx=$($BT_TESTS_CC_BIN -print-file-name=libstdc++.so)
			local -x LD_PRELOAD=$lib_asan:$lib_stdcxx${LD_PRELOAD:+:}${LD_PRELOAD:-}
		fi

		local -x ASAN_OPTIONS=${ASAN_OPTIONS:-}${ASAN_OPTIONS:+,}detect_leaks=0
	fi

	bt_run_in_py_utils_env "$@"
}

# Runs the Python tests matching the pattern `$2` (optional, `*` if
# missing) in the directory `$1` using `testrunner.py`.
#
# This function uses bt_run_in_py_env(), therefore such tests can import
# the testing Python modules (in `tests/utils/python`) and the `bt2`
# Python package.
bt_run_py_test() {
	local -r test_dir=$1
	local -r test_pattern=${2:-*}
	local python_exec

	if [[ ${BT_TESTS_COVERAGE:-} == 1 ]]; then
		python_exec=_bt_tests_check_coverage
	else
		python_exec=$BT_TESTS_PYTHON_BIN
	fi

	bt_run_in_py_env \
		"$python_exec" "$BT_TESTS_SRCDIR/utils/python/testrunner.py" \
		--pattern "$test_pattern" "$test_dir"

	local -r ret=$?

	if [[ ${BT_TESTS_COVERAGE_REPORT:-} == 1 ]]; then
		coverage report -m
	fi

	if [[ ${BT_TESTS_COVERAGE_HTML:-} == 1 ]]; then
		coverage html
	fi

	return $ret
}

# Generates a CTF trace into the directory `$2` from the moultipart
# document `$1` using `mctf.py`.
bt_gen_mctf_trace() {
	local -r input_file=$1
	local -r base_dir=$2
	local -r cmd=(
		"$BT_TESTS_PYTHON_BIN" "$BT_TESTS_SRCDIR/utils/python/mctf.py"
		--base-dir "$base_dir"
		"$input_file"
	)

	_bt_print "Running: \`${cmd[*]}\`" >&2
	bt_run_in_py_utils_env "${cmd[@]}"
}

# Runs `diag` with the contents of file `$1`.
diag_file() {
	diag "$(cat "$1")"
}

# On MinGW, prints `$1` passed through `cygpath -m`. Otherwise, print `$1`
# unmodified.
bt_maybe_cygpath_m() {
	local path=$1

	if [[ $BT_TESTS_OS_TYPE == mingw ]]; then
		path=$(cygpath -m "$path")
	fi

	echo "$path"
}

# Returns whether `src.ctf.fs` supports the CTF version `$1`
# (`1` or `2`) when operating with the MIP version `$2` (`0` or `1`).
bt_is_valid_ctf_mip_combo() {
	local -r ctf="$1"
	local -r mip="$2"

	((ctf == 1 || mip == 1))
}
