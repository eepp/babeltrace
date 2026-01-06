# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt_tests_utils as btu


def test_valid_trace_exit_status(ctf_traces_dir, build_root_dir):
    btu.run_cli(
        build_root_dir,
        ["-o", "ctf-metadata", str(ctf_traces_dir / "1/succeed/wk-heartbeat-u")],
        check=True,
    )


def test_valid_trace_output(ctf_traces_dir, data_dir, build_root_dir):
    result = btu.run_cli(
        build_root_dir,
        ["-o", "ctf-metadata", str(ctf_traces_dir / "1/succeed/wk-heartbeat-u")],
        check=True,
    )
    assert result.stdout == (data_dir / "cli/test-output-ctf-metadata.ref").read_text()


def test_invalid_trace_exit_status(ctf_traces_dir, build_root_dir):
    # Using the root `ctf-traces` directory (not a valid trace
    # directory) should fail.
    assert (
        btu.run_cli(
            build_root_dir, ["-o", "ctf-metadata", str(ctf_traces_dir)]
        ).returncode
        != 0
    )
