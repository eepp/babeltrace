# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

# This test file verifies that generic (non-LTTng) CTF traces are output
# with the expected directory structure.
#
# Traces found when invoking
#
#     $ babeltrace2 in -c sink.ctf.fs -p 'path="out"'
#
# are expected to use the same directory structure relative to `out` as
# the original traces had relative to `in`.

import shutil
import pathlib

import pytest
import bt_tests_cli_utils as btu_cli


@pytest.fixture(scope="module")
def output_dir(ctf_traces_dir, tmp_path_factory, build_root_dir):
    tmp_path = tmp_path_factory.mktemp("data")
    input_dir = tmp_path / "input"

    # Create nested directory structure with traces
    (input_dir / "a/b/c").mkdir(parents=True)
    shutil.copytree(
        ctf_traces_dir / "1/intersection/3eventsintersect",
        input_dir / "a/b/c/3eventsintersect",
    )
    shutil.copytree(
        ctf_traces_dir / "1/intersection/3eventsintersectreverse",
        input_dir / "a/b/c/3eventsintersectreverse",
    )

    (input_dir / "d/e/f").mkdir(parents=True)
    shutil.copytree(
        ctf_traces_dir / "1/intersection/nointersect",
        input_dir / "d/e/f/nointersect",
    )

    output_dir = tmp_path / "output"

    btu_cli.run_cli(
        build_root_dir,
        [
            str(input_dir),
            "-c",
            "sink.ctf.fs",
            btu_cli.CliParams({"path": str(output_dir)}),
        ],
        check=True,
    )

    return output_dir


@pytest.mark.parametrize(
    "trace_path",
    [
        pytest.param(pathlib.Path("a/b/c/3eventsintersect"), id="3eventsintersect"),
        pytest.param(
            pathlib.Path("a/b/c/3eventsintersectreverse"),
            id="3eventsintersectreverse",
        ),
        pytest.param(pathlib.Path("d/e/f/nointersect"), id="nointersect"),
    ],
)
def test_output_trace_exists(output_dir, trace_path):
    assert (output_dir / trace_path / "metadata").is_file()
