# SPDX-FileCopyrightText: 2015 Julien Desfossez <jdesfossez@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_cli_utils as btu_cli


# Counts the number of lines in `stdout`.
def _count_lines(stdout):
    return len(stdout.strip().split("\n")) if stdout.strip() else 0


# Runs the `babeltrace2` CLI.
def _run_cli(build_root_dir, trace_path, stream_intersection=False):
    args = [str(trace_path)]

    if stream_intersection:
        args = ["--stream-intersection"] + args

    return btu_cli.run_cli(build_root_dir, args)


@pytest.mark.parametrize(
    ["trace_name", "total_event_count", "intersect_event_count", "expected_error"],
    [
        pytest.param(
            "3eventsintersect",
            8,
            3,
            None,
            id="2-streams-offsetted-3-packets-intersecting",
        ),
        pytest.param(
            "3eventsintersectreverse",
            8,
            3,
            None,
            id="2-streams-offsetted-3-packets-intersecting-exchanged-filenames",
        ),
        pytest.param(
            "onestream",
            3,
            3,
            None,
            id="only-1-stream",
        ),
        pytest.param(
            "nointersect",
            6,
            None,
            "Trimming time range's beginning time is greater than end time",
            id="no-intersection-between-2-streams",
        ),
        pytest.param(
            "nostream",
            0,
            None,
            "Trace has no streams",
            id="no-stream-at-all",
        ),
    ],
)
def test_intersection(
    ctf_traces_dir,
    build_root_dir,
    trace_name,
    total_event_count,
    intersect_event_count,
    expected_error,
):
    trace_path = ctf_traces_dir / "1/intersection" / trace_name

    # Run without `--stream-intersection`
    result = _run_cli(build_root_dir, trace_path, stream_intersection=False)
    assert result.returncode == 0
    assert _count_lines(result.stdout) == total_event_count

    # Run with `--stream-intersection`
    result = _run_cli(build_root_dir, trace_path, stream_intersection=True)

    if expected_error is not None:
        assert result.returncode != 0
        assert expected_error in result.stderr
    else:
        assert result.returncode == 0
        assert _count_lines(result.stdout) == intersect_event_count
