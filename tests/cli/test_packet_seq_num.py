# SPDX-FileCopyrightText: 2015 Julien Desfossez <jdesfossez@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import re

import pytest
import bt_tests_cli_utils as btu_cli


@pytest.mark.parametrize(
    "trace_name",
    ["no-lost", "no-lost-not-starting-at-0"],
)
def test_no_lost(ctf_traces_dir, build_root_dir, trace_name):
    result = btu_cli.run_cli(
        build_root_dir,
        [str(ctf_traces_dir / "1/packet-seq-num" / trace_name)],
        check=True,
    )
    assert "WARNING: Tracer discarded" not in result.stderr


@pytest.mark.parametrize(
    ["trace_name", "expected_counts"],
    [
        ("2-lost-before-last", [2]),
        ("2-streams-lost-in-1", [2]),
        ("2-streams-lost-in-2", [2, 3, 1]),
    ],
)
def test_lost(ctf_traces_dir, build_root_dir, trace_name, expected_counts):
    result = btu_cli.run_cli(
        build_root_dir,
        [str(ctf_traces_dir / "1/packet-seq-num" / trace_name)],
        check=True,
    )

    # Extract counts from warnings like:
    #
    #     WARNING: Tracer discarded 2 packets
    actual_counts = [
        int(m)
        for m in re.findall(r"WARNING: Tracer discarded (\d+) packet", result.stderr)
    ]

    assert actual_counts == expected_counts
