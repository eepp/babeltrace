# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import bt_tests_utils as btu


def test_ctf_writer_trace(build_root_dir, tmp_path):
    trace_dir = tmp_path / "ctf-writer-trace"
    trace_dir.mkdir()
    btu.run(
        build_root_dir,
        btu.build_dir_of_source_file(build_root_dir, __file__) / "test-ctf-writer",
        ["CTF writer: full"],
        extra_env={"TEST_CTF_WRITER_TRACE_DIR": str(trace_dir)},
        check=True,
    )
    assert len(btu.tcmi_events(str(trace_dir))) == 100003
