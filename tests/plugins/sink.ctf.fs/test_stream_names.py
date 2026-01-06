# SPDX-FileCopyrightText: 2020-2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu


@pytest.fixture(scope="module")
def trace_dir(data_dir, tmp_path_factory, sink_ctf_comp_cls):
    output_dir = tmp_path_factory.mktemp("stream-names")

    btu.convert(
        bt2.ComponentSpec(
            btu.find_comp_cls_in_path(
                data_dir / "plugins/sink.ctf.fs/stream-names",
                "foo",
                btu.CompClsType.SOURCE,
                "TheSource",
            )
        ),
        btu.SinkComponentSpec(
            sink_ctf_comp_cls,
            {"path": str(output_dir), "quiet": True, "ctf-version": "1"},
        ),
    )

    return output_dir / "trace"


def test_output_file_count(trace_dir):
    assert len(list(trace_dir.iterdir())) == 4


def test_metadata_file_exists(trace_dir):
    assert (trace_dir / "metadata").is_file()


def test_metadata_0_file_exists(trace_dir):
    assert (trace_dir / "metadata-0").is_file()


def test_the_stream_file_exists(trace_dir):
    assert (trace_dir / "the-stream").is_file()


def test_the_stream_0_file_exists(trace_dir):
    assert (trace_dir / "the-stream-0").is_file()


def test_read_back(trace_dir):
    events = btu.tcmi_events(str(trace_dir))
    assert len(events) == 3
    assert all(e.name == "the-event" for e in events)
