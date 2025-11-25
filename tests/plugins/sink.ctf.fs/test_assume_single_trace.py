# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

import bt2
import pytest
import bt_tests_utils as btu


@pytest.fixture(scope="module")
def trace_dir(sink_ctf_comp_cls, data_dir, tmp_path_factory):
    trace_dir = tmp_path_factory.mktemp("single-trace") / "the-trace"

    # Run conversion
    btu.convert(
        bt2.ComponentSpec(
            btu.find_comp_cls_in_path(
                data_dir / "plugins/sink.ctf.fs/assume-single-trace",
                "foo",
                btu.CompClsType.SOURCE,
                "TheSource",
            )
        ),
        btu.SinkComponentSpec(
            sink_ctf_comp_cls,
            {
                "path": str(trace_dir),
                "assume-single-trace": True,
                "quiet": True,
                "ctf-version": "1",
            },
        ),
    )

    return trace_dir


def test_output_dir_structure(trace_dir):
    assert len(list(trace_dir.iterdir())) == 2
    assert (trace_dir / "metadata").is_file()
    assert (trace_dir / "the-stream").is_file()


def test_read_back(trace_dir):
    events = btu.tcmi_events(str(trace_dir))
    assert len(events) == 1
    assert events[0].name == "the-event"
