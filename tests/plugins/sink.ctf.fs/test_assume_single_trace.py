# SPDX-FileCopyrightText: 2020-2025 EfficiOS Inc.
# SPDX-License-Identifier: MIT

import bt2
import pytest
import bt_tests_utils as btu


class _MyIter(bt2._UserMessageIterator):
    def __init__(self, config, port):
        tc, sc, ec = port.user_data
        stream = tc().create_stream(sc, name="the-stream")
        self._msgs = [
            self._create_stream_beginning_message(stream),
            self._create_event_message(ec, stream),
            self._create_stream_end_message(stream),
        ]

    def __next__(self):
        if len(self._msgs) == 0:
            raise StopIteration

        return self._msgs.pop(0)


class _MySrc(bt2._UserSourceComponent, message_iterator_class=_MyIter):
    def __init__(self, config, params, obj):
        tc = self._create_trace_class()
        sc = tc.create_stream_class()
        ec = sc.create_event_class(name="the-event")
        self._add_output_port("out", user_data=(tc, sc, ec))


@pytest.fixture(scope="module")
def trace_dir(sink_ctf_comp_cls, tmp_path_factory):
    trace_dir = tmp_path_factory.mktemp("single-trace") / "the-trace"

    # Run conversion
    btu.convert(
        bt2.ComponentSpec(_MySrc),
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
