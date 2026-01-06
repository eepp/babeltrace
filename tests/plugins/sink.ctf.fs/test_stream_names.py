# SPDX-FileCopyrightText: 2020-2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu


class _MsgIter(bt2._UserMessageIterator):
    def __init__(self, config, port):
        tc, sc, ec = port.user_data
        trace = tc()

        # Make two streams with the same name, to verify the stream file
        # names are de-duplicated properly. Make one with the name
        # `metadata` to verify the resulting data file is not named
        # `metadata`.
        stream_1 = trace.create_stream(sc, name="the-stream")
        stream_2 = trace.create_stream(sc, name="the-stream")
        stream_3 = trace.create_stream(sc, name="metadata")

        # Create messages
        self._msgs = [
            self._create_stream_beginning_message(stream_1),
            self._create_stream_beginning_message(stream_2),
            self._create_stream_beginning_message(stream_3),
            self._create_event_message(ec, stream_1),
            self._create_event_message(ec, stream_2),
            self._create_event_message(ec, stream_3),
            self._create_stream_end_message(stream_1),
            self._create_stream_end_message(stream_2),
            self._create_stream_end_message(stream_3),
        ]

    def __next__(self):
        if len(self._msgs) == 0:
            raise StopIteration

        return self._msgs.pop(0)


class _Src(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        tc = self._create_trace_class()
        sc = tc.create_stream_class()
        ec = sc.create_event_class(name="the-event")
        self._add_output_port("out", user_data=(tc, sc, ec))


@pytest.fixture(scope="module")
def trace_dir(tmp_path_factory, sink_ctf_comp_cls):
    output_dir = tmp_path_factory.mktemp("stream-names")

    btu.convert(
        bt2.ComponentSpec(_Src),
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
