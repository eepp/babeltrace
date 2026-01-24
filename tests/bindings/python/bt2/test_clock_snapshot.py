# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import types

import bt2
import utils
import pytest
from bt2 import clock_class as bt2_clk_cls


# Returns an object containing:
#
# `clk_cls`:
#     Clock class with frequency 1000 Hz and offset (45 s, 354 cycles).
#
# `msg`:
#     Event message with default clock snapshot value 123.
#
# `msg_clk_overflow`:
#     Event message with default clock snapshot value 2^63.
@pytest.fixture(scope="module")
def cs_setup():
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            ec, stream = self_port_output.user_data

            self._msgs = [
                self._create_stream_beginning_message(stream),
                self._create_event_message(ec, stream, 123),
                self._create_event_message(ec, stream, 2**63),
                self._create_stream_end_message(stream),
            ]

        def __next__(self):
            if self._msgs:
                return self._msgs.pop(0)

            raise bt2.Stop

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            nonlocal clk_cls_from_src

            clk_cls_from_src = self._create_clock_class(
                1000, "my_clk_cls", offset=bt2.ClockOffset(45, 354)
            )
            tc = self._create_trace_class()
            sc = tc.create_stream_class(default_clock_class=clk_cls_from_src)
            ec = sc.create_event_class(name="salut")
            stream = tc().create_stream(sc)
            self._add_output_port("out", (ec, stream))

    clk_cls_from_src = None
    graph = bt2.Graph()
    src_comp = graph.add_component(MySrc, "my_source")
    msg_iter = utils.TestOutputPortMessageIterator(graph, src_comp.output_ports["out"])
    msg = None
    msg_clk_overflow = None

    for i, cur_msg in enumerate(msg_iter):
        if i == 1:
            assert type(cur_msg) is bt2._EventMessageConst
            msg = cur_msg
        elif i == 2:
            assert type(cur_msg) is bt2._EventMessageConst
            msg_clk_overflow = cur_msg
            break

    assert msg is not None
    assert msg_clk_overflow is not None
    return types.SimpleNamespace(
        clk_cls=clk_cls_from_src, msg=msg, msg_clk_overflow=msg_clk_overflow
    )


def test_create_def(cs_setup):
    assert cs_setup.msg.default_clock_snapshot.clock_class.addr == cs_setup.clk_cls.addr
    assert cs_setup.msg.default_clock_snapshot.value == 123


def test_clk_cls(cs_setup):
    cs_clk_cls = cs_setup.msg.default_clock_snapshot.clock_class
    assert cs_clk_cls.addr == cs_setup.clk_cls.addr
    assert type(cs_clk_cls) is bt2_clk_cls._ClockClassConst


def test_ns_from_orig(cs_setup):
    s_from_orig = 45 + ((354 + 123) / 1000)
    ns_from_orig = int(s_from_orig * 1e9)
    assert cs_setup.msg.default_clock_snapshot.ns_from_origin == ns_from_orig


def test_ns_from_orig_overflow(cs_setup):
    with pytest.raises(bt2._OverflowError):
        cs_setup.msg_clk_overflow.default_clock_snapshot.ns_from_origin


def test_eq_int(cs_setup):
    assert cs_setup.msg.default_clock_snapshot == 123


def test_eq_invalid(cs_setup):
    assert not (cs_setup.msg.default_clock_snapshot == 23)


def test_comparison(cs_setup):
    cs = cs_setup.msg.default_clock_snapshot
    assert cs > 100
    assert not (cs > 200)
    assert cs >= 123
    assert not (cs >= 200)
    assert cs < 200
    assert not (cs < 100)
    assert cs <= 123
    assert not (cs <= 100)
