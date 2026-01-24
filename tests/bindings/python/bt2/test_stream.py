# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import utils
import pytest
from bt2 import trace as bt2_trace
from bt2 import value as bt2_value
from bt2 import stream as bt2_stream
from bt2 import stream_class as bt2_sc


@pytest.fixture
def stream_env():
    def f(comp_self):
        return comp_self._create_trace_class()

    tc = utils.run_in_component_init(0, f)
    sc = tc.create_stream_class(assigns_automatic_stream_id=True)
    trace = tc()
    return tc, sc, trace


@pytest.fixture
def tc(stream_env):
    return stream_env[0]


@pytest.fixture
def sc(stream_env):
    return stream_env[1]


@pytest.fixture
def trace(stream_env):
    return stream_env[2]


def test_create_default(sc, trace):
    stream = trace.create_stream(sc)
    assert stream.name is None
    assert type(stream) is bt2_stream._Stream
    assert len(stream.user_attributes) == 0


def test_name(sc, trace):
    stream = trace.create_stream(sc, name="équidistant")
    assert stream.name == "équidistant"


def test_invalid_name(sc, trace):
    with pytest.raises(TypeError):
        trace.create_stream(sc, name=22)


def test_create_user_attrs(sc, trace):
    stream = trace.create_stream(sc, user_attributes={"salut": 23})
    assert stream.user_attributes == {"salut": 23}
    assert type(stream.user_attributes) is bt2_value.MapValue


def test_const_user_attrs(const_stream_beginning_msg):
    stream = const_stream_beginning_msg.stream
    assert stream.user_attributes == {"a-stream-attribute": 1}
    assert type(stream.user_attributes) is bt2_value._MapValueConst


def test_create_invalid_user_attrs(sc, trace):
    with pytest.raises(TypeError):
        trace.create_stream(sc, user_attributes=object())


def test_create_invalid_user_attrs_value_type(sc, trace):
    with pytest.raises(TypeError):
        trace.create_stream(sc, user_attributes=23)


def test_sc(sc, trace):
    stream = trace.create_stream(sc)
    assert stream.cls == sc
    assert type(stream.cls) is bt2_sc._StreamClass


def test_const_sc(const_stream_beginning_msg):
    stream = const_stream_beginning_msg.stream
    assert type(stream.cls) is bt2_sc._StreamClassConst


def test_trace(sc, trace):
    stream = trace.create_stream(sc)
    assert stream.trace.addr == trace.addr
    assert type(stream.trace) is bt2_trace._Trace


def test_const_trace(const_stream_beginning_msg):
    stream = const_stream_beginning_msg.stream
    assert type(stream.trace) is bt2_trace._TraceConst


def test_invalid_id(tc, trace):
    sc_no_auto_id = tc.create_stream_class(assigns_automatic_stream_id=False)

    with pytest.raises(TypeError):
        trace.create_stream(sc_no_auto_id, id="string")
