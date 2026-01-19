# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import uuid

import utils
import pytest
from bt2 import trace as bt2_trace
from bt2 import utils as bt2_utils
from bt2 import value as bt2_value
from bt2 import stream as bt2_stream
from bt2 import trace_class as bt2_tc


def test_create_def(def_tc):
    trace = def_tc()
    assert trace.name is None
    assert trace.uuid is None
    assert len(trace.environment) == 0
    assert len(trace.user_attributes) == 0


def test_create_invalid_name(def_tc):
    with pytest.raises(TypeError):
        def_tc(name=17)


def test_create_user_attrs(def_tc):
    trace = def_tc(user_attributes={"salut": 23})
    assert trace.user_attributes == {"salut": 23}
    assert type(trace.user_attributes) is bt2_value.MapValue


def test_const_user_attrs(const_stream_beginning_msg):
    trace = const_stream_beginning_msg.stream.trace
    assert trace.user_attributes == {"a-trace-attribute": 1}
    assert type(trace.user_attributes) is bt2_value._MapValueConst


def test_create_invalid_user_attrs(def_tc):
    with pytest.raises(TypeError):
        def_tc(user_attributes=object())


def test_create_invalid_user_attrs_value_type(def_tc):
    with pytest.raises(TypeError):
        def_tc(user_attributes=23)


def test_attr_rc(def_tc):
    trace = def_tc()
    assert trace.cls.addr == def_tc.addr
    assert type(trace.cls) is bt2_tc._TraceClass


def test_const_attr_tc(const_stream_beginning_msg):
    trace = const_stream_beginning_msg.stream.trace
    assert type(trace.cls) is bt2_tc._TraceClassConst


def test_attr_name(def_tc):
    trace = def_tc(name="mein trace")
    assert trace.name == "mein trace"


def test_attr_uuid(def_tc):
    trace = def_tc(uuid=uuid.UUID("da7d6b6f-3108-4706-89bd-ab554732611b"))
    assert trace.uuid == uuid.UUID("da7d6b6f-3108-4706-89bd-ab554732611b")


def test_env_get(def_tc):
    trace = def_tc(environment={"hello": "you", "foo": -5})
    assert type(trace.environment) is bt2_trace._TraceEnvironment
    assert type(trace.environment["foo"]) is bt2_value.SignedIntegerValue
    assert trace.environment["hello"] == "you"
    assert trace.environment["foo"] == -5


def test_env_iter(def_tc):
    trace = def_tc(environment={"hello": "you", "foo": -5})
    values = set(trace.environment)
    assert values == {"hello", "foo"}


def test_const_env_get(const_stream_beginning_msg):
    trace = const_stream_beginning_msg.stream.trace
    assert type(trace.environment) is bt2_trace._TraceEnvironmentConst
    assert type(trace.environment["patate"]) is bt2_value._SignedIntegerValueConst


def test_const_env_iter(const_stream_beginning_msg):
    trace = const_stream_beginning_msg.stream.trace
    values = set(trace.environment)
    assert values == {"patate"}


def test_const_env_set(const_stream_beginning_msg):
    trace = const_stream_beginning_msg.stream.trace
    with pytest.raises(TypeError):
        trace.environment["patate"] = 33


def test_env_get_non_existent(def_tc):
    trace = def_tc(environment={"hello": "you", "foo": -5})

    with pytest.raises(KeyError):
        trace.environment["lel"]


def test_len(def_tc):
    trace = def_tc()
    sc = def_tc.create_stream_class()
    assert len(trace) == 0
    trace.create_stream(sc)
    assert len(trace) == 1


@pytest.fixture
def trace_with_some_streams(def_tc):
    sc = def_tc.create_stream_class(assigns_automatic_stream_id=False)
    trace = def_tc()
    trace.create_stream(sc, id=12)
    trace.create_stream(sc, id=15)
    trace.create_stream(sc, id=17)
    return trace


def test_iter(trace_with_some_streams):
    stream_ids = set(trace_with_some_streams)
    assert stream_ids == {12, 15, 17}


def test_getitem(trace_with_some_streams):
    assert trace_with_some_streams[12].id == 12
    assert type(trace_with_some_streams[12]) is bt2_stream._Stream


def test_const_getitem(const_stream_beginning_msg):
    trace = const_stream_beginning_msg.stream.trace
    assert type(trace[0]) is bt2_stream._StreamConst


def test_getitem_invalid_key(trace_with_some_streams):
    with pytest.raises(KeyError):
        trace_with_some_streams[18]


def test_destruction_listener():
    def on_tc_destruction(tc):
        nonlocal num_tc_destroyed_calls

        num_tc_destroyed_calls += 1

    def on_trace_destruction(trace):
        nonlocal num_trace_destroyed_calls

        num_trace_destroyed_calls += 1
        assert type(trace) is bt2_trace._TraceConst

    num_tc_destroyed_calls = 0
    num_trace_destroyed_calls = 0
    tc = utils.get_default_trace_class()
    sc = tc.create_stream_class()
    trace = tc()
    stream = trace.create_stream(sc)

    # Add destruction listeners
    tc.add_destruction_listener(on_tc_destruction)
    td_handle_1 = trace.add_destruction_listener(on_trace_destruction)
    td_handle_2 = trace.add_destruction_listener(on_trace_destruction)

    assert type(td_handle_1) is bt2_utils._ListenerHandle

    # Remove one listener
    trace.remove_destruction_listener(td_handle_2)

    assert num_tc_destroyed_calls == 0
    assert num_trace_destroyed_calls == 0

    # Delete trace (stream still holds a reference)
    del trace

    assert num_tc_destroyed_calls == 0
    assert num_trace_destroyed_calls == 0

    # Delete stream (trace gets destroyed)
    del stream

    assert num_tc_destroyed_calls == 0
    assert num_trace_destroyed_calls == 1

    # Delete trace class (stream class still holds a reference)
    del tc
    assert num_tc_destroyed_calls == 0
    assert num_trace_destroyed_calls == 1

    # Delete stream class (trace class gets destroyed)
    del sc
    assert num_tc_destroyed_calls == 1
    assert num_trace_destroyed_calls == 1


def test_remove_destruction_listener_wrong_type(def_tc):
    trace = def_tc()

    with pytest.raises(
        TypeError, match=r"'int' is not a '<class 'bt2.utils._ListenerHandle'>' object"
    ):
        trace.remove_destruction_listener(123)


def test_remove_destruction_listener_wrong_object():
    def on_trace_destruction(trace):
        pass

    tc_1 = utils.get_default_trace_class()
    trace_1 = tc_1()
    tc_2 = utils.get_default_trace_class()
    trace_2 = tc_2()
    handle_1 = trace_1.add_destruction_listener(on_trace_destruction)

    with pytest.raises(
        ValueError,
        match=r"This trace destruction listener does not match the trace object\.",
    ):
        trace_2.remove_destruction_listener(handle_1)


def test_remove_destruction_listener_twice(def_tc):
    def on_trace_destruction(trace_class):
        pass

    trace = def_tc()
    handle = trace.add_destruction_listener(on_trace_destruction)
    trace.remove_destruction_listener(handle)

    with pytest.raises(
        ValueError, match=r"This trace destruction listener was already removed\."
    ):
        trace.remove_destruction_listener(handle)


def test_raise_in_destruction_listener(def_tc):
    listener_called = False

    def on_trace_destruction(trace):
        nonlocal listener_called

        listener_called = True
        raise ValueError("it hurts")

    trace = def_tc()
    trace.add_destruction_listener(on_trace_destruction)
    del trace
    assert listener_called
