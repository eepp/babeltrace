# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import utils
import pytest
from bt2 import utils as bt2_utils
from bt2 import value as bt2_value
from bt2 import trace_class as bt2_tc
from bt2 import stream_class as bt2_sc


def _run_in_component_init(f):
    return utils.run_in_component_init(0, f)


def _assert_raises_in_component_init(expected_exc_type, user_code):
    def f(self_comp):
        try:
            user_code(self_comp)
        except Exception as exc:
            return type(exc)

    exc_type = _run_in_component_init(f)
    assert exc_type is not None
    assert exc_type == expected_exc_type


def test_create_def():
    def f(self_comp):
        return self_comp._create_trace_class()

    tc = _run_in_component_init(f)
    assert len(tc) == 0
    assert type(tc) is bt2_tc._TraceClass
    assert tc.assigns_automatic_stream_class_id
    assert len(tc.user_attributes) == 0


def test_create_user_attrs():
    def f(self_comp):
        return self_comp._create_trace_class(user_attributes={"salut": 23})

    tc = _run_in_component_init(f)
    assert tc.user_attributes == {"salut": 23}
    assert type(tc.user_attributes) is bt2_value.MapValue


def test_const_user_attrs(const_stream_beginning_msg):
    tc = const_stream_beginning_msg.stream.trace.cls
    assert tc.user_attributes == {"a-trace-class-attribute": 1}
    assert type(tc.user_attributes) is bt2_value._MapValueConst


def test_create_invalid_user_attrs():
    def f(self_comp):
        return self_comp._create_trace_class(user_attributes=object())

    _assert_raises_in_component_init(TypeError, f)


def test_create_invalid_user_attrs_value_type():
    def f(self_comp):
        return self_comp._create_trace_class(user_attributes=23)

    _assert_raises_in_component_init(TypeError, f)


def test_create_invalid_automatic_sc_id_type():
    def f(self_comp):
        return self_comp._create_trace_class(
            assigns_automatic_stream_class_id="perchaude"
        )

    _assert_raises_in_component_init(TypeError, f)


def test_automatic_stream_class_id():
    def f(self_comp):
        return self_comp._create_trace_class(assigns_automatic_stream_class_id=True)

    tc = _run_in_component_init(f)
    assert tc.assigns_automatic_stream_class_id

    # This should not throw
    sc1 = tc.create_stream_class()
    sc2 = tc.create_stream_class()
    assert type(sc1) is bt2_sc._StreamClass
    assert type(sc2) is bt2_sc._StreamClass
    assert sc1.id != sc2.id


def test_automatic_stream_class_id_raises():
    def f(self_comp):
        return self_comp._create_trace_class(assigns_automatic_stream_class_id=True)

    tc = _run_in_component_init(f)
    assert tc.assigns_automatic_stream_class_id

    with pytest.raises(ValueError):
        tc.create_stream_class(23)


def test_no_assigns_automatic_sc_id():
    def f(self_comp):
        return self_comp._create_trace_class(assigns_automatic_stream_class_id=False)

    tc = _run_in_component_init(f)
    assert not tc.assigns_automatic_stream_class_id
    sc = tc.create_stream_class(id=28).id == 28


def test_no_assigns_automatic_sc_id_raises():
    def f(self_comp):
        return self_comp._create_trace_class(assigns_automatic_stream_class_id=False)

    tc = _run_in_component_init(f)
    assert not tc.assigns_automatic_stream_class_id

    # In this mode, it is required to pass an explicit ID
    with pytest.raises(ValueError):
        tc.create_stream_class()


@pytest.fixture
def tc_with_some_scs():
    def f(self_comp):
        return self_comp._create_trace_class(assigns_automatic_stream_class_id=False)

    tc = _run_in_component_init(f)

    return (
        tc,
        tc.create_stream_class(id=12),
        tc.create_stream_class(id=54),
        tc.create_stream_class(id=2018),
    )


def test_getitem(tc_with_some_scs):
    tc, _, _, sc3 = tc_with_some_scs
    assert type(tc[2018]) is bt2_sc._StreamClass
    assert tc[2018].addr == sc3.addr


def test_const_getitem(const_stream_beginning_msg):
    const_tc = const_stream_beginning_msg.stream.trace.cls
    assert type(const_tc[0]) is bt2_sc._StreamClassConst


def test_getitem_wrong_key_type(tc_with_some_scs):
    tc, _, _, _ = tc_with_some_scs

    with pytest.raises(TypeError):
        tc["hello"]


def test_getitem_wrong_key(tc_with_some_scs):
    tc, _, _, _ = tc_with_some_scs

    with pytest.raises(KeyError):
        tc[4]


def test_len(def_tc):
    assert len(def_tc) == 0
    def_tc.create_stream_class()
    assert len(def_tc) == 1


def test_iter(tc_with_some_scs):
    tc, sc1, sc2, sc3 = tc_with_some_scs

    for sc_id, sc in tc.items():
        if sc_id == 12:
            assert type(sc) is bt2_sc._StreamClass
            assert sc.addr == sc1.addr
        elif sc_id == 54:
            assert sc.addr == sc2.addr
        elif sc_id == 2018:
            assert sc.addr == sc3.addr


def test_const_iter(const_stream_beginning_msg):
    const_tc = const_stream_beginning_msg.stream.trace.cls
    const_sc = list(const_tc.values())[0]
    assert type(const_sc) is bt2_sc._StreamClassConst


def test_destruction_listener():
    def on_tc_destruction(tc):
        nonlocal num_destruct_calls

        num_destruct_calls += 1
        assert type(tc) is bt2_tc._TraceClassConst

    num_destruct_calls = 0

    # Add destruction listeners
    tc = utils.def_tc()
    handle_1 = tc.add_destruction_listener(on_tc_destruction)
    assert type(handle_1) is bt2_utils._ListenerHandle
    handle_2 = tc.add_destruction_listener(on_tc_destruction)

    # Remove one listener
    tc.remove_destruction_listener(handle_2)
    assert num_destruct_calls == 0

    # Delete trace class (triggers destruction listener)
    del tc
    assert num_destruct_calls == 1


def test_remove_destruction_listener_wrong_type(def_tc):
    with pytest.raises(
        TypeError, match=r"'int' is not a '<class 'bt2.utils._ListenerHandle'>' object"
    ):
        def_tc.remove_destruction_listener(123)


def test_remove_destruction_listener_wrong_obj():
    def on_tc_destruction(trace_class):
        pass

    tc_1 = utils.def_tc()
    tc_2 = utils.def_tc()
    handle_1 = tc_1.add_destruction_listener(on_tc_destruction)

    with pytest.raises(
        ValueError,
        match=r"This trace class destruction listener does not match the trace class object\.",
    ):
        tc_2.remove_destruction_listener(handle_1)


def test_remove_destruction_listener_twice(def_tc):
    def on_tc_destruction(trace_class):
        pass

    handle = def_tc.add_destruction_listener(on_tc_destruction)
    def_tc.remove_destruction_listener(handle)

    with pytest.raises(
        ValueError, match=r"This trace class destruction listener was already removed\."
    ):
        def_tc.remove_destruction_listener(handle)


def test_raise_in_destruction_listener(def_tc):
    def on_tc_destruction(tc):
        raise ValueError("it hurts")

    def_tc.add_destruction_listener(on_tc_destruction)
    del def_tc
