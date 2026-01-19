# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import utils
import pytest
from bt2 import value as bt2_value
from bt2 import event_class as bt2_ec
from bt2 import field_class as bt2_fc
from bt2 import stream_class as bt2_sc


@pytest.fixture
def sc(def_tc):
    return def_tc.create_stream_class(assigns_automatic_event_class_id=True)


@pytest.fixture
def const_ec(def_tc, sc):
    fc1 = def_tc.create_structure_field_class()
    fc2 = def_tc.create_structure_field_class()
    ec = sc.create_event_class(
        payload_field_class=fc1, specific_context_field_class=fc2
    )

    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            trace = def_tc()
            stream = trace.create_stream(sc)
            self._msgs = [
                self._create_stream_beginning_message(stream),
                self._create_event_message(ec, stream),
            ]

        def __next__(self):
            if len(self._msgs) == 0:
                raise StopIteration

            return self._msgs.pop(0)

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out", params)

    graph = bt2.Graph()
    src_comp = graph.add_component(MySrc, "my_source", None)
    msg_iter = utils.TestOutputPortMessageIterator(graph, src_comp.output_ports["out"])

    # Ignore first message (stream beginning)
    next(msg_iter)
    return next(msg_iter).event.cls


def test_create_def(sc):
    ec = sc.create_event_class()
    assert type(ec) is bt2_ec._EventClass
    assert ec.name is None
    assert type(ec.id) is int
    assert ec.specific_context_field_class is None
    assert ec.payload_field_class is None
    assert ec.emf_uri is None
    assert ec.log_level is None
    assert len(ec.user_attributes) == 0


def test_create_invalid_id(def_tc):
    sc = def_tc.create_stream_class(assigns_automatic_event_class_id=False)

    with pytest.raises(TypeError):
        sc.create_event_class(id="lel")

    assert len(sc) == 0


def test_create_specific_context_field_class(def_tc, sc):
    fc = def_tc.create_structure_field_class()
    ec = sc.create_event_class(specific_context_field_class=fc)
    assert ec.specific_context_field_class.addr == fc.addr
    assert type(ec.specific_context_field_class) is bt2_fc._StructureFieldClass


def test_const_create_specific_context_field_class(const_ec):
    assert (
        type(const_ec.specific_context_field_class) is bt2_fc._StructureFieldClassConst
    )


def test_create_invalid_specific_context_field_class(sc):
    with pytest.raises(TypeError):
        sc.create_event_class(specific_context_field_class="lel")

    assert len(sc) == 0


def test_create_payload_field_class(def_tc, sc):
    fc = def_tc.create_structure_field_class()
    ec = sc.create_event_class(payload_field_class=fc)
    assert ec.payload_field_class.addr == fc.addr
    assert type(ec.payload_field_class) is bt2_fc._StructureFieldClass


def test_const_create_payload_field_class(const_ec):
    assert type(const_ec.payload_field_class) is bt2_fc._StructureFieldClassConst


def test_create_invalid_payload_field_class(sc):
    with pytest.raises(TypeError):
        sc.create_event_class(payload_field_class="lel")

    assert len(sc) == 0


def test_create_name(sc):
    ec = sc.create_event_class(name="viande à chien")
    assert ec.name == "viande à chien"


def test_create_invalid_name(sc):
    with pytest.raises(TypeError):
        sc.create_event_class(name=2)

    assert len(sc) == 0


def test_emf_uri(sc):
    ec = sc.create_event_class(emf_uri="salut")
    assert ec.emf_uri == "salut"


def test_create_invalid_emf_uri(sc):
    with pytest.raises(TypeError):
        sc.create_event_class(emf_uri=23)

    assert len(sc) == 0


def test_create_log_level(sc):
    ec = sc.create_event_class(log_level=bt2.EventClassLogLevel.EMERGENCY)
    assert ec.log_level == bt2.EventClassLogLevel.EMERGENCY


def test_create_invalid_log_level(sc):
    with pytest.raises(ValueError):
        sc.create_event_class(log_level="zoom")

    assert len(sc) == 0


def test_create_user_attrs(sc):
    ec = sc.create_event_class(user_attributes={"salut": 23})
    assert ec.user_attributes == {"salut": 23}
    assert type(ec.user_attributes) is bt2_value.MapValue


def test_const_create_user_attrs(const_ec):
    assert type(const_ec.user_attributes) is bt2_value._MapValueConst


def test_create_invalid_user_attrs(sc):
    with pytest.raises(TypeError):
        sc.create_event_class(user_attributes=object())

    assert len(sc) == 0


def test_create_invalid_user_attrs_value_type(sc):
    with pytest.raises(TypeError):
        sc.create_event_class(user_attributes=23)

    assert len(sc) == 0


def test_stream_class(sc):
    ec = sc.create_event_class()
    assert ec.stream_class.addr == sc.addr
    assert type(ec.stream_class) is bt2_sc._StreamClass


def test_const_stream_class(const_ec):
    assert type(const_ec.stream_class) is bt2_sc._StreamClassConst
