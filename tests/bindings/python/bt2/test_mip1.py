# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 EfficiOS Inc.

import bt2
import pytest


# Assert that `obj` is of type `expected_type` and return it.
def _assert_type(obj, expected_type):
    assert type(obj) is expected_type
    return obj


# Runs the graph and captures the event payload field of the first
# event message.
#
# The field remains valid after graph execution as long as we hold a
# Python reference to it (a field holds a reference to its
# owning message).
@pytest.fixture(scope="module")
def payload_field():
    field = None

    class FieldCapture(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._in = self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._iter = self._create_message_iterator(self._in)

        def _user_consume(self):
            nonlocal field

            msg = next(self._iter)

            if type(msg) is bt2._EventMessageConst:
                field = msg.event.payload_field

    graph = bt2.Graph(1)
    trace_ir = bt2.find_plugin("trace-ir-test")
    assert trace_ir is not None
    all_fields = trace_ir.source_component_classes["AllFields"]
    assert all_fields is not None

    graph.connect_ports(
        graph.add_component(all_fields, "the-source").output_ports["out"],
        graph.add_component(FieldCapture, "the-sink").input_ports["in"],
    )

    graph.run()
    assert field is not None
    return field


class TestBlobFc:
    @pytest.fixture(scope="class")
    def static_field(self, payload_field):
        return _assert_type(payload_field["static-blob"], bt2._StaticBlobFieldConst)

    @pytest.fixture(scope="class")
    def dyn_field_no_len(self, payload_field):
        return _assert_type(
            payload_field["dynamic-blob-without-length-field"],
            bt2._DynamicBlobFieldConst,
        )

    @pytest.fixture(scope="class")
    def dyn_field_with_len(self, payload_field):
        return _assert_type(
            payload_field["dynamic-blob-with-length-field"],
            bt2._DynamicBlobFieldWithLengthFieldConst,
        )

    def test_fc_media_type(self, static_field, dyn_field_no_len, dyn_field_with_len):
        assert static_field.cls.media_type == "application/x-gameboy-rom"
        assert dyn_field_no_len.cls.media_type == "application/x-shockwave-flash"
        assert dyn_field_with_len.cls.media_type == "application/vnd.wordperfect"

    def test_static_fc_len(self, static_field):
        assert static_field.cls.length == 10

    def test_dyn_with_len_fc_len_field_loc(self, dyn_field_with_len):
        lfl = dyn_field_with_len.cls.length_field_location
        assert lfl.root_scope == bt2.FieldLocationScope.EVENT_PAYLOAD
        assert list(lfl) == ["dynamic-blob-with-length-field-length"]

    def test_data(self, static_field, dyn_field_no_len, dyn_field_with_len):
        assert static_field.data == b"Masbourian"
        assert dyn_field_no_len.data == b"mdr"
        assert dyn_field_with_len.data == b"buick"

    def test_len(self, static_field, dyn_field_no_len, dyn_field_with_len):
        assert len(static_field) == 10
        assert static_field.length == 10
        assert len(dyn_field_no_len) == 3
        assert dyn_field_no_len.length == 3
        assert len(dyn_field_with_len) == 5
        assert dyn_field_with_len.length == 5


class TestBitArrayFc:
    @pytest.fixture(scope="class")
    def field(self, payload_field):
        return _assert_type(payload_field["bit-array"], bt2._BitArrayFieldConst)

    def test_fc_len(self, field):
        assert field.cls.length == 16

    def test_fc_active_flags_for_value_as_integer(self, field):
        fc = field.cls
        assert [flag.label for flag in fc.active_flags_for_value_as_integer(0b10)] == [
            "flag1"
        ]
        assert fc.active_flags_for_value_as_integer(0b10000000000) == []

    def test_fc_len(self, field):
        assert len(field.cls) == 2

    def test_fc_iter_getitem_flag_label_ranges(self, field):
        fc = field.cls

        def flag_to_tuple(flag):
            assert isinstance(flag.label, str)
            assert isinstance(flag.ranges, bt2._UnsignedIntegerRangeSetConst)
            return (flag.label, [(rng.lower, rng.upper) for rng in flag.ranges])

        assert [flag_to_tuple(fc[name]) for name in fc] == [
            ("flag1", [(1, 3), (6, 9)]),
            ("flag2", [(4, 6)]),
        ]

    def test_active_flag_labels(self, field):
        assert field.active_flag_labels == ["flag1", "flag2"]


class TestOptFc:
    @pytest.fixture(scope="class")
    def field(self, payload_field):
        return _assert_type(
            payload_field["option-with-bool-selector-field-with-value"],
            bt2._OptionFieldWithBoolSelectorFieldConst,
        )

    def test_fc_sel_field_loc(self, field):
        sfl = field.cls.selector_field_location
        assert sfl.root_scope == bt2.FieldLocationScope.EVENT_PAYLOAD
        assert list(sfl) == ["option-with-bool-selector-field-selector-true"]


class TestVarFc:
    @pytest.fixture(scope="class")
    def field(self, payload_field):
        return _assert_type(
            payload_field["variant-without-selector-field"], bt2._VariantFieldConst
        )

    def test_fc_iter_yields_indices(self, field):
        assert list(field.cls) == [0, 1]

    def test_fc_option_name_can_be_none(self, field):
        assert field.cls[0].name == "opt1"
        assert field.cls[1].name is None
