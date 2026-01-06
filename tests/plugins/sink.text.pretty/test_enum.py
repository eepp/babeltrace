# SPDX-FileCopyrightText: 2020 Geneviève Bastien <gbastien@versatic.net>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import re
import types
import pathlib
import tempfile

import bt2
import pytest
import bt_tests_utils as btu


class _MsgIter(bt2._UserMessageIterator):
    def __init__(self, config, port):
        stream = port.user_data.tc().create_stream(port.user_data.sc)
        self._msgs = [self._create_stream_beginning_message(stream)]
        ev_msg = self._create_event_message(port.user_data.ec, stream)
        ev_msg.event.payload_field["enum_field"] = port.user_data.value
        self._msgs.append(ev_msg)
        self._msgs.append(self._create_stream_end_message(stream))
        self._at = 0
        config.can_seek_forward = True

    def _user_seek_beginning(self):
        self._at = 0

    def __next__(self):
        if self._at < len(self._msgs):
            msg = self._msgs[self._at]
            self._at += 1
            return msg

        raise StopIteration


class _Src(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        tc = self._create_trace_class()
        sc = tc.create_stream_class()

        # Create the enumeration field class with the mappings
        # from `obj`.
        if obj.is_signed:
            enum_fc = tc.create_signed_enumeration_field_class()
            range_set_type = bt2.SignedIntegerRangeSet
        else:
            enum_fc = tc.create_unsigned_enumeration_field_class()
            range_set_type = bt2.UnsignedIntegerRangeSet

        for label, ranges in obj.mappings.items():
            enum_fc.add_mapping(label, range_set_type(ranges))

        self._add_output_port(
            "out",
            types.SimpleNamespace(
                tc=tc,
                sc=sc,
                ec=sc.create_event_class(
                    name="with_enum",
                    payload_field_class=tc.create_structure_field_class(
                        members=(("enum_field", enum_fc),)
                    ),
                ),
                value=obj.value,
            ),
        )


_NORMAL_ENUM_MAPPINGS = {
    "single": [(1, 1)],
    "single2": [(2, 2)],
    "single3": [(4, 4)],
    "range": [(4, 8)],
    "range2": [(15, 20)],
}

_NORMAL_ENUM_NEGATIVE_MAPPINGS = {
    "zero": [(0, 0)],
    "single": [(1, 1)],
    "single2": [(2, 2)],
    "single3": [(4, 4)],
    "range": [(4, 8)],
    "negative": [(-1, -1)],
    "rangeNegative": [(-6, -2)],
}

_BIT_FLAG_ENUM_MAPPINGS = {
    "bit0": [(1, 1)],
    "bit0bis": [(1, 1)],
    "bit1": [(2, 2)],
    "bit3": [(4, 4)],
    "bit4": [(8, 8)],
    "bit5": [(16, 16), (32, 32)],
}

_MIXED_ENUM_BITS_AT_BEGINNING_MAPPINGS = {
    "bit0": [(1, 1)],
    "bit1": [(2, 2)],
    "bit2": [(4, 4)],
    "bit3": [(8, 8)],
    "bit4": [(16, 16)],
    "range": [(32, 44)],
    "singleValue": [(45, 45)],
}

_MIXED_ENUM_BITS_AT_END_MAPPINGS = {
    "val1": [(1, 1)],
    "val2": [(2, 2)],
    "val3": [(3, 3)],
    "val4": [(4, 4)],
    "val5": [(5, 5)],
    "bit3": [(8, 8)],
    "bit4": [(16, 16)],
    "bit5": [(32, 32)],
}


@pytest.mark.parametrize(
    ["enum_mappings", "is_signed", "value", "expected"],
    [
        # Normal enum (unsigned)
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            False,
            1,
            'with_enum: { enum_field = ( "single" : container = 1 ) }',
            id="normal-unsigned-single-value",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            False,
            7,
            'with_enum: { enum_field = ( "range" : container = 7 ) }',
            id="normal-unsigned-single-range",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            False,
            4,
            'with_enum: { enum_field = ( { "single3", "range" } : container = 4 ) }',
            id="normal-unsigned-range-and-value",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            False,
            21,
            "with_enum: { enum_field = ( <unknown> : container = 21 ) }",
            id="normal-unsigned-unknown",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            False,
            12,
            "with_enum: { enum_field = ( <unknown> : container = 12 ) }",
            id="normal-unsigned-unknown-bits-range-larger-than-1",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            False,
            0,
            "with_enum: { enum_field = ( <unknown> : container = 0 ) }",
            id="normal-unsigned-unknown-zero",
        ),
        # Normal enum (signed)
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            True,
            1,
            'with_enum: { enum_field = ( "single" : container = 1 ) }',
            id="normal-signed-single-value",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            True,
            7,
            'with_enum: { enum_field = ( "range" : container = 7 ) }',
            id="normal-signed-single-range",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            True,
            4,
            'with_enum: { enum_field = ( { "single3", "range" } : container = 4 ) }',
            id="normal-signed-range-and-value",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            True,
            21,
            "with_enum: { enum_field = ( <unknown> : container = 21 ) }",
            id="normal-signed-unknown",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            True,
            12,
            "with_enum: { enum_field = ( <unknown> : container = 12 ) }",
            id="normal-signed-unknown-bits-range-larger-than-1",
        ),
        pytest.param(
            _NORMAL_ENUM_MAPPINGS,
            True,
            0,
            "with_enum: { enum_field = ( <unknown> : container = 0 ) }",
            id="normal-signed-unknown-zero",
        ),
        # Normal enum with negative values (signed)
        pytest.param(
            _NORMAL_ENUM_NEGATIVE_MAPPINGS,
            True,
            -1,
            'with_enum: { enum_field = ( "negative" : container = -1 ) }',
            id="negative-single-value",
        ),
        pytest.param(
            _NORMAL_ENUM_NEGATIVE_MAPPINGS,
            True,
            -6,
            'with_enum: { enum_field = ( "rangeNegative" : container = -6 ) }',
            id="negative-single-range",
        ),
        pytest.param(
            _NORMAL_ENUM_NEGATIVE_MAPPINGS,
            True,
            -7,
            "with_enum: { enum_field = ( <unknown> : container = -7 ) }",
            id="negative-unknown",
        ),
        pytest.param(
            _NORMAL_ENUM_NEGATIVE_MAPPINGS,
            True,
            0,
            'with_enum: { enum_field = ( "zero" : container = 0 ) }',
            id="negative-zero",
        ),
        # Bit flag enum (unsigned)
        pytest.param(
            _BIT_FLAG_ENUM_MAPPINGS,
            False,
            2,
            'with_enum: { enum_field = ( "bit1" : container = 2 ) }',
            id="bit-flag-unsigned-single-hit",
        ),
        pytest.param(
            _BIT_FLAG_ENUM_MAPPINGS,
            False,
            12,
            'with_enum: { enum_field = ( "bit3" | "bit4" : container = 12 ) }',
            id="bit-flag-unsigned-multiple-flags",
        ),
        pytest.param(
            _BIT_FLAG_ENUM_MAPPINGS,
            False,
            68,
            "with_enum: { enum_field = ( <unknown> : container = 68 ) }",
            id="bit-flag-unsigned-unknown-bit",
        ),
        pytest.param(
            _BIT_FLAG_ENUM_MAPPINGS,
            False,
            1,
            'with_enum: { enum_field = ( { "bit0", "bit0bis" } : container = 1 ) }',
            id="bit-flag-unsigned-multiple-labels-bit0",
        ),
        pytest.param(
            _BIT_FLAG_ENUM_MAPPINGS,
            False,
            3,
            'with_enum: { enum_field = ( { "bit0", "bit0bis" } | "bit1" : container = 3 ) }',
            id="bit-flag-unsigned-two-labels-bit0-one-label-bit1",
        ),
        pytest.param(
            _BIT_FLAG_ENUM_MAPPINGS,
            False,
            48,
            'with_enum: { enum_field = ( "bit5" | "bit5" : container = 48 ) }',
            id="bit-flag-unsigned-single-label-bit5",
        ),
        # Bit flag enum (signed, negative value)
        pytest.param(
            _BIT_FLAG_ENUM_MAPPINGS,
            True,
            -1,
            "with_enum: { enum_field = ( <unknown> : container = -1 ) }",
            id="bit-flag-signed-negative",
        ),
        # Mixed enum (bits at beginning)
        pytest.param(
            _MIXED_ENUM_BITS_AT_BEGINNING_MAPPINGS,
            False,
            31,
            'with_enum: { enum_field = ( "bit0" | "bit1" | "bit2" | "bit3" | "bit4" : container = 31 ) }',
            id="mixed-bits-beginning-bit-fields",
        ),
        pytest.param(
            _MIXED_ENUM_BITS_AT_BEGINNING_MAPPINGS,
            False,
            36,
            'with_enum: { enum_field = ( "range" : container = 36 ) }',
            id="mixed-bits-beginning-within-range",
        ),
        pytest.param(
            _MIXED_ENUM_BITS_AT_BEGINNING_MAPPINGS,
            False,
            45,
            'with_enum: { enum_field = ( "singleValue" : container = 45 ) }',
            id="mixed-bits-beginning-corresponding-to-value",
        ),
        pytest.param(
            _MIXED_ENUM_BITS_AT_BEGINNING_MAPPINGS,
            False,
            46,
            "with_enum: { enum_field = ( <unknown> : container = 46 ) }",
            id="mixed-bits-beginning-above-ranges",
        ),
        # Mixed enum (bits at end)
        pytest.param(
            _MIXED_ENUM_BITS_AT_END_MAPPINGS,
            False,
            16,
            'with_enum: { enum_field = ( "bit4" : container = 16 ) }',
            id="mixed-bits-end-bit-field",
        ),
        pytest.param(
            _MIXED_ENUM_BITS_AT_END_MAPPINGS,
            False,
            17,
            'with_enum: { enum_field = ( "val1" | "bit4" : container = 17 ) }',
            id="mixed-bits-end-beginning-and-end",
        ),
    ],
)
def test_enum(capfd, pretty_comp_cls, enum_mappings, is_signed, value, expected):
    def sorted_enum_output(text):
        # The order in which enum labels are printed by a
        # `sink.text.pretty` component directly depends on the order in
        # which mappings were added to the enum field class in the
        # source component.
        #
        # This order should not be relied on when testing.
        return "".join(sorted(re.findall(r"\w+|\W+", text.strip())))

    with tempfile.TemporaryDirectory(prefix="bt-test-enum-") as temp_dir:
        out_path = pathlib.Path(temp_dir) / "output.txt"

        btu.convert(
            bt2.ComponentSpec(
                _Src,
                obj=types.SimpleNamespace(
                    mappings=enum_mappings, is_signed=is_signed, value=value
                ),
            ),
            btu.SinkComponentSpec(
                pretty_comp_cls,
                {"print-enum-flags": True, "path": str(out_path)},
            ),
        )

        output = out_path.read_text()
        assert sorted_enum_output(output) == sorted_enum_output(expected)
        assert capfd.readouterr().err == ""
