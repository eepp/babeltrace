# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

import os
import typing
import unittest

import bt2

# pyright: strict,  reportPrivateUsage=false

T = typing.TypeVar("T")


# Assert that `obj` is of type `expected_type` and return it as a `T`.
def c(obj: object, expected_type: typing.Type[T]) -> T:
    assert type(obj) is expected_type
    return obj


class TheSink(bt2._UserSinkComponent):
    def __init__(
        self,
        config: bt2._UserSinkComponentConfiguration,
        params: bt2._MapValueConst,
        obj: object,
    ):
        self._in = self._add_input_port("in")
        self._test = typing.cast(unittest.TestCase, obj)

    def _user_graph_is_configured(self):
        self._iter = self._create_message_iterator(self._in)

    def _test_blob(
        self,
        static_blob: bt2._StaticBlobFieldConst,
        dynamic_blob_without_length_field: bt2._DynamicBlobFieldConst,
        dynamic_blob_with_length_field: bt2._DynamicBlobFieldWithLengthFieldConst,
    ):
        # Test `_BlobFieldClassConst.media_type`
        self._test.assertEqual(static_blob.cls.media_type, "application/x-gameboy-rom")
        self._test.assertEqual(
            dynamic_blob_without_length_field.cls.media_type,
            "application/x-shockwave-flash",
        )
        self._test.assertEqual(
            dynamic_blob_with_length_field.cls.media_type, "application/vnd.wordperfect"
        )

        # Test `_StaticBlobFieldClassConst.length`
        self._test.assertEqual(static_blob.cls.length, 10)

        # Test `_DynamicBlobFieldClassWithLengthFieldConst.length_field_location`
        lfl = dynamic_blob_with_length_field.cls.length_field_location
        self._test.assertEqual(lfl.root_scope, bt2.FieldLocationScope.EVENT_PAYLOAD)
        self._test.assertEqual(list(lfl), ["dynamic-blob-with-length-field-length"])

        # Test _BlobFieldConst.data
        self._test.assertEqual(static_blob.data, b"Masbourian")
        self._test.assertEqual(dynamic_blob_without_length_field.data, b"mdr")
        self._test.assertEqual(dynamic_blob_with_length_field.data, b"buick")

        # Test `_BlobFieldConst.length` and `_BlobFieldConst.__len__()`
        self._test.assertEqual(len(static_blob), 10)
        self._test.assertEqual(static_blob.length, 10)
        self._test.assertEqual(len(dynamic_blob_without_length_field), 3)
        self._test.assertEqual(dynamic_blob_without_length_field.length, 3)
        self._test.assertEqual(len(dynamic_blob_with_length_field), 5)
        self._test.assertEqual(dynamic_blob_with_length_field.length, 5)

    def _test_bit_array(self, bit_array: bt2._BitArrayFieldConst):
        bit_array_fc = bit_array.cls

        # Test `_BitArrayFieldClassConst.length`
        self._test.assertEqual(bit_array_fc.length, 16)

        # Test `_BitArrayFieldClassConst.active_flags_for_value_as_integer`
        self._test.assertEqual(
            [
                flag.label
                for flag in bit_array_fc.active_flags_for_value_as_integer(0b10)
            ],
            ["flag1"],
        )
        self._test.assertEqual(
            bit_array_fc.active_flags_for_value_as_integer(0b10000000000), []
        )

        # Test `_BitArrayFieldClassConst.__len__()`
        self._test.assertEqual(len(bit_array_fc), 2)

        def flag_to_tuple(flag: bt2._BitArrayFieldClassFlagConst):
            self._test.assertIsInstance(flag.label, str)
            self._test.assertIsInstance(flag.ranges, bt2._UnsignedIntegerRangeSetConst)
            return (flag.label, [(rng.lower, rng.upper) for rng in flag.ranges])

        # Test `_BitArrayFieldClassConst.__iter__()`,
        # `_BitArrayFieldClassConst.__getitem__()`,
        # `_BitArrayFieldClassFlagConst.label` and
        # `_BitArrayFieldClassFlagConst.ranges`
        self._test.assertEqual(
            [flag_to_tuple(bit_array_fc[name]) for name in bit_array_fc],
            [
                ("flag1", [(1, 3), (6, 9)]),
                ("flag2", [(4, 6)]),
            ],
        )

        # Test `_BitArrayFieldConst.active_flag_labels`
        self._test.assertEqual(bit_array.active_flag_labels, ["flag1", "flag2"])

    def _test_option(
        self,
        field: bt2._OptionFieldWithBoolSelectorFieldConst,
    ):
        # Test `_OptionFieldClassWithSelectorFieldConst.selector_field_location`
        sfl = field.cls.selector_field_location
        self._test.assertEqual(sfl.root_scope, bt2.FieldLocationScope.EVENT_PAYLOAD)
        self._test.assertEqual(
            list(sfl), ["option-with-bool-selector-field-selector-true"]
        )

    def _test_variant(self, field: bt2._VariantFieldConst):
        # Test that iterating on a variant with MIP 1 yields
        # indices, not strings.
        self._test.assertEqual(list(field.cls), [0, 1])

        # Test that option names can be `None`.
        self._test.assertEqual(field.cls[0].name, "opt1")
        self._test.assertEqual(field.cls[1].name, None)

    def _user_consume(self):
        msg = next(self._iter)

        if type(msg) is not bt2._EventMessageConst:
            return

        p = msg.event.payload_field
        assert p is not None

        self._test_blob(
            c(p["static-blob"], bt2._StaticBlobFieldConst),
            c(
                p["dynamic-blob-without-length-field"],
                bt2._DynamicBlobFieldConst,
            ),
            c(
                p["dynamic-blob-with-length-field"],
                bt2._DynamicBlobFieldWithLengthFieldConst,
            ),
        )
        self._test_bit_array(c(p["bit-array"], bt2._BitArrayFieldConst))
        self._test_option(
            c(
                p["option-with-bool-selector-field-with-value"],
                bt2._OptionFieldWithBoolSelectorFieldConst,
            ),
        )
        self._test_variant(
            c(p["variant-without-selector-field"], bt2._VariantFieldConst)
        )


class TestMIP1(unittest.TestCase):
    def test_all_fields(self):
        g = bt2.Graph(1)
        trace_ir = bt2.find_plugin("trace-ir-test")

        if trace_ir is None:
            raise RuntimeError("`trace-ir-test` plugin not found")

        all_fields = trace_ir.source_component_classes["AllFields"]
        if all_fields is None:
            raise RuntimeError("`AllFields` source component class not found")

        g.connect_ports(
            g.add_component(all_fields, "the-source").output_ports["out"],
            g.add_component(TheSink, "the-sink", obj=self).input_ports["in"],
        )
        g.run()


if __name__ == "__main__":
    unittest.main()
