import bt2.fields
import unittest
import bt2


class _TestIntegerFieldTypeProps:
    def test_range_prop(self):
        self.assertEqual(self._ft.range, 35)

    def test_assign_base(self):
        self._ft.base = bt2.IntegerDisplayBase.HEXADECIMAL
        self.assertEqual(self._ft.base, bt2.IntegerDisplayBase.HEXADECIMAL)

    def test_assign_invalid_base(self):
        with self.assertRaises(TypeError):
            self._ft.base = 'hey'


class IntegerFieldTypeTestCase(_TestIntegerFieldTypeProps, unittest.TestCase):
    def setUp(self):
        self._ft = bt2.SignedIntegerFieldType(35)

    def tearDown(self):
        del self._ft

    def test_create_default(self):
        self.assertEqual(self._ft.range, 35)

    def test_create_invalid_range(self):
        with self.assertRaises(TypeError):
            ft = bt2.SignedIntegerFieldType('yes')

    def test_create_neg_range(self):
        with self.assertRaises(ValueError):
            ft = bt2.SignedIntegerFieldType(-2)

    def test_create_zero_range(self):
        with self.assertRaises(ValueError):
            ft = bt2.SignedIntegerFieldType(0)

    def test_create_full(self):
        ft = bt2.UnsignedIntegerFieldType(24, display_base=bt2.IntegerDisplayBase.OCTAL)
        self.assertEqual(ft.range, 24)
        self.assertEqual(ft.base, bt2.IntegerDisplayBase.OCTAL)


class RealFieldTypeTestCase(unittest.TestCase):
    def setUp(self):
        self._ft = bt2.RealFieldType()

    def tearDown(self):
        del self._ft

    def test_create_default(self):
        pass

    def test_create_full(self):
        ft = bt2.RealFieldType(is_single_precision=True)
        self.assertTrue(ft.single_precision)

class EnumerationFieldTypeTestCase(_TestIntegerFieldTypeProps, unittest.TestCase):
    def setUp(self):
        self._ft = bt2.SignedEnumerationFieldType(range=35)
        self._unsigned_ft = bt2.UnsignedEnumerationFieldType(range=35)

    def tearDown(self):
        del self._ft
        del self._unsigned_ft

    def test_create_from_invalid_type(self):
        with self.assertRaises(TypeError):
            self._ft = bt2.SignedEnumerationFieldType('coucou')

    def test_create_from_invalid_ft(self):
        with self.assertRaises(TypeError):
            ft = bt2.RealFieldType()
            self._ft = bt2.SignedEnumerationFieldType(ft)

    def test_create_full(self):
        ft = bt2.SignedEnumerationFieldType(range=24, display_base=bt2.IntegerDisplayBase.OCTAL)
        self.assertEqual(ft.range, 24)
        self.assertEqual(ft.base, bt2.IntegerDisplayBase.OCTAL)

    def test_add_mapping_simple(self):
        self._ft.map_range('hello', 24)
        mapping = self._ft['hello']
        first_range = next(iter(mapping))
        self.assertEqual(mapping.label, 'hello')
        self.assertEqual(first_range.lower, 24)
        self.assertEqual(first_range.upper, 24)

    def test_add_mapping_simple_kwargs(self):
        self._ft.map_range(label='hello', lower=17, upper=23)
        mapping = self._ft['hello']
        first_range = next(iter(mapping))
        self.assertEqual(mapping.label, 'hello')
        self.assertEqual(first_range.lower, 17)
        self.assertEqual(first_range.upper, 23)

    def test_add_mapping_range(self):
        self._ft.map_range('hello', 21, 199)
        mapping = self._ft['hello']
        first_range = next(iter(mapping))
        self.assertEqual(mapping.label, 'hello')
        self.assertEqual(first_range.lower, 21)
        self.assertEqual(first_range.upper, 199)

    def test_add_mapping_invalid_name(self):
        with self.assertRaises(TypeError):
            self._ft.map_range(17, 21, 199)

    def test_add_mapping_invalid_signedness_lower(self):
        with self.assertRaises(ValueError):
            self._unsigned_ft.map_range('hello', -21, 199)

    def test_add_mapping_invalid_signedness_upper(self):
        with self.assertRaises(ValueError):
            self._unsigned_ft.map_range('hello', 21, -199)

    def test_add_mapping_simple_signed(self):
        self._ft.map_range('hello', -24)
        mapping = self._ft['hello']
        first_range = next(iter(mapping))
        self.assertEqual(mapping.label, 'hello')
        self.assertEqual(first_range.lower, -24)
        self.assertEqual(first_range.upper, -24)

    def test_add_mapping_range_signed(self):
        self._ft.map_range('hello', -21, 199)
        mapping = self._ft['hello']
        first_range = next(iter(mapping))
        self.assertEqual(mapping.label, 'hello')
        self.assertEqual(first_range.lower, -21)
        self.assertEqual(first_range.upper, 199)

    def test_iadd(self):
        enum_ft = bt2.SignedEnumerationFieldType(range=16)
        enum_ft.map_range('c', 4, 5)
        enum_ft.map_range('d', 6, 18)
        enum_ft.map_range('e', 20, 27)
        self._ft.map_range('a', 0, 2)
        self._ft.map_range('b', 3)
        self._ft += enum_ft


        self.assertEqual(self._ft['a'].label, 'a')
        first_range = next(iter(self._ft['a']))
        self.assertEqual(first_range.lower, 0)
        self.assertEqual(first_range.upper, 2)

        self.assertEqual(self._ft['b'].label, 'b')
        first_range = next(iter(self._ft['b']))
        self.assertEqual(first_range.lower, 3)
        self.assertEqual(first_range.upper, 3)

        self.assertEqual(self._ft['c'].label, 'c')
        first_range = next(iter(self._ft['c']))
        self.assertEqual(first_range.lower, 4)
        self.assertEqual(first_range.upper, 5)

        self.assertEqual(self._ft['d'].label, 'd')
        first_range = next(iter(self._ft['d']))
        self.assertEqual(first_range.lower, 6)
        self.assertEqual(first_range.upper, 18)

        self.assertEqual(self._ft['e'].label, 'e')
        first_range = next(iter(self._ft['e']))
        self.assertEqual(first_range.lower, 20)
        self.assertEqual(first_range.upper, 27)

    def test_bool_op(self):
        self.assertFalse(self._ft)
        self._ft.map_range('a', 0)
        self.assertTrue(self._ft)

    def test_len(self):
        self._ft.map_range('a', 0)
        self._ft.map_range('b', 1)
        self._ft.map_range('c', 2)
        self.assertEqual(len(self._ft), 3)

    def test_getitem(self):
        self._ft.map_range('a', 0)
        self._ft.map_range('b', 1, 3)
        self._ft.map_range('c', 5)
        mapping = self._ft['b']
        self.assertEqual(mapping.label, 'b')
        first_range = next(iter(mapping))
        self.assertEqual(first_range.lower, 1)
        self.assertEqual(first_range.upper, 3)

    def test_iter(self):
        mappings = (
            ('a', 1, 5),
            ('b', 10, 17),
            ('c', 20, 1504),
            ('d', 22510, 99999),
        )

        for mapping in mappings:
            self._ft.map_range(*mapping)


        for ft_mapping, mapping in zip(self._ft, mappings):
            self.assertEqual(ft_mapping.label, mapping[0])
            first_range = next(iter(ft_mapping))
            self.assertEqual(first_range.lower, mapping[1])
            self.assertEqual(first_range.upper, mapping[2])

    def _test_find_by_name(self, ft):
        ft.map_range('a', 0)
        ft.map_range('b', 1, 3)
        ft.map_range('a', 5)
        ft.map_range('a', 17, 123)
        ft.map_range('C', 5)
        mapping = ft['a']
        a0 = False
        a5 = False
        a17_123 = False
        i = 0

        self.assertEqual(mapping.label, 'a')
        
        for range in mapping:
            if range.lower == 0 and range.upper == 0:
                a0 = True
            elif range.lower == 5 and range.upper == 5:
                a5 = True
            elif range.lower == 17 and range.upper == 123:
                a17_123 = True

        self.assertEqual(len(mapping), 3)
        self.assertTrue(a0)
        self.assertTrue(a5)
        self.assertTrue(a17_123)

    def test_find_by_name_signed(self):
        self._test_find_by_name(bt2.SignedEnumerationFieldType(range=8))

    def test_find_by_name_unsigned(self):
        self._test_find_by_name(bt2.UnsignedEnumerationFieldType(range=8))

    def _test_find_by_value(self, ft):
        ft.map_range('a', 0)
        ft.map_range('b', 1, 3)
        ft.map_range('c', 5, 19)
        ft.map_range('d', 8, 15)
        ft.map_range('e', 10, 21)
        ft.map_range('f', 0)
        ft.map_range('g', 14)

        labels = ft.labels_by_value(14)


        expected_labels = ['c', 'd', 'e', 'g']

        self.assertTrue(all(label in labels for label in expected_labels))

    def test_find_by_value_signed(self):
        self._test_find_by_value(bt2.SignedEnumerationFieldType(range=8))

    def test_find_by_value_unsigned(self):
        self._test_find_by_value(bt2.UnsignedEnumerationFieldType(range=8))


class StringFieldTypeTestCase(unittest.TestCase):
    def setUp(self):
        self._ft = bt2.StringFieldType()

    def tearDown(self):
        del self._ft

    def test_create_default(self):
        self.assertIsNotNone(self._ft)


class _TestFieldContainer():
    def test_append_field(self):
        int_field_type = bt2.SignedIntegerFieldType(32)
        self._ft.append_field('int32', int_field_type)
        field_type = self._ft['int32']
        self.assertEqual(field_type.addr, int_field_type.addr)

    def test_append_field_kwargs(self):
        int_field_type = bt2.SignedIntegerFieldType(32)
        self._ft.append_field(name='int32', field_type=int_field_type)
        field_type = self._ft['int32']
        self.assertEqual(field_type.addr, int_field_type.addr)

    def test_append_field_invalid_name(self):
        with self.assertRaises(TypeError):
            self._ft.append_field(23, bt2.StringFieldType())

    def test_append_field_invalid_field_type(self):
        with self.assertRaises(TypeError):
            self._ft.append_field('yes', object())

    def test_iadd(self):
        struct_ft = bt2.StructureFieldType()
        c_field_type = bt2.StringFieldType()
        d_field_type = bt2.SignedEnumerationFieldType(range=32)
        e_field_type = bt2.StructureFieldType()
        struct_ft.append_field('c_string', c_field_type)
        struct_ft.append_field('d_enum', d_field_type)
        struct_ft.append_field('e_struct', e_field_type)
        a_field_type = bt2.RealFieldType()
        b_field_type = bt2.SignedIntegerFieldType(17)
        self._ft.append_field('a_float', a_field_type)
        self._ft.append_field('b_int', b_field_type)
        self._ft += struct_ft
        self.assertEqual(self._ft['a_float'].addr, a_field_type.addr)
        self.assertEqual(self._ft['b_int'].addr, b_field_type.addr)
        self.assertEqual(self._ft['c_string'].addr, c_field_type.addr)
        self.assertEqual(self._ft['d_enum'].addr, d_field_type.addr)
        self.assertEqual(self._ft['e_struct'].addr, e_field_type.addr)

    def test_bool_op(self):
        self.assertFalse(self._ft)
        self._ft.append_field('a', bt2.StringFieldType())
        self.assertTrue(self._ft)

    def test_len(self):
        ft = bt2.StringFieldType()
        self._ft.append_field('a', ft)
        self._ft.append_field('b', ft)
        self._ft.append_field('c', ft)
        self.assertEqual(len(self._ft), 3)

    def test_getitem(self):
        a_ft = bt2.SignedIntegerFieldType(32)
        b_ft = bt2.StringFieldType()
        c_ft = bt2.RealFieldType()
        self._ft.append_field('a', a_ft)
        self._ft.append_field('b', b_ft)
        self._ft.append_field('c', c_ft)
        self.assertEqual(self._ft['b'].addr, b_ft.addr)

    def test_getitem_invalid_key_type(self):
        with self.assertRaises(TypeError):
            self._ft[0]

    def test_getitem_invalid_key(self):
        with self.assertRaises(KeyError):
            self._ft['no way']

    def test_contains(self):
        self.assertFalse('a' in self._ft)
        self._ft.append_field('a', bt2.StringFieldType())
        self.assertTrue('a' in self._ft)

    def test_iter(self):
        a_ft = bt2.SignedIntegerFieldType(32)
        b_ft = bt2.StringFieldType()
        c_ft = bt2.RealFieldType()
        fields = (
            ('a', a_ft),
            ('b', b_ft),
            ('c', c_ft),
        )

        for field in fields:
            self._ft.append_field(*field)

        for (name, ft_field_type), field in zip(self._ft.items(), fields):
            self.assertEqual(name, field[0])
            self.assertEqual(ft_field_type.addr, field[1].addr)

    def test_at_index(self):
        a_ft = bt2.SignedIntegerFieldType(32)
        b_ft = bt2.StringFieldType()
        c_ft = bt2.RealFieldType()
        self._ft.append_field('c', c_ft)
        self._ft.append_field('a', a_ft)
        self._ft.append_field('b', b_ft)
        self.assertEqual(self._ft.at_index(1).addr, a_ft.addr)

    def test_at_index_invalid(self):
        self._ft.append_field('c', bt2.SignedIntegerFieldType(32))

        with self.assertRaises(TypeError):
            self._ft.at_index('yes')

    def test_at_index_out_of_bounds_after(self):
        self._ft.append_field('c', bt2.SignedIntegerFieldType(32))

        with self.assertRaises(IndexError):
            self._ft.at_index(len(self._ft))


class StructureFieldTypeTestCase(_TestFieldContainer, unittest.TestCase):
    def setUp(self):
        self._ft = bt2.StructureFieldType()

    def tearDown(self):
        del self._ft

    def test_create_default(self):
        self.assertIsNotNone(self._ft)


class VariantFieldTypeTestCase(_TestFieldContainer, unittest.TestCase):
    def setUp(self):
        selector_ft = bt2.UnsignedEnumerationFieldType(range=42)
        selector_ft.map_range('first', 1)
        selector_ft.map_range('second', 2, 434)

        self._ft = bt2.VariantFieldType(selector_ft)

    def tearDown(self):
        del self._ft

    def test_selector_field_path(self):
        selector_ft = bt2.UnsignedEnumerationFieldType(range=42)
        selector_ft.map_range('first', 1)
        selector_ft.map_range('second', 2, 434)

        ft = bt2.VariantFieldType(selector_ft)
        ft.append_field('a', bt2.RealFieldType())
        ft.append_field('b', bt2.SignedIntegerFieldType(21))
        ft.append_field('c', bt2.UnsignedIntegerFieldType(34))

        foo_ft = bt2.RealFieldType()
        bar_ft = bt2.StringFieldType()
        baz_ft = bt2.StringFieldType()

        inner_struct_ft = bt2.StructureFieldType()
        inner_struct_ft.append_field('selector', selector_ft)
        inner_struct_ft.append_field('bar', bar_ft)
        inner_struct_ft.append_field('baz', baz_ft)
        inner_struct_ft.append_field('variant', ft)

        outer_struct_ft = bt2.StructureFieldType()
        outer_struct_ft.append_field('foo', foo_ft)
        outer_struct_ft.append_field('inner_struct', inner_struct_ft)
        trace = bt2.Trace(packet_header_field_type=outer_struct_ft)

        self.assertEqual(list(ft.selector_field_path), [1, 0])


class StaticArrayFieldTypeTestCase(unittest.TestCase):
    def setUp(self):
        self._elem_ft = bt2.SignedIntegerFieldType(23)
        self._ft = bt2.StaticArrayFieldType(self._elem_ft, 45)

    def tearDown(self):
        del self._ft
        del self._elem_ft

    def test_create_default(self):
        self.assertEqual(self._ft.element_field_type.addr, self._elem_ft.addr)
        self.assertEqual(self._ft.length, 45)

    def test_create_invalid_field_type(self):
        with self.assertRaises(TypeError):
            self._ft = bt2.StaticArrayFieldType(object(), 45)

    def test_create_invalid_length(self):
        with self.assertRaises(ValueError):
            self._ft = bt2.StaticArrayFieldType(bt2.StringFieldType(), -17)

    def test_create_invalid_length_type(self):
        with self.assertRaises(TypeError):
            self._ft = bt2.StaticArrayFieldType(bt2.StringFieldType(), 'the length')


class DynamicArrayFieldTypeTestCase(unittest.TestCase):
    def setUp(self):
        self._elem_ft = bt2.SignedIntegerFieldType(23)
        self._len_ft = bt2.UnsignedIntegerFieldType(12)
        self._ft = bt2.DynamicArrayFieldType(self._elem_ft, self._len_ft)

    def test_create_default(self):
        self.assertEqual(self._ft.element_field_type.addr, self._elem_ft.addr)

    def test_field_path(self):
        foo_ft = bt2.RealFieldType()
        bar_ft = bt2.StringFieldType()
        baz_ft = bt2.StringFieldType()

        inner_struct_ft = bt2.StructureFieldType()
        inner_struct_ft.append_field('bar', bar_ft)
        inner_struct_ft.append_field('baz', baz_ft)
        inner_struct_ft.append_field('len', self._len_ft)
        inner_struct_ft.append_field('dyn_array', self._ft)

        outer_struct_ft = bt2.StructureFieldType()
        outer_struct_ft.append_field('foo', foo_ft)
        outer_struct_ft.append_field('inner_struct', inner_struct_ft)
        trace = bt2.Trace(packet_header_field_type=outer_struct_ft)

        self.assertEqual(list(self._ft.length_field_path), [1, 2])

    def test_create_invalid_field_type(self):
        len_ft = bt2.UnsignedIntegerFieldType(12)
        with self.assertRaises(TypeError):
            ft = bt2.DynamicArrayFieldType(object(), len_ft)

    def test_create_invalid_length_type(self):
        with self.assertRaises(TypeError):
            ft = bt2.DynamicArrayFieldType(bt2.StringFieldType(), 17)
