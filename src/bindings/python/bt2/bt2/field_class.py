# The MIT License (MIT)
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from bt2 import native_bt, object, utils
import collections.abc
from bt2 import field_path as bt2_field_path
from bt2 import integer_range_set as bt2_integer_range_set
from bt2 import value as bt2_value
import bt2


def _create_field_class_from_ptr_and_get_ref_template(type_map, ptr):
    typeid = native_bt.field_class_get_type(ptr)
    return type_map[typeid]._create_from_ptr_and_get_ref(ptr)


def _create_field_class_from_ptr_and_get_ref(ptr):
    return _create_field_class_from_ptr_and_get_ref_template(
        _FIELD_CLASS_TYPE_TO_OBJ, ptr
    )


def _create_field_class_from_const_ptr_and_get_ref(ptr):
    return _create_field_class_from_ptr_and_get_ref_template(
        _FIELD_CLASS_TYPE_TO_CONST_OBJ, ptr
    )


class IntegerDisplayBase:
    BINARY = native_bt.FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_BINARY
    OCTAL = native_bt.FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_OCTAL
    DECIMAL = native_bt.FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_DECIMAL
    HEXADECIMAL = native_bt.FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL


class _FieldClassConst(object._SharedObject):
    _get_ref = staticmethod(native_bt.field_class_get_ref)
    _put_ref = staticmethod(native_bt.field_class_put_ref)
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.field_class_borrow_user_attributes_const
    )
    _create_value_from_ptr_and_get_ref = staticmethod(
        bt2_value._create_from_const_ptr_and_get_ref
    )

    def _check_create_status(self, ptr):
        if ptr is None:
            raise bt2._MemoryError(
                'cannot create {} field class object'.format(self._NAME.lower())
            )

    @property
    def user_attributes(self):
        ptr = self._borrow_user_attributes_ptr(self._ptr)
        assert ptr is not None
        return self._create_value_from_ptr_and_get_ref(ptr)


class _FieldClass(_FieldClassConst):
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.field_class_borrow_user_attributes
    )
    _create_value_from_ptr_and_get_ref = staticmethod(
        bt2_value._create_from_ptr_and_get_ref
    )

    def _user_attributes(self, user_attributes):
        value = bt2_value.create_value(user_attributes)
        utils._check_type(value, bt2_value.MapValue)
        native_bt.field_class_set_user_attributes(self._ptr, value._ptr)

    _user_attributes = property(fset=_user_attributes)


class _BoolFieldClassConst(_FieldClassConst):
    _NAME = 'Const Boolean'


class _BoolFieldClass(_BoolFieldClassConst, _FieldClass):
    _NAME = 'Boolean'


class _BitArrayFieldClassConst(_FieldClassConst):
    _NAME = 'Const Bit array'

    @property
    def length(self):
        length = native_bt.field_class_bit_array_get_length(self._ptr)
        assert length >= 1
        return length


class _BitArrayFieldClass(_BitArrayFieldClassConst, _FieldClass):
    _NAME = 'Bit array'


class _IntegerFieldClassConst(_FieldClassConst):
    @property
    def field_value_range(self):
        size = native_bt.field_class_integer_get_field_value_range(self._ptr)
        assert size >= 1
        return size

    @property
    def preferred_display_base(self):
        base = native_bt.field_class_integer_get_preferred_display_base(self._ptr)
        assert base >= 0
        return base


class _IntegerFieldClass(_FieldClass, _IntegerFieldClassConst):
    def _field_value_range(self, size):
        if size < 1 or size > 64:
            raise ValueError("Value is outside valid range [1, 64] ({})".format(size))
        native_bt.field_class_integer_set_field_value_range(self._ptr, size)

    _field_value_range = property(fset=_field_value_range)

    def _preferred_display_base(self, base):
        utils._check_uint64(base)

        if base not in (
            IntegerDisplayBase.BINARY,
            IntegerDisplayBase.OCTAL,
            IntegerDisplayBase.DECIMAL,
            IntegerDisplayBase.HEXADECIMAL,
        ):
            raise ValueError("Display base is not a valid IntegerDisplayBase value")

        native_bt.field_class_integer_set_preferred_display_base(self._ptr, base)

    _preferred_display_base = property(fset=_preferred_display_base)


class _UnsignedIntegerFieldClassConst(_IntegerFieldClassConst, _FieldClassConst):
    _NAME = 'Const unsigned integer'


class _UnsignedIntegerFieldClass(
    _UnsignedIntegerFieldClassConst, _IntegerFieldClass, _FieldClass
):
    _NAME = 'Unsigned integer'


class _SignedIntegerFieldClassConst(_IntegerFieldClassConst, _FieldClassConst):
    _NAME = 'Const signed integer'


class _SignedIntegerFieldClass(
    _SignedIntegerFieldClassConst, _IntegerFieldClass, _FieldClass
):
    _NAME = 'Signed integer'


class _RealFieldClassConst(_FieldClassConst):
    pass


class _SinglePrecisionRealFieldClassConst(_RealFieldClassConst):
    _NAME = 'Const single-precision real'


class _DoublePrecisionRealFieldClassConst(_RealFieldClassConst):
    _NAME = 'Const double-precision real'


class _RealFieldClass(_FieldClass, _RealFieldClassConst):
    pass


class _SinglePrecisionRealFieldClass(_RealFieldClass):
    _NAME = 'Single-precision real'


class _DoublePrecisionRealFieldClass(_RealFieldClass):
    _NAME = 'Double-precision real'


# an enumeration field class mapping does not have a reference count, so
# we copy the properties here to avoid eventual memory access errors.
class _EnumerationFieldClassMapping:
    def __init__(self, mapping_ptr):
        base_mapping_ptr = self._as_enumeration_field_class_mapping_ptr(mapping_ptr)
        self._label = native_bt.field_class_enumeration_mapping_get_label(
            base_mapping_ptr
        )
        assert self._label is not None
        ranges_ptr = self._mapping_borrow_ranges_ptr(mapping_ptr)
        assert ranges_ptr is not None
        self._ranges = self._range_set_pycls._create_from_ptr_and_get_ref(ranges_ptr)

    @property
    def label(self):
        return self._label

    @property
    def ranges(self):
        return self._ranges


class _UnsignedEnumerationFieldClassMappingConst(_EnumerationFieldClassMapping):
    _range_set_pycls = bt2_integer_range_set.UnsignedIntegerRangeSet
    _as_enumeration_field_class_mapping_ptr = staticmethod(
        native_bt.field_class_enumeration_unsigned_mapping_as_mapping_const
    )
    _mapping_borrow_ranges_ptr = staticmethod(
        native_bt.field_class_enumeration_unsigned_mapping_borrow_ranges_const
    )


class _SignedEnumerationFieldClassMappingConst(_EnumerationFieldClassMapping):
    _range_set_pycls = bt2_integer_range_set.SignedIntegerRangeSet
    _as_enumeration_field_class_mapping_ptr = staticmethod(
        native_bt.field_class_enumeration_signed_mapping_as_mapping_const
    )
    _mapping_borrow_ranges_ptr = staticmethod(
        native_bt.field_class_enumeration_signed_mapping_borrow_ranges_const
    )


class _EnumerationFieldClassConst(_IntegerFieldClassConst, collections.abc.Mapping):
    def __len__(self):
        count = native_bt.field_class_enumeration_get_mapping_count(self._ptr)
        assert count >= 0
        return count

    def mappings_for_value(self, value):
        self._check_int_type(value)

        status, labels = self._get_mapping_labels_for_value(self._ptr, value)
        utils._handle_func_status(
            status, 'cannot get mapping labels for value {}'.format(value)
        )
        return [self[label] for label in labels]

    def __iter__(self):
        for idx in range(len(self)):
            mapping_ptr = self._borrow_mapping_ptr_by_index(self._ptr, idx)
            yield self._mapping_pycls(mapping_ptr).label

    def __getitem__(self, label):
        utils._check_str(label)
        mapping_ptr = self._borrow_mapping_ptr_by_label(self._ptr, label)

        if mapping_ptr is None:
            raise KeyError(label)

        return self._mapping_pycls(mapping_ptr)


class _EnumerationFieldClass(_EnumerationFieldClassConst, _IntegerFieldClass):
    def add_mapping(self, label, ranges):
        utils._check_str(label)
        utils._check_type(ranges, self._range_set_pycls)

        if label in self:
            raise ValueError("duplicate mapping label '{}'".format(label))

        status = self._add_mapping(self._ptr, label, ranges._ptr)
        utils._handle_func_status(
            status, 'cannot add mapping to enumeration field class object'
        )

    def __iadd__(self, mappings):
        for label, ranges in mappings:
            self.add_mapping(label, ranges)

        return self


class _UnsignedEnumerationFieldClassConst(
    _EnumerationFieldClassConst, _UnsignedIntegerFieldClassConst
):
    _NAME = 'Const nsigned enumeration'
    _range_set_pycls = bt2_integer_range_set.UnsignedIntegerRangeSet
    _borrow_mapping_ptr_by_label = staticmethod(
        native_bt.field_class_enumeration_unsigned_borrow_mapping_by_label_const
    )
    _borrow_mapping_ptr_by_index = staticmethod(
        native_bt.field_class_enumeration_unsigned_borrow_mapping_by_index_const
    )
    _mapping_pycls = property(lambda _: _UnsignedEnumerationFieldClassMappingConst)
    _get_mapping_labels_for_value = staticmethod(
        native_bt.field_class_enumeration_unsigned_get_mapping_labels_for_value
    )
    _check_int_type = staticmethod(utils._check_uint64)


class _UnsignedEnumerationFieldClass(
    _UnsignedEnumerationFieldClassConst,
    _EnumerationFieldClass,
    _UnsignedIntegerFieldClass,
):
    _NAME = 'Unsigned enumeration'
    _add_mapping = staticmethod(native_bt.field_class_enumeration_unsigned_add_mapping)


class _SignedEnumerationFieldClassConst(
    _EnumerationFieldClassConst, _SignedIntegerFieldClassConst
):
    _NAME = 'Const signed enumeration'
    _range_set_pycls = bt2_integer_range_set.SignedIntegerRangeSet
    _borrow_mapping_ptr_by_label = staticmethod(
        native_bt.field_class_enumeration_signed_borrow_mapping_by_label_const
    )
    _borrow_mapping_ptr_by_index = staticmethod(
        native_bt.field_class_enumeration_signed_borrow_mapping_by_index_const
    )
    _mapping_pycls = property(lambda _: _SignedEnumerationFieldClassMappingConst)
    _get_mapping_labels_for_value = staticmethod(
        native_bt.field_class_enumeration_signed_get_mapping_labels_for_value
    )
    _check_int_type = staticmethod(utils._check_int64)


class _SignedEnumerationFieldClass(
    _SignedEnumerationFieldClassConst, _EnumerationFieldClass, _SignedIntegerFieldClass
):
    _NAME = 'Signed enumeration'
    _add_mapping = staticmethod(native_bt.field_class_enumeration_signed_add_mapping)


class _StringFieldClassConst(_FieldClassConst):
    _NAME = 'Const string'


class _StringFieldClass(_StringFieldClassConst, _FieldClass):
    _NAME = 'String'


class _StructureFieldClassMemberConst:
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_const_ptr_and_get_ref
    )
    _borrow_field_class_ptr = staticmethod(
        native_bt.field_class_structure_member_borrow_field_class_const
    )
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.field_class_structure_member_borrow_user_attributes_const
    )
    _create_value_from_ptr_and_get_ref = staticmethod(
        bt2_value._create_from_const_ptr_and_get_ref
    )

    def __init__(self, owning_struct_fc, member_ptr):
        # this field class owns the member; keeping it here maintains
        # the member alive as members are not shared objects
        self._owning_struct_fc = owning_struct_fc
        self._ptr = member_ptr

    @property
    def name(self):
        name = native_bt.field_class_structure_member_get_name(self._ptr)
        assert name is not None
        return name

    @property
    def field_class(self):
        fc_ptr = self._borrow_field_class_ptr(self._ptr)
        assert fc_ptr is not None
        return self._create_field_class_from_ptr_and_get_ref(fc_ptr)

    @property
    def user_attributes(self):
        ptr = self._borrow_user_attributes_ptr(self._ptr)
        assert ptr is not None
        return self._create_value_from_ptr_and_get_ref(ptr)


class _StructureFieldClassMember(_StructureFieldClassMemberConst):
    _borrow_field_class_ptr = staticmethod(
        native_bt.field_class_structure_member_borrow_field_class
    )
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.field_class_structure_member_borrow_user_attributes
    )
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_ptr_and_get_ref
    )
    _create_value_from_ptr_and_get_ref = staticmethod(
        bt2_value._create_from_ptr_and_get_ref
    )

    def _user_attributes(self, user_attributes):
        value = bt2_value.create_value(user_attributes)
        utils._check_type(value, bt2_value.MapValue)
        native_bt.field_class_structure_member_set_user_attributes(
            self._ptr, value._ptr
        )

    _user_attributes = property(fset=_user_attributes)


class _StructureFieldClassConst(_FieldClassConst, collections.abc.Mapping):
    _NAME = 'Const structure'
    _borrow_member_ptr_by_index = staticmethod(
        native_bt.field_class_structure_borrow_member_by_index_const
    )
    _borrow_member_ptr_by_name = staticmethod(
        native_bt.field_class_structure_borrow_member_by_name_const
    )
    _structure_member_field_class_pycls = property(
        lambda _: _StructureFieldClassMemberConst
    )

    def __len__(self):
        count = native_bt.field_class_structure_get_member_count(self._ptr)
        assert count >= 0
        return count

    def __getitem__(self, key):
        if not isinstance(key, str):
            raise TypeError(
                "key must be a 'str' object, got '{}'".format(key.__class__.__name__)
            )

        member_ptr = self._borrow_member_ptr_by_name(self._ptr, key)

        if member_ptr is None:
            raise KeyError(key)

        return self._structure_member_field_class_pycls(self, member_ptr)

    def __iter__(self):
        for idx in range(len(self)):
            member_ptr = self._borrow_member_ptr_by_index(self._ptr, idx)
            assert member_ptr is not None
            yield native_bt.field_class_structure_member_get_name(member_ptr)

    def member_at_index(self, index):
        utils._check_uint64(index)

        if index >= len(self):
            raise IndexError

        member_ptr = self._borrow_member_ptr_by_index(self._ptr, index)
        assert member_ptr is not None
        return self._structure_member_field_class_pycls(self, member_ptr)


class _StructureFieldClass(_StructureFieldClassConst, _FieldClass):
    _NAME = 'Structure'
    _borrow_member_by_index = staticmethod(
        native_bt.field_class_structure_borrow_member_by_index
    )
    _borrow_member_ptr_by_name = staticmethod(
        native_bt.field_class_structure_borrow_member_by_name
    )
    _structure_member_field_class_pycls = property(lambda _: _StructureFieldClassMember)

    def append_member(self, name, field_class, user_attributes=None):
        utils._check_str(name)
        utils._check_type(field_class, _FieldClass)

        if name in self:
            raise ValueError("duplicate member name '{}'".format(name))

        user_attributes_value = None

        if user_attributes is not None:
            # check now that user attributes are valid
            user_attributes_value = bt2.create_value(user_attributes)

        status = native_bt.field_class_structure_append_member(
            self._ptr, name, field_class._ptr
        )
        utils._handle_func_status(
            status, 'cannot append member to structure field class object'
        )

        if user_attributes is not None:
            self[name]._user_attributes = user_attributes_value

    def __iadd__(self, members):
        for name, field_class in members:
            self.append_member(name, field_class)

        return self


class _OptionFieldClassConst(_FieldClassConst):
    _NAME = 'Const Option'
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_const_ptr_and_get_ref
    )
    _borrow_field_class_ptr = staticmethod(
        native_bt.field_class_option_borrow_field_class_const
    )

    @property
    def field_class(self):
        elem_fc_ptr = self._borrow_field_class_ptr(self._ptr)
        return self._create_field_class_from_ptr_and_get_ref(elem_fc_ptr)


class _OptionWithSelectorFieldClassConst(_OptionFieldClassConst):
    @property
    def selector_field_path(self):
        ptr = native_bt.field_class_option_borrow_selector_field_path_const(self._ptr)
        if ptr is None:
            return

        return bt2_field_path._FieldPathConst._create_from_ptr_and_get_ref(ptr)


class _OptionWithBoolSelectorFieldClassConst(_OptionWithSelectorFieldClassConst):
    @property
    def selector_is_reversed(self):
        return bool(
            native_bt.field_class_option_with_selector_bool_selector_is_reversed(
                self._ptr
            )
        )


class _OptionWithIntegerSelectorFieldClassConst(_OptionWithSelectorFieldClassConst):
    pass


class _OptionWithUnsignedIntegerSelectorFieldClassConst(
    _OptionWithIntegerSelectorFieldClassConst
):
    @property
    def ranges(self):
        range_set_ptr = native_bt.field_class_option_with_selector_integer_unsigned_borrow_ranges_const(
            self._ptr
        )
        assert range_set_ptr is not None
        return bt2_integer_range_set.UnsignedIntegerRangeSet(range_set_ptr)


class _OptionWithSignedIntegerSelectorFieldClassConst(
    _OptionWithIntegerSelectorFieldClassConst
):
    @property
    def ranges(self):
        range_set_ptr = native_bt.field_class_option_with_selector_integer_signed_borrow_ranges_const(
            self._ptr
        )
        assert range_set_ptr is not None
        return bt2_integer_range_set.SignedIntegerRangeSet(range_set_ptr)


class _OptionFieldClass(_OptionFieldClassConst, _FieldClass):
    _NAME = 'Option'
    _borrow_field_class_ptr = staticmethod(
        native_bt.field_class_option_borrow_field_class
    )
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_ptr_and_get_ref
    )


class _OptionWithSelectorFieldClass(
    _OptionWithSelectorFieldClassConst, _OptionFieldClass
):
    pass


class _OptionWithBoolSelectorFieldClass(
    _OptionWithBoolSelectorFieldClassConst, _OptionWithSelectorFieldClass
):
    def _selector_is_reversed(self, selector_is_reversed):
        utils._check_bool(selector_is_reversed)
        native_bt.field_class_option_with_selector_bool_set_selector_is_reversed(
            self._ptr, value._ptr
        )

    _selector_is_reversed = property(fset=_selector_is_reversed)


class _OptionWithIntegerSelectorFieldClass(
    _OptionWithIntegerSelectorFieldClassConst, _OptionWithSelectorFieldClass
):
    pass


class _OptionWithUnsignedIntegerSelectorFieldClass(
    _OptionWithUnsignedIntegerSelectorFieldClassConst,
    _OptionWithIntegerSelectorFieldClass,
):
    pass


class _OptionWithSignedIntegerSelectorFieldClass(
    _OptionWithSignedIntegerSelectorFieldClassConst,
    _OptionWithIntegerSelectorFieldClass,
):
    pass


class _VariantFieldClassOptionConst:
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_const_ptr_and_get_ref
    )
    _borrow_field_class_ptr = staticmethod(
        native_bt.field_class_variant_option_borrow_field_class_const
    )
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.field_class_variant_option_borrow_user_attributes_const
    )
    _create_value_from_ptr_and_get_ref = staticmethod(
        bt2_value._create_from_const_ptr_and_get_ref
    )

    def __init__(self, owning_var_fc, option_ptr):
        # this field class owns the option; keeping it here maintains
        # the option alive as options are not shared objects
        self._owning_var_fc = owning_var_fc
        self._ptr = option_ptr

    @property
    def name(self):
        name = native_bt.field_class_variant_option_get_name(self._ptr)
        assert name is not None
        return name

    @property
    def field_class(self):
        fc_ptr = self._borrow_field_class_ptr(self._ptr)
        assert fc_ptr is not None
        return self._create_field_class_from_ptr_and_get_ref(fc_ptr)

    @property
    def user_attributes(self):
        ptr = self._borrow_user_attributes_ptr(self._ptr)
        assert ptr is not None
        return self._create_value_from_ptr_and_get_ref(ptr)


class _VariantFieldClassOption(_VariantFieldClassOptionConst):
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_ptr_and_get_ref
    )
    _borrow_field_class_ptr = staticmethod(
        native_bt.field_class_variant_option_borrow_field_class
    )
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.field_class_variant_option_borrow_user_attributes
    )
    _create_value_from_ptr_and_get_ref = staticmethod(
        bt2_value._create_from_ptr_and_get_ref
    )

    def _user_attributes(self, user_attributes):
        value = bt2_value.create_value(user_attributes)
        utils._check_type(value, bt2_value.MapValue)
        native_bt.field_class_variant_option_set_user_attributes(self._ptr, value._ptr)

    _user_attributes = property(fset=_user_attributes)


class _VariantFieldClassWithSelectorOptionConst(_VariantFieldClassOptionConst):
    def __init__(self, owning_var_fc, spec_opt_ptr):
        self._spec_ptr = spec_opt_ptr
        super().__init__(owning_var_fc, self._as_option_ptr(spec_opt_ptr))

    @property
    def ranges(self):
        range_set_ptr = self._borrow_ranges_ptr(self._spec_ptr)
        assert range_set_ptr is not None
        return self._range_set_pycls._create_from_ptr_and_get_ref(range_set_ptr)


class _VariantFieldClassWithSelectorOption(
    _VariantFieldClassWithSelectorOptionConst, _VariantFieldClassOption
):
    pass


class _VariantFieldClassWithSignedSelectorOptionConst(
    _VariantFieldClassWithSelectorOptionConst
):
    _as_option_ptr = staticmethod(
        native_bt.field_class_variant_with_selector_signed_option_as_option_const
    )
    _borrow_ranges_ptr = staticmethod(
        native_bt.field_class_variant_with_selector_signed_option_borrow_ranges_const
    )
    _range_set_pycls = bt2_integer_range_set.SignedIntegerRangeSet


class _VariantFieldClassWithSignedSelectorOption(
    _VariantFieldClassWithSignedSelectorOptionConst,
    _VariantFieldClassWithSelectorOption,
):
    pass


class _VariantFieldClassWithUnsignedSelectorOptionConst(
    _VariantFieldClassWithSelectorOptionConst
):
    _as_option_ptr = staticmethod(
        native_bt.field_class_variant_with_selector_unsigned_option_as_option_const
    )
    _borrow_ranges_ptr = staticmethod(
        native_bt.field_class_variant_with_selector_unsigned_option_borrow_ranges_const
    )
    _range_set_pycls = bt2_integer_range_set.UnsignedIntegerRangeSet


class _VariantFieldClassWithUnsignedSelectorOption(
    _VariantFieldClassWithUnsignedSelectorOptionConst,
    _VariantFieldClassWithSelectorOption,
):
    pass


class _VariantFieldClassConst(_FieldClassConst, collections.abc.Mapping):
    _NAME = 'Const Variant'
    _borrow_option_ptr_by_name = staticmethod(
        native_bt.field_class_variant_borrow_option_by_name_const
    )
    _borrow_option_ptr_by_index = staticmethod(
        native_bt.field_class_variant_borrow_option_by_index_const
    )
    _variant_option_pycls = _VariantFieldClassOptionConst

    @staticmethod
    def _as_option_ptr(opt_ptr):
        return opt_ptr

    def _create_option_from_ptr(self, opt_ptr):
        return self._variant_option_pycls(self, opt_ptr)

    def __len__(self):
        count = native_bt.field_class_variant_get_option_count(self._ptr)
        assert count >= 0
        return count

    def __getitem__(self, key):
        if not isinstance(key, str):
            raise TypeError(
                "key must be a 'str' object, got '{}'".format(key.__class__.__name__)
            )

        opt_ptr = self._borrow_option_ptr_by_name(self._ptr, key)

        if opt_ptr is None:
            raise KeyError(key)

        return self._create_option_from_ptr(opt_ptr)

    def __iter__(self):
        for idx in range(len(self)):
            opt_ptr = self._borrow_option_ptr_by_index(self._ptr, idx)
            assert opt_ptr is not None
            base_opt_ptr = self._as_option_ptr(opt_ptr)
            yield native_bt.field_class_variant_option_get_name(base_opt_ptr)

    def option_at_index(self, index):
        utils._check_uint64(index)

        if index >= len(self):
            raise IndexError

        opt_ptr = self._borrow_option_ptr_by_index(self._ptr, index)
        assert opt_ptr is not None
        return self._create_option_from_ptr(opt_ptr)


class _VariantFieldClass(_VariantFieldClassConst, _FieldClass, collections.abc.Mapping):
    _NAME = 'Variant'
    _borrow_option_ptr_by_name = staticmethod(
        native_bt.field_class_variant_borrow_option_by_name
    )
    _borrow_option_ptr_by_index = staticmethod(
        native_bt.field_class_variant_borrow_option_by_index
    )
    _variant_option_pycls = _VariantFieldClassOption


class _VariantFieldClassWithoutSelectorConst(_VariantFieldClassConst):
    _NAME = 'Const Variant (without selector)'


class _VariantFieldClassWithoutSelector(
    _VariantFieldClassWithoutSelectorConst, _VariantFieldClass
):
    _NAME = 'Variant (without selector)'

    def append_option(self, name, field_class, user_attributes=None):
        utils._check_str(name)
        utils._check_type(field_class, _FieldClass)

        if name in self:
            raise ValueError("duplicate option name '{}'".format(name))

        user_attributes_value = None

        if user_attributes is not None:
            # check now that user attributes are valid
            user_attributes_value = bt2.create_value(user_attributes)

        status = native_bt.field_class_variant_without_selector_append_option(
            self._ptr, name, field_class._ptr
        )
        utils._handle_func_status(
            status, 'cannot append option to variant field class object'
        )

        if user_attributes is not None:
            self[name]._user_attributes = user_attributes_value

    def __iadd__(self, options):
        for name, field_class in options:
            self.append_option(name, field_class)

        return self


class _VariantFieldClassWithSelectorConst(_VariantFieldClassConst):
    _NAME = 'Const Variant (with selector)'

    @property
    def selector_field_path(self):
        ptr = native_bt.field_class_variant_with_selector_borrow_selector_field_path_const(
            self._ptr
        )

        if ptr is None:
            return

        return bt2_field_path._FieldPathConst._create_from_ptr_and_get_ref(ptr)


class _VariantFieldClassWithSelector(
    _VariantFieldClassWithSelectorConst, _VariantFieldClass
):
    _NAME = 'Variant (with selector)'

    def append_option(self, name, field_class, ranges, user_attributes=None):
        utils._check_str(name)
        utils._check_type(field_class, _FieldClass)
        utils._check_type(ranges, self._variant_option_pycls._range_set_pycls)

        if name in self:
            raise ValueError("duplicate option name '{}'".format(name))

        if len(ranges) == 0:
            raise ValueError('range set is empty')

        user_attributes_value = None

        if user_attributes is not None:
            # check now that user attributes are valid
            user_attributes_value = bt2.create_value(user_attributes)

        # TODO: check overlaps (precondition of self._append_option())

        status = self._append_option(self._ptr, name, field_class._ptr, ranges._ptr)
        utils._handle_func_status(
            status, 'cannot append option to variant field class object'
        )

        if user_attributes is not None:
            self[name]._user_attributes = user_attributes_value

    def __iadd__(self, options):
        for name, field_class, ranges in options:
            self.append_option(name, field_class, ranges)

        return self


class _VariantFieldClassWithUnsignedSelectorConst(_VariantFieldClassWithSelectorConst):
    _NAME = 'Const Variant (with unsigned selector)'
    _borrow_option_ptr_by_name = staticmethod(
        native_bt.field_class_variant_with_selector_unsigned_borrow_option_by_name_const
    )
    _borrow_option_ptr_by_index = staticmethod(
        native_bt.field_class_variant_with_selector_unsigned_borrow_option_by_index_const
    )
    _variant_option_pycls = _VariantFieldClassWithUnsignedSelectorOptionConst
    _as_option_ptr = staticmethod(_variant_option_pycls._as_option_ptr)


class _VariantFieldClassWithUnsignedSelector(
    _VariantFieldClassWithUnsignedSelectorConst, _VariantFieldClassWithSelector
):
    _NAME = 'Variant (with unsigned selector)'
    _variant_option_pycls = _VariantFieldClassWithUnsignedSelectorOption
    _as_option_ptr = staticmethod(_variant_option_pycls._as_option_ptr)
    _append_option = staticmethod(
        native_bt.field_class_variant_with_selector_unsigned_append_option
    )


class _VariantFieldClassWithSignedSelectorConst(_VariantFieldClassWithSelectorConst):
    _NAME = 'Const Variant (with signed selector)'
    _borrow_option_ptr_by_name = staticmethod(
        native_bt.field_class_variant_with_selector_signed_borrow_option_by_name_const
    )
    _borrow_option_ptr_by_index = staticmethod(
        native_bt.field_class_variant_with_selector_signed_borrow_option_by_index_const
    )
    _variant_option_pycls = _VariantFieldClassWithSignedSelectorOptionConst
    _as_option_ptr = staticmethod(_variant_option_pycls._as_option_ptr)


class _VariantFieldClassWithSignedSelector(
    _VariantFieldClassWithSignedSelectorConst, _VariantFieldClassWithSelector
):
    _NAME = 'Variant (with signed selector)'
    _variant_option_pycls = _VariantFieldClassWithSignedSelectorOption
    _as_option_ptr = staticmethod(_variant_option_pycls._as_option_ptr)
    _append_option = staticmethod(
        native_bt.field_class_variant_with_selector_signed_append_option
    )


class _ArrayFieldClassConst(_FieldClassConst):
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_const_ptr_and_get_ref
    )
    _borrow_element_field_class = staticmethod(
        native_bt.field_class_array_borrow_element_field_class_const
    )

    @property
    def element_field_class(self):
        elem_fc_ptr = self._borrow_element_field_class(self._ptr)
        return self._create_field_class_from_ptr_and_get_ref(elem_fc_ptr)


class _ArrayFieldClass(_ArrayFieldClassConst, _FieldClass):
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        _create_field_class_from_ptr_and_get_ref
    )
    _borrow_element_field_class = staticmethod(
        native_bt.field_class_array_borrow_element_field_class
    )


class _StaticArrayFieldClassConst(_ArrayFieldClassConst):
    _NAME = 'Const static array'

    @property
    def length(self):
        return native_bt.field_class_array_static_get_length(self._ptr)


class _StaticArrayFieldClass(_StaticArrayFieldClassConst, _ArrayFieldClass):
    _NAME = 'Static array'


class _DynamicArrayFieldClassConst(_ArrayFieldClassConst):
    _NAME = 'Const dynamic array'

    @property
    def length_field_path(self):
        ptr = native_bt.field_class_array_dynamic_borrow_length_field_path_const(
            self._ptr
        )
        if ptr is None:
            return

        return bt2_field_path._FieldPathConst._create_from_ptr_and_get_ref(ptr)


class _DynamicArrayFieldClass(_DynamicArrayFieldClassConst, _ArrayFieldClass):
    _NAME = 'Dynamic Array'


_FIELD_CLASS_TYPE_TO_CONST_OBJ = {
    native_bt.FIELD_CLASS_TYPE_BOOL: _BoolFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_BIT_ARRAY: _BitArrayFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_UNSIGNED_INTEGER: _UnsignedIntegerFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_SIGNED_INTEGER: _SignedIntegerFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL: _SinglePrecisionRealFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL: _DoublePrecisionRealFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_UNSIGNED_ENUMERATION: _UnsignedEnumerationFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_SIGNED_ENUMERATION: _SignedEnumerationFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_STRING: _StringFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_STRUCTURE: _StructureFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_STATIC_ARRAY: _StaticArrayFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_DYNAMIC_ARRAY: _DynamicArrayFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITHOUT_SELECTOR: _OptionFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITH_BOOL_SELECTOR: _OptionWithBoolSelectorFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITH_UNSIGNED_INTEGER_SELECTOR: _OptionWithUnsignedIntegerSelectorFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITH_SIGNED_INTEGER_SELECTOR: _OptionWithSignedIntegerSelectorFieldClassConst,
    native_bt.FIELD_CLASS_TYPE_VARIANT_WITHOUT_SELECTOR: _VariantFieldClassWithoutSelectorConst,
    native_bt.FIELD_CLASS_TYPE_VARIANT_WITH_UNSIGNED_SELECTOR: _VariantFieldClassWithUnsignedSelectorConst,
    native_bt.FIELD_CLASS_TYPE_VARIANT_WITH_SIGNED_SELECTOR: _VariantFieldClassWithSignedSelectorConst,
}

_FIELD_CLASS_TYPE_TO_OBJ = {
    native_bt.FIELD_CLASS_TYPE_BOOL: _BoolFieldClass,
    native_bt.FIELD_CLASS_TYPE_BIT_ARRAY: _BitArrayFieldClass,
    native_bt.FIELD_CLASS_TYPE_UNSIGNED_INTEGER: _UnsignedIntegerFieldClass,
    native_bt.FIELD_CLASS_TYPE_SIGNED_INTEGER: _SignedIntegerFieldClass,
    native_bt.FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL: _SinglePrecisionRealFieldClass,
    native_bt.FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL: _DoublePrecisionRealFieldClass,
    native_bt.FIELD_CLASS_TYPE_UNSIGNED_ENUMERATION: _UnsignedEnumerationFieldClass,
    native_bt.FIELD_CLASS_TYPE_SIGNED_ENUMERATION: _SignedEnumerationFieldClass,
    native_bt.FIELD_CLASS_TYPE_STRING: _StringFieldClass,
    native_bt.FIELD_CLASS_TYPE_STRUCTURE: _StructureFieldClass,
    native_bt.FIELD_CLASS_TYPE_STATIC_ARRAY: _StaticArrayFieldClass,
    native_bt.FIELD_CLASS_TYPE_DYNAMIC_ARRAY: _DynamicArrayFieldClass,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITHOUT_SELECTOR: _OptionFieldClass,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITH_BOOL_SELECTOR: _OptionWithBoolSelectorFieldClass,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITH_UNSIGNED_INTEGER_SELECTOR: _OptionWithUnsignedIntegerSelectorFieldClass,
    native_bt.FIELD_CLASS_TYPE_OPTION_WITH_SIGNED_INTEGER_SELECTOR: _OptionWithSignedIntegerSelectorFieldClass,
    native_bt.FIELD_CLASS_TYPE_VARIANT_WITHOUT_SELECTOR: _VariantFieldClassWithoutSelector,
    native_bt.FIELD_CLASS_TYPE_VARIANT_WITH_UNSIGNED_SELECTOR: _VariantFieldClassWithUnsignedSelector,
    native_bt.FIELD_CLASS_TYPE_VARIANT_WITH_SIGNED_SELECTOR: _VariantFieldClassWithSignedSelector,
}
