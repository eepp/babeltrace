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

__all__ = ['IntegerDisplayBase', 'UnsignedIntegerFieldType', 'SignedIntegerFieldType',
        'RealFieldType', 'UnsignedEnumerationFieldType', 'SignedEnumerationFieldType',
        'StringFieldType', 'StructureFieldType', 'VariantFieldType',
        'StaticArrayFieldType', 'DynamicArrayFieldType']

import collections
from bt2 import native_bt, utils, object
import bt2

def _create_field_type_from_ptr(ptr):
    typeid = native_bt.field_type_get_type_id(ptr)
    return _FIELD_TYPE_ID_TO_OBJ[typeid]._create_from_ptr(ptr)

class IntegerDisplayBase:
    BINARY = native_bt.FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_BINARY
    OCTAL = native_bt.FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_OCTAL
    DECIMAL = native_bt.FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_DECIMAL
    HEXADECIMAL = native_bt.FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL 

class _FieldType(object._SharedObject):  
    def __init__(self, ptr):
        super().__init__(ptr)

    def _check_create_status(self, ptr):
        if ptr is None:
            raise bt2.CreationError('cannot create {} field type object'.format(self._NAME.lower()))


class _IntegerFieldType(_FieldType):
    def __init__(self, ptr, range=None, display_base=None):
        super().__init__(ptr)
        if range is not None:
            utils._check_uint64(range)
            if range == 0:
                raise ValueError("IntegerFieldType range is zero")
            self.range=range

        if display_base is not None:
            utils._check_int(display_base)
            self.base = display_base

    @property
    def range(self):
        size = native_bt.field_type_integer_get_field_value_range(self._ptr)
        assert(size >= 1)
        return size

    @range.setter
    def range(self, size):
        native_bt.field_type_integer_set_field_value_range(self._ptr, size)

    @property
    def base(self):
        base = native_bt.field_type_integer_get_preferred_display_base(self._ptr)
        assert(base >= 0)
        return base

    @base.setter
    def base(self, base):
        native_bt.field_type_integer_set_preferred_display_base(self._ptr, base)


class _UnsignedIntegerFieldType(_IntegerFieldType):
    pass
class _SignedIntegerFieldType(_IntegerFieldType):
    pass

class UnsignedIntegerFieldType(_UnsignedIntegerFieldType):
    _NAME = 'UnsignedInteger'
    def __init__(self, range=None, display_base=None):
        ptr = native_bt.field_type_unsigned_integer_create();
        self._check_create_status(ptr)
        super().__init__(ptr, range, display_base)

class SignedIntegerFieldType(_SignedIntegerFieldType):
    _NAME = 'SignedInteger'
    def __init__(self, range=None, display_base=None):
        ptr = native_bt.field_type_signed_integer_create();
        self._check_create_status(ptr)
        super().__init__(ptr, range, display_base)


class RealFieldType(_FieldType):
    _NAME = 'SignedInteger'
    def __init__(self, is_single_precision=None):
        ptr = native_bt.field_type_real_create();
        self._check_create_status(ptr)
        super().__init__(ptr)
        
        if is_single_precision is not None:
            self.single_precision = True


    @property
    def single_precision(self):
        return native_bt.field_type_real_is_single_precision(self._ptr)

    @single_precision.setter
    def single_precision(self, is_single_precision):
        utils._check_bool(is_single_precision)
        native_bt.field_type_real_set_is_single_precision(self._ptr, is_single_precision)

class _EnumerationFieldTypeMappingRange:
    def __init__(self, lower, upper):
        self._lower = lower
        self._upper = upper

    @property
    def lower(self):
        return self._lower

    @property
    def upper(self):
        return self._upper


class _EnumerationFieldTypeMapping(collections.abc.Set):
    def __init__(self, mapping_ptr, label, is_signed):
        self._mapping_ptr = mapping_ptr
        self._is_signed = is_signed
        self._label = label
        if self._is_signed:
            self._range_count = native_bt.field_type_signed_enumeration_mapping_ranges_get_range_count(self._mapping_ptr)
        else:
            self._range_count = native_bt.field_type_unsigned_enumeration_mapping_ranges_get_range_count(self._mapping_ptr)
    
    @property
    def label(self):
        return self._label

    def __len__(self):
        return self._range_count

    def __contains__(self, other_range):
        for curr_range in self:
            if curr_mapping == other_range:
                return True
        return False

    def __iter__(self):
        if self._is_signed:
            mapping_ranges_get_range_by_index_fn = native_bt.field_type_signed_enumeration_mapping_ranges_get_range_by_index
        else:
            mapping_ranges_get_range_by_index_fn = native_bt.field_type_unsigned_enumeration_mapping_ranges_get_range_by_index

        for idx in range(len(self)):
            lower, upper = mapping_ranges_get_range_by_index_fn(self._mapping_ptr, idx)
            yield _EnumerationFieldTypeMappingRange(lower, upper)

class _EnumerationFieldType(_IntegerFieldType, collections.abc.Mapping):
    def __len__(self):
        return native_bt.field_type_enumeration_get_mapping_count(self._ptr)

    def map_range(self, label, lower, upper=None):
        utils._check_str(label)

        if upper is None:
            upper = lower

        if self._is_signed:
            utils._check_int64(lower)
            utils._check_int64(upper)
            map_range_fn = native_bt.field_type_signed_enumeration_map_range
        else:
            utils._check_uint64(lower)
            utils._check_uint64(upper)
            map_range_fn = native_bt.field_type_unsigned_enumeration_map_range

        map_range_fn(self._ptr, label, lower, upper)


    def labels_by_value(self, value):
        labels = []
        for curr_mapping in self:
            for curr_range in curr_mapping:
                if value >= curr_range.lower and value <= curr_range.upper:
                    labels.append(curr_mapping.label)
        return labels


    def __iter__(self):
        if self._is_signed:
            borrow_mapping_by_index_fn = native_bt.field_type_signed_enumeration_borrow_mapping_by_index
        else:
            borrow_mapping_by_index_fn = native_bt.field_type_unsigned_enumeration_borrow_mapping_by_index

        for idx in range(len(self)):
            label, mapping_ptr = borrow_mapping_by_index_fn(self._ptr, idx)
            yield _EnumerationFieldTypeMapping(mapping_ptr, label, is_signed=self._is_signed)

    def __getitem__(self, key):
        utils._check_str(key)
        
        for mapping in self:
            if mapping.label in key:
                return mapping

    def __iadd__(self, mappings):
        for mapping in mappings:
            for range in mapping:
                self.map_range(mapping.label, range.lower, range.upper)

        return self


class UnsignedEnumerationFieldType(_EnumerationFieldType, _UnsignedIntegerFieldType):
    _NAME = 'UnsignedEnumerationFieldType'
    _is_signed = False
    def __init__(self, range=None, display_base=None):
        ptr = native_bt.field_type_unsigned_enumeration_create();
        self._check_create_status(ptr)
        super().__init__(ptr, range, display_base)


class SignedEnumerationFieldType(_EnumerationFieldType, _SignedIntegerFieldType):
    _NAME = 'SignedEnumerationFieldType'
    _is_signed = True
    def __init__(self, range=None, display_base=None):
        ptr = native_bt.field_type_signed_enumeration_create();
        self._check_create_status(ptr)
        super().__init__(ptr, range, display_base)


class StringFieldType(_FieldType):
    _NAME = 'String'
    def __init__(self):
        ptr = native_bt.field_type_string_create();
        self._check_create_status(ptr)
        super().__init__(ptr)


class _FieldContainer(collections.abc.Mapping):
    def __len__(self):
        count = self._count()
        assert(count >= 0)
        return count

    def __getitem__(self, key):
        if not isinstance(key, str):
            raise TypeError("'{}' is not a 'str' object".format(key.__class__.__name__))

        ptr = self._borrow_field_type_ptr_by_name(key)

        native_bt.get(ptr)

        if ptr is None:
            raise KeyError(key)

        return _create_field_type_from_ptr(ptr)

    def __iter__(self):
        return self._ITER_CLS(self)

    def append_field(self, name, field_type):
        utils._check_str(name)
        utils._check_type(field_type, _FieldType)
        ret = self._add_field(name, field_type._ptr)
        utils._handle_ret(ret, "cannot add field to {} field type object".format(self._NAME.lower()))

    def __iadd__(self, fields):
        for name, field_type in fields.items():
            self.append_field(name, field_type)

        return self

    def at_index(self, index):
        utils._check_uint64(index)
        return self._at(index)


class _StructureFieldTypeFieldIterator(collections.abc.Iterator):
    def __init__(self, struct_field_type):
        self._struct_field_type = struct_field_type
        self._at = 0

    def __next__(self):
        if self._at == len(self._struct_field_type):
            raise StopIteration

        get_ft_by_index = native_bt.field_type_structure_borrow_member_by_index
        name, field_type_ptr = get_ft_by_index(self._struct_field_type._ptr, self._at)
        self._at += 1
        return name


class StructureFieldType(_FieldType, _FieldContainer):
    _NAME = 'Structure'
    _ITER_CLS = _StructureFieldTypeFieldIterator
    def __init__(self):
        ptr = native_bt.field_type_structure_create()
        self._check_create_status(ptr)
        super().__init__(ptr)

    def _count(self):
        return native_bt.field_type_structure_get_member_count(self._ptr)

    def _add_field(self, name, ptr):
        return native_bt.field_type_structure_append_member(self._ptr, name, ptr)

    def _borrow_field_type_ptr_by_name(self, key):
        field_type_ptr = native_bt.field_type_structure_borrow_member_field_type_by_name(self._ptr, key)
        return field_type_ptr

    def _at(self, index):
        if index < 0 or index >= len(self):
            raise IndexError

        name, field_type_ptr = native_bt.field_type_structure_borrow_member_by_index(self._ptr, index)
        native_bt.get(field_type_ptr)
        return _create_field_type_from_ptr(field_type_ptr)


class _VariantFieldTypeFieldIterator(collections.abc.Iterator):
    def __init__(self, variant_field_type):
        self._variant_field_type = variant_field_type
        self._at = 0

    def __next__(self):
        if self._at == len(self._variant_field_type):
            raise StopIteration

        name, field_type_ptr = native_bt.field_type_variant_borrow_option_by_index(self._variant_field_type._ptr,
                                                                                    self._at)
        self._at += 1
        return name

class VariantFieldType(_FieldType, _FieldContainer):
    _NAME = 'Variant'
    _ITER_CLS = _VariantFieldTypeFieldIterator

    def __init__(self, selector_ft=None):
        ptr = native_bt.field_type_variant_create()
        self._check_create_status(ptr)
        super().__init__(ptr)

        if selector_ft is not None:
            self.selector_field_type = selector_ft

    @property
    def selector_field_path(self):
        ptr = native_bt.field_type_variant_borrow_selector_field_path(self._ptr);
        if ptr is None:
            return

        native_bt.get(ptr)
        return bt2.FieldPath._create_from_ptr(ptr)

    def _set_selector_field_type(self, selector_ft):
        ret = native_bt.field_type_variant_set_selector_field_type(self._ptr, selector_ft._ptr)
        utils._handle_ret(ret, "cannot set variant selector field type")

    selector_field_type = property(fset = _set_selector_field_type)

    def _count(self):
        return native_bt.field_type_variant_get_option_count(self._ptr)

    def _add_field(self, name, ptr):
        return native_bt.field_type_variant_append_option(self._ptr, name, ptr)

    def _borrow_field_type_ptr_by_name(self, key):
        field_type_ptr = native_bt.field_type_variant_borrow_option_field_type_by_name(self._ptr, key)
        return field_type_ptr

    def _at(self, index):
        if index < 0 or index >= len(self):
            raise IndexError

        name, field_type_ptr = native_bt.field_type_variant_borrow_option_by_index(self._ptr, index)
        native_bt.get(field_type_ptr)
        return _create_field_type_from_ptr(field_type_ptr)


class ArrayFieldType(_FieldType):
    @property
    def element_field_type(self):
        elem_ft_ptr = native_bt.field_type_array_borrow_element_field_type(self._ptr)
        native_bt.get(elem_ft_ptr)
        return _create_field_type_from_ptr(elem_ft_ptr)
        

class StaticArrayFieldType(ArrayFieldType):
    def __init__(self, elem_ft, length):
        utils._check_type(elem_ft, _FieldType)
        utils._check_uint64(length)
        ptr = native_bt.field_type_static_array_create(elem_ft._ptr, length)
        self._check_create_status(ptr)
        super().__init__(ptr)

    @property
    def length(self):
        return native_bt.field_type_static_array_get_length(self._ptr)


class DynamicArrayFieldType(ArrayFieldType):
    def __init__(self, elem_ft, length_ft=None):
        utils._check_type(elem_ft, _FieldType)
        ptr = native_bt.field_type_dynamic_array_create(elem_ft._ptr)
        self._check_create_status(ptr)
        super().__init__(ptr)

        if length_ft is not None:
            self.length_field_type = length_ft

    @property
    def length_field_path(self):
        ptr = native_bt.field_type_dynamic_array_borrow_length_field_path(self._ptr)
        if ptr is None:
            return

        native_bt.get(ptr)
        return bt2.FieldPath._create_from_ptr(ptr)

    def _set_length_field_type(self, length_ft):
        utils._check_type(length_ft, _UnsignedIntegerFieldType)
        ret = native_bt.field_type_dynamic_array_set_length_field_type(self._ptr, length_ft._ptr)
        utils._handle_ret(ret, "cannot set dynamic array length field type")

    length_field_type = property(fset=_set_length_field_type)


_FIELD_TYPE_ID_TO_OBJ = {
    native_bt.FIELD_TYPE_ID_UNSIGNED_INTEGER: UnsignedIntegerFieldType,
    native_bt.FIELD_TYPE_ID_SIGNED_INTEGER: SignedIntegerFieldType,
    native_bt.FIELD_TYPE_ID_REAL: RealFieldType,
    native_bt.FIELD_TYPE_ID_UNSIGNED_ENUMERATION: UnsignedEnumerationFieldType,
    native_bt.FIELD_TYPE_ID_SIGNED_ENUMERATION: SignedEnumerationFieldType,
    native_bt.FIELD_TYPE_ID_STRING: StringFieldType,
    native_bt.FIELD_TYPE_ID_STRUCTURE: StructureFieldType,
    native_bt.FIELD_TYPE_ID_STATIC_ARRAY: StaticArrayFieldType,
    native_bt.FIELD_TYPE_ID_DYNAMIC_ARRAY: DynamicArrayFieldType,
    native_bt.FIELD_TYPE_ID_VARIANT: VariantFieldType,
}
