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

__all__ = ['ByteOrder', 'Encoding', 'Base', 'FieldType', 'IntegerFieldType',
        'FloatingPointNumberFieldType', 'EnumerationFieldType',
        'StringFieldType', 'StructureFieldType', 'VariantFieldType',
        'ArrayFieldType', 'SequenceFieldType']

import collections
from . import domain
from bt2 import internal, native_bt, utils


ByteOrder = domain._Domain.ByteOrder
Encoding = domain._Domain.Encoding
Base = domain._Domain.Base


class FieldType():
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            # not comparing apples to apples
            return False

        if self.addr == other.addr:
            return True

        ret = self._Domain.field_type_compare(self._ptr, other._ptr)
        utils._handle_ret(ret, "cannot compare field types")
        return ret == 0

    def __deepcopy__(self, memo):
        ptr = self._Domain.field_type_copy(self._ptr)
        utils._handle_ptr(ptr, 'cannot copy {} field type object'.format(self._NAME.lower()))
        cpy = self._Domain.create_field_type_from_ptr(ptr)
        memo[id(self)] = cpy
        return cpy


class IntegerFieldType(FieldType, internal._IntegerFieldType, domain._DomainProvider):
    pass


class FloatingPointNumberFieldType(FieldType, internal._FloatingPointNumberFieldType, domain._DomainProvider):
    pass


class _EnumerationFieldTypeMappingIterator(internal.object._SharedObject,
                                           collections.abc.Iterator):
    def __init__(self, enum_field_type, iter_ptr, is_signed):
        super().__init__(iter_ptr)
        self._enum_field_type = enum_field_type
        self._is_signed = is_signed
        self._done = (iter_ptr is None)

    def __next__(self):
        if self._done:
            raise StopIteration

        ret = self._enum_field_type._Domain.field_type_enumeration_mapping_iterator_next(self._ptr)
        if ret < 0:
            self._done = True
            raise StopIteration

        if self._is_signed:
            ret, name, lower, upper = self._enum_field_type._Domain.field_type_enumeration_mapping_iterator_signed_get(self._ptr)
        else:
            ret, name, lower, upper = self._enum_field_type._Domain.field_type_enumeration_mapping_iterator_unsigned_get(self._ptr)

        assert(ret == 0)
        mapping = internal._EnumerationFieldTypeMapping(name, lower, upper)

        return mapping


class EnumerationFieldType(FieldType, internal._EnumerationFieldType, domain._DomainProvider):
    def _get_mapping_iter(self, iter_ptr):
        return _EnumerationFieldTypeMappingIterator(self, iter_ptr, self.is_signed)

    def mappings_by_name(self, name):
        utils._check_str(name)
        iter_ptr = self._Domain.field_type_enumeration_find_mappings_by_name(self._ptr, name)
        return self._get_mapping_iter(iter_ptr)

    def mappings_by_value(self, value):
        if self.is_signed:
            utils._check_int64(value)
            iter_ptr = self._Domain.field_type_enumeration_signed_find_mappings_by_value(self._ptr, value)
        else:
            utils._check_uint64(value)
            iter_ptr = self._Domain.field_type_enumeration_unsigned_find_mappings_by_value(self._ptr, value)

        return self._get_mapping_iter(iter_ptr)



class StringFieldType(FieldType, internal._StringFieldType, domain._DomainProvider):
    pass


class _StructureFieldTypeFieldIterator(collections.abc.Iterator):
    def __init__(self, struct_field_type):
        self._struct_field_type = struct_field_type
        self._at = 0

    def __next__(self):
        if self._at == len(self._struct_field_type):
            raise StopIteration

        ret, name, field_type_ptr = native_bt.field_type_structure_borrow_field_by_index(
                self._struct_field_type._ptr, self._at)
        assert(ret == 0)
        self._at += 1
        return name


class StructureFieldType(FieldType, internal._StructureFieldType, domain._DomainProvider):
    _ITER_CLS = _StructureFieldTypeFieldIterator
    def _get_field_type_ptr_by_name(self, key):
        field_type_ptr = native_bt.field_type_structure_get_field_type_by_name(self._ptr, key)
        return field_type_ptr

    def _at(self, index):
        if index < 0 or index >= len(self):
            raise IndexError

        ret, name, field_type_ptr = native_bt.field_type_structure_get_field_by_index(self._ptr, index)
        assert(ret == 0)
        return self._Domain.create_field_type_from_ptr(field_type_ptr)


class VariantFieldType(FieldType, internal._VariantFieldType, domain._DomainProvider):
    pass


class ArrayFieldType(FieldType, internal._ArrayFieldType, domain._DomainProvider):
    pass


class SequenceFieldType(FieldType, internal._SequenceFieldType, domain._DomainProvider):
    pass


domain._Domain._FIELD_TYPE_ID_TO_OBJ = {
    domain._Domain.FIELD_TYPE_ID_INTEGER: IntegerFieldType,
    domain._Domain.FIELD_TYPE_ID_FLOAT: FloatingPointNumberFieldType,
    domain._Domain.FIELD_TYPE_ID_ENUM: EnumerationFieldType,
    domain._Domain.FIELD_TYPE_ID_STRING: StringFieldType,
    domain._Domain.FIELD_TYPE_ID_STRUCT: StructureFieldType,
    domain._Domain.FIELD_TYPE_ID_ARRAY: ArrayFieldType,
    domain._Domain.FIELD_TYPE_ID_SEQUENCE: SequenceFieldType,
    domain._Domain.FIELD_TYPE_ID_VARIANT: VariantFieldType,
}

domain._Domain.IntegerFieldType = IntegerFieldType
domain._Domain.FloatingPointNumberFieldType = FloatingPointNumberFieldType
domain._Domain.EnumerationFieldType = EnumerationFieldType
domain._Domain.StringFieldType = StringFieldType
domain._Domain.StructureFieldType = StructureFieldType
domain._Domain.VariantFieldType = VariantFieldType
domain._Domain.ArrayFieldType = ArrayFieldType
domain._Domain.SequenceFieldType = SequenceFieldType
