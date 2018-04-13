# The MIT License (MIT)
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>
# Copyright (c) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
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

__all__ = ['IntegerFieldType', 'FloatingPointNumberFieldType',
        'EnumerationFieldType', 'StringFieldType', 'StructureFieldType',
        'VariantFieldType', 'ArrayFieldType', 'SequenceFieldType']

from . import domain
from bt2 import internal


ByteOrder = domain._Domain.ByteOrder
Encoding = domain._Domain.Encoding
Base = domain._Domain.Base


class FieldType:
    pass


class IntegerFieldType(FieldType, internal._IntegerFieldType, domain._DomainProvider):
    pass


class FloatingPointNumberFieldType(FieldType, internal._FloatingPointNumberFieldType, domain._DomainProvider):
    pass


class EnumerationFieldType(FieldType, internal._EnumerationFieldType, domain._DomainProvider):
    pass


class StringFieldType(FieldType, internal._StringFieldType, domain._DomainProvider):
    pass


class _CTFStructureFieldTypeFieldIterator(collections.abc.Iterator):
    def __init__(self, struct_field_type):
        self._struct_field_type = struct_field_type
        self._at = 0

    def __next__(self):
        if self._at == len(self._struct_field_type):
            raise StopIteration

        get_ft_by_index = native_bt.ctf_field_type_structure_get_field_by_index
        ret, name, field_type_ptr = get_ft_by_index(self._struct_field_type._ptr,
                                                    self._at)
        assert(ret == 0)
        self._struct_field_type._Domain.put(field_type_ptr)
        self._at += 1
        return name


class StructureFieldType(FieldType, internal._StructureFieldType, domain._DomainProvider):
    _ITER_CLS = _CTFStructureFieldTypeFieldIterator
    def _get_field_by_name(self, key):
        return native_bt.ctf_field_type_structure_get_field_type_by_name(self._ptr, key)

    def _at(self, index):
        if index < 0 or index >= len(self):
            raise IndexError

        ret, name, field_type_ptr = native_bt.ctf_field_type_structure_get_field_by_index(self._ptr, index)
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
