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

__all__ = ['_FieldType', '_IntegerFieldType', '_FloatingPointNumberFieldType',
        '_EnumerationFieldTypeMapping', '_EnumerationFieldType',
        '_StringFieldType', '_StructureFieldType', '_ArrayFieldType',
        '_SequenceFieldType', '_VariantFieldType']

import bt2
import collections.abc

from bt2 import utils
from . import fields, object

class _FieldType(object._SharedObject):
    def __init__(self, ptr):
        super().__init__(ptr)

    def _check_create_status(self, ptr):
        if ptr is None:
            raise bt2.CreationError('cannot create {} field type object'.format(self._NAME.lower()))


class _AlignmentProp:
    @property
    def alignment(self):
        alignment = self._Domain.field_type_get_alignment(self._ptr)
        assert(alignment >= 0)
        return alignment

    @alignment.setter
    def alignment(self, alignment):
        utils._check_alignment(alignment)
        ret = self._Domain.field_type_set_alignment(self._ptr, alignment)
        utils._handle_ret(ret, "cannot set field type object's alignment")


class _ByteOrderProp:
    @property
    def byte_order(self):
        bo = self._Domain.field_type_get_byte_order(self._ptr)
        assert(bo >= 0)
        return bo

    @byte_order.setter
    def byte_order(self, byte_order):
        utils._check_int(byte_order)
        ret = self._Domain.field_type_set_byte_order(self._ptr, byte_order)
        utils._handle_ret(ret, "cannot set field type object's byte order")


class _IntegerFieldType(_FieldType, _AlignmentProp, _ByteOrderProp):
    _NAME = 'Integer'

    def __init__(self, size, alignment=None, byte_order=None, is_signed=None,
                 base=None, encoding=None, mapped_clock_class=None):
        utils._check_uint64(size)

        if size == 0:
            raise ValueError('size is 0 bits')

        ptr = self._Domain.field_type_integer_create(size)
        self._check_create_status(ptr)
        super().__init__(ptr)

        if alignment is not None:
            self.alignment = alignment

        if byte_order is not None:
            self.byte_order = byte_order

        if is_signed is not None:
            self.is_signed = is_signed

        if base is not None:
            self.base = base

        if encoding is not None:
            self.encoding = encoding

        if mapped_clock_class is not None:
            self.mapped_clock_class = mapped_clock_class

    @property
    def size(self):
        size = self._Domain.field_type_integer_get_size(self._ptr)
        assert(size >= 1)
        return size

    @property
    def is_signed(self):
        is_signed = self._Domain.field_type_integer_is_signed(self._ptr)
        assert(is_signed >= 0)
        return is_signed > 0

    @is_signed.setter
    def is_signed(self, is_signed):
        utils._check_bool(is_signed)
        ret = self._Domain.field_type_integer_set_is_signed(self._ptr, int(is_signed))
        utils._handle_ret(ret, "cannot set integer field type object's signedness")

    @property
    def base(self):
        base = self._Domain.field_type_integer_get_base(self._ptr)
        assert(base >= 0)
        return base

    @base.setter
    def base(self, base):
        utils._check_int(base)
        ret = self._Domain.field_type_integer_set_base(self._ptr, base)
        utils._handle_ret(ret, "cannot set integer field type object's base")

    @property
    def encoding(self):
        encoding = self._Domain.field_type_integer_get_encoding(self._ptr)
        assert(encoding >= 0)
        return encoding

    @encoding.setter
    def encoding(self, encoding):
        utils._check_int(encoding)
        ret = self._Domain.field_type_integer_set_encoding(self._ptr, encoding)
        utils._handle_ret(ret, "cannot set integer field type object's encoding")

    @property
    def mapped_clock_class(self):
        ptr = self._Domain.field_type_integer_get_mapped_clock_class(self._ptr)

        if ptr is None:
            return

        return self._Domain.ClockClass._create_from_ptr(ptr)

    @mapped_clock_class.setter
    def mapped_clock_class(self, clock_class):
        utils._check_type(clock_class, self._Domain.ClockClass)
        ret = self._Domain.field_type_integer_set_mapped_clock_class(self._ptr, clock_class._ptr)
        utils._handle_ret(ret, "cannot set integer field type object's mapped clock class")


class _FloatingPointNumberFieldType(_FieldType, _AlignmentProp, _ByteOrderProp):
    _NAME = 'Floating point number'

    def __init__(self, alignment=None, byte_order=None, exponent_size=None,
                 mantissa_size=None):
        ptr = self._Domain.field_type_floating_point_create()
        self._check_create_status(ptr)
        super().__init__(ptr)

        if alignment is not None:
            self.alignment = alignment

        if byte_order is not None:
            self.byte_order = byte_order

        if exponent_size is not None:
            self.exponent_size = exponent_size

        if mantissa_size is not None:
            self.mantissa_size = mantissa_size

    @property
    def exponent_size(self):
        exp_size = self._Domain.field_type_floating_point_get_exponent_digits(self._ptr)
        assert(exp_size >= 0)
        return exp_size

    @exponent_size.setter
    def exponent_size(self, exponent_size):
        utils._check_uint64(exponent_size)
        ret = self._Domain.field_type_floating_point_set_exponent_digits(self._ptr, exponent_size)
        utils._handle_ret(ret, "cannot set floating point number field type object's exponent size")

    @property
    def mantissa_size(self):
        mant_size = self._Domain.field_type_floating_point_get_mantissa_digits(self._ptr)
        assert(mant_size >= 0)
        return mant_size

    @mantissa_size.setter
    def mantissa_size(self, mantissa_size):
        utils._check_uint64(mantissa_size)
        ret = self._Domain.field_type_floating_point_set_mantissa_digits(self._ptr, mantissa_size)
        utils._handle_ret(ret, "cannot set floating point number field type object's mantissa size")


class _EnumerationFieldTypeMapping:
    def __init__(self, name, lower, upper):
        self._name = name
        self._lower = lower
        self._upper = upper

    @property
    def name(self):
        return self._name

    @property
    def lower(self):
        return self._lower

    @property
    def upper(self):
        return self._upper

    def __eq__(self, other):
        if type(other) is not self.__class__:
            return False

        return (self.name, self.lower, self.upper) == (other.name, other.lower, other.upper)


class _EnumerationFieldType(_IntegerFieldType, collections.abc.Sequence):
    _NAME = 'Enumeration'

    def __init__(self, int_field_type=None, size=None, alignment=None,
                 byte_order=None, is_signed=None, base=None, encoding=None,
                 mapped_clock_class=None):
        if int_field_type is None:
            int_field_type = self._Domain.IntegerFieldType(size=size, alignment=alignment,
                                              byte_order=byte_order,
                                              is_signed=is_signed, base=base,
                                              encoding=encoding,
                                              mapped_clock_class=mapped_clock_class)

        utils._check_type(int_field_type, _IntegerFieldType)
        ptr = self._Domain.field_type_enumeration_create(int_field_type._ptr)
        self._check_create_status(ptr)
        _FieldType.__init__(self, ptr)

    @property
    def integer_field_type(self):
        ptr = self._Domain.field_type_enumeration_get_container_field_type(self._ptr)
        assert(ptr)
        return self._Domain.create_field_type_from_ptr(ptr)

    @property
    def size(self):
        return self.integer_field_type.size

    @property
    def alignment(self):
        return self.integer_field_type.alignment

    @alignment.setter
    def alignment(self, alignment):
        self.integer_field_type.alignment = alignment

    @property
    def byte_order(self):
        return self.integer_field_type.byte_order

    @byte_order.setter
    def byte_order(self, byte_order):
        self.integer_field_type.byte_order = byte_order

    @property
    def is_signed(self):
        return self.integer_field_type.is_signed

    @is_signed.setter
    def is_signed(self, is_signed):
        self.integer_field_type.is_signed = is_signed

    @property
    def base(self):
        return self.integer_field_type.base

    @base.setter
    def base(self, base):
        self.integer_field_type.base = base

    @property
    def encoding(self):
        return self.integer_field_type.encoding

    @encoding.setter
    def encoding(self, encoding):
        self.integer_field_type.encoding = encoding

    @property
    def mapped_clock_class(self):
        return self.integer_field_type.mapped_clock_class

    @mapped_clock_class.setter
    def mapped_clock_class(self, mapped_clock_class):
        self.integer_field_type.mapped_clock_class = mapped_clock_class

    def __len__(self):
        count = self._Domain.field_type_enumeration_get_mapping_count(self._ptr)
        assert(count >= 0)
        return count

    def __getitem__(self, index):
        utils._check_uint64(index)

        if index >= len(self):
            raise IndexError

        if self.is_signed:
            get_fn = self._Domain.field_type_enumeration_signed_get_mapping_by_index
        else:
            get_fn = self._Domain.field_type_enumeration_unsigned_get_mapping_by_index

        ret, name, lower, upper = get_fn(self._ptr, index)
        assert(ret == 0)
        return _EnumerationFieldTypeMapping(name, lower, upper)

    def add_mapping(self, name, lower, upper=None):
        utils._check_str(name)

        if upper is None:
            upper = lower

        if self.is_signed:
            add_fn = self._Domain.field_type_enumeration_signed_add_mapping
            utils._check_int64(lower)
            utils._check_int64(upper)
        else:
            add_fn = self._Domain.field_type_enumeration_unsigned_add_mapping
            utils._check_uint64(lower)
            utils._check_uint64(upper)

        ret = add_fn(self._ptr, name, lower, upper)
        utils._handle_ret(ret, "cannot add mapping to enumeration field type object")

    def __iadd__(self, mappings):
        for mapping in mappings:
            self.add_mapping(mapping.name, mapping.lower, mapping.upper)

        return self


class _StringFieldType(_FieldType):
    _NAME = 'String'

    def __init__(self, encoding=None):
        ptr = self._Domain.field_type_string_create()
        self._check_create_status(ptr)
        super().__init__(ptr)

        if encoding is not None:
            self.encoding = encoding

    @property
    def encoding(self):
        encoding = self._Domain.field_type_string_get_encoding(self._ptr)
        assert(encoding >= 0)
        return encoding

    @encoding.setter
    def encoding(self, encoding):
        utils._check_int(encoding)
        ret = self._Domain.field_type_string_set_encoding(self._ptr, encoding)
        utils._handle_ret(ret, "cannot set string field type object's encoding")


class _FieldContainer(collections.abc.Mapping):
    def __len__(self):
        count = self._count()
        assert(count >= 0)
        return count

    def __getitem__(self, key):
        if not isinstance(key, str):
            raise TypeError("'{}' is not a 'str' object".format(key.__class__.__name__))

        ptr = self._get_field_type_ptr_by_name(key)

        if ptr is None:
            raise KeyError(key)

        return self._Domain.create_field_type_from_ptr(ptr)

    def __iter__(self):
        return self._ITER_CLS(self)

    def append_field(self, name, field_type):
        utils._check_str(name)
        utils._check_type(field_type, _FieldType)
        ret = self._add_field(field_type._ptr, name)
        utils._handle_ret(ret, "cannot add field to {} field type object".format(self._NAME.lower()))

    def __iadd__(self, fields):
        for name, field_type in fields.items():
            self.append_field(name, field_type)

        return self

    def at_index(self, index):
        utils._check_uint64(index)
        return self._at(index)


class _StructureFieldType(_FieldType, _FieldContainer, _AlignmentProp):
    _NAME = 'Structure'

    def __init__(self, min_alignment=None):
        ptr = self._Domain.field_type_structure_create()
        self._check_create_status(ptr)
        super().__init__(ptr)

        if min_alignment is not None:
            self.min_alignment = min_alignment

    def _count(self):
        return self._Domain.field_type_structure_get_field_count(self._ptr)

    def _add_field(self, ptr, name):
        return self._Domain.field_type_structure_add_field(self._ptr, ptr,
                                                        name)


_StructureFieldType.min_alignment = property(fset=_StructureFieldType.alignment.fset)
_StructureFieldType.alignment = property(fget=_StructureFieldType.alignment.fget)


class _VariantFieldTypeFieldIterator(collections.abc.Iterator):
    def __init__(self, variant_field_type):
        self._variant_field_type = variant_field_type
        self._at = 0

    def __next__(self):
        if self._at == len(self._variant_field_type):
            raise StopIteration

        ret, name, field_type_ptr = self._variant_field_type._Domain.field_type_variant_get_field_by_index(self._variant_field_type._ptr,
                                                                                    self._at)
        assert(ret == 0)
        self._variant_field_type._Domain.put(field_type_ptr)
        self._at += 1
        return name


class _VariantFieldType(_FieldType, _FieldContainer, _AlignmentProp):
    _NAME = 'Variant'
    _ITER_CLS = _VariantFieldTypeFieldIterator

    def __init__(self, tag_name, tag_field_type=None):
        utils._check_str(tag_name)

        if tag_field_type is None:
            tag_ft_ptr = None
        else:
            utils._check_type(tag_field_type, _EnumerationFieldType)
            tag_ft_ptr = tag_field_type._ptr

        ptr = self._Domain.field_type_variant_create(tag_ft_ptr,
                                                  tag_name)
        self._check_create_status(ptr)
        super().__init__(ptr)

    @property
    def tag_name(self):
        tag_name = self._Domain.field_type_variant_get_tag_name(self._ptr)
        assert(tag_name is not None)
        return tag_name

    @tag_name.setter
    def tag_name(self, tag_name):
        utils._check_str(tag_name)
        ret = self._Domain.field_type_variant_set_tag_name(self._ptr, tag_name)
        utils._handle_ret(ret, "cannot set variant field type object's tag name")

    @property
    def tag_field_type(self):
        ft_ptr = self._Domain.field_type_variant_get_tag_type(self._ptr)

        if ft_ptr is None:
            return

        return self._Domain.create_field_type_from_ptr(ft_ptr)

    def _count(self):
        return self._Domain.field_type_variant_get_field_count(self._ptr)

    def _get_field_type_ptr_by_name(self, key):
        return self._Domain.field_type_variant_get_field_type_by_name(self._ptr, key)

    def _add_field(self, ptr, name):
        return self._Domain.field_type_variant_add_field(self._ptr, ptr, name)

    def _at(self, index):
        if index < 0 or index >= len(self):
            raise IndexError

        ret, name, field_type_ptr = self._Domain.field_type_variant_get_field_by_index(self._ptr, index)
        assert(ret == 0)
        return self._Domain.create_field_type_from_ptr(field_type_ptr)


class _ArrayFieldType(_FieldType):
    _NAME = 'Array'

    def __init__(self, element_field_type, length):
        utils._check_type(element_field_type, _FieldType)
        utils._check_uint64(length)
        ptr = self._Domain.field_type_array_create(element_field_type._ptr, length)
        self._check_create_status(ptr)
        super().__init__(ptr)

    @property
    def length(self):
        length = self._Domain.field_type_array_get_length(self._ptr)
        assert(length >= 0)
        return length

    @property
    def element_field_type(self):
        ptr = self._Domain.field_type_array_get_element_field_type(self._ptr)
        assert(ptr)
        return self._Domain.create_field_type_from_ptr(ptr)


class _SequenceFieldType(_FieldType):
    _NAME = 'Sequence'

    def __init__(self, element_field_type, length_name):
        utils._check_type(element_field_type, _FieldType)
        utils._check_str(length_name)
        ptr = self._Domain.field_type_sequence_create(element_field_type._ptr,
                                                   length_name)
        self._check_create_status(ptr)
        super().__init__(ptr)

    @property
    def length_name(self):
        length_name = self._Domain.field_type_sequence_get_length_field_name(self._ptr)
        assert(length_name is not None)
        return length_name

    @property
    def element_field_type(self):
        ptr = self._Domain.field_type_sequence_get_element_field_type(self._ptr)
        assert(ptr)
        return self._Domain.create_field_type_from_ptr(ptr)
