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

__all__ = ['_StaticArrayField', '_DynamicArrayField', '_UnsignedEnumerationField',
        '_UnsignedEnumerationField', '_Field' ,'_RealField', '_IntegerField',
        '_StringField', '_StructureField', '_VariantField']

from bt2 import field_types, native_bt, utils
import abc
import bt2
import collections.abc
import functools
import math
import numbers

def _create_field_from_ptr(ptr, owner_ptr):
    # recreate the field wrapper of this field's type (the identity
    # could be different, but the underlying address should be the
    # same)
    field_type_ptr = native_bt.field_borrow_type(ptr)
    native_bt.get(field_type_ptr)
    utils._handle_ptr(field_type_ptr, "cannot get field object's type")
    field_type = bt2.field_types._create_field_type_from_ptr(field_type_ptr)
    typeid = native_bt.field_type_get_type_id(field_type._ptr)
    field = _FIELD_ID_TO_OBJ[typeid]._create_from_ptr(ptr, owner_ptr)
    field._field_type = field_type
    return field

def _get_leaf_field(obj):
    if not isinstance(obj, _VariantField):
        return obj

    return _get_leaf_field(obj.selected_field)

class _Field(bt2.object._UniqueObject):
    def __eq__(self, other):
        other = _get_leaf_field(other)
        return self._spec_eq(other)

    @property
    def field_type(self):
        return self._field_type

    def _repr(self):
        raise NotImplementedError

    def __repr__(self):
        return self._repr()

@functools.total_ordering
class _NumericField(_Field):
    @staticmethod
    def _extract_value(other):
        if other is True or other is False:
            return other

        if isinstance(other, numbers.Integral):
            return int(other)

        if isinstance(other, numbers.Real):
            return float(other)

        if isinstance(other, numbers.Complex):
            return complex(other)

        raise TypeError("'{}' object is not a number object".format(other.__class__.__name__))

    def __hash__(self):
        return self._value.__hash__()

    def __int__(self):
        return int(self._value)

    def __float__(self):
        return float(self._value)

    def _repr(self):
        return repr(self._value)

    def __lt__(self, other):
        if not isinstance(other, numbers.Number):
            raise TypeError('unorderable types: {}() < {}()'.format(self.__class__.__name__,
                                                                    other.__class__.__name__))

        return self._value < float(other)

    def __le__(self, other):
        if not isinstance(other, numbers.Number):
            raise TypeError('unorderable types: {}() <= {}()'.format(self.__class__.__name__,
                                                                     other.__class__.__name__))

        return self._value <= float(other)

    def _spec_eq(self, other):
        if not isinstance(other, numbers.Number):
            return NotImplemented

        return self._value == complex(other)

    def __rmod__(self, other):
        return self._extract_value(other) % self._value

    def __mod__(self, other):
        return self._value % self._extract_value(other)

    def __rfloordiv__(self, other):
        return self._extract_value(other) // self._value

    def __floordiv__(self, other):
        return self._value // self._extract_value(other)

    def __round__(self, ndigits=None):
        if ndigits is None:
            return round(self._value)
        else:
            return round(self._value, ndigits)

    def __ceil__(self):
        return math.ceil(self._value)

    def __floor__(self):
        return math.floor(self._value)

    def __trunc__(self):
        return int(self._value)

    def __abs__(self):
        return abs(self._value)

    def __add__(self, other):
        return self._value + self._extract_value(other)

    def __radd__(self, other):
        return self.__add__(other)

    def __neg__(self):
        return -self._value

    def __pos__(self):
        return +self._value

    def __mul__(self, other):
        return self._value * self._extract_value(other)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        return self._value / self._extract_value(other)

    def __rtruediv__(self, other):
        return self._extract_value(other) / self._value

    def __pow__(self, exponent):
        return self._value ** self._extract_value(exponent)

    def __rpow__(self, base):
        return self._extract_value(base) ** self._value

    def __iadd__(self, other):
        self.value = self + other
        return self

    def __isub__(self, other):
        self.value = self - other
        return self

    def __imul__(self, other):
        self.value = self * other
        return self

    def __itruediv__(self, other):
        self.value = self / other
        return self

    def __ifloordiv__(self, other):
        self.value = self // other
        return self

    def __imod__(self, other):
        self.value = self % other
        return self

    def __ipow__(self, other):
        self.value = self ** other
        return self


class _IntegralField(_NumericField, numbers.Integral):
    def __lshift__(self, other):
        return self._value << self._extract_value(other)

    def __rlshift__(self, other):
        return self._extract_value(other) << self._value

    def __rshift__(self, other):
        return self._value >> self._extract_value(other)

    def __rrshift__(self, other):
        return self._extract_value(other) >> self._value

    def __and__(self, other):
        return self._value & self._extract_value(other)

    def __rand__(self, other):
        return self._extract_value(other) & self._value

    def __xor__(self, other):
        return self._value ^ self._extract_value(other)

    def __rxor__(self, other):
        return self._extract_value(other) ^ self._value

    def __or__(self, other):
        return self._value | self._extract_value(other)

    def __ror__(self, other):
        return self._extract_value(other) | self._value

    def __invert__(self):
        return ~self._value

    def __ilshift__(self, other):
        self.value = self << other
        return self

    def __irshift__(self, other):
        self.value = self >> other
        return self

    def __iand__(self, other):
        self.value = self & other
        return self

    def __ixor__(self, other):
        self.value = self ^ other
        return self

    def __ior__(self, other):
        self.value = self | other
        return self


class _IntegerField(_IntegralField, _Field):
    _NAME = 'Integer'



class _UnsignedIntegerField(_IntegerField, _Field):
    def _value_to_int(self, value):
        if not isinstance(value, numbers.Real):
            raise TypeError('expecting a real number object')

        value = int(value)
        utils._check_uint64(value)

        return value

    @property
    def _value(self):
        return native_bt.field_unsigned_integer_get_value(self._ptr)

    def _set_value(self, value):
        value = self._value_to_int(value)
        native_bt.field_unsigned_integer_set_value(self._ptr, value)

    value = property(fset=_set_value)


class _SignedIntegerField(_IntegerField, _Field):
    def _value_to_int(self, value):
        if not isinstance(value, numbers.Real):
            raise TypeError('expecting a real number object')

        value = int(value)
        utils._check_int64(value)

        return value

    @property
    def _value(self):
        return native_bt.field_signed_integer_get_value(self._ptr)

    def _set_value(self, value):
        value = self._value_to_int(value)
        native_bt.field_signed_integer_set_value(self._ptr, value)

    value = property(fset=_set_value)


class _RealField(_NumericField, numbers.Real):
    _NAME = 'Real number'

    def _value_to_float(self, value):
        if not isinstance(value, numbers.Real):
            raise TypeError("expecting a real number object")

        return float(value)

    @property
    def _value(self):
        return native_bt.field_real_get_value(self._ptr)

    def _set_value(self, value):
        value = self._value_to_float(value)
        native_bt.field_real_set_value(self._ptr, value)

    value = property(fset=_set_value)


class _EnumerationField(_IntegerField):
    _NAME = 'Enumeration'

    def _repr(self):
        return '{} ({})'.format(self._value, ', '.join(self.labels))

    @property
    def labels(self):
        return self.field_type.labels_by_value(self._value)

class _UnsignedEnumerationField(_EnumerationField, _UnsignedIntegerField):
    _NAME = 'Enumeration'

class _SignedEnumerationField(_EnumerationField, _SignedIntegerField):
    _NAME = 'Enumeration'

class _StringField(_Field):
    _NAME = 'String'

    def _value_to_str(self, value):
        if isinstance(value, self.__class__):
            value = value._value

        if not isinstance(value, str):
            raise TypeError("expecting a 'str' object")

        return value

    @property
    def _value(self):
        return native_bt.field_string_get_value(self._ptr)

    def _set_value(self, value):
        value = self._value_to_str(value)
        native_bt.field_string_set_value(self._ptr, value)

    value = property(fset=_set_value)

    def _spec_eq(self, other):
        try:
            other = self._value_to_str(other)
        except:
            return False

        return self._value == other

    def __le__(self, other):
        return self._value <= self._value_to_str(other)

    def __lt__(self, other):
        return self._value < self._value_to_str(other)

    def __bool__(self):
        return bool(self._value)

    def _repr(self):
        return repr(self._value)

    def __str__(self):
        return self._value

    def __getitem__(self, index):
        return self._value[index]

    def __len__(self):
        return len(self._value)

    def __iadd__(self, value):
        value = self._value_to_str(value)
        ret = native_bt.field_string_append(self._ptr, value)
        utils._handle_ret(ret, "cannot append to string field object's value")
        return self

class _ContainerField(_Field):
    def __bool__(self):
        return len(self) != 0

    def __len__(self):
        count = self._count()
        assert(count >= 0)
        return count

    def __delitem__(self, index):
        raise NotImplementedError


class _StructureField(_ContainerField, collections.abc.MutableMapping):
    _NAME = 'Structure'

    def _count(self):
        return len(self.field_type)

    def __setitem__(self, key, value):
        # raises if key is somehow invalid
        field = self[key]

        # the field's property does the appropriate conversion or raises
        # the appropriate exception
        field.value = value

    def __iter__(self):
        # same name iterator
        return iter(self.field_type)

    def _spec_eq(self, other):
        try:
            if len(self) != len(other):
                return False

            for self_key, self_value in self.items():
                if self_key not in other:
                    return False

                other_value = other[self_key]

                if self_value != other_value:
                    return False

            return True
        except:
            return False

    @property
    def _value(self):
        return {key: value._value for key, value in self.items()}

    def _set_value(self, values):

        try:
            for key, value in values.items():
                self[key].value = value
        except:
            raise

    value = property(fset=_set_value)

    def _repr(self):
        items = ['{}: {}'.format(repr(k), repr(v)) for k, v in self.items()]
        return '{{{}}}'.format(', '.join(items))

    def __getitem__(self, key):
        utils._check_str(key)
        field_ptr = native_bt.field_structure_borrow_member_field_by_name(self._ptr, key)

        if field_ptr is None:
            raise KeyError(key)

        return _create_field_from_ptr(field_ptr, self._owning_ptr)

    def at_index(self, index):
        utils._check_uint64(index)

        if index >= len(self):
            raise IndexError

        field_ptr = native_bt.field_structure_borrow_member_field_by_index(self._ptr, index)
        assert(field_ptr)
        return _create_field_from_ptr(field_ptr, self._owning_ptr)


class _VariantField(_ContainerField, _Field):
    _NAME = 'Variant'

    def field(self):
        field_ptr = native_bt.field_variant_borrow_selected_option_field(self._ptr)
        utils._handle_ptr(field_ptr, "cannot select variant field object's field")

        return _create_field_from_ptr(field_ptr, self._owning_ptr)

    @property
    def selected_index(self):
        return native_bt.field_variant_get_selected_option_field(self._ptr)

    @selected_index.setter
    def selected_index(self, index):
        native_bt.field_variant_select_option_field(self._ptr, index)

    @property
    def selected_field(self):
        return self.field()

    def _spec_eq(self, other):
        new_self = _get_leaf_field(self)
        return new_self == other

    def __bool__(self):
        return bool(self.selected_field)

    def __str__(self):
        return str(self.selected_field)

    def _repr(self):
        return repr(self.selected_field)

    @property
    def _value(self):
        if self.selected_field is not None:
            return self.selected_field._value

    def _set_value(self, value):
        self.selected_field.value = value

    value = property(fset=_set_value)


class _ArrayField(_ContainerField, _Field):

    def __getitem__(self, index):
        if not isinstance(index, numbers.Integral):
            raise TypeError("'{}' is not an integral number object: invalid index".format(index.__class__.__name__))

        index = int(index)

        if index < 0 or index >= len(self):
            raise IndexError('{} field object index is out of range'.format(self._NAME))

        field_ptr = native_bt.field_array_borrow_element_field_by_index(self._ptr, index)
        assert(field_ptr)
        return _create_field_from_ptr(field_ptr, self._owning_ptr)

    def __setitem__(self, index, value):
        # we can only set numbers and strings
        if not isinstance(value, (numbers.Number, _StringField, str)):
            raise TypeError('expecting number or string object')

        # raises if index is somehow invalid
        field = self[index]

        if not isinstance(field, (_NumericField, _StringField)):
            raise TypeError('can only set the value of a number or string field')

        # the field's property does the appropriate conversion or raises
        # the appropriate exception
        field.value = value

    def insert(self, index, value):
        raise NotImplementedError

    def _spec_eq(self, other):
        try:
            if len(self) != len(other):
                return False

            for self_field, other_field in zip(self, other):
                if self_field != other_field:
                    return False

            return True
        except:
            return False

    @property
    def _value(self):
        return [field._value for field in self]

    def _repr(self):
        return '[{}]'.format(', '.join([repr(v) for v in self]))

class _StaticArrayField(_ArrayField, _Field):
    _NAME = 'StaticArray'

    def _count(self):
        return self.field_type.length

    def _set_value(self, values):
        if len(self) != len(values):
            raise ValueError(
                'expected length of value and array field to match')

        try:
            for index, value in enumerate(values):
                if value is not None:
                    self[index].value = value
        except:
            raise

    value = property(fset=_set_value)

class _DynamicArrayField(_ArrayField, _Field):
    _NAME = 'DynamicArray'

    def _count(self):
        return self.length

    @property
    def length(self):
        return native_bt.field_array_get_length(self._ptr)

    @length.setter
    def length(self, length):
        # should we check the return value of this call
        native_bt.field_dynamic_array_set_length(self._ptr, length)

    def _set_value(self, values):
        original_length_field = self.length

        if len(values) != self.length:
            self.length = len(values)

        try:
            for index, value in enumerate(values):
                if value is not None:
                    self[index].value = value
        except:
            self.length = original_length_field
            raise

    value = property(fset=_set_value)


_FIELD_ID_TO_OBJ = {
    native_bt.FIELD_TYPE_ID_UNSIGNED_INTEGER: _UnsignedIntegerField,
    native_bt.FIELD_TYPE_ID_SIGNED_INTEGER: _SignedIntegerField,
    native_bt.FIELD_TYPE_ID_REAL: _RealField,
    native_bt.FIELD_TYPE_ID_UNSIGNED_ENUMERATION: _UnsignedEnumerationField,
    native_bt.FIELD_TYPE_ID_SIGNED_ENUMERATION: _SignedEnumerationField,
    native_bt.FIELD_TYPE_ID_STRING: _StringField,
    native_bt.FIELD_TYPE_ID_STRUCTURE: _StructureField,
    native_bt.FIELD_TYPE_ID_STATIC_ARRAY: _StaticArrayField,
    native_bt.FIELD_TYPE_ID_DYNAMIC_ARRAY: _DynamicArrayField,
    native_bt.FIELD_TYPE_ID_VARIANT: _VariantField,
}
