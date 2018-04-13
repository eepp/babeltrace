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

__all__ = ['_ArrayField', '_EnumerationField', '_Field'
        ,'_FloatingPointNumberField', '_IntegerField', '_SequenceField'
        ,'_StringField', '_StructureField', '_VariantField']

from . import domain
from bt2 import field_types, native_bt, internal, utils


class _Field(internal._Field, domain._DomainProvider):
    pass


class _IntegerField(internal._IntegerField, _Field, domain._DomainProvider):
    pass


class _FloatingPointNumberField(internal._FloatingPointNumberField, _Field, domain._DomainProvider):
    pass


class _EnumerationField(internal._EnumerationField, _IntegerField, domain._DomainProvider):
    @property
    def mappings(self):
        iter_ptr = self._Domain.field_enumeration_get_mappings(self._ptr)
        assert(iter_ptr)
        return field_types._EnumerationFieldTypeMappingIterator(self, iter_ptr, self.field_type.is_signed)


class _StringField(internal._StringField, _Field,  domain._DomainProvider):
    pass


class _StructureField(internal._StructureField, _Field, domain._DomainProvider):
    def __getitem__(self, key):
        utils._check_str(key)
        field_ptr = native_bt.field_structure_borrow_field_by_name(self._ptr, key)

        if field_ptr is None:
            raise KeyError(key)

        return self._Domain.create_field_from_ptr(field_ptr, self._owning_ptr)

    def at_index(self, index):
        utils._check_uint64(index)

        if index >= len(self):
            raise IndexError

        field_ptr = self._Domain.field_structure_borrow_field_by_index(self._ptr, index)
        assert(field_ptr)
        return self._Domain.create_field_from_ptr(field_ptr, self._owning_ptr)


class _VariantField(internal._VariantField, _Field, domain._DomainProvider):
    def field(self):
        field_ptr = self._Domain.field_variant_borrow_current_field(self._ptr)
        utils._handle_ptr(field_ptr, "cannot select variant field object's field")

        return self._Domain.create_field_from_ptr(field_ptr, self._owning_ptr)


class _ArrayField(internal._ArrayField, _Field, domain._DomainProvider):
    def _get_field_ptr_at_index(self, index):
        return self._Domain.field_array_borrow_field(self._ptr, index)


class _SequenceField(internal._SequenceField, _Field, domain._DomainProvider):
    def _get_field_ptr_at_index(self, index):
        return self._Domain.field_sequence_borrow_field(self._ptr, index)


domain._Domain._FIELD_ID_TO_OBJ = {
    domain._Domain.FIELD_ID_INTEGER: _IntegerField,
    domain._Domain.FIELD_ID_FLOAT: _FloatingPointNumberField,
    domain._Domain.FIELD_ID_ENUM: _EnumerationField,
    domain._Domain.FIELD_ID_STRING: _StringField,
    domain._Domain.FIELD_ID_STRUCT: _StructureField,
    domain._Domain.FIELD_ID_ARRAY: _ArrayField,
    domain._Domain.FIELD_ID_SEQUENCE: _SequenceField,
    domain._Domain.FIELD_ID_VARIANT: _VariantField,
}

domain._Domain.IntegerField = _IntegerField
domain._Domain.FloatingPointNumberField = _FloatingPointNumberField
domain._Domain.EnumerationField = _EnumerationField
domain._Domain.StringField = _StringField
domain._Domain.StructureField = _StructureField
domain._Domain.VariantField = _VariantField
domain._Domain.ArrayField = _ArrayField
domain._Domain.SequenceField = _SequenceField
