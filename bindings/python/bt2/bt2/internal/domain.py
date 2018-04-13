# The MIT License (MIT)
#
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

__all__ = ['_Domain']

from bt2 import native_bt, utils


class _Domain:
    put = native_bt.put
    get = native_bt.get

    @classmethod
    def create_field_type_from_ptr(cls, ptr):
        typeid = cls.field_type_get_type_id(ptr)
        return cls._FIELD_TYPE_ID_TO_OBJ[typeid]._create_from_ptr(ptr)

    @classmethod
    def create_field_from_ptr(cls, ptr, owner_ptr):
        # recreate the field wrapper of this field's type (the identity
        # could be different, but the underlying address should be the
        # same)
        field_type_ptr = cls.field_get_type(ptr)
        utils._handle_ptr(field_type_ptr, "cannot get field object's type")
        field_type = cls.create_field_type_from_ptr(field_type_ptr)
        typeid = cls.field_type_get_type_id(field_type._ptr)
        field = cls._FIELD_ID_TO_OBJ[typeid]._create_from_ptr(ptr, owner_ptr)
        field._field_type = field_type
        return field

    @classmethod
    def create_event_from_ptr(cls, ptr, owner_ptr):
        # recreate the event class wrapper of this event's class (the
        # identity could be different, but the underlying address should be
        # the same)
        event_class_ptr = cls.event_get_class(ptr)
        utils._handle_ptr(event_class_ptr, "cannot get event object's class")
        new_event_class = cls.EventClass._create_from_ptr(event_class_ptr)
        new_event = cls.Event._create_from_ptr(ptr, owner_ptr)
        new_event._event_class = new_event_class
        return new_event

    @classmethod
    def create_stream_from_ptr(cls, ptr):
        return cls.Stream._create_from_ptr(ptr)
