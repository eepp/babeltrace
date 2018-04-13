# The MIT License (MIT)
#
# Copyright (c) 2016-2017 Philippe Proulx <pproulx@efficios.com>
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

__all__ = ['_Event']

import abc
import collections
import numbers
import bt2
from bt2 import utils
from . import object, fields


class _Event(object._UniqueObject):
    @property
    def event_class(self):
        return self._event_class

    @property
    def name(self):
        return self._event_class.name

    @property
    def id(self):
        return self._event_class.id

    @property
    def stream(self):
        stream_ptr = self._Domain.event_get_stream(self._ptr)

        if stream_ptr is None:
            return stream_ptr

        return self._Domain.Stream._create_from_ptr(stream_ptr)

    @property
    def header_field(self):
        field_ptr = self._Domain.event_borrow_header(self._ptr)

        if field_ptr is None:
            return

        return self._Domain.create_field_from_ptr(field_ptr, self._owning_ptr)

    @property
    def stream_event_context_field(self):
        field_ptr = self._Domain.event_borrow_stream_event_context(self._ptr)

        if field_ptr is None:
            return

        return self._Domain.create_field_from_ptr(field_ptr, self._owning_ptr)

    @property
    def context_field(self):
        field_ptr = self._Domain.event_borrow_context(self._ptr)

        if field_ptr is None:
            return

        return self._Domain.create_field_from_ptr(field_ptr, self._owning_ptr)

    @property
    def payload_field(self):
        field_ptr = self._Domain.event_borrow_payload(self._ptr)

        if field_ptr is None:
            return

        return self._Domain.create_field_from_ptr(field_ptr, self._owning_ptr)
