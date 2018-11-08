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

from bt2 import native_bt
import bt2

class _Event(bt2.object._SharedObject):
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
        stream_ptr = native_bt.ctf_ctf_event_get_stream(self._ptr)

        if stream_ptr is None:
            return

        return bt2.ctfwriter._Stream._create_from_ptr(stream_ptr)

    @property
    def stream(self):
        stream_ptr = native_bt.ctf_event_get_stream(self._ptr)

        if stream_ptr is None:
            return stream_ptr

        return bt2.ctfwriter.stream._Stream._create_from_ptr(stream_ptr)

    @property
    def header_field(self):
        field_ptr = native_bt.ctf_event_get_header(self._ptr)

        if field_ptr is None:
            return

        return bt2.ctfwriter.fields._create_from_ptr(field_ptr)

    @header_field.setter
    def header_field(self, header_field):
        header_field_ptr = None

        if header_field is not None:
            utils._check_type(header_field, bt2.ctfwriter.fields._Field)
            header_field_ptr = header_field._ptr

        ret = native_bt.ctf_event_set_header(self._ptr, header_field_ptr)
        utils._handle_ret(ret, "cannot set event object's header field")

    @property
    def stream_event_context_field(self):
        field_ptr = native_bt.ctf_event_get_stream_event_context(self._ptr)

        if field_ptr is None:
            return

        return bt2.ctfwriter.fields._create_from_ptr(field_ptr)

    @stream_event_context_field.setter
    def stream_event_context_field(self, stream_event_context):
        stream_event_context_ptr = None

        if stream_event_context is not None:
            utils._check_type(stream_event_context, bt2.ctfwriter.fields._Field)
            stream_event_context_ptr = stream_event_context._ptr

        ret = native_bt.ctf_event_set_stream_event_context(self._ptr,
                                                       stream_event_context_ptr)
        utils._handle_ret(ret, "cannot set event object's stream event context field")

    @property
    def context_field(self):
        field_ptr = native_bt.ctf_event_get_context(self._ptr)

        if field_ptr is None:
            return

        return bt2.ctfwriter.fields._create_from_ptr(field_ptr)

    @context_field.setter
    def context_field(self, context):
        context_ptr = None

        if context is not None:
            utils._check_type(context, bt2.ctfwriter.fields._Field)
            context_ptr = context._ptr

        ret = native_bt.ctf_event_set_event_context(self._ptr, context_ptr)
        utils._handle_ret(ret, "cannot set event object's context field")

    @property
    def payload_field(self):
        field_ptr = native_bt.ctf_event_get_payload_field(self._ptr)

        if field_ptr is None:
            return

        return bt2.ctfwriter.fields._create_from_ptr(field_ptr)

    @payload_field.setter
    def payload_field(self, payload):
        payload_ptr = None

        if payload is not None:
            utils._check_type(payload, bt2.ctfwriter.fields._Field)
            payload_ptr = payload._ptr

        ret = native_bt.ctf_event_set_event_payload(self._ptr, payload_ptr)
        utils._handle_ret(ret, "cannot set event object's payload field")
