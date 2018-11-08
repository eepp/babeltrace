# The MIT License (MIT)
#
# Copyright (c) 2016-2017 Philippe Proulx <pproulx@efficios.com>
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
import abc
import bt2
from bt2.ctfwriter import fields, event


class _Stream(bt2.object._SharedObject):
    @property
    def stream_class(self):
        stream_class_ptr = native_bt.stream_get_class(self._ptr)
        assert(stream_class_ptr)
        return bt2.StreamClass._create_from_ptr(stream_class_ptr)

    @property
    def name(self):
        return native_bt.stream_get_name(self._ptr)

    @property
    def id(self):
        id = native_bt.stream_get_id(self._ptr)
        return id if id >= 0 else None

    def append_event(self, ev):
        utils._check_type(ev, event._Event)
        ret = native_bt.ctf_stream_append_event(self._ptr, ev._ptr)
        utils._handle_ret(ret)

    def append_discarded_event(self, nb_event):
        native_bt.ctf_stream_append_discarded_event(self._ptr, nb_event)

    @property
    def packet_header(self):
        field_ptr = native_bt.ctf_stream_get_packet_header(self._ptr)

        if field_ptr is None:
            return
        
        return bt2.ctfwriter.fields._create_from_ptr(field_ptr)

    @packet_header.setter
    def packet_header(self, packet_header):
        utils._check_type(packet_header, fields._Field)
        ret = native_bt.ctf_stream_set_packet_header(self._ptr, packet_header._ptr)
        utils._handle_ret(ret)

    @property
    def packet_context(self):
        field_ptr = native_bt.ctf_stream_get_packet_context(self._ptr)

        if field_ptr is None:
            return
        
        return bt2.ctfwriter.fields._create_from_ptr(field_ptr)

    @packet_context.setter
    def packet_context(self, packet_context):
        utils._check_type(packet_context, fields._Field)
        ret = native_bt.ctf_stream_set_packet_context(self._ptr, packet_context._ptr)
        utils._handle_ret(ret)

    def flush(self):
        ret = native_bt.ctf_stream_flush(self._ptr)
        utils._handle_ret(ret)


