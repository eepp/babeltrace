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

__all__ = ['_Stream']

from . import domain
import bt2.packet
from bt2 import ctfwriter, internal, native_bt, utils


class _Stream(internal._Stream, domain._DomainProvider):
    @property
    def discarded_events_count(self):
        ret, count = native_bt.stream_get_discarded_events_count(self._ptr)
        utils._handle_ret(ret, "cannot get CTF writer stream object's discarded events count")
        return count

    def append_discarded_events(self, count):
        utils._check_uint64(count)
        native_bt.stream_append_discarded_events(self._ptr, count)

    def append_event(self, event):
        utils._check_type(event, bt2.ctfwriter.event._Event)
        ret = native_bt.ctf_stream_append_event(self._ptr, event._ptr)
        utils._handle_ret(ret, 'cannot append event object to CTF writer stream object')

    def flush(self):
        ret = native_bt.ctf_stream_flush(self._ptr)
        utils._handle_ret(ret, 'cannot flush CTF writer stream object')

    @property
    def packet_header_field(self):
        field_ptr = native_bt.stream_get_packet_header(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_from_ptr(field_ptr)

    @packet_header_field.setter
    def packet_header_field(self, packet_header_field):
        packet_header_field_ptr = None

        if packet_header_field is not None:
            utils._check_type(packet_header_field, bt2.fields._Field)
            packet_header_field_ptr = packet_header_field._ptr

        ret = native_bt.stream_set_packet_header(self._ptr,
                                                 packet_header_field_ptr)
        utils._handle_ret(ret, "cannot set CTF writer stream object's packet header field")

    @property
    def packet_context_field(self):
        field_ptr = native_bt.stream_get_packet_context(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_from_ptr(field_ptr)

    @packet_context_field.setter
    def packet_context_field(self, packet_context_field):
        packet_context_field_ptr = None

        if packet_context_field is not None:
            utils._check_type(packet_context_field, bt2.fields._Field)
            packet_context_field_ptr = packet_context_field._ptr

        ret = native_bt.stream_set_packet_context(self._ptr,
                                                  packet_context_field_ptr)
        utils._handle_ret(ret, "cannot set CTF writer stream object's packet context field")


domain._Domain.Stream = _Stream
