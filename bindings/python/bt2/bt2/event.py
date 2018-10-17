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

__all__ = ['_Event']

import collections
from bt2 import native_bt, utils
import bt2.clock_value
import bt2.packet
import bt2

def _create_event_from_ptr(ptr, owner_ptr):
    # recreate the event class wrapper of this event's class (the
    # identity could be different, but the underlying address should be
    # the same)
    event_class_ptr = native_bt.event_borrow_class(ptr)
    native_bt.get(event_class_ptr)
    utils._handle_ptr(event_class_ptr, "cannot get event object's class")
    event_class = bt2.event_class._EventClass._create_from_ptr(event_class_ptr)
    event = _Event._create_from_ptr(ptr, owner_ptr)
    event._event_class = event_class
    return event


class _Event(bt2.object._UniqueObject):
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
        stream_ptr = native_bt.event_borrow_stream(self._ptr)

        if stream_ptr is None:
            return

        native_bt.get(stream_ptr)

        return bt2._Stream._create_from_ptr(stream_ptr)

    @property
    def header_field(self):
        field_ptr = native_bt.event_borrow_header_field(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_field_from_ptr(field_ptr, self._owning_ptr)

    @property
    def common_context_field(self):
        field_ptr = native_bt.event_borrow_common_context_field(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_field_from_ptr(field_ptr, self._owning_ptr)

    @property
    def specific_context_field(self):
        field_ptr = native_bt.event_borrow_specific_context_field(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_field_from_ptr(field_ptr, self._owning_ptr)

    @property
    def payload_field(self):
        field_ptr = native_bt.event_borrow_payload_field(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_field_from_ptr(field_ptr, self._owning_ptr)
    @property
    def packet(self):
        packet_ptr = native_bt.event_borrow_packet(self._ptr)

        if packet_ptr is None:
            return packet_ptr

        native_bt.get(packet_ptr)

        return bt2.packet._Packet._create_from_ptr(packet_ptr)

    def __getitem__(self, key):
        utils._check_str(key)
        payload_field = self.payload_field

        if payload_field is not None and key in payload_field:
            return payload_field[key]

        specific_context_field = self.specific_context_field

        if specific_context_field is not None and key in specific_context_field:
            return specific_context_field[key]

        sec_field = self.common_context_field

        if sec_field is not None and key in sec_field:
            return sec_field[key]

        header_field = self.header_field

        if header_field is not None and key in header_field:
            return header_field[key]

        packet = self.packet

        if packet is None:
            raise KeyError(key)

        pkt_context_field = packet.context_field

        if pkt_context_field is not None and key in pkt_context_field:
            return pkt_context_field[key]

        pkt_header_field = packet.header_field

        if pkt_header_field is not None and key in pkt_header_field:
            return pkt_header_field[key]

        raise KeyError(key)

    @property
    def default_clock_value(self):
        status, value_ptr = native_bt.event_borrow_default_clock_value(self._ptr)

        if status is native_bt.CLOCK_VALUE_STATUS_UNKNOWN:
            return

        if value_ptr is None:
            return

        return bt2.clock_value._ClockValue._create_from_ptr(value_ptr, self._owning_ptr)

    @default_clock_value.setter
    def default_clock_value(self, value):
        ret = native_bt.event_set_default_clock_value(self._ptr, value);
        utils._handle_ret(ret, "cannot set event default clock value")
