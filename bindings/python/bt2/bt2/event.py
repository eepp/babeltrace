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
from . import domain
from bt2 import native_bt, utils, internal
import bt2.clock_value
import bt2.packet
import bt2


class _Event(internal._Event, domain._DomainProvider):
    @property
    def packet(self):
        packet_ptr = native_bt.event_get_packet(self._ptr)

        if packet_ptr is None:
            return packet_ptr

        return bt2.packet._Packet._create_from_ptr(packet_ptr)

    def __getitem__(self, key):
        utils._check_str(key)
        payload_field = self.payload_field

        if payload_field is not None and key in payload_field:
            return payload_field[key]

        context_field = self.context_field

        if context_field is not None and key in context_field:
            return context_field[key]

        sec_field = self.stream_event_context_field

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

    def set_clock_value(self, clock_class, value, is_default=True):
        if clock_class is None:
            raise ValueError('clock_class argument is None')

        ret = native_bt.event_set_clock_value(self._ptr, clock_class._ptr, value, is_default);
        utils._handle_ret(ret, "cannot set event default clock value")

    @property
    def default_clock_value(self):
        value_ptr = native_bt.event_borrow_default_clock_value(self._ptr)

        if value_ptr is None:
            return

        return bt2.clock_value._create_clock_value_from_ptr(value_ptr, self._owning_ptr)


domain._Domain.Event = _Event
