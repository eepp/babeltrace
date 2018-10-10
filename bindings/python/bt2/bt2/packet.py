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

import copy
from bt2 import native_bt, utils, domain
from . import domain
import bt2.fields
import bt2

class _Packet(bt2.object._SharedObject):
    @property
    def stream(self):
        stream_ptr = native_bt.packet_borrow_stream(self._ptr)
        native_bt.get(stream_ptr)
        assert(stream_ptr)
        return bt2.stream._Stream._create_from_ptr(stream_ptr)

    @property
    def default_beginning_clock_value(self):
        prop_avail_status, value_ptr = native_bt.packet_borrow_default_beginning_clock_value(self._ptr)
        if prop_avail_status is bt2.PropertyAvailability.NOT_AVAILABLE:
            return

        return bt2.clock_value._create_clock_value_from_ptr(value_ptr, self._ptr)

    @default_beginning_clock_value.setter
    def default_beginning_clock_value(self, cycles):
        utils._check_uint64(cycles)
        native_bt.packet_set_default_beginning_clock_value(self._ptr, cycles)

    @property
    def default_end_clock_value(self):
        prop_avail_status, value_ptr = native_bt.packet_borrow_default_end_clock_value(self._ptr)
        if prop_avail_status is bt2.PropertyAvailability.NOT_AVAILABLE:
            return

        return bt2.clock_value._create_clock_value_from_ptr(value_ptr, self._ptr)

    @default_end_clock_value.setter
    def default_end_clock_value(self, cycles):
        utils._check_uint64(cycles)
        native_bt.packet_set_default_end_clock_value(self._ptr, cycles)

    @property
    def discarded_event_counter_snapshot(self):
        prop_avail_status, discarded_event_counter = native_bt.packet_get_discarded_event_counter_snapshot(self._ptr)
        if prop_avail_status is bt2.PropertyAvailability.NOT_AVAILABLE:
            return

        return discarded_event_counter
    
    @discarded_event_counter_snapshot.setter
    def discarded_event_counter_snapshot(self, value):
        ret =  native_bt.packet_set_discarded_event_counter_snapshot(self._ptr, value)
        utils._handle_ret(ret, "cannot set discarded event counter snapshot")

    @property
    def packet_counter_snapshot(self):
        prop_avail_status, packet_counter = native_bt.packet_get_packet_counter_snapshot(self._ptr)
        if prop_avail_status is bt2.PropertyAvailability.NOT_AVAILABLE:
            return

        return packet_counter
    
    @packet_counter_snapshot.setter
    def packet_counter_snapshot(self, value):
        ret =  native_bt.packet_set_packet_counter_snapshot(self._ptr, value)
        utils._handle_ret(ret, "cannot set discarded event counter snapshot")

    @property
    def header_field(self):
        field_ptr = native_bt.packet_borrow_header_field(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_field_from_ptr(field_ptr, self._ptr)

    @property
    def context_field(self):
        field_ptr = native_bt.packet_borrow_context_field(self._ptr)

        if field_ptr is None:
            return

        return bt2.fields._create_field_from_ptr(field_ptr, self._ptr)
