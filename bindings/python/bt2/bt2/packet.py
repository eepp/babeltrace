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
from bt2.internal import object
from . import domain
import bt2.fields
import bt2

__all__ = ['PreviousPacketAvailability']

class PreviousPacketAvailability:
	AVAILABLE = native_bt.PACKET_PREVIOUS_PACKET_AVAILABILITY_AVAILABLE
	NOT_AVAILABLE = native_bt.PACKET_PREVIOUS_PACKET_AVAILABILITY_NOT_AVAILABLE
	NONE = native_bt.PACKET_PREVIOUS_PACKET_AVAILABILITY_NONE

class _Packet(object._SharedObject):
    @property
    def stream(self):
        stream_ptr = native_bt.packet_get_stream(self._ptr)
        assert(stream_ptr)
        return domain._Domain.create_stream_from_ptr(stream_ptr)

    @property
    def default_beginning_clock_value(self):
        prop_avail_status, value_ptr = native_bt.packet_borrow_default_beginning_clock_value(self._ptr)
        if prop_avail_status is native_bt.PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE:
            return

        return bt2.clock_value._create_clock_value_from_ptr(value_ptr, self._ptr)

    @property
    def default_end_clock_value(self):
        prop_avail_status, value_ptr = native_bt.packet_borrow_default_end_clock_value(self._ptr)
        if prop_avail_status is native_bt.PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE:
            return

        return bt2.clock_value._create_clock_value_from_ptr(value_ptr, self._ptr)

    @property
    def previous_packet_default_end_clock_value(self):
        prop_avail_status, value_ptr = native_bt.packet_borrow_previous_packet_default_end_clock_value(self._ptr)
        if prop_avail_status is native_bt.PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE:
            return

        return bt2.clock_value._create_clock_value_from_ptr(value_ptr, self._ptr)

    @property
    def discarded_event_counter(self):
        prop_avail_status, discarded_event_counter = native_bt.packet_get_discarded_event_counter(self._ptr)
        if prop_avail_status is native_bt.PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE:
            return

        return discarded_event_counter

    @property
    def sequence_number(self):
        prop_avail_status, sequence_number = native_bt.packet_get_sequence_number(self._ptr)
        if prop_avail_status is native_bt.PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE:
            return

        return sequence_number

    @property
    def discarded_event_count(self):
        prop_avail_status, discarded_event_count = native_bt.packet_get_discarded_event_count(self._ptr)
        if prop_avail_status is native_bt.PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE:
            return

        return discarded_event_count

    @property
    def discarded_packet_count(self):
        prop_avail_status, discarded_packet_count = native_bt.packet_get_discarded_packet_count(self._ptr)
        if prop_avail_status is native_bt.PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE:
            return

        return discarded_packet_count

    @property
    def header_field(self):
        field_ptr = native_bt.packet_borrow_header(self._ptr)

        if field_ptr is None:
            return

        return domain._Domain.create_field_from_ptr(field_ptr, self._ptr)

    @property
    def context_field(self):
        field_ptr = native_bt.packet_borrow_context(self._ptr)

        if field_ptr is None:
            return

        return domain._Domain.create_field_from_ptr(field_ptr, self._ptr)
