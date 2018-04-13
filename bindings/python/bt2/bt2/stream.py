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

__all__ = ['_Stream']

from . import domain
from bt2 import internal, native_bt
import bt2.packet


class _Stream(internal._Stream, domain._DomainProvider):
    def create_packet(self, previous_packet_availability, previous_packet):
        previous_packet_ptr = None
        if previous_packet is not None:
            previous_packet_ptr = previous_packet._ptr
        packet_ptr = native_bt.packet_create(self._ptr, previous_packet_availability, previous_packet_ptr)

        if packet_ptr is None:
            raise bt2.CreationError('cannot create packet object')

        return bt2.packet._Packet._create_from_ptr(packet_ptr)


domain._Domain.Stream = _Stream
