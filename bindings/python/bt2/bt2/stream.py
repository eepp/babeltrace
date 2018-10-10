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
from bt2 import native_bt, utils
import bt2.packet

def _create_stream_from_ptr(ptr):
    return _Stream._create_from_ptr(ptr)

class _Stream(bt2.object._SharedObject):
    @property
    def stream_class(self):
        stream_class_ptr = native_bt.stream_borrow_class(self._ptr)
        native_bt.get(stream_class_ptr)
        assert(stream_class_ptr)
        return bt2.stream_class._StreamClass._create_from_ptr(stream_class_ptr)

    @property
    def name(self):
        return native_bt.stream_get_name(self._ptr)

    @name.setter
    def name(self, name):
        utils._check_str(name)
        native_bt.stream_set_name(self._ptr, name)

    @property
    def id(self):
        id = native_bt.stream_get_id(self._ptr)
        return id if id >= 0 else None

    def create_packet(self):
        packet_ptr = native_bt.packet_create(self._ptr)

        if packet_ptr is None:
            raise bt2.CreationError('cannot create packet object')

        return bt2.packet._Packet._create_from_ptr(packet_ptr)
