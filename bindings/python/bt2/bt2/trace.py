# The MIT License (MIT)
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>
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

__all__ = ['Trace']

from . import domain
from bt2 import internal, native_bt, utils


class Trace(internal._Trace, domain._DomainProvider):
    def __init__(self, name=None, native_byte_order=None, env=None,
                 packet_header_field_type=None, clock_classes=None,
                 stream_classes=None):

        ptr = native_bt.trace_create()

        if ptr is None:
            raise bt2.CreationError('cannot create trace class object')

        super().__init__(ptr)

        if name is not None:
            self.name = name

        if native_byte_order is not None:
            self.native_byte_order = native_byte_order

        if packet_header_field_type is not None:
            self.packet_header_field_type = packet_header_field_type

        if env is not None:
            for key, value in env.items():
                self.env[key] = value

        if clock_classes is not None:
            for clock_class in clock_classes:
                self.add_clock_class(clock_class)

        if stream_classes is not None:
            for stream_class in stream_classes:
                self.add_stream_class(stream_class)

    @property
    def is_static(self):
        is_static = native_bt.trace_is_static(self._ptr)
        return is_static > 0

    def set_is_static(self):
        ret = native_bt.trace_set_is_static(self._ptr)
        utils._handle_ret(ret, "cannot set trace object as static")


domain._Domain.Trace = Trace
