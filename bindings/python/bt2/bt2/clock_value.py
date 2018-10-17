# The MIT License (MIT)
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>
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

__all__ = []

import numbers
from bt2 import native_bt, utils
import bt2


class _ClockValue(bt2.object._UniqueObject):
    @property
    def clock_class(self):
        cc_ptr = native_bt.clock_value_borrow_clock_class(self._ptr)
        assert(cc_ptr)
        native_bt.get(cc_ptr)
        return bt2.ClockClass._create_from_ptr(cc_ptr)

    @property
    def cycles(self):
        cycles = native_bt.clock_value_get_value(self._ptr)
        return cycles

    @property
    def ns_from_origin(self):
        ret, ns = native_bt.clock_value_get_ns_from_origin(self._ptr)
        utils._handle_ret(ret, "cannot get clock value object's nanoseconds from origin")
        return ns

    def __eq__(self, other):
        if not isinstance(other, numbers.Integral):
            raise NotImplementedError
        return int(other) == self.cycles
