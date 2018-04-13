# The MIT License (MIT)
#
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

__all__ = ['Clock']

from bt2 import object, utils, native_bt
import bt2
import uuid as uuidp


class Clock(object._SharedObject):
    def __init__(self, name, description=None, frequency=None, precision=None,
                 offset=None, is_absolute=None, uuid=None):
        utils._check_str(name)
        ptr = native_bt.ctf_clock_create(name)

        if ptr is None:
            raise bt2.CreationError('cannot create CTF writer clock object')

        super().__init__(ptr)

        if description is not None:
            self.description = description

        if frequency is not None:
            self.frequency = frequency

        if precision is not None:
            self.precision = precision

        if offset is not None:
            self.offset = offset

        if is_absolute is not None:
            self.is_absolute = is_absolute

        if uuid is not None:
            self.uuid = uuid

    @property
    def name(self):
        name = native_bt.ctf_clock_get_name(self._ptr)
        assert(name is not None)
        return name

    @property
    def description(self):
        description = native_bt.ctf_clock_get_description(self._ptr)
        return description

    @description.setter
    def description(self, description):
        utils._check_str(description)
        ret = native_bt.ctf_clock_set_description(self._ptr, description)
        utils._handle_ret(ret, "cannot set CTF writer clock object's description")

    @property
    def frequency(self):
        frequency = native_bt.ctf_clock_get_frequency(self._ptr)
        assert(frequency >= 1)
        return frequency

    @frequency.setter
    def frequency(self, frequency):
        utils._check_uint64(frequency)
        ret = native_bt.ctf_clock_set_frequency(self._ptr, frequency)
        utils._handle_ret(ret, "cannot set CTF writer clock object's frequency")

    @property
    def precision(self):
        precision = native_bt.ctf_clock_get_precision(self._ptr)
        assert(precision >= 0)
        return precision

    @precision.setter
    def precision(self, precision):
        utils._check_uint64(precision)
        ret = native_bt.ctf_clock_set_precision(self._ptr, precision)
        utils._handle_ret(ret, "cannot set CTF writer clock object's precision")

    @property
    def offset(self):
        ret, offset_s = native_bt.ctf_clock_get_offset_s(self._ptr)
        assert(ret == 0)
        ret, offset_cycles = native_bt.ctf_clock_get_offset(self._ptr)
        assert(ret == 0)
        return bt2.ClockClassOffset(offset_s, offset_cycles)

    @offset.setter
    def offset(self, offset):
        utils._check_type(offset, bt2.ClockClassOffset)
        ret = native_bt.ctf_clock_set_offset_s(self._ptr, offset.seconds)
        utils._handle_ret(ret, "cannot set CTF writer clock object's offset (seconds)")
        ret = native_bt.ctf_clock_set_offset(self._ptr, offset.cycles)
        utils._handle_ret(ret, "cannot set CTF writer clock object's offset (cycles)")

    @property
    def is_absolute(self):
        is_absolute = native_bt.ctf_clock_get_is_absolute(self._ptr)
        assert(is_absolute >= 0)
        return is_absolute > 0

    @is_absolute.setter
    def is_absolute(self, is_absolute):
        utils._check_bool(is_absolute)
        ret = native_bt.ctf_clock_set_is_absolute(self._ptr, int(is_absolute))
        utils._handle_ret(ret, "cannot set CTF writer clock object's absoluteness")

    @property
    def uuid(self):
        uuid_bytes = native_bt.ctf_clock_get_uuid(self._ptr)
        assert(uuid_bytes is not None)
        return uuidp.UUID(bytes=uuid_bytes)

    @uuid.setter
    def uuid(self, uuid):
        utils._check_type(uuid, uuidp.UUID)
        ret = native_bt.ctf_clock_set_uuid(self._ptr, uuid.bytes)
        utils._handle_ret(ret, "cannot set CTF writer clock object's UUID")

    def _time(self, time):
        utils._check_int64(time)
        ret = native_bt.ctf_clock_set_time(self._ptr, time)

    time = property(fset=_time)
