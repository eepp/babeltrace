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

__all__ = ['_Trace']

import collections.abc
import copy

from bt2 import utils
import bt2
from . import object, field_types, stream_class

class _StreamClassIterator(collections.abc.Iterator):
    def __init__(self, trace):
        self._trace = trace
        self._at = 0

    def __next__(self):
        if self._at == len(self._trace):
            raise StopIteration

        sc_ptr = self._trace._Domain.trace_get_stream_class_by_index(self._trace._ptr,
                                                           self._at)
        assert(sc_ptr)
        id = self._trace._Domain.stream_class_get_id(sc_ptr)
        self._trace._Domain.put(sc_ptr)
        assert(id >= 0)
        self._at += 1
        return id


class _TraceStreams(collections.abc.Sequence):
    def __init__(self, trace):
        self._trace = trace

    def __len__(self):
        count = self._trace._Domain.trace_get_stream_count(self._trace._ptr)
        assert(count >= 0)
        return count

    def __getitem__(self, index):
        utils._check_uint64(index)

        if index >= len(self):
            raise IndexError

        stream_ptr = self._trace._Domain.trace_get_stream_by_index(self._trace._ptr,
                                                         index)
        assert(stream_ptr)
        return self._trace._Domain.create_stream_from_ptr(stream_ptr)


class _TraceClockClassesIterator(collections.abc.Iterator):
    def __init__(self, trace_clock_classes):
        self._trace_clock_classes = trace_clock_classes
        self._at = 0

    def __next__(self):
        if self._at == len(self._trace_clock_classes):
            raise StopIteration

        trace = self._trace_clock_classes._trace
        trace_ptr = trace._ptr
        cc_ptr = trace._Domain.trace_get_clock_class_by_index(trace_ptr, self._at)
        assert(cc_ptr)
        name = trace._Domain.clock_class_get_name(cc_ptr)
        trace._Domain.put(cc_ptr)
        assert(name is not None)
        self._at += 1
        return name


class _TraceClockClasses(collections.abc.Mapping):
    def __init__(self, trace):
        self._trace = trace

    def __getitem__(self, key):
        utils._check_str(key)
        cc_ptr = self._trace._Domain.trace_get_clock_class_by_name(self._trace._ptr, key)

        if cc_ptr is None:
            raise KeyError(key)

        return self._trace._Domain.ClockClass._create_from_ptr(cc_ptr)

    def __len__(self):
        count = self._trace._Domain.trace_get_clock_class_count(self._trace._ptr)
        assert(count >= 0)
        return count

    def __iter__(self):
        return _TraceClockClassesIterator(self)


class _TraceEnvIterator(collections.abc.Iterator):
    def __init__(self, trace_env):
        self._trace_env = trace_env
        self._at = 0

    def __next__(self):
        if self._at == len(self._trace_env):
            raise StopIteration

        trace_ptr = self._trace_env._trace._ptr
        entry_name = self._trace_env._trace._Domain.trace_get_environment_field_name_by_index(trace_ptr,
                                                                         self._at)
        assert(entry_name is not None)
        self._at += 1
        return entry_name


class _TraceEnv(collections.abc.MutableMapping):
    def __init__(self, trace):
        self._trace = trace

    def __getitem__(self, key):
        utils._check_str(key)
        value_ptr = self._trace._Domain.trace_get_environment_field_value_by_name(self._trace._ptr,
                                                                        key)

        if value_ptr is None:
            raise KeyError(key)

        return bt2.values._create_from_ptr(value_ptr)

    def __setitem__(self, key, value):
        utils._check_str(key)
        value = bt2.create_value(value)
        ret = self._trace._Domain.trace_set_environment_field(self._trace._ptr,
                                                    key, value._ptr)
        utils._handle_ret(ret, "cannot set trace class object's environment entry")

    def __delitem__(self, key):
        raise NotImplementedError

    def __len__(self):
        count = self._trace._Domain.trace_get_environment_field_count(self._trace._ptr)
        assert(count >= 0)
        return count

    def __iter__(self):
        return _TraceEnvIterator(self)


class _Trace(object._SharedObject, collections.abc.Mapping):
    def __getitem__(self, key):
        utils._check_int64(key)
        sc_ptr = self._Domain.trace_get_stream_class_by_id(self._ptr, key)

        if sc_ptr is None:
            raise KeyError(key)

        return self._Domain.StreamClass._create_from_ptr(sc_ptr)

    def __len__(self):
        count = self._Domain.trace_get_stream_class_count(self._ptr)
        assert(count >= 0)
        return count

    def __iter__(self):
        return _StreamClassIterator(self)

    def add_stream_class(self, stream_class):
        utils._check_type(stream_class, self._Domain.StreamClass)
        ret = self._Domain.trace_add_stream_class(self._ptr, stream_class._ptr)
        utils._handle_ret(ret, "cannot add stream class object to trace class object")

    @property
    def name(self):
        return self._Domain.trace_get_name(self._ptr)

    @name.setter
    def name(self, name):
        utils._check_str(name)
        ret = self._Domain.trace_set_name(self._ptr, name)
        utils._handle_ret(ret, "cannot set trace class object's name")

    @property
    def native_byte_order(self):
        bo = self._Domain.trace_get_native_byte_order(self._ptr)
        assert(bo >= 0)
        return bo

    @native_byte_order.setter
    def native_byte_order(self, native_byte_order):
        utils._check_int(native_byte_order)
        ret = self._Domain.trace_set_native_byte_order(self._ptr, native_byte_order)
        utils._handle_ret(ret, "cannot set trace class object's native byte order")

    @property
    def env(self):
        return _TraceEnv(self)

    @property
    def clock_classes(self):
        return _TraceClockClasses(self)

    def add_clock_class(self, clock_class):
        utils._check_type(clock_class, self._Domain.ClockClass)
        ret = self._Domain.trace_add_clock_class(self._ptr, clock_class._ptr)
        utils._handle_ret(ret, "cannot add clock class object to trace class object")

    @property
    def streams(self):
        return _TraceStreams(self)

    @property
    def packet_header_field_type(self):
        ft_ptr = self._Domain.trace_get_packet_header_field_type(self._ptr)

        if ft_ptr is None:
            return

        return self._Domain.create_field_type_from_ptr(ft_ptr)

    @packet_header_field_type.setter
    def packet_header_field_type(self, packet_header_field_type):
        packet_header_field_type_ptr = None

        if packet_header_field_type is not None:
            utils._check_type(packet_header_field_type, field_types._FieldType)
            packet_header_field_type_ptr = packet_header_field_type._ptr

        ret = self._Domain.trace_set_packet_header_field_type(self._ptr,
                                                     packet_header_field_type_ptr)
        utils._handle_ret(ret, "cannot set trace class object's packet header field type")

    def __eq__(self, other):
        if type(other) is not type(self):
            # not comparing apples to apples
            return False

        if self.addr == other.addr:
            return True

        self_stream_classes = list(self.values())
        self_clock_classes = list(self.clock_classes.values())
        self_env = {key: val for key, val in self.env.items()}
        other_stream_classes = list(other.values())
        other_clock_classes = list(other.clock_classes.values())
        other_env = {key: val for key, val in other.env.items()}
        self_props = (
            self_stream_classes,
            self_clock_classes,
            self_env,
            self.name,
            self.native_byte_order,
            self.packet_header_field_type,
        )
        other_props = (
            other_stream_classes,
            other_clock_classes,
            other_env,
            other.name,
            other.native_byte_order,
            other.packet_header_field_type,
        )
        return self_props == other_props
