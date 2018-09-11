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

import collections.abc

from bt2 import utils, native_bt
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

        return bt2.clock_class.ClockClass._create_from_ptr(cc_ptr)

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
        value_ptr = native_bt.trace_borrow_environment_entry_value_by_name(self._trace._ptr,
                                                                        key)

        if value_ptr is None:
            raise KeyError(key)

        return bt2.values._create_from_ptr(value_ptr)

    def __setitem__(self, key, value):
        if isinstance(value, (str, int)) == False:
            abort();
        value = bt2.create_value(value)

        if isinstance(value, str):
            set_env_entry_fn = native_bt.trace_set_environment_entry_string
        elif isinstance(value, int):
            set_env_entry_fn = native_bt.trace_set_environment_entry_integer

        ret = set_env_entry_fn(self._trace._ptr, key, value._ptr)

        utils._handle_ret(ret, "cannot set trace class object's environment entry")

    def __delitem__(self, key):
        raise NotImplementedError

    def __len__(self):
        count = native_bt.trace_get_environment_entry_count(self._trace._ptr)
        assert(count >= 0)
        return count

    def __iter__(self):
        return _TraceEnvIterator(self)


class Trace(object._SharedObject, collections.abc.Mapping):
    def __init__(self, name=None, uuid=None, env=None,
                 packet_header_field_type=None, automatic_stream_class_id=None):

        ptr = native_bt.trace_create()

        if ptr is None:
            raise bt2.CreationError('cannot create trace class object')

        super().__init__(ptr)

        if name is not None:
            self.name = name

        if packet_header_field_type is not None:
            self.packet_header_field_type = packet_header_field_type

        if env is not None:
            for key, value in env.items():
                self.env[key] = value
        if automatic_stream_class_id is not None:
            self.automatic_stream_class_id = automatic_stream_class_id

    def __getitem__(self, key):
        utils._check_int64(key)
        sc_ptr = native_bt.trace_get_stream_class_by_id(self._ptr, key)

        if sc_ptr is None:
            raise KeyError(key)

        return bt2.stream_class._StreamClass._create_from_ptr(sc_ptr)

    def __len__(self):
        count = native_bt.trace_get_stream_class_count(self._ptr)
        assert(count >= 0)
        return count

    def __iter__(self):
        return _StreamClassIterator(self)

    def create_stream_class(self, id=None):
        if self.assign_automatic_stream_class_id:
            sc_ptr = native_bt.stream_class_create(self._ptr)
        else:
            if id is None:
                raise bt2.CreationError('cannot create stream class object')
            sc_ptr = native_bt.stream_class_create_with_id(self._ptr, id)

        return bt2.stream_class._StreamClass._create_from_ptr(sc_ptr)

    @property
    def name(self):
        return native_bt.trace_get_name(self._ptr)

    @name.setter
    def name(self, name):
        utils._check_str(name)
        ret = native_bt.trace_set_name(self._ptr, name)
        utils._handle_ret(ret, "cannot set trace class object's name")

    @property
    def uuid(self):
        return native_bt.trace_get_uuid(self._ptr)

    @uuid.setter
    def uuid(self, uuid):
        utils._check_str(name)
        ret = native_bt.trace_set_uuid(self._ptr, uuid)
        utils._handle_ret(ret, "cannot set trace class object's name")

    @property
    def env(self):
        return _TraceEnv(self)

    @property
    def assign_automatic_stream_class_id(self):
        return native_bt.trace_assigns_automatic_stream_class_id(self._ptr)

    @assign_automatic_stream_class_id.setter
    def assign_automatic_stream_class_id(self, automatic_ids):
        utils._check_bool(automatic_ids)
        return native_bt.trace_set_assigns_automatic_stream_class_id(self._ptr, automatic_ids)

    @property
    def streams(self):
        return _TraceStreams(self)

    @property
    def packet_header_field_type(self):
        ft_ptr = native_bt.trace_get_packet_header_field_type(self._ptr)

        if ft_ptr is None:
            return

        return native_bt.create_field_type_from_ptr(ft_ptr)

    @packet_header_field_type.setter
    def packet_header_field_type(self, packet_header_field_type):
        packet_header_field_type_ptr = None

        if packet_header_field_type is not None:
            utils._check_type(packet_header_field_type, field_types._FieldType)
            packet_header_field_type_ptr = packet_header_field_type._ptr

        ret = native_bt.trace_set_packet_header_field_type(self._ptr,
                                                     packet_header_field_type_ptr)
        utils._handle_ret(ret, "cannot set trace class object's packet header field type")

    @property
    def is_static(self):
        is_static = native_bt.trace_is_static(self._ptr)
        return is_static > 0

    def set_is_static(self):
        ret = native_bt.trace_set_is_static(self._ptr)
        utils._handle_ret(ret, "cannot set trace object as static")
