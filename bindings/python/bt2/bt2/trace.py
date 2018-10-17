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

import uuid as uuidp
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

        sc_ptr = native_bt.trace_borrow_stream_class_by_index(self._trace._ptr,
                                                           self._at)
        assert(sc_ptr)
        id = native_bt.stream_class_get_id(sc_ptr)
        assert(id >= 0)
        self._at += 1
        return id


class _TraceStreams(collections.abc.Sequence):
    def __init__(self, trace):
        self._trace = trace

    def __len__(self):
        count = native_bt.trace_get_stream_count(self._trace._ptr)
        assert(count >= 0)
        return count

    def __getitem__(self, index):
        utils._check_uint64(index)

        if index >= len(self):
            raise IndexError

        stream_ptr = native_bt.trace_borrow_stream_by_index(self._trace._ptr,
                                                         index)
        assert(stream_ptr)
        native_bt.get(stream_ptr)
        return bt2.stream._create_stream_from_ptr(stream_ptr)


class _TraceEnvIterator(collections.abc.Iterator):
    def __init__(self, trace_env):
        self._trace_env = trace_env
        self._at = 0

    def __next__(self):
        if self._at == len(self._trace_env):
            raise StopIteration

        trace_ptr = self._trace_env._trace._ptr
        entry_name, value = native_bt.trace_borrow_environment_entry_by_index(trace_ptr,
                                                                     self._at)
        assert(entry_name is not None)
        self._at += 1
        return entry_name


class _TraceEnv(collections.abc.MutableMapping):
    def __init__(self, trace):
        self._trace = trace

    def __getitem__(self, key):
        utils._check_str(key)

        for idx, entry in enumerate(self):
            if entry == key:
                entry_name, value_ptr = native_bt.trace_borrow_environment_entry_by_index(self._trace._ptr,
                                                                        idx)
                native_bt.get(value_ptr)
                return bt2.values._create_from_ptr(value_ptr)

        raise KeyError(key)

    def __setitem__(self, key, value):
        if isinstance(value, (str, int)) == False:
            abort();

        if isinstance(value, str):
            set_env_entry_fn = native_bt.trace_set_environment_entry_string
        elif isinstance(value, int):
            set_env_entry_fn = native_bt.trace_set_environment_entry_integer

        ret = set_env_entry_fn(self._trace._ptr, key, value)

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

        if uuid is not None:
            self.uuid = uuid

        if packet_header_field_type is not None:
            self.packet_header_field_type = packet_header_field_type

        if env is not None:
            for key, value in env.items():
                self.env[key] = value

        if automatic_stream_class_id is not None:
            self.assign_automatic_stream_class_id = automatic_stream_class_id

    def __getitem__(self, key):
        utils._check_int64(key)

        for idx, sc_id in enumerate(self):
            if sc_id == key:
                sc_ptr = native_bt.trace_borrow_stream_class_by_index(self._ptr, idx)
                native_bt.get(sc_ptr)
                return bt2.stream_class._StreamClass._create_from_ptr(sc_ptr)

        raise KeyError(key)


    def __len__(self):
        count = native_bt.trace_get_stream_class_count(self._ptr)
        assert(count >= 0)
        return count

    def __iter__(self):
        return _StreamClassIterator(self)

    def create_stream_class(self, id=None, event_header_ft=None, packet_context_ft=None,
                event_common_context_ft=None, default_clock_class=None, default_clock_always_known=None,
                packets_have_discarded_event_counter_snapshot=None, packets_have_packet_counter_snapshot=None,
                packets_have_default_beginning_clock_value=None, packets_have_default_end_clock_value=None,
                automatic_event_class_id=None, automatic_stream_id=None):

        if self.assign_automatic_stream_class_id:
            sc_ptr = native_bt.stream_class_create(self._ptr)
        else:
            if id is None:
                raise bt2.CreationError('cannot create stream class object')
            sc_ptr = native_bt.stream_class_create_with_id(self._ptr, id)

        sc = bt2.stream_class._StreamClass._create_from_ptr(sc_ptr)

        if event_header_ft is not None:
            sc.event_header_field_type = event_header_ft

        if packet_context_ft is not None:
            sc.packet_context_field_type = packet_context_ft

        if event_common_context_ft is not None:
            sc.event_common_context_field_type = event_common_context_ft

        if default_clock_class is not None:
            sc.default_clock_class = default_clock_class

        if default_clock_always_known is not None:
            # Ignored for now
            pass

        if packets_have_discarded_event_counter_snapshot is not None:
            sc.packets_have_discarded_event_counter_snapshot = packets_have_discarded_event_counter_snapshot

        if packets_have_packet_counter_snapshot is not None:
            sc.packets_have_packet_counter_snapshot = packets_have_packet_counter_snapshot

        if packets_have_default_beginning_clock_value is not None:
            sc.packets_have_default_beginning_clock_value = packets_have_default_beginning_clock_value

        if packets_have_default_end_clock_value is not None:
            sc.packets_have_default_end_clock_value = packets_have_default_end_clock_value

        if automatic_event_class_id is not None:
            sc.assigns_automatic_event_class_id = automatic_event_class_id

        if automatic_stream_id is not None:
            sc.assigns_automatic_stream_id = automatic_stream_id

        return sc 

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
        uuid_bytes = native_bt.trace_get_uuid(self._ptr)
        if uuid_bytes is None:
            return

        return uuidp.UUID(bytes=uuid_bytes)

    @uuid.setter
    def uuid(self, uuid):
        utils._check_type(uuid, uuidp.UUID)
        ret = native_bt.trace_set_uuid(self._ptr, uuid.bytes)
        utils._handle_ret(ret, "cannot set trace class object's uuid")

    @property
    def env(self):
        return _TraceEnv(self)

    @property
    def assign_automatic_stream_class_id(self):
        return native_bt.trace_assigns_automatic_stream_class_id(self._ptr)

    @assign_automatic_stream_class_id.setter
    def assign_automatic_stream_class_id(self, auto_id):
        utils._check_bool(auto_id)
        return native_bt.trace_set_assigns_automatic_stream_class_id(self._ptr, auto_id)

    @property
    def streams(self):
        return _TraceStreams(self)

    @property
    def packet_header_field_type(self):
        ft_ptr = native_bt.trace_borrow_packet_header_field_type(self._ptr)

        if ft_ptr is None:
            return
        native_bt.get(ft_ptr)

        return bt2.field_types._create_field_type_from_ptr(ft_ptr)

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

    def make_static(self):
        ret = native_bt.trace_make_static(self._ptr)
        utils._handle_ret(ret, "cannot set trace object as static")
