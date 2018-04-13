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

__all__ = ['_EventClass']

import collections.abc
import copy

from bt2 import utils
import bt2

from . import object, event, field_types

class _EventClass(object._SharedObject):
    def __init__(self, name, id=None, log_level=None, emf_uri=None,
                 context_field_type=None, payload_field_type=None):
        utils._check_str(name)
        ptr = self._Domain.event_class_create(name)

        if ptr is None:
            raise bt2.CreationError('cannot create event class object')

        super().__init__(ptr)

        if id is not None:
            self.id = id

        if log_level is not None:
            self.log_level = log_level

        if emf_uri is not None:
            self.emf_uri = emf_uri

        if context_field_type is not None:
            self.context_field_type = context_field_type

        if payload_field_type is not None:
            self.payload_field_type = payload_field_type

    @property
    def stream_class(self):
        sc_ptr = self._Domain.event_class_get_stream_class(self._ptr)

        if sc_ptr is not None:
            return self._Domain.StreamClass._create_from_ptr(sc_ptr)

    @property
    def name(self):
        return self._Domain.event_class_get_name(self._ptr)

    @property
    def id(self):
        id = self._Domain.event_class_get_id(self._ptr)
        return id if id >= 0 else None

    @id.setter
    def id(self, id):
        utils._check_int64(id)
        ret = self._Domain.event_class_set_id(self._ptr, id)
        utils._handle_ret(ret, "cannot set event class object's ID")

    @property
    def log_level(self):
        log_level = self._Domain.event_class_get_log_level(self._ptr)
        return log_level if log_level >= 0 else None

    @log_level.setter
    def log_level(self, log_level):
        log_levels = (
            self._Domain.EventClassLogLevel.UNSPECIFIED,
            self._Domain.EventClassLogLevel.EMERGENCY,
            self._Domain.EventClassLogLevel.ALERT,
            self._Domain.EventClassLogLevel.CRITICAL,
            self._Domain.EventClassLogLevel.ERROR,
            self._Domain.EventClassLogLevel.WARNING,
            self._Domain.EventClassLogLevel.NOTICE,
            self._Domain.EventClassLogLevel.INFO,
            self._Domain.EventClassLogLevel.DEBUG_SYSTEM,
            self._Domain.EventClassLogLevel.DEBUG_PROGRAM,
            self._Domain.EventClassLogLevel.DEBUG_PROCESS,
            self._Domain.EventClassLogLevel.DEBUG_MODULE,
            self._Domain.EventClassLogLevel.DEBUG_UNIT,
            self._Domain.EventClassLogLevel.DEBUG_FUNCTION,
            self._Domain.EventClassLogLevel.DEBUG_LINE,
            self._Domain.EventClassLogLevel.DEBUG,
        )

        if log_level not in log_levels:
            raise ValueError("'{}' is not a valid log level".format(log_level))

        ret = self._Domain.event_class_set_log_level(self._ptr, log_level)
        utils._handle_ret(ret, "cannot set event class object's log level")

    @property
    def emf_uri(self):
        return self._Domain.event_class_get_emf_uri(self._ptr)

    @emf_uri.setter
    def emf_uri(self, emf_uri):
        utils._check_str(emf_uri)
        ret = self._Domain.event_class_set_emf_uri(self._ptr, emf_uri)
        utils._handle_ret(ret, "cannot set event class object's EMF URI")

    @property
    def context_field_type(self):
        ft_ptr = self._Domain.event_class_get_context_field_type(self._ptr)

        if ft_ptr is None:
            return

        return self._Domain.create_field_type_from_ptr(ft_ptr)

    @context_field_type.setter
    def context_field_type(self, context_field_type):
        context_field_type_ptr = None

        if context_field_type is not None:
            utils._check_type(context_field_type, field_types._FieldType)
            context_field_type_ptr = context_field_type._ptr

        ret = self._Domain.event_class_set_context_field_type(self._ptr, context_field_type_ptr)
        utils._handle_ret(ret, "cannot set event class object's context field type")

    @property
    def payload_field_type(self):
        ft_ptr = self._Domain.event_class_get_payload_field_type(self._ptr)

        if ft_ptr is None:
            return

        return self._Domain.create_field_type_from_ptr(ft_ptr)

    @payload_field_type.setter
    def payload_field_type(self, payload_field_type):
        payload_field_type_ptr = None

        if payload_field_type is not None:
            utils._check_type(payload_field_type, field_types._FieldType)
            payload_field_type_ptr = payload_field_type._ptr

        ret = self._Domain.event_class_set_payload_field_type(self._ptr, payload_field_type_ptr)
        utils._handle_ret(ret, "cannot set event class object's payload field type")
