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

__all__ = ['FieldPath', 'Scope']

import collections
from bt2 import native_bt, utils, object

class Scope:
    PACKET_HEADER           = native_bt.SCOPE_PACKET_HEADER
    PACKET_CONTEXT          = native_bt.SCOPE_PACKET_CONTEXT
    EVENT_HEADER            = native_bt.SCOPE_EVENT_HEADER
    EVENT_COMMON_CONTEXT    = native_bt.SCOPE_EVENT_COMMON_CONTEXT
    EVENT_SPECIFIC_CONTEXT  = native_bt.SCOPE_EVENT_SPECIFIC_CONTEXT
    EVENT_PAYLOAD           = native_bt.SCOPE_EVENT_PAYLOAD


class FieldPath(object._SharedObject, collections.abc.Iterable):
    @property
    def root_scope(self):
        scope = native_bt.field_path_get_root_scope(self._ptr)
        return _SCOPE_TO_OBJ[scope]

    def __len__(self):
        return native_bt.field_path_get_index_count(self._ptr)

    def __iter__(self):
        for idx in range(len(self)):
            yield native_bt.field_path_get_index_by_index(self._ptr, idx)


_SCOPE_TO_OBJ = {
        native_bt.SCOPE_PACKET_HEADER: Scope.PACKET_HEADER,
        native_bt.SCOPE_PACKET_CONTEXT: Scope.PACKET_CONTEXT,
        native_bt.SCOPE_EVENT_HEADER: Scope.EVENT_HEADER,
        native_bt.SCOPE_EVENT_COMMON_CONTEXT: Scope.EVENT_COMMON_CONTEXT,
        native_bt.SCOPE_EVENT_SPECIFIC_CONTEXT: Scope.EVENT_SPECIFIC_CONTEXT,
        native_bt.SCOPE_EVENT_PAYLOAD: Scope.EVENT_PAYLOAD
}
