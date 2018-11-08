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

__all__ = ['CtfWriter']

from bt2 import utils
import bt2
import bt2.native_bt as native_bt
from . import Clock


class CtfWriter(bt2.object._SharedObject):
    def __init__(self, path):
        utils._check_str(path)
        ptr = native_bt.ctf_writer_create(path)

        if ptr is None:
            raise bt2.CreationError('cannot create CTF writer object')

        super().__init__(ptr)

    @property
    def trace(self):
        trace_ptr = native_bt.ctf_writer_get_trace(self._ptr)
        assert(trace_ptr)
        return bt2.ctfwriter.Trace._create_from_ptr(trace_ptr)

    @property
    def metadata_string(self):
        metadata_string = native_bt.ctf_writer_get_metadata_string(self._ptr)
        assert(metadata_string is not None)
        return metadata_string

    def flush_metadata(self):
        native_bt.ctf_writer_flush_metadata(self._ptr)

    def add_clock(self, clock):
        utils._check_type(clock, bt2.ctfwriter.Clock)
        ret = native_bt.ctf_writer_add_clock(self._ptr, clock._ptr)
        utils._handle_ret(ret, 'cannot add CTF writer clock object to CTF writer object')
