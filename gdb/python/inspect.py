# bt-inspect GBB command.
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Philippe Proulx <eepp.ca>
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

from btanalysis import info
import bt_gdb_export
import bt_gdb_vars
import subprocess
import bt_gdb_obj
import gdb
import sys


class _BtInspectCommand(gdb.Command):
    '''Inspect given Babeltrace object with bt-inspect

Convert the argument, an expression resolving to a Babeltrace object,
to a bt-analysis object, export this object and other contextual
information to a file, then launch the bt-inspect program on it.

The latest bt-inspect Python 3 package is needed for this command to
complete successfully.'''

    def __init__(self):
        super().__init__('bt-inspect', gdb.COMMAND_USER,
                         gdb.COMPLETE_EXPRESSION)

    def _launch_bt_inspect(self, filename):
        try:
            process = subprocess.Popen(['bt-inspect', filename], close_fds=False)
        except Exception as e:
            msg = 'Error: cannot execute bt-inspect with file "{}": {}'.format(filename, e)
            print(msg, file=sys.stderr)
            raise e

    def invoke(self, arg, from_tty):
        arg = arg.strip()
        gdb_obj = gdb.parse_and_eval(arg)
        addrs_infos = {}
        root_obj = bt_gdb_obj.model_obj_from_gdb_obj(gdb_obj, addrs_infos)
        backtrace = bt_gdb_vars.get_backtrace(addrs_infos)
        infos = info.Infos(root_obj, addrs_infos, backtrace)
        filename = bt_gdb_export.export_obj_to_file(infos)
        print('"{}" infos exported to "{}"'.format(arg, filename))
        self._launch_bt_inspect(filename)


_BtInspectCommand()
