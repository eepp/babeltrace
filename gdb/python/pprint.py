from __future__ import print_function
from collections import namedtuple
from termcolor import colored
import bt_gdb_helpers_printing as btprint
import bt_gdb_helpers_objects as btobj
import traceback
import gdb


class _PrettyPrintCommand(gdb.Command):
    def __init__(self):
        super(_PrettyPrintCommand, self).__init__('bt-pprint',
                                                    gdb.COMMAND_USER,
                                                    gdb.COMPLETE_EXPRESSION)

    @staticmethod
    def _parse_arg(arg):
        opt_summary = False
        parts = arg.split('#')

        if len(parts) == 1:
            return arg.strip(), btprint._PrintingOptions(summary=opt_summary)

        if 's' in parts[1]:
            opt_summary = True

        return parts[0].strip(), btprint._PrintingOptions(summary=opt_summary)

    def invoke(self, arg, from_tty):
        try:
            obj_expr, options = self._parse_arg(arg)
            gdb_obj = gdb.parse_and_eval(obj_expr)
            ir_obj = btobj._ir_obj_from_gdb_obj(gdb_obj)
            printer = btprint._Printer()
            ir_obj.print_self(options, printer)
        except Exception as e:
            print(btprint._cerror(e))
            traceback.print_exc()


_PrettyPrintCommand()
