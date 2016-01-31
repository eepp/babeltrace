# Finds frames, blocks, and variables in the current context matching
# a given set of addresses.
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

from btanalysis import variables
import gdb


def _get_block_variables(frame, block, addrs_infos):
    vvars = []

    for symbol in block:
        if symbol.is_variable or symbol.is_argument:
            value = symbol.value(frame)
            type = value.type

            if type.code == gdb.TYPE_CODE_PTR:
                try:
                    addr = int(value)
                except:
                    continue

                if addr in addrs_infos:
                    vvars.append(variables.Variable(symbol.name, str(type),
                                                    addr))

    return vvars


def _get_frame_blocks(frame, addrs_infos):
    vblocks = []
    cur_block = frame.block()

    while cur_block is not None:
        if cur_block.is_static or cur_block.is_global:
            cur_block = cur_block.superblock
            continue

        if not cur_block.is_valid():
            break

        vvars = _get_block_variables(frame, cur_block, addrs_infos)

        if vvars:
            vblocks.append(variables.Block(vvars))

        cur_block = cur_block.superblock

    return vblocks


def get_backtrace(addrs_infos):
    vframes = []
    cur_frame = gdb.selected_frame()

    while cur_frame is not None:
        if not cur_frame.is_valid():
            break

        vblocks = _get_frame_blocks(cur_frame, addrs_infos)
        vframes.append(variables.Frame(cur_frame.name(), vblocks))
        cur_frame = cur_frame.older()

    return variables.Backtrace(vframes)
