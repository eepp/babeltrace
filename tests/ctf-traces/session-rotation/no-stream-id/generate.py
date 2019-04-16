#!/usr/bin/python3

from bt2 import ctfwriter as w
import os
from uuid import UUID


def mkdir(p):
    try:
        os.mkdir(p)
    except FileExistsError:
        pass


def new_writer(path, uuid):
    writer = w.CtfWriter(path, auto_uuid=False, uuid=uuid,
                         with_stream_instance_id=False)

    clock = w.Clock('the_clock', uuid=UUID('ffffffffffffffffffffffffffffffff'))
    writer.add_clock(clock)

    stream_class = w.StreamClass('the_stream_class')
    stream_class.clock = clock

    event_class = w.EventClass('the_event_class')

    stream_class.add_event_class(event_class)
    writer.trace.add_stream_class(stream_class)

    stream_class = writer.trace[0]
    stream = stream_class(id=0)
    clock = stream_class.clock
    event_class = stream_class[0]
    return stream, clock, event_class


def write_trace_a():
    mkdir('a1')
    mkdir('a2')
    uuid = UUID('12345678123456781234567812345678')

    def write_trace_a1():
        s, c, ec = new_writer('a1', uuid)

        c.time = 10
        s.append_event(ec())
        c.time = 20
        s.append_event(ec())
        c.time = 30
        s.append_event(ec())
        s.flush()

    def write_trace_a2():
        s, c, ec = new_writer('a2', uuid)

        c.time = 15
        s.append_event(ec())
        c.time = 25
        s.append_event(ec())
        c.time = 35
        s.append_event(ec())
        s.flush()

    write_trace_a1()
    write_trace_a2()


def write_trace_b():
    mkdir('b')

    s, c, ec = new_writer('b', UUID('abcdabcdabcdabcdabcdabcdabcdabcd'))

    c.time = 60
    s.append_event(ec())
    c.time = 70
    s.append_event(ec())
    s.flush()


def write_trace_c():
    mkdir('c')

    s, c, ec = new_writer('c', None)

    c.time = 60
    s.append_event(ec())
    c.time = 70
    s.append_event(ec())
    s.flush()


write_trace_a()
write_trace_b()
write_trace_c()
