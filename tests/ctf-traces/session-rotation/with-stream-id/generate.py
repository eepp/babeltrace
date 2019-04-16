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
                         with_stream_instance_id=True)

    clock = w.Clock('the_clock', uuid=UUID('ffffffffffffffffffffffffffffffff'))
    writer.add_clock(clock)

    stream_class_1 = w.StreamClass('the_stream_class_1', id=1)
    stream_class_1.clock = clock
    event_class_1 = w.EventClass('the_event_class_1', id=1)
    stream_class_1.add_event_class(event_class_1)
    writer.trace.add_stream_class(stream_class_1)

    stream_class_2 = w.StreamClass('the_stream_class_2', id=2)
    stream_class_2.clock = clock
    event_class_2 = w.EventClass('the_event_class_2', id=2)
    stream_class_2.add_event_class(event_class_2)
    writer.trace.add_stream_class(stream_class_2)

    stream_1_11 = stream_class_1(id=11)
    stream_1_22 = stream_class_1(id=22)
    stream_2_11 = stream_class_2(id=11)

    return stream_1_11, stream_1_22, stream_2_11, clock, event_class_1, event_class_2


def write_trace_a():
    mkdir('a1')
    mkdir('a2')
    uuid = UUID('12345678123456781234567812345678')

    def write_trace_a1():
        s_1_11, s_1_22, s_2_11, c, ec_1, ec_2 = new_writer('a1', uuid)

        c.time = 10
        s_1_11.append_event(ec_1())
        c.time = 11
        s_1_22.append_event(ec_1())
        c.time = 20
        s_1_11.append_event(ec_1())
        c.time = 21
        s_1_22.append_event(ec_1())
        c.time = 30
        s_1_11.append_event(ec_1())
        c.time = 31
        s_1_22.append_event(ec_1())

        s_1_11.flush()
        s_1_22.flush()

    def write_trace_a2():
        s_1_11, s_1_22, s_2_11, c, ec_1, ec_2 = new_writer('a2', uuid)

        c.time = 15
        s_1_11.append_event(ec_1())
        c.time = 16
        s_2_11.append_event(ec_2())
        c.time = 25
        s_1_11.append_event(ec_1())
        c.time = 26
        s_2_11.append_event(ec_2())
        c.time = 35
        s_1_11.append_event(ec_1())
        c.time = 36
        s_2_11.append_event(ec_2())

        s_1_11.flush()
        s_2_11.flush()

    write_trace_a1()
    write_trace_a2()


def write_trace_b():
    mkdir('b')

    s_1_11, s_1_22, s_2_11, c, ec_1, ec_2 = new_writer('b', UUID('abcdabcdabcdabcdabcdabcdabcdabcd'))

    c.time = 60
    s_1_11.append_event(ec_1())
    c.time = 70
    s_1_11.append_event(ec_1())

    s_1_11.flush()


def write_trace_c():
    mkdir('c')

    s_1_11, s_1_22, s_2_11, c, ec_1, ec_2 = new_writer('c', None)

    c.time = 60
    s_1_11.append_event(ec_1())
    c.time = 70
    s_1_11.append_event(ec_1())

    s_1_11.flush()


write_trace_a()
write_trace_b()
write_trace_c()
