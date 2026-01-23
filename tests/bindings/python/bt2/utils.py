# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2019 EfficiOS Inc.
#

import types
import typing

import bt2

_RetT = typing.TypeVar("_RetT")


# Run callable `func` in the context of the __init__() method of a component.
#
# The callable is passed the component being initialized.
#
# Returns the value returned by `func`.
def run_in_component_init(
    mip_version: int, func: typing.Callable[[bt2._UserSinkComponent], _RetT]
) -> _RetT:
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            nonlocal res_bound

            res_bound = func(self)

        def _user_consume(self):
            pass

    g = bt2.Graph(mip_version)
    res_bound = None
    g.add_component(MySink, "comp")

    # We deliberately use a different variable for returning the result
    # than the variable bound to the MySink.__init__() context and then
    # delete `res_bound .
    #
    # The MySink.__init__() context stays alive until the end of the
    # program, so if `res_bound` were to still point to our result, it
    # would contribute an unexpected reference to the reference count of
    # the result, from the point of view of the user of this function.
    # It would then affect destruction tests, for example, which want to
    # test what happens when the reference count of a Python object
    # reaches zero.
    res = res_bound
    del res_bound
    return res


# Create an empty trace class with default values.
def def_tc():
    def f(comp_self: bt2._UserSinkComponent):
        return comp_self._create_trace_class()

    return run_in_component_init(0, f)


# Creates and returns a pair of list, the first containing non-const
# messages and the other containing const messages.
def _get_all_msg_types(with_pkt=True):
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_output_port):
            nonlocal bound_msgs

            self._at = 0
            self._msgs = [
                self._create_stream_beginning_message(self_output_port.user_data.stream)
            ]

            if with_pkt:
                assert self_output_port.user_data.packet

                self._msgs.append(
                    self._create_packet_beginning_message(
                        self_output_port.user_data.packet
                    )
                )

            def_cs = 789

            if with_pkt:
                assert self_output_port.user_data.packet
                ev_parent = self_output_port.user_data.packet
            else:
                assert self_output_port.user_data.stream
                ev_parent = self_output_port.user_data.stream

            msg = self._create_event_message(
                self_output_port.user_data.event_class,
                ev_parent,
                def_cs,
            )

            msg.event.payload_field["giraffe"] = 1
            msg.event.specific_context_field["ant"] = -1
            msg.event.common_context_field["cpu_id"] = 1
            self._msgs.append(msg)

            if with_pkt:
                self._msgs.append(
                    self._create_packet_end_message(self_output_port.user_data.packet)
                )

            self._msgs.append(
                self._create_stream_end_message(self_output_port.user_data.stream)
            )

            bound_msgs = self._msgs

        def __next__(self):
            if self._at == len(self._msgs):
                raise bt2.Stop

            msg = self._msgs[self._at]
            self._at += 1
            return msg

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            tc = self._create_trace_class(
                user_attributes={"a-trace-class-attribute": 1}
            )

            sc = tc.create_stream_class(
                default_clock_class=self._create_clock_class(
                    frequency=1000, user_attributes={"a-clock-class-attribute": 1}
                ),
                event_common_context_field_class=tc.create_structure_field_class(
                    members=(("cpu_id", tc.create_signed_integer_field_class(8)),)
                ),
                packet_context_field_class=(
                    tc.create_structure_field_class(
                        members=(
                            ("something", tc.create_unsigned_integer_field_class(8)),
                        )
                    )
                    if with_pkt
                    else None
                ),
                supports_packets=with_pkt,
                user_attributes={"a-stream-class-attribute": 1},
            )

            trace = tc(
                environment={"patate": 12}, user_attributes={"a-trace-attribute": 1}
            )

            stream = trace.create_stream(sc, user_attributes={"a-stream-attribute": 1})

            if with_pkt:
                plt = stream.create_packet()
                plt.context_field["something"] = 154
            else:
                plt = None

            self._add_output_port(
                "out",
                types.SimpleNamespace(
                    tc=tc,
                    stream=stream,
                    event_class=sc.create_event_class(
                        name="garou",
                        specific_context_field_class=tc.create_structure_field_class(
                            members=(("ant", tc.create_signed_integer_field_class(16)),)
                        ),
                        payload_field_class=tc.create_structure_field_class(
                            members=(
                                ("giraffe", tc.create_signed_integer_field_class(32)),
                            )
                        ),
                        user_attributes={"an-event-class-attribute": 1},
                    ),
                    trace=trace,
                    packet=plt,
                ),
            )

    bound_msgs = None
    graph = bt2.Graph()
    msg_iter = TestOutputPortMessageIterator(
        graph, graph.add_component(MySrc, "my_source").output_ports["out"]
    )
    const_msgs = list(msg_iter)

    # Return dicts keyed by message type for easy lookup
    return {type(m): m for m in bound_msgs}, {type(m): m for m in const_msgs}


def stream_beginning_msg():
    return _get_all_msg_types()[0][bt2._StreamBeginningMessage]


def const_stream_beginning_msg():
    return _get_all_msg_types()[1][bt2._StreamBeginningMessageConst]


def stream_end_msg():
    return _get_all_msg_types()[0][bt2._StreamEndMessage]


def pkt_beginning_msg():
    return _get_all_msg_types(with_pkt=True)[0][bt2._PacketBeginningMessage]


def const_pkt_beginning_msg():
    return _get_all_msg_types(with_pkt=True)[1][bt2._PacketBeginningMessageConst]


def pkt_end_msg():
    return _get_all_msg_types(with_pkt=True)[0][bt2._PacketEndMessage]


def ev_msg():
    return _get_all_msg_types()[0][bt2._EventMessage]


def const_ev_msg():
    return _get_all_msg_types()[1][bt2._EventMessageConst]


# Proxy sink component class.
#
# This sink accepts a list of a single item as its
# initialization object.
#
# This sink creates a single input port `in`. When it consumes from this
# port, it puts the returned message in the initialization list as the
# first item.
class _TestProxySink(bt2._UserSinkComponent):
    def __init__(self, config, params, msg_list):
        assert msg_list is not None
        self._msg_list = msg_list
        self._add_input_port("in")

    def _user_graph_is_configured(self):
        self._msg_iter = self._create_message_iterator(self._input_ports["in"])

    def _user_consume(self):
        assert self._msg_list[0] is None
        self._msg_list[0] = next(self._msg_iter)


# This is a helper message iterator for tests.
#
# The constructor accepts a graph and an output port.
#
# Internally, it adds a proxy sink to the graph and connects the
# received output port to the input port of the proxy sink component.
# Its __next__() method then uses the proxy sink component to transfer
# the consumed message to its user.
#
# This message iterator cannot seek.
class TestOutputPortMessageIterator(typing.Iterator[bt2._MessageConst]):
    def __init__(self, graph, output_port):
        self._graph = graph
        self._msg_list = [None]

        graph.connect_ports(
            output_port,
            graph.add_component(
                _TestProxySink, "test-proxy-sink", obj=self._msg_list
            ).input_ports["in"],
        )

    # Needed for compatibility with Python 3.5 in which the typing.Iterator
    # protocol is not implemented in the standard library.
    def __iter__(self):
        return self

    def __next__(self):
        assert self._msg_list[0] is None
        self._graph.run_once()
        msg = self._msg_list[0]
        assert msg is not None
        self._msg_list[0] = None
        return msg


# Creates a const field of the given field class `fc`.
#
# The field is part of a dummy stream, itself part of a dummy trace
# created from the trace class `tc`.
def create_const_field(tc, fc, field_value_setter_func):
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            stream = tc().create_stream(
                tc.create_stream_class(
                    packet_context_field_class=tc.create_structure_field_class(
                        members=((field_name, fc),)
                    ),
                    supports_packets=True,
                )
            )

            pkt = stream.create_packet()
            field_value_setter_func(pkt.context_field[field_name])

            self._msgs = [
                self._create_stream_beginning_message(stream),
                self._create_packet_beginning_message(pkt),
            ]

        def __next__(self):
            if len(self._msgs) == 0:
                raise StopIteration

            return self._msgs.pop(0)

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out", params)

    field_name = "const field"
    graph = bt2.Graph()
    msg_iter = TestOutputPortMessageIterator(
        graph, graph.add_component(MySrc, "my_source", None).output_ports["out"]
    )

    # Ignore first message (stream beginning)
    _ = next(msg_iter)
    pkt_beginning_msg = next(msg_iter)
    return pkt_beginning_msg.packet.context_field[field_name]


# Creates and returns a const field class from the field class `fc`.
#
# This function creates a dummy graph with a source component that
# produces messages containing a field of class `fc`. By iterating the
# messages as a downstream component, the field class becomes const.
#
# `tc` is the trace class used to create the stream class and trace.
#
# `fc` is the field class to convert to a const field class.
#
# `field_value_setter_func` is a callable that receives the created
# field and sets its value. This is necessary because the field must
# have a value before being part of a message.
def create_const_fc(tc, fc, field_value_setter_func):
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            stream = tc().create_stream(
                tc.create_stream_class(
                    packet_context_field_class=tc.create_structure_field_class(
                        members=((field_name, fc),)
                    ),
                    supports_packets=True,
                )
            )

            pkt = stream.create_packet()
            field_value_setter_func(pkt.context_field[field_name])

            self._msgs = [
                self._create_stream_beginning_message(stream),
                self._create_packet_beginning_message(pkt),
            ]

        def __next__(self):
            if len(self._msgs) == 0:
                raise StopIteration

            return self._msgs.pop(0)

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out", params)

    field_name = "const field"
    graph = bt2.Graph()
    msg_iter = TestOutputPortMessageIterator(
        graph, graph.add_component(MySrc, "my_source", None).output_ports["out"]
    )

    # Ignore first message (stream beginning)
    _ = next(msg_iter)
    pkt_beginning_msg = next(msg_iter)
    return pkt_beginning_msg.packet.context_field[field_name].cls


# Runs `msg_iter_next_func` in
# bt2._UserMessageIterator.__next__() context.
#
# For convenience, this function creates a trace and a stream.
#
# To allow the caller to customize the created stream class, the
# `create_stream_class_func` callback is invoked during component
# initialization. It gets passed a trace class and a clock class, and
# must return a stream class.
#
# The `msg_iter_next_func` callback receives two arguments: the message
# iterator and the created stream.
#
# This function returns the value returned by `msg_iter_next_func`.
def run_in_message_iterator_next(create_stream_class_func, msg_iter_next_func):
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            tc, sc = port.user_data
            self._stream = tc().create_stream(sc)

        def __next__(self):
            nonlocal res_bound

            res_bound = msg_iter_next_func(self, self._stream)
            raise bt2.Stop

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            tc = self._create_trace_class()
            self._add_output_port(
                "out", (tc, create_stream_class_func(tc, self._create_clock_class()))
            )

    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._input_port = self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._input_iter = self._create_message_iterator(self._input_port)

        def _user_consume(self):
            next(self._input_iter)

    graph = bt2.Graph()
    res_bound = None
    graph.connect_ports(
        graph.add_component(MySrc, "ze source").output_ports["out"],
        graph.add_component(MySink, "ze sink").input_ports["in"],
    )
    graph.run()

    # We deliberately use a different variable for returning the result
    # than the variable bound to the MyIter.__next__() context. See the
    # big comment about that in run_in_component_init().
    res = res_bound
    del res_bound
    return res
