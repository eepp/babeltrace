# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import sys

import bt2
import utils
import pytest
from bt2 import port as bt2_port
from bt2 import message_iterator as bt2_msg_iter


# Straightforward sink that creates one input port `in` and consumes
# from it.
class _SimpleSink(bt2._UserSinkComponent):
    def __init__(self, config, params, obj):
        self._add_input_port("in")

    def _user_consume(self):
        next(self._msg_iter)

    def _user_graph_is_configured(self):
        self._msg_iter = self._create_message_iterator(self._input_ports["in"])


def _create_graph(src_comp_cls, sink_comp_cls, flt_comp_cls=None):
    graph = bt2.Graph()
    src_comp = graph.add_component(src_comp_cls, "src")
    sink_comp = graph.add_component(sink_comp_cls, "sink")

    if flt_comp_cls is not None:
        flt_comp = graph.add_component(flt_comp_cls, "flt")
        graph.connect_ports(src_comp.output_ports["out"], flt_comp.input_ports["in"])
        graph.connect_ports(flt_comp.output_ports["out"], sink_comp.input_ports["in"])
    else:
        graph.connect_ports(src_comp.output_ports["out"], sink_comp.input_ports["in"])

    return graph


def test_init():
    the_output_port_from_src = None
    the_output_port_from_iter = None

    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            nonlocal initialized, the_output_port_from_iter

            initialized = True
            the_output_port_from_iter = self_port_output

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            nonlocal the_output_port_from_src

            the_output_port_from_src = self._add_output_port("out", "user data")

    initialized = False
    graph = _create_graph(MySrc, _SimpleSink)
    graph.run()
    assert initialized
    assert the_output_port_from_src.addr == the_output_port_from_iter.addr
    assert the_output_port_from_iter.user_data == "user data"


def test_create_from_msg_iter():
    class MySrcIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            nonlocal src_iter_initialized

            src_iter_initialized = True

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MySrcIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    class MyFltIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            nonlocal flt_iter_initialized

            flt_iter_initialized = True
            self._up_iter = self._create_message_iterator(
                self._component._input_ports["in"]
            )

        def __next__(self):
            return next(self._up_iter)

    class MyFlt(bt2._UserFilterComponent, message_iterator_class=MyFltIter):
        def __init__(self, config, params, obj):
            self._add_input_port("in")
            self._add_output_port("out")

    src_iter_initialized = False
    flt_iter_initialized = False
    graph = _create_graph(MySrc, _SimpleSink, MyFlt)
    graph.run()
    assert src_iter_initialized
    assert flt_iter_initialized


# Test that creating a message iterator from a sink component on a
# disconnected input port raises.
def test_create_from_sink_comp_unconnected_port_raises():
    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            comp_self._input_port = comp_self._add_input_port("in")

        def _user_graph_is_configured(comp_self):
            nonlocal called

            with pytest.raises(ValueError, match="input port is not connected"):
                comp_self._create_message_iterator(comp_self._input_port)

            called = True

        def _user_consume(self):
            raise bt2.Stop

    called = False
    graph = bt2.Graph()
    graph.add_component(MySink, "snk")
    graph.run()
    assert called


# Test that creating a message iterator from a message iterator on a
# disconnected input port raises.
def test_create_from_msg_iter_unconnected_port_raises():
    class MyFltIter(bt2._UserMessageIterator):
        def __init__(iter_self, config, port):
            nonlocal called

            called = True
            input_port = iter_self._component._input_ports["in"]

            with pytest.raises(ValueError, match="input port is not connected"):
                iter_self._create_message_iterator(input_port)

    class MyFlt(bt2._UserFilterComponent, message_iterator_class=MyFltIter):
        def __init__(comp_self, config, params, obj):
            comp_self._add_input_port("in")
            comp_self._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            comp_self._input_port = comp_self._add_input_port("in")

        def _user_graph_is_configured(comp_self):
            comp_self._input_iter = comp_self._create_message_iterator(
                comp_self._input_port
            )

        def _user_consume(self):
            raise bt2.Stop

    called = False
    graph = bt2.Graph()
    flt_comp = graph.add_component(MyFlt, "flt")
    snk_comp = graph.add_component(MySink, "snk")
    graph.connect_ports(flt_comp.output_ports["out"], snk_comp.input_ports["in"])
    graph.run()
    assert called


# This tests both error handling by
# _UserSinkComponent._create_message_iterator() and
# _UserMessageIterator._create_message_iterator(), as they are both used
# in the graph.
def test_create_user_error():
    class MySrcIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            raise ValueError("Very bad error")

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MySrcIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    class MyFltIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            # This is expected to raise because of the error in
            # MySrcIter.__init__().
            self._create_message_iterator(self._component._input_ports["in"])

    class MyFlt(bt2._UserFilterComponent, message_iterator_class=MyFltIter):
        def __init__(self, config, params, obj):
            self._add_input_port("in")
            self._add_output_port("out")

    graph = _create_graph(MySrc, _SimpleSink, MyFlt)

    with pytest.raises(bt2._Error) as ctx:
        graph.run()

    cause = ctx.value[0]
    assert isinstance(cause, bt2._MessageIteratorErrorCause)
    assert cause.component_name == "src"
    assert cause.component_output_port_name == "out"
    assert "ValueError: Very bad error" in cause.message


def test_finalize():
    class MyIter(bt2._UserMessageIterator):
        def _user_finalize(self):
            nonlocal finalized

            finalized = True

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    finalized = False
    graph = _create_graph(MySrc, _SimpleSink)
    graph.run()
    del graph
    assert finalized


def test_cfg_param():
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            nonlocal cfg_type

            cfg_type = type(config)

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    cfg_type = None
    graph = _create_graph(MySrc, _SimpleSink)
    graph.run()
    assert cfg_type is bt2_msg_iter._MessageIteratorConfiguration


@pytest.mark.parametrize("set_can_seek_forward", [False, True])
def test_cfg_can_seek_forward(set_can_seek_forward):
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            if set_can_seek_forward:
                config.can_seek_forward = True

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            nonlocal can_seek_forward

            can_seek_forward = self._msg_iter.can_seek_forward

    can_seek_forward = None
    graph = _create_graph(MySrc, MySink)
    graph.run_once()
    assert can_seek_forward is set_can_seek_forward


def test_cfg_can_seek_forward_wrong_type():
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            config.can_seek_forward = 1

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    graph = _create_graph(MySrc, _SimpleSink)

    with pytest.raises(bt2._Error) as ctx:
        graph.run()

    assert "TypeError: 'int' is not a 'bool' object" in ctx.value[0].message


def test_comp():
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            nonlocal called

            called = True
            assert self._component._salut == 23

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")
            self._salut = 23

    called = False
    graph = _create_graph(MySrc, _SimpleSink)
    graph.run()
    assert called


def test_port():
    class MyIter(bt2._UserMessageIterator):
        def __init__(self_iter, config, self_port_output):
            nonlocal called

            called = True
            port = self_iter._port
            assert type(self_port_output) is bt2_port._UserComponentOutputPort
            assert type(port) is bt2_port._UserComponentOutputPort
            assert self_port_output.addr == port.addr

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    called = False
    graph = _create_graph(MySrc, _SimpleSink)
    graph.run()
    assert called


def test_addr():
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            nonlocal called

            called = True
            assert self.addr is not None
            assert self.addr != 0

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    called = False
    graph = _create_graph(MySrc, _SimpleSink)
    graph.run()
    assert called


# Test that messages returned by _UserMessageIterator.__next__() remain
# valid and can be re-used.
def test_reuse_msg():
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            tc, sc, ec = port.user_data
            stream = tc().create_stream(sc)
            pkt = stream.create_packet()

            # This message will be returned twice by __next__()
            ev_msg = self._create_event_message(ec, pkt)

            self._msgs = [
                self._create_stream_beginning_message(stream),
                self._create_packet_beginning_message(pkt),
                ev_msg,
                ev_msg,
            ]

        def __next__(self):
            return self._msgs.pop(0)

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            tc = self._create_trace_class()
            sc = tc.create_stream_class(supports_packets=True)
            self._add_output_port("out", (tc, sc, sc.create_event_class()))

    graph = bt2.Graph()
    src_comp = graph.add_component(MySrc, "src")
    msg_iter = utils.TestOutputPortMessageIterator(graph, src_comp.output_ports["out"])

    # Skip beginning messages
    msg = next(msg_iter)
    assert type(msg) is bt2._StreamBeginningMessageConst
    msg = next(msg_iter)
    assert type(msg) is bt2._PacketBeginningMessageConst

    # Consume event messages
    msg_ev1 = next(msg_iter)
    msg_ev2 = next(msg_iter)
    assert type(msg_ev1) is bt2._EventMessageConst
    assert type(msg_ev2) is bt2._EventMessageConst
    assert msg_ev1.addr == msg_ev2.addr


# Try consuming many times from a message iterator that always raises `bt2.TryAgain`.
#
# This verifies that we are not missing a reference increment of `Py_None`, making the
# reference count of `Py_None` reach 0.
#
# Starting with Python 3.12, `None` is "immortal": its reference count
# operations are no-op. Skip this test in that case.
@pytest.mark.skipif(
    sys.version_info >= (3, 12), reason="`None` is immortal starting with Python 3.12"
)
def test_try_again_many_times():
    class MyIter(bt2._UserMessageIterator):
        def __next__(self):
            raise bt2.TryAgain

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    graph = bt2.Graph()
    it = utils.TestOutputPortMessageIterator(
        graph, graph.add_component(MySrc, "src").output_ports["out"]
    )

    # Three times the initial reference count of `None` iterations
    # should be enough to catch the bug even if there are small
    # differences between configurations.
    for _ in range(sys.getrefcount(None) * 3):
        with pytest.raises(bt2.TryAgain):
            next(it)


# Test a failure that triggered an abort in libbabeltrace2 in
# this situation:
#
# • The filter message iterator creates an upstream iterator.
#
# • The filter message iterator creates a reference cycle,
#   including itself.
#
# • An exception is raised, causing the initialization method of the
#   filter iterator to fail.
def test_error_in_iter_with_cycle_after_having_created_upstream_iter():
    class MySrcIter(bt2._UserMessageIterator):
        pass

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MySrcIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")

    class MyFltIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            # First, create an upstream message iterator
            self._upstream_iter = self._create_message_iterator(
                self._component._input_ports["in"]
            )

            # Then, voluntarily make a reference cycle that will keep
            # this Python object alive, which will keep the upstream
            # libbabeltrace2 message iterator object alive.
            self._self = self

            # Finally, raise an exception to make __init__() fail
            raise ValueError("woops")

    class MyFlt(bt2._UserFilterComponent, message_iterator_class=MyFltIter):
        def __init__(self, config, params, obj):
            self._in = self._add_input_port("in")
            self._out = self._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._input_port = self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._upstream_iter = self._create_message_iterator(self._input_port)

        def _user_consume(self):
            # We should not reach this!
            pytest.fail("Should not be reached")

    graph = bt2.Graph()
    src_comp = graph.add_component(MySrc, "src")
    flt_comp = graph.add_component(MyFlt, "flt")
    snk_comp = graph.add_component(MySink, "snk")
    graph.connect_ports(src_comp.output_ports["out"], flt_comp.input_ports["in"])
    graph.connect_ports(flt_comp.output_ports["out"], snk_comp.input_ports["in"])

    with pytest.raises(bt2._Error, match="ValueError: woops"):
        graph.run()


# Seek test setup helper.
def _setup_seek_test(
    sink_cls,
    user_seek_beginning=None,
    user_can_seek_beginning=None,
    user_seek_ns_from_origin=None,
    user_can_seek_ns_from_origin=None,
    can_seek_forward=False,
):
    class MySrcIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            tc, sc, ec = port.user_data
            stream = tc().create_stream(sc)
            pkt = stream.create_packet()

            self._msgs = [
                self._create_stream_beginning_message(stream),
                self._create_packet_beginning_message(pkt),
                self._create_event_message(ec, pkt),
                self._create_event_message(ec, pkt),
                self._create_packet_end_message(pkt),
                self._create_stream_end_message(stream),
            ]

            self._at = 0
            config.can_seek_forward = can_seek_forward

        def __next__(self):
            if self._at < len(self._msgs):
                msg = self._msgs[self._at]
                self._at += 1
                return msg
            else:
                raise StopIteration

    if user_seek_beginning is not None:
        MySrcIter._user_seek_beginning = user_seek_beginning

    if user_can_seek_beginning is not None:
        MySrcIter._user_can_seek_beginning = user_can_seek_beginning

    if user_seek_ns_from_origin is not None:
        MySrcIter._user_seek_ns_from_origin = user_seek_ns_from_origin

    if user_can_seek_ns_from_origin is not None:
        MySrcIter._user_can_seek_ns_from_origin = user_can_seek_ns_from_origin

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MySrcIter):
        def __init__(self, config, params, obj):
            tc = self._create_trace_class()
            sc = tc.create_stream_class(supports_packets=True)
            self._add_output_port("out", (tc, sc, sc.create_event_class()))

    class MyFltIter(bt2._UserMessageIterator):
        def __init__(self, config, port):
            self._upstream_iter = self._create_message_iterator(
                self._component._input_ports["in"]
            )

            config.can_seek_forward = self._upstream_iter.can_seek_forward

        def __next__(self):
            return next(self._upstream_iter)

        def _user_can_seek_beginning(self):
            return self._upstream_iter.can_seek_beginning()

        def _user_seek_beginning(self):
            self._upstream_iter.seek_beginning()

        def _user_can_seek_ns_from_origin(self, ns_from_origin):
            return self._upstream_iter.can_seek_ns_from_origin(ns_from_origin)

        def _user_seek_ns_from_origin(self, ns_from_origin):
            self._upstream_iter.seek_ns_from_origin(ns_from_origin)

    class MyFlt(bt2._UserFilterComponent, message_iterator_class=MyFltIter):
        def __init__(self, config, params, obj):
            self._add_input_port("in")
            self._add_output_port("out")

    return _create_graph(MySrc, sink_cls, flt_comp_cls=MyFlt)


def test_can_seek_beginning_without_seek_beginning():
    with pytest.raises(
        bt2._IncompleteUserClass,
        match="cannot create component class 'MySrc': message iterator class implements _user_can_seek_beginning but not _user_seek_beginning",
    ):
        _setup_seek_test(_SimpleSink, user_can_seek_beginning=lambda: None)


@pytest.mark.parametrize("expected_can_seek_beginning", [False, True])
def test_can_seek_beginning(expected_can_seek_beginning):
    # Sink component class consuming from the message iterator and
    # calling can_seek_beginning() on it.
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            nonlocal can_seek_beginning

            can_seek_beginning = self._msg_iter.can_seek_beginning()

    def _user_can_seek_beginning(self):
        return expected_can_seek_beginning

    graph = _setup_seek_test(
        MySink,
        user_can_seek_beginning=_user_can_seek_beginning,
        user_seek_beginning=lambda: None,
    )
    can_seek_beginning = None
    graph.run_once()
    assert can_seek_beginning is expected_can_seek_beginning


# Test a message iterator without a _user_can_seek_beginning() method,
# but with a _user_seek_beginning() method.
def test_no_can_seek_beginning_with_seek_beginning():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            nonlocal can_seek_beginning

            can_seek_beginning = self._msg_iter.can_seek_beginning()

    def _user_seek_beginning(self):
        pass

    graph = _setup_seek_test(MySink, user_seek_beginning=_user_seek_beginning)
    can_seek_beginning = None
    graph.run_once()
    assert can_seek_beginning is True


# Test a message iterator without a _user_can_seek_beginning() method
# and without a _user_seek_beginning() method.
def test_no_can_seek_beginning():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            nonlocal can_seek_beginning

            can_seek_beginning = self._msg_iter.can_seek_beginning()

    graph = _setup_seek_test(MySink)
    can_seek_beginning = None
    graph.run_once()
    assert can_seek_beginning is False


def test_can_seek_beginning_user_error():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            # This is expected to raise
            self._msg_iter.can_seek_beginning()

    def _user_can_seek_beginning(self):
        raise ValueError("moustiquaire")

    graph = _setup_seek_test(
        MySink,
        user_can_seek_beginning=_user_can_seek_beginning,
        user_seek_beginning=lambda: None,
    )

    with pytest.raises(bt2._Error) as ctx:
        graph.run_once()

    assert "ValueError: moustiquaire" in ctx.value[0].message


def test_can_seek_beginning_wrong_return_value():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            # This is expected to raise
            self._msg_iter.can_seek_beginning()

    def _user_can_seek_beginning(self):
        return "Amqui"

    graph = _setup_seek_test(
        MySink,
        user_can_seek_beginning=_user_can_seek_beginning,
        user_seek_beginning=lambda: None,
    )

    with pytest.raises(bt2._Error) as ctx:
        graph.run_once()

    cause = ctx.value[0]
    assert "TypeError: 'str' is not a 'bool' object" in cause.message


def test_seek_beginning():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            nonlocal msg

            if do_seek_beginning:
                self._msg_iter.seek_beginning()
                return

            msg = next(self._msg_iter)

    def _user_seek_beginning(self):
        self._at = 0

    msg = None
    graph = _setup_seek_test(MySink, user_seek_beginning=_user_seek_beginning)

    # Consume message
    do_seek_beginning = False
    graph.run_once()
    assert type(msg) is bt2._StreamBeginningMessageConst

    # Consume message
    graph.run_once()
    assert type(msg) is bt2._PacketBeginningMessageConst

    # Seek beginning
    do_seek_beginning = True
    graph.run_once()

    # Consume message
    do_seek_beginning = False
    graph.run_once()
    assert type(msg) is bt2._StreamBeginningMessageConst


def test_seek_beginning_user_error():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            self._msg_iter.seek_beginning()

    def _user_seek_beginning(self):
        raise ValueError("ouch")

    graph = _setup_seek_test(MySink, user_seek_beginning=_user_seek_beginning)

    with pytest.raises(bt2._Error):
        graph.run_once()


# Helper for test_can_seek_ns_from_origin_without_seek_ns_from_origin() and
# test_can_seek_ns_from_origin().
#
# expected_outcome:
#     Expected return value of can_seek_ns_from_origin().
#
# user_can_seek_ns_from_origin_ret_val:
#     Return value of the _user_can_seek_ns_from_origin() method, or `None`
#     if not provided.
#
# user_seek_ns_from_origin_provided:
#     True if the _user_seek_ns_from_origin() method is provided.
#
# iter_can_seek_beginning:
#     True if the message iterator can seek beginning.
#
# iter_can_seek_forward:
#     True if the message iterator is forward-seekable.
def _can_seek_ns_from_origin_test(
    expected_outcome,
    user_can_seek_ns_from_origin_ret_val,
    user_seek_ns_from_origin_provided,
    iter_can_seek_beginning,
    iter_can_seek_forward,
):
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            nonlocal can_seek_ns_from_origin

            can_seek_ns_from_origin = self._msg_iter.can_seek_ns_from_origin(
                passed_ns_from_origin
            )

    if user_can_seek_ns_from_origin_ret_val is not None:

        def user_can_seek_ns_from_origin(self, ns_from_origin):
            nonlocal received_ns_from_origin

            received_ns_from_origin = ns_from_origin
            return user_can_seek_ns_from_origin_ret_val

    else:
        user_can_seek_ns_from_origin = None

    if user_seek_ns_from_origin_provided:

        def user_seek_ns_from_origin(self, ns_from_origin):
            pass

    else:
        user_seek_ns_from_origin = None

    if iter_can_seek_beginning:

        def user_seek_beginning(self):
            pass

    else:
        user_seek_beginning = None

    graph = _setup_seek_test(
        MySink,
        user_can_seek_ns_from_origin=user_can_seek_ns_from_origin,
        user_seek_ns_from_origin=user_seek_ns_from_origin,
        user_seek_beginning=user_seek_beginning,
        can_seek_forward=iter_can_seek_forward,
    )

    passed_ns_from_origin = 77
    received_ns_from_origin = None
    can_seek_ns_from_origin = None
    graph.run_once()
    assert can_seek_ns_from_origin is expected_outcome

    if user_can_seek_ns_from_origin_ret_val is not None:
        assert received_ns_from_origin == passed_ns_from_origin


@pytest.mark.parametrize(
    ("iter_can_seek_beginning", "iter_can_seek_forward"),
    [
        pytest.param(False, False, id="cant-seek-beginning-not-forward-seekable"),
        pytest.param(False, True, id="cant-seek-beginning-forward-seekable"),
        pytest.param(True, False, id="can-seek-beginning-not-forward-seekable"),
        pytest.param(True, True, id="can-seek-beginning-forward-seekable"),
    ],
)
def test_can_seek_ns_from_origin_without_seek_ns_from_origin(
    iter_can_seek_beginning, iter_can_seek_forward
):
    with pytest.raises(
        bt2._IncompleteUserClass,
        match="cannot create component class 'MySrc': message iterator class implements _user_can_seek_ns_from_origin but not _user_seek_ns_from_origin",
    ):
        _can_seek_ns_from_origin_test(
            None,
            user_can_seek_ns_from_origin_ret_val=True,
            user_seek_ns_from_origin_provided=False,
            iter_can_seek_beginning=iter_can_seek_beginning,
            iter_can_seek_forward=iter_can_seek_forward,
        )


@pytest.mark.parametrize(
    [
        "expected_outcome",
        "user_can_seek_ns_from_origin_ret_val",
        "user_seek_ns_from_origin_provided",
        "iter_can_seek_beginning",
        "iter_can_seek_forward",
    ],
    [
        pytest.param(
            True,
            True,
            True,
            False,
            False,
            id="can-seek-ns-returns-true-seek-ns-provided-cant-seek-beg-not-fwd-seekable",
        ),
        pytest.param(
            True,
            True,
            True,
            False,
            True,
            id="can-seek-ns-returns-true-seek-ns-provided-cant-seek-beg-fwd-seekable",
        ),
        pytest.param(
            True,
            True,
            True,
            True,
            False,
            id="can-seek-ns-returns-true-seek-ns-provided-can-seek-beg-not-fwd-seekable",
        ),
        pytest.param(
            True,
            True,
            True,
            True,
            True,
            id="can-seek-ns-returns-true-seek-ns-provided-can-seek-beg-fwd-seekable",
        ),
        pytest.param(
            True,
            False,
            True,
            True,
            True,
            id="can-seek-ns-returns-false-seek-ns-provided-can-seek-beg-fwd-seekable",
        ),
        pytest.param(
            False,
            False,
            True,
            True,
            False,
            id="can-seek-ns-returns-false-seek-ns-provided-can-seek-beg-not-fwd-seekable",
        ),
        pytest.param(
            False,
            False,
            True,
            False,
            True,
            id="can-seek-ns-returns-false-seek-ns-provided-cant-seek-beg-fwd-seekable",
        ),
        pytest.param(
            False,
            False,
            True,
            False,
            False,
            id="can-seek-ns-returns-false-seek-ns-provided-cant-seek-beg-not-fwd-seekable",
        ),
        pytest.param(
            True,
            None,
            True,
            False,
            False,
            id="no-can-seek-ns-seek-ns-provided-cant-seek-beg-not-fwd-seekable",
        ),
        pytest.param(
            True,
            None,
            True,
            False,
            True,
            id="no-can-seek-ns-seek-ns-provided-cant-seek-beg-fwd-seekable",
        ),
        pytest.param(
            True,
            None,
            True,
            True,
            False,
            id="no-can-seek-ns-seek-ns-provided-can-seek-beg-not-fwd-seekable",
        ),
        pytest.param(
            True,
            None,
            True,
            True,
            True,
            id="no-can-seek-ns-seek-ns-provided-can-seek-beg-fwd-seekable",
        ),
        pytest.param(
            True,
            None,
            False,
            True,
            True,
            id="no-can-seek-ns-no-seek-ns-can-seek-beg-fwd-seekable",
        ),
        pytest.param(
            False,
            None,
            False,
            True,
            False,
            id="no-can-seek-ns-no-seek-ns-can-seek-beg-not-fwd-seekable",
        ),
        pytest.param(
            False,
            None,
            False,
            False,
            True,
            id="no-can-seek-ns-no-seek-ns-cant-seek-beg-fwd-seekable",
        ),
        pytest.param(
            False,
            None,
            False,
            False,
            False,
            id="no-can-seek-ns-no-seek-ns-cant-seek-beg-not-fwd-seekable",
        ),
    ],
)
def test_can_seek_ns_from_origin(
    expected_outcome,
    user_can_seek_ns_from_origin_ret_val,
    user_seek_ns_from_origin_provided,
    iter_can_seek_beginning,
    iter_can_seek_forward,
):
    _can_seek_ns_from_origin_test(
        expected_outcome=expected_outcome,
        user_can_seek_ns_from_origin_ret_val=user_can_seek_ns_from_origin_ret_val,
        user_seek_ns_from_origin_provided=user_seek_ns_from_origin_provided,
        iter_can_seek_beginning=iter_can_seek_beginning,
        iter_can_seek_forward=iter_can_seek_forward,
    )


def test_can_seek_ns_from_origin_user_error():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            # This is expected to raise
            self._msg_iter.can_seek_ns_from_origin(2)

    def _user_can_seek_ns_from_origin(self, ns_from_origin):
        raise ValueError("Joutel")

    graph = _setup_seek_test(
        MySink,
        user_can_seek_ns_from_origin=_user_can_seek_ns_from_origin,
        user_seek_ns_from_origin=lambda: None,
    )

    with pytest.raises(bt2._Error) as ctx:
        graph.run_once()

    assert "ValueError: Joutel" in ctx.value[0].message


def test_can_seek_ns_from_origin_wrong_return_value():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            # This is expected to raise
            self._msg_iter.can_seek_ns_from_origin(2)

    def _user_can_seek_ns_from_origin(self, ns_from_origin):
        return "Nitchequon"

    graph = _setup_seek_test(
        MySink,
        user_can_seek_ns_from_origin=_user_can_seek_ns_from_origin,
        user_seek_ns_from_origin=lambda: None,
    )

    with pytest.raises(bt2._Error) as ctx:
        graph.run_once()

    assert "TypeError: 'str' is not a 'bool' object" in ctx.value[0].message


def test_seek_ns_from_origin():
    class MySink(bt2._UserSinkComponent):
        def __init__(self, config, params, obj):
            self._add_input_port("in")

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

        def _user_consume(self):
            self._msg_iter.seek_ns_from_origin(17)

    def _user_seek_ns_from_origin(self, ns_from_origin):
        nonlocal actual_ns_from_origin

        actual_ns_from_origin = ns_from_origin

    graph = _setup_seek_test(MySink, user_seek_ns_from_origin=_user_seek_ns_from_origin)
    actual_ns_from_origin = None
    graph.run_once()
    assert actual_ns_from_origin == 17
