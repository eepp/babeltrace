# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import pytest


class _MyIter(bt2._UserMessageIterator):
    def __init__(self, config, self_output_port):
        self._build_meta()
        self._at = 0

    def _build_meta(self):
        self._tc = self._component._create_trace_class()
        self._t = self._tc()
        self._sc = self._tc.create_stream_class(supports_packets=True)
        self._ec = self._sc.create_event_class(name="salut")
        self._stream = self._t.create_stream(self._sc)
        self._pkt = self._stream.create_packet()


def test_create_def():
    bt2.Graph()


def test_create_known_mip_version():
    bt2.Graph(0)


def test_create_invalid_mip_version_type():
    with pytest.raises(TypeError):
        bt2.Graph("")


def test_create_unknown_mip_version():
    with pytest.raises(ValueError, match="unknown MIP version"):
        bt2.Graph(2)


def test_def_interrupter():
    assert type(bt2.Graph().default_interrupter) is bt2.Interrupter


def test_add_comp_user_cls():
    class MySink(bt2._UserSinkComponent):
        def _user_consume(self):
            pass

    assert bt2.Graph().add_component(MySink, "salut").name == "salut"


def test_add_comp_gen_cls():
    class MySink(bt2._UserSinkComponent):
        def _user_consume(self):
            pass

    graph = bt2.Graph()
    comp = graph.add_component(MySink, "salut")
    assert graph.add_component(comp.cls, "salut2").name == "salut2"


def test_add_comp_params():
    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            nonlocal called

            called = True
            assert params == test_params

        def _user_consume(self):
            pass

    test_params = {"hello": 23, "path": "/path/to/stuff"}
    called = False
    bt2.Graph().add_component(MySink, "salut", test_params)
    assert called


def test_add_comp_obj_python_comp_cls():
    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            nonlocal called

            called = True
            assert obj is the_obj

        def _user_consume(self):
            pass

    the_obj = object()
    called = False
    bt2.Graph().add_component(MySink, "salut", obj=the_obj)
    assert called


def test_add_comp_obj_none_python_comp_cls():
    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            nonlocal called

            called = True
            assert obj is None

        def _user_consume(self):
            pass

    called = False
    bt2.Graph().add_component(MySink, "salut")
    assert called


def test_add_comp_obj_non_python_comp_cls(dmesg_comp_cls):
    with pytest.raises(ValueError):
        bt2.Graph().add_component(dmesg_comp_cls, "salut", obj=57)


def test_add_comp_invalid_cls_type():
    with pytest.raises(TypeError):
        bt2.Graph().add_component(int, "salut")


def test_add_comp_invalid_logging_level_type():
    class MySink(bt2._UserSinkComponent):
        def _user_consume(self):
            pass

    with pytest.raises(TypeError):
        bt2.Graph().add_component(MySink, "salut", logging_level="yo")


def test_add_comp_invalid_params_type():
    class MySink(bt2._UserSinkComponent):
        def _user_consume(self):
            pass

    with pytest.raises(TypeError):
        bt2.Graph().add_component(MySink, "salut", params=12)


def test_add_comp_params_dict():
    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            nonlocal called

            called = True

            # Check equality and not identity because `add_component()`
            # method converts the Python `dict` to a `bt2.MapValue`.
            assert test_params == params

        def _user_consume(self):
            pass

    test_params = {"plage": 12312}
    called = False
    bt2.Graph().add_component(MySink, "salut", params=test_params)
    assert called


def test_add_comp_params_mapvalue():
    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            nonlocal called

            called = True
            assert test_params == params

        def _user_consume(self):
            pass

    test_params = bt2.MapValue({"beachclub": "121"})
    called = False
    bt2.Graph().add_component(MySink, "salut", params=test_params)
    assert called


def test_add_comp_logging_level():
    class MySink(bt2._UserSinkComponent):
        def _user_consume(self):
            pass

    comp = bt2.Graph().add_component(
        MySink, "salut", logging_level=bt2.LoggingLevel.DEBUG
    )
    assert comp.logging_level == bt2.LoggingLevel.DEBUG


def test_connect_ports():
    class MySrc(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self):
            raise bt2.Stop

    graph = bt2.Graph()
    src_comp = graph.add_component(MySrc, "src")
    sink_comp = graph.add_component(MySink, "sink")
    conn = graph.connect_ports(
        src_comp.output_ports["out"], sink_comp.input_ports["in"]
    )
    assert src_comp.output_ports["out"].is_connected
    assert sink_comp.input_ports["in"].is_connected
    assert src_comp.output_ports["out"].connection.addr == conn.addr
    assert sink_comp.input_ports["in"].connection.addr == conn.addr


def test_connect_ports_invalid_direction():
    class MySrc(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self):
            raise bt2.Stop

    graph = bt2.Graph()
    src_comp = graph.add_component(MySrc, "src")
    sink_comp = graph.add_component(MySink, "sink")

    with pytest.raises(TypeError):
        graph.connect_ports(sink_comp.input_ports["in"], src_comp.output_ports["out"])


def test_add_interrupter():
    class MyIter(bt2._UserMessageIterator):
        def __next__(self):
            raise TypeError

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self):
            next(self._msg_iter)

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

    # Add two interrupters, set one of them
    graph = bt2.Graph()
    interrupter = bt2.Interrupter()
    graph.add_interrupter(bt2.Interrupter())
    graph.connect_ports(
        graph.add_component(MySrc, "src").output_ports["out"],
        graph.add_component(MySink, "sink").input_ports["in"],
    )
    graph.add_interrupter(interrupter)

    with pytest.raises(bt2._Error):
        graph.run()

    interrupter.set()

    with pytest.raises(bt2.TryAgain):
        graph.run()

    interrupter.reset()

    with pytest.raises(bt2._Error):
        graph.run()


# Test that bt2.Graph.run() raises `bt2.Interrupted` if the graph gets
# interrupted during execution.
def test_interrupt_while_running():
    class MyIterLocal(_MyIter):
        def __next__(self):
            return self._create_stream_beginning_message(self._stream)

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIterLocal):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self):
            # Pretend that somebody asynchronously interrupted the graph.
            graph.default_interrupter.set()
            return next(self._msg_iter)

        def _user_graph_is_configured(self):
            self._msg_iter = self._create_message_iterator(self._input_ports["in"])

    graph = bt2.Graph()
    graph.connect_ports(
        graph.add_component(MySrc, "down").output_ports["out"],
        graph.add_component(MySink, "up").input_ports["in"],
    )

    with pytest.raises(bt2.TryAgain):
        graph.run()


def test_run():
    class MyIterLocal(_MyIter):
        def __next__(self):
            if self._at == 9:
                raise StopIteration

            if self._at == 0:
                msg = self._create_stream_beginning_message(self._stream)
            elif self._at == 1:
                msg = self._create_packet_beginning_message(self._pkt)
            elif self._at == 7:
                msg = self._create_packet_end_message(self._pkt)
            elif self._at == 8:
                msg = self._create_stream_end_message(self._stream)
            else:
                msg = self._create_event_message(self._ec, self._pkt)

            self._at += 1
            return msg

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIterLocal):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._input_port = self_comp._add_input_port("in")
            self_comp._at = 0

        def _user_consume(self_comp):
            nonlocal consumed_msg_count

            msg = next(self_comp._msg_iter)

            if self_comp._at == 0:
                assert type(msg) is bt2._StreamBeginningMessageConst
            elif self_comp._at == 1:
                assert type(msg) is bt2._PacketBeginningMessageConst
            elif 2 <= self_comp._at <= 6:
                assert type(msg) is bt2._EventMessageConst
                assert msg.event.cls.name == "salut"
            elif self_comp._at == 7:
                assert type(msg) is bt2._PacketEndMessageConst
            elif self_comp._at == 8:
                assert type(msg) is bt2._StreamEndMessageConst

            self_comp._at += 1
            consumed_msg_count += 1

        def _user_graph_is_configured(self_comp):
            self_comp._msg_iter = self_comp._create_message_iterator(
                self_comp._input_port
            )

    consumed_msg_count = 0
    graph = bt2.Graph()
    graph.connect_ports(
        graph.add_component(MySrc, "src").output_ports["out"],
        graph.add_component(MySink, "sink").input_ports["in"],
    )
    graph.run()
    assert consumed_msg_count == 9


def test_run_once():
    class MySrc(bt2._UserSourceComponent, message_iterator_class=_MyIter):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self_comp):
            raise bt2.TryAgain

    graph = bt2.Graph()
    graph.connect_ports(
        graph.add_component(MySrc, "src").output_ports["out"],
        graph.add_component(MySink, "sink").input_ports["in"],
    )

    with pytest.raises(bt2.TryAgain):
        graph.run_once()


def test_run_once_stops():
    class MySrc(bt2._UserSourceComponent, message_iterator_class=_MyIter):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self_comp):
            raise bt2.Stop

    graph = bt2.Graph()
    graph.connect_ports(
        graph.add_component(MySrc, "src").output_ports["out"],
        graph.add_component(MySink, "sink").input_ports["in"],
    )

    with pytest.raises(bt2.Stop):
        graph.run_once()


def test_run_again():
    class MyIterLocal(_MyIter):
        def __next__(self):
            if self._at == 3:
                raise bt2.TryAgain

            if self._at == 0:
                msg = self._create_stream_beginning_message(self._stream)
            elif self._at == 1:
                msg = self._create_packet_beginning_message(self._pkt)
            elif self._at == 2:
                msg = self._create_event_message(self._ec, self._pkt)

            self._at += 1
            return msg

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIterLocal):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._input_port = self_comp._add_input_port("in")
            self_comp._at = 0

        def _user_consume(self_comp):
            msg = next(self_comp._msg_iter)
            if self_comp._at == 0:
                assert type(msg) is bt2._StreamBeginningMessageConst
            elif self_comp._at == 1:
                assert type(msg) is bt2._PacketBeginningMessageConst
            elif self_comp._at == 2:
                assert type(msg) is bt2._EventMessageConst
                raise bt2.TryAgain

            self_comp._at += 1

        def _user_graph_is_configured(self_comp):
            self_comp._msg_iter = self_comp._create_message_iterator(
                self_comp._input_port
            )

    graph = bt2.Graph()
    graph.connect_ports(
        graph.add_component(MySrc, "src").output_ports["out"],
        graph.add_component(MySink, "sink").input_ports["in"],
    )

    with pytest.raises(bt2.TryAgain):
        graph.run()


def test_run_error():
    raised_in_sink = False

    class MyIterLocal(_MyIter):
        def __next__(self):
            # If this gets called after the sink component raised an
            # exception, it is an error.
            assert raised_in_sink is False

            if self._at == 0:
                msg = self._create_stream_beginning_message(self._stream)
            elif self._at == 1:
                msg = self._create_packet_beginning_message(self._pkt)
            elif self._at in (2, 3):
                msg = self._create_event_message(self._ec, self._pkt)
            else:
                raise bt2.TryAgain

            self._at += 1
            return msg

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIterLocal):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._input_port = self_comp._add_input_port("in")
            self_comp._at = 0

        def _user_consume(self_comp):
            msg = next(self_comp._msg_iter)
            if self_comp._at == 0:
                assert type(msg) is bt2._StreamBeginningMessageConst
            elif self_comp._at == 1:
                assert type(msg) is bt2._PacketBeginningMessageConst
            elif self_comp._at == 2:
                assert type(msg) is bt2._EventMessageConst
            elif self_comp._at == 3:
                nonlocal raised_in_sink
                raised_in_sink = True
                raise RuntimeError("error!")

            self_comp._at += 1

        def _user_graph_is_configured(self_comp):
            self_comp._msg_iter = self_comp._create_message_iterator(
                self_comp._input_port
            )

    graph = bt2.Graph()
    graph.connect_ports(
        graph.add_component(MySrc, "src").output_ports["out"],
        graph.add_component(MySink, "sink").input_ports["in"],
    )

    with pytest.raises(bt2._Error):
        graph.run()


def test_listeners():
    class MySrc(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        def __init__(self_comp, config, params, obj):
            self_comp._add_output_port("out")
            self_comp._add_output_port("zero")

    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self):
            raise bt2.Stop

        def _user_port_connected(self_comp, port, other_port):
            self_comp._add_input_port("taste")

    def port_added_listener(comp, port):
        calls.append((port_added_listener, comp, port))

    calls = []
    graph = bt2.Graph()
    graph.add_port_added_listener(port_added_listener)
    graph.connect_ports(
        graph.add_component(MySrc, "src").output_ports["out"],
        graph.add_component(MySink, "sink").input_ports["in"],
    )
    assert len(calls) == 4
    assert calls[0][0] is port_added_listener
    assert calls[0][1].name == "src"
    assert calls[0][2].name == "out"
    assert calls[1][0] is port_added_listener
    assert calls[1][1].name == "src"
    assert calls[1][2].name == "zero"
    assert calls[2][0] is port_added_listener
    assert calls[2][1].name == "sink"
    assert calls[2][2].name == "in"
    assert calls[3][0] is port_added_listener
    assert calls[3][1].name == "sink"
    assert calls[3][2].name == "taste"


def test_invalid_listeners():
    with pytest.raises(TypeError):
        bt2.Graph().add_port_added_listener(1234)


def test_raise_in_comp_init():
    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            raise ValueError("oops!")

        def _user_consume(self):
            raise bt2.Stop

    with pytest.raises(bt2._Error):
        bt2.Graph().add_component(MySink, "comp")


def test_raise_in_port_added_listener():
    class MySink(bt2._UserSinkComponent):
        def __init__(self_comp, config, params, obj):
            self_comp._add_input_port("in")

        def _user_consume(self):
            raise bt2.Stop

    def port_added_listener(comp, port):
        raise ValueError("oh noes!")

    graph = bt2.Graph()
    graph.add_port_added_listener(port_added_listener)

    with pytest.raises(bt2._Error):
        graph.add_component(MySink, "comp")
