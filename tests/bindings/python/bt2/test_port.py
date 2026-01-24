# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import pytest
from bt2 import port as bt2_port


def _create_comp(comp_cls, name=None):
    return bt2.Graph().add_component(comp_cls, name if name is not None else "comp")


def _assert_ports_match(ports, addrs):
    assert ports[0][0] == "clear"
    assert ports[1][0] == "print"
    assert ports[2][0] == "insert"
    assert ports[0][1].addr == addrs[0]
    assert ports[1][1].addr == addrs[1]
    assert ports[2][1].addr == addrs[2]


class TestAdd:
    def test_src_output_port(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                assert comp_self._add_output_port("out").name == "out"

        comp = _create_comp(_MySrc)
        assert len(comp.output_ports) == 1
        assert type(comp.output_ports["out"]) is bt2_port._OutputPortConst

    def test_src_output_port_dup_name_raises(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("out")

                with pytest.raises(
                    ValueError,
                    match=r"source component `comp` already contains an output port named `out`",
                ):
                    comp_self._add_output_port("out")

        called = False
        _create_comp(_MySrc)
        assert called

    def test_flt_output_port(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                assert comp_self._add_output_port("out").name == "out"

        comp = _create_comp(_MyFlt)
        assert len(comp.output_ports) == 1

    def test_flt_output_port_dup_name_raises(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("out")

                with pytest.raises(
                    ValueError,
                    match=r"filter component `comp` already contains an output port named `out`",
                ):
                    comp_self._add_output_port("out")

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_flt_input_port(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                assert comp_self._add_input_port("in").name == "in"

        comp = _create_comp(_MyFlt)
        assert len(comp.input_ports) == 1
        assert type(comp.input_ports["in"]) is bt2_port._InputPortConst

    def test_flt_input_port_dup_name_raises(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("in")

                with pytest.raises(
                    ValueError,
                    match=r"filter component `comp` already contains an input port named `in`",
                ):
                    comp_self._add_input_port("in")

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_sink_input_port(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                assert comp_self._add_input_port("in").name == "in"

            def _user_consume(self):
                pass

        comp = _create_comp(_MySink)
        assert len(comp.input_ports) == 1

    def test_sink_input_port_dup_name_raises(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("in")

                with pytest.raises(
                    ValueError,
                    match=r"sink component `comp` already contains an input port named `in`",
                ):
                    comp_self._add_input_port("in")

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called


class TestUser:
    def test_src_output_ports_getitem(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_output_port("clear")
                port2 = comp_self._add_output_port("print")
                port3 = comp_self._add_output_port("insert")
                assert port1.addr == comp_self._output_ports["clear"].addr
                assert port2.addr == comp_self._output_ports["print"].addr
                assert port3.addr == comp_self._output_ports["insert"].addr

        called = False
        _create_comp(_MySrc)
        assert called

    def test_flt_output_ports_getitem(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_output_port("clear")
                port2 = comp_self._add_output_port("print")
                port3 = comp_self._add_output_port("insert")
                assert port1.addr == comp_self._output_ports["clear"].addr
                assert port2.addr == comp_self._output_ports["print"].addr
                assert port3.addr == comp_self._output_ports["insert"].addr

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_flt_input_ports_getitem(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_input_port("clear")
                port2 = comp_self._add_input_port("print")
                port3 = comp_self._add_input_port("insert")
                assert port1.addr == comp_self._input_ports["clear"].addr
                assert port2.addr == comp_self._input_ports["print"].addr
                assert port3.addr == comp_self._input_ports["insert"].addr

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_sink_input_ports_getitem(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_input_port("clear")
                port2 = comp_self._add_input_port("print")
                port3 = comp_self._add_input_port("insert")
                assert port1.addr == comp_self._input_ports["clear"].addr
                assert port2.addr == comp_self._input_ports["print"].addr
                assert port3.addr == comp_self._input_ports["insert"].addr

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called

    def test_src_output_ports_getitem_invalid_key(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")

                with pytest.raises(KeyError):
                    comp_self._output_ports["hello"]

        called = False
        _create_comp(_MySrc)
        assert called

    def test_flt_output_ports_getitem_invalid_key(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")

                with pytest.raises(KeyError):
                    comp_self._output_ports["hello"]

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_flt_input_ports_getitem_invalid_key(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")

                with pytest.raises(KeyError):
                    comp_self._input_ports["hello"]

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_sink_input_ports_getitem_invalid_key(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")

                with pytest.raises(KeyError):
                    comp_self._input_ports["hello"]

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called

    def test_src_output_ports_len(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")
                assert len(comp_self._output_ports) == 3

        called = False
        _create_comp(_MySrc)
        assert called

    def test_flt_output_ports_len(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")
                assert len(comp_self._output_ports) == 3

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_flt_input_ports_len(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")
                assert len(comp_self._input_ports) == 3

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_sink_input_ports_len(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")
                assert len(comp_self._input_ports) == 3

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called

    def test_src_output_ports_iter(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_output_port("clear")
                port2 = comp_self._add_output_port("print")
                port3 = comp_self._add_output_port("insert")
                ports = list(comp_self._output_ports.items())
                _assert_ports_match(ports, [port1.addr, port2.addr, port3.addr])

        called = False
        _create_comp(_MySrc)
        assert called

    def test_flt_output_ports_iter(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_output_port("clear")
                port2 = comp_self._add_output_port("print")
                port3 = comp_self._add_output_port("insert")
                ports = list(comp_self._output_ports.items())
                _assert_ports_match(ports, [port1.addr, port2.addr, port3.addr])

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_flt_input_ports_iter(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_input_port("clear")
                port2 = comp_self._add_input_port("print")
                port3 = comp_self._add_input_port("insert")
                ports = list(comp_self._input_ports.items())
                _assert_ports_match(ports, [port1.addr, port2.addr, port3.addr])

        called = False
        _create_comp(_MyFlt)
        assert called

    def test_sink_input_ports_iter(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                port1 = comp_self._add_input_port("clear")
                port2 = comp_self._add_input_port("print")
                port3 = comp_self._add_input_port("insert")
                ports = list(comp_self._input_ports.items())
                _assert_ports_match(ports, [port1.addr, port2.addr, port3.addr])

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called


class TestGen:
    def test_src_output_ports_getitem(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_output_port("clear").addr)
                addrs.append(comp_self._add_output_port("print").addr)
                addrs.append(comp_self._add_output_port("insert").addr)

        addrs = []
        comp = _create_comp(_MySrc)
        assert addrs[0] == comp.output_ports["clear"].addr
        assert addrs[1] == comp.output_ports["print"].addr
        assert addrs[2] == comp.output_ports["insert"].addr

    def test_flt_output_ports_getitem(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_output_port("clear").addr)
                addrs.append(comp_self._add_output_port("print").addr)
                addrs.append(comp_self._add_output_port("insert").addr)

        addrs = []
        comp = _create_comp(_MyFlt)
        assert addrs[0] == comp.output_ports["clear"].addr
        assert addrs[1] == comp.output_ports["print"].addr
        assert addrs[2] == comp.output_ports["insert"].addr

    def test_flt_input_ports_getitem(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_input_port("clear").addr)
                addrs.append(comp_self._add_input_port("print").addr)
                addrs.append(comp_self._add_input_port("insert").addr)

        addrs = []
        comp = _create_comp(_MyFlt)
        assert addrs[0] == comp.input_ports["clear"].addr
        assert addrs[1] == comp.input_ports["print"].addr
        assert addrs[2] == comp.input_ports["insert"].addr

    def test_sink_input_ports_getitem(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_input_port("clear").addr)
                addrs.append(comp_self._add_input_port("print").addr)
                addrs.append(comp_self._add_input_port("insert").addr)

            def _user_consume(self):
                pass

        addrs = []
        comp = _create_comp(_MySink)
        assert addrs[0] == comp.input_ports["clear"].addr
        assert addrs[1] == comp.input_ports["print"].addr
        assert addrs[2] == comp.input_ports["insert"].addr

    def test_src_output_ports_getitem_invalid_key(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")

        called = False
        comp = _create_comp(_MySrc)
        assert called

        with pytest.raises(KeyError):
            comp.output_ports["hello"]

    def test_flt_output_ports_getitem_invalid_key(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")

        called = False
        comp = _create_comp(_MyFlt)
        assert called

        with pytest.raises(KeyError):
            comp.output_ports["hello"]

    def test_flt_input_ports_getitem_invalid_key(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")

        called = False
        comp = _create_comp(_MyFlt)
        assert called

        with pytest.raises(KeyError):
            comp.input_ports["hello"]

    def test_sink_input_ports_getitem_invalid_key(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")

                with pytest.raises(KeyError):
                    comp_self._input_ports["hello"]

            def _user_consume(self):
                pass

        called = False
        comp = _create_comp(_MySink)
        assert called

        with pytest.raises(KeyError):
            comp.input_ports["hello"]

    def test_src_output_ports_len(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")

        comp = _create_comp(_MySrc)
        assert len(comp.output_ports) == 3

    def test_flt_output_ports_len(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                comp_self._add_output_port("clear")
                comp_self._add_output_port("print")
                comp_self._add_output_port("insert")

        comp = _create_comp(_MyFlt)
        assert len(comp.output_ports) == 3

    def test_flt_input_ports_len(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")

        comp = _create_comp(_MyFlt)
        assert len(comp.input_ports) == 3

    def test_sink_input_ports_len(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                comp_self._add_input_port("clear")
                comp_self._add_input_port("print")
                comp_self._add_input_port("insert")

            def _user_consume(self):
                pass

        comp = _create_comp(_MySink)
        assert len(comp.input_ports) == 3

    def test_src_output_ports_iter(self):
        class _MySrc(
            bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_output_port("clear").addr)
                addrs.append(comp_self._add_output_port("print").addr)
                addrs.append(comp_self._add_output_port("insert").addr)

        addrs = []
        comp = _create_comp(_MySrc)
        _assert_ports_match(list(comp.output_ports.items()), addrs)

    def test_flt_output_ports_iter(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_output_port("clear").addr)
                addrs.append(comp_self._add_output_port("print").addr)
                addrs.append(comp_self._add_output_port("insert").addr)

        addrs = []
        comp = _create_comp(_MyFlt)
        _assert_ports_match(list(comp.output_ports.items()), addrs)

    def test_flt_input_ports_iter(self):
        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_input_port("clear").addr)
                addrs.append(comp_self._add_input_port("print").addr)
                addrs.append(comp_self._add_input_port("insert").addr)

        addrs = []
        comp = _create_comp(_MyFlt)
        _assert_ports_match(list(comp.input_ports.items()), addrs)

    def test_sink_input_ports_iter(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                addrs.append(comp_self._add_input_port("clear").addr)
                addrs.append(comp_self._add_input_port("print").addr)
                addrs.append(comp_self._add_input_port("insert").addr)

            def _user_consume(self):
                pass

        addrs = []
        comp = _create_comp(_MySink)
        _assert_ports_match(list(comp.input_ports.items()), addrs)


class TestProps:
    def test_name(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                comp_self._add_input_port("clear")

            def _user_consume(self):
                pass

        comp = _create_comp(_MySink)
        assert comp.input_ports["clear"].name == "clear"

    def test_conn_none(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                comp_self._add_input_port("clear")

            def _user_consume(self):
                pass

        comp = _create_comp(_MySink)
        assert comp.input_ports["clear"].connection is None

    def test_is_connected_false(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                comp_self._add_input_port("clear")

            def _user_consume(self):
                pass

        comp = _create_comp(_MySink)
        assert not comp.input_ports["clear"].is_connected

    def test_self_name(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                assert comp_self._add_input_port("clear").name == "clear"

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called

    def test_self_conn_none(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                assert comp_self._add_input_port("clear").connection is None

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called

    def test_self_is_connected_false(self):
        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                nonlocal called

                called = True
                assert not comp_self._add_input_port("clear").is_connected

            def _user_consume(self):
                pass

        called = False
        _create_comp(_MySink)
        assert called


class TestSelfPortUserData:
    def test_src(self):
        class _MyUserData:
            def __del__(self):
                nonlocal objects_deleted

                objects_deleted += 1

        class _MySrc(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                p = comp_self._add_output_port("port1")
                user_datas.append(p.user_data)
                p = comp_self._add_output_port("port2", 2)
                user_datas.append(p.user_data)
                p = comp_self._add_output_port("port3", _MyUserData())
                user_datas.append(p.user_data)

        objects_deleted = 0
        user_datas = []
        comp = _create_comp(_MySrc)
        assert len(user_datas) == 3
        assert user_datas[0] is None
        assert user_datas[1] == 2
        assert type(user_datas[2]) is _MyUserData

        # Verify that the user data gets freed
        assert objects_deleted == 0
        del user_datas
        del comp
        assert objects_deleted == 1

    def test_flt(self):
        class _MyUserData:
            def __del__(self):
                nonlocal objects_deleted

                objects_deleted += 1

        class _MyFlt(
            bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
        ):
            def __init__(comp_self, config, params, obj):
                p = comp_self._add_output_port("port1")
                user_datas.append(p.user_data)
                p = comp_self._add_output_port("port2", "user data string")
                user_datas.append(p.user_data)
                p = comp_self._add_output_port("port3", _MyUserData())
                user_datas.append(p.user_data)

                p = comp_self._add_input_port("port4")
                user_datas.append(p.user_data)
                p = comp_self._add_input_port("port5", user_data={"user data": "dict"})
                user_datas.append(p.user_data)
                p = comp_self._add_input_port("port6", _MyUserData())
                user_datas.append(p.user_data)

        objects_deleted = 0
        user_datas = []
        comp = _create_comp(_MyFlt)
        assert len(user_datas) == 6
        assert user_datas[0] is None
        assert user_datas[1] == "user data string"
        assert type(user_datas[2]) is _MyUserData
        assert user_datas[3] is None
        assert user_datas[4] == {"user data": "dict"}
        assert type(user_datas[5]) is _MyUserData

        # Verify that the user data gets freed
        assert objects_deleted == 0
        del user_datas
        del comp
        assert objects_deleted == 2

    def test_sink(self):
        class _MyUserData:
            def __del__(self):
                nonlocal objects_deleted

                objects_deleted += 1

        class _MySink(bt2._UserSinkComponent):
            def __init__(comp_self, config, params, obj):
                p = comp_self._add_input_port("port1")
                user_datas.append(p.user_data)
                p = comp_self._add_input_port("port2", _MyUserData())
                user_datas.append(p.user_data)

            def _user_consume(self):
                pass

        objects_deleted = 0
        user_datas = []
        comp = _create_comp(_MySink)
        assert len(user_datas) == 2
        assert user_datas[0] is None
        assert type(user_datas[1]) is _MyUserData

        # Verify that the user data gets freed
        assert objects_deleted == 0
        del user_datas
        del comp
        assert objects_deleted == 1
