# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
from bt2 import component as bt2_comp


def _create_comp(comp_cls, name=None, log_level=bt2.LoggingLevel.NONE):
    graph = bt2.Graph()

    if name is None:
        name = "comp"

    return graph.add_component(comp_cls, name, logging_level=log_level)


def test_user_comp_name():
    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            assert comp_self.name == "yaes"

        def _user_consume(self):
            pass

    _create_comp(MySink, "yaes")


def test_user_comp_log_level():
    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            assert comp_self.logging_level == bt2.LoggingLevel.INFO

        def _user_consume(self):
            pass

    _create_comp(MySink, "yaes", bt2.LoggingLevel.INFO)


def test_user_comp_graph_mip_version():
    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            assert comp_self._graph_mip_version == 0

        def _user_consume(self):
            pass

    _create_comp(MySink, "yaes", bt2.LoggingLevel.INFO)


def test_user_comp_cls():
    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            assert comp_self.cls == MySink

        def _user_consume(self):
            pass

    _create_comp(MySink)


def test_user_comp_addr():
    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            assert isinstance(comp_self.addr, int)
            assert comp_self.addr != 0

        def _user_consume(self):
            pass

    _create_comp(MySink)


def test_user_comp_finalize():
    finalized = False

    class MySink(bt2._UserSinkComponent):
        def _user_consume(self):
            pass

        def _user_finalize(comp_self):
            nonlocal finalized
            finalized = True

    graph = bt2.Graph()
    comp = graph.add_component(MySink, "lel")
    del graph
    del comp
    assert finalized


def test_src_comp_cfg():
    class MySrc(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        def __init__(comp_self, config, params, obj):
            assert type(config) is bt2_comp._UserSourceComponentConfiguration

    _create_comp(MySrc)


def test_flt_comp_cfg():
    class MyFlt(
        bt2._UserFilterComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        def __init__(comp_self, config, params, obj):
            assert type(config) is bt2_comp._UserFilterComponentConfiguration

    _create_comp(MyFlt)


def test_sink_comp_cfg():
    class MySink(bt2._UserSinkComponent):
        def __init__(comp_self, config, params, obj):
            assert type(config) is bt2_comp._UserSinkComponentConfiguration

        def _user_consume(self):
            pass

    _create_comp(MySink)


class _MySink(bt2._UserSinkComponent):
    def _user_consume(self):
        pass


def test_generic_comp_name():
    comp = _create_comp(_MySink, "yaes")
    assert comp.name == "yaes"


def test_generic_comp_logging_level():
    comp = _create_comp(_MySink, "yaes", bt2.LoggingLevel.WARNING)
    assert comp.logging_level == bt2.LoggingLevel.WARNING


def test_generic_comp_class():
    comp = _create_comp(_MySink)
    assert comp.cls == _MySink


def test_generic_comp_addr():
    comp = _create_comp(_MySink)
    assert isinstance(comp.addr, int)
    assert comp.addr != 0
