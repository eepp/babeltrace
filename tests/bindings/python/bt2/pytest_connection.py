# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import pytest
from bt2 import port as bt2_port
from bt2 import connection as bt2_conn


class _MySrc(bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator):
    def __init__(self, config, params, obj):
        self._add_output_port("out")


class _MySink(bt2._UserSinkComponent):
    def __init__(self, config, params, obj):
        self._add_input_port("in")

    def _user_consume(self):
        raise bt2.Stop


@pytest.fixture
def conn_env():
    graph = bt2.Graph()
    src_comp = graph.add_component(_MySrc, "src")
    sink_comp = graph.add_component(_MySink, "sink")
    conn = graph.connect_ports(
        src_comp.output_ports["out"], sink_comp.input_ports["in"]
    )
    return conn, src_comp, sink_comp


@pytest.fixture
def conn(conn_env):
    return conn_env[0]


@pytest.fixture
def src_comp(conn_env):
    return conn_env[1]


@pytest.fixture
def sink_comp(conn_env):
    return conn_env[2]


def test_create(conn):
    assert type(conn) is bt2_conn._ConnectionConst


def test_downstream_port(conn, sink_comp):
    assert conn.downstream_port.addr == sink_comp.input_ports["in"].addr
    assert type(conn) is bt2_conn._ConnectionConst
    assert type(conn.downstream_port) is bt2_port._InputPortConst


def test_upstream_port(conn, src_comp):
    assert conn.upstream_port.addr == src_comp.output_ports["out"].addr
    assert type(conn.upstream_port) is bt2_port._OutputPortConst
