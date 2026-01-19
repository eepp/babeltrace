# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import utils
import pytest
from bt2 import field as bt2_field
from bt2 import stream as bt2_stream


def _create_pkt(with_pc):
    def create_tc_cc(comp_self):
        clk_cls = comp_self._create_clock_class(frequency=1000, name="my_cc")
        tc = comp_self._create_trace_class()
        return clk_cls, tc

    # Create clock and trace classes
    clk_cls, tc = utils.run_in_component_init(0, create_tc_cc)

    # Create packet context field class
    pc_fc = tc.create_structure_field_class(
        members=(
            ("something", tc.create_signed_integer_field_class(8)),
            (
                "something_else",
                tc.create_double_precision_real_field_class(),
            ),
            (
                "events_discarded",
                tc.create_unsigned_integer_field_class(64),
            ),
            ("packet_seq_num", tc.create_unsigned_integer_field_class(64)),
        )
    )

    # Create stream
    stream = tc().create_stream(
        tc.create_stream_class(
            default_clock_class=clk_cls,
            event_common_context_field_class=tc.create_structure_field_class(
                members=(
                    ("cpu_id", tc.create_signed_integer_field_class(8)),
                    ("stuff", tc.create_double_precision_real_field_class()),
                )
            ),
            packet_context_field_class=(pc_fc if with_pc else None),
            supports_packets=True,
        )
    )

    # Create packet from stream, and also provide stream and
    # packet context field class.
    return stream.create_packet(), stream, pc_fc


@pytest.fixture
def pkt_with_pc():
    return _create_pkt(True)


@pytest.fixture
def pkt_without_pc():
    return _create_pkt(False)


def test_attr_stream(pkt_with_pc):
    pkt, stream, _ = pkt_with_pc
    assert pkt.stream.addr == stream.addr
    assert type(pkt.stream) is bt2_stream._Stream


def test_const_attr_stream(const_pkt_beginning_msg):
    pkt = const_pkt_beginning_msg.packet
    assert type(pkt.stream) is bt2_stream._StreamConst


def test_pc_field(pkt_with_pc):
    pkt, stream, pc_fc = pkt_with_pc
    assert pkt.context_field.cls.addr == pc_fc.addr
    assert type(pkt.context_field) is bt2_field._StructureField


def test_const_pc_field(const_pkt_beginning_msg):
    pkt = const_pkt_beginning_msg.packet
    assert type(pkt.context_field) is bt2_field._StructureFieldConst


def test_no_pc_field(pkt_without_pc):
    pkt, _, _ = pkt_without_pc
    assert pkt.context_field is None
