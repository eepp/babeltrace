# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import types

import bt2
import utils
import pytest
from bt2 import field as bt2_field
from bt2 import stream as bt2_stream
from bt2 import event_class as bt2_ec
from bt2 import clock_snapshot as bt2_cs


# Creates a test event message with configurable fields.
#
# Returns a `types.SimpleNamespace` object with `msg`, `stream`, `pkt`,
# and `ec` attributes.
def _const_ev_msg(
    *,
    pkt_fc_cfg=None,
    ec_fc_cfg=None,
    with_clk_cls=False,
    with_common_ctx=False,
    with_spec_ctx=False,
    with_payload=False,
    with_pkt=False,
):
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_output_port):
            self._at = 0
            self._msgs = [self._create_stream_beginning_message(test_data.stream)]

            if with_pkt:
                assert test_data.pkt
                self._msgs.append(self._create_packet_beginning_message(test_data.pkt))

            def_cs = 789 if with_clk_cls else None

            if with_pkt:
                assert test_data.pkt is not None
                ev_parent = test_data.pkt
            else:
                assert test_data.stream is not None
                ev_parent = test_data.stream

            msg = self._create_event_message(test_data.ec, ev_parent, def_cs)

            if ec_fc_cfg is not None:
                ec_fc_cfg(msg.event)

            self._msgs.append(msg)

            if with_pkt:
                self._msgs.append(self._create_packet_end_message(test_data.pkt))

            self._msgs.append(self._create_stream_end_message(test_data.stream))

        def __next__(self):
            if self._at == len(self._msgs):
                raise bt2.Stop

            msg = self._msgs[self._at]
            self._at += 1
            return msg

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out")
            tc = self._create_trace_class()
            sc = tc.create_stream_class(
                default_clock_class=(
                    self._create_clock_class(frequency=1000) if with_clk_cls else None
                ),
                event_common_context_field_class=(
                    tc.create_structure_field_class(
                        members=(
                            ("cpu_id", tc.create_signed_integer_field_class(8)),
                            (
                                "stuff",
                                tc.create_double_precision_real_field_class(),
                            ),
                            ("gnu", tc.create_string_field_class()),
                        )
                    )
                    if with_common_ctx
                    else None
                ),
                packet_context_field_class=(
                    tc.create_structure_field_class(
                        members=(
                            (
                                "something",
                                tc.create_unsigned_integer_field_class(8),
                            ),
                            (
                                "something_else",
                                tc.create_double_precision_real_field_class(),
                            ),
                        )
                    )
                    if with_pkt
                    else None
                ),
                supports_packets=with_pkt,
            )
            stream = tc().create_stream(sc)

            if with_pkt:
                pkt = stream.create_packet()
            else:
                pkt = None

            if pkt_fc_cfg is not None:
                assert pkt is not None
                pkt_fc_cfg(pkt)

            test_data.pkt = pkt
            test_data.stream = stream
            test_data.ec = sc.create_event_class(
                name="garou",
                specific_context_field_class=(
                    tc.create_structure_field_class(
                        members=(
                            ("ant", tc.create_signed_integer_field_class(16)),
                            ("msg", tc.create_string_field_class()),
                        )
                    )
                    if with_spec_ctx
                    else None
                ),
                payload_field_class=(
                    tc.create_structure_field_class(
                        members=(
                            ("giraffe", tc.create_signed_integer_field_class(32)),
                            ("gnu", tc.create_signed_integer_field_class(8)),
                            ("mosquito", tc.create_signed_integer_field_class(8)),
                        )
                    )
                    if with_payload
                    else None
                ),
            )

    test_data = types.SimpleNamespace(msg=None, stream=None, pkt=None, ec=None)
    graph = bt2.Graph()
    msg_iter = utils.TestOutputPortMessageIterator(
        graph, graph.add_component(MySrc, "my_source").output_ports["out"]
    )

    for msg in msg_iter:
        if type(msg) is bt2._EventMessageConst:
            test_data.msg = msg
            return test_data

    raise RuntimeError("No event message found")


def _ec_payload_fc_cfg(event):
    event.payload_field["giraffe"] = 1
    event.payload_field["gnu"] = 23
    event.payload_field["mosquito"] = 42


def _ec_fc_cfg(event):
    _ec_payload_fc_cfg(event)
    event.specific_context_field["ant"] = -1
    event.specific_context_field["msg"] = "hellooo"
    event.common_context_field["cpu_id"] = 1
    event.common_context_field["stuff"] = 13.194
    event.common_context_field["gnu"] = "salut"


def _pkt_fc_cfg(packet):
    packet.context_field["something"] = 154
    packet.context_field["something_else"] = 17.2


def test_const_attr_ec():
    d = _const_ev_msg()
    assert d.msg.event.cls.addr == d.ec.addr
    assert type(d.msg.event.cls) is bt2_ec._EventClassConst


def test_attr_ec(ev_msg):
    assert type(ev_msg.event.cls) is bt2_ec._EventClass


def test_const_attr_name():
    d = _const_ev_msg()
    assert d.msg.event.name == d.ec.name


def test_const_attr_id():
    d = _const_ev_msg()
    assert d.msg.event.id == d.ec.id


def test_const_get_common_ctx_field():
    def ec_fc_cfg(event):
        event.common_context_field["cpu_id"] = 1
        event.common_context_field["stuff"] = 13.194
        event.common_context_field["gnu"] = "salut"

    d = _const_ev_msg(ec_fc_cfg=ec_fc_cfg, with_common_ctx=True)
    assert d.msg.event.common_context_field["cpu_id"] == 1
    assert d.msg.event.common_context_field["stuff"] == 13.194
    assert d.msg.event.common_context_field["gnu"] == "salut"
    assert type(d.msg.event.common_context_field) is bt2_field._StructureFieldConst


def test_attr_common_ctx_field(ev_msg):
    assert type(ev_msg.event.common_context_field) is bt2_field._StructureField


def test_const_no_common_ctx_field():
    d = _const_ev_msg(with_common_ctx=False)
    assert d.msg.event.common_context_field is None


def test_const_get_spec_ctx_field():
    def ec_fc_cfg(ev):
        ev.specific_context_field["ant"] = -1
        ev.specific_context_field["msg"] = "hellooo"

    d = _const_ev_msg(ec_fc_cfg=ec_fc_cfg, with_spec_ctx=True)
    assert d.msg.event.specific_context_field["ant"] == -1
    assert d.msg.event.specific_context_field["msg"] == "hellooo"
    assert type(d.msg.event.specific_context_field) is bt2_field._StructureFieldConst


def test_attr_spec_ctx_field(ev_msg):
    assert type(ev_msg.event.specific_context_field) is bt2_field._StructureField


def test_const_no_spec_ctx_field():
    d = _const_ev_msg(with_spec_ctx=False)
    assert d.msg.event.specific_context_field is None


def test_const_get_ev_payload_field():
    def ec_fc_cfg(ev):
        ev.payload_field["giraffe"] = 1
        ev.payload_field["gnu"] = 23
        ev.payload_field["mosquito"] = 42

    d = _const_ev_msg(ec_fc_cfg=ec_fc_cfg, with_payload=True)
    assert d.msg.event.payload_field["giraffe"] == 1
    assert d.msg.event.payload_field["gnu"] == 23
    assert d.msg.event.payload_field["mosquito"] == 42
    assert type(d.msg.event.payload_field) is bt2_field._StructureFieldConst


def test_attr_payload_field(ev_msg):
    assert type(ev_msg.event.payload_field) is bt2_field._StructureField


def test_const_no_payload_field():
    assert _const_ev_msg(with_payload=False).msg.event.payload_field is None


def test_const_clk_value():
    d = _const_ev_msg(with_clk_cls=True)
    assert d.msg.default_clock_snapshot.value == 789
    assert type(d.msg.default_clock_snapshot) is bt2_cs._ClockSnapshotConst


def test_clk_value(ev_msg):
    assert ev_msg.default_clock_snapshot.value == 789
    assert type(ev_msg.default_clock_snapshot) is bt2_cs._ClockSnapshotConst


def test_const_no_clk_value():
    d = _const_ev_msg(with_clk_cls=False)
    with pytest.raises(ValueError, match="stream class has no default clock class"):
        d.msg.default_clock_snapshot


def test_const_stream():
    d = _const_ev_msg()
    assert d.msg.event.stream.addr == d.stream.addr
    assert type(d.msg.event.stream) is bt2_stream._StreamConst


def test_stream(ev_msg):
    assert type(ev_msg.event.stream) is bt2_stream._Stream


def test_const_getitem():
    ev = _const_ev_msg(
        pkt_fc_cfg=_pkt_fc_cfg,
        ec_fc_cfg=_ec_fc_cfg,
        with_common_ctx=True,
        with_spec_ctx=True,
        with_payload=True,
        with_pkt=True,
    ).msg.event

    # Test event fields
    assert ev["giraffe"] == 1
    assert type(ev["giraffe"]) is bt2_field._SignedIntegerFieldConst
    assert ev["gnu"] == 23
    assert ev["mosquito"] == 42
    assert ev["ant"] == -1
    assert type(ev["ant"]) is bt2_field._SignedIntegerFieldConst
    assert ev["msg"] == "hellooo"
    assert ev["cpu_id"] == 1
    assert type(ev["cpu_id"]) is bt2_field._SignedIntegerFieldConst
    assert ev["stuff"] == 13.194

    # Test packet fields
    assert ev["something"] == 154
    assert type(ev["something"]) is bt2_field._UnsignedIntegerFieldConst
    assert ev["something_else"] == 17.2

    with pytest.raises(KeyError):
        ev["yes"]


def test_const_getitem_no_pkt():
    d = _const_ev_msg(
        ec_fc_cfg=_ec_payload_fc_cfg,
        with_payload=True,
    )

    with pytest.raises(KeyError):
        d.msg.event["yes"]


def test_getitem(ev_msg):
    ev = ev_msg.event
    assert ev["giraffe"] == 1
    assert type(ev["giraffe"]) is bt2_field._SignedIntegerField
    assert ev["ant"] == -1
    assert type(ev["ant"]) is bt2_field._SignedIntegerField
    assert ev["cpu_id"] == 1
    assert type(ev["cpu_id"]) is bt2_field._SignedIntegerField
    assert ev["something"] == 154
    assert type(ev["something"]) is bt2_field._UnsignedIntegerField


_EXPECTED_FIELD_NAMES = [
    # Payload
    "giraffe",
    "gnu",
    "mosquito",
    # Specific context
    "ant",
    "msg",
    # Common context
    "cpu_id",
    "stuff",
    # Packet context
    "something",
    "something_else",
]


def test_iter_full():
    d = _const_ev_msg(
        pkt_fc_cfg=_pkt_fc_cfg,
        ec_fc_cfg=_ec_fc_cfg,
        with_common_ctx=True,
        with_spec_ctx=True,
        with_payload=True,
        with_pkt=True,
    )

    assert list(d.msg.event) == _EXPECTED_FIELD_NAMES


_EXPECTED_PAYLOAD_FIELD_NAMES = [
    # Payload
    "giraffe",
    "gnu",
    "mosquito",
]


def test_iter_payload_only():
    d = _const_ev_msg(
        ec_fc_cfg=_ec_payload_fc_cfg,
        with_payload=True,
    )

    assert list(d.msg.event) == _EXPECTED_PAYLOAD_FIELD_NAMES


def test_len_full():
    d = _const_ev_msg(
        pkt_fc_cfg=_pkt_fc_cfg,
        ec_fc_cfg=_ec_fc_cfg,
        with_common_ctx=True,
        with_spec_ctx=True,
        with_payload=True,
        with_pkt=True,
    )

    assert len(d.msg.event) == 9


def test_len_payload_only():
    d = _const_ev_msg(
        pkt_fc_cfg=None,
        ec_fc_cfg=_ec_payload_fc_cfg,
        with_payload=True,
    )

    assert len(d.msg.event) == 3


def test_in_full():
    d = _const_ev_msg(
        pkt_fc_cfg=_pkt_fc_cfg,
        ec_fc_cfg=_ec_fc_cfg,
        with_common_ctx=True,
        with_spec_ctx=True,
        with_payload=True,
        with_pkt=True,
    )

    for field_name in _EXPECTED_FIELD_NAMES:
        assert field_name in d.msg.event

    assert "lol" not in d.msg.event


def test_in_payload_only():
    d = _const_ev_msg(
        pkt_fc_cfg=None,
        ec_fc_cfg=_ec_payload_fc_cfg,
        with_payload=True,
    )

    for field_name in _EXPECTED_PAYLOAD_FIELD_NAMES:
        assert field_name in d.msg.event

    assert "lol" not in d.msg.event
