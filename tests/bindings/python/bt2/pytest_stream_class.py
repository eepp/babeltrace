# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import utils
import pytest
from bt2 import value as bt2_value
from bt2 import clock_class as bt2_clk_cls
from bt2 import event_class as bt2_ec
from bt2 import field_class as bt2_fc
from bt2 import trace_class as bt2_tc
from bt2 import stream_class as bt2_sc


@pytest.fixture
def tc_and_cc():
    def f(self_comp):
        return (
            self_comp._create_trace_class(assigns_automatic_stream_class_id=True),
            self_comp._create_clock_class(),
        )

    return utils.run_in_component_init(0, f)


@pytest.fixture
def tc(tc_and_cc):
    return tc_and_cc[0]


@pytest.fixture
def cc(tc_and_cc):
    return tc_and_cc[1]


@pytest.fixture
def trace(tc):
    return tc()


def test_create_def(tc):
    sc = tc.create_stream_class()
    assert type(sc) is bt2_sc._StreamClass
    assert sc.name is None
    assert sc.packet_context_field_class is None
    assert sc.event_common_context_field_class is None
    assert sc.default_clock_class is None
    assert sc.assigns_automatic_event_class_id is True
    assert sc.assigns_automatic_stream_id is True
    assert sc.supports_packets is False
    assert sc.packets_have_beginning_default_clock_snapshot is False
    assert sc.packets_have_end_default_clock_snapshot is False
    assert sc.supports_discarded_events is False
    assert sc.discarded_events_have_default_clock_snapshots is False
    assert sc.supports_discarded_packets is False
    assert sc.discarded_packets_have_default_clock_snapshots is False
    assert len(sc.user_attributes) == 0


def test_create_name(tc):
    assert tc.create_stream_class(name="bozo").name == "bozo"


def test_create_invalid_name(tc):
    with pytest.raises(TypeError, match="'int' is not a 'str' object"):
        tc.create_stream_class(name=17)

    assert len(tc) == 0


def test_create_pkt_ctx_fc(tc):
    fc = tc.create_structure_field_class()
    sc = tc.create_stream_class(packet_context_field_class=fc, supports_packets=True)
    assert sc.packet_context_field_class == fc
    assert type(sc.packet_context_field_class) is bt2_fc._StructureFieldClass


def test_create_invalid_pkt_ctx_fc(tc):
    with pytest.raises(
        TypeError,
        match="'int' is not a '<class 'bt2.field_class._StructureFieldClass'>' object",
    ):
        tc.create_stream_class(packet_context_field_class=22, supports_packets=True)

    assert len(tc) == 0


def test_create_invalid_pkt_ctx_fc_no_pkts(tc):
    fc = tc.create_structure_field_class()

    with pytest.raises(
        ValueError,
        match="cannot have a packet context field class without supporting packets",
    ):
        tc.create_stream_class(packet_context_field_class=fc)

    assert len(tc) == 0


def test_create_ev_common_ctx_fc(tc):
    fc = tc.create_structure_field_class()
    sc = tc.create_stream_class(event_common_context_field_class=fc)
    assert sc.event_common_context_field_class == fc
    assert type(sc.event_common_context_field_class) is bt2_fc._StructureFieldClass


def test_create_invalid_ev_common_ctx_fc(tc):
    with pytest.raises(
        TypeError,
        match="'int' is not a '<class 'bt2.field_class._StructureFieldClass'>' object",
    ):
        tc.create_stream_class(event_common_context_field_class=22)

    assert len(tc) == 0


def test_create_def_clk_cls(tc, cc):
    sc = tc.create_stream_class(default_clock_class=cc)
    assert sc.default_clock_class.addr == cc.addr
    assert type(sc.default_clock_class) is bt2_clk_cls._ClockClass


def test_create_invalid_def_clk_cls(tc):
    with pytest.raises(
        TypeError, match="'int' is not a '<class 'bt2.clock_class._ClockClass'>' object"
    ):
        tc.create_stream_class(default_clock_class=12)

    assert len(tc) == 0


def test_create_user_attrs(tc):
    sc = tc.create_stream_class(user_attributes={"salut": 23})
    assert sc.user_attributes == {"salut": 23}
    assert type(sc.user_attributes) is bt2_value.MapValue


def test_const_user_attrs(const_stream_beginning_msg):
    sc = const_stream_beginning_msg.stream.cls
    assert sc.user_attributes == {"a-stream-class-attribute": 1}
    assert type(sc.user_attributes) is bt2_value._MapValueConst


def test_create_invalid_user_attrs(tc):
    with pytest.raises(
        TypeError, match="cannot create value object from 'object' object"
    ):
        tc.create_stream_class(user_attributes=object())

    assert len(tc) == 0


def test_create_invalid_user_attrs_value_type(tc):
    with pytest.raises(
        TypeError,
        match="'SignedIntegerValue' is not a '<class 'bt2.value.MapValue'>' object",
    ):
        tc.create_stream_class(user_attributes=23)

    assert len(tc) == 0


def test_automatic_stream_ids(tc, trace):
    sc = tc.create_stream_class(assigns_automatic_stream_id=True)
    assert sc.assigns_automatic_stream_id is True

    stream = trace.create_stream(sc)
    assert stream.id is not None


def test_automatic_stream_ids_raises(tc, trace):
    sc = tc.create_stream_class(assigns_automatic_stream_id=True)
    assert sc.assigns_automatic_stream_id is True

    with pytest.raises(
        ValueError, match="id provided, but stream class assigns automatic stream ids"
    ):
        trace.create_stream(sc, id=123)

    assert len(trace) == 0


def test_automatic_stream_ids_wrong_type(tc):
    with pytest.raises(TypeError, match="str' is not a 'bool' object"):
        tc.create_stream_class(assigns_automatic_stream_id="True")

    assert len(tc) == 0


def test_no_automatic_stream_ids(tc, trace):
    sc = tc.create_stream_class(assigns_automatic_stream_id=False)
    assert sc.assigns_automatic_stream_id is False
    stream = trace.create_stream(sc, id=333)
    assert stream.id == 333


def test_no_automatic_stream_ids_raises(tc, trace):
    sc = tc.create_stream_class(assigns_automatic_stream_id=False)
    assert sc.assigns_automatic_stream_id is False

    with pytest.raises(
        ValueError,
        match="id not provided, but stream class does not assign automatic stream ids",
    ):
        trace.create_stream(sc)

    assert len(trace) == 0


def test_automatic_ec_ids(tc):
    sc = tc.create_stream_class(assigns_automatic_event_class_id=True)
    assert sc.assigns_automatic_event_class_id is True

    ec = sc.create_event_class()
    assert ec.id is not None


def test_automatic_ec_ids_raises(tc):
    sc = tc.create_stream_class(assigns_automatic_event_class_id=True)
    assert sc.assigns_automatic_event_class_id is True

    with pytest.raises(
        ValueError,
        match="id provided, but stream class assigns automatic event class ids",
    ):
        sc.create_event_class(id=123)

    assert len(sc) == 0


def test_automatic_ec_ids_wrong_type(tc):
    with pytest.raises(TypeError, match="'str' is not a 'bool' object"):
        tc.create_stream_class(assigns_automatic_event_class_id="True")

    assert len(tc) == 0


def test_no_automatic_ec_ids(tc):
    sc = tc.create_stream_class(assigns_automatic_event_class_id=False)
    assert sc.assigns_automatic_event_class_id is False

    ec = sc.create_event_class(id=333)
    assert ec.id == 333


def test_no_automatic_ec_ids_raises(tc):
    sc = tc.create_stream_class(assigns_automatic_event_class_id=False)
    assert sc.assigns_automatic_event_class_id is False

    with pytest.raises(
        ValueError,
        match="id not provided, but stream class does not assign automatic event class ids",
    ):
        sc.create_event_class()

    assert len(sc) == 0


def test_supports_pkts_without_cs(tc, cc):
    sc = tc.create_stream_class(default_clock_class=cc, supports_packets=True)
    assert sc.supports_packets is True
    assert sc.packets_have_beginning_default_clock_snapshot is False
    assert sc.packets_have_end_default_clock_snapshot is False


def test_supports_pkts_with_begin_cs(tc, cc):
    sc = tc.create_stream_class(
        default_clock_class=cc,
        supports_packets=True,
        packets_have_beginning_default_clock_snapshot=True,
    )
    assert sc.supports_packets is True
    assert sc.packets_have_beginning_default_clock_snapshot is True
    assert sc.packets_have_end_default_clock_snapshot is False


def test_supports_pkts_with_end_cs(tc, cc):
    sc = tc.create_stream_class(
        default_clock_class=cc,
        supports_packets=True,
        packets_have_end_default_clock_snapshot=True,
    )
    assert sc.supports_packets is True
    assert sc.packets_have_beginning_default_clock_snapshot is False
    assert sc.packets_have_end_default_clock_snapshot is True


def test_supports_pkts_raises_type_error(tc, cc):
    with pytest.raises(TypeError, match="'int' is not a 'bool' object"):
        tc.create_stream_class(default_clock_class=cc, supports_packets=23)

    assert len(tc) == 0


def test_pkts_have_begin_def_cs_raises_type_error(tc, cc):
    with pytest.raises(TypeError, match="'int' is not a 'bool' object"):
        tc.create_stream_class(
            default_clock_class=cc,
            packets_have_beginning_default_clock_snapshot=23,
        )

    assert len(tc) == 0


def test_pkts_have_end_def_cs_raises_type_error(tc, cc):
    with pytest.raises(TypeError, match="'int' is not a 'bool' object"):
        tc.create_stream_class(
            default_clock_class=cc, packets_have_end_default_clock_snapshot=23
        )

    assert len(tc) == 0


def test_does_not_support_pkts_raises_with_begin_cs(tc, cc):
    with pytest.raises(
        ValueError,
        match="cannot not support packets, but have packet beginning default clock snapshot",
    ):
        tc.create_stream_class(
            default_clock_class=cc,
            packets_have_beginning_default_clock_snapshot=True,
        )

    assert len(tc) == 0


def test_does_not_support_pkts_raises_with_end_cs(tc, cc):
    with pytest.raises(
        ValueError,
        match="cannot not support packets, but have packet end default clock snapshots",
    ):
        tc.create_stream_class(
            default_clock_class=cc,
            packets_have_end_default_clock_snapshot=True,
        )

    assert len(tc) == 0


def test_supports_discarded_evs_without_cs(tc, cc):
    sc = tc.create_stream_class(default_clock_class=cc, supports_discarded_events=True)
    assert sc.supports_discarded_events is True
    assert sc.discarded_events_have_default_clock_snapshots is False


def test_supports_discarded_evs_with_cs(tc, cc):
    sc = tc.create_stream_class(
        default_clock_class=cc,
        supports_discarded_events=True,
        discarded_events_have_default_clock_snapshots=True,
    )
    assert sc.supports_discarded_events is True
    assert sc.discarded_events_have_default_clock_snapshots is True


def test_supports_discarded_evs_raises_type_error(tc, cc):
    with pytest.raises(TypeError, match="'int' is not a 'bool' object"):
        tc.create_stream_class(default_clock_class=cc, supports_discarded_events=23)

    assert len(tc) == 0


def test_discarded_evs_have_def_cs_raises_type_error(tc, cc):
    with pytest.raises(TypeError, match="'int' is not a 'bool' object"):
        tc.create_stream_class(
            default_clock_class=cc,
            discarded_events_have_default_clock_snapshots=23,
        )

    assert len(tc) == 0


def test_does_not_support_discarded_evs_raises_with_cs(tc, cc):
    with pytest.raises(
        ValueError,
        match="cannot not support discarded events, but have default clock snapshots for discarded event messages",
    ):
        tc.create_stream_class(
            default_clock_class=cc,
            discarded_events_have_default_clock_snapshots=True,
        )

    assert len(tc) == 0


def test_supports_discarded_evs_with_cs_without_def_clk_cls_raises(tc):
    with pytest.raises(
        ValueError,
        match="cannot have no default clock class, but have default clock snapshots for discarded event messages",
    ):
        tc.create_stream_class(
            supports_discarded_events=True,
            discarded_events_have_default_clock_snapshots=True,
        )

    assert len(tc) == 0


def test_supports_discarded_pkts_without_cs(tc, cc):
    sc = tc.create_stream_class(
        default_clock_class=cc,
        supports_discarded_packets=True,
        supports_packets=True,
    )
    assert sc.supports_discarded_packets is True
    assert sc.discarded_packets_have_default_clock_snapshots is False


def test_supports_discarded_pkts_with_cs(tc, cc):
    sc = tc.create_stream_class(
        default_clock_class=cc,
        supports_discarded_packets=True,
        discarded_packets_have_default_clock_snapshots=True,
        supports_packets=True,
    )
    assert sc.supports_discarded_packets is True
    assert sc.discarded_packets_have_default_clock_snapshots is True


def test_supports_discarded_pkts_raises_without_pkt_support(tc, cc):
    with pytest.raises(
        ValueError, match="cannot support discarded packets, but not support packets"
    ):
        tc.create_stream_class(default_clock_class=cc, supports_discarded_packets=True)

    assert len(tc) == 0


def test_supports_discarded_pkts_raises_type_error(tc, cc):
    with pytest.raises(TypeError, match="'int' is not a 'bool' object"):
        tc.create_stream_class(
            default_clock_class=cc,
            supports_discarded_packets=23,
            supports_packets=True,
        )

    assert len(tc) == 0


def test_discarded_pkts_have_def_cs_raises_type_error(tc, cc):
    with pytest.raises(TypeError, match="'int' is not a 'bool' object"):
        tc.create_stream_class(
            default_clock_class=cc,
            discarded_packets_have_default_clock_snapshots=23,
            supports_packets=True,
        )

    assert len(tc) == 0


def test_does_not_support_discarded_pkts_raises_with_cs(tc, cc):
    with pytest.raises(
        ValueError,
        match="cannot not support discarded packets, but have default clock snapshots for discarded packet messages",
    ):
        tc.create_stream_class(
            default_clock_class=cc,
            discarded_packets_have_default_clock_snapshots=True,
            supports_packets=True,
        )

    assert len(tc) == 0


def test_supports_discarded_pkts_with_cs_without_def_clk_cls_raises(tc):
    with pytest.raises(
        ValueError,
        match="cannot have no default clock class, but have default clock snapshots for discarded packet messages",
    ):
        tc.create_stream_class(
            supports_packets=True,
            supports_discarded_packets=True,
            discarded_packets_have_default_clock_snapshots=True,
        )

    assert len(tc) == 0


def test_tc(tc):
    sc = tc.create_stream_class()
    assert sc.trace_class.addr == tc.addr
    assert type(sc.trace_class) is bt2_tc._TraceClass


@pytest.fixture
def sc_with_ecs(tc):
    sc = tc.create_stream_class(assigns_automatic_event_class_id=False)
    ec1 = sc.create_event_class(id=23)
    ec2 = sc.create_event_class(id=17)
    return sc, ec1, ec2


@pytest.fixture
def sc(sc_with_ecs):
    return sc_with_ecs[0]


def test_getitem(sc_with_ecs):
    sc, ec1, ec2 = sc_with_ecs
    assert sc[23].addr == ec1.addr
    assert type(sc[23]) is bt2_ec._EventClass
    assert sc[17].addr == ec2.addr
    assert type(sc[17]) is bt2_ec._EventClass


def test_getitem_wrong_key_type(sc):
    with pytest.raises(TypeError, match="'str' is not an 'int' object"):
        sc["event23"]


def test_getitem_wrong_key(sc):
    with pytest.raises(KeyError, match="19"):
        sc[19]


def test_len(sc):
    assert len(sc) == 2


def test_iter(sc):
    assert sorted(sc) == [17, 23]
