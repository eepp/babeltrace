# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import types

import bt2
import utils
import pytest
from bt2 import event as bt2_ev
from bt2 import field as bt2_field
from bt2 import trace as bt2_trace
from bt2 import packet as bt2_pkt
from bt2 import stream as bt2_stream
from bt2 import event_class as bt2_ec
from bt2 import trace_class as bt2_tc
from bt2 import stream_class as bt2_sc
from bt2 import clock_snapshot as bt2_cs


def _create_all_msgs(with_clk_cls, with_stream_msgs_cs=False):
    class MyIter(bt2._UserMessageIterator):
        def __init__(self, config, self_port_output):
            self._at = 0
            self._with_stream_msgs_cs = self_port_output.user_data.get(
                "with_stream_msgs_cs", False
            )

        def __next__(self):
            if data.clk_cls:
                if self._at == 0:
                    if self._with_stream_msgs_cs:
                        msg = self._create_stream_beginning_message(
                            data.stream, default_clock_snapshot=self._at
                        )
                    else:
                        msg = self._create_stream_beginning_message(data.stream)

                    assert type(msg) is bt2._StreamBeginningMessage
                elif self._at == 1:
                    msg = self._create_packet_beginning_message(data.pkt, self._at)

                    assert type(msg) is bt2._PacketBeginningMessage
                elif self._at == 2:
                    msg = self._create_event_message(data.ec, data.pkt, self._at)

                    assert type(msg) is bt2._EventMessage
                elif self._at == 3:
                    msg = self._create_message_iterator_inactivity_message(
                        data.clk_cls, self._at
                    )
                elif self._at == 4:
                    msg = self._create_discarded_events_message(
                        data.stream, 890, self._at, self._at
                    )

                    assert type(msg) is bt2._DiscardedEventsMessage
                elif self._at == 5:
                    msg = self._create_packet_end_message(data.pkt, self._at)

                    assert type(msg) is bt2._PacketEndMessage
                elif self._at == 6:
                    msg = self._create_discarded_packets_message(
                        data.stream, 678, self._at, self._at
                    )

                    assert type(msg) is bt2._DiscardedPacketsMessage
                elif self._at == 7:
                    if self._with_stream_msgs_cs:
                        msg = self._create_stream_end_message(
                            data.stream, default_clock_snapshot=self._at
                        )
                    else:
                        msg = self._create_stream_end_message(data.stream)

                    assert type(msg) is bt2._StreamEndMessage
                elif self._at >= 8:
                    raise bt2.Stop
            else:
                if self._at == 0:
                    msg = self._create_stream_beginning_message(data.stream)
                elif self._at == 1:
                    msg = self._create_packet_beginning_message(data.pkt)
                elif self._at == 2:
                    msg = self._create_event_message(data.ec, data.pkt)
                elif self._at == 3:
                    msg = self._create_discarded_events_message(data.stream, 890)
                elif self._at == 4:
                    msg = self._create_packet_end_message(data.pkt)
                elif self._at == 5:
                    msg = self._create_discarded_packets_message(data.stream, 678)
                elif self._at == 6:
                    msg = self._create_stream_end_message(data.stream)
                elif self._at >= 7:
                    raise bt2.Stop

            self._at += 1
            return msg

    class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
        def __init__(self, config, params, obj):
            self._add_output_port("out", params)

            with_clk_cls = bool(params["with_clk_cls"])
            tc = self._create_trace_class()

            if with_clk_cls:
                clk_cls = self._create_clock_class()
            else:
                clk_cls = None

            sc = tc.create_stream_class(
                default_clock_class=clk_cls,
                supports_packets=True,
                packets_have_beginning_default_clock_snapshot=with_clk_cls,
                packets_have_end_default_clock_snapshot=with_clk_cls,
                supports_discarded_events=True,
                discarded_events_have_default_clock_snapshots=with_clk_cls,
                supports_discarded_packets=True,
                discarded_packets_have_default_clock_snapshots=with_clk_cls,
            )

            trace = tc()
            stream = trace.create_stream(sc)

            data.trace = trace
            data.stream = stream
            data.pkt = stream.create_packet()
            data.ec = sc.create_event_class(
                name="salut",
                payload_field_class=tc.create_structure_field_class(
                    members=(("my_int", tc.create_signed_integer_field_class(32)),)
                ),
                specific_context_field_class=tc.create_structure_field_class(
                    members=(("my_int", tc.create_signed_integer_field_class(32)),)
                ),
            )
            data.clk_cls = clk_cls

    data = types.SimpleNamespace()
    params = {"with_clk_cls": with_clk_cls, "with_stream_msgs_cs": with_stream_msgs_cs}
    graph = bt2.Graph()
    msg_iter = utils.TestOutputPortMessageIterator(
        graph, graph.add_component(MySrc, "my_source", params).output_ports["out"]
    )
    msgs = list(msg_iter)

    # Build and return result
    res = types.SimpleNamespace(
        trace=data.trace,
        stream=data.stream,
        pkt=data.pkt,
        ec=data.ec,
        clk_cls=data.clk_cls,
        stream_beg_msg=msgs[0],
        pkt_beg_msg=msgs[1],
        ev_msg=msgs[2],
    )

    if with_clk_cls:
        res.msg_iter_inactivity_msg = msgs[3]
        res.discarded_ev_msg = msgs[4]
        res.pkt_end_msg = msgs[5]
        res.discarded_pkt_msg = msgs[6]
        res.stream_end_msg = msgs[7]
    else:
        res.discarded_ev_msg = msgs[3]
        res.pkt_end_msg = msgs[4]
        res.discarded_pkt_msg = msgs[5]
        res.stream_end_msg = msgs[6]

    return res


@pytest.fixture(scope="module")
def msgs_with_clk_cls():
    return _create_all_msgs(with_clk_cls=True)


@pytest.fixture(scope="module")
def msgs_without_clk_cls():
    return _create_all_msgs(with_clk_cls=False)


class TestStreamBeginning:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.stream_beg_msg
        assert type(msg) is bt2._StreamBeginningMessageConst
        assert type(msg.stream) is bt2_stream._StreamConst
        assert msg.stream.addr == msgs_with_clk_cls.stream.addr
        assert isinstance(msg.default_clock_snapshot, bt2._UnknownClockSnapshot)

    def test_without_clk_cls(self, msgs_without_clk_cls):
        msg = msgs_without_clk_cls.stream_beg_msg
        assert isinstance(msg, bt2._StreamBeginningMessageConst)
        assert type(msg.stream) is bt2_stream._StreamConst
        assert msg.stream.addr == msgs_without_clk_cls.stream.addr

        with pytest.raises(ValueError, match="stream class has no default clock class"):
            msg.default_clock_snapshot

    def test_non_const_type(self, stream_beginning_msg):
        assert type(stream_beginning_msg.stream) is bt2_stream._Stream


class TestStreamEnd:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.stream_end_msg
        assert type(msg) is bt2._StreamEndMessageConst
        assert type(msg.stream) is bt2_stream._StreamConst
        assert msg.stream.addr == msgs_with_clk_cls.stream.addr
        assert type(msg.default_clock_snapshot) is bt2._UnknownClockSnapshot

    def test_without_clk_cls(self, msgs_without_clk_cls):
        msg = msgs_without_clk_cls.stream_end_msg
        assert isinstance(msg, bt2._StreamEndMessageConst)
        assert type(msg.stream) is bt2_stream._StreamConst
        assert msg.stream.addr == msgs_without_clk_cls.stream.addr

        with pytest.raises(ValueError, match="stream class has no default clock class"):
            msg.default_clock_snapshot

    def test_non_const_type(self, stream_end_msg):
        assert type(stream_end_msg.stream) is bt2_stream._Stream

    def test_with_cs(self):
        data = _create_all_msgs(with_clk_cls=True, with_stream_msgs_cs=True)
        assert isinstance(data.stream_beg_msg, bt2._StreamBeginningMessageConst)
        assert (
            type(data.stream_beg_msg.default_clock_snapshot)
            is bt2_cs._ClockSnapshotConst
        )
        assert data.stream_beg_msg.default_clock_snapshot.value == 0
        assert isinstance(data.stream_end_msg, bt2._StreamEndMessageConst)
        assert (
            type(data.stream_end_msg.default_clock_snapshot)
            is bt2_cs._ClockSnapshotConst
        )
        assert data.stream_end_msg.default_clock_snapshot.value == 7


class TestPktBeginning:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.pkt_beg_msg
        assert type(msg) is bt2._PacketBeginningMessageConst
        assert type(msg.packet) is bt2_pkt._PacketConst
        assert type(msg.default_clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert msg.packet.addr == msgs_with_clk_cls.pkt.addr
        assert msg.default_clock_snapshot.value == 1

    def test_without_clk_cls(self, msgs_without_clk_cls):
        msg = msgs_without_clk_cls.pkt_beg_msg
        assert isinstance(msg, bt2._PacketBeginningMessageConst)
        assert type(msg.packet) is bt2_pkt._PacketConst
        assert msg.packet.addr == msgs_without_clk_cls.pkt.addr

    def test_non_const_type(self, pkt_beginning_msg):
        assert type(pkt_beginning_msg.packet) is bt2_pkt._Packet


class TestPktEnd:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.pkt_end_msg
        assert type(msg) is bt2._PacketEndMessageConst
        assert type(msg.packet) is bt2_pkt._PacketConst
        assert type(msg.default_clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert msg.packet.addr == msgs_with_clk_cls.pkt.addr
        assert msg.default_clock_snapshot.value == 5

    def test_without_clk_cls(self, msgs_without_clk_cls):
        msg = msgs_without_clk_cls.pkt_end_msg
        assert isinstance(msg, bt2._PacketEndMessageConst)
        assert type(msg.packet) is bt2_pkt._PacketConst
        assert msg.packet.addr == msgs_without_clk_cls.pkt.addr

    def test_non_const_type(self, pkt_end_msg):
        assert type(pkt_end_msg.packet) is bt2_pkt._Packet


class TestEv:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.ev_msg
        assert type(msg) is bt2._EventMessageConst
        assert type(msg.event) is bt2_ev._EventConst
        assert type(msg.default_clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert type(msg.event.payload_field) is bt2_field._StructureFieldConst
        assert (
            type(msg.event.payload_field["my_int"])
            is bt2_field._SignedIntegerFieldConst
        )
        assert msg.event.cls.addr == msgs_with_clk_cls.ec.addr
        assert msg.default_clock_snapshot.value == 2

    def test_without_clk_cls(self, msgs_without_clk_cls):
        msg = msgs_without_clk_cls.ev_msg
        assert isinstance(msg, bt2._EventMessageConst)
        assert type(msg.event) is bt2_ev._EventConst
        assert type(msg.event.cls) is bt2_ec._EventClassConst
        assert msg.event.cls.addr == msgs_without_clk_cls.ec.addr

        with pytest.raises(ValueError, match="stream class has no default clock class"):
            msg.default_clock_snapshot

    def test_non_const_type(self, ev_msg):
        assert type(ev_msg.event) is bt2_ev._Event


class TestMsgIterInactivity:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.msg_iter_inactivity_msg
        assert type(msg) is bt2._MessageIteratorInactivityMessageConst
        assert type(msg.clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert msg.clock_snapshot.value == 3


class TestDiscardedEvs:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.discarded_ev_msg
        assert type(msg) is bt2._DiscardedEventsMessageConst
        assert type(msg.stream) is bt2_stream._StreamConst
        assert type(msg.stream.cls) is bt2_sc._StreamClassConst
        assert type(msg.beginning_default_clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert type(msg.end_default_clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert msg.stream.addr == msgs_with_clk_cls.stream.addr
        assert msg.count == 890
        assert msg.stream.cls.default_clock_class.addr == msgs_with_clk_cls.clk_cls.addr
        assert msg.beginning_default_clock_snapshot.value == 4
        assert msg.end_default_clock_snapshot.value == 4

    def test_without_clk_cls(self, msgs_without_clk_cls):
        msg = msgs_without_clk_cls.discarded_ev_msg
        assert isinstance(msg, bt2._DiscardedEventsMessageConst)
        assert type(msg.stream) is bt2_stream._StreamConst
        assert type(msg.stream.cls) is bt2_sc._StreamClassConst
        assert msg.stream.addr == msgs_without_clk_cls.stream.addr
        assert msg.count == 890
        assert msg.stream.cls.default_clock_class is None

        with pytest.raises(
            ValueError,
            match="such a message has no clock snapshots for this stream class",
        ):
            msg.beginning_default_clock_snapshot

        with pytest.raises(
            ValueError,
            match="such a message has no clock snapshots for this stream class",
        ):
            msg.end_default_clock_snapshot

    def test_create(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(supports_discarded_events=True)

        def msg_iter_next(msg_iter, stream):
            return msg_iter._create_discarded_events_message(stream)

        msg = utils.run_in_message_iterator_next(create_sc, msg_iter_next)
        assert type(msg) is bt2._DiscardedEventsMessage
        assert msg.count is None

    def test_create_with_count(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(supports_discarded_events=True)

        def msg_iter_next(msg_iter, stream):
            return msg_iter._create_discarded_events_message(stream, count=242)

        msg = utils.run_in_message_iterator_next(create_sc, msg_iter_next)
        assert type(msg) is bt2._DiscardedEventsMessage
        assert msg.count == 242

    def test_create_with_count_zero_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(supports_discarded_events=True)

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(ValueError, match="discarded event count is 0"):
                msg_iter._create_discarded_events_message(stream, count=0)

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_with_cs(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                default_clock_class=clk_cls,
                supports_discarded_events=True,
                discarded_events_have_default_clock_snapshots=True,
            )

        def msg_iter_next(msg_iter, stream):
            return msg_iter._create_discarded_events_message(
                stream, beg_clock_snapshot=10, end_clock_snapshot=20
            )

        msg = utils.run_in_message_iterator_next(create_sc, msg_iter_next)
        assert type(msg) is bt2._DiscardedEventsMessage
        assert msg.beginning_default_clock_snapshot == 10
        assert msg.end_default_clock_snapshot == 20

    def test_create_unsupported_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class()

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError, match="stream class does not support discarded events"
            ):
                msg_iter._create_discarded_events_message(stream)

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_unsupported_cs_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(supports_discarded_events=True)

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError,
                match="discarded events have no default clock snapshots for this stream class",
            ):
                msg_iter._create_discarded_events_message(
                    stream, beg_clock_snapshot=10, end_clock_snapshot=20
                )

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_missing_cs_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                default_clock_class=clk_cls,
                supports_discarded_events=True,
                discarded_events_have_default_clock_snapshots=True,
            )

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError,
                match="discarded events have default clock snapshots for this stream class",
            ):
                msg_iter._create_discarded_events_message(stream)

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_cs_end_gt_begin_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                default_clock_class=clk_cls,
                supports_discarded_events=True,
                discarded_events_have_default_clock_snapshots=True,
            )

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError,
                match=r"beginning default clock snapshot value \(20\) is greater than end default clock snapshot value \(10\)",
            ):
                msg_iter._create_discarded_events_message(
                    stream, beg_clock_snapshot=20, end_clock_snapshot=10
                )

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)


class TestDiscardedPkts:
    def test_with_clk_cls(self, msgs_with_clk_cls):
        msg = msgs_with_clk_cls.discarded_pkt_msg
        assert type(msg) is bt2._DiscardedPacketsMessageConst
        assert type(msg.stream) is bt2_stream._StreamConst
        assert type(msg.stream.trace) is bt2_trace._TraceConst
        assert type(msg.stream.trace.cls) is bt2_tc._TraceClassConst
        assert type(msg.beginning_default_clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert type(msg.end_default_clock_snapshot) is bt2_cs._ClockSnapshotConst
        assert msg.stream.addr == msgs_with_clk_cls.stream.addr
        assert msg.count == 678
        assert msg.stream.cls.default_clock_class.addr == msgs_with_clk_cls.clk_cls.addr
        assert msg.beginning_default_clock_snapshot.value == 6
        assert msg.end_default_clock_snapshot.value == 6

    def test_without_clk_cls(self, msgs_without_clk_cls):
        msg = msgs_without_clk_cls.discarded_pkt_msg
        assert isinstance(msg, bt2._DiscardedPacketsMessageConst)
        assert type(msg.stream) is bt2_stream._StreamConst
        assert type(msg.stream.cls) is bt2_sc._StreamClassConst
        assert type(msg.stream.cls.trace_class) is bt2_tc._TraceClassConst
        assert msg.stream.addr == msgs_without_clk_cls.stream.addr
        assert msg.count == 678
        assert msg.stream.cls.default_clock_class is None

        with pytest.raises(
            ValueError,
            match="such a message has no clock snapshots for this stream class",
        ):
            msg.beginning_default_clock_snapshot

        with pytest.raises(
            ValueError,
            match="such a message has no clock snapshots for this stream class",
        ):
            msg.end_default_clock_snapshot

    def test_create(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                supports_packets=True, supports_discarded_packets=True
            )

        def msg_iter_next(msg_iter, stream):
            return msg_iter._create_discarded_packets_message(stream)

        msg = utils.run_in_message_iterator_next(create_sc, msg_iter_next)
        assert type(msg) is bt2._DiscardedPacketsMessage
        assert msg.count is None

    def test_create_with_count(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                supports_packets=True, supports_discarded_packets=True
            )

        def msg_iter_next(msg_iter, stream):
            return msg_iter._create_discarded_packets_message(stream, count=242)

        msg = utils.run_in_message_iterator_next(create_sc, msg_iter_next)
        assert type(msg) is bt2._DiscardedPacketsMessage
        assert msg.count == 242

    def test_create_with_count_zero_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                supports_packets=True, supports_discarded_packets=True
            )

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(ValueError, match="discarded packet count is 0"):
                msg_iter._create_discarded_packets_message(stream, count=0)

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_with_cs(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                default_clock_class=clk_cls,
                supports_packets=True,
                supports_discarded_packets=True,
                discarded_packets_have_default_clock_snapshots=True,
            )

        def msg_iter_next(msg_iter, stream):
            return msg_iter._create_discarded_packets_message(
                stream, beg_clock_snapshot=10, end_clock_snapshot=20
            )

        msg = utils.run_in_message_iterator_next(create_sc, msg_iter_next)
        assert type(msg) is bt2._DiscardedPacketsMessage
        assert msg.beginning_default_clock_snapshot == 10
        assert msg.end_default_clock_snapshot == 20

    def test_create_unsupported_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(supports_packets=True)

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError, match="stream class does not support discarded packets"
            ):
                msg_iter._create_discarded_packets_message(stream)

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_unsupported_cs_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                supports_packets=True, supports_discarded_packets=True
            )

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError,
                match="discarded packets have no default clock snapshots for this stream class",
            ):
                msg_iter._create_discarded_packets_message(
                    stream, beg_clock_snapshot=10, end_clock_snapshot=20
                )

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_missing_cs_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                default_clock_class=clk_cls,
                supports_packets=True,
                supports_discarded_packets=True,
                discarded_packets_have_default_clock_snapshots=True,
            )

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError,
                match="discarded packets have default clock snapshots for this stream class",
            ):
                msg_iter._create_discarded_packets_message(stream)

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)

    def test_create_cs_end_gt_begin_raises(self):
        def create_sc(tc, clk_cls):
            return tc.create_stream_class(
                default_clock_class=clk_cls,
                supports_packets=True,
                supports_discarded_packets=True,
                discarded_packets_have_default_clock_snapshots=True,
            )

        def msg_iter_next(msg_iter, stream):
            with pytest.raises(
                ValueError,
                match=r"beginning default clock snapshot value \(20\) is greater than end default clock snapshot value \(10\)",
            ):
                msg_iter._create_discarded_packets_message(
                    stream, beg_clock_snapshot=20, end_clock_snapshot=10
                )

        utils.run_in_message_iterator_next(create_sc, msg_iter_next)
