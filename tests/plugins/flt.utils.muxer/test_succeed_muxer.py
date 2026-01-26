# SPDX-FileCopyrightText: 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu


# Generic message iterator that calls the message function stored in its
# user data.
class _MsgIter(bt2._UserMessageIterator):
    def __init__(self, config, port):
        port.user_data(self)
        self._at = 0

    def __next__(self):
        if self._at < len(self._msgs):
            msg = self._msgs[self._at]
            self._at += 1
            return msg

        raise StopIteration


# Tests that messages are ordered by timestamp across
# multiple iterators.
class _BasicTsOrderingSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, ts):
            def func(msg_iter):
                stream = tc().create_stream(
                    tc.create_stream_class(default_clock_class=clk_cls)
                )

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, ts),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc = self._create_trace_class()
        clk_cls = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, 0))
        self._add_output_port("out2", make_msgs(2, 120))
        self._add_output_port("out3", make_msgs(3, 4))


# Tests ordering of event messages with different event class IDs.
class _DiffEcIdSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, ec_id):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls,
                    id=0,
                    assigns_automatic_stream_id=False,
                    assigns_automatic_event_class_id=False,
                    supports_packets=False,
                )

                ec = sc.create_event_class(id=ec_id)
                stream = tc().create_stream(sc, 0)

                # Use event class ID as timestamp so that both stream
                # beginning messages are not at the same time!
                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, ec.id),
                    msg_iter._create_event_message(ec, stream, 50),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, 1))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, 2))


# Tests ordering of event messages with different event class names.
class _DiffEcNameSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, ec_name):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls,
                    id=0,
                    assigns_automatic_stream_id=False,
                    supports_packets=False,
                )

                ec = sc.create_event_class(name=ec_name)
                stream = tc().create_stream(sc, 0)

                # Use event class name length as timestamp so that both
                # stream beginning messages are not at the same time.
                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, len(ec.name)),
                    msg_iter._create_event_message(ec, stream, 50),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, "Hull"))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, "Gatineau"))


# Tests ordering of inactivity messages with different clock classes.
class _DiffInactivityMsgCsSrc(
    bt2._UserSourceComponent, message_iterator_class=_MsgIter
):
    def __init__(self, config, params, obj):
        def make_msgs(clk_cls):
            def func(msg_iter):
                msg_iter._msgs = [
                    msg_iter._create_message_iterator_inactivity_message(clk_cls, 0)
                ]

            return func

        clk_cls_1 = self._create_clock_class(
            frequency=1, name="La Baie", offset=bt2.ClockOffset(0)
        )
        clk_cls_2 = self._create_clock_class(
            frequency=1, name="Chicoutimi", offset=bt2.ClockOffset(0)
        )
        self._add_output_port("out1", make_msgs(clk_cls_1))
        self._add_output_port("out2", make_msgs(clk_cls_2))


# Tests ordering of messages with different stream class IDs.
class _DiffScIdSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, stream_class_id):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls,
                    id=stream_class_id,
                    assigns_automatic_stream_id=False,
                )

                stream = tc().create_stream(sc, 0)

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, 0),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, 18))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, 23))


# Tests ordering of messages with different stream class names.
class _DiffScNameSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, stream_class_name):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls,
                    id=0,
                    name=stream_class_name,
                    assigns_automatic_stream_id=False,
                )

                stream = tc().create_stream(sc, 0)

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, 0),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, "one"))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, "two"))


# Tests ordering of messages where one stream class has a name and the
# other doesn't.
class _DiffScNoNameSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, stream_class_name):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls,
                    id=0,
                    name=stream_class_name,
                    assigns_automatic_stream_id=False,
                )

                stream = tc().create_stream(sc, 0)

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, 0),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, "one"))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, None))


# Tests ordering of messages with different stream IDs.
class _DiffStreamIdSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, stream_id):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls, assigns_automatic_stream_id=False
                )

                stream = tc().create_stream(sc, stream_id)

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, 0),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class()
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class()
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, 18))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, 23))


# Tests ordering of messages with different stream names.
class _DiffStreamNameSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, stream_name):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls, assigns_automatic_stream_id=False
                )

                stream = tc().create_stream(sc, 0, stream_name)

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, 0),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class()
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class()
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, "port-daniel"))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, "gascon"))


# Tests ordering of messages where one stream has a name and the
# other doesn't.
class _DiffStreamNoNameSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, stream_name):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls, assigns_automatic_stream_id=False
                )

                stream = tc().create_stream(sc, 0, name=stream_name)

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, 0),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class()
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class()
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, "one"))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, None))


# Tests ordering of messages with different trace names.
class _DiffTraceNameSrc(bt2._UserSourceComponent, message_iterator_class=_MsgIter):
    def __init__(self, config, params, obj):
        def make_msgs(iter_id, tc, clk_cls, trace_name):
            def func(msg_iter):
                sc = tc.create_stream_class(
                    default_clock_class=clk_cls, assigns_automatic_stream_id=False
                )

                stream = tc(name=trace_name).create_stream(sc, 0)

                msg_iter._msgs = [
                    msg_iter._create_stream_beginning_message(stream, 0),
                    msg_iter._create_stream_end_message(stream, iter_id * 193),
                ]

            return func

        tc1 = self._create_trace_class()
        clk_cls_1 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        tc2 = self._create_trace_class()
        clk_cls_2 = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))
        self._add_output_port("out1", make_msgs(1, tc1, clk_cls_1, "rouyn"))
        self._add_output_port("out2", make_msgs(2, tc2, clk_cls_2, "noranda"))


# Tests ordering of messages from multiple iterators when they share the
# same timestamp (deterministic tie-breaking).
class _MultiMsgIterOrderingSrc(
    bt2._UserSourceComponent, message_iterator_class=_MsgIter
):
    def __init__(self, config, params, obj):
        def make_msgs_1(msg_iter):
            # Event, 2500 ns, trace "hello", stream class 0, stream 1
            stream_class0 = tc1.create_stream_class(
                id=0, default_clock_class=clk_cls, assigns_automatic_stream_id=False
            )

            sc_0_stream_1 = tc1(name="hello").create_stream(stream_class0, id=1)
            event_class = stream_class0.create_event_class(name="saumon atlantique")

            msg_iter._msgs = [
                msg_iter._create_stream_beginning_message(sc_0_stream_1, 0),
                msg_iter._create_event_message(event_class, sc_0_stream_1, cs_value),
                msg_iter._create_stream_end_message(sc_0_stream_1, 193),
            ]

        def make_msgs_2(msg_iter):
            # Packet beginning, 2500 ns, trace "meow", stream class 0, stream 1
            stream_class0 = tc2.create_stream_class(
                id=0,
                default_clock_class=clk_cls,
                supports_packets=True,
                packets_have_beginning_default_clock_snapshot=True,
                packets_have_end_default_clock_snapshot=True,
                assigns_automatic_stream_id=False,
            )

            sc_0_stream_1 = tc2(name="meow").create_stream(stream_class0, id=1)
            packet = sc_0_stream_1.create_packet()

            msg_iter._msgs = [
                msg_iter._create_stream_beginning_message(sc_0_stream_1, 1),
                msg_iter._create_packet_beginning_message(packet, cs_value),
                msg_iter._create_packet_end_message(packet, 2 * 79),
                msg_iter._create_stream_end_message(sc_0_stream_1, 2 * 193),
            ]

        def make_msgs_3(msg_iter):
            # Stream beginning, 2500 ns, trace "hello", stream class 0, stream 0
            stream_class0 = tc3.create_stream_class(
                id=0, default_clock_class=clk_cls, assigns_automatic_stream_id=False
            )

            sc_0_stream_0 = tc3(name="hello").create_stream(stream_class0, id=0)

            msg_iter._msgs = [
                msg_iter._create_stream_beginning_message(sc_0_stream_0, cs_value),
                msg_iter._create_stream_end_message(sc_0_stream_0, 3 * 193),
            ]

        def make_msgs_4(msg_iter):
            # Event, 2500 ns, trace "meow", stream class 1, stream 1
            stream_class1 = tc4.create_stream_class(
                id=1, default_clock_class=clk_cls, assigns_automatic_stream_id=False
            )

            sc_1_stream_1 = tc4(name="meow").create_stream(stream_class1, id=1)
            event_class = stream_class1.create_event_class(name="bar rayé")

            msg_iter._msgs = [
                msg_iter._create_stream_beginning_message(sc_1_stream_1, 3),
                msg_iter._create_event_message(event_class, sc_1_stream_1, cs_value),
                msg_iter._create_stream_end_message(sc_1_stream_1, 4 * 193),
            ]

        tc1 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        tc2 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        tc3 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        tc4 = self._create_trace_class(assigns_automatic_stream_class_id=False)
        clk_cls = self._create_clock_class(frequency=1, offset=bt2.ClockOffset(0))

        # Craft list of messages for each message iterator so that the
        # last messages of each message iterator are all sharing the
        # same timestamp.
        cs_value = 25
        self._add_output_port("out1", make_msgs_1)
        self._add_output_port("out2", make_msgs_2)
        self._add_output_port("out3", make_msgs_3)
        self._add_output_port("out4", make_msgs_4)


_TEST_CASES = [
    ("basic-timestamp-ordering", _BasicTsOrderingSrc),
    ("diff-event-class-id", _DiffEcIdSrc),
    ("diff-event-class-name", _DiffEcNameSrc),
    ("diff-inactivity-msg-cs", _DiffInactivityMsgCsSrc),
    ("diff-stream-class-id", _DiffScIdSrc),
    ("diff-stream-class-name", _DiffScNameSrc),
    ("diff-stream-class-no-name", _DiffScNoNameSrc),
    ("diff-stream-id", _DiffStreamIdSrc),
    ("diff-stream-name", _DiffStreamNameSrc),
    ("diff-stream-no-name", _DiffStreamNoNameSrc),
    ("diff-trace-name", _DiffTraceNameSrc),
    ("multi-iter-ordering", _MultiMsgIterOrderingSrc),
]


@pytest.mark.parametrize(
    ["test_name", "src_comp_cls"],
    [pytest.param(name, comp_cls, id=name) for name, comp_cls in _TEST_CASES],
)
def test_muxer_succeed(test_name, src_comp_cls):
    btu.convert_sink_text_details_test(
        bt2.ComponentSpec(src_comp_cls),
        btu.this_src_dir(__file__) / "{}.expect".format(test_name),
        details_params={"compact": False, "with-metadata": False},
    )
